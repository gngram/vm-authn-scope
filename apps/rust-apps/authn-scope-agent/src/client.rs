//! Client logic — connects to the CA server and provides the local Workload API.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct X509Credentials {
    #[allow(dead_code)]
    pub spiffe_id: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_cert_pem: String,
}
use tokio::{net::UnixListener, sync::Mutex};
use tracing::info;

use authn_scope_proto::{
    codec::{recv_json, send_json},
    wire::{
        AgentRequest, AgentResponse, PROTOCOL_VERSION, PROTOCOL_VERSION_DUAL_TPM,
        PROTOCOL_VERSION_TPM, WorkloadConfig,
    },
};

use anyhow::{Context, Result, bail};

use crate::{config::AgentConfig, csr::generate_csr, transport};

// JSON request/response structures for Workload API
#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct WorkloadRequest {
    #[serde(rename = "type")]
    pub req_type: String,
}

#[allow(dead_code)]
#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum WorkloadResponse {
    Success {
        cert_pem: String,
        key_pem: String,
        ca_cert_pem: String,
    },
    Error {
        message: String,
    },
}

struct CachedCredential {
    cert_pem: String,
    key_pem: String,
    ca_cert_pem: String,
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
pub struct AgentSvid {
    pub cert_pem: String,
    pub key_pem: String,
}

struct AgentState {
    cache: Mutex<HashMap<String, CachedCredential>>,
    dial_mutex: Mutex<()>,
    vsock_listener: Mutex<Option<tokio_vsock::VsockListener>>,
    workloads: Mutex<HashMap<String, WorkloadConfig>>,
    agent_svid: Mutex<Option<AgentSvid>>,
}

fn sign_agent_request(key_pem: &str, payload: &[u8]) -> Result<String> {
    use ring::signature::EcdsaKeyPair;
    use ring::rand::SystemRandom;

    let key_der = pem_key_to_der(key_pem);
    if key_der.is_empty() {
        bail!("Failed to parse Agent SVID private key DER");
    }

    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &key_der,
        &rng,
    )
    .map_err(|e| anyhow::anyhow!("failed to parse PKCS8 key for Agent SVID: {:?}", e))?;

    let sig = key_pair
        .sign(&rng, payload)
        .map_err(|e| anyhow::anyhow!("signing payload with Agent SVID key failed: {:?}", e))?;

    Ok(base64_encode(sig.as_ref()))
}

/// Run agent: Handshake first, then start workloads UDS listener.
pub async fn run_agent(config: &AgentConfig) -> Result<()> {
    // 1. Perform boot-time handshake with Host/Server to retrieve workloads configuration and Agent SVID.
    let (workloads, agent_svid) = perform_handshake(config).await?;

    // 2. If using vsock, bind the persistent listener to client port (901) to protect it.
    let persistent_listener = if config.transport == "vsock" {
        let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, config.client_port);
        let mut attempts = 0;
        let listener = loop {
            match tokio_vsock::VsockListener::bind(addr) {
                Ok(l) => break l,
                Err(e) => {
                    if attempts < 10 {
                        attempts += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    return Err(e).context(format!(
                        "binding persistent listener to client port {} to secure it",
                        config.client_port
                    ));
                }
            }
        };
        Some(listener)
    } else {
        None
    };

    let state = Arc::new(AgentState {
        cache: Mutex::new(HashMap::new()),
        dial_mutex: Mutex::new(()),
        vsock_listener: Mutex::new(persistent_listener),
        workloads: Mutex::new(workloads),
        agent_svid: Mutex::new(agent_svid),
    });

    // 3. Launch Workload API UDS server concurrently if configured.
    if let Some(ref socket_path) = config.workload_api_socket {
        let config_clone = Arc::new(config.clone());
        let state_clone = Arc::clone(&state);
        let path_clone = socket_path.clone();
        tokio::spawn(async move {
            if let Err(e) = run_workload_api(config_clone, state_clone, path_clone).await {
                tracing::error!("Workload API server stopped with error: {:?}", e);
            }
        });
    }

    // 4. Launch background notification listener to receive time sync signals from host CA server.
    let config_clone = Arc::new(config.clone());
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        run_notification_listener(config_clone, state_clone).await;
    });

    info!(
        transport = %config.transport,
        "Agent online and ready. Running main event loop..."
    );

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn run_notification_listener(config: Arc<AgentConfig>, state: Arc<AgentState>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        info!("Connecting to CA server notification channel...");
        match connect_and_listen_notifications(&config, &state).await {
            Ok(()) => {
                info!("Notification subscription connection ended cleanly");
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                tracing::warn!(error = %e, "Notification channel error. Retrying in {:?}", backoff);
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, Duration::from_secs(30));
            }
        }
    }
}

async fn connect_and_listen_notifications(
    config: &AgentConfig,
    state: &AgentState,
) -> Result<()> {
    info!(
        notification_port = config.notification_port,
        "Connecting to CA server notification channel from dedicated notification port..."
    );

    let mut stream = transport::connect_to_server_port(config, config.notification_port)
        .await
        .context("connecting to server notification channel failed")?;

    let (agent_svid_pem, agent_svid_signature) = {
        let svid_guard = state.agent_svid.lock().await;
        if let Some(ref svid) = *svid_guard {
            let payload = format!("subscribe_{}", config.vm_name);
            let sig = sign_agent_request(&svid.key_pem, payload.as_bytes())?;
            (Some(svid.cert_pem.clone()), Some(sig))
        } else {
            (None, None)
        }
    };

    let req = AgentRequest::SubscribeNotifications {
        version: PROTOCOL_VERSION,
        vm_name: config.vm_name.clone(),
        agent_svid_pem,
        agent_svid_signature,
    };

    send_json(&mut stream, &req)
        .await
        .context("sending SubscribeNotifications request")?;

    info!("Subscribed to CA server notifications on port {}. Waiting for events...", config.notification_port);

    listen_loop(&mut stream, config, state).await
}

async fn listen_loop(
    stream: &mut transport::TransportStream,
    config: &AgentConfig,
    state: &AgentState,
) -> Result<()> {
    loop {
        let resp: AgentResponse = recv_json(stream).await.context("reading notification")?;
        match resp {
            AgentResponse::TimeSyncNotification { timestamp } => {
                info!(
                    timestamp,
                    "Received TimeSyncNotification from server! Flushing cache and rotating all workload certificates..."
                );
                {
                    let mut cache = state.cache.lock().await;
                    cache.clear();
                }

                let workloads: Vec<String> = {
                    let wl_map = state.workloads.lock().await;
                    wl_map.keys().cloned().collect()
                };

                for identity_name in workloads {
                    info!(identity = %identity_name, "Proactively requesting rotated certificate post-time-sync");
                    if let Err(e) = get_or_fetch_credentials(config, &identity_name, state).await {
                        tracing::error!(identity = %identity_name, error = %e, "Failed to rotate certificate after time sync");
                    }
                }
            }
            AgentResponse::Error { message } => {
                bail!("Server notification channel returned error: {}", message);
            }
            _ => {
                tracing::debug!("Received unexpected response on notification channel: {:?}", resp);
            }
        }
    }
}

async fn perform_handshake(
    config: &AgentConfig,
) -> Result<(HashMap<String, WorkloadConfig>, Option<AgentSvid>)> {
    // Detect TPM if present
    let tpm_info = match authn_scope_tpm::try_detect_tpm() {
        Ok(tcti) => {
            info!("TPM detected at {}", tcti);
            match authn_scope_tpm::create_attestation_key(&tcti) {
                Ok((ak_pub, ak_handle)) => {
                    info!("Attestation key ready (handle 0x{:08x})", ak_handle);
                    Some((tcti, ak_pub, ak_handle))
                }
                Err(e) => {
                    tracing::warn!("Failed to create/load attestation key: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            info!(
                "No TPM device detected ({}) - proceeding without TPM attestation",
                e
            );
            None
        }
    };

    let ak_pub_b64 = tpm_info
        .as_ref()
        .map(|(_, ak, _)| base64_encode(&ak.public_bytes));

    // Generate a 32-byte client challenge nonce for server hardware attestation if TPM is present
    let client_nonce = if tpm_info.is_some() {
        let n = generate_nonce();
        Some(base64_encode(&n))
    } else {
        None
    };

    let version = if client_nonce.is_some() {
        PROTOCOL_VERSION_DUAL_TPM
    } else if ak_pub_b64.is_some() {
        PROTOCOL_VERSION_TPM
    } else {
        PROTOCOL_VERSION
    };

    info!(
        vm_name = %config.vm_name,
        transport = %config.transport,
        has_tpm = tpm_info.is_some(),
        "[Agent Step 1] Connecting to Host CA Server to perform handshake..."
    );

    let mut stream = transport::connect_to_server(config)
        .await
        .context("handshake transport connection failed")?;

    let req = AgentRequest::Handshake {
        version,
        vm_name: config.vm_name.clone(),
        ak_pub: ak_pub_b64,
        client_nonce: client_nonce.clone(),
    };
    send_json(&mut stream, &req)
        .await
        .context("sending handshake request")?;

    let resp: AgentResponse = recv_json(&mut stream)
        .await
        .context("receiving handshake response")?;

    match resp {
        AgentResponse::DualAttestationChallenge {
            server_nonce,
            server_ak_pub,
            server_attest,
            server_signature,
        } => {
            info!("Received DualAttestationChallenge from CA server");

            // 1. If server sent a hardware quote, verify it against client_nonce
            if let (Some(s_ak_b64), Some(s_attest_b64), Some(s_sig_b64)) =
                (server_ak_pub, server_attest, server_signature)
            {
                if let Some(ref c_nonce_b64) = client_nonce {
                    let s_ak_bytes = base64_decode(&s_ak_b64)?;
                    let s_attest_bytes = base64_decode(&s_attest_b64)?;
                    let s_sig_bytes = base64_decode(&s_sig_b64)?;
                    let c_nonce_bytes = base64_decode(c_nonce_b64)?;

                    let s_quote = authn_scope_tpm::TpmQuote {
                        attest_bytes: s_attest_bytes,
                        signature_bytes: s_sig_bytes,
                    };

                    authn_scope_tpm::verify_quote(&s_ak_bytes, &c_nonce_bytes, &s_quote).map_err(
                        |e| anyhow::anyhow!("Server hardware TPM quote verification failed: {}", e),
                    )?;

                    let tcti_ref = tpm_info.as_ref().map(|(tcti, _, _)| tcti.as_str());
                    verify_or_learn_server(&s_ak_b64, tcti_ref)?;
                    info!("Dual Attestation: Server hardware TPM verified successfully!");
                }
            } else if config.server_attestation_required.unwrap_or(false) {
                bail!(
                    "Server attestation is required by config but server did not provide a hardware TPM quote"
                );
            }

            // 2. Generate agent's TPM quote for server_nonce using NO_PCRS
            let (tcti, _ak_pub, ak_handle) = tpm_info.ok_or_else(|| {
                anyhow::anyhow!("Received attestation challenge but no TPM is available")
            })?;

            let server_nonce_bytes = base64_decode(&server_nonce)?;
            let quote = authn_scope_tpm::generate_quote(
                &tcti,
                ak_handle,
                &server_nonce_bytes,
                authn_scope_tpm::NO_PCRS,
            )
            .map_err(|e| anyhow::anyhow!("Failed to generate TPM quote: {}", e))?;

            let attest_resp = AgentRequest::AttestationResponse {
                attest: base64_encode(&quote.attest_bytes),
                signature: base64_encode(&quote.signature_bytes),
            };

            send_json(&mut stream, &attest_resp)
                .await
                .context("sending attestation response")?;

            let final_resp: AgentResponse = recv_json(&mut stream)
                .await
                .context("receiving post-attestation response")?;

            match final_resp {
                AgentResponse::HandshakeOk {
                    workloads,
                    agent_svid_cert_pem,
                    agent_svid_key_pem,
                    ..
                } => {
                    info!(
                        "Dual attestation verified by server! Received {} workload configurations",
                        workloads.len()
                    );
                    let svid = match (agent_svid_cert_pem, agent_svid_key_pem) {
                        (Some(cert_pem), Some(key_pem)) => Some(AgentSvid { cert_pem, key_pem }),
                        _ => None,
                    };
                    Ok((workloads, svid))
                }
                AgentResponse::Error { message } => {
                    bail!("Attestation rejected by server: {}", message);
                }
                _ => {
                    bail!("Unexpected post-attestation response from server");
                }
            }
        }
        AgentResponse::AttestationChallenge { nonce } => {
            info!("Received AttestationChallenge from CA server");
            let (tcti, _ak_pub, ak_handle) = tpm_info.ok_or_else(|| {
                anyhow::anyhow!("Received attestation challenge but no TPM is available")
            })?;

            let nonce_bytes = base64_decode(&nonce)?;
            let quote = authn_scope_tpm::generate_quote(
                &tcti,
                ak_handle,
                &nonce_bytes,
                authn_scope_tpm::NO_PCRS,
            )
            .map_err(|e| anyhow::anyhow!("Failed to generate TPM quote: {}", e))?;

            let attest_resp = AgentRequest::AttestationResponse {
                attest: base64_encode(&quote.attest_bytes),
                signature: base64_encode(&quote.signature_bytes),
            };

            send_json(&mut stream, &attest_resp)
                .await
                .context("sending attestation response")?;

            let final_resp: AgentResponse = recv_json(&mut stream)
                .await
                .context("receiving post-attestation response")?;

            match final_resp {
                AgentResponse::HandshakeOk {
                    workloads,
                    agent_svid_cert_pem,
                    agent_svid_key_pem,
                    ..
                } => {
                    info!(
                        "Attestation verified by server! Received {} workload configurations",
                        workloads.len()
                    );
                    let svid = match (agent_svid_cert_pem, agent_svid_key_pem) {
                        (Some(cert_pem), Some(key_pem)) => Some(AgentSvid { cert_pem, key_pem }),
                        _ => None,
                    };
                    Ok((workloads, svid))
                }
                AgentResponse::Error { message } => {
                    bail!("Attestation rejected by server: {}", message);
                }
                _ => {
                    bail!("Unexpected post-attestation response from server");
                }
            }
        }
        AgentResponse::HandshakeOk {
            workloads,
            agent_svid_cert_pem,
            agent_svid_key_pem,
            ..
        } => {
            info!(
                "Handshake successful, received {} workload configurations",
                workloads.len()
            );
            let svid = match (agent_svid_cert_pem, agent_svid_key_pem) {
                (Some(cert_pem), Some(key_pem)) => Some(AgentSvid { cert_pem, key_pem }),
                _ => None,
            };
            Ok((workloads, svid))
        }
        AgentResponse::Error { message } => {
            bail!("Handshake rejected by server: {}", message);
        }
        _ => {
            bail!("Unexpected handshake response from server: {:?}", resp);
        }
    }
}

use authn_scope_proto::spiffe::workload::{
    spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer},
    X509svid, X509svidRequest, X509svidResponse,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

#[derive(Clone, Debug)]
pub struct UdsConnectInfo {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

pub struct SpiffeWorkloadServiceImpl {
    config: Arc<AgentConfig>,
    state: Arc<AgentState>,
}

fn get_proc_info(pid: u32) -> (Option<String>, Option<String>, Option<String>) {
    if pid == 0 {
        return (None, None, None);
    }

    let bin_path = std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    let mut unitpath = None;
    let mut unitname = None;

    if let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
        for line in cgroup.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let path = parts[2];
                if path.contains(".service") {
                    unitpath = Some(path.to_string());
                    if let Some(name) = path.split('/').last() {
                        unitname = Some(name.to_string());
                    }
                    break;
                }
            }
        }
    }

    (bin_path, unitpath, unitname)
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for SpiffeWorkloadServiceImpl {
    type FetchX509SVIDStream = ReceiverStream<Result<X509svidResponse, Status>>;

    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        let peer_info = request.extensions().get::<UdsConnectInfo>().cloned();
        info!(?peer_info, "[Agent WorkloadAPI] Received FetchX509SVID request on Workload API UDS socket");
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let config = Arc::clone(&self.config);
        let state = Arc::clone(&self.state);

        tokio::spawn(async move {
            let mut iter_count = 0u64;
            loop {
                iter_count += 1;
                // Wait for agent handshake to complete and workloads to be populated
                let identity_name = loop {
                    let workloads = state.workloads.lock().await;
                    if !workloads.is_empty() {
                        let matched = if let Some(ref peer) = peer_info {
                            let (bin_path, unitpath, unitname) = get_proc_info(peer.pid);
                            match_workload(
                                &workloads,
                                peer.uid,
                                peer.gid,
                                bin_path.as_deref(),
                                unitpath.as_deref(),
                                unitname.as_deref(),
                            )
                        } else {
                            None
                        };

                        let selected = matched
                            .or_else(|| workloads.keys().next().cloned())
                            .unwrap();
                        break selected;
                    }
                    drop(workloads);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                };

                info!(identity = %identity_name, ?peer_info, iter = iter_count, "[Agent WorkloadAPI] Processing FetchX509SVID iteration #{}", iter_count);

                match get_or_fetch_credentials(&config, &identity_name, &state).await {
                    Ok(creds) => {
                        let cert_der = pem_to_der(&creds.cert_pem);
                        let key_der = pem_key_to_der(&creds.key_pem);
                        let ca_der = pem_to_der(&creds.ca_cert_pem);

                        let spiffe_id = if let Ok((_, x509)) = x509_parser::parse_x509_certificate(&cert_der) {
                            if let Ok(Some(sans)) = x509.subject_alternative_name() {
                                sans.value.general_names.iter().find_map(|san| {
                                    if let x509_parser::extensions::GeneralName::URI(uri) = san {
                                        Some(uri.to_string())
                                    } else {
                                        None
                                    }
                                }).unwrap_or_else(|| format!("spiffe://example.org/workload/{}", identity_name))
                            } else {
                                format!("spiffe://example.org/workload/{}", identity_name)
                            }
                        } else {
                            format!("spiffe://example.org/workload/{}", identity_name)
                        };

                        let svid = X509svid {
                            spiffe_id: spiffe_id.clone(),
                            x509_svid: cert_der,
                            x509_svid_key: key_der,
                            bundle: ca_der,
                            hint: "authn-scope".to_string(),
                        };

                        let resp = X509svidResponse {
                            svids: vec![svid],
                            crl: vec![],
                            federated_bundles: std::collections::HashMap::new(),
                        };

                        info!(identity = %identity_name, spiffe_id = %spiffe_id, iter = iter_count, "[Agent WorkloadAPI] Sending X509SVID response over gRPC stream");

                        if tx.send(Ok(resp)).await.is_err() {
                            tracing::warn!("[Agent WorkloadAPI] Client disconnected from gRPC stream");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "[Agent WorkloadAPI] Failed to get credentials for stream response");
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn pem_to_der(pem_str: &str) -> Vec<u8> {
    use rustls_pemfile::certs;
    certs(&mut pem_str.as_bytes())
        .filter_map(|r| r.ok())
        .next()
        .map(|c| c.to_vec())
        .unwrap_or_default()
}

fn pem_key_to_der(pem_str: &str) -> Vec<u8> {
    use rustls_pemfile::private_key;
    private_key(&mut pem_str.as_bytes())
        .ok()
        .flatten()
        .map(|k| k.secret_der().to_vec())
        .unwrap_or_default()
}

struct UdsStream {
    stream: tokio::net::UnixStream,
    connect_info: UdsConnectInfo,
}

impl tokio::io::AsyncRead for UdsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for UdsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for UdsStream {
    type ConnectInfo = UdsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.connect_info.clone()
    }
}

/// Start standard SPIFFE Workload API UDS server loop.
async fn run_workload_api(
    config: Arc<AgentConfig>,
    state: Arc<AgentState>,
    socket_path: String,
) -> Result<()> {
    let _ = std::fs::remove_file(&socket_path);

    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = UnixListener::bind(&socket_path)?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))?;

    info!(
        "Standard SPIFFE Workload API gRPC server listening on UDS at {}",
        socket_path
    );

    let incoming = async_stream::stream! {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let cred_info = if let Ok(cred) = stream.peer_cred() {
                        UdsConnectInfo {
                            uid: cred.uid(),
                            gid: cred.gid(),
                            pid: cred.pid().unwrap_or(0) as u32,
                        }
                    } else {
                        UdsConnectInfo { uid: 0, gid: 0, pid: 0 }
                    };
                    yield Ok::<_, std::io::Error>(UdsStream {
                        stream,
                        connect_info: cred_info,
                    });
                }
                Err(e) => yield Err(e),
            }
        }
    };

    let service = SpiffeWorkloadServiceImpl { config, state };

    tonic::transport::Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}


fn match_workload(
    workloads: &HashMap<String, WorkloadConfig>,
    proc_uid: u32,
    proc_gid: u32,
    proc_bin_path: Option<&str>,
    proc_unitpath: Option<&str>,
    proc_unitname: Option<&str>,
) -> Option<String> {
    let mut candidates = Vec::new();

    for (name, config) in workloads {
        let mut matches = true;
        let mut systemd_matched = false;
        let mut bin_path_matched = false;
        let mut uid_matched = false;
        let mut gid_matched = false;

        if let Some(ref unix) = config.selector.unix {
            if let Some(ref wl_user) = unix.user {
                let wl_uid = uzers::get_user_by_name(wl_user).map(|u| u.uid());
                if wl_uid != Some(proc_uid) {
                    matches = false;
                } else {
                    uid_matched = true;
                }
            }
            if let Some(ref wl_group) = unix.group {
                let wl_gid = uzers::get_group_by_name(wl_group).map(|g| g.gid());
                if wl_gid != Some(proc_gid) {
                    matches = false;
                } else {
                    gid_matched = true;
                }
            }
            if let Some(ref wl_bin_path) = unix.bin_path {
                if Some(wl_bin_path.as_str()) != proc_bin_path {
                    matches = false;
                } else {
                    bin_path_matched = true;
                }
            }
        }

        if let Some(ref systemd) = config.selector.systemd {
            let mut has_sysd_selector = false;
            let mut sysd_matches = true;
            if let Some(ref wl_unitpath) = systemd.unitpath {
                has_sysd_selector = true;
                if Some(wl_unitpath.as_str()) != proc_unitpath {
                    sysd_matches = false;
                }
            }
            if let Some(ref wl_unitname) = systemd.unitname {
                has_sysd_selector = true;
                let proc_name = proc_unitname.unwrap_or("");
                let proc_name_stripped = proc_name.strip_suffix(".service").unwrap_or(proc_name);
                if wl_unitname != proc_name && wl_unitname != proc_name_stripped {
                    sysd_matches = false;
                }
            }
            if has_sysd_selector {
                if sysd_matches {
                    systemd_matched = true;
                } else {
                    matches = false;
                }
            }
        }

        if matches {
            let mut score = 0;
            if systemd_matched {
                score += 100;
            }
            if bin_path_matched {
                score += 10;
            }
            if uid_matched {
                score += 1;
            }
            if gid_matched {
                score += 1;
            }
            candidates.push((score, name.clone()));
        }
    }

    candidates.sort_by_key(|b| std::cmp::Reverse(b.0));
    candidates.first().map(|c| c.1.clone())
}

async fn get_or_fetch_credentials(
    config: &AgentConfig,
    identity_name: &str,
    state: &AgentState,
) -> Result<X509Credentials> {
    let mut cache = state.cache.lock().await;

    if let Some(cached) = cache.get(identity_name) {
        let ttl_secs = get_cert_validity_seconds(&cached.cert_pem).unwrap_or(600);
        let rotation_threshold = Duration::from_secs(ttl_secs / 2);
        let elapsed = cached.fetched_at.elapsed();
        if elapsed < rotation_threshold {
            info!(identity = %identity_name, elapsed_secs = elapsed.as_secs(), threshold_secs = rotation_threshold.as_secs(), "[Agent Cache] Cache HIT for identity (credentials valid)");
            let spiffe_id = format!("spiffe://example.org/workload/{}", identity_name);
            return Ok(X509Credentials {
                spiffe_id,
                cert_pem: cached.cert_pem.clone(),
                key_pem: cached.key_pem.clone(),
                ca_cert_pem: cached.ca_cert_pem.clone(),
            });
        }
        info!(identity = %identity_name, elapsed_secs = elapsed.as_secs(), threshold_secs = rotation_threshold.as_secs(), "[Agent Cache] Cache EXPIRED/THRESHOLD reached for identity — requesting new certificate");
    } else {
        info!(identity = %identity_name, "[Agent Cache] Cache MISS for identity — requesting new certificate on demand");
    }

    let creds = request_cert_on_demand(config, identity_name, state).await?;
    cache.insert(
        identity_name.to_string(),
        CachedCredential {
            cert_pem: creds.cert_pem.clone(),
            key_pem: creds.key_pem.clone(),
            ca_cert_pem: creds.ca_cert_pem.clone(),
            fetched_at: Instant::now(),
        },
    );

    Ok(creds)
}

/// Request a new certificate on demand.
async fn request_cert_on_demand(
    config: &AgentConfig,
    identity_name: &str,
    state: &AgentState,
) -> Result<X509Credentials> {
    info!(identity = %identity_name, "[Agent CSR] Requesting certificate from CA server on demand");

    let generated = generate_csr(identity_name)
        .with_context(|| format!("CSR generation for identity '{}'", identity_name))?;

    let _dial_guard = state.dial_mutex.lock().await;

    // For vsock, briefly release the port 901 listener so the connected socket can bind port 901
    if config.transport == "vsock" {
        *state.vsock_listener.lock().await = None;
    }

    let mut stream = transport::connect_to_server(config)
        .await
        .context("connecting on demand failed")?;

    let (agent_svid_pem, agent_svid_signature) = {
        let svid_guard = state.agent_svid.lock().await;
        if let Some(ref svid) = *svid_guard {
            let payload = format!("{}{}{}", generated.csr_pem, identity_name, config.vm_name);
            let sig = sign_agent_request(&svid.key_pem, payload.as_bytes())?;
            (Some(svid.cert_pem.clone()), Some(sig))
        } else {
            (None, None)
        }
    };

    let req = AgentRequest::CertRequest {
        version: PROTOCOL_VERSION,
        vm_name: config.vm_name.clone(),
        identity: identity_name.to_string(),
        csr_pem: generated.csr_pem,
        agent_svid_pem,
        agent_svid_signature,
    };
    send_json(&mut stream, &req)
        .await
        .context("sending CertRequest")?;

    let resp: AgentResponse = recv_json(&mut stream)
        .await
        .context("receiving AgentResponse")?;

    // Drop the stream before re-binding the vsock listener
    std::mem::drop(stream);

    if config.transport == "vsock" {
        let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, config.client_port);
        let mut attempts = 0;
        let new_listener = loop {
            match tokio_vsock::VsockListener::bind(addr) {
                Ok(l) => break l,
                Err(e) => {
                    if attempts < 10 {
                        attempts += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    return Err(e)
                        .context("failed to re-bind port 901 listener after on-demand dial");
                }
            }
        };
        *state.vsock_listener.lock().await = Some(new_listener);
    }

    match resp {
        AgentResponse::CertOk {
            cert_pem,
            ca_cert_pem,
        } => Ok(X509Credentials {
            spiffe_id: format!("spiffe://example.org/workload/{}", identity_name),
            cert_pem,
            key_pem: generated.key_pem,
            ca_cert_pem,
        }),
        AgentResponse::Error { message } => {
            bail!(
                "Server rejected request for '{}': {}",
                identity_name,
                message
            );
        }
        _ => {
            bail!("Unexpected response from CA server");
        }
    }
}

fn get_cert_validity_seconds(cert_pem: &str) -> Result<u64> {
    use x509_parser::pem::parse_x509_pem;
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {:?}", e))?;
    let x509 = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("Failed to parse X.509: {:?}", e))?;
    let validity = x509.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    if not_after > not_before {
        Ok((not_after - not_before) as u64)
    } else {
        Ok(0)
    }
}

fn get_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AUTHN_SCOPE_STATE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    PathBuf::from("/var/lib/authn-scope")
}

fn get_known_server_path() -> PathBuf {
    get_state_dir().join("known_server.json")
}

fn get_known_server_seal_path() -> PathBuf {
    get_state_dir().join("known_server_seal.json")
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct KnownServer {
    pub ak_pub: String,
    pub learned_at: String,
}

fn verify_or_learn_server(ak_pub_b64: &str, tcti_opt: Option<&str>) -> Result<()> {
    let path = get_known_server_path();
    let seal_path = get_known_server_seal_path();

    if path.exists() {
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("reading TOFU server state from {}", path.display()))?;

        // If vTPM and seal file exist, verify the seal of known_server.json
        if seal_path.exists() {
            if let Some(tcti) = tcti_opt {
                let seal_data = std::fs::read_to_string(&seal_path)
                    .context("reading known_server seal file")?;
                let blob: authn_scope_tpm::SealedBlob =
                    serde_json::from_str(&seal_data).context("parsing known_server seal file")?;
                match authn_scope_tpm::unseal_data(tcti, &blob) {
                    Ok(unsealed) => {
                        let stored_hash_hex = String::from_utf8(unsealed)
                            .context("sealed data is not valid UTF-8")?;
                        let current_hash = sha256(data.as_bytes());
                        let current_hash_hex = hex_encode(&current_hash);
                        if stored_hash_hex != current_hash_hex {
                            bail!(
                                "KNOWN_SERVER INTEGRITY VIOLATION: known_server.json has been tampered with!\n\
                                 Expected hash: {}\n\
                                 Current hash:  {}\n\
                                 The file was modified outside vTPM authority.",
                                stored_hash_hex,
                                current_hash_hex
                            );
                        }
                        info!("known_server.json integrity verified via vTPM seal");
                    }
                    Err(e) => {
                        tracing::warn!("Failed to unseal known_server hash from vTPM: {}", e);
                    }
                }
            }
        }

        let known: KnownServer = serde_json::from_str(&data)
            .with_context(|| format!("parsing TOFU server state from {}", path.display()))?;
        if known.ak_pub != ak_pub_b64 {
            bail!(
                "SERVER HARDWARE AK INTEGRITY VIOLATION: Server AK public key has changed!\n\
                 This indicates the server machine key has been modified or replaced."
            );
        }
        info!("Server hardware AK verified (matches stored TOFU baseline)");
    } else {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let now = format!(
            "{}s-since-epoch",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        let known = KnownServer {
            ak_pub: ak_pub_b64.to_string(),
            learned_at: now,
        };
        let data = serde_json::to_string_pretty(&known)?;
        std::fs::write(&path, &data)
            .with_context(|| format!("writing TOFU server state to {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        // Seal known_server.json hash into vTPM if available
        if let Some(tcti) = tcti_opt {
            let hash = sha256(data.as_bytes());
            let hash_hex = hex_encode(&hash);
            match authn_scope_tpm::seal_data(tcti, hash_hex.as_bytes()) {
                Ok(blob) => {
                    let blob_json = serde_json::to_string_pretty(&blob)?;
                    let _ = std::fs::write(&seal_path, &blob_json);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &seal_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                    info!(
                        "known_server.json hash sealed into vTPM at {}",
                        seal_path.display()
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to seal known_server.json hash into vTPM: {}", e);
                }
            }
        }

        info!("TOFU: Learned server hardware AK public key baseline");
    }
    Ok(())
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_nonce() -> Vec<u8> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut nonce = vec![0u8; 32];
    rng.fill(&mut nonce).expect("system RNG failed");
    nonce
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("base64 decode error: {}", e))
}
