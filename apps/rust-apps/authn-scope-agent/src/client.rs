//! Client logic — connects to the CA server and provides the local Workload API.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use authn_scope_workload::X509Credentials;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
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
#[derive(Debug, serde::Deserialize)]
struct WorkloadRequest {
    #[serde(rename = "type")]
    pub req_type: String,
}

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

struct AgentState {
    cache: Mutex<HashMap<String, CachedCredential>>,
    dial_mutex: Mutex<()>,
    vsock_listener: Mutex<Option<tokio_vsock::VsockListener>>,
    workloads: Mutex<HashMap<String, WorkloadConfig>>,
}

/// Run agent: Handshake first, then start workloads UDS listener.
pub async fn run_agent(config: &AgentConfig) -> Result<()> {
    // 1. Perform boot-time handshake with Host/Server to retrieve workloads configuration.
    let workloads = perform_handshake(config).await?;

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

    info!(
        transport = %config.transport,
        "Agent online and ready. Running main event loop..."
    );

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn perform_handshake(config: &AgentConfig) -> Result<HashMap<String, WorkloadConfig>> {
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
        "Connecting to CA server to perform handshake..."
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
                AgentResponse::HandshakeOk { workloads } => {
                    info!(
                        "Dual attestation verified by server! Received {} workload configurations",
                        workloads.len()
                    );
                    Ok(workloads)
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
                AgentResponse::HandshakeOk { workloads } => {
                    info!(
                        "Attestation verified by server! Received {} workload configurations",
                        workloads.len()
                    );
                    Ok(workloads)
                }
                AgentResponse::Error { message } => {
                    bail!("Attestation rejected by server: {}", message);
                }
                _ => {
                    bail!("Unexpected post-attestation response from server");
                }
            }
        }
        AgentResponse::HandshakeOk { workloads } => {
            info!(
                "Handshake successful, received {} workload configurations",
                workloads.len()
            );
            Ok(workloads)
        }
        AgentResponse::Error { message } => {
            bail!("Handshake rejected by server: {}", message);
        }
        _ => {
            bail!("Unexpected handshake response from server: {:?}", resp);
        }
    }
}

/// Start UDS server loop.
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

    // Set 0666 permissions so any workload can connect
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))?;

    info!(
        "Workload API listening on Unix Domain Socket at {}",
        socket_path
    );

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let config = Arc::clone(&config);
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_workload_conn(stream, &config, &state).await {
                        tracing::error!("Error handling workload connection: {:?}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("Failed to accept workload connection: {:?}", e);
            }
        }
    }
}

/// Process a single workload client connection.
async fn handle_workload_conn(
    stream: UnixStream,
    config: &AgentConfig,
    state: &AgentState,
) -> Result<()> {
    let cred = stream.peer_cred()?;
    let uid = cred.uid();
    let gid = cred.gid();
    let pid = cred.pid().unwrap_or(0) as u32;

    let uid_gid = format!("{}:{}", uid, gid);

    // 1. Discover bin_path
    let proc_bin_path = std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    // 2. Discover systemd unitpath / unitname
    let mut proc_unitpath = None;
    let mut proc_unitname = None;
    if let Ok(content) = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let path = parts[2];
                if path.contains(".service") {
                    proc_unitpath = Some(path.to_string());
                    if let Some(name) = path.split('/').next_back() {
                        proc_unitname = Some(name.to_string());
                    }
                    break;
                }
            }
        }
    }

    info!(
        uid_gid = %uid_gid,
        pid,
        bin_path = ?proc_bin_path,
        unitpath = ?proc_unitpath,
        unitname = ?proc_unitname,
        "Accepted workload connection"
    );

    let workloads = state.workloads.lock().await;
    let identity_name = match match_workload(
        &workloads,
        uid,
        gid,
        proc_bin_path.as_deref(),
        proc_unitpath.as_deref(),
        proc_unitname.as_deref(),
    ) {
        Some(name) => name,
        None => {
            let err_msg = format!(
                "Attestation failed: no workload selector matches UID '{}', GID '{}', bin_path '{:?}', systemd unit name '{:?}'",
                uid, gid, proc_bin_path, proc_unitname
            );
            tracing::warn!("{}", err_msg);
            let mut stream = stream;
            let resp = WorkloadResponse::Error { message: err_msg };
            let resp_json = serde_json::to_string(&resp)? + "\n";
            stream.write_all(resp_json.as_bytes()).await?;
            return Ok(());
        }
    };

    info!(workload = %identity_name, "Discovered workload mapping");

    let mut reader = tokio::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    if line.is_empty() {
        return Ok(());
    }

    let req: WorkloadRequest = serde_json::from_str(&line)?;
    if req.req_type != "fetch" {
        let err_msg = format!("Unsupported request type: {}", req.req_type);
        let resp = WorkloadResponse::Error { message: err_msg };
        let mut writer = reader.into_inner();
        let resp_json = serde_json::to_string(&resp)? + "\n";
        writer.write_all(resp_json.as_bytes()).await?;
        return Ok(());
    }

    let creds = get_or_fetch_credentials(config, &identity_name, state).await?;

    let resp = WorkloadResponse::Success {
        cert_pem: creds.cert_pem,
        key_pem: creds.key_pem,
        ca_cert_pem: creds.ca_cert_pem,
    };
    let mut writer = reader.into_inner();
    let resp_json = serde_json::to_string(&resp)? + "\n";
    writer.write_all(resp_json.as_bytes()).await?;

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
        if cached.fetched_at.elapsed() < rotation_threshold {
            return Ok(X509Credentials {
                cert_pem: cached.cert_pem.clone(),
                key_pem: cached.key_pem.clone(),
                ca_cert_pem: cached.ca_cert_pem.clone(),
            });
        }
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
    info!(identity = %identity_name, "Requesting certificate from CA server on demand");

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

    let req = AgentRequest::CertRequest {
        version: PROTOCOL_VERSION,
        vm_name: config.vm_name.clone(),
        identity: identity_name.to_string(),
        csr_pem: generated.csr_pem,
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
