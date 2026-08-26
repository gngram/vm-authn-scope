//! vsock client — connects to the host CA and requests certificates.

use libc::{connect, sockaddr, sockaddr_vm, socklen_t};
use std::{
    collections::HashMap,
    os::unix::io::FromRawFd,
    sync::Arc,
    time::{Duration, Instant},
};

use authn_scope_workload::X509Credentials;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
use tokio_vsock::VsockStream;
use tracing::info;

use authn_scope_proto::{
    codec::{recv_json, send_json},
    wire::{AgentRequest, AgentResponse, PROTOCOL_VERSION, WorkloadConfig},
};

use anyhow::{bail, Context, Result};

use crate::{
    config::AgentConfig,
    csr::generate_csr,
};

async fn connect_with_local_port(host_cid: u32, port: u32, local_port: u32) -> Result<VsockStream> {
    let mut attempts = 0;
    loop {
        let socket =
            unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if socket < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // Bind to the local port
        let local_addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: local_port,
            svm_cid: libc::VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };

        let optval: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        if unsafe {
            libc::bind(
                socket,
                &local_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        } >= 0
        {
            // Bind succeeded, now connect!
            let sockaddr = sockaddr_vm {
                svm_family: libc::AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: host_cid,
                svm_zero: [0; 4],
            };

            if unsafe {
                connect(
                    socket,
                    &sockaddr as *const _ as *const sockaddr,
                    std::mem::size_of::<sockaddr_vm>() as socklen_t,
                )
            } >= 0
            {
                let stream = unsafe { vsock::VsockStream::from_raw_fd(socket) };
                let stream = VsockStream::new(stream)?;
                return Ok(stream);
            }

            let conn_err = std::io::Error::last_os_error();
            unsafe { libc::close(socket) };
            return Err(anyhow::anyhow!("vsock connect failed: {}", conn_err));
        }

        let err = std::io::Error::last_os_error();
        unsafe { libc::close(socket) };

        if err.kind() == std::io::ErrorKind::AddrInUse && attempts < 10 {
            attempts += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        return Err(err).context(format!(
            "binding vsock client socket to local port {}",
            local_port
        ));
    }
}

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
    listener: Mutex<Option<tokio_vsock::VsockListener>>,
    workloads: Mutex<HashMap<String, WorkloadConfig>>,
}

/// Run agent: Handshake first, then start workloads UDS listener.
pub async fn run_agent(config: &AgentConfig) -> Result<()> {
    // 1. Perform boot-time handshake with Host to retrieve workloads configuration.
    let workloads = perform_handshake(config).await?;

    // 2. Bind the persistent listener to client port (901) to protect it.
    let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, config.client_port);
    let mut attempts = 0;
    let persistent_listener = loop {
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

    let state = Arc::new(AgentState {
        cache: Mutex::new(HashMap::new()),
        dial_mutex: Mutex::new(()),
        listener: Mutex::new(Some(persistent_listener)),
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
        port = config.client_port,
        "Agent keeping client port secured. Running main event loop..."
    );

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn perform_handshake(config: &AgentConfig) -> Result<HashMap<String, WorkloadConfig>> {
    let host_cid = std::env::var("VSOCK_HOST_CID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(2); // VMADDR_CID_HOST

    info!(vm_name = %config.vm_name, "Connecting to host CA to perform handshake...");
    let mut attempts = 0;
    let mut stream = loop {
        match connect_with_local_port(host_cid, config.server_port, config.client_port).await {
            Ok(s) => break s,
            Err(e) => {
                if attempts < 15 {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                return Err(e).context("handshake vsock connection failed");
            }
        }
    };

    let req = AgentRequest::Handshake {
        version: PROTOCOL_VERSION,
        vm_name: config.vm_name.clone(),
    };
    send_json(&mut stream, &req)
        .await
        .context("sending handshake request")?;

    let resp: AgentResponse = recv_json(&mut stream)
        .await
        .context("receiving handshake response")?;

    match resp {
        AgentResponse::HandshakeOk { workloads } => {
            info!("Handshake successful, received {} workload configurations", workloads.len());
            Ok(workloads)
        }
        AgentResponse::Error { message } => {
            bail!("Handshake rejected by server: {}", message);
        }
        _ => {
            bail!("Unexpected handshake response from server");
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

    info!("Workload API listening on Unix Domain Socket at {}", socket_path);

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
                    if let Some(name) = path.split('/').last() {
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
                // Allow matching either exact unit name (e.g. service-a.service)
                // or stripped suffix (e.g. service-a)
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
            // Priority scoring:
            // 1. systemd-matched: 100
            // 2. bin-path-matched: 10
            // 3. uid-matched: 1, gid-matched: 1
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

    candidates.sort_by(|a, b| b.0.cmp(&a.0));
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

/// Request a new certificate on demand (briefly releasing/re-acquiring client port 901 listener).
async fn request_cert_on_demand(
    config: &AgentConfig,
    identity_name: &str,
    state: &AgentState,
) -> Result<X509Credentials> {
    info!(identity = %identity_name, "Requesting certificate from host CA on demand");

    let generated = generate_csr(identity_name)
        .with_context(|| format!("CSR generation for identity '{}'", identity_name))?;

    let host_cid = std::env::var("VSOCK_HOST_CID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(2); // VMADDR_CID_HOST

    // Acquire lock and drop current listener to release port 901
    let _dial_guard = state.dial_mutex.lock().await;
    *state.listener.lock().await = None;

    let connect_res = connect_with_local_port(host_cid, config.server_port, config.client_port).await;
    let mut stream = connect_res.context("vsock connect on demand failed")?;

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

    // Drop the stream to release the local port 901 connected socket!
    std::mem::drop(stream);

    // Re-bind listener to protect port 901 now that the connected socket is closed.
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
                return Err(e).context("failed to re-bind port 901 listener after on-demand dial");
            }
        }
    };
    *state.listener.lock().await = Some(new_listener);

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
            bail!("Unexpected response from host CA");
        }
    }
}

fn get_cert_validity_seconds(cert_pem: &str) -> Result<u64> {
    use x509_parser::pem::parse_x509_pem;
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {:?}", e))?;
    let x509 = pem.parse_x509()
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
