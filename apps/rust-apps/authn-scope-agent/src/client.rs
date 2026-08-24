//! vsock client — connects to the host CA and requests certificates.

use libc::{connect, sockaddr, sockaddr_vm, socklen_t};
use std::os::unix::io::FromRawFd;

use tokio_vsock::VsockStream;
use tracing::info;

use authn_scope_proto::{
    codec::{recv_json, send_json},
    wire::{CertRequest, CertResponse, PROTOCOL_VERSION},
};

use anyhow::{bail, Context, Result};

use crate::{
    config::{AgentConfig, IdentityEntry},
    csr::generate_csr,
    store::store_identity_credentials,
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
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }

        return Err(anyhow::anyhow!(
            "bind to client port {} failed: {}",
            local_port,
            err
        ));
    }
}

/// Request and store certificates for every identity in the config.
pub async fn run_agent(config: &AgentConfig) -> Result<()> {
    for identity in &config.identities {
        match request_cert(config, identity).await {
            Ok(()) => info!(identity = %identity.name, "Certificate stored successfully"),
            Err(e) => {
                tracing::error!(identity = %identity.name, error = ?e, "Certificate request failed")
            }
        }
    }

    // Secure the client port by binding a listener to it so no other process can use it.
    // We retry binding in case the port is still lingering in TIME_WAIT from the last client connection.
    let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, config.client_port);
    let mut attempts = 0;
    let _listener = loop {
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

    info!(
        port = config.client_port,
        "Agent keeping client port secured. Sleeping indefinitely..."
    );
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

/// Request and store a certificate for a single identity.
async fn request_cert(config: &AgentConfig, identity: &IdentityEntry) -> Result<()> {
    info!(identity = %identity.name, "Requesting certificate from host CA");

    // Generate a fresh keypair and CSR for this identity.
    let generated = generate_csr(&identity.name)
        .with_context(|| format!("CSR generation for identity '{}'", identity.name))?;

    // Connect to the host over vsock.
    let host_cid = std::env::var("VSOCK_HOST_CID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(2); // VMADDR_CID_HOST

    let mut stream = connect_with_local_port(host_cid, config.server_port, config.client_port)
        .await
        .context("vsock connect with local port failed")?;

    // Send certificate request.
    let req = CertRequest {
        version: PROTOCOL_VERSION,
        vm_name: config.vm_name.clone(),
        identity: identity.name.clone(),
        csr_pem: generated.csr_pem,
    };
    send_json(&mut stream, &req)
        .await
        .context("sending CertRequest")?;

    // Receive response.
    let resp: CertResponse = recv_json(&mut stream)
        .await
        .context("receiving CertResponse")?;

    match resp {
        CertResponse::Ok {
            cert_pem,
            ca_cert_pem,
        } => {
            store_identity_credentials(
                identity,
                &cert_pem,
                &generated.key_pem,
                &ca_cert_pem,
            )?;
        }
        CertResponse::Error { message } => {
            bail!(
                "Server rejected request for '{}': {}",
                identity.name,
                message
            );
        }
    }

    Ok(())
}
