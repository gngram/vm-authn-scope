//! Per-connection request handler.
//!
//! Each accepted vsock+TLS connection follows this flow:
//!   1. Read a [`CertRequest`] frame.
//!   2. Validate the claimed CID against the actual vsock peer CID.
//!   3. Look up the CID+identity in the policy config.
//!   4. Sign the CSR and embed capability claims.
//!   5. Send a [`CertResponse`] frame.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info, warn};

use authn_scope_ca::{
    signing::{sign_csr, SigningRequest},
    CertificateAuthority,
};
use authn_scope_proto::{
    codec::{recv_json, send_json},
    wire::{CertRequest, CertResponse, PROTOCOL_VERSION},
};

use crate::{config::HostConfig, policy::resolve};

/// Handle a single authenticated connection.
///
/// `peer_cid` is the actual vsock CID of the peer (from the kernel),
/// used to cross-check the self-reported CID in the request.
pub async fn handle_connection<IO>(
    mut stream: IO,
    peer_cid: u32,
    config: Arc<HostConfig>,
    ca: Arc<CertificateAuthority>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match handle_inner(&mut stream, peer_cid, &config, &ca).await {
        Ok(()) => {}
        Err(e) => {
            error!(peer_cid, error = %e, "Error handling connection");
            // Best-effort error response.
            let _ = send_json(
                &mut stream,
                &CertResponse::Error {
                    message: e.to_string(),
                },
            )
            .await;
        }
    }
}

async fn handle_inner<IO>(
    stream: &mut IO,
    peer_cid: u32,
    config: &HostConfig,
    ca: &CertificateAuthority,
) -> anyhow::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // Read request.
    let req: CertRequest = recv_json(stream).await?;

    // Protocol version check.
    if req.version != PROTOCOL_VERSION {
        let msg = format!(
            "unsupported protocol version {} (expected {})",
            req.version, PROTOCOL_VERSION
        );
        warn!(peer_cid, identity = %req.identity, "{}", msg);
        send_json(stream, &CertResponse::Error { message: msg }).await?;
        return Ok(());
    }

    info!(
        peer_cid,
        identity = %req.identity,
        "Received certificate request"
    );

    // Policy lookup.
    let decision = match resolve(config, &req.vm_name, &req.identity) {
        Some(d) => d,
        None => {
            let msg = format!(
                "VM '{}' / identity '{}' not authorised",
                req.vm_name, req.identity
            );
            warn!(peer_cid, vm_name = %req.vm_name, identity = %req.identity, "{}", msg);
            send_json(stream, &CertResponse::Error { message: msg }).await?;
            return Ok(());
        }
    };

    // Verify CID
    if decision.vm_cid != peer_cid {
        let msg = format!(
            "CID verification failed for VM '{}': expected {}, got peer CID {}",
            req.vm_name, decision.vm_cid, peer_cid
        );
        error!(peer_cid, vm_name = %req.vm_name, expected_cid = decision.vm_cid, "{}", msg);
        // Immediately return error to close the connection without sending a response
        return Err(anyhow::anyhow!("CID verification failed"));
    }

    // Sign CSR.
    let cert_pem = sign_csr(
        ca,
        SigningRequest {
            csr_pem: &req.csr_pem,
            identity: req.identity.clone(),
            vm_name: decision.vm_name,
            cid: peer_cid,
            claims: decision.caps,
            validity_days: decision.validity_days,
        },
    )
    .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;

    info!(
        peer_cid,
        identity = %req.identity,
        "Certificate issued successfully"
    );

    send_json(
        stream,
        &CertResponse::Ok {
            cert_pem,
            ca_cert_pem: ca.cert_pem.clone(),
        },
    )
    .await?;

    Ok(())
}
