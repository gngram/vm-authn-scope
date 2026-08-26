//! Per-connection request handler.

use std::sync::Arc;
use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info, warn};

use authn_scope_ca::{
    signing::{sign_csr, SigningRequest},
    CertificateAuthority,
};
use authn_scope_proto::{
    codec::{recv_json, send_json},
    wire::{AgentRequest, AgentResponse, PROTOCOL_VERSION, WorkloadConfig},
};

use crate::{config::HostConfig, policy::resolve};

/// Handle a single authenticated connection.
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
            let _ = send_json(
                &mut stream,
                &AgentResponse::Error {
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
    let req: AgentRequest = recv_json(stream).await?;

    match req {
        AgentRequest::Handshake { version, vm_name } => {
            if version != PROTOCOL_VERSION {
                let msg = format!(
                    "unsupported protocol version {} (expected {})",
                    version, PROTOCOL_VERSION
                );
                warn!(peer_cid, vm_name = %vm_name, "{}", msg);
                send_json(stream, &AgentResponse::Error { message: msg }).await?;
                return Ok(());
            }

            info!(peer_cid, vm_name = %vm_name, "Received agent handshake");

            let vm_entry = match config.vms.get(&vm_name) {
                Some(entry) => entry,
                None => {
                    let msg = format!("VM '{}' not registered in host config", vm_name);
                    warn!(peer_cid, vm_name = %vm_name, "{}", msg);
                    send_json(stream, &AgentResponse::Error { message: msg }).await?;
                    return Ok(());
                }
            };

            if vm_entry.vm_cid != peer_cid {
                let msg = format!(
                    "CID verification failed: expected {}, got peer CID {}",
                    vm_entry.vm_cid, peer_cid
                );
                error!(peer_cid, vm_name = %vm_name, "{}", msg);
                send_json(stream, &AgentResponse::Error { message: msg }).await?;
                return Ok(());
            }

            let mut workloads = HashMap::new();
            for (name, policy) in &vm_entry.identities {
                let validity_seconds = policy.ttl_minutes * 60;
                let selector = match policy.parse_selector() {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = format!("failed to parse selector for workload '{}': {}", name, e);
                        error!(peer_cid, vm_name = %vm_name, "{}", msg);
                        send_json(stream, &AgentResponse::Error { message: msg }).await?;
                        return Ok(());
                    }
                };

                workloads.insert(
                    name.clone(),
                    WorkloadConfig {
                        selector,
                        validity_seconds,
                    },
                );
            }

            send_json(stream, &AgentResponse::HandshakeOk { workloads }).await?;
            info!(peer_cid, vm_name = %vm_name, "Handshake successful, sent workload selectors");
            Ok(())
        }
        AgentRequest::CertRequest {
            version,
            vm_name,
            identity,
            csr_pem,
        } => {
            if version != PROTOCOL_VERSION {
                let msg = format!(
                    "unsupported protocol version {} (expected {})",
                    version, PROTOCOL_VERSION
                );
                warn!(peer_cid, identity = %identity, "{}", msg);
                send_json(stream, &AgentResponse::Error { message: msg }).await?;
                return Ok(());
            }

            info!(
                peer_cid,
                identity = %identity,
                "Received certificate request"
            );

            // Policy lookup.
            let decision = match resolve(config, &vm_name, &identity) {
                Some(d) => d,
                None => {
                    let msg = format!(
                        "VM '{}' / identity '{}' not authorised",
                        vm_name, identity
                    );
                    warn!(peer_cid, vm_name = %vm_name, identity = %identity, "{}", msg);
                    send_json(stream, &AgentResponse::Error { message: msg }).await?;
                    return Ok(());
                }
            };

            // Verify CID
            if decision.vm_cid != peer_cid {
                let msg = format!(
                    "CID verification failed for VM '{}': expected {}, got peer CID {}",
                    vm_name, decision.vm_cid, peer_cid
                );
                error!(peer_cid, vm_name = %vm_name, expected_cid = decision.vm_cid, "{}", msg);
                return Err(anyhow::anyhow!("CID verification failed"));
            }

            // Sign CSR.
            let cert_pem = sign_csr(
                ca,
                SigningRequest {
                    csr_pem: &csr_pem,
                    identity: identity.clone(),
                    vm_name: decision.vm_name,
                    cid: peer_cid,
                    ip: decision.ip,
                    validity_seconds: decision.validity_seconds,
                },
            )
            .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;

            info!(
                peer_cid,
                identity = %identity,
                "Certificate issued successfully"
            );

            send_json(
                stream,
                &AgentResponse::CertOk {
                    cert_pem,
                    ca_cert_pem: ca.cert_pem.clone(),
                },
            )
            .await?;

            Ok(())
        }
    }
}
