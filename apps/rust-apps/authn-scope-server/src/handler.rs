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
    wire::{AgentRequest, AgentResponse, PROTOCOL_VERSION, PROTOCOL_VERSION_TPM, WorkloadConfig},
};

use crate::{config::HostConfig, policy::resolve, attestation::KnownVms};

use tokio::sync::Mutex;

/// Handle a single authenticated connection.
pub async fn handle_connection<IO>(
    mut stream: IO,
    peer_cid: u32,
    config: Arc<HostConfig>,
    ca: Arc<CertificateAuthority>,
    known_vms: Arc<Mutex<KnownVms>>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match handle_inner(&mut stream, peer_cid, &config, &ca, &known_vms).await {
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
    known_vms: &Mutex<KnownVms>,
) -> anyhow::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // Read request.
    let req: AgentRequest = recv_json(stream).await?;

    match req {
        AgentRequest::Handshake { version, vm_name, ak_pub } => {
            if version != PROTOCOL_VERSION && version != PROTOCOL_VERSION_TPM {
                let msg = format!(
                    "unsupported protocol version {} (expected {} or {})",
                    version, PROTOCOL_VERSION, PROTOCOL_VERSION_TPM
                );
                warn!(peer_cid, vm_name = %vm_name, "{}", msg);
                send_json(stream, &AgentResponse::Error { message: msg }).await?;
                return Ok(());
            }

            info!(peer_cid, vm_name = %vm_name, has_tpm = ak_pub.is_some(), "Received agent handshake");

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

            // ── vTPM Attestation ──────────────────────────────────────────
            let attestation_required = vm_entry.attestation
                .as_ref()
                .map(|a| a.required)
                .unwrap_or(false);

            if attestation_required {
                let ak_pub_b64 = match &ak_pub {
                    Some(ak) => ak.clone(),
                    None => {
                        let msg = format!(
                            "VM '{}' requires vTPM attestation but agent did not provide an AK public key",
                            vm_name
                        );
                        error!(peer_cid, vm_name = %vm_name, "{}", msg);
                        send_json(stream, &AgentResponse::Error { message: msg }).await?;
                        return Ok(());
                    }
                };

                // 1. Generate random nonce (32 bytes)
                let nonce = generate_nonce();
                let nonce_b64 = base64_encode(&nonce);

                // 2. Send attestation challenge
                info!(peer_cid, vm_name = %vm_name, "Sending attestation challenge");
                send_json(stream, &AgentResponse::AttestationChallenge {
                    nonce: nonce_b64,
                }).await?;

                // 3. Receive attestation response
                let attest_req: AgentRequest = recv_json(stream).await?;
                let (attest_b64, signature_b64) = match attest_req {
                    AgentRequest::AttestationResponse { attest, signature } => {
                        (attest, signature)
                    }
                    _ => {
                        let msg = "Expected AttestationResponse but received different message type";
                        error!(peer_cid, vm_name = %vm_name, "{}", msg);
                        send_json(stream, &AgentResponse::Error { message: msg.to_string() }).await?;
                        return Ok(());
                    }
                };

                // 4. Decode base64
                let ak_pub_bytes = base64_decode(&ak_pub_b64)?;
                let attest_bytes = base64_decode(&attest_b64)?;
                let signature_bytes = base64_decode(&signature_b64)?;

                let quote = authn_scope_tpm::TpmQuote {
                    attest_bytes,
                    signature_bytes,
                };

                // 5. Verify the TPM quote
                let pcr_digest = authn_scope_tpm::verify_quote(
                    &ak_pub_bytes,
                    &nonce,
                    &quote,
                ).map_err(|e| {
                    anyhow::anyhow!("vTPM attestation verification failed for VM '{}': {}", vm_name, e)
                })?;

                let pcr_digest_hex = hex_encode(&pcr_digest);

                // 6. TOFU: check or learn PCR values
                let mut state = known_vms.lock().await;
                state.check_or_learn(&vm_name, &pcr_digest_hex, &ak_pub_b64)?;
                state.save()?;

                info!(peer_cid, vm_name = %vm_name, "vTPM attestation verified successfully");
            } else if ak_pub.is_some() {
                info!(
                    peer_cid, vm_name = %vm_name,
                    "Agent provided AK but attestation is not required for this VM — skipping"
                );
            }

            // ── Build workload map ────────────────────────────────────────
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
        AgentRequest::AttestationResponse { .. } => {
            let msg = "Unexpected AttestationResponse without a preceding Handshake";
            warn!(peer_cid, "{}", msg);
            send_json(stream, &AgentResponse::Error { message: msg.to_string() }).await?;
            Ok(())
        }
        AgentRequest::CertRequest {
            version,
            vm_name,
            identity,
            csr_pem,
        } => {
            if version != PROTOCOL_VERSION && version != PROTOCOL_VERSION_TPM {
                let msg = format!(
                    "unsupported protocol version {} (expected {} or {})",
                    version, PROTOCOL_VERSION, PROTOCOL_VERSION_TPM
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

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Generate a cryptographically secure random nonce (32 bytes).
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

fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("base64 decode error: {}", e))
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
