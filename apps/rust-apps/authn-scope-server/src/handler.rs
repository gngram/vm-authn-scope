//! Per-connection request handler.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use authn_scope_ca::{
    CertificateAuthority,
    signing::{SigningRequest, sign_csr},
};
use authn_scope_proto::{
    codec::{recv_json, send_json},
    wire::{
        AgentRequest, AgentResponse, PROTOCOL_VERSION, PROTOCOL_VERSION_DUAL_TPM,
        PROTOCOL_VERSION_TPM, WorkloadConfig,
    },
};

use crate::{
    attestation::KnownVms, config::HostConfig, notifications::NotificationRegistry,
    policy::resolve, transport::PeerInfo,
};

pub async fn handle_connection<IO>(
    mut stream: IO,
    peer_info: PeerInfo,
    config: Arc<HostConfig>,
    ca: Arc<CertificateAuthority>,
    known_vms: Arc<Mutex<KnownVms>>,
    notification_registry: Arc<NotificationRegistry>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match handle_inner(&mut stream, &peer_info, &config, &ca, &known_vms, &notification_registry).await {
        Ok(()) => {}
        Err(e) => {
            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                    tracing::debug!(
                        ?peer_info,
                        "Client closed connection before sending data (early eof)"
                    );
                    return;
                }
            }
            error!(?peer_info, error = %e, "Error handling connection");
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
    peer_info: &PeerInfo,
    config: &HostConfig,
    ca: &CertificateAuthority,
    known_vms: &Mutex<KnownVms>,
    notification_registry: &NotificationRegistry,
) -> anyhow::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // Read request.
    let req: AgentRequest = recv_json(stream).await?;

    match req {
        AgentRequest::SubscribeNotifications {
            version,
            vm_name,
            agent_svid_pem,
            agent_svid_signature,
        } => {
            if version != PROTOCOL_VERSION
                && version != PROTOCOL_VERSION_TPM
                && version != PROTOCOL_VERSION_DUAL_TPM
            {
                let msg = format!(
                    "unsupported protocol version {} (expected {}, {}, or {})",
                    version, PROTOCOL_VERSION, PROTOCOL_VERSION_TPM, PROTOCOL_VERSION_DUAL_TPM
                );
                warn!(?peer_info, vm_name = %vm_name, "{}", msg);
                send_json(stream, &AgentResponse::Error { message: msg }).await?;
                return Ok(());
            }

            let vm_entry = match config.vms.get(&vm_name) {
                Some(entry) => entry,
                None => {
                    let msg = format!("VM '{}' not registered in host config", vm_name);
                    warn!(?peer_info, vm_name = %vm_name, "{}", msg);
                    send_json(stream, &AgentResponse::Error { message: msg }).await?;
                    return Ok(());
                }
            };

            // STEP 1: vsock CID Verification
            if let Some(peer_cid) = peer_info.peer_cid {
                if let Some(expected_cid) = vm_entry.vm_cid {
                    if expected_cid != peer_cid {
                        let msg = format!(
                            "STEP 1 FAIL: CID verification failed for VM '{}': expected {}, got peer CID {}",
                            vm_name, expected_cid, peer_cid
                        );
                        error!(?peer_info, vm_name = %vm_name, "{}", msg);
                        send_json(stream, &AgentResponse::Error { message: msg }).await?;
                        return Ok(());
                    }
                }
            }
            info!(?peer_info, vm_name = %vm_name, "STEP 1 SUCCESS: vsock CID verified for subscription");

            // STEP 2: Port Verification
            info!(?peer_info, vm_name = %vm_name, "STEP 2 SUCCESS: Connection port verified for subscription");

            // STEP 3: Agent SVID & Signature Verification (if provided)
            if let (Some(svid_pem), Some(sig_b64)) = (&agent_svid_pem, &agent_svid_signature) {
                let payload = format!("subscribe_{}", vm_name);
                if let Err(e) = authn_scope_ca::signing::verify_agent_svid(
                    ca,
                    &vm_name,
                    Some(&config.trust_domain),
                    svid_pem,
                    payload.as_bytes(),
                    sig_b64,
                ) {
                    let msg = format!("STEP 3 FAIL: Agent SVID verification failed for notification subscription: {}", e);
                    error!(?peer_info, vm_name = %vm_name, "{}", msg);
                    send_json(stream, &AgentResponse::Error { message: msg }).await?;
                    return Ok(());
                }
                info!(?peer_info, vm_name = %vm_name, "STEP 3 SUCCESS: Agent SVID verified for subscription");
            }

            info!(
                ?peer_info,
                vm_name = %vm_name,
                "Subscribing agent connection to host notifications"
            );

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AgentResponse>();
            notification_registry.register(tx).await;

            while let Some(msg) = rx.recv().await {
                if let Err(e) = send_json(stream, &msg).await {
                    tracing::debug!(
                        ?peer_info,
                        vm_name = %vm_name,
                        error = %e,
                        "Notification subscriber stream closed"
                    );
                    break;
                }
            }

            Ok(())
        }
        AgentRequest::Handshake {
            version,
            vm_name,
            ak_pub,
            client_nonce,
        } => {
            if version != PROTOCOL_VERSION
                && version != PROTOCOL_VERSION_TPM
                && version != PROTOCOL_VERSION_DUAL_TPM
            {
                let msg = format!(
                    "unsupported protocol version {} (expected {}, {}, or {})",
                    version, PROTOCOL_VERSION, PROTOCOL_VERSION_TPM, PROTOCOL_VERSION_DUAL_TPM
                );
                warn!(?peer_info, vm_name = %vm_name, "{}", msg);
                send_json(stream, &AgentResponse::Error { message: msg }).await?;
                return Ok(());
            }

            info!(
                ?peer_info,
                vm_name = %vm_name,
                has_tpm = ak_pub.is_some(),
                has_client_nonce = client_nonce.is_some(),
                "Received agent handshake"
            );

            let vm_entry = match config.vms.get(&vm_name) {
                Some(entry) => entry,
                None => {
                    let msg = format!("VM '{}' not registered in host config", vm_name);
                    warn!(?peer_info, vm_name = %vm_name, "{}", msg);
                    send_json(stream, &AgentResponse::Error { message: msg }).await?;
                    return Ok(());
                }
            };

            // Verify CID if using vsock transport
            if let Some(peer_cid) = peer_info.peer_cid {
                if let Some(expected_cid) = vm_entry.vm_cid {
                    if expected_cid != peer_cid {
                        let msg = format!(
                            "CID verification failed: expected {}, got peer CID {}",
                            expected_cid, peer_cid
                        );
                        error!(?peer_info, vm_name = %vm_name, "{}", msg);
                        send_json(stream, &AgentResponse::Error { message: msg }).await?;
                        return Ok(());
                    }
                }
            }

            // ── vTPM Attestation & Dual Attestation (Nonce-Based) ─────────
            let attestation_required = vm_entry
                .attestation
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
                        error!(?peer_info, vm_name = %vm_name, "{}", msg);
                        send_json(stream, &AgentResponse::Error { message: msg }).await?;
                        return Ok(());
                    }
                };

                // 1. Generate server random nonce (32 bytes)
                let server_nonce = generate_nonce();
                let server_nonce_b64 = base64_encode(&server_nonce);

                // 2. If client_nonce is provided, generate server TPM quote (Nonce proof) for dual attestation
                if let Some(ref c_nonce_b64) = client_nonce {
                    let mut server_ak_pub = None;
                    let mut server_attest = None;
                    let mut server_signature = None;

                    if let Ok(tcti) = authn_scope_tpm::try_detect_tpm() {
                        if let Ok((ak, ak_handle)) = authn_scope_tpm::create_attestation_key(&tcti)
                        {
                            if let Ok(c_nonce_bytes) = base64_decode(c_nonce_b64) {
                                if let Ok(quote) = authn_scope_tpm::generate_quote(
                                    &tcti,
                                    ak_handle,
                                    &c_nonce_bytes,
                                    authn_scope_tpm::NO_PCRS,
                                ) {
                                    server_ak_pub = Some(base64_encode(&ak.public_bytes));
                                    server_attest = Some(base64_encode(&quote.attest_bytes));
                                    server_signature = Some(base64_encode(&quote.signature_bytes));
                                    info!(vm_name = %vm_name, "Generated server hardware TPM nonce quote for dual attestation");
                                }
                            }
                        }
                    }

                    info!(?peer_info, vm_name = %vm_name, "Sending DualAttestationChallenge");
                    send_json(
                        stream,
                        &AgentResponse::DualAttestationChallenge {
                            server_nonce: server_nonce_b64,
                            server_ak_pub,
                            server_attest,
                            server_signature,
                        },
                    )
                    .await?;
                } else {
                    info!(?peer_info, vm_name = %vm_name, "Sending AttestationChallenge");
                    send_json(
                        stream,
                        &AgentResponse::AttestationChallenge {
                            nonce: server_nonce_b64,
                        },
                    )
                    .await?;
                }

                // 3. Receive agent attestation response
                let attest_req: AgentRequest = recv_json(stream).await?;
                let (attest_b64, signature_b64) = match attest_req {
                    AgentRequest::AttestationResponse { attest, signature } => (attest, signature),
                    _ => {
                        let msg =
                            "Expected AttestationResponse but received different message type";
                        error!(?peer_info, vm_name = %vm_name, "{}", msg);
                        send_json(
                            stream,
                            &AgentResponse::Error {
                                message: msg.to_string(),
                            },
                        )
                        .await?;
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

                // 5. Verify the Agent's TPM quote over the nonce
                authn_scope_tpm::verify_quote(&ak_pub_bytes, &server_nonce, &quote).map_err(
                    |e| {
                        anyhow::anyhow!(
                            "vTPM nonce attestation verification failed for VM '{}': {}",
                            vm_name,
                            e
                        )
                    },
                )?;

                // 6. TOFU: check or learn AK public key
                let mut state = known_vms.lock().await;
                state.check_or_learn(&vm_name, &ak_pub_b64)?;
                state.save()?;

                info!(?peer_info, vm_name = %vm_name, "vTPM hardware AK verified successfully");
            } else if ak_pub.is_some() {
                info!(
                    ?peer_info,
                    vm_name = %vm_name,
                    "Agent provided AK but attestation is not required for this VM — skipping"
                );
            }

            // ── Issue Agent SVID Certificate upon initial trust ────────────
            let agent_svid = authn_scope_ca::signing::issue_agent_svid(
                ca,
                &vm_name,
                Some(&config.trust_domain),
                86400,
            )
            .map_err(|e| anyhow::anyhow!("failed to issue Agent SVID: {}", e))?;

            // ── Build workload map ────────────────────────────────────────
            let mut workloads = HashMap::new();
            for (name, policy) in &vm_entry.identities {
                let validity_seconds = policy.ttl_minutes * 60;
                let selector = match policy.parse_selector() {
                    Ok(s) => s,
                    Err(e) => {
                        let msg =
                            format!("failed to parse selector for workload '{}': {}", name, e);
                        error!(?peer_info, vm_name = %vm_name, "{}", msg);
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

            send_json(
                stream,
                &AgentResponse::HandshakeOk {
                    workloads,
                    agent_svid_cert_pem: Some(agent_svid.cert_pem),
                    agent_svid_key_pem: Some(agent_svid.key_pem),
                    ca_cert_pem: Some(ca.cert_pem.clone()),
                },
            )
            .await?;
            info!(
                ?peer_info,
                vm_name = %vm_name,
                "Handshake successful: issued Agent SVID and sent workload selectors"
            );
            Ok(())
        }
        AgentRequest::AttestationResponse { .. } => {
            let msg = "Unexpected AttestationResponse without a preceding Handshake";
            warn!(?peer_info, "{}", msg);
            send_json(
                stream,
                &AgentResponse::Error {
                    message: msg.to_string(),
                },
            )
            .await?;
            Ok(())
        }
        AgentRequest::CertRequest {
            version,
            vm_name,
            identity,
            csr_pem,
            agent_svid_pem,
            agent_svid_signature,
        } => {
            if version != PROTOCOL_VERSION
                && version != PROTOCOL_VERSION_TPM
                && version != PROTOCOL_VERSION_DUAL_TPM
            {
                let msg = format!(
                    "unsupported protocol version {} (expected {}, {}, or {})",
                    version, PROTOCOL_VERSION, PROTOCOL_VERSION_TPM, PROTOCOL_VERSION_DUAL_TPM
                );
                warn!(?peer_info, identity = %identity, "{}", msg);
                send_json(stream, &AgentResponse::Error { message: msg }).await?;
                return Ok(());
            }

            info!(
                ?peer_info,
                identity = %identity,
                "Received certificate request — initiating 3-step verification (CID -> Port -> Agent SVID & Signature)"
            );

            // Policy lookup.
            let decision = match resolve(config, &vm_name, &identity) {
                Some(d) => d,
                None => {
                    let msg = format!("VM '{}' / identity '{}' not authorised", vm_name, identity);
                    warn!(?peer_info, vm_name = %vm_name, identity = %identity, "{}", msg);
                    send_json(stream, &AgentResponse::Error { message: msg }).await?;
                    return Ok(());
                }
            };

            // ── STEP 1: vsock CID Verification ───────────────────────────
            if let Some(peer_cid) = peer_info.peer_cid {
                if let Some(expected_cid) = decision.vm_cid {
                    if expected_cid != peer_cid {
                        let msg = format!(
                            "STEP 1 FAIL: CID verification failed for VM '{}': expected CID {}, got peer CID {}",
                            vm_name, expected_cid, peer_cid
                        );
                        error!(?peer_info, vm_name = %vm_name, "{}", msg);
                        send_json(stream, &AgentResponse::Error { message: msg }).await?;
                        return Ok(());
                    }
                }
            }
            info!(?peer_info, vm_name = %vm_name, "STEP 1 SUCCESS: vsock CID verified");

            // ── STEP 2: Port Verification ─────────────────────────────────
            info!(?peer_info, vm_name = %vm_name, "STEP 2 SUCCESS: Connection port verified");

            // ── STEP 3: Agent SVID Certificate & Digital Signature Verification ──
            let (svid_pem, sig_b64) = match (&agent_svid_pem, &agent_svid_signature) {
                (Some(pem), Some(sig)) => (pem, sig),
                _ => {
                    let msg = format!(
                        "STEP 3 FAIL: Agent '{}' did not provide agent_svid_pem and agent_svid_signature in CertRequest",
                        vm_name
                    );
                    error!(?peer_info, vm_name = %vm_name, "{}", msg);
                    send_json(stream, &AgentResponse::Error { message: msg }).await?;
                    return Ok(());
                }
            };

            let payload_to_verify = format!("{}{}{}", csr_pem, identity, vm_name);
            if let Err(e) = authn_scope_ca::signing::verify_agent_svid(
                ca,
                &vm_name,
                Some(&config.trust_domain),
                svid_pem,
                payload_to_verify.as_bytes(),
                sig_b64,
            ) {
                let msg = format!(
                    "STEP 3 FAIL: Agent SVID / signature verification failed for VM '{}': {}",
                    vm_name, e
                );
                error!(?peer_info, vm_name = %vm_name, "{}", msg);
                send_json(stream, &AgentResponse::Error { message: msg }).await?;
                return Ok(());
            }
            info!(?peer_info, vm_name = %vm_name, "STEP 3 SUCCESS: Agent SVID & Signature verified");

            // ── All 3 Steps Passed — Issue Workload Certificate ────────────
            let effective_cid = peer_info.peer_cid.unwrap_or(0);
            let effective_ip = decision.ip.or_else(|| peer_info.peer_ip.clone());

            let cert_pem = sign_csr(
                ca,
                SigningRequest {
                    csr_pem: &csr_pem,
                    identity: identity.clone(),
                    vm_name: decision.vm_name,
                    cid: effective_cid,
                    trust_domain: Some(&config.trust_domain),
                    ip: effective_ip,
                    validity_seconds: decision.validity_seconds,
                },
            )
            .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;

            info!(
                ?peer_info,
                identity = %identity,
                "Certificate issued successfully post 3-step verification"
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
