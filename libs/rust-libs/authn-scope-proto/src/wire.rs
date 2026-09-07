//! Wire-protocol request/response types exchanged over the vsock channel.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protocol version constant (v1: no attestation).
pub const PROTOCOL_VERSION: u32 = 1;

/// Protocol version with vTPM attestation support.
pub const PROTOCOL_VERSION_TPM: u32 = 2;

/// Protocol version with Dual Hardware Attestation support.
pub const PROTOCOL_VERSION_DUAL_TPM: u32 = 3;

/// Request sent by the agent to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    Handshake {
        version: u32,
        vm_name: String,
        /// Base64-encoded AK public key (TPMT_PUBLIC).
        /// Present when the guest has a vTPM; absent otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ak_pub: Option<String>,
        /// Base64-encoded client challenge nonce for server hardware attestation (32 bytes).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_nonce: Option<String>,
    },
    SubscribeNotifications {
        version: u32,
        vm_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_svid_pem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_svid_signature: Option<String>,
    },
    /// Attestation response sent after receiving an AttestationChallenge.
    AttestationResponse {
        /// Base64-encoded TPMS_ATTEST bytes (contains nonce + PCR digest).
        attest: String,
        /// Base64-encoded TPMT_SIGNATURE bytes over the attest data.
        signature: String,
    },
    CertRequest {
        version: u32,
        vm_name: String,
        identity: String, // mapped workload name
        csr_pem: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_svid_pem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_svid_signature: Option<String>,
    },
}

/// Workload configuration containing its selector and capabilities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadConfig {
    pub selector: SelectorConfig,
    pub validity_seconds: u32,
}

/// Selector configuration containing unix and/or systemd identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SelectorConfig {
    #[serde(default)]
    pub unix: Option<UnixSelector>,
    #[serde(default)]
    pub systemd: Option<SystemdSelector>,
}

/// Unix peer identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UnixSelector {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(rename = "bin-path", default)]
    pub bin_path: Option<String>,
}

/// Systemd process identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SystemdSelector {
    #[serde(default)]
    pub unitpath: Option<String>,
    #[serde(default)]
    pub unitname: Option<String>,
}

/// Response sent by the host to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum AgentResponse {
    /// Attestation challenge: server sends a random nonce for TPM2_Quote.
    #[serde(rename = "attestation_challenge")]
    AttestationChallenge {
        /// Base64-encoded random nonce (32 bytes).
        nonce: String,
    },
    /// Dual attestation challenge: server sends its own hardware quote and challenges the agent.
    #[serde(rename = "dual_attestation_challenge")]
    DualAttestationChallenge {
        /// Base64-encoded server random nonce for agent TPM2_Quote (32 bytes).
        server_nonce: String,
        /// Base64-encoded Server AK public key.
        server_ak_pub: Option<String>,
        /// Base64-encoded Server TPMS_ATTEST bytes (over client_nonce + server PCRs).
        server_attest: Option<String>,
        /// Base64-encoded Server TPMT_SIGNATURE bytes.
        server_signature: Option<String>,
    },
    #[serde(rename = "time_sync_notification")]
    TimeSyncNotification {
        timestamp: u64,
    },
    HandshakeOk {
        workloads: HashMap<String, WorkloadConfig>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_svid_cert_pem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_svid_key_pem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca_cert_pem: Option<String>,
    },
    CertOk {
        cert_pem: String,
        ca_cert_pem: String,
    },
    Error {
        message: String,
    },
}
