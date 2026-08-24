//! Wire-protocol request/response types exchanged over the vsock+TLS channel.

use serde::{Deserialize, Serialize};

/// Protocol version constant.
pub const PROTOCOL_VERSION: u32 = 1;

/// Sent by the guest agent to the host CA to request a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRequest {
    /// Must equal [`PROTOCOL_VERSION`].
    pub version: u32,
    /// Name of the VM requesting the certificate.
    pub vm_name: String,
    /// Name of the entity (service/process) requesting the certificate.
    pub entity: String,
    /// PEM-encoded PKCS#10 Certificate Signing Request.
    pub csr_pem: String,
}

/// Response sent by the host CA to the guest agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CertResponse {
    /// Certificate issued successfully.
    Ok {
        /// PEM-encoded signed end-entity certificate.
        cert_pem: String,
        /// PEM-encoded CA certificate (for trust-chain distribution).
        ca_cert_pem: String,
    },
    /// The request was rejected.
    Error {
        /// Human-readable rejection reason.
        message: String,
    },
}
