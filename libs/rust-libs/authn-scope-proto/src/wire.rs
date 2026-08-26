//! Wire-protocol request/response types exchanged over the vsock+TLS channel.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protocol version constant.
pub const PROTOCOL_VERSION: u32 = 1;

/// Request sent by the agent to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    Handshake {
        version: u32,
        vm_name: String,
    },
    CertRequest {
        version: u32,
        vm_name: String,
        identity: String, // mapped workload name
        csr_pem: String,
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
    HandshakeOk {
        workloads: HashMap<String, WorkloadConfig>,
    },
    CertOk {
        cert_pem: String,
        ca_cert_pem: String,
    },
    Error {
        message: String,
    },
}
