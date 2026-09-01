//! Guest agent configuration.
//!
//! Loaded from a JSON file (default: `/etc/authn-scope/agent.json`).

use serde::{Deserialize, Serialize};

/// Top-level agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Name of the VM (sent in Handshake/CertRequest to identify the caller).
    pub vm_name: String,
    /// Transport type: "vsock" (default) or "tcp".
    #[serde(default = "default_transport")]
    pub transport: String,
    /// vsock port the server listens on (should be < 1000).
    #[serde(default = "default_server_port")]
    pub server_port: u32,
    /// The client port to bind to when dialing vsock.
    #[serde(default = "default_client_port")]
    pub client_port: u32,
    /// Server address (e.g. "127.0.0.1:9000" or "server-host:9000") when using TCP transport.
    #[serde(default)]
    pub server_addr: Option<String>,
    /// Whether server hardware attestation verification is required.
    #[serde(default)]
    pub server_attestation_required: Option<bool>,
    /// Optional path to the Unix Domain Socket for the Workload API.
    pub workload_api_socket: Option<String>,
}

fn default_transport() -> String {
    "vsock".to_string()
}

fn default_server_port() -> u32 {
    900
}

fn default_client_port() -> u32 {
    901
}

impl AgentConfig {
    /// Load and parse the config from a JSON file.
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let cfg: Self = serde_json::from_str(&data)?;

        if cfg.transport == "vsock" && cfg.server_port >= 1000 {
            anyhow::bail!(
                "server_port must be less than 1000 for vsock, got {}",
                cfg.server_port
            );
        }

        Ok(cfg)
    }
}
