//! Guest agent configuration.
//!
//! Loaded from a JSON file (default: `/etc/authn-scope/agent.json`).

use serde::{Deserialize, Serialize};

/// Top-level agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Name of the VM (sent in Handshake/CertRequest to identify the caller).
    pub vm_name: String,
    /// vsock port the server listens on (should be < 1000).
    #[serde(default = "default_server_port")]
    pub server_port: u32,
    /// The client port to bind to when dialing.
    #[serde(default = "default_client_port")]
    pub client_port: u32,
    /// Optional path to the Unix Domain Socket for the Workload API.
    pub workload_api_socket: Option<String>,
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

        if cfg.server_port >= 1000 {
            anyhow::bail!(
                "server_port must be less than 1000, got {}",
                cfg.server_port
            );
        }

        Ok(cfg)
    }
}
