//! Guest agent configuration.
//!
//! Loaded from a JSON file (default: `/etc/authn-scope/agent.json`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Name of the VM (sent in CertRequest to identify the caller).
    pub vm_name: String,
    /// vsock port the server listens on (should be < 1000).
    #[serde(default = "default_server_port")]
    pub server_port: u32,
    /// List of entities (services/processes) to request certificates for.
    pub entities: Vec<EntityEntry>,
    /// The client port to bind to when dialing.
    #[serde(default = "default_client_port")]
    pub client_port: u32,
}

fn default_server_port() -> u32 {
    900
}

fn default_client_port() -> u32 {
    901
}

/// Configuration for a single entity that needs a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityEntry {
    /// Entity name — must match the name registered in the host config.
    pub name: String,
    /// Destination path for the signed certificate PEM.
    pub cert_path: PathBuf,
    /// Destination path for the private key PEM.
    pub key_path: PathBuf,
    /// Destination path for the CA certificate PEM.
    pub ca_path: PathBuf,
    /// Unix UID for the written files (requires agent runs as root).
    pub owner_uid: u32,
    /// Unix GID for the written files.
    pub owner_gid: u32,
    /// Unix permission mode for the certificate file (e.g. "0640").
    #[serde(default = "default_cert_mode")]
    pub cert_mode: String,
    /// Unix permission mode for the private key file (e.g. "0600").
    #[serde(default = "default_key_mode")]
    pub key_mode: String,
}

fn default_cert_mode() -> String {
    "0640".into()
}
fn default_key_mode() -> String {
    "0600".into()
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
