//! Host CA server configuration.
//!
//! Loaded from a JSON file (default: `/etc/authn-scope/host.json`).

use std::{collections::HashMap, path::PathBuf};

use serde::{Deserialize, Serialize};

use authn_scope_proto::wire::SelectorConfig;

/// Top-level host configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Path to the CA certificate PEM file.
    pub ca_cert_path: PathBuf,
    /// Path to the CA private key PEM file.
    pub ca_key_path: PathBuf,
    /// vsock port on which to listen (should be privileged / < 1000).
    #[serde(default = "default_server_port")]
    pub server_port: u32,
    /// Map of VM name → VM entry.
    pub vms: HashMap<String, VmEntry>,
    /// Expected peer port of the client agent.
    #[serde(default = "default_peer_port")]
    pub peer_port: u32,
}

fn default_server_port() -> u32 {
    900
}

fn default_peer_port() -> u32 {
    901
}

/// Per-VM configuration entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmEntry {
    /// vsock CID of the VM.
    pub vm_cid: u32,
    /// IP address of the VM (embedded in issued certificates).
    pub ip: Option<String>,
    /// Map of Workload name → Identity policy.
    pub identities: HashMap<String, IdentityPolicy>,
    /// Optional vTPM attestation policy for this VM.
    #[serde(default)]
    pub attestation: Option<AttestationPolicy>,
}

/// vTPM attestation policy for a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicy {
    /// If true, the VM must present a valid TPM quote during handshake.
    /// If false (or if the attestation block is absent), CID-only trust is used.
    #[serde(default)]
    pub required: bool,
}

/// Policy for a single Workload running inside a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPolicy {
    /// Comma-separated selector string (e.g. "unix:uid:1000,systemd:unitname:service-a").
    pub selector: String,
    /// TTL in minutes for the issued certificate.
    pub ttl_minutes: u32,
}

impl IdentityPolicy {
    /// Parse the selector string into SelectorConfig wire representation.
    pub fn parse_selector(&self) -> anyhow::Result<SelectorConfig> {
        let mut unix = authn_scope_proto::wire::UnixSelector::default();
        let mut systemd = authn_scope_proto::wire::SystemdSelector::default();
        let mut has_unix = false;
        let mut has_systemd = false;

        for part in self.selector.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let subparts: Vec<&str> = part.splitn(3, ':').collect();
            if subparts.len() < 3 {
                anyhow::bail!("Invalid selector component: '{}'", part);
            }

            let domain = subparts[0];
            let key = subparts[1];
            let value = subparts[2];

            match (domain, key) {
                ("unix", "user") => {
                    unix.user = Some(value.to_string());
                    has_unix = true;
                }
                ("unix", "group") => {
                    unix.group = Some(value.to_string());
                    has_unix = true;
                }
                ("unix", "bin") => {
                    unix.bin_path = Some(value.to_string());
                    has_unix = true;
                }
                ("systemd", "unitname") => {
                    systemd.unitname = Some(value.to_string());
                    has_systemd = true;
                }
                ("systemd", "unitpath") => {
                    systemd.unitpath = Some(value.to_string());
                    has_systemd = true;
                }
                _ => {
                    anyhow::bail!("Unknown selector component: '{}'", part);
                }
            }
        }

        if unix.bin_path.is_some() && (unix.user.is_none() || unix.group.is_none()) {
            anyhow::bail!("if bin-path is specified then it must be attached to a user:group (both unix:user and unix:group must be present)");
        }

        Ok(SelectorConfig {
            unix: if has_unix { Some(unix) } else { None },
            systemd: if has_systemd { Some(systemd) } else { None },
        })
    }
}

impl HostConfig {
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

        // Validate all workload selectors
        for (vm_name, vm) in &cfg.vms {
            for (workload_name, policy) in &vm.identities {
                policy.parse_selector().map_err(|e| {
                    anyhow::anyhow!("VM '{}' workload '{}' selector error: {}", vm_name, workload_name, e)
                })?;
            }
        }

        Ok(cfg)
    }
}
