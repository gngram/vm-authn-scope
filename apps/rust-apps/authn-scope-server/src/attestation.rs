//! TOFU (Trust-On-First-Use) attestation state management.
//!
//! Stores and verifies learned PCR values from guest VMs.
//! The state file (`known_vms.json`) can optionally be sealed
//! by the host's own TPM.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

fn get_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AUTHN_SCOPE_STATE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    PathBuf::from("/var/lib/authn-scope")
}

/// Path where TOFU state is stored.
pub fn get_state_path() -> PathBuf {
    get_state_dir().join("known_vms.json")
}

/// Path where the sealed known_vms hash is stored.
pub fn get_seal_path() -> PathBuf {
    get_state_dir().join("known_vms_seal.json")
}

/// TOFU state: maps VM names to their known attestation data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnownVms {
    /// Map of VM name → known PCR digest (hex-encoded SHA-256).
    pub vms: HashMap<String, KnownVmEntry>,
}

/// Stored attestation data for a single VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownVmEntry {
    /// The PCR digest from the TPM quote (hex-encoded).
    pub pcr_digest: String,
    /// The AK public key bytes (base64-encoded) used to verify the quote.
    pub ak_pub: String,
    /// Timestamp of when this entry was first learned (ISO 8601).
    pub learned_at: String,
}

impl KnownVms {
    /// Load the TOFU state from the default path.
    pub fn load() -> Result<Self> {
        Self::load_from(&get_state_path())
    }

    /// Load the TOFU state from a specific path and verify its Host TPM seal if present.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading TOFU state from {}", path.display()))?;

        // If host TPM and seal file exist, verify the seal of known_vms.json
        let seal_path = get_seal_path();
        if seal_path.exists() {
            match authn_scope_tpm::try_detect_tpm() {
                Ok(tcti) => {
                    let seal_data = std::fs::read_to_string(&seal_path)
                        .context("reading known_vms seal file")?;
                    let blob: authn_scope_tpm::SealedBlob = serde_json::from_str(&seal_data)
                        .context("parsing known_vms seal file")?;
                    match authn_scope_tpm::unseal_data(&tcti, &blob) {
                        Ok(unsealed) => {
                            let stored_hash_hex = String::from_utf8(unsealed)
                                .context("sealed data is not valid UTF-8")?;
                            let current_hash = sha256(data.as_bytes());
                            let current_hash_hex = hex_encode(&current_hash);
                            if stored_hash_hex != current_hash_hex {
                                bail!(
                                    "KNOWN_VMS INTEGRITY VIOLATION: known_vms.json has been tampered with!\n\
                                     Expected hash: {}\n\
                                     Current hash:  {}\n\
                                     The file was modified outside Host TPM authority.",
                                    stored_hash_hex,
                                    current_hash_hex
                                );
                            }
                            info!("known_vms.json integrity verified via Host TPM seal");
                        }
                        Err(e) => {
                            warn!("Failed to unseal known_vms hash from host TPM: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("No host TPM detected ({}), skipping known_vms seal verification", e);
                }
            }
        }

        let state: Self = serde_json::from_str(&data)
            .with_context(|| format!("parsing TOFU state from {}", path.display()))?;
        Ok(state)
    }

    /// Save the TOFU state to the default path and seal its hash with the Host TPM.
    pub fn save(&self) -> Result<()> {
        self.save_to(&get_state_path())
    }

    /// Save the TOFU state to a specific path and seal its hash with the Host TPM.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
        let data = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, &data)
            .with_context(|| format!("writing TOFU state to {}", path.display()))?;

        // Restrict permissions to root only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        // Seal known_vms.json hash into Host TPM if available
        let seal_path = get_seal_path();
        match authn_scope_tpm::try_detect_tpm() {
            Ok(tcti) => {
                let hash = sha256(data.as_bytes());
                let hash_hex = hex_encode(&hash);
                seal_known_vms_hash(&tcti, &hash_hex, &seal_path)?;
            }
            Err(e) => {
                warn!("No host TPM detected ({}), known_vms sealing disabled", e);
            }
        }

        Ok(())
    }

    /// Check or learn PCR values for a VM (TOFU logic).
    ///
    /// - If no entry exists for `vm_name`, learns the PCR digest (trust-on-first-use)
    /// - If an entry exists, verifies the PCR digest matches
    ///
    /// Returns `Ok(true)` if newly learned, `Ok(false)` if matched existing.
    pub fn check_or_learn(
        &mut self,
        vm_name: &str,
        pcr_digest_hex: &str,
        ak_pub_b64: &str,
    ) -> Result<bool> {
        if let Some(known) = self.vms.get(vm_name) {
            // Existing entry — verify PCR digest matches
            if known.pcr_digest != pcr_digest_hex {
                bail!(
                    "PCR attestation failed for VM '{}': stored digest '{}' != received '{}'.\n\
                     This may indicate the VM image has been tampered with or updated.\n\
                     To accept the new image, run: authn-scope-server --reset-attestation {}",
                    vm_name,
                    known.pcr_digest,
                    pcr_digest_hex,
                    vm_name
                );
            }
            info!(vm_name, "PCR attestation verified (matches stored values)");
            Ok(false)
        } else {
            // First-use — learn and store
            let now = time_now_iso8601();
            self.vms.insert(
                vm_name.to_string(),
                KnownVmEntry {
                    pcr_digest: pcr_digest_hex.to_string(),
                    ak_pub: ak_pub_b64.to_string(),
                    learned_at: now,
                },
            );
            info!(
                vm_name,
                "TOFU: learned PCR attestation for VM (first boot)"
            );
            Ok(true)
        }
    }

    /// Remove the stored attestation for a VM (for `--reset-attestation`).
    pub fn reset(&mut self, vm_name: &str) -> bool {
        self.vms.remove(vm_name).is_some()
    }
}

/// Seal the known_vms hash into the host TPM.
pub fn seal_known_vms_hash(tcti: &str, hash_hex: &str, seal_path: &Path) -> Result<()> {
    let blob = authn_scope_tpm::seal_data(tcti, hash_hex.as_bytes())
        .context("sealing known_vms hash")?;

    if let Some(parent) = seal_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let data = serde_json::to_string_pretty(&blob)?;
    std::fs::write(seal_path, &data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(seal_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("known_vms.json hash sealed into host TPM at {}", seal_path.display());
    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn time_now_iso8601() -> String {
    // Simple UTC timestamp without external dependencies
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s-since-epoch", duration.as_secs())
}
