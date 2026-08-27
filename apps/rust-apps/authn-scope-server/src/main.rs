//! authn-scope-server — host CA daemon.
//!
//! # Usage
//!
//! ```
//! # Initialise a new CA (idempotent):
//! sudo authn-scope-server --init --config /etc/authn-scope/host.json
//!
//! # Start the certificate-issuing daemon:
//! sudo authn-scope-server --config /etc/authn-scope/host.json
//! ```

use std::{path::PathBuf, process, sync::Arc};

use clap::Parser;
use tokio::sync::Mutex;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use authn_scope_ca::CertificateAuthority;

mod attestation;
mod config;
mod handler;
mod listener;
mod policy;

use attestation::KnownVms;
use config::HostConfig;

/// authn-scope host CA server.
#[derive(Debug, Parser)]
#[command(
    name = "authn-scope-server",
    about = "Vsock certificate authority for multi-VM environments",
    version
)]
struct Cli {
    /// Path to the host JSON configuration file.
    #[arg(
        short,
        long,
        default_value = "/etc/authn-scope/host.json",
        value_name = "FILE"
    )]
    config: PathBuf,

    /// Generate the CA key and certificate (overwriting existing ones if they exist) before starting the server.
    #[arg(long)]
    genkey: bool,

    /// Reset stored attestation state for the specified VM (allowing TOFU re-learning).
    #[arg(long, value_name = "VM_NAME")]
    reset_attestation: Option<String>,
}

#[tokio::main]
async fn main() {
    // Initialise structured logging. Level can be overridden via RUST_LOG.
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Require root.
    #[cfg(unix)]
    if unsafe { libc_getuid() } != 0 {
        error!("authn-scope-server must run as root (vsock bind requires privilege)");
        process::exit(1);
    }

    let cli = Cli::parse();

    // Handle --reset-attestation
    if let Some(ref vm_name) = cli.reset_attestation {
        let mut known = match KnownVms::load() {
            Ok(k) => k,
            Err(e) => {
                error!(error = %e, "Failed to load attestation state");
                process::exit(1);
            }
        };
        if known.reset(vm_name) {
            if let Err(e) = known.save() {
                error!(error = %e, "Failed to save attestation state");
                process::exit(1);
            }
            info!(vm_name = %vm_name, "Attestation state reset successfully. Next connection will re-learn PCRs.");
        } else {
            info!(vm_name = %vm_name, "No attestation state found for VM.");
        }
        return;
    }

    // Load config.
    let cfg = match HostConfig::from_file(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!(config = %cli.config.display(), error = %e, "Failed to load config");
            process::exit(1);
        }
    };

    // Load attestation state (TOFU)
    let known_vms = match KnownVms::load() {
        Ok(k) => Arc::new(Mutex::new(k)),
        Err(e) => {
            error!(error = %e, "Failed to load attestation state");
            process::exit(1);
        }
    };

    // Initialise or load the CA.
    let ca = if cli.genkey {
        match CertificateAuthority::init(&cfg.ca_cert_path, &cfg.ca_key_path, false) {
            Ok(ca) => {
                info!("CA initialised/regenerated successfully");
                ca
            }
            Err(e) => {
                error!(error = %e, "CA initialisation/regeneration failed");
                process::exit(1);
            }
        }
    } else {
        match CertificateAuthority::load(&cfg.ca_cert_path, &cfg.ca_key_path) {
            Ok(ca) => ca,
            Err(e) => {
                error!(error = %e, "Failed to load CA — CA files must exist or run with --genkey");
                process::exit(1);
            }
        }
    };

    let cfg = Arc::new(cfg);
    let ca = Arc::new(ca);

    if let Err(e) = listener::run_listener(cfg, ca, known_vms).await {
        error!(error = %e, "Listener terminated with error");
        process::exit(1);
    }
}

// ─── minimal libc shim for getuid() ──────────────────────────────────────────
// Avoids a full libc dependency by using an extern "C" declaration.

#[cfg(unix)]
extern "C" {
    fn getuid() -> u32;
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    getuid()
}
