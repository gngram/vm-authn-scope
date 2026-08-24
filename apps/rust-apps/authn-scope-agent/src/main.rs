//! authn-scope-agent — guest VM certificate agent.
//!
//! # Usage
//!
//! ```
//! sudo authn-scope-agent --config /etc/authn-scope/agent.json
//! ```
//!
//! The agent connects to the host CA over vsock, requests certificates for
//! every entity listed in the config, and writes the credentials to disk
//! with the configured POSIX ownership and permissions.

use std::{path::PathBuf, process};

use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

mod client;
mod config;
mod csr;
mod store;

use config::AgentConfig;

/// authn-scope guest agent — requests X.509 certificates from the host CA.
#[derive(Debug, Parser)]
#[command(
    name = "authn-scope-agent",
    about = "Guest agent: requests entity certificates from the authn-scope host CA",
    version
)]
struct Cli {
    /// Path to the agent JSON configuration file.
    #[arg(
        short,
        long,
        default_value = "/etc/authn-scope/agent.json",
        value_name = "FILE"
    )]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Require root for file ownership operations.
    #[cfg(unix)]
    if unsafe { libc_getuid() } != 0 {
        error!("authn-scope-agent must run as root to set file ownership");
        process::exit(1);
    }

    let cli = Cli::parse();

    let cfg = match AgentConfig::from_file(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!(config = %cli.config.display(), error = %e, "Failed to load config");
            process::exit(1);
        }
    };

    info!("Starting authn-scope-agent");

    if let Err(e) = client::run_agent(&cfg).await {
        error!(error = %e, "Agent encountered a fatal error");
        process::exit(1);
    }

    info!("authn-scope-agent completed successfully");
}

// ─── minimal libc shim ────────────────────────────────────────────────────────

#[cfg(unix)]
extern "C" {
    fn getuid() -> u32;
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    getuid()
}
