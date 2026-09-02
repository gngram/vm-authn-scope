//! TCP listener implementation for authn-scope-server.

use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info};

use authn_scope_ca::CertificateAuthority;

use crate::{
    attestation::KnownVms, config::HostConfig, handler::handle_connection,
    notifications::NotificationRegistry, transport::PeerInfo,
};

/// Start the TCP listener loop.
pub async fn run_tcp_listener(
    config: Arc<HostConfig>,
    ca: Arc<CertificateAuthority>,
    known_vms: Arc<Mutex<KnownVms>>,
    notification_registry: Arc<NotificationRegistry>,
) -> anyhow::Result<()> {
    let addr_str = config
        .listen_addr
        .clone()
        .unwrap_or_else(|| format!("0.0.0.0:{}", config.server_port));

    let listener = TcpListener::bind(&addr_str).await?;
    info!(addr = %addr_str, "authn-scope-server listening on TCP");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let peer_ip = peer_addr.ip().to_string();
                info!(peer = %peer_addr, "Accepted TCP connection");

                let config = Arc::clone(&config);
                let ca = Arc::clone(&ca);
                let known_vms = Arc::clone(&known_vms);
                let notification_registry = Arc::clone(&notification_registry);
                let peer_info = PeerInfo::from_tcp(peer_ip);

                tokio::spawn(async move {
                    handle_connection(stream, peer_info, config, ca, known_vms, notification_registry).await;
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept TCP connection");
            }
        }
    }
}
