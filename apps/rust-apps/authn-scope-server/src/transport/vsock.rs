//! vsock listener implementation for authn-scope-server.

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};
use tracing::{error, info};

use authn_scope_ca::CertificateAuthority;

use crate::{
    attestation::KnownVms, config::HostConfig, handler::handle_connection, transport::PeerInfo,
};

/// Start the vsock listener loop.
pub async fn run_vsock_listener(
    config: Arc<HostConfig>,
    ca: Arc<CertificateAuthority>,
    known_vms: Arc<Mutex<KnownVms>>,
) -> anyhow::Result<()> {
    let port = config.server_port;

    let addr = VsockAddr::new(VMADDR_CID_ANY, port);
    let mut listener = VsockListener::bind(addr)?;

    info!(port, "authn-scope-server listening on vsock");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let peer_cid = peer_addr.cid();
                let peer_port = peer_addr.port();
                info!(peer_cid, peer_port, "Accepted vsock connection");

                // Verify the peer port of the client
                if peer_port != config.peer_port {
                    error!(
                        peer_port,
                        expected = config.peer_port,
                        "Rejected connection: peer port mismatch"
                    );
                    continue; // Drop stream
                }

                let config = Arc::clone(&config);
                let ca = Arc::clone(&ca);
                let known_vms = Arc::clone(&known_vms);
                let peer_info = PeerInfo::from_vsock(peer_cid);

                tokio::spawn(async move {
                    handle_connection(stream, peer_info, config, ca, known_vms).await;
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept vsock connection");
            }
        }
    }
}
