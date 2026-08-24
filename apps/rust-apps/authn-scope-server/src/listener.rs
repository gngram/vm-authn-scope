//! vsock listener — accepts connections and spawns TLS-wrapped handlers.

use std::sync::Arc;

use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use tracing::{error, info};

use authn_scope_ca::CertificateAuthority;

use crate::{config::HostConfig, handler::handle_connection};

/// Start the vsock+TLS listener loop.
///
/// Runs until the process is terminated.
pub async fn run_listener(
    config: Arc<HostConfig>,
    ca: Arc<CertificateAuthority>,
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
                    continue; // Terminate connection by dropping the stream
                }

                let config = Arc::clone(&config);
                let ca = Arc::clone(&ca);

                tokio::spawn(async move {
                    handle_connection(stream, peer_cid, config, ca).await;
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept vsock connection");
            }
        }
    }
}
