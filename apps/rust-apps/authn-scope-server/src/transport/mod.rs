//! Transport layer module for authn-scope-server.
//!
//! Provides isolated connection listeners for vsock and TCP transports.

pub mod tcp;
pub mod vsock;

/// Peer information extracted from the underlying transport connection.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// vsock Context ID (present when using vsock transport).
    pub peer_cid: Option<u32>,
    /// Remote IP address (present when using TCP transport).
    pub peer_ip: Option<String>,
}

impl PeerInfo {
    pub fn from_vsock(cid: u32) -> Self {
        Self {
            peer_cid: Some(cid),
            peer_ip: None,
        }
    }

    pub fn from_tcp(ip: String) -> Self {
        Self {
            peer_cid: None,
            peer_ip: Some(ip),
        }
    }
}
