//! TCP client transport implementation.

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::net::TcpStream;

use crate::config::AgentConfig;
use crate::transport::TransportStream;

/// Connect to the CA server over TCP.
pub async fn connect_tcp(config: &AgentConfig) -> Result<TransportStream> {
    let addr = config
        .server_addr
        .clone()
        .unwrap_or_else(|| format!("127.0.0.1:{}", config.server_port));

    let mut attempts = 0;
    loop {
        match TcpStream::connect(&addr).await {
            Ok(stream) => return Ok(TransportStream::Tcp(stream)),
            Err(e) => {
                if attempts < 15 {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                return Err(e).context(format!("connecting to server over TCP at {}", addr));
            }
        }
    }
}
