//! Transport layer module for authn-scope-agent.
//!
//! Provides isolated connection handlers for vsock and TCP transports.

pub mod tcp;
pub mod vsock;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_vsock::VsockStream;

/// Unified async stream representing an established connection over vsock or TCP.
pub enum TransportStream {
    Vsock(VsockStream),
    Tcp(TcpStream),
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportStream::Vsock(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TransportStream::Vsock(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportStream::Vsock(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportStream::Vsock(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Connect to the CA server using the configured transport (vsock or TCP).
pub async fn connect_to_server(
    config: &crate::config::AgentConfig,
) -> anyhow::Result<TransportStream> {
    connect_to_server_port(config, config.client_port).await
}

/// Connect to the CA server using a specific local client port.
pub async fn connect_to_server_port(
    config: &crate::config::AgentConfig,
    client_port: u32,
) -> anyhow::Result<TransportStream> {
    match config.transport.as_str() {
        "tcp" => tcp::connect_tcp(config).await,
        _ => vsock::connect_vsock_port(config, client_port).await,
    }
}
