//! vsock client transport implementation.

use anyhow::{Context, Result};
use libc::{connect, sockaddr, sockaddr_vm, socklen_t};
use std::os::unix::io::FromRawFd;
use std::time::Duration;
use tokio_vsock::VsockStream;

use crate::config::AgentConfig;
use crate::transport::TransportStream;

/// Connect to the host CA server over vsock while binding the local port.
pub async fn connect_vsock(config: &AgentConfig) -> Result<TransportStream> {
    let host_cid = std::env::var("VSOCK_HOST_CID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(2); // VMADDR_CID_HOST

    let mut attempts = 0;
    loop {
        let socket =
            unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if socket < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // Bind to the local port (e.g. 901)
        let local_addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: config.client_port,
            svm_cid: libc::VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };

        let optval: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        if unsafe {
            libc::bind(
                socket,
                &local_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        } >= 0
        {
            // Bind succeeded, connect to host server
            let sockaddr = sockaddr_vm {
                svm_family: libc::AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: config.server_port,
                svm_cid: host_cid,
                svm_zero: [0; 4],
            };

            if unsafe {
                connect(
                    socket,
                    &sockaddr as *const _ as *const sockaddr,
                    std::mem::size_of::<sockaddr_vm>() as socklen_t,
                )
            } >= 0
            {
                let stream = unsafe { vsock::VsockStream::from_raw_fd(socket) };
                let stream = VsockStream::new(stream)?;
                return Ok(TransportStream::Vsock(stream));
            }

            let conn_err = std::io::Error::last_os_error();
            unsafe { libc::close(socket) };
            if attempts < 15 {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            return Err(anyhow::anyhow!("vsock connect failed: {}", conn_err));
        }

        let err = std::io::Error::last_os_error();
        unsafe { libc::close(socket) };

        if err.kind() == std::io::ErrorKind::AddrInUse && attempts < 15 {
            attempts += 1;
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        return Err(err).context(format!(
            "binding vsock client socket to local port {}",
            config.client_port
        ));
    }
}
