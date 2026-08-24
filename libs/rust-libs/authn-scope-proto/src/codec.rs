//! Length-prefixed framing for JSON messages over an async byte stream.
//!
//! Frame format: [4-byte big-endian length][payload bytes]

use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum allowed message size (4 MiB). Guards against malformed frames.
const MAX_MSG_BYTES: usize = 4 * 1024 * 1024;

/// Serialize `value` to JSON and send it as a length-prefixed frame.
pub async fn send_json<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let payload = serde_json::to_vec(value)?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame and deserialize it as JSON.
pub async fn recv_json<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MSG_BYTES {
        bail!(
            "incoming frame too large: {} bytes (max {})",
            len,
            MAX_MSG_BYTES
        );
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let value = serde_json::from_slice(&buf)?;
    Ok(value)
}
