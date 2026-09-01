//! authn-scope-workload — client library for requesting credentials over the Workload API.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};

/// Ephemeral in-memory X.509 credentials returned by the Workload API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509Credentials {
    /// PEM-encoded workload certificate.
    pub cert_pem: String,
    /// PEM-encoded workload private key.
    pub key_pem: String,
    /// PEM-encoded trust CA root certificate.
    pub ca_cert_pem: String,
}

/// JSON request frame sent to the agent's Workload API.
#[derive(Debug, Serialize, Deserialize)]
struct WorkloadRequest {
    #[serde(rename = "type")]
    pub req_type: String,
}

/// JSON response frame returned by the agent's Workload API.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum WorkloadResponse {
    Success {
        cert_pem: String,
        key_pem: String,
        ca_cert_pem: String,
    },
    Error {
        message: String,
    },
}

/// Client to fetch and dynamically rotate credentials via the guest agent's Unix Domain Socket.
#[derive(Clone)]
pub struct WorkloadClient {
    socket_path: String,
    cached: Arc<RwLock<Option<X509Credentials>>>,
}

impl WorkloadClient {
    /// Create a new WorkloadClient targeting the given UDS socket path.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            cached: Arc::new(RwLock::new(None)),
        }
    }

    /// Perform a one-shot fetch of X.509 credentials over the Unix Domain Socket.
    pub async fn fetch_credentials(&self) -> Result<X509Credentials> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "Failed to connect to Workload API socket at {}",
                    self.socket_path
                )
            })?;

        let req = WorkloadRequest {
            req_type: "fetch".to_string(),
        };
        let req_json = serde_json::to_string(&req)? + "\n";
        stream.write_all(req_json.as_bytes()).await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.is_empty() {
            bail!("Workload API closed connection without sending a response");
        }

        let resp: WorkloadResponse =
            serde_json::from_str(&line).context("Parsing WorkloadResponse")?;

        match resp {
            WorkloadResponse::Success {
                cert_pem,
                key_pem,
                ca_cert_pem,
            } => Ok(X509Credentials {
                cert_pem,
                key_pem,
                ca_cert_pem,
            }),
            WorkloadResponse::Error { message } => {
                bail!("Workload API returned error: {}", message);
            }
        }
    }

    /// Retrieve the currently cached credentials from memory.
    pub async fn current_credentials(&self) -> Option<X509Credentials> {
        self.cached.read().await.clone()
    }

    /// Start a background task that periodically fetches credentials to keep them updated in memory.
    pub fn start_rotation_loop(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let client = self.clone();
        tokio::spawn(async move {
            loop {
                match client.fetch_credentials().await {
                    Ok(creds) => {
                        *client.cached.write().await = Some(creds);
                    }
                    Err(e) => {
                        eprintln!("Workload API client failed to rotate credentials: {:?}", e);
                    }
                }
                sleep(interval).await;
            }
        })
    }
}
