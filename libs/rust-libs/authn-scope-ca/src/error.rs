//! Strongly-typed error type for the CA engine.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("CA key file not found at {path}: {source}")]
    KeyNotFound {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("CA cert file not found at {path}: {source}")]
    CertNotFound {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse CA key PEM: {0}")]
    KeyParseFailed(String),

    #[error("failed to parse CA cert PEM: {0}")]
    CertParseFailed(String),

    #[error("certificate generation error: {0}")]
    RcgenError(#[from] rcgen::Error),

    #[error("ring crypto error: {0}")]
    RingError(String),

    #[error("JWT build error: {0}")]
    JwtError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialisation error: {0}")]
    SerdeError(#[from] serde_json::Error),
}

impl From<ring::error::Unspecified> for CaError {
    fn from(e: ring::error::Unspecified) -> Self {
        CaError::RingError(e.to_string())
    }
}

impl From<ring::error::KeyRejected> for CaError {
    fn from(e: ring::error::KeyRejected) -> Self {
        CaError::RingError(e.to_string())
    }
}
