//! Evaluator for authn-scope peer certificates.

use thiserror::Error;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("X.509 parse error: {0}")]
    X509Parse(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),
}

/// Evaluator validates peer certificates against the trusted CA.
pub struct Evaluator {
    pub identity: String,
}

impl Evaluator {
    /// Create a new Evaluator by verifying a peer certificate's signature
    /// against the CA's public key and extracting its subject CN.
    pub fn from_cert_pem(peer_cert_pem: &str, ca_cert_pem: &str) -> Result<Self, EvalError> {
        // 1. Parse CA cert
        let (_, ca_pem) = parse_x509_pem(ca_cert_pem.as_bytes())
            .map_err(|e| EvalError::X509Parse(format!("CA PEM parse failed: {:?}", e)))?;
        let (_, ca_cert) = parse_x509_certificate(&ca_pem.contents)
            .map_err(|e| EvalError::X509Parse(format!("CA cert parse failed: {:?}", e)))?;
        let ca_pubkey = ca_cert.public_key();

        // 2. Parse peer cert
        let (_, peer_pem) = parse_x509_pem(peer_cert_pem.as_bytes())
            .map_err(|e| EvalError::X509Parse(format!("Peer PEM parse failed: {:?}", e)))?;
        let (_, peer_cert) = parse_x509_certificate(&peer_pem.contents)
            .map_err(|e| EvalError::X509Parse(format!("Peer cert parse failed: {:?}", e)))?;

        // 3. Verify peer certificate signature using CA public key
        peer_cert.verify_signature(Some(ca_pubkey)).map_err(|e| {
            EvalError::SignatureVerification(format!("Signature verification failed: {:?}", e))
        })?;

        // 4. Extract subject Common Name (CN)
        let subject = peer_cert.subject();
        let identity = subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| EvalError::X509Parse("Subject Common Name (CN) is missing".into()))?;

        Ok(Self { identity })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authn_scope_ca::{
        ca::CertificateAuthority,
        signing::{SigningRequest, sign_csr},
    };
    use rcgen::{CertificateParams, KeyPair};
    use tempfile::tempdir;

    #[test]
    fn test_evaluator_verification() {
        let dir = tempdir().unwrap();
        let ca_cert_path = dir.path().join("ca-cert.pem");
        let ca_key_path = dir.path().join("ca-key.pem");

        // 1. Generate CA
        let ca = CertificateAuthority::init(&ca_cert_path, &ca_key_path, false).unwrap();

        // 2. Mock Agent CSR
        let agent_key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["peer-service".to_string()]).unwrap();
        let csr_pem = params.serialize_request(&agent_key).unwrap().pem().unwrap();

        // 3. Server issues cert
        let peer_cert_pem = sign_csr(
            &ca,
            SigningRequest {
                csr_pem: &csr_pem,
                identity: "peer-service".into(),
                vm_name: "peer-vm".into(),
                cid: 10,
                ip: Some("127.0.0.1".into()),
                validity_seconds: 3600,
            },
        )
        .unwrap();

        // 4. Evaluator logic
        let eval = Evaluator::from_cert_pem(&peer_cert_pem, &ca.cert_pem).unwrap();

        assert_eq!(eval.identity, "peer-service");
    }
}
