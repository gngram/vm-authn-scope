//! Evaluator for authn-scope peer capability certificates.

use authn_scope_ca::jwt::{verify_cap_jwt, CAP_EXTENSION_OID};
use authn_scope_proto::caps::CapClaim;
use thiserror::Error;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("X.509 parse error: {0}")]
    X509Parse(String),

    #[error("Capability extension (OID 1.3.6.1.4.1.99999.1) not found in peer certificate")]
    MissingCapabilityExtension,

    #[error("JWT verification failed: {0}")]
    JwtVerification(#[from] authn_scope_ca::error::CaError),
}

/// Evaluator validates peer certificates against the CA and evaluates their capabilities.
pub struct Evaluator {
    pub claim: CapClaim,
}

impl Evaluator {
    /// Create a new Evaluator by verifying a peer certificate's capability JWT
    /// against the CA's public key.
    pub fn from_cert_pem(peer_cert_pem: &str, ca_cert_pem: &str) -> Result<Self, EvalError> {
        // Parse CA cert to extract SPKI
        let (_, ca_pem) = parse_x509_pem(ca_cert_pem.as_bytes())
            .map_err(|e| EvalError::X509Parse(format!("CA PEM parse failed: {:?}", e)))?;
        let (_, ca_cert) = parse_x509_certificate(&ca_pem.contents)
            .map_err(|e| EvalError::X509Parse(format!("CA cert parse failed: {:?}", e)))?;
        let spki = ca_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .as_ref();

        // Parse peer cert to extract the capability JWT from custom extension
        let (_, peer_pem) = parse_x509_pem(peer_cert_pem.as_bytes())
            .map_err(|e| EvalError::X509Parse(format!("Peer PEM parse failed: {:?}", e)))?;
        let (_, peer_cert) = parse_x509_certificate(&peer_pem.contents)
            .map_err(|e| EvalError::X509Parse(format!("Peer cert parse failed: {:?}", e)))?;

        let mut jwt_bytes = None;
        for ext in peer_cert.tbs_certificate.extensions() {
            // Check for our custom capability OID: 1.3.6.1.4.1.99999.1
            let ext_oid: Vec<u64> = ext.oid.iter().unwrap().collect();
            if ext_oid == CAP_EXTENSION_OID {
                jwt_bytes = Some(ext.value);
                break;
            }
        }

        let jwt_bytes = jwt_bytes.ok_or(EvalError::MissingCapabilityExtension)?;

        // The extension value is an ASN.1 OCTET STRING wrapping the payload.
        // We do a minimal unwrap of the DER tag (0x04) and length.
        if jwt_bytes.is_empty() || jwt_bytes[0] != 0x04 {
            return Err(EvalError::X509Parse(
                "Extension value is not an OCTET STRING".into(),
            ));
        }
        let mut offset = 1;
        let len_byte = jwt_bytes[offset];
        offset += 1;

        let mut len = 0;
        if len_byte & 0x80 == 0 {
            len = len_byte as usize;
        } else {
            let num_bytes = (len_byte & 0x7F) as usize;
            for i in 0..num_bytes {
                len = (len << 8) | (jwt_bytes[offset + i] as usize);
            }
            offset += num_bytes;
        }

        let inner_bytes = &jwt_bytes[offset..offset + len];

        let jwt_str = std::str::from_utf8(inner_bytes)
            .map_err(|_| EvalError::X509Parse("JWT extension is not valid UTF-8".into()))?;

        // Verify the JWT signature using the CA's public key
        let claim = verify_cap_jwt(jwt_str, spki)?;

        Ok(Self { claim })
    }

    /// Check if the peer is authorized to invoke a specific RPC module or module.method
    /// on the specified target VM.
    pub fn can_call_rpc(&self, my_vm_name: &str, module: &str, method: &str) -> bool {
        let full_method = format!("{}.{}", module, method);

        for cap in &self.claim.caps {
            if cap.target_vm == my_vm_name {
                // If they have full access to the module, allow it
                if cap.rpc_modules.iter().any(|m| m == module) {
                    return true;
                }
                // If they have access to the specific method, allow it
                if cap.rpc_methods.iter().any(|m| m == &full_method) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if the peer is authorized to access a specific path with the requested mode
    /// on the specified target VM.
    pub fn can_access_path(&self, my_vm_name: &str, path: &str, access_mode: &str) -> bool {
        for cap in &self.claim.caps {
            if cap.target_vm == my_vm_name {
                for p in &cap.paths {
                    // Exact match for path
                    if p.path == path {
                        if p.access.iter().any(|a| a == access_mode) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authn_scope_ca::{
        ca::CertificateAuthority,
        signing::{sign_csr, SigningRequest},
    };
    use authn_scope_proto::caps::{Capability, PathAccess};
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_evaluator_grants() {
        let dir = tempdir().unwrap();
        let ca_cert_path = dir.path().join("ca-cert.pem");
        let ca_key_path = dir.path().join("ca-key.pem");

        // 1. Generate CA
        let ca = CertificateAuthority::init(&ca_cert_path, &ca_key_path, false).unwrap();

        // 2. Mock Agent CSR
        let agent_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let csr_pem = params.serialize_request(&agent_key).unwrap().pem().unwrap();

        // 3. Define capability granted to peer
        let caps = vec![Capability {
            target_vm: "my-vm".into(),
            rpc_modules: vec!["auth".into()],
            rpc_methods: vec!["data.read_secure".into()],
            paths: vec![PathAccess {
                path: "/api/v1/health".into(),
                access: vec!["read".into()],
            }],
        }];

        // 4. Server issues cert
        let peer_cert_pem = sign_csr(
            &ca,
            SigningRequest {
                csr_pem: &csr_pem,
                identity: "peer-service".into(),
                vm_name: "peer-vm".into(),
                cid: 10,
                claims: caps,
                validity_days: 10,
            },
        )
        .unwrap();

        // 5. Evaluator logic
        let eval = Evaluator::from_cert_pem(&peer_cert_pem, &ca.cert_pem).unwrap();

        assert_eq!(eval.claim.sub, "peer-service");

        // Allowed RPCs
        assert!(eval.can_call_rpc("my-vm", "auth", "login")); // Entire module allowed
        assert!(eval.can_call_rpc("my-vm", "data", "read_secure")); // Specific method allowed

        // Denied RPCs
        assert!(!eval.can_call_rpc("my-vm", "data", "write"));
        assert!(!eval.can_call_rpc("other-vm", "auth", "login"));

        // Allowed paths
        assert!(eval.can_access_path("my-vm", "/api/v1/health", "read"));

        // Denied paths
        assert!(!eval.can_access_path("my-vm", "/api/v1/health", "write"));
        assert!(!eval.can_access_path("my-vm", "/api/v1/admin", "read"));
    }
}
