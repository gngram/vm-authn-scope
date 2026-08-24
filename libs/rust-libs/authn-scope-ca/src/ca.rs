//! [`CertificateAuthority`] — manages the root CA key and certificate.
//!
//! On first run (`init`) the CA generates a self-signed ECDSA P-256
//! root certificate and saves both key and cert as PEM files.
//! On subsequent starts it loads them from disk.

use std::{fs, path::Path};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use tracing::{debug, info};

use crate::error::CaError;

/// Holds the root CA's PEM-encoded key and certificate, and the raw
/// DER bytes needed for direct ring/rustls operations.
pub struct CertificateAuthority {
    /// PEM-encoded CA private key (PKCS#8 ECDSA P-256).
    pub key_pem: String,
    /// PEM-encoded self-signed CA certificate.
    pub cert_pem: String,
    /// DER-encoded CA certificate bytes.
    pub cert_der: Vec<u8>,
    /// DER-encoded CA private key bytes (PKCS#8).
    pub key_der: Vec<u8>,
}

impl CertificateAuthority {
    /// Load an existing CA from PEM files on disk.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self, CaError> {
        debug!("Loading CA cert from {}", cert_path.display());
        let cert_pem = fs::read_to_string(cert_path).map_err(|e| CaError::CertNotFound {
            path: cert_path.display().to_string(),
            source: e,
        })?;

        debug!("Loading CA key from {}", key_path.display());
        let key_pem = fs::read_to_string(key_path).map_err(|e| CaError::KeyNotFound {
            path: key_path.display().to_string(),
            source: e,
        })?;

        let key_pair =
            KeyPair::from_pem(&key_pem).map_err(|e| CaError::KeyParseFailed(e.to_string()))?;
        let key_der = key_pair.serialize_der();

        // Parse the cert DER from PEM.
        let cert_der = pem_to_der(&cert_pem)
            .ok_or_else(|| CaError::CertParseFailed("no CERTIFICATE block found".into()))?;

        Ok(Self {
            key_pem,
            cert_pem,
            cert_der,
            key_der,
        })
    }

    /// Generate a new CA and write PEM files to disk.
    ///
    /// If `idempotent` is `true` and the files already exist, this is a no-op.
    pub fn init(cert_path: &Path, key_path: &Path, idempotent: bool) -> Result<Self, CaError> {
        if idempotent && cert_path.exists() && key_path.exists() {
            info!("CA files already exist — skipping init (idempotent)");
            return Self::load(cert_path, key_path);
        }

        if !idempotent {
            if cert_path.exists() {
                let _ = fs::remove_file(cert_path);
            }
            if key_path.exists() {
                let _ = fs::remove_file(key_path);
            }
        }

        info!("Generating new ECDSA P-256 CA key and self-signed certificate");

        // Generate key pair.
        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(CaError::RcgenError)?;

        // Build certificate parameters.
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "authn-scope-ca");
        dn.push(DnType::OrganizationName, "authn-scope");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        // 10-year validity.
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 1, 1);

        let cert = params.self_signed(&key_pair)?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // Write files — create parent directories first.
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(cert_path, &cert_pem)?;
        // Key file: restrict to root-only.
        fs::write(key_path, &key_pem)?;
        set_mode_600(key_path)?;

        info!("CA certificate written to {}", cert_path.display());
        info!("CA private key   written to {}", key_path.display());

        Ok(Self {
            key_pem,
            cert_pem,
            cert_der,
            key_der,
        })
    }

    /// Re-create the rcgen [`KeyPair`] from the stored PEM (needed by signing).
    pub fn key_pair(&self) -> Result<KeyPair, CaError> {
        KeyPair::from_pem(&self.key_pem).map_err(|e| CaError::KeyParseFailed(e.to_string()))
    }

    /// Re-create the rcgen [`rcgen::Certificate`] from PEM (needed as
    /// the signing issuer in [`rcgen::CertificateSigningRequestParams::signed_by`]).
    ///
    /// This re-signs the CA cert with the loaded key, producing an object
    /// with identical DN and key — sufficient for use as a signing issuer.
    pub fn rcgen_cert(&self) -> Result<rcgen::Certificate, CaError> {
        let key_pair = self.key_pair()?;
        let params = CertificateParams::from_ca_cert_pem(&self.cert_pem)
            .map_err(|e| CaError::CertParseFailed(e.to_string()))?;
        let cert = params.self_signed(&key_pair)?;
        Ok(cert)
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Parse the first CERTIFICATE PEM block and return the raw DER bytes.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    use rustls_pemfile::certs;
    use std::io::BufReader;

    // Collect into a Vec first so the BufReader borrow is dropped.
    let mut reader = BufReader::new(pem.as_bytes());
    let all: Vec<_> = certs(&mut reader).collect();
    all.into_iter()
        .next()
        .and_then(|r| r.ok())
        .map(|c| c.to_vec())
}

/// Set Unix file permissions to 0600 (owner read/write only).
#[cfg(unix)]
fn set_mode_600(path: &Path) -> Result<(), CaError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode_600(_path: &Path) -> Result<(), CaError> {
    Ok(())
}
