//! ECDSA P-256 keypair and PKCS#10 CSR generation for a single entity.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

use anyhow::Result;

/// A freshly-generated keypair plus the PEM CSR ready to send to the CA.
pub struct GeneratedCsr {
    /// PEM-encoded PKCS#8 private key (store securely).
    pub key_pem: String,
    /// PEM-encoded PKCS#10 CSR.
    pub csr_pem: String,
}

/// Generate an ECDSA P-256 keypair and build a PKCS#10 CSR for `entity_name`.
pub fn generate_csr(entity_name: &str) -> Result<GeneratedCsr> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, entity_name);
    dn.push(DnType::OrganizationName, "authn-scope");
    params.distinguished_name = dn;

    let csr = params.serialize_request(&key)?;
    let csr_pem = csr.pem()?;
    let key_pem = key.serialize_pem();

    Ok(GeneratedCsr { key_pem, csr_pem })
}
