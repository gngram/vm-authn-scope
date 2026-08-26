//! CSR signing: validates and issues leaf certificate.

use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, Ia5String,
    KeyUsagePurpose, SanType,
};
use tracing::info;

use crate::{
    ca::CertificateAuthority,
    error::CaError,
};

/// Parameters for signing a single CSR.
pub struct SigningRequest<'a> {
    /// PEM-encoded PKCS#10 CSR from the agent.
    pub csr_pem: &'a str,
    /// The Identity name (must match the CSR subject CN).
    pub identity: String,
    /// The VM name of the requesting guest.
    pub vm_name: String,
    /// vsock CID of the requesting guest.
    pub cid: u32,
    /// Optional IP address to embed in the certificate's subjectAltName.
    pub ip: Option<String>,
    /// Certificate validity in seconds.
    pub validity_seconds: u32,
}

/// Sign a CSR and return the PEM-encoded leaf certificate.
pub fn sign_csr(ca: &CertificateAuthority, req: SigningRequest<'_>) -> Result<String, CaError> {
    info!(
        identity = %req.identity,
        vm = %req.vm_name,
        cid = req.cid,
        "Signing CSR"
    );

    // Parse the incoming CSR.
    let mut csr_params = CertificateSigningRequestParams::from_pem(req.csr_pem)
        .map_err(|e| CaError::RcgenError(e))?;

    // Set leaf-cert key usages to digitalSignature only.
    csr_params.params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
    ];

    // Set extended key usages to serverAuth, clientAuth.
    csr_params.params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // Set subjectAltName to DNS:<identity> and optionally IP:<ip>.
    let dns_name = Ia5String::try_from(req.identity.clone())
        .map_err(|e| CaError::CertParseFailed(e.to_string()))?;
    let mut sans = vec![SanType::DnsName(dns_name)];
    if let Some(ref ip_str) = req.ip {
        let ip_addr: std::net::IpAddr = ip_str
            .parse()
            .map_err(|e| CaError::CertParseFailed(format!("invalid IP address '{}': {}", ip_str, e)))?;
        sans.push(SanType::IpAddress(ip_addr));
    }
    csr_params.params.subject_alt_names = sans;

    // Set validity on the params using the time crate.
    let now = time::OffsetDateTime::now_utc();
    csr_params.params.not_before = now;
    csr_params.params.not_after = now + time::Duration::seconds(req.validity_seconds as i64);

    // Get the CA as an rcgen Certificate (issuer).
    let ca_cert = ca.rcgen_cert()?;
    let ca_kp = ca.key_pair()?;

    // Sign.
    let leaf_cert = csr_params.signed_by(&ca_cert, &ca_kp)?;
    Ok(leaf_cert.pem())
}
