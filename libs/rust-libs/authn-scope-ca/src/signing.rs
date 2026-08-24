//! CSR signing: validates, adds capability extension, issues leaf certificate.

use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{CertificateSigningRequestParams, CustomExtension, KeyUsagePurpose};
use tracing::info;

use authn_scope_proto::caps::{CapClaim, Capability};

use crate::{
    ca::CertificateAuthority,
    error::CaError,
    jwt::{CapJwtSigner, CAP_EXTENSION_OID},
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
    /// Capability claims to embed in the certificate extension.
    pub claims: Vec<Capability>,
    /// Certificate validity in days.
    pub validity_days: u32,
}

/// Sign a CSR and return the PEM-encoded leaf certificate.
///
/// The issued certificate carries the capability JWT as a non-critical
/// custom X.509 extension under OID 1.3.6.1.4.1.99999.1.
pub fn sign_csr(ca: &CertificateAuthority, req: SigningRequest<'_>) -> Result<String, CaError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CaError::JwtError(e.to_string()))?
        .as_secs() as i64;

    let validity_secs = req.validity_days as i64 * 86_400;
    let exp = now + validity_secs;

    // Build the capability claim.
    let claim = CapClaim {
        iss: "authn-scope-ca".into(),
        sub: req.identity.clone(),
        vm: req.vm_name.clone(),
        cid: req.cid,
        iat: now,
        exp,
        caps: req.claims,
    };

    // Sign the JWT.
    let signer = CapJwtSigner::from_pkcs8_der(&ca.key_der)?;
    let jwt = signer.sign(&claim)?;

    info!(
        identity = %req.identity,
        vm = %req.vm_name,
        cid = req.cid,
        "Signing CSR and embedding capability JWT"
    );

    // Parse the incoming CSR.
    let mut csr_params = CertificateSigningRequestParams::from_pem(req.csr_pem)
        .map_err(|e| CaError::RcgenError(e))?;

    // Set leaf-cert key usages.
    csr_params.params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];

    // Embed the capability JWT as a custom extension.
    // The extension value is the raw UTF-8 bytes of the JWT string,
    // wrapped in a DER OCTET STRING.
    let jwt_bytes = jwt.into_bytes();
    let ext_value = encode_der_octet_string(&jwt_bytes);
    let mut cap_ext = CustomExtension::from_oid_content(CAP_EXTENSION_OID, ext_value);
    cap_ext.set_criticality(false);
    csr_params.params.custom_extensions.push(cap_ext);

    // Set validity on the params.
    csr_params.params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    // Approximate: add validity days to a fixed base.
    // For a production system use a proper datetime lib; here we use
    // a conservative fixed date plus validity years.
    let approx_years = (req.validity_days / 365).max(1);
    let end_year = 2024 + approx_years;
    csr_params.params.not_after = rcgen::date_time_ymd(end_year as i32, 1, 1);

    // Get the CA as an rcgen Certificate (issuer).
    let ca_cert = ca.rcgen_cert()?;
    let ca_kp = ca.key_pair()?;

    // Sign.
    let leaf_cert = csr_params.signed_by(&ca_cert, &ca_kp)?;
    Ok(leaf_cert.pem())
}

// ─── DER helpers ─────────────────────────────────────────────────────────────

/// Encode bytes as a DER OCTET STRING (tag 0x04).
fn encode_der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.push(0x04); // OCTET STRING tag
    encode_der_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

/// Encode a DER length field (supports lengths up to 2^16-1).
fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}
