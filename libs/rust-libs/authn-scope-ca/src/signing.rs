//! CSR signing: validates and issues leaf certificate with SPIFFE SVID compliance.

use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, Ia5String, KeyUsagePurpose, SanType,
};
use tracing::info;

use crate::{ca::CertificateAuthority, error::CaError};

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
    /// Configured SPIFFE trust domain name.
    pub trust_domain: Option<&'a str>,
    /// Optional IP address to embed in the certificate's subjectAltName.
    pub ip: Option<String>,
    /// Certificate validity in seconds.
    pub validity_seconds: u32,
}

/// Sign a CSR and return the PEM-encoded leaf certificate containing SPIFFE URI SAN.
pub fn sign_csr(ca: &CertificateAuthority, req: SigningRequest<'_>) -> Result<String, CaError> {
    info!(
        identity = %req.identity,
        vm = %req.vm_name,
        cid = req.cid,
        "Signing SPIFFE SVID CSR"
    );

    // Parse the incoming CSR.
    let mut csr_params =
        CertificateSigningRequestParams::from_pem(req.csr_pem).map_err(CaError::RcgenError)?;

    // Set Subject CommonName to identity.
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, req.identity.clone());
    csr_params.params.distinguished_name = dn;

    // Set leaf-cert key usages to digitalSignature only.
    csr_params.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    // Set explicit NoCa to ensure BasicConstraints (2.5.29.19) extension is included with cA=false (SPIFFE SVID requirement).
    csr_params.params.is_ca = rcgen::IsCa::ExplicitNoCa;

    // Set extended key usages to serverAuth, clientAuth.
    csr_params.params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // Build SAN list with DNS name, SPIFFE URI SAN, and optional IP address.
    let dns_name = Ia5String::try_from(req.identity.clone())
        .map_err(|e| CaError::CertParseFailed(e.to_string()))?;
    let mut sans = vec![SanType::DnsName(dns_name)];

    // Attach SPIFFE SVID URI SAN (spiffe://<trust_domain>/workload/<identity>)
    let domain = req.trust_domain.unwrap_or("example.org");
    let spiffe_id_str = format!("spiffe://{}/workload/{}", domain, req.identity);
    let spiffe_ia5 = Ia5String::try_from(spiffe_id_str)
        .map_err(|e| CaError::CertParseFailed(e.to_string()))?;
    sans.push(SanType::URI(spiffe_ia5));

    if let Some(ref ip_str) = req.ip {
        let ip_addr: std::net::IpAddr = ip_str.parse().map_err(|e| {
            CaError::CertParseFailed(format!("invalid IP address '{}': {}", ip_str, e))
        })?;
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

/// Issued Agent SVID credential (cert PEM + key PEM).
#[derive(Debug, Clone)]
pub struct AgentSvidCredential {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Issue an Agent SVID certificate & private keypair signed by the CA.
pub fn issue_agent_svid(
    ca: &CertificateAuthority,
    vm_name: &str,
    trust_domain: Option<&str>,
    validity_seconds: u32,
) -> Result<AgentSvidCredential, CaError> {
    info!(vm_name = %vm_name, "Issuing Agent SVID certificate");

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(CaError::RcgenError)?;

    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, format!("agent-{}", vm_name));
    params.distinguished_name = dn;

    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];

    let domain = trust_domain.unwrap_or("example.org");
    let spiffe_id_str = format!("spiffe://{}/agent/{}", domain, vm_name);
    let spiffe_ia5 = Ia5String::try_from(spiffe_id_str)
        .map_err(|e| CaError::CertParseFailed(e.to_string()))?;
    params.subject_alt_names = vec![SanType::URI(spiffe_ia5)];

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::seconds(validity_seconds as i64);

    let ca_cert = ca.rcgen_cert()?;
    let ca_kp = ca.key_pair()?;

    let cert = params.signed_by(&key_pair, &ca_cert, &ca_kp)?;

    Ok(AgentSvidCredential {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

/// Verify an Agent SVID certificate and request signature.
pub fn verify_agent_svid(
    ca: &CertificateAuthority,
    vm_name: &str,
    trust_domain: Option<&str>,
    agent_svid_pem: &str,
    payload_to_verify: &[u8],
    signature_b64: &str,
) -> Result<(), CaError> {
    use base64::Engine;
    use x509_parser::pem::parse_x509_pem;

    // 1. Parse Agent SVID certificate
    let (_, pem) = parse_x509_pem(agent_svid_pem.as_bytes())
        .map_err(|e| CaError::CertParseFailed(format!("failed to parse Agent SVID PEM: {:?}", e)))?;
    let agent_cert = pem
        .parse_x509()
        .map_err(|e| CaError::CertParseFailed(format!("failed to parse Agent SVID X.509: {:?}", e)))?;

    // 2. Parse CA certificate
    let (_, ca_pem) = parse_x509_pem(ca.cert_pem.as_bytes())
        .map_err(|e| CaError::CertParseFailed(format!("failed to parse CA PEM: {:?}", e)))?;
    let ca_cert = ca_pem
        .parse_x509()
        .map_err(|e| CaError::CertParseFailed(format!("failed to parse CA X.509: {:?}", e)))?;

    // 3. Verify certificate signature against CA
    agent_cert
        .verify_signature(Some(ca_cert.public_key()))
        .map_err(|e| CaError::CertParseFailed(format!("Agent SVID signature verification against CA failed: {:?}", e)))?;

    // 4. Verify validity timeframe
    if !agent_cert.validity().is_valid() {
        return Err(CaError::CertParseFailed("Agent SVID certificate is expired or not yet valid".into()));
    }

    // 5. Verify SPIFFE URI SAN or CommonName matches agent identity
    let domain = trust_domain.unwrap_or("example.org");
    let expected_spiffe_id = format!("spiffe://{}/agent/{}", domain, vm_name);
    let expected_cn = format!("agent-{}", vm_name);

    let mut id_matched = false;
    if let Ok(Some(sans)) = agent_cert.subject_alternative_name() {
        for san in &sans.value.general_names {
            if let x509_parser::extensions::GeneralName::URI(uri) = san {
                if *uri == expected_spiffe_id.as_str() {
                    id_matched = true;
                    break;
                }
            }
        }
    }
    if !id_matched {
        if agent_cert.subject().to_string().contains(&expected_cn) {
            id_matched = true;
        }
    }
    if !id_matched {
        return Err(CaError::CertParseFailed(format!(
            "Agent SVID identity mismatch: expected SPIFFE ID '{}' or CN '{}'",
            expected_spiffe_id, expected_cn
        )));
    }

    // 6. Decode signature and verify payload using Agent SVID public key
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| CaError::CertParseFailed(format!("invalid signature base64: {}", e)))?;

    let public_key_bytes = agent_cert.public_key().subject_public_key.data.as_ref();
    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        public_key_bytes,
    );

    peer_public_key
        .verify(payload_to_verify, &sig_bytes)
        .map_err(|e| CaError::CertParseFailed(format!("Agent request signature verification failed: {:?}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::pem::parse_x509_pem;

    #[test]
    fn test_sign_csr_includes_basic_constraints_and_key_usage() {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let cert_path = std::env::temp_dir().join(format!("ca-cert-{}.pem", nonce));
        let key_path = std::env::temp_dir().join(format!("ca-key-{}.pem", nonce));

        let ca = CertificateAuthority::init(&cert_path, &key_path, true).unwrap();

        // Create client CSR
        let client_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut client_params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "grpc-app");
        client_params.distinguished_name = dn;
        let csr = client_params.serialize_request(&client_key).unwrap();
        let csr_pem = csr.pem().unwrap();

        let signed_pem = sign_csr(
            &ca,
            SigningRequest {
                csr_pem: &csr_pem,
                identity: "grpc-app".to_string(),
                vm_name: "vm-1".to_string(),
                cid: 3,
                trust_domain: Some("example.org"),
                ip: None,
                validity_seconds: 60,
            },
        )
        .unwrap();

        let (_, pem) = parse_x509_pem(signed_pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();

        // Verify Basic Constraints (2.5.29.19) is present and ca=false
        let basic_ext = cert
            .tbs_certificate
            .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)
            .unwrap()
            .expect("BasicConstraints extension must be present on leaf cert");
        match basic_ext.parsed_extension() {
            ParsedExtension::BasicConstraints(b) => {
                assert!(!b.ca, "Leaf certificate cA flag must be false");
            }
            _ => panic!("Failed to parse BasicConstraints extension"),
        }

        // Verify Key Usage (2.5.29.15) has digital_signature and not key_cert_sign/crl_sign
        let ku_ext = cert
            .tbs_certificate
            .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
            .unwrap()
            .expect("KeyUsage extension must be present on leaf cert");
        match ku_ext.parsed_extension() {
            ParsedExtension::KeyUsage(k) => {
                assert!(k.digital_signature(), "Digital signature must be set");
                assert!(!k.key_cert_sign(), "Key cert sign must NOT be set on leaf cert");
                assert!(!k.crl_sign(), "CRL sign must NOT be set on leaf cert");
            }
            _ => panic!("Failed to parse KeyUsage extension"),
        }

        // Verify URI SAN
        let san_ext = cert
            .tbs_certificate
            .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .unwrap()
            .expect("SubjectAlternativeName extension must be present");
        match san_ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                let uris: Vec<_> = san
                    .general_names
                    .iter()
                    .filter_map(|name| {
                        if let x509_parser::extensions::GeneralName::URI(uri) = name {
                            Some(*uri)
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(uris.len(), 1);
                assert_eq!(uris[0], "spiffe://example.org/workload/grpc-app");
            }
            _ => panic!("Failed to parse SubjectAlternativeName extension"),
        }

        // Verify that spiffe crate parses this SVID without any errors
        let cert_der = rustls_pemfile::certs(&mut signed_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec();
        let key_der = client_key.serialize_der();
        let svid = spiffe::X509Svid::parse_from_der(&cert_der, &key_der)
            .expect("SPIFFE SDK X509Svid::parse_from_der must succeed on issued cert");
        assert_eq!(svid.spiffe_id().to_string(), "spiffe://example.org/workload/grpc-app");
    }
}
