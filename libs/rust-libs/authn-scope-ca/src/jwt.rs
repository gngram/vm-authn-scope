//! JWT-style capability token signer.
//!
//! We implement a minimal ES256 JWT builder using `ring` directly so that
//! we have zero non-Rust dependencies (no OpenSSL, no `jsonwebtoken` C code).
//!
//! The JWT is embedded as a custom X.509 extension (OID 1.3.6.1.4.1.99999.1).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};

use authn_scope_proto::caps::CapClaim;

use crate::error::CaError;

/// JWT header for ES256 capability tokens.
const CAP_JWT_HEADER: &str = r#"{"alg":"ES256","typ":"CAP"}"#;

/// OID for the authn-scope capability extension (private enterprise arc).
/// 1.3.6.1.4.1.99999.1
pub const CAP_EXTENSION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// Signs [`CapClaim`] payloads into compact JWTs using ECDSA P-256 / SHA-256.
pub struct CapJwtSigner {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl CapJwtSigner {
    /// Construct a signer from raw PKCS#8 DER bytes of an ECDSA P-256 key.
    pub fn from_pkcs8_der(key_der: &[u8]) -> Result<Self, CaError> {
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key_der, &rng)?;
        Ok(Self { key_pair, rng })
    }

    /// Build and sign a compact JWT from a [`CapClaim`].
    ///
    /// Returns the compact serialisation `header.payload.signature`.
    pub fn sign(&self, claim: &CapClaim) -> Result<String, CaError> {
        let header_b64 = URL_SAFE_NO_PAD.encode(CAP_JWT_HEADER.as_bytes());
        let payload_json = serde_json::to_string(claim)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = self
            .key_pair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|e| CaError::JwtError(e.to_string()))?;

        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
        Ok(format!("{}.{}", signing_input, sig_b64))
    }
}

/// Verify a capability JWT and return the decoded [`CapClaim`].
///
/// `public_key_der` must be the raw uncompressed public key point (65 bytes)
/// or the SubjectPublicKeyInfo DER of the CA's ECDSA P-256 key.
pub fn verify_cap_jwt(jwt: &str, public_key_spki_der: &[u8]) -> Result<CapClaim, CaError> {
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(CaError::JwtError("invalid JWT structure".into()));
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| CaError::JwtError(format!("bad signature base64: {}", e)))?;

    let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_spki_der);
    pk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| CaError::JwtError("JWT signature verification failed".into()))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| CaError::JwtError(format!("bad payload base64: {}", e)))?;
    let claim: CapClaim = serde_json::from_slice(&payload_bytes)?;
    Ok(claim)
}
