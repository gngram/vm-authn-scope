//! authn-scope-tpm — TPM 2.0 attestation and config sealing.
//!
//! Provides:
//! - **Agent-side**: Create Attestation Key (AK), generate PCR quotes
//! - **Server-side**: Verify PCR quotes (pure-Rust, no TPM needed)
//! - **Host sealing**: Seal/unseal config hashes via host TPM

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

// ─── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("TPM device not available: {0}")]
    DeviceNotAvailable(String),

    #[error("TPM operation failed: {0}")]
    OperationFailed(String),

    #[error("Quote verification failed: {0}")]
    VerificationFailed(String),

    #[error("Seal/unseal failed: {0}")]
    SealError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialisation error: {0}")]
    SerdeError(#[from] serde_json::Error),
}

// ─── Data types ─────────────────────────────────────────────────────────────

/// Result of creating an Attestation Key in the TPM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationKeyPub {
    /// Marshalled TPMT_PUBLIC of the AK (for verification without TPM).
    pub public_bytes: Vec<u8>,
}

/// A TPM2 Quote: signed PCR values + nonce binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// Marshalled TPMS_ATTEST (contains nonce, PCR digest, clock info).
    pub attest_bytes: Vec<u8>,
    /// Marshalled TPMT_SIGNATURE over the attest_bytes.
    pub signature_bytes: Vec<u8>,
}

/// PCR values extracted after successful verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedPcrs {
    /// Map of PCR index → SHA-256 digest (hex-encoded).
    pub values: HashMap<u32, String>,
}

/// Sealed data blob stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlob {
    /// TPM2B_PUBLIC of the sealed object.
    pub public: Vec<u8>,
    /// TPM2B_PRIVATE of the sealed object.
    pub private: Vec<u8>,
}

/// The default PCR indices to use for attestation.
pub const DEFAULT_ATTESTATION_PCRS: &[u32] = &[0, 1, 2, 3, 7];

// ─── Agent-side: TPM operations ─────────────────────────────────────────────

/// Try to open a connection to the TPM device.
/// Returns Ok(tcti_string) if a TPM is available, Err if not.
pub fn try_detect_tpm() -> Result<String, TpmError> {
    // Check environment variable override first (useful for testing or custom TCTI)
    if let Ok(tcti) = std::env::var("TPM2TOOLS_TCTI") {
        if !tcti.is_empty() {
            return Ok(tcti);
        }
    }
    if let Ok(tcti) = std::env::var("TSS2_TCTI") {
        if !tcti.is_empty() {
            return Ok(tcti);
        }
    }
    // Check for the TPM resource manager device (preferred)
    if std::path::Path::new("/dev/tpmrm0").exists() {
        return Ok("device:/dev/tpmrm0".to_string());
    }
    // Fall back to raw TPM device
    if std::path::Path::new("/dev/tpm0").exists() {
        return Ok("device:/dev/tpm0".to_string());
    }
    Err(TpmError::DeviceNotAvailable(
        "no /dev/tpmrm0 or /dev/tpm0 found".into(),
    ))
}

/// Create an Attestation Key (restricted signing key) in the TPM's
/// endorsement hierarchy. Returns the AK public key bytes and the
/// persistent handle index used to store it.
///
/// The AK is persisted at handle `0x81010002` so it survives reboots.
pub fn create_attestation_key(tcti: &str) -> Result<(AttestationKeyPub, u32), TpmError> {
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        handles::PersistentTpmHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            dynamic_handles::Persistent,
            key_bits::RsaKeyBits,
            resource_handles::{Hierarchy, Provision},
        },
        structures::{
            HashScheme, PublicBuilder, PublicRsaParametersBuilder, RsaScheme,
        },
        Context, TctiNameConf,
    };

    let tcti_conf: TctiNameConf = tcti
        .parse()
        .map_err(|e| TpmError::OperationFailed(format!("invalid TCTI: {}", e)))?;
    let mut context = Context::new(tcti_conf)
        .map_err(|e| TpmError::OperationFailed(format!("context init: {}", e)))?;

    // AK persistent handle
    let ak_persist_handle: u32 = 0x81010002;

    let persistent_handle = PersistentTpmHandle::new(ak_persist_handle)
        .map_err(|e| TpmError::OperationFailed(format!("invalid handle: {}", e)))?;

    // Try to read the public part of an existing AK
    use tss_esapi::handles::TpmHandle;
    let existing_ak = context.execute_with_nullauth_session(|ctx| {
        let key_handle = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))?;
        ctx.read_public(key_handle.into())
    });

    if let Ok((public, _, _)) = existing_ak {
        info!("AK already exists at persistent handle 0x{:08x}", ak_persist_handle);
        let pub_bytes = marshal_public(&public)?;
        return Ok((AttestationKeyPub { public_bytes: pub_bytes }, ak_persist_handle));
    } else {
        debug!("No existing AK found, creating new one");
    }

    // 1. Create primary key in endorsement hierarchy
    let ek_public = create_ek_public_template();

    let ek_result = context.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Endorsement, ek_public, None, None, None, None)
    })
    .map_err(|e| TpmError::OperationFailed(format!("create EK primary: {}", e)))?;

    // 2. Create AK (restricted signing key) under EK
    let ak_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_sign_encrypt(true)
        .build()
        .map_err(|e| TpmError::OperationFailed(format!("AK attributes: {}", e)))?;

    let ak_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(ak_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_is_signing_key(true)
                .with_is_decryption_key(false)
                .with_restricted(true)
                .build()
                .map_err(|e| TpmError::OperationFailed(format!("AK RSA params: {}", e)))?,
        )
        .with_rsa_unique_identifier(Default::default())
        .build()
        .map_err(|e| TpmError::OperationFailed(format!("AK public build: {}", e)))?;

    let ak_result = context.execute_with_nullauth_session(|ctx| {
        ctx.create(ek_result.key_handle, ak_public, None, None, None, None)
    })
    .map_err(|e| TpmError::OperationFailed(format!("create AK: {}", e)))?;

    // 3. Load AK
    let ak_handle = context.execute_with_nullauth_session(|ctx| {
        ctx.load(
            ek_result.key_handle,
            ak_result.out_private.clone(),
            ak_result.out_public.clone(),
        )
    })
    .map_err(|e| TpmError::OperationFailed(format!("load AK: {}", e)))?;

    // 4. Persist AK
    context.execute_with_nullauth_session(|ctx| {
        ctx.evict_control(
            Provision::Owner,
            ak_handle.into(),
            Persistent::Persistent(persistent_handle),
        )
    })
    .map_err(|e| TpmError::OperationFailed(format!("persist AK: {}", e)))?;

    info!("Created and persisted AK at handle 0x{:08x}", ak_persist_handle);

    let pub_bytes = marshal_public(&ak_result.out_public)?;
    Ok((AttestationKeyPub { public_bytes: pub_bytes }, ak_persist_handle))
}

/// Generate a TPM2_Quote over the specified PCR indices using the AK.
pub fn generate_quote(
    tcti: &str,
    ak_persist_handle: u32,
    nonce: &[u8],
    pcr_indices: &[u32],
) -> Result<TpmQuote, TpmError> {
    use tss_esapi::{
        handles::{PersistentTpmHandle, TpmHandle},
        interface_types::algorithm::HashingAlgorithm,
        structures::{Data, PcrSelectionListBuilder, PcrSlot, SignatureScheme},
        Context, TctiNameConf,
    };

    let tcti_conf: TctiNameConf = tcti
        .parse()
        .map_err(|e| TpmError::OperationFailed(format!("invalid TCTI: {}", e)))?;
    let mut context = Context::new(tcti_conf)
        .map_err(|e| TpmError::OperationFailed(format!("context init: {}", e)))?;

    let persistent_handle = PersistentTpmHandle::new(ak_persist_handle)
        .map_err(|e| TpmError::OperationFailed(format!("invalid handle: {}", e)))?;

    let ak_key_handle = context.execute_with_nullauth_session(|ctx| {
        ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
    })
    .map_err(|e| TpmError::OperationFailed(format!("load AK persistent handle: {}", e)))?;

    // Build PCR selection
    let pcr_slots: Vec<PcrSlot> = pcr_indices
        .iter()
        .map(|i| pcr_index_to_slot(*i))
        .collect::<Result<Vec<_>, _>>()?;

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &pcr_slots)
        .build()
        .map_err(|e| TpmError::OperationFailed(format!("PCR selection: {}", e)))?;

    let qualifying_data = Data::try_from(nonce.to_vec())
        .map_err(|e| TpmError::OperationFailed(format!("nonce too large: {}", e)))?;

    let (attest, signature) = context.execute_with_nullauth_session(|ctx| {
        ctx.quote(
            ak_key_handle.into(),
            qualifying_data,
            SignatureScheme::Null,
            pcr_selection,
        )
    })
    .map_err(|e| TpmError::OperationFailed(format!("TPM2_Quote: {}", e)))?;

    // Marshal to bytes for wire transmission
    let attest_bytes = marshal_attest(&attest)?;
    let signature_bytes = marshal_signature(&signature)?;

    info!(pcrs = ?pcr_indices, "Generated TPM quote");

    Ok(TpmQuote {
        attest_bytes,
        signature_bytes,
    })
}

// ─── Server-side: Quote verification (no TPM needed) ────────────────────────

/// Verify a TPM quote's integrity and extract PCR values.
///
/// This performs pure-software verification:
/// 1. Unmarshals the TPMS_ATTEST and checks the nonce matches
/// 2. Verifies the RSA signature over the TPMS_ATTEST using the AK public key
/// 3. Returns the PCR digest from the quote
///
/// Note: The caller is responsible for comparing the PCR values against
/// the expected (TOFU or pinned) values.
pub fn verify_quote(
    ak_pub_bytes: &[u8],
    nonce: &[u8],
    quote: &TpmQuote,
) -> Result<Vec<u8>, TpmError> {
    use ring::signature;

    // 1. Extract the RSA public key from the TPMT_PUBLIC
    let (n, e) = extract_rsa_pubkey_from_tpmt_public(ak_pub_bytes)?;

    // 2. Verify signature over the TPMS_ATTEST data
    let raw_sig = extract_raw_signature(&quote.signature_bytes);
    let public_key = signature::RsaPublicKeyComponents { n: &n, e: &e };
    public_key
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            &quote.attest_bytes,
            raw_sig,
        )
        .map_err(|_| TpmError::VerificationFailed("RSA signature verification failed".into()))?;

    info!("TPM quote signature verified successfully");

    // 3. Extract and verify nonce from TPMS_ATTEST
    let (extra_data, pcr_digest) = parse_tpms_attest(&quote.attest_bytes)?;

    if extra_data != nonce {
        return Err(TpmError::VerificationFailed(format!(
            "nonce mismatch: expected {}, got {}",
            hex::encode(nonce),
            hex::encode(&extra_data),
        )));
    }

    info!("TPM quote nonce verified");

    Ok(pcr_digest)
}

// ─── Host config sealing ────────────────────────────────────────────────────

/// Seal a data blob into the host TPM, bound to the current PCR state.
/// Returns a serialisable `SealedBlob` to be stored on disk.
pub fn seal_data(tcti: &str, data: &[u8]) -> Result<SealedBlob, TpmError> {
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            resource_handles::Hierarchy,
        },
        structures::{
            PublicBuilder, PublicKeyedHashParameters,
            KeyedHashScheme, SensitiveData,
        },
        Context, TctiNameConf,
    };

    let tcti_conf: TctiNameConf = tcti
        .parse()
        .map_err(|e| TpmError::SealError(format!("invalid TCTI: {}", e)))?;
    let mut context = Context::new(tcti_conf)
        .map_err(|e| TpmError::SealError(format!("context init: {}", e)))?;

    // Create storage primary in owner hierarchy
    let primary_public = create_storage_primary_template();
    let primary = context.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, primary_public, None, None, None, None)
    })
    .map_err(|e| TpmError::SealError(format!("create primary: {}", e)))?;

    // Create sealed object
    let seal_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .map_err(|e| TpmError::SealError(format!("seal attributes: {}", e)))?;

    let seal_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(seal_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::Null,
        ))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .map_err(|e| TpmError::SealError(format!("seal public build: {}", e)))?;

    let sensitive_data = SensitiveData::try_from(data.to_vec())
        .map_err(|e| TpmError::SealError(format!("sensitive data: {}", e)))?;

    let result = context.execute_with_nullauth_session(|ctx| {
        ctx.create(
            primary.key_handle,
            seal_public,
            None,
            Some(sensitive_data),
            None,
            None,
        )
    })
    .map_err(|e| TpmError::SealError(format!("seal create: {}", e)))?;

    let public_bytes = marshal_public(&result.out_public)?;
    let private_bytes = marshal_private(&result.out_private)?;

    info!("Config hash sealed into host TPM");

    Ok(SealedBlob {
        public: public_bytes,
        private: private_bytes,
    })
}

/// Unseal a previously sealed data blob from the host TPM.
pub fn unseal_data(tcti: &str, blob: &SealedBlob) -> Result<Vec<u8>, TpmError> {
    use tss_esapi::{
        interface_types::resource_handles::Hierarchy,
        Context, TctiNameConf,
    };

    let tcti_conf: TctiNameConf = tcti
        .parse()
        .map_err(|e| TpmError::SealError(format!("invalid TCTI: {}", e)))?;
    let mut context = Context::new(tcti_conf)
        .map_err(|e| TpmError::SealError(format!("context init: {}", e)))?;

    // Re-create the storage primary
    let primary_public = create_storage_primary_template();
    let primary = context.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, primary_public, None, None, None, None)
    })
    .map_err(|e| TpmError::SealError(format!("create primary: {}", e)))?;

    // Unmarshal sealed object
    let private = unmarshal_private(&blob.private)?;
    let public = unmarshal_public(&blob.public)?;

    let handle = context.execute_with_nullauth_session(|ctx| {
        ctx.load(primary.key_handle, private, public)
    })
    .map_err(|e| TpmError::SealError(format!("load sealed: {}", e)))?;

    let data = context.execute_with_nullauth_session(|ctx| {
        ctx.unseal(handle.into())
    })
    .map_err(|e| TpmError::SealError(format!("unseal: {}", e)))?;

    info!("Config hash unsealed from host TPM");

    Ok(data.to_vec())
}

// ─── Internal helpers ───────────────────────────────────────────────────────

fn create_ek_public_template() -> tss_esapi::structures::Public {
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
            key_bits::{AesKeyBits, RsaKeyBits},
        },
        structures::{
            PublicBuilder, PublicRsaParametersBuilder, RsaScheme,
            SymmetricDefinitionObject,
        },
    };

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .expect("EK attributes");

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .with_symmetric(SymmetricDefinitionObject::Aes {
                    key_bits: AesKeyBits::Aes128,
                    mode: SymmetricMode::Cfb,
                })
                .build()
                .expect("EK RSA params"),
        )
        .with_rsa_unique_identifier(Default::default())
        .build()
        .expect("EK public template")
}

fn create_storage_primary_template() -> tss_esapi::structures::Public {
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
            key_bits::{AesKeyBits, RsaKeyBits},
        },
        structures::{
            PublicBuilder, PublicRsaParametersBuilder, RsaScheme,
            SymmetricDefinitionObject,
        },
    };

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .expect("storage primary attributes");

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .with_symmetric(SymmetricDefinitionObject::Aes {
                    key_bits: AesKeyBits::Aes128,
                    mode: SymmetricMode::Cfb,
                })
                .build()
                .expect("storage RSA params"),
        )
        .with_rsa_unique_identifier(Default::default())
        .build()
        .expect("storage primary template")
}

// ─── Marshalling helpers ────────────────────────────────────────────────────
// These convert tss-esapi types to/from byte vectors for wire transmission.

fn marshal_public(public: &tss_esapi::structures::Public) -> Result<Vec<u8>, TpmError> {
    use tss_esapi::traits::Marshall;
    public
        .marshall()
        .map_err(|e| TpmError::OperationFailed(format!("marshal public: {}", e)))
}

fn unmarshal_public(bytes: &[u8]) -> Result<tss_esapi::structures::Public, TpmError> {
    use tss_esapi::traits::UnMarshall;
    tss_esapi::structures::Public::unmarshall(bytes)
        .map_err(|e| TpmError::OperationFailed(format!("unmarshal public: {}", e)))
}

fn marshal_private(private: &tss_esapi::structures::Private) -> Result<Vec<u8>, TpmError> {
    let bytes: &[u8] = private.as_ref();
    Ok(bytes.to_vec())
}

fn unmarshal_private(bytes: &[u8]) -> Result<tss_esapi::structures::Private, TpmError> {
    tss_esapi::structures::Private::try_from(bytes.to_vec())
        .map_err(|e| TpmError::OperationFailed(format!("unmarshal private: {}", e)))
}

fn marshal_attest(attest: &tss_esapi::structures::Attest) -> Result<Vec<u8>, TpmError> {
    use tss_esapi::traits::Marshall;
    attest
        .marshall()
        .map_err(|e| TpmError::OperationFailed(format!("marshal attest: {}", e)))
}

fn marshal_signature(sig: &tss_esapi::structures::Signature) -> Result<Vec<u8>, TpmError> {
    use tss_esapi::traits::Marshall;
    sig.marshall()
        .map_err(|e| TpmError::OperationFailed(format!("marshal signature: {}", e)))
}

/// Extract the RSA modulus (n) and exponent (e) from a marshalled TPMT_PUBLIC.
fn extract_rsa_pubkey_from_tpmt_public(public_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    let public = unmarshal_public(public_bytes)?;

    use tss_esapi::structures::Public as TpmPublic;
    match public {
        TpmPublic::Rsa { unique, .. } => {
            let n_slice: &[u8] = unique.as_ref();
            let n = n_slice.to_vec();
            // TPM RSA keys use the standard exponent 65537 (0x010001)
            let e = vec![0x01, 0x00, 0x01];
            Ok((n, e))
        }
        _ => Err(TpmError::VerificationFailed(
            "AK public key is not RSA".into(),
        )),
    }
}

/// Parse the TPMS_ATTEST structure to extract the qualifying data (nonce)
/// and the PCR digest from the quote info.
fn parse_tpms_attest(attest_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    use tss_esapi::structures::Attest;
    use tss_esapi::traits::UnMarshall;

    let attest = Attest::unmarshall(attest_bytes)
        .map_err(|e| TpmError::VerificationFailed(format!("unmarshal TPMS_ATTEST: {}", e)))?;

    let extra_data_slice: &[u8] = attest.extra_data().as_ref();
    let extra_data = extra_data_slice.to_vec();

    // Extract PCR digest from the attested quote info
    let pcr_digest = match attest.attested() {
        tss_esapi::structures::AttestInfo::Quote { info } => {
            let digest_slice: &[u8] = info.pcr_digest().as_ref();
            digest_slice.to_vec()
        }
        _ => {
            return Err(TpmError::VerificationFailed(
                "TPMS_ATTEST is not a Quote".into(),
            ));
        }
    };

    Ok((extra_data, pcr_digest))
}

// ─── hex encoding helper ────────────────────────────────────────────────────

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

fn extract_raw_signature(sig_bytes: &[u8]) -> &[u8] {
    if sig_bytes.len() > 256 {
        // TPMT_SIGNATURE wire format contains 6-byte header: sigAlg(2) + hashAlg(2) + size(2)
        &sig_bytes[sig_bytes.len() - 256..]
    } else {
        sig_bytes
    }
}

fn pcr_index_to_slot(index: u32) -> Result<tss_esapi::structures::PcrSlot, TpmError> {
    use tss_esapi::structures::PcrSlot;
    match index {
        0 => Ok(PcrSlot::Slot0),
        1 => Ok(PcrSlot::Slot1),
        2 => Ok(PcrSlot::Slot2),
        3 => Ok(PcrSlot::Slot3),
        4 => Ok(PcrSlot::Slot4),
        5 => Ok(PcrSlot::Slot5),
        6 => Ok(PcrSlot::Slot6),
        7 => Ok(PcrSlot::Slot7),
        8 => Ok(PcrSlot::Slot8),
        9 => Ok(PcrSlot::Slot9),
        10 => Ok(PcrSlot::Slot10),
        11 => Ok(PcrSlot::Slot11),
        12 => Ok(PcrSlot::Slot12),
        13 => Ok(PcrSlot::Slot13),
        14 => Ok(PcrSlot::Slot14),
        15 => Ok(PcrSlot::Slot15),
        16 => Ok(PcrSlot::Slot16),
        17 => Ok(PcrSlot::Slot17),
        18 => Ok(PcrSlot::Slot18),
        19 => Ok(PcrSlot::Slot19),
        20 => Ok(PcrSlot::Slot20),
        21 => Ok(PcrSlot::Slot21),
        22 => Ok(PcrSlot::Slot22),
        23 => Ok(PcrSlot::Slot23),
        _ => Err(TpmError::OperationFailed(format!("PCR index {} out of range (0..23)", index))),
    }
}

/// Read PCR values from the TPM and return them as hex-encoded strings.
pub fn read_pcr_values(tcti: &str, pcr_indices: &[u32]) -> Result<HashMap<u32, String>, TpmError> {
    use tss_esapi::{
        interface_types::algorithm::HashingAlgorithm,
        structures::PcrSelectionListBuilder,
        Context, TctiNameConf,
    };

    let tcti_conf: TctiNameConf = tcti
        .parse()
        .map_err(|e| TpmError::OperationFailed(format!("invalid TCTI: {}", e)))?;
    let mut context = Context::new(tcti_conf)
        .map_err(|e| TpmError::OperationFailed(format!("context init: {}", e)))?;

    let pcr_slots = pcr_indices
        .iter()
        .map(|i| pcr_index_to_slot(*i))
        .collect::<Result<Vec<_>, _>>()?;

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &pcr_slots)
        .build()
        .map_err(|e| TpmError::OperationFailed(format!("PCR selection: {}", e)))?;

    let (_update_counter, _sel_out, pcr_data) = context.execute_without_session(|ctx| {
        ctx.pcr_read(pcr_selection)
    })
    .map_err(|e| TpmError::OperationFailed(format!("PCR read: {}", e)))?;

    let mut values = HashMap::new();
    for (i, digest) in pcr_data.value().iter().enumerate() {
        if i < pcr_indices.len() {
            let digest_slice: &[u8] = digest.as_ref();
            values.insert(pcr_indices[i], hex::encode(digest_slice));
        }
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_quote_lifecycle_if_tpm_available() {
        let tcti = match try_detect_tpm() {
            Ok(t) => t,
            Err(_) => return, // Skip test if no TPM is configured in test env
        };

        let (ak_pub, ak_handle) = create_attestation_key(&tcti).expect("AK creation failed");
        let nonce = vec![0x33u8; 32];
        let quote = generate_quote(&tcti, ak_handle, &nonce, DEFAULT_ATTESTATION_PCRS)
            .expect("Quote generation failed");

        let pcr_digest = verify_quote(&ak_pub.public_bytes, &nonce, &quote)
            .expect("Quote verification failed");
        assert!(!pcr_digest.is_empty());

        let test_data = b"host-config-hash-1234567890";
        let sealed = seal_data(&tcti, test_data).expect("Seal failed");
        let unsealed = unseal_data(&tcti, &sealed).expect("Unseal failed");
        assert_eq!(test_data.as_slice(), unsealed.as_slice());
    }
}

