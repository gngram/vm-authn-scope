use authn_scope_ca::CertificateAuthority;
use authn_scope_ca::signing::SigningRequest;
use std::path::Path;
use std::time::Instant;

fn get_rss_kb() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

fn get_vsize_kb() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmSize:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PERFORMANCE & MEMORY PROFILER ===");
    println!("Baseline VmRSS:  {:?} KB", get_rss_kb().unwrap_or(0));
    println!("Baseline VmSize: {:?}", get_vsize_kb().unwrap_or(0));

    // 1. Initialize CA benchmark
    let cert_path = Path::new("/tmp/profile-ca-cert.pem");
    let key_path = Path::new("/tmp/profile-ca-key.pem");
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);

    let start_ca = Instant::now();
    let ca = CertificateAuthority::init(cert_path, key_path, true)?;
    let duration_ca = start_ca.elapsed();
    println!("\n[1] CA Initialization:");
    println!("  Init Time:     {:?}", duration_ca);
    println!("  Post-CA VmRSS: {:?} KB", get_rss_kb().unwrap_or(0));

    // 2. Keygen/CSR and Signing Benchmark
    let iterations = 200;
    println!("\n[2] Workload Benchmark ({} iterations):", iterations);

    let mut keygen_durations = Vec::new();
    let mut signing_durations = Vec::new();

    for i in 0..iterations {
        // 2a. Keygen + CSR generation
        let start_keygen = Instant::now();
        let key_pair = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec![format!("service-{}", i)])?;
        params.is_ca = rcgen::IsCa::NoCa;
        let csr_pem = params.serialize_request(&key_pair)?.pem()?;
        keygen_durations.push(start_keygen.elapsed());

        // 2b. CA Signing
        let start_signing = Instant::now();
        let _cert_pem = authn_scope_ca::signing::sign_csr(
            &ca,
            SigningRequest {
                csr_pem: &csr_pem,
                identity: format!("service-{}", i),
                vm_name: "test-vm".to_string(),
                cid: 3,
                trust_domain: Some("example.org"),
                ip: Some("127.0.0.1".to_string()),
                validity_seconds: 3600,
            },
        )?;
        signing_durations.push(start_signing.elapsed());
    }

    let avg_keygen = keygen_durations.iter().sum::<std::time::Duration>() / iterations;
    let avg_signing = signing_durations.iter().sum::<std::time::Duration>() / iterations;

    // 3. TPM Attestation Quote Verification Benchmark (Pure Rust)
    println!(
        "\n[3] TPM Quote Verification Benchmark ({} iterations):",
        iterations
    );

    // Static test 2048-bit RSA key in PKCS#8 DER format for benchmark
    const TEST_RSA_PKCS8_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzwBuB5AQAdreW\n\
l89CQhLSpcyJN6LaJh+tIKNgYt1Ob4oP8s++JrHfHuFTIC9BcYVCWwa8Xukj34IA\n\
KM9dWwNp/PVzYt/Pk0Y6ubNymaR9DmkAZigh4Yg3b+pXOjPJW39Wh11FSiMfI51i\n\
D++OlmBGEfaQ+1hnZA061+ppYRDKESfLbM2kVufcFijddx8Q+VVfgu9xN8gu8l5w\n\
HoGVsqkWYv5+h1u/rCbXlXZ0DsB7rFw9ubZE+Vur7Bb7vsE+jvVn0G1/X4lDcyBF\n\
AeIx3yMZDvap9ngYjxVE7VVC2hQYJnb8YhpphxKyQd/6NzVIN73oKehhYNLtXqL+\n\
Dc54gRr7AgMBAAECggEAPrqhHuBLATps8VIDU3Upinev/Ib8/zJkxY9pVJ7L6q6E\n\
OPKcyxhH5LyrF85Yj3clcTXBEQXySMGcZZ/YVhUICPntUppDzvXvgVkDJdA2lins\n\
POZpxQEm/2nAFzbJkdCrjK/qvd6UiS5toyY6jMEv0eQ87vW4MUS6VTm6pZHpQQrL\n\
0m+MrFZftrLKzK+Co7oqscQmwGHUIBLtHDJJywi4NPxrcJ8jPxDvgHLt+YvYxMPR\n\
MODWNLMAJjx4TQTIjax0WnMaxF8uO3C+HiK82WjMsnvGvWVnWPFy8VKXgi9Cad4r\n\
BmBr4R8h+WUE8sVcysc0PSIYJRKNqE2FeB3OHH5LsQKBgQDdhF8hMZTOSvkgw4wc\n\
iVAzax/ToWUq5sj/grXv6VrLFtuxUVCOiPNG6z6pvBxe9hZpyRY+O+LINUPqf9WY\n\
RsWPpE6iA0Q++vDOfvkJtND49NrwGvWpBW+KXHfPsfXgtC8D82DbVG3dTc3yKiC2\n\
OyNtXW5GV/LqAHSwlpEue4dk6QKBgQDPu01OSs8g0bnmIrwbTx1ek+z99vhXTZE9\n\
5ROF6q8Gqpk9SwECLYIT2vwYqL+YA8V/EXSGCxyiHN6FoewHwKYa4dXjFgCwNn/c\n\
o1CYJfQjoo7g4Vx5FaTa5bXzp1vZeVbRFe2Tuwmo/XEX3juM/C16DcSmzaN48F7c\n\
0QwEx5ziQwKBgCsOCXdoLaYTCG0H1PnO7pmv3pXBruoxxSt0emxRDOagYL8MMP4j\n\
PDWyj5FqEJGcfyq8fOhHt4J2Z+byRc+9IbUTmH0A6YjcOWXJZBow3NUmsk8szka1\n\
2cIoytjBnCq6mtDHwzGeLWRwNPE2ovkIcZBWMpLVkU9OG2AfQ8SnGd/RAoGBAMV3\n\
3H3vWURueZQOMtiW9WlBn0iwa9S51LaMu2lS9TyWEYOVeAj077EmOvzJ9Q9xjl1D\n\
X4xIpdhpLxLDINchyATH54WuFctsk1FPIj7v3Uu+rKmTMU+dRpAbS0KqNgLeeKvb\n\
d3M2mnE9MzOoOt3DnwtmaSjTVHGTtemdAxrMEhN3AoGAdf5BLzFgICjOHJ5H9eO3\n\
hZLzB6i9djLqaVXisgWhySZDHbEzbTCOOxP9EbvUXWwkTd0vfY39FAAAvGpo2rlw\n\
/8Hj+Oyg26JCfItr/QYr05K0yqZN6go++IZSdE54HxwCI++GPBN3qzLusJcPXZHw\n\
6KiT3MCBLq36BqlhldE1npM=\n\
-----END PRIVATE KEY-----";

    let mut cursor = std::io::Cursor::new(TEST_RSA_PKCS8_PEM.as_bytes());
    let pkcs8_der = rustls_pemfile::private_key(&mut cursor)?
        .ok_or_else(|| anyhow::anyhow!("failed to parse test private key PEM"))?
        .secret_der()
        .to_vec();

    // Create a mock TPM quote
    let nonce = vec![0x42u8; 32];
    let mock_pcr_digest = vec![0x11u8; 32];

    // Build minimal TPMS_ATTEST structure for verification benchmark
    // TPMS_ATTEST wire format: magic(4) + type(2) + qualifiedSigner(len+bytes) + extraData(len+bytes) + clockInfo + firmwareVersion + quoteInfo
    let mut attest_bytes = Vec::new();
    attest_bytes.extend_from_slice(&[0xff, 0x54, 0x43, 0x47]); // TPM_GENERATED_VALUE (0xff544347)
    attest_bytes.extend_from_slice(&[0x80, 0x18]); // TPM_ST_ATTEST_QUOTE (0x8018)
    // Qualified signer (TPM2B_NAME): size(2) + name
    attest_bytes.extend_from_slice(&0x0020u16.to_be_bytes());
    attest_bytes.extend_from_slice(&[0xAA; 32]);
    // Extra data (TPM2B_DATA): size(2) + nonce
    attest_bytes.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    attest_bytes.extend_from_slice(&nonce);
    // TPMS_CLOCK_INFO: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17 bytes
    attest_bytes.extend_from_slice(&[0u8; 17]);
    // Firmware version: 8 bytes
    attest_bytes.extend_from_slice(&[0u8; 8]);
    // TPMS_QUOTE_INFO: pcrSelect(TPML_PCR_SELECTION) + pcrDigest(TPM2B_DIGEST)
    // TPML_PCR_SELECTION: count(4) + [hash(2)+size(1)+pcrSelect(3)]
    attest_bytes.extend_from_slice(&1u32.to_be_bytes());
    attest_bytes.extend_from_slice(&[0x00, 0x0B, 0x03, 0x8F, 0x00, 0x00]); // SHA-256, select PCRs 0,1,2,3,7
    // pcrDigest: size(2) + digest
    attest_bytes.extend_from_slice(&(mock_pcr_digest.len() as u16).to_be_bytes());
    attest_bytes.extend_from_slice(&mock_pcr_digest);

    // Generate valid RSA signature over attest_bytes
    use ring::signature::RsaKeyPair;
    let ring_key_pair = RsaKeyPair::from_pkcs8(&pkcs8_der)
        .map_err(|e| anyhow::anyhow!("RSA keypair from pkcs8: {:?}", e))?;

    let mut sig_bytes = vec![0u8; ring_key_pair.public().modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    ring_key_pair
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &rng,
            &attest_bytes,
            &mut sig_bytes,
        )
        .map_err(|e| anyhow::anyhow!("RSA sign: {:?}", e))?;

    // Create TPMT_PUBLIC representation for verification
    // TPMT_PUBLIC wire format: type(2, 0x0001=RSA) + nameAlg(2, 0x000B=SHA256) + objectAttributes(4) + authPolicy(2+len) + parameters + unique
    let mut tpmt_public = Vec::new();
    tpmt_public.extend_from_slice(&[0x00, 0x01]); // TPM_ALG_RSA
    tpmt_public.extend_from_slice(&[0x00, 0x0B]); // TPM_ALG_SHA256
    tpmt_public.extend_from_slice(&[0x00, 0x04, 0x00, 0x72]); // attributes
    tpmt_public.extend_from_slice(&[0x00, 0x00]); // empty authPolicy
    // TPMS_RSA_PARMS: symmetric(2, Null=0x0010) + scheme(2, RSASSA=0x0014) + hash(2, SHA256=0x000B) + keyBits(2, 2048=0x0800) + exponent(4, 0)
    tpmt_public.extend_from_slice(&[
        0x00, 0x10, 0x00, 0x14, 0x00, 0x0B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    // TPM2B_PUBLIC_KEY_RSA (unique modulus): size(2) + modulus bytes
    let mut n_slice = &pkcs8_der[..];
    if let Some(pos) = pkcs8_der
        .windows(4)
        .position(|w| w == [0x02, 0x82, 0x01, 0x01])
    {
        n_slice = &pkcs8_der[pos + 5..pos + 5 + 256];
    } else if let Some(pos) = pkcs8_der
        .windows(4)
        .position(|w| w == [0x02, 0x82, 0x01, 0x00])
    {
        n_slice = &pkcs8_der[pos + 4..pos + 4 + 256];
    }
    tpmt_public.extend_from_slice(&(n_slice.len() as u16).to_be_bytes());
    tpmt_public.extend_from_slice(n_slice);

    let quote = authn_scope_tpm::TpmQuote {
        attest_bytes,
        signature_bytes: sig_bytes,
    };

    let mut quote_verify_durations = Vec::new();
    for _ in 0..iterations {
        let start_verify = Instant::now();
        let verified_digest = authn_scope_tpm::verify_quote(&tpmt_public, &nonce, &quote)?;
        quote_verify_durations.push(start_verify.elapsed());
        assert_eq!(verified_digest, mock_pcr_digest);
    }

    let avg_quote_verify = quote_verify_durations.iter().sum::<std::time::Duration>() / iterations;

    println!("\n=== PROFILE RESULTS SUMMARY ===");
    println!(
        "Avg Key Gen + CSR Creation:     {:?} µs",
        avg_keygen.as_micros()
    );
    println!(
        "Avg CSR Signing (Host CA):      {:?} µs",
        avg_signing.as_micros()
    );
    println!(
        "Avg TPM Quote Verification:     {:?} µs",
        avg_quote_verify.as_micros()
    );
    println!(
        "Final VmRSS:                    {:?} KB",
        get_rss_kb().unwrap_or(0)
    );
    println!(
        "Final VmSize:                   {:?} KB",
        get_vsize_kb().unwrap_or(0)
    );

    // Clean up temporary files
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);

    Ok(())
}
