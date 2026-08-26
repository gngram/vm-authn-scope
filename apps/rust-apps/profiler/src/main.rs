use std::time::Instant;
use std::path::Path;
use authn_scope_ca::CertificateAuthority;
use authn_scope_ca::signing::SigningRequest;

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

    // Initialize CA using temporary paths
    let cert_path = Path::new("/tmp/profile-ca-cert.pem");
    let key_path = Path::new("/tmp/profile-ca-key.pem");
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);

    let start_ca = Instant::now();
    let ca = CertificateAuthority::init(cert_path, key_path, true)?;
    let duration_ca = start_ca.elapsed();
    println!("CA Init Time:    {:?}", duration_ca);
    println!("Post-CA VmRSS:   {:?} KB", get_rss_kb().unwrap_or(0));

    // Run keygen/CSR and signing benchmark
    let iterations = 200;
    println!("\nRunning {} iterations of key generation, CSR creation, and certificate signing...", iterations);

    let mut keygen_durations = Vec::new();
    let mut signing_durations = Vec::new();

    for i in 0..iterations {
        // 1. Keygen + CSR generation
        let start_keygen = Instant::now();
        let key_pair = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec![format!("service-{}", i)])?;
        params.is_ca = rcgen::IsCa::NoCa;
        let csr_pem = params.serialize_request(&key_pair)?.pem()?;
        keygen_durations.push(start_keygen.elapsed());

        // 2. Signing
        let start_signing = Instant::now();
        let _cert_pem = authn_scope_ca::signing::sign_csr(
            &ca,
            SigningRequest {
                csr_pem: &csr_pem,
                identity: format!("service-{}", i),
                vm_name: "test-vm".to_string(),
                cid: 3,
                ip: Some("127.0.0.1".to_string()),
                validity_seconds: 3600,
            },
        )?;
        signing_durations.push(start_signing.elapsed());
    }

    let avg_keygen = keygen_durations.iter().sum::<std::time::Duration>() / iterations;
    let avg_signing = signing_durations.iter().sum::<std::time::Duration>() / iterations;

    println!("\n=== PROFILE RESULTS ===");
    println!("Avg Key Gen + CSR Creation:  {:?} microseconds", avg_keygen.as_micros());
    println!("Avg CSR Signing (Host CA):   {:?} microseconds", avg_signing.as_micros());
    println!("Final VmRSS:                 {:?} KB", get_rss_kb().unwrap_or(0));
    println!("Final VmSize:                {:?} KB", get_vsize_kb().unwrap_or(0));

    // Clean up temporary files
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);

    Ok(())
}
