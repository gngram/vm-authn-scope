use anyhow::{Context, Result};
use base64::Engine;
use spiffe::WorkloadApiClient;
use std::{env, fs, time::Duration};

pub struct Certs {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_cert_pem: String,
}

fn der_to_pem(tag: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", tag);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", tag));
    pem
}

async fn fetch_svid(socket_path: &str) -> Result<Certs> {
    let endpoint_str = if socket_path.starts_with("unix:") || socket_path.starts_with("tcp:") {
        socket_path.to_string()
    } else {
        format!("unix://{}", socket_path)
    };

    let client = WorkloadApiClient::connect_to(&endpoint_str)
        .await
        .with_context(|| format!("Failed to connect to SPIFFE Workload API at {}", endpoint_str))?;

    let context = client
        .fetch_x509_context()
        .await
        .context("FetchX509SVID via official SPIFFE SDK failed")?;

    let svid = context
        .default_svid()
        .context("No default SVID returned in X509Context")?;

    let mut cert_pem = String::new();
    for cert in svid.cert_chain() {
        cert_pem.push_str(&der_to_pem("CERTIFICATE", cert.as_bytes()));
    }

    let key_pem = der_to_pem("PRIVATE KEY", svid.private_key().as_bytes());

    let trust_domain = svid.spiffe_id().trust_domain();
    let mut ca_cert_pem = String::new();
    if let Some(bundle) = context.bundle_set().get(trust_domain) {
        for authority in bundle.authorities() {
            ca_cert_pem.push_str(&der_to_pem("CERTIFICATE", authority.as_bytes()));
        }
    }

    Ok(Certs {
        cert_pem,
        key_pem,
        ca_cert_pem,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let socket_path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("/run/authn-scope/workload.sock");

    println!("Connecting to official SPIFFE Workload API socket: {}", socket_path);

    let username = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let cert_path = format!("/tmp/workload-cert-{}.pem", username);
    let key_path = format!("/tmp/workload-key-{}.pem", username);
    let ca_path = format!("/tmp/workload-ca-{}.pem", username);

    if args.iter().any(|arg| arg == "--test-rotation") {
        println!("Running certificate rotation test...");
        let creds1 = fetch_svid(socket_path).await?;
        println!("Initial certificate fetched via official SPIFFE SDK.");

        fs::write(&cert_path, &creds1.cert_pem)?;
        fs::write(&key_path, &creds1.key_pem)?;
        fs::write(&ca_path, &creds1.ca_cert_pem)?;

        println!("Sleeping for 32 seconds to allow rotation threshold to pass...");
        tokio::time::sleep(Duration::from_secs(32)).await;

        let creds2 = fetch_svid(socket_path).await?;
        println!("Second certificate fetched via official SPIFFE SDK.");

        if creds1.cert_pem == creds2.cert_pem {
            eprintln!("Error: Certificate did not rotate!");
            std::process::exit(1);
        }

        println!("Success: Certificate rotated successfully!");
        fs::write("/tmp/rotation-passed", "1")?;
        return Ok(());
    }

    println!("Fetching credentials via official SPIFFE SDK...");
    let creds = fetch_svid(socket_path).await?;

    println!("Credentials fetched successfully via official SPIFFE SDK!");

    fs::write(&cert_path, &creds.cert_pem)?;
    fs::write(&key_path, &creds.key_pem)?;
    fs::write(&ca_path, &creds.ca_cert_pem)?;

    println!("Wrote fetched credentials to {}", cert_path);

    Ok(())
}
