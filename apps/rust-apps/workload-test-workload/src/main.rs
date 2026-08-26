use std::{env, fs, time::Duration};
use authn_scope_workload::WorkloadClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let socket_path = args.get(1)
        .map(|s| s.as_str())
        .unwrap_or("/run/authn-scope/workload.sock");

    println!("Connecting to workload socket: {}", socket_path);
    let client = WorkloadClient::new(socket_path);

    let username = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let cert_path = format!("/tmp/workload-cert-{}.pem", username);
    let key_path = format!("/tmp/workload-key-{}.pem", username);
    let ca_path = format!("/tmp/workload-ca-{}.pem", username);

    if args.iter().any(|arg| arg == "--test-rotation") {
        println!("Running certificate certificate rotation test...");
        let creds1 = client.fetch_credentials().await?;
        println!("Initial certificate fetched.");

        // Write them to /tmp/ for test script inspection
        fs::write(&cert_path, &creds1.cert_pem)?;
        fs::write(&key_path, &creds1.key_pem)?;
        fs::write(&ca_path, &creds1.ca_cert_pem)?;

        println!("Sleeping for 32 seconds to allow rotation threshold to pass...");
        tokio::time::sleep(Duration::from_secs(32)).await;

        let creds2 = client.fetch_credentials().await?;
        println!("Second certificate fetched.");

        if creds1.cert_pem == creds2.cert_pem {
            eprintln!("Error: Certificate did not rotate!");
            std::process::exit(1);
        }

        println!("Success: Certificate rotated successfully!");
        fs::write("/tmp/rotation-passed", "1")?;
        return Ok(());
    }

    println!("Fetching credentials...");
    let creds = client.fetch_credentials().await?;

    println!("Credentials fetched successfully!");
    
    // Write them to /tmp/ for test script inspection
    fs::write(&cert_path, &creds.cert_pem)?;
    fs::write(&key_path, &creds.key_pem)?;
    fs::write(&ca_path, &creds.ca_cert_pem)?;

    println!("Wrote fetched credentials to {}", cert_path);

    Ok(())
}
