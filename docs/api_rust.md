# Rust Workload API Usage & Client Library

The **Workload API** is exposed by `authn-scope-agent` via a Unix Domain Socket (default path: `/run/authn-scope/workload.sock`). Applications running inside a guest VM can obtain dynamically issued X.509 certificates and keys without managing CSRs or long-term private keys.

---

## Option 1: Using the Official `authn-scope-workload` Client Crate

The workspace provides the `authn-scope-workload` library which manages background rotation automatically:

### `Cargo.toml`
```toml
[dependencies]
authn-scope-workload = { path = "libs/rust-libs/authn-scope-workload" }
tokio = { version = "1", features = ["full"] }
```

### Usage Example
```rust
use std::time::Duration;
use authn_scope_workload::WorkloadClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WorkloadClient::new("/run/authn-scope/workload.sock");

    // 1. Synchronous fetch on startup
    let creds = client.fetch_credentials().await?;
    println!("Fetched initial certificate for workload!");
    println!("Cert PEM:\n{}", creds.cert_pem);

    // 2. Start automatic background rotation loop (e.g. refresh every 30s)
    let _handle = client.start_rotation_loop(Duration::from_secs(30));

    // 3. Retrieve latest credentials thread-safely at any time
    if let Some(current) = client.current_credentials().await {
        println!("Current valid cert: {}", &current.cert_pem[..30]);
    }

    Ok(())
}
```

---

## Option 2: Direct Socket Interaction (Standard Library / Tokio)

If you prefer not to take on crate dependencies, you can connect directly over the Unix Domain Socket:

```rust
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use serde_json::json;

fn fetch_credentials(socket_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;

    // Send single newline-terminated JSON request
    let req = json!({ "type": "fetch" }).to_string() + "\n";
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    // Read newline-terminated JSON response
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let resp: serde_json::Value = serde_json::from_str(&line)?;
    if resp["status"] == "success" {
        let cert_pem = resp["cert_pem"].as_str().unwrap();
        let key_pem = resp["key_pem"].as_str().unwrap();
        let ca_cert_pem = resp["ca_cert_pem"].as_str().unwrap();
        println!("Certificate PEM:\n{}", cert_pem);
        println!("Key PEM:\n{}", key_pem);
        println!("CA Cert PEM:\n{}", ca_cert_pem);
    } else {
        eprintln!("Workload API error: {}", resp["message"].as_str().unwrap_or("unknown"));
    }
    Ok(())
}
```

---

## Automatic Credential Rotation in the Background

* **Agent-side Caching**: The guest agent caches credentials in memory and will automatically request a fresh certificate from the host CA when half of the validity (`ttl_minutes / 2`) has elapsed.
* **Workload-side Rotation Loop**: Using `client.start_rotation_loop(interval)`, your application updates its in-memory TLS certificate store smoothly without process restarts.

---

**References**
* Client crate – `libs/rust-libs/authn-scope-workload/src/lib.rs`
* Test binary – `apps/rust-apps/workload-test-workload/src/main.rs`
* Agent implementation – `apps/rust-apps/authn-scope-agent/src/client.rs`
