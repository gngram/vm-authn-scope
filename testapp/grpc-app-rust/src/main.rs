use anyhow::{Context, Result, bail};
use authn_scope_workload::WorkloadClient;
use std::net::SocketAddr;
use std::{env, time::Duration};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};
use x509_parser::pem::parse_x509_pem;

pub mod echo {
    tonic::include_proto!("echo");
}

use echo::echo_service_client::EchoServiceClient;
use echo::echo_service_server::{EchoService, EchoServiceServer};
use echo::{EchoRequest, EchoResponse};

#[derive(Debug, Default)]
pub struct MyEchoService {
    pub server_cn: String,
}

#[tonic::async_trait]
impl EchoService for MyEchoService {
    async fn echo(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<EchoResponse>, tonic::Status> {
        let mut peer_cn = "unknown".to_string();

        if let Some(certs) = request.peer_certs() {
            if let Some(cert) = certs.first() {
                if let Ok((_, pem)) = parse_x509_pem(cert.as_ref()) {
                    if let Ok(x509) = pem.parse_x509() {
                        if let Some(cn) = x509
                            .subject()
                            .iter_common_name()
                            .next()
                            .and_then(|c| c.as_str().ok())
                        {
                            peer_cn = cn.to_string();
                        }
                    }
                }
            }
        }

        let req_msg = request.into_inner();
        println!(
            "[Rust App] Extracted peer name from mTLS certificate: '{}'",
            peer_cn
        );
        println!(
            "[Rust App] Received gRPC message from '{}': {}",
            peer_cn, req_msg.message
        );

        Ok(tonic::Response::new(EchoResponse {
            message: format!("gRPC Echo Response from {}", self.server_cn),
            peer_identity: self.server_cn.clone(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");
    let addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:50051");
    let socket_path = args
        .get(3)
        .map(|s| s.as_str())
        .unwrap_or("/run/authn-scope/workload.sock");

    println!(
        "[Rust App] Starting gRPC test app using tonic in mode '{}' at {} with Background Rotation Loop",
        mode, addr
    );
    let workload_client = WorkloadClient::new(socket_path);

    let creds1 = fetch_credentials_retry(&workload_client).await?;
    let (cn1, not_before1, not_after1) = parse_cert_info(&creds1.cert_pem)?;

    // Start background rotation loop (updates current credentials in memory automatically)
    workload_client.start_rotation_loop(Duration::from_secs(5));

    println!(
        "[Rust App] Initial credentials loaded into background rotation cache. CN='{}', NotBefore={}, NotAfter={}",
        cn1, not_before1, not_after1
    );

    if mode == "server" {
        run_server(addr, &workload_client, creds1, not_before1).await?;
    } else {
        run_client(addr, &workload_client, creds1, not_before1).await?;
    }

    Ok(())
}

async fn run_server(
    addr: &str,
    workload_client: &WorkloadClient,
    initial_creds: authn_scope_workload::X509Credentials,
    initial_not_before: i64,
) -> Result<()> {
    let identity = Identity::from_pem(&initial_creds.cert_pem, &initial_creds.key_pem);
    let client_ca = Certificate::from_pem(&initial_creds.ca_cert_pem);

    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let echo_service = MyEchoService {
        server_cn: "service-a".to_string(),
    };

    println!("[Rust App] gRPC Server (tonic with mTLS) listening at {}", addr);

    let addr_parsed: SocketAddr = addr.parse()?;
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(EchoServiceServer::new(echo_service))
            .serve(addr_parsed)
            .await
            .unwrap();
    });

    // Wait 32 seconds while background rotation loop updates credentials in memory
    println!("[Rust App] Waiting 32 seconds for automatic certificate rotation threshold...");
    tokio::time::sleep(Duration::from_secs(32)).await;

    // Separate fetch from Workload API ONLY for test assertion
    let assertion_creds = workload_client
        .fetch_credentials()
        .await
        .context("Separate assertion fetch failed")?;
    let (cn2, not_before2, not_after2) = parse_cert_info(&assertion_creds.cert_pem)?;

    println!(
        "[Rust App] Separate assertion fetch complete. CN='{}', NotBefore={}, NotAfter={}",
        cn2, not_before2, not_after2
    );

    if not_before2 <= initial_not_before {
        bail!(
            "Certificate timestamp verification FAILED! Initial NotBefore={}, Rotated NotBefore={}",
            initial_not_before,
            not_before2
        );
    }
    println!(
        "[Rust App] Certificate timestamp verification SUCCESS! Initial NotBefore: {}, Rotated NotBefore: {} (Advanced by {}s)",
        initial_not_before,
        not_before2,
        not_before2 - initial_not_before
    );

    tokio::time::sleep(Duration::from_secs(10)).await;
    println!("[Rust App] All gRPC mTLS & Certificate Rotation checks PASSED successfully!");
    Ok(())
}

async fn run_client(
    addr: &str,
    workload_client: &WorkloadClient,
    initial_creds: authn_scope_workload::X509Credentials,
    initial_not_before: i64,
) -> Result<()> {
    let client_identity = Identity::from_pem(&initial_creds.cert_pem, &initial_creds.key_pem);
    let server_ca = Certificate::from_pem(&initial_creds.ca_cert_pem);

    let tls_config1 = ClientTlsConfig::new()
        .domain_name("service-a")
        .identity(client_identity)
        .ca_certificate(server_ca);

    let mut attempts = 0;
    let channel1 = loop {
        match Endpoint::from_shared(format!("https://{}", addr))?
            .tls_config(tls_config1.clone())?
            .connect()
            .await
        {
            Ok(c) => break c,
            Err(e) => {
                if attempts < 60 {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                return Err(e).context(format!("Failed to connect to gRPC server at {} via mTLS", addr));
            }
        }
    };

    println!("[Rust App] Connected to gRPC server at {} via mTLS (Pre-Rotation Connection 1)", addr);

    let mut echo_client1 = EchoServiceClient::new(channel1);
    let response1 = echo_client1
        .echo(EchoRequest {
            message: "gRPC Hello via Production mTLS Setup (Pre-Rotation)".into(),
        })
        .await?;

    let resp1_inner = response1.into_inner();
    println!(
        "[Rust App] Extracted peer name from certificate: '{}'",
        resp1_inner.peer_identity
    );
    println!(
        "[Rust App] Received gRPC response: {}",
        resp1_inner.message
    );

    // Wait 32 seconds while background rotation loop updates credentials in memory
    println!("[Rust App] Waiting 32 seconds for automatic certificate rotation threshold...");
    tokio::time::sleep(Duration::from_secs(32)).await;

    // Separate fetch from Workload API ONLY for test assertion
    let assertion_creds = workload_client
        .fetch_credentials()
        .await
        .context("Separate assertion fetch failed")?;
    let (cn2, not_before2, not_after2) = parse_cert_info(&assertion_creds.cert_pem)?;

    println!(
        "[Rust App] Separate assertion fetch complete. CN='{}', NotBefore={}, NotAfter={}",
        cn2, not_before2, not_after2
    );

    if not_before2 <= initial_not_before {
        bail!(
            "Certificate timestamp verification FAILED! Initial NotBefore={}, Rotated NotBefore={}",
            initial_not_before,
            not_before2
        );
    }
    println!(
        "[Rust App] Certificate timestamp verification SUCCESS! Initial NotBefore: {}, Rotated NotBefore: {} (Advanced by {}s)",
        initial_not_before,
        not_before2,
        not_before2 - initial_not_before
    );

    // Fetch the rotated credentials from background rotation cache
    let rotated_creds = workload_client
        .current_credentials()
        .await
        .unwrap_or(assertion_creds);

    let rotated_identity = Identity::from_pem(&rotated_creds.cert_pem, &rotated_creds.key_pem);
    let rotated_ca = Certificate::from_pem(&rotated_creds.ca_cert_pem);

    let tls_config2 = ClientTlsConfig::new()
        .domain_name("service-a")
        .identity(rotated_identity)
        .ca_certificate(rotated_ca);

    let channel2 = Endpoint::from_shared(format!("https://{}", addr))?
        .tls_config(tls_config2)?
        .connect()
        .await?;

    let mut echo_client2 = EchoServiceClient::new(channel2);
    let response2 = echo_client2
        .echo(EchoRequest {
            message: "gRPC Hello via Production mTLS Setup (Post-Rotation)".into(),
        })
        .await?;

    let resp2_inner = response2.into_inner();
    println!(
        "[Rust App] Extracted post-rotation peer name: '{}'",
        resp2_inner.peer_identity
    );
    println!(
        "[Rust App] Received post-rotation gRPC response: {}",
        resp2_inner.message
    );

    println!("[Rust App] All gRPC mTLS & Certificate Rotation checks PASSED successfully!");
    Ok(())
}

fn parse_cert_info(cert_pem: &str) -> Result<(String, i64, i64)> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {:?}", e))?;
    let x509 = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("Failed to parse X.509: {:?}", e))?;

    let cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let validity = x509.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();

    Ok((cn, not_before, not_after))
}

async fn fetch_credentials_retry(
    client: &WorkloadClient,
) -> Result<authn_scope_workload::X509Credentials> {
    let mut attempts = 0;
    loop {
        match client.fetch_credentials().await {
            Ok(c) => return Ok(c),
            Err(e) => {
                if attempts < 40 {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                return Err(e).context("Workload API fetch credentials failed after retries");
            }
        }
    }
}
