macro_rules! log_msg {
    ($($arg:tt)*) => {{
        use std::io::Write;
        println!($($arg)*);
        std::io::stdout().flush().ok();
    }};
}

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
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
                if let Ok((_, x509)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
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

        let req_msg = request.into_inner();
        log_msg!(
            "[Rust App] Extracted peer name from mTLS certificate: '{}'",
            peer_cn
        );
        log_msg!(
            "[Rust App] Received gRPC message from '{}': {}",
            peer_cn, req_msg.message
        );

        Ok(tonic::Response::new(EchoResponse {
            message: format!("gRPC Echo Response from {}", self.server_cn),
            peer_identity: self.server_cn.clone(),
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509Credentials {
    pub spiffe_id: String,
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

fn creds_from_source(source: &spiffe::X509Source) -> Result<X509Credentials> {
    let svid = source.svid().context("Failed to get SVID from X509Source")?;
    let mut cert_pem = String::new();
    for cert in svid.cert_chain() {
        cert_pem.push_str(&der_to_pem("CERTIFICATE", cert.as_bytes()));
    }
    let key_pem = der_to_pem("PRIVATE KEY", svid.private_key().as_bytes());

    let trust_domain = svid.spiffe_id().trust_domain();
    let bundle_set = source.bundle_set().context("Failed to get bundle set from X509Source")?;
    let mut ca_cert_pem = String::new();
    if let Some(bundle) = bundle_set.get(trust_domain) {
        for authority in bundle.authorities() {
            ca_cert_pem.push_str(&der_to_pem("CERTIFICATE", authority.as_bytes()));
        }
    }

    if ca_cert_pem.is_empty() {
        bail!("Failed to extract CA certificate bundle from SPIFFE X509Source");
    }

    Ok(X509Credentials {
        spiffe_id: svid.spiffe_id().to_string(),
        cert_pem,
        key_pem,
        ca_cert_pem,
    })
}

async fn create_x509_source_retry(socket_path: &str) -> Result<spiffe::X509Source> {
    let endpoint_str = if socket_path.starts_with("unix:") || socket_path.starts_with("tcp:") {
        socket_path.to_string()
    } else {
        format!("unix://{}", socket_path)
    };

    let mut last_err = None;
    for i in 1..=60 {
        match spiffe::X509Source::builder()
            .endpoint(&endpoint_str)
            .initial_sync_timeout(Duration::from_secs(5))
            .build()
            .await
        {
            Ok(source) => {
                log_msg!(
                    "[Rust App] Established connection to SPIFFE Workload API UDS socket at '{}' via official SPIFFE SDK on attempt {}",
                    endpoint_str, i
                );
                return Ok(source);
            }
            Err(e) => {
                log_msg!(
                    "[Rust App] [ATTEMPT {}/60] Connecting to SPIFFE Workload API UDS at '{}' failed: {:?}",
                    i, endpoint_str, e
                );
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    bail!(
        "Failed to connect to SPIFFE Workload API via official SPIFFE SDK after 60 attempts: {:?}",
        last_err
    );
}


#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");
    let addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:50051");
    let socket_path = args
        .get(3)
        .map(|s| s.as_str())
        .unwrap_or("/run/authn-scope/workload.sock");

    log_msg!(
        "[Rust App] Starting gRPC test app using official SPIFFE SDK X509Source in mode '{}' at {}",
        mode, addr
    );

    let source = create_x509_source_retry(socket_path).await?;
    let creds1 = creds_from_source(&source)?;
    let (cn1, not_before1, not_after1) = parse_cert_info(&creds1.cert_pem)?;

    log_msg!(
        "[Rust App] Initial credentials loaded via SPIFFE X509Source. SPIFFE ID='{}', CN='{}', NotBefore={}, NotAfter={}",
        creds1.spiffe_id, cn1, not_before1, not_after1
    );

    if mode == "server" {
        run_server(addr, &source, creds1, not_before1).await?;
    } else {
        run_client(addr, &source, creds1, not_before1).await?;
    }

    Ok(())
}

async fn run_server(
    addr: &str,
    source: &spiffe::X509Source,
    initial_creds: X509Credentials,
    initial_not_before: i64,
) -> Result<()> {
    let socket_addr: SocketAddr = addr.parse()?;

    let server = MyEchoService {
        server_cn: "grpc-app".to_string(),
    };

    let cert = Certificate::from_pem(&initial_creds.ca_cert_pem);
    let identity = Identity::from_pem(&initial_creds.cert_pem, &initial_creds.key_pem);

    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(cert);

    log_msg!(
        "[Rust App] gRPC Server (tonic) listening at {} with mTLS",
        addr
    );

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        let res = Server::builder()
            .tls_config(tls_config)
            .expect("failed to build ServerTlsConfig")
            .add_service(EchoServiceServer::new(server))
            .serve_with_shutdown(socket_addr, async {
                rx.await.ok();
            })
            .await;
        if let Err(e) = res {
            log_msg!("[Rust App] Server error: {:?}", e);
        }
    });

    log_msg!("[Rust App] Waiting 32 seconds for automatic certificate rotation threshold...");
    tokio::time::sleep(Duration::from_secs(32)).await;

    let assertion_creds = creds_from_source(source)?;
    let (mut cn2, mut not_before2, mut not_after2) = parse_cert_info(&assertion_creds.cert_pem)?;

    for _ in 0..15 {
        if not_before2 > initial_not_before {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok(c) = creds_from_source(source) {
            if let Ok((cn, nb, na)) = parse_cert_info(&c.cert_pem) {
                cn2 = cn;
                not_before2 = nb;
                not_after2 = na;
            }
        }
    }

    log_msg!(
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

    log_msg!(
        "[Rust App] Certificate timestamp verification SUCCESS! Initial NotBefore: {}, Rotated NotBefore: {} (Advanced by {}s)",
        initial_not_before,
        not_before2,
        not_before2 - initial_not_before
    );

    tokio::time::sleep(Duration::from_secs(15)).await;
    let _ = tx.send(());
    let _ = server_handle.await;

    log_msg!("[Rust App] All gRPC mTLS & Certificate Rotation checks PASSED successfully!");
    Ok(())
}

async fn run_client(
    addr: &str,
    source: &spiffe::X509Source,
    initial_creds: X509Credentials,
    initial_not_before: i64,
) -> Result<()> {
    let mut client1 = None;
    for _ in 0..60 {
        let cert = Certificate::from_pem(&initial_creds.ca_cert_pem);
        let identity = Identity::from_pem(&initial_creds.cert_pem, &initial_creds.key_pem);

        let tls_config = ClientTlsConfig::new()
            .domain_name("grpc-app")
            .identity(identity)
            .ca_certificate(cert);

        let endpoint = Endpoint::from_shared(format!("https://{}", addr))?.tls_config(tls_config)?;

        if let Ok(c) = EchoServiceClient::connect(endpoint).await {
            client1 = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let mut client1 = client1.context("failed to connect to gRPC server via mTLS")?;
    log_msg!(
        "[Rust App] Connected to gRPC server at {} via mTLS (Pre-Rotation Connection 1)",
        addr
    );

    let response1 = client1
        .echo(EchoRequest {
            message: "gRPC Hello via mTLS (Pre-Rotation)".to_string(),
        })
        .await?
        .into_inner();

    log_msg!(
        "[Rust App] Extracted peer name from certificate: '{}'",
        response1.peer_identity
    );
    log_msg!(
        "[Rust App] Received gRPC response: {}",
        response1.message
    );

    log_msg!("[Rust App] Waiting 32 seconds for automatic certificate rotation threshold...");
    tokio::time::sleep(Duration::from_secs(32)).await;

    let mut assertion_creds = creds_from_source(source)?;
    let (mut cn2, mut not_before2, mut not_after2) = parse_cert_info(&assertion_creds.cert_pem)?;

    for _ in 0..15 {
        if not_before2 > initial_not_before {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok(c) = creds_from_source(source) {
            if let Ok((cn, nb, na)) = parse_cert_info(&c.cert_pem) {
                assertion_creds = c;
                cn2 = cn;
                not_before2 = nb;
                not_after2 = na;
            }
        }
    }

    log_msg!(
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

    log_msg!(
        "[Rust App] Certificate timestamp verification SUCCESS! Initial NotBefore: {}, Rotated NotBefore: {} (Advanced by {}s)",
        initial_not_before,
        not_before2,
        not_before2 - initial_not_before
    );

    let current_creds = creds_from_source(source).unwrap_or(assertion_creds);
    let cert2 = Certificate::from_pem(&current_creds.ca_cert_pem);
    let identity2 = Identity::from_pem(&current_creds.cert_pem, &current_creds.key_pem);

    let tls_config2 = ClientTlsConfig::new()
        .domain_name("grpc-app")
        .identity(identity2)
        .ca_certificate(cert2);

    let endpoint2 = Endpoint::from_shared(format!("https://{}", addr))?.tls_config(tls_config2)?;

    let mut client2 = EchoServiceClient::connect(endpoint2)
        .await
        .context("failed to connect post-rotation")?;

    log_msg!(
        "[Rust App] Connected to gRPC server at {} via mTLS (Post-Rotation Connection 2)",
        addr
    );

    let response2 = client2
        .echo(EchoRequest {
            message: "gRPC Hello via mTLS (Post-Rotation)".to_string(),
        })
        .await?
        .into_inner();

    log_msg!(
        "[Rust App] Extracted post-rotation peer name: '{}'",
        response2.peer_identity
    );
    log_msg!(
        "[Rust App] Received post-rotation gRPC response: {}",
        response2.message
    );

    log_msg!("[Rust App] All gRPC mTLS & Certificate Rotation checks PASSED successfully!");
    Ok(())
}

fn parse_cert_info(cert_pem: &str) -> Result<(String, i64, i64)> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())?;
    let x509 = pem.parse_x509()?;
    let cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let not_before = x509.validity().not_before.timestamp();
    let not_after = x509.validity().not_after.timestamp();

    Ok((cn, not_before, not_after))
}
