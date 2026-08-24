use authn_scope_evaluator::Evaluator;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: authn-scope-eval-test <peer_cert.pem> <ca_cert.pem>");
        std::process::exit(1);
    }

    let peer_cert_pem = fs::read_to_string(&args[1]).expect("Failed to read peer cert");
    let ca_cert_pem = fs::read_to_string(&args[2]).expect("Failed to read CA cert");

    // Initialize Evaluator
    let eval = Evaluator::from_cert_pem(&peer_cert_pem, &ca_cert_pem)
        .expect("Evaluator failed to extract and verify capability JWT");

    // The test in flake.nix grants service-a the following for "local-vm":
    // rpc_modules: ["auth"]
    // rpc_methods: ["data.read_secure"]
    // paths: [ { path: "/api/v1/health", access: ["read"] } ]

    println!("Evaluating RPC capabilities...");
    assert!(eval.can_call_rpc("local-vm", "auth", "any_method")); // entire module allowed
    assert!(eval.can_call_rpc("local-vm", "data", "read_secure")); // specific method allowed
    assert!(!eval.can_call_rpc("local-vm", "data", "write")); // not allowed

    println!("Evaluating Path capabilities...");
    assert!(eval.can_access_path("local-vm", "/api/v1/health", "read")); // allowed
    assert!(!eval.can_access_path("local-vm", "/api/v1/health", "write")); // not allowed
    assert!(!eval.can_access_path("local-vm", "/api/v1/admin", "read")); // not allowed

    println!("All evaluations passed successfully!");
}
