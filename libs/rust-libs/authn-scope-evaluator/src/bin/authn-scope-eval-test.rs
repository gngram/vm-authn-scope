use authn_scope_evaluator::Evaluator;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!("Usage: authn-scope-eval-test <peer_cert.pem> <ca_cert.pem> [expected_identity]");
        std::process::exit(1);
    }

    let peer_cert_pem = fs::read_to_string(&args[1]).expect("Failed to read peer cert");
    let ca_cert_pem = fs::read_to_string(&args[2]).expect("Failed to read CA cert");

    // Initialize Evaluator
    let eval = Evaluator::from_cert_pem(&peer_cert_pem, &ca_cert_pem)
        .expect("Evaluator failed to verify certificate");

    println!("Evaluating peer certificate identity: {}", eval.identity);
    if args.len() == 4 {
        let expected = &args[3];
        assert_eq!(&eval.identity, expected, "Identity mismatch");
    } else {
        assert!(!eval.identity.is_empty(), "Identity is empty");
    }
    
    println!("All evaluations passed successfully!");
}
