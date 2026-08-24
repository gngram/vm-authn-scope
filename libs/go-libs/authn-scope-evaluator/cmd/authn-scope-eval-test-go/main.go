package main

import (
	"fmt"
	"os"

	evaluator "authn-scope-evaluator"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <peer-cert.pem> <ca-cert.pem>\n", os.Args[0])
		os.Exit(1)
	}

	peerCertPath := os.Args[1]
	caCertPath := os.Args[2]

	peerCertPEM, err := os.ReadFile(peerCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading peer cert: %v\n", err)
		os.Exit(1)
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CA cert: %v\n", err)
		os.Exit(1)
	}

	eval, err := evaluator.NewEvaluator(peerCertPEM, caCertPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Evaluator initialization failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[Go Evaluator] Successfully verified capability JWT for Identity: %s\n", eval.Claim.Sub)

	// Validate against the integration test configured capabilities in run_integration_test.sh
	// The host configuration grants "service-a" the following:
	// target_vm: local-vm
	// rpc_modules: ["auth"]
	// rpc_methods: ["data.read_secure"]
	// paths: "/api/v1/health" with "read"

	targetVM := "local-vm"

	// 1. Should be allowed full module access
	if !eval.CanCallRpc(targetVM, "auth", "login") {
		fmt.Fprintf(os.Stderr, "Expected 'auth.login' to be allowed\n")
		os.Exit(1)
	}

	// 2. Should be allowed specific method access
	if !eval.CanCallRpc(targetVM, "data", "read_secure") {
		fmt.Fprintf(os.Stderr, "Expected 'data.read_secure' to be allowed\n")
		os.Exit(1)
	}

	// 3. Should be denied other methods
	if eval.CanCallRpc(targetVM, "data", "write") {
		fmt.Fprintf(os.Stderr, "Expected 'data.write' to be denied\n")
		os.Exit(1)
	}

	// 4. Should be allowed specific path
	if !eval.CanAccessPath(targetVM, "/api/v1/health", "read") {
		fmt.Fprintf(os.Stderr, "Expected path '/api/v1/health' with 'read' to be allowed\n")
		os.Exit(1)
	}

	// 5. Should be denied path with wrong mode
	if eval.CanAccessPath(targetVM, "/api/v1/health", "write") {
		fmt.Fprintf(os.Stderr, "Expected path '/api/v1/health' with 'write' to be denied\n")
		os.Exit(1)
	}

	fmt.Println("[Go Evaluator] All capability tests passed!")
}
