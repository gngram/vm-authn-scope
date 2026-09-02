package main

import (
	"fmt"
	"os"

	evaluator "authn-scope-evaluator"
)

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <peer-cert.pem> <ca-cert.pem> [expected-identity]\n", os.Args[0])
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

	fmt.Printf("[Go Evaluator] Successfully verified certificate for Identity: %s\n", eval.Identity)

	if len(os.Args) == 4 {
		expected := os.Args[3]
		if eval.Identity != expected {
			fmt.Fprintf(os.Stderr, "Expected CN '%s', got '%s'\n", expected, eval.Identity)
			os.Exit(1)
		}
	} else {
		if eval.Identity == "" {
			fmt.Fprintf(os.Stderr, "Identity is empty\n")
			os.Exit(1)
		}
	}

	fmt.Println("[Go Evaluator] All tests passed!")
}
