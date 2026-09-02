package evaluator

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type Evaluator struct {
	Identity string
}

// NewEvaluator creates a new Evaluator by verifying a peer certificate's signature
// against the CA's certificate and extracting its subject CommonName.
func NewEvaluator(peerCertPEM, caCertPEM []byte) (*Evaluator, error) {
	// 1. Parse CA Cert
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, errors.New("failed to decode CA PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	// 2. Parse Peer Cert
	peerBlock, _ := pem.Decode(peerCertPEM)
	if peerBlock == nil {
		return nil, errors.New("failed to decode peer PEM")
	}
	peerCert, err := x509.ParseCertificate(peerBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer cert: %w", err)
	}

	// 3. Verify Peer Cert signature against CA Cert
	if err := peerCert.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("certificate signature verification failed: %w", err)
	}

	if peerCert.Subject.CommonName == "" {
		return nil, errors.New("subject CommonName (CN) is missing")
	}

	return &Evaluator{Identity: peerCert.Subject.CommonName}, nil
}
