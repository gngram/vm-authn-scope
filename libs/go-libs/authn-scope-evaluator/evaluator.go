package evaluator

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var CapExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

type PathAccess struct {
	Path   string   `json:"path"`
	Access []string `json:"access"`
}

type Capability struct {
	TargetVM   string       `json:"target_vm"`
	RPCModules []string     `json:"rpc_modules"`
	RPCMethods []string     `json:"rpc_methods"`
	Paths      []PathAccess `json:"paths"`
}

type CapClaim struct {
	Iss  string       `json:"iss"`
	Sub  string       `json:"sub"`
	VM   string       `json:"vm"`
	CID  uint32       `json:"cid"`
	Iat  int64        `json:"iat"`
	Exp  int64        `json:"exp"`
	Caps []Capability `json:"caps"`
}

type Evaluator struct {
	Claim CapClaim
}

// NewEvaluator creates a new Evaluator by verifying a peer certificate's capability JWT
// against the CA's public key.
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

	caPubKey, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("CA public key is not ECDSA")
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

	// 3. Find custom capability extension
	var jwtBytes []byte
	for _, ext := range peerCert.Extensions {
		if ext.Id.Equal(CapExtensionOID) {
			jwtBytes = ext.Value
			break
		}
	}
	if jwtBytes == nil {
		return nil, errors.New("capability extension (OID 1.3.6.1.4.1.99999.1) not found in peer certificate")
	}

	// The extension value is an ASN.1 OCTET STRING wrapping the raw JWT string.
	var innerJWT []byte
	if _, err := asn1.Unmarshal(jwtBytes, &innerJWT); err != nil {
		return nil, fmt.Errorf("failed to unwrap ASN.1 OCTET STRING: %w", err)
	}
	jwtStr := string(innerJWT)

	// 4. Verify and Parse JWT
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT structure")
	}

	// The signature is base64url decoded
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature encoding: %w", err)
	}
	if len(sig) != 64 {
		return nil, fmt.Errorf("invalid ES256 signature length: got %d, expected 64", len(sig))
	}

	// Hash header + "." + payload
	signedData := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signedData))

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.Verify(caPubKey, hash[:], r, s) {
		return nil, errors.New("JWT verification failed: invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}

	var claim CapClaim
	if err := json.Unmarshal(payloadBytes, &claim); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT payload: %w", err)
	}

	return &Evaluator{Claim: claim}, nil
}

// CanCallRpc checks if the peer is authorized to invoke a specific RPC module or module.method
// on the specified target VM.
func (e *Evaluator) CanCallRpc(myVmName, module, method string) bool {
	fullMethod := module + "." + method

	for _, cap := range e.Claim.Caps {
		if cap.TargetVM == myVmName {
			// Check if full module access is granted
			for _, m := range cap.RPCModules {
				if m == module {
					return true
				}
			}
			// Check if specific method access is granted
			for _, m := range cap.RPCMethods {
				if m == fullMethod {
					return true
				}
			}
		}
	}
	return false
}

// CanAccessPath checks if the peer is authorized to access a specific path with the requested mode
// on the specified target VM.
func (e *Evaluator) CanAccessPath(myVmName, path, accessMode string) bool {
	for _, cap := range e.Claim.Caps {
		if cap.TargetVM == myVmName {
			for _, p := range cap.Paths {
				if p.Path == path {
					for _, a := range p.Access {
						if a == accessMode {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
