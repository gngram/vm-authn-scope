package workload

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// X509Credentials holds the workload certificates and key in memory.
type X509Credentials struct {
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	CaCertPEM string `json:"ca_cert_pem"`
}

type workloadRequest struct {
	Type string `json:"type"`
}

type workloadResponse struct {
	Status    string `json:"status"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	CaCertPEM string `json:"ca_cert_pem"`
	Message   string `json:"message"`
}

// WorkloadClient manages credential retrieval and automatic renewal over UDS.
type WorkloadClient struct {
	socketPath string
	mu         sync.RWMutex
	cached     *X509Credentials
}

// NewWorkloadClient creates a new client for the given UDS socket path.
func NewWorkloadClient(socketPath string) *WorkloadClient {
	return &WorkloadClient{
		socketPath: socketPath,
	}
}

// FetchCredentials performs a synchronous fetch of the credentials.
func (c *WorkloadClient) FetchCredentials() (*X509Credentials, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Workload API socket at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	req := workloadRequest{
		Type: "fetch",
	}
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	_, err = conn.Write(append(reqData, '\n'))
	if err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response line: %w", err)
	}

	var resp workloadResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	if resp.Status != "success" {
		return nil, fmt.Errorf("workload API returned error: %s", resp.Message)
	}

	if resp.CertPEM == "" || resp.KeyPEM == "" || resp.CaCertPEM == "" {
		return nil, errors.New("workload API returned incomplete credentials")
	}

	return &X509Credentials{
		CertPEM:   resp.CertPEM,
		KeyPEM:    resp.KeyPEM,
		CaCertPEM: resp.CaCertPEM,
	}, nil
}

// CurrentCredentials gets the latest cached credentials in memory.
func (c *WorkloadClient) CurrentCredentials() *X509Credentials {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cached
}

// StartRotationLoop spawns a background goroutine to periodically fetch credentials.
func (c *WorkloadClient) StartRotationLoop(interval time.Duration) {
	go func() {
		for {
			creds, err := c.FetchCredentials()
			if err == nil {
				c.mu.Lock()
				c.cached = creds
				c.mu.Unlock()
			} else {
				// Log or print warning
				fmt.Printf("Workload API client failed to rotate credentials: %v\n", err)
			}
			time.Sleep(interval)
		}
	}()
}
