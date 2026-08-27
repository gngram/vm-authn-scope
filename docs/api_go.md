# Go Workload API Usage & Client Library

The **Workload API** is exposed by `authn-scope-agent` via a Unix Domain Socket (default path: `/run/authn-scope/workload.sock`). Applications running inside guest VMs can fetch and automatically rotate X.509 credentials.

---

## Option 1: Using the Official Go `authn-scope-workload` Package

The repository includes a ready-to-use Go package at `libs/go-libs/authn-scope-workload`:

```go
package main

import (
    "fmt"
    "log"
    "time"

    workload "authn-scope-workload"
)

func main() {
    client := workload.NewWorkloadClient("/run/authn-scope/workload.sock")

    // 1. Initial synchronous fetch
    creds, err := client.FetchCredentials()
    if err != nil {
        log.Fatalf("Failed to fetch credentials: %v", err)
    }
    fmt.Printf("Workload Certificate PEM:\n%s\n", creds.CertPEM)

    // 2. Start automatic background rotation loop (e.g. every 30s)
    client.StartRotationLoop(30 * time.Second)

    // 3. Access the latest cached credentials thread-safely
    time.Sleep(1 * time.Second)
    current := client.CurrentCredentials()
    if current != nil {
        fmt.Println("Current in-memory certificate is active and ready.")
    }
}
```

---

## Option 2: Direct Socket Interaction (Standard Library Only)

```go
package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "log"
    "net"
)

type FetchRequest struct {
    Type string `json:"type"`
}

type FetchResponse struct {
    Status    string `json:"status"`
    CertPEM   string `json:"cert_pem,omitempty"`
    KeyPEM    string `json:"key_pem,omitempty"`
    CACertPEM string `json:"ca_cert_pem,omitempty"`
    Message   string `json:"message,omitempty"`
}

func fetchCredentials() (*FetchResponse, error) {
    conn, err := net.Dial("unix", "/run/authn-scope/workload.sock")
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    // Send request with trailing newline
    req := FetchRequest{Type: "fetch"}
    reqData, err := json.Marshal(req)
    if err != nil {
        return nil, err
    }
    if _, err := conn.Write(append(reqData, '\n')); err != nil {
        return nil, err
    }

    // Read newline-terminated response
    reader := bufio.NewReader(conn)
    line, err := reader.ReadBytes('\n')
    if err != nil {
        return nil, err
    }

    var resp FetchResponse
    if err := json.Unmarshal(line, &resp); err != nil {
        return nil, err
    }
    return &resp, nil
}

func main() {
    resp, err := fetchCredentials()
    if err != nil {
        log.Fatalf("Failed to fetch credentials: %v", err)
    }
    if resp.Status != "success" {
        log.Fatalf("Workload API error: %s", resp.Message)
    }
    fmt.Printf("Certificate PEM:\n%s\n", resp.CertPEM)
    fmt.Printf("Key PEM:\n%s\n", resp.KeyPEM)
    fmt.Printf("CA Cert PEM:\n%s\n", resp.CACertPEM)
}
```

---

## Background Rotation Without Application Overhead

* **Agent-side Rotation**: The guest agent caches credentials in memory and automatically refreshes them with the host CA before certificate expiration (`ttl_minutes / 2`).
* **Workload-side Rotation**: The application simply queries the cached credentials in memory or calls `FetchCredentials()` on connection establishment.

---

**References**
* Go workload package – `libs/go-libs/authn-scope-workload/workload.go`
* Go evaluator test – `libs/go-libs/authn-scope-evaluator/evaluator.go`
* Agent implementation – `apps/rust-apps/authn-scope-agent/src/client.rs`
