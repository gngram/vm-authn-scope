# VM-AuthN-Scope: vsock Certificate Authority & Workload API — Design Document

## Overview

A pure-Rust (zero OpenSSL/C crypto library) PKI and attestation system for multi-VM Linux environments.
The **host CA** issues X.509 certificates over vsock with mutual hardware-backed trust established via **vTPM attestation** and **host TPM configuration sealing**.
Each **guest VM** runs an agent that authenticates with the host CA and exposes a local **Workload API** (over a Unix Domain Socket) to provision ephemeral X.509 certificates to local processes based on fine-grained process selectors.

---

## Design Decisions

| Scope | Implementation |
| --- | --- |
| Key algorithm | ECDSA P-256 (Leaf & CA) |
| vsock transport | Length-prefixed JSON framing over vsock |
| Trust Establishment | vTPM remote attestation (TPM2_Quote over PCRs 0, 1, 2, 3, 7) with TOFU |
| Config & State Integrity | Immutable Nix Store for `host.json` + Host TPM sealing of `known_vms.json` |
| Credential Delivery | On-demand via local Workload API Unix Domain Socket (no disk storage) |
| Credential Rotation | Automatic in-memory rotation at 50% certificate TTL (`ttl_minutes / 2`) |
| Key generation | `--genkey` CLI flag (regenerates/overwrites CA keys and starts server in a single step) |
| Process Attestation | Linux peer credentials (`SO_PEERCRED`), `/proc/<pid>/exe`, and `/proc/<pid>/cgroup` |
| Server privilege enforcement | Requires root privilege to run (due to vsock bind constraints) |

---

## Architecture

![System Architecture Diagram #S#R](architecture_diagram.jpg)

### Complete Attestation & Certificate Issuance Flow

```mermaid
sequenceDiagram
    autonumber
    participant Workload as Workload (Process)
    participant Agent as Guest Agent (authn-scope-agent)
    participant vTPM as Guest vTPM (/dev/tpmrm0)
    participant Server as Host CA (authn-scope-server)
    participant HostTPM as Host TPM (/dev/tpmrm0)

    %% PHASE 1: Host Server Startup & Initialization
    rect rgb(240, 245, 255)
    Note over Server,HostTPM: Phase 1: Host Server Startup & Initialization
    Server->>Server: Read immutable host.json from Nix Store (/nix/store/...)
    Server->>HostTPM: Verify/Unseal known_vms.json hash from Host TPM (known_vms_seal.json)
    Server->>Server: Initialize ECDSA P-256 Root CA & bind vsock:900
    end

    %% PHASE 2: Guest Boot & Attestation Handshake
    rect rgb(245, 255, 245)
    Note over Agent,Server: Phase 2: Guest Boot & Hardware-Backed Attestation (TOFU)
    Agent->>vTPM: Create/Load Attestation Key (AK) at handle 0x81010002
    vTPM-->>Agent: Public AK (TPMT_PUBLIC)
    Agent->>Server: Handshake { version: 2, vm_name: "local-vm", ak_pub } (vsock)
    Server->>Server: Verify caller CID=3 & generate 32-byte secure random nonce
    Server-->>Agent: AttestationChallenge { nonce }
    Agent->>vTPM: TPM2_Quote(AK, nonce, PCRs 0, 1, 2, 3, 7)
    vTPM-->>Agent: TPMS_ATTEST + RSA signature
    Agent->>Server: AttestationResponse { attest, signature }
    Server->>Server: Verify quote RSA signature & nonce (pure Rust)
    Server->>Server: Check/Record PCRs in known_vms.json (TOFU)
    Server-->>Agent: HandshakeOk { workloads: [service-a, service-b] }
    Agent->>Agent: Bind protect listener to client port 901 & serve UDS /run/authn-scope/workload.sock
    end

    %% PHASE 3: On-Demand Credential Issuance
    rect rgb(255, 250, 240)
    Note over Workload,Server: Phase 3: Workload Authentication & Certificate Issuance
    Workload->>Agent: Connect to /run/authn-scope/workload.sock {"type": "fetch"}
    Agent->>Agent: Inspect caller credentials (SO_PEERCRED, /proc/pid/exe, /proc/pid/cgroup)
    Agent->>Agent: Match selectors -> resolve identity "service-a"
    Agent->>Agent: Generate ephemeral ECDSA P-256 key pair & PKCS#10 CSR
    Agent->>Server: CertRequest { vm_name: "local-vm", identity: "service-a", csr_pem } (from port 901)
    Server->>Server: Validate identity authorized for CID=3 & sign leaf cert (TTL + IP SAN)
    Server-->>Agent: CertOk { cert_pem, ca_cert_pem }
    Agent->>Agent: Cache credentials in memory & re-bind port 901 listener
    Agent-->>Workload: WorkloadResponse { cert_pem, key_pem, ca_cert_pem }
    end

    %% PHASE 4: Credential Rotation
    rect rgb(250, 240, 255)
    Note over Workload,Agent: Phase 4: Automatic In-Memory Credential Rotation
    Workload->>Workload: Background rotation loop triggers at 50% TTL
    Workload->>Agent: Connect to /run/authn-scope/workload.sock {"type": "fetch"}
    Agent->>Server: Request renewed certificate from Host CA
    Server-->>Agent: CertOk { new_cert_pem, ca_cert_pem }
    Agent-->>Workload: Return rotated in-memory credentials
    end
```

---

## Wire Protocol

A length-prefixed JSON protocol over the vsock channel:

```
[4-byte big-endian length][JSON payload bytes]
```

### 1. Handshake Request (agent → server)

```json
{
  "type": "handshake",
  "version": 2,
  "vm_name": "local-vm",
  "ak_pub": "<base64-encoded TPMT_PUBLIC bytes>"
}
```

### 2. Attestation Challenge (server → agent)

```json
{
  "status": "attestation_challenge",
  "nonce": "<base64-encoded 32-byte random nonce>"
}
```

### 3. Attestation Response (agent → server)

```json
{
  "type": "attestation_response",
  "attest": "<base64-encoded TPMS_ATTEST bytes>",
  "signature": "<base64-encoded TPMT_SIGNATURE bytes>"
}
```

### 4. Handshake Response (server → agent)

```json
{
  "status": "handshakeok",
  "workloads": {
    "service-a": {
      "selector": {
        "unix": {
          "user": "service-a",
          "group": "service-a",
          "bin-path": "/usr/local/bin/service-a"
        },
        "systemd": {
          "unitname": "service-a"
        }
      },
      "validity_seconds": 600
    }
  }
}
```

### 5. On-Demand CertRequest (agent → server)

```json
{
  "type": "cert_request",
  "version": 2,
  "vm_name": "local-vm",
  "identity": "service-a",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

### 6. CertResponse (server → agent)

```json
{
  "status": "certok",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

---

## Configuration Schema

### Host config (`/etc/authn-scope/host.json`)

```json
{
  "ca_cert_path": "/etc/authn-scope/ca/ca-cert.pem",
  "ca_key_path": "/etc/authn-scope/ca/ca-key.pem",
  "server_port": 900,
  "peer_port": 901,
  "vms": {
    "local-vm": {
      "vm_cid": 3,
      "ip": "127.0.0.1",
      "attestation": {
        "required": true
      },
      "identities": {
        "service-a": {
          "selector": "unix:user:service-a,unix:group:service-a,systemd:unitname:service-a",
          "ttl_minutes": 10
        },
        "service-b": {
          "selector": "unix:user:service-b,unix:group:service-b",
          "ttl_minutes": 60
        }
      }
    }
  }
}
```

### Guest/Agent config (`/etc/authn-scope/agent.json`)

```json
{
  "vm_name": "local-vm",
  "server_port": 900,
  "client_port": 901,
  "workload_api_socket": "/run/authn-scope/workload.sock"
}
```

---

## Secure Port Binding & Verification

1. **Client Port (Peer) Verification**:
   When the server accepts a connection, it verifies the client source port (`peer_addr.port()`). The server requires the client to bind to `peer_port` (default `901`). Connections from other ports are rejected.
2. **Server-Side Privilege Verification**:
   The server daemon binds to a low-numbered port (`server_port`, default `900`). The kernel limits bindings on these ports to privileged processes running as `root`.
3. **VM Identity Matching**:
   The guest agent sends its expected `vm_name` in the handshake request. The server looks up this VM and validates that the connection's source CID matches `vm_cid`.
4. **vTPM Hardware Attestation**:
   The guest proves its boot integrity by signing PCR measurements (0, 1, 2, 3, 7) with its TPM Attestation Key.

---

## File & Module Layout

```
authn-scope/
├── Cargo.toml               # workspace root
├── Cargo.lock
│
├── libs/
│   ├── rust-libs/
│   │   ├── authn-scope-proto/     # wire types, framing codecs, protocol versions
│   │   ├── authn-scope-ca/        # pure-Rust CA engine, CSR signing
│   │   ├── authn-scope-tpm/       # TPM 2.0 AK management, quote verification, sealing
│   │   ├── authn-scope-workload/  # Rust client library for Workload API
│   │   └── authn-scope-evaluator/ # certificate verification library
│   └── go-libs/
│       ├── authn-scope-workload/  # Go client library for Workload API
│       └── authn-scope-evaluator/ # Go certificate verification library
│
└── apps/
    └── rust-apps/
        ├── authn-scope-server/        # host CA daemon with TPM sealing & attestation
        ├── authn-scope-agent/         # guest agent with Workload API & vTPM quote
        ├── workload-test-workload/    # test workload for rotation verification
        └── profiler/                  # memory and latency profiling benchmark
```

---

## References & Further Reading

* [Threat Model & Attack Analysis](threat_model.md)
* [Server Configuration Reference](server_configuration.md)
* [Agent Configuration Reference](agent_configuration.md)
* [Rust Workload API Guide](api_rust.md)
* [Go Workload API Guide](api_go.md)
