# VM-AuthN-Scope: vsock Certificate Authority — Design Document

## Overview

A pure-Rust (no OpenSSL/C dependency) PKI system for multi-VM Linux environments.
The **host CA** issues X.509 certificates over vsock, embedding capability claims (RBAC/CBAC) as a
custom X.509 extension encoded as a JSON Web Token (JWT)-style structure.
Each **guest VM** runs an agent that requests certificates on behalf of local identities (services/processes).

---

## Design Decisions

| Scope | Implementation |
| --- | --- |
| Key algorithm | ECDSA P-256 |
| vsock transport | Plain vsock (no TLS wrapper) |
| Certificate requests | One-shot (requested and stored on startup) |
| CA key | Plain PEM PKCS#8 |
| Cap JWT signature | Signed using the same CA private key |
| Key generation | `--genkey` CLI flag (regenerates/overwrites CA keys and starts server in a single step) |
| Server privilege enforcement | Requires root privilege to run (due to vsock binding constraints) |

---

## Architecture

![System Architecture Diagram #S#R](architecture_diagram.jpg)

---

## Wire Protocol

A simple length-prefixed JSON protocol over the vsock channel:

```
[4-byte big-endian length][JSON payload bytes]
```

### CertRequest (agent → server)

```json
{
  "version": 1,
  "Identity": "service-a",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

### CertResponse (server → agent)

```json
{
  "status": "ok",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

or on error:

```json
{
  "status": "error",
  "message": "CID not authorized"
}
```

---

## Capability / JWT Claim Structure

Capabilities are embedded as a **custom X.509 extension** (OID `1.3.6.1.4.1.99999.1`)
whose value is a compact JWT signed by the CA's private key.

### JWT Header

```json
{ "alg": "ES256", "typ": "CAP" }
```

### JWT Payload

```json
{
  "iss": "authn-scope-ca",
  "sub": "service-a",
  "vm":  "local-vm",
  "cid": 3,
  "iat": 1700000000,
  "exp": 1731536000,
  "caps": [
    {
      "target_vm":  "local-vm",
      "rpc_modules": ["auth"],
      "rpc_methods": ["data.read_secure"],
      "paths": [
        { "path": "/api/v1/health", "access": ["read"] }
      ]
    }
  ]
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
  "cert_validity_days": 365,
  "vms": {
    "local-vm": {
      "vm_cid": 3,
      "identities": {
        "service-a": {
          "caps": [
            {
              "target_vm": "local-vm",
              "rpc_modules": ["auth"],
              "rpc_methods": ["data.read_secure"],
              "paths": [
                { "path": "/api/v1/health", "access": ["read"] }
              ]
            }
          ]
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
  "identities": [
    {
      "name": "service-a",
      "cert_path": "/var/lib/service-a/cert.pem",
      "key_path": "/var/lib/service-a/key.pem",
      "ca_path": "/var/lib/service-a/ca.pem",
      "owner_uid": 0,
      "owner_gid": 0,
      "cert_mode": "0644",
      "key_mode": "0600"
    }
  ]
}
```

---

## Secure Port Binding & Verification

Unlike standard TCP/IP networks, vsock does not natively enforce privileged vsock ports (e.g. binding ports under 1024) across all kernel distributions. Any unprivileged process running inside the Guest VM or Host could theoretically attempt to bind to a designated port.

To eliminate this vulnerability, the system implements a robust verification mechanism:

1. **Client Port (Peer) Verification**:
   When the server accepts a connection, it extracts the peer address and verifies the client source port (`peer_addr.port()`). The server requires the client to bind to a specific, configured client port (configured via `peer_port`, defaulting to `901`). Connections originating from any other source ports are immediately terminated, preventing spoofing or malicious local processes from bypassing the agent.
2. **Server-Side Privilege Verification**:
   The server daemon binds to a low-numbered port (configured via `server_port`, defaulting to `900`). The kernel limits bindings on these ports to privileged processes running as `root`.
3. **VM IdIdentity Matching**:
   The guest agent sends its expected `vm_name` in the certificate request. The server looks up this VM in its configurations and validates that the connection's source CID matches the registered `vm_cid` of that VM.

> [!IMPORTANT]
> **Early Service Startup Recommendation**:
> To prevent malicious or unprivileged user-space processes from hijacking the designated ports, it is highly recommended to run both the server and the guest agent as early systemd services (triggered immediately when `/dev/vsock` is initialized). By binding to the designated ports early in the boot cycle, the services secure them and prevent any subsequent processes from binding to them.

---

## Early Service Startup with /dev/vsock in NixOS

To ensure the VM-AuthN-Scope agent and server initialize as early as possible during the guest VM boot process, the services do not wait for standard network targets. Instead, they dynamically bind to the existence of the guest kernel's virtual socket device node `/dev/vsock`.

### 1. Udev Device Tagging

A custom udev rule matches the vsock driver load and tags the device node with `systemd`:

```udev
KERNEL=="vsock", TAG+="systemd"
```

This instructs systemd to monitor the device and create a standard dependency unit called `dev-vsock.device` as soon as `/dev/vsock` is initialized by the kernel.

### 2. Service Bindings

Both the server and guest agent services declare explicit systemd dependencies:

```ini
[Unit]
BindsTo=dev-vsock.device
After=dev-vsock.device
```

This ensures the services are started immediately when the virtualization channel is available, allowing early credential provisioning.

By default, the host CID is a fixed system constant (`2`, representing the hypervisor/host). To support local testing or custom loopback environments, developers can override this value by setting the `VSOCK_HOST_CID` environment variable (e.g. `VSOCK_HOST_CID=1`).

---

## File & Module Layout

```
authn-scope/
├── Cargo.toml               # workspace root
├── Cargo.lock
│
├── libs/
│   ├── rust-libs/
│   │   ├── authn-scope-proto/ # shared wire types, capability structures & codecs
│   │   ├── authn-scope-ca/    # CA key/cert generation, signing, and JWT creation
│   │   └── authn-scope-evaluator/ # capability validation utilities
│   └── go-libs/
│       └── authn-scope-evaluator/ # capability validation utilities (Go version)
│
└── apps/
    └── rust-apps/
        ├── authn-scope-server/ # host CA daemon
        └── authn-scope-agent/  # guest agent
```

---

## CA Key Management

- Running `authn-scope-server` with `--genkey` generates a self-signed P-256 Root CA keypair using `rcgen`.
- If keys already exist at the paths specified in `/etc/authn-scope/host.json`, they are automatically removed and regenerated before starting the listener.
- If `--genkey` is omitted, the server attempts to load existing keys. If they do not exist, it throws an error and exits immediately.
