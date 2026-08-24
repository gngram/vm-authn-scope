# authn-scope

A pure-Rust, zero-OpenSSL PKI system for securely issuing X.509 certificates
to services across a multi-VM Linux vsock environment.

## Architecture

```
┌──── HOST VM ────────────────────────────────────────────────────┐
│  authn-scope-server                                              │
│    • Listens on vsock port (default 9000) as the CA             │
│    • Reads /etc/authn-scope/host.json for VM/entity policy       │
│    • Issues ECDSA P-256 certificates with embedded capabilities │
└─────────────────────────────┬───────────────────────────────────┘
                              │ vsock + TLS (rustls/ring)
┌──── GUEST VM (CID N) ───────▼───────────────────────────────────┐
│  authn-scope-agent                                               │
│    • Reads /etc/authn-scope/agent.json for entity list           │
│    • Generates per-entity ECDSA P-256 keypair + CSR             │
│    • Sends CSR over vsock TLS, stores signed cert + key         │
└─────────────────────────────────────────────────────────────────┘
```

## Crate Layout

| Crate | Role |
|---|---|
| `authn-scope-proto` | Shared wire types (`CertRequest`/`CertResponse`), capability structs, framing codec |
| `authn-scope-ca` | CA engine: init/load, CSR signing, JWT capability signer |
| `authn-scope-server` | Host CA daemon binary (`authn-scope-server`) |
| `authn-scope-agent` | Guest agent binary (`authn-scope-agent`) |

## Capability Mechanism

Capabilities are embedded in issued X.509 certificates as a custom extension
(**OID `1.3.6.1.4.1.99999.1`**) whose value is a compact JWT signed by the CA's
ECDSA P-256 private key.

### JWT Payload Example

```json
{
  "iss": "authn-scope-ca",
  "sub": "frontend-api",
  "vm":  "vm-frontend",
  "cid": 42,
  "iat": 1700000000,
  "exp": 1731536000,
  "caps": [
    {
      "target_vm":   "vm-backend",
      "target_cid":  10,
      "rpc_modules": ["auth", "storage"],
      "rpc_methods": ["auth.login", "storage.read"],
      "paths": [
        { "path": "/api/v1/data",  "access": ["read"] },
        { "path": "/api/v1/files", "access": ["read", "write"] }
      ]
    }
  ]
}
```

## Prerequisites

### Non-Nix Platforms
If you are developing on a standard Linux distribution (e.g. Ubuntu, Fedora, Arch), you must have the following installed:
- `rustc` and `cargo` (Rust toolchain 1.75+)
- `qemu-system-x86_64` (provided by `qemu` or `qemu-system-x86`)
- `gcc` and `pkg-config` (for standard library compilation)
- A Linux kernel with vsock support (`CONFIG_VHOST_VSOCK=y`)

### Nix Platforms
If you are using Nix, simply enter the development shell which natively provisions all required dependencies (including QEMU for the integration tests):
```bash
nix develop
```

## Build

```bash
cargo build --release --workspace
```

Output binaries:
- `target/release/authn-scope-server`
- `target/release/authn-scope-agent`
- `target/release/authn-scope-eval-test`

## Integration Testing

We provide a robust integration test script (`run_integration_test.sh`) that natively provisions a lightweight QEMU virtual machine to validate the end-to-end vsock architecture on **any** Linux platform.

This script directly mounts your host's root filesystem into the VM via `virtio-9p`, allowing the guest agent to execute natively against the host CA daemon over a real `vhost-vsock-pci` boundary without requiring any pre-built VM disk images.

To run the test:
```bash
# On Nix platforms (via devShell alias):
run-test

# On non-Nix platforms:
sudo ./run_integration_test.sh
```

## Quick Start

### 1. Host: Initialise the CA (one-time)

```bash
sudo authn-scope-server --init --config config-examples/host.json
# → Writes /etc/authn-scope/ca/ca-cert.pem and ca-key.pem
```

### 2. Host: Start the CA daemon

```bash
sudo authn-scope-server --config /etc/authn-scope/host.json
```

### 3. Guest: Run the agent

```bash
# First, copy the CA cert from the host to the guest (out-of-band)
scp host:/etc/authn-scope/ca/ca-cert.pem /etc/authn-scope/ca/ca-cert.pem

# Request certificates for all configured entities
sudo authn-scope-agent --config /etc/authn-scope/agent.json
```

## Configuration Reference

### Host (`host.json`)

| Field | Type | Description |
|---|---|---|
| `ca_cert_path` | string | Path to CA certificate PEM |
| `ca_key_path` | string | Path to CA private key PEM |
| `server_port` | number | vsock port to listen on |
| `cert_validity_days` | number | Default cert lifetime (days) |
| `vms` | object | Map of **CID string** → `VmEntry` |

**`VmEntry`**

| Field | Type | Description |
|---|---|---|
| `vm_name` | string | Human-readable VM name |
| `entities` | object | Map of entity name → `EntityPolicy` |

**`EntityPolicy`**

| Field | Type | Description |
|---|---|---|
| `caps` | array | List of `Capability` grants |
| `validity_days` | number? | Optional per-entity validity override |

### Agent (`agent.json`)

| Field | Type | Description |
|---|---|---|
| `server_ca_cert` | string | Path to CA cert for TLS pinning |
| `vsock_host_cid` | number | Host CID (default: 2) |
| `server_port` | number | Server vsock port |
| `entities` | array | List of `EntityEntry` |

**`EntityEntry`**

| Field | Type | Description |
|---|---|---|
| `name` | string | Entity name (must match host config) |
| `cert_path` | string | Where to write the signed cert |
| `key_path` | string | Where to write the private key |
| `ca_path` | string | Where to write the CA cert |
| `owner_uid` | number | File owner UID |
| `owner_gid` | number | File owner GID |
| `cert_mode` | string | Octal permissions for cert (default "0640") |
| `key_mode` | string | Octal permissions for key (default "0600") |

## Security Design Notes

- **No OpenSSL / no C crypto library**: all cryptography via `ring` (pure Rust, with asm optimisations); TLS via `rustls`.
- **CID validation**: the server cross-checks the CID claimed in the request payload against the actual vsock peer CID from the kernel — an attacker cannot spoof its own CID on the vsock layer.
- **Certificate pinning**: the agent uses a custom `ServerCertVerifier` that accepts only the exact CA certificate bytes — standard CA trust anchors are not used.
- **Capability JWT**: signed with the CA's ECDSA P-256 key using the IEEE P1363 fixed-length signature format (ES256). Any verifier with the CA's public key can validate capabilities without a separate PKI.
- **Key file permissions**: the CA private key is written with mode 0600; entity keys are stored with the configured mode (default 0600).
- **Root enforcement**: both binaries refuse to start without root privileges.

## Dependency Inventory (no C library deps)

| Crate | Purpose |
|---|---|
| `ring` | ECDSA P-256 signing/verification, random number generation |
| `rustls` | TLS 1.3 over vsock (ring backend) |
| `tokio-rustls` | Async TLS wrapping for tokio streams |
| `rcgen` | X.509 cert/CSR generation (uses ring) |
| `tokio-vsock` | Async vsock listener/connector |
| `tokio` | Async runtime |
| `serde` / `serde_json` | Serialisation |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |
| `thiserror` / `anyhow` | Error handling |
| `base64` | Base64url encoding for JWT |
