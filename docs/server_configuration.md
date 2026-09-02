# VM-AuthN-Scope Host Server Configuration Reference

This document describes the configuration options for the **VM-AuthN-Scope Host Server** (`authn-scope-server`). The configuration is stored as JSON (default location `/etc/authn-scope/host.json`).

## Configuration Options

| Option              | Type    | Description                                                                                           | Default |
| :---                | :---    | :---------------------------------------------------------------------------------------------------- | :------ |
| `ca_cert_path`      | `string` | Path to the PEM‑encoded CA root certificate (or where it will be generated).                         | *required* |
| `ca_key_path`       | `string` | Path to the PEM‑encoded CA private key (or where it will be generated).                              | *required* |
| `server_port`       | `integer`| The vsock port on which the server listens (must be **< 1000**).                                    | `900` |
| `peer_port`         | `integer`| Expected source port for guest agent CSR requests. Connections from other ports are rejected.        | `901` |
| `notification_port` | `integer`| Expected source port for guest agent notification subscriptions.                                      | `902` |
| `vms`               | `object` | Map of VM entries keyed by VM name. See **VM Configuration** below.                                   | `{}` |

---

## VM Configuration

Each entry under `vms` represents a guest VM.

```json
{
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
      "ttl_minutes": 10
    }
  }
}
```

| Field          | Type    | Description                                                                                       |
| :---           | :---    | :------------------------------------------------------------------------------------------------ |
| `vm_cid`       | `integer`| The vsock CID of the guest VM (used to verify the caller).                                         |
| `ip`           | `string` | Optional IP address embedded in issued certificates (as an IP SAN).                                |
| `attestation`  | `object` | Optional vTPM attestation policy (see **Attestation Policy** below).                              |
| `identities`   | `object` | Map of **Identity** definitions (see below).                                                      |

### Attestation Policy (`attestation`)

| Field      | Type   | Description | Default |
| :---       | :---   | :---        | :---    |
| `required` | `bool` | When `true`, the guest VM must present a valid vTPM quote during the handshake. If `false` or omitted, CID-only trust is used. | `false` |

### Identity Definition

| Field          | Type    | Description                                                                                       |
| :---           | :---    | :------------------------------------------------------------------------------------------------ |
| `selector`     | `string`| Comma‑separated selector string used by the **agent** to match the requesting process. Supported components: `unix:user:<name>`, `unix:group:<name>`, `unix:bin:<path>`, `systemd:unitname:<name>`, `systemd:unitpath:<path>`. |
| `ttl_minutes`  | `integer`| Lifetime of the issued certificate in **minutes**. The server includes this in the certificate validity period. |

---

## CLI Options

```bash
# Start server using default /etc/authn-scope/host.json
sudo authn-scope-server

# Start server with custom config and generate new CA keys
sudo authn-scope-server --config /path/to/host.json --genkey

# Reset attestation state (TOFU) for a specific VM after image updates (automatically re-seals known_vms.json)
sudo authn-scope-server --reset-attestation local-vm
```

---

## Hardware-Backed Trust Architecture

1. **Guest vTPM Attestation (TOFU)**:
   - When a guest VM connects, the server sends a cryptographically secure random nonce (`AttestationChallenge`).
   - The guest agent uses its vTPM Attestation Key (AK) to sign a quote over PCRs 0, 1, 2, 3, 7 and the nonce.
   - The server verifies the RSA signature and nonce in pure Rust (no host TPM dependency for verification).
   - On the first connection, the server records the PCR digest (Trust-On-First-Use) into `/var/lib/authn-scope/known_vms.json`.
   - On subsequent connections, the quote must match the recorded digest. If the guest firmware or bootloader was tampered with, attestation fails and the handshake is rejected.
2. **Host TPM Sealing of TOFU State (`known_vms.json`)**:
   - Whenever `known_vms.json` is updated or learned, its SHA-256 hash is sealed into the host's own TPM (`known_vms_seal.json`).
   - On startup, the server loads `known_vms.json` and verifies the unsealed hash matches the file contents, preventing unauthorized modification of trusted VM baselines on disk.

---

## Migration Guide

* **Remove `cert_validity_days`** – validity is now driven per‑identity via `ttl_minutes`.
* **Replace capability blocks** (`caps`) with a `selector` string and `ttl_minutes` per identity.
* **Enable vTPM attestation** by adding `"attestation": { "required": true }` to your VM definitions.

---

## Security Considerations

* The server runs as `root` to bind a privileged vsock port (`< 1000`).
* It validates the source CID against `vm_cid` and the source port against `peer_port`.
* Combined with vTPM attestation and host config sealing, it guarantees mutual hardware-backed trust between host and guest.

---

**References**
* Sample host configuration – `config-examples/host.json`.
* Wire protocol – `libs/rust-libs/authn-scope-proto/src/wire.rs`.
* Agent implementation – `apps/rust-apps/authn-scope-agent/src/client.rs`.
* TPM library – `libs/rust-libs/authn-scope-tpm/src/lib.rs`.
