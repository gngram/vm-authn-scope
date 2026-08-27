# VM-AuthN-Scope Guest Agent Configuration Reference

This document describes the configuration and operational model of the **VM-AuthN-Scope Guest Agent** (`authn-scope-agent`). The configuration is stored as JSON (default location `/etc/authn-scope/agent.json`).

## Configuration Options

| Option                | Type    | Description                                                                          | Default |
| :---                  | :---    | :----------------------------------------------------------------------------------- | :------ |
| `vm_name`             | `string`| Human‑readable name of this VM. Sent to the host during the handshake.                 | *required* |
| `server_port`         | `integer`| The vsock port on which the host CA server is listening.                             | `900` |
| `client_port`         | `integer`| The local vsock port the agent binds to when dialing the host.                        | `901` |
| `workload_api_socket` | `string`| Path of the Unix‑Domain Socket exposing the **Workload API** to local applications.  | `"/run/authn-scope/workload.sock"` |

---

## vTPM Attestation & Trust

On startup, the agent checks for an available TPM 2.0 device (looking for `/dev/tpmrm0` or `/dev/tpm0`):

1. **Attestation Key (AK) Creation**: If a TPM is found, the agent creates an RSA 2048-bit restricted signing key under the TPM's Endorsement Hierarchy and persists it at handle `0x81010002`.
2. **Handshake with Public AK**: The agent connects to the host server over vsock and sends its `vm_name` along with the base64-encoded public part of its AK.
3. **Challenge Response**: When the host server sends an `AttestationChallenge` with a cryptographic nonce, the agent performs a `TPM2_Quote` over PCRs 0, 1, 2, 3, 7 and the nonce, returning the signed quote to the host.
4. **Graceful Fallback**: If no TPM is detected in the VM, the agent performs a standard handshake without AK data (succeeds if the server's policy does not mark attestation as required for this VM).

---

## Host Hypervisor Setup for Guest vTPM

To attach a vTPM device to a guest VM from the host:

### 1. Initialize vTPM State on Host
```bash
mkdir -p /var/lib/swtpm-guest1
swtpm_setup \
  --tpm-state /var/lib/swtpm-guest1 \
  --tpm2 \
  --create-ek-cert \
  --create-platform-cert
```

### 2. Start `swtpm` Daemon
```bash
swtpm socket \
  --tpmstate dir=/var/lib/swtpm-guest1 \
  --ctrl type=unixio,path=/var/run/swtpm-guest1.sock \
  --tpm2 \
  --flags not-need-init \
  --daemon
```

### 3. Launch QEMU with vTPM and vsock
```bash
qemu-system-x86_64 \
  -enable-kvm -m 2048 -smp 2 \
  -drive file=guest.qcow2,if=virtio \
  -device vhost-vsock-pci,guest-cid=3 \
  -chardev socket,id=chrtpm,path=/var/run/swtpm-guest1.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0
```

> **ARM64 / aarch64**: Use `-device tpm-tis-device,tpmdev=tpm0` or `tpm-crb`.

### 4. Declarative NixOS VM Option
```nix
virtualisation.vmVariant.virtualisation.qemu.options = [
  "-device vhost-vsock-pci,guest-cid=3"
  "-chardev socket,id=chrtpm,path=/var/run/swtpm-guest1.sock"
  "-tpmdev emulator,id=tpm0,chardev=chrtpm"
  "-device tpm-tis,tpmdev=tpm0"
];
```

### 5. Multi-VM Socket Architecture & Isolation

| Socket Type | Shared Across VMs? | Scope & Reason |
|---|---|---|
| **vTPM Socket (`swtpm`)** | ❌ **No (1 per VM)** | **Isolated**. Each VM has its own hardware registers (PCRs 0–23), NVRAM, and Endorsement/Attestation Keys. Sharing a vTPM socket causes PCR measurement corruption, session race conditions, and cryptographic identity collisions. |
| **Host CA vsock (`vsock:900`)** | ✅ **Yes (Shared)** | **Multiplexed**. All VMs dial `host_cid=2, port=900`. The server identifies callers using their distinct Linux vsock `CID` (e.g. CID 3, CID 4). |
| **Workload UDS (`workload.sock`)** | ✅ **Yes (Per-VM)** | **Shared by local processes**. All workloads inside VM-1 share VM-1's `/run/authn-scope/workload.sock`. The agent inspects `SO_PEERCRED` to identify each calling process. |

---

## Workload API Overview

The agent runs a lightweight JSON‑RPC server on the Unix Domain Socket defined by `workload_api_socket` (default: `/run/authn-scope/workload.sock` with `0666` permissions). Applications obtain X.509 credentials by sending a single JSON line:

```json
{ "type": "fetch" }
```

The agent inspects the calling process (UID, GID, executable binary path via `/proc/<pid>/exe`, systemd unit via `/proc/<pid>/cgroup`) and selects the matching identity configured on the host server.

Response on success:
```json
{
  "status": "success",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

Response on error (or if process fails attestation):
```json
{
  "status": "error",
  "message": "Attestation failed: no workload selector matches UID '1001', GID '1001'..."
}
```

---

## Automatic Credential Rotation

* Each identity on the host defines a `ttl_minutes` validity.
* The agent caches credentials in memory and automatically requests a fresh certificate when 50% of the validity duration has passed.
* Applications calling the Workload API always receive valid, fresh credentials without needing to implement their own rotation logic.
* Private keys and certificates remain ephemeral in memory unless explicitly written out by the application.

---

## Security Considerations

* The agent runs as `root` only to bind the client vsock port (`901`) and access `/proc/<pid>/cgroup` of calling processes.
* The Workload API enforces least privilege by ensuring workloads only receive credentials matching their exact POSIX / systemd identity.

---

**References**
* Sample `agent.json` – `config-examples/agent.json`.
* Wire protocol – `libs/rust-libs/authn-scope-proto/src/wire.rs`.
* TPM library – `libs/rust-libs/authn-scope-tpm/src/lib.rs`.
* Workload client libraries – `libs/rust-libs/authn-scope-workload` (Rust) and `libs/go-libs/authn-scope-workload` (Go).
