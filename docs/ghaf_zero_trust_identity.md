# Ghaf Zero-Trust Workload Identity: ghaf-secureid vs. SPIRE

## 1. Objective

This document evaluates the zero-trust identity requirements of Ghaf and compares newly proposed **`ghaf-secureid`** against **SPIRE (SPIFFE Runtime Environment)** as the identity provider and attestation engine.

---

## 2. Zero-Trust Requirements in Ghaf to issue identity to workloads for inter-vm communication

Securely issue identity to workloads running in each VM. The identity should adhere to the zero-trust architecture of Ghaf:
- **CA Location:** CA should run in either host or admin VM.
- **Node Attestation:** It must attest each VM node before issuing identity to workloads.
- **Time Synchronization:** It should handle timesync gracefully, and should void old issued certificates if a time reset happens.
- **Identity Rotation:** Identity should be rotated to minimize the risk of possible identity theft.
- **Resource Efficiency:** Should be CPU and memory efficient.
- **In-Memory Secrets:** Credentials by default should not be stored on disk.
- **Standard Distribution:** Should follow a standard mechanism to distribute identity so that workloads can easily adopt it.
- **NixOS Integration:** Should support deaclarative way to enable it.
---

## 3. Available Solutions: Requirement-by-Requirement Comparison

### Requirement 1: CA should run in either host/admin.
- **`ghaf-secureid`**:
  - By default, the CA runs on the host and uses `AF_VSOCK` to communicate with other VMs, eliminating network MITM attacks.
  - The CA can be moved to `AdminVM` by forwarding the vsock port in the host kernel, or by running over the built-in TCP transport without requiring vsock forwarding.
- **`SPIRE`**:
  - The SPIRE Server runs as a TCP daemon and can be placed in `AdminVM` or the host.
  - However, it requires a full TCP/IP network stack running, acan not issue identity to workloads which need identity in early stage of VM boot.

### Requirement 2: It must attest each VM node before issuing identity to workloads.
- **`ghaf-secureid`**:
  - Uses hardware vTPM 2.0 remote attestation to establish initial trust with Trust-On-First-Use (TOFU). In case of a compromised VM, untrusted processes cannot access credentials.
  - Also supports static X.509 certificates to establish initial trust between CA and VM nodes if TPM is absent.
- **`SPIRE`**:
  - Supports node attestation via plugins (`tpm`, `x509pop`, `join_token`, `k8s_psat` etc).
 
### Requirement 3: It should handle timesync gracefully, and should void old issued certificates if time reset happens.
- **`ghaf-secureid`**:
  - Features a dedicated vsock `TimeSyncNotification` channel. When a host clock shift occurs, the host broadcasts the notification; agents immediately void outdated credentials and proactively request fresh certificates before validity issues arise.
- **`SPIRE`**:
  - Relies entirely on the system OS clock and external NTP. No builtin mecahnism to handle clock sync. 
  - If a VM clock desynchronizes or jumps backward after a suspend/resume event, certificates fail validity checks until clock resynchronization occurs.

### Requirement 4: Identity should be rotated to minimize risk of possible identity theft.
- **`ghaf-secureid`**:
  - Issues short-lived certificates (configurable, e.g., 5–10 min TTL) and automatically rotates them in memory at 50% TTL.
  - Workloads use Spiffee compliant dynamic TLS callbacks for hot-reloading without connection drops.
- **`SPIRE`**:
  - Natively issues short-lived X.509-SVIDs rotated automatically at 50% TTL by the SPIRE Agent streaming updates over the Workload API.

### Requirement 5: Should be CPU/memory efficient.
- **`ghaf-secureid`**:
  - Written in pure Rust with zero OpenSSL dependencies and zero garbage collection.
  - Consumes **<10 MB RAM combined** (agent ~5 MB, server ~8 MB) with microsecond-level crypto operations.
- **`SPIRE`**:
  - Consumes **50–100+ MB RAM per VM**.

### Requirement 6: Credentials by default should not be stored on disk.
- **`ghaf-secureid`**:
  - Ephemeral ECDSA P-256 private keys and certificates are generated in memory and delivered strictly over a Unix Domain Socket (`/run/authn-scope/workload.sock`). Keys never touch persistent disk.
- **`SPIRE`**:
  - SPIRE Agent streams X.509-SVIDs in memory over a Unix Domain Socket; private keys reside in memory and are not persisted to disk by default.


### Requirement 7: Should follow some standard mechanism to distribute identity so that workloads can easily adopt it.
- **`ghaf-secureid`**:
  - Implements the official **SPIFFE Workload API standard** (`spiffe.workload.SpiffeWorkloadAPI` gRPC service over UDS). Workloads using standard libraries (`go-spiffe/v2`, Rust `spiffe` crate, Envoy SDS) integrate with zero code changes.
- **`SPIRE`**:
  - Is the reference implementation of the **SPIFFE Workload API standard**, natively supported by official SPIFFE libraries, Envoy, and service meshes.


### Requirement 8: NixOS Integration
- **`ghaf-secureid (Seamless & 100% Declarative)`**:
  - Zero Registration Delays: Supports fully declarative configuration. Workload policies, selectors, and VM mappings are pre-compiled into immutable Nix store config (host.json); the server can issue identity to authorized workloads dynamically during the early-boot vsock handshake (sysinit.target), so workloads are ready immediately on boot with no extra registration services or scripts.
  - Zero Auxiliary Bootstrap Services: The Root CA trust bundle is delivered in-band over the authenticated vsock/TCP channel.

- **`SPIRE (Auxiliary Services & Startup Delays)`**:
  - Runtime Registration Bottlenecks: Workloads cannot obtain identities until an imperative registration service/script executes spire-server entry create at runtime, creating complex systemd dependency chains and noticeable service startup delays.
  - Auxiliary Bundle & Database Overhead: Requires an extra custom service to distribute the bootstrap CA trust bundle to all VM agents before they can connect. Though it one time service, but it is shared through shared file system path.

## 4. Important Caveat: 
ghaf-secureid is fundamentally built on the architectural principle that the Host runs on trusted compute.

## 5. Next:
Separate each feature as Rust feature to enable selective build.
