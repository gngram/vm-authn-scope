#!/usr/bin/env bash
# ==============================================================================
# Multi-VM Hardware Dual-Attestation & Host TPM Sealing Integration Test
# ==============================================================================
# This script executes an end-to-end integration test demonstrating:
# 1. Host Physical TPM 2.0 Sealing (Config & TOFU State).
# 2. Host TPM Master Key Sealing of VM vTPM State Encryption Keys (AES-256).
# 3. Scalable 'Load -> Unseal -> Flush' TPM Memory Management (Supports 12+ VMs).
# 4. Multi-VM Nonce-based Hardware Attestation & Credential Issuance.
# ==============================================================================
set -e

# Ensure execution as root for attaching vhost-vsock, running swtpm, and 9p filesystem passthrough
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (or use sudo) to attach /dev/vhost-vsock to QEMU."
    exec sudo --preserve-env=PKG_CONFIG_PATH,PATH,RUST_LOG,VSOCK_HOST_CID,TPM2TOOLS_TCTI "$0" "$@"
fi

# Auto-discover tss2-sys pkg-config path from Nix store if not already set
if ! pkg-config --exists tss2-sys 2>/dev/null; then
    NIX_TSS_PC=$(find /nix/store -maxdepth 4 -name "tss2-sys.pc" 2>/dev/null | head -n 1)
    if [ -n "$NIX_TSS_PC" ]; then
        NIX_TSS_DIR=$(dirname "$NIX_TSS_PC")
        export PKG_CONFIG_PATH="$NIX_TSS_DIR${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    fi
fi

WORKSPACE_DIR="$(pwd)"

# ==============================================================================
# SECTION 1: Build the Workspace Binaries
# ==============================================================================
# Builds both Rust and Go workspace packages in release mode.
# If invoked via sudo, drops permissions to SUDO_USER for the build step.
echo "=> 1. Building the Rust & Go workspace binaries..."
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" cargo build --release
    sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" bash -c "cd libs/go-libs/authn-scope-evaluator && go build -o ../../../target/release/authn-scope-eval-test-go ./cmd/authn-scope-eval-test-go"
else
    cargo build --release
    cd libs/go-libs/authn-scope-evaluator && go build -o ../../../target/release/authn-scope-eval-test-go ./cmd/authn-scope-eval-test-go && cd ../../..
fi

# ==============================================================================
# SECTION 2: Setup Test Environment & Host CA Configuration
# ==============================================================================
# Prepares isolated state directories for the Host TPM, VM vTPMs, logs, and keys.
echo "=> 2. Setting up test host configuration & state directories..."
rm -rf "$WORKSPACE_DIR/test-result"
rm -f "$WORKSPACE_DIR"/vm-*.qcow2 "$WORKSPACE_DIR"/authn-scope*.qcow2
mkdir -p "$WORKSPACE_DIR/test-result/temp"
mkdir -p "$WORKSPACE_DIR/test-result/logs"
mkdir -p "$WORKSPACE_DIR/test-result/state"
mkdir -p "$WORKSPACE_DIR/test-result/host-tpm"
cd "$WORKSPACE_DIR"

# Write host server configuration:
# - Binds CA server to vsock port 900 (peer verification on port 901)
# - Declares authorized VM identities with Attestation Required:
#     • vm-1 (CID=3): Allowed workload identity 'service-a'
#     • vm-2 (CID=4): Allowed workload identity 'service-b'
cat <<JSON >"$WORKSPACE_DIR/test-result/temp/test-host.json"
{
  "ca_cert_path": "$WORKSPACE_DIR/test-result/ca-cert.pem",
  "ca_key_path": "$WORKSPACE_DIR/test-result/ca-key.pem",
  "server_port": 900,
  "peer_port": 901,
  "vms": {
    "vm-1": {
      "vm_cid": 3,
      "ip": "127.0.0.1",
      "attestation": {
        "required": true
      },
      "identities": {
        "service-a": {
          "selector": "unix:user:service-a,unix:group:service-a",
          "ttl_minutes": 10
        }
      }
    },
    "vm-2": {
      "vm_cid": 4,
      "ip": "127.0.0.1",
      "attestation": {
        "required": true
      },
      "identities": {
        "service-b": {
          "selector": "unix:user:service-b,unix:group:service-b",
          "ttl_minutes": 10
        }
      }
    }
  }
}
JSON

# Direct server state storage (known_vms.json & known_vms_seal.json) to test directory
export AUTHN_SCOPE_STATE_DIR="$WORKSPACE_DIR/test-result/state"

# ==============================================================================
# SECTION 3: Initialize Host Physical TPM 2.0 Emulator
# ==============================================================================
# Starts an emulator representing the Host Motherboard's Physical TPM 2.0 chip.
# Used by the CA Server to seal configuration and TOFU learned VM state.
echo "=> 3. Starting host TPM emulator for server config & TOFU state sealing..."
rm -rf "$WORKSPACE_DIR/test-result/host-tpm"
mkdir -p "$WORKSPACE_DIR/test-result/host-tpm"
swtpm_setup --tpm-state "$WORKSPACE_DIR/test-result/host-tpm" --tpm2 --create-ek-cert --create-platform-cert 2>/dev/null || true
swtpm socket --tpmstate dir="$WORKSPACE_DIR/test-result/host-tpm" \
    --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --flags not-need-init >"$WORKSPACE_DIR/test-result/logs/swtpm-host.log" 2>&1 &
HOST_SWTPM_PID=$!
sleep 1

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c 2>/dev/null || true
export RUST_LOG='info'

# ==============================================================================
# SECTION 4: Start Host CA Server
# ==============================================================================
# Launches authn-scope-server in the background. On startup, it:
# 1. Derives/loads the Host Attestation Key (AK).
# 2. Seals its configuration into the Host TPM.
# 3. Listens on vsock port 900 for VM handshakes and credential requests.
echo "=> 4. Starting host CA server in background (sealing config and generating keys)..."
./target/release/authn-scope-server --config "$WORKSPACE_DIR/test-result/temp/test-host.json" --genkey >"$WORKSPACE_DIR/test-result/logs/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID $HOST_SWTPM_PID $VM1_SWTPM_PID $VM2_SWTPM_PID 2>/dev/null || true; rm -f /tmp/swtpm-vm1.sock /tmp/swtpm-vm2.sock' EXIT

sleep 2 # Allow server to bind and initialize keys

# ==============================================================================
# SECTION 5: Host TPM Key Sealing & Scalable vTPM Startup (Supports 12+ VMs)
# ==============================================================================
# SCALABILITY ARCHITECTURE:
# To support 12+ concurrent VMs without exhausting the physical TPM's transient RAM
# slots (which typically holds only 3-4 objects), we execute an atomic lifecycle:
#   1. Generate fresh random 256-bit AES master key for the VM.
#   2. Seal the AES key into Host TPM (produces .pub metadata and .priv ciphertext).
#   3. Wipe the raw plaintext key immediately.
#   4. At boot: Load object -> Unseal AES key to memory -> FLUSH context immediately.
#   5. Launch swtpm with AES-256-CBC encrypted NVRAM state.
echo "=> 5. Sealing VM vTPM encryption keys into Host Hardware TPM & starting encrypted emulators..."

# Flush any leftover transient handles from previous runs and persist Primary Key to NVRAM handle 0x81000001
tpm2_flushcontext -t 2>/dev/null || true
tpm2_evictcontrol -C o -c 0x81000001 2>/dev/null || true
tpm2_createprimary -C o -c /tmp/srk.ctx 2>/dev/null || true
tpm2_evictcontrol -C o -c /tmp/srk.ctx 0x81000001 2>/dev/null || true
rm -f /tmp/srk.ctx
tpm2_flushcontext -t 2>/dev/null || true

# Helper function to provision, seal, and start an encrypted vTPM instance
start_encrypted_vtpm() {
    local vm_id="$1"
    local socket_path="/tmp/swtpm-${vm_id}.sock"
    local state_dir="$WORKSPACE_DIR/test-result/${vm_id}-tpm"
    local key_file="$WORKSPACE_DIR/test-result/temp/${vm_id}.key"
    local pub_file="$WORKSPACE_DIR/test-result/state/${vm_id}_key.pub"
    local priv_file="$WORKSPACE_DIR/test-result/state/${vm_id}_key.priv"

    # Step 5a: Generate random 256-bit AES master key & seal into Host TPM under persistent SRK 0x81000001
    openssl rand -hex 32 >"/tmp/${vm_id}_raw.key"
    chmod 0600 "/tmp/${vm_id}_raw.key"
    tpm2_create -C 0x81000001 \
        -i "/tmp/${vm_id}_raw.key" \
        -u "$pub_file" \
        -r "$priv_file" 2>/dev/null
    rm -f "/tmp/${vm_id}_raw.key"
    echo "   [+] ${vm_id} vTPM Master Key sealed into Host Hardware TPM (${pub_file}, ${priv_file})"

    # Step 5b: Ephemeral Unseal & Immediate Context Flush (Frees TPM slot for next VM)
    tpm2_load -C 0x81000001 \
        -u "$pub_file" \
        -r "$priv_file" \
        -c "/tmp/${vm_id}_key.ctx" 2>/dev/null

    tpm2_unseal -c "/tmp/${vm_id}_key.ctx" >"$key_file" 2>/dev/null
    rm -f "/tmp/${vm_id}_key.ctx"
    tpm2_flushcontext -t 2>/dev/null || true
    chmod 0600 "$key_file"

    # Step 5c: Initialize and launch swtpm instance with AES-256 encrypted NVRAM
    rm -rf "$state_dir" "$socket_path"
    mkdir -p "$state_dir"
    swtpm_setup --tpm-state "$state_dir" --tpm2 --keyfile "$key_file" --cipher aes-256-cbc --create-ek-cert --create-platform-cert --create-config-files skip-if-exist 2>/dev/null || true
    swtpm socket --tpmstate dir="$state_dir" \
        --key file="$key_file",mode=aes-256-cbc,format=hex \
        --ctrl type=unixio,path="$socket_path" \
        --tpm2 \
        --flags not-need-init >"$WORKSPACE_DIR/test-result/logs/swtpm-${vm_id}.log" 2>&1 &
}

# Start VM-1 encrypted vTPM
start_encrypted_vtpm "vm1"
VM1_SWTPM_PID=$!

# Start VM-2 encrypted vTPM (instantly reuses freed TPM slot)
start_encrypted_vtpm "vm2"
VM2_SWTPM_PID=$!

# Persistent SRK 0x81000001 remains ready in NVRAM for dynamic VM spawns (uses 0 transient RAM slots)

# ==============================================================================
# SECTION 6: Build NixOS Guest VMs
# ==============================================================================
# Builds the NixOS QEMU runner images for VM-1 and VM-2.
echo "=> 6. Building NixOS Guest VMs (VM-1 and VM-2)..."
rm -f target/result-vm1 target/result-vm2
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm1.nix -o target/result-vm1
    sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm2.nix -o target/result-vm2
else
    nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm1.nix -o target/result-vm1
    nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm2.nix -o target/result-vm2
fi

rm -f "$WORKSPACE_DIR/test-result/vm1-result-summary" "$WORKSPACE_DIR/test-result/vm2-result-summary"

# ==============================================================================
# SECTION 7: Launch Guest VMs Concurrently
# ==============================================================================
# Starts VM-1 and VM-2 under QEMU attached to their respective vTPM sockets and vsock.
echo "=> 7. Launching Guest VM-1 and Guest VM-2 concurrently..."
./target/result-vm1/bin/run-vm-1-vm >"$WORKSPACE_DIR/test-result/logs/vm1.log" 2>&1 &
VM1_PID=$!

./target/result-vm2/bin/run-vm-2-vm >"$WORKSPACE_DIR/test-result/logs/vm2.log" 2>&1 &
VM2_PID=$!

trap 'kill $VM1_PID $VM2_PID $SERVER_PID $HOST_SWTPM_PID $VM1_SWTPM_PID $VM2_SWTPM_PID 2>/dev/null || true; rm -f /tmp/swtpm-vm1.sock /tmp/swtpm-vm2.sock' EXIT INT TERM

# ==============================================================================
# SECTION 8: Await Attestation, Hardware Sealing & Verification
# ==============================================================================
# Polls until both VMs finish their local boot, dual attestation, and workload tests.
echo "=> 8. Waiting for attestation & credential evaluation on both VMs (up to 120s)..."
TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ -f "$WORKSPACE_DIR/test-result/vm1-result-summary" ] && [ -f "$WORKSPACE_DIR/test-result/vm2-result-summary" ]; then
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ $((ELAPSED % 10)) -eq 0 ]; then
        echo "   ... waiting for VMs to complete attestation & tests (${ELAPSED}s / ${TIMEOUT}s elapsed)"
    fi
done

echo "======================================================"
echo "                   TEST RESULTS                       "
echo "======================================================"
echo "Host Server Log:"
cat "$WORKSPACE_DIR/test-result/logs/server.log"
echo "------------------------------------------------------"
echo "Host TPM Seal State (known_vms_seal.json):"
[ -f "$WORKSPACE_DIR/test-result/state/known_vms_seal.json" ] && cat "$WORKSPACE_DIR/test-result/state/known_vms_seal.json" || echo "Not found"
echo "------------------------------------------------------"
echo "Host TOFU Learned VMs (known_vms.json):"
[ -f "$WORKSPACE_DIR/test-result/state/known_vms.json" ] && cat "$WORKSPACE_DIR/test-result/state/known_vms.json" || echo "Not found"
echo "------------------------------------------------------"
echo "VM vTPM Encryption Keys Sealed in Host Hardware TPM:"
[ -f "$WORKSPACE_DIR/test-result/state/vm1_key.pub" ] && echo "VM-1 Key Sealed Blob: $(wc -c <"$WORKSPACE_DIR/test-result/state/vm1_key.pub") bytes pub, $(wc -c <"$WORKSPACE_DIR/test-result/state/vm1_key.priv") bytes priv" || echo "VM-1 seal not found"
[ -f "$WORKSPACE_DIR/test-result/state/vm2_key.pub" ] && echo "VM-2 Key Sealed Blob: $(wc -c <"$WORKSPACE_DIR/test-result/state/vm2_key.pub") bytes pub, $(wc -c <"$WORKSPACE_DIR/test-result/state/vm2_key.priv") bytes priv" || echo "VM-2 seal not found"
echo "------------------------------------------------------"
echo "VM Encrypted vTPM States on Host Disk (AES-256):"
[ -f "$WORKSPACE_DIR/test-result/vm1-tpm/tpm2-00.permall" ] && {
    echo "VM-1 NVRAM (Ciphertext):"
    head -c 32 "$WORKSPACE_DIR/test-result/vm1-tpm/tpm2-00.permall" | xxd
} || echo "VM1 NVRAM not found"
[ -f "$WORKSPACE_DIR/test-result/vm2-tpm/tpm2-00.permall" ] && {
    echo "VM-2 NVRAM (Ciphertext):"
    head -c 32 "$WORKSPACE_DIR/test-result/vm2-tpm/tpm2-00.permall" | xxd
} || echo "VM2 NVRAM not found"
echo "======================================================"

VM1_OK=false
VM2_OK=false

if [ -f "$WORKSPACE_DIR/test-result/vm1-result-summary" ] && [ "$(cat "$WORKSPACE_DIR/test-result/vm1-result-summary")" = "SUCCESS" ]; then
    VM1_OK=true
fi

if [ -f "$WORKSPACE_DIR/test-result/vm2-result-summary" ] && [ "$(cat "$WORKSPACE_DIR/test-result/vm2-result-summary")" = "SUCCESS" ]; then
    VM2_OK=true
fi

if [ "$VM1_OK" = true ] && [ "$VM2_OK" = true ]; then
    echo "======================================================"
    echo " Multi-VM Integration Test: SUCCESS"
    echo " Both VM-1 and VM-2 attested via isolated vTPMs!"
    echo "======================================================"
    echo ""
    echo "==> BOTH VMs ARE CURRENTLY RUNNING FOR LIVE INSPECTION!"
    echo "    • VM-1 (CID=3): service-a credentials issued and verified"
    echo "    • VM-2 (CID=4): service-b credentials issued and verified"
    echo "    • Root auto-login is active on both VM consoles."
    echo ""
    echo "Press [ENTER] to terminate both VMs and finish the test..."
    read -r _ || true
    chmod -R 777 "$WORKSPACE_DIR/test-result" 2>/dev/null || true
    exit 0
else
    echo "Multi-VM Test FAILED!"
    echo "--- VM-1 Log ---"
    cat "$WORKSPACE_DIR/test-result/logs/vm1.log" 2>/dev/null || true
    echo "--- VM-2 Log ---"
    cat "$WORKSPACE_DIR/test-result/logs/vm2.log" 2>/dev/null || true
    echo "Press [ENTER] to terminate VMs after inspecting..."
    read -r _ || true
    chmod -R 777 "$WORKSPACE_DIR/test-result" 2>/dev/null || true
    exit 1
fi
