#!/usr/bin/env bash
# ==============================================================================
# Multi-VM Hardware Dual-Attestation & Host TPM Sealing Integration Test
# ==============================================================================
set -e

# Disable ANSI color escape formatting from Rust tracing loggers
export NO_COLOR=1
export RUST_LOG_STYLE=never

# Ensure execution as root for attaching vhost-vsock, running swtpm, and 9p filesystem passthrough
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (or use sudo) to attach /dev/vhost-vsock to QEMU."
    exec sudo --preserve-env=PKG_CONFIG_PATH,PATH,RUST_LOG,NO_COLOR,RUST_LOG_STYLE,VSOCK_HOST_CID,TPM2TOOLS_TCTI,DISPLAY,XAUTHORITY "$0" "$@"
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
TEST_RESULT_DIR="$WORKSPACE_DIR/test-result"
FULL_LOG_FILE="$TEST_RESULT_DIR/integration_test_full.log"

# Clean up stale test state directory to prevent TOFU AK key mismatch from previous runs
rm -rf "$TEST_RESULT_DIR"
mkdir -p "$TEST_RESULT_DIR/logs" "$TEST_RESULT_DIR/temp" "$TEST_RESULT_DIR/state" "$TEST_RESULT_DIR/host-tpm"
rm -f "$FULL_LOG_FILE"

# Helper function to append structured step headers and logs (with ANSI codes stripped for clean Mousepad rendering)
append_log_section() {
    local step_title="$1"
    local log_content="$2"
    local clean_content
    clean_content=$(echo "$log_content" | sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g')
    {
        echo "=================================================================="
        printf "%s\n" "$step_title"
        echo "=================================================================="
        echo "Log follows"
        echo ""
        echo "$clean_content"
        echo ""
    } >> "$FULL_LOG_FILE"
}

# Helper to open full log file in Mousepad (or graphical editor fallback)
open_log_in_editor() {
    local log_path="$1"
    if [ -n "$SUDO_USER" ] && [ -n "$DISPLAY" ]; then
        sudo -u "$SUDO_USER" env "DISPLAY=$DISPLAY" "XAUTHORITY=$XAUTHORITY" mousepad "$log_path" >/dev/null 2>&1 &
    elif command -v mousepad >/dev/null 2>&1; then
        mousepad "$log_path" >/dev/null 2>&1 &
    elif command -v geany >/dev/null 2>&1; then
        geany "$log_path" >/dev/null 2>&1 &
    elif command -v gedit >/dev/null 2>&1; then
        gedit "$log_path" >/dev/null 2>&1 &
    elif command -v kate >/dev/null 2>&1; then
        kate "$log_path" >/dev/null 2>&1 &
    fi
}

# ==============================================================================
# SECTION 1: Build the Workspace Binaries
# ==============================================================================
echo "=> 1. Building the Rust & Go workspace binaries..."
BUILD_OUT=""
if [ -n "$SUDO_USER" ]; then
    BUILD_OUT=$(
        sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" "NO_COLOR=1" "RUST_LOG_STYLE=never" cargo build --release 2>&1
        sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" bash -c "cd testapp/authn-scope-evaluator-go && go build -o ../../target/release/authn-scope-eval-test-go ./cmd/authn-scope-eval-test-go" 2>&1
        sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" bash -c "cd testapp/grpc-app-go && go build -o ../../target/release/grpc-app-go main.go" 2>&1
    )
else
    BUILD_OUT=$(
        cargo build --release 2>&1
        cd testapp/authn-scope-evaluator-go && go build -o ../../target/release/authn-scope-eval-test-go ./cmd/authn-scope-eval-test-go && cd ../.. 2>&1
        cd testapp/grpc-app-go && go build -o ../../target/release/grpc-app-go main.go && cd ../.. 2>&1
    )
fi
append_log_section "Workspace Binaries Build" "$BUILD_OUT"

# ==============================================================================
# SECTION 2: Setup Test Environment & Host CA Configuration
# ==============================================================================
echo "=> 2. Setting up test host configuration & state directories..."
rm -f "$WORKSPACE_DIR"/vm-*.qcow2 "$WORKSPACE_DIR"/authn-scope*.qcow2
cd "$WORKSPACE_DIR"

cat <<JSON >"$TEST_RESULT_DIR/temp/test-host.json"
{
  "ca_cert_path": "$TEST_RESULT_DIR/ca-cert.pem",
  "ca_key_path": "$TEST_RESULT_DIR/ca-key.pem",
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
          "ttl_minutes": 1
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
          "ttl_minutes": 1
        }
      }
    }
  }
}
JSON

export AUTHN_SCOPE_STATE_DIR="$TEST_RESULT_DIR/state"
append_log_section "Test Host Configuration (test-host.json)" "$(cat "$TEST_RESULT_DIR/temp/test-host.json")"

# ==============================================================================
# SECTION 3: Initialize Host Physical TPM 2.0 Emulator
# ==============================================================================
echo "=> 3. Starting host TPM emulator for server config & TOFU state sealing..."
rm -rf "$TEST_RESULT_DIR/host-tpm"
mkdir -p "$TEST_RESULT_DIR/host-tpm"

SWTPM_HOST_SETUP_OUT=$(swtpm_setup --tpm-state "$TEST_RESULT_DIR/host-tpm" --tpm2 --create-ek-cert --create-platform-cert >/dev/null 2>&1 || true)
swtpm socket --tpmstate dir="$TEST_RESULT_DIR/host-tpm" \
    --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --flags not-need-init >"$TEST_RESULT_DIR/logs/swtpm-host.log" 2>&1 &
HOST_SWTPM_PID=$!
sleep 1

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
TPM_STARTUP_OUT=$(tpm2_startup -c >/dev/null 2>&1 || true)
export RUST_LOG='info'

append_log_section "Host TPM Emulator Startup" "Swtpm started on tcp:2321/2322 (PID: $HOST_SWTPM_PID)\nSetup Output:\n$SWTPM_HOST_SETUP_OUT\nStartup Output:\n$TPM_STARTUP_OUT"

# ==============================================================================
# SECTION 4: Start Host CA Server
# ==============================================================================
echo "=> 4. Starting host CA server in background..."
NO_COLOR=1 RUST_LOG_STYLE=never ./target/release/authn-scope-server --config "$TEST_RESULT_DIR/temp/test-host.json" --genkey >"$TEST_RESULT_DIR/logs/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID $HOST_SWTPM_PID $VM1_SWTPM_PID $VM2_SWTPM_PID 2>/dev/null || true; rm -f /tmp/swtpm-vm1.sock /tmp/swtpm-vm2.sock' EXIT

sleep 2
append_log_section "Host CA Server Startup" "authn-scope-server launched on vsock:900 (PID: $SERVER_PID)"

# ==============================================================================
# SECTION 5: Host TPM Key Sealing & Scalable vTPM Startup
# ==============================================================================
echo "=> 5. Sealing VM vTPM encryption keys into Host Hardware TPM & starting encrypted emulators..."

tpm2_flushcontext -t >/dev/null 2>&1 || true
if tpm2_getcap handles-persistent 2>/dev/null | grep -q "0x81000001"; then
    tpm2_evictcontrol -C o -c 0x81000001 >/dev/null 2>&1 || true
fi

tpm2_createprimary -C o -c /tmp/srk.ctx >/dev/null 2>&1 || true
tpm2_evictcontrol -C o -c /tmp/srk.ctx 0x81000001 >/dev/null 2>&1 || true
rm -f /tmp/srk.ctx
tpm2_flushcontext -t >/dev/null 2>&1 || true

SEAL_LOG="Persistent SRK 0x81000001 initialized in Host TPM NVRAM\n"

start_encrypted_vtpm() {
    local vm_id="$1"
    local socket_path="/tmp/swtpm-${vm_id}.sock"
    local state_dir="$TEST_RESULT_DIR/${vm_id}-tpm"
    local key_file="$TEST_RESULT_DIR/temp/${vm_id}.key"
    local pub_file="$TEST_RESULT_DIR/state/${vm_id}_key.pub"
    local priv_file="$TEST_RESULT_DIR/state/${vm_id}_key.priv"

    openssl rand -hex 32 >"/tmp/${vm_id}_raw.key"
    chmod 0600 "/tmp/${vm_id}_raw.key"
    tpm2_create -C 0x81000001 \
        -i "/tmp/${vm_id}_raw.key" \
        -u "$pub_file" \
        -r "$priv_file" >/dev/null 2>&1
    rm -f "/tmp/${vm_id}_raw.key"

    SEAL_LOG="${SEAL_LOG}${vm_id} vTPM Master Key sealed into Host TPM (${pub_file}, ${priv_file})\n"

    tpm2_load -C 0x81000001 \
        -u "$pub_file" \
        -r "$priv_file" \
        -c "/tmp/${vm_id}_key.ctx" >/dev/null 2>&1

    tpm2_unseal -c "/tmp/${vm_id}_key.ctx" >"$key_file" 2>/dev/null
    rm -f "/tmp/${vm_id}_key.ctx"
    tpm2_flushcontext -t >/dev/null 2>&1 || true
    chmod 0600 "$key_file"

    rm -rf "$state_dir" "$socket_path"
    mkdir -p "$state_dir"
    swtpm_setup --tpm-state "$state_dir" --tpm2 --keyfile "$key_file" --cipher aes-256-cbc --create-ek-cert --create-platform-cert --create-config-files skip-if-exist >/dev/null 2>&1 || true
    swtpm socket --tpmstate dir="$state_dir" \
        --key file="$key_file",mode=aes-256-cbc,format=hex \
        --ctrl type=unixio,path="$socket_path" \
        --tpm2 \
        --flags not-need-init >"$TEST_RESULT_DIR/logs/swtpm-${vm_id}.log" 2>&1 &
}

start_encrypted_vtpm "vm1"
VM1_SWTPM_PID=$!

start_encrypted_vtpm "vm2"
VM2_SWTPM_PID=$!

append_log_section "Sealed vTPM Master Keys Setup" "$SEAL_LOG"

# ==============================================================================
# SECTION 6: Build NixOS Guest VMs
# ==============================================================================
echo "=> 6. Building NixOS Guest VMs (VM-1 and VM-2)..."
rm -f target/result-vm1 target/result-vm2
NIX_BUILD_LOG=""
if [ -n "$SUDO_USER" ]; then
    NIX_BUILD_LOG=$(
        sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm1.nix -o target/result-vm1 2>&1
        sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm2.nix -o target/result-vm2 2>&1
    )
else
    NIX_BUILD_LOG=$(
        nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm1.nix -o target/result-vm1 2>&1
        nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm2.nix -o target/result-vm2 2>&1
    )
fi
rm -f "$TEST_RESULT_DIR/vm1-result-summary" "$TEST_RESULT_DIR/vm2-result-summary"
append_log_section "NixOS Guest VMs Build" "$NIX_BUILD_LOG"

# ==============================================================================
# SECTION 7: Launch Guest VMs Concurrently
# ==============================================================================
echo "=> 7. Launching Guest VM-1 and Guest VM-2 concurrently..."
rm -f /tmp/vm1-disk.qcow2 /tmp/vm2-disk.qcow2
QEMU_NET_OPTS="hostfwd=tcp::50052-:50052" NIX_DISK_IMAGE=/tmp/vm1-disk.qcow2 ./target/result-vm1/bin/run-vm-1-vm >"$TEST_RESULT_DIR/logs/vm1.log" 2>&1 &
VM1_PID=$!

NIX_DISK_IMAGE=/tmp/vm2-disk.qcow2 ./target/result-vm2/bin/run-vm-2-vm >"$TEST_RESULT_DIR/logs/vm2.log" 2>&1 &
VM2_PID=$!

trap 'kill $VM1_PID $VM2_PID $SERVER_PID $HOST_SWTPM_PID $VM1_SWTPM_PID $VM2_SWTPM_PID 2>/dev/null || true; rm -f /tmp/vm1-disk.qcow2 /tmp/vm2-disk.qcow2 /tmp/swtpm-vm1.sock /tmp/swtpm-vm2.sock' EXIT INT TERM
append_log_section "Guest VMs QEMU Launch" "VM-1 QEMU PID: $VM1_PID, VM-2 QEMU PID: $VM2_PID"

# ==============================================================================
# SECTION 8: Await Attestation, Hardware Sealing & Verification
# ==============================================================================
echo "=> 8. Waiting for attestation & credential evaluation on both VMs (up to 120s)..."
TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ -f "$TEST_RESULT_DIR/vm1-result-summary" ] && [ -f "$TEST_RESULT_DIR/vm2-result-summary" ]; then
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ $((ELAPSED % 10)) -eq 0 ]; then
        echo "   ... waiting for VMs to complete attestation & tests (${ELAPSED}s / ${TIMEOUT}s elapsed)"
    fi
done

# Compile final execution logs into structured step sections inside FULL_LOG_FILE
SERVER_LOG=$(cat "$TEST_RESULT_DIR/logs/server.log" 2>/dev/null || echo "Not found")
append_log_section "Host CA Server Log" "$SERVER_LOG"

SEAL_STATE=$( [ -f "$TEST_RESULT_DIR/state/known_vms_seal.json" ] && cat "$TEST_RESULT_DIR/state/known_vms_seal.json" || echo "Not found" )
append_log_section "Host TPM Seal State (known_vms_seal.json)" "$SEAL_STATE"

TOFU_STATE=$( [ -f "$TEST_RESULT_DIR/state/known_vms.json" ] && cat "$TEST_RESULT_DIR/state/known_vms.json" || echo "Not found" )
append_log_section "Host TOFU Learned VMs (known_vms.json)" "$TOFU_STATE"

VTPM_KEYS_INFO=""
[ -f "$TEST_RESULT_DIR/state/vm1_key.pub" ] && VTPM_KEYS_INFO="VM-1 Key Sealed Blob: $(wc -c <"$TEST_RESULT_DIR/state/vm1_key.pub") bytes pub, $(wc -c <"$TEST_RESULT_DIR/state/vm1_key.priv") bytes priv\n"
[ -f "$TEST_RESULT_DIR/state/vm2_key.pub" ] && VTPM_KEYS_INFO="${VTPM_KEYS_INFO}VM-2 Key Sealed Blob: $(wc -c <"$TEST_RESULT_DIR/state/vm2_key.pub") bytes pub, $(wc -c <"$TEST_RESULT_DIR/state/vm2_key.priv") bytes priv\n"
append_log_section "Sealed VM vTPM Keys State" "$VTPM_KEYS_INFO"

NVRAM_INFO=""
if [ -f "$TEST_RESULT_DIR/vm1-tpm/tpm2-00.permall" ]; then
    NVRAM_INFO="VM-1 NVRAM Ciphertext Header:\n$(head -c 32 "$TEST_RESULT_DIR/vm1-tpm/tpm2-00.permall" | xxd)\n"
fi
if [ -f "$TEST_RESULT_DIR/vm2-tpm/tpm2-00.permall" ]; then
    NVRAM_INFO="${NVRAM_INFO}\nVM-2 NVRAM Ciphertext Header:\n$(head -c 32 "$TEST_RESULT_DIR/vm2-tpm/tpm2-00.permall" | xxd)\n"
fi
append_log_section "VM Encrypted vTPM States on Host Disk (AES-256)" "$NVRAM_INFO"

VM1_GRPC_LOG=$(cat "$TEST_RESULT_DIR/vm1-grpc-app.log" 2>/dev/null || echo "Not found")
append_log_section "VM-1 Rust gRPC Server Log" "$VM1_GRPC_LOG"

VM2_GRPC_LOG=$(cat "$TEST_RESULT_DIR/vm2-grpc-app.log" 2>/dev/null || echo "Not found")
append_log_section "VM-2 Go gRPC Client Log" "$VM2_GRPC_LOG"

VM1_QEMU_LOG=$(cat "$TEST_RESULT_DIR/logs/vm1.log" 2>/dev/null || echo "Not found")
append_log_section "QEMU Guest VM-1 Boot Log" "$VM1_QEMU_LOG"

VM2_QEMU_LOG=$(cat "$TEST_RESULT_DIR/logs/vm2.log" 2>/dev/null || echo "Not found")
append_log_section "QEMU Guest VM-2 Boot Log" "$VM2_QEMU_LOG"

VM1_OK=false
VM2_OK=false

if [ -f "$TEST_RESULT_DIR/vm1-result-summary" ] && [ "$(cat "$TEST_RESULT_DIR/vm1-result-summary")" = "SUCCESS" ]; then
    VM1_OK=true
fi

if [ -f "$TEST_RESULT_DIR/vm2-result-summary" ] && [ "$(cat "$TEST_RESULT_DIR/vm2-result-summary")" = "SUCCESS" ]; then
    VM2_OK=true
fi

# Automatically launch Mousepad to display the structured full log file
open_log_in_editor "$FULL_LOG_FILE"

if [ "$VM1_OK" = true ] && [ "$VM2_OK" = true ]; then
    echo "======================================================"
    echo " Multi-VM Integration Test: SUCCESS"
    echo " Both VM-1 and VM-2 attested via isolated vTPMs!"
    echo "======================================================"
    echo ""
    echo "==> FULL EXECUTION LOG OPENED IN MOUSEPAD TEXT VIEWER:"
    echo "    File: $FULL_LOG_FILE"
    echo ""
    echo "==> BOTH VMs ARE CURRENTLY RUNNING FOR LIVE INSPECTION!"
    echo "    • VM-1 (CID=3): service-a credentials issued & verified"
    echo "    • VM-2 (CID=4): service-b credentials issued & verified"
    echo "    • Root auto-login active on both QEMU VM windows."
    echo ""
    echo "Press [ENTER] to terminate both VMs and finish the test..."
    read -r _ || true
    chmod -R 777 "$TEST_RESULT_DIR" 2>/dev/null || true
    exit 0
else
    echo "======================================================"
    echo " Multi-VM Integration Test: FAILED!"
    echo "======================================================"
    echo ""
    echo "==> FULL EXECUTION LOG OPENED IN MOUSEPAD TEXT VIEWER:"
    echo "    File: $FULL_LOG_FILE"
    echo ""
    echo "Press [ENTER] to terminate VMs after inspecting..."
    read -r _ || true
    chmod -R 777 "$TEST_RESULT_DIR" 2>/dev/null || true
    exit 1
fi
