#!/usr/bin/env bash
# ==============================================================================
# Multi-VM Hardware Dual-Attestation & Plain vTPM Integration Test
# ==============================================================================
set -e

# Disable ANSI color escape formatting from Rust tracing loggers
export NO_COLOR=1
export RUST_LOG_STYLE=never

# ==============================================================================
# Parse Command Line Options
# ==============================================================================
INSPECT_MODE=false

for arg in "$@"; do
    case "$arg" in
        --inspect|-i|--keep-open|--interactive)
            INSPECT_MODE=true
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --inspect, -i, --keep-open   Launch each guest VM in a separate terminal window and keep them open for live inspection."
            echo "                               By default, VMs run in the background and terminate automatically at test end."
            echo "  --help, -h                   Show this help message."
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--inspect|-i|--keep-open] [--help|-h]"
            exit 1
            ;;
    esac
done

# Ensure execution as root for attaching vhost-vsock, running swtpm, and 9p filesystem passthrough
if [ "$EUID" -ne 0 ] && [ ! -w /dev/vhost-vsock ]; then
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
if [ -d "$TEST_RESULT_DIR" ]; then
    mv "$TEST_RESULT_DIR" "${TEST_RESULT_DIR}-stale-$(date +%s%N)" 2>/dev/null || true
    rm -rf "${TEST_RESULT_DIR}-stale-"* 2>/dev/null || true
fi
mkdir -p "$TEST_RESULT_DIR/logs" "$TEST_RESULT_DIR/temp" "$TEST_RESULT_DIR/state" "$TEST_RESULT_DIR/host-tpm"
rm -f "$FULL_LOG_FILE" 2>/dev/null || true

SERVER_PID=""
HOST_SWTPM_PID=""
VM1_SWTPM_PID=""
VM2_SWTPM_PID=""
VM1_PID=""
VM2_PID=""
VM1_TERM_PID=""
VM2_TERM_PID=""

# Unified cleanup function for process lifecycle and terminal restoration
cleanup_env() {
    # Terminate background VM and server processes
    for pid in $VM1_PID $VM2_PID $VM1_TERM_PID $VM2_TERM_PID $SERVER_PID $HOST_SWTPM_PID $VM1_SWTPM_PID $VM2_SWTPM_PID; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    sleep 0.2
    for pid in $VM1_PID $VM2_PID $VM1_TERM_PID $VM2_TERM_PID; do
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null || true
    done

    rm -f "$TEST_RESULT_DIR/vm1-disk.qcow2" "$TEST_RESULT_DIR/vm2-disk.qcow2" /tmp/swtpm-vm1.sock /tmp/swtpm-vm2.sock 2>/dev/null || true
    chmod -R 777 "$TEST_RESULT_DIR" 2>/dev/null || true

    # Reset terminal and drain any pending unread characters (e.g. terminal CPR/DSR query responses)
    if [ -t 0 ]; then
        perl -e 'use POSIX; POSIX::tcflush(0, POSIX::TCIFLUSH);' 2>/dev/null || true
        while read -r -t 0.05 -n 1024 _; do :; done 2>/dev/null || true
        stty sane 2>/dev/null || true
    fi
}
trap cleanup_env EXIT INT TERM

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

# Helper to launch a command inside a separate terminal window
launch_vm_terminal() {
    local title="$1"
    local geom="$2"
    local script_path="$3"

    export DISPLAY="${DISPLAY:-:0.0}"
    [ -n "$XAUTHORITY" ] && export XAUTHORITY

    local term_pid=""
    if command -v xfce4-terminal >/dev/null 2>&1; then
        xfce4-terminal --disable-server --title="$title" --geometry="$geom" -e "$script_path" >/dev/null 2>&1 &
        term_pid=$!
    elif command -v konsole >/dev/null 2>&1; then
        konsole --nofork --title "$title" -e "$script_path" >/dev/null 2>&1 &
        term_pid=$!
    elif command -v xterm >/dev/null 2>&1; then
        xterm -T "$title" -geometry "$geom" -e "$script_path" >/dev/null 2>&1 &
        term_pid=$!
    fi

    echo "$term_pid"
}

# ==============================================================================
# SECTION 1: Build the Workspace Binaries
# ==============================================================================
echo "=> 1. Building the Rust & Go workspace binaries..."
mkdir -p "$WORKSPACE_DIR/target/release"
BUILD_OUT=""
if [ -n "$SUDO_USER" ]; then
    BUILD_OUT=$(
        sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" "NO_COLOR=1" "RUST_LOG_STYLE=never" cargo build --release 2>&1
        sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" bash -c "cd testapp/check-svid-go && go build -o ../../target/release/check-svid-go ./cmd/check-svid-go" 2>&1
        sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" bash -c "cd testapp/grpc-app-go && go build -o ../../target/release/grpc-app-go main.go" 2>&1
    )
else
    BUILD_OUT=$(
        cargo build --release 2>&1
        (cd testapp/check-svid-go && go build -o ../../target/release/check-svid-go ./cmd/check-svid-go) 2>&1
        (cd testapp/grpc-app-go && go build -o ../../target/release/grpc-app-go main.go) 2>&1
    )
fi
append_log_section "Workspace Binaries Build" "$BUILD_OUT"

# ==============================================================================
# SECTION 2: Setup Test Environment & Host CA Configuration
# ==============================================================================
echo "=> 2. Setting up test host configuration & state directories..."
pkill -f "authn-scope-server.*test-host.json" 2>/dev/null || true
pkill -f "swtpm.*host-tpm" 2>/dev/null || true
pkill -f "swtpm.*swtpm-vm" 2>/dev/null || true
sleep 0.5
rm -f "$WORKSPACE_DIR"/vm-*.qcow2 "$WORKSPACE_DIR"/authn-scope*.qcow2
cd "$WORKSPACE_DIR"

cat <<JSON >"$TEST_RESULT_DIR/temp/test-host.json"
{
  "trust_domain": "example.org",
  "ca_cert_path": "$TEST_RESULT_DIR/ca-cert.pem",
  "ca_key_path": "$TEST_RESULT_DIR/ca-key.pem",
  "transport": "tcp",
  "server_port": 9000,
  "listen_addr": "0.0.0.0:9000",
  "vms": {
    "vm-1": {
      "vm_cid": 3,
      "ip": "127.0.0.1",
      "attestation": {
        "required": true
      },
      "identities": {
        "check-svid-rust": {
          "selector": "systemd:unitname:check-svid-rust.service",
          "ttl_minutes": 1
        },
        "check-svid-go": {
          "selector": "systemd:unitname:check-svid-go.service",
          "ttl_minutes": 1
        },
        "grpc-app": {
          "selector": "systemd:unitname:grpc-app.service",
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
        "check-svid-rust": {
          "selector": "systemd:unitname:check-svid-rust.service",
          "ttl_minutes": 1
        },
        "check-svid-go": {
          "selector": "systemd:unitname:check-svid-go.service",
          "ttl_minutes": 1
        },
        "grpc-app": {
          "selector": "systemd:unitname:grpc-app.service",
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

sleep 2
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: authn-scope-server failed to start on port 9000!"
    cat "$TEST_RESULT_DIR/logs/server.log"
    exit 1
fi
chmod -R 777 "$TEST_RESULT_DIR" 2>/dev/null || true
append_log_section "Host CA Server Startup" "authn-scope-server launched on port:9000 (PID: $SERVER_PID)"

# ==============================================================================
# SECTION 5: Plain vTPM Startup
# ==============================================================================
echo "=> 5. Starting plain unencrypted vTPM emulators for guest VMs..."

VTPM_LOG=""

start_plain_vtpm() {
    local vm_id="$1"
    local socket_path="/tmp/swtpm-${vm_id}.sock"
    local state_dir="$TEST_RESULT_DIR/${vm_id}-tpm"

    rm -rf "$state_dir" 2>/dev/null || true
    rm -f "$socket_path" 2>/dev/null || true
    mkdir -p "$state_dir"
    swtpm_setup --tpm-state "$state_dir" --tpm2 --create-ek-cert --create-platform-cert --create-config-files skip-if-exist >/dev/null 2>&1 || true
    swtpm socket --tpmstate dir="$state_dir" \
        --ctrl type=unixio,path="$socket_path" \
        --tpm2 \
        --flags not-need-init >"$TEST_RESULT_DIR/logs/swtpm-${vm_id}.log" 2>&1 &
    sleep 0.5
    chmod 777 "$socket_path" 2>/dev/null || true
    
    VTPM_LOG="${VTPM_LOG}${vm_id} plain vTPM started on socket ${socket_path}\n"
}

start_plain_vtpm "vm1"
VM1_SWTPM_PID=$!

start_plain_vtpm "vm2"
VM2_SWTPM_PID=$!

append_log_section "Plain vTPM Setup" "$VTPM_LOG"

# ==============================================================================
# SECTION 6: Build NixOS Guest VMs
# ==============================================================================
echo "=> 6. Building NixOS Guest VMs (VM-1 and VM-2)..."
rm -f target/result-vm1 target/result-vm2
NIX_BUILD_LOG=""
if [ -n "$SUDO_USER" ]; then
    NIX_BUILD_LOG=$(
        sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm1.nix -o target/result-vm1 #2>&1
        sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm2.nix -o target/result-vm2 #2>&1
    )
else
    NIX_BUILD_LOG=$(
        nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm1.nix -o target/result-vm1 #2>&1
        nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm2.nix -o target/result-vm2 #2>&1
    )
fi
rm -f "$TEST_RESULT_DIR/vm1-result-summary" "$TEST_RESULT_DIR/vm2-result-summary"
append_log_section "NixOS Guest VMs Build" "$NIX_BUILD_LOG"

# ==============================================================================
# SECTION 7: Launch Guest VMs Concurrently
# ==============================================================================
rm -f "$TEST_RESULT_DIR/vm1-disk.qcow2" "$TEST_RESULT_DIR/vm2-disk.qcow2" 2>/dev/null || true
rm -f "$TEST_RESULT_DIR/temp/vm1.pid" "$TEST_RESULT_DIR/temp/vm2.pid" 2>/dev/null || true

VM1_PID=""
VM2_PID=""
VM1_TERM_PID=""
VM2_TERM_PID=""

HAS_TERMINAL=false
if [ -n "$DISPLAY" ] && (command -v xfce4-terminal || command -v konsole || command -v xterm) >/dev/null 2>&1; then
    HAS_TERMINAL=true
fi

# Provide dumb terminal parameters and fixed dimensions to guest kernel & systemd
# to eliminate ANSI probing escapes (\e[6n, \e[18t, \e[32766;32766H) at the originator.
export QEMU_KERNEL_PARAMS="TERM=dumb systemd.tty.term.console=dumb systemd.tty.term.ttyS0=dumb systemd.tty.rows.console=24 systemd.tty.columns.console=80 systemd.tty.rows.ttyS0=24 systemd.tty.columns.ttyS0=80 systemd.color=0"

if [ "$INSPECT_MODE" = true ] && [ "$HAS_TERMINAL" = true ]; then
    echo "=> 7. Launching Guest VM-1 and Guest VM-2 in separate terminal windows (inspect mode)..."

    cat <<EOF > "$TEST_RESULT_DIR/temp/run-vm1.sh"
#!/usr/bin/env bash
export QEMU_NET_OPTS="hostfwd=tcp:0.0.0.0:50052-:50052"
export NIX_DISK_IMAGE="$TEST_RESULT_DIR/vm1-disk.qcow2"
export QEMU_OPTS="-pidfile $TEST_RESULT_DIR/temp/vm1.pid"
export QEMU_KERNEL_PARAMS="$QEMU_KERNEL_PARAMS"
./target/result-vm1/bin/run-vm-1-vm 2>&1 | tee "$TEST_RESULT_DIR/logs/vm1.log"
EOF
    chmod +x "$TEST_RESULT_DIR/temp/run-vm1.sh"

    cat <<EOF > "$TEST_RESULT_DIR/temp/run-vm2.sh"
#!/usr/bin/env bash
export NIX_DISK_IMAGE="$TEST_RESULT_DIR/vm2-disk.qcow2"
export QEMU_OPTS="-pidfile $TEST_RESULT_DIR/temp/vm2.pid"
export QEMU_KERNEL_PARAMS="$QEMU_KERNEL_PARAMS"
./target/result-vm2/bin/run-vm-2-vm 2>&1 | tee "$TEST_RESULT_DIR/logs/vm2.log"
EOF
    chmod +x "$TEST_RESULT_DIR/temp/run-vm2.sh"

    VM1_TERM_PID=$(launch_vm_terminal "VM-1 Guest (CID=3)" "100x30+40+40" "$TEST_RESULT_DIR/temp/run-vm1.sh")
    VM2_TERM_PID=$(launch_vm_terminal "VM-2 Guest (CID=4)" "100x30+880+40" "$TEST_RESULT_DIR/temp/run-vm2.sh")

    # Await QEMU PID files
    for i in $(seq 1 40); do
        if [ -f "$TEST_RESULT_DIR/temp/vm1.pid" ] && [ -f "$TEST_RESULT_DIR/temp/vm2.pid" ]; then
            break
        fi
        sleep 0.5
    done
    VM1_PID=$(cat "$TEST_RESULT_DIR/temp/vm1.pid" 2>/dev/null || echo "")
    VM2_PID=$(cat "$TEST_RESULT_DIR/temp/vm2.pid" 2>/dev/null || echo "")
else
    if [ "$INSPECT_MODE" = true ] && [ "$HAS_TERMINAL" = false ]; then
        echo "=> 7. [!] No DISPLAY or terminal emulator detected; launching VMs in background for inspection..."
    else
        echo "=> 7. Launching Guest VM-1 and Guest VM-2 concurrently in background..."
    fi
    QEMU_NET_OPTS="hostfwd=tcp:0.0.0.0:50052-:50052" NIX_DISK_IMAGE="$TEST_RESULT_DIR/vm1-disk.qcow2" ./target/result-vm1/bin/run-vm-1-vm < /dev/null >"$TEST_RESULT_DIR/logs/vm1.log" 2>&1 &
    VM1_PID=$!

    NIX_DISK_IMAGE="$TEST_RESULT_DIR/vm2-disk.qcow2" ./target/result-vm2/bin/run-vm-2-vm < /dev/null >"$TEST_RESULT_DIR/logs/vm2.log" 2>&1 &
    VM2_PID=$!
fi

append_log_section "Guest VMs QEMU Launch" "VM-1 QEMU PID: $VM1_PID (Terminal PID: $VM1_TERM_PID), VM-2 QEMU PID: $VM2_PID (Terminal PID: $VM2_TERM_PID)"

# ==============================================================================
# SECTION 8: Await Attestation, Credential Evaluation & Verification
# ==============================================================================
echo "=> 8. Waiting for attestation & credential evaluation on both VMs (up to 120s)..."
TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ -f "$TEST_RESULT_DIR/vm1-check-svid-rust-summary" ] && \
       [ -f "$TEST_RESULT_DIR/vm1-check-svid-go-summary" ] && \
       [ -f "$TEST_RESULT_DIR/vm1-grpc-app-summary" ] && \
       [ -f "$TEST_RESULT_DIR/vm2-check-svid-rust-summary" ] && \
       [ -f "$TEST_RESULT_DIR/vm2-check-svid-go-summary" ] && \
       [ -f "$TEST_RESULT_DIR/vm2-grpc-app-summary" ]; then
        echo "   ... All test service summary files detected!"
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

VTPM_INFO=""
[ -d "$TEST_RESULT_DIR/vm1-tpm" ] && VTPM_INFO="VM-1 vTPM State Dir: $TEST_RESULT_DIR/vm1-tpm (plain)\n"
[ -d "$TEST_RESULT_DIR/vm2-tpm" ] && VTPM_INFO="${VTPM_INFO}VM-2 vTPM State Dir: $TEST_RESULT_DIR/vm2-tpm (plain)\n"
append_log_section "Guest VM vTPM State (Plain)" "$VTPM_INFO"

VM1_GRPC_LOG=$(cat "$TEST_RESULT_DIR/vm1-grpc-app.log" 2>/dev/null || echo "Not found")
append_log_section "VM-1 Rust gRPC Server Log" "$VM1_GRPC_LOG"

VM2_GRPC_LOG=$(cat "$TEST_RESULT_DIR/vm2-grpc-app.log" 2>/dev/null || echo "Not found")
append_log_section "VM-2 Go gRPC Client Log" "$VM2_GRPC_LOG"

VM1_QEMU_LOG=$(cat "$TEST_RESULT_DIR/logs/vm1.log" 2>/dev/null || echo "Not found")
append_log_section "QEMU Guest VM-1 Boot Log" "$VM1_QEMU_LOG"

VM2_QEMU_LOG=$(cat "$TEST_RESULT_DIR/logs/vm2.log" 2>/dev/null || echo "Not found")
append_log_section "QEMU Guest VM-2 Boot Log" "$VM2_QEMU_LOG"

VM1_RUST_OK=$( [ -f "$TEST_RESULT_DIR/vm1-check-svid-rust-summary" ] && cat "$TEST_RESULT_DIR/vm1-check-svid-rust-summary" || echo "FAIL" )
VM1_GO_OK=$( [ -f "$TEST_RESULT_DIR/vm1-check-svid-go-summary" ] && cat "$TEST_RESULT_DIR/vm1-check-svid-go-summary" || echo "FAIL" )
VM1_GRPC_OK=$( [ -f "$TEST_RESULT_DIR/vm1-grpc-app-summary" ] && cat "$TEST_RESULT_DIR/vm1-grpc-app-summary" || echo "FAIL" )

VM2_RUST_OK=$( [ -f "$TEST_RESULT_DIR/vm2-check-svid-rust-summary" ] && cat "$TEST_RESULT_DIR/vm2-check-svid-rust-summary" || echo "FAIL" )
VM2_GO_OK=$( [ -f "$TEST_RESULT_DIR/vm2-check-svid-go-summary" ] && cat "$TEST_RESULT_DIR/vm2-check-svid-go-summary" || echo "FAIL" )
VM2_GRPC_OK=$( [ -f "$TEST_RESULT_DIR/vm2-grpc-app-summary" ] && cat "$TEST_RESULT_DIR/vm2-grpc-app-summary" || echo "FAIL" )

VM1_RUST_LOG=$(cat "$TEST_RESULT_DIR/vm1-check-svid-rust.log" 2>/dev/null || echo "Not found")
VM1_GO_LOG=$(cat "$TEST_RESULT_DIR/vm1-check-svid-go.log" 2>/dev/null || echo "Not found")
VM2_RUST_LOG=$(cat "$TEST_RESULT_DIR/vm2-check-svid-rust.log" 2>/dev/null || echo "Not found")
VM2_GO_LOG=$(cat "$TEST_RESULT_DIR/vm2-check-svid-go.log" 2>/dev/null || echo "Not found")

# Print all logs directly to screen (stdout) for maximum debuggability
echo ""
echo "=================================================================="
echo "                     INTEGRATION TEST LOGS ON SCREEN"
echo "=================================================================="
echo ""
echo "------------------------------------------------------------------"
echo "--- Host CA Server Log ($TEST_RESULT_DIR/logs/server.log) ---"
echo "------------------------------------------------------------------"
echo "$SERVER_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- VM-1 check-svid-rust Log ($TEST_RESULT_DIR/vm1-check-svid-rust.log) ---"
echo "------------------------------------------------------------------"
echo "$VM1_RUST_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- VM-1 check-svid-go Log ($TEST_RESULT_DIR/vm1-check-svid-go.log) ---"
echo "------------------------------------------------------------------"
echo "$VM1_GO_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- VM-1 Rust gRPC Server Log ($TEST_RESULT_DIR/vm1-grpc-app.log) ---"
echo "------------------------------------------------------------------"
echo "$VM1_GRPC_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- VM-2 check-svid-rust Log ($TEST_RESULT_DIR/vm2-check-svid-rust.log) ---"
echo "------------------------------------------------------------------"
echo "$VM2_RUST_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- VM-2 check-svid-go Log ($TEST_RESULT_DIR/vm2-check-svid-go.log) ---"
echo "------------------------------------------------------------------"
echo "$VM2_GO_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- VM-2 Go gRPC Client Log ($TEST_RESULT_DIR/vm2-grpc-app.log) ---"
echo "------------------------------------------------------------------"
echo "$VM2_GRPC_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- QEMU Guest VM-1 Boot & Serial Log ($TEST_RESULT_DIR/logs/vm1.log) ---"
echo "------------------------------------------------------------------"
echo "$VM1_QEMU_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- QEMU Guest VM-2 Boot & Serial Log ($TEST_RESULT_DIR/logs/vm2.log) ---"
echo "------------------------------------------------------------------"
echo "$VM2_QEMU_LOG"
echo ""
echo "------------------------------------------------------------------"
echo "--- Test Service Summary Results ---"
echo "------------------------------------------------------------------"
echo "  • VM-1 check-svid-rust: $VM1_RUST_OK"
echo "  • VM-1 check-svid-go:   $VM1_GO_OK"
echo "  • VM-1 grpc-app:        $VM1_GRPC_OK"
echo "  • VM-2 check-svid-rust: $VM2_RUST_OK"
echo "  • VM-2 check-svid-go:   $VM2_GO_OK"
echo "  • VM-2 grpc-app:        $VM2_GRPC_OK"
echo "=================================================================="
echo ""

VM1_OK=false
VM2_OK=false

if [ "$VM1_RUST_OK" = "SUCCESS" ] && [ "$VM1_GO_OK" = "SUCCESS" ] && [ "$VM1_GRPC_OK" = "SUCCESS" ]; then
    VM1_OK=true
fi

if [ "$VM2_RUST_OK" = "SUCCESS" ] && [ "$VM2_GO_OK" = "SUCCESS" ] && [ "$VM2_GRPC_OK" = "SUCCESS" ]; then
    VM2_OK=true
fi

# Automatically launch Mousepad to display the structured full log file
if [ "$INSPECT_MODE" = true ]; then
    open_log_in_editor "$FULL_LOG_FILE"
fi    

if [ "$VM1_OK" = true ] && [ "$VM2_OK" = true ]; then
    echo "======================================================"
    echo " Multi-VM Integration Test: SUCCESS"
    echo " Both VM-1 and VM-2 attested via isolated vTPMs!"
    echo " 3 Separate Test Services Passed on Each VM:"
    echo "   • VM-1 (CID=3): check-svid-rust ($VM1_RUST_OK), check-svid-go ($VM1_GO_OK), grpc-app ($VM1_GRPC_OK)"
    echo "   • VM-2 (CID=4): check-svid-rust ($VM2_RUST_OK), check-svid-go ($VM2_GO_OK), grpc-app ($VM2_GRPC_OK)"
    echo "======================================================"
    echo ""
    echo "==> FULL EXECUTION LOG OPENED IN MOUSEPAD TEXT VIEWER:"
    echo "    File: $FULL_LOG_FILE"
    echo ""
    if [ "$INSPECT_MODE" = true ]; then
        if [ "$HAS_TERMINAL" = true ]; then
            echo "==> [INSPECT MODE] Both VMs are running in separate terminal windows for live inspection."
            echo "    • VM-1 (CID=3): Terminal window active (root auto-login active)"
            echo "    • VM-2 (CID=4): Terminal window active (root auto-login active)"
            echo "    • VM logs: $TEST_RESULT_DIR/logs/vm1.log, $TEST_RESULT_DIR/logs/vm2.log"
        else
            echo "==> [INSPECT MODE] Both VMs remain running in background for inspection."
            echo "    • VM logs: $TEST_RESULT_DIR/logs/vm1.log, $TEST_RESULT_DIR/logs/vm2.log"
        fi
        echo ""
        if [ -t 0 ]; then
            echo "Press [ENTER] to terminate both VMs and close terminal windows..."
            read -r _ || true
        else
            echo "Non-interactive terminal detected in inspect mode; keeping VMs alive until killed (Ctrl+C)..."
            wait $VM1_PID $VM2_PID 2>/dev/null || true
        fi
    else
        echo "==> Automatically terminating guest VMs and cleaning up test environment."
        echo "    (Tip: pass '--inspect' or '-i' to open VMs in separate terminal windows for live inspection)"
    fi
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
    if [ "$INSPECT_MODE" = true ]; then
        if [ "$HAS_TERMINAL" = true ]; then
            echo "==> [INSPECT MODE] VMs remain running in separate terminal windows for live debugging."
            echo "    • VM logs: $TEST_RESULT_DIR/logs/vm1.log, $TEST_RESULT_DIR/logs/vm2.log"
        else
            echo "==> [INSPECT MODE] VMs remain running for debugging."
            echo "    • VM logs: $TEST_RESULT_DIR/logs/vm1.log, $TEST_RESULT_DIR/logs/vm2.log"
        fi
        echo ""
        if [ -t 0 ]; then
            echo "Press [ENTER] to terminate VMs and close terminal windows..."
            read -r _ || true
        else
            echo "Non-interactive terminal detected in inspect mode; keeping VMs alive until killed (Ctrl+C)..."
            wait $VM1_PID $VM2_PID 2>/dev/null || true
        fi
    else
        echo "==> Automatically terminating guest VMs and cleaning up test environment."
        echo "    (Tip: pass '--inspect' or '-i' to open VMs in separate terminal windows for live inspection)"
    fi
    chmod -R 777 "$TEST_RESULT_DIR" 2>/dev/null || true
    exit 1
fi
