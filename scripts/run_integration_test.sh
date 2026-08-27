#!/usr/bin/env bash
set -e

# Make sure we are root (for vhost-vsock, swtpm, and 9p passthrough)
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (or use sudo) to attach /dev/vhost-vsock to QEMU."
    exec sudo --preserve-env=PKG_CONFIG_PATH,PATH,RUST_LOG,VSOCK_HOST_CID,TPM2TOOLS_TCTI "$0" "$@"
fi

# If PKG_CONFIG_PATH is missing or tss2-sys is not found, auto-discover from nix store
if ! pkg-config --exists tss2-sys 2>/dev/null; then
    NIX_TSS_PC=$(find /nix/store -maxdepth 4 -name "tss2-sys.pc" 2>/dev/null | head -n 1)
    if [ -n "$NIX_TSS_PC" ]; then
        NIX_TSS_DIR=$(dirname "$NIX_TSS_PC")
        export PKG_CONFIG_PATH="$NIX_TSS_DIR${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    fi
fi

WORKSPACE_DIR="$(pwd)"
echo "=> 1. Building the Rust workspace..."
# Drop privileges just for the cargo build to avoid root ownership issues, preserving PKG_CONFIG_PATH
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" cargo build --release
    sudo -u "$SUDO_USER" env "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" "PATH=$PATH" bash -c "cd libs/go-libs/authn-scope-evaluator && go build -o ../../../target/release/authn-scope-eval-test-go ./cmd/authn-scope-eval-test-go"
else
    cargo build --release
    cd libs/go-libs/authn-scope-evaluator && go build -o ../../../target/release/authn-scope-eval-test-go ./cmd/authn-scope-eval-test-go && cd ../../..
fi

echo "=> 2. Setting up test host configuration & state directories..."
rm -rf "$WORKSPACE_DIR/test-result"
mkdir -p "$WORKSPACE_DIR/test-result/temp"
mkdir -p "$WORKSPACE_DIR/test-result/logs"
mkdir -p "$WORKSPACE_DIR/test-result/state"
mkdir -p "$WORKSPACE_DIR/test-result/host-tpm"
mkdir -p "$WORKSPACE_DIR/test-result/agent-tpm"
cd "$WORKSPACE_DIR"

# Write host server config with vTPM attestation enabled for both VM-1 and VM-2 (TOFU on first boot)
cat <<EOF >$WORKSPACE_DIR/test-result/temp/test-host.json
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
EOF

# Direct server state storage (known_vms.json & config_seal.json) to test directory
export AUTHN_SCOPE_STATE_DIR="$WORKSPACE_DIR/test-result/state"

echo "=> 3. Starting host swtpm for server config sealing..."
rm -rf "$WORKSPACE_DIR/test-result/host-tpm"
mkdir -p "$WORKSPACE_DIR/test-result/host-tpm"
swtpm_setup --tpm-state "$WORKSPACE_DIR/test-result/host-tpm" --tpm2 --create-ek-cert --create-platform-cert 2>/dev/null || true
swtpm socket --tpmstate dir="$WORKSPACE_DIR/test-result/host-tpm" \
  --tpm2 \
  --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 \
  --flags not-need-init >$WORKSPACE_DIR/test-result/logs/swtpm-host.log 2>&1 &
HOST_SWTPM_PID=$!
sleep 1

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c 2>/dev/null || true
export RUST_LOG='info'

echo "=> 4. Starting host CA server in background (sealing config and generating keys)..."
./target/release/authn-scope-server --config $WORKSPACE_DIR/test-result/temp/test-host.json --genkey >$WORKSPACE_DIR/test-result/logs/server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID $HOST_SWTPM_PID $VM1_SWTPM_PID $VM2_SWTPM_PID 2>/dev/null || true; rm -f /tmp/swtpm-vm1.sock /tmp/swtpm-vm2.sock' EXIT

sleep 2 # Let server bind and generate keys

echo "=> 5. Starting isolated vTPM emulators for VM-1 and VM-2..."
# VM-1 vTPM
rm -rf "$WORKSPACE_DIR/test-result/vm1-tpm" /tmp/swtpm-vm1.sock
mkdir -p "$WORKSPACE_DIR/test-result/vm1-tpm"
swtpm_setup --tpm-state "$WORKSPACE_DIR/test-result/vm1-tpm" --tpm2 --create-ek-cert --create-platform-cert 2>/dev/null || true
swtpm socket --tpmstate dir="$WORKSPACE_DIR/test-result/vm1-tpm" \
  --ctrl type=unixio,path=/tmp/swtpm-vm1.sock \
  --tpm2 \
  --flags not-need-init >$WORKSPACE_DIR/test-result/logs/swtpm-vm1.log 2>&1 &
VM1_SWTPM_PID=$!

# VM-2 vTPM
rm -rf "$WORKSPACE_DIR/test-result/vm2-tpm" /tmp/swtpm-vm2.sock
mkdir -p "$WORKSPACE_DIR/test-result/vm2-tpm"
swtpm_setup --tpm-state "$WORKSPACE_DIR/test-result/vm2-tpm" --tpm2 --create-ek-cert --create-platform-cert 2>/dev/null || true
swtpm socket --tpmstate dir="$WORKSPACE_DIR/test-result/vm2-tpm" \
  --ctrl type=unixio,path=/tmp/swtpm-vm2.sock \
  --tpm2 \
  --flags not-need-init >$WORKSPACE_DIR/test-result/logs/swtpm-vm2.log 2>&1 &
VM2_SWTPM_PID=$!

sleep 1

echo "=> 6. Building NixOS Guest VMs (VM-1 and VM-2)..."
rm -f target/result-vm1 target/result-vm2
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm1.nix -o target/result-vm1
    sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm2.nix -o target/result-vm2
else
    nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm1.nix -o target/result-vm1
    nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm2.nix -o target/result-vm2
fi

# Ensure any previous test results are removed
rm -f "$WORKSPACE_DIR/test-result/vm1-result-summary" "$WORKSPACE_DIR/test-result/vm2-result-summary"

echo "=> 7. Launching Guest VM-1 and Guest VM-2 concurrently (with QEMU display windows)..."
./target/result-vm1/bin/run-vm-1-vm >$WORKSPACE_DIR/test-result/logs/vm1.log 2>&1 &
VM1_PID=$!

./target/result-vm2/bin/run-vm-2-vm >$WORKSPACE_DIR/test-result/logs/vm2.log 2>&1 &
VM2_PID=$!

trap 'kill $VM1_PID $VM2_PID $SERVER_PID $HOST_SWTPM_PID $VM1_SWTPM_PID $VM2_SWTPM_PID 2>/dev/null || true; rm -f /tmp/swtpm-vm1.sock /tmp/swtpm-vm2.sock' EXIT INT TERM

echo "=> 8. Waiting for attestation & credential evaluation on both VMs..."
TIMEOUT=45
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ -f "$WORKSPACE_DIR/test-result/vm1-result-summary" ] && [ -f "$WORKSPACE_DIR/test-result/vm2-result-summary" ]; then
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

echo "======================================================"
echo "                   TEST RESULTS                       "
echo "======================================================"
echo "Host Server Log:"
cat $WORKSPACE_DIR/test-result/logs/server.log
echo "------------------------------------------------------"
echo "Host TPM Seal State (known_vms_seal.json):"
[ -f "$WORKSPACE_DIR/test-result/state/known_vms_seal.json" ] && cat "$WORKSPACE_DIR/test-result/state/known_vms_seal.json" || echo "Not found"
echo "------------------------------------------------------"
echo "Host TOFU Learned VMs (known_vms.json):"
[ -f "$WORKSPACE_DIR/test-result/state/known_vms.json" ] && cat "$WORKSPACE_DIR/test-result/state/known_vms.json" || echo "Not found"
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
    chmod -R 777 $WORKSPACE_DIR/test-result 2>/dev/null || true
    exit 0
else
    echo "Multi-VM Test FAILED!"
    echo "--- VM-1 Log ---"
    cat $WORKSPACE_DIR/test-result/logs/vm1.log 2>/dev/null || true
    echo "--- VM-2 Log ---"
    cat $WORKSPACE_DIR/test-result/logs/vm2.log 2>/dev/null || true
    echo "Press [ENTER] to terminate VMs after inspecting..."
    read -r _ || true
    chmod -R 777 $WORKSPACE_DIR/test-result 2>/dev/null || true
    exit 1
fi
