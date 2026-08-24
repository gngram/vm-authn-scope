#!/usr/bin/env bash
set -e

# Make sure we are root (for vhost-vsock and 9p passthrough)
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (or use sudo) to attach /dev/vhost-vsock to QEMU."
    exec sudo "$0" "$@"
fi

WORKSPACE_DIR="$(pwd)"
echo "=> 1. Building the Rust workspace..."
# Drop privileges just for the cargo build to avoid root ownership issues if possible
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" cargo build --release
    sudo -u "$SUDO_USER" bash -c "cd libs/go-libs/authn-scope-evaluator && go build -o ../../../target/release/authn-scope-eval-test-go ./cmd/authn-scope-eval-test-go"
else
    cargo build --release
    cd libs/go-libs/authn-scope-evaluator && go build -o ../../../target/release/authn-scope-eval-test-go ./cmd/authn-scope-eval-test-go && cd ../../..
fi

echo "=> 2. Setting up test host configuration..."
rm -rf "$WORKSPACE_DIR/test-result"
mkdir -p "$WORKSPACE_DIR/test-result/temp"
mkdir -p "$WORKSPACE_DIR/test-result/logs"
cd "$WORKSPACE_DIR"

cat <<EOF >$WORKSPACE_DIR/test-result/temp/test-host.json
{
  "ca_cert_path": "$WORKSPACE_DIR/test-result/ca-cert.pem",
  "ca_key_path": "$WORKSPACE_DIR/test-result/ca-key.pem",
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
        },
        "service-b": { "caps": [] },
        "service-c": { "caps": [] }
      }
    }
  }
}
EOF
export RUST_LOG='debug'
echo "=> 3. Starting host CA server in background (generating keys)..."
./target/release/authn-scope-server --config $WORKSPACE_DIR/test-result/temp/test-host.json --genkey >$WORKSPACE_DIR/test-result/logs/server.log 2>&1 &
SERVER_PID=$!

sleep 2 # Let server bind

echo "=> 5. Building NixOS Guest VM..."
# Build the VM as the original user to avoid Nix environment problems under sudo
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm.nix -o target/result-vm
else
    nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm.nix -o target/result-vm
fi

# Ensure any previous test result is removed
rm -f "$WORKSPACE_DIR/test-result/result-summary"

echo "=> 6. Booting NixOS Guest VM..."
./target/result-vm/bin/run-authn-scope-vm >$WORKSPACE_DIR/test-result/logs/vm.log 2>&1

echo "=> 7. Stopping Server...PID: $SERVER_PID"
kill $SERVER_PID || true

echo "======================================================"
echo "                   TEST RESULTS                       "
echo "======================================================"
echo "Host Server Logs:"
cat $WORKSPACE_DIR/test-result/logs/server.log
echo "======================================================"
if [ -f "$WORKSPACE_DIR/test-result/result-summary" ] && [ "$(cat "$WORKSPACE_DIR/test-result/result-summary")" = "SUCCESS" ]; then
    echo "Test completed successfully!"
    chmod -R 777 $WORKSPACE_DIR/test-result
    exit 0
else
    echo "Test failed!"
    chmod -R 777 $WORKSPACE_DIR/test-result
    exit 1
fi
