#!/usr/bin/env bash
set -e

# Make sure we are root (for vhost-vsock and 9p passthrough)
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (or use sudo) to attach /dev/vhost-vsock to QEMU."
    exec sudo "$0" "$@"
fi

WORKSPACE_DIR="$(pwd)"
echo "=> 1. Building the Rust workspace..."
# Drop privileges just for the cargo build to avoid root ownership issues
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

# Write host server config in the new format (no cert_validity_days, no caps,
# selector strings with unix:user/group and systemd:unitname, ttl_minutes per identity)
cat <<EOF >$WORKSPACE_DIR/test-result/temp/test-host.json
{
  "ca_cert_path": "$WORKSPACE_DIR/test-result/ca-cert.pem",
  "ca_key_path": "$WORKSPACE_DIR/test-result/ca-key.pem",
  "server_port": 900,
  "peer_port": 901,
  "vms": {
    "local-vm": {
      "vm_cid": 3,
      "ip": "127.0.0.1",
      "identities": {
        "service-a": {
          "selector": "unix:user:service-a,unix:group:service-a",
          "ttl_minutes": 10
        },
        "service-b": {
          "selector": "unix:user:service-b,unix:group:service-b",
          "ttl_minutes": 10
        },
        "service-c": {
          "selector": "unix:user:service-c,unix:group:service-c",
          "ttl_minutes": 10
        }
      }
    }
  }
}
EOF

export RUST_LOG='info'
echo "=> 3. Starting host CA server in background (generating keys)..."
./target/release/authn-scope-server --config $WORKSPACE_DIR/test-result/temp/test-host.json --genkey >$WORKSPACE_DIR/test-result/logs/server.log 2>&1 &
SERVER_PID=$!

sleep 2 # Let server bind and generate keys

echo "=> 4. Building NixOS Guest VM..."
# Build the VM as the original user to avoid Nix environment problems under sudo
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm.nix -o target/result-vm
else
    nix-build '<nixpkgs/nixos>' -A vm -I nixos-config=nix/checks/agent-vm.nix -o target/result-vm
fi

# Ensure any previous test result is removed
rm -f "$WORKSPACE_DIR/test-result/result-summary"

echo "=> 5. Booting NixOS Guest VM..."
./target/result-vm/bin/run-authn-scope-vm >$WORKSPACE_DIR/test-result/logs/vm.log 2>&1

echo "=> 6. Stopping Server...PID: $SERVER_PID"
kill $SERVER_PID || true

echo "======================================================"
echo "                   TEST RESULTS                       "
echo "======================================================"
echo "Host Server Log:"
cat $WORKSPACE_DIR/test-result/logs/server.log
echo "======================================================"
if [ -f "$WORKSPACE_DIR/test-result/result-summary" ] && [ "$(cat "$WORKSPACE_DIR/test-result/result-summary")" = "SUCCESS" ]; then
    echo "Test completed successfully!"
    chmod -R 777 $WORKSPACE_DIR/test-result
    exit 0
else
    echo "Test FAILED! VM logs:"
    cat $WORKSPACE_DIR/test-result/logs/vm.log
    chmod -R 777 $WORKSPACE_DIR/test-result
    exit 1
fi
