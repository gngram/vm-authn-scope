#!/usr/bin/env bash
# ==============================================================================
# gRPC Cross-Language (Rust <-> Go) Workload API & Cert Rotation Test Runner
# ==============================================================================
set -e

WORKSPACE_DIR="$(pwd)"
echo "=> 1. Building workspace binaries..."
cargo build --release --bin authn-scope-server --bin authn-scope-agent --bin grpc-app-rust
cd testapp/grpc-app-go && go build -o "../../target/release/grpc-app-go" main.go && cd ../..

echo "=> 2. Setting up test directory..."
TMP_DIR="$(mktemp -d /tmp/grpc-test-XXXXXX)"
trap 'kill $SERVER_PID $AGENT_PID $RUST_APP_PID 2>/dev/null || true; rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/state"

cat <<JSON >"$TMP_DIR/host.json"
{
  "ca_cert_path": "$TMP_DIR/ca-cert.pem",
  "ca_key_path": "$TMP_DIR/ca-key.pem",
  "transport": "tcp",
  "listen_addr": "127.0.0.1:9000",
  "peer_port": 901,
  "notification_port": 902,
  "vms": {
    "local-vm": {
      "ip": "127.0.0.1",
      "identities": {
        "service-a": {
          "selector": "unix:user:$(id -un),unix:group:$(id -gn)",
          "ttl_minutes": 1
        }
      }
    }
  }
}
JSON

cat <<JSON >"$TMP_DIR/agent.json"
{
  "vm_name": "local-vm",
  "transport": "tcp",
  "server_port": 9000,
  "server_addr": "127.0.0.1:9000",
  "workload_api_socket": "$TMP_DIR/workload.sock"
}
JSON

export AUTHN_SCOPE_STATE_DIR="$TMP_DIR/state"
export AUTHN_SCOPE_ALLOW_NON_ROOT="1"

echo "=> 3. Starting authn-scope-server..."
./target/release/authn-scope-server --config "$TMP_DIR/host.json" --genkey >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1.5

echo "=> 4. Starting authn-scope-agent..."
./target/release/authn-scope-agent --config "$TMP_DIR/agent.json" >"$TMP_DIR/agent.log" 2>&1 &
AGENT_PID=$!

echo "=> Waiting for agent Workload API socket ($TMP_DIR/workload.sock)..."
WAIT_COUNT=0
until [ -S "$TMP_DIR/workload.sock" ]; do
    sleep 0.5
    WAIT_COUNT=$((WAIT_COUNT + 1))
    if [ $WAIT_COUNT -gt 20 ]; then
        echo "ERROR: Timed out waiting for Workload API socket!"
        echo "=== SERVER LOG ==="
        cat "$TMP_DIR/server.log"
        echo "=== AGENT LOG ==="
        cat "$TMP_DIR/agent.log"
        exit 1
    fi
done
echo "   [+] Workload API socket active!"

echo "=> 5. Running Rust gRPC Server in background..."
./target/release/grpc-app-rust server 127.0.0.1:50052 "$TMP_DIR/workload.sock" >"$TMP_DIR/rust-app.log" 2>&1 &
RUST_APP_PID=$!
sleep 1

echo "=> 6. Running Go gRPC Client..."
./target/release/grpc-app-go client 127.0.0.1:50052 "$TMP_DIR/workload.sock" | tee "$TMP_DIR/go-app.log"

echo "=> 7. Waiting for Rust gRPC Server to complete post-rotation checks..."
wait $RUST_APP_PID

echo "======================================================"
echo "                 RUST APP LOG OUTPUT                  "
echo "======================================================"
cat "$TMP_DIR/rust-app.log"
echo "======================================================"
echo "SUCCESS: Rust <-> Go gRPC Workload API & Rotation Verified!"
echo "======================================================"
