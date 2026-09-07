# agent-vm2.nix
# NixOS VM configuration for Integration Test Guest 2 (vm-2).
# Boots as CID=4 with dedicated vTPM (/tmp/swtpm-vm2.sock).
{
  config,
  pkgs,
  ...
}: let
  authScope = pkgs.callPackage ../pkgs/authn-scope-rust.nix {};
  authScopeGo = pkgs.callPackage ../pkgs/authn-scope-go.nix {};
  grpcAppGo = pkgs.callPackage ../pkgs/grpc-app-go.nix {};

  checkSvidRustScript = pkgs.writeShellScript "run-check-svid-rust" ''
    set -x
    exec > /workspace/test-result/vm2-check-svid-rust.log 2>&1
    trap 'echo "FAILED at line $LINENO: command ($BASH_COMMAND) exited with status $?" ; echo FAILURE > /workspace/test-result/vm2-check-svid-rust-summary' ERR

    mkdir -p /workspace/test-result

    echo "==> [VM-2 check-svid-rust] Waiting for Workload API socket..."
    for i in $(seq 1 60); do
      [ -S /run/authn-scope/workload.sock ] && break
      sleep 1
    done
    [ -S /run/authn-scope/workload.sock ] || { echo "[VM-2] Workload socket never appeared"; exit 1; }

    echo "==> [VM-2 check-svid-rust] Fetching credentials via Workload API (systemd selector: check-svid-rust.service)..."
    env USER=check-svid-rust /workspace/target/release/workload-test-workload /run/authn-scope/workload.sock

    cp /tmp/workload-cert-check-svid-rust.pem /workspace/test-result/vm2-check-svid-rust-cert.pem
    cp /tmp/workload-ca-check-svid-rust.pem   /workspace/test-result/ca-cert.pem

    echo "==> [VM-2 check-svid-rust] Evaluating certificate (check-svid-rust)..."
    /workspace/target/release/check-svid-rust \
      /workspace/test-result/vm2-check-svid-rust-cert.pem \
      /workspace/test-result/ca-cert.pem \
      check-svid-rust

    echo SUCCESS > /workspace/test-result/vm2-check-svid-rust-summary
    echo "==> [VM-2 check-svid-rust] Passed!"
  '';

  checkSvidGoScript = pkgs.writeShellScript "run-check-svid-go" ''
    set -x
    exec > /workspace/test-result/vm2-check-svid-go.log 2>&1
    trap 'echo "FAILED at line $LINENO: command ($BASH_COMMAND) exited with status $?" ; echo FAILURE > /workspace/test-result/vm2-check-svid-go-summary' ERR

    mkdir -p /workspace/test-result

    echo "==> [VM-2 check-svid-go] Waiting for Workload API socket..."
    for i in $(seq 1 60); do
      [ -S /run/authn-scope/workload.sock ] && break
      sleep 1
    done
    [ -S /run/authn-scope/workload.sock ] || { echo "[VM-2] Workload socket never appeared"; exit 1; }

    echo "==> [VM-2 check-svid-go] Fetching credentials via Workload API (systemd selector: check-svid-go.service)..."
    env USER=check-svid-go /workspace/target/release/workload-test-workload /run/authn-scope/workload.sock

    cp /tmp/workload-cert-check-svid-go.pem /workspace/test-result/vm2-check-svid-go-cert.pem

    echo "==> [VM-2 check-svid-go] Evaluating certificate (check-svid-go)..."
    /workspace/target/release/check-svid-go \
      /workspace/test-result/vm2-check-svid-go-cert.pem \
      /workspace/test-result/ca-cert.pem \
      check-svid-go

    echo SUCCESS > /workspace/test-result/vm2-check-svid-go-summary
    echo "==> [VM-2 check-svid-go] Passed!"
  '';

  grpcAppScript = pkgs.writeShellScript "run-grpc-app-service" ''
    set -x
    exec >> /workspace/test-result/vm2-grpc-app.log 2>&1
    trap 'echo "FAILED at line $LINENO: command ($BASH_COMMAND) exited with status $?" ; echo FAILURE > /workspace/test-result/vm2-grpc-app-summary' ERR

    mkdir -p /workspace/test-result

    echo "==> [VM-2 grpc-app] Waiting for Workload API socket..."
    for i in $(seq 1 60); do
      [ -S /run/authn-scope/workload.sock ] && break
      sleep 1
    done
    [ -S /run/authn-scope/workload.sock ] || { echo "[VM-2] Workload socket never appeared"; exit 1; }

    echo "==> [VM-2 grpc-app] Running Go gRPC test application (systemd selector: grpc-app.service)..."
    /workspace/target/release/grpc-app-go client 10.0.2.2:50052 /run/authn-scope/workload.sock

    echo SUCCESS > /workspace/test-result/vm2-grpc-app-summary
    echo SUCCESS > /workspace/test-result/vm2-result-summary
    echo "==> [VM-2 grpc-app] Passed!"
  '';
in {
  imports = [
    ../modules/authn-scope.nix
  ];

  networking.hostName = "vm-2";
  networking.firewall.allowedTCPPorts = [50052];
  networking.firewall.enable = false;
  services.getty.autologinUser = "root";

  boot.kernelParams = [
    "TERM=dumb"
    "systemd.tty.term.console=dumb"
    "systemd.tty.term.ttyS0=dumb"
    "systemd.tty.rows.console=24"
    "systemd.tty.columns.console=80"
    "systemd.tty.rows.ttyS0=24"
    "systemd.tty.columns.ttyS0=80"
    "systemd.color=0"
    "systemd.show_status=auto"
  ];

  systemd.services."serial-getty@ttyS0".environment.TERM = "dumb";

  users.users.nixos = {
    isNormalUser = true;
    initialPassword = "nixos";
    extraGroups = ["wheel"];
  };

  time.timeZone = "Asia/Dubai";
  environment.systemPackages = [pkgs.tpm2-tools];

  virtualisation.vmVariant = {
    virtualisation.graphics = false;
    virtualisation.writableStoreUseTmpfs = true;
    virtualisation.sharedDirectories.workspace = {
      source = toString ./../..;
      target = "/workspace";
    };

    virtualisation.qemu.options = [
      "-device vhost-vsock-pci,guest-cid=4"
      "-chardev socket,id=chrtpm,path=/tmp/swtpm-vm2.sock"
      "-tpmdev emulator,id=tpm0,chardev=chrtpm"
      "-device tpm-tis,tpmdev=tpm0"
    ];
  };

  systemd.tmpfiles.rules = [
    "d /run/authn-scope 0755 root root -"
  ];

  services.authn-scope.agent = {
    enable = true;
    package = authScope;
    settings = {
      vm_name = "vm-2";
      transport = "tcp";
      server_addr = "10.0.2.2:9000";
      workload_api_socket = "/run/authn-scope/workload.sock";
    };
  };

  systemd.services.check-svid-rust = {
    description = "Run VM-2 check-svid-rust test";
    wantedBy = ["multi-user.target"];
    after = ["authn-scope-agent.service" "network.target"];
    requires = ["authn-scope-agent.service"];
    serviceConfig = {
      Type = "oneshot";
      User = "root";
      ExecStart = checkSvidRustScript;
    };
  };

  systemd.services.check-svid-go = {
    description = "Run VM-2 check-svid-go test";
    wantedBy = ["multi-user.target"];
    after = ["authn-scope-agent.service" "network.target"];
    requires = ["authn-scope-agent.service"];
    serviceConfig = {
      Type = "oneshot";
      User = "root";
      ExecStart = checkSvidGoScript;
    };
  };

  systemd.services.grpc-app = {
    description = "Run VM-2 gRPC client application test";
    wantedBy = ["multi-user.target"];
    after = ["authn-scope-agent.service" "network.target"];
    requires = ["authn-scope-agent.service"];
    serviceConfig = {
      Type = "oneshot";
      User = "root";
      ExecStart = grpcAppScript;
    };
  };

  system.stateVersion = "26.05";
}
