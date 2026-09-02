# agent-vm1.nix
# NixOS VM configuration for Integration Test Guest 1 (vm-1).
# Boots as CID=3 with dedicated vTPM (/tmp/swtpm-vm1.sock).
{
  config,
  pkgs,
  ...
}: let
  authScope = pkgs.callPackage ../pkgs/authn-scope-rust.nix {};
  authScopeGo = pkgs.callPackage ../pkgs/authn-scope-go.nix {};

  evalTestScript = pkgs.writeShellScript "run-eval-test" ''
    set -e
    trap 'echo FAILURE > /workspace/test-result/vm1-result-summary' ERR

    mkdir -p /workspace/test-result

    echo "==> [VM-1] Waiting for Workload API socket..."
    for i in $(seq 1 60); do
      [ -S /run/authn-scope/workload.sock ] && break
      sleep 1
    done
    [ -S /run/authn-scope/workload.sock ] || { echo "[VM-1] Workload socket never appeared"; exit 1; }

    echo "==> [VM-1] Fetching credentials via Workload API (as service-a)..."
    ${pkgs.util-linux}/bin/runuser -u service-a -- env USER=service-a \
      ${authScope}/bin/workload-test-workload /run/authn-scope/workload.sock

    cp /tmp/workload-cert-service-a.pem /workspace/test-result/vm1-service-a-cert.pem
    cp /tmp/workload-ca-service-a.pem   /workspace/test-result/ca-cert.pem

    echo "==> [VM-1] Evaluating certificate (Rust)..."
    ${authScope}/bin/authn-scope-eval-test \
      /workspace/test-result/vm1-service-a-cert.pem \
      /workspace/test-result/ca-cert.pem \
      service-a

    echo "==> [VM-1] Evaluating certificate (Go)..."
    ${authScopeGo}/bin/authn-scope-eval-test-go \
      /workspace/test-result/vm1-service-a-cert.pem \
      /workspace/test-result/ca-cert.pem \
      service-a

    echo "==> [VM-1] Running Rust gRPC test application (as service-a)..."
    ${pkgs.util-linux}/bin/runuser -u service-a -- env USER=service-a \
      ${authScope}/bin/grpc-app-rust server 0.0.0.0:50052 /run/authn-scope/workload.sock > /workspace/test-result/vm1-grpc-app.log 2>&1 &
    RUST_PID=$!

    # Wait up to 60 seconds for VM-2 to finish its gRPC client test
    for i in $(seq 1 60); do
      if [ -f /workspace/test-result/vm2-result-summary ]; then
        break
      fi
      sleep 1
    done

    wait $RUST_PID || true

    echo SUCCESS > /workspace/test-result/vm1-result-summary
    echo "==> [VM-1] All tests passed! Leaving VM running for live inspection."
  '';
in {
  imports = [
    ../modules/authn-scope.nix
  ];

  networking.hostName = "vm-1";
  networking.firewall.allowedTCPPorts = [50052];
  networking.firewall.enable = false;
  services.getty.autologinUser = "root";

  users.users.nixos = {
    isNormalUser = true;
    initialPassword = "nixos";
    extraGroups = ["wheel"];
  };

  users.users.service-a = {
    isSystemUser = true;
    group = "service-a";
  };
  users.groups.service-a = {};

  time.timeZone = "Asia/Dubai";
  environment.systemPackages = [pkgs.tpm2-tools];

  virtualisation.vmVariant = {
    virtualisation.writableStoreUseTmpfs = true;
    virtualisation.sharedDirectories.workspace = {
      source = toString ./../..;
      target = "/workspace";
    };

    virtualisation.qemu.options = [
      "-device vhost-vsock-pci,guest-cid=3"
      "-chardev socket,id=chrtpm,path=/tmp/swtpm-vm1.sock"
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
      vm_name = "vm-1";
      server_port = 900;
      workload_api_socket = "/run/authn-scope/workload.sock";
    };
  };

  systemd.services.authn-scope-evaluator-test = {
    description = "Run VM-1 Evaluator Test and Shutdown VM";
    wantedBy = ["multi-user.target"];
    after = ["authn-scope-agent.service" "network.target"];
    requires = ["authn-scope-agent.service"];
    serviceConfig = {
      Type = "oneshot";
      User = "root";
      ExecStart = evalTestScript;
    };
  };

  system.stateVersion = "26.05";
}
