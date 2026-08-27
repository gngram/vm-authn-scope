# agent-vm2.nix
# NixOS VM configuration for Integration Test Guest 2 (vm-2).
# Boots as CID=4 with dedicated vTPM (/tmp/swtpm-vm2.sock).
{
  config,
  pkgs,
  ...
}: let
  authScope   = pkgs.callPackage ../pkgs/authn-scope-rust.nix {};
  authScopeGo = pkgs.callPackage ../pkgs/authn-scope-go.nix {};

  evalTestScript = pkgs.writeShellScript "run-eval-test" ''
    set -e
    trap 'echo FAILURE > /workspace/test-result/vm2-result-summary' ERR

    mkdir -p /workspace/test-result

    echo "==> [VM-2] Waiting for Workload API socket..."
    for i in $(seq 1 30); do
      [ -S /run/authn-scope/workload.sock ] && break
      sleep 1
    done
    [ -S /run/authn-scope/workload.sock ] || { echo "[VM-2] Workload socket never appeared"; exit 1; }

    echo "==> [VM-2] Fetching credentials via Workload API (as service-b)..."
    ${pkgs.util-linux}/bin/runuser -u service-b -- env USER=service-b \
      ${authScope}/bin/workload-test-workload /run/authn-scope/workload.sock

    cp /tmp/workload-cert-service-b.pem /workspace/test-result/vm2-service-b-cert.pem
    cp /tmp/workload-ca-service-b.pem   /workspace/test-result/ca-cert.pem

    echo "==> [VM-2] Evaluating certificate (Rust)..."
    ${authScope}/bin/authn-scope-eval-test \
      /workspace/test-result/vm2-service-b-cert.pem \
      /workspace/test-result/ca-cert.pem \
      service-b

    echo "==> [VM-2] Evaluating certificate (Go)..."
    ${authScopeGo}/bin/authn-scope-eval-test-go \
      /workspace/test-result/vm2-service-b-cert.pem \
      /workspace/test-result/ca-cert.pem \
      service-b

    echo SUCCESS > /workspace/test-result/vm2-result-summary
    echo "==> [VM-2] All tests passed! Leaving VM running for live inspection."
  '';
in {
  imports = [
    ../modules/authn-scope.nix
  ];

  networking.hostName = "vm-2";
  services.getty.autologinUser = "root";

  users.users.nixos = {
    isNormalUser = true;
    initialPassword = "nixos";
    extraGroups = ["wheel"];
  };

  users.users.service-b = {
    isSystemUser = true;
    group        = "service-b";
  };
  users.groups.service-b = {};

  time.timeZone = "Asia/Dubai";
  environment.systemPackages = [pkgs.tpm2-tools];

  virtualisation.vmVariant = {
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
    enable  = true;
    package = authScope;
    settings = {
      vm_name             = "vm-2";
      server_port         = 900;
      workload_api_socket = "/run/authn-scope/workload.sock";
    };
  };

  systemd.services.authn-scope-evaluator-test = {
    description = "Run VM-2 Evaluator Test and Shutdown VM";
    wantedBy    = ["multi-user.target"];
    after       = ["authn-scope-agent.service" "network.target"];
    requires    = ["authn-scope-agent.service"];
    serviceConfig = {
      Type      = "oneshot";
      User      = "root";
      ExecStart = evalTestScript;
    };
  };

  system.stateVersion = "26.05";
}
