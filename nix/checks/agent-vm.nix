# agent-vm.nix
# NixOS VM configuration for the integration test guest.
# Boots as CID=3, connects to the host server over vsock, performs a handshake,
# fetches certs for service-a via the Workload API, evaluates them and writes
# "SUCCESS" / "FAILURE" to /workspace/test-result/result-summary then shuts down.
{
  config,
  pkgs,
  ...
}: let
  authScope   = pkgs.callPackage ../pkgs/authn-scope-rust.nix {};
  authScopeGo = pkgs.callPackage ../pkgs/authn-scope-go.nix {};

  evalTestScript = pkgs.writeShellScript "run-eval-test" ''
    set -e
    trap 'echo FAILUReeeE > /workspace/test-result/result-summary' ERR

    # Ensure output directory is writable
    mkdir -p /workspace/test-result

    # Wait up to 30 s for the Workload API socket to appear
    echo "==> Waiting for Workload API socket..."
    for i in $(seq 1 30); do
      [ -S /run/authn-scope/workload.sock ] && break
      sleep 1
    done
    [ -S /run/authn-scope/workload.sock ] || { echo "Workload socket never appeared"; exit 1; }

    echo "==> Fetching credentials via Workload API (as service-a)..."
    # Use runuser (no PAM) to switch to service-a so the UNIX selector matches.
    # workload-test-workload writes to /tmp/workload-cert-<USER>.pem
    ${pkgs.util-linux}/bin/runuser -u service-a -- env USER=service-a \
      ${authScope}/bin/workload-test-workload /run/authn-scope/workload.sock

    # Copy the issued cert to the shared workspace for inspection
    cp /tmp/workload-cert-service-a.pem /workspace/test-result/service-a-cert.pem
    cp /tmp/workload-ca-service-a.pem   /workspace/test-result/ca-cert.pem

    echo "==> Evaluating certificate (Rust)..."
    ${authScope}/bin/authn-scope-eval-test \
      /workspace/test-result/service-a-cert.pem \
      /workspace/test-result/ca-cert.pem

    echo "==> Evaluating certificate (Go)..."
    ${authScopeGo}/bin/authn-scope-eval-test-go \
      /workspace/test-result/service-a-cert.pem \
      /workspace/test-result/ca-cert.pem

    echo SUCCESS > /workspace/test-result/result-summary
    echo "==> All tests passed! Shutting down VM."
    poweroff -f
  '';
in {
  imports = [
    ../modules/authn-scope.nix
  ];

  # --- Hostname ---
  networking.hostName = "authn-scope";

  users.users.nixos = {
    isNormalUser = true;
    initialPassword = "nixos";
    extraGroups = ["wheel"]; # For sudo access
  };

  # --- User Accounts ---
  # service-a system user so the agent's UNIX selector can match it
  users.users.service-a = {
    isSystemUser = true;
    group        = "service-a";
  };
  users.groups.service-a = {};

  time.timeZone = "Asia/Dubai";

  # --- Shared Workspace & VSOCK / vTPM Configuration ---
  environment.systemPackages = [pkgs.tpm2-tools];

  virtualisation.vmVariant = {
    virtualisation.sharedDirectories.workspace = {
      source = toString ./../..;
      target = "/workspace";
    };

    virtualisation.qemu.options = [
      "-device vhost-vsock-pci,guest-cid=3"
      "-chardev socket,id=chrtpm,path=/tmp/swtpm-agent.sock"
      "-tpmdev emulator,id=tpm0,chardev=chrtpm"
      "-device tpm-tis,tpmdev=tpm0"
    ];
  };

  # --- Workload API socket directory ---
  systemd.tmpfiles.rules = [
    "d /run/authn-scope 0755 root root -"
  ];

  # --- Agent Configuration ---
  services.authn-scope.agent = {
    enable  = true;
    package = authScope;
    settings = {
      vm_name             = "local-vm";
      server_port         = 900;
      workload_api_socket = "/run/authn-scope/workload.sock";
    };
  };

  # --- Evaluator Test Service ---
  # Runs as root so it can write to /workspace and call runuser for the workload fetch.
  # On any error the ERR trap writes FAILURE and powers off the VM.
  systemd.services.authn-scope-evaluator-test = {
    description = "Run VM-AuthN-Scope Evaluator Test and Shutdown VM";
    wantedBy    = ["multi-user.target"];
    after       = ["authn-scope-agent.service" "network.target"];
    requires    = ["authn-scope-agent.service"];
    serviceConfig = {
      Type      = "oneshot";
      User      = "root";
      ExecStart = evalTestScript;
    };
  };

  # --- Basic System Settings ---
  system.stateVersion = "26.05";
}
