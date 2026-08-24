# my-vm.nix
# This is a standard NixOS configuration, just like your system's configuration.nix
{
  config,
  pkgs,
  ...
}: let
  authScope = pkgs.callPackage ../pkgs/authn-scope-rust.nix {};
  authScopeGo = pkgs.callPackage ../pkgs/authn-scope-go.nix {};
in {
  imports = [
    ../modules/authn-scope.nix
  ];

  # Set a hostname for the VM
  networking.hostName = "authn-scope";
  nix.settings.experimental-features = ["nix-command" "flakes"];
  nix.nixPath = ["nixpkgs=${pkgs.path}"];

  # --- User Accounts ---
  # Create a user 'demo' with password 'nixos' so you can log in.
  users.users.demo = {
    isNormalUser = true;
    initialPassword = "nixos";
    extraGroups = ["wheel"]; # For sudo access
  };

  # Set the timezone to your current location for convenience
  time.timeZone = "Asia/Dubai";

  # --- Shared Workspace & VSOCK Configuration ---
  virtualisation.vmVariant = {
    virtualisation.sharedDirectories.workspace = {
      source = toString ./../..;
      target = "/workspace";
    };

    virtualisation.qemu.options = [
      "-device vhost-vsock-pci,guest-cid=3"
    ];
  };

  # --- VM-AuthN-Scope Agent Configuration ---
  services.authn-scope.agent = {
    enable = true;
    package = authScope;
    settings = {
      vm_name = "local-vm";
      server_port = 900;
      identities = [
        {
          name = "service-b";
          cert_path = "/workspace/test-result/service-b-cert.pem";
          key_path = "/workspace/test-result/service-b-key.pem";
          ca_path = "/workspace/test-result/service-b-ca.pem";
          owner_user = "root";
          owner_group = "root";
          cert_mode = "0644";
          key_mode = "0600";
        }
        {
          name = "service-a";
          cert_path = "/workspace/test-result/service-a-cert.pem";
          key_path = "/workspace/test-result/service-a-key.pem";
          ca_path = "/workspace/test-result/service-a-ca.pem";
          owner_user = "root";
          owner_group = "root";
          cert_mode = "0644";
          key_mode = "0600";
        }
      ];
    };
  };

  # --- Evaluator Test Coordination Service ---
  systemd.services.authn-scope-evaluator-test = {
    description = "Run VM-AuthN-Scope Evaluator Test and Shutdown VM";
    wantedBy = ["multi-user.target"];
    after = ["authn-scope-agent.service"];
    requires = ["authn-scope-agent.service"];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = pkgs.writeShellScript "run-eval-test" ''
        # Run tests and capture result
        echo "==> Evaluating generated capabilities (Rust)..."
        if ${authScope}/bin/authn-scope-eval-test \
          /workspace/test-result/service-a-cert.pem \
          /workspace/test-result/ca-cert.pem && \
          echo "==> Evaluating generated capabilities (Go)..." && \
          ${authScopeGo}/bin/authn-scope-eval-test-go \
          /workspace/test-result/service-a-cert.pem \
          /workspace/test-result/ca-cert.pem; then
            echo "SUCCESS" > /workspace/test-result/result-summary
        else
            echo "FAILURE" > /workspace/test-result/result-summary
        fi
      '';
    };
  };

  # --- Basic System Settings ---
  system.stateVersion = "26.05";
}
