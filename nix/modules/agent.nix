{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.authn-scope.agent;
  shared = config.services.authn-scope;
in {
  options.services.authn-scope.agentPort = lib.mkOption {
    type = lib.types.port;
    default = 901;
    description = "The vsock port the agent binds/dials from.";
  };

  options.services.authn-scope.agent = {
    enable = lib.mkEnableOption "VM-AuthN-Scope Agent";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The authn-scope package to use.";
    };

    settings = lib.mkOption {
      type = (pkgs.formats.json {}).type;
      default = {};
      description = "Configuration for the agent, mapped directly to `agent.json`. Detailed documentation is available at [docs/agent_configuration.md](../../docs/agent_configuration.md) and sample file at [config-examples/agent.json](../../config-examples/agent.json).";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [cfg.package];

    services.udev.extraRules = ''
      KERNEL=="vsock", TAG+="systemd"
    '';

    environment.etc."authn-scope/agent.json".source =
      (pkgs.formats.json {}).generate "agent.json" ({
        vm_name = config.networking.hostName;
      } // cfg.settings // {
        client_port = shared.agentPort;
      });

    systemd.services.authn-scope-agent = {
      description = "VM-AuthN-Scope Agent";
      # Anchor to early boot instead of normal multi-user startup
      wantedBy = [ "sysinit.target" ];
      unitConfig = {
        DefaultDependencies = false;
      };
      bindsTo = [ "dev-vsock.device" ];
      after = [ "dev-vsock.device" ];
      before = [ "sysinit.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/authn-scope-agent --config /etc/authn-scope/agent.json";
        Restart = "always";
      };
    };
  };
}
