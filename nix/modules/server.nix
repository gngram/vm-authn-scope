{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.authn-scope.server;
  shared = config.services.authn-scope;
in {
  options.services.authn-scope.serverPort = lib.mkOption {
    type = lib.types.port;
    default = 900;
    description = "The vsock port the server listens on.";
  };

  options.services.authn-scope.server = {
    enable = lib.mkEnableOption "VM-AuthN-Scope Server";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The authn-scope package to use.";
    };

    settings = lib.mkOption {
      type = (pkgs.formats.json {}).type;
      default = {};
      description = "Configuration for the server, mapped directly to `host.json`. Detailed documentation is available at [docs/server_configuration.md](../../docs/server_configuration.md) and sample file at [config-examples/host.json](../../config-examples/host.json).";
    };

    generateKey = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to generate the CA key on startup (using --genkey).";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [cfg.package];

    services.udev.extraRules = ''
      KERNEL=="vsock", TAG+="systemd"
    '';

    environment.etc."authn-scope/host.json".source =
      (pkgs.formats.json {}).generate "host.json" (cfg.settings // {
        server_port = shared.serverPort;
      });

    systemd.services.authn-scope-server = {
      description = "VM-AuthN-Scope Host Server";
      wantedBy = [ "sysinit.target" ];
      unitConfig = {
        DefaultDependencies = false;
      };
      bindsTo = [ "dev-vsock.device" ];
      after = [ "dev-vsock.device" ];
      before = [ "sysinit.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/authn-scope-server --config /etc/authn-scope/host.json${lib.optionalString cfg.generateKey " --genkey"}";
        Restart = "always";
      };
    };
  };
}
