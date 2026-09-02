# ==============================================================================
# NixOS Integration Test: Multi-VM TCP Dual-Attestation & Symmetric TPM Sealing
# ==============================================================================
# Architecture Tested:
# 1. 3-Node Topology:
#    - `server`: Host CA Server listening on TCP port 9000 with physical TPM.
#    - `agent1`: Guest VM 1 running authn-scope-agent & workload "service-a".
#    - `agent2`: Guest VM 2 running authn-scope-agent & workload "service-b".
# 2. Production Service Lifecycle:
#    - Dedicated `swtpm.service` units managing AES-256 encrypted NVRAM states.
#    - Automatic `tpm2_startup` on startup via systemd `ExecStartPost`.
#    - Systemd dependency chaining (`requires = [ "swtpm.service" ]`).
# 3. Dual Hardware Attestation & Mutual Nonce Challenges (Version 3 Wire Protocol):
#    - Fresh 32-byte nonces exchanged in both directions without PCR dependency.
#    - Host Physical TPM seals `known_vms.json` -> `known_vms_seal.json`.
#    - Guest vTPM seals `known_server.json` -> `known_server_seal.json`.
# ==============================================================================
{
  pkgs,
  nixosModules,
  authScope,
  authScopeGo,
  grpcAppGo,
}: let
  # ----------------------------------------------------------------------------
  # 1. Common Server Configuration Module (Host CA Node)
  # ----------------------------------------------------------------------------
  commonServerModule = {lib, ...}: {
    imports = [nixosModules.default];

    # Open network firewall ports for CA communication (9000) and TPM emulator (2321/2322)
    networking.firewall.allowedTCPPorts = [9000 2321 2322];
    environment.systemPackages = [pkgs.time authScope pkgs.openssl pkgs.swtpm pkgs.tpm2-tools];

    # Create root-only directories for CA secrets and TPM emulator states
    systemd.tmpfiles.rules = [
      "d /etc/authn-scope/ca 0700 root root"
      "d /etc/swtpm 0700 root root"
      "d /var/lib/swtpm/server 0700 root root"
    ];

    # Dedicated Production systemd unit for the Server's Hardware TPM Emulator
    systemd.services.swtpm = {
      description = "Software TPM 2.0 Daemon (Encrypted State)";
      wantedBy = [];
      before = ["authn-scope-server.service"];
      serviceConfig = {
        Type = "simple";
        ExecStartPre = pkgs.writeShellScript "swtpm-setup" ''
          mkdir -p /var/lib/swtpm/server /etc/swtpm
          if [ ! -f /etc/swtpm/server.key ]; then
            ${pkgs.openssl}/bin/openssl rand -hex 32 > /etc/swtpm/server.key
            chmod 0600 /etc/swtpm/server.key
          fi
          ${pkgs.swtpm}/bin/swtpm_setup --tpm-state /var/lib/swtpm/server --tpm2 --keyfile /etc/swtpm/server.key --create-ek-cert --create-platform-cert 2>/dev/null || true
        '';
        ExecStart = "${pkgs.swtpm}/bin/swtpm socket --tpmstate dir=/var/lib/swtpm/server --key file=/etc/swtpm/server.key,mode=aes-256-cbc,format=hex --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --tpm2 --flags not-need-init";
        ExecStartPost = pkgs.writeShellScript "swtpm-init" ''
          sleep 0.5
          ${pkgs.tpm2-tools}/bin/tpm2_startup -c -T swtpm:host=127.0.0.1,port=2321 2>/dev/null || true
        '';
        Restart = "always";
      };
    };

    # Configure authn-scope-server in TCP mode with dual attestation required for both VMs
    services.authn-scope.server = {
      enable = true;
      package = authScope;
      generateKey = true;
      settings = {
        transport = "tcp";
        listen_addr = "0.0.0.0:9000";
        ca_cert_path = "/etc/authn-scope/ca/ca-cert.pem";
        ca_key_path = "/etc/authn-scope/ca/ca-key.pem";
        vms = {
          "agent-vm1" = {
            ip = "192.168.1.2";
            attestation = {
              required = true;
            };
            identities = {
              service-a = {
                selector = "unix:user:service-a,unix:group:service-a,systemd:unitname:service-a";
                ttl_minutes = 1;
              };
            };
          };
          "agent-vm2" = {
            ip = "192.168.1.3";
            attestation = {
              required = true;
            };
            identities = {
              service-b = {
                selector = "unix:user:service-b,unix:group:service-b,systemd:unitname:service-b";
                ttl_minutes = 1;
              };
            };
          };
        };
      };
    };

    # Bind authn-scope-server to the swtpm service dependency and set TCTI environment
    systemd.services.authn-scope-server = {
      wantedBy = lib.mkForce [];
      requires = ["swtpm.service"];
      after = ["swtpm.service"];
      environment = {
        TPM2TOOLS_TCTI = "swtpm:host=127.0.0.1,port=2321";
        TCTI = "swtpm:host=127.0.0.1,port=2321";
      };
    };
  };

  # ----------------------------------------------------------------------------
  # 2. Reusable Agent VM Configuration Module (Guest Nodes)
  # ----------------------------------------------------------------------------
  agentModule = vmName: identityName: uidVal: isRustApp: {lib, ...}: {
    imports = [nixosModules.default];

    networking.firewall.allowedTCPPorts = [50052];
    environment.systemPackages = [pkgs.time authScope authScopeGo grpcAppGo pkgs.openssl pkgs.swtpm pkgs.tpm2-tools];

    systemd.tmpfiles.rules = [
      "d /etc/swtpm 0700 root root"
      "d /var/lib/swtpm/${vmName} 0700 root root"
    ];

    # Dedicated Production systemd unit for the Guest VM's vTPM Emulator
    systemd.services.swtpm = {
      description = "Software TPM 2.0 Daemon (Encrypted State)";
      wantedBy = [];
      before = ["authn-scope-agent.service"];
      serviceConfig = {
        Type = "simple";
        ExecStartPre = pkgs.writeShellScript "swtpm-setup" ''
          mkdir -p /var/lib/swtpm/${vmName} /etc/swtpm
          if [ ! -f /etc/swtpm/${vmName}.key ]; then
            ${pkgs.openssl}/bin/openssl rand -hex 32 > /etc/swtpm/${vmName}.key
            chmod 0600 /etc/swtpm/${vmName}.key
          fi
          ${pkgs.swtpm}/bin/swtpm_setup --tpm-state /var/lib/swtpm/${vmName} --tpm2 --keyfile /etc/swtpm/${vmName}.key --create-ek-cert --create-platform-cert 2>/dev/null || true
        '';
        ExecStart = "${pkgs.swtpm}/bin/swtpm socket --tpmstate dir=/var/lib/swtpm/${vmName} --key file=/etc/swtpm/${vmName}.key,mode=aes-256-cbc,format=hex --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --tpm2 --flags not-need-init";
        ExecStartPost = pkgs.writeShellScript "swtpm-init" ''
          sleep 0.5
          ${pkgs.tpm2-tools}/bin/tpm2_startup -c -T swtpm:host=127.0.0.1,port=2321 2>/dev/null || true
        '';
        Restart = "always";
      };
    };

    # Create unprivileged workload user & group
    users.groups.${identityName}.gid = uidVal;
    users.users.${identityName} = {
      isSystemUser = true;
      group = identityName;
      uid = uidVal;
    };

    # Configure authn-scope-agent with TCP transport and server hardware attestation requirement
    services.authn-scope.agent = {
      enable = true;
      package = authScope;
      settings = {
        transport = "tcp";
        vm_name = vmName;
        server_addr = "server:9000";
        server_attestation_required = true;
        workload_api_socket = "/run/authn-scope/workload.sock";
      };
    };

    systemd.services.authn-scope-agent = {
      wantedBy = lib.mkForce [];
      requires = ["swtpm.service"];
      after = ["swtpm.service"];
      environment = {
        TPM2TOOLS_TCTI = "swtpm:host=127.0.0.1,port=2321";
        TCTI = "swtpm:host=127.0.0.1,port=2321";
      };
    };

    # gRPC Test Workload Unit: requests credentials from local Workload API & communicates across VMs
    systemd.services."${identityName}" = {
      description = "${identityName} Cross-VM gRPC Workload";
      wantedBy = [];
      after = ["authn-scope-agent.service"];
      serviceConfig = {
        ExecStart =
          if isRustApp
          then "${authScope}/bin/grpc-app-rust server 0.0.0.0:50052 /run/authn-scope/workload.sock"
          else "${grpcAppGo}/bin/grpc-app-go client agent1:50052 /run/authn-scope/workload.sock";
        User = identityName;
        Group = identityName;
        Type = "simple";
        PrivateTmp = false;
        Environment = "USER=${identityName}";
      };
    };
  };
in
  pkgs.testers.runNixOSTest {
    name = "tcp-dual-attestation-test";
    nodes = {
      server = commonServerModule;
      agent1 = agentModule "agent-vm1" "service-a" 997 true;
      agent2 = agentModule "agent-vm2" "service-b" 998 false;
    };

    # --------------------------------------------------------------------------
    # 3. Test Execution Script
    # --------------------------------------------------------------------------
    testScript = ''
      # ------------------------------------------------------------------------
      # Phase 1: Boot All 3 VM Nodes
      # ------------------------------------------------------------------------
      start_all()
      server.wait_for_unit("multi-user.target")
      agent1.wait_for_unit("multi-user.target")
      agent2.wait_for_unit("multi-user.target")

      # ------------------------------------------------------------------------
      # Phase 2: Start CA Server with Production swtpm.service Dependency
      # ------------------------------------------------------------------------
      with subtest("-- start server & production swtpm service --"):
          server.succeed("systemctl start authn-scope-server.service")
          server.wait_for_unit("swtpm.service")
          server.wait_for_unit("authn-scope-server.service")
          print("\033[94m" + "Server online with production swtpm systemd service" + "\033[0m")

      # ------------------------------------------------------------------------
      # Phase 3: Agent 1 Dual Attestation & Rust gRPC Server Start (service-a)
      # ------------------------------------------------------------------------
      with subtest("-- agent 1 dual attestation & rust grpc server --"):
          agent1.succeed("systemctl start authn-scope-agent.service")
          agent1.wait_for_unit("swtpm.service")
          agent1.wait_for_file("/run/authn-scope/workload.sock")

          agent1.wait_for_file("/var/lib/authn-scope/known_server.json")
          agent1.wait_for_file("/var/lib/authn-scope/known_server_seal.json")
          server.wait_for_file("/var/lib/authn-scope/known_vms.json")
          server.wait_for_file("/var/lib/authn-scope/known_vms_seal.json")

          # Start Rust gRPC Server workload on VM 1
          agent1.succeed("systemctl start service-a.service")
          print("\033[94m" + "Agent 1 Dual Attestation & Rust gRPC Server online!" + "\033[0m")

      # ------------------------------------------------------------------------
      # Phase 4: Agent 2 Dual Attestation & Go gRPC Client Connect (service-b)
      # ------------------------------------------------------------------------
      with subtest("-- agent 2 dual attestation & cross-VM Go gRPC client --"):
          agent2.succeed("systemctl start authn-scope-agent.service")
          agent2.wait_for_unit("swtpm.service")
          agent2.wait_for_file("/run/authn-scope/workload.sock")
          agent2.wait_for_file("/var/lib/authn-scope/known_server.json")
          agent2.wait_for_file("/var/lib/authn-scope/known_server_seal.json")

          # Start Go gRPC Client workload on VM 2 (connects across network to VM 1)
          agent2.succeed("systemctl start service-b.service")
          print("\033[94m" + "Agent 2 Dual Attestation & Go gRPC Client online!" + "\033[0m")

      # ------------------------------------------------------------------------
      # Phase 5: Cross-VM mTLS & Automatic Certificate Rotation Verification
      # ------------------------------------------------------------------------
      with subtest("-- verify cross-VM gRPC mTLS & cert rotation --"):
          # Wait for both gRPC workloads to complete rotation and timestamp checks
          agent2.wait_for_unit("service-b.service")
          agent1.wait_for_unit("service-a.service")

          log_a = agent1.succeed("journalctl -u service-a.service")
          log_b = agent2.succeed("journalctl -u service-b.service")

          # Verify peer name extraction from certificate
          assert "Extracted peer name from certificate: 'service-b'" in log_a
          assert "Extracted peer name from certificate: 'service-a'" in log_b

          # Verify timestamp rotation success
          assert "Certificate timestamp verification SUCCESS!" in log_a
          assert "Certificate timestamp verification SUCCESS!" in log_b

          print("\033[94m" + "Extracted peer identities across VM1 (Rust) <-> VM2 (Go) successfully!" + "\033[0m")
          print("\033[94m" + "Verified automatic certificate rotation & timestamp advancement across VMs!" + "\033[0m")
          print("\033[92m" + "ALL MULTI-VM CROSS-NODE gRPC WORKLOAD TESTS PASSED!" + "\033[0m")
    '';
  }
