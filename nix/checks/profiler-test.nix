{
  pkgs,
  authScope,
}: let
  testModule = {lib, ...}: {
    environment.systemPackages = [authScope];
  };
in
  pkgs.testers.runNixOSTest {
    name = "authn-scope-profiler-test";
    nodes.machine = testModule;

    testScript = ''
      machine.wait_for_unit("multi-user.target")

      output = machine.succeed("profiler")
      print("\n=== PROFILER OUTPUT ===")
      print(output)
      print("=======================\n")
    '';
  }
