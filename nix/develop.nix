{pkgs}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    rustc
    gcc
    pkg-config
    rustfmt
    clippy
    alejandra
    qemu
    go
    tpm2-tss
    tpm2-tools
    swtpm
    openssl
  ];

  shellHook = ''
    clear
    alias run-integration-test="sudo --preserve-env=PKG_CONFIG_PATH,PATH ./scripts/run_integration_test.sh"
    alias run-nixos-module-test='nix build .#checks.\${pkgs.stdenv.hostPlatform.system}.vm-test.driver -o target/vm-test-driver && ./target/vm-test-driver/bin/nixos-test-driver'
    alias run-profiler='nix build .#checks.\${pkgs.stdenv.hostPlatform.system}.profiler-test.driver -o target/profiler-test-driver && ./target/profiler-test-driver/bin/nixos-test-driver'
    
    echo -e "\n\033[1;32m            -- development shell for vm-authn-scope -- \033[0m\n"
    echo -e "\033[1;33mCommands:\033[0m"
    echo -e "\033[1;34mrun-integration-test:\033[0m    Execute the test suite for integration verification."
    echo -e "\033[1;34mrun-nixos-module-test:\033[0m   Execute NixOS tests to validate system modules."
    echo -e "\033[1;34mrun-profiler:\033[0m            Run profiler."
    echo -e "\033[1;32m                                 --- \033[0m\n"
    export PS1="\[\033[1;32m\][DEVELOP]\[\033[0m\] $PS1"
  '';
}
