{
  description = "VM-AuthN-Scope NixOS VM Test";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    treefmt-nix, # Added to outputs destructured argument list
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {inherit system;};

    authScope = pkgs.callPackage ./nix/pkgs/authn-scope-rust.nix {};
    authScopeGo = pkgs.callPackage ./nix/pkgs/authn-scope-go.nix {};

    # Evaluate multi-language treefmt rules for this specific target system
    treefmtEval = treefmt-nix.lib.evalModule pkgs {
      projectRootFile = "flake.nix";

      # Enable requested code formatter programs
      programs.alejandra.enable = true;
      programs.rustfmt.enable = true;
      programs.gofmt.enable = true;
      programs.shfmt = {
        enable = true;
        indent_size = 4;
      };
    };
  in {
    # Binds configuration wrapper dynamically to standard `nix fmt` terminal call
    formatter.${system} = treefmtEval.config.build.wrapper;

    nixosModules.default = ./nix/modules/authn-scope.nix;

    # Pass the treefmt wrapper downstream into your development environment if required
    devShells.${system}.default = import ./nix/develop.nix {
      inherit pkgs;
      # You can reference treefmtEval.config.build.wrapper here if you'd like to append it to your devShell path inside develop.nix
    };

    checks.${system}.vm-test = import ./nix/checks/vm-test.nix {
      inherit pkgs;
      nixosModules = self.nixosModules;
      inherit authScope authScopeGo;
    };
  };
}
