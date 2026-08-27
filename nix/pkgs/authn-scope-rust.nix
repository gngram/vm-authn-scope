{
  lib,
  rustPlatform,
  pkg-config,
  tpm2-tss,
}: let
  cleanSrc = lib.cleanSourceWith {
    src = ../../.;
    filter = name: type: let
      base = baseNameOf name;
    in
      base
      == "Cargo.lock"
      || base == "Cargo.toml"
      || (type == "directory" && (base == "apps" || base == "libs"))
      || lib.hasPrefix (toString ../../apps) name
      || lib.hasPrefix (toString ../../libs) name;
  };
in
  rustPlatform.buildRustPackage {
    pname = "authn-scope";
    version = "0.1.0";
    src = cleanSrc;
    cargoLock.lockFile = ../../Cargo.lock;
    nativeBuildInputs = [pkg-config];
    buildInputs = [tpm2-tss];
    doCheck = false;
  }
