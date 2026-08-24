{
  lib,
  rustPlatform,
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
    doCheck = false;
  }
