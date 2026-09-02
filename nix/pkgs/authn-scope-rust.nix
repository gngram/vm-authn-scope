{
  lib,
  rustPlatform,
  pkg-config,
  tpm2-tss,
  protobuf,
}: let
  cleanSrc = lib.cleanSourceWith {
    src = ../../.;
    filter = name: type: let
      base = baseNameOf name;
    in
      base
      == "Cargo.lock"
      || base == "Cargo.toml"
      || (type == "directory" && (base == "apps" || base == "libs" || base == "testapp"))
      || lib.hasPrefix (toString ../../apps) name
      || lib.hasPrefix (toString ../../libs) name
      || lib.hasPrefix (toString ../../testapp) name;
  };
in
  rustPlatform.buildRustPackage {
    pname = "authn-scope";
    version = "0.1.0";
    src = cleanSrc;
    cargoLock.lockFile = ../../Cargo.lock;
    nativeBuildInputs = [pkg-config protobuf];
    buildInputs = [tpm2-tss];
    doCheck = false;
  }
