{
  lib,
  rustPlatform,
  pkg-config,
  tpm2-tss,
  protobuf,
}: let
  srcFilter = path: type:
    let
      baseName = baseNameOf (toString path);
    in
      !(lib.hasPrefix "test-result" baseName
        || lib.hasPrefix "target" baseName
        || lib.hasPrefix "result" baseName
        || baseName == ".git"
        || baseName == ".direnv")
      && lib.cleanSourceFilter path type;

  cleanSrc = lib.cleanSourceWith {
    filter = srcFilter;
    src = ../../.;
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
