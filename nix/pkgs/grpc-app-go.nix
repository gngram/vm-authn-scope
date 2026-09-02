{
  lib,
  buildGoModule,
}: let
  cleanSrc = lib.cleanSourceWith {
    src = ../../.;
    filter = name: type: let
      base = baseNameOf name;
    in
      base == "go.mod" || base == "go.sum" ||
      (type == "directory" && (base == "testapp" || base == "libs" || base == "grpc-app-go" || base == "go-libs" || base == "authn-scope-workload")) ||
      lib.hasPrefix (toString ../../testapp/grpc-app-go) name ||
      lib.hasPrefix (toString ../../libs/go-libs/authn-scope-workload) name;
  };
in
  buildGoModule {
    pname = "grpc-app-go";
    version = "0.1.0";
    src = cleanSrc;
    preBuild = "cd testapp/grpc-app-go";
    subPackages = ["."];
    proxyVendor = true;
    vendorHash = "sha256-zX+D0PuicHNppEuuAEvaiXXweQQXSJwOmP9iaFuQYho=";
  }
