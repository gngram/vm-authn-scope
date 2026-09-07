{
  buildGoModule,
}:
buildGoModule {
  pname = "grpc-app-go";
  version = "0.1.0";
  src = ../../testapp/grpc-app-go;
  proxyVendor = true;
  vendorHash = "sha256-lYdTva9uxPym+qeKyP4jaINicvF/CutxKOjX0ZAFzoI=";
}
