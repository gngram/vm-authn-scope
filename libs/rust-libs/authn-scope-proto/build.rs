fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .compile_protos(
            &["proto/spiffe/workload/workload.proto"],
            &["proto/spiffe/workload"],
        )?;
    Ok(())
}
