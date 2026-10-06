fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/service.proto");
    println!("cargo:rerun-if-changed=proto/compact_formats.proto");
    println!("cargo:rerun-if-changed=proto/snapshot.proto");
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure().compile_with_config(
        config,
        &["proto/service.proto", "proto/snapshot.proto"],
        &["proto"],
    )?;
    Ok(())
}
