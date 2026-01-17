fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/continuum.proto");
    println!("cargo:rerun-if-changed=proto/enrollment.proto");

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(out_dir.join("continuum_descriptor.bin"))
        .compile_protos(
            &["proto/continuum.proto", "proto/enrollment.proto"],
            &["proto"],
        )?;

    Ok(())
}
