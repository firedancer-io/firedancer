fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .compile_protos(&["../../src/disco/events/schema/event.proto"], &["../../src/disco/events/schema"])?;
    Ok(())
}
