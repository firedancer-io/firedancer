use tonic_build::configure;

fn main() -> Result<(), std::io::Error> {
    const PROTOC_ENVAR: &str = "PROTOC";
    if std::env::var(PROTOC_ENVAR).is_err() {
        #[cfg(not(windows))]
        std::env::set_var(PROTOC_ENVAR, protobuf_src::protoc());
    }

    let proto_base_path = std::path::PathBuf::from("protos");
    let proto_files = [
        "auth.proto",
        "block_engine.proto",
        "bundle.proto",
        "packet.proto",
        "relayer.proto",
        "shared.proto",
    ];
    let mut protos = Vec::new();
    for proto_file in &proto_files {
        let proto = proto_base_path.join(proto_file);
        println!("cargo:rerun-if-changed={}", proto.display());
        protos.push(proto);
    }

    configure()
        .build_client(true)
        .build_server(false)
        .type_attribute(
            "TransactionErrorType",
            "#[cfg_attr(test, derive(enum_iterator::Sequence))]",
        )
        .type_attribute(
            "InstructionErrorType",
            "#[cfg_attr(test, derive(enum_iterator::Sequence))]",
        )
        .compile(&protos, &[proto_base_path])
}
