use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::{Certificate, DistinguishedName};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async_main(&args));
}

async fn async_main(args: &[String]) {
    match args.get(1).map(|s| s.as_str()) {
        Some("server") => run_server(&args[2..]).await,
        Some("client") => run_client(&args[2..]).await,
        _ => {
            eprintln!("Usage: quinn_test <server/client>");
            std::process::exit(1);
        }
    };
}

fn gen_cert() -> (rustls::Certificate, rustls::PrivateKey) {
    // Hardcode cert and private key as this is a test
    const PRIVATE_KEY_BYTES: [u8; 32] = [
        0xd7, 0x6e, 0x59, 0xeb, 0xd0, 0xb2, 0x91, 0x3e, 0x6f, 0x69, 0xb4, 0x3e, 0x09, 0x92, 0x65,
        0xb4, 0x0d, 0x24, 0x90, 0xe4, 0x21, 0x0c, 0xba, 0x6f, 0x33, 0x0a, 0x3f, 0x38, 0x0e, 0x53,
        0x8d, 0xd9,
    ];
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&PRIVATE_KEY_BYTES).unwrap();
    let mut cert_bytes: Vec<u8> = vec![
        0x30, 0x81, 0xf1, 0x30, 0x81, 0xa4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x11,
        0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x53, 0x6f, 0x6c, 0x61,
        0x6e, 0x61, 0x30, 0x20, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x34, 0x30, 0x39, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x00, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b,
        0x65, 0x70, 0x03, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xa3, 0x29, 0x30, 0x27, 0x30, 0x17, 0x06, 0x03,
        0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x0d, 0x30, 0x0b, 0x82, 0x09, 0x6c, 0x6f, 0x63,
        0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,
        0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
    ];
    cert_bytes[0x5f..0x7f].copy_from_slice(key_pair.public_key().as_ref());
    let cert = rustls::Certificate(cert_bytes);
    let mut private_key_pkcs8 = Vec::<u8>::with_capacity(48);
    private_key_pkcs8.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    private_key_pkcs8.extend_from_slice(&PRIVATE_KEY_BYTES);
    let private_key = rustls::PrivateKey(private_key_pkcs8);

    (cert, private_key)
}

struct IgnoreCert;

impl rustls::client::ServerCertVerifier for IgnoreCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

impl rustls::server::ClientCertVerifier for IgnoreCert {
    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::ClientCertVerified::assertion())
    }
}

async fn run_server(args: &[String]) {
    // Configure server
    let listen_port = match args.get(0).and_then(|x| x.parse::<u16>().ok()) {
        Some(p) => p,
        None => {
            eprintln!("Usage: quinn_test server <port>");
            std::process::exit(1);
        }
    };

    let (cert, private_key) = gen_cert();
    let mut crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(IgnoreCert))
        .with_single_cert(vec![cert], private_key)
        .unwrap();
    crypto.alpn_protocols = vec![b"solana-tpu".to_vec()];

    let local_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listen_port);
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(server_config, local_addr).unwrap();
    let conn = endpoint
        .accept()
        .await
        .expect("Failed to accept connection")
        .await
        .expect("Failed to accept connection");
    eprintln!("Connected");

    let mut stream = conn.accept_uni().await.expect("Failed to accept stream");
    eprintln!("Accepted stream");

    loop {
        let mut buf = [0u8; 1024];
        if stream
            .read(&mut buf)
            .await
            .expect("Failed to read stream data")
            .is_none()
        {
            break;
        }
    }
    eprintln!("Consumed stream");

    drop(conn);
    eprintln!("OK");
    std::process::exit(0);
}

async fn run_client(args: &[String]) {
    let dest_addr = match args.get(0).and_then(|s| SocketAddr::from_str(s).ok()) {
        Some(s) => s,
        None => {
            eprintln!("Usage: quinn_test client <IP>:<port>");
            std::process::exit(1);
        }
    };

    let (cert, private_key) = gen_cert();
    let mut crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(IgnoreCert))
        .with_client_auth_cert(vec![cert], private_key)
        .unwrap();
    crypto.enable_early_data = true;
    crypto.alpn_protocols = vec![b"solana-tpu".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let local_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    let mut endpoint = quinn::Endpoint::client(local_addr).expect("Failed to create endpoint");
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(dest_addr, "server_name")
        .expect("Failed to connect to endpoint")
        .await
        .expect("Failed to connect to endpoint");
    eprintln!("Connected");

    let mut stream = conn.open_uni().await.expect("Failed to open stream");
    eprintln!("Created stream");

    stream.write_all(b"Hello").await.expect("Failed to write stream data");
    eprintln!("Wrote stream data");

    stream.finish().await.expect("Failed to finish stream");
    eprintln!("Peer acknowledged stream data");

    drop(conn);
    eprintln!("OK");
    std::process::exit(0);
}
