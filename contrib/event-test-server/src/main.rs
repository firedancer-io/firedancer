use std::sync::Arc;

use async_stream::try_stream;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
};
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::{
    version, DigitallySignedStruct, Error as TlsError, ServerConfig, SignatureScheme,
};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::server::{TcpConnectInfo, TlsConnectInfo},
    transport::Server,
    Request, Response, Status,
};

pub mod events {
    tonic::include_proto!("events.v1");
}

use events::event::Event;
use events::event_service_server::{EventService, EventServiceServer};
use events::{HelloRequest, HelloResponse, StreamEventsRequest, StreamEventsResponse};

const ALPN_H2: &[u8] = b"h2";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

const SERVER_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x4f, 0x30, 0x82, 0x01, 0x01, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x72,
    0xe9, 0x82, 0x60, 0xef, 0x3b, 0xa1, 0x19, 0xd3, 0x9c, 0x24, 0x06, 0x7e, 0x63, 0xf0, 0x8f, 0x45,
    0x6b, 0x1f, 0x48, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x1c, 0x31, 0x1a, 0x30, 0x18,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x65, 0x73,
    0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x36,
    0x30, 0x31, 0x30, 0x31, 0x30, 0x34, 0x34, 0x31, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30,
    0x35, 0x30, 0x38, 0x30, 0x31, 0x30, 0x34, 0x34, 0x31, 0x5a, 0x30, 0x1c, 0x31, 0x1a, 0x30, 0x18,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x65, 0x73,
    0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x70, 0x03, 0x21, 0x00, 0x23, 0x8b, 0xc4, 0xee, 0x4d, 0xa9, 0x3f, 0x52, 0x43, 0x3e, 0xe3, 0x23,
    0xb7, 0x0d, 0xfe, 0xb7, 0xa3, 0x0c, 0x21, 0xd3, 0xb3, 0x23, 0x05, 0x6c, 0x6e, 0xa7, 0xd3, 0x17,
    0xbf, 0xfc, 0xe1, 0xa1, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    0x16, 0x04, 0x14, 0x79, 0x03, 0xc0, 0xd9, 0x41, 0x63, 0x05, 0xbe, 0xca, 0x8c, 0xeb, 0x6b, 0x2b,
    0x69, 0xb1, 0xd9, 0xc0, 0x22, 0x59, 0x2a, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0x79, 0x03, 0xc0, 0xd9, 0x41, 0x63, 0x05, 0xbe, 0xca, 0x8c, 0xeb, 0x6b,
    0x2b, 0x69, 0xb1, 0xd9, 0xc0, 0x22, 0x59, 0x2a, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x03, 0x41, 0x00, 0x9d, 0xbe, 0x72, 0xd7, 0xcb, 0x17, 0xb6, 0x61, 0x3d, 0x9f, 0x68, 0xc3, 0x07,
    0xb1, 0x6a, 0x3a, 0x69, 0xd7, 0xc8, 0xc3, 0xcd, 0x20, 0xc4, 0x43, 0x8b, 0x87, 0xa2, 0xb3, 0x44,
    0x83, 0xca, 0x7f, 0xb7, 0xbf, 0x11, 0x11, 0x11, 0x26, 0xd1, 0x44, 0xf0, 0x74, 0x99, 0xe2, 0xcf,
    0x1d, 0x19, 0xb7, 0xf0, 0xc9, 0x6d, 0xb5, 0x0d, 0x58, 0x12, 0x54, 0x10, 0x87, 0xcd, 0x65, 0x3b,
    0xa1, 0x68, 0x01,
];

// This key is plaintext intentionally -- this file is only used for
// testing.
const SERVER_KEY_DER: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x22, 0xe8, 0xff, 0xec, 0xd8, 0x12, 0x17, 0xc1, 0x60, 0xe2, 0xf6, 0xe7, 0xf4, 0x87, 0x6d, 0xdb,
    0x7d, 0xf4, 0x9b, 0x55, 0x83, 0x5f, 0x37, 0xb3, 0xe4, 0x50, 0x33, 0x8b, 0x6e, 0x33, 0xaf, 0xb9,
];

fn event_kind_name(event: &Option<events::Event>) -> &'static str {
    match event.as_ref().and_then(|e| e.event.as_ref()) {
        Some(Event::Txn(_)) => "Txn",
        Some(Event::Shred(_)) => "Shred",
        None => "<none>",
    }
}

fn client_public_key(request: &Request<tonic::Streaming<StreamEventsRequest>>) -> Option<[u8; 32]> {
    let connect_info = request
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()?;
    let certs = connect_info.peer_certs()?;
    let spki = certs.first()?.as_ref();
    spki.strip_prefix(ED25519_SPKI_PREFIX)?.try_into().ok()
}

#[derive(Debug)]
struct AnyRpkVerifier {
    supported_algs: tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms,
}

impl AnyRpkVerifier {
    fn new() -> Self {
        Self {
            supported_algs: ring::default_provider().signature_verification_algorithms,
        }
    }

    fn is_ed25519_subject_public_key_info(spki: &[u8]) -> bool {
        spki.len() == ED25519_SPKI_PREFIX.len() + 32 && spki.starts_with(ED25519_SPKI_PREFIX)
    }
}

impl ClientCertVerifier for AnyRpkVerifier {
    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::General(
                "client raw public key must not include intermediates".into(),
            ));
        }
        if !Self::is_ed25519_subject_public_key_info(end_entity.as_ref()) {
            return Err(TlsError::General(
                "client raw public key must be Ed25519 SubjectPublicKeyInfo".into(),
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General(
            "raw public key client authentication requires TLS 1.3".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        tokio_rustls::rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn tls_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cert = CertificateDer::from(SERVER_CERT_DER.to_vec());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(SERVER_KEY_DER.to_vec()));
    let verifier = Arc::new(AnyRpkVerifier::new());
    let mut config = ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)?;
    config.alpn_protocols.push(ALPN_H2.to_vec());
    Ok(config)
}

fn tls_incoming(
    listener: TcpListener,
    acceptor: TlsAcceptor,
) -> impl tokio_stream::Stream<
    Item = Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error>,
> {
    try_stream! {
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            match acceptor.accept(stream).await {
                Ok(tls_stream) => yield tls_stream,
                Err(err) => eprintln!("TLS handshake failed from {peer_addr}: {err}"),
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct MyEventService;

#[tonic::async_trait]
impl EventService for MyEventService {
    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn hello(
        &self,
        _request: Request<HelloRequest>,
    ) -> Result<Response<HelloResponse>, Status> {
        println!("Received hello request");
        Ok(Response::new(HelloResponse {}))
    }

    async fn stream_events(
        &self,
        request: Request<tonic::Streaming<StreamEventsRequest>>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        match client_public_key(&request) {
            Some(public_key) => println!("Client connected: public_key={}", hex::encode(public_key)),
            None => println!("Client connected: public_key=<unknown>"),
        }

        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            loop {
                match stream.message().await {
                    Ok(Some(event_tx)) => {
                        println!(
                            "Received event: nonce={}, event_id={}, kind={}",
                            event_tx.nonce,
                            event_tx.event_id,
                            event_kind_name(&event_tx.event)
                        );
                        let ack = StreamEventsResponse {
                            nonce: event_tx.nonce,
                        };
                        if tx.send(Ok(ack)).await.is_err() {
                            eprintln!("Failed to send ack, client disconnected");
                            break;
                        }
                    }
                    Ok(None) => {
                        println!("Client closed stream");
                        break;
                    }
                    Err(e) => {
                        println!("Error receiving event: {:?}", e);
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:7878";
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config()?));
    println!("Listening on https://{}", addr);

    Server::builder()
        .add_service(EventServiceServer::new(MyEventService))
        .serve_with_incoming(tls_incoming(listener, acceptor))
        .await?;

    Ok(())
}
