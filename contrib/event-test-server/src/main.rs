use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use prost::Message;
use std::marker::PhantomData;

pub mod events {
    tonic::include_proto!("events.v1");
}

use events::event_service_server::{EventService, EventServiceServer};
use events::{
    StreamEventsRequest, StreamEventsResponse,
    StreamEventsZstdRequest, StreamEventsZstdResponse,
    AuthenticateRequest, AuthenticateResponse,
};
use events::event::Event;

fn event_kind_name(event: &Option<events::Event>) -> &'static str {
    match event.as_ref().and_then(|e| e.event.as_ref()) {
        Some(Event::Txn(_)) => "Txn",
        Some(Event::Shred(_)) => "Shred",
        Some(_) => "<other>",
        None => "<none>",
    }
}

#[derive(Debug, Default)]
pub struct MyEventService;

/// Ack each event and log it; shared by both stream RPCs.
fn handle_events(
    mut events: impl tokio_stream::Stream<Item = Result<Vec<StreamEventsRequest>, Status>> + Unpin + Send + 'static,
) -> ReceiverStream<Result<StreamEventsResponse, Status>> {
    use tokio_stream::StreamExt;
    let (tx, rx) = mpsc::channel(128);
    tokio::spawn(async move {
        loop {
            match events.next().await {
                Some(Ok(batch)) => {
                    // Heartbeat: no-op ack so the client sees a response
                    if batch.is_empty() && tx.send(Ok(StreamEventsResponse { nonce: u64::MAX })).await.is_err() {
                        return;
                    }
                    for event_tx in batch {
                        println!("Received event: nonce={}, event_id={}, kind={}",
                            event_tx.nonce, event_tx.event_id, event_kind_name(&event_tx.event));
                        let ack = StreamEventsResponse { nonce: event_tx.nonce };
                        if tx.send(Ok(ack)).await.is_err() {
                            eprintln!("Failed to send ack, client disconnected");
                            return;
                        }
                    }
                }
                None => {
                    println!("Client closed stream");
                    return;
                }
                Some(Err(e)) => {
                    println!("Error receiving event: {:?}", e);
                    return;
                }
            }
        }
    });
    ReceiverStream::new(rx)
}

#[tonic::async_trait]
impl EventService for MyEventService {
    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn authenticate(
        &self,
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthenticateResponse>, Status> {
        println!("Received authenticate request from identity: {:?}",
            hex::encode(&request.get_ref().identity_pubkey));
        let challenge = vec![0u8; 217];
        Ok(Response::new(AuthenticateResponse { challenge, max_stream_body: 0 }))
    }

    async fn stream_events(
        &self,
        request: Request<tonic::Streaming<StreamEventsRequest>>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        use tokio_stream::StreamExt;
        println!("Client connected");
        let events = request.into_inner().map(|r| r.map(|e| vec![e]));
        Ok(Response::new(handle_events(Box::pin(events))))
    }

    type StreamEventsZstdStream = ReceiverStream<Result<StreamEventsZstdResponse, Status>>;

    /// Unused: StreamEventsZstd is routed to `zstd_route` before the generated service.
    async fn stream_events_zstd(
        &self,
        _request: Request<tonic::Streaming<StreamEventsZstdRequest>>,
    ) -> Result<Response<Self::StreamEventsZstdStream>, Status> {
        Err(Status::unimplemented("routed separately"))
    }
}

/// StreamEventsZstd: one zstd stream per call, each gRPC message the compressor output at one
/// flush; decompressed, the stream is varint(len) | StreamEventsRequest, repeated.
struct ZstdCodec;

struct ZstdDecoder {
    dctx: zstd::stream::raw::Decoder<'static>,
    pending: Vec<u8>,
}

impl tonic::codec::Codec for ZstdCodec {
    type Encode = StreamEventsResponse;
    type Decode = Vec<StreamEventsRequest>;
    type Encoder = tonic_prost::ProstEncoder<StreamEventsResponse>;
    type Decoder = ZstdDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        tonic_prost::ProstEncoder::new(tonic::codec::BufferSettings::default())
    }

    fn decoder(&mut self) -> Self::Decoder {
        let mut dctx = zstd::stream::raw::Decoder::new().expect("zstd decoder");
        dctx.set_parameter(zstd::stream::raw::DParameter::WindowLogMax(20)).expect("zstd window");
        ZstdDecoder { dctx, pending: Vec::new() }
    }
}

impl tonic::codec::Decoder for ZstdDecoder {
    type Item = Vec<StreamEventsRequest>;
    type Error = Status;

    fn decode(&mut self, buf: &mut tonic::codec::DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        use bytes::Buf;
        use zstd::stream::raw::{InBuffer, Operation, OutBuffer};
        let chunk = buf.copy_to_bytes(buf.remaining());
        let mut input = InBuffer::around(&chunk[..]);
        let mut out = [0u8; 64 * 1024];
        loop {
            let mut output = OutBuffer::around(&mut out[..]);
            self.dctx.run(&mut input, &mut output).map_err(|e| Status::invalid_argument(format!("zstd: {e}")))?;
            let n = output.pos();
            self.pending.extend_from_slice(&out[..n]);
            if input.pos() == chunk.len() && n < out.len() {
                break;
            }
        }
        let mut events = Vec::new();
        let mut off = 0usize;
        loop {
            let mut rest = &self.pending[off..];
            let before = rest.len();
            let Ok(len) = prost::encoding::decode_varint(&mut rest) else { break };
            let len = len as usize;
            if rest.len() < len {
                break;
            }
            let start = off + (before - rest.len());
            let event = StreamEventsRequest::decode(&self.pending[start..start + len])
                .map_err(|e| Status::invalid_argument(format!("event: {e}")))?;
            events.push(event);
            off = start + len;
        }
        self.pending.drain(..off);
        Ok(Some(events))
    }

    fn buffer_settings(&self) -> tonic::codec::BufferSettings {
        tonic::codec::BufferSettings::default()
    }
}

struct ZstdSvc;

impl tonic::server::StreamingService<Vec<StreamEventsRequest>> for ZstdSvc {
    type Response = StreamEventsResponse;
    type ResponseStream = ReceiverStream<Result<StreamEventsResponse, Status>>;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response<Self::ResponseStream>, Status>> + Send>>;

    fn call(&mut self, request: Request<tonic::Streaming<Vec<StreamEventsRequest>>>) -> Self::Future {
        println!("Client connected (zstd)");
        let events = request.into_inner();
        Box::pin(async move { Ok(Response::new(handle_events(events))) })
    }
}

/// Routes StreamEventsZstd to `ZstdSvc` and everything else to the generated service.
#[derive(Clone)]
struct Router<S> {
    inner: S,
    _pd: PhantomData<()>,
}

impl<S> tower::Service<http::Request<tonic::body::Body>> for Router<S>
where
    S: tower::Service<http::Request<tonic::body::Body>, Response = http::Response<tonic::body::Body>, Error = std::convert::Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        if req.uri().path() == "/events.v1.EventService/StreamEventsZstd" {
            return Box::pin(async move {
                Ok(tonic::server::Grpc::new(ZstdCodec)
                    .max_decoding_message_size(16 * 1024 * 1024)
                    .streaming(ZstdSvc, req).await)
            });
        }
        Box::pin(self.inner.call(req))
    }
}

impl<S> tonic::server::NamedService for Router<S> {
    const NAME: &'static str = "events.v1.EventService";
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:7878".parse()?;
    println!("Listening on {}", addr);

    Server::builder()
        .add_service(Router { inner: EventServiceServer::new(MyEventService), _pd: PhantomData })
        .serve(addr)
        .await?;

    Ok(())
}
