use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};

pub mod events {
    tonic::include_proto!("events.v1");
}

use events::event_service_server::{EventService, EventServiceServer};
use events::{
    StreamEventsRequest, StreamEventsResponse,
    GenerateAuthChallengeRequest, GenerateAuthChallengeResponse,
    ConfirmAuthChallengeRequest, ConfirmAuthChallengeResponse,
};
use events::event::Event;

fn event_kind_name(event: &Option<events::Event>) -> &'static str {
    match event.as_ref().and_then(|e| e.event.as_ref()) {
        Some(Event::Txn(_)) => "Txn",
        Some(Event::Shred(_)) => "Shred",
        Some(Event::MetricsNet(_)) => "MetricsNet",
        Some(Event::MetricsSock(_)) => "MetricsSock",
        Some(Event::MetricsQuic(_)) => "MetricsQuic",
        Some(Event::MetricsSend(_)) => "MetricsSend",
        Some(Event::MetricsBundle(_)) => "MetricsBundle",
        Some(Event::MetricsVerify(_)) => "MetricsVerify",
        Some(Event::MetricsDedup(_)) => "MetricsDedup",
        Some(Event::MetricsResolf(_)) => "MetricsResolf",
        Some(Event::MetricsPack(_)) => "MetricsPack",
        Some(Event::MetricsBankf(_)) => "MetricsBankf",
        Some(Event::MetricsPoh(_)) => "MetricsPoh",
        Some(Event::MetricsShred(_)) => "MetricsShred",
        Some(Event::MetricsReplay(_)) => "MetricsReplay",
        Some(Event::MetricsRepair(_)) => "MetricsRepair",
        Some(Event::MetricsGossip(_)) => "MetricsGossip",
        Some(Event::MetricsGossvf(_)) => "MetricsGossvf",
        Some(Event::MetricsSign(_)) => "MetricsSign",
        Some(Event::MetricsNetlnk(_)) => "MetricsNetlnk",
        Some(Event::MetricsSnapct(_)) => "MetricsSnapct",
        Some(Event::MetricsSnapld(_)) => "MetricsSnapld",
        Some(Event::MetricsSnapdc(_)) => "MetricsSnapdc",
        Some(Event::MetricsSnapin(_)) => "MetricsSnapin",
        Some(Event::MetricsSnapwr(_)) => "MetricsSnapwr",
        Some(Event::MetricsSnapwh(_)) => "MetricsSnapwh",
        Some(Event::MetricsSnapla(_)) => "MetricsSnapla",
        Some(Event::MetricsSnapls(_)) => "MetricsSnapls",
        Some(Event::MetricsSnapwm(_)) => "MetricsSnapwm",
        Some(Event::MetricsSnaplh(_)) => "MetricsSnaplh",
        Some(Event::MetricsSnaplv(_)) => "MetricsSnaplv",
        Some(Event::MetricsMetric(_)) => "MetricsMetric",
        Some(Event::MetricsRpc(_)) => "MetricsRpc",
        Some(Event::MetricsCswtch(_)) => "MetricsCswtch",
        Some(Event::MetricsGenesi(_)) => "MetricsGenesi",
        Some(Event::MetricsIpecho(_)) => "MetricsIpecho",
        Some(Event::MetricsExec(_)) => "MetricsExec",
        Some(Event::MetricsTower(_)) => "MetricsTower",
        Some(Event::MetricsGui(_)) => "MetricsGui",
        Some(Event::MetricsEvent(_)) => "MetricsEvent",
        Some(Event::MetricsVinyl(_)) => "MetricsVinyl",
        None => "<none>",
    }
}

#[derive(Debug, Default)]
pub struct MyEventService;

#[tonic::async_trait]
impl EventService for MyEventService {
    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn authenticate(
        &self,
        request: Request<GenerateAuthChallengeRequest>,
    ) -> Result<Response<GenerateAuthChallengeResponse>, Status> {
        println!("Received authenticate request from identity: {:?}", 
            hex::encode(&request.get_ref().identity_pubkey));
        // Return a simple challenge for testing
        let challenge = vec![0u8; 32]; // In production, use a random challenge
        Ok(Response::new(GenerateAuthChallengeResponse { challenge }))
    }

    async fn confirm_auth_challenge(
        &self,
        request: Request<ConfirmAuthChallengeRequest>,
    ) -> Result<Response<ConfirmAuthChallengeResponse>, Status> {
        println!("Received confirm_auth_challenge with signed challenge: {:?}",
            hex::encode(&request.get_ref().signed_challenge));
        // Accept any signature for testing purposes
        Ok(Response::new(ConfirmAuthChallengeResponse {}))
    }

    async fn stream_events(
        &self,
        request: Request<tonic::Streaming<StreamEventsRequest>>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        println!("Client connected");

        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            loop {
                match stream.message().await {
                    Ok(Some(event_tx)) => {
                        println!("Received event: nonce={}, event_id={}, kind={}",
                            event_tx.nonce, event_tx.event_id, event_kind_name(&event_tx.event));
                        let ack = StreamEventsResponse { nonce: event_tx.nonce };
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8787".parse()?;
    println!("Listening on {}", addr);

    Server::builder()
        .add_service(EventServiceServer::new(MyEventService))
        .serve(addr)
        .await?;

    Ok(())
}
