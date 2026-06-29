use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};

pub mod events {
    tonic::include_proto!("events.v1");
}

use events::event_service_server::{EventService, EventServiceServer};
use events::{
    StreamEventsRequest, StreamEventsResponse,
    AuthenticateRequest, AuthenticateResponse,
    ConfirmAuthChallengeRequest, ConfirmAuthChallengeResponse,
};
use events::event::Event;

fn event_kind_name(event: &Option<events::Event>) -> &'static str {
    match event.as_ref().and_then(|e| e.event.as_ref()) {
        Some(Event::Txn(_)) => "Txn",
        Some(Event::Shred(_)) => "Shred",
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
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthenticateResponse>, Status> {
        println!("Received authenticate request from identity: {:?}",
            hex::encode(&request.get_ref().identity_pubkey));
        let challenge = vec![0u8; 32];
        Ok(Response::new(AuthenticateResponse { challenge }))
    }

    async fn confirm_auth_challenge(
        &self,
        request: Request<ConfirmAuthChallengeRequest>,
    ) -> Result<Response<ConfirmAuthChallengeResponse>, Status> {
        println!("Received confirm_auth_challenge with signed challenge: {:?}",
            hex::encode(&request.get_ref().signed_challenge));
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
    let addr = "127.0.0.1:7878".parse()?;
    println!("Listening on {}", addr);

    Server::builder()
        .add_service(EventServiceServer::new(MyEventService))
        .serve(addr)
        .await?;

    Ok(())
}
