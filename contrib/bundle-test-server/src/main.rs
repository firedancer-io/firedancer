use std::pin::Pin;

use crate::proto::auth::auth_service_server::{AuthService, AuthServiceServer};
use crate::proto::auth::{self, Token};
use crate::proto::bundle::{Bundle, BundleUuid};
use crate::proto::packet::{Packet, PacketBatch};
use base64::prelude::*;
use chrono::{Duration, Utc};
use futures::select;
use futures::FutureExt;
use futures_util::stream::Stream;
use log::info;
use prost_types::Timestamp;
use rustyline::{error::ReadlineError, DefaultEditor};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tonic::{transport::Server, Request, Response, Status};

use crate::proto::block_engine::block_engine_validator_server::{
    BlockEngineValidator, BlockEngineValidatorServer,
};
use crate::proto::block_engine::{
    BlockBuilderFeeInfoRequest, BlockBuilderFeeInfoResponse, SubscribeBundlesRequest,
    SubscribeBundlesResponse, SubscribePacketsRequest, SubscribePacketsResponse,
};

pub struct Service {
    kill_streams: broadcast::Receiver<()>,
}

#[derive(Clone)]
pub struct ServiceHandle(Arc<Service>);

type PacketResponseStream =
    Pin<Box<dyn Stream<Item = Result<SubscribePacketsResponse, Status>> + Send>>;
type BundleResponseStream =
    Pin<Box<dyn Stream<Item = Result<SubscribeBundlesResponse, Status>> + Send>>;

pub(crate) mod proto {
    pub(crate) mod auth {
        tonic::include_proto!("auth");
    }
    pub(crate) mod block_engine {
        tonic::include_proto!("block_engine");
    }
    pub(crate) mod bundle {
        tonic::include_proto!("bundle");
    }
    pub(crate) mod packet {
        tonic::include_proto!("packet");
    }
    pub(crate) mod relayer {
        tonic::include_proto!("relayer");
    }
    pub(crate) mod shared {
        tonic::include_proto!("shared");
    }
}

#[tonic::async_trait]
impl BlockEngineValidator for ServiceHandle {
    type SubscribePacketsStream = PacketResponseStream;
    type SubscribeBundlesStream = BundleResponseStream;

    async fn subscribe_packets(
        &self,
        _request: Request<SubscribePacketsRequest>,
    ) -> Result<Response<Self::SubscribePacketsStream>, Status> {
        let mut kill_streams = self.0.kill_streams.resubscribe();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            info!("Packet stream start");
            let msg = SubscribePacketsResponse {
                header: None,
                batch: Some(PacketBatch {
                    packets: vec![
                        Packet {
                            meta: None,
                            data: vec![0; 1232],
                        },
                        Packet {
                            meta: None,
                            data: vec![0; 1232],
                        },
                    ],
                }),
            };
            loop {
                select! {
                    _ = kill_streams.recv().fuse() => break,
                    res = tx.send(Ok(msg.clone())).fuse() => if res.is_err() { break }
                }
            }
            info!("Packet stream stop");
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn subscribe_bundles(
        &self,
        _request: Request<SubscribeBundlesRequest>,
    ) -> Result<Response<Self::SubscribeBundlesStream>, Status> {
        let mut kill_streams = self.0.kill_streams.resubscribe();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            info!("Bundle stream start");
            let msg = SubscribeBundlesResponse {
                bundles: vec![
                    BundleUuid {
                        uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                        bundle: Some(Bundle {
                            header: None,
                            packets: vec![
                                Packet {
                                    meta: None,
                                    data: BASE64_STANDARD.decode(b"AplgYeL7lZ//2fZyq0hgs57Pqevr2XhcDslxchP9MCwSL1T53TQquo1Q8YjXW87hsLOZUrGf9rJSNOZxkjkzuQkqX7ELf9NRH4IduEUMCdNk+4eQKaeNPD0qxwjMnThpPy4W5twMcpqsIwBUn8nBin9zDiGIw45q9+cAIRnxQcIFAgEFCmK1c3bBvURtMIVYcRrqWeDmpFe3rMTamh3isH57X+VPJoNzHmgKQDMBH7YdnfpZnoZziXznBbYn0l84zte8nzqeV4BovTKBuUW4r+kDb0rcqF1E1a3dEQrWAap98xF9WXtE2rBhEteCr6t2wb2dkwc3bua8xiAAl5CvmaQjcZf1u2Zrh2RnqnIAyiqCAgVGWHAqq0RQXvouEI3tZUSNWDAGp9UXGSxWjuCKhF9z0peIzwNcMUWyGrNE2AYuqUAAAAmQEHCdkn/s4XyQQwWBqtUGKmQGpVL+cpvyQlwCxD/PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpW0bsAXCA/sc0H8S3yQY1dU5OrWgtx5+nJyXamTjQ7tAEBwMCBQEEBAAAAAgACQOAw8kBAAAAAAgABQIQJwAACQQDBgQACgymPaYcAgAAAAY=").unwrap(),
                                },
                                Packet {
                                    meta: None,
                                    data: BASE64_STANDARD.decode(b"AijKJ5H5jDNza6wwLLB5pFCMLaHBAJ1P5spx4QkBg0vdKsnfEmdf+fgI7sJgcp68OONRxp1Tuwrpkc5Q8BTuDQWZAsNYQnvXD4n4RPImcMrus0SUBMbQrX+t7fUlMU/SBscsCPjQRAoVlTWlc5/8MA0cg89W0dSlonX8UJXbMwUAAgEFCiA0jtjBgydimHmbOX9EM63N1d6wTAAyO4LyrIAh6nJiJoNzHmgKQDMBH7YdnfpZnoZziXznBbYn0l84zte8nzqfQneRHfpJJef849c/Ti3mq0yjQHCFQZPzdPEb644M0I9vSd8BuAJ2fFMkc1ynhn6lJ9DMAkzNWj21LlOVQI7veaXsBCiWbSSY43Sr0fBad1SBWBG56mAt1QkTqxVpiacGp9UXGSxWjuCKhF9z0peIzwNcMUWyGrNE2AYuqUAAAM4BDmCv7bInF71jGS9UFFo/llozu4LSxwKess4eIIJkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpW0bsAXCA/sc0H8S3yQY1dU5OrWgtx5+nJyXamTjQ7tAEBwMCBQEEBAAAAAgACQOAw8kBAAAAAAgABQIQJwAACQQDBgQACgwAZc0dAAAAAAY=").unwrap(),
                                },
                                Packet {
                                    meta: None,
                                    data: BASE64_STANDARD.decode(b"ApbANVN5DAFCeUVlGFMJiDoblInErsUb3SXvH/zedTvI3N/2VQXbiD7YBCMMM7z70CHDAtwUN6QyDXTfX9f50AeLiJsJFALf+yx+y8VCmkIHrydT0xO2AktOUAPAwSEUrLO9vx2w34zTQH7825CP0KJq0P0qbh8s5ZnqMRCWomQGAgEFCq0GX6spT4f2ZZTU4jmnw1c4N5Rh8PnkcZSKcTZtN125JoNzHmgKQDMBH7YdnfpZnoZziXznBbYn0l84zte8nzo9Qv0uUDVQ5kxt1XdzjHfKkFC6suwka3+AymtKrvnB+QfuvVvIlFZT5CJZqW9OOIKqfTbS7kzxgNWErlC5OF1WeaXsBCiWbSSY43Sr0fBad1SBWBG56mAt1QkTqxVpiacGp9UXGSxWjuCKhF9z0peIzwNcMUWyGrNE2AYuqUAAAM4BDmCv7bInF71jGS9UFFo/llozu4LSxwKess4eIIJkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpW0bsAXCA/sc0H8S3yQY1dU5OrWgtx5+nJyXamTjQ7tAEBwMCBQEEBAAAAAgACQOAw8kBAAAAAAgABQIQJwAACQQDBgQACgwpYx0gAAAAAAY=").unwrap(),
                                },
                            ],
                        })
                    },
                ]
            };
            loop {
                select! {
                    _ = kill_streams.recv().fuse() => break,
                    res = tx.send(Ok(msg.clone())).fuse() => if res.is_err() { break }
                }
            }
            info!("Bundle stream stop");
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn get_block_builder_fee_info(
        &self,
        _request: Request<BlockBuilderFeeInfoRequest>,
    ) -> Result<Response<BlockBuilderFeeInfoResponse>, Status> {
        let response = BlockBuilderFeeInfoResponse {
            commission: 5,
            pubkey: "DNVZMSqeRH18Xa4MCTrb1MndNf3Npg4MEwqswo23eWkf".to_string(),
        };

        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl AuthService for ServiceHandle {
    async fn generate_auth_challenge(
        &self,
        request: Request<auth::GenerateAuthChallengeRequest>,
    ) -> Result<Response<auth::GenerateAuthChallengeResponse>, Status> {
        let req_data = request.into_inner();
        info!(
            "Received auth challenge request from {}",
            bs58::encode(&req_data.pubkey).into_string()
        );
        Ok(Response::new(auth::GenerateAuthChallengeResponse {
            challenge: "012345678".to_string(),
        }))
    }

    async fn generate_auth_tokens(
        &self,
        _request: Request<auth::GenerateAuthTokensRequest>,
    ) -> Result<Response<auth::GenerateAuthTokensResponse>, Status> {
        Ok(Response::new(auth::GenerateAuthTokensResponse {
            access_token: Some(Token {
                value: "token".to_string(),
                expires_at_utc: Some(Timestamp {
                    seconds: (Utc::now() + Duration::seconds(60)).timestamp(),
                    nanos: 0,
                }),
            }),
            refresh_token: Some(Token {
                value: "token".to_string(),
                expires_at_utc: Some(Timestamp {
                    seconds: (Utc::now() + Duration::seconds(60)).timestamp(),
                    nanos: 0,
                }),
            }),
        }))
    }

    async fn refresh_access_token(
        &self,
        _request: Request<auth::RefreshAccessTokenRequest>,
    ) -> Result<Response<auth::RefreshAccessTokenResponse>, Status> {
        Ok(Response::new(auth::RefreshAccessTokenResponse {
            access_token: Some(Token {
                value: "012345678".to_string(),
                expires_at_utc: Some(Timestamp {
                    seconds: (Utc::now() + Duration::seconds(60)).timestamp(),
                    nanos: 0,
                }),
            }),
        }))
    }
}

struct Cnc {
    kill_streams_tx: broadcast::Sender<()>,
    kill_server_tx: broadcast::Sender<()>,
}

fn handle_line(cnc: &mut Cnc, line: &str) -> bool {
    match line {
        "" => return false,
        "help" => {
            println!("Available commands:");
            println!("  help - Show this help message");
            println!("  exit - Exit the server");
            println!("  kill-streams - Kill all active streams");
            println!("  kill-server - Kill and restart the server");
        }
        "exit" | "quit" => {
            println!("Exiting...");
            std::process::exit(0);
        }
        "kill-streams" => {
            let _ = cnc.kill_streams_tx.send(());
        }
        "kill-server" => {
            let _ = cnc.kill_server_tx.send(());
        }
        cmd => {
            println!("Unknown command: {}", cmd);
            return false;
        }
    }
    true
}

async fn run_server(
    service: ServiceHandle,
    listen_addr: SocketAddr,
    mut kill_signal: broadcast::Receiver<()>,
) {
    loop {
        let server = Server::builder()
            .add_service(BlockEngineValidatorServer::new(service.clone()))
            .add_service(AuthServiceServer::new(service.clone()))
            .serve_with_shutdown(listen_addr.clone(), kill_signal.recv().map(|_| ()));
        server.await.unwrap();
        info!("Restarting server");
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let (kill_streams_tx, kill_streams_rx) = broadcast::channel(2);
    let (kill_server_tx, kill_server_rx) = broadcast::channel(2);

    let mut cnc = Cnc {
        kill_streams_tx,
        kill_server_tx,
    };

    // Spawn a thread handling all gRPC I/O
    let addr: SocketAddr = "127.0.0.1:50051".parse().unwrap();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let service = ServiceHandle(Arc::new(Service {
            kill_streams: kill_streams_rx,
        }));
        rt.block_on(run_server(service, addr, kill_server_rx));
    });

    // Run a REPL on the current thread
    let mut rl = match DefaultEditor::new() {
        Ok(rl) => rl,
        Err(_) => {
            handle.join().unwrap();
            std::process::exit(1);
        }
    };
    println!("Block Engine Validator Server listening on {}", addr);
    loop {
        let readline = rl.readline("");
        match readline {
            Ok(line) => {
                if handle_line(&mut cnc, &line) {
                    let _ = rl.add_history_entry(&line);
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                std::process::exit(0);
            }
            Err(err) => panic!("Unexpected error: {}", err),
        }
    }
}
