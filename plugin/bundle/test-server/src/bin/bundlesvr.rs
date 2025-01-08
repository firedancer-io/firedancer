use std::iter;
use std::pin::Pin;

use bundle_test_server::proto::auth::{self, Token};
use bundle_test_server::proto::auth::auth_service_server::{AuthService, AuthServiceServer};
use bundle_test_server::proto::bundle::{Bundle, BundleUuid};
use bundle_test_server::proto::packet::{Packet, PacketBatch};
use chrono::{Duration, Utc};
use futures::{stream, StreamExt};
use log::info;
use prost_types::Timestamp;
use tonic::{transport::Server, Request, Response, Status};
use futures_util::stream::Stream;

use bundle_test_server::proto::block_engine::block_engine_validator_server::{BlockEngineValidator, BlockEngineValidatorServer};
use bundle_test_server::proto::block_engine::{SubscribePacketsRequest, SubscribePacketsResponse, SubscribeBundlesRequest, SubscribeBundlesResponse, BlockBuilderFeeInfoRequest, BlockBuilderFeeInfoResponse};

#[derive(Debug, Default)]
pub struct BlockEngineValidatorService;

type PacketResponseStream = Pin<Box<dyn Stream<Item = Result<SubscribePacketsResponse, Status>> + Send>>;
type BundleResponseStream = Pin<Box<dyn Stream<Item = Result<SubscribeBundlesResponse, Status>> + Send>>;

#[tonic::async_trait]
impl BlockEngineValidator for BlockEngineValidatorService {
    type SubscribePacketsStream = PacketResponseStream;
    type SubscribeBundlesStream = BundleResponseStream;

    async fn subscribe_packets(
        &self,
        _request: Request<SubscribePacketsRequest>,
    ) -> Result<Response<Self::SubscribePacketsStream>, Status> {
        Ok(Response::new(stream::iter(iter::repeat_with(|| {
            Ok(SubscribePacketsResponse {
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
            })
        })).boxed()))
    }

    async fn subscribe_bundles(
        &self,
        _request: Request<SubscribeBundlesRequest>,
    ) -> Result<Response<Self::SubscribeBundlesStream>, Status> {
        Ok(Response::new(stream::iter(iter::repeat_with(|| {
            Ok(SubscribeBundlesResponse {
                bundles: vec![
                    BundleUuid {
                        uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                        bundle: Some(Bundle {
                            header: None,
                            packets: vec![
                                Packet {
                                    meta: None,
                                    data: vec![0; 1232],
                                },
                                Packet {
                                    meta: None,
                                    data: vec![0; 1232],
                                },
                                Packet {
                                    meta: None,
                                    data: vec![0; 1232],
                                },
                                Packet {
                                    meta: None,
                                    data: vec![0; 1232],
                                },
                                Packet {
                                    meta: None,
                                    data: vec![0; 1232],
                                },
                            ],
                        })
                    },
                ]
            })
        })).boxed()))
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

#[derive(Debug, Default)]
pub struct Auth;

#[tonic::async_trait]
impl AuthService for Auth {
    async fn generate_auth_challenge(
        &self,
        _request: Request<auth::GenerateAuthChallengeRequest>,
    ) -> Result<Response<auth::GenerateAuthChallengeResponse>, Status> {
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
                value: "".to_string(),
                expires_at_utc: Some(Timestamp {
                    seconds: (Utc::now() + Duration::seconds(60)).timestamp(),
                    nanos: 0,
                }),
            }),
            refresh_token: Some(Token {
                value: "".to_string(),
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let addr = "127.0.0.1:50051".parse()?;
    info!("Block Engine Validator Server listening on {}", addr);

    Server::builder()
        .add_service(BlockEngineValidatorServer::new(BlockEngineValidatorService::default()))
        .add_service(AuthServiceServer::new(Auth::default()))
        .serve(addr)
        .await?;

    Ok(())
}
