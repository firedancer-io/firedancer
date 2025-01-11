use {
    crate::{
        auth::{generate_auth_tokens, maybe_refresh_auth_tokens, AuthInterceptor},
        proto::{
            auth::{auth_service_client::AuthServiceClient, Token},
            block_engine::{
                self, block_engine_validator_client::BlockEngineValidatorClient,
                BlockBuilderFeeInfoRequest,
            },
            block_engine::{SubscribeBundlesResponse, SubscribePacketsResponse},
            bundle::BundleUuid,
            packet::Packet,
        },
        ProxyError,
    },
    log::*,
    std::ffi::{c_void, CStr},
    std::{
        future::{Future, ready},
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Duration,
    },
    tonic::{
        codegen::InterceptedService,
        transport::{Channel, Endpoint},
        Streaming,
    },
    futures::{
        StreamExt,
        stream::{self, Stream, once},
        stream_select,
    },
    tokio::{
        runtime::{self, Runtime},
        time::{interval, sleep, timeout},
    },
    tokio_stream::wrappers::IntervalStream,
};

struct TileFuture {
    pending: u64,
    stream: Arc<Mutex<Pin<Box<dyn Stream<Item = BundleOrPacket> + Send>>>>,
}

impl Future for TileFuture {
    type Output = Option<BundleOrPacket>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Incredibly dumb series of stuff here ... we want to drive the
        // future from the tile outer loop, so it's like ...
        //
        //  while (1) {
        //    do_housekeeping();
        //    receive_credits();
        //    poll_futures();
        //    ...
        //  }
        //
        // Unfortunately Tokio makes it extremely difficult to turn the
        // futures one time, so this pending count and wake here kind of
        // achieve that. I wrote a custom futures executor to do this,
        // but unfortuantely the libraries require Tokio to use some of
        // the I/O functionality and will error without a Tokio Runtime.
        cx.waker().clone().wake();

        if self.pending == 0 {
            return Poll::Ready(None);
        }
        self.pending -= 1;

        let mut stream = self.stream.lock().unwrap();
        match stream.as_mut().poll_next_unpin(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some(item)),
            Poll::Ready(None) => unreachable!(),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct TileExecutor {
    runtime: Runtime,
    stream: Arc<Mutex<Pin<Box<dyn Stream<Item = BundleOrPacket> + Send>>>>,
}

#[no_mangle]
pub extern "C" fn plugin_bundle_init(
    url: *const i8,
    domain_name: *const i8,
    pubkey: *const u8,
) -> *mut c_void {
    extern "C" {
        fn fd_log_private_1(
            level: i32,
            now: i64,
            file: *const i8,
            line: i32,
            func: *const i8,
            msg: *const i8,
        );
        fn fd_log_wallclock() -> i64;
        fn fd_log_level_logfile() -> i32;
    }

    struct FDLogger {}

    impl log::Log for FDLogger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            match metadata.level() {
                log::Level::Error | log::Level::Warn | log::Level::Info => true,
                log::Level::Debug | log::Level::Trace => false,
            }
        }

        fn log(&self, record: &log::Record) {
            match record.level() {
                log::Level::Error | log::Level::Warn | log::Level::Info => (),
                log::Level::Debug | log::Level::Trace => return,
            };

            let level: i32 = match record.level() {
                log::Level::Error => 4,
                log::Level::Warn => 3,
                log::Level::Info => 1, /* Info -> DEBUG, so it doesn't spam stdout */
                log::Level::Debug => 1,
                log::Level::Trace => 0,
            };

            const UNKNOWN: &'static str = "unknown";

            let file = if let Some(file) = record.file() {
                std::ffi::CString::new(file).unwrap_or(std::ffi::CString::new(UNKNOWN).unwrap())
            } else {
                std::ffi::CString::new(UNKNOWN).unwrap()
            };

            let msg = std::ffi::CString::new(record.args().to_string())
                .unwrap_or(std::ffi::CString::new(UNKNOWN).unwrap());
            let target = std::ffi::CString::new(record.target())
                .unwrap_or(std::ffi::CString::new(UNKNOWN).unwrap());

            unsafe {
                // We reroute log messages to the Firedancer logger.
                // There are a few problems with this.  The message should be
                // printed into the target buffer, rather than a heap
                // allocated string. None the less, it's good enough for now.
                fd_log_private_1(
                    level,
                    fd_log_wallclock(),
                    file.as_ptr(),
                    record.line().unwrap_or(0) as i32,
                    target.as_ptr(),
                    msg.as_ptr(),
                );
            }
        }

        fn flush(&self) {}
    }
    let _logger_thread: Option<std::thread::JoinHandle<()>> = None;
    static LOGGER: FDLogger = FDLogger {};
    let log_level = match unsafe { fd_log_level_logfile() } {
        0 => LevelFilter::Trace,
        1 => LevelFilter::Debug,
        2 => LevelFilter::Info,
        3 => LevelFilter::Warn,
        4 => LevelFilter::Error,
        _ => LevelFilter::Off,
    };
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log_level))
        .unwrap();

    let pubkey: [u8; 32] = unsafe { std::ptr::read(pubkey as *const [u8; 32]) };

    let task = produce_bundles(
        unsafe { CStr::from_ptr(url).to_string_lossy().into_owned() },
        unsafe { CStr::from_ptr(domain_name).to_string_lossy().into_owned() },
        pubkey,
    );

    let executor = TileExecutor {
        runtime: runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap(),
        stream: Arc::new(Mutex::new(Box::pin(task))),
    };

    Box::into_raw(Box::new(executor)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn plugin_bundle_poll(
    plugin: *mut c_void,
    out_type: *mut i32,
    out_block_builder_pubkey: *mut u8,
    out_block_builder_commission: *mut u64,
    out_bundle_len: *mut u64,
    out_data: *mut u8,
) {
    let executor = unsafe { &mut *(plugin as *mut TileExecutor) };

    let future = TileFuture {
        pending: 64,
        stream: Arc::clone(&executor.stream),
    };

    unsafe { *out_type = 0 };

    unsafe { *out_bundle_len = 0 };
    match executor.runtime.block_on(future) {
        Some(BundleOrPacket::Disconnected) => {
            unsafe { *out_type = -1i32 };
        }
        Some(BundleOrPacket::Connecting) => {
            unsafe { *out_type = -2i32 };
        }
        Some(BundleOrPacket::Connected) => {
            unsafe { *out_type = -3i32 };
        }
        Some(BundleOrPacket::Bundle(bundle, block_builder_pubkey, commission)) => {
            let bundle = match bundle.bundle {
                None => {
                    warn!("bundle message has no actual bundle, ignoring");
                    return;
                }
                Some(bundle) => bundle,
            };

            if bundle.packets.is_empty() {
                warn!("bundle has no packets, ignoring");
                return;
            }

            if bundle.packets.len() > 5 {
                warn!("bundle has more than 5 packets, ignoring");
                return;
            }

            unsafe { *out_type = 1i32 };
            unsafe { *out_bundle_len = bundle.packets.len() as u64 };
            unsafe { std::ptr::copy(block_builder_pubkey.as_ptr(), out_block_builder_pubkey, 32) };
            unsafe { *out_block_builder_commission = commission };

            let mut offset: usize = 0;
            let out_slice = unsafe { std::slice::from_raw_parts_mut(out_data, 5 * (8 + 1232)) };
            for packet in bundle.packets {
                out_slice[offset..offset + 8]
                    .copy_from_slice(&(packet.data.len() as u64).to_le_bytes());
                out_slice[offset + 8..offset + 8 + packet.data.len()].copy_from_slice(&packet.data);
                offset += 8 + packet.data.len();
            }
        }
        Some(BundleOrPacket::Packet(packet)) => {
            unsafe { *out_type = 2i32 };
            unsafe { *out_bundle_len = 1u64 };

            let out_slice = unsafe { std::slice::from_raw_parts_mut(out_data, 8 + 1232) };
            out_slice[0..8].copy_from_slice(&(packet.data.len() as u64).to_le_bytes());
            out_slice[8..8 + packet.data.len()].copy_from_slice(&packet.data);
        }
        None => (),
    }
}

enum BundleOrPacket {
    Disconnected,
    Connecting,
    Connected,
    Bundle(BundleUuid, [u8; 32], u64),
    Packet(Packet),
}

enum StreamSelector {
    Bundle(BundleUuid),
    Packet(Packet),
    AuthTimer,
    MaintenanceTimer,
    Err(ProxyError),
}

struct StreamState {
    identity_pubkey: [u8; 32],
    client: BlockEngineValidatorClient<InterceptedService<Channel, AuthInterceptor>>,
    auth_client: AuthServiceClient<Channel>,
    access_token: Token,
    refresh_token: Token,
    block_builder_pubkey: [u8; 32],
    block_builder_commission: u64,
}

fn produce_bundles(
    url: String,
    domain_name: String,
    identity_pubkey: [u8; 32],
) -> impl Stream<Item = BundleOrPacket> {
    enum Status {
        DisconnectedNotify,
        Disconnected,
        ConnectingNotify,
        Connecting,
        ConnectedNotify(
            BlockEngineValidatorClient<InterceptedService<Channel, AuthInterceptor>>,
            AuthServiceClient<Channel>,
            Token,
            Token,
        ),
        Connected(
            BlockEngineValidatorClient<InterceptedService<Channel, AuthInterceptor>>,
            AuthServiceClient<Channel>,
            Token,
            Token,
        )
    }

    let status = Status::Connecting;
    stream::unfold((status, url, domain_name, identity_pubkey), |(status, url, domain_name, identity_pubkey)| async move {
        match status {
            Status::DisconnectedNotify => {
                Some((Some(once(ready(BundleOrPacket::Disconnected)).boxed()), (Status::Disconnected, url, domain_name, identity_pubkey)))
            }
            Status::Disconnected => {
                sleep(Duration::from_secs(5)).await;
                Some((None, (Status::ConnectingNotify, url, domain_name, identity_pubkey)))
            }
            Status::ConnectingNotify => {
                Some((Some(once(ready(BundleOrPacket::Connecting)).boxed()), (Status::Connecting, url, domain_name, identity_pubkey)))
            }
            Status::ConnectedNotify(client, auth_client, access_token, refresh_token) => {
                Some((Some(once(ready(BundleOrPacket::Connected)).boxed()), (Status::Connected(client, auth_client, access_token, refresh_token), url, domain_name, identity_pubkey)))
            }
            Status::Connecting => {
                let (client, auth_client, access_token, refresh_token) = match connect_auth(&url, &domain_name, &identity_pubkey).await {
                    Ok(result) => result,
                    Err(ProxyError::AuthenticationPermissionDenied) => {
                        // This error is frequent on hot spares, and the parsed string does not work
                        // with datapoints (incorrect escaping).
                        warn!("block engine permission denied. not on leader schedule. ignore if hot-spare.");
                        return Some((None, (Status::DisconnectedNotify, url, domain_name, identity_pubkey)));
                    },
                    Err(err) => {
                        warn!("block engine connection error: {:?}", err);
                        return Some((None, (Status::DisconnectedNotify, url, domain_name, identity_pubkey)));
                    }
                };

                Some((None, (Status::ConnectedNotify(client, auth_client, access_token, refresh_token), url, domain_name, identity_pubkey)))
            }
            Status::Connected(mut client, auth_client, access_token, refresh_token) => {
                log::info!("Connected to block engine: {}", url);

                let (subscribe_bundles_stream, subscribe_packets_stream, block_builder_pubkey, block_builder_commission) = match subscribe_block_engine_bundles_and_packets(&mut client).await {
                    Ok(result) => result,
                    Err(_) => {
                        warn!("block engine subscription error");
                        return Some((None, (Status::DisconnectedNotify, url, domain_name, identity_pubkey)));
                    }
                };
        
                let auth_timer = IntervalStream::new(interval(Duration::from_secs(5))).map(|_| StreamSelector::AuthTimer);
                let maintenance_timer = IntervalStream::new(interval(Duration::from_secs(600))).map(|_| StreamSelector::MaintenanceTimer);
                let combined_stream = stream_select!(
                    subscribe_bundles_stream.flat_map(|x| match x {
                        Ok(bundles_response) => futures::stream::iter(bundles_response.bundles.into_iter().map(StreamSelector::Bundle).collect::<Vec<_>>()),
                        Err(_) => futures::stream::iter(vec![StreamSelector::Err(ProxyError::GrpcStreamDisconnected)]),
                    }),
                    subscribe_packets_stream.flat_map(|x| match x {
                        Ok(packets_response) => {
                            if let Some(batch) = packets_response.batch {
                                futures::stream::iter(batch.packets.into_iter().map(StreamSelector::Packet).collect::<Vec<_>>()).boxed()
                            } else {
                                futures::stream::empty().boxed()
                            }
                        },
                        Err(_) => futures::stream::iter(vec![StreamSelector::Err(ProxyError::GrpcStreamDisconnected)]).boxed(),
                    }),
                    auth_timer,
                    maintenance_timer,
                );
        
                // Annoying to have to use Arc<Mutex<T>> here ... technically this shouldn't be
                // needed if we could convince the compiler of the right lifetimes.
                let state = Arc::new(Mutex::new(StreamState {
                    identity_pubkey,
                    client,
                    auth_client,
                    access_token,
                    refresh_token,
                    block_builder_pubkey,
                    block_builder_commission,
                }));
        
                let stream = combined_stream.scan(state, |state, item| {
                    let _state = state.clone();
        
                    let state = _state.lock().unwrap();
                    let identity_pubkey = state.identity_pubkey.clone();
                    let mut client = state.client.clone();
                    let mut auth_client = state.auth_client.clone();
                    let access_token = state.access_token.clone();
                    let refresh_token = state.refresh_token.clone();
                    let block_builder_pubkey = state.block_builder_pubkey.clone();
                    let block_builder_commission = state.block_builder_commission.clone();
                    drop(state);
        
                    async move {
                        match item {
                            StreamSelector::AuthTimer => {
                                debug!("auth timer");
                                let (maybe_new_access, maybe_new_refresh) = match maybe_refresh_auth_tokens(
                                    &identity_pubkey,
                                    &mut auth_client,
                                    &access_token,
                                    &refresh_token,
                                    &Duration::from_secs(5),
                                    1,
                                ).await {
                                    Ok(result) => result,
                                    Err(_) => {
                                        debug!("auth error");
                                        return None;
                                    }
                                };
        
                                let mut state = _state.lock().unwrap();
                                if let Some(new_token) = maybe_new_access {
                                    state.access_token = new_token;
                                }
                                if let Some(new_token) = maybe_new_refresh {
                                    state.refresh_token = new_token;
                                }
                            }
                            StreamSelector::MaintenanceTimer => {
                                debug!("maintenance timer");
                                let (block_builder_pubkey, block_builder_commission) = match refresh_block_builder_info(&mut client).await {
                                    Ok(result) => result,
                                    Err(_) => {
                                        debug!("maintenance error");
                                        return None;
                                    }
                                };
        
                                let mut state = _state.lock().unwrap();
                                state.block_builder_pubkey = block_builder_pubkey;
                                state.block_builder_commission = block_builder_commission;
                            }
                            _ => (),
                        };
        
                        Some((item, block_builder_pubkey, block_builder_commission))
                    }
                });
        
                let stream = stream.filter_map(|item| async {
                    match item {
                        (StreamSelector::Bundle(bundle), pubkey, commission) => {
                            Some(Ok(BundleOrPacket::Bundle(bundle, pubkey, commission)))
                        }
                        (StreamSelector::Packet(packet), _, _) => {
                            Some(Ok(BundleOrPacket::Packet(packet)))
                        }
                        (StreamSelector::AuthTimer, _, _) => None,
                        (StreamSelector::MaintenanceTimer, _, _) => None,
                        (StreamSelector::Err(err), _, _) => Some(Err(err))
                    }
                }).filter_map(|x| async {
                    match x {
                        Ok(x) => Some(x),
                        Err(err) => {
                            warn!("stream error: {:?}", err);
                            None
                        }
                    }
                });
        
                Some((Some(stream.boxed()), (Status::DisconnectedNotify, url, domain_name, identity_pubkey)))
            }
        }
    }).filter_map(|x| async { x }).flatten()
}

async fn refresh_block_builder_info(
    client: &mut BlockEngineValidatorClient<InterceptedService<Channel, AuthInterceptor>>,
) -> crate::Result<([u8; 32], u64)> {
    let block_builder_info = timeout(
        Duration::from_secs(5),
        client.get_block_builder_fee_info(BlockBuilderFeeInfoRequest {}),
    )
    .await
    .map_err(|_| ProxyError::MethodTimeout("get_block_builder_fee_info".to_string()))?
    .map_err(|e| ProxyError::MethodError(e.to_string()))?
    .into_inner();

    let block_builder_pubkey = bs58::decode(&block_builder_info.pubkey)
        .into_vec()
        .map_err(|_| {
            ProxyError::InvalidData(format!(
                "Invalid block_builder pubkey {}",
                block_builder_info.pubkey
            ))
        })?
        .try_into()
        .map_err(|_| ProxyError::InvalidData("Invalid block_builder pubkey".to_string()))?;
    Ok((block_builder_pubkey, block_builder_info.commission))
}

async fn connect_auth(
    url: &str,
    domain_name: &str,
    identity_pubkey: &[u8; 32],
) -> crate::Result<(
    BlockEngineValidatorClient<InterceptedService<Channel, AuthInterceptor>>,
    AuthServiceClient<Channel>,
    Token,
    Token,
)> {
    let mut backend_endpoint = Endpoint::from_shared(url.to_owned())
        .map_err(|_| {
            ProxyError::BlockEngineConnectionError(format!(
                "invalid block engine url value: {}",
                url
            ))
        })?
        .tcp_keepalive(Some(Duration::from_secs(60)));

    debug!("connecting to block engine: {} ... {}", url, domain_name);

    if url.starts_with("https") {
        backend_endpoint = backend_endpoint
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .with_webpki_roots()
                    .domain_name(domain_name),
            )
            .map_err(|_| {
                ProxyError::BlockEngineConnectionError(
                    "failed to set tls_config for block engine service".to_string(),
                )
            })?;
    }

    debug!("connecting to auth: {}", url);
    let auth_channel = timeout(Duration::from_secs(5), backend_endpoint.connect())
        .await
        .map_err(|_| ProxyError::AuthenticationConnectionTimeout)?
        .map_err(|e| ProxyError::AuthenticationConnectionError(format!("{:#?}", e)))?;

    let mut auth_client = AuthServiceClient::new(auth_channel);

    debug!("generating authentication token");
    let (access_token, refresh_token) = timeout(
        Duration::from_secs(5),
        generate_auth_tokens(&mut auth_client, identity_pubkey),
    )
    .await
    .map_err(|_| ProxyError::AuthenticationTimeout)??;

    debug!("connecting to block engine: {}", url);
    let block_engine_channel = timeout(Duration::from_secs(5), backend_endpoint.connect())
        .await
        .map_err(|_| ProxyError::BlockEngineConnectionTimeout)?
        .map_err(|e| ProxyError::BlockEngineConnectionError(e.to_string()))?;

    let block_engine_client = BlockEngineValidatorClient::with_interceptor(
        block_engine_channel,
        AuthInterceptor::new(access_token.clone()),
    );

    Ok((
        block_engine_client,
        auth_client,
        access_token,
        refresh_token,
    ))
}

async fn subscribe_block_engine_bundles_and_packets(
    client: &mut BlockEngineValidatorClient<InterceptedService<Channel, AuthInterceptor>>,
) -> crate::Result<(
    Streaming<SubscribeBundlesResponse>,
    Streaming<SubscribePacketsResponse>,
    [u8; 32],
    u64,
)> {
    let subscribe_packets_stream = timeout(
        Duration::from_secs(5),
        client.subscribe_packets(block_engine::SubscribePacketsRequest {}),
    )
    .await
    .map_err(|_| ProxyError::MethodTimeout("block_engine_subscribe_packets".to_string()))?
    .map_err(|e| ProxyError::MethodError(e.to_string()))?
    .into_inner();

    let subscribe_bundles_stream = timeout(
        Duration::from_secs(5),
        client.subscribe_bundles(block_engine::SubscribeBundlesRequest {}),
    )
    .await
    .map_err(|_| ProxyError::MethodTimeout("subscribe_bundles".to_string()))?
    .map_err(|e| ProxyError::MethodError(e.to_string()))?
    .into_inner();

    let block_builder_info = timeout(
        Duration::from_secs(5),
        client.get_block_builder_fee_info(BlockBuilderFeeInfoRequest {}),
    )
    .await
    .map_err(|_| ProxyError::MethodTimeout("get_block_builder_fee_info".to_string()))?
    .map_err(|e| ProxyError::MethodError(e.to_string()))?
    .into_inner();

    let block_builder_pubkey = bs58::decode(&block_builder_info.pubkey)
        .into_vec()
        .map_err(|_| {
            ProxyError::InvalidData(format!(
                "Invalid block_builder pubkey {}",
                block_builder_info.pubkey
            ))
        })?
        .try_into()
        .map_err(|_| ProxyError::InvalidData("Invalid block_builder pubkey".to_string()))?;

    Ok((
        subscribe_bundles_stream,
        subscribe_packets_stream,
        block_builder_pubkey,
        block_builder_info.commission,
    ))
}
