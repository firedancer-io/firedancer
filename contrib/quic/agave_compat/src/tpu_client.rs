use solana_tpu_client_next::{
    leader_updater::create_pinned_leader_updater, Client, ClientBuilder, TransactionSender,
};
use std::{net::SocketAddr, num::NonZeroUsize};
use tokio::runtime::{Builder, Runtime};

pub(crate) struct TpuClient {
    runtime: Runtime,
    sender: TransactionSender,
    client: Option<Client>,
}

impl TpuClient {
    pub(crate) fn new(dst: SocketAddr) -> Self {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create TPU client runtime");
        let bind_socket = std::net::UdpSocket::bind(match dst {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .expect("failed to bind TPU client socket");
        let (sender, client) = ClientBuilder::new(create_pinned_leader_updater(dst))
            .runtime_handle(runtime.handle().clone())
            .bind_socket(bind_socket)
            .leader_send_fanout(1)
            .max_cache_size(NonZeroUsize::new(1).unwrap())
            .build()
            .expect("failed to build TPU client");
        Self {
            runtime,
            sender,
            client: Some(client),
        }
    }

    pub(crate) fn send_batch<T>(&self, wire_transactions: Vec<T>)
    where
        T: AsRef<[u8]> + Send + 'static,
    {
        self.runtime
            .block_on(self.sender.send_transactions_in_batch(wire_transactions))
            .expect("TPU client failed to queue transaction batch");
    }

    pub(crate) fn shutdown(mut self) {
        self.runtime
            .block_on(self.client.take().unwrap().shutdown())
            .expect("TPU client failed to shut down");
    }
}
