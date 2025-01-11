pub mod proto {
    pub mod auth {
        tonic::include_proto!("auth");
    }
    pub mod block_engine {
        tonic::include_proto!("block_engine");
    }
    pub mod bundle {
        tonic::include_proto!("bundle");
    }
    pub mod packet {
        tonic::include_proto!("packet");
    }
    pub mod relayer {
        tonic::include_proto!("relayer");
    }
    pub mod shared {
        tonic::include_proto!("shared");
    }    
}
