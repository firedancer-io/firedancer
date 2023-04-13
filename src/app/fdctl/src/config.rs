use std::env::VarError;
use std::path::PathBuf;
use std::{
    env,
    fs,
    path,
};

use paste::paste;
use serde::Deserialize;

use crate::utility::*;
use crate::*;

pub(crate) struct Config {
    pub(crate) name: String,
    pub(crate) user: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,

    pub(crate) frank: FrankConfig,

    pub(crate) binary_dir: String,
    pub(crate) scratch_directory: String,

    pub(crate) layout: LayoutConfig,
    pub(crate) shmem: ShmemConfig,
    pub(crate) development: DevelopmentConfig,

    pub(crate) tiles: TilesConfig,
}

fn default_user() -> String {
    if let Ok(name) = env::var("SUDO_USER") {
        return name;
    }

    match env::var("LOGNAME") {
        Ok(name) => name,
        _ => username(),
    }
}

impl UserConfig {
    pub(crate) fn load(path: &Option<path::PathBuf>) -> Self {
        let mut config: Self = toml::from_str(include_str!("../config/default.toml")).unwrap();

        if let Some(config_str) = match path {
            Some(path) => Some(fs::read_to_string(path).unwrap()),
            None => match env::var("FIREDANCER_CONFIG_TOML") {
                Err(VarError::NotPresent) => None,
                Ok(path) => Some(fs::read_to_string(path).unwrap()),
                err => panic!("{:?}", err),
            },
        } {
            let config_delta: UserConfigDelta = toml::from_str(&config_str).unwrap();
            config.merge(config_delta);
        }

        config
    }

    pub(crate) fn into_config(self, cli: &Cli) -> Config {
        let user = if self.user.is_empty() {
            default_user()
        } else {
            self.user
        };

        let interface = &self.tiles.quic.interface;
        assert!(
            !interface.is_empty(),
            "Configuration must specify an interface to listen to with [tiles.quic.interface]"
        );

        if self.development.netns.enabled {
            assert_eq!(
                interface, &self.development.netns.interface0,
                "if using [netns] expect [tiles.quic.interface] to be the same as \
                 [development.netns.interface0]"
            );
        } else {
            assert!(
                interface_exists(interface),
                "Configuration specifies a network interface \"{interface}\" which does not exist"
            );
        }

        Config {
            name: self.name.clone(),
            user: user.clone(),

            uid: get_uid_by_username(&user).unwrap(),
            gid: get_uid_by_username(&user).unwrap(),

            frank: FrankConfig {
                pod: 0,
                main_cnc: 0,
                src_mac_address: "".to_string(),
                listen_address: "".to_string(),
            },

            binary_dir: load_binary_dir(cli),
            scratch_directory: self
                .scratch_directory
                .replace("{user}", &user)
                .replace("{name}", &self.name),

            layout: self.layout,
            shmem: self.shmem,
            development: self.development,

            tiles: self.tiles,
        }
    }
}

fn load_binary_dir(args: &Cli) -> String {
    match &args.binary_dir {
        Some(path) => path.to_str().unwrap().into(),
        None => match env::var("FIREDANCER_BINARY_DIR") {
            Ok(path) => path,
            Err(_) => panic!(
                "No binary directory specified. Either set `--binary-dir <path>` or \
                 FIREDANCER_BINARY_DIR environment variable"
            ),
        },
    }
}

pub(crate) struct FrankConfig {
    pub(crate) pod: u32,
    pub(crate) main_cnc: u32,
    pub(crate) src_mac_address: String,
    pub(crate) listen_address: String,
}

macro_rules! config_struct {
    ($name:ident {
        {
            $($primitive_field:ident: $primitive_field_type:ty),*
        }
        $($field:ident: $field_type:ty),*
    }) => {
        #[derive(Deserialize)]
        pub(crate) struct $name {
            $(
                pub(crate) $primitive_field: $primitive_field_type,
            )*
            $(
                pub(crate) $field: $field_type,
            )*
        }

        paste! {
            impl $name {
                fn merge(&mut self, other: [<$name Delta>]) {
                    $(
                        self.$primitive_field.merge(other.$primitive_field.as_ref());
                    )*
                    $(
                        if let Some(field) = other.$field {
                            self.$field.merge(field);
                        }
                    )*
                }
            }

            #[derive(Deserialize)]
            struct [<$name Delta>] {
                $(
                    pub(crate) $primitive_field: Option<$primitive_field_type>,
                )*
                $(
                    pub(crate) $field: Option<[<$field_type Delta>]>,
                )*
            }
        }
    }
}

trait Mergable {
    fn merge(&mut self, other: Option<&Self>);
}

macro_rules! impl_merge {
    ( $type:ty ) => {
        impl Mergable for $type {
            fn merge(&mut self, other: Option<&Self>) {
                if let Some(other) = other {
                    *self = other.clone();
                }
            }
        }
    };
}

impl_merge!(String);
impl_merge!(PathBuf);
impl_merge!(u32);
impl_merge!(bool);

config_struct!(UserConfig {
    {
        name: String,
        user: String,

        scratch_directory: String
    }

    layout: LayoutConfig,
    shmem: ShmemConfig,

    tiles: TilesConfig,
    development: DevelopmentConfig
});

config_struct!(TilesConfig {
    {}
    quic: QuicConfig,
    verify: VerifyConfig,
    pack: PackConfig,
    dedup: DedupConfig
});

config_struct!(VerifyConfig {
    {
        receive_buffer_size: u32,
        mtu: u32
    }
});

config_struct!(PackConfig {
    {
        max_pending_transactions: u32,
        compute_unit_estimator_table_size: u32,
        compute_unit_estimator_ema_history: u32,
        compute_unit_estimator_ema_default: u32,
        solana_labs_bank_thread_count: u32,
        solana_labs_bank_thread_compute_units_executed_per_second: u32
    }
});

config_struct!(DedupConfig {
    {
        signature_cache_size: u32
    }
});

config_struct!(DevelopmentConfig {
    {
        sandbox: bool,
        sudo: bool
    }
    netns: NetNsConfig
});

config_struct!(NetNsConfig {
    {
        enabled: bool,
        interface0: String,
        interface0_mac: String,
        interface0_addr: String,
        interface1: String,
        interface1_mac: String,
        interface1_addr: String
    }
});

config_struct!(LayoutConfig {
    {
        affinity: String,
        verify_tile_count: u32
    }
});

config_struct!(ShmemConfig {
    {
        gigantic_page_mount_path: String,
        huge_page_mount_path: String,
        min_kernel_gigantic_pages: u32,
        min_kernel_huge_pages: u32,
        workspace_page_size: String,
        workspace_page_count: u32
    }
});

impl ShmemConfig {
    pub(crate) fn workspace_size(&self) -> u64 {
        match self.workspace_page_size.as_ref() {
            "gigantic" => self.workspace_page_count as u64 * 1024 * 1024 * 1024,
            "huge" => self.workspace_page_count as u64 * 2 * 1024 * 1024,
            _ => unreachable!(),
        }
    }
}

config_struct!(QuicConfig {
    {
        interface: String,
        listen_port: u32,
        max_concurrent_connections: u32,
        max_concurrent_connection_ids_per_connection: u32,
        max_concurrent_streams_per_connection: u32,
        max_concurrent_handshakes: u32,
        max_inflight_quic_packets: u32,
        tx_buf_size: u32,
        rx_buf_size: u32,
        xdp_mode: String,
        xdp_rx_queue_size: u32,
        xdp_tx_queue_size: u32,
        xdp_aio_depth: u32
    }
});

impl Config {
    pub(crate) fn dump_to_bash(&self) {
        let build = PathBuf::from(&self.binary_dir)
            .parent()
            .unwrap()
            .display()
            .to_string();

        let name = &self.name;
        let affinity = &self.layout.affinity;
        let pod = &self.frank.pod;
        let main_cnc = &self.frank.main_cnc;
        let interface = &self.tiles.quic.interface;
        let src_mac_address = &self.frank.src_mac_address;
        let quic_listen_port = &self.tiles.quic.listen_port;
        let quic_max_concurrent_connections = &self.tiles.quic.max_concurrent_connections;
        let quic_max_concurrent_connection_ids_per_connection =
            &self.tiles.quic.max_concurrent_connection_ids_per_connection;
        let quic_max_concurrent_streams_per_connection =
            &self.tiles.quic.max_concurrent_streams_per_connection;
        let quic_max_concurrent_handshakes = &self.tiles.quic.max_concurrent_handshakes;
        let quic_max_inflight_quic_packets = &self.tiles.quic.max_inflight_quic_packets;
        let quic_tx_buf_size = &self.tiles.quic.tx_buf_size;
        let quic_rx_buf_size = &self.tiles.quic.rx_buf_size;
        let listen_address = &self.frank.listen_address;

        let path = format!("{}/config.cfg", self.scratch_directory);
        #[rustfmt::skip]
        std::fs::write(&path, format!("#!/bin/bash \n\
            # AUTOGENERATED \n\
            BUILD={build} \n\
            WKSP={name}.wksp \n\
            AFFINITY={affinity} \n\
            APP={name} \n\
            POD={name}.wksp:{pod} \n\
            RUN_ARGS=--pod\\ {name}.wksp:{pod}\\ --log-app\\ {name}\\ --log-thread\\ main \n\
            MON_ARGS=--pod\\ {name}.wksp:{pod}\\ --log-app\\ {name}\\ --log-thread\\ mon \n\
            MAIN_CNC={name}.wksp:{main_cnc} \n\
            IFACE={interface} \n\
            LISTEN_ADDRS={listen_address} \n\
            SRC_MAC_ADDR={src_mac_address} \n\
            QUIC_LISTEN_PORT={quic_listen_port} \n\
            QUIC_CONN_CNT={quic_max_concurrent_connections} \n\
            QUIC_CONN_ID_CNT={quic_max_concurrent_connection_ids_per_connection} \n\
            QUIC_STREAM_CNT={quic_max_concurrent_streams_per_connection} \n\
            QUIC_HANDSHAKE_CNT={quic_max_concurrent_handshakes} \n\
            QUIC_MAX_INFLIGHT_PKTS={quic_max_inflight_quic_packets} \n\
            QUIC_TX_BUF_SZ={quic_tx_buf_size} \n\
            QUIC_RX_BUF_SZ={quic_rx_buf_size} \n\
        ")).unwrap();
        repermission(&path, self.uid, self.uid, 0o700);
    }
}
