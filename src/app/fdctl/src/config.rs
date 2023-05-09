use libc::getpwnam_r;
use serde::Deserialize;

use crate::*;

use std::env::current_exe;
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs, path};

pub(crate) struct Config {
    pub(crate) name: String,
    pub(crate) user: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,

    pub(crate) frank: FrankConfig,

    pub(crate) binary_dir: PathBuf,
    pub(crate) scratch_directory: String,

    pub(crate) affinity: String,
    pub(crate) pod_size: u32,
    pub(crate) cnc_app_size: u32,

    pub(crate) workspace: WorkspaceConfig,
    pub(crate) shmem: ShmemConfig,
    pub(crate) netns: NetNsConfig,

    pub(crate) tiles: TilesConfig,
}

#[derive(Deserialize)]
pub(crate) struct UserConfig {
    pub(crate) name: String,
    pub(crate) user: String,

    pub(crate) scratch_directory: String,

    pub(crate) affinity: String,
    pub(crate) pod_size: u32,
    pub(crate) cnc_app_size: u32,

    pub(crate) workspace: WorkspaceConfig,
    pub(crate) shmem: ShmemConfig,
    pub(crate) netns: NetNsConfig,

    pub(crate) tiles: TilesConfig,
}

impl UserConfig {
    pub(crate) fn load(path: &Option<path::PathBuf>) -> Self {
        let config_str = match path {
            Some(path) => fs::read_to_string(path).unwrap(),
            None => {
                match env::var("FIREDANCER_CONFIG_TOML") {
                    Ok(path) => fs::read_to_string(path).unwrap(),
                    Err(_) => panic!("No configuration file specified. Either set `--config <path>` or FIREDANCER_CONFIG_TOML environment variable"),
                }
            }
        };

        toml::from_str(&config_str).unwrap()
    }
}

#[link(name = "c")]
extern "C" {
    fn getuid() -> i32;
    fn getlogin_r(name: *mut i8, name_len: u64) -> i32;
}

/// Escalate the process to root if it's not already.
/// 
/// Returns true if we were not root, and the process got escalated. In this case, the caller
/// should exit and not do anything else as a new process was started in its place.
pub(crate) fn escalate_root() -> bool {
    let uid = unsafe { getuid() };
    if uid == 0 {
        return false;
    }

    let mut command = Command::new("/usr/bin/sudo");
    command.arg("-E");
    command.env_clear();
    for var in ["FIREDANCER_CONFIG_TOML", "FIREDANCER_BINARY_DIR", "RUST_LOG", "RUST_BACKTRACE"] {
        if let Ok(value) = env::var(var) {
            command.env(var, value);
        }
    }
    command.arg(current_exe().unwrap());
    command.args(env::args().skip(1));

    let status = command.spawn().unwrap().wait().unwrap();
    assert!(status.success());

    true
}

fn get_uid_by_username(username: &str) -> Option<u32> {
    let c_username = CString::new(username).unwrap();

    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let bufsize = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let bufsize = if bufsize > 0 { bufsize as usize } else { 1024 };

    let mut buf = Vec::with_capacity(bufsize);

    let err = unsafe {
        getpwnam_r(
            c_username.as_ptr(),
            &mut passwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.capacity(),
            &mut result,
        )
    };

    if err == 0 && !result.is_null() {
        Some(unsafe { (*result).pw_uid })
    } else {
        None
    }
}

fn default_user() -> String {
    match env::var("SUDO_USER") {
        Ok(name) => return name,
        _ => (),
    };

    match env::var("LOGNAME") {
        Ok(name) => name,
        _ => {
            let mut username: [i8; 32] = [0; 32];
            assert_eq!(0, unsafe { getlogin_r(username.as_mut_ptr(), 32) });
            unsafe {
                CStr::from_ptr(username.as_ptr())
                    .to_str()
                    .unwrap()
                    .to_owned()
            }
        }
    }
}

impl UserConfig {
    pub(crate) fn into_config(self, cli: &Cli) -> Config {
        let user = if self.user == "" {
            default_user()
        } else {
            self.user
        };

        Config {
            name: self.name.clone(),
            user: user.clone(),

            uid: get_uid_by_username(&user).unwrap(),
            gid: get_uid_by_username(&user).unwrap(),

            frank: FrankConfig {
                pod: 0,
                main_cnc: 0,
                src_mac_address: "".to_string(),
                listen_addresses: vec![],
            },

            binary_dir: load_binary_dir(&cli),
            scratch_directory: self
                .scratch_directory
                .replace("{user}", &user)
                .replace("{name}", &self.name),

            affinity: self.affinity,
            pod_size: self.pod_size,
            cnc_app_size: self.cnc_app_size,

            workspace: self.workspace,
            shmem: self.shmem,
            netns: self.netns,

            tiles: self.tiles,
        }
    }
}

fn load_binary_dir(args: &Cli) -> PathBuf {
    match &args.binary_dir {
        Some(path) => path.clone(),
        None => {
            match env::var("FIREDANCER_BINARY_DIR") {
                Ok(path) => PathBuf::from(path),
                Err(_) => panic!("No binary directory specified. Either set `--binary-dir <path>` or FIREDANCER_BINARY_DIR environment variable"),
            }
        }
    }
}

pub(crate) struct FrankConfig {
    pub(crate) pod: u32,
    pub(crate) main_cnc: u32,
    pub(crate) src_mac_address: String,
    pub(crate) listen_addresses: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct TilesConfig {
    pub(crate) quic: QuicConfig,
    pub(crate) verify: VerifyConfig,
    pub(crate) pack: PackConfig,
    pub(crate) dedup: DedupConfig,
}

#[derive(Deserialize)]
pub(crate) struct VerifyConfig {
    pub(crate) count: u32,
    pub(crate) depth: u32,
    pub(crate) mtu: u32,
}

#[derive(Deserialize)]
pub(crate) struct PackConfig {
    pub(crate) bank_count: u32,
    pub(crate) prq_size: u32,
    pub(crate) cu_est_table_size: u32,
    pub(crate) cu_est_history: u32,
    pub(crate) cu_est_default: u32,
    pub(crate) cu_limit: u32,
}

#[derive(Deserialize)]
pub(crate) struct DedupConfig {
    pub(crate) tcache_depth: u32,
    pub(crate) tcache_map_count: u32,
}

#[derive(Deserialize)]
pub(crate) struct NetNsConfig {
    pub(crate) enabled: bool,
    pub(crate) workspace: String,
    pub(crate) interface0: String,
    pub(crate) interface0_mac: String,
    pub(crate) interface0_addr: String,
    pub(crate) interface1: String,
    pub(crate) interface1_mac: String,
    pub(crate) interface1_addr: String,
}

#[derive(Deserialize)]
pub(crate) struct WorkspaceConfig {
    pub(crate) page_count: u32,
    pub(crate) page_size: String,
}

#[derive(Deserialize)]
pub(crate) struct ShmemConfig {
    pub(crate) path: String,
    pub(crate) gigantic_pages: u32,
    pub(crate) huge_pages: u32,
}

#[derive(Deserialize)]
pub(crate) struct QuicConfig {
    pub(crate) interface: String,
    pub(crate) listen_port: u32,
    pub(crate) connection_count: u32,
    pub(crate) connection_id_count: u32,
    pub(crate) stream_count: u32,
    pub(crate) handshake_count: u32,
    pub(crate) max_inflight_packets: u32,
    pub(crate) tx_buf_size: u32,
    pub(crate) rx_buf_size: u32,
    pub(crate) xdp_mode: String,
    pub(crate) xdp_frame_size: u32,
    pub(crate) xdp_rx_depth: u32,
    pub(crate) xdp_tx_depth: u32,
    pub(crate) xdp_aio_depth: u32,
}

impl Config {
    pub(crate) fn dump_to_bash(&self) {
        let build = self.binary_dir.parent().unwrap().display();
        let name = &self.name;
        let affinity = &self.affinity;
        let pod = &self.frank.pod;
        let main_cnc = &self.frank.main_cnc;
        let interface = &self.tiles.quic.interface;
        let src_mac_address = &self.frank.src_mac_address;
        let quic_listen_port = &self.tiles.quic.listen_port;
        let quic_connection_count = &self.tiles.quic.connection_count;
        let quic_connection_id_count = &self.tiles.quic.connection_id_count;
        let quic_stream_count = &self.tiles.quic.stream_count;
        let quic_handshake_count = &self.tiles.quic.handshake_count;
        let quic_max_inflight_packets = &self.tiles.quic.max_inflight_packets;
        let quic_tx_buf_size = &self.tiles.quic.tx_buf_size;
        let quic_rx_buf_size = &self.tiles.quic.rx_buf_size;
        let listen_addresses = self.frank.listen_addresses.join(",");

        std::fs::write(&format!("{}/{}.cfg", self.scratch_directory, self.name), format!("#!/bin/bash \n\
            # AUTOGENERATED \n\
            BUILD={build} \n\
            WKSP={name}.wksp \n\
            AFFINITY={affinity} \n\
            APP={name} \n\
            POD={name}.wksp:{pod} \n\
            RUN_ARGS=--pod\\ {name}.wksp:{pod}\\ --cfg\\ {name}\\ --log-app\\ {name}\\ --log-thread\\ main \n\
            MON_ARGS=--pod\\ {name}.wksp:{pod}\\ --cfg\\ {name}\\ --log-app\\ {name}\\ --log-thread\\ mon \n\
            MAIN_CNC={name}.wksp:{main_cnc} \n\
            IFACE={interface} \n\
            LISTEN_ADDRS={listen_addresses} \n\
            SRC_MAC_ADDR={src_mac_address} \n\
            QUIC_LISTEN_PORT={quic_listen_port} \n\
            QUIC_CONN_CNT={quic_connection_count} \n\
            QUIC_CONN_ID_CNT={quic_connection_id_count} \n\
            QUIC_STREAM_CNT={quic_stream_count} \n\
            QUIC_HANDSHAKE_CNT={quic_handshake_count} \n\
            QUIC_MAX_INFLIGHT_PKTS={quic_max_inflight_packets} \n\
            QUIC_TX_BUF_SZ={quic_tx_buf_size} \n\
            QUIC_RX_BUF_SZ={quic_rx_buf_size} \n\
        ")).unwrap();
    }
}
