#![allow(non_camel_case_types)]

use libc::{in_addr, sockaddr_in, socket, strlen, AF_INET, FILE, IPPROTO_UDP, SOCK_DGRAM};
use rand::Rng;
use solana_client::connection_cache::ConnectionCache;
use solana_connection_cache::client_connection::ClientConnection;
use solana_sdk::net::DEFAULT_TPU_COALESCE;
use solana_sdk::signer::keypair::Keypair;
use solana_streamer::nonblocking::quic::DEFAULT_MAX_CONNECTIONS_PER_IPADDR_PER_MINUTE;
use solana_streamer::nonblocking::quic::DEFAULT_MAX_STREAMS_PER_MS;
use solana_streamer::nonblocking::quic::DEFAULT_WAIT_FOR_CHUNK_TIMEOUT;
use solana_streamer::streamer::StakedNodes;
use std::ffi::{CString, c_char, c_void};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::ptr::null;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(unused)]
#[allow(clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use crate::bindings::{
    fd_aio_pcapng_get_aio, fd_aio_pcapng_join, fd_aio_pcapng_start, fd_aio_pcapng_t, fd_boot,
    fd_halt, fd_pcapng_fwrite_tls_key_log, fd_quic_connect, fd_quic_get_aio_net_rx, fd_quic_init,
    fd_quic_limits_t, fd_quic_new_anonymous, fd_quic_new_anonymous_small, fd_quic_service,
    fd_quic_set_aio_net_tx, fd_quic_stream_t, fd_quic_t, fd_rng_t, fd_udpsock_align,
    fd_udpsock_footprint, fd_udpsock_get_tx, fd_udpsock_join, fd_udpsock_new, fd_udpsock_service,
    fd_udpsock_set_rx, fd_udpsock_t, fd_wksp_new_anon, fd_wksp_t, FD_QUIC_CONN_STATE_ACTIVE,
    FD_QUIC_CONN_STATE_DEAD, FD_QUIC_ROLE_CLIENT, FD_QUIC_ROLE_SERVER,
};
use libc::{fflush, fopen};

unsafe fn fd_wksp_new_anonymous(
    page_sz: u64,
    page_cnt: u64,
    cpu_idx: u64,
    name: *const c_char,
    opt_part_max: u64,
) -> *mut fd_wksp_t {
    let sub_page_cnt = [page_cnt];
    let sub_cpu_idx = [cpu_idx];
    fd_wksp_new_anon(
        name,
        page_sz,
        1,
        sub_page_cnt.as_ptr(),
        sub_cpu_idx.as_ptr(),
        0,
        opt_part_max,
    )
}

unsafe fn new_udp_socket() -> (i32, u16) {
    let udp_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert!(udp_sock_fd > 0);

    let mut listen_addr: sockaddr_in = std::mem::zeroed();
    listen_addr.sin_family = AF_INET as u16;
    listen_addr.sin_addr = in_addr {
        s_addr: u32::from(Ipv4Addr::new(127, 0, 0, 1)).to_be(),
    };
    listen_addr.sin_port = 0;
    assert!(
        0 == libc::bind(
            udp_sock_fd,
            &listen_addr as *const sockaddr_in as *const libc::sockaddr,
            std::mem::size_of_val(&listen_addr) as u32
        )
    );

    let mut listen_addr_size = std::mem::size_of_val(&listen_addr) as u32;
    assert!(
        0 == libc::getsockname(
            udp_sock_fd,
            &mut listen_addr as *mut sockaddr_in as *mut libc::sockaddr,
            &mut listen_addr_size
        )
    );
    assert!(listen_addr_size == std::mem::size_of_val(&listen_addr) as u32);
    let listen_port = u16::from_be(listen_addr.sin_port);
    (udp_sock_fd, listen_port)
}

unsafe fn agave_to_fdquic() {
    // Set up Firedancer components

    let (udp_sock_fd, listen_port) = new_udp_socket();

    let wksp = fd_wksp_new_anonymous(4096, 16384, 0, b"test\0".as_ptr() as *const c_char, 0);
    assert!(!wksp.is_null(), "Failed to create workspace");

    let mut rng = fd_rng_t {
        idx: 0,
        seq: 0x172046447c516741,
    };

    let udpsock_mem = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
        fd_udpsock_footprint(2048, 256, 256) as usize,
        fd_udpsock_align() as usize,
    )) as *mut c_void;
    let udpsock = fd_udpsock_join(fd_udpsock_new(udpsock_mem, 2048, 256, 256), udp_sock_fd);
    assert!(!udpsock.is_null(), "Failed to create fd_udpsock_t");

    let quic = fd_quic_new_anonymous_small(wksp, FD_QUIC_ROLE_SERVER as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");
    (*quic).config.retry = 1;

    fd_quic_set_aio_net_tx(quic, fd_udpsock_get_tx(udpsock));
    fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic));

    assert!(!fd_quic_init(quic).is_null(), "fd_quic_init failed");

    // Rust's type system prevents us from passing raw pointers to a
    // thread even with appropriate synchronization barriers and unsafe.
    // To escape this hostage situation, we indrect via usize ... sigh
    let udpsock2 = udpsock as usize;
    let quic2 = quic as usize;
    let stop_ptr = Box::leak(Box::new(AtomicU32::new(0))) as *mut AtomicU32 as usize;
    let fd_quic_thread = std::thread::spawn(move || {
        let stop = stop_ptr as *mut AtomicU32;
        let udpsock3: *mut fd_udpsock_t = udpsock2 as *mut fd_udpsock_t;
        let quic3: *mut fd_quic_t = quic2 as *mut fd_quic_t;
        while (*stop).load(Ordering::Relaxed) == 0 {
            fd_udpsock_service(udpsock3);
            fd_quic_service(quic3);
        }
        let metrics = &(*quic3).metrics.__bindgen_anon_1;
        // Limit packet counts to reasonable numbers
        assert!(metrics.net_rx_pkt_cnt < 64);
        assert!(metrics.net_tx_pkt_cnt < metrics.net_rx_pkt_cnt);
        assert!(metrics.net_tx_byte_cnt < metrics.net_rx_byte_cnt);
        assert!(metrics.conn_active_cnt <= 1);
        assert!(metrics.conn_created_cnt == 1);
        assert!(metrics.conn_closed_cnt <= 1);
        assert!(metrics.conn_aborted_cnt <= 1);
        assert!(metrics.conn_retry_cnt == 1);
        assert!(metrics.conn_err_no_slots_cnt == 0);
        assert!(metrics.conn_err_tls_fail_cnt == 0);
        assert!(metrics.conn_err_retry_fail_cnt == 0);
        assert!(metrics.hs_created_cnt == 1);
        assert!(metrics.hs_err_alloc_fail_cnt == 0);
        eprintln!("Shutting down fd_quic");
    });

    // Set up Agave components

    let conn_cache = ConnectionCache::new_quic("test", 16);
    let conn = conn_cache.get_connection(&SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        listen_port,
    ));
    conn.send_data(b"Hello").expect("Failed to send data");

    let stop = stop_ptr as *mut AtomicU32;
    (*stop).store(1, Ordering::Relaxed);
    fd_quic_thread.join().unwrap();
    fd_halt();
}

unsafe extern "C" fn stream_new_cb(
    _stream: *mut fd_quic_stream_t,
    _ctx: *mut c_void,
) {
}

unsafe extern "C" fn stream_notify_cb(
    _stream: *mut fd_quic_stream_t,
    _ctx: *mut c_void,
    _event: i32,
) {
}

unsafe extern "C" fn stream_receive_cb(
    _stream: *mut fd_quic_stream_t,
    _ctx: *mut c_void,
    _buf: *const u8,
    _len: u64,
    _offset: u64,
    _fin: i32,
) {
}

unsafe fn agave_to_fdquic_bench() {
    // Set up Firedancer components

    let (udp_sock_fd, listen_port) = new_udp_socket();

    let wksp = fd_wksp_new_anonymous(4096, 16384, 0, b"test\0".as_ptr() as *const c_char, 0);
    assert!(!wksp.is_null(), "Failed to create workspace");

    let mut rng = fd_rng_t {
        idx: 0,
        seq: 0x172046447c516741,
    };

    let quic_limits = fd_quic_limits_t {
        conn_cnt: 1,
        handshake_cnt: 1,
        conn_id_cnt: 4,
        rx_stream_cnt: 16,
        stream_id_cnt: 16,
        inflight_pkt_cnt: 1024,
        tx_buf_sz: 0,
        stream_pool_cnt: 8,
    };
    let quic = fd_quic_new_anonymous(wksp, &quic_limits, FD_QUIC_ROLE_SERVER as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");
    (*quic).config.retry = 1;
    (*quic).cb.stream_new = Some(stream_new_cb);
    (*quic).cb.stream_notify = Some(stream_notify_cb);
    (*quic).cb.stream_receive = Some(stream_receive_cb);

    // Rust's type system prevents us from passing raw pointers to a
    // thread even with appropriate synchronization barriers and unsafe.
    // To escape this hostage situation, we indrect via usize ... sigh
    let quic2 = quic as usize;
    std::thread::spawn(move || {
        let quic3: *mut fd_quic_t = quic2 as *mut fd_quic_t;

        let udpsock_mem = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
            fd_udpsock_footprint(2048, 1024, 1024) as usize,
            fd_udpsock_align() as usize,
        )) as *mut c_void;
        let udpsock = fd_udpsock_join(fd_udpsock_new(udpsock_mem, 2048, 1024, 1024), udp_sock_fd);
        assert!(!udpsock.is_null(), "Failed to create fd_udpsock_t");

        let pcap = std::env::var("PCAP").unwrap_or_default();
        if !pcap.is_empty() {
            let pcap_path_cstr = CString::new(pcap).unwrap();
            let pcap_file = fopen(
                pcap_path_cstr.as_ptr() as *const c_char,
                "wb\x00".as_ptr() as *const c_char,
            );
            assert!(!pcap_file.is_null());
            fd_aio_pcapng_start(pcap_file as *mut c_void);
            fflush(pcap_file);

            static mut PCAP_FILE_GLOB: *mut FILE = std::ptr::null_mut();
            PCAP_FILE_GLOB = pcap_file;

            let mut aio_pcapng1_mem: fd_aio_pcapng_t = MaybeUninit::zeroed().assume_init();
            let mut aio_pcapng2_mem: fd_aio_pcapng_t = MaybeUninit::zeroed().assume_init();
            let aio_pcapng1 = fd_aio_pcapng_join(
                &mut aio_pcapng1_mem as *mut fd_aio_pcapng_t as *mut c_void,
                fd_udpsock_get_tx(udpsock),
                pcap_file as *mut c_void,
            );
            let aio_pcapng2 = fd_aio_pcapng_join(
                &mut aio_pcapng2_mem as *mut fd_aio_pcapng_t as *mut c_void,
                fd_quic_get_aio_net_rx(quic3),
                pcap_file as *mut c_void,
            );
            assert!(!aio_pcapng1.is_null());
            assert!(!aio_pcapng2.is_null());

            fd_quic_set_aio_net_tx(quic3, fd_aio_pcapng_get_aio(aio_pcapng1));
            fd_udpsock_set_rx(udpsock, fd_aio_pcapng_get_aio(aio_pcapng2));

            unsafe extern "C" fn tls_keylog_cb(_ctx: *mut c_void, line: *const c_char) {
                fd_pcapng_fwrite_tls_key_log(
                    line as *const u8,
                    strlen(line) as u32,
                    PCAP_FILE_GLOB as *mut c_void,
                );
            }
            (*quic3).cb.tls_keylog = Some(tls_keylog_cb);
        } else {
            fd_quic_set_aio_net_tx(quic3, fd_udpsock_get_tx(udpsock));
            fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic3));
        }

        assert!(!fd_quic_init(quic3).is_null(), "fd_quic_init failed");

        std::thread::spawn(move || {
            let quic4: *mut fd_quic_t = quic2 as *mut fd_quic_t;
            let metrics = &(*quic4).metrics.__bindgen_anon_1;
            let mut last_cnt = 0u64;
            loop {
                std::thread::sleep(Duration::from_secs(1));
                println!("{}", metrics.net_rx_pkt_cnt - last_cnt);
                last_cnt = metrics.net_rx_pkt_cnt;
            }
        });

        loop {
            fd_udpsock_service(udpsock);
            fd_quic_service(quic3);
        }
    });

    // Set up Agave components

    const BUF: [u8; 1232] = [0u8; 1232];

    let conn_cache = ConnectionCache::new_quic("test", 16);
    let conn = conn_cache.get_connection(&SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        listen_port,
    ));

    let mut batch = Vec::<Vec<u8>>::with_capacity(1024);

    let mut rng = rand::thread_rng();
    loop {
        let cnt: usize = rng.gen_range(1..batch.capacity());
        batch.clear();
        for _ in 0..cnt {
            batch.push(BUF[0..rng.gen_range(1..BUF.len())].to_vec());
        }
        if let Err(err) = conn.send_data_batch(&batch) {
            eprintln!("{:?}", err);
        }
    }
}

unsafe fn fdquic_to_agave() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let listen_port = udp_socket.local_addr().unwrap().port();
    let keypair = Keypair::new();
    let (agave_tx, _agave_rx) = crossbeam_channel::bounded(16);
    let exit = Arc::new(AtomicBool::new(false));
    let agave_server_handle = solana_streamer::quic::spawn_server(
        "agave_server",
        "agave_server",
        udp_socket,
        &keypair,
        agave_tx,
        Arc::clone(&exit),
        1,
        Arc::new(RwLock::new(StakedNodes::default())),
        1,
        1,
        DEFAULT_MAX_STREAMS_PER_MS,
        DEFAULT_MAX_CONNECTIONS_PER_IPADDR_PER_MINUTE,
        DEFAULT_WAIT_FOR_CHUNK_TIMEOUT,
        DEFAULT_TPU_COALESCE,
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(500));

    let (udp_sock_fd, client_port) = new_udp_socket();

    let wksp = fd_wksp_new_anonymous(4096, 16384, 0, b"test\0".as_ptr() as *const c_char, 0);
    assert!(!wksp.is_null(), "Failed to create workspace");

    let mut rng = fd_rng_t {
        idx: 0,
        seq: 0x172046447c516741,
    };

    let udpsock_mem = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
        fd_udpsock_footprint(2048, 256, 256) as usize,
        fd_udpsock_align() as usize,
    )) as *mut c_void;
    let udpsock = fd_udpsock_join(fd_udpsock_new(udpsock_mem, 2048, 256, 256), udp_sock_fd);
    assert!(!udpsock.is_null(), "Failed to create fd_udpsock_t");

    let quic = fd_quic_new_anonymous_small(wksp, FD_QUIC_ROLE_CLIENT as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");
    (*quic).config.net.ephem_udp_port.lo = client_port;
    (*quic).config.net.ephem_udp_port.hi = client_port;

    fd_quic_set_aio_net_tx(quic, fd_udpsock_get_tx(udpsock));
    fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic));

    assert!(!fd_quic_init(quic).is_null(), "fd_quic_init failed");

    eprintln!(
        "Connecting from 127.0.0.1:{} to 127.0.0.1:{}",
        client_port, listen_port
    );
    let conn = fd_quic_connect(quic, 0x0100007f, listen_port, null());
    assert!(!conn.is_null());
    let conn_start = Instant::now();
    loop {
        fd_quic_service(quic);
        fd_udpsock_service(udpsock);
        if (*conn).state == FD_QUIC_CONN_STATE_ACTIVE || (*conn).state == FD_QUIC_CONN_STATE_DEAD {
            break;
        }
        assert!(conn_start.elapsed() < Duration::from_secs(3));
    }

    fd_halt();
    exit.store(true, Ordering::Relaxed);
    agave_server_handle.thread.join().unwrap();
}

static USAGE: &str = r"Usage: ./firedancer-agave-quic-test <command>

Available commands are:

  ping-server: Ping solana_client to fd_quic server
  ping-client: Ping fd_quic client to solana_streamer server
  spam-server: Benchmark single solana_streamer client to fd_quic server";

fn main() {
    env_logger::init();
    let arg = if let Some(arg) = std::env::args().nth(1) {
        arg
    } else {
        eprintln!("{}", USAGE);
        std::process::exit(1);
    };

    std::env::set_var("FD_LOG_PATH", "");
    std::env::set_var("FD_LOG_LEVEL_LOGFILE", "0");
    std::env::set_var("FD_LOG_LEVEL_STDERR", "0");
    let mut argc = 1;
    let mut argv = vec![b"test\0".as_ptr() as *mut c_char, std::ptr::null_mut()];
    let mut argv_ptr = argv.as_mut_ptr();
    unsafe {
        fd_boot(&mut argc, &mut argv_ptr);
    }

    match arg.as_str() {
        "ping-server" => unsafe { agave_to_fdquic() },
        "ping-client" => unsafe { fdquic_to_agave() },
        "spam-server" => unsafe { agave_to_fdquic_bench() },
        _ => panic!("Unknown arg"),
    }
}
