#![allow(non_camel_case_types)]

use agave_votor_messages::{consensus_message::ConsensusMessage, vote::Vote};
use libc::{in_addr, sockaddr_in, socket, strlen, AF_INET, FILE, IPPROTO_UDP, SOCK_DGRAM};
use rand::RngExt;
use solana_bls_signatures::{Signature as BLSSignature, BLS_SIGNATURE_AFFINE_SIZE};
use solana_client::connection_cache::ConnectionCache;
use solana_connection_cache::client_connection::ClientConnection;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_streamer::nonblocking::simple_qos::SimpleQosConfig;
use solana_streamer::nonblocking::swqos::SwQosConfig;
use solana_streamer::streamer::StakedNodes;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CString};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

mod blaster;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(unused)]
#[allow(clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use crate::bindings::{
    fd_aio_pcapng_get_aio, fd_aio_pcapng_join, fd_aio_pcapng_start_l3, fd_aio_pcapng_t, fd_boot,
    fd_halt, fd_log_wallclock, fd_pcapng_fwrite_tls_key_log, fd_quic_conn_new_stream,
    fd_quic_conn_t, fd_quic_connect, fd_quic_get_aio_net_rx, fd_quic_init, fd_quic_limits_t,
    fd_quic_new_anonymous, fd_quic_new_anonymous_small, fd_quic_service, fd_quic_set_aio_net_tx,
    fd_quic_stream_send, fd_quic_t, fd_rng_t, fd_udpsock_align, fd_udpsock_footprint,
    fd_udpsock_get_tx, fd_udpsock_join, fd_udpsock_new, fd_udpsock_service, fd_udpsock_set_layer,
    fd_udpsock_set_rx, fd_udpsock_t, fd_wksp_new_anon, fd_wksp_t, FD_QUIC_CONN_STATE_ACTIVE,
    FD_QUIC_CONN_STATE_DEAD, FD_QUIC_ROLE_CLIENT, FD_QUIC_ROLE_SERVER, FD_UDPSOCK_LAYER_IP,
};
use libc::{fflush, fopen};

struct StreamRxState {
    buf: Vec<u8>,
    fin: bool,
}

static mut FD_STREAM_RX_STATE: *const Mutex<StreamRxState> = std::ptr::null();

unsafe extern "C" fn fd_stream_rx_collect(
    _conn: *mut fd_quic_conn_t,
    _stream_id: u64,
    offset: u64,
    data: *const u8,
    data_sz: u64,
    fin: i32,
) -> i32 {
    if FD_STREAM_RX_STATE.is_null() {
        return -1;
    }
    let state = &*FD_STREAM_RX_STATE;
    let mut state = state.lock().unwrap();
    let offset = offset as usize;
    let data_sz = data_sz as usize;
    let end = offset + data_sz;
    if state.buf.len() < end {
        state.buf.resize(end, 0);
    }
    state.buf[offset..end].copy_from_slice(std::slice::from_raw_parts(data, data_sz));
    if fin != 0 {
        state.fin = true;
    }
    0
}

fn alpenglow_test_message() -> ConsensusMessage {
    ConsensusMessage::new_vote(
        Vote::new_skip_vote(5),
        BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        1,
    )
}

fn alpenglow_test_wire() -> Vec<u8> {
    wincode::serialize(&alpenglow_test_message()).expect("failed to serialize Alpenglow message")
}

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
    new_udp_socket_at(Ipv4Addr::new(127, 0, 0, 1), 0)
}

unsafe fn new_udp_socket_at(ip: Ipv4Addr, port: u16) -> (i32, u16) {
    let udp_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert!(udp_sock_fd > 0);

    let mut listen_addr: sockaddr_in = std::mem::zeroed();
    listen_addr.sin_family = AF_INET as u16;
    listen_addr.sin_addr = in_addr {
        s_addr: u32::from(ip).to_be(),
    };
    listen_addr.sin_port = port.to_be();
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

fn fd_ip4(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

fn local_ipv4_for(dst: SocketAddrV4) -> Ipv4Addr {
    let probe = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    probe.connect(dst).unwrap();
    match probe.local_addr().unwrap() {
        SocketAddr::V4(addr) => *addr.ip(),
        SocketAddr::V6(_) => panic!("IPv6 local address selected for IPv4 destination"),
    }
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
    fd_udpsock_set_layer(udpsock, FD_UDPSOCK_LAYER_IP);

    let quic = fd_quic_new_anonymous_small(wksp, FD_QUIC_ROLE_SERVER as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");
    (*quic).config.retry = 1;
    (*quic).config.idle_timeout = 10_000_000_000; // 10s

    fd_quic_set_aio_net_tx(quic, fd_udpsock_get_tx(udpsock));
    fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic));

    assert!(!fd_quic_init(quic).is_null(), "fd_quic_init failed");

    // Rust's type system prevents us from passing raw pointers to a
    // thread even with appropriate synchronization barriers and unsafe.
    // To escape this hostage situation, we indirect via usize ... sigh
    let udpsock2 = udpsock as usize;
    let quic2 = quic as usize;
    let stop_ptr = Box::leak(Box::new(AtomicU32::new(0))) as *mut AtomicU32 as usize;
    let fd_quic_thread = std::thread::spawn(move || {
        let stop = stop_ptr as *mut AtomicU32;
        let udpsock3: *mut fd_udpsock_t = udpsock2 as *mut fd_udpsock_t;
        let quic3: *mut fd_quic_t = quic2 as *mut fd_quic_t;
        while (*stop).load(Ordering::Relaxed) == 0 {
            fd_udpsock_service(udpsock3);
            fd_quic_service(quic3, fd_log_wallclock());
        }
        let metrics = &(*quic3).metrics.__bindgen_anon_1;
        // Limit packet counts to reasonable numbers
        println!("fd_quic server received {} packets", metrics.net_rx_pkt_cnt);
        println!(
            "fd_quic server transmitted {} packets",
            metrics.net_tx_pkt_cnt
        );
        assert!(metrics.net_rx_pkt_cnt < 64);
        assert!(metrics.net_tx_pkt_cnt < metrics.net_rx_pkt_cnt);
        assert!(metrics.net_tx_byte_cnt < metrics.net_rx_byte_cnt);
        assert!(metrics.conn_alloc_cnt <= 1);
        assert!(metrics.conn_created_cnt == 1);
        assert!(metrics.conn_closed_cnt <= 1);
        assert!(metrics.conn_aborted_cnt <= 1);
        assert!(metrics.conn_retry_cnt == 1);
        assert!(metrics.conn_err_no_slots_cnt == 0);
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

unsafe fn agave_alpenglow_to_fdquic() {
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
    fd_udpsock_set_layer(udpsock, FD_UDPSOCK_LAYER_IP);

    let quic = fd_quic_new_anonymous_small(wksp, FD_QUIC_ROLE_SERVER as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");
    (*quic).config.retry = 1;
    (*quic).config.idle_timeout = 10_000_000_000; // 10s

    let rx_state = Box::leak(Box::new(Mutex::new(StreamRxState {
        buf: Vec::new(),
        fin: false,
    })));
    FD_STREAM_RX_STATE = rx_state as *const Mutex<StreamRxState>;
    (*quic).cb.stream_rx = Some(fd_stream_rx_collect);

    fd_quic_set_aio_net_tx(quic, fd_udpsock_get_tx(udpsock));
    fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic));

    assert!(!fd_quic_init(quic).is_null(), "fd_quic_init failed");

    let udpsock2 = udpsock as usize;
    let quic2 = quic as usize;
    let stop_ptr = Box::leak(Box::new(AtomicU32::new(0))) as *mut AtomicU32 as usize;
    let fd_quic_thread = std::thread::spawn(move || {
        let stop = stop_ptr as *mut AtomicU32;
        let udpsock3: *mut fd_udpsock_t = udpsock2 as *mut fd_udpsock_t;
        let quic3: *mut fd_quic_t = quic2 as *mut fd_quic_t;
        while (*stop).load(Ordering::Relaxed) == 0 {
            fd_udpsock_service(udpsock3);
            fd_quic_service(quic3, fd_log_wallclock());
        }
        let metrics = &(*quic3).metrics.__bindgen_anon_1;
        println!("fd_quic server received {} packets", metrics.net_rx_pkt_cnt);
        println!(
            "fd_quic server received {} stream bytes",
            metrics.stream_rx_byte_cnt
        );
        assert!(metrics.stream_rx_byte_cnt > 0);
    });

    let expected = alpenglow_test_message();
    let wire = alpenglow_test_wire();
    let conn_cache = ConnectionCache::new_quic("test_alpenglow", 1);
    let conn = conn_cache.get_connection(&SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        listen_port,
    ));
    conn.send_data(&wire)
        .expect("Failed to send Alpenglow message");

    let start = Instant::now();
    loop {
        if rx_state.lock().unwrap().fin {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "timed out waiting for fd_quic Alpenglow stream"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let received = rx_state.lock().unwrap().buf.clone();
    let actual: ConsensusMessage =
        wincode::deserialize_exact(&received).expect("failed to deserialize Alpenglow message");
    assert_eq!(actual, expected);
    println!("fd_quic server received valid Alpenglow message");

    let stop = stop_ptr as *mut AtomicU32;
    (*stop).store(1, Ordering::Relaxed);
    fd_quic_thread.join().unwrap();
    FD_STREAM_RX_STATE = std::ptr::null();
    fd_halt();
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
        stream_id_cnt: 16,
        inflight_frame_cnt: 1024,
        min_inflight_frame_cnt_conn: 128,
        tx_buf_sz: 0,
        stream_pool_cnt: 8,
        log_depth: 128,
    };
    let quic = fd_quic_new_anonymous(wksp, &quic_limits, FD_QUIC_ROLE_SERVER as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");
    (*quic).config.retry = 1;

    // Rust's type system prevents us from passing raw pointers to a
    // thread even with appropriate synchronization barriers and unsafe.
    // To escape this hostage situation, we indirect via usize ... sigh
    let quic2 = quic as usize;
    std::thread::spawn(move || {
        let quic3: *mut fd_quic_t = quic2 as *mut fd_quic_t;

        let udpsock_mem = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
            fd_udpsock_footprint(2048, 1024, 1024) as usize,
            fd_udpsock_align() as usize,
        )) as *mut c_void;
        let udpsock = fd_udpsock_join(fd_udpsock_new(udpsock_mem, 2048, 1024, 1024), udp_sock_fd);
        assert!(!udpsock.is_null(), "Failed to create fd_udpsock_t");
        fd_udpsock_set_layer(udpsock, FD_UDPSOCK_LAYER_IP);

        let pcap = std::env::var("PCAP").unwrap_or_default();
        if !pcap.is_empty() {
            let pcap_path_cstr = CString::new(pcap).unwrap();
            let pcap_file = fopen(
                pcap_path_cstr.as_ptr() as *const c_char,
                "wb\x00".as_ptr() as *const c_char,
            );
            assert!(!pcap_file.is_null());
            fd_aio_pcapng_start_l3(pcap_file as *mut c_void);
            fflush(pcap_file);

            static mut PCAP_FILE_GLOB: *mut FILE = std::ptr::null_mut();
            PCAP_FILE_GLOB = pcap_file;

            let aio_pcapng1_mem: &mut fd_aio_pcapng_t = Box::leak(Box::new(
                MaybeUninit::<fd_aio_pcapng_t>::zeroed().assume_init(),
            ));
            let aio_pcapng2_mem: &mut fd_aio_pcapng_t = Box::leak(Box::new(
                MaybeUninit::<fd_aio_pcapng_t>::zeroed().assume_init(),
            ));
            let aio_pcapng1 = fd_aio_pcapng_join(
                aio_pcapng1_mem as *mut fd_aio_pcapng_t as *mut c_void,
                fd_udpsock_get_tx(udpsock),
                pcap_file as *mut c_void,
            );
            let aio_pcapng2 = fd_aio_pcapng_join(
                aio_pcapng2_mem as *mut fd_aio_pcapng_t as *mut c_void,
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
            let mut last_net_rx_pkt_cnt = 0u64;
            let mut last_net_rx_byte_cnt = 0u64;
            let mut last_stream_rx_byte_cnt = 0u64;
            loop {
                let net_rx_pkt_d = metrics.net_rx_pkt_cnt - last_net_rx_pkt_cnt;
                let net_rx_byte_d = metrics.net_rx_byte_cnt - last_net_rx_byte_cnt;
                let stream_rx_byte_d = metrics.stream_rx_byte_cnt - last_stream_rx_byte_cnt;
                let net_rx_gbps = ((8 * net_rx_byte_d) as f64) / 1e9f64;
                let net_rx_mpps = (net_rx_pkt_d as f64) / 1e6f64;
                let stream_rx_gbps = ((8 * stream_rx_byte_d) as f64) / 1e9f64;
                last_net_rx_pkt_cnt = metrics.net_rx_pkt_cnt;
                last_net_rx_byte_cnt = metrics.net_rx_byte_cnt;
                last_stream_rx_byte_cnt = metrics.stream_rx_byte_cnt;
                std::thread::sleep(Duration::from_secs(1));
                println!(
                    "data={:.3} Gbps  net_rx=({:.3} Gbps {:.3} Mpps)",
                    net_rx_gbps, net_rx_mpps, stream_rx_gbps
                );
            }
        });

        loop {
            (*quic3).cb.stream_rx = None;
            fd_udpsock_service(udpsock);
            fd_quic_service(quic3, fd_log_wallclock());
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

    let mut rng = rand::rng();
    loop {
        let cnt: usize = rng.random_range(1..batch.capacity());
        batch.clear();
        for _ in 0..cnt {
            batch.push(BUF[0..rng.random_range(1..BUF.len())].to_vec());
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
    let cancel = CancellationToken::new();
    let agave_server_handle = solana_streamer::quic::spawn_server_with_cancel(
        "agave_server",
        "agave_server",
        [udp_socket],
        &keypair,
        agave_tx,
        Arc::new(RwLock::new(StakedNodes::default())),
        solana_streamer::quic::QuicStreamerConfig::default(),
        SwQosConfig::default(),
        cancel.clone(),
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
    fd_udpsock_set_layer(udpsock, FD_UDPSOCK_LAYER_IP);

    let quic = fd_quic_new_anonymous_small(wksp, FD_QUIC_ROLE_CLIENT as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");

    fd_quic_set_aio_net_tx(quic, fd_udpsock_get_tx(udpsock));
    fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic));

    assert!(!fd_quic_init(quic).is_null(), "fd_quic_init failed");

    eprintln!(
        "Connecting from 127.0.0.1:{} to 127.0.0.1:{}",
        client_port, listen_port
    );
    let conn = fd_quic_connect(
        quic,
        0x0100007f,
        listen_port,
        0x0100007f,
        client_port,
        fd_log_wallclock(),
    );
    assert!(!conn.is_null());
    let conn_start = Instant::now();
    loop {
        fd_quic_service(quic, fd_log_wallclock());
        fd_udpsock_service(udpsock);
        if (*conn).state == FD_QUIC_CONN_STATE_ACTIVE || (*conn).state == FD_QUIC_CONN_STATE_DEAD {
            break;
        }
        assert!(conn_start.elapsed() < Duration::from_secs(3));
    }

    fd_halt();
    cancel.cancel();
    agave_server_handle.thread.join().unwrap();
}

unsafe fn fdquic_to_agave_alpenglow() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let listen_port = udp_socket.local_addr().unwrap().port();
    let keypair = Keypair::new();
    let (agave_tx, agave_rx) = crossbeam_channel::bounded(16);
    let cancel = CancellationToken::new();
    let staked_nodes = Arc::new(RwLock::new(StakedNodes::default()));
    let agave_server_handle = solana_streamer::quic::spawn_simple_qos_server_with_cancel(
        "agave_alpenglow_server",
        "agave_alpenglow_server",
        [udp_socket],
        &keypair,
        agave_tx,
        staked_nodes.clone(),
        solana_streamer::quic::QuicStreamerConfig::default(),
        SimpleQosConfig::default(),
        cancel.clone(),
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
    fd_udpsock_set_layer(udpsock, FD_UDPSOCK_LAYER_IP);

    let quic_limits = fd_quic_limits_t {
        conn_cnt: 1,
        handshake_cnt: 1,
        conn_id_cnt: 4,
        stream_id_cnt: 16,
        inflight_frame_cnt: 1024,
        min_inflight_frame_cnt_conn: 128,
        tx_buf_sz: 1 << 15,
        stream_pool_cnt: 8,
        log_depth: 128,
    };
    let quic = fd_quic_new_anonymous(wksp, &quic_limits, FD_QUIC_ROLE_CLIENT as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");
    let client_pubkey = Pubkey::from((*quic).config.identity_public_key);
    *staked_nodes.write().unwrap() = StakedNodes::new(
        Arc::new(HashMap::from([(client_pubkey, 1_000_000u64)])),
        HashMap::default(),
    );

    fd_quic_set_aio_net_tx(quic, fd_udpsock_get_tx(udpsock));
    fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic));

    assert!(!fd_quic_init(quic).is_null(), "fd_quic_init failed");

    eprintln!(
        "Connecting from 127.0.0.1:{} to 127.0.0.1:{}",
        client_port, listen_port
    );
    let conn = fd_quic_connect(
        quic,
        0x0100007f,
        listen_port,
        0x0100007f,
        client_port,
        fd_log_wallclock(),
    );
    assert!(!conn.is_null());
    let conn_start = Instant::now();
    loop {
        fd_quic_service(quic, fd_log_wallclock());
        fd_udpsock_service(udpsock);
        if (*conn).state == FD_QUIC_CONN_STATE_ACTIVE || (*conn).state == FD_QUIC_CONN_STATE_DEAD {
            break;
        }
        assert!(conn_start.elapsed() < Duration::from_secs(3));
    }
    assert_eq!((*conn).state, FD_QUIC_CONN_STATE_ACTIVE);

    let wire = alpenglow_test_wire();
    let stream_start = Instant::now();
    let stream = loop {
        let stream = fd_quic_conn_new_stream(conn);
        if !stream.is_null() {
            break stream;
        }
        fd_quic_service(quic, fd_log_wallclock());
        fd_udpsock_service(udpsock);
        assert!(
            stream_start.elapsed() < Duration::from_secs(3),
            "fd_quic_conn_new_stream failed: state={} tx_next={} tx_sup={}",
            (*conn).state,
            (*conn).tx_next_stream_id,
            (*conn).tx_sup_stream_id
        );
    };
    let send_rc = fd_quic_stream_send(stream, wire.as_ptr() as *const c_void, wire.len() as u64, 1);
    assert_eq!(send_rc, 0, "fd_quic_stream_send failed");

    let receive_start = Instant::now();
    let received = loop {
        fd_quic_service(quic, fd_log_wallclock());
        fd_udpsock_service(udpsock);
        if let Ok(packets) = agave_rx.try_recv() {
            if let Some(packet) = packets.iter().next() {
                break packet.data(..).expect("discarded packet").to_vec();
            }
        }
        assert!(
            receive_start.elapsed() < Duration::from_secs(3),
            "timed out waiting for Agave Alpenglow packet"
        );
    };

    let expected = alpenglow_test_message();
    let actual: ConsensusMessage =
        wincode::deserialize_exact(&received).expect("failed to deserialize Alpenglow message");
    assert_eq!(actual, expected);
    println!("Agave Alpenglow server received valid fd_quic message");

    fd_halt();
    cancel.cancel();
    agave_server_handle.thread.join().unwrap();
}

unsafe fn fdquic_to_remote_agave_alpenglow(dst: SocketAddrV4, requested_local_port: u16) {
    let local_ip = local_ipv4_for(dst);
    let (udp_sock_fd, client_port) = new_udp_socket_at(local_ip, requested_local_port);

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
    fd_udpsock_set_layer(udpsock, FD_UDPSOCK_LAYER_IP);

    let quic_limits = fd_quic_limits_t {
        conn_cnt: 1,
        handshake_cnt: 1,
        conn_id_cnt: 4,
        stream_id_cnt: 16,
        inflight_frame_cnt: 1024,
        min_inflight_frame_cnt_conn: 128,
        tx_buf_sz: 1 << 15,
        stream_pool_cnt: 8,
        log_depth: 128,
    };
    let quic = fd_quic_new_anonymous(wksp, &quic_limits, FD_QUIC_ROLE_CLIENT as i32, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");

    fd_quic_set_aio_net_tx(quic, fd_udpsock_get_tx(udpsock));
    fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic));

    assert!(!fd_quic_init(quic).is_null(), "fd_quic_init failed");

    eprintln!("Connecting from {}:{} to {}", local_ip, client_port, dst);
    let conn = fd_quic_connect(
        quic,
        fd_ip4(*dst.ip()),
        dst.port(),
        fd_ip4(local_ip),
        client_port,
        fd_log_wallclock(),
    );
    assert!(!conn.is_null());

    let wire = alpenglow_test_wire();
    let mut next_send = Instant::now();
    let mut sent = 0u64;
    let start = Instant::now();
    loop {
        fd_quic_service(quic, fd_log_wallclock());
        fd_udpsock_service(udpsock);

        if (*conn).state == FD_QUIC_CONN_STATE_ACTIVE && Instant::now() >= next_send {
            let stream = fd_quic_conn_new_stream(conn);
            if !stream.is_null() {
                let send_rc = fd_quic_stream_send(
                    stream,
                    wire.as_ptr() as *const c_void,
                    wire.len() as u64,
                    1,
                );
                if send_rc == 0 {
                    sent += 1;
                    eprintln!("Sent Alpenglow message {}", sent);
                } else {
                    eprintln!("fd_quic_stream_send failed: {}", send_rc);
                }
            }
            next_send += Duration::from_millis(200);
        }

        if (*conn).state == FD_QUIC_CONN_STATE_DEAD {
            eprintln!("Connection died after sending {} messages", sent);
            break;
        }
        if start.elapsed() > Duration::from_secs(20) {
            eprintln!("Timed out after 20s: state={} sent={}", (*conn).state, sent);
            break;
        }
    }

    fd_halt();
}

fn agave_votor_to_remote(dst: SocketAddr) {
    let wire = Arc::new(alpenglow_test_wire());
    let connection_cache = ConnectionCache::new_quic("agave_votor_remote_client", 1);
    let conn = connection_cache.get_connection(&dst);
    let start = Instant::now();
    let mut next_send = Instant::now();
    let mut sent = 0u64;

    while start.elapsed() < Duration::from_secs(20) {
        if Instant::now() >= next_send {
            match conn.send_data_async(wire.clone()) {
                Ok(()) => {
                    sent += 1;
                    eprintln!("Queued Agave votor message {}", sent);
                }
                Err(err) => eprintln!("Agave votor send failed: {err:?}"),
            }
            next_send += Duration::from_millis(200);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    eprintln!("Finished Agave votor remote send: queued={sent}");
}

static USAGE: &str = r"Usage: ./firedancer-agave-quic-test <command>

Available commands are:

  blast:       Flood target with MTU-size QUIC streams
  ping-server: Ping solana_client to fd_quic server
  ping-client: Ping fd_quic client to solana_streamer server
  spam-server: Benchmark single solana_streamer client to fd_quic server
  alpenglow-ping-server: Ping Agave Alpenglow client to fd_quic server
  alpenglow-ping-client: Ping fd_quic client to Agave Alpenglow server
  alpenglow-remote-client: Ping remote QUIC endpoint with fd_quic Alpenglow payload
  agave-votor-remote-client: Ping remote QUIC endpoint with Agave votor send path";

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
        "blast" => {
            let arg = if let Some(arg) = std::env::args().nth(2) {
                arg
            } else {
                eprintln!("Usage firedancer-agave-quic-test blast <endpoint:port>");
                std::process::exit(1);
            };
            blaster::blast(arg);
        }
        "ping-server" => unsafe { agave_to_fdquic() },
        "ping-client" => unsafe { fdquic_to_agave() },
        "spam-server" => unsafe { agave_to_fdquic_bench() },
        "alpenglow-ping-server" => unsafe { agave_alpenglow_to_fdquic() },
        "alpenglow-ping-client" => unsafe { fdquic_to_agave_alpenglow() },
        "alpenglow-remote-client" => {
            let endpoint = std::env::args()
                .nth(2)
                .unwrap_or_else(|| "64.130.37.11:8011".to_string());
            let dst: SocketAddrV4 = endpoint
                .parse()
                .unwrap_or_else(|_| panic!("expected IPv4 endpoint, got {}", endpoint));
            let local_port = std::env::args()
                .nth(3)
                .map(|arg| arg.parse().expect("local port must be u16"))
                .unwrap_or(0);
            unsafe { fdquic_to_remote_agave_alpenglow(dst, local_port) }
        }
        "agave-votor-remote-client" => {
            let endpoint = std::env::args()
                .nth(2)
                .unwrap_or_else(|| "64.130.37.11:8011".to_string());
            let dst: SocketAddr = endpoint
                .parse()
                .unwrap_or_else(|_| panic!("expected endpoint, got {}", endpoint));
            agave_votor_to_remote(dst);
        }
        _ => panic!("Unknown arg"),
    }
}
