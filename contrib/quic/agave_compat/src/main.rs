#![allow(non_camel_case_types)]

use libc::{in_addr, sockaddr_in, socket, AF_INET, IPPROTO_UDP, SOCK_DGRAM};
use solana_client::connection_cache::ConnectionCache;
use solana_client::tpu_connection::TpuConnection;
use solana_sdk::signer::keypair::Keypair;
use solana_streamer::streamer::StakedNodes;
use std::ffi::{c_char, c_void};
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
    fd_boot, fd_halt, fd_quic_connect, fd_quic_get_aio_net_rx, fd_quic_init,
    fd_quic_new_anonymous_small, fd_quic_service, fd_quic_set_aio_net_tx, fd_quic_t, fd_rng_t,
    fd_udpsock_align, fd_udpsock_footprint, fd_udpsock_get_tx, fd_udpsock_join, fd_udpsock_new,
    fd_udpsock_service, fd_udpsock_set_rx, fd_udpsock_t, fd_wksp_new_anon, fd_wksp_t,
    FD_QUIC_ROLE_CLIENT, FD_QUIC_ROLE_SERVER, FD_QUIC_CONN_STATE_ACTIVE, FD_QUIC_CONN_STATE_DEAD
};

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

    let wksp = fd_wksp_new_anonymous(4096, 1024, 0, b"test\0".as_ptr() as *const c_char, 0);
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

unsafe fn fdquic_to_agave() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let listen_port = udp_socket.local_addr().unwrap().port();
    let keypair = Keypair::new();
    let (agave_tx, agave_rx) = crossbeam_channel::bounded(16);
    let exit = Arc::new(AtomicBool::new(false));
    let agave_server_handle = solana_streamer::quic::spawn_server(
        "agave_server",
        udp_socket,
        &keypair,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        agave_tx,
        exit,
        1,
        Arc::new(RwLock::new(StakedNodes::default())),
        1,
        1,
        10,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(500));

    let (udp_sock_fd, client_port) = new_udp_socket();

    let wksp = fd_wksp_new_anonymous(4096, 1024, 0, b"test\0".as_ptr() as *const c_char, 0);
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

    eprintln!("Connecting from 127.0.0.1:{} to 127.0.0.1:{}", client_port, listen_port);
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

    agave_server_handle.thread.join().unwrap();
}

fn main() {
    env_logger::init();
    let arg = std::env::args()
        .nth(1)
        .expect("Usage: ./firedancer-agave-quic-test <server|client>");

    std::env::set_var("FD_LOG_PATH", "");
    std::env::set_var("FD_LOG_LEVEL_LOGFILE", "0");
    std::env::set_var("FD_LOG_LEVEL_STDERR", "0");
    let mut argc = 1;
    let argv = &mut [b"test\0".as_ptr() as *mut c_char].as_mut_ptr();
    unsafe {
        fd_boot(&mut argc, argv);
    }

    match arg.as_str() {
        "server" => unsafe { agave_to_fdquic() },
        "client" => unsafe { fdquic_to_agave() },
        _ => panic!("Unknown arg"),
    }
}
