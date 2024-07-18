#![allow(non_camel_case_types)]

use libc::{in_addr, sockaddr_in, socket, AF_INET, IPPROTO_UDP, SOCK_DGRAM};
use solana_client::connection_cache::ConnectionCache;
use solana_client::tpu_connection::TpuConnection;
use std::ffi::{c_char, c_void};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};

type fd_aio_t = c_void;
type fd_quic_t = c_void;
type fd_udpsock_t = c_void;
type fd_wksp_t = c_void;

#[repr(C, align(16))]
struct fd_rng_t {
    seq: u64,
    idx: u64,
}

const FD_QUIC_ROLE_SERVER: i32 = 2;

#[link(name = "fd_quic", kind = "static")]
#[link(name = "fd_waltz", kind = "static")] // net
#[link(name = "fd_tls", kind = "static")]
#[link(name = "fd_ballet", kind = "static")] // crypto
#[link(name = "fd_util", kind = "static")]
#[link(name = "stdc++", kind = "static")]
extern "C" {
    fn fd_boot(pargc: *mut i32, pargv: *mut *mut *mut c_char);
    fn fd_halt();

    fn fd_wksp_new_anon(
        name: *const c_char,
        page_sz: u64,
        sub_cnt: u64,
        sub_page_cnt: *const u64,
        sub_cpu_idx: *const u64,
        seed: u32,
        opt_part_max: u64,
    ) -> *mut fd_wksp_t;

    fn fd_udpsock_align() -> u64;
    fn fd_udpsock_footprint(mtu: u64, rx_pkt_cnt: u64, tx_pkt_cnt: u64) -> u64;

    fn fd_udpsock_new(
        shmem: *mut c_void,
        mtu: u64,
        rx_pkt_cnt: u64,
        tx_pkt_cnt: u64,
    ) -> *mut c_void;
    fn fd_udpsock_join(shsock: *mut c_void, fd: i32) -> *mut fd_udpsock_t;
    fn fd_udpsock_set_rx(sock: *mut fd_udpsock_t, aio: *const fd_aio_t);
    fn fd_udpsock_get_tx(sock: *mut fd_udpsock_t) -> *const fd_aio_t;
    fn fd_udpsock_service(sock: *mut fd_udpsock_t);

    fn fd_quic_new_anonymous_small(
        wksp: *mut fd_wksp_t,
        role: i32,
        rng: *mut fd_rng_t,
    ) -> *mut fd_quic_t;
    fn fd_quic_get_aio_net_rx(quic: *mut fd_quic_t) -> *const fd_aio_t;
    fn fd_quic_set_aio_net_tx(quic: *mut fd_quic_t, aio_tx: *const fd_aio_t);
    fn fd_quic_init(quic: *mut fd_quic_t) -> *mut fd_quic_t;
    fn fd_quic_service(quic: *mut fd_quic_t);
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

unsafe fn _main() {
    // Set up Firedancer components

    std::env::set_var("FD_LOG_PATH", "");
    std::env::set_var("FD_LOG_LEVEL_LOGFILE", "0");
    std::env::set_var("FD_LOG_LEVEL_STDERR", "0");
    let mut argc = 1;
    let argv = &mut [b"test\0".as_ptr() as *mut c_char].as_mut_ptr();
    fd_boot(&mut argc, argv);

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

    let quic = fd_quic_new_anonymous_small(wksp, FD_QUIC_ROLE_SERVER, &mut rng);
    assert!(!quic.is_null(), "Failed to create fd_quic_t");

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

fn main() {
    env_logger::init();
    unsafe {
        _main();
    }
}
