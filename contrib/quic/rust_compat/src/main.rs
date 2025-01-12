use libc::{in_addr, sockaddr_in, socket, AF_INET, IPPROTO_UDP, SOCK_DGRAM};
use std::ffi::c_char;
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::Mutex;

mod quiche;
mod quinn;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(unused)]
#[allow(clippy::all)]
pub(crate) mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use crate::bindings::{fd_boot, fd_wksp_new_anon, fd_wksp_t};

pub(crate) unsafe fn fd_wksp_new_anonymous(
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

pub(crate) unsafe fn new_udp_socket() -> (i32, u16) {
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

struct StdoutWriter {
    lock: Mutex<()>,
}

impl StdoutWriter {
    fn new() -> Self {
        Self {
            lock: Mutex::new(()),
        }
    }
}

impl Write for StdoutWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let guard = self.lock.lock().unwrap();
        print!("{}", unsafe { std::str::from_utf8_unchecked(buf) });
        drop(guard);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

static USAGE: &str = r"Usage: ./firedancer-quiche-quic-test <command>

Available commands are:

  quiche-fd:       Ping quiche client (BoringSSL) to fd_quic server
  quinn-awslc-fd:  Ping quinn client (rustls aws-ls-rc) to fd_quic server
  quinn-pq-fd:     Ping quinn client (rustls aws-ls-rc post quantum) to fd_quic server
  quinn-ring-fd:   Ping quinn client (rustls ring) to fd_quic server";

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
        "quiche-fd" => unsafe { crate::quiche::quiche_to_fdquic() },
        "quinn-awslc-fd" => unsafe {
            crate::quinn::quinn_to_fdquic(rustls::crypto::aws_lc_rs::default_provider())
        },
        "quinn-pq-fd" => unsafe { crate::quinn::quinn_to_fdquic(rustls_post_quantum::provider()) },
        "quinn-ring-fd" => unsafe {
            crate::quinn::quinn_to_fdquic(rustls::crypto::ring::default_provider())
        },
        _ => panic!("Unknown arg"),
    }
}
