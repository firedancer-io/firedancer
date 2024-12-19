use crate::bindings::{
    fd_aio_pcapng_get_aio, fd_aio_pcapng_join, fd_aio_pcapng_start, fd_aio_pcapng_t, fd_halt,
    fd_pcapng_fwrite_tls_key_log, fd_quic_get_aio_net_rx, fd_quic_init,
    fd_quic_new_anonymous_small, fd_quic_service, fd_quic_set_aio_net_tx, fd_quic_t, fd_rng_t,
    fd_udpsock_align, fd_udpsock_footprint, fd_udpsock_get_tx, fd_udpsock_join, fd_udpsock_new,
    fd_udpsock_service, fd_udpsock_set_rx, fd_udpsock_t, FD_QUIC_ROLE_SERVER,
};
use libc::{fflush, fopen, strlen, FILE};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::UnixTime;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use std::ffi::{c_char, c_void, CString};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[derive(Debug)]
struct IgnoreServerCert;

impl ServerCertVerifier for IgnoreServerCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

pub(crate) unsafe fn quinn_to_fdquic(crypto_provider: CryptoProvider) {
    // Set up Firedancer components

    let (udp_sock_fd, listen_port) = crate::new_udp_socket();

    let wksp = crate::fd_wksp_new_anonymous(4096, 16384, 0, b"test\0".as_ptr() as *const c_char, 0);
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
            fd_quic_get_aio_net_rx(quic),
            pcap_file as *mut c_void,
        );
        assert!(!aio_pcapng1.is_null());
        assert!(!aio_pcapng2.is_null());

        fd_quic_set_aio_net_tx(quic, fd_aio_pcapng_get_aio(aio_pcapng1));
        fd_udpsock_set_rx(udpsock, fd_aio_pcapng_get_aio(aio_pcapng2));

        unsafe extern "C" fn tls_keylog_cb(_ctx: *mut c_void, line: *const c_char) {
            fd_pcapng_fwrite_tls_key_log(
                line as *const u8,
                strlen(line) as u32,
                PCAP_FILE_GLOB as *mut c_void,
            );
        }
        (*quic).cb.tls_keylog = Some(tls_keylog_cb);
    } else {
        fd_quic_set_aio_net_tx(quic, fd_udpsock_get_tx(udpsock));
        fd_udpsock_set_rx(udpsock, fd_quic_get_aio_net_rx(quic));
    }

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
            fd_quic_service(quic3);
        }
        let metrics = &(*quic3).metrics.__bindgen_anon_1;
        // Limit packet counts to reasonable numbers
        eprintln!("Received {} packets", metrics.net_rx_pkt_cnt);
        assert!(metrics.net_rx_pkt_cnt < 64);
        assert!(metrics.net_tx_pkt_cnt < metrics.net_rx_pkt_cnt);
        assert!(metrics.net_tx_byte_cnt < metrics.net_rx_byte_cnt);
        assert!(metrics.conn_active_cnt <= 1);
        assert!(metrics.conn_created_cnt == 1);
        assert!(metrics.conn_closed_cnt <= 1);
        assert!(metrics.conn_aborted_cnt <= 1);
        assert!(metrics.conn_retry_cnt == 1);
        //assert!(metrics.conn_err_no_slots_cnt == 0);
        assert!(metrics.conn_err_retry_fail_cnt == 0);
        assert!(metrics.hs_created_cnt == 1);
        assert!(metrics.hs_err_alloc_fail_cnt == 0);
        eprintln!("Shutting down fd_quic");
    });

    // Set up quinn components

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut client_crypto =
            rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
                .with_protocol_versions(rustls::ALL_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(IgnoreServerCert))
                .with_no_client_auth();

        client_crypto.alpn_protocols = vec![b"solana-tpu".to_vec()];

        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
        let mut endpoint =
            quinn::Endpoint::client(SocketAddr::from_str("127.0.0.1:0").unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);

        let sa = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), listen_port);
        let conn = endpoint.connect(sa, "node").unwrap().await.unwrap();
        drop(conn);
    });

    let stop = stop_ptr as *mut AtomicU32;
    (*stop).store(1, Ordering::Relaxed);
    fd_quic_thread.join().unwrap();
    fd_halt();
}
