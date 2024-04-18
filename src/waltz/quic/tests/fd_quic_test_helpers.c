#include "fd_quic_test_helpers.h"
#include "../../../util/net/fd_pcapng.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

static FILE * test_pcap;

/* Mac address counter, incremented for each new QUIC */
static ulong test_mac_addr_seq = 0x0A0000000000;
/* IP address counter, incremented for each new QUIC */
static uint  test_ip_addr_seq  = FD_IP4_ADDR( 127, 10, 0, 0 );

/* Default implementations of callbacks */

static void
fd_quic_test_cb_conn_new( fd_quic_conn_t * conn,
                          void *           quic_ctx ) {
  FD_LOG_DEBUG(( "cb_conn_new(conn=%p, quic_ctx=%p)",
                 (void *)conn, (void *)quic_ctx ));
}

static void
fd_quic_test_cb_conn_handshake_complete( fd_quic_conn_t * conn,
                                         void *           quic_ctx ) {
  FD_LOG_DEBUG(( "cb_conn_handshake_complete(conn=%p, quic_ctx=%p)",
                 (void *)conn, (void *)quic_ctx ));
}

static void
fd_quic_test_cb_conn_final( fd_quic_conn_t * conn,
                            void *           quic_ctx ) {
  FD_LOG_DEBUG(( "cb_conn_final(conn=%p, quic_ctx=%p)",
                 (void *)conn, (void *)quic_ctx ));
}

static void
fd_quic_test_cb_stream_new( fd_quic_stream_t * stream,
                            void *             quic_ctx,
                            int                stream_type ) {
  FD_LOG_DEBUG(( "cb_stream_new(stream=%lu, quic_ctx=%p, stream_type=%#x)",
                 stream->stream_id, (void *)quic_ctx, stream_type ));
}

static void
fd_quic_test_cb_stream_notify( fd_quic_stream_t * stream,
                               void *             quic_ctx,
                               int                notify_type ) {
  FD_LOG_DEBUG(( "cb_stream_notify(stream=%lu, quic_ctx=%p, notify_type=%d)",
                 stream->stream_id, quic_ctx, notify_type ));
}

static void
fd_quic_test_cb_stream_receive( fd_quic_stream_t * stream,
                                void *             quic_ctx,
                                uchar const *      data,
                                ulong              data_sz,
                                ulong              offset,
                                int                fin ) {
  FD_LOG_DEBUG(( "cb_stream_receive(stream=%lu, quic_ctx=%p, data=%p, data_sz=%lu, offset=%lu, fin=%d)",
                 stream->stream_id, quic_ctx, (void const *)data, data_sz, offset, fin ));
}

static void
fd_quic_test_cb_tls_keylog( void *       quic_ctx,
                            char const * line ) {
  (void)quic_ctx;
  if( test_pcap )
    fd_pcapng_fwrite_tls_key_log( (uchar const *)line, (uint)strlen( line ), test_pcap );
}

static ulong
fd_quic_test_now( void * context ) {
  (void)context;
  return (ulong)fd_log_wallclock();
}

/* Test runtime */

void
fd_quic_test_boot( int *    pargc,
                   char *** pargv ) {
  char const * _pcap = fd_env_strip_cmdline_cstr( pargc, pargv, "--pcap", NULL, NULL );

  if( _pcap ) {
    FD_LOG_NOTICE(( "Logging to --pcap %s", _pcap ));
    test_pcap = fopen( _pcap, "ab" );
    FD_TEST( test_pcap );
  }
}

void
fd_quic_test_halt( void ) {
  if( test_pcap ) {
    FD_TEST( 0==fclose( test_pcap ) );
    test_pcap = NULL;
  }
}

/* QUIC creation helper */

void
fd_quic_config_anonymous( fd_quic_t * quic,
                          int         role ) {

  fd_quic_config_t * config = &quic->config;
  config->role = role;

  /* Generate MAC address */
  test_mac_addr_seq++;
  ulong mac_addr_be = fd_ulong_bswap( test_mac_addr_seq )>>16UL;
  memcpy( config->link.src_mac_addr, &mac_addr_be, 6 );

  /* Set destination MAC to dummy */
  static uchar const dst_mac_addr[6] = "\x06\x00\xde\xad\xbe\xef";
  memcpy( config->link.dst_mac_addr, dst_mac_addr, 6 );

  /* Generate IP address */
  test_ip_addr_seq = fd_uint_bswap( fd_uint_bswap( test_ip_addr_seq ) + 1 );
  config->net.ip_addr = test_ip_addr_seq;

  config->net.listen_udp_port   =  9000;
  config->net.ephem_udp_port.lo = 10000;
  config->net.ephem_udp_port.hi = 10100;

  /* Default settings */
  config->idle_timeout     = (ulong)200e6; /* 200ms */
  config->service_interval = (ulong) 10e6; /*  10ms */
  strcpy( config->sni, "local" );

  /* Default callbacks */
  quic->cb.conn_new         = fd_quic_test_cb_conn_new;
  quic->cb.conn_hs_complete = fd_quic_test_cb_conn_handshake_complete;
  quic->cb.conn_final       = fd_quic_test_cb_conn_final;
  quic->cb.stream_new       = fd_quic_test_cb_stream_new;
  quic->cb.stream_notify    = fd_quic_test_cb_stream_notify;
  quic->cb.stream_receive   = fd_quic_test_cb_stream_receive;
  quic->cb.tls_keylog       = fd_quic_test_cb_tls_keylog;
  quic->cb.now              = fd_quic_test_now;
  quic->cb.now_ctx          = NULL;
}

void
fd_quic_config_test_signer( fd_quic_t *              quic,
                            fd_tls_test_sign_ctx_t * sign_ctx ) {
  fd_quic_config_t * config = &quic->config;
  fd_memcpy( config->identity_public_key, sign_ctx->public_key, 32UL );
  config->sign_ctx = sign_ctx;
  config->sign     = fd_tls_test_sign_sign;
}

fd_quic_t *
fd_quic_new_anonymous( fd_wksp_t *              wksp,
                       fd_quic_limits_t const * limits,
                       int                      role,
                       fd_rng_t *               rng ) {
  void * shquic = fd_quic_new( fd_wksp_alloc_laddr( wksp, fd_quic_align(), fd_quic_footprint( limits ), 1UL ), limits );
  FD_TEST( shquic );

  fd_quic_t * quic = fd_quic_join( shquic );
  FD_TEST( quic );

  fd_quic_config_anonymous( quic, role );

  fd_tls_test_sign_ctx_t * sign_ctx = fd_wksp_alloc_laddr( wksp, alignof(fd_tls_test_sign_ctx_t), sizeof(fd_tls_test_sign_ctx_t), 1UL );
  *sign_ctx = fd_tls_test_sign_ctx( rng );
  fd_quic_config_test_signer( quic, sign_ctx );

  return quic;
}

static void
fd_quic_virtual_pair_direct( fd_quic_virtual_pair_t * pair,
                             fd_quic_t *              quic_a,
                             fd_quic_t *              quic_b ) {

  pair->quic_a = quic_a;
  pair->quic_b = quic_b;

  fd_aio_t const * rx_a = fd_quic_get_aio_net_rx( quic_a );
  fd_aio_t const * rx_b = fd_quic_get_aio_net_rx( quic_b );

  fd_quic_set_aio_net_tx( quic_a, rx_b );
  fd_quic_set_aio_net_tx( quic_b, rx_a );
}

static void
fd_quic_virtual_pair_pcap( fd_quic_virtual_pair_t * pair,
                           fd_quic_t *              quic_a,
                           fd_quic_t *              quic_b,
                           FILE *                   pcap ) {

  pair->quic_a = quic_a;
  pair->quic_b = quic_b;

  fd_aio_t const * rx_a = fd_quic_get_aio_net_rx( quic_a );
  fd_aio_t const * rx_b = fd_quic_get_aio_net_rx( quic_b );

  /* Write pcapng header */

  FD_TEST( 1UL==fd_aio_pcapng_start( pcap ) );

  /* Install captures */

  FD_TEST( fd_aio_pcapng_join( &pair->quic_b2a, rx_a, pcap ) );
  FD_TEST( fd_aio_pcapng_join( &pair->quic_a2b, rx_b, pcap ) );

  /* Set send target */

  fd_quic_set_aio_net_tx( quic_a, fd_aio_pcapng_get_aio( &pair->quic_a2b ) );
  fd_quic_set_aio_net_tx( quic_b, fd_aio_pcapng_get_aio( &pair->quic_b2a ) );
}

void
fd_quic_virtual_pair_init( fd_quic_virtual_pair_t * pair,
                           fd_quic_t * quic_a,
                           fd_quic_t * quic_b ) {
  memset( pair, 0, sizeof(fd_quic_virtual_pair_t) );
  if( !test_pcap )
    fd_quic_virtual_pair_direct( pair, quic_a, quic_b );
  else
    fd_quic_virtual_pair_pcap  ( pair, quic_a, quic_b, test_pcap );
}

void
fd_quic_virtual_pair_fini( fd_quic_virtual_pair_t * pair ) {
  if( pair->quic_a2b.pcapng ) {
    FD_TEST( fd_aio_pcapng_leave( &pair->quic_a2b ) );
    FD_TEST( fd_aio_pcapng_leave( &pair->quic_b2a ) );
  }
  fd_quic_set_aio_net_tx( pair->quic_a, NULL );
  fd_quic_set_aio_net_tx( pair->quic_b, NULL );
}

void
fd_quic_test_keylog( fd_quic_virtual_pair_t const * pair,
                     char const *                   line ) {

  /* Skip if not capturing packets */
  if( !pair->quic_a2b.pcapng ) return;

  fd_pcapng_fwrite_tls_key_log( (uchar const *)line, (uint)strlen( line ), pair->quic_a2b.pcapng );
}

fd_quic_udpsock_t *
fd_quic_client_create_udpsock(fd_quic_udpsock_t * udpsock,
                              fd_wksp_t *      wksp,
                              fd_aio_t const * rx_aio,
                              uint listen_ip) {
  ulong        mtu          = 2048UL;
  ulong        rx_depth     = 1024UL;
  ulong        tx_depth     = 1024UL;

  int sock_fd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
  if( FD_UNLIKELY( sock_fd<0 ) ) {
    FD_LOG_WARNING(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  struct sockaddr_in listen_addr = {
      .sin_family = AF_INET,
      .sin_addr   = { .s_addr = listen_ip },
      .sin_port   = 0,
  };
  if( FD_UNLIKELY( 0!=bind( sock_fd, (struct sockaddr const *)fd_type_pun_const( &listen_addr ), sizeof(struct sockaddr_in) ) ) ) {
    FD_LOG_WARNING(( "bind(sock_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( sock_fd );
    return NULL;
  }

  void * sock_mem = fd_wksp_alloc_laddr( wksp, fd_udpsock_align(),
                                         fd_udpsock_footprint( mtu, rx_depth, tx_depth ),
                                         1UL );
  if( FD_UNLIKELY( !sock_mem ) ) {
    FD_LOG_WARNING(( "fd_wksp_alloc_laddr() failed" ));
    close( sock_fd );
    return NULL;
  }

  fd_udpsock_t * sock = fd_udpsock_join( fd_udpsock_new( sock_mem, mtu, rx_depth, tx_depth ), sock_fd );
  if( FD_UNLIKELY( !sock ) ) {
    FD_LOG_WARNING(( "fd_udpsock_join() failed" ));
    close( sock_fd );
    fd_wksp_free_laddr( sock_mem );
    return NULL;
  }

  udpsock->type            = FD_QUIC_UDPSOCK_TYPE_UDPSOCK;
  udpsock->wksp            = wksp;
  udpsock->udpsock.sock    = sock;
  udpsock->udpsock.sock_fd = sock_fd;
  udpsock->aio             = fd_udpsock_get_tx( sock );
  udpsock->listen_ip       = fd_udpsock_get_ip4_address( sock );
  udpsock->listen_port     = (ushort)fd_udpsock_get_listen_port( sock );
  fd_udpsock_set_rx( sock, rx_aio );

  FD_LOG_NOTICE(( "UDP socket listening on " FD_IP4_ADDR_FMT ":%u",
      FD_IP4_ADDR_FMT_ARGS( udpsock->listen_ip ), udpsock->listen_port ));
  return udpsock;
}

// TODO: LML complete this thought?
fd_quic_udpsock_t *
create_udp_socket(fd_quic_udpsock_t * udpsock) {
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr("0.0.0.0", &udpsock->listen_ip ) ) ) {
    goto error_1;
  }
  udpsock->listen_port = 0; // TODO: check this where is it set in flood?
  error_1:
  FD_LOG_NOTICE(( "invalid --listen-ip" ));
  return NULL;
}

fd_quic_udpsock_t *
fd_quic_udpsock_create( void *           _sock,
                        int *            pargc,
                        char ***         pargv,
                        fd_wksp_t *      wksp,
                        fd_aio_t const * rx_aio ) {

  /* This kinda sucks, should be cleaned up */

  fd_quic_udpsock_t * quic_sock = (fd_quic_udpsock_t *)_sock;

  char const * iface        = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--iface",        NULL,      NULL );
  uint         ifqueue      = fd_env_strip_cmdline_uint  ( pargc, pargv, "--ifqueue",      NULL,       0U  );
  char const * _src_mac     = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--src-mac",      NULL,      NULL );
  char const * xdp_app_name = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--bpf-dir",      NULL,      NULL );
  ulong        mtu          = fd_env_strip_cmdline_ulong ( pargc, pargv, "--mtu",          NULL,    2048UL );
  ulong        rx_depth     = fd_env_strip_cmdline_ulong ( pargc, pargv, "--rx-depth",     NULL,    1024UL );
  ulong        tx_depth     = fd_env_strip_cmdline_ulong ( pargc, pargv, "--tx-depth",     NULL,    1024UL );
  ulong        xsk_pkt_cnt  = fd_env_strip_cmdline_ulong ( pargc, pargv, "--xsk-pkt-cnt",  NULL,      32UL );
  char const * _listen_ip   = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--listen-ip",    NULL, "0.0.0.0" );
  ushort       listen_port  = fd_env_strip_cmdline_ushort( pargc, pargv, "--listen-port",  NULL,       0U  );

  uint listen_ip = 0;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _listen_ip, &listen_ip ) ) ) FD_LOG_ERR(( "invalid --listen-ip" ));

  quic_sock->listen_ip   = listen_ip;
  quic_sock->listen_port = listen_port;

  int is_xsk = (!!xdp_app_name);
  FD_LOG_NOTICE(( "is_xsk %d", is_xsk ));
  if( is_xsk ) {
    FD_TEST( _src_mac );
    if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _src_mac, quic_sock->self_mac ) ) ) FD_LOG_ERR(( "invalid --src-mac" ));

    ulong xsk_sz = fd_xsk_footprint( mtu, rx_depth, rx_depth, tx_depth, tx_depth );
    if( FD_UNLIKELY( !xsk_sz ) ) {
      FD_LOG_WARNING(( "invalid XSK command-line params" ));
      return NULL;
    }

    FD_LOG_NOTICE(( "Creating XSK" ));
    void * xsk_mem = fd_wksp_alloc_laddr( wksp, fd_xsk_align(), xsk_sz, 1UL );
    if( FD_UNLIKELY( !fd_xsk_new( xsk_mem, mtu, rx_depth, rx_depth, tx_depth, tx_depth ) ) ) {
      FD_LOG_WARNING(( "failed to create XSK" ));
      return NULL;
    }

    FD_LOG_NOTICE(( "Binding XSK (--iface %s, --ifqueue %u)", iface, ifqueue ));
    if( FD_UNLIKELY( !fd_xsk_bind( xsk_mem, xdp_app_name, iface, ifqueue ) ) ) {
      FD_LOG_WARNING(( "failed to bind XSK" ));
      fd_wksp_free_laddr( xsk_mem );
      return NULL;
    }

    FD_LOG_NOTICE(( "Joining XSK" ));
    fd_xsk_t * xsk = fd_xsk_join( xsk_mem );
    if( FD_UNLIKELY( !xsk ) ) {
      FD_LOG_WARNING(( "failed to join XSK" ));
      fd_wksp_free_laddr( xsk_mem );
      return NULL;
    }

    FD_LOG_NOTICE(( "Creating fd_xsk_aio" ));
    void * xsk_aio_mem =
      fd_wksp_alloc_laddr( wksp, fd_xsk_aio_align(), fd_xsk_aio_footprint( tx_depth, xsk_pkt_cnt ), 1UL );
    if( FD_UNLIKELY( !fd_xsk_aio_new( xsk_aio_mem, tx_depth, xsk_pkt_cnt ) ) ) {
      FD_LOG_WARNING(( "failed to create fd_xsk_aio" ));
      fd_xsk_leave( xsk );
      fd_wksp_free_laddr( xsk_mem     );
      fd_wksp_free_laddr( xsk_aio_mem );
      return NULL;
    }

    FD_LOG_NOTICE(( "Joining fd_xsk_aio" ));
    fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( xsk_aio_mem, xsk );
    if( FD_UNLIKELY( !xsk_aio ) ) {
      FD_LOG_WARNING(( "failed to join fd_xsk_aio" ));
      fd_xsk_leave( xsk );
      fd_wksp_free_laddr( xsk_mem     );
      fd_wksp_free_laddr( xsk_aio_mem );
      return NULL;
    }

    FD_LOG_NOTICE(( "Adding UDP listener (" FD_IP4_ADDR_FMT ":%u)",
                    FD_IP4_ADDR_FMT_ARGS( quic_sock->listen_ip ), quic_sock->listen_port ));
    if( FD_UNLIKELY( 0!=fd_xdp_listen_udp_ports( xdp_app_name, quic_sock->listen_ip, 1, &quic_sock->listen_port, 0 ) ) ) {
      FD_LOG_WARNING(( "failed to add UDP listener" ));
      fd_xsk_aio_leave( xsk_aio );
      fd_xsk_leave( xsk );
      fd_wksp_free_laddr( xsk_mem     );
      fd_wksp_free_laddr( xsk_aio_mem );
      return NULL;
    }

    quic_sock->type        = FD_QUIC_UDPSOCK_TYPE_XSK;
    quic_sock->wksp        = wksp;
    quic_sock->xsk.xsk     = xsk;
    quic_sock->xsk.xsk_aio = xsk_aio;
    quic_sock->aio         = fd_xsk_aio_get_tx( quic_sock->xsk.xsk_aio );
    fd_xsk_aio_set_rx( xsk_aio, rx_aio );

    FD_LOG_NOTICE(( "AF_XDP listening on " FD_IP4_ADDR_FMT ":%u",
                    FD_IP4_ADDR_FMT_ARGS( quic_sock->listen_ip ), quic_sock->listen_port ));
  } else {
    int sock_fd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
    if( FD_UNLIKELY( sock_fd<0 ) ) {
      FD_LOG_WARNING(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return NULL;
    }

    struct sockaddr_in listen_addr = {
      .sin_family = AF_INET,
      .sin_addr   = { .s_addr = listen_ip },
      .sin_port   = (ushort)fd_ushort_bswap( (ushort)listen_port ),
    };
    if( FD_UNLIKELY( 0!=bind( sock_fd, (struct sockaddr const *)fd_type_pun_const( &listen_addr ), sizeof(struct sockaddr_in) ) ) ) {
      FD_LOG_WARNING(( "bind(sock_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      close( sock_fd );
      return NULL;
    }

    void * sock_mem = fd_wksp_alloc_laddr( wksp, fd_udpsock_align(),
                        fd_udpsock_footprint( mtu, rx_depth, tx_depth ),
                        1UL );
    if( FD_UNLIKELY( !sock_mem ) ) {
      FD_LOG_WARNING(( "fd_wksp_alloc_laddr() failed" ));
      close( sock_fd );
      return NULL;
    }

    fd_udpsock_t * sock = fd_udpsock_join( fd_udpsock_new( sock_mem, mtu, rx_depth, tx_depth ), sock_fd );
    if( FD_UNLIKELY( !sock ) ) {
      FD_LOG_WARNING(( "fd_udpsock_join() failed" ));
      close( sock_fd );
      fd_wksp_free_laddr( sock_mem );
      return NULL;
    }

    quic_sock->type            = FD_QUIC_UDPSOCK_TYPE_UDPSOCK;
    quic_sock->wksp            = wksp;
    quic_sock->udpsock.sock    = sock;
    quic_sock->udpsock.sock_fd = sock_fd;
    quic_sock->aio             = fd_udpsock_get_tx( sock );
    quic_sock->listen_ip       = fd_udpsock_get_ip4_address( sock );
    quic_sock->listen_port     = (ushort)fd_udpsock_get_listen_port( sock );
    fd_udpsock_set_rx( sock, rx_aio );

    FD_LOG_NOTICE(( "UDP socket listening on " FD_IP4_ADDR_FMT ":%u",
                    FD_IP4_ADDR_FMT_ARGS( quic_sock->listen_ip ), quic_sock->listen_port ));
  }

  return quic_sock;
}

void *
fd_quic_udpsock_destroy( fd_quic_udpsock_t * udpsock ) {
  if( FD_UNLIKELY( !udpsock ) )
    return NULL;

  switch( udpsock->type ) {
  case FD_QUIC_UDPSOCK_TYPE_XSK:
    fd_wksp_free_laddr( fd_xsk_aio_delete( fd_xsk_aio_leave( udpsock->xsk.xsk_aio ) ) );
    fd_wksp_free_laddr( fd_xsk_delete    ( fd_xsk_leave    ( udpsock->xsk.xsk     ) ) );
    break;
  case FD_QUIC_UDPSOCK_TYPE_UDPSOCK:
    fd_wksp_free_laddr( fd_udpsock_delete( fd_udpsock_leave( udpsock->udpsock.sock ) ) );
    close( udpsock->udpsock.sock_fd );
    break;
  }

  return udpsock;
}

void
fd_quic_udpsock_service( fd_quic_udpsock_t const * udpsock ) {
  switch( udpsock->type ) {
  case FD_QUIC_UDPSOCK_TYPE_XSK:
    fd_xsk_aio_service( udpsock->xsk.xsk_aio );
    break;
  case FD_QUIC_UDPSOCK_TYPE_UDPSOCK:
    fd_udpsock_service( udpsock->udpsock.sock );
    break;
  }
}
