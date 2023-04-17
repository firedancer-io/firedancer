#include "fd_quic_test_helpers.h"
#include "../../../util/net/fd_pcapng.h"

static FILE * test_pcap;

/* Mac address counter, incremented for each new QUIC */
static ulong test_mac_addr_seq = 0x0A0000000000;
/* IP address counter, incremented for each new QUIC */
static uint  test_ip_addr_seq  = 0x7f0a0000;

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
  FD_LOG_DEBUG(( "cb_stream_notify(stream=%lu, quic_ctx=%p, notify_type=%#x)",
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
                 stream->stream_id, quic_ctx, data, data_sz, offset, fin ));
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

fd_quic_t *
fd_quic_new_anonymous( fd_wksp_t *              wksp,
                       fd_quic_limits_t const * limits,
                       int                      role ) {
  void * shquic = fd_quic_new( fd_wksp_alloc_laddr( wksp, fd_quic_align(), fd_quic_footprint( limits ), 1UL ), limits );
  FD_TEST( shquic );

  fd_quic_t * quic = fd_quic_join( shquic );
  FD_TEST( quic );

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
  test_ip_addr_seq++;
  config->net.ip_addr         = test_ip_addr_seq;

  config->net.listen_udp_port   =  9000;
  config->net.ephem_udp_port.lo = 10000;
  config->net.ephem_udp_port.hi = 10100;

  /* Default settings */
  config->idle_timeout     = (ulong)100e6; /* 10ms */
  config->service_interval = (ulong) 10e6; /* 10ms */
  strcpy( config->cert_file, "cert.pem" );
  strcpy( config->key_file,  "key.pem"  );
  strcpy( config->sni,       "local"    );

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

