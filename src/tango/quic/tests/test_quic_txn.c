#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../ballet/base64/fd_base64.h"


FD_IMPORT_BINARY(transaction, "src/tango/quic/tests/quic_txn.bin");

int g_handshake_complete = 0;
int g_conn_final = 0;
int g_stream_notify = 0;

void
cb_conn_new( fd_quic_conn_t  * conn,
             void *            quic_ctx ) {
  (void)quic_ctx;
  FD_LOG_NOTICE(( "cb_conn_new %lu", conn->tx_max_data ));
}

void
cb_conn_handshake_complete( fd_quic_conn_t * conn,
                            void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;
  FD_LOG_NOTICE(( "cb_conn_handshake_complete %lu", conn->tx_max_data ));
  g_handshake_complete = 1;
}

void
cb_conn_final( fd_quic_conn_t * conn,
               void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;
  FD_LOG_NOTICE(( "cb_conn_final" ));
  g_conn_final = 1;
}

void
cb_stream_new( fd_quic_stream_t * stream,
               void *             quic_ctx,
               int stream_type ) {
  (void)stream;
  (void)quic_ctx;
  (void)stream_type;
  FD_LOG_NOTICE(( "cb_stream_new" ));
}

void
cb_stream_notify( fd_quic_stream_t * stream,
                  void *             stream_ctx,
                  int                notify_type ) {
  (void)stream;
  (void)stream_ctx;
  g_stream_notify = 1;
  FD_LOG_NOTICE(( "cb_stream_notify %d", notify_type ));
}

void
cb_stream_receive( fd_quic_stream_t * stream,
                   void *             stream_ctx,
                   uchar const *      data,
                   ulong              data_sz,
                   ulong              offset,
                   int                fin ) {
  (void)stream;
  (void)stream_ctx;
  (void)data;
  (void)data_sz;
  (void)offset;
  (void)fin;
}

ulong
cb_now( void * context ) {
  (void)context;
  return (ulong)fd_log_wallclock();
}

int
run_quic_client( fd_quic_t *         quic,
                 fd_quic_udpsock_t * udpsock,
                 fd_aio_pkt_info_t * pkt,
                 uint                dst_ip,
                 ushort              dst_port ) {

  #define MSG_SZ_MIN (1UL)
  #define MSG_SZ_MAX (1232UL-64UL-32UL)
  #define MSG_SIZE_RANGE (MSG_SZ_MAX - MSG_SZ_MIN + 1UL)

  quic->cb.conn_new = cb_conn_new;
  quic->cb.conn_hs_complete = cb_conn_handshake_complete;
  quic->cb.conn_final = cb_conn_final;
  quic->cb.stream_new = cb_stream_new;
  quic->cb.stream_notify = cb_stream_notify;
  quic->cb.stream_receive = cb_stream_receive;
  quic->cb.now = cb_now;
  quic->cb.now_ctx = NULL;

  fd_quic_set_aio_net_tx( quic, udpsock->aio );
  FD_TEST( fd_quic_init( quic ) );

  fd_quic_conn_t * conn = fd_quic_connect( quic, dst_ip, dst_port, NULL );
  while ( FD_UNLIKELY( !( g_handshake_complete || g_conn_final ) ) ) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );
  }
  FD_TEST( conn );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );
  FD_TEST( stream );
  int rc = 0;
  if( stream ) {
    #define CHUNK_SIZE 500
    #define MAX_CHUNKS 5
    fd_aio_pkt_info_t chunks[MAX_CHUNKS] = { 0};
    ulong num_chunks = 0;
    for( ulong i=0; i<5; i++ ) {
        ulong offset = ( ushort ) ( i * CHUNK_SIZE );
        chunks[i].buf = (uchar *)pkt->buf + offset;
        if( (i+1)*CHUNK_SIZE <= pkt->buf_sz ) {
          chunks[i].buf_sz = CHUNK_SIZE;
        } else {
          chunks[i].buf_sz = ( ushort ) ( pkt->buf_sz - (i*CHUNK_SIZE) );
          num_chunks = i+1;
          break;
        }
    }
    for( ulong j=0; j < MAX_CHUNKS; j++ ) {
      FD_LOG_NOTICE(( "chunk %lu %d", j, chunks[j].buf_sz));
    }

    rc = fd_quic_stream_send( stream, chunks, num_chunks, 1 );
    FD_LOG_NOTICE(( "rc %d", rc ));
  }
  while ( FD_UNLIKELY( !( g_stream_notify || g_conn_final ) ) ) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );
  }

  if( conn ) {
    fd_quic_conn_close( conn, 0 );
  }
  fd_quic_fini( quic );

  return rc;
}

int
main( int argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  const char * payload_b64 = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--payload-base64-encoded", NULL, NULL );
  const char * dst_ip_cstr = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dst-ip",   NULL, NULL );
  ushort       dst_port    = fd_env_strip_cmdline_ushort( &argc, &argv, "--dst-port", NULL, 0U );

  if( FD_UNLIKELY( !dst_ip_cstr ) ) FD_LOG_ERR(( "missing --dst-ip" ));
  if( FD_UNLIKELY( !dst_port    ) ) FD_LOG_ERR(( "missing --dst-port" ));

  uint dst_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( dst_ip_cstr, &dst_ip ) ) ) FD_LOG_ERR(( "invalid --dst-ip" ));

  FD_LOG_NOTICE(( "Connecting to " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( dst_ip ), dst_port ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_aio_pkt_info_t pkt;
  if( !payload_b64 ) {
    FD_LOG_NOTICE(( "Payload not specified, using hardcoded txn payload" ));
    pkt.buf =    ( void * )transaction;
    pkt.buf_sz = ( ushort )transaction_sz;
  } else {
    ulong payload_b64_sz = strlen( payload_b64 );

    static uchar buf[ 1UL << 15UL ];
    if( FD_UNLIKELY( FD_BASE64_DEC_SZ( payload_b64_sz ) > sizeof(buf) ) )
      FD_LOG_ERR(( "Input payload is too large (max %lu bytes)", sizeof(buf) ));

    long res = fd_base64_decode( buf, payload_b64, payload_b64_sz );
    if( FD_UNLIKELY( res<0 ) )
      FD_LOG_ERR(( "Bad input payload" ));

    FD_LOG_NOTICE(( "transaction size %ld!", res ));
    pkt.buf    = (void *)buf;
    pkt.buf_sz = (ushort)res;
  }

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ,
                                            1UL << 15,
                                            fd_shmem_cpu_idx( 0 ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  fd_quic_limits_t quic_limits = {
     .conn_cnt         = 1024UL,
     .handshake_cnt    = 256UL,
     .conn_id_cnt      = 16UL,
     .conn_id_sparsity = 4.0,
     .stream_cnt = { 0UL,   // FD_QUIC_STREAM_TYPE_BIDI_CLIENT
                     0UL,   // FD_QUIC_STREAM_TYPE_BIDI_SERVER
                     2UL,   // FD_QUIC_STREAM_TYPE_UNI_CLIENT
                     0UL }, // FD_QUIC_STREAM_TYPE_UNI_SERVER
     .stream_sparsity  = 4.0,
     .inflight_pkt_cnt = 64UL,
     .tx_buf_sz        = 1UL<<15UL
  };
  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_quic_align(), quic_footprint, 1UL );
  fd_ip_t * ip = fd_ip_join( fd_ip_new( fd_wksp_alloc_laddr( wksp, fd_ip_align(), fd_ip_footprint( 256UL, 256UL ), 1UL ), 256UL, 256UL ) );
  fd_quic_t * quic = fd_quic_new( mem, &quic_limits, ip );
  FD_TEST( quic );

  fd_quic_udpsock_t _udpsock;
  uint listen_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr("0.0.0.0", &listen_ip ) ) ) {
    FD_LOG_NOTICE(( "invalid listen-ip" ));
    return 1;
  }
  fd_quic_udpsock_t * udpsock = fd_quic_client_create_udpsock( &_udpsock, wksp, fd_quic_get_aio_net_rx( quic ), listen_ip );
  FD_TEST( udpsock == &_udpsock );

  fd_quic_config_t * client_cfg = &quic->config;
  client_cfg->role = FD_QUIC_ROLE_CLIENT;
  FD_TEST( fd_quic_config_from_env( &argc, &argv, client_cfg ) );
  memcpy(client_cfg->link.dst_mac_addr, "\x52\xF1\x7E\xDA\x2C\xE0", 6UL);
  client_cfg->net.ip_addr         = udpsock->listen_ip;
  client_cfg->net.ephem_udp_port.lo = (ushort)udpsock->listen_port;
  client_cfg->net.ephem_udp_port.hi = (ushort)(udpsock->listen_port + 1);
  client_cfg->initial_rx_max_stream_data = 1<<15;
  for( ulong j=0UL; j<16UL; j++ ) client_cfg->identity_key[ j ] = (uchar)fd_rng_uchar( rng );

  int num_sent = run_quic_client( quic, udpsock, &pkt, dst_ip, dst_port );

  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( quic ) ) );
  fd_quic_udpsock_destroy( udpsock );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();

  switch( num_sent ) {
    case 1: return 0; /* If no packets were successfully transmitted return one. */
    case 2: return 0; /* If no packets were successfully transmitted return one. */
    case 3: return 0; /* If no packets were successfully transmitted return one. */
    case 0: return 1; /* If the single packet was transmitted successfully return zero. */
    default: return -num_sent;
  }
}
