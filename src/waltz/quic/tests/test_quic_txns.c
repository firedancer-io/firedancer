#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"
#include "../../../ballet/base64/fd_base64.h"
#include "../../../util/net/fd_ip4.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>


FD_IMPORT_BINARY(transaction, "src/waltz/quic/tests/quic_txn.bin");

fd_quic_conn_t *   gbl_conn   = NULL;
fd_quic_stream_t * gbl_stream = NULL;

int g_handshake_complete = 0;
int g_conn_final = 0;
int g_stream_notify = 0;

/* track txns sent */
ulong sent_cnt = 0UL;

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

  gbl_conn = NULL;
  gbl_stream = NULL;
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

  stream = NULL;

  if( notify_type == FD_QUIC_NOTIFY_END ) {
    sent_cnt++;
  } else {
    FD_LOG_WARNING(( "stream ended in failure: %d", (int)notify_type ));
  }
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


ulong
findch( char * buf, ulong buf_sz, char ch ) {
  for( ulong j = 0UL; j < buf_sz; ++j ) {
    char cur = buf[j];

    if( cur == '\0' ) return -1UL;
    if( cur == ch   ) return j;
  }

  return -1UL;
}


int
read_pkt( uchar * out_buf, ulong * out_buf_sz );


void
run_quic_client( fd_quic_t *         quic,
                 fd_quic_udpsock_t * udpsock ) {

  uchar buf[2048];

  fd_aio_pkt_info_t pkt = { .buf = buf, .buf_sz = 0UL };

  uint dst_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( "198.18.0.1", &dst_ip  ) ) ) FD_LOG_ERR(( "invalid --dst-ip" ));
  ushort dst_port = 9001;


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

  /* zero length indicates no input */
  pkt.buf_sz = 0UL;

  while( 1 ) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );

    if( !gbl_conn ) {
      /* if no connection, try making one */
      FD_LOG_NOTICE(( "Creating connection" ));

      gbl_conn = fd_quic_connect( quic, dst_ip, dst_port, NULL );

      continue;
    }

    if( gbl_conn->state != FD_QUIC_CONN_STATE_ACTIVE ) {
      continue;
    }

    if( !gbl_stream ) {
      gbl_stream = fd_quic_conn_new_stream( gbl_conn, FD_QUIC_TYPE_UNIDIR );

      continue;
    }

    if( pkt.buf_sz == 0UL ) {
      ulong out_buf_sz = 0UL;
      if( read_pkt( pkt.buf, &out_buf_sz ) ) {
        /* no input, so done */
        break;
      }

      /* skip empty lines */
      if( out_buf_sz == 0UL ) {
        continue;
      }

      pkt.buf_sz = (ushort)out_buf_sz;
    }

    /* have gbl_conn, gbl_stream and input, so try sending a transaction */
    int rc = fd_quic_stream_send( gbl_stream, &pkt, 1 /* num chunks */, 1 /* FIN flag */ );
    if( rc == 1 ) {
      /* we sent 1 chunk */

      /* set buf_sz to zero to indicate more input needed */
      pkt.buf_sz = 0UL;

      /* we used this gbl_stream, so set to NULL */
      gbl_stream = NULL;
    }
  }

  if( gbl_conn ) {
    FD_LOG_NOTICE(( "Closing connection" ));
    fd_quic_conn_close( gbl_conn, 0 );
  }

  /* wait for connection to close */
  while( gbl_conn ) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );
  }

  /* finalize quic */
  fd_quic_fini( quic );
}


int
read_pkt( uchar * out_buf, ulong * out_buf_sz ) {
  char buf[2048];
  ulong buf_sz = sizeof( buf );

  if( fgets( buf, (int)buf_sz, stdin ) == NULL ) {
    if( ferror( stdin ) ) {
      FD_LOG_WARNING(( "Error reading input: %d %s", errno, strerror( errno ) ));
    }
    return 1;
  }

  ulong j = findch( buf, sizeof( buf ), '\n' );
  if( j == ( -1UL ) ) {
    /* filled up input without carriage return, so line too long */
    FD_LOG_WARNING(( "Input line too long" ));
    return 1;
  }

  buf[j] = '\0';

  /* base64 decode (TODO bounds check) */
  long base64_sz = fd_base64_decode( out_buf, buf, j );

  if( base64_sz == -1L ) {
    FD_LOG_WARNING(( "Failed to base64 decode input line" ));
    FD_LOG_HEXDUMP_NOTICE(( "data", buf, j ));
    return 1;
  }

  *out_buf_sz = (ulong)base64_sz;

  return 0;
}


int
main( int argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ,
                                            1UL << 15,
                                            fd_shmem_cpu_idx( 0 ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  fd_quic_limits_t quic_limits = {
     .conn_cnt           = 1024UL,
     .handshake_cnt      = 256UL,
     .conn_id_cnt        = 16UL,
     .conn_id_sparsity   = 4.0,
     .stream_cnt         = { 0UL,   // FD_QUIC_STREAM_TYPE_BIDI_CLIENT
                             0UL,   // FD_QUIC_STREAM_TYPE_BIDI_SERVER
                             2UL,   // FD_QUIC_STREAM_TYPE_UNI_CLIENT
                             0UL }, // FD_QUIC_STREAM_TYPE_UNI_SERVER
     .initial_stream_cnt = { 0UL,   // FD_QUIC_STREAM_TYPE_BIDI_CLIENT
                             0UL,   // FD_QUIC_STREAM_TYPE_BIDI_SERVER
                             2UL,   // FD_QUIC_STREAM_TYPE_UNI_CLIENT
                             0UL }, // FD_QUIC_STREAM_TYPE_UNI_SERVER
     .stream_pool_cnt    = 2048UL,
     .stream_sparsity    = 4.0,
     .inflight_pkt_cnt   = 64UL,
     .tx_buf_sz          = 1UL<<15UL
  };
  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_quic_align(), quic_footprint, 1UL );
  fd_quic_t * quic = fd_quic_new( mem, &quic_limits );
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
  client_cfg->idle_timeout = (ulong)10000e6;

  run_quic_client( quic, udpsock );

  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( quic ) ) );
  fd_quic_udpsock_destroy( udpsock );
  fd_wksp_delete_anonymous( wksp );

  fd_halt();

  FD_LOG_NOTICE(( "Sent %lu transactions", sent_cnt ));

  return (int)sent_cnt;
}
