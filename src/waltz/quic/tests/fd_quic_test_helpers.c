#include "fd_quic_test_helpers.h"
#include "../../../util/net/fd_pcapng.h"
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../../../util/net/fd_ip4.h"

#if defined(__linux__)
#include <linux/if_link.h>
#endif

FILE * fd_quic_test_pcap;

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
fd_quic_test_cb_stream_notify( fd_quic_stream_t * stream,
                               void *             quic_ctx,
                               int                notify_type ) {
  FD_LOG_DEBUG(( "cb_stream_notify(stream=%lu, quic_ctx=%p, notify_type=%d)",
                 stream->stream_id, quic_ctx, notify_type ));
}

static int
fd_quic_test_cb_stream_rx( fd_quic_conn_t * conn,
                           ulong            stream_id,
                           ulong            offset,
                           uchar const *    data,
                           ulong            data_sz,
                           int              fin ) {
  FD_LOG_DEBUG(( "cb_stream_rx(conn=%p, stream=%lu, offset=%lu, data=%p, data_sz=%lu, fin=%d)",
                 (void *)conn, stream_id, offset, (void const *)data, data_sz, fin ));
  return FD_QUIC_SUCCESS;
}

void
fd_quic_test_cb_tls_keylog( void *       quic_ctx,
                            char const * line ) {
  (void)quic_ctx;
  if( fd_quic_test_pcap )
    fd_pcapng_fwrite_tls_key_log( (uchar const *)line, (uint)strlen( line ), fd_quic_test_pcap );
}

static void
flush_pcap( void ) {
  fflush( fd_quic_test_pcap );
}

/* Test runtime */

void
fd_quic_test_boot( int *    pargc,
                   char *** pargv ) {
  char const * _pcap = fd_env_strip_cmdline_cstr( pargc, pargv, "--pcap", NULL, NULL );

  if( _pcap ) {
    FD_LOG_NOTICE(( "Logging to --pcap %s", _pcap ));
    fd_quic_test_pcap = fopen( _pcap, "ab" );
    FD_TEST( fd_quic_test_pcap );
    atexit( flush_pcap );
  }
}

void
fd_quic_test_halt( void ) {
  if( fd_quic_test_pcap ) {
    FD_TEST( 0==fclose( fd_quic_test_pcap ) );
    fd_quic_test_pcap = NULL;
  }
}

/* QUIC creation helper */

void
fd_quic_config_anonymous( fd_quic_t * quic,
                          int         role ) {

  fd_quic_config_t * config = &quic->config;
  config->role = role;

  /* Generate IP address */
  test_ip_addr_seq = fd_uint_bswap( fd_uint_bswap( test_ip_addr_seq ) + 1 );

  /* Default settings */
  config->idle_timeout     = FD_QUIC_DEFAULT_IDLE_TIMEOUT;
  config->ack_delay        = FD_QUIC_DEFAULT_ACK_DELAY;
  config->ack_threshold    = FD_QUIC_DEFAULT_ACK_THRESHOLD;
  config->initial_rx_max_stream_data = FD_TXN_MTU;

  /* Default callbacks */
  quic->cb.conn_new         = fd_quic_test_cb_conn_new;
  quic->cb.conn_hs_complete = fd_quic_test_cb_conn_handshake_complete;
  quic->cb.conn_final       = fd_quic_test_cb_conn_final;
  quic->cb.stream_notify    = fd_quic_test_cb_stream_notify;
  quic->cb.stream_rx        = fd_quic_test_cb_stream_rx;
  quic->cb.tls_keylog       = fd_quic_test_cb_tls_keylog;
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
  fd_quic_get_state( quic )->now = 1L;

  fd_tls_test_sign_ctx_t * sign_ctx = fd_wksp_alloc_laddr( wksp, alignof(fd_tls_test_sign_ctx_t), sizeof(fd_tls_test_sign_ctx_t), 1UL );
  fd_tls_test_sign_ctx( sign_ctx, rng );
  fd_quic_config_test_signer( quic, sign_ctx );

  return quic;
}

fd_quic_t *
fd_quic_new_anonymous_small( fd_wksp_t * wksp,
                             int         role,
                             fd_rng_t *  rng ) {

  fd_quic_limits_t quic_limits = {
    .conn_cnt           = 1UL,
    .handshake_cnt      = 1UL,
    .conn_id_cnt        = 4UL,
    .inflight_frame_cnt = 64UL,
    .tx_buf_sz          = 1UL<<15UL,
    .stream_pool_cnt    = 1024
  };

  return fd_quic_new_anonymous( wksp, &quic_limits, role, rng );
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

  pair->aio_a2b = rx_b;
  pair->aio_b2a = rx_a;
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

  FD_TEST( 1UL==fd_aio_pcapng_start_l3( pcap ) );

  /* Install captures */

  FD_TEST( fd_aio_pcapng_join( &pair->pcapng_b2a, rx_a, pcap ) );
  FD_TEST( fd_aio_pcapng_join( &pair->pcapng_a2b, rx_b, pcap ) );

  /* Set send target */

  fd_quic_set_aio_net_tx( quic_a, fd_aio_pcapng_get_aio( &pair->pcapng_a2b ) );
  fd_quic_set_aio_net_tx( quic_b, fd_aio_pcapng_get_aio( &pair->pcapng_b2a ) );

  pair->aio_a2b = &pair->pcapng_a2b.local;
  pair->aio_b2a = &pair->pcapng_b2a.local;
}

void
fd_quic_virtual_pair_init( fd_quic_virtual_pair_t * pair,
                           fd_quic_t * quic_a,
                           fd_quic_t * quic_b ) {
  memset( pair, 0, sizeof(fd_quic_virtual_pair_t) );
  if( !fd_quic_test_pcap )
    fd_quic_virtual_pair_direct( pair, quic_a, quic_b );
  else
    fd_quic_virtual_pair_pcap  ( pair, quic_a, quic_b, fd_quic_test_pcap );
}

void
fd_quic_virtual_pair_fini( fd_quic_virtual_pair_t * pair ) {
  if( pair->pcapng_a2b.pcapng ) {
    FD_TEST( fd_aio_pcapng_leave( &pair->pcapng_a2b ) );
    FD_TEST( fd_aio_pcapng_leave( &pair->pcapng_b2a ) );
  }
  fd_quic_set_aio_net_tx( pair->quic_a, NULL );
  fd_quic_set_aio_net_tx( pair->quic_b, NULL );
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
  if( FD_UNLIKELY( 0!=bind( sock_fd, fd_type_pun_const( &listen_addr ), sizeof(struct sockaddr_in) ) ) ) {
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
  fd_udpsock_set_layer( sock, FD_UDPSOCK_LAYER_IP );

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

fd_quic_udpsock_t *
fd_quic_udpsock_create( void *           _sock,
                        int *            pargc,
                        char ***         pargv,
                        fd_wksp_t *      wksp,
                        fd_aio_t const * rx_aio ) {

  /* FIXME simplify this / use fdctl tile architecture */
  fd_quic_udpsock_t * quic_sock = _sock;

  ulong        mtu           = fd_env_strip_cmdline_ulong ( pargc, pargv, "--mtu",          NULL,    2048UL );
  ulong        rx_depth      = fd_env_strip_cmdline_ulong ( pargc, pargv, "--rx-depth",     NULL,    1024UL );
  ulong        tx_depth      = fd_env_strip_cmdline_ulong ( pargc, pargv, "--tx-depth",     NULL,    1024UL );
  char const * _listen_ip    = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--listen-ip",    NULL, "0.0.0.0" );
  ushort       listen_port   = fd_env_strip_cmdline_ushort( pargc, pargv, "--listen-port",  NULL,     9090U );

  uint listen_ip = 0;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _listen_ip, &listen_ip ) ) ) FD_LOG_ERR(( "invalid --listen-ip" ));

  quic_sock->listen_ip   = listen_ip;
  quic_sock->listen_port = listen_port;

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
    if( FD_UNLIKELY( 0!=bind( sock_fd, fd_type_pun_const( &listen_addr ), sizeof(struct sockaddr_in) ) ) ) {
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
    fd_udpsock_set_layer( sock, FD_UDPSOCK_LAYER_IP );

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

  return quic_sock;
}

void *
fd_quic_udpsock_destroy( fd_quic_udpsock_t * udpsock ) {
  if( FD_UNLIKELY( !udpsock ) )
    return NULL;

  switch( udpsock->type ) {
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
  case FD_QUIC_UDPSOCK_TYPE_UDPSOCK:
    fd_udpsock_service( udpsock->udpsock.sock );
    break;
  }
}


fd_quic_netem_t *
fd_quic_netem_init( fd_quic_netem_t * netem,
                    float             thres_drop,
                    float             thres_reorder ) {
  *netem = (fd_quic_netem_t) {
    .thresh_drop    = thres_drop,
    .thresh_reorder = thres_reorder,
  };
  fd_aio_new( &netem->local, netem, fd_quic_netem_send );
  return netem;
}

int
fd_quic_netem_send( void *                    ctx, /* fd_quic_net_em_t */
                    fd_aio_pkt_info_t const * batch,
                    ulong                     batch_cnt,
                    ulong *                   opt_batch_idx FD_PARAM_UNUSED,
                    int                       flush ) {
  fd_quic_netem_t * mitm_ctx = ctx;

  /* go packet by packet */
  for( ulong j = 0UL; j < batch_cnt; ++j ) {
    /* generate a random number and compare with threshold, and either pass thru or drop */
    static FD_TL uint seed = 0; /* FIXME use fd_log_tid */
    ulong l = fd_rng_private_expand( seed++ );
    float rnd_num = (float)l * (float)0x1p-64;
    int weighted_tail = (int)((l&0x7)==0x7); /* 12.5% chance of being 1, else head */

    if( rnd_num < mitm_ctx->thresh_drop ) {
      /* dropping behaves as-if the send was successful */
      continue;
    }

    if( rnd_num < mitm_ctx->thresh_reorder ) {
      /* logic: if either buf free, buf it. Else, flush and replace send more recent one if head */
      schar free = -1;
      if( mitm_ctx->reorder_buf[0].sz==0 ) free = 0;
      else if( mitm_ctx->reorder_buf[0].sz==1 ) free = 1;

      if( free>=0 ) {
        fd_memcpy( mitm_ctx->reorder_buf[free].buf, batch[j].buf, batch[j].buf_sz );
        mitm_ctx->reorder_buf[free].sz = batch[j].buf_sz;
        mitm_ctx->reorder_mru = free;
      } else {
        /* send more recent one if head */
        int replace_idx = mitm_ctx->reorder_mru ^ weighted_tail;
        fd_aio_pkt_info_t batch_1[1] = {{ .buf = mitm_ctx->reorder_buf[replace_idx].buf, .buf_sz = (ushort)mitm_ctx->reorder_buf[replace_idx].sz }};
        fd_aio_send( mitm_ctx->dst, batch_1, 1UL, NULL, flush );

        fd_memcpy( mitm_ctx->reorder_buf[replace_idx].buf, batch[j].buf, batch[j].buf_sz );
        mitm_ctx->reorder_buf[replace_idx].sz = batch[j].buf_sz;
        mitm_ctx->reorder_mru = replace_idx;
      }
      continue;
    }

    /* send new packet */
    fd_aio_pkt_info_t batch_0[1] = { batch[j] };
    fd_aio_send( mitm_ctx->dst, batch_0, 1UL, NULL, flush );

    /* we aren't dropping or reordering, but we might have a prior reorder */
    int send = -1;
    if( mitm_ctx->reorder_buf[0].sz > 0 ) send = 0;
    if( mitm_ctx->reorder_buf[1].sz > 0 ) {
      if( send == -1 ) send = 1; /* only this one free */
      else send = mitm_ctx->reorder_mru ^ weighted_tail; /* if head, send mru */
    }

    if( send>=0 ) {
      fd_aio_pkt_info_t batch_1[1] = {{ .buf = mitm_ctx->reorder_buf[send].buf, .buf_sz = (ushort)mitm_ctx->reorder_buf[send].sz }};
      fd_aio_send( mitm_ctx->dst, batch_1, 1UL, NULL, flush );
      mitm_ctx->reorder_buf[send].sz = 0;
      mitm_ctx->reorder_mru = send ^ 0x1; /* toggle mru */
    }
  }

  return FD_AIO_SUCCESS;
}
