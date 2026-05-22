/* fd_bundle_client.c steps gRPC related tasks. */

#define _GNU_SOURCE /* SOL_TCP */
#include "fd_bundle_auth.h"
#include "fd_bundle_tile_private.h"
#include "fd_bundle_tile.h"
#include "../fd_txn_m.h"
#include "../../waltz/h2/fd_h2_conn.h"
#include "../../waltz/http/fd_url.h" /* fd_url_unescape */
#include "../../waltz/openssl/fd_openssl.h"
#include "../../ballet/pb/fd_pb_tokenize.h"
#include "../../util/net/fd_ip4.h"

#include <fcntl.h>
#include <errno.h>
#include <unistd.h> /* close */
#include <poll.h> /* poll */
#include <sys/socket.h> /* socket */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define FD_BUNDLE_CLIENT_REQUEST_TIMEOUT ((long)8e9) /* 8 seconds */


__attribute__((weak)) long
fd_bundle_now( void ) {
  return fd_log_wallclock();
}

void
fd_bundle_client_reset( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->tcp_sock >= 0 ) ) {
    if( FD_UNLIKELY( 0!=close( ctx->tcp_sock ) ) ) {
      FD_LOG_ERR(( "close(tcp_sock=%i) failed (%i-%s)", ctx->tcp_sock, errno, fd_io_strerror( errno ) ));
    }
    ctx->tcp_sock = -1;
    ctx->tcp_sock_connected = 0;
  }
  ctx->defer_reset = 0;

  ctx->builder_info_avail       = 0;
  ctx->builder_info_wait        = 0;
  ctx->packet_subscription_live = 0;
  ctx->packet_subscription_wait = 0;
  ctx->bundle_subscription_live = 0;
  ctx->bundle_subscription_wait = 0;

  fd_memset( ctx->rtt, 0, sizeof(fd_rtt_estimate_t) );

# if FD_HAS_OPENSSL
  if( FD_UNLIKELY( ctx->ssl ) ) {
    SSL_free( ctx->ssl );
    ctx->ssl = NULL;
  }
# endif

  fd_bundle_tile_backoff( ctx, fd_bundle_now() );

  fd_bundle_auther_reset( &ctx->auther );
  fd_grpc_client_reset( ctx->grpc_client );
}

static int
fd_bundle_client_do_connect( fd_bundle_tile_t const * ctx,
                             uint                     ip4_addr ) {
  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = ip4_addr,
    .sin_port        = fd_ushort_bswap( ctx->server_tcp_port )
  };
  int err = connect( ctx->tcp_sock, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) );
  /* FD_LIKELY is used here as EINPROGRESS is expected even to local tcp ports */
  if( FD_LIKELY( err==-1 ) ) {
    return errno;
  }
  return 0;
}

static int
fd_bundle_client_get_connect_result( fd_bundle_tile_t const * ctx ) {
  int so_err = 0;
  socklen_t so_err_sz = sizeof(so_err);
  if( FD_UNLIKELY( getsockopt( ctx->tcp_sock, SOL_SOCKET, SO_ERROR, &so_err, &so_err_sz )==-1 ) ) {
    return errno;
  }
  return so_err;
}

static void
fd_bundle_client_create_conn( fd_bundle_tile_t * ctx ) {
  fd_bundle_client_reset( ctx );

  /* FIXME IPv6 support */
  fd_addrinfo_t hints = {0};
  hints.ai_family = AF_INET;
  fd_addrinfo_t * res = NULL;
  uchar scratch[ 4096 ];
  void * pscratch = scratch;
  int err = fd_getaddrinfo( ctx->server_fqdn, &hints, &res, &pscratch, sizeof(scratch) );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_getaddrinfo `%s` failed (%d-%s)", ctx->server_fqdn, err, fd_gai_strerror( err ) ));
    fd_bundle_client_reset( ctx );
    ctx->metrics.transport_fail_cnt++;
    return;
  }
  uint const ip4_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  ctx->server_ip4_addr = ip4_addr;

  int tcp_sock = socket( AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( tcp_sock<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->tcp_sock = tcp_sock;

  if( FD_UNLIKELY( 0!=setsockopt( tcp_sock, SOL_SOCKET, SO_RCVBUF, &ctx->so_rcvbuf, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_RCVBUF,%i) failed (%i-%s)", ctx->so_rcvbuf, errno, fd_io_strerror( errno ) ));
  }

  int tcp_nodelay = 1;
  if( FD_UNLIKELY( 0!=setsockopt( tcp_sock, SOL_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fcntl( tcp_sock, F_SETFL, O_NONBLOCK )==-1 ) ) {
    FD_LOG_ERR(( "fcntl(tcp_sock,F_SETFL,O_NONBLOCK) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  char const * scheme = "http";
# if FD_HAS_OPENSSL
  if( ctx->is_ssl ) scheme = "https";
# endif

  FD_LOG_INFO(( "Connecting to %s://" FD_IP4_ADDR_FMT ":%hu (%.*s)",
                scheme,
                FD_IP4_ADDR_FMT_ARGS( ip4_addr ), ctx->server_tcp_port,
                (int)ctx->server_sni_len, ctx->server_sni ));

  int connect_err = fd_bundle_client_do_connect( ctx, ip4_addr );
  /* FD_LIKELY as EINPROGRESS is expected */
  if( FD_LIKELY( connect_err ) ) {
    if( FD_UNLIKELY( connect_err!=EINPROGRESS ) ) {
      FD_LOG_WARNING(( "connect(tcp_sock," FD_IP4_ADDR_FMT ":%u) failed (%i-%s)",
                      FD_IP4_ADDR_FMT_ARGS( ip4_addr ), ctx->server_tcp_port,
                      connect_err, fd_io_strerror( connect_err ) ));
      fd_bundle_client_reset( ctx );
      ctx->metrics.transport_fail_cnt++;
      return;
    }
  }

# if FD_HAS_OPENSSL
  if( ctx->is_ssl ) {
    BIO * bio = fd_openssl_bio_new_socket( ctx->tcp_sock, BIO_NOCLOSE );
    if( FD_UNLIKELY( !bio ) ) {
      FD_LOG_ERR(( "fd_openssl_bio_new_socket failed" ));
    }

    SSL * ssl = SSL_new( ctx->ssl_ctx );
    if( FD_UNLIKELY( !ssl ) ) {
      FD_LOG_ERR(( "SSL_new failed" ));
    }

    SSL_set_bio( ssl, bio, bio ); /* moves ownership of bio */
    SSL_set_connect_state( ssl );

    /* Indicate to endpoint which server name we want */
    if( FD_UNLIKELY( !SSL_set_tlsext_host_name( ssl, ctx->server_sni ) ) ) {
      FD_LOG_ERR(( "SSL_set_tlsext_host_name failed" ));
    }

    /* Enable hostname verification */
    if( FD_UNLIKELY( !SSL_set1_host( ssl, ctx->server_sni ) ) ) {
      FD_LOG_ERR(( "SSL_set1_host failed" ));
    }

    ctx->ssl = ssl;
  }
# endif /* FD_HAS_OPENSSL */

  fd_grpc_client_reset( ctx->grpc_client );
  fd_keepalive_init( ctx->keepalive, ctx->rng, ctx->keepalive_interval, ctx->keepalive_interval, fd_bundle_now() );
}

static int
fd_bundle_client_drive_io( fd_bundle_tile_t * ctx,
                           int *              charge_busy ) {
# if FD_HAS_OPENSSL
  if( ctx->is_ssl ) {
    return fd_grpc_client_rxtx_ossl( ctx->grpc_client, ctx->ssl, charge_busy );
  }
# endif /* FD_HAS_OPENSSL */

  return fd_grpc_client_rxtx_socket( ctx->grpc_client, ctx->tcp_sock, charge_busy );
}

static void
fd_bundle_client_request_builder_info( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( ctx->grpc_client ) ) ) return;

  static char const path[] = "/block_engine.BlockEngineValidator/GetBlockBuilderFeeInfo";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      ctx->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo,
      NULL, 0UL, /* empty request */
      ctx->auther.access_token, ctx->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  ctx->builder_info_wait = 1;
}

static void
fd_bundle_client_subscribe_packets( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( ctx->grpc_client ) ) ) return;

  static char const path[] = "/block_engine.BlockEngineValidator/SubscribePackets";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      ctx->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets,
      NULL, 0UL, /* empty request */
      ctx->auther.access_token, ctx->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_HEADER,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  ctx->packet_subscription_wait = 1;
}

static void
fd_bundle_client_subscribe_bundles( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( ctx->grpc_client ) ) ) return;

  static char const path[] = "/block_engine.BlockEngineValidator/SubscribeBundles";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      ctx->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles,
      NULL, 0UL, /* empty request */
      ctx->auther.access_token, ctx->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_HEADER,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT
  );

  ctx->bundle_subscription_wait = 1;
}

void
fd_bundle_client_send_ping( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->grpc_client ) ) return; /* no client */
  fd_h2_conn_t * conn = fd_grpc_client_h2_conn( ctx->grpc_client );
  if( FD_UNLIKELY( !conn ) ) return; /* no conn */
  if( FD_UNLIKELY( conn->flags ) ) return; /* conn busy */
  fd_h2_rbuf_t * rbuf_tx = fd_grpc_client_rbuf_tx( ctx->grpc_client );

  if( FD_LIKELY( fd_h2_tx_ping( conn, rbuf_tx ) ) ) {
    long now = fd_bundle_now();
    fd_keepalive_tx( ctx->keepalive, ctx->rng, now );
    FD_LOG_DEBUG(( "Keepalive TX (deadline=+%gs)", (double)( ctx->keepalive->ts_deadline-now )/1e9 ));
  }
}

int
fd_bundle_client_step_reconnect( fd_bundle_tile_t * ctx,
                                 long               now ) {
  /* Drive auth */
  if( FD_UNLIKELY( ctx->auther.needs_poll ) ) {
    fd_bundle_auther_poll( &ctx->auther, ctx->grpc_client, ctx->keyguard_client );
    return 1;
  }
  if( FD_UNLIKELY( ctx->auther.state!=FD_BUNDLE_AUTH_STATE_DONE_WAIT ) ) return 0;

  /* Request block builder info */
  int const builder_info_expired = ( ctx->builder_info_valid_until - now )<0;
  if( FD_UNLIKELY( ( ( !ctx->builder_info_avail ) |
                     ( builder_info_expired     ) ) &
                   ( !ctx->builder_info_wait      ) ) ) {
    fd_bundle_client_request_builder_info( ctx );
    return 1;
  }

  /* Subscribe to packets */
  if( FD_UNLIKELY( !ctx->packet_subscription_live && !ctx->packet_subscription_wait ) ) {
    fd_bundle_client_subscribe_packets( ctx );
    return 1;
  }

  /* Subscribe to bundles */
  if( FD_UNLIKELY( !ctx->bundle_subscription_live && !ctx->bundle_subscription_wait ) ) {
    fd_bundle_client_subscribe_bundles( ctx );
    return 1;
  }

  /* Send a PING */
  if( FD_UNLIKELY( fd_keepalive_should_tx( ctx->keepalive, now ) ) ) {
    fd_bundle_client_send_ping( ctx );
    return 1;
  }

  return 0;
}

static void
fd_bundle_client_step1( fd_bundle_tile_t * ctx,
                        int *              charge_busy ) {

  /* Wait for TCP socket to connect */
  if( FD_UNLIKELY( !ctx->tcp_sock_connected ) ) {
    if( FD_UNLIKELY( ctx->tcp_sock < 0 ) ) goto reconnect;

    struct pollfd pfds[1] = {
      { .fd = ctx->tcp_sock, .events = POLLOUT }
    };
    int poll_res = fd_syscall_poll( pfds, 1, 0 );
    if( FD_UNLIKELY( poll_res<0 ) ) {
      FD_LOG_ERR(( "fd_syscall_poll(tcp_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( poll_res==0 ) return;

    int connect_result = 0;
    if( pfds[0].revents & (POLLERR|POLLHUP) ) {
      connect_result = fd_bundle_client_get_connect_result( ctx );
    connect_failed:
      FD_LOG_INFO(( "Bundle gRPC connect attempt failed (%i-%s)", connect_result, fd_io_strerror( connect_result ) ));
      fd_bundle_client_reset( ctx );
      ctx->metrics.transport_fail_cnt++;
      *charge_busy = 1;
      return;
    }
    if( pfds[0].revents & POLLOUT ) {
      connect_result = fd_bundle_client_get_connect_result( ctx );
      if( FD_UNLIKELY( connect_result!=0 ) ) {
        goto connect_failed;
      }
      FD_LOG_DEBUG(( "Bundle TCP socket connected" ));
      ctx->tcp_sock_connected = 1;
      *charge_busy = 1;
      return;
    }
    return;
  }

  /* gRPC conn died? */
  if( FD_UNLIKELY( !ctx->grpc_client ) ) {
    long sleep_start;
  reconnect:
    sleep_start = fd_bundle_now();
    if( FD_UNLIKELY( fd_bundle_tile_should_stall( ctx, sleep_start ) ) ) {
      long wait_dur = ctx->backoff_until - sleep_start;
      fd_log_sleep( fd_long_min( wait_dur, 1e6 ) );
      return;
    }
    fd_bundle_client_create_conn( ctx );
    *charge_busy = 1;
    return;
  }

  /* Did a HTTP/2 PING time out */
  long check_ts = ctx->cached_ts = fd_bundle_now();
  if( FD_UNLIKELY( fd_keepalive_is_timeout( ctx->keepalive, check_ts ) ) ) {
    FD_LOG_WARNING(( "Bundle gRPC timed out (HTTP/2 PING went unanswered for %.2f seconds)",
                     (double)( check_ts - ctx->keepalive->ts_last_tx )/1e9 ));
    ctx->keepalive->inflight = 0;
    ctx->defer_reset = 1;
    *charge_busy = 1;
    return;
  }

  /* Drive I/O, SSL handshake, and any inflight requests */
  if( FD_UNLIKELY( -1==fd_bundle_client_drive_io( ctx, charge_busy ) || ctx->defer_reset /* new error? */ ) ) {
    fd_bundle_client_reset( ctx );
    ctx->metrics.transport_fail_cnt++;
    *charge_busy = 1;
    return;
  }

  /* Are we ready to issue a new request? */
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( ctx->grpc_client ) ) ) return;
  long io_ts = fd_bundle_now();
  if( FD_UNLIKELY( fd_bundle_tile_should_stall( ctx, io_ts ) ) ) return;

  *charge_busy |= fd_bundle_client_step_reconnect( ctx, io_ts );
}

static void
fd_bundle_client_log_status( fd_bundle_tile_t * ctx ) {
  int status = fd_bundle_client_status( ctx );

  int const connected_now    = ( status==FD_BUNDLE_STATE_CONNECTED );
  int const connected_before = ( ctx->bundle_status_logged==FD_BUNDLE_STATE_CONNECTED );

  if( FD_UNLIKELY( connected_now!=connected_before ) ) {
    long ts = fd_log_wallclock();
    if( FD_LIKELY( ts-(ctx->last_bundle_status_log_nanos) >= (long)1e6 ) ) {
      if( connected_now ) FD_LOG_INFO(( "Connected to bundle server" ));
      else                FD_LOG_INFO(( "Disconnected from bundle server" ));
      ctx->last_bundle_status_log_nanos = ts;
      ctx->bundle_status_logged = (uchar)status;
    }
  }
}

void
fd_bundle_client_step( fd_bundle_tile_t * ctx,
                       int *              charge_busy ) {
  /* Edge-trigger logging with rate limiting */
  fd_bundle_client_step1( ctx, charge_busy );
  fd_bundle_client_log_status( ctx );
}

void
fd_bundle_tile_backoff( fd_bundle_tile_t * ctx,
                        long               now ) {
  uint iter = ctx->backoff_iter;
  if( now < ctx->backoff_reset ) iter = 0U;
  iter++;

  /* FIXME proper backoff */
  long wait_ns = (long)2e9;
  wait_ns = (long)( fd_rng_ulong( ctx->rng ) & ( (1UL<<fd_ulong_find_msb_w_default( (ulong)wait_ns, 0 ))-1UL ) );

  ctx->backoff_until = now +   wait_ns;
  ctx->backoff_reset = now + 2*wait_ns;

  ctx->backoff_iter = iter;
}

static void
fd_bundle_client_grpc_conn_established( void * app_ctx ) {
  (void)app_ctx;
  FD_LOG_INFO(( "Bundle gRPC connection established" ));
}

static void
fd_bundle_client_grpc_conn_dead( void * app_ctx,
                                 uint   h2_err,
                                 int    closed_by ) {
  fd_bundle_tile_t * ctx = app_ctx;
  FD_LOG_INFO(( "Bundle gRPC connection closed %s (%u-%s)",
                closed_by ? "by peer" : "due to error",
                h2_err, fd_h2_strerror( h2_err ) ));
  ctx->defer_reset = 1;
}

/* Handle a SubscribePacketsResponse from a SubscribePackets gRPC call. */

struct fd_bundle_packet_meta {
  ulong  size;
  uint   src_addr;
  ushort src_port;
  uint   discard:1;
  uint   forward:1;
  uint   repair:1;
  uint   simple_vote_tx:1;
  uint   tracer_packet:1;
  uint   from_staked_node:1;
  ulong  sender_stake;
};
typedef struct fd_bundle_packet_meta fd_bundle_packet_meta_t;

static fd_bundle_packet_meta_t const *
fd_bundle_client_decode_packet_meta(
    fd_pb_inbuf_t in,
    fd_bundle_packet_meta_t * meta
) {
  *meta = (fd_bundle_packet_meta_t){0};
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    switch( tlv->field_id ) {
    case 1: /* size */
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return NULL;
      meta->size = tlv->varint;
      break;
    case 2: { /* addr */
      char cstr[ 16 ];
      if( FD_LIKELY( fd_pb_tlv_cstr( &in, tlv, cstr, sizeof(cstr) ) ) ) {
        fd_cstr_to_ip4_addr( cstr, &meta->src_addr );
      }
      break;
    }
    case 3: /* src_port */
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return NULL;
      if( FD_UNLIKELY( tlv->varint > USHRT_MAX ) ) return NULL;
      meta->src_port = (ushort)tlv->varint;
      break;
    case 4: { /* flags */
      fd_pb_inbuf_t sub;
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, &sub ) ) ) return NULL;
      while( fd_pb_inbuf_sz( &sub ) ) {
        fd_pb_tlv_t flag_tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &sub, flag_tlv ) ) ) return NULL;
        if( flag_tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) return NULL;
        switch( flag_tlv->field_id ) {
        case 1: meta->discard          = !!flag_tlv->varint; break;
        case 2: meta->forward          = !!flag_tlv->varint; break;
        case 3: meta->repair           = !!flag_tlv->varint; break;
        case 4: meta->simple_vote_tx   = !!flag_tlv->varint; break;
        case 5: meta->tracer_packet    = !!flag_tlv->varint; break;
        case 6: meta->from_staked_node = !!flag_tlv->varint; break;
        }
        if( FD_UNLIKELY( !fd_pb_tlv_skip( &sub, flag_tlv ) ) ) return NULL;
      }
      break;
    }
    case 5: /* sender_stake */
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return NULL;
      meta->sender_stake = tlv->varint;
      break;
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return NULL;
  }
  return meta;
}

static int
fd_bundle_client_handle_packet(
    fd_bundle_tile_t * ctx,
    fd_pb_inbuf_t      in,
    ulong              bundle_txn_cnt
) {
  fd_bundle_packet_meta_t meta   = {0};
  uchar const *           pkt    = NULL;
  ulong                   pkt_sz = 0UL;

  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    switch( tlv->field_id ) {
    case 1: /* data */
      pkt    = fd_pb_tlv_bytes( &in, tlv );
      pkt_sz = tlv->len;
      if( FD_UNLIKELY( !pkt ) ) return 0;
      break;
    case 2: { /* meta */
      fd_pb_inbuf_t sub;
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, &sub ) ) ) return 0;
      if( FD_UNLIKELY( !fd_bundle_client_decode_packet_meta( sub, &meta ) ) ) return 0;
      break;
    }
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }

  /* If zero sz, abort entire bundle.
     For PacketBatch allow it, as it might be a keepalive packet */
  if( FD_UNLIKELY( !pkt_sz ) ) return !bundle_txn_cnt;

  if( FD_UNLIKELY( pkt_sz > FD_TXN_MTU ) ) {
    FD_LOG_WARNING(( "Ignoring oversize transaction from bundle server (%lu bytes)", pkt_sz ));
    return 0;
  }

  /* FIXME return 0 if meta.discard is set? */

  if( !bundle_txn_cnt ) ctx->metrics.packet_received_cnt++;

  if( FD_UNLIKELY( bundle_txn_cnt && !ctx->builder_info_avail ) ) {
    ctx->metrics.missing_builder_info_fail_cnt++; /* unreachable */
    return 1;
  }
  if( FD_UNLIKELY( pending_txn_full( ctx->pending_txns ) ) ) {
    ctx->metrics.backpressure_drop_cnt++;
    return 1;
  }

  fd_bundle_pending_txn_t * entry = pending_txn_push_tail_nocopy( ctx->pending_txns );
  fd_memcpy( entry->payload, pkt, pkt_sz );
  entry->payload_sz     = (ushort)pkt_sz;
  entry->source_ipv4    = meta.src_addr;
  if( bundle_txn_cnt ) {
    entry->sig            = 1UL;
    entry->bundle_seq     = ctx->bundle_seq;
    entry->bundle_txn_cnt = bundle_txn_cnt;
    entry->commission     = (uchar)ctx->builder_commission;
    fd_memcpy( entry->commission_pubkey, ctx->builder_pubkey, 32UL );
  } else {
    entry->sig            = 0UL;
    entry->bundle_seq     = 0UL;
    entry->bundle_txn_cnt = 1UL;
    entry->commission     = 0U;
    fd_memset( entry->commission_pubkey, 0, 32UL );
  }
  ctx->metrics.txn_received_cnt++;

  return 1;
}

static int
fd_bundle_client_handle_packet_batch(
    fd_bundle_tile_t * ctx,
    fd_pb_inbuf_t      in
) {
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    switch( tlv->field_id ) {
    case 1: /* header */
      break;
    case 2: { /* packet.PacketBatch batch */
      fd_pb_inbuf_t batch;
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, &batch ) ) ) return 0;
      while( fd_pb_inbuf_sz( &batch ) ) {
        fd_pb_tlv_t packet_tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &batch, packet_tlv ) ) ) return 0;
        if( packet_tlv->field_id==1 ) { /* repeated packet.Packet packets */
          fd_pb_inbuf_t packet;
          if( FD_UNLIKELY( !fd_pb_tlv_submsg( &batch, packet_tlv, &packet ) ) ) return 0;
          if( FD_UNLIKELY( !fd_bundle_client_handle_packet( ctx, packet, 0UL ) ) ) {
            FD_LOG_WARNING(( "Dropping invalid transaction from bundle server" ));
          }
        }
        if( FD_UNLIKELY( !fd_pb_tlv_skip( &batch, packet_tlv ) ) ) return 0;
      }
    }
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }
  return 1;
}

/* Handle a SubscribeBundlesResponse from a SubscribeBundles gRPC call. */

static int
handle_bundle_packets(
    fd_bundle_tile_t * ctx,
    fd_pb_inbuf_t      in_
) {
  fd_pb_inbuf_t in = in_;
  ulong cnt = 0UL;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    if( tlv->field_id==3 ) cnt++;
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }
  if( FD_UNLIKELY( cnt > FD_BUNDLE_CLIENT_MAX_TXN_PER_BUNDLE ) ) {
    FD_LOG_WARNING(( "Ignoring bundle with %lu transactions (too many)", cnt ));
    return 1;
  }
  if( FD_UNLIKELY( pending_txn_avail( ctx->pending_txns )<cnt ) ) {
    ctx->metrics.backpressure_drop_cnt += cnt;
    return 1;
  }

  ulong pending_txn_cnt0      = pending_txn_cnt( ctx->pending_txns );
  ulong bundle_seq0          = ctx->bundle_seq;
  ulong txn_received_cnt0    = ctx->metrics.txn_received_cnt;
  ulong bundle_received_cnt0 = ctx->metrics.bundle_received_cnt;

  ctx->bundle_seq++;
  ctx->metrics.bundle_received_cnt++;

  in = in_;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) goto fail;
    if( tlv->field_id==3 ) { /* repeated packet.Packet packets */
      fd_pb_inbuf_t ele;
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, &ele ) ) ) goto fail;
      if( FD_UNLIKELY( !fd_bundle_client_handle_packet( ctx, ele, cnt ) ) ) goto fail;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) goto fail;
  }
  return 1;

fail:
  while( pending_txn_cnt( ctx->pending_txns )>pending_txn_cnt0 ) {
    pending_txn_remove_tail( ctx->pending_txns );
  }
  ctx->bundle_seq                  = bundle_seq0;
  ctx->metrics.txn_received_cnt    = txn_received_cnt0;
  ctx->metrics.bundle_received_cnt = bundle_received_cnt0;
  return 0;
}

static int
handle_bundle_uuid(
    fd_bundle_tile_t * ctx,
    fd_pb_inbuf_t      in
) {
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    if( tlv->field_id==1 ) { /* bundle.Bundle bundle */
      fd_pb_inbuf_t bundle;
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, &bundle ) ) ) return 0;
      if( FD_UNLIKELY( !handle_bundle_packets( ctx, bundle ) ) ) return 0;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }
  return 1;
}

static int
fd_bundle_client_handle_bundle_batch(
    fd_bundle_tile_t * ctx,
    fd_pb_inbuf_t      in
) {
  if( FD_UNLIKELY( !ctx->builder_info_avail ) ) {
    ctx->metrics.missing_builder_info_fail_cnt++;
    return 1;
  }

  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1]; if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    if( tlv->field_id==1 ) { /* repeated bundle.BundleUuid bundles */
      fd_pb_inbuf_t ele;
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, &ele ) ) ) return 0;
      if( FD_UNLIKELY( !handle_bundle_uuid( ctx, ele ) ) ) return 0;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }
  return 1;
}

/* Handle a BlockBuilderFeeInfoResponse from a GetBlockBuilderFeeInfo
   gRPC call. */

static int
fd_bundle_client_handle_builder_fee_info(
    fd_bundle_tile_t * ctx,
    fd_pb_inbuf_t      in
) {
  ulong commission = 0UL;
  fd_pubkey_t pubkey = {0};

  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    switch( tlv->field_id ) {
    case 1: { /* pubkey */
      if( FD_UNLIKELY( !fd_pb_tlv_base58_32( &in, tlv, pubkey.key ) ) ) return 0;
      break;
    }
    case 2: /* commission (0-100) */
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return 0;
      commission = tlv->varint;
      if( FD_UNLIKELY( commission > 100UL ) ) {
        FD_LOG_WARNING(( "BlockBuilderFeeInfoResponse commission out of range (0-100): %lu", commission ));
        return 0;
      }
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }

  if( FD_UNLIKELY( fd_pubkey_check_zero( &pubkey ) ) ) {
    FD_LOG_WARNING(( "BlockBuilderFeeInfoResponse did not contain valid pubkey" ));
    return 0;
  }

  ctx->builder_commission = (uchar)commission;
  fd_memcpy( ctx->builder_pubkey, pubkey.key, sizeof(ctx->builder_pubkey) );

  long validity_duration_ns = (long)( 60e9 * 5. ); /* 5 minutes */
  ctx->builder_info_avail = 1;
  ctx->builder_info_valid_until = fd_bundle_now() + validity_duration_ns;
  return 1;
}

static void
fd_bundle_client_grpc_tx_complete(
    void * app_ctx,
    ulong  request_ctx
) {
  (void)app_ctx; (void)request_ctx;
}

void
fd_bundle_client_grpc_rx_start(
    void * app_ctx,
    ulong  request_ctx
) {
  fd_bundle_tile_t * ctx = app_ctx;
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    ctx->packet_subscription_live = 1;
    ctx->packet_subscription_wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    ctx->bundle_subscription_live = 1;
    ctx->bundle_subscription_wait = 0;
    break;
  }
}

void
fd_bundle_client_grpc_rx_msg(
    void *       app_ctx,
    void const * protobuf,
    ulong        protobuf_sz,
    ulong        request_ctx
) {
  fd_bundle_tile_t * ctx = app_ctx;
  ctx->metrics.proto_received_bytes += protobuf_sz;

  fd_pb_inbuf_t in;
  fd_pb_inbuf_init( &in, protobuf, protobuf_sz );

  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
    if( FD_UNLIKELY( !fd_bundle_auther_handle_challenge_resp( &ctx->auther, in ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      fd_bundle_tile_backoff( ctx, fd_bundle_now() );
    }
    break;
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    if( FD_UNLIKELY( !fd_bundle_auther_handle_tokens_resp( &ctx->auther, in ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      fd_bundle_tile_backoff( ctx, fd_bundle_now() );
    }
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    if( FD_UNLIKELY( !fd_bundle_client_handle_bundle_batch( ctx, in ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      FD_LOG_WARNING(( "Failed to decode SubscribeBundles response" ));
    }
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    if( FD_UNLIKELY( !fd_bundle_client_handle_packet_batch( ctx, in ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      FD_LOG_WARNING(( "Failed to decode SubscribePackets response" ));
    }
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    if( FD_UNLIKELY( !fd_bundle_client_handle_builder_fee_info( ctx, in ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      FD_LOG_WARNING(( "Failed to decode GetBlockBuilderFeeInfo response" ));
    }
    break;
  default:
    FD_LOG_ERR(( "Received unexpected gRPC message (request_ctx=%lu)", request_ctx ));
  }
}

static void
fd_bundle_client_request_failed( fd_bundle_tile_t * ctx,
                                 ulong              request_ctx ) {
  fd_bundle_tile_backoff( ctx, fd_bundle_now() );
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    fd_bundle_auther_handle_request_fail( &ctx->auther );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    ctx->builder_info_wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    ctx->packet_subscription_live = 0;
    ctx->packet_subscription_wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    ctx->bundle_subscription_live = 0;
    ctx->bundle_subscription_wait = 0;
    break;
  }
}

void
fd_bundle_client_grpc_rx_end(
    void *                app_ctx,
    ulong                 request_ctx,
    fd_grpc_resp_hdrs_t * resp
) {
  fd_bundle_tile_t * ctx = app_ctx;
  if( FD_UNLIKELY( resp->h2_status!=200 ) ) {
    FD_LOG_WARNING(( "gRPC request failed (HTTP status %u)", resp->h2_status ));
    fd_bundle_client_request_failed( ctx, request_ctx );
    return;
  }

  resp->grpc_msg_len = (uint)fd_url_unescape( resp->grpc_msg, resp->grpc_msg_len );
  if( !resp->grpc_msg_len ) {
    fd_memcpy( resp->grpc_msg, "unknown error", 13 );
    resp->grpc_msg_len = 13;
  }

  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    ctx->packet_subscription_live = 0;
    ctx->packet_subscription_wait = 0;
    fd_bundle_tile_backoff( ctx, fd_bundle_now() );
    ctx->defer_reset = 1;
    FD_LOG_INFO(( "SubscribePackets stream failed (gRPC status %u-%s). Reconnecting ...",
                  resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ) ));
    return;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    ctx->bundle_subscription_live = 0;
    ctx->bundle_subscription_wait = 0;
    fd_bundle_tile_backoff( ctx, fd_bundle_now() );
    ctx->defer_reset = 1;
    FD_LOG_INFO(( "SubscribeBundles stream failed (gRPC status %u-%s). Reconnecting ...",
                  resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ) ));
    return;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    ctx->builder_info_wait = 0;
    break;
  default:
    break;
  }

  if( FD_UNLIKELY( resp->grpc_status!=FD_GRPC_STATUS_OK ) ) {
    FD_LOG_INFO(( "gRPC request failed (gRPC status %u-%s): %.*s",
                  resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ),
                  (int)resp->grpc_msg_len, resp->grpc_msg ));
    fd_bundle_client_request_failed( ctx, request_ctx );
    if( resp->grpc_status==FD_GRPC_STATUS_UNAUTHENTICATED ||
        resp->grpc_status==FD_GRPC_STATUS_PERMISSION_DENIED ) {
      fd_bundle_auther_reset( &ctx->auther );
    }
    return;
  }
}

void
fd_bundle_client_grpc_rx_timeout(
    void * app_ctx,
    ulong  request_ctx,  /* FD_BUNDLE_CLIENT_REQ_{...} */
    int    deadline_kind /* FD_GRPC_DEADLINE_{HEADER|RX_END} */
) {
  (void)deadline_kind;
  FD_LOG_WARNING(( "Request timed out: %s", fd_bundle_request_ctx_cstr( request_ctx ) ));
  fd_bundle_tile_t * ctx = app_ctx;
  ctx->defer_reset = 1;
}

static void
fd_bundle_client_grpc_ping_ack( void * app_ctx ) {
  fd_bundle_tile_t * ctx = app_ctx;
  long rtt_sample = fd_keepalive_rx( ctx->keepalive, fd_bundle_now() );
  if( FD_LIKELY( rtt_sample ) ) {
    fd_rtt_sample( ctx->rtt, (float)rtt_sample, 0 );
    FD_LOG_DEBUG(( "Keepalive ACK" ));
  }
  ctx->metrics.ping_ack_cnt++;
}

fd_grpc_client_callbacks_t fd_bundle_client_grpc_callbacks = {
  .conn_established = fd_bundle_client_grpc_conn_established,
  .conn_dead        = fd_bundle_client_grpc_conn_dead,
  .tx_complete      = fd_bundle_client_grpc_tx_complete,
  .rx_start         = fd_bundle_client_grpc_rx_start,
  .rx_msg           = fd_bundle_client_grpc_rx_msg,
  .rx_end           = fd_bundle_client_grpc_rx_end,
  .rx_timeout       = fd_bundle_client_grpc_rx_timeout,
  .ping_ack         = fd_bundle_client_grpc_ping_ack,
};

int
fd_bundle_client_status( fd_bundle_tile_t const * ctx ) {
  if( FD_UNLIKELY( ( !ctx->tcp_sock_connected ) |
                   ( !ctx->grpc_client        ) ) ) {
    return FD_BUNDLE_STATE_DISCONNECTED;
  }

  fd_h2_conn_t * conn = fd_grpc_client_h2_conn( ctx->grpc_client );
  if( FD_UNLIKELY( !conn ) ) {
    return FD_BUNDLE_STATE_DISCONNECTED; /* no conn */
  }
  if( FD_UNLIKELY( conn->flags &
      ( FD_H2_CONN_FLAGS_DEAD |
        FD_H2_CONN_FLAGS_SEND_GOAWAY ) ) ) {
    return FD_BUNDLE_STATE_DISCONNECTED;
  }

  if( FD_UNLIKELY( conn->flags &
      ( FD_H2_CONN_FLAGS_CLIENT_INITIAL      |
        FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0 |
        FD_H2_CONN_FLAGS_WAIT_SETTINGS_0     |
        FD_H2_CONN_FLAGS_SERVER_INITIAL ) ) ) {
    return FD_BUNDLE_STATE_CONNECTING; /* connection is not ready */
  }

  if( FD_UNLIKELY( ctx->auther.state != FD_BUNDLE_AUTH_STATE_DONE_WAIT ) ) {
    return FD_BUNDLE_STATE_CONNECTING; /* not authenticated */
  }

  if( FD_UNLIKELY( ( !ctx->builder_info_avail       ) |
                   ( !ctx->packet_subscription_live ) |
                   ( !ctx->bundle_subscription_live ) ) ) {
    return FD_BUNDLE_STATE_CONNECTING; /* not fully connected */
  }

  if( FD_UNLIKELY( fd_keepalive_is_timeout( ctx->keepalive, fd_bundle_now() ) ) ) {
    return FD_BUNDLE_STATE_DISCONNECTED; /* possible timeout */
  }

  if( FD_UNLIKELY( !fd_grpc_client_is_connected( ctx->grpc_client ) ) ) {
    return FD_BUNDLE_STATE_CONNECTING;
  }

  /* As far as we know, the bundle connection is alive and well. */
  return FD_BUNDLE_STATE_CONNECTED;
}

#undef DISCONNECTED
#undef CONNECTING
#undef CONNECTED

FD_FN_CONST char const *
fd_bundle_request_ctx_cstr( ulong request_ctx ) {
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
    return "GenerateAuthChallenge";
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    return "GenerateAuthTokens";
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    return "SubscribePackets";
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    return "SubscribeBundles";
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    return "GetBlockBuilderFeeInfo";
  default:
    return "unknown";
  }
}
