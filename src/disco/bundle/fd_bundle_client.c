/* fd_bundle_client.c steps gRPC related tasks. */

#include "fd_bundle_auth.h"
#include "fd_bundle_tile_private.h"
#include "proto/block_engine.pb.h"
#include "proto/bundle.pb.h"
#include "proto/packet.pb.h"
#include "../fd_txn_m_t.h"
#include "../plugin/fd_plugin.h"
#include "../../waltz/h2/fd_h2_conn.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/nanopb/pb_decode.h"
#include "../../util/net/fd_ip4.h"

#include <fcntl.h>
#include <errno.h>
#include <unistd.h> /* close */
#include <poll.h> /* poll */
#include <sys/socket.h> /* socket */
#include <netinet/in.h>

static void
fd_bundle_client_reset( fd_bundle_tile_t * ctx ) {
  if( ( !!ctx->bundle_subscription_live ) |
      ( !!ctx->packet_subscription_live ) ) {
    /* Client was connected before but now is not.  Inform user. */
    FD_LOG_WARNING(( "Disconnected from bundle server" ));
  }

  if( FD_UNLIKELY( ctx->tcp_sock >= 0 ) ) {
    if( FD_UNLIKELY( 0!=close( ctx->tcp_sock ) ) ) {
      FD_LOG_ERR(( "close(tcp_sock=%i) failed (%i-%s)", ctx->tcp_sock, errno, fd_io_strerror( errno ) ));
    }
    ctx->tcp_sock = -1;
    ctx->tcp_sock_connected = 0;
  }
  ctx->defer_reset = 0;

  ctx->builder_info_wait        = 0;
  ctx->packet_subscription_live = 0;
  ctx->packet_subscription_wait = 0;
  ctx->bundle_subscription_live = 0;
  ctx->bundle_subscription_wait = 0;

# if FD_HAS_OPENSSL
  if( FD_UNLIKELY( ctx->ssl ) ) {
    SSL_free( ctx->ssl );
    ctx->ssl = NULL;
  }
# endif

  /* No need to free, self-contained object */
  ctx->grpc_client = NULL;

  fd_bundle_tile_backoff( ctx, fd_tickcount() );

  fd_bundle_auther_handle_request_fail( &ctx->auther );
}

static int
fd_bundle_client_do_connect( fd_bundle_tile_t const * ctx,
                             uint                     ip4_addr ) {
  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = ip4_addr,
    .sin_port        = fd_ushort_bswap( ctx->server_tcp_port )
  };
  errno = 0;
  connect( ctx->tcp_sock, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) );
  return errno;
}

/* Provided by fdctl/firedancer version.c */
extern char const fdctl_version_string[];

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
  if( FD_UNLIKELY( connect_err ) ) {
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
    BIO * bio = BIO_new_socket( ctx->tcp_sock, BIO_NOCLOSE );
    if( FD_UNLIKELY( !bio ) ) {
      FD_LOG_ERR(( "BIO_new_socket failed" ));
    }

    SSL * ssl = SSL_new( ctx->ssl_ctx );
    if( FD_UNLIKELY( !ssl ) ) {
      FD_LOG_ERR(( "SSL_new failed" ));
    }

    SSL_set_bio( ssl, bio, bio ); /* moves ownership of bio */
    SSL_set_connect_state( ssl );

    if( FD_UNLIKELY( !SSL_set_tlsext_host_name( ssl, ctx->server_sni ) ) ) {
      FD_LOG_ERR(( "SSL_set_tlsext_host_name failed" ));
    }

    ctx->ssl = ssl;
  }
# endif /* FD_HAS_OPENSSL */

  ctx->grpc_client = fd_grpc_client_new( ctx->grpc_client_mem, &fd_bundle_client_grpc_callbacks, ctx->grpc_metrics, ctx, ctx->map_seed );
  if( FD_UNLIKELY( !ctx->grpc_client ) ) {
    FD_LOG_CRIT(( "fd_grpc_client_new failed" )); /* unreachable */
  }
  fd_grpc_client_set_version( ctx->grpc_client, fdctl_version_string, strlen( fdctl_version_string ) );
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

  block_engine_BlockBuilderFeeInfoRequest req = block_engine_BlockBuilderFeeInfoRequest_init_default;
  static char const path[] = "/block_engine.BlockEngineValidator/GetBlockBuilderFeeInfo";
  int req_ok = fd_grpc_client_request_start(
      ctx->grpc_client,
      ctx->server_sni, ctx->server_sni_len, ctx->server_tcp_port,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo,
      &block_engine_BlockBuilderFeeInfoRequest_msg, &req,
      ctx->auther.access_token, ctx->auther.access_token_sz
  );
  if( FD_UNLIKELY( !req_ok ) ) return;

  ctx->builder_info_wait = 1;
}

static void
fd_bundle_client_subscribe_packets( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( ctx->grpc_client ) ) ) return;

  block_engine_SubscribePacketsRequest req = block_engine_SubscribePacketsRequest_init_default;
  static char const path[] = "/block_engine.BlockEngineValidator/SubscribePackets";
  int req_ok = fd_grpc_client_request_start(
      ctx->grpc_client,
      ctx->server_sni, ctx->server_sni_len, ctx->server_tcp_port,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets,
      &block_engine_SubscribePacketsRequest_msg, &req,
      ctx->auther.access_token, ctx->auther.access_token_sz
  );
  if( FD_UNLIKELY( !req_ok ) ) return;

  ctx->packet_subscription_wait = 1;
}

static void
fd_bundle_client_subscribe_bundles( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( ctx->grpc_client ) ) ) return;

  block_engine_SubscribeBundlesRequest req = block_engine_SubscribeBundlesRequest_init_default;
  static char const path[] = "/block_engine.BlockEngineValidator/SubscribeBundles";
  int req_ok = fd_grpc_client_request_start(
      ctx->grpc_client,
      ctx->server_sni, ctx->server_sni_len, ctx->server_tcp_port,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles,
      &block_engine_SubscribeBundlesRequest_msg, &req,
      ctx->auther.access_token, ctx->auther.access_token_sz
  );
  if( FD_UNLIKELY( !req_ok ) ) return;

  ctx->bundle_subscription_wait = 1;
}

static void
fd_bundle_client_send_ping( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->grpc_client ) ) return; /* no client */
  fd_h2_conn_t * conn = fd_grpc_client_h2_conn( ctx->grpc_client );
  if( FD_UNLIKELY( !conn ) ) return; /* no conn */
  if( FD_UNLIKELY( conn->flags ) ) return; /* conn busy */
  fd_h2_rbuf_t * rbuf_tx = fd_grpc_client_rbuf_tx( ctx->grpc_client );

  if( FD_LIKELY( fd_h2_tx_ping( conn, rbuf_tx ) ) ) {
    ctx->last_ping_tx_ts = fd_tickcount();
    ctx->ping_randomize  = fd_rng_ulong( ctx->rng );
  }
}

FD_FN_PURE static int
fd_bundle_client_keepalive_due( fd_bundle_tile_t const * ctx,
                                long                     now_ticks ) {
  ulong delay_min = ctx->ping_threshold_ticks>>1;
  ulong delay_rng = ctx->ping_threshold_ticks & ctx->ping_randomize;
  ulong delay     = delay_min + delay_rng;
  long  deadline  = ctx->last_ping_tx_ts + (long)delay;
  return now_ticks >= deadline;
}

void
fd_bundle_client_step( fd_bundle_tile_t * ctx,
                       int *              charge_busy ) {

  /* Wait for TCP socket to connect */
  if( FD_UNLIKELY( !ctx->tcp_sock_connected ) ) {
    if( FD_UNLIKELY( ctx->tcp_sock < 0 ) ) goto reconnect;

    struct pollfd pfds[1] = {
      { .fd = ctx->tcp_sock, .events = POLLOUT }
    };
    int poll_res = poll( pfds, 1, 0 );
    if( FD_UNLIKELY( poll_res<0 ) ) {
      FD_LOG_ERR(( "poll(tcp_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( poll_res==0 ) return;

    if( pfds[0].revents & (POLLERR|POLLHUP) ) {
      int connect_err = fd_bundle_client_do_connect( ctx, 0 );
      FD_LOG_INFO(( "Bundle gRPC connect attempt failed (%i-%s)", connect_err, fd_io_strerror( connect_err ) ));
      fd_bundle_client_reset( ctx );
      ctx->metrics.transport_fail_cnt++;
      *charge_busy = 1;
      return;
    }
    if( pfds[0].revents & POLLOUT ) {
      FD_LOG_DEBUG(( "Bundle TCP socket connected" ));
      ctx->tcp_sock_connected = 1;
      *charge_busy = 1;
      return;
    }
    return;
  }

  /* gRPC conn died? */
  if( FD_UNLIKELY( !ctx->grpc_client ) ) {
  reconnect:
    if( FD_UNLIKELY( fd_bundle_tile_should_stall( ctx, fd_tickcount() ) ) ) {
      return;
    }
    fd_bundle_client_create_conn( ctx );
    *charge_busy = 1;
    return;
  }

  /* Drive I/O, SSL handshake, and any inflight requests */
  if( FD_UNLIKELY( !fd_bundle_client_drive_io( ctx, charge_busy ) ||
                   ctx->defer_reset /* new error? */ ) ) {
    fd_bundle_client_reset( ctx );
    ctx->metrics.transport_fail_cnt++;
    *charge_busy = 1;
    return;
  }

  /* Are we ready to issue a new request? */
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( ctx->grpc_client ) ) ) return;
  long io_ts = fd_tickcount();
  if( FD_UNLIKELY( fd_bundle_tile_should_stall( ctx, io_ts ) ) ) return;

  /* Drive auth */
  if( FD_UNLIKELY( ctx->auther.needs_poll ) ) {
    fd_bundle_auther_poll( &ctx->auther, ctx->grpc_client, ctx->keyguard_client, ctx->server_sni, ctx->server_sni_len, ctx->server_tcp_port );
    *charge_busy = 1;
    return;
  }
  if( FD_UNLIKELY( ctx->auther.state!=FD_BUNDLE_AUTH_STATE_DONE_WAIT ) ) return;

  /* Request block builder info */
  if( FD_UNLIKELY( !ctx->builder_info_live && !ctx->builder_info_wait ) ) {
    fd_bundle_client_request_builder_info( ctx );
    goto busy_exit;
  }

  /* Subscribe to packets */
  if( FD_UNLIKELY( !ctx->packet_subscription_live && !ctx->packet_subscription_wait ) ) {
    fd_bundle_client_subscribe_packets( ctx );
    goto busy_exit;
  }

  /* Subscribe to bundles */
  if( FD_UNLIKELY( !ctx->bundle_subscription_live && !ctx->bundle_subscription_wait ) ) {
    fd_bundle_client_subscribe_bundles( ctx );
    goto busy_exit;
  }

  /* Send a PING */
  if( FD_UNLIKELY( fd_bundle_client_keepalive_due( ctx, io_ts ) ) ) {
    fd_bundle_client_send_ping( ctx );
    goto busy_exit;
  }

  return;
busy_exit:
  *charge_busy = 1;
  return;
}

void
fd_bundle_tile_backoff( fd_bundle_tile_t * ctx,
                        long               ts_ticks ) {
  uint iter = ctx->backoff_iter;
  if( ts_ticks < ctx->backoff_reset ) iter = 0U;
  iter++;

  /* FIXME proper backoff */
  long wait_ticks = (long)( 500e6 * fd_tempo_tick_per_ns( NULL ) );
  wait_ticks = (long)( fd_rng_ulong( ctx->rng ) & ( (1UL<<fd_ulong_find_msb_w_default( (ulong)wait_ticks, 0 ))-1UL ) );

  ctx->backoff_until = ts_ticks +   wait_ticks;
  ctx->backoff_reset = ts_ticks + 2*wait_ticks;

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

/* Forwards a bundle transaction to the tango message bus. */

static void
fd_bundle_tile_publish_bundle_txn(
    fd_bundle_tile_t * ctx,
    void const *       txn,
    ulong              txn_sz,  /* <=FD_TXN_MTU */
    ulong              bundle_txn_cnt
) {
  if( FD_UNLIKELY( !ctx->builder_info_avail ) ) {
    ctx->metrics.missing_builder_info_fail_cnt++; /* unreachable */
    return;
  }

  fd_txn_m_t * txnm = fd_chunk_to_laddr( ctx->verify_out.mem, ctx->verify_out.chunk );
  *txnm = (fd_txn_m_t) {
    .reference_slot = 0UL,
    .payload_sz     = (ushort)txn_sz,
    .txn_t_sz       = 0,
    .block_engine   = {
      .bundle_id      = ctx->bundle_seq,
      .bundle_txn_cnt = bundle_txn_cnt,
      .commission     = (uchar)ctx->builder_commission
    },
  };
  memcpy( txnm->block_engine.commission_pubkey, ctx->builder_pubkey, 32UL );
  fd_memcpy( fd_txn_m_payload( txnm ), txn, txn_sz );

  ulong sz  = fd_txn_m_realized_footprint( txnm, 0, 0 );
  ulong sig = 0UL;

  if( FD_UNLIKELY( !ctx->stem ) ) {
    FD_LOG_CRIT(( "ctx->stem not set. This is a bug." ));
  }

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( ctx->stem, ctx->verify_out.idx, sig, ctx->verify_out.chunk, sz, 0UL, 0UL, tspub );
  ctx->verify_out.chunk = fd_dcache_compact_next( ctx->verify_out.chunk, sz, ctx->verify_out.chunk0, ctx->verify_out.wmark );
  ctx->metrics.txn_received_cnt++;
}

/* Forwards a regular transaction to the tango message bus. */

static void
fd_bundle_tile_publish_txn(
    fd_bundle_tile_t * ctx,
    void const *       txn,
    ulong              txn_sz  /* <=FD_TXN_MTU */
) {
  fd_txn_m_t * txnm = fd_chunk_to_laddr( ctx->verify_out.mem, ctx->verify_out.chunk );
  *txnm = (fd_txn_m_t) {
    .reference_slot = 0UL,
    .payload_sz     = (ushort)txn_sz,
    .txn_t_sz       = 0,
    .block_engine   = {
      .bundle_id         = 0UL,
      .bundle_txn_cnt    = 1UL,
      .commission        = 0,
      .commission_pubkey = {0}
    },
  };
  fd_memcpy( fd_txn_m_payload( txnm ), txn, txn_sz );

  ulong sz  = fd_txn_m_realized_footprint( txnm, 0, 0 );
  ulong sig = 0UL;

  if( FD_UNLIKELY( !ctx->stem ) ) {
    FD_LOG_CRIT(( "ctx->stem not set. This is a bug." ));
  }

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( ctx->stem, ctx->verify_out.idx, sig, ctx->verify_out.chunk, sz, 0UL, 0UL, tspub );
  ctx->verify_out.chunk = fd_dcache_compact_next( ctx->verify_out.chunk, sz, ctx->verify_out.chunk0, ctx->verify_out.wmark );
  ctx->metrics.txn_received_cnt++;
}

/* Called for each transaction in a bundle.  Simply counts up
   bundle_txn_cnt, but does not publish anything. */

static bool
fd_bundle_client_visit_pb_bundle_txn_preflight(
    pb_istream_t *     istream,
    pb_field_t const * field,
    void **            arg
) {
  (void)istream; (void)field;
  fd_bundle_tile_t * ctx = *arg;
  ctx->bundle_txn_cnt++;
  return true;
}

/* Called for each transaction in a bundle.  Publishes each transaction
   to the tango message bus. */

static bool
fd_bundle_client_visit_pb_bundle_txn(
    pb_istream_t *     istream,
    pb_field_t const * field,
    void **            arg
) {
  (void)field;
  fd_bundle_tile_t * ctx = *arg;

  packet_Packet packet = packet_Packet_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &packet_Packet_msg, &packet ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (packet.Packet) failed" ));
    return false;
  }

  if( FD_UNLIKELY( packet.data.size > FD_TXN_MTU ) ) {
    FD_LOG_WARNING(( "Bundle server delivered an oversize transaction, ignoring" ));
    return true;
  }

  fd_bundle_tile_publish_bundle_txn(
      ctx,
      packet.data.bytes, packet.data.size,
      ctx->bundle_txn_cnt
  );

  return true;
}

/* Called for each BundleUuid in a SubscribeBundlesResponse. */

static bool
fd_bundle_client_visit_pb_bundle_uuid(
    pb_istream_t *     istream,
    pb_field_t const * field,
    void **            arg
) {
  (void)field;
  fd_bundle_tile_t * ctx = *arg;

  /* Reset bundle state */

  ctx->bundle_txn_cnt = 0UL;
  ctx->bundle_seq++;

  /* Do two decode passes.  This is required because we need to know the
     number of transactions in a bundle ahead of time.  However, due to
     the Protobuf wire encoding, we don't know the number of txns that
     will come until we've parsed everything.

     First pass: Count number of bundles. */

  pb_istream_t peek = *istream;
  bundle_BundleUuid bundle = bundle_BundleUuid_init_default;
  bundle.bundle.packets = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bundle_txn_preflight,
    .arg          = ctx
  };
  if( FD_UNLIKELY( !pb_decode( &peek, &bundle_BundleUuid_msg, &bundle ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (bundle.BundleUuid) failed: %s", peek.errmsg ));
    return false;
  }

  /* At this opint, ctx->bundle_txn_cnt is correctly set.
     Second pass: Actually publish bundle packets */

  bundle = (bundle_BundleUuid)bundle_BundleUuid_init_default;
  bundle.bundle.packets = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bundle_txn,
    .arg          = ctx
  };

  ctx->metrics.bundle_received_cnt++;

  if( FD_UNLIKELY( !pb_decode( istream, &bundle_BundleUuid_msg, &bundle ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (bundle.BundleUuid) failed (internal error): %s", istream->errmsg ));
    return false;
  }

  return true;
}

/* Handle a SubscribeBundlesResponse from a SubscribeBundles gRPC call. */

static void
fd_bundle_client_handle_bundle_batch(
    fd_bundle_tile_t * ctx,
    pb_istream_t *     istream
) {
  if( FD_UNLIKELY( !ctx->builder_info_avail ) ) {
    ctx->metrics.missing_builder_info_fail_cnt++; /* unreachable */
    return;
  }

  block_engine_SubscribeBundlesResponse res = block_engine_SubscribeBundlesResponse_init_default;
  res.bundles = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bundle_uuid,
    .arg          = ctx
  };
  if( FD_UNLIKELY( !pb_decode( istream, &block_engine_SubscribeBundlesResponse_msg, &res ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block_engine.SubscribeBundlesResponse) failed: %s", istream->errmsg ));
    return;
  }
}

/* Called for each 'Packet' (a regular transaction) of a
   SubscribePacketsResponse. */

static bool
fd_bundle_client_visit_pb_packet(
    pb_istream_t *     istream,
    pb_field_t const * field,
    void **            arg
) {
  (void)field;
  fd_bundle_tile_t * ctx = *arg;

  packet_Packet packet = packet_Packet_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &packet_Packet_msg, &packet ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (packet.Packet) failed" ));
    return false;
  }

  if( FD_UNLIKELY( packet.data.size > FD_TXN_MTU ) ) {
    FD_LOG_WARNING(( "Bundle server delivered an oversize transaction, ignoring" ));
    return true;
  }

  fd_bundle_tile_publish_txn( ctx, packet.data.bytes, packet.data.size );
  ctx->metrics.packet_received_cnt++;

  return true;
}

/* Handle a SubscribePacketsResponse from a SubscribePackets gRPC call. */

static void
fd_bundle_client_handle_packet_batch(
    fd_bundle_tile_t * ctx,
    pb_istream_t *     istream
) {
  block_engine_SubscribePacketsResponse res = block_engine_SubscribePacketsResponse_init_default;
  res.batch.packets = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_packet,
    .arg          = ctx
  };
  if( FD_UNLIKELY( !pb_decode( istream, &block_engine_SubscribePacketsResponse_msg, &res ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block_engine.SubscribePacketsResponse) failed" ));
    return;
  }
}

static void
fd_bundle_client_log_progress( fd_bundle_tile_t * ctx ) {
  if( ( !!ctx->packet_subscription_live ) &
      ( !!ctx->bundle_subscription_live ) &
      ( !!ctx->builder_info_live        ) ) {
    FD_LOG_NOTICE(( "Connected to bundle server" ));
  }
}

/* Handle a BlockBuilderFeeInfoResponse from a GetBlockBuilderFeeInfo
   gRPC call. */

static void
fd_bundle_client_handle_builder_fee_info(
    fd_bundle_tile_t * ctx,
    pb_istream_t *     istream
) {
  _Bool changed = !ctx->builder_info_avail;

  block_engine_BlockBuilderFeeInfoResponse res = block_engine_BlockBuilderFeeInfoResponse_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &block_engine_BlockBuilderFeeInfoResponse_msg, &res ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block_engine.BlockBuilderFeeInfoResponse) failed" ));
    return;
  }
  if( FD_UNLIKELY( res.commission > 100 ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "BlockBuilderFeeInfoResponse commission out of range (0-100): %lu", res.commission ));
    return;
  }

  ctx->builder_commission = (uchar)res.commission;
  if( FD_UNLIKELY( !fd_base58_decode_32( res.pubkey, ctx->builder_pubkey ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "Invalid pubkey in BlockBuilderFeeInfoResponse", res.pubkey, strnlen( res.pubkey, sizeof(res.pubkey) ) ));
    return;
  }

  ctx->builder_info_avail = 1;
  ctx->builder_info_live  = 1;
  if( changed ) fd_bundle_client_log_progress( ctx );
}

static void
fd_bundle_client_grpc_tx_complete(
    void * app_ctx,
    ulong  request_ctx
) {
  (void)app_ctx; (void)request_ctx;
}

static void
fd_bundle_client_grpc_rx_start(
    void * app_ctx,
    ulong  request_ctx
) {
  fd_bundle_tile_t * ctx = app_ctx;
  _Bool changed = 0;
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    ctx->packet_subscription_live = 1;
    ctx->packet_subscription_wait = 0;
    changed = 1;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    ctx->bundle_subscription_live = 1;
    ctx->bundle_subscription_wait = 0;
    changed = 1;
    break;
  }

  if( changed ) fd_bundle_client_log_progress( ctx );
}

void
fd_bundle_client_grpc_rx_msg(
    void *       app_ctx,
    void const * protobuf,
    ulong        protobuf_sz,
    ulong        request_ctx
) {
  fd_bundle_tile_t * ctx = app_ctx;
  pb_istream_t istream = pb_istream_from_buffer( protobuf, protobuf_sz );
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
    if( FD_UNLIKELY( !fd_bundle_auther_handle_challenge_resp( &ctx->auther, protobuf, protobuf_sz ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      fd_bundle_tile_backoff( ctx, fd_tickcount() );
    }
    break;
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    if( FD_UNLIKELY( !fd_bundle_auther_handle_tokens_resp( &ctx->auther, protobuf, protobuf_sz ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      fd_bundle_tile_backoff( ctx, fd_tickcount() );
    }
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    fd_bundle_client_handle_bundle_batch( ctx, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    fd_bundle_client_handle_packet_batch( ctx, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    fd_bundle_client_handle_builder_fee_info( ctx, &istream );
    break;
  default:
    FD_LOG_ERR(( "Received unexpected gRPC message (request_ctx=%lu)", request_ctx ));
  }
}

static void
fd_bundle_client_request_failed( fd_bundle_tile_t * ctx,
                                 ulong              request_ctx ) {
  fd_bundle_tile_backoff( ctx, fd_tickcount() );
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    fd_bundle_auther_handle_request_fail( &ctx->auther );
    break;
  }
}

static inline int
fd_hex_unhex( int c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+0xa;
  if( c>='A' && c<='F' ) return c-'A'+0xa;
  return -1;
}

static ulong
fd_url_unescape( char * const msg,
                 ulong  const len ) {
  char * end = msg+len;
  int state = 0;
  char * dst = msg;
  for( char * src=msg; src<end; src++ ) {
    /* invariant: p<=msg */
    switch( state ) {
    case 0:
      if( FD_LIKELY( (*src)!='%' ) ) {
        *dst = *src;
        dst++;
      } else {
        state = 1;
      }
      break;
    case 1:
      if( FD_LIKELY( (*src)!='%' ) )  {
        *dst = (char)( ( fd_hex_unhex( *src )&0xf )<<4 );
        state = 2;
      } else {
        /* FIXME is 'aa%%aa' a valid escape? */
        *(dst++) = '%';
        state = 0;
      }
      break;
    case 2:
      *dst = (char)( (*dst) | ( fd_hex_unhex( *src )&0xf ) );
      dst++;
      state = 0;
      break;
    }
  }
  return (ulong)( dst-msg );
}

static void
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
    fd_bundle_tile_backoff( ctx, fd_tickcount() );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    ctx->bundle_subscription_live = 0;
    ctx->bundle_subscription_wait = 0;
    fd_bundle_tile_backoff( ctx, fd_tickcount() );
    break;
  default:
    break;
  }

  if( FD_UNLIKELY( resp->grpc_status!=FD_GRPC_STATUS_OK ) ) {
    FD_LOG_WARNING(( "gRPC request failed (gRPC status %u-%s): %.*s",
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

static void
fd_bundle_client_grpc_ping_ack( void * app_ctx ) {
  fd_bundle_tile_t * ctx = app_ctx;
  ctx->last_ping_rx_ts = fd_tickcount();
  ctx->metrics.ping_ack_cnt++;
}

fd_grpc_client_callbacks_t fd_bundle_client_grpc_callbacks = {
  .conn_established = fd_bundle_client_grpc_conn_established,
  .conn_dead        = fd_bundle_client_grpc_conn_dead,
  .tx_complete      = fd_bundle_client_grpc_tx_complete,
  .rx_start         = fd_bundle_client_grpc_rx_start,
  .rx_msg           = fd_bundle_client_grpc_rx_msg,
  .rx_end           = fd_bundle_client_grpc_rx_end,
  .ping_ack         = fd_bundle_client_grpc_ping_ack,
};

/* Decrease verbosity */
#define DISCONNECTED FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_DISCONNECTED
#define CONNECTING   FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_CONNECTING
#define CONNECTED    FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_CONNECTED

int
fd_bundle_client_status( fd_bundle_tile_t const * ctx ) {
  if( FD_UNLIKELY( ( !ctx->tcp_sock_connected ) |
                   ( !ctx->grpc_client        ) ) ) {
    return DISCONNECTED;
  }

  fd_h2_conn_t * conn = fd_grpc_client_h2_conn( ctx->grpc_client );
  if( FD_UNLIKELY( !conn ) ) {
    return DISCONNECTED; /* no conn */
  }
  if( FD_UNLIKELY( conn->flags &
      ( FD_H2_CONN_FLAGS_DEAD |
        FD_H2_CONN_FLAGS_SEND_GOAWAY ) ) ) {
    return DISCONNECTED;
  }

  if( FD_UNLIKELY( conn->flags &
      ( FD_H2_CONN_FLAGS_CLIENT_INITIAL      |
        FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0 |
        FD_H2_CONN_FLAGS_WAIT_SETTINGS_0     |
        FD_H2_CONN_FLAGS_SERVER_INITIAL ) ) ) {
    return CONNECTING; /* connection is not ready */
  }

  if( FD_UNLIKELY( ctx->auther.state != FD_BUNDLE_AUTH_STATE_DONE_WAIT ) ) {
    return CONNECTING; /* not authenticated */
  }

  if( FD_UNLIKELY( ( !ctx->builder_info_avail       ) |
                   ( !ctx->packet_subscription_live ) |
                   ( !ctx->bundle_subscription_live ) ) ) {
    return CONNECTING; /* not fully connected */
  }

  long ping_timeout = (long)( 3UL * ctx->ping_threshold_ticks );
  if( FD_UNLIKELY( fd_tickcount() > ctx->last_ping_rx_ts + ping_timeout ) ) {
    return DISCONNECTED; /* possible timeout */
  }

  /* As far as we know, the bundle connection is alive and well. */
  return CONNECTED;
}

#undef DISCONNECTED
#undef CONNECTING
#undef CONNECTED
