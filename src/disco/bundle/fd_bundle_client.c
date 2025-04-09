/* fd_bundle_client.c steps gRPC related tasks. */

#include "fd_bundle_tile_private.h"
#include "../tiles.h" /* fd_txn_m_t */
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h> /* close */
#include <sys/socket.h> /* socket */
#include <netinet/in.h> /* IPPROTO_TCP */
#include "../../flamenco/nanopb/pb_decode.h"
#include "proto/block_engine.pb.h"
#include "proto/bundle.pb.h"
#include "proto/packet.pb.h"
#include "proto/shredstream.pb.h"

static void
fd_bundle_client_reset( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->tcp_sock >= 0 ) ) {
    if( FD_UNLIKELY( 0!=close( ctx->tcp_sock ) ) ) {
      FD_LOG_ERR(( "close(tcp_sock=%i) failed (%i-%s)", ctx->tcp_sock, errno, fd_io_strerror( errno ) ));
    }
    ctx->tcp_sock = -1;
  }

  if( FD_UNLIKELY( ctx->ssl ) ) {
    SSL_free( ctx->ssl );
    ctx->ssl = NULL;
  }

  /* No need to free, self-contained object */
  ctx->grpc_client = NULL;
}

static void
fd_bundle_client_create_conn( fd_bundle_tile_t * ctx ) {
  fd_bundle_client_reset( ctx );

  int tcp_sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
  if( FD_UNLIKELY( tcp_sock<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_STREAM,IPPROTO_TCP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int flags = fcntl( tcp_sock, F_GETFL, 0 );
  if( FD_UNLIKELY( flags==-1 ) ) {
    FD_LOG_ERR(( "fcntl(tcp_sock,F_GETFL) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( fcntl( tcp_sock, F_SETFL, flags|O_NONBLOCK )==-1 ) ) {
    FD_LOG_ERR(( "fcntl(tcp_sock,F_SETFL,+O_NONBLOCK) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* FIXME setsockopt */

  BIO * bio = BIO_new_socket( ctx->tcp_sock, BIO_NOCLOSE );
  if( FD_UNLIKELY( !bio ) ) {
    FD_LOG_ERR(( "BIO_new_socket failed" ));
  }

  SSL * ssl = SSL_new( ctx->ssl_ctx );
  if( FD_UNLIKELY( !ssl ) ) {
    FD_LOG_ERR(( "SSL_new failed" ));
  }

  SSL_set_bio( ssl, bio, bio ); /* moves ownership of bio */

  ctx->ssl = ssl;

  ctx->grpc_client = fd_grpc_client_new( ctx->grpc_client, &fd_bundle_client_grpc_callbacks, ctx->grpc_metrics, ctx );
  if( FD_UNLIKELY( !ctx->grpc_client ) ) {
    FD_LOG_CRIT(( "fd_grpc_client_new failed" )); /* unreachable */
  }
}

void
fd_bundle_client_step( fd_bundle_tile_t * bundle ) {

  /* Need to create a connection? */
  if( FD_UNLIKELY( !bundle->grpc_client ) ) {
    fd_bundle_client_create_conn( bundle );
    return;
  }

  /* Drive I/O, SSL handshake, and any inflight requests */
  fd_grpc_client_rxtx_ossl( bundle->grpc_client, bundle->ssl );

  /* Are we ready to issue a new request? */
  if( fd_grpc_client_request_is_blocked( bundle->grpc_client ) ) return;

}

static void
fd_bundle_client_grpc_conn_dead( void * app_ctx ) {
  (void)app_ctx;
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
    FD_LOG_CRIT(( "block builder info not available" )); /* unreachable */
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
    FD_LOG_WARNING(( "ctx->stem not set. This is a bug." ));
  }

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( ctx->stem, ctx->verify_out.idx, sig, ctx->verify_out.chunk, sz, 0UL, 0UL, tspub );
  ctx->verify_out.chunk = fd_dcache_compact_next( ctx->verify_out.chunk, sz, ctx->verify_out.chunk0, ctx->verify_out.wmark );
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
    FD_LOG_WARNING(( "ctx->stem not set. This is a bug." ));
  }

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( ctx->stem, ctx->verify_out.idx, sig, ctx->verify_out.chunk, sz, 0UL, 0UL, tspub );
  ctx->verify_out.chunk = fd_dcache_compact_next( ctx->verify_out.chunk, sz, ctx->verify_out.chunk0, ctx->verify_out.wmark );
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
  if( FD_UNLIKELY( !pb_decode( &peek, &bundle_Bundle_msg, &bundle ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (bundle.Bundle) failed" ));
    return false;
  }

  /* At this opint, ctx->bundle_txn_cnt is correctly set.
     Second pass: Actually publish bundle packets */

  bundle = (bundle_BundleUuid)bundle_BundleUuid_init_default;
  bundle.bundle.packets = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bundle_txn,
    .arg          = ctx
  };

  return pb_decode( &peek, &bundle_Bundle_msg, &bundle );
}

/* Handle a SubscribeBundlesResponse from a SubscribeBundles gRPC call. */

static void
fd_bundle_client_handle_bundle_batch(
    fd_bundle_tile_t * ctx,
    pb_istream_t *     istream
) {
  block_engine_SubscribeBundlesResponse res = block_engine_SubscribeBundlesResponse_init_default;
  res.bundles = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bundle_uuid,
    .arg          = ctx
  };
  if( FD_UNLIKELY( !pb_decode( istream, &block_engine_SubscribeBundlesResponse_msg, &res ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block_engine.SubscribeBundlesResponse) failed" ));
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
fd_bundle_client_handle_shredstream_heartbeat_response(
    fd_bundle_tile_t * ctx,
    pb_istream_t *     istream
) {
  shredstream_HeartbeatResponse resp = shredstream_HeartbeatResponse_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &shredstream_HeartbeatResponse_msg, &resp ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (shredstream.HeartbeatResponse) failed" ));
    return;
  }

  (void)ctx; (void)istream;
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
    fd_bundle_auther_handle_challenge_resp( &ctx->auther, protobuf, protobuf_sz );
    break;
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    fd_bundle_auther_handle_tokens_resp( &ctx->auther, protobuf, protobuf_sz );
    break;
  case FD_BUNDLE_CLIENT_REQ_Auth_RefreshAccessToken:
    fd_bundle_auther_handle_refresh_resp( &ctx->auther, protobuf, protobuf_sz );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    fd_bundle_client_handle_bundle_batch( ctx, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    fd_bundle_client_handle_packet_batch( ctx, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Shredstream_SendHeartbeat:
    fd_bundle_client_handle_shredstream_heartbeat_response( ctx, &istream );
    break;
  default:
    FD_LOG_ERR(( "Received unexpected gRPC message (request_ctx=%lu)", request_ctx ));
  }
}

static void
fd_bundle_client_grpc_rx_end(
    void * app_ctx,
    ulong  request_ctx
) {
  (void)app_ctx; (void)request_ctx;
}

fd_grpc_client_callbacks_t fd_bundle_client_grpc_callbacks = {
  .conn_dead = fd_bundle_client_grpc_conn_dead,
  .rx_msg    = fd_bundle_client_grpc_rx_msg,
  .rx_end    = fd_bundle_client_grpc_rx_end
};
