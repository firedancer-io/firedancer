#include "test_bundle_common.c"
#include "fd_bundle_tile.h"
#include "proto/bam_api.pb.h"
#include "proto/block_engine.pb.h"
#include "../keyguard/fd_keyguard.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../third_party/nanopb/pb_encode.h"
#include "../../third_party/nanopb/pb_decode.h"
#include "../../util/tmpl/fd_unit_test.c"

#include <sys/socket.h>

FD_IMPORT_BINARY( test_bundle_response, "src/disco/bundle/test_bundle_response.binpb" );

static long g_clock = 1L;

__attribute__((weak)) long
fd_bundle_now( fd_bundle_tile_t const * ctx ) {
  (void)ctx;
  return g_clock;
}

static fd_wksp_t * wksp;

/* Test that packets and bundles get forwarded correctly to Firedancer
   components. */

/* fd_bundle_client_step flushes frame_tx to the socket in the same
   step; read the transmitted bytes back from the mock peer. */

static fd_h2_rbuf_t *
wire_rx( test_bundle_env_t * env ) {
  static uchar        wire_buf[ 65536 ];
  static fd_h2_rbuf_t wire[1];
  fd_h2_rbuf_init( wire, wire_buf, sizeof(wire_buf) );
  uchar tmp[ 4096 ];
  for(;;) {
    long n = recv( env->server_sock, tmp, sizeof(tmp), MSG_DONTWAIT );
    if( n<=0L ) break;
    fd_h2_rbuf_push( wire, tmp, (ulong)n );
  }
  return wire;
}

FD_UNIT_TEST( bundle_rx ) {
  test_bundle_env_t env[1]; test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  /* A SubscribePacketsResponse message with 2 packets included. The
     first packet is 1 byte { 0x48 }, the second packet is 2 bytes
     {0x48, 0x48}.

     message SubscribePacketsResponse {
      shared.Header header = 1;
      packet.PacketBatch batch = 2;
    }
  */
  static uchar subscribe_packets_msg[] = {
    0x12, 0x13, 0x0a, 0x07, 0x0a, 0x01, 0x48, 0x12,
    0x02, 0x08, 0x01, 0x0a, 0x08, 0x0a, 0x02, 0x48,
    0x48, 0x12, 0x02, 0x08, 0x02
  };
  fd_bundle_client_grpc_rx_msg(
      state->conn,
      subscribe_packets_msg, sizeof(subscribe_packets_msg),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  FD_TEST( pending_txn_peek_head( state->pending_txns )->sig==0UL );

  state->conn->builder.avail = 1;

  fd_bundle_client_grpc_rx_msg(
      state->conn,
      test_bundle_response, test_bundle_response_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )>2UL );

  test_bundle_env_destroy( env );
}

FD_UNIT_TEST( bundle_rx_too_many_txns ) {
  test_bundle_env_t env[1]; test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  /*
  Contains a single bundle with 6 transactions
  {
    "bundles": [
      {
        "bundle": {
          "header": null,
          "packets": [
            {
              "data": [
                72
              ],
              "meta": {
                "size": 1,
                "addr": "",
                "port": 0,
                "flags": null,
                "sender_stake": 0
              }
            },
            ...x5
          ]
        },
        "uuid": [0, 0, 0]
      }
    ]
  }
  */
  static uchar subscribe_bundles_msg_x5[] = {
    0x0a, 0x52, 0x0a, 0x4b, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08,
    0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d, 0x0a,
    0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28,
    0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12,
    0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12,
    0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d,
    0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00,
    0x28, 0x00, 0x12, 0x03, 0x00, 0x00, 0x00
  };

  state->conn->builder.avail = 1;
  fd_bundle_client_grpc_rx_msg(
      state->conn,
      subscribe_bundles_msg_x5, sizeof(subscribe_bundles_msg_x5),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );
  test_bundle_env_destroy( env );

  test_bundle_env_create( env, wksp );
  state = env->state;

  /* Same as above, now with 6 transactions. Should be a NOP */
  static uchar subscribe_bundles_msg_x6[] = {
    0x0a, 0x61, 0x0a, 0x5a, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08,
    0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d, 0x0a,
    0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28,
    0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12,
    0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12,
    0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d,
    0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00,
    0x28, 0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01,
    0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x12, 0x03, 0x00, 0x00, 0x00
  };

  state->conn->builder.avail = 1;
  fd_bundle_client_grpc_rx_msg(
      state->conn,
      subscribe_bundles_msg_x6, sizeof(subscribe_bundles_msg_x6),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==0UL );
  FD_TEST( state->metrics.bundle_received_cnt==0UL );
  test_bundle_env_destroy( env );
}

/* Ensure forwarding of bundles stops when builder fee info is missing. */

FD_UNIT_TEST( bundle_no_builder_fee_info ) {
  test_bundle_env_t env[1]; test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->conn->builder.avail = 0;

  /* Regular packets are always forwarded */
  static uchar subscribe_packets_msg[] = {
    0x12, 0x09, 0x0a, 0x07, 0x0a, 0x01, 0x48, 0x12,
    0x02, 0x08, 0x01
  };
  fd_bundle_client_grpc_rx_msg(
      state->conn,
      subscribe_packets_msg, sizeof(subscribe_packets_msg),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );
  FD_TEST( state->metrics.packet_received_cnt          ==1UL );
  FD_TEST( state->metrics.missing_builder_info_fail_cnt==0UL );

  /* Bundles are no longer forwarded */

  fd_bundle_client_grpc_rx_msg(
      state->conn,
      test_bundle_response, test_bundle_response_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );
  FD_TEST( state->metrics.bundle_received_cnt          ==0UL );
  FD_TEST( state->metrics.missing_builder_info_fail_cnt==1UL );

  test_bundle_env_destroy( env );
}

/* Ensure that the client reconnects (with a new TCP socket) if the
   server ends the stream */

FD_UNIT_TEST( bundle_stream_ended ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state = env->state;
  fd_h2_rbuf_t * rbuf_tx = fd_grpc_client_rbuf_tx( state->conn->grpc_client );
  FD_TEST( rbuf_tx->hi_off==0UL );
  fd_grpc_resp_hdrs_t hdrs = {
    .h2_status   = 200,
    .grpc_status = FD_GRPC_STATUS_OK
  };
  FD_TEST( state->conn->defer_reset==0 );
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles, &hdrs );
  FD_TEST( state->conn->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Same as above, but with hard stream resets */

FD_UNIT_TEST( bundle_stream_reset ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state   = env->state;
  fd_grpc_client_t * client  = state->conn->grpc_client;
  fd_h2_conn_t *     h2_conn = fd_grpc_client_h2_conn( client );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;

  FD_TEST( state->conn->defer_reset==0 );
  fd_grpc_client_h2_callbacks.rst_stream( h2_conn, &stream->s, 0U, 1 );
  FD_TEST( state->conn->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test response header timeout */

FD_UNIT_TEST( bundle_header_timeout ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->conn->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status        = 200;
  stream->hdrs.is_grpc_proto    = 1;
  stream->has_header_deadline   = 1;
  stream->header_deadline_nanos = 99L;

  /* FIXME ensure that receiving a header disarms the timeout */

  fd_grpc_client_service_streams( client, 100L );
  FD_TEST( state->conn->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test response timeout */

FD_UNIT_TEST( bundle_rx_end_timeout ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->conn->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status        = 200;
  stream->hdrs.is_grpc_proto    = 1;
  stream->has_rx_end_deadline   = 1;
  stream->rx_end_deadline_nanos = 99L;

  fd_grpc_client_service_streams( client, 100L );
  FD_TEST( state->conn->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test ping timeout */

FD_UNIT_TEST( bundle_ping ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state       = env->state;
  fd_grpc_client_t * grpc_client = state->conn->grpc_client;
  long const ts_ping_tx = g_clock;
  fd_keepalive_tx( state->conn->keepalive, state->rng, ts_ping_tx );
  state->conn->grpc_client->conn->ping_tx = 1;
  FD_TEST( state->conn->keepalive->inflight==1 );
  FD_TEST( !!state->conn->keepalive->ts_deadline );
  FD_TEST( state->conn->keepalive->ts_next_tx >= ts_ping_tx + (state->conn->keepalive->interval>>1) );
  FD_TEST( state->conn->keepalive->ts_last_tx==ts_ping_tx );
  FD_TEST( fd_keepalive_is_timeout( state->conn->keepalive, ts_ping_tx )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->conn->keepalive, ts_ping_tx )==0 );

  /* PING ACK should update timer */
  g_clock += (long)10e6; /* 10ms passed */
  long const ts_ping_rx = g_clock;
  grpc_client->conn->ping_tx = 1;
  fd_h2_frame_hdr_t ping_ack_hdr = {
    .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ),
    .flags  = FD_H2_FLAG_ACK
  };
  fd_h2_rbuf_push( grpc_client->frame_rx, &ping_ack_hdr, sizeof(fd_h2_frame_hdr_t) );
  ulong const ping_seq = 1UL;
  fd_h2_rbuf_push( grpc_client->frame_rx, &ping_seq, sizeof(ulong) );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_rx )==0UL );
  FD_TEST( grpc_client->conn->ping_tx == 0 );
  FD_TEST( state->conn->defer_reset==0 );
  FD_TEST( state->conn->keepalive->ts_last_tx==ts_ping_tx );
  FD_TEST( state->conn->keepalive->ts_last_rx==ts_ping_rx );
  FD_TEST( !state->conn->keepalive->inflight );
  FD_TEST( state->metrics.ping_ack_cnt==1UL );
  FD_TEST( state->conn->rtt->latest_rtt==10e6f );
  FD_TEST( fd_keepalive_is_timeout( state->conn->keepalive, ts_ping_rx )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->conn->keepalive, ts_ping_rx )==0 );

  /* Test PING TX */
  g_clock = state->conn->keepalive->ts_next_tx;
  long const ts_ping_tx2 = g_clock;
  FD_TEST( fd_keepalive_is_timeout( state->conn->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->conn->keepalive, ts_ping_tx2 )==1 );
  FD_TEST( state->conn->keepalive->inflight==0 );
  charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->defer_reset==0 );
  FD_TEST( fd_keepalive_is_timeout( state->conn->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->conn->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( state->conn->keepalive->inflight==1 );
  FD_TEST( charge_busy==1 );
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )==0 ); /* flushed in-step */
  fd_h2_rbuf_t * wire = wire_rx( env );
  FD_TEST( fd_h2_rbuf_used_sz( wire )==sizeof(fd_h2_ping_t) );
  fd_h2_ping_t ping;
  fd_h2_rbuf_pop_copy( wire, &ping, sizeof(fd_h2_ping_t) );
  FD_TEST( ping.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ) );
  FD_TEST( ping.hdr.flags==0 );
  FD_TEST( state->conn->keepalive->inflight==1 );
  charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( charge_busy==0 );
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )==0 );

  /* Test timeout */
  g_clock = state->conn->keepalive->ts_deadline + 1L;
  long const ts_ping_timeout = g_clock;
  FD_TEST( fd_keepalive_is_timeout( state->conn->keepalive, ts_ping_timeout )==1 );

  /* Stepping should cause a reset due to timeout */
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Check the client's behavior if an oversized message is received */

FD_UNIT_TEST( bundle_msg_oversized ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->conn->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;

  fd_h2_conn_t * h2_conn = fd_grpc_client_h2_conn( state->conn->grpc_client );
  fd_grpc_hdr_t hdr = {
    .compressed = 0,
    .msg_sz     = fd_uint_bswap( USHORT_MAX )
  };

  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live );
  fd_grpc_client_h2_callbacks.data( h2_conn, &stream->s, &hdr, sizeof(fd_grpc_hdr_t), 0UL );
  FD_TEST( !state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live );
  FD_TEST( state->conn->defer_reset );

  test_bundle_env_destroy( env );
}

/* Ensure that the client disconnects and halts signing while switching keys */

FD_UNIT_TEST( bundle_keyswitch ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;

  void * keyswitch_mem = fd_wksp_alloc_laddr( wksp, fd_keyswitch_align(), fd_keyswitch_footprint(), 1UL );
  FD_TEST( keyswitch_mem );
  state->keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  memset( state->conn->auther.pubkey, 0, 32 );

  fd_bundle_tile_housekeeping( state ); /* should not switch */
  FD_TEST( !state->conn->defer_reset );

  fd_keyswitch_state( state->keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  state->keyswitch->bytes[0] = 0x01;
  fd_bundle_tile_housekeeping( state ); /* should halt and install the new public key */
  FD_TEST( state->conn->tcp_sock==-1 );
  FD_TEST( state->halt_signing );
  FD_TEST( fd_keyswitch_state_query( state->keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( !state->conn->defer_reset );
  FD_TEST( state->conn->auther.pubkey[0]==0x01 && state->identity_pubkey[0]==0x01 );

  state->sleep_check_ns = 1L;
  fd_keyswitch_state( state->keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  fd_bundle_tile_housekeeping( state ); /* should resume with the new public key */
  FD_TEST( !state->halt_signing );
  FD_TEST( state->conn->defer_reset );
  FD_TEST( state->sleep_check_ns==0L );
  FD_TEST( fd_keyswitch_state_query( state->keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( state->conn->auther.pubkey[0]==0x01 && state->identity_pubkey[0]==0x01 );

  test_bundle_env_destroy( env );
  fd_wksp_free_laddr( keyswitch_mem );
}

/* Verify that the bundle client status is reported correctly */

FD_UNIT_TEST( bundle_client_status ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;
  fd_bundle_tile_t state_backup  = *state;
  fd_grpc_client_t client_backup = *state->conn->grpc_client;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->conn->tcp_sock_connected = 0;
  FD_TEST( fd_bundle_client_status( state )==0 );
  *state = state_backup;

  ushort const conn_dead_flags[] = {
    FD_H2_CONN_FLAGS_DEAD,
    FD_H2_CONN_FLAGS_SEND_GOAWAY
  };
  for( ulong i=0; i<sizeof(conn_dead_flags)/sizeof(ushort); i++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->conn->grpc_client->conn->flags |= conn_dead_flags[ i ];
    FD_TEST( fd_bundle_client_status( state )==0 );
    *state->conn->grpc_client = client_backup;
  }

  ushort const conn_prog_flags[] = {
    FD_H2_CONN_FLAGS_CLIENT_INITIAL,
    FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0,
    FD_H2_CONN_FLAGS_WAIT_SETTINGS_0,
    FD_H2_CONN_FLAGS_SERVER_INITIAL
  };
  for( ulong i=0; i<sizeof(conn_prog_flags)/sizeof(ushort); i++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->conn->grpc_client->conn->flags |= conn_prog_flags[ i ];
    FD_TEST( fd_bundle_client_status( state )==1 );
    *state->conn->grpc_client = client_backup;
  }

  for( int auth_state=0; auth_state<FD_BUNDLE_AUTH_STATE_DONE_WAIT; auth_state++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->conn->auther.state = auth_state;
    FD_TEST( fd_bundle_client_status( state )==1 );
    state->conn->auther.state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  }

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->conn->builder.wait = 1;
  FD_TEST( fd_bundle_client_status( state )==2 ); /* rotate builder info without downtime */
  state->conn->auther.state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->conn->builder.avail = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].live = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->conn->keepalive->inflight     = 1;
  state->conn->keepalive->ts_deadline -= g_clock-1L;
  FD_TEST( fd_bundle_client_status( state )==0 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->conn->grpc_client->h2_hs_done = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state->conn->grpc_client = client_backup;

  test_bundle_env_destroy( env );
}

/* Verify that reset clears everything */

FD_UNIT_TEST( bundle_client_reset ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;

  FD_TEST( state->conn->tcp_sock!=-1 );
  FD_TEST( state->conn->tcp_sock_connected==1 );
  FD_TEST( state->conn->defer_reset==0 );
  FD_TEST( state->conn->builder.avail==1 );
  FD_TEST( state->conn->builder.wait==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].live==1 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live==1 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==0 );
  FD_TEST( state->conn->rtt->is_rtt_valid==0 );
  FD_TEST( state->conn->auther.state==FD_BUNDLE_AUTH_STATE_DONE_WAIT );
  FD_TEST( state->conn->auther.needs_poll==0 );
  FD_TEST( state->conn->grpc_client->h2_hs_done==1 );
  FD_TEST( state->conn->grpc_client->stream_cnt==2 );
  state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live = 1;
  state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].wait = 1;
  state->conn->strategy_set                     = 1;
  state->conn->strategy_wait                    = 1;

  fd_bundle_client_reset( state );

  FD_TEST( state->conn->tcp_sock==-1 );
  FD_TEST( state->conn->tcp_sock_connected==0 );
  FD_TEST( state->conn->defer_reset==0 );
  FD_TEST( state->conn->builder.avail==0 );
  FD_TEST( state->conn->builder.wait==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].live==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].wait==0 );
  FD_TEST( state->conn->strategy_set==0 );
  FD_TEST( state->conn->strategy_wait==0 );
  FD_TEST( state->conn->rtt->is_rtt_valid==0 );
  FD_TEST( state->conn->auther.state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
  FD_TEST( state->conn->auther.needs_poll==1 );
  FD_TEST( state->conn->grpc_client->h2_hs_done==0 );
  FD_TEST( state->conn->grpc_client->stream_cnt==0 );

  test_bundle_env_destroy( env );
}

/* Utility to parse a request header */

static void
expect_h2_hdr( fd_h2_rbuf_t *       rbuf,
               ulong                stream_id,
               char const * const * pstr ) {
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( rbuf )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( rbuf, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_HEADERS );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_HEADERS );

  uchar frame_body[ 512 ];
  ulong frame_sz = fd_h2_frame_length( frame_hdr.typlen );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf )>=frame_sz );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf )<=sizeof(frame_body) );
  fd_h2_rbuf_pop_copy( rbuf, frame_body, frame_sz );

  fd_hpack_rd_t hpack_rd[1];
  FD_TEST( fd_hpack_rd_init( hpack_rd, frame_body, frame_sz ) );

  while( *pstr ) {
    char const * exp_name = *(pstr++);
    char const * exp_val  = *(pstr++);
    fd_h2_hdr_t hdr;
    uchar scratch[ 128 ];
    uchar * pscratch = scratch;
    FD_TEST( !fd_hpack_rd_done( hpack_rd ) );
    FD_TEST( fd_hpack_rd_next( hpack_rd, &hdr, &pscratch, scratch+sizeof(scratch) )==FD_H2_SUCCESS );

    FD_LOG_DEBUG(( "Header: %.*s: %.*s",
                   (int)hdr.name_len,  hdr.name,
                   (int)hdr.value_len, hdr.value ));
    FD_TEST( hdr.name_len ==strlen( exp_name ) && 0==memcmp( hdr.name, exp_name, hdr.name_len  ) );
    FD_TEST( hdr.value_len==strlen( exp_val  ) && 0==memcmp( hdr.value, exp_val, hdr.value_len ) );
  }
  FD_TEST( fd_hpack_rd_done( hpack_rd ) );
}

/* Verify that the client requests builder fee info */

FD_UNIT_TEST( bundle_client_request_builder_fee_info ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->conn->grpc_client;

  /* Client should request new builder info */
  state->conn->builder.avail = 0;
  state->conn->builder.next  = 0L;
  FD_TEST( state->conn->builder.wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==0 );
  FD_TEST( state->conn->grpc_client->stream_cnt==2 );
  state->conn->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->builder.wait==0 );

  /* Unblock it ... */
  state->conn->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->builder.wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->conn->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->conn->grpc_client->stream_pool[ 2 ];
  FD_TEST( stream->s.stream_id==stream_id );
  FD_TEST( stream->request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );

  /* Request header */
  char const * const hdrs[] = {
    ":method",      "POST",
    ":scheme",      "https",
    ":path",        "/block_engine.BlockEngineValidator/GetBlockBuilderFeeInfo",
    "te",           "trailers",
    "content-type", "application/grpc+proto",
    "user-agent",   "grpc-firedancer/0.0.0",
    NULL
  };
  fd_h2_rbuf_t * wire = wire_rx( env );
  expect_h2_hdr( wire, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( wire )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( wire, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( wire )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( wire, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  fd_bundle_client_grpc_rx_start( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );

  uchar prev_builder_pubkey[ 32 ];
  for( ulong i=0UL; i<sizeof(prev_builder_pubkey); i++ ) prev_builder_pubkey[ i ] = (uchar)( i + 1U );
  fd_memcpy( state->conn->builder.pubkey, prev_builder_pubkey, sizeof(prev_builder_pubkey) );
  uchar prev_builder_commission = 11U;
  state->conn->builder.commission = prev_builder_commission;
  long prev_builder_next = 123456789L;
  state->conn->builder.next = prev_builder_next;

  /* Protobuf encoder util */
  uchar pb_buf[ 128 ];
  ulong pb_sz = 0UL;
  block_engine_BlockBuilderFeeInfoResponse resp = block_engine_BlockBuilderFeeInfoResponse_init_default;
#define ENCODE_MSG() do { \
    pb_ostream_t ostream = pb_ostream_from_buffer( pb_buf, sizeof(pb_buf) ); \
    FD_TEST( pb_encode( &ostream, &block_engine_BlockBuilderFeeInfoResponse_msg, &resp ) ); \
    pb_sz = ostream.bytes_written; \
  } while(0)

  /* Invalid Base58 and decoded zero keys leave metadata unavailable. */
  char const * invalid_pubkeys[] = { "hello", "11111111111111111111111111111111" };
  resp.commission = 2;
  for( ulong i=0UL; i<2UL; i++ ) {
    strcpy( resp.pubkey, invalid_pubkeys[i] );
    ENCODE_MSG();
    fd_bundle_client_grpc_rx_msg( state->conn, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
    FD_TEST( state->conn->builder.avail==0 && state->conn->builder.wait==1 );
    FD_TEST( state->conn->builder.commission==prev_builder_commission );
    FD_TEST( fd_memeq( state->conn->builder.pubkey, prev_builder_pubkey, sizeof(prev_builder_pubkey) ) );
    FD_TEST( state->conn->builder.next==prev_builder_next );
  }

  /* Invalid commission */
  uchar const pubkey[32] = { 1,2,3,4,5 };
  fd_base58_encode_32( pubkey, NULL, resp.pubkey );
  resp.commission = 101;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state->conn, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->conn->builder.avail==0 );
  FD_TEST( state->conn->builder.wait==1 ); /* retry ... */
  FD_TEST( state->conn->builder.commission==prev_builder_commission );
  FD_TEST( 0==memcmp( state->conn->builder.pubkey, prev_builder_pubkey, sizeof(prev_builder_pubkey) ) );
  FD_TEST( state->conn->builder.next==prev_builder_next );

  /* Valid response */
  resp.commission = 2;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state->conn, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->conn->builder.avail==1 );
  FD_TEST( state->conn->builder.wait==1 );
  FD_TEST( state->conn->builder.commission==2U );
  uchar decoded_builder_pubkey[ 32 ];
  FD_TEST( fd_base58_decode_32( resp.pubkey, decoded_builder_pubkey ) );
  FD_TEST( 0==memcmp( state->conn->builder.pubkey, decoded_builder_pubkey, sizeof(decoded_builder_pubkey) ) );
  FD_TEST( state->conn->builder.next!=prev_builder_next );

  /* Preserve the last valid metadata when a later response has a zero
     key, just as for an invalid Base58 response. */
  long valid_until = state->conn->builder.next;
  strcpy( resp.pubkey, "11111111111111111111111111111111" );
  resp.commission = 3;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state->conn, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->conn->builder.avail==1 && state->conn->builder.wait==1 );
  FD_TEST( state->conn->builder.commission==2U );
  FD_TEST( fd_memeq( state->conn->builder.pubkey, decoded_builder_pubkey, sizeof(decoded_builder_pubkey) ) );
  FD_TEST( state->conn->builder.next==valid_until );
  fd_base58_encode_32( prev_builder_pubkey, NULL, resp.pubkey );
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state->conn, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->conn->builder.avail==1 && state->conn->builder.commission==3U );
  FD_TEST( fd_memeq( state->conn->builder.pubkey, prev_builder_pubkey, sizeof(prev_builder_pubkey) ) );

  /* End stream */
  fd_grpc_resp_hdrs_t grpc_resp_hdrs = {
    .h2_status   = 200,
    .grpc_status = FD_GRPC_STATUS_OK
  };
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo, &grpc_resp_hdrs );
  FD_TEST( state->conn->builder.wait==0 );

#undef ENCODE_MSG

  test_bundle_env_destroy( env );
}

/* Verify that the client subscribes to packets */

FD_UNIT_TEST( bundle_client_subscribe_packets ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->conn->grpc_client;

  state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].live = 0;
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==0 );
  FD_TEST( state->conn->grpc_client->stream_cnt==2 );
  state->conn->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==0 );

  /* Unblock it ... */
  state->conn->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->conn->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->conn->grpc_client->stream_pool[ 2 ];
  FD_TEST( stream->s.stream_id==stream_id );
  FD_TEST( stream->request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );

  /* Request header */
  char const * const hdrs[] = {
    ":method",      "POST",
    ":scheme",      "https",
    ":path",        "/block_engine.BlockEngineValidator/SubscribePackets",
    "te",           "trailers",
    "content-type", "application/grpc+proto",
    "user-agent",   "grpc-firedancer/0.0.0",
    NULL
  };
  fd_h2_rbuf_t * wire = wire_rx( env );
  expect_h2_hdr( wire, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( wire )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( wire, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( wire )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( wire, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==1 );
  fd_bundle_client_grpc_rx_start( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==0 );

  test_bundle_env_destroy( env );
}

/* Verify that the client subscribes to bundles */

FD_UNIT_TEST( bundle_client_subscribe_bundles ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->conn->grpc_client;

  state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live = 0;
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==0 );
  FD_TEST( state->conn->grpc_client->stream_cnt==2 );
  state->conn->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==0 );

  /* Unblock it ... */
  state->conn->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->conn->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->conn->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->conn->grpc_client->stream_pool[ 2 ];
  FD_TEST( stream->s.stream_id==stream_id );
  FD_TEST( stream->request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );

  /* Request header */
  char const * const hdrs[] = {
    ":method",      "POST",
    ":scheme",      "https",
    ":path",        "/block_engine.BlockEngineValidator/SubscribeBundles",
    "te",           "trailers",
    "content-type", "application/grpc+proto",
    "user-agent",   "grpc-firedancer/0.0.0",
    NULL
  };
  fd_h2_rbuf_t * wire = wire_rx( env );
  expect_h2_hdr( wire, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( wire )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( wire, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( wire )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( wire, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==1 );
  fd_bundle_client_grpc_rx_start( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==0 );

  test_bundle_env_destroy( env );
}

/* Pops the header frame of a request for path off the wire */

static void
expect_request_hdr( fd_h2_rbuf_t * wire,
                    ulong          stream_id,
                    char const *   path ) {
  char const * const hdrs[] = {
    ":method",      "POST",
    ":scheme",      "https",
    ":path",        path,
    "te",           "trailers",
    "content-type", "application/grpc+proto",
    "user-agent",   "grpc-firedancer/0.0.0",
    NULL
  };
  expect_h2_hdr( wire, stream_id, hdrs );
}

/* Pops one DATA frame holding a single gRPC message off the wire and
   decodes the message into msg */

static void
expect_msg( fd_h2_rbuf_t *       wire,
            ulong                stream_id,
            uint                 flags,
            pb_msgdesc_t const * fields,
            void *               msg ) {
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( wire )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( wire, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==flags );

  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( wire )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( wire, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  ulong msg_sz = fd_uint_bswap( grpc_hdr.msg_sz );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==sizeof(fd_grpc_hdr_t)+msg_sz );

  uchar body[ 256 ];
  FD_TEST( msg_sz<=sizeof(body) && fd_h2_rbuf_used_sz( wire )>=msg_sz );
  fd_h2_rbuf_pop_copy( wire, body, msg_sz );
  pb_istream_t istream = pb_istream_from_buffer( body, msg_sz );
  FD_TEST( pb_decode( &istream, fields, msg ) );
}

/* Pops a unary request off the wire and decodes its message into msg */

static void
expect_request( fd_h2_rbuf_t *       wire,
                ulong                stream_id,
                char const *         path,
                pb_msgdesc_t const * fields,
                void *               msg ) {
  expect_request_hdr( wire, stream_id, path );
  expect_msg( wire, stream_id, FD_H2_FLAG_END_STREAM, fields, msg );
}

/* Verify that a Harmonic client sets the scheduling strategy, and only
   subscribes once the block engine acknowledged it */

FD_UNIT_TEST( bundle_client_harmonic_set_strategy ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state = env->state;
  state->protocol                                = FD_BUNDLE_PROTOCOL_HARMONIC;
  state->strategy                                = FD_BUNDLE_STRATEGY_MREV;
  state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].live = 0;

  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->strategy_wait==1 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==0 );

  ulong const stream_id = state->conn->grpc_client->stream_ids[ 2 ];
  FD_TEST( state->conn->grpc_client->stream_pool[ 2 ].request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy );
  block_engine_SetStrategyRequest req = block_engine_SetStrategyRequest_init_default;
  expect_request( wire_rx( env ), stream_id, "/block_engine.BlockEngineValidator/SetStrategy",
                  &block_engine_SetStrategyRequest_msg, &req );
  FD_TEST( req.strategy==block_engine_SchedulingStrategy_SCHEDULING_STRATEGY_MREV );

  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==0 );

  /* A rejected strategy is retried */
  fd_grpc_resp_hdrs_t hdrs = { .h2_status = 200, .grpc_status = FD_GRPC_STATUS_INVALID_ARGUMENT };
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy, &hdrs );
  FD_TEST( state->conn->strategy_wait==0 && state->conn->strategy_set==0 );

  state->conn->strategy_wait = 1;
  hdrs.grpc_status = FD_GRPC_STATUS_OK;
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy, &hdrs );
  FD_TEST( state->conn->strategy_wait==0 && state->conn->strategy_set==1 );

  test_bundle_env_destroy( env );
}

/* Verify that a Harmonic client subscribes to blocks, and that the
   connection is only healthy while the block stream is live */

FD_UNIT_TEST( bundle_client_harmonic_subscribe_blocks ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state = env->state;
  state->protocol           = FD_BUNDLE_PROTOCOL_HARMONIC;
  state->conn->strategy_set = 1;
  FD_TEST( fd_bundle_client_status( state )==FD_BUNDLE_STATE_CONNECTING );

  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].wait==1 );

  ulong const stream_id = state->conn->grpc_client->stream_ids[ 2 ];
  FD_TEST( state->conn->grpc_client->stream_pool[ 2 ].request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks );
  block_engine_SubscribeBlocksRequest req = block_engine_SubscribeBlocksRequest_init_default;
  expect_request( wire_rx( env ), stream_id, "/block_engine.BlockEngineValidator/SubscribeBlocks2",
                  &block_engine_SubscribeBlocksRequest_msg, &req );
  FD_TEST( !strncmp( req.version,     fd_version_cstr,    sizeof(req.version)-1     ) );
  FD_TEST( !strncmp( req.commit_hash, fd_commit_ref_cstr, sizeof(req.commit_hash)-1 ) );

  fd_bundle_client_grpc_rx_start( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live==1 && state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].wait==0 );
  FD_TEST( fd_bundle_client_status( state )==FD_BUNDLE_STATE_CONNECTED );

  /* The block stream ending forces a reconnect */
  fd_grpc_resp_hdrs_t hdrs = { .h2_status = 200, .grpc_status = FD_GRPC_STATUS_OK };
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks, &hdrs );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live==0 );
  FD_TEST( state->conn->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Verify that a Harmonic client sends the queued leader window notice
   ahead of other requests once the block stream is live, and drops it
   once the slot has ended */

FD_UNIT_TEST( bundle_client_harmonic_leader_window ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state = env->state;
  state->protocol                               = FD_BUNDLE_PROTOCOL_HARMONIC;
  state->conn->strategy_set                     = 1;
  state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live = 1;

  long const end_ns = g_clock + (long)1e9 + 7L;
  state->harmonic.leader_window_pending = 1;
  state->harmonic.leader_window_slot    = 500UL;
  state->harmonic.leader_window_end_ns  = end_ns;

  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( !state->harmonic.leader_window_pending );

  ulong const stream_id = state->conn->grpc_client->stream_ids[ 2 ];
  FD_TEST( state->conn->grpc_client->stream_pool[ 2 ].request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SubmitLeaderWindowInfo );
  block_engine_SubmitLeaderWindowInfoRequest req = block_engine_SubmitLeaderWindowInfoRequest_init_default;
  expect_request( wire_rx( env ), stream_id, "/block_engine.BlockEngineValidator/SubmitLeaderWindowInfo",
                  &block_engine_SubmitLeaderWindowInfoRequest_msg, &req );
  FD_TEST( req.slot==500UL );
  FD_TEST( req.has_start_timestamp );
  FD_TEST( req.has_end_timestamp );
  FD_TEST( req.end_timestamp.seconds==end_ns/(long)1e9 && req.end_timestamp.nanos==(int)( end_ns%(long)1e9 ) );

  /* The empty response is accepted */
  fd_bundle_client_grpc_rx_msg( state->conn, NULL, 0UL, FD_BUNDLE_CLIENT_REQ_Bundle_SubmitLeaderWindowInfo );

  /* A notice for a slot that already ended is dropped unsent */
  ulong stream_cnt = state->conn->grpc_client->stream_cnt;
  state->harmonic.leader_window_pending = 1;
  state->harmonic.leader_window_slot    = 501UL;
  state->harmonic.leader_window_end_ns  = g_clock;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( !state->harmonic.leader_window_pending );
  FD_TEST( state->conn->grpc_client->stream_cnt==stream_cnt );

  /* A notice waits for the block stream */
  state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live = 0;
  state->harmonic.leader_window_pending         = 1;
  state->harmonic.leader_window_slot            = 502UL;
  state->harmonic.leader_window_end_ns          = end_ns;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->harmonic.leader_window_pending );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].wait );

  test_bundle_env_destroy( env );
}

/* Hands the client a Block for slot as a SubscribeBlocks2 message.
   Transaction i is the single byte i, in bundle bundle_ids[ i ]. */

typedef struct {
  ulong const * bundle_ids;
  ulong         cnt;
} test_block_txns_t;

static bool
test_encode_block_txns( pb_ostream_t *     stream,
                        pb_field_t const * field,
                        void * const *     arg ) {
  test_block_txns_t const * txns = *arg;
  for( ulong i=0UL; i<txns->cnt; i++ ) {
    block_Transaction txn = block_Transaction_init_default;
    txn.transaction.bytes[ 0 ] = (uchar)i;
    txn.transaction.size       = 1U;
    txn.bundle_id              = txns->bundle_ids[ i ];
    if( !pb_encode_tag_for_field( stream, field ) || !pb_encode_submessage( stream, &block_Transaction_msg, &txn ) ) return false;
  }
  return true;
}

static void
test_rx_block( fd_bundle_tile_t * state,
               ulong              slot,
               ulong const *      bundle_ids,
               ulong              cnt ) {
  test_block_txns_t txns  = { .bundle_ids = bundle_ids, .cnt = cnt };
  block_Block       block = block_Block_init_default;
  block.slot         = slot;
  block.transactions = (pb_callback_t) { .funcs.encode = test_encode_block_txns, .arg = &txns };
  static uchar buf[ 4096 ];
  pb_ostream_t ostream = pb_ostream_from_buffer( buf, sizeof(buf) );
  FD_TEST( pb_encode( &ostream, &block_Block_msg, &block ) );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, ostream.bytes_written, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks );
}

/* Verify that Block transactions are grouped into numbered bundles */

FD_UNIT_TEST( bundle_client_harmonic_block ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * const state = env->state;
  state->protocol           = FD_BUNDLE_PROTOCOL_HARMONIC;
  state->leader_state->slot = 500UL;
  ulong const seq0 = state->bundle_seq;

  /* A standalone transaction, a two transaction bundle, and another
     standalone transaction */
  ulong const ids[] = { 0UL, 7UL, 7UL, 0UL };
  test_rx_block( state, 500UL, ids, 4UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==4UL );
  static struct { ulong seq; ulong txn_cnt; uchar atomic; } const want[] = {
    { 1UL, 1UL, 0 }, { 2UL, 2UL, 1 }, { 2UL, 2UL, 1 }, { 3UL, 1UL, 0 }
  };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_bundle_pending_txn_t const * e = pending_txn_peek_index_const( state->pending_txns, i );
    FD_TEST( e->payload_sz==1 && e->payload[ 0 ]==(uchar)i && e->sig==1UL );
    FD_TEST( e->bundle_seq==seq0+want[ i ].seq && e->bundle_txn_cnt==want[ i ].txn_cnt );
    FD_TEST( e->block_slot==500UL && e->block_seq==want[ i ].seq && e->atomic==want[ i ].atomic );
  }

  /* A Block for another slot is dropped, without using up this slot's
     sequence */
  test_rx_block( state, 499UL, ids, 4UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==4UL );
  FD_TEST( state->harmonic.block_seq==3UL );

  /* A bundle too large for pack is dropped, keeping its sequence number */
  ulong const big[] = { 9UL, 9UL, 9UL, 9UL, 9UL, 9UL, 0UL };
  test_rx_block( state, 500UL, big, 7UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );
  fd_bundle_pending_txn_t const * last = pending_txn_peek_index_const( state->pending_txns, 4UL );
  FD_TEST( last->payload[ 0 ]==6 && last->block_seq==5UL && last->bundle_txn_cnt==1UL );

  /* A new leader slot restarts the sequence */
  state->leader_state->slot = 501UL;
  fd_bundle_client_leader_state_update( state, 1 );
  FD_TEST( state->harmonic.block_seq==0UL );

  test_bundle_env_destroy( env );
}

/* Verify that a reset while the block is streaming drops the rest of
   that slot's block, but not later slots */

FD_UNIT_TEST( bundle_client_harmonic_block_reset ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state = env->state;
  state->protocol                    = FD_BUNDLE_PROTOCOL_HARMONIC;
  state->leader_state->slot          = 500UL;
  state->leader_state->slot_end_ns   = g_clock + (long)1e9;
  ulong const ids[] = { 0UL };

  /* After the slot ends, a reset loses nothing */
  state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live = 1;
  state->leader_state->slot_end_ns              = g_clock;
  fd_bundle_client_reset( state );
  FD_TEST( state->harmonic.block_lost_slot==ULONG_MAX );

  /* Without a live block stream, a reset loses nothing */
  state->leader_state->slot_end_ns = g_clock + (long)1e9;
  fd_bundle_client_reset( state );
  FD_TEST( state->harmonic.block_lost_slot==ULONG_MAX );

  state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live = 1;
  fd_bundle_client_reset( state );
  FD_TEST( state->harmonic.block_lost_slot==500UL );
  FD_TEST( !state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live );

  test_rx_block( state, 500UL, ids, 1UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  state->leader_state->slot = 501UL;
  fd_bundle_client_leader_state_update( state, 1 );
  test_rx_block( state, 501UL, ids, 1UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );

  test_bundle_env_destroy( env );
}

/* Verify that a Harmonic client subscribes to bundles with
   SubscribeBundles2 */

FD_UNIT_TEST( bundle_client_harmonic_subscribe_bundles ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state = env->state;
  state->protocol                                = FD_BUNDLE_PROTOCOL_HARMONIC;
  state->conn->strategy_set                      = 1;
  state->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live  = 1;
  state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live = 0;

  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==1 );

  ulong const stream_id = state->conn->grpc_client->stream_ids[ 2 ];
  FD_TEST( state->conn->grpc_client->stream_pool[ 2 ].request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  block_engine_SubscribeBundlesRequest req = block_engine_SubscribeBundlesRequest_init_default;
  expect_request( wire_rx( env ), stream_id, "/block_engine.BlockEngineValidator/SubscribeBundles2",
                  &block_engine_SubscribeBundlesRequest_msg, &req );

  test_bundle_env_destroy( env );
}

static ulong
test_encode( uchar *              buf,
             ulong                buf_sz,
             pb_msgdesc_t const * fields,
             void const *         msg ) {
  pb_ostream_t ostream = pb_ostream_from_buffer( buf, buf_sz );
  FD_TEST( pb_encode( &ostream, fields, msg ) );
  return ostream.bytes_written;
}

/* A mock sign tile behind the tile's keyguard client.  The response to
   the first signing request is published up front, so signing returns
   at once. */

#define TEST_SIGN_DEPTH (16UL)

typedef struct {
  fd_frag_meta_t * req_mcache;
  uchar *          req_dcache;
  fd_frag_meta_t * resp_mcache;
  uchar *          resp_dcache;
} test_sign_t;

static void *
test_alloc( ulong align,
            ulong sz ) {
  void * mem = fd_wksp_alloc_laddr( wksp, align, sz, 1UL );
  FD_TEST( mem );
  return mem;
}

static void
test_sign_create( test_sign_t *      sign,
                  fd_bundle_tile_t * ctx,
                  uchar const        signature[ 64 ] ) {
  ulong const req_data_sz  = fd_dcache_req_data_sz( FD_KEYGUARD_BAM_AUTH_MTU, TEST_SIGN_DEPTH, 1UL, 1 );
  ulong const resp_data_sz = fd_dcache_req_data_sz( 64UL,                     TEST_SIGN_DEPTH, 1UL, 1 );
  sign->req_mcache  = fd_mcache_join( fd_mcache_new( test_alloc( fd_mcache_align(), fd_mcache_footprint( TEST_SIGN_DEPTH, 0UL ) ), TEST_SIGN_DEPTH, 0UL, 0UL ) );
  sign->resp_mcache = fd_mcache_join( fd_mcache_new( test_alloc( fd_mcache_align(), fd_mcache_footprint( TEST_SIGN_DEPTH, 0UL ) ), TEST_SIGN_DEPTH, 0UL, 0UL ) );
  sign->req_dcache  = fd_dcache_join( fd_dcache_new( test_alloc( fd_dcache_align(), fd_dcache_footprint( req_data_sz,  0UL ) ), req_data_sz,  0UL ) );
  sign->resp_dcache = fd_dcache_join( fd_dcache_new( test_alloc( fd_dcache_align(), fd_dcache_footprint( resp_data_sz, 0UL ) ), resp_data_sz, 0UL ) );
  FD_TEST( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client, sign->req_mcache, sign->req_dcache, sign->resp_mcache, sign->resp_dcache,
                                                            FD_KEYGUARD_BAM_AUTH_MTU, 64UL, NULL, 0UL, ULONG_MAX ) ) );

  ulong chunk = fd_dcache_compact_chunk0( wksp, sign->resp_dcache );
  fd_memcpy( fd_chunk_to_laddr( wksp, chunk ), signature, 64UL );
  fd_mcache_publish( sign->resp_mcache, TEST_SIGN_DEPTH, 0UL, 0UL, chunk, 64UL, 0UL, 0UL, 0UL );
}

static void
test_sign_destroy( test_sign_t * sign ) {
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( sign->req_mcache  ) ) );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( sign->resp_mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( sign->req_dcache  ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( sign->resp_dcache ) ) );
}

static void
test_rx_bam_heartbeat( fd_bundle_tile_t * state ) {
  bam_api_SchedulerResponse resp = {
    .which_versioned_msg = bam_api_SchedulerResponse_v0_tag,
    .versioned_msg.v0    = { .which_resp = bam_api_SchedulerResponseV0_heart_beat_tag }
  };
  uchar buf[ 64 ];
  ulong sz = test_encode( buf, sizeof(buf), &bam_api_SchedulerResponse_msg, &resp );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream );
}

/* Verify the BAM session: the client logs in with a signed challenge as
   the first message of the scheduler stream, sends heartbeats, answers
   pings, and polls the builder config once the node accepted the
   stream */

FD_UNIT_TEST( bam_client_session ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn_empty( env );
  fd_bundle_tile_t * const state  = env->state;
  fd_grpc_client_t * const client = state->conn->grpc_client;
  test_bundle_env_mock_h2_hs( state );
  state->protocol                  = FD_BUNDLE_PROTOCOL_BAM;
  state->conn->keepalive->interval = 0L; /* keep HTTP/2 PINGs off the wire */
  for( ulong i=0UL; i<32UL; i++ ) state->identity_pubkey[ i ] = (uchar)( i+1UL );

  uchar signature[ 64 ];
  fd_memset( signature, 0x11, sizeof(signature) );
  test_sign_t sign[1];
  test_sign_create( sign, state, signature );

  uchar                  buf[ 512 ];
  int                    charge_busy = 0;
  fd_grpc_resp_hdrs_t    ok          = { .h2_status = 200, .grpc_status = FD_GRPC_STATUS_OK };
  bam_api_SchedulerMessage msg;

  /* Request a challenge */
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->bam.challenge_wait );
  bam_api_AuthChallengeRequest challenge_req;
  expect_request( wire_rx( env ), client->stream_ids[ client->stream_cnt-1UL ], "/bam_api.BamNodeApi/GetAuthChallenge",
                  &bam_api_AuthChallengeRequest_msg, &challenge_req );

  bam_api_AuthChallengeResponse challenge = { .challenge_to_sign = "challenge-abc" };
  ulong sz = test_encode( buf, sizeof(buf), &bam_api_AuthChallengeResponse_msg, &challenge );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge );
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge, &ok );
  FD_TEST( !state->bam.challenge_wait && !strcmp( state->bam.challenge, "challenge-abc" ) );

  /* Sign the labeled challenge and open the stream with the proof */
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->bam.stream && !state->bam.challenge[ 0 ] );
  fd_frag_meta_t const * req = sign->req_mcache + fd_mcache_line_idx( 0UL, TEST_SIGN_DEPTH );
  FD_TEST( req->sig==FD_KEYGUARD_SIGN_TYPE_ED25519 && req->sz==FD_KEYGUARD_BAM_AUTH_LABEL_SZ+13UL );
  FD_TEST( fd_memeq( fd_chunk_to_laddr( wksp, req->chunk ), FD_KEYGUARD_BAM_AUTH_LABEL "\0challenge-abc", req->sz ) );

  ulong const    stream_id = state->bam.stream->s.stream_id;
  fd_h2_rbuf_t * wire      = wire_rx( env );
  expect_request_hdr( wire, stream_id, "/bam_api.BamNodeApi/InitSchedulerStream" );
  expect_msg( wire, stream_id, 0U, &bam_api_SchedulerMessage_msg, &msg );
  FD_TEST( msg.which_versioned_msg==bam_api_SchedulerMessage_v0_tag );
  FD_TEST( msg.versioned_msg.v0.which_msg==bam_api_SchedulerMessageV0_auth_proof_tag );
  bam_types_AuthProof const * proof = &msg.versioned_msg.v0.msg.auth_proof;
  char b58[ FD_BASE58_ENCODED_64_SZ ];
  FD_TEST( !strcmp( proof->challenge_to_sign, "challenge-abc" ) );
  FD_TEST( !strcmp( proof->validator_pubkey,  fd_base58_encode_32( state->identity_pubkey, NULL, b58 ) ) );
  FD_TEST( !strcmp( proof->signature,         fd_base58_encode_64( signature,            NULL, b58 ) ) );

  /* A heartbeat follows right away, then nothing until the node accepts
     the stream */
  g_clock += (long)1e9;
  fd_bundle_client_step( state, &charge_busy );
  expect_msg( wire_rx( env ), stream_id, 0U, &bam_api_SchedulerMessage_msg, &msg );
  FD_TEST( msg.versioned_msg.v0.which_msg==bam_api_SchedulerMessageV0_heart_beat_tag );
  FD_TEST( msg.versioned_msg.v0.msg.heart_beat.time_sent_microseconds==(ulong)g_clock/1000UL );
  FD_TEST( state->bam.heartbeat_next==g_clock+(long)5e9 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( !fd_h2_rbuf_used_sz( wire_rx( env ) ) );
  FD_TEST( fd_bundle_client_status( state )==FD_BUNDLE_STATE_CONNECTING );

  /* The node accepts the stream with a ping, answered with a pong */
  bam_api_SchedulerResponse resp = {
    .which_versioned_msg = bam_api_SchedulerResponse_v0_tag,
    .versioned_msg.v0    = { .which_resp = bam_api_SchedulerResponseV0_ping_tag, .resp.ping = { .id = 7U } }
  };
  sz = test_encode( buf, sizeof(buf), &bam_api_SchedulerResponse_msg, &resp );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream );
  FD_TEST( state->bam.stream_accepted && state->bam.pong_pending );
  fd_bundle_client_step( state, &charge_busy );
  expect_msg( wire_rx( env ), stream_id, 0U, &bam_api_SchedulerMessage_msg, &msg );
  FD_TEST( msg.versioned_msg.v0.which_msg==bam_api_SchedulerMessageV0_pong_tag && msg.versioned_msg.v0.msg.pong.id==7U );
  FD_TEST( !state->bam.pong_pending );

  /* Pack's leader state is forwarded, and dropped once its slot ends */
  *state->leader_state = (fd_pack_leader_state_t){ .slot=500UL, .slot_end_ns=g_clock+(long)4e8, .tick=3UL, .cus_remaining=1000UL };
  FD_TEST( fd_bundle_client_leader_state_update( state, 1 ) && state->bam.leader_state_pending );
  fd_bundle_client_step( state, &charge_busy );
  expect_msg( wire_rx( env ), stream_id, 0U, &bam_api_SchedulerMessage_msg, &msg );
  bam_types_LeaderState const * leader = &msg.versioned_msg.v0.msg.leader_state;
  FD_TEST( msg.versioned_msg.v0.which_msg==bam_api_SchedulerMessageV0_leader_state_tag );
  FD_TEST( leader->slot==500UL && leader->tick==3U && leader->slot_cu_budget_remaining==1000U );
  FD_TEST( !state->bam.leader_state_pending );
  FD_TEST( fd_bundle_client_leader_state_update( state, 0 ) );
  state->leader_state->slot_end_ns = g_clock;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( !state->bam.leader_state_pending && !fd_h2_rbuf_used_sz( wire_rx( env ) ) );

  /* Then the builder config is polled, and a builder completes the
     login */
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->bam.builder.wait );
  bam_api_ConfigRequest config_req;
  expect_request( wire_rx( env ), client->stream_ids[ client->stream_cnt-1UL ], "/bam_api.BamNodeApi/GetBuilderConfig",
                  &bam_api_ConfigRequest_msg, &config_req );

  uchar builder[ 32 ];
  fd_memset( builder, 0x22, sizeof(builder) );
  bam_api_ConfigResponse config = bam_api_ConfigResponse_init_default;
  config.has_block_engine_config                = 1;
  config.block_engine_config.builder_commission = 5U;
  fd_base58_encode_32( builder, NULL, config.block_engine_config.builder_pubkey );
  config.has_bam_config = 1;
  config.bam_config     = (bam_types_BamConfig){ .has_tpu_sock = 1, .tpu_sock = { .ip = "1.2.3.4", .port = 8000U },
                                                 .has_tpu_fwd_sock = 1, .tpu_fwd_sock = { .ip = "1.2.3.4", .port = 8001U } };
  sz = test_encode( buf, sizeof(buf), &bam_api_ConfigResponse_msg, &config );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig );
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig, &ok );
  FD_TEST( !state->bam.builder.wait && state->bam.builder.avail );
  FD_TEST( state->bam.builder.commission==5U && fd_memeq( state->bam.builder.pubkey, builder, sizeof(builder) ) );
  FD_TEST( fd_bundle_client_status( state )==FD_BUNDLE_STATE_CONNECTING );

  fd_bundle_tpu_t const tpu = { .ip4 = FD_IP4_ADDR( 1, 2, 3, 4 ), .port = 8000, .fwd_ip4 = FD_IP4_ADDR( 1, 2, 3, 4 ), .fwd_port = 8001 };
  FD_TEST( fd_memeq( &state->conn->tpu, &tpu, sizeof(tpu) ) );

  /* A heartbeat from the node makes the session healthy, and its TPU is
     advertised */
  void * keyswitch_mem = fd_wksp_alloc_laddr( wksp, fd_keyswitch_align(), fd_keyswitch_footprint(), 1UL );
  state->keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  fd_bundle_tile_housekeeping( state );
  FD_TEST( !state->tpu_dirty );
  test_rx_bam_heartbeat( state );
  FD_TEST( state->bam.heartbeat_seen && state->bam.heartbeat_rx==g_clock );
  FD_TEST( fd_bundle_client_status( state )==FD_BUNDLE_STATE_CONNECTED );
  fd_bundle_tile_housekeeping( state );
  FD_TEST( state->tpu_dirty && fd_memeq( &state->tpu_advertised, &tpu, sizeof(tpu) ) );
  state->tpu_dirty = 0;

  /* Once a builder is known, the config is refreshed every minute */
  FD_TEST( state->bam.builder.next==g_clock+(long)60e9 );
  g_clock += (long)59e9;
  test_rx_bam_heartbeat( state );
  for( ulong i=0UL; i<4UL; i++ ) fd_bundle_client_step( state, &charge_busy );
  FD_TEST( !state->bam.builder.wait );
  g_clock += (long)1e9;
  test_rx_bam_heartbeat( state );
  for( ulong i=0UL; i<4UL && !state->bam.builder.wait; i++ ) fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->bam.builder.wait );
  wire_rx( env );

  /* Six seconds without a heartbeat reconnects */
  FD_TEST( fd_bundle_client_next_deadline( state, g_clock )<=g_clock+(long)6e9 );
  g_clock += (long)6e9-1L;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( !state->conn->defer_reset );
  g_clock += 1L;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->defer_reset );
  wire_rx( env );

  /* The stream ending reconnects, and the reset clears the session */
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream, &ok );
  FD_TEST( !state->bam.stream && state->conn->defer_reset );
  fd_bundle_client_reset( state );
  FD_TEST( !state->bam.stream_accepted && !state->bam.heartbeat_seen && !state->bam.builder.wait && !state->bam.builder.avail );

  /* Disconnected, our own TPU is advertised again, but BAM's is kept
     for the next session */
  fd_bundle_tile_housekeeping( state );
  fd_bundle_tpu_t const zero = {0};
  FD_TEST( state->tpu_dirty && fd_memeq( &state->tpu_advertised, &zero, sizeof(zero) ) );
  FD_TEST( fd_memeq( &state->conn->tpu, &tpu, sizeof(tpu) ) );

  fd_wksp_free_laddr( fd_keyswitch_delete( fd_keyswitch_leave( state->keyswitch ) ) );
  test_sign_destroy( sign );
  test_bundle_env_destroy( env );
}

/* Verify that only a valid pair of BAM TPU sockets replaces the TPU */

FD_UNIT_TEST( bam_client_tpu ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * const state = env->state;
  state->protocol = FD_BUNDLE_PROTOCOL_BAM;

  /* The first pair is valid, and every later one is rejected */
  struct { char const * ip; uint port; char const * fwd_ip; uint fwd_port; } const cases[] = {
    { "1.2.3.4", 8000U,  "5.6.7.8", 9000U },
    { "2.2.2.2", 8000U,  "bad",     9000U },
    { "0.0.0.0", 8000U,  "5.6.7.8", 9000U },
    { "2.2.2.2", 0U,     "5.6.7.8", 9000U },
    { "2.2.2.2", 65530U, "5.6.7.8", 9000U }, /* no room for the QUIC port */
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    bam_api_ConfigResponse config = bam_api_ConfigResponse_init_default;
    config.has_bam_config = 1;
    config.bam_config.has_tpu_sock     = 1;
    config.bam_config.has_tpu_fwd_sock = 1;
    fd_cstr_ncpy( config.bam_config.tpu_sock.ip,     cases[ i ].ip,     sizeof(config.bam_config.tpu_sock.ip)     );
    fd_cstr_ncpy( config.bam_config.tpu_fwd_sock.ip, cases[ i ].fwd_ip, sizeof(config.bam_config.tpu_fwd_sock.ip) );
    config.bam_config.tpu_sock.port     = cases[ i ].port;
    config.bam_config.tpu_fwd_sock.port = cases[ i ].fwd_port;
    uchar buf[ 512 ];
    ulong sz = test_encode( buf, sizeof(buf), &bam_api_ConfigResponse_msg, &config );
    fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig );
    FD_TEST( state->conn->tpu.ip4==FD_IP4_ADDR( 1, 2, 3, 4 ) && state->conn->tpu.port==8000 );
    FD_TEST( state->conn->tpu.fwd_ip4==FD_IP4_ADDR( 5, 6, 7, 8 ) && state->conn->tpu.fwd_port==9000 );
  }

  /* A config without a BamConfig keeps the TPU */
  bam_api_ConfigResponse config = bam_api_ConfigResponse_init_default;
  uchar buf[ 64 ];
  ulong sz = test_encode( buf, sizeof(buf), &bam_api_ConfigResponse_msg, &config );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig );
  FD_TEST( state->conn->tpu.ip4==FD_IP4_ADDR( 1, 2, 3, 4 ) );

  test_bundle_env_destroy( env );
}

/* Verify that an empty challenge is retried, and that a scheduler
   response without a v0 message drops the connection */

FD_UNIT_TEST( bam_client_bad_responses ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn_empty( env );
  fd_bundle_tile_t * const state = env->state;
  state->protocol = FD_BUNDLE_PROTOCOL_BAM;

  uchar buf[ 512 ];
  bam_api_AuthChallengeResponse challenge = bam_api_AuthChallengeResponse_init_default;
  ulong sz = test_encode( buf, sizeof(buf), &bam_api_AuthChallengeResponse_msg, &challenge );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge );
  FD_TEST( !state->bam.challenge[ 0 ] && state->metrics.decode_fail_cnt==1UL && state->conn->backoff_iter==1U );

  bam_api_SchedulerResponse resp = bam_api_SchedulerResponse_init_default;
  sz = test_encode( buf, sizeof(buf), &bam_api_SchedulerResponse_msg, &resp );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream );
  FD_TEST( !state->bam.stream_accepted && state->metrics.decode_fail_cnt==2UL && state->conn->defer_reset );

  test_bundle_env_destroy( env );
}

/* Verify that a BAM client does not dial while the node would refuse
   the login, this close to our next leader slot */

FD_UNIT_TEST( bam_client_login_cutoff ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * const state = env->state;
  state->protocol         = FD_BUNDLE_PROTOCOL_BAM;
  state->next_leader_slot = 1039UL;
  state->reset_slot       = 1000UL;

  int charge_busy = 0;
  FD_TEST( fd_bundle_client_next_deadline( state, g_clock )==g_clock+(long)4e8 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->conn->tcp_sock<0 && !charge_busy );

  state->reset_slot = 999UL;
  FD_TEST( fd_bundle_client_next_deadline( state, g_clock )==g_clock );
  state->protocol   = FD_BUNDLE_PROTOCOL_JITO;
  state->reset_slot = 1000UL;
  FD_TEST( fd_bundle_client_next_deadline( state, g_clock )==g_clock );

  test_bundle_env_destroy( env );
}

typedef struct {
  uint  seq_id;
  ulong cnt;
  uchar revert[ 6 ];
} test_bam_batch_t;

typedef struct {
  test_bam_batch_t const * batches;
  ulong                    cnt;
} test_bam_batches_t;

static bool
test_encode_bam_packets( pb_ostream_t *     stream,
                         pb_field_t const * field,
                         void * const *     arg ) {
  test_bam_batch_t const * batch = *arg;
  for( ulong i=0UL; i<batch->cnt; i++ ) {
    bam_types_Packet packet = bam_types_Packet_init_default;
    packet.data.bytes[ 0 ]            = (uchar)(batch->seq_id*16U+i);
    packet.data.size                  = 1U;
    packet.has_meta                   = 1;
    packet.meta.has_flags             = 1;
    packet.meta.flags.revert_on_error = batch->revert[ i ];
    if( !pb_encode_tag_for_field( stream, field ) || !pb_encode_submessage( stream, &bam_types_Packet_msg, &packet ) ) return false;
  }
  return true;
}

static bool
test_encode_bam_batches( pb_ostream_t *     stream,
                         pb_field_t const * field,
                         void * const *     arg ) {
  test_bam_batches_t const * batches = *arg;
  for( ulong i=0UL; i<batches->cnt; i++ ) {
    bam_types_AtomicTxnBatch batch = bam_types_AtomicTxnBatch_init_default;
    batch.seq_id            = batches->batches[ i ].seq_id;
    batch.max_schedule_slot = 600UL;
    batch.packets           = (pb_callback_t) { .funcs.encode = test_encode_bam_packets, .arg = (void *)&batches->batches[ i ] };
    if( !pb_encode_tag_for_field( stream, field ) || !pb_encode_submessage( stream, &bam_types_AtomicTxnBatch_msg, &batch ) ) return false;
  }
  return true;
}

static void
test_rx_bam_batches( fd_bundle_tile_t *       state,
                     test_bam_batch_t const * batches,
                     ulong                    cnt ) {
  test_bam_batches_t arg = { .batches = batches, .cnt = cnt };
  bam_api_SchedulerResponse resp = bam_api_SchedulerResponse_init_default;
  resp.which_versioned_msg        = bam_api_SchedulerResponse_v0_tag;
  resp.versioned_msg.v0.which_resp = bam_api_SchedulerResponseV0_multiple_atomic_txn_batch_tag;
  resp.versioned_msg.v0.resp.multiple_atomic_txn_batch.batches = (pb_callback_t) { .funcs.encode = test_encode_bam_batches, .arg = &arg };
  static uchar buf[ 4096 ];
  ulong sz = test_encode( buf, sizeof(buf), &bam_api_SchedulerResponse_msg, &resp );
  fd_bundle_client_grpc_rx_msg( state->conn, buf, sz, FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream );
}

/* Verify that each BAM batch becomes one bundle, and that invalid
   batches are dropped whole */

FD_UNIT_TEST( bam_client_batches ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * const state = env->state;
  state->protocol = FD_BUNDLE_PROTOCOL_BAM;

  test_bam_batch_t const batches[] = {
    { .seq_id=0U, .cnt=2UL, .revert={ 1, 1 } },             /* atomic */
    { .seq_id=1U, .cnt=1UL, .revert={ 0 } },                /* standalone */
    { .seq_id=2U, .cnt=2UL, .revert={ 0, 0 } },             /* non-atomic with two transactions */
    { .seq_id=3U, .cnt=2UL, .revert={ 1, 0 } },             /* mixed flags */
    { .seq_id=4U, .cnt=6UL, .revert={ 1, 1, 1, 1, 1, 1 } }, /* too large */
    { .seq_id=5U, .cnt=1UL, .revert={ 1 } },
  };

  /* Without a builder, batches are not forwarded */
  test_rx_bam_batches( state, batches, 1UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) && state->metrics.missing_builder_info_fail_cnt==1UL );

  state->bam.builder.avail = 1;
  ulong const seq0 = state->bundle_seq;
  test_rx_bam_batches( state, batches, 6UL );
  FD_TEST( state->bam.stream_accepted && state->metrics.bundle_received_cnt==3UL );

  struct { uint seq_id; ulong bundle_seq; ulong txn_cnt; uchar atomic; } const want[] = {
    { 0U, 1UL, 2UL, 1 }, { 0U, 1UL, 2UL, 1 }, { 1U, 2UL, 1UL, 0 }, { 5U, 6UL, 1UL, 1 },
  };
  FD_TEST( pending_txn_cnt( state->pending_txns )==4UL );
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_bundle_pending_txn_t const * e = pending_txn_peek_index( state->pending_txns, i );
    FD_TEST( e->sig==1UL && e->bundle_seq==seq0+want[ i ].bundle_seq && e->bundle_txn_cnt==want[ i ].txn_cnt );
    FD_TEST( e->block_slot==600UL && e->block_seq==want[ i ].seq_id && e->atomic==want[ i ].atomic && e->want_result );
  }

  /* A batch that only partly fits is dropped whole */
  ulong const cap = pending_txn_max( state->pending_txns );
  while( pending_txn_cnt( state->pending_txns )<cap-1UL ) pending_txn_push_tail( state->pending_txns, (fd_bundle_pending_txn_t){0} );
  test_rx_bam_batches( state, batches, 1UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==cap-1UL && state->metrics.backpressure_drop_cnt==2UL );

  test_bundle_env_destroy( env );
}

#define TEST_STEM_BURST (5UL)

typedef struct {
  uchar const * payload;
  ulong         payload_sz;
} test_packet_desc_t;

typedef struct {
  test_packet_desc_t const * packets;
  ulong                      packet_cnt;
} test_packet_list_t;

typedef struct {
  test_packet_desc_t const * packets;
  ulong                      packet_cnt;
  uchar                      uuid[ 16 ];
  ulong                      uuid_sz;
} test_bundle_desc_t;

typedef struct {
  test_bundle_desc_t const * bundles;
  ulong                      bundle_cnt;
} test_bundle_list_t;

static bool
encode_test_packet_list( pb_ostream_t *     stream,
                         pb_field_t const * field,
                         void * const *     arg ) {
  test_packet_list_t const * packet_list = *arg;

  for( ulong i=0UL; i<packet_list->packet_cnt; i++ ) {
    test_packet_desc_t const * desc = &packet_list->packets[ i ];
    packet_Packet packet = packet_Packet_init_default;
    FD_TEST( desc->payload_sz<=sizeof(packet.data.bytes) );
    packet.data.size = (pb_size_t)desc->payload_sz;
    fd_memcpy( packet.data.bytes, desc->payload, desc->payload_sz );

    if( FD_UNLIKELY( !pb_encode_tag_for_field( stream, field ) ) ) return false;
    if( FD_UNLIKELY( !pb_encode_submessage( stream, &packet_Packet_msg, &packet ) ) ) return false;
  }

  return true;
}

static bool
encode_test_bundle_list( pb_ostream_t *     stream,
                         pb_field_t const * field,
                         void * const *     arg ) {
  test_bundle_list_t const * bundle_list = *arg;

  for( ulong i=0UL; i<bundle_list->bundle_cnt; i++ ) {
    test_bundle_desc_t const * desc = &bundle_list->bundles[ i ];
    test_packet_list_t packet_list = {
      .packets    = desc->packets,
      .packet_cnt = desc->packet_cnt,
    };
    bundle_BundleUuid bundle_uuid = bundle_BundleUuid_init_default;
    bundle_uuid.has_bundle = true;
    bundle_uuid.bundle.packets = (pb_callback_t) {
      .funcs.encode = encode_test_packet_list,
      .arg          = &packet_list,
    };
    FD_TEST( desc->uuid_sz<=sizeof(bundle_uuid.uuid.bytes) );
    bundle_uuid.uuid.size = (pb_size_t)desc->uuid_sz;
    fd_memcpy( bundle_uuid.uuid.bytes, desc->uuid, desc->uuid_sz );

    if( FD_UNLIKELY( !pb_encode_tag_for_field( stream, field ) ) ) return false;
    if( FD_UNLIKELY( !pb_encode_submessage( stream, &bundle_BundleUuid_msg, &bundle_uuid ) ) ) return false;
  }

  return true;
}

static ulong
encode_subscribe_packets_response( uchar const *          payload_buf,
                                   ulong                  payload_buf_sz,
                                   test_packet_desc_t *   packets,
                                   ulong                  packet_cnt ) {
  block_engine_SubscribePacketsResponse resp = block_engine_SubscribePacketsResponse_init_default;
  test_packet_list_t packet_list = {
    .packets    = packets,
    .packet_cnt = packet_cnt,
  };
  resp.has_batch = true;
  resp.batch.packets = (pb_callback_t) {
    .funcs.encode = encode_test_packet_list,
    .arg          = &packet_list,
  };

  pb_ostream_t ostream = pb_ostream_from_buffer( (pb_byte_t *)payload_buf, payload_buf_sz );
  FD_TEST( pb_encode( &ostream, &block_engine_SubscribePacketsResponse_msg, &resp ) );
  return ostream.bytes_written;
}

static ulong
encode_subscribe_bundles_response( uchar const *          payload_buf,
                                   ulong                  payload_buf_sz,
                                   test_bundle_desc_t *   bundles,
                                   ulong                  bundle_cnt ) {
  block_engine_SubscribeBundlesResponse resp = block_engine_SubscribeBundlesResponse_init_default;
  test_bundle_list_t bundle_list = {
    .bundles    = bundles,
    .bundle_cnt = bundle_cnt,
  };
  resp.bundles = (pb_callback_t) {
    .funcs.encode = encode_test_bundle_list,
    .arg          = &bundle_list,
  };

  pb_ostream_t ostream = pb_ostream_from_buffer( (pb_byte_t *)payload_buf, payload_buf_sz );
  FD_TEST( pb_encode( &ostream, &block_engine_SubscribeBundlesResponse_msg, &resp ) );
  return ostream.bytes_written;
}

static ulong
published_txn_cnt( test_bundle_env_t const * env ) {
  return env->stem_seqs[ 0 ];
}

static fd_txn_m_t const *
published_txn( test_bundle_env_t const *  env,
               ulong                      seq,
               fd_frag_meta_t const **    opt_meta ) {
  FD_TEST( seq<published_txn_cnt( env ) );
  fd_frag_meta_t const * meta = env->out_mcache + fd_mcache_line_idx( seq, env->stem_depths[ 0 ] );
  FD_TEST( meta->seq==seq );
  if( opt_meta ) *opt_meta = meta;
  return (fd_txn_m_t const *)fd_chunk_to_laddr( env->out_dcache, meta->chunk );
}

static void
expect_published_txn( test_bundle_env_t const * env,
                      ulong                     seq,
                      ulong                     sig,
                      uchar const *             payload,
                      ulong                     payload_sz,
                      ulong                     bundle_id,
                      ulong                     bundle_txn_cnt,
                      uchar                     commission,
                      uchar const *             commission_pubkey ) {
  fd_frag_meta_t const * meta = NULL;
  fd_txn_m_t const * txnm = published_txn( env, seq, &meta );

  FD_TEST( meta->sig==sig );
  FD_TEST( txnm->payload_sz==payload_sz );
  FD_TEST( txnm->txn_t_sz==0U );
  FD_TEST( txnm->source_tpu==FD_TXN_M_TPU_SOURCE_BUNDLE );
  FD_TEST( txnm->block_engine.bundle_id==bundle_id );
  FD_TEST( txnm->block_engine.bundle_txn_cnt==bundle_txn_cnt );
  FD_TEST( txnm->block_engine.commission==commission );
  FD_TEST( 0==memcmp( txnm->block_engine.commission_pubkey, commission_pubkey, 32UL ) );
  FD_TEST( txnm->block_engine.slot==0UL && txnm->block_engine.seq==0UL );
  FD_TEST( txnm->block_engine.atomic==!!bundle_id );
  FD_TEST( !txnm->block_engine.want_result && !txnm->block_engine.preprocess_failed );
  FD_TEST( 0==memcmp( fd_txn_m_payload_const( txnm ), payload, payload_sz ) );
}

/* Mirror the production after_credit publish loop so tests can verify
   actual published output without exposing the static callback. */

static ulong
publish_after_credit( fd_bundle_tile_t * state ) {
  if( pending_txn_empty( state->pending_txns ) ) return 0UL;

  fd_stem_context_t * stem = state->stem;
  fd_bundle_pending_txn_t * head = pending_txn_peek_head( state->pending_txns );
  ulong drain_seq = head->bundle_seq;
  ulong drain_sig = head->sig;
  ulong drain_cnt = 0UL;

  do {
    fd_bundle_pending_txn_t const * txn = pending_txn_peek_head( state->pending_txns );

    ulong sz    = fd_bundle_pending_txn_write( fd_chunk_to_laddr( state->verify_out.mem, state->verify_out.chunk ), txn );
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_bundle_now( state ) );
    fd_stem_publish( stem, state->verify_out.idx, txn->sig, state->verify_out.chunk, sz, 0UL, 0UL, tspub );
    state->verify_out.chunk = fd_dcache_compact_next( state->verify_out.chunk, sz, state->verify_out.chunk0, state->verify_out.wmark );

    pending_txn_remove_head( state->pending_txns );
    drain_cnt++;
  } while( fd_bundle_drain_continue( state->pending_txns, drain_sig, drain_seq, drain_cnt, TEST_STEM_BURST ) );

  return drain_cnt;
}

/* Simulate after_credit drain using the same continuation logic as
   production (fd_bundle_drain_continue). */

static ulong
drain_one_bundle( fd_bundle_pending_txn_t * deque ) {
  if( pending_txn_empty( deque ) ) return 0UL;

  fd_bundle_pending_txn_t * head = pending_txn_peek_head( deque );
  ulong drain_seq = head->bundle_seq;
  ulong drain_sig = head->sig;
  ulong cnt = 0UL;

  do {
    pending_txn_pop_head( deque );
    cnt++;
  } while( fd_bundle_drain_continue( deque, drain_sig, drain_seq, cnt, TEST_STEM_BURST ) );

  return cnt;
}

/* Verify that the drain logic publishes one complete bundle
   atomically, stopping at bundle boundaries. */

FD_UNIT_TEST( packet_publish_after_credit ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  uchar const payload0[] = { 0x48 };
  uchar const payload1[] = { 0xAA, 0xBB };
  test_packet_desc_t packets[] = {
    { .payload=payload0, .payload_sz=sizeof(payload0) },
    { .payload=payload1, .payload_sz=sizeof(payload1) },
  };
  uchar pb_buf[ 256 ];
  ulong pb_sz = encode_subscribe_packets_response( pb_buf, sizeof(pb_buf), packets, 2UL );

  fd_bundle_client_grpc_rx_msg(
      state->conn,
      pb_buf, pb_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  FD_TEST( published_txn_cnt( env )==0UL );

  uchar const zero_pubkey[ 32 ] = {0};
  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );
  FD_TEST( published_txn_cnt( env )==2UL );
  expect_published_txn( env, 0UL, 0UL, payload0, sizeof(payload0), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 1UL, 0UL, payload1, sizeof(payload1), 0UL, 1UL, 0U, zero_pubkey );

  test_bundle_env_destroy( env );
}

/* Verify that Block bundles are published in order with their slot,
   position, and atomicity */

FD_UNIT_TEST( harmonic_block_publish ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->protocol           = FD_BUNDLE_PROTOCOL_HARMONIC;
  state->leader_state->slot = 500UL;

  ulong const ids[] = { 0UL, 7UL, 7UL };
  test_rx_block( state, 500UL, ids, 3UL );
  FD_TEST( publish_after_credit( state )==1UL );
  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( published_txn_cnt( env )==3UL );

  static struct { ulong seq; ulong txn_cnt; uchar atomic; } const want[] = {
    { 1UL, 1UL, 0 }, { 2UL, 2UL, 1 }, { 2UL, 2UL, 1 }
  };
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_frag_meta_t const * meta = NULL;
    fd_txn_m_t const * txnm = published_txn( env, i, &meta );
    FD_TEST( meta->sig==1UL && fd_txn_m_payload_const( txnm )[ 0 ]==(uchar)i );
    FD_TEST( txnm->block_engine.bundle_id && txnm->block_engine.bundle_txn_cnt==want[ i ].txn_cnt );
    FD_TEST( txnm->block_engine.slot==500UL && txnm->block_engine.seq==want[ i ].seq );
    FD_TEST( txnm->block_engine.atomic==want[ i ].atomic );
    FD_TEST( !txnm->block_engine.want_result && !txnm->block_engine.preprocess_failed );
  }

  test_bundle_env_destroy( env );
}

/* Verify that bundles publish atomically: one full bundle per
   after_credit-style drain, never crossing into the next bundle. */

FD_UNIT_TEST( packet_publish_after_credit_atomic ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->conn->builder.avail      = 1;
  state->conn->builder.commission = 7U;
  uchar builder_pubkey[ 32 ];
  for( ulong i=0UL; i<32UL; i++ ) builder_pubkey[ i ] = (uchar)( i + 1U );
  fd_memcpy( state->conn->builder.pubkey, builder_pubkey, sizeof(builder_pubkey) );

  uchar const bundle_a0[] = { 0xA0 };
  uchar const bundle_a1[] = { 0xA1 };
  uchar const bundle_a2[] = { 0xA2 };
  uchar const bundle_b0[] = { 0xB0 };
  uchar const bundle_b1[] = { 0xB1 };
  test_packet_desc_t bundle_a[] = {
    { .payload=bundle_a0, .payload_sz=sizeof(bundle_a0) },
    { .payload=bundle_a1, .payload_sz=sizeof(bundle_a1) },
    { .payload=bundle_a2, .payload_sz=sizeof(bundle_a2) },
  };
  test_packet_desc_t bundle_b[] = {
    { .payload=bundle_b0, .payload_sz=sizeof(bundle_b0) },
    { .payload=bundle_b1, .payload_sz=sizeof(bundle_b1) },
  };
  test_bundle_desc_t bundles[] = {
    { .packets=bundle_a, .packet_cnt=3UL, .uuid={1,2,3}, .uuid_sz=3UL },
    { .packets=bundle_b, .packet_cnt=2UL, .uuid={4,5,6}, .uuid_sz=3UL },
  };
  uchar pb_buf[ 512 ];
  ulong pb_sz = encode_subscribe_bundles_response( pb_buf, sizeof(pb_buf), bundles, 2UL );

  fd_bundle_client_grpc_rx_msg(
      state->conn,
      pb_buf, pb_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );
  FD_TEST( published_txn_cnt( env )==0UL );

  FD_TEST( publish_after_credit( state )==3UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  FD_TEST( pending_txn_peek_head( state->pending_txns )->bundle_seq==2UL );
  expect_published_txn( env, 0UL, 1UL, bundle_a0, sizeof(bundle_a0), 1UL, 3UL, 7U, builder_pubkey );
  expect_published_txn( env, 1UL, 1UL, bundle_a1, sizeof(bundle_a1), 1UL, 3UL, 7U, builder_pubkey );
  expect_published_txn( env, 2UL, 1UL, bundle_a2, sizeof(bundle_a2), 1UL, 3UL, 7U, builder_pubkey );

  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );
  FD_TEST( published_txn_cnt( env )==5UL );
  expect_published_txn( env, 3UL, 1UL, bundle_b0, sizeof(bundle_b0), 2UL, 2UL, 7U, builder_pubkey );
  expect_published_txn( env, 4UL, 1UL, bundle_b1, sizeof(bundle_b1), 2UL, 2UL, 7U, builder_pubkey );

  test_bundle_env_destroy( env );
}

/* Bundles are all-or-nothing at the head of the queue: after_credit
   must publish the entire bundle before touching following packets. */

FD_UNIT_TEST( bundle_publish_all_or_nothing ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->conn->builder.avail = 1;

  uchar const b0[] = { 0x10 };
  uchar const b1[] = { 0x11 };
  uchar const b2[] = { 0x12 };
  uchar const b3[] = { 0x13 };
  uchar const b4[] = { 0x14 };
  uchar const pkt[] = { 0x99 };
  test_packet_desc_t bundle_packets[] = {
    { .payload=b0, .payload_sz=sizeof(b0) },
    { .payload=b1, .payload_sz=sizeof(b1) },
    { .payload=b2, .payload_sz=sizeof(b2) },
    { .payload=b3, .payload_sz=sizeof(b3) },
    { .payload=b4, .payload_sz=sizeof(b4) },
  };
  test_bundle_desc_t bundles[] = {
    { .packets=bundle_packets, .packet_cnt=5UL, .uuid={7,7,7}, .uuid_sz=3UL },
  };
  test_packet_desc_t trailing_packet[] = {
    { .payload=pkt, .payload_sz=sizeof(pkt) },
  };
  uchar bundle_buf[ 512 ];
  uchar packet_buf[ 128 ];
  ulong bundle_sz = encode_subscribe_bundles_response( bundle_buf, sizeof(bundle_buf), bundles, 1UL );
  ulong packet_sz = encode_subscribe_packets_response( packet_buf, sizeof(packet_buf), trailing_packet, 1UL );

  fd_bundle_client_grpc_rx_msg(
      state->conn,
      bundle_buf, bundle_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );
  fd_bundle_client_grpc_rx_msg(
      state->conn,
      packet_buf, packet_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==6UL );
  FD_TEST( publish_after_credit( state )==5UL );
  FD_TEST( published_txn_cnt( env )==5UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );
  FD_TEST( pending_txn_peek_head( state->pending_txns )->sig==0UL );

  uchar const zero_pubkey[ 32 ] = {0};
  expect_published_txn( env, 0UL, 1UL, b0, sizeof(b0), 1UL, 5UL, 0U, zero_pubkey );
  expect_published_txn( env, 1UL, 1UL, b1, sizeof(b1), 1UL, 5UL, 0U, zero_pubkey );
  expect_published_txn( env, 2UL, 1UL, b2, sizeof(b2), 1UL, 5UL, 0U, zero_pubkey );
  expect_published_txn( env, 3UL, 1UL, b3, sizeof(b3), 1UL, 5UL, 0U, zero_pubkey );
  expect_published_txn( env, 4UL, 1UL, b4, sizeof(b4), 1UL, 5UL, 0U, zero_pubkey );

  FD_TEST( publish_after_credit( state )==1UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );
  expect_published_txn( env, 5UL, 0UL, pkt, sizeof(pkt), 0UL, 1UL, 0U, zero_pubkey );

  test_bundle_env_destroy( env );
}

/* Verify queue boundary behavior with mixed packets and bundles. */

FD_UNIT_TEST( mixed_queue_boundary_behavior ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->conn->builder.avail = 1;

  uchar const p0[] = { 0x20 };
  uchar const p1[] = { 0x21 };
  uchar const p2[] = { 0x22 };
  uchar const p3[] = { 0x23 };
  uchar const b0[] = { 0x30 };
  uchar const b1[] = { 0x31 };
  uchar const p4[] = { 0x24 };
  uchar const p5[] = { 0x25 };
  test_packet_desc_t leading_packets[] = {
    { .payload=p0, .payload_sz=sizeof(p0) },
    { .payload=p1, .payload_sz=sizeof(p1) },
    { .payload=p2, .payload_sz=sizeof(p2) },
    { .payload=p3, .payload_sz=sizeof(p3) },
  };
  test_packet_desc_t bundle_packets[] = {
    { .payload=b0, .payload_sz=sizeof(b0) },
    { .payload=b1, .payload_sz=sizeof(b1) },
  };
  test_bundle_desc_t bundles[] = {
    { .packets=bundle_packets, .packet_cnt=2UL, .uuid={9,9,9}, .uuid_sz=3UL },
  };
  test_packet_desc_t trailing_packets[] = {
    { .payload=p4, .payload_sz=sizeof(p4) },
    { .payload=p5, .payload_sz=sizeof(p5) },
  };
  uchar packet_buf0[ 256 ];
  uchar bundle_buf [ 256 ];
  uchar packet_buf1[ 256 ];
  ulong packet_sz0 = encode_subscribe_packets_response( packet_buf0, sizeof(packet_buf0), leading_packets, 4UL );
  ulong bundle_sz  = encode_subscribe_bundles_response( bundle_buf, sizeof(bundle_buf), bundles, 1UL );
  ulong packet_sz1 = encode_subscribe_packets_response( packet_buf1, sizeof(packet_buf1), trailing_packets, 2UL );

  fd_bundle_client_grpc_rx_msg( state->conn, packet_buf0, packet_sz0, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );
  fd_bundle_client_grpc_rx_msg( state->conn, bundle_buf,  bundle_sz,  FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  fd_bundle_client_grpc_rx_msg( state->conn, packet_buf1, packet_sz1, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );

  uchar const zero_pubkey[ 32 ] = {0};
  FD_TEST( pending_txn_cnt( state->pending_txns )==8UL );

  FD_TEST( publish_after_credit( state )==4UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==4UL );
  expect_published_txn( env, 0UL, 0UL, p0, sizeof(p0), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 1UL, 0UL, p1, sizeof(p1), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 2UL, 0UL, p2, sizeof(p2), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 3UL, 0UL, p3, sizeof(p3), 0UL, 1UL, 0U, zero_pubkey );

  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  expect_published_txn( env, 4UL, 1UL, b0, sizeof(b0), 1UL, 2UL, 0U, zero_pubkey );
  expect_published_txn( env, 5UL, 1UL, b1, sizeof(b1), 1UL, 2UL, 0U, zero_pubkey );

  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );
  expect_published_txn( env, 6UL, 0UL, p4, sizeof(p4), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 7UL, 0UL, p5, sizeof(p5), 0UL, 1UL, 0U, zero_pubkey );

  test_bundle_env_destroy( env );
}

/* Messages are only buffered by grpc_rx_msg. Nothing should hit the
   output link until after_credit runs. */

FD_UNIT_TEST( no_publish_before_after_credit ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->conn->builder.avail = 1;

  uchar const packet_payload[] = { 0x55 };
  uchar const bundle_payload0[] = { 0x66 };
  uchar const bundle_payload1[] = { 0x67 };
  test_packet_desc_t packets[] = {
    { .payload=packet_payload, .payload_sz=sizeof(packet_payload) },
  };
  test_packet_desc_t bundle_packets[] = {
    { .payload=bundle_payload0, .payload_sz=sizeof(bundle_payload0) },
    { .payload=bundle_payload1, .payload_sz=sizeof(bundle_payload1) },
  };
  test_bundle_desc_t bundles[] = {
    { .packets=bundle_packets, .packet_cnt=2UL, .uuid={5,4,3}, .uuid_sz=3UL },
  };
  uchar packet_buf[ 128 ];
  uchar bundle_buf[ 256 ];
  ulong packet_sz = encode_subscribe_packets_response( packet_buf, sizeof(packet_buf), packets, 1UL );
  ulong bundle_sz = encode_subscribe_bundles_response( bundle_buf, sizeof(bundle_buf), bundles, 1UL );

  fd_bundle_client_grpc_rx_msg(
      state->conn,
      packet_buf, packet_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );
  FD_TEST( published_txn_cnt( env )==0UL );

  fd_bundle_client_grpc_rx_msg(
      state->conn,
      bundle_buf, bundle_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );
  FD_TEST( pending_txn_cnt( state->pending_txns )==3UL );
  FD_TEST( published_txn_cnt( env )==0UL );

  test_bundle_env_destroy( env );
}

FD_UNIT_TEST( bundle_drain_atomicity ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->conn->builder.avail = 1;

  /* Push bundle A (3 txns, bundle_seq=1) */
  for( ulong i=0; i<3; i++ ) {
    fd_bundle_pending_txn_t entry = { .sig=1UL, .bundle_seq=1UL };
    pending_txn_push_tail( state->pending_txns, entry );
  }

  /* Push bundle B (2 txns, bundle_seq=2) */
  for( ulong i=0; i<2; i++ ) {
    fd_bundle_pending_txn_t entry = { .sig=1UL, .bundle_seq=2UL };
    pending_txn_push_tail( state->pending_txns, entry );
  }

  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );

  /* First drain: should pop exactly bundle A (3 txns) */
  ulong drained = drain_one_bundle( state->pending_txns );
  FD_TEST( drained==3UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  FD_TEST( pending_txn_peek_head( state->pending_txns )->bundle_seq==2UL );

  /* Second drain: should pop exactly bundle B (2 txns) */
  drained = drain_one_bundle( state->pending_txns );
  FD_TEST( drained==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  test_bundle_env_destroy( env );
}

/* Verify that individual packets drain up to STEM_BURST per call. */

FD_UNIT_TEST( packet_drain_batch ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  /* Push 4 packets (< STEM_BURST) -- should drain in one call */
  for( ulong i=0; i<4; i++ ) {
    fd_bundle_pending_txn_t entry = { .sig=0UL, .bundle_seq=0UL };
    pending_txn_push_tail( state->pending_txns, entry );
  }
  FD_TEST( drain_one_bundle( state->pending_txns )==4UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  /* Push 8 packets (> STEM_BURST) -- should drain 5 then 3 */
  for( ulong i=0; i<8; i++ ) {
    fd_bundle_pending_txn_t entry = { .sig=0UL, .bundle_seq=0UL };
    pending_txn_push_tail( state->pending_txns, entry );
  }
  FD_TEST( drain_one_bundle( state->pending_txns )==TEST_STEM_BURST );
  FD_TEST( pending_txn_cnt( state->pending_txns )==3UL );
  FD_TEST( drain_one_bundle( state->pending_txns )==3UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  test_bundle_env_destroy( env );
}

/* Verify correct drain ordering when bundles and packets are
   interleaved in the deque. */

FD_UNIT_TEST( interleaved_drain ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->conn->builder.avail = 1;

  /* packet, bundle(3 txns), packet, packet */
  fd_bundle_pending_txn_t pkt = { .sig=0UL, .bundle_seq=0UL };
  pending_txn_push_tail( state->pending_txns, pkt );

  for( ulong i=0; i<3; i++ ) {
    fd_bundle_pending_txn_t b = { .sig=1UL, .bundle_seq=5UL };
    pending_txn_push_tail( state->pending_txns, b );
  }

  pending_txn_push_tail( state->pending_txns, pkt );
  pending_txn_push_tail( state->pending_txns, pkt );

  FD_TEST( pending_txn_cnt( state->pending_txns )==6UL );

  /* Drain 1: leading packet (1, stops because next entry is a bundle) */
  FD_TEST( drain_one_bundle( state->pending_txns )==1UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );

  /* Drain 2: bundle (3 txns, same bundle_seq) */
  FD_TEST( drain_one_bundle( state->pending_txns )==3UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );

  /* Drain 3: trailing 2 packets batched (2 < STEM_BURST) */
  FD_TEST( drain_one_bundle( state->pending_txns )==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  test_bundle_env_destroy( env );
}

/* Verify that the pending_txn_full guard fires and counts drops. */

FD_UNIT_TEST( deque_overflow_guard ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  ulong cap = pending_txn_max( state->pending_txns );
  for( ulong i=0; i<cap; i++ ) {
    fd_bundle_pending_txn_t entry = {0};
    entry.sig = 0UL;
    pending_txn_push_tail( state->pending_txns, entry );
  }
  FD_TEST( pending_txn_full( state->pending_txns ) );
  FD_TEST( state->metrics.backpressure_drop_cnt==0UL );

  static uchar single_packet_msg[] = {
    0x12, 0x09, 0x0a, 0x07, 0x0a, 0x01, 0x48, 0x12,
    0x02, 0x08, 0x01
  };
  fd_bundle_client_grpc_rx_msg(
      state->conn,
      single_packet_msg, sizeof(single_packet_msg),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==cap );
  FD_TEST( state->metrics.backpressure_drop_cnt==1UL );

  test_bundle_env_destroy( env );
}

/* Verify that an HTTP error on each request type clears the
   corresponding wait flag, restarts authentication, and resets the
   connection. */

FD_UNIT_TEST( request_failed_clears_wait ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;

  fd_grpc_resp_hdrs_t hdrs = {
    .h2_status   = 503,
    .grpc_status = FD_GRPC_STATUS_OK
  };

  /* GetBlockBuilderFeeInfo: builder_info_wait should be cleared */
  state->conn->builder.wait = 1;
  state->conn->auther.state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  state->conn->defer_reset  = 0;
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo, &hdrs );
  FD_TEST( state->conn->builder.wait==0 );
  FD_TEST( state->conn->auther.state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
  FD_TEST( state->conn->defer_reset==1 );

  /* SubscribePackets: its wait flag should be cleared */
  state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait = 1;
  state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].live = 1;
  state->conn->auther.state                      = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  state->conn->defer_reset                       = 0;
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets, &hdrs );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].wait==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_PACKETS ].live==0 );
  FD_TEST( state->conn->auther.state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
  FD_TEST( state->conn->defer_reset==1 );

  /* SubscribeBundles: its wait flag should be cleared */
  state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait = 1;
  state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live = 1;
  state->conn->auther.state                      = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  state->conn->defer_reset                       = 0;
  fd_bundle_client_grpc_rx_end( state->conn, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles, &hdrs );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].wait==0 );
  FD_TEST( state->conn->sub[ FD_BUNDLE_SUB_BUNDLES ].live==0 );
  FD_TEST( state->conn->auther.state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
  FD_TEST( state->conn->defer_reset==1 );

  test_bundle_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL, "normal"                     );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL, 512UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );

  wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 16UL );
  FD_TEST( wksp );

  fd_unit_tests( argc, argv );

  /* Check for memory leaks */
  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
