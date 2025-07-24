#include "test_bundle_common.c"
#include "proto/block_engine.pb.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/nanopb/pb_encode.h"

FD_IMPORT_BINARY( test_bundle_response, "src/disco/bundle/test_bundle_response.binpb" );

__attribute__((weak)) char const fdctl_version_string[] = "0.0.0";

static long g_clock = 1L;

__attribute__((weak)) long
fd_bundle_now( void ) {
  return g_clock;
}

/* Test that packets and bundles get forwarded correctly to Firedancer
   components. */

static void
test_bundle_rx( fd_wksp_t * wksp ) {
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
      state,
      subscribe_packets_msg, sizeof(subscribe_packets_msg),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  /* Wipe timestamps */
  for( ulong i=0UL; i<(env->stem_depths[0]); i++ ) {
    env->out_mcache[ i ].tsorig = 0U;
    env->out_mcache[ i ].tspub  = 0U;
  }

  const ulong packet1_sz = 1UL;
  const ulong packet2_sz = 2UL;
  fd_frag_meta_t expected[2] = {
    { .seq=0UL, .sig=0UL, .chunk=0, .sz=sizeof(fd_txn_m_t)+packet1_sz, .ctl=0 },
    { .seq=1UL, .sig=0UL, .chunk=2, .sz=sizeof(fd_txn_m_t)+packet2_sz, .ctl=0 }
  };
  FD_TEST( fd_memeq( env->out_mcache, expected, 2*sizeof(fd_frag_meta_t) ) );

  state->builder_info_avail = 1;

  fd_bundle_client_grpc_rx_msg(
      state,
      test_bundle_response, test_bundle_response_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  test_bundle_env_destroy( env );
}

/* Ensure forwarding of bundles stops when builder fee info is missing. */

static void
test_bundle_no_builder_fee_info( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1]; test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->builder_info_avail = 0;

  /* Regular packets are always forwarded */
  static uchar subscribe_packets_msg[] = {
    0x12, 0x09, 0x0a, 0x07, 0x0a, 0x01, 0x48, 0x12,
    0x02, 0x08, 0x01
  };
  fd_bundle_client_grpc_rx_msg(
      state,
      subscribe_packets_msg, sizeof(subscribe_packets_msg),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );
  FD_TEST( fd_seq_eq( env->out_mcache[ 0 ].seq, 0UL ) );
  FD_TEST( state->metrics.packet_received_cnt          ==1UL );
  FD_TEST( state->metrics.missing_builder_info_fail_cnt==0UL );

  /* Bundles are no longer forwarded */

  fd_bundle_client_grpc_rx_msg(
      state,
      test_bundle_response, test_bundle_response_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );
  FD_TEST( fd_seq_ne( env->out_mcache[ 1 ].seq, 1UL ) );
  FD_TEST( state->metrics.bundle_received_cnt          ==0UL );
  FD_TEST( state->metrics.missing_builder_info_fail_cnt==1UL );

  test_bundle_env_destroy( env );
}

/* Ensure that the client reconnects (with a new TCP socket) if the
   server ends the stream */

static void
test_bundle_stream_ended( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state = env->state;
  fd_h2_rbuf_t * rbuf_tx = fd_grpc_client_rbuf_tx( state->grpc_client );
  FD_TEST( rbuf_tx->hi_off==0UL );
  fd_grpc_resp_hdrs_t hdrs = {
    .h2_status   = 200,
    .grpc_status = FD_GRPC_STATUS_OK
  };
  FD_TEST( state->defer_reset==0 );
  fd_bundle_client_grpc_rx_end( state, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles, &hdrs );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Same as above, but with hard stream resets */

static void
test_bundle_stream_reset( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state   = env->state;
  fd_grpc_client_t * client  = state->grpc_client;
  fd_h2_conn_t *     h2_conn = fd_grpc_client_h2_conn( client );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;

  FD_TEST( state->defer_reset==0 );
  fd_grpc_client_h2_callbacks.rst_stream( h2_conn, &stream->s, 0U, 1 );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test response header timeout */

static void
test_bundle_header_timeout( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status        = 200;
  stream->hdrs.is_grpc_proto    = 1;
  stream->has_header_deadline   = 1;
  stream->header_deadline_nanos = 99L;

  /* FIXME ensure that receiving a header disarms the timeout */

  fd_grpc_client_service_streams( client, 100L );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test response timeout */

static void
test_bundle_rx_end_timeout( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status        = 200;
  stream->hdrs.is_grpc_proto    = 1;
  stream->has_rx_end_deadline   = 1;
  stream->rx_end_deadline_nanos = 99L;

  fd_grpc_client_service_streams( client, 100L );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test ping timeout */

static void
test_bundle_ping( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state       = env->state;
  fd_grpc_client_t * grpc_client = state->grpc_client;
  long const ts_ping_tx = g_clock;
  fd_keepalive_tx( state->keepalive, state->rng, ts_ping_tx );
  state->grpc_client->conn->ping_tx = 1;
  FD_TEST( state->keepalive->inflight==1 );
  FD_TEST( !!state->keepalive->ts_deadline );
  FD_TEST( state->keepalive->ts_next_tx >= ts_ping_tx + (state->keepalive->interval>>1) );
  FD_TEST( state->keepalive->ts_last_tx==ts_ping_tx );
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_tx )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->keepalive, ts_ping_tx )==0 );

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
  FD_TEST( state->defer_reset==0 );
  FD_TEST( state->keepalive->ts_last_tx==ts_ping_tx );
  FD_TEST( state->keepalive->ts_last_rx==ts_ping_rx );
  FD_TEST( !state->keepalive->inflight );
  FD_TEST( state->metrics.ping_ack_cnt==1UL );
  FD_TEST( state->rtt->latest_rtt==10e6f );
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_rx )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->keepalive, ts_ping_rx )==0 );

  /* Test PING TX */
  g_clock = state->keepalive->ts_next_tx;
  long const ts_ping_tx2 = g_clock;
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->keepalive, ts_ping_tx2 )==1 );
  FD_TEST( state->keepalive->inflight==0 );
  charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->defer_reset==0 );
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( state->keepalive->inflight==1 );
  FD_TEST( charge_busy==1 );
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )==sizeof(fd_h2_ping_t) );
  fd_h2_ping_t ping;
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &ping, sizeof(fd_h2_ping_t) );
  FD_TEST( ping.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ) );
  FD_TEST( ping.hdr.flags==0 );
  FD_TEST( state->keepalive->inflight==1 );
  charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( charge_busy==0 );
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )==0 );

  /* Test timeout */
  g_clock = state->keepalive->ts_deadline + 1L;
  long const ts_ping_timeout = g_clock;
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_timeout )==1 );

  /* Stepping should cause a reset due to timeout */
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Check the client's behavior if an oversized message is received */

static void
test_bundle_msg_oversized( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;

  fd_h2_conn_t * h2_conn = fd_grpc_client_h2_conn( state->grpc_client );
  fd_grpc_hdr_t hdr = {
    .compressed = 0,
    .msg_sz     = fd_uint_bswap( USHORT_MAX )
  };

  FD_TEST( state->bundle_subscription_live );
  fd_grpc_client_h2_callbacks.data( h2_conn, &stream->s, &hdr, sizeof(fd_grpc_hdr_t), 0UL );
  FD_TEST( !state->bundle_subscription_live );
  FD_TEST( state->defer_reset );

  test_bundle_env_destroy( env );
}

/* Ensure that the client resets after switching keys */

static void
test_bundle_keyswitch( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;

  void * keyswitch_mem = fd_wksp_alloc_laddr( wksp, fd_keyswitch_align(), fd_keyswitch_footprint(), 1UL );
  FD_TEST( keyswitch_mem );
  state->keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  memset( state->auther.pubkey, 0, 32 );

  fd_bundle_tile_housekeeping( state ); /* should not switch */
  FD_TEST( !state->defer_reset );

  fd_keyswitch_state( state->keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  state->keyswitch->bytes[0] = 0x01;
  fd_bundle_tile_housekeeping( state ); /* should switch */
  FD_TEST( state->defer_reset );
  FD_TEST( state->auther.pubkey[0] == 0x01 );

  test_bundle_env_destroy( env );
  fd_wksp_free_laddr( keyswitch_mem );
}

/* Verify that the bundle client status is reported correctly */

static void
test_bundle_client_status( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;
  fd_bundle_tile_t state_backup  = *state;
  fd_grpc_client_t client_backup = *state->grpc_client;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->tcp_sock_connected = 0;
  FD_TEST( fd_bundle_client_status( state )==0 );
  *state = state_backup;

  ushort const conn_dead_flags[] = {
    FD_H2_CONN_FLAGS_DEAD,
    FD_H2_CONN_FLAGS_SEND_GOAWAY
  };
  for( ulong i=0; i<sizeof(conn_dead_flags)/sizeof(ushort); i++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->grpc_client->conn->flags |= conn_dead_flags[ i ];
    FD_TEST( fd_bundle_client_status( state )==0 );
    *state->grpc_client = client_backup;
  }

  ushort const conn_prog_flags[] = {
    FD_H2_CONN_FLAGS_CLIENT_INITIAL,
    FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0,
    FD_H2_CONN_FLAGS_WAIT_SETTINGS_0,
    FD_H2_CONN_FLAGS_SERVER_INITIAL
  };
  for( ulong i=0; i<sizeof(conn_prog_flags)/sizeof(ushort); i++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->grpc_client->conn->flags |= conn_prog_flags[ i ];
    FD_TEST( fd_bundle_client_status( state )==1 );
    *state->grpc_client = client_backup;
  }

  for( int auth_state=0; auth_state<FD_BUNDLE_AUTH_STATE_DONE_WAIT; auth_state++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->auther.state = auth_state;
    FD_TEST( fd_bundle_client_status( state )==1 );
    state->auther.state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  }

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->builder_info_wait = 1;
  FD_TEST( fd_bundle_client_status( state )==2 ); /* rotate builder info without downtime */
  state->auther.state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->builder_info_avail = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->packet_subscription_live = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->bundle_subscription_live = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->keepalive->inflight     = 1;
  state->keepalive->ts_deadline -= g_clock-1L;
  FD_TEST( fd_bundle_client_status( state )==0 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->grpc_client->h2_hs_done = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state->grpc_client = client_backup;

  test_bundle_env_destroy( env );
}

/* Verify that reset clears everything */

static void
test_bundle_client_reset( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;

  FD_TEST( state->tcp_sock!=-1 );
  FD_TEST( state->tcp_sock_connected==1 );
  FD_TEST( state->defer_reset==0 );
  FD_TEST( state->builder_info_avail==1 );
  FD_TEST( state->builder_info_wait==0 );
  FD_TEST( state->packet_subscription_live==1 );
  FD_TEST( state->packet_subscription_wait==0 );
  FD_TEST( state->bundle_subscription_live==1 );
  FD_TEST( state->bundle_subscription_wait==0 );
  FD_TEST( state->rtt->is_rtt_valid==0 );
  FD_TEST( state->auther.state==FD_BUNDLE_AUTH_STATE_DONE_WAIT );
  FD_TEST( state->auther.needs_poll==0 );
  FD_TEST( state->grpc_client->ssl_hs_done==0 );
  FD_TEST( state->grpc_client->h2_hs_done==1 );
  FD_TEST( state->grpc_client->stream_cnt==2 );

  fd_bundle_client_reset( state );

  FD_TEST( state->tcp_sock==-1 );
  FD_TEST( state->tcp_sock_connected==0 );
  FD_TEST( state->defer_reset==0 );
  FD_TEST( state->builder_info_avail==0 );
  FD_TEST( state->builder_info_wait==0 );
  FD_TEST( state->packet_subscription_live==0 );
  FD_TEST( state->packet_subscription_wait==0 );
  FD_TEST( state->bundle_subscription_live==0 );
  FD_TEST( state->bundle_subscription_wait==0 );
  FD_TEST( state->rtt->is_rtt_valid==0 );
  FD_TEST( state->auther.state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
  FD_TEST( state->auther.needs_poll==1 );
  FD_TEST( state->grpc_client->ssl_hs_done==0 );
  FD_TEST( state->grpc_client->h2_hs_done==0 );
  FD_TEST( state->grpc_client->stream_cnt==0 );

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

static void
test_bundle_client_request_builder_fee_info( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->grpc_client;

  /* Client should request new builder info */
  state->builder_info_avail = 0;
  FD_TEST( state->builder_info_wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  FD_TEST( state->grpc_client->stream_cnt==2 );
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->builder_info_wait==0 );

  /* Unblock it ... */
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->builder_info_wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->grpc_client->stream_pool[ 2 ];
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
  expect_h2_hdr( grpc_client->frame_tx, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  fd_bundle_client_grpc_rx_start( state, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );

  /* Protobuf encoder util */
  uchar pb_buf[ 128 ];
  ulong pb_sz = 0UL;
  block_engine_BlockBuilderFeeInfoResponse resp = block_engine_BlockBuilderFeeInfoResponse_init_default;
#define ENCODE_MSG() do { \
    pb_ostream_t ostream = pb_ostream_from_buffer( pb_buf, sizeof(pb_buf) ); \
    FD_TEST( pb_encode( &ostream, &block_engine_BlockBuilderFeeInfoResponse_msg, &resp ) ); \
    pb_sz = ostream.bytes_written; \
  } while(0)

  /* Invalid Base58 */
  strcpy( resp.pubkey, "hello" );
  resp.commission = 2;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->builder_info_avail==0 );
  FD_TEST( state->builder_info_wait==1 ); /* retry ... */

  /* Invalid commission */
  uchar const pubkey[32] = { 1,2,3,4,5 };
  fd_base58_encode_32( pubkey, NULL, resp.pubkey );
  resp.commission = 101;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->builder_info_avail==0 );
  FD_TEST( state->builder_info_wait==1 ); /* retry ... */

  /* Valid response */
  resp.commission = 2;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->builder_info_avail==1 );
  FD_TEST( state->builder_info_wait==1 );

  /* End stream */
  fd_grpc_resp_hdrs_t grpc_resp_hdrs = {
    .h2_status   = 200,
    .grpc_status = FD_GRPC_STATUS_OK
  };
  fd_bundle_client_grpc_rx_end( state, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo, &grpc_resp_hdrs );
  FD_TEST( state->builder_info_wait==0 );

#undef ENCODE_MSG

  test_bundle_env_destroy( env );
}

/* Verify that the client subscribes to packets */

static void
test_bundle_client_subscribe_packets( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->grpc_client;

  state->packet_subscription_live = 0;
  FD_TEST( state->packet_subscription_wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  FD_TEST( state->grpc_client->stream_cnt==2 );
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->packet_subscription_wait==0 );

  /* Unblock it ... */
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->packet_subscription_wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->grpc_client->stream_pool[ 2 ];
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
  expect_h2_hdr( grpc_client->frame_tx, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  FD_TEST( state->packet_subscription_wait==1 );
  fd_bundle_client_grpc_rx_start( state, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );
  FD_TEST( state->packet_subscription_wait==0 );

  test_bundle_env_destroy( env );
}

/* Verify that the client subscribes to bundles */

static void
test_bundle_client_subscribe_bundles( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->grpc_client;

  state->bundle_subscription_live = 0;
  FD_TEST( state->bundle_subscription_wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  FD_TEST( state->grpc_client->stream_cnt==2 );
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->bundle_subscription_wait==0 );

  /* Unblock it ... */
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->bundle_subscription_wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->grpc_client->stream_pool[ 2 ];
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
  expect_h2_hdr( grpc_client->frame_tx, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  FD_TEST( state->bundle_subscription_wait==1 );
  fd_bundle_client_grpc_rx_start( state, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( state->bundle_subscription_wait==0 );

  test_bundle_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL, "normal"                     );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL, 256UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 16UL );
  FD_TEST( wksp );

  test_bundle_rx( wksp );
  test_bundle_stream_ended( wksp );
  test_bundle_stream_reset( wksp );
  test_bundle_header_timeout( wksp );
  test_bundle_rx_end_timeout( wksp );
  test_bundle_ping( wksp );
  test_bundle_msg_oversized( wksp );
  test_bundle_keyswitch( wksp );
  test_bundle_client_status( wksp );
  test_bundle_client_reset( wksp );
  test_bundle_no_builder_fee_info( wksp );
  test_bundle_client_request_builder_fee_info( wksp );
  test_bundle_client_subscribe_packets( wksp );
  test_bundle_client_subscribe_bundles( wksp );

  /* Check for memory leaks */
  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
