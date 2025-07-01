#include "fd_bundle_auth.h"
#include "fd_bundle_tile_private.h"
#include "../fd_txn_m_t.h"
#include "../../waltz/grpc/fd_grpc_client_private.h"
#include "../../waltz/h2/fd_h2_conn.h"

FD_IMPORT_BINARY( test_bundle_response, "src/disco/bundle/test_bundle_response.binpb" );

__attribute__((weak)) char const fdctl_version_string[] = "0.0.0";

/* Util for creating a mock bundle topology. */

struct test_bundle_env {
  fd_stem_context_t stem[1];
  ulong             stem_seqs    [1];
  ulong             stem_depths  [1];
  ulong             stem_cr_avail[1];
  fd_frag_meta_t *  out_mcache;
  uchar *           out_dcache;

  fd_bundle_tile_t state[1];
};

typedef struct test_bundle_env test_bundle_env_t;

static test_bundle_env_t *
test_bundle_env_create( test_bundle_env_t * env,
                        fd_wksp_t *         wksp ) {
  fd_memset( env, 0, sizeof(test_bundle_env_t) );

  ulong const mcache_depth = FD_MCACHE_BLOCK;
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new(
      fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( mcache_depth, 0UL ), 1UL ),
      FD_MCACHE_BLOCK, 0UL, 0UL ) );
  FD_TEST( mcache );

  ulong const mtu = FD_TPU_PARSED_MTU;
  ulong const dcache_data_sz = fd_dcache_req_data_sz( mtu, mcache_depth, 1UL, 1 );
  void * dcache = fd_dcache_join( fd_dcache_new(
      fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL ),
      dcache_data_sz, 0UL ) );
  FD_TEST( dcache );

  /* Create a fake stem context */
  env->out_mcache       = mcache;
  env->out_dcache       = dcache;
  env->stem_seqs    [0] = 0UL;
  env->stem_depths  [0] = mcache_depth;
  env->stem_cr_avail[0] = ULONG_MAX;
  *env->stem = (fd_stem_context_t) {
    .mcaches  = &env->out_mcache,
    .seqs     = env->stem_seqs,
    .depths   = env->stem_depths,
    .cr_avail = env->stem_cr_avail,
    .cr_decrement_amount = 0UL
  };

  fd_bundle_tile_t * state = env->state;
  state->stem = env->stem;
  state->verify_out = (fd_bundle_out_ctx_t) {
    .mem    = dcache,
    .chunk0 = 0UL,
    .chunk  = 0UL,
    .wmark  = fd_dcache_compact_wmark( dcache, dcache, FD_TPU_PARSED_MTU ),
    .idx    = 0UL,
  };

  state->grpc_buf_max    = 4096UL;
  state->grpc_client_mem = fd_wksp_alloc_laddr( wksp, fd_grpc_client_align(), fd_grpc_client_footprint( state->grpc_buf_max ), 1UL );
  state->grpc_client     = fd_grpc_client_new( state->grpc_client_mem, &fd_bundle_client_grpc_callbacks, state->grpc_metrics, state, state->grpc_buf_max, 1UL );
  fd_h2_conn_t * h2_conn = fd_grpc_client_h2_conn( state->grpc_client );
  h2_conn->flags = 0;

  state->ping_threshold_ticks = fd_ulong_pow2_up( (ulong)( (double)1e9 * fd_tempo_tick_per_ns( NULL ) ) );

  return env;
}

static void
test_bundle_env_mock_conn( test_bundle_env_t * env ) {
  fd_bundle_tile_t * ctx = env->state;
  ctx->tcp_sock_connected       = 1;
  ctx->grpc_client->h2_hs_done  = 1;
  ctx->builder_info_avail       = 1;
  ctx->bundle_subscription_live = 1;
  ctx->packet_subscription_live = 1;
  ctx->auther.state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  ctx->last_ping_rx_ts          = fd_tickcount();
  FD_TEST( fd_bundle_client_status( ctx )==2 );
  FD_TEST( fd_h2_rbuf_free_sz( ctx->grpc_client->frame_tx )>=2048UL );
  FD_TEST( !fd_grpc_client_request_is_blocked( ctx->grpc_client ) );
  FD_TEST( !fd_bundle_tile_should_stall( ctx, fd_tickcount() ) );
}

static void
test_bundle_env_destroy( test_bundle_env_t * env ) {
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( env->out_mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( env->out_dcache ) ) );
  fd_wksp_free_laddr( env->state->grpc_client_mem );
  fd_memset( env, 0, sizeof(test_bundle_env_t) );
}

/* Test that packets and bundles get forwarded correctly to Firedancer
   components. */

static void
test_data_path( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1]; test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

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

  fd_frag_meta_t expected[2] = {
    { .seq=0UL, .sig=0UL, .chunk=0, .sz=sizeof(fd_txn_m_t)+8, .ctl=0 },
    { .seq=1UL, .sig=0UL, .chunk=2, .sz=sizeof(fd_txn_m_t)+8, .ctl=0 }
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
test_missing_builder_fee_info( fd_wksp_t * wksp ) {
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
test_stream_ended( fd_wksp_t * wksp ) {
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

static void
test_stream_reset( fd_wksp_t * wksp ) {
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

static void
test_conn_timeout( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state   = env->state;
  fd_grpc_client_t * client  = state->grpc_client;

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

static void
test_stream_msg_oversized( fd_wksp_t * wksp ) {
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

#if FD_HAS_INT128

/* Ensure that the client resets after switching keys */

static void
test_keyswitch( fd_wksp_t * wksp ) {
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

#else

static void
test_keyswitch( fd_wksp_t * wksp ) {
  (void)wksp;
}

#endif

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

  test_data_path( wksp );
  test_missing_builder_fee_info( wksp );
  test_stream_ended( wksp );
  test_stream_reset( wksp );
  test_conn_timeout( wksp );
  test_stream_msg_oversized( wksp );
  test_keyswitch( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
