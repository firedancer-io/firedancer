#include "../fd_txn_m_t.h"
#include "fd_bundle_auth.h"
#include "fd_bundle_tile_private.h"
#include "../../waltz/grpc/fd_grpc_client_private.h"
#include "../../waltz/h2/fd_h2_conn.h"
#include <sys/socket.h>
#include <unistd.h>

/* Util for creating a mock bundle topology. */

struct test_bundle_env {
  fd_stem_context_t stem[1];
  ulong             stem_seqs    [1];
  ulong             stem_depths  [1];
  ulong             stem_cr_avail[1];
  fd_frag_meta_t *  out_mcache;
  uchar *           out_dcache;
  int               server_sock;

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
  env->server_sock = -1;

  fd_bundle_tile_t * state = env->state;
  state->stem = env->stem;
  state->verify_out = (fd_bundle_out_ctx_t) {
    .mem    = dcache,
    .chunk0 = 0UL,
    .chunk  = 0UL,
    .wmark  = fd_dcache_compact_wmark( dcache, dcache, FD_TPU_PARSED_MTU ),
    .idx    = 0UL,
  };

  state->tcp_sock        = -1;
  state->grpc_buf_max    = 4096UL;
  state->grpc_client_mem = fd_wksp_alloc_laddr( wksp, fd_grpc_client_align(), fd_grpc_client_footprint( state->grpc_buf_max ), 1UL );
  state->grpc_client     = fd_grpc_client_new( state->grpc_client_mem, &fd_bundle_client_grpc_callbacks, state->grpc_metrics, state, state->grpc_buf_max, 1UL );
  fd_h2_conn_t * h2_conn = fd_grpc_client_h2_conn( state->grpc_client );
  h2_conn->flags = 0;

  state->ping_threshold_ticks = fd_ulong_pow2_up( (ulong)( (double)1e9 * fd_tempo_tick_per_ns( NULL ) ) );

  return env;
}

FD_FN_UNUSED static void
test_bundle_env_mock_conn_empty( test_bundle_env_t * env ) {
  fd_bundle_tile_t * ctx = env->state;
  long const ts_start = fd_bundle_tickcount();
  fd_rng_new( ctx->rng, 42U, 42UL );
  ctx->tcp_sock_connected = 1;
  ctx->auther.state       = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  ctx->last_ping_rx_ticks = ts_start;
  ctx->last_ping_tx_ticks = ts_start;
  ctx->last_ping_tx_nanos = fd_log_wallclock();
  fd_rng_new( ctx->rng, 42U, 42UL );
  fd_bundle_client_set_ping_interval( ctx, (long)1e9 );
  FD_TEST( fd_bundle_client_ping_is_timeout( ctx, ts_start )==0 );
  FD_TEST( !fd_bundle_client_ping_is_due( ctx, ts_start ) );

  int sockpair[2] = { -1, -1 };
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM, 0, sockpair ) );
  env->server_sock = sockpair[0];
  ctx->tcp_sock    = sockpair[1];
}

FD_FN_UNUSED static void
test_bundle_env_mock_h2_hs( fd_bundle_tile_t * ctx ) {
  ctx->grpc_client->h2_hs_done  = 1;
  FD_TEST( !fd_grpc_client_request_is_blocked( ctx->grpc_client ) );
  long const ts_start = fd_bundle_tickcount();
  FD_TEST( !fd_bundle_tile_should_stall( ctx, ts_start ) );
}

FD_FN_UNUSED static void
test_bundle_env_mock_builder_info( fd_bundle_tile_t * ctx ) {
  ctx->builder_info_avail = 1;
  /* FIXME actually fill it in ... */
}

FD_FN_UNUSED static void
test_bundle_env_mock_builder_info_req( fd_bundle_tile_t * ctx ) {
  ctx->builder_info_wait = 1;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( ctx->grpc_client, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;
}

FD_FN_UNUSED static void
test_bundle_env_mock_bundle_stream( fd_bundle_tile_t * ctx ) {
  ctx->bundle_subscription_live = 1;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( ctx->grpc_client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;
}

FD_FN_UNUSED static void
test_bundle_env_mock_packet_stream( fd_bundle_tile_t * ctx ) {
  ctx->packet_subscription_live = 1;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( ctx->grpc_client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;
}

FD_FN_UNUSED static void
test_bundle_env_mock_conn( test_bundle_env_t * env ) {
  test_bundle_env_mock_conn_empty( env );

  fd_bundle_tile_t * ctx = env->state;
  test_bundle_env_mock_h2_hs( ctx );
  test_bundle_env_mock_builder_info( ctx );
  test_bundle_env_mock_bundle_stream( ctx );
  test_bundle_env_mock_packet_stream( ctx );

  FD_TEST( fd_bundle_client_status( ctx )==2 );
  FD_TEST( fd_h2_rbuf_free_sz( ctx->grpc_client->frame_tx )>=2048UL );
}

static void
test_bundle_env_destroy( test_bundle_env_t * env ) {
  if( env && env->server_sock>=0 ) {
    FD_TEST( 0==close( env->server_sock ) );
    env->server_sock = -1;
  }
  if( env && env->state->tcp_sock>=0 ) {
    FD_TEST( 0==close( env->state->tcp_sock ) );
    env->state->tcp_sock = -1;
  }
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( env->out_mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( env->out_dcache ) ) );
  fd_wksp_free_laddr( env->state->grpc_client_mem );
  fd_memset( env, 0, sizeof(test_bundle_env_t) );
}
