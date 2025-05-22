#include "fd_bundle_tile_private.h"
#include "../tiles.h" /* FD_TPU_PARSED_MTU */

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
  return env;
}

static void
test_bundle_env_destroy( test_bundle_env_t * env ) {
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( env->out_mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( env->out_dcache ) ) );
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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL, "normal"                     );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL, 96UL                         );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_data_path( wksp );
  test_missing_builder_fee_info( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
