#include "fd_bundle_tile_private.h"
#include "../tiles.h" /* FD_TPU_PARSED_MTU */

FD_IMPORT_BINARY( test_bundle_response, "src/disco/bundle/test_bundle_response.binpb" );

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
  fd_frag_meta_t * stem_mcaches [1] = {mcache};
  ulong            stem_seqs    [1] = {0UL};
  ulong            stem_depths  [1] = {mcache_depth};
  ulong            stem_cr_avail[1] = {ULONG_MAX};
  fd_stem_context_t stem_ctx = {
    .mcaches  = stem_mcaches,
    .seqs     = stem_seqs,
    .depths   = stem_depths,
    .cr_avail = stem_cr_avail,
    .cr_decrement_amount = 0UL
  };

  fd_bundle_tile_t state[1] = {0};
  state->stem = &stem_ctx;
  state->verify_out = (fd_bundle_out_ctx_t) {
    .mem    = dcache,
    .chunk0 = 0UL,
    .chunk  = 0UL,
    .wmark  = fd_dcache_compact_wmark( dcache, dcache, FD_TPU_PARSED_MTU ),
    .idx    = 0UL,
  };

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
  for( ulong i=0UL; i<mcache_depth; i++ ) {
    mcache[ i ].tsorig = 0U;
    mcache[ i ].tspub  = 0U;
  }

  fd_frag_meta_t expected[2] = {
    { .seq=0UL, .sig=0UL, .chunk=0, .sz=sizeof(fd_txn_m_t)+8, .ctl=0 },
    { .seq=1UL, .sig=0UL, .chunk=2, .sz=sizeof(fd_txn_m_t)+8, .ctl=0 }
  };
  FD_TEST( fd_memeq( mcache, expected, 2*sizeof(fd_frag_meta_t) ) );

  state->builder_info_avail = 1;

  fd_bundle_client_grpc_rx_msg(
      state,
      test_bundle_response, test_bundle_response_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( dcache ) ) );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
