#include "fd_fec_chainer.h"
#include "../../disco/fd_disco_base.h"

void
test_fec_ordering( fd_wksp_t * wksp ){
  ulong fec_max = 32;

  void * mem = fd_wksp_alloc_laddr( wksp, fd_fec_chainer_align(), fd_fec_chainer_footprint( fec_max ), 1UL );
  FD_TEST( mem );
  fd_fec_chainer_t * chainer = fd_fec_chainer_join( fd_fec_chainer_new( mem, fec_max, 0UL ) );

  uchar mr_root[FD_SHRED_MERKLE_ROOT_SZ] = { 1 };
  uchar mr1_0  [FD_SHRED_MERKLE_ROOT_SZ] = { 2 };
  uchar mr1_32 [FD_SHRED_MERKLE_ROOT_SZ] = { 3 };
  uchar mr2_0  [FD_SHRED_MERKLE_ROOT_SZ] = { 4 };
  uchar mr2_32 [FD_SHRED_MERKLE_ROOT_SZ] = { 5 };
  uchar mr3_0  [FD_SHRED_MERKLE_ROOT_SZ] = { 6 };
  uchar mr3_32 [FD_SHRED_MERKLE_ROOT_SZ] = { 7 };
  uchar mr3_64 [FD_SHRED_MERKLE_ROOT_SZ] = { 8 };

  /* Receive (0, 64) -> (1, 32) -> (1, 0) -> (2, 0) -> (3, 64) -> (2, 32) -> (3, 32) -> (3, 0) */
  ulong keys[7] = { 1UL << 32 | 0,
                    1UL << 32 | 32,
                    2UL << 32 | 0,
                    2UL << 32 | 32,
                    3UL << 32 | 0,
                    3UL << 32 | 32,
                    3UL << 32 | 64 };

  fd_fec_ele_t * f0_64 = fd_fec_chainer_init( chainer, 0, mr_root );
  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &f0_64->key, NULL, chainer->pool ) == f0_64 );

  fd_fec_ele_t * f1_32 = fd_fec_chainer_insert( chainer, 1, 32, 32, 1, 1, 1, mr1_32, mr1_0 );
  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f1_32->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f1_32->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_orphaned_ele_query( chainer->orphaned, &f1_32->key, NULL, chainer->pool ) == f1_32 );

  fd_fec_ele_t * f1_0 = fd_fec_chainer_insert( chainer, 1, 0, 32, 0, 0, 1, mr1_0, mr_root );
  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f1_0->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_ancestry_ele_query( chainer->ancestry, &f1_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f1_0->key, NULL, chainer->pool ) );

  FD_TEST(  fd_fec_frontier_ele_query( chainer->frontier, &f1_32->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f1_32->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f1_32->key, NULL, chainer->pool ) );

  fd_fec_ele_t * f2_0 = fd_fec_chainer_insert( chainer, 2, 0, 32, 0, 0, 1, mr2_0, mr1_32 );
  FD_TEST(  fd_fec_frontier_ele_query( chainer->frontier, &f2_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f2_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f2_0->key, NULL, chainer->pool ) );

  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f1_32->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_ancestry_ele_query( chainer->ancestry, &f1_32->key, NULL, chainer->pool ) );

  fd_fec_ele_t * f3_64 = fd_fec_chainer_insert( chainer, 3, 64, 32, 1, 1, 2, mr3_64, mr3_32 );
  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f3_64->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f3_64->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_orphaned_ele_query( chainer->orphaned, &f3_64->key, NULL, chainer->pool ) );

  FD_TEST(  fd_fec_frontier_ele_query( chainer->frontier, &f2_0->key, NULL, chainer->pool ) );

  fd_fec_ele_t * f2_32 = fd_fec_chainer_insert( chainer, 2, 32, 32, 1, 1, 1, mr2_32, mr2_0 );
  FD_TEST(  fd_fec_frontier_ele_query( chainer->frontier, &f2_32->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f2_32->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f2_32->key, NULL, chainer->pool ) );

  FD_TEST(  fd_fec_ancestry_ele_query( chainer->ancestry, &f2_0->key, NULL, chainer->pool ) );

  fd_fec_ele_t * f3_32 = fd_fec_chainer_insert( chainer, 3, 32, 32, 0, 0, 2, mr3_32, mr3_0 );
  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f3_32->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f3_32->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_orphaned_ele_query( chainer->orphaned, &f3_32->key, NULL, chainer->pool ) );

  fd_fec_ele_t * f3_0 = fd_fec_chainer_insert( chainer, 3, 0, 32, 0, 0, 2, mr3_0, mr1_32 );
  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f3_0->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_ancestry_ele_query( chainer->ancestry, &f3_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f3_0->key, NULL, chainer->pool ) );

  FD_TEST(  fd_fec_frontier_ele_query( chainer->frontier, &f3_64->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f3_64->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_ancestry_ele_query( chainer->ancestry, &f3_32->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f3_32->key, NULL, chainer->pool ) );

  ulong i = 0;
  while ( !fd_fec_out_empty( chainer->out ) ) {
    fd_fec_out_t out = fd_fec_out_pop_head( chainer->out );
    ulong        key = out.slot << 32 | out.fec_set_idx;
    // FD_LOG_NOTICE(( "%lu: (%lu, %u) %lu %lu", i, out.slot, out.fec_set_idx, key, keys[i] ));
    FD_TEST( out.err == FD_FEC_CHAINER_SUCCESS );
    FD_TEST( key == keys[i] );
    i++;
  }

  fd_fec_out_t actual[1];
  fd_fec_out_t expected[1];

  /* Chained merkle root conflict for first FEC of slot 4 (doesn't chain
     correctly off last FEC of slot 3).

     (3, 64) formerly in the frontier now expected to be in the ancestry
     because (4, 0) is a child. But since (4, 0) is an invalid child, it
     shouldn't actually be inserted into the frontier. */

  fd_fec_ele_t * f4_0 = fd_fec_chainer_insert( chainer, 4, 0, 32, 0, 0, 1, (uchar[FD_SHRED_MERKLE_ROOT_SZ]){ 9 }, (uchar[FD_SHRED_MERKLE_ROOT_SZ]){ 42 } /* invalid chained merkle root */ );
  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f4_0->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_ancestry_ele_query( chainer->ancestry, &f3_64->key, NULL, chainer->pool ) );
  FD_TEST(  fd_fec_out_cnt( chainer->out ) == 1 );
  *actual   = fd_fec_out_pop_head( chainer->out );
  *expected = (fd_fec_out_t){ 4, 0, .err = FD_FEC_CHAINER_ERR_MERKLE };
  FD_TEST( 0 == memcmp( actual, expected, sizeof(fd_fec_out_t) ) );

  /* Equivocating FEC (slot 3, fec_set_idx 0) that chains off slot 2
     instead of slot 1 (parent_off = 1 instead of 2) with the correct
     chained merkle root. */

  fd_fec_ele_t * f3_0_eqvoc = fd_fec_chainer_insert( chainer, 3, 0, 32, 0, 0, 1, (uchar[FD_SHRED_MERKLE_ROOT_SZ]){ 9 }, mr2_32 );
  FD_TEST( !f3_0_eqvoc );
  FD_TEST(  fd_fec_out_cnt( chainer->out ) == 1 );
  *actual   = fd_fec_out_pop_head( chainer->out );
  *expected = (fd_fec_out_t){ 3, 0, .err = FD_FEC_CHAINER_ERR_UNIQUE };
  FD_TEST( 0 == memcmp( actual, expected, sizeof(fd_fec_out_t) ) );

  /* TODO more robust testing */

  fd_wksp_free_laddr( fd_fec_chainer_delete( fd_fec_chainer_leave( chainer ) ) );

}

void
test_single_fec( fd_wksp_t * wksp ){
  ulong fec_max = 32;

  void * mem = fd_wksp_alloc_laddr( wksp, fd_fec_chainer_align(), fd_fec_chainer_footprint( fec_max ), 1UL );
  FD_TEST( mem );
  fd_fec_chainer_t * chainer = fd_fec_chainer_join( fd_fec_chainer_new( mem, fec_max, 0UL ) );

  uchar mr_root[FD_SHRED_MERKLE_ROOT_SZ] = { 1 };
  uchar mr1_0  [FD_SHRED_MERKLE_ROOT_SZ] = { 2 };
  uchar mr2_0  [FD_SHRED_MERKLE_ROOT_SZ] = { 4 };
  uchar mr3_0  [FD_SHRED_MERKLE_ROOT_SZ] = { 6 };

  /* Receive (0, 64) -> (1, 0) -> (3, 0) -> (2, 0)
     single FEC slots */
  ulong keys[3] = { 1UL << 32 | 0,
                    2UL << 32 | 0,
                    3UL << 32 | 0 };

  fd_fec_ele_t * f0_64 = fd_fec_chainer_init( chainer, 0, mr_root );
  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &f0_64->key, NULL, chainer->pool ) == f0_64 );

  fd_fec_ele_t * f1_0 = fd_fec_chainer_insert( chainer, 1, 0, 32, 1, 1, 1, mr1_0, mr_root );
  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &f1_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f1_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f1_0->key, NULL, chainer->pool ) );

  fd_fec_ele_t * f3_0 = fd_fec_chainer_insert( chainer, 3, 0, 32, 1, 1, 1, mr3_0, mr2_0 );
  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f3_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f3_0->key, NULL, chainer->pool ) );
  FD_TEST( fd_fec_orphaned_ele_query( chainer->orphaned, &f3_0->key, NULL, chainer->pool ) );

  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &f1_0->key, NULL, chainer->pool ) );

  fd_fec_ele_t * f2_0 = fd_fec_chainer_insert( chainer, 2, 0, 32, 1, 1, 1, mr2_0, mr1_0 );
  FD_TEST( !fd_fec_frontier_ele_query( chainer->frontier, &f2_0->key, NULL, chainer->pool ) );
  FD_TEST( fd_fec_ancestry_ele_query( chainer->ancestry, &f2_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f2_0->key, NULL, chainer->pool ) );

  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &f3_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_ancestry_ele_query( chainer->ancestry, &f3_0->key, NULL, chainer->pool ) );
  FD_TEST( !fd_fec_orphaned_ele_query( chainer->orphaned, &f3_0->key, NULL, chainer->pool ) );

  ulong i = 0;
  while ( !fd_fec_out_empty( chainer->out ) ) {
    fd_fec_out_t out = fd_fec_out_pop_head( chainer->out );
    ulong        key = out.slot << 32 | out.fec_set_idx;
    // FD_LOG_NOTICE(( "%lu: (%lu, %u) %lu %lu", i, out.slot, out.fec_set_idx, key, keys[i] ));
    FD_TEST( out.err == FD_FEC_CHAINER_SUCCESS );
    FD_TEST( key == keys[i] );
    i++;
  }

  fd_wksp_free_laddr( fd_fec_chainer_delete( fd_fec_chainer_leave( chainer ) ) );

}

void
test_publish( fd_wksp_t * wksp ){
  ulong fec_max = 32;

  void * mem = fd_wksp_alloc_laddr( wksp, fd_fec_chainer_align(), fd_fec_chainer_footprint( fec_max ), 1UL );
  FD_TEST( mem );
  fd_fec_chainer_t * chainer = fd_fec_chainer_join( fd_fec_chainer_new( mem, fec_max, 0UL ) );

  uchar mr_root[FD_SHRED_MERKLE_ROOT_SZ] = { 1 };
  fd_fec_ele_t * f0_64 = fd_fec_chainer_init( chainer, 1, mr_root );

  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &f0_64->key, NULL, chainer->pool ) == f0_64 );

  /* Typical startup behavior, turbine orphan FECs added */
  fd_fec_chainer_insert( chainer, 10, 0, 32, 1, 1, 1, mr_root, mr_root );
  fd_fec_chainer_insert( chainer, 9, 0, 32, 1, 1, 1, mr_root, mr_root );

  /* simulating no FECs chained, but a new root is published */
  ulong new_root = 2UL << 32 | 0;
  fd_fec_chainer_publish( chainer, 2 );

  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &new_root, NULL, chainer->pool ) );

  /* Chain off of root slot for a bit */
  fd_fec_chainer_insert( chainer, 3, 0, 32, 1, 1, 1, mr_root, mr_root );
  fd_fec_chainer_insert( chainer, 4, 0, 32, 1, 1, 1, mr_root, mr_root );
  ulong new_frontier = 4UL << 32 | 0;
  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &new_frontier, NULL, chainer->pool ) );

  /* Publish to ancestor */
  fd_fec_chainer_publish( chainer, 3 );
  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &new_frontier, NULL, chainer->pool ) );

  /* Make a tree

  3 - 4 - 8 - 9 - 10
    \ 5 - 6 - 7

  */

  fd_fec_chainer_insert( chainer, 5, 0, 32, 1, 1, 2, mr_root, mr_root );
  fd_fec_chainer_insert( chainer, 6, 0, 32, 1, 1, 1, mr_root, mr_root );
  fd_fec_chainer_insert( chainer, 7, 0, 32, 1, 1, 1, mr_root, mr_root );
  fd_fec_chainer_insert( chainer, 8, 0, 32, 1, 1, 4, mr_root, mr_root );

  uint frontier_cnt = 0;
  ulong frontier_keys[2] = { 7UL << 32 | 0, 10UL << 32 | 0 };
  for( fd_fec_frontier_iter_t iter = fd_fec_frontier_iter_init( chainer->frontier, chainer->pool ); !fd_fec_frontier_iter_done( iter, chainer->frontier, chainer->pool ); iter = fd_fec_frontier_iter_next( iter, chainer->frontier, chainer->pool ) ){
    frontier_cnt++;
  }
  FD_TEST( frontier_cnt == sizeof(frontier_keys) / sizeof(ulong) );
  for( uint i = 0; i < sizeof(frontier_keys) / sizeof(ulong); i++ ){
    FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &frontier_keys[i], NULL, chainer->pool ) );
  }

  /* Publish down the tree */
  fd_fec_chainer_publish( chainer, 4 );
  new_frontier = 10UL << 32 | 0;
  FD_TEST( fd_fec_frontier_ele_query( chainer->frontier, &new_frontier, NULL, chainer->pool ) );

  FD_TEST( fd_fec_chainer_query( chainer, 4, 0 ) );
  FD_TEST( !fd_fec_chainer_query( chainer, 5, 0 ) );
  FD_TEST( !fd_fec_chainer_query( chainer, 6, 0 ) );
  FD_TEST( !fd_fec_chainer_query( chainer, 7, 0 ) );
  FD_TEST( fd_fec_chainer_query( chainer, 8, 0 ) );
  FD_TEST( fd_fec_chainer_query( chainer, 9, 0 ) );
  FD_TEST( fd_fec_chainer_query( chainer, 10, 0 ) );

  fd_wksp_free_laddr( fd_fec_chainer_delete( fd_fec_chainer_leave( chainer ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  // test_fec_ordering( wksp );
  // test_single_fec( wksp );
  test_publish( wksp );

  ulong sig = fd_disco_repair_replay_sig( 3508496, 1, 32, 128 );
  FD_TEST( fd_disco_repair_replay_sig_slot( sig ) == 3508496 );
  FD_TEST( fd_disco_repair_replay_sig_parent_off( sig ) == 1 );
  FD_TEST( fd_disco_repair_replay_sig_data_cnt( sig ) == 32 );
  FD_TEST( fd_disco_repair_replay_sig_slot_complete( sig ) == 1 );

  fd_halt();
  return 0;
}
