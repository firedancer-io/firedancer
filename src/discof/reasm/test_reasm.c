#include "fd_reasm.h"
#include "fd_reasm_private.h"
#include "../../disco/fd_disco_base.h"

#define PRINT_MAP(name)                                                       \
  do {                                                                        \
    name##_t * name = reasm->name;                                            \
    fd_reasm_fec_t * pool = reasm->pool;                                      \
    FD_LOG_NOTICE(( #name ));                                                 \
    for( name##_iter_t iter = name##_iter_init(       name, pool );           \
                             !name##_iter_done( iter, name, pool );           \
                       iter = name##_iter_next( iter, name, pool ) ) {        \
      fd_reasm_fec_t const * fec = name##_iter_ele_const( iter, name, pool ); \
      FD_LOG_NOTICE(( "(%lu, %u)", fec->slot, fec->fec_set_idx ));            \
    }                                                                         \
  } while(0)

void
test_insert( fd_wksp_t * wksp ) {
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_reasm_fec_t * pool = reasm->pool;
  // ulong            null = pool_idx_null( pool );

  ancestry_t * ancestry = reasm->ancestry;
  frontier_t * frontier = reasm->frontier;
  orphaned_t * orphaned = reasm->orphaned;
  subtrees_t * subtrees = reasm->subtrees;

  /* Receive (0, 64) -> (1, 32) -> (1, 0) -> (2, 0) -> (3, 64) -> (2, 32) -> (3, 32) -> (3, 0) */

  fd_hash_t mr0_64[1] = {{{ 0 }}};
  fd_hash_t mr1_00[1] = {{{ 1 }}};
  fd_hash_t mr1_32[1] = {{{ 2 }}};
  fd_hash_t mr2_00[1] = {{{ 3 }}};
  fd_hash_t mr2_32[1] = {{{ 4 }}};
  fd_hash_t mr3_00[1] = {{{ 5 }}};
  fd_hash_t mr3_32[1] = {{{ 6 }}};
  fd_hash_t mr3_64[1] = {{{ 7 }}};

  fd_reasm_init( reasm, mr0_64, 0 );
  fd_reasm_fec_t * f0_64 = fd_reasm_query( reasm, mr0_64 );
  FD_TEST( f0_64 );
  FD_TEST( frontier_ele_query( frontier, &f0_64->key, NULL, pool ) == f0_64 );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, mr1_32, mr1_00, 1, 32, 1, 32, 1, 1 );
  FD_TEST( subtrees_ele_query( subtrees, &f1_32->key, NULL, pool ) == f1_32 );

  fd_reasm_fec_t * f1_00 = fd_reasm_insert( reasm, mr1_00, mr0_64, 1, 0, 1, 32, 0, 0 );
  FD_TEST( ancestry_ele_query( ancestry, &f1_00->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f0_64->key, NULL, pool ) );
  FD_TEST( frontier_ele_query( frontier, &f1_32->key, NULL, pool ) );

  fd_reasm_fec_t * f2_00 = fd_reasm_insert( reasm, mr2_00, mr1_32, 2, 0, 1, 32, 0, 0 );
  FD_TEST( frontier_ele_query( frontier, &f2_00->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f1_32->key, NULL, pool ) );

  fd_reasm_fec_t * f3_64 = fd_reasm_insert( reasm, mr3_64, mr3_32, 3, 64, 2, 32, 1, 1 );
  FD_TEST( subtrees_ele_query( subtrees, &f3_64->key, NULL, pool ) );

  fd_reasm_fec_t * f2_32 = fd_reasm_insert( reasm, mr2_32, mr2_00, 2, 32, 1, 32, 1, 1 );
  FD_TEST( frontier_ele_query( frontier, &f2_32->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f2_00->key, NULL, pool ) );

  fd_reasm_fec_t * f3_32 = fd_reasm_insert( reasm, mr3_32, mr3_00, 3, 32, 2, 32, 0, 0 );
  FD_TEST( subtrees_ele_query( subtrees, &f3_32->key, NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, &f3_64->key, NULL, pool ) );

  fd_reasm_fec_t * f3_00 = fd_reasm_insert( reasm, mr3_00, mr1_32, 3, 0, 2, 32, 0, 0 );
  FD_TEST( ancestry_ele_query( ancestry, &f3_00->key,  NULL, pool ) );
  FD_TEST( frontier_ele_query( frontier, &f2_32->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f3_32->key, NULL, pool ) );
  FD_TEST( frontier_ele_query( frontier, &f3_64->key, NULL, pool ) );

  fd_hash_t order[7] = {
      f1_00->key,
      f1_32->key,
      f2_00->key,
      f2_32->key,
      f3_00->key,
      f3_32->key,
      f3_64->key,
  };
  fd_reasm_fec_t * fec = NULL; ulong i = 0;
  while( FD_LIKELY( fec = fd_reasm_next( reasm ) ) ) { FD_TEST( 0==memcmp( &fec->key, &order[i], sizeof(fd_hash_t) ) ); i++; }
  FD_TEST( i==sizeof(order) / sizeof(fd_hash_t) );

  /* Equivocating last FEC set for slot 3 (mr3_64a), child (3, 64) of
     parent (3, 32). */

  fd_hash_t        mr3_64a[1] = { { { 9 } } }; /* equivocating  */
  fd_reasm_fec_t * f3_64a     = fd_reasm_insert( reasm, mr3_64a, mr3_32, 3, 64, 2, 32, 1, 1 );
  FD_TEST( frontier_ele_query( frontier, &f3_64a->key, NULL, pool ) );

  /* Equivocating first FEC set for slot 3 (mr3_0a) that chains of a
     different parent slot (2, 32) than the other version (mr3_0 chains
     off mr1_32). */

  fd_hash_t        mr3_0a[1] = { { { 10 } } };
  fd_reasm_fec_t * f3_0a     = fd_reasm_insert( reasm, mr3_0a, mr2_32, 3, 0, 1, 32, 0, 0 );
  FD_TEST( frontier_ele_query( frontier, &f3_0a->key, NULL, pool ) );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );
}

void
test_publish( fd_wksp_t * wksp ) {
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_hash_t mr0[1] = {{{ 0 }}};
  fd_hash_t mr1[1] = {{{ 1 }}};
  fd_hash_t mr2[1] = {{{ 2 }}};
  fd_hash_t mr3[1] = {{{ 3 }}};
  fd_hash_t mr4[1] = {{{ 4 }}};
  fd_hash_t mr5[1] = {{{ 5 }}};
  fd_hash_t mr6[1] = {{{ 6 }}};

  /*
         slot 0
           |
         slot 1
         /    \
    slot 2    |
       |    slot 3
    slot 4    |
            slot 5
              |
            slot 6
  */

  /* Set the root (snapshot slot). */

  fd_reasm_init( reasm, mr0, 0 );

  /* Typical startup behavior, turbine orphan FECs added. */

  fd_reasm_insert( reasm, mr4, mr2, 4, 0, 2, 0, 1, 1 );
  fd_reasm_insert( reasm, mr6, mr5, 6, 0, 1, 0, 1, 1 );

  /* Repairing backwards, interleaved. */

  fd_reasm_insert( reasm, mr5, mr3, 5, 0, 2, 0, 1, 1 );
  fd_reasm_insert( reasm, mr2, mr1, 2, 0, 1, 0, 1, 1 );
  fd_reasm_insert( reasm, mr3, mr1, 3, 0, 2, 0, 1, 1 );
  fd_reasm_insert( reasm, mr1, mr0, 1, 0, 1, 0, 1, 1 );

  /* Check in-order delivery. */

  fd_reasm_fec_t * fec = NULL;
  while( FD_LIKELY( fec ) ) {
    fec = fd_reasm_next( reasm );
    FD_TEST( 0==memcmp( &fec->key, &mr0, sizeof(fd_hash_t) ) );
    FD_TEST( 0==memcmp( &fec->key, &mr1, sizeof(fd_hash_t) ) );
    FD_TEST( 0==memcmp( &fec->key, &mr2, sizeof(fd_hash_t) ) );
    FD_TEST( 0==memcmp( &fec->key, &mr4, sizeof(fd_hash_t) ) );
    FD_TEST( 0==memcmp( &fec->key, &mr3, sizeof(fd_hash_t) ) );
    FD_TEST( 0==memcmp( &fec->key, &mr5, sizeof(fd_hash_t) ) );
  }

  /* Publish. */

  fd_reasm_fec_t * oldr = fd_reasm_root( reasm );
  FD_TEST( oldr );
  fd_reasm_publish( reasm, mr2 );
  fd_reasm_fec_t * newr = fd_reasm_root( reasm );
  FD_TEST( newr );
  FD_TEST( 0==memcmp( newr, mr2, sizeof(fd_hash_t) ) );
  FD_TEST( ancestry_ele_query( reasm->ancestry, mr2, NULL, reasm->pool ) != NULL );
  FD_TEST( frontier_ele_query( reasm->frontier, mr4, NULL, reasm->pool ) != NULL );
  FD_TEST( !fd_reasm_query( reasm, mr0 ) );
  FD_TEST( !fd_reasm_query( reasm, mr1 ) );
  FD_TEST( !fd_reasm_query( reasm, mr3 ) );
  FD_TEST( !fd_reasm_query( reasm, mr5 ) );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );
}

void
test_slot_mr( fd_wksp_t * wksp ) {
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );
  FD_TEST( reasm->slot_mr );

  fd_reasm_fec_t * pool = reasm->pool;
  // ulong            null = pool_idx_null( pool );

  ancestry_t * ancestry = reasm->ancestry;
  frontier_t * frontier = reasm->frontier;
  subtrees_t * subtrees = reasm->subtrees;

  fd_hash_t mr0[1] = {{{ 0 }}};
  fd_hash_t mr1[1] = {{{ 1 }}};
  fd_hash_t mr2[1] = {{{ 2 }}};
  fd_hash_t mr3[1] = {{{ 3 }}};
  fd_hash_t mr4[1] = {{{ 4 }}};

  fd_reasm_init( reasm, mr1, 1 );
  fd_reasm_fec_t * fec1 = fd_reasm_query( reasm, mr1 );
  FD_TEST( fec1 );
  FD_TEST( frontier_ele_query( frontier, &fec1->key, NULL, pool ) == fec1 );

  fd_reasm_fec_t * fec2 = fd_reasm_insert( reasm, mr2, mr0, 2, 0, 1, 32, 0, 1 ); /* insert with bad mr0 should be mr1 */
  FD_TEST( ancestry_ele_query( ancestry, &fec1->key, NULL, pool ) );             /* successfully chains anyways */
  FD_TEST( frontier_ele_query( frontier, &fec2->key, NULL, pool ) );

  fd_reasm_fec_t * fec4 = fd_reasm_insert( reasm, mr4, mr0, 4, 0, 1, 32, 0, 1 ); /* insert with bad mr0 should be mr3 */
  FD_TEST( subtrees_ele_query( subtrees, &fec4->key, NULL, pool ) );             /* orphaned */

  fd_reasm_fec_t * fec3 = fd_reasm_insert( reasm, mr3, mr2, 3, 0, 1, 32, 0, 1 );
  FD_TEST( ancestry_ele_query( ancestry, &fec3->key, NULL, pool ) );             /* mr3 should chain to 2 */
  FD_TEST( frontier_ele_query( frontier, &fec4->key, NULL, pool ) );             /* mr4 should have chained */
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_insert( wksp );
  test_publish( wksp );
  test_slot_mr( wksp );

  ulong sig = fd_disco_repair_replay_sig( 3508496, 1, 32, 128 );
  FD_TEST( fd_disco_repair_replay_sig_slot( sig ) == 3508496 );
  FD_TEST( fd_disco_repair_replay_sig_parent_off( sig ) == 1 );
  FD_TEST( fd_disco_repair_replay_sig_data_cnt( sig ) == 32 );
  FD_TEST( fd_disco_repair_replay_sig_slot_complete( sig ) == 1 );

  fd_halt();
  return 0;
}
