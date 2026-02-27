#include "fd_reasm.h"
#include "fd_reasm_private.h"

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

  fd_reasm_fec_t * pool = reasm_pool( reasm );
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

  fd_reasm_insert( reasm, mr0_64, NULL, 0, 0, 0, 0, 0, 0, 0, NULL, NULL );
  fd_reasm_fec_t * f0_64 = fd_reasm_query( reasm, mr0_64 );
  FD_TEST( f0_64 );
  FD_TEST( frontier_ele_query( frontier, &f0_64->key, NULL, pool ) == f0_64 );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, mr1_32, mr1_00, 1, 32, 1, 32, 1, 1, 0, NULL, NULL );
  FD_TEST( subtrees_ele_query( subtrees, &f1_32->key, NULL, pool ) == f1_32 );

  fd_reasm_fec_t * f1_00 = fd_reasm_insert( reasm, mr1_00, mr0_64, 1, 0, 1, 32, 0, 0, 0, NULL, NULL );
  FD_TEST( ancestry_ele_query( ancestry, &f1_00->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f0_64->key, NULL, pool ) );
  FD_TEST( frontier_ele_query( frontier, &f1_32->key, NULL, pool ) );

  fd_reasm_fec_t * f2_00 = fd_reasm_insert( reasm, mr2_00, mr1_32, 2, 0, 1, 32, 0, 0, 0, NULL, NULL );
  FD_TEST( frontier_ele_query( frontier, &f2_00->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f1_32->key, NULL, pool ) );

  fd_reasm_fec_t * f3_64 = fd_reasm_insert( reasm, mr3_64, mr3_32, 3, 64, 2, 32, 1, 1, 0, NULL, NULL );
  FD_TEST( subtrees_ele_query( subtrees, &f3_64->key, NULL, pool ) );

  fd_reasm_fec_t * f2_32 = fd_reasm_insert( reasm, mr2_32, mr2_00, 2, 32, 1, 32, 1, 1, 0, NULL, NULL );
  FD_TEST( frontier_ele_query( frontier, &f2_32->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f2_00->key, NULL, pool ) );

  fd_reasm_fec_t * f3_32 = fd_reasm_insert( reasm, mr3_32, mr3_00, 3, 32, 2, 32, 0, 0, 0, NULL, NULL);
  FD_TEST( subtrees_ele_query( subtrees, &f3_32->key, NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, &f3_64->key, NULL, pool ) );

  fd_reasm_fec_t * f3_00 = fd_reasm_insert( reasm, mr3_00, mr1_32, 3, 0, 2, 32, 0, 0, 0, NULL, NULL);
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
  while( FD_LIKELY( fec = fd_reasm_pop( reasm ) ) ) { FD_TEST( 0==memcmp( &fec->key, &order[i], sizeof(fd_hash_t) ) ); i++; }
  FD_TEST( i==sizeof(order) / sizeof(fd_hash_t) );

  /* Equivocating last FEC set for slot 3 (mr3_64a), child (3, 64) of
     parent (3, 32). */

  fd_hash_t        mr3_64a[1] = { { { 9 } } }; /* equivocating  */
  fd_reasm_fec_t * f3_64a     = fd_reasm_insert( reasm, mr3_64a, mr3_32, 3, 64, 2, 32, 1, 1, 0, NULL, NULL );
  FD_TEST( frontier_ele_query( frontier, &f3_64a->key, NULL, pool ) );

  /* Equivocating first FEC set for slot 3 (mr3_0a) that chains of a
     different parent slot (2, 32) than the other version (mr3_0 chains
     off mr1_32). */

  fd_hash_t        mr3_0a[1] = { { { 10 } } };
  fd_reasm_fec_t * f3_0a     = fd_reasm_insert( reasm, mr3_0a, mr2_32, 3, 0, 1, 32, 0, 0, 0, NULL, NULL );
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

  fd_reasm_insert( reasm, mr0, NULL, 0, 0, 0, 0, 0, 1, 0, NULL, NULL );

  /* Typical startup behavior, turbine orphan FECs added. */

  fd_reasm_insert( reasm, mr4, mr2, 4, 0, 2, 0, 1, 1, 0, NULL, NULL );
  fd_reasm_insert( reasm, mr6, mr5, 6, 0, 1, 0, 1, 1, 0, NULL, NULL );

  /* Repairing backwards, interleaved. */

  fd_reasm_insert( reasm, mr5, mr3, 5, 0, 2, 0, 1, 1, 0, NULL, NULL );
  fd_reasm_insert( reasm, mr2, mr1, 2, 0, 1, 0, 1, 1, 0, NULL, NULL );
  fd_reasm_insert( reasm, mr3, mr1, 3, 0, 2, 0, 1, 1, 0, NULL, NULL );
  fd_reasm_insert( reasm, mr1, mr0, 1, 0, 1, 0, 1, 1, 0, NULL, NULL );

  /* Check in-order delivery. */

  fd_reasm_fec_t * fec = NULL;
  while( FD_LIKELY( fec ) ) {
    fec = fd_reasm_pop( reasm );
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
  fd_reasm_publish( reasm, mr2, NULL );
  fd_reasm_fec_t * newr = fd_reasm_root( reasm );
  FD_TEST( newr );
  FD_TEST( 0==memcmp( newr, mr2, sizeof(fd_hash_t) ) );
  FD_TEST( ancestry_ele_query( reasm->ancestry, mr2, NULL, reasm_pool( reasm ) ) != NULL );
  FD_TEST( frontier_ele_query( reasm->frontier, mr4, NULL, reasm_pool( reasm ) ) != NULL );
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

  fd_reasm_fec_t * pool = reasm_pool( reasm );
  // ulong            null = pool_idx_null( pool );

  ancestry_t * ancestry = reasm->ancestry;
  frontier_t * frontier = reasm->frontier;
  subtrees_t * subtrees = reasm->subtrees;

  fd_hash_t mr0[1] = {{{ 0 }}};
  fd_hash_t mr1[1] = {{{ 1 }}};
  fd_hash_t mr2[1] = {{{ 2 }}};
  fd_hash_t mr3[1] = {{{ 3 }}};
  fd_hash_t mr4[1] = {{{ 4 }}};

  fd_reasm_insert( reasm, mr1, NULL, 1, 0, 0, 0, 0, 1, 0, NULL, NULL ); /* set root */
  fd_reasm_fec_t * fec1 = fd_reasm_query( reasm, mr1 );
  FD_TEST( fec1 );
  FD_TEST( frontier_ele_query( frontier, &fec1->key, NULL, pool ) == fec1 );

  fd_reasm_fec_t * fec2 = fd_reasm_insert( reasm, mr2, mr0, 2, 0, 1, 32, 0, 1, 0, NULL, NULL ); /* insert with bad mr0 should be mr1 */
  FD_TEST( ancestry_ele_query( ancestry, &fec1->key, NULL, pool ) );                /* successfully chains anyways */
  FD_TEST( frontier_ele_query( frontier, &fec2->key, NULL, pool ) );

  fd_reasm_fec_t * fec4 = fd_reasm_insert( reasm, mr4, mr0, 4, 0, 1, 32, 0, 1, 0 , NULL, NULL ); /* insert with bad mr0 should be mr3 */
  FD_TEST( subtrees_ele_query( subtrees, &fec4->key, NULL, pool ) );                /* orphaned */

  fd_reasm_fec_t * fec3 = fd_reasm_insert( reasm, mr3, mr2, 3, 0, 1, 32, 0, 1, 0, NULL, NULL );
  FD_TEST( ancestry_ele_query( ancestry, &fec3->key, NULL, pool ) );                /* mr3 should chain to 2 */
  FD_TEST( frontier_ele_query( frontier, &fec4->key, NULL, pool ) );                /* mr4 should have chained */
}

void
test_eqvoc( fd_wksp_t * wksp ) {
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_hash_t mr1[1]  = {{{ 1 }}};
  fd_hash_t mr1a[1] = {{{ 1, 0xa }}};
  fd_hash_t mr1b[1] = {{{ 1, 0xb }}};

  fd_reasm_insert( reasm, mr1, NULL, 1, 0, 1, 32, 0, 0, 0, NULL, NULL );

  /* Slot 1 equivocates. */

  fd_reasm_insert( reasm, mr1a, mr1, /* slot */ 1, /* fec_set_idx */ 32, 1, 32, 0, 0, 0, NULL, NULL );
  fd_reasm_insert( reasm, mr1b, mr1, /* slot */ 1, /* fec_set_idx */ 32, 1, 32, 0, 0, 0, NULL, NULL );

  fd_reasm_fec_t * fec1a = fd_reasm_query( reasm, mr1a );
  FD_TEST( fec1a );
  FD_TEST( fec1a->eqvoc );
  FD_TEST( !fec1a->confirmed );
  FD_TEST( fec1a==pool_ele( reasm_pool( reasm ), *out_peek_index( reasm->out, 0 ) ) );

  fd_reasm_fec_t * fec1b = fd_reasm_query( reasm, mr1b );
  FD_TEST( fec1b );
  FD_TEST( fec1b->eqvoc );
  FD_TEST( !fec1b->confirmed );
  FD_TEST( fec1b==pool_ele( reasm_pool( reasm ), *out_peek_index( reasm->out, 1 ) ) );

  FD_TEST( !fd_reasm_pop( reasm ) ); /* everything is equivocating so nothing should get popped */

  /* Confirm one branch of the equivocation. */

  fd_reasm_confirm( reasm, mr1b );
  FD_TEST( fec1b->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr1 )->confirmed );

  FD_TEST( fd_reasm_pop( reasm ) == fec1b ); /* pop fec1b */
  fd_hash_t mr1ba[1] = {{{ 1, 0xb, 0xa }}};
  fd_hash_t mr1bb[1] = {{{ 1, 0xb, 0xb }}};
  fd_hash_t mr2[1]   = {{{ 2 }}};

  /* Confirm 1bb before it has been inserted.  This has no effect. */

  fd_reasm_confirm( reasm, mr1bb );
  FD_TEST( !fd_reasm_pop( reasm ) );

  /* Insert some descendants of mr1b. */

  fd_reasm_insert( reasm, mr1ba, mr1b,  /* slot */ 1, 64, /* parent_off */ 1, /* data_cnt */ 32, /* data_complete */ 1, /* slot_complete */ 1, /* is_leader */ 0, NULL, NULL );
  fd_reasm_insert( reasm, mr1bb, mr1b,  /* slot */ 1, 64, /* parent_off */ 1, /* data_cnt */ 32, /* data_complete */ 1, /* slot_complete */ 1, /* is_leader */ 0, NULL, NULL );
  fd_reasm_insert( reasm, mr2,   mr1bb, /* slot */ 2, 0,  /* parent_off */ 1, /* data_cnt */ 32, /* data_complete */ 0, /* slot_complete */ 0, /* is_leader */ 0, NULL, NULL );

  /* mr1ba and mr1bb should not be delivered by pop even though they are
     chained to mr1b because they equivocate and are not valid. */

  FD_TEST( !fd_reasm_pop( reasm ) );

  /* Confirming a descendant should confirm the ancestors.  Note this
     confirms 1bb after the "missed" earlier confirmation (1bb's confirm
     arrived before its insertion). */

  fd_reasm_confirm( reasm, mr2 );
  FD_TEST( fd_reasm_query( reasm, mr2 )->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr1bb )->confirmed );
  FD_TEST( !fd_reasm_query( reasm, mr1ba )->confirmed );

  /* mr1bb was marked valid and should be delivered before mr2. */

  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr1bb ) );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr2 ) );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );
}

void
test_eqvoc_xidbid( fd_wksp_t * wksp ) {
  // checks the properties of the xid and bid maps are maintained correctly
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_hash_t mr0[1] = {{{ 1, 0 }}};
  fd_reasm_insert( reasm, mr0, NULL, 0, 0, 0, 0, 0, 1, 0, NULL, NULL );

  fd_hash_t mr1[1] = {{{ 1, 1 }}};
  fd_hash_t mr2[1] = {{{ 1, 2 }}};
  fd_hash_t mr3[1] = {{{ 1, 3 }}};
  fd_hash_t mr4[1] = {{{ 1, 4 }}};

                          fd_reasm_insert( reasm, mr1, mr0,  1, 0,  1, 32, 0, 0, 0, NULL, NULL );
                          fd_reasm_insert( reasm, mr2, mr1,  1, 32, 1, 32, 0, 0, 0, NULL, NULL );
  fd_reasm_fec_t * fec3 = fd_reasm_insert( reasm, mr3, mr2,  1, 64, 1, 32, 0, 1, 0, NULL, NULL );

  ulong last_xid = (1UL << 32) | 64UL;
  ulong bid      = (1UL << 32) | UINT_MAX;

  FD_TEST( xid_query( reasm->xid, bid, NULL )->cnt == 1 );
  FD_TEST( xid_query( reasm->xid, bid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec3 ) );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->cnt == 1 );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec3 ) );

  fd_reasm_fec_t * fec4 = fd_reasm_insert( reasm, mr4, mr2,  1, 64, 1, 32, 0, 1, 0, NULL, NULL ); /* equivocate on last fec set idx */
  FD_TEST( xid_query( reasm->xid, bid, NULL )->cnt == 2 );
  FD_TEST( xid_query( reasm->xid, bid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec3 ) );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->cnt == 2 );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec3 ) );

  fd_reasm_confirm( reasm, mr4 );
  FD_TEST( xid_query( reasm->xid, bid, NULL )->cnt == 2 );
  FD_TEST( xid_query( reasm->xid, bid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec4 ) );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->cnt == 2 );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec4 ) );

  /* publishing forward to mr4 (doesn't actually happen ... ) but should update the xid and bid maps to cnt 1 */
  fd_reasm_publish( reasm, mr4, NULL );
  FD_TEST( xid_query( reasm->xid, bid, NULL )->cnt == 1 );
  FD_TEST( xid_query( reasm->xid, bid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec4 ) );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->cnt == 1 );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec4 ) );

  fd_hash_t mr5[1] = {{{ 1, 5 }}};
  fd_reasm_insert( reasm, mr5, mr4,  2, 0, 1, 32, 0, 1, 0, NULL, NULL );
  fd_reasm_publish( reasm, mr5, NULL );
  ulong bid2      = (2UL << 32) | UINT_MAX;
  FD_TEST( !xid_query( reasm->xid, bid, NULL ) );
  FD_TEST( !xid_query( reasm->xid, last_xid, NULL ) );
  FD_TEST( xid_query( reasm->xid, bid2, NULL )->cnt == 1 );
}

void
test_eqvoc_transitive( fd_wksp_t * wksp ) {
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_hash_t mr1[1]    = {{{ 1 }}};
  fd_hash_t mr2a[1]   = {{{ 2, 0xa }}};
  fd_hash_t mr2b[1]   = {{{ 2, 0xb }}};
  fd_hash_t mr2aa[1]  = {{{ 2, 0xa, 0xa }}};
  fd_hash_t mr3[1] = {{{ 3 }}};
  fd_hash_t mr4[1] = {{{ 4 }}};
  fd_hash_t mr5[1] = {{{ 5 }}};

  fd_reasm_insert( reasm, mr1,  NULL,  /* slot */ 1, /* fec_set_idx */ 0,  1, 32, 0, 0, 0, NULL, NULL );
  fd_reasm_insert( reasm, mr2a, mr1,   /* slot */ 2, /* fec_set_idx */ 32, 1, 32, 0, 0, 0, NULL, NULL );
  fd_reasm_insert( reasm, mr3,  mr2aa, /* slot */ 3, /* fec_set_idx */ 0,  1, 32, 0, 0, 0, NULL, NULL );
  fd_reasm_insert( reasm, mr4,  mr2aa, /* slot */ 4, /* fec_set_idx */ 0,  1, 32, 0, 0, 0, NULL, NULL );

  /* Introduce 2b (which equivocates with 2a). */

  fd_reasm_insert( reasm, mr2b, mr1, /* slot */ 2, /* fec_set_idx */ 32, 1, 32, 0, 0, 0, NULL, NULL );

  /* Introduce 2aa, which un-orphans 3 and 4.  This should transitively
     mark 2aa, 3 and 4 all as equivocating because 2a equivocates. */

  fd_reasm_insert( reasm, mr2aa, mr2a, /* slot */ 2, /* fec_set_idx */ 64, 1, 32, 0, 1, 0, NULL, NULL );

  FD_TEST( !fd_reasm_query( reasm, mr1 )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr2a )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr2b )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr2aa )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr3 )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr4 )->eqvoc );

  /* Confirm 3, which also should confirm mr1aa, mr1a, mr1. */

  fd_reasm_confirm( reasm, mr4 );

  FD_TEST( fd_reasm_query( reasm, mr4 )->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr2aa )->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr2a )->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr1 )->confirmed );
  FD_TEST( !fd_reasm_query( reasm, mr3 )->confirmed );
  FD_TEST( !fd_reasm_query( reasm, mr2b )->confirmed );

  /* Insert 4, which is a child of 3.  Even though 3 is eqvoc, 4 should
     not be eqvoc because 3 is confirmed. */

  fd_reasm_insert( reasm, mr5, mr4, /* slot */ 5, /* fec_set_idx */ 0, 1, 32, 0, 0, 0, NULL, NULL );

  FD_TEST( !fd_reasm_query( reasm, mr5 )->eqvoc );
  FD_TEST( !fd_reasm_query( reasm, mr5 )->confirmed );
  fd_reasm_print( reasm );
}

void
test_fec_after_eos(fd_wksp_t *wksp) {
  ulong fec_max = 32;
  void *mem = fd_wksp_alloc_laddr(wksp, fd_reasm_align(),
                                  fd_reasm_footprint(fec_max), 1UL);
  fd_reasm_t *reasm = fd_reasm_join(fd_reasm_new(mem, fec_max, 0UL));
  FD_TEST(reasm);

  fd_hash_t mr0[1] = {{{0}}};  fd_hash_t mr7[1] = {{{7}}};
  fd_hash_t mr1[1] = {{{1}}};  fd_hash_t mr8[1] = {{{8}}};
  fd_hash_t mr2[1] = {{{2}}};  fd_hash_t mr9[1] = {{{9}}};
  fd_hash_t mr3[1] = {{{3}}};
  fd_hash_t mr4[1] = {{{4}}};
  fd_hash_t mr5[1] = {{{5}}};
  fd_hash_t mr6[1] = {{{6}}};
  /*                               slot fecidx p_off data_cnt data_cmpl slot_cmpl is_leader */
  fd_reasm_insert(reasm, mr0, NULL, 0,   0,    0,    0,       0,        1,        0, NULL, NULL);
  fd_reasm_insert(reasm, mr1, mr0,  1,   0,    1,    32,      0,        0,        0, NULL, NULL);
  fd_reasm_insert(reasm, mr2, mr1,  1,   32,   1,    32,      0,        0,        0, NULL, NULL);
  fd_reasm_insert(reasm, mr3, mr2,  1,   64,   1,    32,      0,        1,        0, NULL, NULL);
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr1) );
  /* show evidence of equivocation */
  fd_reasm_insert(reasm, mr4, mr3,  1,   96,   1,    32,      0,        0,        0, NULL, NULL);
  FD_TEST( fd_reasm_pop(reasm) == NULL );
  fd_reasm_insert(reasm, mr5, mr4,  1,   128,  1,    32,      0,        1,        0, NULL, NULL);
  FD_TEST( fd_reasm_pop(reasm) == NULL );

  fd_reasm_confirm(reasm, mr3);
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr2) );
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr3) );
  FD_TEST( fd_reasm_pop(reasm) == NULL );

  fd_reasm_insert( reasm, mr6, mr3,  2,   0,    1,    32,      0,        0,        0, NULL, NULL);
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr6) );

  /* now get these out of order. */
  fd_reasm_insert( reasm, mr9, mr8,  2,   96,    1,   32,      0,        0,        0, NULL, NULL); /* currently an orphan */
  fd_reasm_insert( reasm, mr8, mr7,  2,   64,    1,   32,      0,        1,        0, NULL, NULL); /* middle slot complete */

  FD_TEST( fd_reasm_query(reasm, mr8)->eqvoc );
  FD_TEST( fd_reasm_query(reasm, mr9)->eqvoc );

  /* now connect slot 2 from frontier to orphan*/
  fd_reasm_insert( reasm, mr7, mr6,  2,   32,    1,   32,      0,        0,        0, NULL, NULL);
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr7) );
  FD_TEST( fd_reasm_pop(reasm) == NULL );
}

void
test_xid_capacity( fd_wksp_t * wksp ) {
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  FD_LOG_NOTICE( ( "xid key cnt %lu", xid_key_max( reasm->xid ) ));
  FD_TEST( xid_key_max( reasm->xid ) >= fec_max + fd_ulong_max(fec_max / 1024, 1UL) );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );

  fec_max = 4096;
  mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  FD_LOG_NOTICE( ( "xid key cnt %lu", xid_key_max( reasm->xid ) ));
  FD_TEST( xid_key_max( reasm->xid ) >= fec_max + (fec_max / 1024) );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );

}

void
test_evict( fd_wksp_t * wksp ) {
  ulong        fec_max = 8;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );

  /* we expect xid map to hold > fec_max + fec_max / 1024 keys. In this case, it should be at least
     fec_max / 1024 is 0..... so idk. lets floor it at 1 in reasm for now. */

  FD_LOG_NOTICE( ( "xid key max %lu",  xid_key_max( reasm->xid ) ));
  FD_TEST( xid_key_max( reasm->xid ) >= fec_max + fd_ulong_max(fec_max / 1024, 1UL) );
  FD_TEST( reasm );

  fd_hash_t mr0[1] = {{{ 0 }}}; fd_hash_t mr9 [1] = {{{ 9 }}};
  fd_hash_t mr1[1] = {{{ 1 }}}; fd_hash_t mr10[1] = {{{ 10 }}};
  fd_hash_t mr2[1] = {{{ 2 }}};
  fd_hash_t mr3[1] = {{{ 3 }}};
  fd_hash_t mr4[1] = {{{ 4 }}};
  fd_hash_t mr5[1] = {{{ 5 }}};
  fd_hash_t mr6[1] = {{{ 6 }}};
  fd_hash_t mr7[1] = {{{ 7 }}};
  fd_hash_t mr8[1] = {{{ 8 }}};

  fd_reasm_evicted_t evicted[1];
  evicted->slot = ULONG_MAX;
                               /*  mr    cmr   slot fec_idx  p_off  data_cnt -  slot_cmpl - - */
  FD_TEST( fd_reasm_insert( reasm, mr0,  NULL, 1,   0,       1,     32,      0, 1,        0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr1,  mr0,  2,   0,       1,     32,      0, 1,        0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr2,  mr1,  3,   0,       1,     32,      0, 1,        0, NULL, evicted ) );
  /* fork 4 and 5 off 3*/
  FD_TEST( fd_reasm_insert( reasm, mr3,  mr2,  4,   0,       1,     32,      0, 0,        0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr4,  mr2, 5 ,   0 ,      1,   	32,      0, 0 ,       0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr5,  mr4,  5,   32,      1,     32,      0, 1,        0, NULL, evicted ) );
  fd_reasm_fec_t * replay5 = fd_reasm_query( reasm, mr4 );
  replay5->bank_idx = 1;
  replay5 = fd_reasm_query( reasm, mr5 );
  replay5->bank_idx = 1;

  /* now for orphans */
  FD_TEST( fd_reasm_insert( reasm, mr8,  mr7,  8,    0,       1,     32,     0, 0,        0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr9,  mr8,  8,    0,       1,     32,     0, 1,        0, NULL, evicted ) ); /* By the way maybe this should be rejected? agave will reject it. But lowkeys we would replay it.... */

  /* should be full */
  fd_reasm_print( reasm );
  FD_TEST( evicted->slot == ULONG_MAX ); /* nothing should have been evicted yet */

  /* evict and unconfirmed orphan */
  FD_TEST( fd_reasm_insert( reasm, mr6,  mr5,  6,    0,       1,     32,     0, 0,        0, NULL, evicted ) );
  FD_TEST( !fd_reasm_query( reasm, mr9 )); /* evicts unconfirmed orphan */
  FD_TEST( evicted->slot == 8 && evicted->fec_set_idx == 0 );

  /* evict an unconfirmed leaf */
  FD_TEST( fd_reasm_insert( reasm, mr9,  mr8,  8,    32,       1,     32,     0, 1,        0, NULL, evicted ) );
  FD_TEST( !fd_reasm_query( reasm, mr6 )); /* evicts unconfirmed leaf */
  FD_TEST( evicted->slot == 6 && evicted->fec_set_idx == 0 );

  FD_TEST( fd_reasm_insert( reasm, mr10, mr9,  10,    0,       1,     32,     0, 0,        0, NULL, evicted ) );
  FD_TEST( !fd_reasm_query( reasm, mr5 ) ); /* evicts only leaf even though bank idx is set */
  FD_TEST( fd_reasm_query( reasm, mr4 ) );
  FD_TEST( evicted->slot == 5 && evicted->fec_set_idx == 32 );
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
  test_eqvoc( wksp );
  test_xid_capacity( wksp );
  test_fec_after_eos( wksp );
  test_eqvoc_transitive( wksp );
  test_eqvoc_xidbid( wksp );
  test_evict( wksp );

  fd_halt();
  return 0;
}
