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

  fd_reasm_fec_t * ev[1];
  fd_reasm_insert( reasm, mr0_64, NULL, 0, 0, 0, 0, 0, 0, 0, NULL, ev );
  fd_reasm_fec_t * f0_64 = fd_reasm_query( reasm, mr0_64 );
  FD_TEST( f0_64 );
  FD_TEST( frontier_ele_query( frontier, &f0_64->key, NULL, pool ) == f0_64 );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, mr1_32, mr1_00, 1, 32, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( subtrees_ele_query( subtrees, &f1_32->key, NULL, pool ) == f1_32 );

  fd_reasm_fec_t * f1_00 = fd_reasm_insert( reasm, mr1_00, mr0_64, 1, 0, 1, 32, 0, 0, 0, NULL, ev );
  FD_TEST( ancestry_ele_query( ancestry, &f1_00->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f0_64->key, NULL, pool ) );
  FD_TEST( frontier_ele_query( frontier, &f1_32->key, NULL, pool ) );

  fd_reasm_fec_t * f2_00 = fd_reasm_insert( reasm, mr2_00, mr1_32, 2, 0, 1, 32, 0, 0, 0, NULL, ev );
  FD_TEST( frontier_ele_query( frontier, &f2_00->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f1_32->key, NULL, pool ) );

  fd_reasm_fec_t * f3_64 = fd_reasm_insert( reasm, mr3_64, mr3_32, 3, 64, 2, 32, 1, 1, 0, NULL, ev );
  FD_TEST( subtrees_ele_query( subtrees, &f3_64->key, NULL, pool ) );

  fd_reasm_fec_t * f2_32 = fd_reasm_insert( reasm, mr2_32, mr2_00, 2, 32, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( frontier_ele_query( frontier, &f2_32->key, NULL, pool ) );
  FD_TEST( ancestry_ele_query( ancestry, &f2_00->key, NULL, pool ) );

  fd_reasm_fec_t * f3_32 = fd_reasm_insert( reasm, mr3_32, mr3_00, 3, 32, 2, 32, 0, 0, 0, NULL, ev);
  FD_TEST( subtrees_ele_query( subtrees, &f3_32->key, NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, &f3_64->key, NULL, pool ) );

  fd_reasm_fec_t * f3_00 = fd_reasm_insert( reasm, mr3_00, mr1_32, 3, 0, 2, 32, 0, 0, 0, NULL, ev);
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
  fd_reasm_fec_t * f3_64a     = fd_reasm_insert( reasm, mr3_64a, mr3_32, 3, 64, 2, 32, 1, 1, 0, NULL, ev );
  FD_TEST( frontier_ele_query( frontier, &f3_64a->key, NULL, pool ) );

  /* Equivocating first FEC set for slot 3 (mr3_0a) that chains of a
     different parent slot (2, 32) than the other version (mr3_0 chains
     off mr1_32). */

  fd_hash_t        mr3_0a[1] = { { { 10 } } };
  fd_reasm_fec_t * f3_0a     = fd_reasm_insert( reasm, mr3_0a, mr2_32, 3, 0, 1, 32, 0, 0, 0, NULL, ev );
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

  fd_reasm_fec_t * ev[1];
  fd_reasm_insert( reasm, mr0, NULL, 0, 0, 0, 0, 0, 1, 0, NULL, ev );

  /* Typical startup behavior, turbine orphan FECs added. */

  fd_reasm_insert( reasm, mr4, mr2, 4, 0, 2, 0, 1, 1, 0, NULL, ev );
  fd_reasm_insert( reasm, mr6, mr5, 6, 0, 1, 0, 1, 1, 0, NULL, ev );

  /* Repairing backwards, interleaved. */

  fd_reasm_insert( reasm, mr5, mr3, 5, 0, 2, 0, 1, 1, 0, NULL, ev );
  fd_reasm_insert( reasm, mr2, mr1, 2, 0, 1, 0, 1, 1, 0, NULL, ev );
  fd_reasm_insert( reasm, mr3, mr1, 3, 0, 2, 0, 1, 1, 0, NULL, ev );
  fd_reasm_insert( reasm, mr1, mr0, 1, 0, 1, 0, 1, 1, 0, NULL, ev );

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
  fd_reasm_fec_t * ev[1];

  fd_reasm_insert( reasm, mr1, NULL, 1, 0, 0, 0, 0, 1, 0, NULL, ev ); /* set root */
  fd_reasm_fec_t * fec1 = fd_reasm_query( reasm, mr1 );
  FD_TEST( fec1 );
  FD_TEST( frontier_ele_query( frontier, &fec1->key, NULL, pool ) == fec1 );

  fd_reasm_fec_t * fec2 = fd_reasm_insert( reasm, mr2, mr0, 2, 0, 1, 32, 0, 1, 0, NULL, ev ); /* insert with bad mr0 should be mr1 */
  FD_TEST( ancestry_ele_query( ancestry, &fec1->key, NULL, pool ) );                /* successfully chains anyways */
  FD_TEST( frontier_ele_query( frontier, &fec2->key, NULL, pool ) );

  fd_reasm_fec_t * fec4 = fd_reasm_insert( reasm, mr4, mr0, 4, 0, 1, 32, 0, 1, 0 , NULL, ev ); /* insert with bad mr0 should be mr3 */
  FD_TEST( subtrees_ele_query( subtrees, &fec4->key, NULL, pool ) );                /* orphaned */

  fd_reasm_fec_t * fec3 = fd_reasm_insert( reasm, mr3, mr2, 3, 0, 1, 32, 0, 1, 0, NULL, ev );
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
  fd_reasm_fec_t * ev[1];

  fd_reasm_insert( reasm, mr1, NULL, 1, 0, 1, 32, 0, 0, 0, NULL, ev );

  /* Slot 1 equivocates. */

  fd_reasm_insert( reasm, mr1a, mr1, /* slot */ 1, /* fec_set_idx */ 32, 1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr1b, mr1, /* slot */ 1, /* fec_set_idx */ 32, 1, 32, 0, 0, 0, NULL, ev );

  fd_reasm_fec_t * fec1a = fd_reasm_query( reasm, mr1a );
  FD_TEST( fec1a );
  FD_TEST( fec1a->eqvoc );
  FD_TEST( !fec1a->confirmed );
  FD_TEST( fec1a==fd_reasm_query( reasm, &out_ele_peek_head( reasm->out, reasm_pool( reasm ) )->key ) );

  fd_reasm_fec_t * fec1b = fd_reasm_query( reasm, mr1b );
  FD_TEST( fec1b );
  FD_TEST( fec1b->eqvoc );
  FD_TEST( !fec1b->confirmed );

  /* get second element in out dlist */
  out_iter_t iter = out_iter_fwd_init( reasm->out, reasm_pool( reasm ) );
  iter = out_iter_fwd_next( iter, reasm->out, reasm_pool( reasm ) );

  FD_TEST( fec1b==fd_reasm_query( reasm, &out_iter_ele( iter, reasm->out, reasm_pool( reasm ) )->key ) );

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

  fd_reasm_insert( reasm, mr1ba, mr1b,  /* slot */ 1, 64, /* parent_off */ 1, /* data_cnt */ 32, /* data_complete */ 1, /* slot_complete */ 1, /* is_leader */ 0, NULL, ev );
  fd_reasm_insert( reasm, mr1bb, mr1b,  /* slot */ 1, 64, /* parent_off */ 1, /* data_cnt */ 32, /* data_complete */ 1, /* slot_complete */ 1, /* is_leader */ 0, NULL, ev );
  fd_reasm_insert( reasm, mr2,   mr1bb, /* slot */ 2, 0,  /* parent_off */ 1, /* data_cnt */ 32, /* data_complete */ 0, /* slot_complete */ 0, /* is_leader */ 0, NULL, ev );

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
  fd_reasm_fec_t * ev[1];

  fd_hash_t mr0[1] = {{{ 1, 0 }}};
  fd_reasm_insert( reasm, mr0, NULL, 0, 0, 0, 0, 0, 1, 0, NULL, ev );

  fd_hash_t mr1[1] = {{{ 1, 1 }}};
  fd_hash_t mr2[1] = {{{ 1, 2 }}};
  fd_hash_t mr3[1] = {{{ 1, 3 }}};
  fd_hash_t mr4[1] = {{{ 1, 4 }}};

                          fd_reasm_insert( reasm, mr1, mr0,  1, 0,  1, 32, 0, 0, 0, NULL, ev );
                          fd_reasm_insert( reasm, mr2, mr1,  1, 32, 1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_fec_t * fec3 = fd_reasm_insert( reasm, mr3, mr2,  1, 64, 1, 32, 0, 1, 0, NULL, ev );

  ulong last_xid = (1UL << 32) | 64UL;
  ulong bid      = (1UL << 32) | UINT_MAX;

  FD_TEST( xid_query( reasm->xid, bid, NULL )->cnt == 1 );
  FD_TEST( xid_query( reasm->xid, bid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec3 ) );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->cnt == 1 );
  FD_TEST( xid_query( reasm->xid, last_xid, NULL )->idx == pool_idx( reasm_pool( reasm ), fec3 ) );

  fd_reasm_fec_t * fec4 = fd_reasm_insert( reasm, mr4, mr2,  1, 64, 1, 32, 0, 1, 0, NULL, ev ); /* equivocate on last fec set idx */
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
  fd_reasm_insert( reasm, mr5, mr4,  2, 0, 1, 32, 0, 1, 0, NULL, ev );
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

  fd_reasm_fec_t * ev[1];
  fd_reasm_insert( reasm, mr1,  NULL,  /* slot */ 1, /* fec_set_idx */ 0,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr2a, mr1,   /* slot */ 2, /* fec_set_idx */ 32, 1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr3,  mr2aa, /* slot */ 3, /* fec_set_idx */ 0,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr4,  mr2aa, /* slot */ 4, /* fec_set_idx */ 0,  1, 32, 0, 0, 0, NULL, ev );

  /* Introduce 2b (which equivocates with 2a). */

  fd_reasm_insert( reasm, mr2b, mr1, /* slot */ 2, /* fec_set_idx */ 32, 1, 32, 0, 0, 0, NULL, ev );

  /* Introduce 2aa, which un-orphans 3 and 4.  This should transitively
     mark 2aa, 3 and 4 all as equivocating because 2a equivocates. */

  fd_reasm_insert( reasm, mr2aa, mr2a, /* slot */ 2, /* fec_set_idx */ 64, 1, 32, 0, 1, 0, NULL, ev );

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

  fd_reasm_insert( reasm, mr5, mr4, /* slot */ 5, /* fec_set_idx */ 0, 1, 32, 0, 0, 0, NULL, ev );

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
  fd_reasm_fec_t * ev[1];
  /*                               slot fecidx p_off data_cnt data_cmpl slot_cmpl is_leader */
  fd_reasm_insert(reasm, mr0, NULL, 0,   0,    0,    0,       0,        1,        0, NULL, ev );
  fd_reasm_insert(reasm, mr1, mr0,  1,   0,    1,    32,      0,        0,        0, NULL, ev );
  fd_reasm_insert(reasm, mr2, mr1,  1,   32,   1,    32,      0,        0,        0, NULL, ev );
  fd_reasm_insert(reasm, mr3, mr2,  1,   64,   1,    32,      0,        1,        0, NULL, ev );
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr1) );
  /* show evidence of equivocation */
  fd_reasm_insert(reasm, mr4, mr3,  1,   96,   1,    32,      0,        0,        0, NULL, ev );
  FD_TEST( fd_reasm_pop(reasm) == NULL );
  fd_reasm_insert(reasm, mr5, mr4,  1,   128,  1,    32,      0,        1,        0, NULL, ev );
  FD_TEST( fd_reasm_pop(reasm) == NULL );

  fd_reasm_confirm(reasm, mr3);
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr2) );
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr3) );
  FD_TEST( fd_reasm_pop(reasm) == NULL );

  fd_reasm_insert( reasm, mr6, mr3,  2,   0,    1,    32,      0,        0,        0, NULL, ev );
  FD_TEST( fd_reasm_pop(reasm) == fd_reasm_query(reasm, mr6) );

  /* now get these out of order. */
  fd_reasm_insert( reasm, mr9, mr8,  2,   96,    1,   32,      0,        0,        0, NULL, ev ); /* currently an orphan */
  fd_reasm_insert( reasm, mr8, mr7,  2,   64,    1,   32,      0,        1,        0, NULL, ev ); /* middle slot complete */

  FD_TEST( fd_reasm_query(reasm, mr8)->eqvoc );
  FD_TEST( fd_reasm_query(reasm, mr9)->eqvoc );

  /* now connect slot 2 from frontier to orphan*/
  fd_reasm_insert( reasm, mr7, mr6,  2,   32,    1,   32,      0,        0,        0, NULL, ev );
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

  fd_reasm_fec_t * evicted[1];
                               /*  mr    cmr   slot fec_idx  p_off  data_cnt -  slot_cmpl - - */
  FD_TEST( fd_reasm_insert( reasm, mr0,  NULL, 1,   0,       1,     32,      0, 1,        0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr1,  mr0,  2,   0,       1,     32,      0, 1,        0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr2,  mr1,  3,   0,       1,     32,      0, 1,        0, NULL, evicted ) );
  /* fork 4 and 5 off 3 */
  FD_TEST( fd_reasm_insert( reasm, mr3,  mr2,  4,   0,       1,     32,      0, 0,        0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr4,  mr2,  5,   0,       1,   	32,      0, 0,        0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr5,  mr4,  5,   32,      1,     32,      0, 1,        0, NULL, evicted ) );
  fd_reasm_fec_t * replay5 = fd_reasm_query( reasm, mr4 );
  replay5->bank_idx = 1;
  replay5 = fd_reasm_query( reasm, mr5 );
  replay5->bank_idx = 1;

  /* now for orphans */
  FD_TEST( fd_reasm_insert( reasm, mr8,  mr7,  8,    0,       1,     32,     0, 0,        0, NULL, evicted ) );

  /* should be full - 1 */
  fd_reasm_print( reasm );
  FD_TEST( *evicted == NULL ); /* nothing should have been evicted yet */

  /* evict and unconfirmed orphan */
  FD_TEST( fd_reasm_insert( reasm, mr6,  mr5,  6,    0,       1,     32,     0, 0,        0, NULL, evicted ) );
  FD_TEST( !fd_reasm_query( reasm, mr8 )); /* evicts unconfirmed orphan */
  FD_TEST( *evicted );

  FD_LOG_NOTICE(("evicted: %lu, %u", (*evicted)->slot, (*evicted)->fec_set_idx  ));

  FD_TEST( (*evicted)->slot == 8 && (*evicted)->fec_set_idx == 0 );
  fd_reasm_pool_release( reasm, *evicted );

  /* evict an unconfirmed leaf */
  FD_TEST( fd_reasm_insert( reasm, mr9,  mr8,  8,    32,       1,     32,     0, 1,        0, NULL, evicted ) );
  FD_TEST( !fd_reasm_query( reasm, mr6 )); /* evicts unconfirmed leaf */
  FD_TEST( evicted[0] );
  FD_TEST( (*evicted)->slot == 6 && (*evicted)->fec_set_idx == 0 );
  fd_reasm_pool_release( reasm, *evicted );

  FD_TEST( fd_reasm_insert( reasm, mr10, mr9,  10,    0,       1,     32,     0, 0,        0, NULL, evicted ) );

  FD_TEST( fd_reasm_query( reasm, mr5 ) ); /* Evicts slot 4, because slot 5 is complete  */
  FD_TEST( !fd_reasm_query( reasm, mr3 ) );
  FD_TEST( (*evicted)->slot == 4 && (*evicted)->fec_set_idx == 0 );
  fd_reasm_pool_release( reasm, *evicted );
}

/* Verify that every element in the out dlist has in_out==1, is in
   ancestry or frontier (ie. the connected tree), and that parents
   precede children. */
static void
verify_out_invariants( fd_reasm_t * reasm ) {
  fd_reasm_fec_t * pool = reasm_pool( reasm );

  /* 1. Every element with in_out==1 is in the dlist and vice versa. */
  ulong out_cnt = 0;
  for( out_iter_t iter = out_iter_fwd_init(       reasm->out, pool );
                        !out_iter_done    ( iter, reasm->out, pool );
                  iter = out_iter_fwd_next( iter, reasm->out, pool ) ) {
    fd_reasm_fec_t * fec = out_iter_ele( iter, reasm->out, pool );
    FD_TEST( fec->in_out );

    /* Must be in the connected tree (ancestry or frontier). */
    FD_TEST( ancestry_ele_query( reasm->ancestry, &fec->key, NULL, pool ) ||
             frontier_ele_query( reasm->frontier, &fec->key, NULL, pool ) );
    out_cnt++;
  }

  /* Check that no element outside the dlist has in_out==1. */
  ulong in_out_cnt = 0;
  for( ancestry_iter_t iter = ancestry_iter_init(       reasm->ancestry, pool );
                              !ancestry_iter_done( iter, reasm->ancestry, pool );
                        iter = ancestry_iter_next( iter, reasm->ancestry, pool ) ) {
    fd_reasm_fec_t * fec = ancestry_iter_ele( iter, reasm->ancestry, pool );
    if( fec->in_out ) in_out_cnt++;
  }
  for( frontier_iter_t iter = frontier_iter_init(       reasm->frontier, pool );
                              !frontier_iter_done( iter, reasm->frontier, pool );
                        iter = frontier_iter_next( iter, reasm->frontier, pool ) ) {
    fd_reasm_fec_t * fec = frontier_iter_ele( iter, reasm->frontier, pool );
    if( fec->in_out ) in_out_cnt++;
  }
  FD_TEST( in_out_cnt == out_cnt );
}

/* Verify the out dlist contains exactly the expected keys in order.
   `expected` is an array of fd_hash_t, `n` is the count. */
static void
verify_out_order( fd_reasm_t * reasm, fd_hash_t const * expected, ulong n ) {
  fd_reasm_fec_t * pool = reasm_pool( reasm );
  ulong i = 0;
  for( out_iter_t iter = out_iter_fwd_init(       reasm->out, pool );
                        !out_iter_done    ( iter, reasm->out, pool );
                  iter = out_iter_fwd_next( iter, reasm->out, pool ) ) {
    fd_reasm_fec_t * fec = out_iter_ele( iter, reasm->out, pool );
    if( fec->popped ) continue; /* skip already-popped elements */
    FD_TEST( i < n );
    FD_TEST( 0==memcmp( &fec->key, &expected[i], sizeof(fd_hash_t) ) );
    i++;
  }
  FD_TEST( i == n );
}

void
test_confirm_out_ordering( fd_wksp_t * wksp ) {
  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_reasm_fec_t * ev[1];

  fd_hash_t root[1] = {{{ 100 }}};
  fd_hash_t mrA[1]  = {{{ 1 }}};
  fd_hash_t mrB[1]  = {{{ 2 }}};
  fd_hash_t mrC[1]  = {{{ 3 }}};
  fd_hash_t mrD[1]  = {{{ 4 }}};

  /* Set the root (snapshot slot). */
  fd_reasm_insert( reasm, root, NULL, 0, 0, 0, 0, 0, 1, 0, NULL, ev );
  verify_out_invariants( reasm );

  /* Case 1: Linear chain inserted in order.
     Insert A -> B -> C -> D, all connected immediately.
     Out dlist should be [A, B, C, D] after inserts. */

  fd_reasm_insert( reasm, mrA, root, 1, 0,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mrB, mrA,  1, 32, 1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mrC, mrB,  1, 64, 1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mrD, mrC,  1, 96, 1, 32, 0, 1, 0, NULL, ev );

  verify_out_invariants( reasm );

  /* Verify insertion order: A, B, C, D. */
  {
    fd_hash_t expected[4] = { *mrA, *mrB, *mrC, *mrD };
    verify_out_order( reasm, expected, 4 );
  }

  /* Pop all so we start fresh for next cases. */
  FD_TEST( fd_reasm_pop( reasm ) );
  FD_TEST( fd_reasm_pop( reasm ) );
  FD_TEST( fd_reasm_pop( reasm ) );
  FD_TEST( fd_reasm_pop( reasm ) );
  FD_TEST( !fd_reasm_pop( reasm ) );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );

  /* Case 2: Confirm adds FECs to the out dlist that were not already
     there (eqvoc FECs that become confirmed).  Confirm must maintain
     parent-before-child ordering even though it walks upward.

     Build: root -> A -> B -> C, all equivocating.
     Since they equivocate and are not confirmed, pop returns nothing.
     Then confirm C, which walks C -> B -> A, confirming and adding
     each to out.  Out ordering must be [A, B, C]. */

  mem   = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  reasm = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_hash_t root2[1]  = {{{ 200 }}};
  fd_hash_t mr2A[1]   = {{{ 11 }}};
  fd_hash_t mr2B[1]   = {{{ 12 }}};
  fd_hash_t mr2C[1]   = {{{ 13 }}};
  fd_hash_t mr2Ap[1]  = {{{ 14 }}}; /* equivocating versions */
  fd_hash_t mr2Bp[1]  = {{{ 15 }}};
  fd_hash_t mr2Cp[1]  = {{{ 16 }}};

  fd_reasm_insert( reasm, root2, NULL, 0, 0, 0, 0, 0, 1, 0, NULL, ev );

  /* Insert first version of the chain. */
  fd_reasm_insert( reasm, mr2A, root2, 1, 0,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr2B, mr2A,  1, 32, 1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr2C, mr2B,  1, 64, 1, 32, 0, 1, 0, NULL, ev );

  verify_out_invariants( reasm );

  /* Pop A, B, C — they are not eqvoc yet. */
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr2A ) );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr2B ) );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr2C ) );
  verify_out_invariants( reasm );

  /* Insert equivocating versions.  These cause eqvoc to be set on both
     versions.  The primed versions are in_out but can't be popped. */
  fd_reasm_insert( reasm, mr2Ap, root2, 1, 0,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr2Bp, mr2Ap, 1, 32, 1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr2Cp, mr2Bp, 1, 64, 1, 32, 0, 1, 0, NULL, ev );

  verify_out_invariants( reasm );

  /* All primed versions are eqvoc, unconfirmed. Pop returns nothing. */
  FD_TEST( !fd_reasm_pop( reasm ) );

  /* Confirm the primed chain via C'. Walks C' -> B' -> A'.
     After confirm, out dlist must deliver in order A', B', C'. */
  fd_reasm_confirm( reasm, mr2Cp );
  verify_out_invariants( reasm );

  FD_TEST( fd_reasm_query( reasm, mr2Ap )->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr2Bp )->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr2Cp )->confirmed );

  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr2Ap ) );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr2Bp ) );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr2Cp ) );
  FD_TEST( !fd_reasm_pop( reasm ) );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );

  /* Case 3: Confirm interleaves with insert-driven out pushes.

     Build: root -> A -> B (all eqvoc, not in out because popped already
     or similar).  Then insert C (child of B), which pushes C to out.
     Then confirm D (child of C), which should insert D after C in out.

     More concretely:
       root -> A -> B -> C -> D -> E
     A and B are inserted and popped (non-eqvoc initially).
     Then equivocating versions A', B' arrive, marking the originals eqvoc.
     C is inserted (connected to B, eqvoc propagated from B).
     D is inserted (connected to C, eqvoc propagated).
     E is inserted (connected to D, eqvoc propagated).
     All of C, D, E are in out but can't be popped (eqvoc, unconfirmed).
     Confirm E: walks E -> D -> C -> B -> A.  B and A are already popped.
     C, D, E should become confirmed.
     Pop should return C, D, E in that order. */

  mem   = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  reasm = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_hash_t root3[1]  = {{{ 67 }}};
  fd_hash_t mr3A[1]   = {{{ 21 }}};
  fd_hash_t mr3B[1]   = {{{ 22 }}};
  fd_hash_t mr3C[1]   = {{{ 23 }}};
  fd_hash_t mr3D[1]   = {{{ 24 }}};
  fd_hash_t mr3E[1]   = {{{ 25 }}};
  fd_hash_t mr3Ap[1]  = {{{ 26 }}}; /* equivocating */
  fd_hash_t mr3Bp[1]  = {{{ 27 }}};

  fd_reasm_insert( reasm, root3, NULL, 0, 0, 0, 0, 0, 1, 0, NULL, ev );

  /* Insert A and B, pop them (not eqvoc yet). */
  fd_reasm_insert( reasm, mr3A, root3, 1, 0,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr3B, mr3A,  1, 32, 1, 32, 0, 0, 0, NULL, ev );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr3A ) );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr3B ) );
  verify_out_invariants( reasm );

  /* Insert equivocating A', B'. */
  fd_reasm_insert( reasm, mr3Ap, root3, 1, 0,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr3Bp, mr3Ap, 1, 32, 1, 32, 0, 0, 0, NULL, ev );

  /* A and B are now eqvoc (already popped). A', B' are eqvoc, in out. */
  FD_TEST( fd_reasm_query( reasm, mr3A )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr3B )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr3Ap )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr3Bp )->eqvoc );

  /* Insert C, D, E — children of B.  They are eqvoc because B is
     eqvoc and unconfirmed. */
  fd_reasm_insert( reasm, mr3C, mr3B,  1, 64,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr3D, mr3C,  1, 96,  1, 32, 0, 0, 0, NULL, ev );
  fd_reasm_insert( reasm, mr3E, mr3D,  1, 128, 1, 32, 0, 1, 0, NULL, ev );

  FD_TEST( fd_reasm_query( reasm, mr3C )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr3D )->eqvoc );
  FD_TEST( fd_reasm_query( reasm, mr3E )->eqvoc );

  verify_out_invariants( reasm );

  /* Nothing poppable — all eqvoc, unconfirmed. */
  FD_TEST( !fd_reasm_pop( reasm ) );

  /* Confirm E.  Walks E -> D -> C -> B -> A.
     A and B are already popped so they stay as-is.
     C, D, E become confirmed and are already in out.
     The dlist ordering must still have C before D before E. */
  fd_reasm_confirm( reasm, mr3E );
  verify_out_invariants( reasm );

  FD_TEST( fd_reasm_query( reasm, mr3C )->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr3D )->confirmed );
  FD_TEST( fd_reasm_query( reasm, mr3E )->confirmed );

  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr3C ) );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr3D ) );
  FD_TEST( fd_reasm_pop( reasm ) == fd_reasm_query( reasm, mr3E ) );
  FD_TEST( !fd_reasm_pop( reasm ) );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );
  FD_LOG_NOTICE(( "test_confirm_out_ordering passed" ));
}

void
test_remove_bank_eviction( fd_wksp_t * wksp ) {
  /* Tree structure after all inserts:

     root(0,0) ── (1,0) ── (1,32) ── (1,64)[slot_complete]
                                        ├── (2,0) ── (2,32) ── (2,64) ── (2,96)
                                        └── (3,0) ── (3,32)

     Simulate the replay tile having popped and replayed the first 2
     FECs of slot 1 ((1,0) and (1,32)).  Then simulate bank eviction
     by calling fd_reasm_remove on (1,32) — the latest FEC that was
     replayed on this bank */

  ulong        fec_max = 32;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_reasm_fec_t * pool     = reasm_pool( reasm );
  frontier_t *     frontier = reasm->frontier;
  subtrees_t *     subtrees = reasm->subtrees;
  orphaned_t *     orphaned = reasm->orphaned;

  fd_reasm_fec_t * ev[1];

  /* Merkle roots for each FEC. */
  fd_hash_t mr_root[1] = {{{ 99 }}};

  fd_hash_t mr1_0 [1] = {{{ 10 }}};
  fd_hash_t mr1_32[1] = {{{ 11 }}};
  fd_hash_t mr1_64[1] = {{{ 12 }}};

  fd_hash_t mr2_0 [1] = {{{ 20 }}};
  fd_hash_t mr2_32[1] = {{{ 21 }}};
  fd_hash_t mr2_64[1] = {{{ 22 }}};
  fd_hash_t mr2_96[1] = {{{ 23 }}};

  fd_hash_t mr3_0 [1] = {{{ 30 }}};
  fd_hash_t mr3_32[1] = {{{ 31 }}};

  /* Insert root (snapshot slot). */
  fd_reasm_insert( reasm, mr_root, NULL, 0, 0, 0, 0, 0, 1, 0, NULL, ev );

  /* Insert slot 1: 3 FECs. (1,64) has slot_complete. */
  /*                                mr       cmr       slot fec_idx p_off data_cnt dc   sc   ldr        */
  fd_reasm_insert( reasm, mr1_0,  mr_root, 1,   0,     1,   32,     0,   0,   0, NULL, ev );
  fd_reasm_insert( reasm, mr1_32, mr1_0,   1,   32,    1,   32,     0,   0,   0, NULL, ev );
  fd_reasm_insert( reasm, mr1_64, mr1_32,  1,   64,    1,   32,     0,   1,   0, NULL, ev );

  /* Insert slot 2: 4 FECs chaining off slot 1. */
  fd_reasm_insert( reasm, mr2_0,  mr1_64,  2,   0,     1,   32,     0,   0,   0, NULL, ev );
  fd_reasm_insert( reasm, mr2_32, mr2_0,   2,   32,    1,   32,     0,   0,   0, NULL, ev );
  fd_reasm_insert( reasm, mr2_64, mr2_32,  2,   64,    1,   32,     0,   0,   0, NULL, ev );
  fd_reasm_insert( reasm, mr2_96, mr2_64,  2,   96,    1,   32,     0,   1,   0, NULL, ev );

  /* Insert slot 3: 2 FECs chaining off slot 1 (fork). */
  fd_reasm_insert( reasm, mr3_0,  mr1_64,  3,   0,     2,   32,     0,   0,   0, NULL, ev );
  fd_reasm_insert( reasm, mr3_32, mr3_0,   3,   32,    2,   32,     0,   1,   0, NULL, ev );

  verify_out_invariants( reasm );

  /* Simulate replay: pop the first 2 FECs in slot 1.
     In the replay tile, this means the bank has replayed (1,0) and
     (1,32).  The replay tile's latest_mr would be mr1_32. */

  fd_reasm_fec_t * popped1 = fd_reasm_pop( reasm );
  FD_TEST( popped1 );
  FD_TEST( 0==memcmp( &popped1->key, mr1_0, sizeof(fd_hash_t) ) );
  popped1->bank_idx = 1; /* simulate bank assignment */

  fd_reasm_fec_t * popped2 = fd_reasm_pop( reasm );
  FD_TEST( popped2 );
  FD_TEST( 0==memcmp( &popped2->key, mr1_32, sizeof(fd_hash_t) ) );
  popped2->bank_idx = 1; /* same bank */

  /* Simulate bank eviction: call fd_reasm_remove on the second FEC
     that was popped ((1,32)), mimicking the replay tile querying
     latest_mr and passing the result to remove. */

  fd_reasm_fec_t * fec_to_evict = fd_reasm_query( reasm, mr1_32 );
  FD_TEST( fec_to_evict );
  FD_TEST( fec_to_evict->child != ULONG_MAX );                  /* NOT a leaf  */

  fd_reasm_fec_t * evicted_head = fd_reasm_remove( reasm, fec_to_evict, NULL );
  FD_TEST( evicted_head );

  /* The evicted chain should be (1,0) -> (1,32).  head walks up from
     (1,32) to (1,0) because fec_set_idx 0 is the stop condition. */

  FD_TEST( 0==memcmp( &evicted_head->key, mr1_0, sizeof(fd_hash_t) ) );
  fd_reasm_fec_t * evicted_child = fd_reasm_child( reasm, evicted_head );
  FD_TEST( 0==memcmp( &evicted_child->key, mr1_32, sizeof(fd_hash_t) ) );

  /* (1,0) and (1,32) should no longer be in any map. */

  FD_TEST( !fd_reasm_query( reasm, mr1_0  ) );
  FD_TEST( !fd_reasm_query( reasm, mr1_32 ) );

  /* (1,64) should now be a subtree root — it was the direct child of
     tail=(1,32) and became orphaned by the removal. */

  FD_TEST( subtrees_ele_query( subtrees, mr1_64, NULL, pool ) );

  /* (1,64)'s children from slot 2 and slot 3 should be in orphaned. */

  FD_TEST( orphaned_ele_query( orphaned, mr2_0,  NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, mr2_32, NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, mr2_64, NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, mr2_96, NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, mr3_0,  NULL, pool ) );
  FD_TEST( orphaned_ele_query( orphaned, mr3_32, NULL, pool ) );

  /* Slot 2's first FEC and slot 3's first FEC should be subtree roots
     (they are direct children of (1,64) which is the tail's child, so
     actually (2,0) and (3,0) should be subtree roots if the code
     re-roots each direct child of tail). */

  /* The out dlist should be empty — all previously connected FECs
     were either popped ((1,0), (1,32)) or orphaned ((1,64) and
     descendants). */

  FD_TEST( out_is_empty( reasm->out, pool ) );

  /* The root should now be a frontier leaf (its only child (1,0) was
     evicted, so it has no children). */

  FD_TEST( frontier_ele_query( frontier, mr_root, NULL, pool ) );

  /* Clean up: release evicted elements back to pool. */

  fd_reasm_pool_release( reasm, evicted_child );
  fd_reasm_pool_release( reasm, evicted_head );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );

  FD_LOG_NOTICE(( "test_remove_bank_eviction passed" ));
}

void
test_insert_rejects_when_full_and_nothing_is_evictable( fd_wksp_t * wksp ) {
  ulong        fec_max = 4UL;
  void *       mem     = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  fd_reasm_t * reasm   = fd_reasm_join( fd_reasm_new( mem, fec_max, 0UL ) );
  FD_TEST( reasm );

  fd_hash_t mr0[1] = {{{ 0 }}};
  fd_hash_t mr1[1] = {{{ 1 }}};
  fd_hash_t mr2[1] = {{{ 2 }}};
  fd_hash_t mr3[1] = {{{ 3 }}};

  fd_reasm_fec_t * evicted[1];

  FD_TEST( fd_reasm_insert( reasm, mr0, NULL, 0UL, 0U, 0, 0, 0, 1, 0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr1, mr0,  1UL, 0U, 1, 32, 0, 1, 0, NULL, evicted ) );
  FD_TEST( fd_reasm_insert( reasm, mr2, mr1,  2UL, 0U, 1, 32, 0, 1, 0, NULL, evicted ) );

  fd_reasm_fec_t * inserted = fd_reasm_insert( reasm, mr3, mr2, 3UL, 0U, 1, 32, 0, 1, 0, NULL, evicted );
  FD_TEST( inserted == NULL );
  FD_TEST( evicted[0] );
  FD_TEST( 0==memcmp( &evicted[0]->key, mr3, sizeof(fd_hash_t) ) );
  FD_TEST( 0==memcmp( &evicted[0]->cmr, mr2, sizeof(fd_hash_t) ) );
  FD_TEST( evicted[0]->slot        == 3UL );
  FD_TEST( evicted[0]->fec_set_idx == 0U );
  FD_TEST( evicted[0]->parent_off  == 1U );
  FD_TEST( !fd_reasm_query( reasm, mr3 ) );

  fd_reasm_pool_release( reasm, evicted[0] );

  fd_wksp_free_laddr( fd_reasm_delete( fd_reasm_leave( reasm ) ) );

  FD_LOG_NOTICE(( "test_insert_rejects_when_full_and_nothing_is_evictable passed" ));
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
  test_confirm_out_ordering( wksp );
  test_remove_bank_eviction( wksp );
  test_insert_rejects_when_full_and_nothing_is_evictable( wksp );

  fd_halt();
  return 0;
}
