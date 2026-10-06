#include "fd_rotor.h"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"

#define SLOT_MAX (16UL)
#define FEC_MAX  (SLOT_MAX*AG_EQVOC_BLOCK_HASH_MAX*FD_FEC_BLK_MAX)

static uchar mem    [ 64UL<<20 ] __attribute__((aligned(128UL)));
static uchar scratch[ 64UL<<20 ] __attribute__((aligned(128UL)));

static fd_mr32_t
hash( uchar b ) {
  fd_mr32_t h; memset( h.uc, b, sizeof(fd_mr32_t) );
  return h;
}

/* complete reports FEC set fec_idx of (slot, parent_slot) as complete
   under merkle root mr, the way the shred tile does, as our own leader
   FEC set if is_leader. */

static fd_rotor_fec_t *
complete_as( fd_rotor_t *      rotor,
             ulong             slot,
             ulong             parent_slot,
             uint              fec_idx,
             int               last,
             fd_mr32_t const * mr,
             int               is_leader ) {
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot            = slot;
  shred->idx             = fec_idx*FD_FEC_SHRED_CNT + FD_FEC_SHRED_CNT - 1U;
  shred->data.parent_off = (ushort)( slot-parent_slot );
  shred->data.flags      = last ? FD_SHRED_DATA_FLAG_SLOT_COMPLETE : 0;
  return fd_rotor_fec_complete( rotor, shred, mr, is_leader, 0L );
}

static fd_rotor_fec_t *
complete( fd_rotor_t *      rotor,
          ulong             slot,
          ulong             parent_slot,
          uint              fec_idx,
          int               last,
          fd_mr32_t const * mr ) {
  return complete_as( rotor, slot, parent_slot, fec_idx, last, mr, 0 );
}

/* notar creates the notar blk (slot, dmr).  fecs notarizes its FEC
   sets, FEC set k under merkle root hash( dmr+1+k ). */

static fd_rotor_blk_t *
notar( fd_rotor_t * rotor,
       ulong        slot,
       uchar        dmr ) {
  fd_mr32_t        id  = hash( dmr );
  fd_rotor_blk_t * blk = fd_rotor_blk_notarized( rotor, slot, &id );
  FD_TEST( blk );
  return blk;
}

static void
fecs( fd_rotor_t * rotor,
      ulong        slot,
      uchar        dmr,
      uint         fec_set_cnt ) {
  fd_mr32_t id = hash( dmr );
  for( uint k=0U; k<fec_set_cnt; k++ ) {
    fd_mr32_t         mr = hash( (uchar)( dmr+1U+k ) );
    fd_mr20_t key; memcpy( key.uc, mr.uc, sizeof(fd_mr20_t) );
    FD_TEST( fd_rotor_fec_notarized( rotor, slot, &id, k*FD_FEC_SHRED_CNT, &key ) );
  }
}

static void
parented( fd_rotor_t * rotor,
          ulong        slot,
          uchar        dmr,
          ulong        parent_slot,
          uchar        parent_dmr,
          uint         fec_set_cnt ) {
  fd_mr32_t id = hash( dmr ), pid = hash( parent_dmr );
  fd_rotor_blk_parented( rotor, slot, &id, parent_slot, &pid, fec_set_cnt );
}

static void
expect( fd_rotor_t *           rotor,
        fd_rotor_blk_t const * blk,
        uint                   fec_idx ) {
  FD_TEST( !fd_rotor_deque_empty( rotor->reasm_deque ) );
  fd_rotor_deque_t out = fd_rotor_deque_pop_head( rotor->reasm_deque );
  FD_TEST( out.blk_idx==blk_pool_idx( rotor->blk_pool, blk ) && out.fec_idx==fec_idx );
}

/* shred0 inserts the first data shred of slot, whose payload is the
   block header naming (parent_slot, parent_mr), under FEC set 0's
   merkle root fec0_mr. */

static void
shred0( fd_rotor_t *      rotor,
        ulong             slot,
        ulong             parent_slot,
        fd_mr32_t const * parent_mr,
        fd_mr32_t const * fec0_mr ) {
  uchar             buf[ FD_SHRED_MIN_SZ ] __attribute__((aligned(8UL))); memset( buf, 0, sizeof(buf) );
  uchar             ser[ FD_BLOCK_MARKER_SER_MAX ];
  fd_block_marker_t marker[1]; memset( marker, 0, sizeof(fd_block_marker_t) );
  marker->kind                   = FD_BLOCK_MARKER_KIND_HEADER;
  marker->header.parent_slot     = parent_slot;
  marker->header.parent_block_id = *parent_mr;
  ulong sz = fd_block_marker_ser( marker, ser );
  memcpy( buf+FD_SHRED_DATA_HEADER_SZ, ser, sz );

  fd_shred_t * shred = (fd_shred_t *)buf;
  shred->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  shred->slot            = slot;
  shred->idx             = 0U;
  shred->data.parent_off = (ushort)( slot-parent_slot );
  shred->data.size       = (ushort)( FD_SHRED_DATA_HEADER_SZ+sz );
  fd_rotor_shred_insert( rotor, shred, fec0_mr, 0L );
}

static int
is_eager( fd_rotor_t const *     rotor,
          fd_rotor_blk_t const * blk ) {
  return rotor->slot_meta[ blk->slot % rotor->slot_max ].eager==blk_pool_idx( rotor->blk_pool, blk );
}

static fd_rotor_t *
setup_in( uchar * buf ) {
  FD_TEST( fd_rotor_footprint( SLOT_MAX, FEC_MAX )<=sizeof(mem) );
  fd_rotor_t * rotor = fd_rotor_join( fd_rotor_new( buf, SLOT_MAX, FEC_MAX, 42UL ) );
  fd_mr32_t    root  = hash( 0xEE );
  fd_rotor_init( rotor, 0UL, &root, NULL, NULL );
  return rotor;
}

static fd_rotor_t *
setup( void ) {
  return setup_in( mem );
}

/* FEC sets complete out of order and a chain completes bottom up.
   Nothing is delivered until the top blk is complete, then the chain is
   delivered parent first. */

static void
test_chain( void ) {
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 1UL, 0x10 );
  fd_rotor_blk_t * b     = notar( rotor, 2UL, 0x20 );
  fd_rotor_blk_t * c     = notar( rotor, 3UL, 0x30 );
  parented( rotor, 3UL, 0x30, 2UL, 0x20, 1U );
  parented( rotor, 2UL, 0x20, 1UL, 0x10, 2U );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 2U );
  fecs( rotor, 1UL, 0x10, 2U );
  fecs( rotor, 2UL, 0x20, 2U );
  fecs( rotor, 3UL, 0x30, 1U );

  fd_mr32_t mr;
  mr = hash( 0x31 ); complete( rotor, 3UL, 2UL, 0U, 1, &mr );
  mr = hash( 0x22 ); complete( rotor, 2UL, 1UL, 1U, 1, &mr );
  mr = hash( 0x21 ); complete( rotor, 2UL, 1UL, 0U, 0, &mr );
  mr = hash( 0x12 ); complete( rotor, 1UL, 0UL, 1U, 1, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 0, &mr );
  expect( rotor, a, 0U ); expect( rotor, a, 1U );
  expect( rotor, b, 0U ); expect( rotor, b, 1U );
  expect( rotor, c, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A blk whose FEC sets are all in before its parent is known is
   delivered as soon as it is linked under a complete parent. */

static void
test_link_late( void ) {
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 1UL, 0x10 );
  fecs( rotor, 1UL, 0x10, 1U );
  fd_mr32_t mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 1, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 1U );
  expect( rotor, a, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Finalizing one version of a slot frees its competitor, and the
   competitor's child is unlinked so it is never delivered. */

static void
test_finalize_unlinks( void ) {
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 1UL, 0x10 );
  fd_rotor_blk_t * b     = notar( rotor, 1UL, 0x40 );
  fd_rotor_blk_t * c     = notar( rotor, 2UL, 0x50 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 1U );
  parented( rotor, 1UL, 0x40, 0UL, 0xEE, 1U );
  parented( rotor, 2UL, 0x50, 1UL, 0x40, 1U );
  FD_TEST( c->parent==blk_pool_idx( rotor->blk_pool, b ) );

  fd_mr32_t id = hash( 0x10 );
  FD_TEST( fd_rotor_blk_finalized( rotor, 1UL, &id )==a );
  FD_TEST( c->parent==blk_pool_idx_null( rotor->blk_pool ) );

  fecs( rotor, 2UL, 0x50, 1U );
  fd_mr32_t mr = hash( 0x51 ); complete( rotor, 2UL, 1UL, 0U, 1, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* the block id slot 1 has once FEC sets m10 and m11 complete, computed
   by a scratch rotor */

static fd_mr32_t
slot1_dmr( fd_mr32_t const * m10,
           fd_mr32_t const * m11 ) {
  fd_mr32_t    root = hash( 0xEE );
  fd_rotor_t * pre  = setup_in( scratch );
  shred0  ( pre, 1UL, 0UL, &root, m10 );
  complete( pre, 1UL, 0UL, 0U, 0, m10 );
  complete( pre, 1UL, 0UL, 1U, 1, m11 );
  ulong     one = 1UL;
  fd_mr32_t d1  = blk_map_ele_query( pre->blk_map, &one, NULL, pre->blk_pool )->dmr;
  FD_TEST( memcmp( &d1, &hash_null, sizeof(fd_mr32_t) ) );
  return d1;
}

/* Pipelined turbine: slot 2's header names slot 1's block before any of
   slot 1 arrives, so slot 2 links under slot 1's turbine version,
   created empty.  Slot 1's FEC sets arrive out of order.  When slot 1
   completes, its dmr matches what slot 2 named, and slot 1 then slot 2
   are delivered.  Slot 3 then links straight to slot 2, whose dmr is
   known. */

static void
test_eager_chain( void ) {
  fd_mr32_t root = hash( 0xEE );
  fd_mr32_t m10  = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 ), m30 = hash( 0x31 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );

  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 2UL, 1UL, &d1, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( is_eager( rotor, e1 ) && !blk_map_ele_next_const( e1, NULL, rotor->blk_pool ) ); /* no notar blk from a turbine header */
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( !memcmp( &e1->dmr, &d1, sizeof(fd_mr32_t) ) && e2->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  expect( rotor, e1, 0U ); expect( rotor, e1, 1U );
  expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  shred0  ( rotor, 3UL, 2UL, &e2->dmr, &m30 );
  complete( rotor, 3UL, 2UL, 0U, 1, &m30 );
  ulong            three = 3UL;
  fd_rotor_blk_t * e3    = blk_map_ele_query( rotor->blk_map, &three, NULL, rotor->blk_pool );
  FD_TEST( e3->parent==blk_pool_idx( rotor->blk_pool, e2 ) );
  expect( rotor, e3, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A child that names a block id its parent slot's turbine version does
   not produce is unlinked when that version completes, and is never
   delivered.  No notar blk is created for the id it named. */

static void
test_eager_wrong_parent( void ) {
  fd_mr32_t root = hash( 0xEE ), other = hash( 0x99 );
  fd_mr32_t m10  = hash( 0x11 ), m20   = hash( 0x21 );

  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 2UL, 1UL, &other, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  shred0  ( rotor, 1UL, 0UL, &root,  &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );

  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( is_eager( rotor, e1 ) && !blk_map_ele_next_const( e1, NULL, rotor->blk_pool ) );
  FD_TEST( e2->parent==blk_pool_idx_null( rotor->blk_pool ) && e1->child==blk_pool_idx_null( rotor->blk_pool ) );
  expect( rotor, e1, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Votor names slot 1's block before turbine completes it, and a notar
   child links under that notar blk.  When slot 1's turbine version
   completes with the same dmr, the notar blk is merged into it: the
   eager blk takes the child, and slot 1 then the child are delivered. */

static void
test_twin_merge( void ) {
  fd_mr32_t root = hash( 0xEE );
  fd_mr32_t m10  = hash( 0x11 ), m11 = hash( 0x12 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );

  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * n1    = fd_rotor_blk_notarized( rotor, 1UL, &d1 );
  fd_rotor_blk_t * c     = notar( rotor, 2UL, 0x50 );
  fd_mr32_t        c_id  = hash( 0x50 );
  fd_rotor_blk_parented( rotor, 2UL, &c_id, 1UL, &d1, 1U );
  FD_TEST( c->parent==blk_pool_idx( rotor->blk_pool, n1 ) );
  fecs( rotor, 2UL, 0x50, 1U );
  fd_mr32_t m51 = hash( 0x51 ); complete( rotor, 2UL, 1UL, 0U, 1, &m51 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  ulong            one = 1UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( is_eager( rotor, e1 ) && !blk_map_ele_next_const( e1, NULL, rotor->blk_pool ) ); /* the notar blk was merged */
  FD_TEST( c->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  expect( rotor, e1, 0U ); expect( rotor, e1, 1U );
  expect( rotor, c,  0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Slot 2 links under slot 1's eager blk before slot 1's FEC sets are
   notarized.  Slot 1's shreds then arrive for notarized FEC sets.  They
   still build the eager blk, which completes as the notar blk, merges,
   and releases slot 2. */

static void
test_notarized_shreds_build_eager( void ) {
  fd_mr32_t root = hash( 0xEE );
  fd_mr32_t m10  = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );

  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 2UL, 1UL, &d1, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( is_eager( rotor, e1 ) && e2->parent==blk_pool_idx( rotor->blk_pool, e1 ) );

  fd_rotor_blk_t *  n1     = fd_rotor_blk_notarized( rotor, 1UL, &d1 );
  ulong             n1_idx = blk_pool_idx( rotor->blk_pool, n1 );
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );
  fd_mr20_t k11; memcpy( k11.uc, m11.uc, sizeof(fd_mr20_t) );
  fd_rotor_blk_parented ( rotor, 1UL, &d1, 0UL, &root, 2U );
  fd_rotor_fec_notarized( rotor, 1UL, &d1, 0U,               &k10 );
  fd_rotor_fec_notarized( rotor, 1UL, &d1, FD_FEC_SHRED_CNT, &k11 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( !memcmp( &e1->dmr, &d1, sizeof(fd_mr32_t) ) );
  FD_TEST( blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool )==e1 && !blk_map_ele_next_const( e1, NULL, rotor->blk_pool ) ); /* the notar blk was merged */
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  fd_rotor_deque_t a0 = fd_rotor_deque_pop_head( rotor->reasm_deque ), b0 = fd_rotor_deque_pop_head( rotor->reasm_deque ); /* both versions consumed FEC set 0 */
  FD_TEST( a0.fec_idx==0U && b0.fec_idx==0U && a0.blk_idx+b0.blk_idx==n1_idx+blk_pool_idx( rotor->blk_pool, e1 ) && a0.blk_idx!=b0.blk_idx );
  expect( rotor, e1, 1U );
  expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Slot 1's turbine version is already complete when slot 2 names a
   different block id for it.  Slot 2 must not link under it. */

static void
test_eager_finished_wrong_parent( void ) {
  fd_mr32_t root = hash( 0xEE ), y = hash( 0x77 );
  fd_mr32_t m10  = hash( 0x11 ), m20 = hash( 0x21 );

  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  expect( rotor, e1, 0U );

  shred0  ( rotor, 2UL, 1UL, &y, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  fd_rotor_blk_t * e2 = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( e2->parent==blk_pool_idx_null( rotor->blk_pool ) && e1->child==blk_pool_idx_null( rotor->blk_pool ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A child naming a block id the root slot does not have gets no
   parent, and no turbine version is created in the root slot. */

static void
test_root_wrong_parent( void ) {
  fd_mr32_t    y     = hash( 0x77 ), m10 = hash( 0x11 );
  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &y, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  ulong            zero = 0UL, one = 1UL;
  fd_rotor_blk_t * r    = blk_map_ele_query( rotor->blk_map, &zero, NULL, rotor->blk_pool );
  fd_rotor_blk_t * e1   = blk_map_ele_query( rotor->blk_map, &one,  NULL, rotor->blk_pool );
  FD_TEST( !blk_map_ele_next_const( r, NULL, rotor->blk_pool ) && r->child==blk_pool_idx_null( rotor->blk_pool ) );
  FD_TEST( e1->parent==blk_pool_idx_null( rotor->blk_pool ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Slot 2 names a slot 1 block id that slot 1's turbine version does
   not complete as, so it is unlinked.  It still computes its dmr when
   it completes, and dedup then adopts the parent the notar blk of the
   same dmr was given. */

static void
test_orphan_adopted( void ) {
  fd_mr32_t root = hash( 0xEE ), y = hash( 0x77 );
  fd_mr32_t m10  = hash( 0x11 ), m20 = hash( 0x21 );

  fd_rotor_t * pre = setup_in( scratch );
  shred0  ( pre, 2UL, 1UL, &y, &m20 );
  complete( pre, 2UL, 1UL, 0U, 1, &m20 );
  ulong     one = 1UL, two = 2UL;
  fd_mr32_t d2  = blk_pool_ele( pre->blk_pool, pre->slot_meta[ two % pre->slot_max ].eager )->dmr;
  FD_TEST( memcmp( &d2, &hash_null, sizeof(fd_mr32_t) ) );

  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 2UL, 1UL, &y, &m20 );
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  fd_rotor_blk_t * e1 = blk_pool_ele( rotor->blk_pool, rotor->slot_meta[ one % rotor->slot_max ].eager );
  fd_rotor_blk_t * e2 = blk_pool_ele( rotor->blk_pool, rotor->slot_meta[ two % rotor->slot_max ].eager );
  FD_TEST( e2->parent==blk_pool_idx_null( rotor->blk_pool ) );
  expect( rotor, e1, 0U );

  fd_rotor_blk_notarized( rotor, 2UL, &d2 );
  fd_rotor_blk_t * n1 = fd_rotor_blk_parented( rotor, 2UL, &d2, 1UL, &y, 1U );
  FD_TEST( n1 );

  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  FD_TEST( !memcmp( &e2->dmr, &d2, sizeof(fd_mr32_t) ) );
  FD_TEST( blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool )==e2 && !blk_map_ele_next_const( e2, NULL, rotor->blk_pool ) );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, n1 ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Replay lost a bank: everything under the root is delivered again,
   parents first. */

static void
test_fec_reconsume( void ) {
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 );
  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  shred0  ( rotor, 2UL, 1UL, &e1->dmr, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  expect( rotor, e1, 0U ); expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  fd_rotor_fec_reconsume( rotor );
  expect( rotor, e1, 0U ); expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Replay reports slot 1 dead: it is freed with its FEC sets, slot 2
   under it is orphaned, turbine does not rebuild slot 1, and nothing is
   redelivered. */

static void
test_blk_dead( void ) {
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 );
  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  fd_mr32_t        d1  = e1->dmr;
  shred0  ( rotor, 2UL, 1UL, &d1, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  expect( rotor, e1, 0U ); expect( rotor, e2, 0U );

  fd_rotor_blk_dead( rotor, 1UL, &d1 );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool ) );
  FD_TEST( e2->parent==blk_pool_idx_null( rotor->blk_pool ) );
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );
  FD_TEST( !fec_map_ele_query( rotor->fec_map, &k10, NULL, rotor->fec_pool ) );

  shred0( rotor, 1UL, 0UL, &root, &m10 );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool ) );
  fd_rotor_fec_reconsume( rotor );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Slot 2 is partly delivered under slot 1's turbine version when a
   different slot 1 blk is finalized.  Slot 2 is orphaned and its later
   FEC sets are not delivered. */

static void
test_orphan_stops( void ) {
  fd_mr32_t    root  = hash( 0xEE ), y = hash( 0x77 );
  fd_mr32_t    m10   = hash( 0x11 ), m20 = hash( 0x21 ), m21 = hash( 0x22 );
  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  shred0  ( rotor, 2UL, 1UL, &e1->dmr, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 0, &m20 );
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  expect( rotor, e1, 0U ); expect( rotor, e2, 0U );

  FD_TEST( fd_rotor_blk_finalized( rotor, 1UL, &y ) );
  FD_TEST( e2->parent==blk_pool_idx_null( rotor->blk_pool ) && e2->cons_fec_cnt==1U );
  complete( rotor, 2UL, 1UL, 1U, 1, &m21 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A second, different shred 0 for the slot invalidates the turbine
   version instead of overwriting its parent, whatever parent it names;
   so does a different FEC set at an index it already holds. */

static void
test_eqvoc_invalidates( void ) {
  fd_mr32_t root = hash( 0xEE ), y = hash( 0x77 ), m10 = hash( 0x11 ), m19 = hash( 0x19 );
  ulong     one  = 1UL, two = 2UL;

  fd_rotor_t * rotor = setup();
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  shred0( rotor, 1UL, 0UL, &y,    &m19 );
  fd_rotor_blk_t * e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( rotor->slot_meta[ one % rotor->slot_max ].invalidated );
  FD_TEST( !memcmp( &e1->parent_blk_mr, &root, sizeof(fd_mr32_t) ) );

  fd_mr32_t m20 = hash( 0x21 ), m29 = hash( 0x29 );
  complete( rotor, 2UL, 1UL, 1U, 0, &m20 );
  complete( rotor, 2UL, 1UL, 1U, 0, &m29 );
  FD_TEST( rotor->slot_meta[ two % rotor->slot_max ].invalidated );
}

/* A FecSetRoot leaf equal to a live FEC set of another slot, or of
   another index in the same slot, is refused instead of shared, so the
   free paths never release a FEC set another slot still holds. */

static void
test_fec_alias_refused( void ) {
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 );
  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );

  fd_rotor_blk_t * t = notar( rotor, 2UL, 0x50 );
  parented( rotor, 2UL, 0x50, 0UL, 0xEE, 2U );
  fd_mr32_t        t_id = hash( 0x50 );
  FD_TEST( !fd_rotor_fec_notarized( rotor, 2UL, &t_id, 0U, &k10 ) );               /* another slot */
  FD_TEST( t->fecs[ 0 ]==fec_pool_idx_null( rotor->fec_pool ) );

  fd_rotor_blk_t * s = notar( rotor, 1UL, 0x30 );
  parented( rotor, 1UL, 0x30, 0UL, 0xEE, 2U );
  fd_mr32_t        s_id = hash( 0x30 );
  FD_TEST( !fd_rotor_fec_notarized( rotor, 1UL, &s_id, FD_FEC_SHRED_CNT, &k10 ) ); /* another index */
  FD_TEST( s->fecs[ 1 ]==fec_pool_idx_null( rotor->fec_pool ) );
}

/* role is a blk's role in its slot_meta: the slot's final blk, its
   first notar or stronger blk, or else eager. */

#define ROLE_FINAL (0UL)
#define ROLE_NOTAR (1UL)
#define ROLE_EAGER (2UL)

static ulong
role( fd_rotor_t const *     rotor,
      fd_rotor_blk_t const * blk ) {
  fd_rotor_slot_meta_t const * meta = &rotor->slot_meta[ blk->slot % rotor->slot_max ];
  ulong                        idx  = blk_pool_idx( rotor->blk_pool, blk );
  return meta->final==idx ? ROLE_FINAL : meta->notar==idx ? ROLE_NOTAR : ROLE_EAGER;
}

/* blk_treap_pop takes the lowest slot blk of the first non-empty treap,
   final, then notar, then eager, as the tile does. */

static fd_rotor_blk_t *
blk_treap_pop( fd_rotor_t * rotor ) {
  fd_rotor_treap_t * treap = fd_rotor_treap_ele_cnt( rotor->final_treap ) ? rotor->final_treap :
                             fd_rotor_treap_ele_cnt( rotor->notar_treap ) ? rotor->notar_treap :
                             fd_rotor_treap_ele_cnt( rotor->eager_treap ) ? rotor->eager_treap :
                                                                            NULL;
  if( FD_UNLIKELY( !treap ) ) return NULL;
  fd_rotor_blk_t * blk = fd_rotor_treap_fwd_iter_ele( fd_rotor_treap_fwd_iter_init( treap, rotor->blk_pool ), rotor->blk_pool );
  fd_rotor_treap_ele_remove( treap, blk, rotor->blk_pool );
  blk->in_blk_treap = 0;
  return blk;
}

/* pop takes the next blk off the blk_treaps, as the tile does, and
   checks it is of kind c. */

static fd_rotor_blk_t *
pop( fd_rotor_t * rotor,
     ulong        c ) {
  fd_rotor_blk_t * blk = blk_treap_pop( rotor );
  FD_TEST( blk && role( rotor, blk )==c && !blk->in_blk_treap );
  return blk;
}

/* blk_treap_cnt is the number of blks in every blk_treap. */

static ulong
blk_treap_cnt( fd_rotor_t const * rotor ) {
  ulong cnt = 0UL;
  FD_TEST( !fd_rotor_treap_verify( rotor->eager_treap, rotor->blk_pool ) );
  FD_TEST( !fd_rotor_treap_verify( rotor->notar_treap, rotor->blk_pool ) );
  FD_TEST( !fd_rotor_treap_verify( rotor->final_treap, rotor->blk_pool ) );
  cnt += fd_rotor_treap_ele_cnt( rotor->eager_treap ) + fd_rotor_treap_ele_cnt( rotor->notar_treap ) + fd_rotor_treap_ele_cnt( rotor->final_treap );
  return cnt;
}

/* Repair blk_treap: a blk is in its kind's blk_treap when it may have
   new missing work, once until the tile pops it; kinds follow certs;
   eviction forgets the evicted shreds. */

static void
test_repair_blk_treap( void ) {
  fd_mr32_t        root  = hash( 0xEE );
  fd_rotor_t *     rotor = setup();
  FD_TEST( !blk_treap_cnt( rotor ) );                                          /* the root blk is never repaired */
  fd_rotor_blk_t * n1    = notar( rotor, 1UL, 0x10 );
  FD_TEST( role( rotor, n1 )==ROLE_NOTAR && n1->in_blk_treap );
  FD_TEST( pop( rotor, ROLE_NOTAR )==n1 && !blk_treap_pop( rotor ) );

  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 2U );                                 /* FEC set count known */
  FD_TEST( n1->in_blk_treap && pop( rotor, ROLE_NOTAR )==n1 );
  fecs    ( rotor, 1UL, 0x10, 1U );
  fd_mr32_t m11 = hash( 0x11 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m11 );                                   /* buffering a FEC set adds no work */
  FD_TEST( !n1->in_blk_treap );

  /* Eager: turbine showing a higher FEC set inserts it and stamps it. */

  while( blk_treap_pop( rotor ) );                                    /* slot 1's turbine version */
  fd_mr32_t m30 = hash( 0x31 ), m32 = hash( 0x33 );
  shred0( rotor, 3UL, 0UL, &root, &m30 );
  ulong            three = 3UL;
  fd_rotor_blk_t * e3    = blk_map_ele_query( rotor->blk_map, &three, NULL, rotor->blk_pool );
  FD_TEST( role( rotor, e3 )==ROLE_EAGER && pop( rotor, ROLE_EAGER )==e3 );
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot = 3UL; shred->idx = 2U*FD_FEC_SHRED_CNT; shred->data.parent_off = 3;
  fd_rotor_shred_insert( rotor, shred, &m32, 77L );
  FD_TEST( e3->in_blk_treap && e3->last_fec_ts==77L && e3->rcvd_fec_cnt==3U );
  pop( rotor, ROLE_EAGER );

  /* Eviction of an incomplete FEC set forgets the shreds it had. */

  fd_mr20_t k32; memcpy( k32.uc, m32.uc, sizeof(fd_mr20_t) );
  fd_rotor_fec_evicted( rotor, 3UL, 2U*FD_FEC_SHRED_CNT, &k32 );
  FD_TEST( !fec_pool_ele( rotor->fec_pool, e3->fecs[ 2 ] )->rcvd );

  /* Finalized blks are ROLE_FINAL. */

  fd_mr32_t        f5  = hash( 0x50 );
  fd_rotor_blk_t * fin = fd_rotor_blk_finalized( rotor, 5UL, &f5 );
  FD_TEST( fin && role( rotor, fin )==ROLE_FINAL );
}

/* A blk in a blk_treap that is freed leaves it at once, by a prune or
   by the root advancing past it, and the next pop returns the next
   blk. */

static void
test_blk_treap_freed( void ) {
  fd_mr32_t        h20   = hash( 0x20 ), h30 = hash( 0x30 );
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 2UL, 0x20 );
  fd_rotor_blk_t * b     = notar( rotor, 3UL, 0x30 );
  FD_TEST( a->in_blk_treap && b->in_blk_treap && blk_treap_cnt( rotor )==2UL );
  fd_rotor_blk_dead( rotor, 2UL, &h20 );
  FD_TEST( blk_treap_cnt( rotor )==1UL );
  FD_TEST( pop( rotor, ROLE_NOTAR )==b && !blk_treap_pop( rotor ) );

  rotor = setup();
  notar( rotor, 1UL, 0x10 );
  notar( rotor, 2UL, 0x20 );
  fd_rotor_blk_t * c = notar( rotor, 3UL, 0x30 );
  fd_rotor_slot_skipped( rotor, 1UL );
  FD_TEST( blk_treap_cnt( rotor )==2UL );
  fd_rotor_root_advanced( rotor, 2UL, &h20 );
  FD_TEST( blk_treap_cnt( rotor )==1UL );                                      /* the new root leaves, as the root blk at init */
  FD_TEST( pop( rotor, ROLE_NOTAR )==c && !blk_treap_pop( rotor ) );
  fd_rotor_blk_dead( rotor, 3UL, &h30 );
  FD_TEST( !blk_treap_cnt( rotor ) );
}

/* A promotion while in a treap moves the blk to its new role's treap,
   so it pops before lower roles whatever its slot.  A blk promoted
   while not in one stays out. */

static void
test_blk_treap_promote( void ) {
  fd_mr32_t        root  = hash( 0xEE ), h30 = hash( 0x30 ), m40 = hash( 0x41 );
  ulong            four  = 4UL;
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * n     = notar( rotor, 1UL, 0x10 );
  fd_rotor_blk_t * m     = notar( rotor, 3UL, 0x30 );
  shred0  ( rotor, 4UL, 0UL, &root, &m40 );
  complete( rotor, 4UL, 0UL, 0U, 1, &m40 );
  fd_rotor_blk_t * e     = blk_map_ele_query( rotor->blk_map, &four, NULL, rotor->blk_pool );
  FD_TEST( role( rotor, e )==ROLE_EAGER && e->eager && e->in_blk_treap && memcmp( &e->dmr, &hash_null, sizeof(fd_mr32_t) ) );

  FD_TEST( fd_rotor_blk_finalized( rotor, 3UL, &h30 )==m );
  FD_TEST( role( rotor, m )==ROLE_FINAL && m->in_blk_treap );
  fd_mr32_t d4 = e->dmr;
  FD_TEST( !fd_rotor_blk_notarized( rotor, 4UL, &d4 ) );
  FD_TEST( role( rotor, e )==ROLE_NOTAR && !e->eager && e->in_blk_treap );
  FD_TEST( fd_rotor_treap_ele_cnt( rotor->final_treap )==1UL );
  FD_TEST( fd_rotor_treap_ele_cnt( rotor->notar_treap )==2UL );
  FD_TEST( !fd_rotor_treap_ele_cnt( rotor->eager_treap ) );

  FD_TEST( pop( rotor, ROLE_FINAL )==m );
  FD_TEST( pop( rotor, ROLE_NOTAR )==n );
  FD_TEST( pop( rotor, ROLE_NOTAR )==e );
  FD_TEST( !blk_treap_pop( rotor ) );

  fd_mr32_t h10 = hash( 0x10 );
  FD_TEST( fd_rotor_blk_finalized( rotor, 1UL, &h10 )==n );
  FD_TEST( role( rotor, n )==ROLE_FINAL && !n->in_blk_treap && !blk_treap_cnt( rotor ) );
}

/* Pops come final, then notar, then eager, then slot order.  Only a
   slot's first notar blk is notar, a second one is eager, repaired by
   blk id. */

static void
test_blk_treap_order( void ) {
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 ), m30 = hash( 0x31 ), h40 = hash( 0x40 ), h60 = hash( 0x60 );
  fd_rotor_t * rotor = setup();
  fd_rotor_blk_t * n5  = notar( rotor, 5UL, 0x50 );
  fd_rotor_blk_t * n2a = notar( rotor, 2UL, 0x20 );
  fd_rotor_blk_t * n7  = notar( rotor, 7UL, 0x70 );
  fd_rotor_blk_t * n2b = notar( rotor, 2UL, 0x21 );
  shred0( rotor, 3UL, 0UL, &root, &m30 );
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  fd_rotor_blk_t * f6  = fd_rotor_blk_finalized( rotor, 6UL, &h60 );
  fd_rotor_blk_t * f4  = fd_rotor_blk_finalized( rotor, 4UL, &h40 );
  FD_TEST( blk_treap_cnt( rotor )==8UL );

  FD_TEST( pop( rotor, ROLE_FINAL )==f4 );
  FD_TEST( pop( rotor, ROLE_FINAL )==f6 );
  FD_TEST( pop( rotor, ROLE_NOTAR )==n2a );
  FD_TEST( pop( rotor, ROLE_NOTAR )==n5 );
  FD_TEST( pop( rotor, ROLE_NOTAR )==n7 );
  FD_TEST( pop( rotor, ROLE_EAGER )->slot==1UL );
  FD_TEST( pop( rotor, ROLE_EAGER )==n2b && !n2b->eager );
  FD_TEST( pop( rotor, ROLE_EAGER )->slot==3UL );
  FD_TEST( !blk_treap_pop( rotor ) );
}

/* was_eager is the predicate the eager bit replaces: blk is its slot's
   eager blk, the turbine version, and the slot is not invalidated,
   finalized, or ours. */

static int
was_eager( fd_rotor_t const *     rotor,
           fd_rotor_blk_t const * blk ) {
  fd_rotor_slot_meta_t const * meta = &rotor->slot_meta[ blk->slot % rotor->slot_max ];
  return meta->slot==blk->slot && !meta->invalidated && meta->final==blk_pool_idx_null( rotor->blk_pool ) && !meta->leader &&
         meta->eager==blk_pool_idx( rotor->blk_pool, blk ) && role( rotor, blk )==ROLE_EAGER;
}

/* check_eager checks the eager bit matches the predicate, and that a
   turbine version that must not be repaired is not in a blk_treap. */

static void
check_eager( fd_rotor_t const *     rotor,
             fd_rotor_blk_t const * blk ) {
  FD_TEST( blk->eager==was_eager( rotor, blk ) );
  FD_TEST( blk->eager || role( rotor, blk )!=ROLE_EAGER || !blk->in_blk_treap );
}

/* The eager bit follows the slot's eager blk across invalidation,
   finalization of it or of another blk, a dedup that names it, and our
   own leader FEC sets. */

static void
test_eager_bit( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m12 = hash( 0x13 ), h77 = hash( 0x77 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );
  ulong     zero = 0UL, one = 1UL;

  fd_rotor_t * rotor = setup();
  check_eager( rotor, blk_map_ele_query( rotor->blk_map, &zero, NULL, rotor->blk_pool ) );
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  fd_rotor_blk_t * e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( e1->eager && e1->in_blk_treap ); check_eager( rotor, e1 );
  fd_rotor_slot_invalidated( rotor, 1UL, 0 );
  FD_TEST( !e1->eager && !e1->in_blk_treap ); check_eager( rotor, e1 );

  rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( e1->eager ); check_eager( rotor, e1 );
  FD_TEST( fd_rotor_blk_finalized( rotor, 1UL, &d1 )==e1 );
  FD_TEST( !e1->eager && role( rotor, e1 )==ROLE_FINAL ); check_eager( rotor, e1 );

  rotor = setup();
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  fd_rotor_blk_t * fin = fd_rotor_blk_finalized( rotor, 1UL, &h77 );
  FD_TEST( fin && fin!=e1 && !e1->eager && !e1->in_blk_treap ); check_eager( rotor, e1 ); check_eager( rotor, fin );
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot = 1UL; shred->idx = 2U*FD_FEC_SHRED_CNT; shred->data.parent_off = 1;
  fd_rotor_shred_insert( rotor, shred, &m12, 0L );                            /* turbine moves its limit */
  FD_TEST( e1->rcvd_fec_cnt==3U && !e1->in_blk_treap ); check_eager( rotor, e1 );

  rotor = setup();
  fd_rotor_blk_t * n1 = fd_rotor_blk_notarized( rotor, 1UL, &d1 );
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  e1 = blk_pool_ele( rotor->blk_pool, rotor->slot_meta[ one % rotor->slot_max ].eager );
  FD_TEST( e1!=n1 && e1->eager ); check_eager( rotor, e1 ); check_eager( rotor, n1 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool )==e1 && !blk_map_ele_next_const( e1, NULL, rotor->blk_pool ) );
  FD_TEST( !e1->eager && role( rotor, e1 )==ROLE_NOTAR ); check_eager( rotor, e1 );

  rotor = setup();
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( e1->eager );
  complete_as( rotor, 1UL, 0UL, 0U, 1, &m10, 1 );
  FD_TEST( !e1->eager && !e1->in_blk_treap ); check_eager( rotor, e1 );

  rotor = setup();
  complete_as( rotor, 1UL, 0UL, 0U, 0, &m10, 1 );
  e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( !e1->eager && !e1->in_blk_treap ); check_eager( rotor, e1 );

  rotor = fd_rotor_join( fd_rotor_new( mem, SLOT_MAX, FEC_MAX, 42UL ) );
  fd_rotor_init( rotor, 0UL, &hash_null, NULL, NULL );
  fd_rotor_blk_t * r = blk_map_ele_query( rotor->blk_map, &zero, NULL, rotor->blk_pool );
  FD_TEST( role( rotor, r )==ROLE_FINAL && !r->in_blk_treap ); check_eager( rotor, r );
}

/* Booting from genesis, the root's block id is zero and slot 1 names
   it.  Slot 1 still computes its dmr, so slot 2 links to it.  A notar
   blk naming the zero id also links under the root. */

static void
test_genesis( void ) {
  fd_rotor_t * rotor = fd_rotor_join( fd_rotor_new( mem, SLOT_MAX, FEC_MAX, 42UL ) );
  fd_rotor_init( rotor, 0UL, &hash_null, NULL, NULL );
  fd_mr32_t m10 = hash( 0x11 ), m20 = hash( 0x21 );

  shred0  ( rotor, 1UL, 0UL, &hash_null, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  expect( rotor, e1, 0U );

  shred0  ( rotor, 2UL, 1UL, &e1->dmr, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  expect( rotor, blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool ), 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  fd_rotor_blk_t * n3    = notar( rotor, 3UL, 0x30 );
  fd_mr32_t        n3_id = hash( 0x30 ), m30 = hash( 0x31 );
  ulong            zero  = 0UL;
  FD_TEST( !fd_rotor_blk_parented( rotor, 3UL, &n3_id, 0UL, &hash_null, 1U ) );
  FD_TEST( n3->parent==blk_pool_idx( rotor->blk_pool, blk_map_ele_query( rotor->blk_map, &zero, NULL, rotor->blk_pool ) ) );
  fecs    ( rotor, 3UL, 0x30, 1U );
  complete( rotor, 3UL, 0UL, 0U, 1, &m30 );
  expect( rotor, n3, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* An eager blk in a slot finalized as skipped is never consumed. */

static void
test_skipped_not_consumed( void ) {
  fd_rotor_t * rotor = setup();
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 );
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  fd_rotor_slot_skipped( rotor, 1UL );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A slot complete shred below a FEC set already received invalidates
   the eager blk, which is then never consumed. */

static void
test_complete_below_rcvd( void ) {
  fd_rotor_t * rotor = setup();
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m12 = hash( 0x13 );
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 2U, 0, &m12 );
  FD_TEST( !complete( rotor, 1UL, 0UL, 1U, 1, &m11 ) );
  ulong            one = 1UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( rotor->slot_meta[ e1->slot % rotor->slot_max ].invalidated );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* An eager blk that is whole when it is invalidated has a dmr, so it is
   still consumed once its parent is. */

static void
test_invalidated_after_whole( void ) {
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 1UL, 0x10 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 1U );
  fecs    ( rotor, 1UL, 0x10, 1U );

  fd_mr32_t a_id = hash( 0x10 ), m20 = hash( 0x21 );
  shred0  ( rotor, 2UL, 1UL, &a_id, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  ulong            two = 2UL;
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, a ) && memcmp( &e2->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  fd_rotor_slot_invalidated( rotor, 2UL, 0 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  fd_mr32_t m11 = hash( 0x11 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m11 );
  expect( rotor, a,  0U );
  expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* FEC sets of an eager blk complete out of order: the slot complete FEC
   set first, so its count is known before anything is buffered, or
   last, so earlier FEC sets stream while the count is unknown. */

static void
test_eager_out_of_order( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m12 = hash( 0x13 );
  ulong     one  = 1UL;

  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 2U, 1, &m12 );
  fd_rotor_blk_t * e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( e1->cmpl_fec_cnt==3U && !e1->buff_fec_cnt );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  expect( rotor, e1, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  complete( rotor, 1UL, 0UL, 1U, 0, &m11 );
  FD_TEST( memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  expect( rotor, e1, 1U ); expect( rotor, e1, 2U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  expect( rotor, e1, 0U );
  complete( rotor, 1UL, 0UL, 1U, 0, &m11 );
  expect( rotor, e1, 1U );
  FD_TEST( !e1->cmpl_fec_cnt && !memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  complete( rotor, 1UL, 0UL, 2U, 1, &m12 );
  FD_TEST( e1->cmpl_fec_cnt==3U && memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  expect( rotor, e1, 2U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A FEC set completed again is not delivered twice. */

static void
test_complete_again( void ) {
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 );
  fd_rotor_t * rotor = setup();
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot            = 1UL;
  shred->idx             = FD_FEC_SHRED_CNT - 1U;
  shred->data.parent_off = 1;
  shred->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  FD_TEST( fd_rotor_fec_complete( rotor, shred, &m10, 1, 0L )->is_leader );
  FD_TEST( complete( rotor, 1UL, 0UL, 0U, 1, &m10 )->is_leader );
  ulong one = 1UL;
  expect( rotor, blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool ), 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A notar blk learns its FEC set count before, after, or while its FEC
   sets complete out of order. */

static void
test_notar_out_of_order( void ) {
  fd_mr32_t mr;

  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * n     = notar( rotor, 1UL, 0x10 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 3U );
  fecs    ( rotor, 1UL, 0x10, 3U );
  mr = hash( 0x13 ); complete( rotor, 1UL, 0UL, 2U, 1, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 0, &mr );
  expect( rotor, n, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  mr = hash( 0x12 ); complete( rotor, 1UL, 0UL, 1U, 0, &mr );
  expect( rotor, n, 1U ); expect( rotor, n, 2U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  rotor = setup();
  n     = notar( rotor, 1UL, 0x10 );
  fecs( rotor, 1UL, 0x10, 2U );
  mr = hash( 0x12 ); complete( rotor, 1UL, 0UL, 1U, 1, &mr );
  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 0, &mr );
  FD_TEST( n->buff_fec_cnt==2U && fd_rotor_deque_empty( rotor->reasm_deque ) );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 2U );
  expect( rotor, n, 0U ); expect( rotor, n, 1U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  rotor = setup();
  n     = notar( rotor, 1UL, 0x10 );
  fecs( rotor, 1UL, 0x10, 3U );
  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 0, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 3U );
  expect( rotor, n, 0U );
  mr = hash( 0x13 ); complete( rotor, 1UL, 0UL, 2U, 1, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  mr = hash( 0x12 ); complete( rotor, 1UL, 0UL, 1U, 0, &mr );
  expect( rotor, n, 1U ); expect( rotor, n, 2U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A FEC set held by both the eager blk and a notar blk of the slot is
   delivered for both, in blk_map chain order. */

static void
test_shared_fec( void ) {
  fd_mr32_t        root  = hash( 0xEE ), m10 = hash( 0x11 );
  fd_rotor_t *     rotor = setup();
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  fd_rotor_blk_t * n1    = notar( rotor, 1UL, 0x10 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 2U );
  fecs    ( rotor, 1UL, 0x10, 1U );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  ulong            one   = 1UL;
  fd_rotor_blk_t * e1    = blk_pool_ele( rotor->blk_pool, rotor->slot_meta[ one % rotor->slot_max ].eager );
  FD_TEST( e1!=n1 && !rotor->slot_meta[ one % rotor->slot_max ].invalidated );
  expect( rotor, n1, 0U ); expect( rotor, e1, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A notar blk notarizes a FEC set the eager blk already completed.  No
   completion follows, so the notarization itself delivers it. */

static void
test_notarized_complete_fec( void ) {
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 );
  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  ulong            one = 1UL;
  fd_rotor_blk_t * e1  = blk_pool_ele( rotor->blk_pool, rotor->slot_meta[ one % rotor->slot_max ].eager );
  expect( rotor, e1, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  fd_rotor_blk_t * n1 = notar( rotor, 1UL, 0x10 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 2U );
  fecs    ( rotor, 1UL, 0x10, 1U );
  FD_TEST( n1->buff_fec_cnt==1U );
  expect( rotor, n1, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Invalidation of the eager blk: by a FEC set past the slot complete
   one, by a slot complete shred below FEC sets already delivered, and
   explicitly before its only FEC set completes.  Nothing is delivered
   after the invalidation, and later shreds of the slot are dropped. */

static void
test_eager_invalidated( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m12 = hash( 0x13 ), m13 = hash( 0x14 );
  ulong     one  = 1UL;

  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( !complete( rotor, 1UL, 0UL, 2U, 0, &m12 ) );
  FD_TEST( rotor->slot_meta[ one % rotor->slot_max ].invalidated );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 0, &m11 );
  complete( rotor, 1UL, 0UL, 2U, 0, &m12 );
  fd_rotor_blk_t * e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  expect( rotor, e1, 0U ); expect( rotor, e1, 1U ); expect( rotor, e1, 2U );
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot            = 1UL;
  shred->idx             = FD_FEC_SHRED_CNT + 8U;
  shred->data.parent_off = 1;
  shred->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  fd_rotor_shred_insert( rotor, shred, &m11, 0L );
  FD_TEST( rotor->slot_meta[ one % rotor->slot_max ].invalidated );
  FD_TEST( !complete( rotor, 1UL, 0UL, 3U, 1, &m13 ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  rotor = setup();
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  fd_rotor_slot_invalidated( rotor, 1UL, 0 );
  FD_TEST( complete( rotor, 1UL, 0UL, 0U, 1, &m10 ) );
  e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( !memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Finalizing a slot as a block rotor does not have frees the eager blk
   and drops its later FEC sets.  A second finalization of the slot as
   another block, or finalizing a skipped slot, is refused. */

static void
test_finalize_other( void ) {
  fd_mr32_t    root  = hash( 0xEE ), m10 = hash( 0x11 ), h77 = hash( 0x77 ), h40 = hash( 0x40 ), h20 = hash( 0x20 );
  fd_rotor_t * rotor = setup();
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  fd_rotor_blk_t * fin = fd_rotor_blk_finalized( rotor, 1UL, &h77 );
  ulong            one = 1UL, two = 2UL;
  FD_TEST( fin && !is_eager( rotor, fin ) );
  fd_rotor_blk_t * e1  = blk_pool_ele( rotor->blk_pool, rotor->slot_meta[ one % rotor->slot_max ].eager );
  FD_TEST( e1 && e1!=fin ); /* the unfinished turbine version stays */
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 ); /* it completes as another blk and is pruned */
  FD_TEST( blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool )==fin && !blk_map_ele_next_const( fin, NULL, rotor->blk_pool ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  FD_TEST( !fd_rotor_blk_finalized( rotor, 1UL, &h40 ) );
  FD_TEST( blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool )==fin && !blk_map_ele_next_const( fin, NULL, rotor->blk_pool ) );

  fd_rotor_slot_skipped( rotor, 2UL );
  FD_TEST( !fd_rotor_blk_finalized( rotor, 2UL, &h20 ) );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool ) );
}

/* A child that named a block before rotor had it links under the parent
   slot's turbine version.  Finalizing that block moves the child to the
   finalized blk and keeps the unfinished turbine version, which then
   completes as the finalized blk and takes its place: the child is
   delivered after it.  If the finalized blk was already delivered, the
   child is delivered at once. */

static void
test_finalize_moves_child( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );
  ulong     two  = 2UL;

  fd_rotor_t * rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  shred0  ( rotor, 2UL, 1UL, &d1,   &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  fd_rotor_blk_t * e2 = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  fd_rotor_blk_t * n1 = fd_rotor_blk_finalized( rotor, 1UL, &d1 );
  FD_TEST( n1 && !is_eager( rotor, n1 ) && e2->parent==blk_pool_idx( rotor->blk_pool, n1 ) );
  fd_rotor_blk_parented( rotor, 1UL, &d1, 0UL, &root, 2U );
  fd_mr20_t k0; memcpy( k0.uc, m10.uc, sizeof(fd_mr20_t) );
  fd_mr20_t k1; memcpy( k1.uc, m11.uc, sizeof(fd_mr20_t) );
  FD_TEST( fd_rotor_fec_notarized( rotor, 1UL, &d1, 0U,               &k0 ) );
  FD_TEST( fd_rotor_fec_notarized( rotor, 1UL, &d1, FD_FEC_SHRED_CNT, &k1 ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  ulong            one    = 1UL;
  ulong            n1_idx = blk_pool_idx( rotor->blk_pool, n1 );
  fd_rotor_blk_t * e1     = blk_pool_ele( rotor->blk_pool, rotor->slot_meta[ one % rotor->slot_max ].eager );
  FD_TEST( e1 && e1!=n1 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( rotor->slot_meta[ one % rotor->slot_max ].final==blk_pool_idx( rotor->blk_pool, e1 ) );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  fd_rotor_deque_t a0 = fd_rotor_deque_pop_head( rotor->reasm_deque ), b0 = fd_rotor_deque_pop_head( rotor->reasm_deque ); /* both versions consumed FEC set 0 */
  FD_TEST( a0.fec_idx==0U && b0.fec_idx==0U && a0.blk_idx+b0.blk_idx==n1_idx+blk_pool_idx( rotor->blk_pool, e1 ) && a0.blk_idx!=b0.blk_idx );
  expect( rotor, e1, 1U );
  expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  fd_mr32_t a_id = hash( 0x10 ), m61 = hash( 0x61 ), m11a = hash( 0x11 );
  rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m61 );
  shred0  ( rotor, 2UL, 1UL, &a_id, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  e2 = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  fd_rotor_blk_t * a = notar( rotor, 1UL, 0x10 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 1U );
  fecs    ( rotor, 1UL, 0x10, 1U );
  complete( rotor, 1UL, 0UL, 0U, 1, &m11a );
  expect( rotor, a, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  FD_TEST( fd_rotor_blk_finalized( rotor, 1UL, &a_id )==a );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, a ) );
  expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* ParentAndFecSetCount responses: a chain parented bottom up before its
   parents exist creates them; a response naming a parent at or after
   the blk is refused without latching; duplicates and conflicting
   repeats are ignored; a parent at the root slot with another id, in a
   slot finalized as another block, or in a skipped slot is never
   linked. */

static void
test_parented( void ) {
  fd_mr32_t h10 = hash( 0x10 ), h20 = hash( 0x20 ), h30 = hash( 0x30 ), h40 = hash( 0x40 ), h77 = hash( 0x77 ), hEE = hash( 0xEE );
  fd_mr32_t mr;
  ulong     zero = 0UL, one = 1UL;

  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * c     = notar( rotor, 3UL, 0x30 );
  fd_rotor_blk_t * n2    = fd_rotor_blk_parented( rotor, 3UL, &h30, 2UL, &h20, 1U );
  FD_TEST( n2 && n2->slot==2UL && n2->child==blk_pool_idx( rotor->blk_pool, c ) && c->parent==blk_pool_idx( rotor->blk_pool, n2 ) );
  FD_TEST( !fd_rotor_blk_notarized( rotor, 2UL, &h20 ) );
  fd_rotor_blk_t * n1    = fd_rotor_blk_parented( rotor, 2UL, &h20, 1UL, &h10, 1U );
  FD_TEST( n1 && n2->parent==blk_pool_idx( rotor->blk_pool, n1 ) );
  FD_TEST( !fd_rotor_blk_parented( rotor, 1UL, &h10, 0UL, &hEE, 1U ) );
  FD_TEST( n1->parent==blk_pool_idx( rotor->blk_pool, blk_map_ele_query( rotor->blk_map, &zero, NULL, rotor->blk_pool ) ) );
  fecs( rotor, 3UL, 0x30, 1U );
  fecs( rotor, 2UL, 0x20, 1U );
  fecs( rotor, 1UL, 0x10, 1U );
  mr = hash( 0x31 ); complete( rotor, 3UL, 2UL, 0U, 1, &mr );
  mr = hash( 0x21 ); complete( rotor, 2UL, 1UL, 0U, 1, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 1, &mr );
  expect( rotor, n1, 0U ); expect( rotor, n2, 0U ); expect( rotor, c, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  rotor = setup();
  fd_rotor_blk_t * b = notar( rotor, 2UL, 0x20 );
  FD_TEST( !fd_rotor_blk_parented( rotor, 2UL, &h20, 2UL, &h10, 1U ) && b->parent_slot==ULONG_MAX );
  n1 = fd_rotor_blk_parented( rotor, 2UL, &h20, 1UL, &h10, 1U );
  FD_TEST( n1 && b->parent==blk_pool_idx( rotor->blk_pool, n1 ) );
  FD_TEST( !fd_rotor_blk_parented( rotor, 2UL, &h20, 1UL, &h40, 1U ) );
  FD_TEST( !fd_rotor_blk_parented( rotor, 2UL, &h20, 1UL, &h10, 1U ) );
  FD_TEST( b->parent==blk_pool_idx( rotor->blk_pool, n1 ) && n1->child==blk_pool_idx( rotor->blk_pool, b ) );
  FD_TEST( b->sibling==blk_pool_idx_null( rotor->blk_pool ) && !memcmp( &b->parent_blk_mr, &h10, sizeof(fd_mr32_t) ) );
  FD_TEST( blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool )==n1 && !blk_map_ele_next_const( n1, NULL, rotor->blk_pool ) );

  rotor = setup();
  b     = notar( rotor, 2UL, 0x20 );
  FD_TEST( !fd_rotor_blk_parented( rotor, 2UL, &h20, 0UL, &h77, 1U ) );
  FD_TEST( b->parent==blk_pool_idx_null( rotor->blk_pool ) && !blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool ) );
  fecs( rotor, 2UL, 0x20, 1U );
  mr = hash( 0x21 ); complete( rotor, 2UL, 0UL, 0U, 1, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  rotor = setup();
  b     = notar( rotor, 2UL, 0x20 );
  c     = notar( rotor, 3UL, 0x30 );
  n1    = fd_rotor_blk_finalized( rotor, 1UL, &h10 );
  FD_TEST( !fd_rotor_blk_parented( rotor, 2UL, &h20, 1UL, &h40, 1U ) && b->parent==blk_pool_idx_null( rotor->blk_pool ) );
  FD_TEST( blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool )==n1 && !blk_map_ele_next_const( n1, NULL, rotor->blk_pool ) );
  FD_TEST( !fd_rotor_blk_parented( rotor, 3UL, &h30, 1UL, &h10, 1U ) && c->parent==blk_pool_idx( rotor->blk_pool, n1 ) );

  rotor = setup();
  fd_rotor_slot_skipped( rotor, 1UL );
  b     = notar( rotor, 2UL, 0x20 );
  FD_TEST( !fd_rotor_blk_parented( rotor, 2UL, &h20, 1UL, &h10, 1U ) && b->parent==blk_pool_idx_null( rotor->blk_pool ) );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool ) );
}

/* A fork: two children of one parent in different slots, one complete
   and one partial when the parent completes.  The partial child streams
   its prefix and the rest of it follows its last FEC set. */

static void
test_fork( void ) {
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 1UL, 0x10 );
  fd_rotor_blk_t * b     = notar( rotor, 2UL, 0x20 );
  fd_rotor_blk_t * c     = notar( rotor, 3UL, 0x30 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 1U );
  parented( rotor, 2UL, 0x20, 1UL, 0x10, 1U );
  parented( rotor, 3UL, 0x30, 1UL, 0x10, 2U );
  fecs( rotor, 1UL, 0x10, 1U );
  fecs( rotor, 2UL, 0x20, 1U );
  fecs( rotor, 3UL, 0x30, 2U );

  fd_mr32_t mr;
  mr = hash( 0x21 ); complete( rotor, 2UL, 1UL, 0U, 1, &mr );
  mr = hash( 0x31 ); complete( rotor, 3UL, 1UL, 0U, 0, &mr );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 1, &mr );
  expect( rotor, a, 0U ); expect( rotor, c, 0U ); expect( rotor, b, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  mr = hash( 0x32 ); complete( rotor, 3UL, 1UL, 1U, 1, &mr );
  expect( rotor, c, 1U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Skipping a slot frees its blks and unlinks their children: the middle
   of a notar chain, and an eager blk already delivered in full.  The
   orphaned descendants are never delivered. */

static void
test_skip_unlinks( void ) {
  ulong two = 2UL;

  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 1UL, 0x10 );
  notar( rotor, 2UL, 0x20 );
  fd_rotor_blk_t * c     = notar( rotor, 3UL, 0x30 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 1U );
  parented( rotor, 2UL, 0x20, 1UL, 0x10, 1U );
  parented( rotor, 3UL, 0x30, 2UL, 0x20, 1U );
  fd_rotor_slot_skipped( rotor, 2UL );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool ) );
  FD_TEST( a->child==blk_pool_idx_null( rotor->blk_pool ) );
  FD_TEST( c->parent==blk_pool_idx_null( rotor->blk_pool ) && c->sibling==blk_pool_idx_null( rotor->blk_pool ) );
  fecs( rotor, 1UL, 0x10, 1U );
  fecs( rotor, 3UL, 0x30, 1U );
  fd_mr32_t mr;
  mr = hash( 0x31 ); complete( rotor, 3UL, 2UL, 0U, 1, &mr );
  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 1, &mr );
  expect( rotor, a, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 );
  ulong     one  = 1UL;
  rotor = setup();
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 1, &m10 );
  fd_rotor_blk_t * e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  expect( rotor, e1, 0U );
  fd_mr32_t d1 = e1->dmr;
  shred0( rotor, 2UL, 1UL, &d1, &m20 );
  fd_rotor_blk_t * e2 = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  fd_rotor_slot_skipped( rotor, 1UL );
  FD_TEST( e2->parent==blk_pool_idx_null( rotor->blk_pool ) );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Twin merges where the notar twin has children: a notar child and an
   eager child that linked to it by dmr, alongside an eager child of the
   turbine version that named another block; and an eager child alone.
   The eager blk takes the twin's children and drops the one that named
   another block. */

static void
test_twin_merge_children( void ) {
  fd_mr32_t root = hash( 0xEE ), other = hash( 0x99 );
  fd_mr32_t m10  = hash( 0x11 ), m11   = hash( 0x12 ), m20 = hash( 0x21 ), m30 = hash( 0x31 ), m40 = hash( 0x41 ), m51 = hash( 0x51 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );
  ulong     one  = 1UL, two = 2UL, three = 3UL, four = 4UL;

  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * n1    = fd_rotor_blk_notarized( rotor, 1UL, &d1 );
  fd_rotor_blk_t * c     = notar( rotor, 2UL, 0x50 );
  fd_mr32_t        c_id  = hash( 0x50 );
  fd_rotor_blk_parented( rotor, 2UL, &c_id, 1UL, &d1, 1U );
  fecs    ( rotor, 2UL, 0x50, 1U );
  complete( rotor, 2UL, 1UL, 0U, 1, &m51 );
  shred0  ( rotor, 3UL, 1UL, &d1, &m30 );
  complete( rotor, 3UL, 1UL, 0U, 1, &m30 );
  shred0  ( rotor, 4UL, 1UL, &other, &m40 );
  complete( rotor, 4UL, 1UL, 0U, 1, &m40 );
  fd_rotor_blk_t * e3 = blk_map_ele_query( rotor->blk_map, &three, NULL, rotor->blk_pool );
  fd_rotor_blk_t * e4 = blk_map_ele_query( rotor->blk_map, &four,  NULL, rotor->blk_pool );
  fd_rotor_blk_t * e1 = blk_pool_ele( rotor->blk_pool, rotor->slot_meta[ one % rotor->slot_max ].eager );
  FD_TEST( e3->parent==blk_pool_idx( rotor->blk_pool, n1 ) && e4->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  expect( rotor, e1, 0U );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool )==e1 && !blk_map_ele_next_const( e1, NULL, rotor->blk_pool ) );
  FD_TEST( c->parent==blk_pool_idx( rotor->blk_pool, e1 ) && e3->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  FD_TEST( e4->parent==blk_pool_idx_null( rotor->blk_pool ) );
  expect( rotor, e1, 1U );
  expect( rotor, c,  0U ); expect( rotor, e3, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  rotor = setup();
  n1    = fd_rotor_blk_notarized( rotor, 1UL, &d1 );
  shred0  ( rotor, 2UL, 1UL, &d1, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  fd_rotor_blk_t * e2 = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, n1 ) );
  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  e1 = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  FD_TEST( is_eager( rotor, e1 ) && !blk_map_ele_next_const( e1, NULL, rotor->blk_pool ) );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, e1 ) );
  expect( rotor, e1, 0U ); expect( rotor, e1, 1U );
  expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* The root advances into the middle of a chain while a child is part
   delivered.  The new root keeps its children, which treat it as
   consumed in full, and the child's remaining FEC set follows. */

static void
test_root_advanced( void ) {
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 1UL, 0x10 );
  fd_rotor_blk_t * b     = notar( rotor, 2UL, 0x20 );
  fd_rotor_blk_t * c     = notar( rotor, 3UL, 0x30 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 2U );
  parented( rotor, 2UL, 0x20, 1UL, 0x10, 2U );
  parented( rotor, 3UL, 0x30, 2UL, 0x20, 2U );
  fecs( rotor, 1UL, 0x10, 2U );
  fecs( rotor, 2UL, 0x20, 2U );
  fecs( rotor, 3UL, 0x30, 2U );

  fd_mr32_t mr;
  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 0, &mr );
  mr = hash( 0x12 ); complete( rotor, 1UL, 0UL, 1U, 1, &mr );
  mr = hash( 0x21 ); complete( rotor, 2UL, 1UL, 0U, 0, &mr );
  mr = hash( 0x22 ); complete( rotor, 2UL, 1UL, 1U, 1, &mr );
  mr = hash( 0x31 ); complete( rotor, 3UL, 2UL, 0U, 0, &mr );
  expect( rotor, a, 0U ); expect( rotor, a, 1U );
  expect( rotor, b, 0U ); expect( rotor, b, 1U );
  expect( rotor, c, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  fd_mr32_t b_id = hash( 0x20 );
  ulong     zero = 0UL, one = 1UL;
  fd_rotor_root_advanced( rotor, 2UL, &b_id );
  FD_TEST( rotor->root==2UL );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &zero, NULL, rotor->blk_pool ) && !blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool ) );
  FD_TEST( b->parent==blk_pool_idx_null( rotor->blk_pool ) && c->parent==blk_pool_idx( rotor->blk_pool, b ) );
  FD_TEST( b->fecs[ 0 ]==fec_pool_idx_null( rotor->fec_pool ) && b->fecs[ 1 ]==fec_pool_idx_null( rotor->fec_pool ) );
  mr = hash( 0x32 ); complete( rotor, 3UL, 2UL, 1U, 1, &mr );
  expect( rotor, c, 1U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* next_perm advances p to the next lexicographic permutation of its n
   elements, and returns 0 once p was the last one. */

static int
next_perm( uint * p,
           uint   n ) {
  uint i = n-1U;
  while( i && p[ i-1U ]>=p[ i ] ) i--;
  if( !i ) return 0;
  uint j = n-1U;
  while( p[ j ]<=p[ i-1U ] ) j--;
  uint t = p[ i-1U ]; p[ i-1U ] = p[ j ]; p[ j ] = t;
  for( uint l=i, r=n-1U; l<r; l++, r-- ) { t = p[ l ]; p[ l ] = p[ r ]; p[ r ] = t; }
  return 1;
}

/* check_delivery drains the reasm queue and checks that each FEC set of
   blks[k], which has cnt[k] of them, was delivered exactly once, in
   index order, with its first after the last of blks[par[k]] (par[k]<0
   for a child of the root). */

static void
check_delivery( fd_rotor_t *            rotor,
                fd_rotor_blk_t * const * blks,
                uint const *            cnt,
                int const *             par,
                ulong                   blk_cnt ) {
  uint done[ 8 ] = {0};
  while( !fd_rotor_deque_empty( rotor->reasm_deque ) ) {
    fd_rotor_deque_t out = fd_rotor_deque_pop_head( rotor->reasm_deque );
    ulong   k   = 0UL;
    while( k<blk_cnt && out.blk_idx!=blk_pool_idx( rotor->blk_pool, blks[ k ] ) ) k++;
    FD_TEST( k<blk_cnt && out.fec_idx==done[ k ] );
    FD_TEST( out.fec_idx || par[ k ]<0 || done[ par[ k ] ]==cnt[ par[ k ] ] );
    done[ k ]++;
  }
  for( ulong k=0UL; k<blk_cnt; k++ ) FD_TEST( done[ k ]==cnt[ k ] );
}

/* Every ordering of the three ParentAndFecSetCount responses and the
   four FEC set completions of a notar chain A<-B<-C with 2/1/1 FEC sets,
   whose FEC sets are notarized up front. */

static void
test_perm_notar_chain( void ) {
  fd_mr32_t    root     = hash( 0xEE );
  uint const   cnt[ 3 ] = { 2U, 1U, 1U };
  int const    par[ 3 ] = { -1, 0, 1 };
  uint         p[ 7 ]   = { 0U, 1U, 2U, 3U, 4U, 5U, 6U };
  ulong        perm_cnt = 0UL;
  fd_rotor_t * rotor    = setup();
  do {
    fd_rotor_fini( rotor );
    fd_rotor_init( rotor, 0UL, &root, NULL, NULL );
    fd_rotor_blk_t * blks[ 3 ];
    blks[ 0 ] = notar( rotor, 1UL, 0x10 );
    blks[ 1 ] = notar( rotor, 2UL, 0x20 );
    blks[ 2 ] = notar( rotor, 3UL, 0x30 );
    fecs( rotor, 1UL, 0x10, 2U );
    fecs( rotor, 2UL, 0x20, 1U );
    fecs( rotor, 3UL, 0x30, 1U );
    for( ulong i=0UL; i<7UL; i++ ) {
      fd_mr32_t mr;
      switch( p[ i ] ) {
      case 0U: parented( rotor, 1UL, 0x10, 0UL, 0xEE, 2U );                   break;
      case 1U: parented( rotor, 2UL, 0x20, 1UL, 0x10, 1U );                   break;
      case 2U: parented( rotor, 3UL, 0x30, 2UL, 0x20, 1U );                   break;
      case 3U: mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 0, &mr ); break;
      case 4U: mr = hash( 0x12 ); complete( rotor, 1UL, 0UL, 1U, 1, &mr ); break;
      case 5U: mr = hash( 0x21 ); complete( rotor, 2UL, 1UL, 0U, 1, &mr ); break;
      default: mr = hash( 0x31 ); complete( rotor, 3UL, 2UL, 0U, 1, &mr ); break;
      }
    }
    check_delivery( rotor, blks, cnt, par, 3UL );
    perm_cnt++;
  } while( next_perm( p, 7U ) );
  FD_TEST( perm_cnt==5040UL );
}

/* Every ordering of turbine events for slots 1 (2 FEC sets) and 2 (1 FEC
   set, header naming slot 1's real block id) in which a slot's shred 0
   precedes the completion of its FEC set 0, as the shred tile publishes
   them.  Orderings with slot 2's header first link it under slot 1's
   turbine version created empty. */

static void
test_perm_eager_chain( void ) {
  fd_mr32_t    root     = hash( 0xEE );
  fd_mr32_t    m10      = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr32_t    d1       = slot1_dmr( &m10, &m11 );
  uint const   cnt[ 2 ] = { 2U, 1U };
  int const    par[ 2 ] = { -1, 0 };
  uint         p[ 5 ]   = { 0U, 1U, 2U, 3U, 4U };
  ulong        perm_cnt = 0UL;
  ulong        one      = 1UL, two = 2UL;
  fd_rotor_t * rotor    = setup();
  do {
    uint pos[ 5 ];
    for( uint i=0U; i<5U; i++ ) pos[ p[ i ] ] = i;
    if( pos[ 0 ]>pos[ 1 ] || pos[ 3 ]>pos[ 4 ] ) continue;
    fd_rotor_fini( rotor );
    fd_rotor_init( rotor, 0UL, &root, NULL, NULL );
    for( ulong i=0UL; i<5UL; i++ ) {
      switch( p[ i ] ) {
      case 0U: shred0  ( rotor, 1UL, 0UL, &root, &m10 );     break;
      case 1U: complete( rotor, 1UL, 0UL, 0U, 0, &m10 ); break;
      case 2U: complete( rotor, 1UL, 0UL, 1U, 1, &m11 ); break;
      case 3U: shred0  ( rotor, 2UL, 1UL, &d1, &m20 );       break;
      default: complete( rotor, 2UL, 1UL, 0U, 1, &m20 ); break;
      }
    }
    fd_rotor_blk_t * blks[ 2 ];
    blks[ 0 ] = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
    blks[ 1 ] = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
    FD_TEST( is_eager( rotor, blks[ 0 ] ) && !blk_map_ele_next_const( blks[ 0 ], NULL, rotor->blk_pool ) );
    FD_TEST( !memcmp( &blks[ 0 ]->dmr, &d1, sizeof(fd_mr32_t) ) && blks[ 1 ]->parent==blk_pool_idx( rotor->blk_pool, blks[ 0 ] ) );
    check_delivery( rotor, blks, cnt, par, 2UL );
    perm_cnt++;
  } while( next_perm( p, 5U ) );
  FD_TEST( perm_cnt==30UL );
}

/* Our leader FEC sets are delivered before FEC sets already queued,
   including a redelivery of the whole window, and in FEC order when
   several become deliverable at once. */

static void
test_leader_first( void ) {
  fd_rotor_t *     rotor = setup();
  fd_rotor_blk_t * a     = notar( rotor, 1UL, 0x10 );
  parented( rotor, 1UL, 0x10, 0UL, 0xEE, 2U );
  fecs    ( rotor, 1UL, 0x10, 2U );
  fd_mr32_t mr;
  mr = hash( 0x11 ); complete( rotor, 1UL, 0UL, 0U, 0, &mr );
  mr = hash( 0x12 ); complete( rotor, 1UL, 0UL, 1U, 1, &mr );
  fd_rotor_fec_reconsume( rotor );
  FD_TEST( fd_rotor_deque_cnt( rotor->reasm_deque )==4UL );

  fd_mr32_t a_id = hash( 0x10 ), m20 = hash( 0x21 ), m21 = hash( 0x22 ), m22 = hash( 0x23 );
  shred0     ( rotor, 2UL, 1UL, &a_id, &m20 );
  complete_as( rotor, 2UL, 1UL, 1U, 0, &m21, 1 );
  FD_TEST( fd_rotor_deque_cnt( rotor->reasm_deque )==4UL );
  complete_as( rotor, 2UL, 1UL, 0U, 0, &m20, 1 );
  ulong            two = 2UL;
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, a ) );
  expect( rotor, e2, 0U ); expect( rotor, e2, 1U );
  complete_as( rotor, 2UL, 1UL, 2U, 1, &m22, 1 );
  expect( rotor, e2, 2U );
  expect( rotor, a,  0U ); expect( rotor, a,  1U );
  expect( rotor, a,  0U ); expect( rotor, a,  1U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A skip frees the slot's blks, and the network's shreds for the
   skipped slot build nothing. */

static void
test_skipped_refused( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 );
  ulong     one  = 1UL;

  fd_rotor_t * rotor = setup();
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  fd_rotor_slot_skipped( rotor, 1UL );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool ) );
  shred0( rotor, 1UL, 0UL, &root, &m10 );
  FD_TEST( !complete( rotor, 1UL, 0UL, 0U, 0, &m10 ) );
  FD_TEST( !complete( rotor, 1UL, 0UL, 1U, 1, &m11 ) );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* Catchup gives every slot in (root, slot) without an eager blk an
   empty one, in its blk_treap for repair by position, as a first turbine
   shred would.  A slot that has a blk or is skipped is left alone, a
   lower slot does nothing, and a later skip prunes a pre-created blk. */

static void
test_catchup( void ) {
  fd_mr32_t root = hash( 0xEE ), m20 = hash( 0x21 );

  fd_rotor_t * rotor = setup();
  shred0( rotor, 2UL, 0UL, &root, &m20 );
  ulong            zero = 0UL, two = 2UL, four = 4UL;
  fd_rotor_blk_t * e2   = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  fd_rotor_slot_skipped( rotor, 4UL );
  ulong used      = blk_pool_used( rotor->blk_pool );
  ulong treap_cnt = fd_rotor_treap_ele_cnt( rotor->eager_treap );

  fd_rotor_slot_catchup( rotor, 6UL );
  FD_TEST( blk_pool_used( rotor->blk_pool )==used+3UL );
  FD_TEST( fd_rotor_treap_ele_cnt( rotor->eager_treap )==treap_cnt+3UL );
  for( ulong s=1UL; s<6UL; s+=2UL ) {
    fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool );
    FD_TEST( blk && !blk_map_ele_next_const( blk, NULL, rotor->blk_pool ) && is_eager( rotor, blk ) );
    FD_TEST( role( rotor, blk )==ROLE_EAGER && blk->eager && blk->in_blk_treap );
    FD_TEST( !memcmp( &blk->dmr, &hash_null, sizeof(fd_mr32_t) ) );
    FD_TEST( blk->parent==blk_pool_idx_null( rotor->blk_pool ) && blk->parent_slot==ULONG_MAX && !blk->rcvd_fec_cnt );
  }
  FD_TEST( blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool )==e2 && !blk_map_ele_next_const( e2, NULL, rotor->blk_pool ) );
  FD_TEST( e2->rcvd_fec_cnt==1U && e2->parent==blk_pool_idx( rotor->blk_pool, blk_map_ele_query( rotor->blk_map, &zero, NULL, rotor->blk_pool ) ) );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &four, NULL, rotor->blk_pool ) );
  for( ulong s=6UL; s<SLOT_MAX; s++ ) FD_TEST( !blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool ) );

  fd_rotor_slot_catchup( rotor, 3UL );
  FD_TEST( blk_pool_used( rotor->blk_pool )==used+3UL && rotor->catchup_slot==6UL );

  ulong three = 3UL;
  fd_rotor_slot_skipped( rotor, 3UL );
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &three, NULL, rotor->blk_pool ) );
  FD_TEST( blk_pool_used( rotor->blk_pool )==used+2UL );
  FD_TEST( fd_rotor_treap_ele_cnt( rotor->eager_treap )==treap_cnt+2UL );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  fd_mr32_t h8 = hash( 0x80 );
  fd_rotor_slot_invalidated( rotor, 7UL, 0 );
  FD_TEST( fd_rotor_blk_finalized( rotor, 8UL, &h8 ) );
  used = blk_pool_used( rotor->blk_pool );
  fd_rotor_slot_catchup( rotor, 10UL );
  FD_TEST( blk_pool_used( rotor->blk_pool )==used+2UL );
  FD_TEST( fd_rotor_slot_meta( rotor, 7UL )->eager==blk_pool_idx_null( rotor->blk_pool ) );
  FD_TEST( fd_rotor_slot_meta( rotor, 8UL )->eager==blk_pool_idx_null( rotor->blk_pool ) );
  ulong seven = 7UL;
  FD_TEST( !blk_map_ele_query( rotor->blk_map, &seven, NULL, rotor->blk_pool ) );
}

/* Shred 0 of slot 2 links under slot 1's pre-created eager blk, and
   both are delivered once slot 1 completes. */

static void
test_catchup_link( void ) {
  fd_mr32_t root = hash( 0xEE );
  fd_mr32_t m10  = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );

  fd_rotor_t * rotor = setup();
  fd_rotor_slot_catchup( rotor, 3UL );
  ulong            one = 1UL, two = 2UL;
  fd_rotor_blk_t * e1  = blk_map_ele_query( rotor->blk_map, &one, NULL, rotor->blk_pool );
  fd_rotor_blk_t * e2  = blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool );
  FD_TEST( e1 && e2 && is_eager( rotor, e1 ) && is_eager( rotor, e2 ) );

  shred0  ( rotor, 2UL, 1UL, &d1, &m20 );
  complete( rotor, 2UL, 1UL, 0U, 1, &m20 );
  FD_TEST( blk_map_ele_query( rotor->blk_map, &two, NULL, rotor->blk_pool )==e2 && !blk_map_ele_next_const( e2, NULL, rotor->blk_pool ) );
  FD_TEST( e2->parent==blk_pool_idx( rotor->blk_pool, e1 ) && e2->parent_slot==1UL );
  FD_TEST( !blk_map_ele_next_const( e1, NULL, rotor->blk_pool ) );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );

  shred0  ( rotor, 1UL, 0UL, &root, &m10 );
  complete( rotor, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
  complete( rotor, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( !memcmp( &e1->dmr, &d1, sizeof(fd_mr32_t) ) && is_eager( rotor, e1 ) );
  expect( rotor, e1, 0U ); expect( rotor, e1, 1U );
  expect( rotor, e2, 0U );
  FD_TEST( fd_rotor_deque_empty( rotor->reasm_deque ) );
}

/* A root advance frees the pre-created blks at or below the new root,
   and once the root passes the high-water catchup walks from the new
   root. */

static void
test_catchup_root_advanced( void ) {
  fd_rotor_t * rotor = setup();
  fd_rotor_slot_catchup( rotor, 6UL );
  fd_rotor_blk_t * c    = notar( rotor, 3UL, 0x30 );
  fd_mr32_t        c_id = hash( 0x30 );
  fd_rotor_root_advanced( rotor, 3UL, &c_id );
  for( ulong s=0UL; s<3UL; s++ ) FD_TEST( !blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool ) );
  ulong three = 3UL;
  FD_TEST( blk_map_ele_query( rotor->blk_map, &three, NULL, rotor->blk_pool )==c && !blk_map_ele_next_const( c, NULL, rotor->blk_pool ) );
  for( ulong s=4UL; s<6UL; s++ ) {
    fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool );
    FD_TEST( blk && is_eager( rotor, blk ) && blk->in_blk_treap );
  }
  FD_TEST( blk_pool_used( rotor->blk_pool )==3UL );

  fd_rotor_slot_catchup( rotor, 8UL );
  FD_TEST( blk_pool_used( rotor->blk_pool )==5UL );
  for( ulong s=6UL; s<8UL; s++ ) {
    fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool );
    FD_TEST( blk && is_eager( rotor, blk ) && blk->in_blk_treap );
  }

  fd_rotor_blk_t * f    = notar( rotor, 9UL, 0x90 );
  fd_mr32_t        f_id = hash( 0x90 );
  fd_rotor_root_advanced( rotor, 9UL, &f_id );
  FD_TEST( blk_pool_used( rotor->blk_pool )==1UL );
  fd_rotor_slot_catchup( rotor, 12UL );
  for( ulong s=4UL; s<9UL; s++ ) FD_TEST( !blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool ) );
  ulong nine = 9UL;
  FD_TEST( blk_map_ele_query( rotor->blk_map, &nine, NULL, rotor->blk_pool )==f );
  for( ulong s=10UL; s<12UL; s++ ) {
    fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool );
    FD_TEST( blk && is_eager( rotor, blk ) && blk->in_blk_treap );
  }
  FD_TEST( blk_pool_used( rotor->blk_pool )==3UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_chain();
  test_link_late();
  test_finalize_unlinks();
  test_eager_chain();
  test_eager_wrong_parent();
  test_eager_finished_wrong_parent();
  test_root_wrong_parent();
  test_orphan_adopted();
  test_fec_reconsume();
  test_blk_dead();
  test_orphan_stops();
  test_eqvoc_invalidates();
  test_fec_alias_refused();
  test_repair_blk_treap();
  test_blk_treap_freed();
  test_blk_treap_promote();
  test_blk_treap_order();
  test_eager_bit();
  test_twin_merge();
  test_notarized_shreds_build_eager();
  test_genesis();
  test_skipped_not_consumed();
  test_complete_below_rcvd();
  test_invalidated_after_whole();
  test_eager_out_of_order();
  test_complete_again();
  test_notar_out_of_order();
  test_shared_fec();
  test_notarized_complete_fec();
  test_eager_invalidated();
  test_finalize_other();
  test_finalize_moves_child();
  test_parented();
  test_fork();
  test_skip_unlinks();
  test_twin_merge_children();
  test_root_advanced();
  test_perm_notar_chain();
  test_perm_eager_chain();
  test_leader_first();
  test_skipped_refused();
  test_catchup();
  test_catchup_link();
  test_catchup_root_advanced();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
