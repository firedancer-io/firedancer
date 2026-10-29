#include "fd_repair.h"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"
#include "../../disco/events/generated/fd_event_gen.h"

#define SLOT_MAX (16UL)
#define FEC_MAX  (SLOT_MAX*FD_VOTOR_EQVOC_MAX*FD_FEC_BLK_MAX)
#define BLK_FECS (FD_FEC_BLK_MAX)

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

static fd_repair_fec_t *
complete_as( fd_repair_t *     repair,
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
  return fd_repair_fec_complete( repair, shred, mr, is_leader, 0U, 0U, 0U, 0U, 0U, 0U, 0L );
}

static fd_repair_fec_t *
complete( fd_repair_t *     repair,
          ulong             slot,
          ulong             parent_slot,
          uint              fec_idx,
          int               last,
          fd_mr32_t const * mr ) {
  return complete_as( repair, slot, parent_slot, fec_idx, last, mr, 0 );
}

/* notar creates the notar blk (slot, dmr).  fecs notarizes its FEC
   sets, FEC set k under merkle root hash( dmr+1+k ). */

static fd_repair_blk_t *
notar( fd_repair_t * repair,
       ulong         slot,
       uchar         dmr ) {
  fd_mr32_t         id  = hash( dmr );
  fd_repair_blk_t * blk = fd_repair_blk_notarized( repair, slot, &id );
  FD_TEST( blk );
  return blk;
}

static void
fecs( fd_repair_t * repair,
      ulong         slot,
      uchar         dmr,
      uint          fec_set_cnt ) {
  fd_mr32_t id = hash( dmr );
  for( uint k=0U; k<fec_set_cnt; k++ ) {
    fd_mr32_t         mr = hash( (uchar)( dmr+1U+k ) );
    fd_mr20_t key; memcpy( key.uc, mr.uc, sizeof(fd_mr20_t) );
    FD_TEST( fd_repair_fec_notarized( repair, slot, &id, k*FD_FEC_SHRED_CNT, &key, 0L ) );
  }
}

static void
parented( fd_repair_t * repair,
          ulong         slot,
          uchar         dmr,
          ulong         parent_slot,
          uchar         parent_dmr,
          uint          fec_set_cnt ) {
  fd_mr32_t id = hash(  dmr ), pid = hash( parent_dmr );
  fd_repair_blk_parented( repair, slot, &id, parent_slot, &pid, fec_set_cnt, 0L );
}

static void
expect( fd_repair_t *           repair,
        fd_repair_blk_t const * blk,
        uint                    fec_idx ) {
  FD_TEST( !fd_repair_deque_empty( repair->reasm_deque ) );
  fd_repair_deque_t out = fd_repair_deque_pop_head( repair->reasm_deque );
  FD_TEST( out.blk_idx==fd_repair_blk_pool_idx( repair->blk_pool, blk ) && out.fec_idx==fec_idx );
}

/* shred0 inserts the first data shred of slot, whose payload is the
   block header naming (parent_slot, parent_mr), under FEC set 0's
   merkle root fec0_mr. */

static void
shred0( fd_repair_t *     repair,
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
  shred->variant          = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  shred->slot             = slot;
  shred->idx              = 0U;
  shred->data.parent_off  = (ushort)( slot-parent_slot );
  shred->data.size        = (ushort)( FD_SHRED_DATA_HEADER_SZ+sz );
  fd_repair_shred_insert( repair, shred, fec0_mr, 0, 0L );
}

/* shred_up inserts the first data shred of FEC set fec_idx of slot
   under merkle root mr, whose payload is an UpdateParent naming
   (up_slot, up_mr) if up, else an entry batch. */

static void
shred_up( fd_repair_t *     repair,
          ulong             slot,
          ulong             parent_slot,
          uint              fec_idx,
          int               up,
          ulong             up_slot,
          fd_mr32_t const * up_mr,
          fd_mr32_t const * mr ) {
  uchar buf[ FD_SHRED_MIN_SZ ] __attribute__((aligned(8UL))); memset( buf, 0, sizeof(buf) );
  uchar * ser = buf+FD_SHRED_DATA_HEADER_SZ;
  ulong   off = 0UL;
  if( up ) {
    /* fd_block_marker_ser does not produce an UpdateParent, so lay out
       the preamble and the V1 payload by hand. */
    FD_STORE( ulong,  ser+off, 0UL );                             off += sizeof(ulong);
    FD_STORE( ushort, ser+off, (ushort)1 );                       off += sizeof(ushort);
    ser[ off ] = (uchar)FD_BLOCK_MARKER_KIND_UPDATE_PARENT;       off += sizeof(uchar);
    FD_STORE( ushort, ser+off, (ushort)FD_UPDATE_PARENT_SER_SZ ); off += sizeof(ushort);
    ser[ off ] = (uchar)1;                                        off += sizeof(uchar);
    FD_STORE( ulong,  ser+off, up_slot );                         off += sizeof(ulong);
    memcpy( ser+off, up_mr->uc, sizeof(fd_mr32_t) );              off += sizeof(fd_mr32_t);
  } else {
    FD_STORE( ulong, ser, 1UL );                                  off += sizeof(ulong); /* entry_cnt!=0, an entry batch */
  }

  fd_shred_t * shred = (fd_shred_t *)buf;
  shred->variant          = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  shred->slot             = slot;
  shred->idx              = fec_idx*FD_FEC_SHRED_CNT;
  shred->fec_set_idx      = fec_idx*FD_FEC_SHRED_CNT;
  shred->data.parent_off  = (ushort)( slot-parent_slot );
  shred->data.size        = (ushort)( FD_SHRED_DATA_HEADER_SZ+off );
  fd_repair_shred_insert( repair, shred, mr, 0, 0L );
}

static int
is_eager( fd_repair_t const *     repair,
          fd_repair_blk_t const * blk ) {
  return repair->slot_meta[ blk->slot % repair->slot_max ].eager==fd_repair_blk_pool_idx( repair->blk_pool, blk );
}

static fd_repair_t *
setup_in( uchar * buf ) {
  FD_TEST( fd_repair_footprint( SLOT_MAX, FEC_MAX, BLK_FECS )<=sizeof(mem) );
  fd_repair_t * repair = fd_repair_join( fd_repair_new( buf, SLOT_MAX, FEC_MAX, BLK_FECS, 42UL ) );
  fd_mr32_t     root   = hash( 0xEE );
  fd_repair_init( repair, 0UL, &root, NULL, NULL );
  return repair;
}

static fd_repair_t *
setup( void ) {
  return setup_in( mem );
}

/* rooted walks blk's parents and returns 1 if it reaches the root blk. */

static int
rooted( fd_repair_t const *     repair,
        fd_repair_blk_t const * blk ) {
  fd_repair_blk_t const * pool = repair->blk_pool;
  for( fd_repair_blk_t const * b = blk; b; b = fd_repair_blk_pool_ele_const( pool, b->parent ) ) {
    if( b->slot==repair->root && repair->slot_meta[ b->slot%repair->slot_max ].final==fd_repair_blk_pool_idx( pool, b ) ) return 1;
  }
  return 0;
}

/* orphan_cnt checks orphan_map's invariant over every held blk, a blk
   is in it iff unlinked and naming a parent, root excluded, and returns
   the number of orphans. */

static ulong
orphan_cnt( fd_repair_t const * repair ) {
  fd_repair_blk_t const * pool = repair->blk_pool;
  ulong                   cnt  = 0UL;
  FD_TEST( !fd_repair_orphan_map_verify( repair->orphan_map, fd_repair_blk_pool_max( pool ), pool ) );
  for( ulong s=repair->root; s<repair->root+repair->slot_max; s++ ) {
    for( fd_repair_blk_t const * blk = fd_repair_blk_map_ele_query_const( repair->blk_map, &s, NULL, pool );
                                 blk;
                                 blk = fd_repair_blk_map_ele_next_const( blk, NULL, pool ) ) {
      int waiting = blk!=repair->root_blk && blk->parent==fd_repair_blk_pool_idx_null( pool ) && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) );
      fd_repair_blk_t const * o = fd_repair_orphan_map_ele_query_const( repair->orphan_map, &blk->parent_blk_mr, NULL, pool );
      while( o && o!=blk ) o = fd_repair_orphan_map_ele_next_const( o, NULL, pool );
      FD_TEST( waiting==!!o );
      cnt += (ulong)waiting;
    }
  }
  return cnt;
}

/* FEC sets complete out of order and a chain completes bottom up.
   Nothing is delivered until the top blk is complete, then the chain is
   delivered parent first. */

static void
test_chain( void )  {
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a      = notar( repair, 1UL, 0x10 );
  fd_repair_blk_t * b      = notar( repair, 2UL, 0x20 );
  fd_repair_blk_t * c      = notar( repair, 3UL, 0x30 );
  parented( repair, 3UL, 0x30, 2UL, 0x20, 1U );
  parented( repair, 2UL, 0x20, 1UL, 0x10, 2U );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 2U );
  fecs( repair, 1UL, 0x10, 2U );
  fecs( repair, 2UL, 0x20, 2U );
  fecs( repair, 3UL, 0x30, 1U );

  fd_mr32_t mr;
  mr = hash( 0x31 ); complete( repair, 3UL, 2UL, 0U, 1, &mr );
  mr = hash( 0x22 ); complete( repair, 2UL, 1UL, 1U, 1, &mr );
  mr = hash( 0x21 ); complete( repair, 2UL, 1UL, 0U, 0, &mr );
  mr = hash( 0x12 ); complete( repair, 1UL, 0UL, 1U, 1, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 0, &mr );
  expect( repair, a, 0U ); expect( repair, a, 1U );
  expect( repair, b, 0U ); expect( repair, b, 1U );
  expect( repair, c, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A blk whose FEC sets are all in before its parent is known is
   delivered as soon as it is linked under a complete parent. */

static void
test_link_late( void ) {
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a      = notar( repair, 1UL, 0x10 );
  fecs( repair, 1UL, 0x10, 1U );
  fd_mr32_t mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 1, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  parented( repair, 1UL, 0x10, 0UL, 0xEE, 1U );
  expect( repair, a, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Finalizing one version of a slot frees its competitor, and the
   competitor's child is unlinked so it is never delivered. */

static void
test_finalize_unlinks( void ) {
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a      = notar( repair, 1UL, 0x10 );
  fd_repair_blk_t * b      = notar( repair, 1UL, 0x40 );
  fd_repair_blk_t * c      = notar( repair, 2UL, 0x50 );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 1U );
  parented( repair, 1UL, 0x40, 0UL, 0xEE, 1U );
  parented( repair, 2UL, 0x50, 1UL, 0x40, 1U );
  FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, b ) );

  fd_mr32_t id = hash( 0x10 );
  FD_TEST( fd_repair_blk_finalized( repair, 1UL, &id, 0L )==a );
  FD_TEST( c->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );

  fecs( repair, 2UL, 0x50, 1U );
  fd_mr32_t mr = hash( 0x51 ); complete( repair, 2UL, 1UL, 0U, 1, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* the block id slot 1 has once FEC sets m10 and m11 complete, computed
   by a scratch repair */

static fd_mr32_t
slot1_dmr( fd_mr32_t const * m10,
           fd_mr32_t const * m11 ) {
  fd_mr32_t     root = hash( 0xEE );
  fd_repair_t * pre  = setup_in( scratch );
  shred0  ( pre, 1UL, 0UL, &root, m10 );
  complete( pre, 1UL, 0UL, 0U, 0, m10 );
  complete( pre, 1UL, 0UL, 1U, 1, m11 );
  ulong     one = 1UL;
  fd_mr32_t d1  = fd_repair_blk_map_ele_query( pre->blk_map, &one, NULL, pre->blk_pool )->dmr;
  FD_TEST( memcmp( &d1, &hash_null, sizeof(fd_mr32_t) ) );
  return d1;
}

/* Pipelined turbine: slot 2's header names slot 1's block before any of
   slot 1 arrives, so slot 2 links under slot 1's turbine version,
   created empty.  Slot 1's FEC sets arrive out of order.  When slot 1
   completes, its dmr matches what slot 2 named, slot 2 links under it
   and slot 1 then slot 2 are delivered.  Slot 3 then links straight to
   slot 2, whose dmr is known. */

static void
test_eager_chain( void ) {
  fd_mr32_t root = hash( 0xEE );
  fd_mr32_t m10  = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 ), m30 = hash( 0x31 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );

  fd_repair_t * repair = setup();
  shred0  ( repair, 2UL, 1UL, &d1, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  ulong             one = 1UL, two = 2UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( is_eager( repair, e1 ) && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) ); /* no notar blk from a turbine header */
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, e2 ) ); /* e1 has no dmr to name yet */
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( !memcmp( &e1->dmr, &d1, sizeof(fd_mr32_t) ) && e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  expect( repair, e1, 0U ); expect( repair, e1, 1U );
  expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  shred0  ( repair, 3UL, 2UL, &e2->dmr, &m30 );
  complete( repair, 3UL, 2UL, 0U, 1, &m30 );
  ulong             three = 3UL;
  fd_repair_blk_t * e3    = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  FD_TEST( e3->parent==fd_repair_blk_pool_idx( repair->blk_pool, e2 ) );
  expect( repair, e3, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A child that names a block id its parent slot's turbine version does
   not produce is unlinked when that version completes, and is never
   delivered.  No notar blk is created for the id it named. */

static void
test_eager_wrong_parent( void ) {
  fd_mr32_t root = hash( 0xEE ), other = hash( 0x99 );
  fd_mr32_t m10  = hash( 0x11 ), m20   = hash( 0x21 );

  fd_repair_t * repair = setup();
  shred0  ( repair, 2UL, 1UL, &other, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  shred0  ( repair, 1UL, 0UL, &root,  &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );

  ulong             one = 1UL, two = 2UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( is_eager( repair, e1 ) && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && e1->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  expect( repair, e1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
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

  fd_repair_t *     repair = setup();
  fd_repair_blk_t * n1     = fd_repair_blk_notarized( repair, 1UL, &d1 );
  fd_repair_blk_t * c      = notar( repair, 2UL, 0x50 );
  fd_mr32_t         c_id   = hash( 0x50 );
  fd_repair_blk_parented( repair, 2UL, &c_id, 1UL, &d1, 1U, 0L );
  FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) );
  fecs( repair, 2UL, 0x50, 1U );
  fd_mr32_t m51 = hash( 0x51 ); complete( repair, 2UL, 1UL, 0U, 1, &m51 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  ulong             one = 1UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( is_eager( repair, e1 ) && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) ); /* the notar blk was merged */
  FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  expect( repair, e1, 0U ); expect( repair, e1, 1U );
  expect( repair, c,  0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* The twin merge, carrying telemetry: the eager blk's shred counts
   come from its own FEC set completions, the notar blk's request
   telemetry is folded into it, the earliest first timestamps win. */

static void
test_telemetry( void ) {
  fd_mr32_t root = hash( 0xEE );
  fd_mr32_t m10  = hash( 0x11 ), m11 = hash( 0x12 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );

  fd_repair_t *     repair = setup();
  fd_repair_blk_t * n1     = fd_repair_blk_notarized( repair, 1UL, &d1 );
  FD_TEST( n1->telemetry.last_cmpl_fec_idx==UINT_MAX && !n1->telemetry.last_shred_ts );
  n1->telemetry.req_parent_cnt    = 1U;
  n1->telemetry.parent_res_cnt    = 1U;
  n1->telemetry.first_req_ts      = 5L;
  n1->telemetry.first_meta_res_ts = 7L;
  n1->telemetry.last_shred_res_ts = 9L;

  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot            = 1UL;
  shred->data.parent_off = 1;
  shred0( repair, 1UL, 0UL, &root, &m10 );
  ulong             one = 1UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( e1!=n1 && is_eager( repair, e1 ) );
  e1->telemetry.req_window_cnt = 3U;
  e1->telemetry.first_req_ts   = 6L;

  shred->idx = 2U*FD_FEC_SHRED_CNT-1U; shred->data.flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  fd_repair_fec_t const * f11 = fd_repair_fec_complete( repair, shred, &m11, 0, 10U, 2U, 4U, 0x0fffffffU, 0x3U, 0x0000000cU, 20L );
  FD_TEST( f11 && f11->cmpl_ts==20L && f11->data_rcvd==0x0fffffffU && f11->parity_rcvd==0x3U && f11->repair_rcvd==0x0000000cU );
  FD_TEST( e1->telemetry.last_cmpl_fec_idx==FD_FEC_SHRED_CNT && !e1->telemetry.last_shred_ts ); /* FEC set 0 is missing */
  FD_TEST( fd_repair_fec_complete( repair, shred, &m11, 0, 99U, 99U, 99U, 99U, 99U, 99U, 25L )->cmpl_ts==20L && f11->data_rcvd==0x0fffffffU ); /* again, not counted */

  shred->idx = FD_FEC_SHRED_CNT-1U; shred->data.flags = 0;
  FD_TEST( fd_repair_fec_complete( repair, shred, &m10, 0, 30U, 1U, 0U, 0U, 0U, 0U, 40L )->cmpl_ts==40L );
  FD_TEST( is_eager( repair, e1 ) && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) ); /* the notar blk was merged */
  FD_TEST( e1->telemetry.turbine_shred_cnt==40U && e1->telemetry.repair_shred_cnt==3U && e1->telemetry.recovered_shred_cnt==4U );
  FD_TEST( !e1->telemetry.cancelled_reason && !e1->telemetry.cancelled_ts );
  FD_TEST( e1->telemetry.last_cmpl_fec_idx==0U && e1->telemetry.last_shred_ts==40L );
  FD_TEST( e1->telemetry.req_window_cnt==3U && e1->telemetry.req_parent_cnt==1U && e1->telemetry.parent_res_cnt==1U );
  FD_TEST( e1->telemetry.first_req_ts==5L && e1->telemetry.first_meta_res_ts==7L && e1->telemetry.last_shred_res_ts==9L );
  orphan_cnt( repair );
}

/* An equivocation cancels the eager blk at the time it is seen, later
   cancellations keep that time and update the reason.  Finalizing
   another version cancels a notar blk, as reported when it is freed. */

static long  reported_cancelled_ts;
static uchar reported_cancelled_reason;

static void
report_cancelled( void *                  ctx,
                  fd_repair_blk_t const * blk ) {
  (void)ctx;
  if( !blk->telemetry.cancelled_reason ) return;
  reported_cancelled_ts     = blk->telemetry.cancelled_ts;
  reported_cancelled_reason = blk->telemetry.cancelled_reason;
}

static void
test_telemetry_cancelled( void ) {
  fd_mr32_t root = hash( 0xEE ), y = hash( 0x77 ), m10 = hash( 0x11 ), m19 = hash( 0x19 );
  ulong     one  = 1UL;

  fd_repair_t * repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_blk_t * e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( !e1->telemetry.cancelled_reason && !e1->telemetry.cancelled_ts );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 50L );
  FD_TEST( e1->telemetry.cancelled_reason==FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH && e1->telemetry.cancelled_ts==50L );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_INVALID_BLOCK_HEADER, 60L );
  FD_TEST( e1->telemetry.cancelled_reason==FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_INVALID_BLOCK_HEADER && e1->telemetry.cancelled_ts==50L );

  repair = fd_repair_join( fd_repair_new( mem, SLOT_MAX, FEC_MAX, BLK_FECS, 42UL ) );
  fd_repair_init( repair, 0UL, &root, report_cancelled, NULL );
  reported_cancelled_ts = 0L; reported_cancelled_reason = 0;
  notar( repair, 1UL, 0x40 );
  FD_TEST( fd_repair_blk_finalized( repair, 1UL, &y, 70L ) );
  FD_TEST( reported_cancelled_reason==FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_NOTARIZED_VERSION && reported_cancelled_ts==70L );
  (void)m19;
  orphan_cnt( repair );
}

/* A FEC set's final shred source follows each received data shred
   until the set completes, then freezes.  A reconstructed shred leaves
   it alone, our own leader set completes as LEADER. */

static void
test_telemetry_final_src( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );
  fd_mr20_t k11; memcpy( k11.uc, m11.uc, sizeof(fd_mr20_t) );

  fd_repair_t * repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_fec_t const * f10 = fd_repair_fec_map_ele_query_const( repair->fec_map, &k10, NULL, repair->fec_pool );
  FD_TEST( f10 && !f10->final_src ); /* shred0 gives no source */

  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  shred->data.size       = (ushort)FD_SHRED_DATA_HEADER_SZ; /* header only, no payload */
  shred->slot            = 1UL;
  shred->data.parent_off = 1;
  shred->idx = 1U; fd_repair_shred_insert( repair, shred, &m10, FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_TURBINE, 1L );
  FD_TEST( f10->final_src==FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_TURBINE );
  shred->idx = 2U; fd_repair_shred_insert( repair, shred, &m10, FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_REPAIR, 2L );
  shred->idx = 3U; fd_repair_shred_insert( repair, shred, &m10, 0, 3L ); /* reconstructed */
  FD_TEST( f10->final_src==FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_REPAIR );

  shred->idx = FD_FEC_SHRED_CNT-1U;
  FD_TEST( fd_repair_fec_complete( repair, shred, &m10, 0, 0U, 0U, 0U, 0U, 0U, 0U, 4L )==f10 && f10->final_src==FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_REPAIR );
  shred->idx = 4U; fd_repair_shred_insert( repair, shred, &m10, FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_TURBINE, 5L );
  FD_TEST( f10->final_src==FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_REPAIR ); /* frozen */

  shred->idx = FD_FEC_SHRED_CNT; fd_repair_shred_insert( repair, shred, &m11, FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_TURBINE, 6L );
  fd_repair_fec_t const * f11 = fd_repair_fec_map_ele_query_const( repair->fec_map, &k11, NULL, repair->fec_pool );
  FD_TEST( f11 && f11->final_src==FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_TURBINE ); /* a new set takes its first shred's source */

  shred->slot = 2UL; shred->idx = FD_FEC_SHRED_CNT-1U; shred->data.flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  FD_TEST( fd_repair_fec_complete( repair, shred, &m20, 1, 0U, 0U, 0U, 0U, 0U, 0U, 7L )->final_src==FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_LEADER );
  orphan_cnt( repair );
}

/* A verified metadata response is counted on the blk it names, a
   duplicate and a bad parent included, a pruned blk's not at all.  The
   first one stamps first_meta_res_ts. */

static void
test_telemetry_meta( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), gone = hash( 0x99 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );

  fd_repair_t *     repair = setup();
  fd_repair_blk_t * n1     = fd_repair_blk_notarized( repair, 1UL, &d1 );
  FD_TEST( !fd_repair_blk_parented( repair, 1UL, &d1, 1UL, &root, 2U, 30L ) && n1->parent_slot==ULONG_MAX ); /* a bad parent, still counted */
  FD_TEST( n1->telemetry.parent_res_cnt==1U && n1->telemetry.first_meta_res_ts==30L );
  fd_repair_blk_parented( repair, 1UL, &d1, 0UL, &root, 2U, 40L );
  fd_repair_blk_parented( repair, 1UL, &d1, 0UL, &root, 2U, 45L );                                           /* duplicate, still counted */
  FD_TEST( n1->parent_slot==0UL && n1->telemetry.parent_res_cnt==3U && n1->telemetry.first_meta_res_ts==30L );

  FD_TEST(  fd_repair_fec_notarized( repair, 1UL, &d1, 0U, &k10, 50L ) );
  FD_TEST( !fd_repair_fec_notarized( repair, 1UL, &d1, 0U, &k10, 55L ) );                                     /* duplicate, still counted */
  FD_TEST( n1->telemetry.fec_root_res_cnt==2U && n1->telemetry.first_meta_res_ts==30L );

  FD_TEST( !fd_repair_fec_notarized( repair, 1UL, &gone, 0U, &k10, 60L ) );                                   /* names no blk we hold */
  FD_TEST( !fd_repair_blk_parented ( repair, 1UL, &gone, 0UL, &root, 2U, 60L ) );
  FD_TEST( n1->telemetry.fec_root_res_cnt==2U && n1->telemetry.parent_res_cnt==3U );

  fd_repair_blk_t * n2 = fd_repair_blk_notarized( repair, 2UL, &gone );
  FD_TEST( !fd_repair_fec_notarized( repair, 2UL, &gone, FD_FEC_SHRED_CNT, &k10, 70L ) );                     /* a root for another index, still counted */
  FD_TEST( n2->telemetry.fec_root_res_cnt==1U && n2->telemetry.first_meta_res_ts==70L );
  orphan_cnt( repair );
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

  fd_repair_t * repair = setup();
  shred0  ( repair, 2UL, 1UL, &d1, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  ulong             one = 1UL, two = 2UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( is_eager( repair, e1 ) && e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );

  fd_repair_blk_t * n1     = fd_repair_blk_notarized( repair, 1UL, &d1 );
  ulong             n1_idx = fd_repair_blk_pool_idx( repair->blk_pool, n1 );
  FD_TEST( e2->parent==n1_idx ); /* it names n1 */
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );
  fd_mr20_t k11; memcpy( k11.uc, m11.uc, sizeof(fd_mr20_t) );
  fd_repair_blk_parented ( repair, 1UL, &d1, 0UL, &root, 2U, 0L );
  fd_repair_fec_notarized( repair, 1UL, &d1, 0U,               &k10, 0L );
  fd_repair_fec_notarized( repair, 1UL, &d1, FD_FEC_SHRED_CNT, &k11, 0L );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( !memcmp( &e1->dmr, &d1, sizeof(fd_mr32_t) ) );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==e1 && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) ); /* the notar blk was merged */
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  expect( repair, e1, 0U ); /* the notar blk was held behind the eager blk */
  expect( repair, e1, 1U );
  expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Slot 2's turbine version names slot 1's block before slot 1's
   turbine version completes, so it waits unlinked.  Slot 1 equivocates
   and never completes, slot 1's repaired version adopts it, it names
   it, so slot 2's turbine version delivers FEC set 0 under it while its
   repaired version, holding the same FEC sets, is held.  When slot 2's
   turbine version then completes as the same block, it survives the
   merge as the slot's turbine blk and delivers the rest. */

static void
test_twin_merge_ahead( void ) {
  fd_mr32_t root = hash( 0xEE );
  fd_mr32_t m10  = hash( 0x11 ), m20 = hash( 0x21 ), m21 = hash( 0x22 );
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );
  fd_mr20_t k20; memcpy( k20.uc, m20.uc, sizeof(fd_mr20_t) );
  fd_mr20_t k21; memcpy( k21.uc, m21.uc, sizeof(fd_mr20_t) );

  fd_repair_t * pre = setup_in( scratch );
  shred0  ( pre, 1UL, 0UL, &root, &m10 );
  complete( pre, 1UL, 0UL, 0U, 1, &m10 );
  ulong     one = 1UL, two = 2UL;
  fd_mr32_t d1  = fd_repair_blk_map_ele_query( pre->blk_map, &one, NULL, pre->blk_pool )->dmr;
  shred0  ( pre, 2UL, 1UL, &d1, &m20 );
  complete( pre, 2UL, 1UL, 0U, 0, &m20 );
  complete( pre, 2UL, 1UL, 1U, 1, &m21 );
  fd_mr32_t d2  = fd_repair_blk_map_ele_query( pre->blk_map, &two, NULL, pre->blk_pool )->dmr;

  fd_repair_t * repair = setup();
  shred0( repair, 2UL, 1UL, &d1, &m20 );
  fd_repair_blk_t * e1 = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  fd_repair_blk_t * e2 = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ two % repair->slot_max ].eager );
  FD_TEST( e1 && e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, e2 ) );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, e2 ) );

  fd_repair_blk_t * n2 = fd_repair_blk_notarized( repair, 2UL, &d2 );
  fd_repair_blk_t * n1 = fd_repair_blk_parented( repair, 2UL, &d2, 1UL, &d1, 2U, 0L );
  FD_TEST( n1 );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) ); /* adopted, it names n1 */
  fd_repair_blk_parented ( repair, 1UL, &d1, 0UL, &root, 1U, 0L );
  fd_repair_fec_notarized( repair, 1UL, &d1, 0U, &k10, 0L );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  expect( repair, n1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_fec_notarized( repair, 2UL, &d2, 0U,               &k20, 0L );
  fd_repair_fec_notarized( repair, 2UL, &d2, FD_FEC_SHRED_CNT, &k21, 0L );
  complete( repair, 2UL, 1UL, 0U, 0, &m20 );
  expect( repair, e2, 0U ); /* the notar blk is held behind the eager blk */
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) && !n2->cons_fec_cnt );

  complete( repair, 2UL, 1UL, 1U, 1, &m21 );
  FD_TEST( !memcmp( &e2->dmr, &d2, sizeof(fd_mr32_t) ) );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool )==e2 && !fd_repair_blk_map_ele_next_const( e2, NULL, repair->blk_pool ) ); /* the notar blk was merged */
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) );
  FD_TEST( is_eager( repair, e2 ) && e2->cons_fec_cnt==2U );
  expect( repair, e2, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Slot 1's turbine version is already complete when slot 2 names a
   different block id for it.  Slot 2 must not link under it. */

static void
test_eager_finished_wrong_parent( void ) {
  fd_mr32_t root = hash( 0xEE ), y = hash( 0x77 );
  fd_mr32_t m10  = hash( 0x11 ), m20 = hash( 0x21 );

  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  ulong             one = 1UL, two = 2UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( memcmp(  &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  expect( repair, e1, 0U );

  shred0  ( repair, 2UL, 1UL, &y, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  fd_repair_blk_t * e2 = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && e1->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A child naming a block id the root slot does not have gets no
   parent, and no turbine version is created in the root slot. */

static void
test_root_wrong_parent( void ) {
  fd_mr32_t     y      = hash( 0x77 ), m10 = hash( 0x11 );
  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &y, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  ulong             zero = 0UL, one = 1UL;
  fd_repair_blk_t * r    = fd_repair_blk_map_ele_query( repair->blk_map, &zero, NULL, repair->blk_pool );
  fd_repair_blk_t * e1   = fd_repair_blk_map_ele_query( repair->blk_map, &one,  NULL, repair->blk_pool );
  FD_TEST( !fd_repair_blk_map_ele_next_const( r, NULL, repair->blk_pool ) && r->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( e1->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Slot 2 names a slot 1 block id that slot 1's turbine version does
   not complete as, so it is unlinked.  It still computes its dmr when
   it completes, and dedup then adopts the parent the notar blk of the
   same dmr was given. */

static void
test_orphan_adopted( void ) {
  fd_mr32_t root = hash( 0xEE ), y = hash( 0x77 );
  fd_mr32_t m10  = hash( 0x11 ), m20 = hash( 0x21 );

  fd_repair_t * pre = setup_in( scratch );
  shred0  ( pre, 2UL, 1UL, &y, &m20 );
  complete( pre, 2UL, 1UL, 0U, 1, &m20 );
  ulong     one = 1UL, two = 2UL;
  fd_mr32_t d2  = fd_repair_blk_pool_ele( pre->blk_pool, pre->slot_meta[ two % pre->slot_max ].eager )->dmr;
  FD_TEST( memcmp( &d2, &hash_null, sizeof(fd_mr32_t) ) );

  fd_repair_t * repair = setup();
  shred0  ( repair, 2UL, 1UL, &y, &m20 );
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  fd_repair_blk_t * e1 = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  fd_repair_blk_t * e2 = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ two % repair->slot_max ].eager );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  expect( repair, e1, 0U );

  fd_repair_blk_notarized( repair, 2UL, &d2 );
  fd_repair_blk_t * n1 = fd_repair_blk_parented( repair, 2UL, &d2, 1UL, &y, 1U, 0L );
  FD_TEST( n1 );

  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  FD_TEST( !memcmp( &e2->dmr, &d2, sizeof(fd_mr32_t) ) );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool )==e2 && !fd_repair_blk_map_ele_next_const( e2, NULL, repair->blk_pool ) );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Replay lost a bank: the next FEC pushed goes with its ancestry from
   the root, whatever replay was missing, and a sibling fork is not
   delivered again. */

static void
test_fec_reconsume( void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 );
  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  ulong             one = 1UL, two = 2UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  shred0  ( repair, 2UL, 1UL, &e1->dmr, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  expect( repair, e1, 0U ); expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t m30 = hash( 0x31 ); /* a sibling fork off the root, not on e2's chain */
  shred0  ( repair, 3UL, 0UL, &root, &m30 );
  complete( repair, 3UL, 0UL, 0U, 1, &m30 );
  ulong             three = 3UL;
  fd_repair_blk_t * e3    = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  expect( repair, e3, 0U );

  repair->reconsume = 1;
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) ); /* nothing until the next push */

  fd_mr32_t m40 = hash(  0x41 );
  shred0  ( repair, 4UL, 2UL, &e2->dmr, &m40 );
  complete( repair, 4UL, 2UL, 0U, 1, &m40 );
  ulong             four = 4UL;
  fd_repair_blk_t * e4   = fd_repair_blk_map_ele_query( repair->blk_map, &four, NULL, repair->blk_pool );
  expect( repair, e1, 0U  ); expect( repair, e2, 0U ); expect( repair, e4, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t m50 = hash( 0x51 ); /* the next push is a plain one */
  shred0  ( repair, 5UL, 4UL, &e4->dmr, &m50 );
  complete( repair, 5UL, 4UL, 0U, 1, &m50 );
  ulong five = 5UL;
  expect( repair, fd_repair_blk_map_ele_query( repair->blk_map, &five, NULL, repair->blk_pool ), 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Slot 1 has delivered FEC set 0 and replay loses a bank.  The next
   push is slot 1's FEC set 1, which goes with the blk's own earlier FEC
   set 0 first. */

static void
test_fec_reconsume_incomplete( void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 );
  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  ulong             one = 1UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  expect( repair, e1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair->reconsume = 1;
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  expect( repair, e1, 0U ); expect( repair, e1, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Replay reports slot 1 dead: it is held with its FEC sets and slot 2
   under it, the slot is invalidated so turbine does not rebuild it, and
   the eager blk is never repaired again.  A reconsume still redelivers
   it whole ahead of slot 2. */

static void
test_blk_dead(  void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 ), m30 = hash( 0x31 );
  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  ulong             one = 1UL, two = 2UL, three = 3UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  fd_mr32_t         d1  = e1->dmr;
  shred0  ( repair, 2UL, 1UL, &d1, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  expect( repair, e1, 0U ); expect( repair, e2, 0U );

  fd_repair_blk_dead( repair, 1UL, &d1, 0U );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==e1 && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) );
  FD_TEST( repair->slot_meta[ one % repair->slot_max ].invalidated && !e1->eager && !e1->in_blk_treap );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );
  FD_TEST( fd_repair_fec_map_ele_query( repair->fec_map, &k10, NULL, repair->fec_pool ) );
  fd_repair_blk_dead( repair, 1UL, &d1, 0U ); /* SLOT_DEAD again changes nothing */
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  shred0( repair, 1UL, 0UL, &root, &m10 );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==e1 && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) );
  FD_TEST( !e1->in_blk_treap );

  repair->reconsume = 1;
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  fd_mr32_t d2 = e2->dmr;
  shred0  ( repair, 3UL, 2UL, &d2, &m30 );
  complete( repair, 3UL, 2UL, 0U, 1, &m30 );
  fd_repair_blk_t * e3 = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  expect( repair, e1, 0U ); expect( repair, e2, 0U ); expect( repair, e3, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );

  fd_repair_root_advanced( repair, 1UL, &d1 ); /* held blks advance like any other */
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==e1 && repair->root_blk==e1 );
  orphan_cnt( repair );
}

/* The mainnet epoch 1065 crash.  Notar blk B is fully delivered, its
   child C partly.  Replay rejects B and votor keeps naming it, once per
   vote.  Pruning B made a fresh B that had consumed nothing, so the next
   reconsume pushed C ahead of any of B: replay held a half built B from
   the copy it was reading, attached C to it and ran out of room.  B is
   held instead, naming it finds it, and a reconsume sends all of B
   before C. */

static void
test_blk_dead_renamed( void ) {
  fd_mr32_t     B      = hash( 0xB0 ), mB = hash( 0xB1 ), m20 = hash( 0x21 ), m21 = hash( 0x22 );
  fd_repair_t * repair = setup();
  ulong         one    = 1UL, two = 2UL;

  fd_repair_blk_t * b = notar( repair, 1UL, 0xB0 );
  parented( repair, 1UL, 0xB0, 0UL, 0xEE, 1U );
  fecs    ( repair, 1UL, 0xB0, 1U );
  complete( repair, 1UL, 0UL, 0U, 1, &mB );
  expect( repair, b, 0U );

  shred0  ( repair, 2UL, 1UL, &B, &m20 );
  complete( repair, 2UL, 1UL, 0U, 0, &m20 );
  fd_repair_blk_t * c = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  expect( repair, c, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_blk_dead( repair, 1UL, &B, 0U );
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !fd_repair_blk_notarized( repair, 1UL, &B ) ); /* found, not re-created */
  ulong named = 0UL;
  for( fd_repair_blk_t const * x = fd_repair_blk_map_ele_query_const( repair->blk_map, &one, NULL, repair->blk_pool ); x; x = fd_repair_blk_map_ele_next_const( x, NULL, repair->blk_pool ) ) {
    named += (ulong)!memcmp( &x->dmr, &B, sizeof(fd_mr32_t) );
  }
  FD_TEST( named==1UL && b->cons_fec_cnt==1U && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, b ) );

  repair->reconsume = 1; /* MISSING_FEC */
  complete( repair, 2UL, 1UL, 1U, 1, &m21 );
  expect( repair, b, 0U ); /* all of B first */
  expect( repair, c, 0U ); expect( repair, c, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A leader turbines B with a bad bank hash and keeps building on it, a
   minority fork that is never finalized.  Votor still names B through
   SafeToNotar repair events, once per vote.

   Replay rejects B after receiving all of it: the slot is invalidated,
   B is held, and naming it finds it.  Every reconsume redelivers the
   fork from B whole, as the leader's later blks arrive.

   Replay rejects B partway through, so SLOT_DEAD names the incomplete
   turbine copy: it is held with no dmr and turbine stops.  C names B's
   real id and waits unlinked.  A SafeToNotar repair event for that id
   creates the notar copy, under which C waits until all of it has gone
   out.  Replay rejects that copy too, and naming it finds it. */

static void
test_blk_dead_minority_fork( void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 ), m21 = hash( 0x22 ), m30 = hash( 0x31 ), m40 = hash( 0x41 );
  ulong         one    = 1UL, two = 2UL, three = 3UL, four = 4UL;
  fd_repair_t * repair = setup();

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  fd_repair_blk_t * b  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  fd_mr32_t         dB = b->dmr;
  expect( repair, b, 0U );
  shred0  ( repair, 2UL, 1UL, &dB, &m20 );
  complete( repair, 2UL, 1UL, 0U, 0, &m20 );
  fd_repair_blk_t * c  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  expect( repair, c, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_blk_dead( repair, 1UL, &dB, 0U );
  FD_TEST( repair->slot_meta[ one % repair->slot_max ].invalidated && !b->eager && !b->in_blk_treap );
  FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, b ) && fd_repair_deque_empty( repair->reasm_deque ) );

  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !fd_repair_blk_notarized( repair, 1UL, &dB ) ); /* SafeToNotar, found */
  shred0( repair, 1UL, 0UL, &root, &m10 );                                                 /* turbine again */
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==b && !fd_repair_blk_map_ele_next_const( b, NULL, repair->blk_pool ) );
  FD_TEST( !b->in_blk_treap && fd_repair_deque_empty( repair->reasm_deque ) );

  repair->reconsume = 1; /* replay dropped C under the dead B */
  complete( repair, 2UL, 1UL, 1U, 1, &m21 );
  expect( repair, b, 0U ); expect( repair, c, 0U ); expect( repair, c, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t dC = c->dmr; /* the leader builds D on C */
  shred0  ( repair, 3UL, 2UL, &dC, &m30 );
  complete( repair, 3UL, 2UL, 0U, 1, &m30 );
  fd_repair_blk_t * d  = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  expect( repair, d, 0U );

  repair->reconsume = 1; /* and E on D */
  fd_mr32_t dD = d->dmr;
  shred0  ( repair, 4UL, 3UL, &dD, &m40 );
  complete( repair, 4UL, 3UL, 0U, 1, &m40 );
  fd_repair_blk_t * e  = fd_repair_blk_map_ele_query( repair->blk_map, &four, NULL, repair->blk_pool );
  expect( repair, b, 0U ); expect( repair, c, 0U ); expect( repair, c, 1U ); expect( repair, d, 0U ); expect( repair, e, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );

  /* Rejected partway through. */

  fd_mr32_t X = hash( 0xB0 ), mX = hash( 0xB1 ), m11 = hash( 0x12 );
  repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  fd_repair_blk_t * t = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  expect( repair, t, 0U );

  fd_repair_blk_dead( repair, 1UL, &hash_null, 0U ); /* the incomplete turbine copy */
  FD_TEST( repair->slot_meta[ one % repair->slot_max ].invalidated && !t->eager && !t->in_blk_treap );
  FD_TEST( !fd_repair_fec_complete( repair, &(fd_shred_t){ .slot = 1UL, .idx = 2U*FD_FEC_SHRED_CNT-1U, .data = { .parent_off = 1, .flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE } }, &m11, 0, 0U, 0U, 0U, 0U, 0U, 0U, 0L ) );

  shred0  ( repair, 2UL, 1UL, &X, &m20 ); /* the leader builds C on B's real id */
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  c = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( c->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !c->cons_fec_cnt && orphan_cnt( repair )==1UL );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair->reconsume = 1;
  fd_repair_blk_t * n = fd_repair_blk_notarized( repair, 1UL, &X ); /* SafeToNotar for B's real id */
  FD_TEST( n && n!=t && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, n ) && !c->cons_fec_cnt && !orphan_cnt( repair ) );
  FD_TEST( !fd_repair_blk_notarized( repair, 1UL, &X ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  parented( repair, 1UL, 0xB0, 0UL, 0xEE, 1U );
  fecs    ( repair, 1UL, 0xB0, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  complete( repair, 1UL, 0UL, 0U, 1, &mX );
  expect( repair, n, 0U ); expect( repair, c, 0U ); /* all of B before C */
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_blk_dead( repair, 1UL, &X, 0U );
  FD_TEST( !fd_repair_blk_notarized( repair, 1UL, &X ) );
  ulong named = 0UL;
  for( fd_repair_blk_t const * x = fd_repair_blk_map_ele_query_const( repair->blk_map, &one, NULL, repair->blk_pool ); x; x = fd_repair_blk_map_ele_next_const( x, NULL, repair->blk_pool ) ) {
    named += (ulong)!memcmp( &x->dmr, &X, sizeof(fd_mr32_t) );
  }
  FD_TEST( named==1UL && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, n ) && !n->in_blk_treap );
  orphan_cnt( repair );
}

/* Slot 2 is partly delivered under slot 1's turbine version when a
   different slot 1 blk is finalized.  Slot 2 is orphaned and its later
   FEC sets are not delivered. */

static void
test_orphan_stops( void ) {
  fd_mr32_t     root   = hash( 0xEE ), y = hash( 0x77 );
  fd_mr32_t     m10    = hash( 0x11 ), m20 = hash( 0x21 ), m21 = hash( 0x22 );
  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  ulong             one = 1UL, two = 2UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  shred0  ( repair, 2UL, 1UL, &e1->dmr, &m20 );
  complete( repair, 2UL, 1UL, 0U, 0, &m20 );
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  expect( repair, e1, 0U ); expect( repair, e2, 0U );

  FD_TEST( fd_repair_blk_finalized( repair, 1UL, &y, 0L ) );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && e2->cons_fec_cnt==1U );
  complete( repair, 2UL, 1UL, 1U, 1, &m21 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A second, different shred 0 for the slot invalidates the turbine
   version instead of overwriting its parent, whatever parent it names;
   so does a different FEC set at an index it already holds. */

static void
test_eqvoc_invalidates( void ) {
  fd_mr32_t root = hash( 0xEE ), y = hash( 0x77 ), m10 = hash( 0x11 ), m19 = hash( 0x19 );
  ulong     one  = 1UL, two = 2UL;

  fd_repair_t * repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  shred0( repair, 1UL, 0UL, &y,    &m19 );
  fd_repair_blk_t * e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( repair->slot_meta[ one % repair->slot_max ].invalidated );
  FD_TEST( !memcmp( &e1->parent_blk_mr, &root, sizeof(fd_mr32_t) ) );

  fd_mr32_t m20 = hash( 0x21 ), m29 = hash( 0x29 );
  complete( repair, 2UL, 1UL, 1U, 0, &m20 );
  complete( repair, 2UL, 1UL, 1U, 0, &m29 );
  FD_TEST( repair->slot_meta[ two % repair->slot_max ].invalidated );
  orphan_cnt( repair );
}

/* A FecSetRoot leaf equal to a live FEC set of another slot, or of
   another index in the same slot, is refused instead of shared, so the
   free paths never release a FEC set another slot still holds. */

static void
test_fec_alias_refused( void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 );
  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  fd_mr20_t k10; memcpy( k10.uc, m10.uc, sizeof(fd_mr20_t) );

  fd_repair_blk_t * t = notar( repair, 2UL, 0x50 );
  parented( repair, 2UL, 0x50, 0UL, 0xEE, 2U );
  fd_mr32_t         t_id = hash( 0x50 );
  FD_TEST( !fd_repair_fec_notarized( repair, 2UL, &t_id, 0U, &k10, 0L ) );               /* another slot */
  FD_TEST( t->fecs[ 0 ]==fd_repair_fec_pool_idx_null( repair->fec_pool ) );

  fd_repair_blk_t * s = notar( repair, 1UL, 0x30 );
  parented( repair, 1UL, 0x30, 0UL, 0xEE, 2U );
  fd_mr32_t         s_id = hash( 0x30 );
  FD_TEST( !fd_repair_fec_notarized( repair, 1UL, &s_id, FD_FEC_SHRED_CNT, &k10, 0L ) ); /* another index */
  FD_TEST( s->fecs[ 1 ]==fd_repair_fec_pool_idx_null( repair->fec_pool ) );
  orphan_cnt( repair );
}

/* role is a blk's role in its slot_meta: the slot's final blk, its
   first notar or stronger blk, or else eager. */

#define ROLE_FINAL (0UL)
#define ROLE_NOTAR (1UL)
#define ROLE_EAGER (2UL)

static ulong
role( fd_repair_t const *     repair,
      fd_repair_blk_t const * blk ) {
  fd_repair_slot_meta_t const * meta = &repair->slot_meta[ blk->slot % repair->slot_max ];
  ulong                         idx  = fd_repair_blk_pool_idx( repair->blk_pool, blk );
  return meta->final==idx ? ROLE_FINAL : meta->notar==idx ? ROLE_NOTAR : ROLE_EAGER;
}

/* blk_treap_pop takes the lowest slot blk of the first non-empty treap,
   final, then notar, then eager, as the tile does. */

static fd_repair_blk_t *
blk_treap_pop( fd_repair_t * repair ) {
  fd_repair_treap_t * treap = fd_repair_treap_ele_cnt( repair->final_treap ) ? repair->final_treap :
                              fd_repair_treap_ele_cnt( repair->notar_treap ) ? repair->notar_treap :
                              fd_repair_treap_ele_cnt( repair->eager_treap ) ? repair->eager_treap :
                                                                               NULL;
  if( FD_UNLIKELY( !treap ) ) return NULL;
  fd_repair_blk_t * blk = fd_repair_treap_fwd_iter_ele( fd_repair_treap_fwd_iter_init( treap, repair->blk_pool ), repair->blk_pool );
  fd_repair_treap_ele_remove( treap, blk, repair->blk_pool );
  blk->in_blk_treap = 0;
  return blk;
}

/* pop takes the next blk off the blk_treaps, as the tile does, and
   checks it is of kind c. */

static fd_repair_blk_t *
pop( fd_repair_t * repair,
     ulong         c ) {
  fd_repair_blk_t * blk = blk_treap_pop( repair );
  FD_TEST( blk && role( repair, blk )==c && !blk->in_blk_treap );
  return blk;
}

/* blk_treap_cnt is the number of blks in every blk_treap. */

static ulong
blk_treap_cnt( fd_repair_t const * repair ) {
  ulong cnt = 0UL;
  FD_TEST( !fd_repair_treap_verify( repair->eager_treap, repair->blk_pool ) );
  FD_TEST( !fd_repair_treap_verify( repair->notar_treap, repair->blk_pool ) );
  FD_TEST( !fd_repair_treap_verify( repair->final_treap, repair->blk_pool ) );
  cnt += fd_repair_treap_ele_cnt( repair->eager_treap ) + fd_repair_treap_ele_cnt( repair->notar_treap ) + fd_repair_treap_ele_cnt( repair->final_treap );
  return cnt;
}

/* Repair blk_treap: a blk is in its kind's blk_treap when it may have
   new missing work, once until the tile pops it; kinds follow certs;
   eviction forgets the evicted shreds. */

static void
test_repair_blk_treap( void ) {
  fd_mr32_t        root   = hash( 0xEE );
  fd_repair_t *    repair = setup();
  FD_TEST( !blk_treap_cnt( repair ) );                                          /* the root blk is never repaired */
  fd_repair_blk_t * n1    = notar( repair, 1UL, 0x10 );
  FD_TEST( role( repair, n1 )==ROLE_NOTAR && n1->in_blk_treap );
  FD_TEST( pop( repair, ROLE_NOTAR )==n1 && !blk_treap_pop( repair ) );

  parented( repair, 1UL, 0x10, 0UL, 0xEE, 2U );                                 /* FEC set count known */
  FD_TEST( n1->in_blk_treap && pop( repair, ROLE_NOTAR )==n1 );
  fecs    ( repair, 1UL, 0x10, 1U );
  fd_mr32_t m11 = hash( 0x11 );
  complete( repair, 1UL, 0UL, 0U, 0, &m11 );                                   /* buffering a FEC set adds no work */
  FD_TEST( !n1->in_blk_treap );

  /* Eager: turbine showing a higher FEC set inserts it and stamps it. */

  while( blk_treap_pop( repair ) );                                    /* slot 1's turbine version */
  fd_mr32_t m30 = hash( 0x31 ), m32 = hash( 0x33 );
  shred0( repair, 3UL, 0UL, &root, &m30 );
  ulong             three = 3UL;
  fd_repair_blk_t * e3    = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  FD_TEST( role( repair, e3 )==ROLE_EAGER && pop( repair, ROLE_EAGER )==e3 );
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot = 3UL; shred->idx = 2U*FD_FEC_SHRED_CNT; shred->data.parent_off = 3;
  shred->variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 ); shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ; /* header only, no payload */
  fd_repair_shred_insert( repair, shred, &m32, 0, 77L );
  FD_TEST( e3->in_blk_treap && e3->rcvd_fec_ts==77L && e3->rcvd_fec_cnt==3U );
  pop( repair, ROLE_EAGER );

  /* Eviction of an incomplete FEC set forgets the shreds it had. */

  fd_mr20_t k32; memcpy( k32.uc, m32.uc, sizeof(fd_mr20_t) );
  fd_repair_fec_evicted( repair, 3UL, 2U*FD_FEC_SHRED_CNT, &k32 );
  FD_TEST( !fd_repair_fec_pool_ele( repair->fec_pool, e3->fecs[ 2 ] )->rcvd );

  /* Finalized blks are ROLE_FINAL. */

  fd_mr32_t         f5  = hash( 0x50 );
  fd_repair_blk_t * fin = fd_repair_blk_finalized( repair, 5UL, &f5, 0L );
  FD_TEST( fin && role( repair, fin )==ROLE_FINAL );
  orphan_cnt( repair );
}

/* A blk in a blk_treap leaves it at once when replay rejects it or it
   is freed by a prune or the root advancing past it, and the next pop
   returns the next blk. */

static void
test_blk_treap_freed( void ) {
  fd_mr32_t         h20   = hash( 0x20 ), h30 = hash( 0x30 );
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a     = notar( repair, 2UL, 0x20 );
  fd_repair_blk_t * b     = notar( repair, 3UL, 0x30 );
  FD_TEST( a->in_blk_treap && b->in_blk_treap && blk_treap_cnt( repair )==2UL );
  fd_repair_blk_dead( repair, 2UL, &h20, 0U );
  FD_TEST( blk_treap_cnt( repair )==1UL );
  FD_TEST( pop( repair, ROLE_NOTAR )==b && !blk_treap_pop( repair ) );

  repair = setup();
  notar( repair, 1UL, 0x10 );
  notar( repair, 2UL, 0x20 );
  fd_repair_blk_t * c = notar( repair, 3UL, 0x30 );
  fd_repair_slot_skipped( repair, 1UL );
  FD_TEST( blk_treap_cnt( repair )==2UL );
  fd_repair_root_advanced( repair, 2UL, &h20 );
  FD_TEST( blk_treap_cnt( repair )==1UL );                                      /* the new root leaves, as the root blk at init */
  FD_TEST( pop( repair, ROLE_NOTAR )==c && !blk_treap_pop( repair ) );
  fd_repair_blk_dead( repair, 3UL, &h30, 0U );
  FD_TEST( !blk_treap_cnt( repair ) );
  orphan_cnt( repair );
}

/* A promotion while in a treap moves the blk to its new role's treap,
   so it pops before lower roles whatever its slot.  A blk promoted
   while not in one stays out. */

static void
test_blk_treap_promote( void ) {
  fd_mr32_t         root   = hash( 0xEE ), h30 = hash( 0x30 ), m40 = hash( 0x41 );
  ulong             four   = 4UL;
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * n      = notar( repair, 1UL, 0x10 );
  fd_repair_blk_t * m      = notar( repair, 3UL, 0x30 );
  shred0  ( repair, 4UL, 0UL, &root, &m40 );
  complete( repair, 4UL, 0UL, 0U, 1, &m40 );
  fd_repair_blk_t * e     = fd_repair_blk_map_ele_query( repair->blk_map, &four, NULL, repair->blk_pool );
  FD_TEST( role( repair, e )==ROLE_EAGER && e->eager && e->in_blk_treap && memcmp( &e->dmr, &hash_null, sizeof(fd_mr32_t) ) );

  FD_TEST( fd_repair_blk_finalized( repair, 3UL, &h30, 0L )==m );
  FD_TEST( role( repair, m )==ROLE_FINAL && m->in_blk_treap );
  fd_mr32_t d4 = e->dmr;
  FD_TEST( !fd_repair_blk_notarized( repair, 4UL, &d4 ) );
  FD_TEST( role( repair, e )==ROLE_NOTAR && !e->eager && e->in_blk_treap );
  FD_TEST( fd_repair_treap_ele_cnt( repair->final_treap )==1UL );
  FD_TEST( fd_repair_treap_ele_cnt( repair->notar_treap )==2UL );
  FD_TEST( !fd_repair_treap_ele_cnt( repair->eager_treap ) );

  FD_TEST( pop( repair, ROLE_FINAL )==m );
  FD_TEST( pop( repair, ROLE_NOTAR )==n );
  FD_TEST( pop( repair, ROLE_NOTAR )==e );
  FD_TEST( !blk_treap_pop( repair ) );

  fd_mr32_t h10 = hash( 0x10 );
  FD_TEST( fd_repair_blk_finalized( repair, 1UL, &h10, 0L )==n );
  FD_TEST( role( repair, n )==ROLE_FINAL && !n->in_blk_treap && !blk_treap_cnt( repair ) );
  orphan_cnt( repair );
}

/* Pops come final, then notar, then eager, then slot order.  Only a
   slot's first notar blk is notar, a second one is eager, repaired by
   blk id. */

static void
test_blk_treap_order( void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 ), m30 = hash( 0x31 ), h40 = hash( 0x40 ), h60 = hash( 0x60 );
  fd_repair_t * repair = setup();
  fd_repair_blk_t * n5  = notar( repair, 5UL, 0x50 );
  fd_repair_blk_t * n2a = notar( repair, 2UL, 0x20 );
  fd_repair_blk_t * n7  = notar( repair, 7UL, 0x70 );
  fd_repair_blk_t * n2b = notar( repair, 2UL, 0x21 );
  shred0( repair, 3UL, 0UL, &root, &m30 );
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_blk_t * f6  = fd_repair_blk_finalized( repair, 6UL, &h60, 0L );
  fd_repair_blk_t * f4  = fd_repair_blk_finalized( repair, 4UL, &h40, 0L );
  FD_TEST( blk_treap_cnt( repair )==8UL );

  FD_TEST( pop( repair, ROLE_FINAL )==f4 );
  FD_TEST( pop( repair, ROLE_FINAL )==f6 );
  FD_TEST( pop( repair, ROLE_NOTAR )==n2a );
  FD_TEST( pop( repair, ROLE_NOTAR )==n5 );
  FD_TEST( pop( repair, ROLE_NOTAR )==n7 );
  FD_TEST( pop( repair, ROLE_EAGER )->slot==1UL );
  FD_TEST( pop( repair, ROLE_EAGER )==n2b && !n2b->eager );
  FD_TEST( pop( repair, ROLE_EAGER )->slot==3UL );
  FD_TEST( !blk_treap_pop( repair ) );
  orphan_cnt( repair );
}

/* was_eager is the predicate the eager bit replaces: blk is its slot's
   eager blk, the turbine version, and the slot is not invalidated or
   ours.  Finalizing another blk keeps it repaired by position. */

static int
was_eager( fd_repair_t const *     repair,
           fd_repair_blk_t const * blk ) {
  fd_repair_slot_meta_t const * meta = &repair->slot_meta[ blk->slot % repair->slot_max ];
  return meta->slot==blk->slot && !meta->invalidated && !meta->leader &&
         meta->eager==fd_repair_blk_pool_idx( repair->blk_pool, blk ) && role( repair, blk )==ROLE_EAGER;
}

/* check_eager checks the eager bit matches the predicate, and that a
   turbine version that must not be repaired is not in a blk_treap. */

static void
check_eager( fd_repair_t const *     repair,
             fd_repair_blk_t const * blk ) {
  FD_TEST( blk->eager==was_eager( repair, blk ) );
  FD_TEST( blk->eager || role( repair, blk )!=ROLE_EAGER || !blk->in_blk_treap );
}

/* The eager bit follows the slot's eager blk across invalidation,
   finalization of it or of another blk, a dedup that names it, and our
   own leader FEC sets. */

static void
test_eager_bit( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m12 = hash( 0x13 ), h77 = hash( 0x77 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );
  ulong     zero = 0UL, one = 1UL;

  fd_repair_t * repair = setup();
  check_eager( repair, fd_repair_blk_map_ele_query( repair->blk_map, &zero, NULL, repair->blk_pool ) );
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_blk_t * e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( e1->eager && e1->in_blk_treap ); check_eager( repair, e1 );
  fd_repair_slot_invalidated( repair, 1UL, 0, 0L );
  FD_TEST( !e1->eager && !e1->in_blk_treap ); check_eager( repair, e1 );

  repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( e1->eager ); check_eager( repair, e1 );
  FD_TEST( fd_repair_blk_finalized( repair, 1UL, &d1, 0L )==e1 );
  FD_TEST( !e1->eager && role( repair, e1 )==ROLE_FINAL ); check_eager( repair, e1 );

  repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  fd_repair_blk_t * fin = fd_repair_blk_finalized( repair, 1UL, &h77, 0L );
  FD_TEST( fin && fin!=e1 && e1->eager && e1->in_blk_treap ); check_eager( repair, e1 ); check_eager( repair, fin ); /* still repaired by position */
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot = 1UL; shred->idx = 2U*FD_FEC_SHRED_CNT; shred->data.parent_off = 1;
  shred->variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 ); shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ; /* header only, no payload */
  fd_repair_shred_insert( repair, shred, &m12, 0, 0L );                            /* turbine moves its limit */
  FD_TEST( e1->rcvd_fec_cnt==3U && e1->in_blk_treap ); check_eager( repair, e1 );

  repair = setup();
  fd_repair_blk_t * n1 = fd_repair_blk_notarized( repair, 1UL, &d1 );
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  e1 = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  FD_TEST( e1!=n1 && e1->eager ); check_eager( repair, e1 ); check_eager( repair, n1 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==e1 && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) );
  FD_TEST( !e1->eager && role( repair, e1 )==ROLE_NOTAR ); check_eager( repair, e1 );

  repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( e1->eager );
  complete_as( repair, 1UL, 0UL, 0U, 1, &m10, 1 );
  FD_TEST( !e1->eager && !e1->in_blk_treap ); check_eager( repair, e1 );

  repair = setup();
  complete_as( repair, 1UL, 0UL, 0U, 0, &m10, 1 );
  e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( !e1->eager && !e1->in_blk_treap ); check_eager( repair, e1 );

  repair = fd_repair_join( fd_repair_new( mem, SLOT_MAX, FEC_MAX, BLK_FECS, 42UL ) );
  fd_repair_init( repair, 0UL, &hash_null, NULL, NULL );
  fd_repair_blk_t * r = fd_repair_blk_map_ele_query( repair->blk_map, &zero, NULL, repair->blk_pool );
  FD_TEST( role( repair, r )==ROLE_FINAL && !r->in_blk_treap ); check_eager( repair, r );
  orphan_cnt( repair );
}

/* Booting from genesis, the root's block id is zero and slot 1 names
   it.  Slot 1 still computes its dmr, so slot 2 links to it.  A notar
   blk naming the zero id also links under the root. */

static void
test_genesis( void ) {
  fd_repair_t * repair = fd_repair_join( fd_repair_new( mem, SLOT_MAX, FEC_MAX, BLK_FECS, 42UL ) );
  fd_repair_init( repair, 0UL, &hash_null, NULL, NULL );
  fd_mr32_t m10 = hash( 0x11 ), m20 = hash( 0x21 );

  shred0  ( repair, 1UL, 0UL, &hash_null, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  ulong             one = 1UL, two = 2UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( memcmp(  &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  expect( repair, e1, 0U );

  shred0  ( repair, 2UL, 1UL, &e1->dmr, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  expect( repair, fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool ), 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_blk_t * n3    = notar( repair, 3UL, 0x30 );
  fd_mr32_t         n3_id = hash( 0x30 ), m30 = hash( 0x31 );
  ulong             zero  = 0UL;
  FD_TEST( !fd_repair_blk_parented( repair, 3UL, &n3_id, 0UL, &hash_null, 1U, 0L ) );
  FD_TEST( n3->parent==fd_repair_blk_pool_idx( repair->blk_pool, fd_repair_blk_map_ele_query( repair->blk_map, &zero, NULL, repair->blk_pool ) ) );
  fecs    ( repair, 3UL, 0x30, 1U );
  complete( repair, 3UL, 0UL, 0U, 1, &m30 );
  expect( repair, n3, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A repair sized for a raised bench shred limit completes a slot whose
   last FEC set is past FD_FEC_BLK_MAX. */

static void
test_raised_blk_max( void ) {
  ulong        blk_fecs = 4UL*FD_FEC_BLK_MAX;
  ulong        fec_max  = SLOT_MAX*blk_fecs;
  FD_TEST( fd_repair_footprint( SLOT_MAX, fec_max, blk_fecs )<=sizeof(mem) );
  FD_TEST( !fd_repair_new( mem, SLOT_MAX, fec_max, FD_FEC_BLK_MAX-1UL, 42UL ) );
  fd_repair_t * repair = fd_repair_join( fd_repair_new( mem, SLOT_MAX, fec_max, blk_fecs, 42UL ) );
  fd_repair_init( repair, 0UL, &hash_null, NULL, NULL );

  fd_mr32_t m0 = hash( 0x11 );
  shred0     ( repair, 1UL, 0UL, &hash_null, &m0 );
  complete   ( repair, 1UL, 0UL, 0U, 0, &m0 );
  for( uint k=1U; k<(uint)blk_fecs; k++ ) {
    fd_mr32_t mr; memset( mr.uc, 0, sizeof(fd_mr32_t) ); FD_STORE( uint, mr.uc, k );
    FD_TEST( complete( repair, 1UL, 0UL, k, k+1U==(uint)blk_fecs, &mr ) );
  }
  ulong             one = 1UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( e1->cmpl_fec_cnt==blk_fecs && e1->cons_fec_cnt==blk_fecs );
  FD_TEST( memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  for( uint k=0U; k<(uint)blk_fecs; k++ ) expect( repair, e1, k );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
}

/* An eager blk in a slot finalized as skipped is never consumed. */

static void
test_skipped_not_consumed( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 );
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_slot_skipped( repair, 1UL );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A slot complete shred below a FEC set already received invalidates
   the eager blk, which is then never consumed. */

static void
test_complete_below_rcvd( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m12 = hash( 0x13 );
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 2U, 0, &m12 );
  FD_TEST( !complete( repair, 1UL, 0UL, 1U, 1, &m11 ) );
  ulong             one = 1UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( repair->slot_meta[ e1->slot % repair->slot_max ].invalidated );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* An eager blk that is whole when it is invalidated has a dmr, so it is
   still consumed once its parent is. */

static void
test_invalidated_after_whole( void ) {
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a      = notar( repair, 1UL, 0x10 );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 1U );
  fecs    ( repair, 1UL, 0x10, 1U );

  fd_mr32_t a_id =  hash( 0x10 ), m20 = hash( 0x21 );
  shred0  ( repair, 2UL, 1UL, &a_id, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  ulong             two = 2UL;
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, a ) && memcmp( &e2->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  fd_repair_slot_invalidated( repair, 2UL, 0, 0L );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t m11 = hash( 0x11 );
  complete( repair, 1UL, 0UL, 0U, 1, &m11 );
  expect( repair, a,  0U );
  expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* FEC sets of an eager blk complete out of order: the slot complete FEC
   set first, so its count is known before anything is buffered, or
   last, so earlier FEC sets stream while the count is unknown. */

static void
test_eager_out_of_order( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m12 = hash( 0x13 );
  ulong     one  = 1UL;

  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 2U, 1, &m12 );
  fd_repair_blk_t * e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( e1->cmpl_fec_cnt==3U && !e1->buff_fec_cnt );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  expect( repair, e1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  complete( repair, 1UL, 0UL, 1U, 0, &m11 );
  FD_TEST( memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  expect( repair, e1, 1U ); expect( repair, e1, 2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  expect( repair, e1, 0U );
  complete( repair, 1UL, 0UL, 1U, 0, &m11 );
  expect( repair, e1, 1U );
  FD_TEST( !e1->cmpl_fec_cnt && !memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  complete( repair, 1UL, 0UL, 2U, 1, &m12 );
  FD_TEST( e1->cmpl_fec_cnt==3U && memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  expect( repair, e1, 2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A FEC set completed again is not delivered twice. */

static void
test_complete_again(  void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 );
  fd_repair_t * repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot            = 1UL;
  shred->idx             = FD_FEC_SHRED_CNT - 1U;
  shred->data.parent_off = 1;
  shred->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  FD_TEST( fd_repair_fec_complete( repair, shred, &m10, 1, 0U, 0U, 0U, 0U, 0U, 0U, 0L )->is_leader );
  FD_TEST( complete( repair, 1UL, 0UL, 0U, 1, &m10 )->is_leader );
  ulong one = 1UL;
  expect( repair, fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool ), 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A notar blk learns its FEC set count before, after, or while its FEC
   sets complete out of order. */

static void
test_notar_out_of_order( void ) {
  fd_mr32_t mr;

  fd_repair_t *     repair = setup();
  fd_repair_blk_t * n      = notar( repair, 1UL, 0x10 );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L ); /* the notar blk alone builds the block */
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 3U );
  fecs    ( repair, 1UL, 0x10, 3U );
  mr = hash( 0x13 ); complete( repair, 1UL, 0UL, 2U, 1, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 0, &mr );
  expect( repair, n, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  mr = hash( 0x12 ); complete( repair, 1UL, 0UL, 1U, 0, &mr );
  expect( repair, n, 1U ); expect( repair, n, 2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair = setup();
  n      = notar( repair, 1UL, 0x10 );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fecs( repair, 1UL, 0x10, 2U );
  mr = hash( 0x12 ); complete( repair, 1UL, 0UL, 1U, 1, &mr );
  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 0, &mr );
  FD_TEST( n->buff_fec_cnt==2U && fd_repair_deque_empty( repair->reasm_deque ) );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 2U );
  expect( repair, n, 0U ); expect( repair, n, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair = setup();
  n      = notar( repair, 1UL, 0x10 );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fecs( repair, 1UL, 0x10, 3U );
  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 0, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 3U );
  expect( repair, n, 0U );
  mr = hash( 0x13 ); complete( repair, 1UL, 0UL, 2U, 1, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  mr = hash( 0x12 ); complete( repair, 1UL, 0UL, 1U, 0, &mr );
  expect( repair, n, 1U ); expect( repair, n, 2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A FEC set held by both the eager blk and a notar blk of the slot is
   delivered once, for the eager blk, while that blk is live.  When the
   eager blk is invalidated, the notar blk delivers it. */

static void
test_shared_fec( void ) {
  fd_mr32_t        root   = hash( 0xEE ), m10 = hash( 0x11 );
  fd_repair_t *    repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_blk_t * n1    = notar( repair, 1UL, 0x10 );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 2U );
  fecs    ( repair, 1UL, 0x10, 1U );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  ulong             one   = 1UL;
  fd_repair_blk_t * e1    = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  FD_TEST( e1!=n1 && !repair->slot_meta[ one % repair->slot_max ].invalidated );
  expect( repair, e1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) && !n1->cons_fec_cnt );

  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  expect( repair, n1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A notar blk notarizes a FEC set the eager blk already completed and
   delivered.  The notar blk is held: the eager blk carries the block.
   Once the eager blk is invalidated, the notar blk delivers it. */

static void
test_notarized_complete_fec( void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 );
  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  ulong             one = 1UL;
  fd_repair_blk_t * e1  = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  expect( repair, e1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_blk_t * n1 = notar( repair, 1UL, 0x10 );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 2U );
  fecs    ( repair, 1UL, 0x10, 1U );
  FD_TEST( n1->buff_fec_cnt==1U && !n1->cons_fec_cnt );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  expect( repair, n1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Invalidation of the eager blk: by a FEC set past the slot complete
   one, by a slot complete shred below FEC sets already delivered, and
   explicitly before its only FEC set completes.  Nothing is delivered
   after the invalidation, and later shreds of the slot are dropped. */

static void
test_eager_invalidated( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m12 = hash( 0x13 ), m13 = hash( 0x14 );
  ulong     one  = 1UL;

  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( !complete( repair, 1UL, 0UL, 2U, 0, &m12 ) );
  FD_TEST( repair->slot_meta[ one % repair->slot_max ].invalidated );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  complete( repair, 1UL, 0UL, 1U, 0, &m11 );
  complete( repair, 1UL, 0UL, 2U, 0, &m12 );
  fd_repair_blk_t * e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  expect( repair, e1, 0U ); expect( repair, e1, 1U ); expect( repair, e1, 2U );
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot             = 1UL;
  shred->idx              = FD_FEC_SHRED_CNT + 8U;
  shred->data.parent_off  = 1;
  shred->data.flags       = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  fd_repair_shred_insert( repair, shred, &m11, 0, 0L );
  FD_TEST( repair->slot_meta[ one % repair->slot_max ].invalidated );
  FD_TEST( !complete( repair, 1UL, 0UL, 3U, 1, &m13 ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_slot_invalidated( repair, 1UL, 0, 0L );
  FD_TEST( complete( repair, 1UL, 0UL, 0U, 1, &m10 ) );
  e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( !memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Finalizing a slot as a block repair does not have frees the eager blk
   and drops its later FEC sets.  A second finalization of the slot as
   another block, or finalizing a skipped slot, is refused. */

static void
test_finalize_other(  void ) {
  fd_mr32_t     root   = hash( 0xEE ), m10 = hash( 0x11 ), h77 = hash( 0x77 ), h40 = hash( 0x40 ), h20 = hash( 0x20 );
  fd_repair_t * repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_blk_t * fin = fd_repair_blk_finalized( repair, 1UL, &h77, 0L );
  ulong             one = 1UL, two = 2UL;
  FD_TEST( fin && !is_eager( repair, fin ) );
  fd_repair_blk_t * e1  = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  FD_TEST( e1 && e1!=fin ); /* the unfinished turbine version stays */
  complete( repair, 1UL, 0UL, 0U, 1, &m10 ); /* it completes as another blk and is pruned */
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==fin && !fd_repair_blk_map_ele_next_const( fin, NULL, repair->blk_pool ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  FD_TEST( !fd_repair_blk_finalized( repair, 1UL, &h40, 0L ) );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==fin && !fd_repair_blk_map_ele_next_const( fin, NULL, repair->blk_pool ) );

  fd_repair_slot_skipped( repair, 2UL );
  FD_TEST( !fd_repair_blk_finalized( repair, 2UL, &h20, 0L ) );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool ) );
  orphan_cnt( repair );
}

/* The final cert arrives before any turbine shred of the slot, eg. on
   a node whose shred tile lags.  Turbine still builds the eager blk,
   never repaired by position, and its FEC sets serve the finalized blk
   without repair.  It completes as the finalized blk and takes its
   place. */

static void
test_final_before_turbine( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );
  fd_mr20_t k0; memcpy( k0.uc, m10.uc, sizeof(fd_mr20_t) );
  ulong     one  = 1UL;

  fd_repair_t *     repair = setup();
  fd_repair_blk_t * fin    = fd_repair_blk_finalized( repair, 1UL, &d1, 0L );
  FD_TEST( fin && repair->slot_meta[ one % repair->slot_max ].eager==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  fd_repair_blk_parented( repair, 1UL, &d1, 0UL, &root, 2U, 0L );

  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_blk_t * e1 = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  FD_TEST( e1 && e1!=fin && !e1->eager && !e1->in_blk_treap );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( fd_repair_fec_notarized( repair, 1UL, &d1, 0U, &k0, 0L )->complete ); /* the FecRoot reply finds it complete */
  FD_TEST( fin->buff_fec_cnt==1U );
  expect( repair, e1, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( repair->slot_meta[ one % repair->slot_max ].final==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==e1 && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) ); /* the finalized blk was merged */
  expect( repair, e1, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A child that named a block before repair had it waits unlinked.
   Finalizing that block links the child under the finalized blk and
   keeps the unfinished turbine version, which then completes as the
   finalized blk and takes its place: the child is delivered after it.
   If the block is named (notar) before it is finalized, naming it links
   the child already, and the child is delivered as soon as it is. */

static void
test_finalize_moves_child( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );
  ulong     two  = 2UL;

  fd_repair_t * repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  shred0  ( repair, 2UL, 1UL, &d1,   &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  fd_repair_blk_t * e2 = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  fd_repair_blk_t * n1 = fd_repair_blk_finalized( repair, 1UL, &d1, 0L );
  FD_TEST( n1 && !is_eager( repair, n1 ) && e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) );
  fd_repair_blk_parented( repair, 1UL, &d1, 0UL, &root, 2U, 0L );
  fd_mr20_t k0; memcpy( k0.uc, m10.uc, sizeof(fd_mr20_t) );
  fd_mr20_t k1; memcpy( k1.uc, m11.uc, sizeof(fd_mr20_t) );
  FD_TEST( fd_repair_fec_notarized( repair, 1UL, &d1, 0U,               &k0, 0L ) );
  FD_TEST( fd_repair_fec_notarized( repair, 1UL, &d1, FD_FEC_SHRED_CNT, &k1, 0L ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  ulong             one = 1UL;
  fd_repair_blk_t * e1  = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  FD_TEST( e1 && e1!=n1 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( repair->slot_meta[ one % repair->slot_max ].final==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  expect( repair, e1, 0U ); /* the notar blk was held behind the eager blk */
  expect( repair, e1, 1U );
  expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t a_id = hash( 0x10 ), m61 = hash( 0x61 ), m11a = hash( 0x11 );
  repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m61 );
  shred0  ( repair, 2UL, 1UL, &a_id, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  e2 = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  fd_repair_blk_t * a = notar( repair, 1UL, 0x10 );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, a ) ); /* it names a */
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 1U );
  fecs    ( repair, 1UL, 0x10, 1U );
  complete( repair, 1UL, 0UL, 0U, 1, &m11a );
  expect( repair, a,  0U );
  expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  FD_TEST( fd_repair_blk_finalized( repair, 1UL, &a_id, 0L )==a );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, a ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* The leader of slot 1 equivocates: turbine delivers version A while
   the cluster certifies version B, and slot 2's block C names B.  C's
   header arrives before A completes and before B is held, so C waits
   unlinked.  A completes as a different dmr and does not take C.
   Naming B must link C, whichever of A's completion and B's cert comes
   first, so C is delivered after B. */

static void
test_eqvoc_links_waiting( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr32_t dA   = slot1_dmr( &m10, &m11 );
  fd_mr32_t dB   = hash( 0xB0 ), b0 = hash( 0xB1 );
  ulong     one  = 1UL, two = 2UL;
  FD_TEST( memcmp( &dA, &dB, sizeof(fd_mr32_t) ) );

  for( int cert_first=0; cert_first<2; cert_first++ ) {
    fd_repair_t * repair = setup();
    complete( repair, 1UL, 0UL, 1U, 1, &m11 ); /* A begins, header not yet received */
    shred0  ( repair, 2UL, 1UL, &dB, &m20 );
    complete( repair, 2UL, 1UL, 0U, 1, &m20 );
    fd_repair_blk_t * a = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
    fd_repair_blk_t * c = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
    FD_TEST( a && is_eager( repair, a ) && !memcmp( &a->dmr, &hash_null, sizeof(fd_mr32_t) ) );
    FD_TEST( c && c->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, c ) && a->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );

    fd_repair_blk_t * b = NULL;
    if( cert_first ) b = notar( repair, 1UL, 0xB0 );
    shred0  ( repair, 1UL, 0UL, &root, &m10 );
    complete( repair, 1UL, 0UL, 0U, 0, &m10 );
    FD_TEST( !memcmp( &a->dmr, &dA, sizeof(fd_mr32_t) ) && a->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
    if( !cert_first ) b = notar( repair, 1UL, 0xB0 );
    FD_TEST( b && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, b ) && b->child==fd_repair_blk_pool_idx( repair->blk_pool, c ) );

    expect( repair, a, 0U ); expect( repair, a, 1U );
    FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
    parented( repair, 1UL, 0xB0, 0UL, 0xEE, 1U );
    fecs    ( repair, 1UL, 0xB0, 1U );
    complete( repair, 1UL, 0UL, 0U, 1, &b0 );
    expect( repair, b, 0U );
    expect( repair, c, 0U );
    FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

    FD_TEST( fd_repair_blk_finalized( repair, 1UL, &dB, 0L )==b );
    FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, b ) && rooted( repair, c ) );
    FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
    orphan_cnt( repair );
  }
}

/* Slot 2's block C names (1, X) while slot 1's turbine version A is
   unfinished, then slot 1 is invalidated: A never completes.  C waits
   unlinked throughout, an orphan the tile repairs, and A takes no child
   before or after the invalidation.  X is then named and links C, in
   either order with the invalidation, and a fast-finalized descendant D
   of C delivers the chain X, C, D with slot 1 final as X. */

static void
test_invalidated_unlinked( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 ), m30 = hash( 0x31 ), m40 = hash( 0x41 );
  fd_mr32_t dX   = hash( 0xB0 ), x0 = hash( 0xB1 );
  ulong     one  = 1UL, two = 2UL, three = 3UL, four = 4UL;

  for( int cert_first=0; cert_first<2; cert_first++ ) {
    fd_repair_t * repair = setup();
    shred0  ( repair, 1UL, 0UL, &root, &m10 ); /* A begins, FEC 1 outstanding */
    shred0  ( repair, 2UL, 1UL, &dX, &m20 );
    complete( repair, 2UL, 1UL, 0U, 1, &m20 );
    fd_repair_blk_t * a = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
    fd_repair_blk_t * c = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
    FD_TEST( a && is_eager( repair, a ) && rooted( repair, a ) && !memcmp( &a->dmr, &hash_null, sizeof(fd_mr32_t) ) && a->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
    FD_TEST( c && c->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, c ) );
    FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

    fd_repair_blk_t * x = NULL;
    if( cert_first ) {
      x = notar( repair, 1UL, 0xB0 );
      FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) );
    }
    fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
    FD_TEST( a->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
    if( !cert_first ) FD_TEST( c->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, c ) );

    shred0( repair, 4UL, 1UL, &dX, &m40 ); /* nothing links under an invalidated slot's turbine version */
    fd_repair_blk_t * e = fd_repair_blk_map_ele_query( repair->blk_map, &four, NULL, repair->blk_pool );
    FD_TEST( e && e->parent==( cert_first ? fd_repair_blk_pool_idx( repair->blk_pool, x ) : fd_repair_blk_pool_idx_null( repair->blk_pool ) ) );

    if( !cert_first ) x = notar( repair, 1UL, 0xB0 );
    FD_TEST( x && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) && e->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) );
    parented( repair, 1UL, 0xB0, 0UL, 0xEE, 1U );
    fecs    ( repair, 1UL, 0xB0, 1U );
    complete( repair, 1UL, 0UL, 0U, 1, &x0 );
    expect( repair, x, 0U );
    expect( repair, c, 0U );
    FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

    shred0  ( repair, 3UL, 2UL, &c->dmr, &m30 );
    complete( repair, 3UL, 2UL, 0U, 1, &m30 );
    fd_repair_blk_t * d = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
    FD_TEST( d && d->parent==fd_repair_blk_pool_idx( repair->blk_pool, c ) );
    expect( repair, d, 0U );
    FD_TEST( fd_repair_blk_finalized( repair, 3UL, &d->dmr, 0L )==d );
    FD_TEST( repair->slot_meta[ two % repair->slot_max ].final==fd_repair_blk_pool_idx( repair->blk_pool, c ) );
    FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
    FD_TEST( fd_repair_blk_finalized( repair, 1UL, &dX, 0L )==x ); /* votor implicitly finalizes the ancestors */
    FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==x && !fd_repair_blk_map_ele_next_const( x, NULL, repair->blk_pool ) ); /* A is pruned */
    FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) && e->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) );
    FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
    orphan_cnt( repair );
  }
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

  fd_repair_t *     repair = setup();
  fd_repair_blk_t * c      = notar( repair, 3UL, 0x30 );
  fd_repair_blk_t * n2     = fd_repair_blk_parented( repair, 3UL, &h30, 2UL, &h20, 1U, 0L );
  FD_TEST( n2 && n2->slot==2UL && n2->child==fd_repair_blk_pool_idx( repair->blk_pool, c ) && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, n2 ) );
  FD_TEST( !fd_repair_blk_notarized( repair, 2UL, &h20 ) );
  fd_repair_blk_t * n1    = fd_repair_blk_parented( repair, 2UL, &h20, 1UL, &h10, 1U, 0L );
  FD_TEST( n1 && n2->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) );
  FD_TEST( !fd_repair_blk_parented( repair, 1UL, &h10, 0UL, &hEE, 1U, 0L ) );
  FD_TEST( n1->parent==fd_repair_blk_pool_idx( repair->blk_pool, fd_repair_blk_map_ele_query( repair->blk_map, &zero, NULL, repair->blk_pool ) ) );
  fecs( repair, 3UL, 0x30, 1U );
  fecs( repair, 2UL, 0x20, 1U );
  fecs( repair, 1UL, 0x10, 1U );
  mr = hash( 0x31 ); complete( repair, 3UL, 2UL, 0U, 1, &mr );
  mr = hash( 0x21 ); complete( repair, 2UL, 1UL, 0U, 1, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 1, &mr );
  expect( repair, n1, 0U ); expect( repair, n2, 0U ); expect( repair, c, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair = setup();
  fd_repair_blk_t * b = notar( repair, 2UL, 0x20 );
  FD_TEST( !fd_repair_blk_parented( repair, 2UL, &h20, 2UL, &h10, 1U, 0L ) && b->parent_slot==ULONG_MAX );
  n1 = fd_repair_blk_parented( repair, 2UL, &h20, 1UL, &h10, 1U, 0L );
  FD_TEST( n1 && b->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) );
  FD_TEST( !fd_repair_blk_parented( repair, 2UL, &h20, 1UL, &h40, 1U, 0L ) );
  FD_TEST( !fd_repair_blk_parented( repair, 2UL, &h20, 1UL, &h10, 1U, 0L ) );
  FD_TEST( b->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) && n1->child==fd_repair_blk_pool_idx( repair->blk_pool, b ) );
  FD_TEST( b->sibling==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !memcmp( &b->parent_blk_mr, &h10, sizeof(fd_mr32_t) ) );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==n1 && !fd_repair_blk_map_ele_next_const( n1, NULL, repair->blk_pool ) );

  repair = setup();
  b      = notar( repair, 2UL, 0x20 );
  FD_TEST( !fd_repair_blk_parented( repair, 2UL, &h20, 0UL, &h77, 1U, 0L ) );
  FD_TEST( b->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool ) );
  fecs( repair, 2UL, 0x20, 1U );
  mr = hash( 0x21 ); complete( repair, 2UL, 0UL, 0U, 1, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair = setup();
  b      = notar( repair, 2UL, 0x20 );
  c      = notar( repair, 3UL, 0x30 );
  n1     = fd_repair_blk_finalized( repair, 1UL, &h10, 0L );
  FD_TEST( !fd_repair_blk_parented( repair, 2UL, &h20, 1UL, &h40, 1U, 0L ) && b->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==n1 && !fd_repair_blk_map_ele_next_const( n1, NULL, repair->blk_pool ) );
  FD_TEST( !fd_repair_blk_parented( repair, 3UL, &h30, 1UL, &h10, 1U, 0L ) && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) );

  repair = setup();
  fd_repair_slot_skipped( repair, 1UL );
  b      = notar( repair, 2UL, 0x20 );
  FD_TEST( !fd_repair_blk_parented( repair, 2UL, &h20, 1UL, &h10, 1U, 0L ) && b->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool ) );
  orphan_cnt( repair );
}

/* A fork: two children of one parent in different slots, one complete
   and one partial when the parent completes.  The partial child streams
   its prefix and the rest of it follows its last FEC set. */

static void
test_fork( void ) {
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a      = notar( repair, 1UL, 0x10 );
  fd_repair_blk_t * b      = notar( repair, 2UL, 0x20 );
  fd_repair_blk_t * c      = notar( repair, 3UL, 0x30 );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fd_repair_slot_invalidated( repair, 2UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fd_repair_slot_invalidated( repair, 3UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 1U );
  parented( repair, 2UL, 0x20, 1UL, 0x10, 1U );
  parented( repair, 3UL, 0x30, 1UL, 0x10, 2U );
  fecs( repair, 1UL, 0x10, 1U );
  fecs( repair, 2UL, 0x20, 1U );
  fecs( repair, 3UL, 0x30, 2U );

  fd_mr32_t mr;
  mr = hash( 0x21 ); complete( repair, 2UL, 1UL, 0U, 1, &mr );
  mr = hash( 0x31 ); complete( repair, 3UL, 1UL, 0U, 0, &mr );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 1, &mr );
  expect( repair, a, 0U ); expect( repair, c, 0U ); expect( repair, b, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  mr = hash( 0x32 ); complete( repair, 3UL, 1UL, 1U, 1, &mr );
  expect( repair, c, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Skipping a slot frees its blks and unlinks their children: the middle
   of a notar chain, and an eager blk already delivered in full.  The
   orphaned descendants are never delivered. */

static void
test_skip_unlinks( void ) {
  ulong two = 2UL;

  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a      = notar( repair, 1UL, 0x10 );
  notar( repair, 2UL, 0x20 );
  fd_repair_blk_t * c      = notar( repair, 3UL, 0x30 );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 1U );
  parented( repair, 2UL, 0x20, 1UL, 0x10, 1U );
  parented( repair, 3UL, 0x30, 2UL, 0x20, 1U );
  fd_repair_slot_skipped( repair, 2UL );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool ) );
  FD_TEST( a->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( c->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && c->sibling==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  fecs( repair, 1UL, 0x10, 1U );
  fecs( repair, 3UL, 0x30, 1U );
  fd_mr32_t mr;
  mr = hash( 0x31 ); complete( repair, 3UL, 2UL, 0U, 1, &mr );
  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 1, &mr );
  expect( repair, a, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 );
  ulong     one  = 1UL;
  repair = setup();
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  fd_repair_blk_t * e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  expect( repair, e1, 0U );
  fd_mr32_t d1 = e1->dmr;
  shred0( repair, 2UL, 1UL, &d1, &m20 );
  fd_repair_blk_t * e2 = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  fd_repair_slot_skipped( repair, 1UL );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Twin merges where the notar twin has children: a notar child and an
   eager child that linked to it by dmr, alongside an eager child that
   named another block and waits unlinked; and an eager child alone.
   The eager blk takes the twin's children and never the one that named
   another block. */

static void
test_twin_merge_children( void ) {
  fd_mr32_t root = hash( 0xEE ), other = hash( 0x99 );
  fd_mr32_t m10  = hash( 0x11 ), m11   = hash( 0x12 ), m20 = hash( 0x21 ), m30 = hash( 0x31 ), m40 = hash( 0x41 ), m51 = hash( 0x51 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );
  ulong     one  = 1UL, two = 2UL, three = 3UL, four = 4UL;

  fd_repair_t *     repair = setup();
  fd_repair_blk_t * n1     = fd_repair_blk_notarized( repair, 1UL, &d1 );
  fd_repair_blk_t * c      = notar( repair, 2UL, 0x50 );
  fd_mr32_t         c_id   = hash( 0x50 );
  fd_repair_blk_parented( repair, 2UL, &c_id, 1UL, &d1, 1U, 0L );
  fecs    ( repair, 2UL, 0x50, 1U );
  complete( repair, 2UL, 1UL, 0U, 1, &m51 );
  shred0  ( repair, 3UL, 1UL, &d1, &m30 );
  complete( repair, 3UL, 1UL, 0U, 1, &m30 );
  shred0  ( repair, 4UL, 1UL, &other, &m40 );
  complete( repair, 4UL, 1UL, 0U, 1, &m40 );
  fd_repair_blk_t * e3 = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  fd_repair_blk_t * e4 = fd_repair_blk_map_ele_query( repair->blk_map, &four,  NULL, repair->blk_pool );
  fd_repair_blk_t * e1 = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  FD_TEST( e3->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) && e4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && e1->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  expect( repair, e1, 0U );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==e1 && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) );
  FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) && e3->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  expect( repair, e1, 1U );
  expect( repair, c,  0U ); expect( repair, e3, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair = setup();
  n1     = fd_repair_blk_notarized( repair, 1UL, &d1 );
  shred0  ( repair, 2UL, 1UL, &d1, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  fd_repair_blk_t * e2 = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, n1 ) );
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( is_eager( repair, e1 ) && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  expect( repair, e1, 0U ); expect( repair, e1, 1U );
  expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* The root advances into the middle of a chain while a child is part
   delivered.  The new root keeps its children, which treat it as
   consumed in full, and the child's remaining FEC set follows. */

static void
test_root_advanced( void  ) {
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a      = notar( repair, 1UL, 0x10 );
  fd_repair_blk_t * b      = notar( repair, 2UL, 0x20 );
  fd_repair_blk_t * c      = notar( repair, 3UL, 0x30 );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fd_repair_slot_invalidated( repair, 2UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fd_repair_slot_invalidated( repair, 3UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 2U );
  parented( repair, 2UL, 0x20, 1UL, 0x10, 2U );
  parented( repair, 3UL, 0x30, 2UL, 0x20, 2U );
  fecs( repair, 1UL, 0x10, 2U );
  fecs( repair, 2UL, 0x20, 2U );
  fecs( repair, 3UL, 0x30, 2U );

  fd_mr32_t mr;
  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 0, &mr );
  mr = hash( 0x12 ); complete( repair, 1UL, 0UL, 1U, 1, &mr );
  mr = hash( 0x21 ); complete( repair, 2UL, 1UL, 0U, 0, &mr );
  mr = hash( 0x22 ); complete( repair, 2UL, 1UL, 1U, 1, &mr );
  mr = hash( 0x31 ); complete( repair, 3UL, 2UL, 0U, 0, &mr );
  expect( repair, a, 0U ); expect( repair, a, 1U );
  expect( repair, b, 0U ); expect( repair, b, 1U );
  expect( repair, c, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t b_id = hash( 0x20 );
  ulong     zero = 0UL, one = 1UL;
  fd_repair_root_advanced( repair, 2UL, &b_id );
  FD_TEST( repair->root==2UL );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &zero, NULL, repair->blk_pool ) && !fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool ) );
  FD_TEST( b->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, b ) );
  FD_TEST( b->fecs[ 0 ]==fd_repair_fec_pool_idx_null( repair->fec_pool ) && b->fecs[ 1 ]==fd_repair_fec_pool_idx_null( repair->fec_pool ) );
  mr = hash( 0x32 ); complete( repair, 3UL, 2UL, 1U, 1, &mr );
  expect( repair, c, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
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
check_delivery( fd_repair_t *            repair,
                fd_repair_blk_t * const * blks,
                uint const *            cnt,
                int const *             par,
                ulong                   blk_cnt ) {
  uint done[ 8 ] = {0};
  while( !fd_repair_deque_empty( repair->reasm_deque ) ) {
    fd_repair_deque_t out = fd_repair_deque_pop_head( repair->reasm_deque );
    ulong   k   = 0UL;
    while( k<blk_cnt && out.blk_idx!=fd_repair_blk_pool_idx( repair->blk_pool, blks[ k ] ) ) k++;
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
  fd_mr32_t     root     = hash( 0xEE );
  uint const    cnt[ 3 ] = { 2U, 1U, 1U };
  int const     par[ 3 ] = { -1, 0, 1 };
  uint          p[ 7 ]   = { 0U, 1U, 2U, 3U, 4U, 5U, 6U };
  ulong         perm_cnt = 0UL;
  fd_repair_t * repair   = setup();
  do {
    fd_repair_fini( repair );
    fd_repair_init( repair, 0UL, &root, NULL, NULL );
    fd_repair_blk_t * blks[ 3 ];
    blks[ 0 ] = notar( repair, 1UL, 0x10 );
    blks[ 1 ] = notar( repair, 2UL, 0x20 );
    blks[ 2 ] = notar( repair, 3UL, 0x30 );
    fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
    fd_repair_slot_invalidated( repair, 2UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
    fd_repair_slot_invalidated( repair, 3UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
    fecs( repair, 1UL, 0x10, 2U );
    fecs( repair, 2UL, 0x20, 1U );
    fecs( repair, 3UL, 0x30, 1U );
    for( ulong i=0UL; i<7UL; i++ ) {
      fd_mr32_t mr;
      switch( p[ i ] ) {
      case 0U: parented( repair, 1UL, 0x10, 0UL, 0xEE, 2U );                   break;
      case 1U: parented( repair, 2UL, 0x20, 1UL, 0x10, 1U );                   break;
      case 2U: parented( repair, 3UL, 0x30, 2UL, 0x20, 1U );                   break;
      case 3U: mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 0, &mr ); break;
      case 4U: mr = hash( 0x12 ); complete( repair, 1UL, 0UL, 1U, 1, &mr ); break;
      case 5U: mr = hash( 0x21 ); complete( repair, 2UL, 1UL, 0U, 1, &mr ); break;
      default: mr = hash( 0x31 ); complete( repair, 3UL, 2UL, 0U, 1, &mr ); break;
      }
    }
    check_delivery( repair, blks, cnt, par, 3UL );
    perm_cnt++;
  } while( next_perm( p, 7U ) );
  FD_TEST( perm_cnt==5040UL );
  orphan_cnt( repair );
}

/* Every ordering of turbine events for slots 1 (2 FEC sets) and 2 (1 FEC
   set, header naming slot 1's real block id) in which a slot's shred 0
   precedes the completion of its FEC set 0, as the shred tile publishes
   them.  Orderings with slot 2's header first link it under slot 1's
   turbine version created empty. */

static void
test_perm_eager_chain( void ) {
  fd_mr32_t     root     = hash( 0xEE );
  fd_mr32_t     m10      = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr32_t     d1       = slot1_dmr( &m10, &m11 );
  uint const    cnt[ 2 ] = { 2U, 1U };
  int const     par[ 2 ] = { -1, 0 };
  uint          p[ 5 ]   = { 0U, 1U, 2U, 3U, 4U };
  ulong         perm_cnt = 0UL;
  ulong         one      = 1UL, two = 2UL;
  fd_repair_t * repair   = setup();
  do {
    uint pos[ 5 ];
    for( uint i=0U; i<5U; i++ ) pos[ p[ i ] ] = i;
    if( pos[ 0 ]>pos[ 1 ] || pos[ 3 ]>pos[ 4 ] ) continue;
    fd_repair_fini( repair );
    fd_repair_init( repair, 0UL, &root, NULL, NULL );
    for( ulong i=0UL; i<5UL; i++ ) {
      switch( p[ i ] ) {
      case 0U: shred0  ( repair, 1UL, 0UL, &root, &m10 );     break;
      case 1U: complete( repair, 1UL, 0UL, 0U, 0, &m10 ); break;
      case 2U: complete( repair, 1UL, 0UL, 1U, 1, &m11 ); break;
      case 3U: shred0  ( repair, 2UL, 1UL, &d1, &m20 );       break;
      default: complete( repair, 2UL, 1UL, 0U, 1, &m20 ); break;
      }
    }
    fd_repair_blk_t * blks[ 2 ];
    blks[ 0 ] = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
    blks[ 1 ] = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
    FD_TEST( is_eager( repair, blks[ 0 ] ) && !fd_repair_blk_map_ele_next_const( blks[ 0 ], NULL, repair->blk_pool ) );
    FD_TEST( !memcmp( &blks[ 0 ]->dmr, &d1, sizeof(fd_mr32_t) ) && blks[ 1 ]->parent==fd_repair_blk_pool_idx( repair->blk_pool, blks[ 0 ] ) );
    check_delivery( repair, blks, cnt, par, 2UL );
    perm_cnt++;
  } while( next_perm( p, 5U ) );
  FD_TEST( perm_cnt==30UL );
  orphan_cnt( repair );
}

/* Our leader FEC sets are delivered before FEC sets already queued,
   including the chain a reconsume delivers again, and in FEC order when
   several become deliverable at once. */

static void
test_leader_first(  void ) {
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * a      = notar( repair, 1UL, 0x10 );
  fd_repair_slot_invalidated( repair, 1UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 2U );
  fecs    ( repair, 1UL, 0x10, 2U );
  fd_mr32_t mr;
  mr = hash( 0x11 ); complete( repair, 1UL, 0UL, 0U, 0, &mr );
  mr = hash( 0x12 ); complete( repair, 1UL, 0UL, 1U, 1, &mr );
  repair->reconsume = 1;
  FD_TEST( fd_repair_deque_cnt( repair->reasm_deque )==2UL );

  fd_mr32_t a_id = hash( 0x10 ), m20 = hash( 0x21 ), m21 = hash( 0x22 ), m22 = hash( 0x23 );
  shred0     ( repair, 2UL, 1UL, &a_id, &m20 );
  complete_as( repair, 2UL, 1UL, 1U, 0, &m21, 1 );
  FD_TEST( fd_repair_deque_cnt( repair->reasm_deque )==2UL );
  complete_as( repair, 2UL, 1UL, 0U, 0, &m20, 1 );
  ulong             two = 2UL;
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, a ) );
  expect( repair, e2, 0U ); expect( repair, e2, 1U );
  complete_as( repair, 2UL, 1UL, 2U, 1, &m22, 1 );
  expect( repair, e2, 2U );
  expect( repair, a,  0U ); expect( repair, a,  1U );
  expect( repair, a,  0U ); expect( repair, a,  1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A skip frees the slot's blks, and the network's shreds for the
   skipped slot build nothing. */

static void
test_skipped_refused( void ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m11 = hash( 0x12 );
  ulong     one  = 1UL;

  fd_repair_t * repair = setup();
  shred0( repair, 1UL, 0UL, &root, &m10 );
  fd_repair_slot_skipped( repair, 1UL );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool ) );
  shred0( repair, 1UL, 0UL, &root, &m10 );
  FD_TEST( !complete( repair, 1UL, 0UL, 0U, 0, &m10 ) );
  FD_TEST( !complete( repair, 1UL, 0UL, 1U, 1, &m11 ) );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* Catchup gives every slot in (root, slot) without an eager blk an
   empty one, in its blk_treap for repair by position, as a first turbine
   shred would.  A slot that has a blk or is skipped is left alone, a
   lower slot does nothing, and a later skip prunes a pre-created blk. */

static void
test_catchup( void ) {
  fd_mr32_t root = hash( 0xEE ), m20 = hash( 0x21 );

  fd_repair_t * repair = setup();
  shred0( repair, 2UL, 0UL, &root, &m20 );
  ulong             zero = 0UL, two = 2UL, four = 4UL;
  fd_repair_blk_t * e2   = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  fd_repair_slot_skipped( repair, 4UL );
  ulong used      = fd_repair_blk_pool_used( repair->blk_pool );
  ulong treap_cnt = fd_repair_treap_ele_cnt( repair->eager_treap );

  fd_repair_slot_catchup( repair, 6UL );
  FD_TEST( fd_repair_blk_pool_used( repair->blk_pool )==used+3UL );
  FD_TEST( fd_repair_treap_ele_cnt( repair->eager_treap )==treap_cnt+3UL );
  for( ulong s=1UL; s<6UL; s+=2UL ) {
    fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( repair->blk_map, &s, NULL, repair->blk_pool );
    FD_TEST( blk && !fd_repair_blk_map_ele_next_const( blk, NULL, repair->blk_pool ) && is_eager( repair, blk ) );
    FD_TEST( role( repair, blk )==ROLE_EAGER && blk->eager && blk->in_blk_treap );
    FD_TEST( !memcmp( &blk->dmr, &hash_null, sizeof(fd_mr32_t) ) );
    FD_TEST( blk->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && blk->parent_slot==ULONG_MAX && !blk->rcvd_fec_cnt );
  }
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool )==e2 && !fd_repair_blk_map_ele_next_const( e2, NULL, repair->blk_pool ) );
  FD_TEST( e2->rcvd_fec_cnt==1U && e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, fd_repair_blk_map_ele_query( repair->blk_map, &zero, NULL, repair->blk_pool ) ) );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &four, NULL, repair->blk_pool ) );
  for( ulong s=6UL; s<SLOT_MAX; s++ ) FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &s, NULL, repair->blk_pool ) );

  fd_repair_slot_catchup( repair, 3UL );
  FD_TEST( fd_repair_blk_pool_used( repair->blk_pool )==used+3UL && repair->catchup_slot==6UL );

  ulong three = 3UL;
  fd_repair_slot_skipped( repair, 3UL );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool ) );
  FD_TEST( fd_repair_blk_pool_used( repair->blk_pool )==used+2UL );
  FD_TEST( fd_repair_treap_ele_cnt( repair->eager_treap )==treap_cnt+2UL );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t h8 = hash( 0x80 );
  fd_repair_slot_invalidated( repair, 7UL, 0, 0L );
  FD_TEST( fd_repair_blk_finalized( repair, 8UL, &h8, 0L ) );
  used = fd_repair_blk_pool_used( repair->blk_pool );
  fd_repair_slot_catchup( repair, 10UL );
  FD_TEST( fd_repair_blk_pool_used( repair->blk_pool )==used+2UL );
  FD_TEST( fd_repair_slot_meta( repair, 7UL )->eager==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( fd_repair_slot_meta( repair, 8UL )->eager==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  ulong seven = 7UL;
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &seven, NULL, repair->blk_pool ) );
  orphan_cnt( repair );
}

/* Shred 0 of slot 2 names slot 1's pre-created eager blk, which has no
   dmr yet, so it waits unlinked and both are delivered once slot 1
   completes. */

static void
test_catchup_link( void ) {
  fd_mr32_t root = hash( 0xEE );
  fd_mr32_t m10  = hash( 0x11 ), m11 = hash( 0x12 ), m20 = hash( 0x21 );
  fd_mr32_t d1   = slot1_dmr( &m10, &m11 );

  fd_repair_t * repair = setup();
  fd_repair_slot_catchup( repair, 3UL );
  ulong             one = 1UL, two = 2UL;
  fd_repair_blk_t * e1  = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  fd_repair_blk_t * e2  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( e1 && e2 &&  is_eager( repair, e1 ) && is_eager( repair, e2 ) );

  shred0  ( repair, 2UL, 1UL, &d1, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool )==e2 && !fd_repair_blk_map_ele_next_const( e2, NULL, repair->blk_pool ) );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && e2->parent_slot==1UL );
  FD_TEST( !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 1U, 1, &m11 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  complete( repair, 1UL, 0UL, 0U, 0, &m10 );
  FD_TEST( !memcmp( &e1->dmr, &d1, sizeof(fd_mr32_t) ) && is_eager( repair, e1 ) );
  FD_TEST( e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  expect( repair, e1, 0U ); expect( repair, e1, 1U );
  expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* A root advance frees the pre-created blks at or below the new root,
   and once the root passes the high-water catchup walks from the new
   root. */

static void
test_catchup_root_advanced( void ) {
  fd_repair_t * repair = setup();
  fd_repair_slot_catchup( repair, 6UL );
  fd_repair_blk_t * c    = notar( repair, 3UL, 0x30 );
  fd_mr32_t         c_id = hash( 0x30 );
  fd_repair_root_advanced( repair, 3UL, &c_id );
  for( ulong s=0UL; s<3UL; s++ ) FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &s, NULL, repair->blk_pool ) );
  ulong three = 3UL;
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool )==c && !fd_repair_blk_map_ele_next_const( c, NULL, repair->blk_pool ) );
  for( ulong s=4UL; s<6UL; s++ ) {
    fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( repair->blk_map, &s, NULL, repair->blk_pool );
    FD_TEST( blk && is_eager( repair, blk ) && blk->in_blk_treap );
  }
  FD_TEST( fd_repair_blk_pool_used( repair->blk_pool )==3UL );

  fd_repair_slot_catchup( repair, 8UL );
  FD_TEST( fd_repair_blk_pool_used( repair->blk_pool )==5UL );
  for( ulong s=6UL; s<8UL; s++ ) {
    fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( repair->blk_map, &s, NULL, repair->blk_pool );
    FD_TEST( blk && is_eager( repair, blk ) && blk->in_blk_treap );
  }

  fd_repair_blk_t * f    = notar( repair, 9UL, 0x90 );
  fd_mr32_t         f_id = hash( 0x90 );
  fd_repair_root_advanced( repair, 9UL, &f_id );
  FD_TEST( fd_repair_blk_pool_used( repair->blk_pool )==1UL );
  fd_repair_slot_catchup( repair, 12UL );
  for( ulong s=4UL; s<9UL; s++ ) FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &s, NULL, repair->blk_pool ) );
  ulong nine = 9UL;
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &nine, NULL, repair->blk_pool )==f );
  for( ulong s=10UL; s<12UL; s++ ) {
    fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( repair->blk_map, &s, NULL, repair->blk_pool );
    FD_TEST( blk && is_eager( repair, blk ) && blk->in_blk_treap );
  }
  FD_TEST( fd_repair_blk_pool_used( repair->blk_pool )==3UL );
  orphan_cnt( repair );
}

/* Turbine completes C in slot 2, which names B in slot 1, while slot 1
   holds a different completed blk A.  C is orphaned.  Notarizing C
   creates B by the id C commits to and links C under it; a later final
   cert makes B final, and B's PARENT_AND_FEC_SET_COUNT connects the
   chain. */

static void
test_ancestry_held_orphan( void ) {
  fd_mr32_t     root   = hash( 0xEE ), mA = hash( 0xA1 ), mC = hash( 0xC1 ), B = hash( 0xB0 );
  fd_repair_t * repair = setup();
  ulong         one    = 1UL, two = 2UL;
  shred0  ( repair, 1UL, 0UL, &root, &mA );
  complete( repair, 1UL, 0UL, 0U, 1, &mA );
  shred0  ( repair, 2UL, 1UL, &B, &mC );
  complete( repair, 2UL, 1UL, 0U, 1, &mC );
  fd_repair_blk_t * a = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  fd_repair_blk_t * c = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( rooted( repair, a ) && c->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, c ) );

  fd_mr32_t cid = c->dmr;
  FD_TEST( !fd_repair_blk_notarized( repair, 2UL, &cid ) );
  fd_repair_blk_t * b = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  while( b && memcmp( &b->dmr, &B, sizeof(fd_mr32_t) ) ) b = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( b, NULL, repair->blk_pool );
  FD_TEST( b && role( repair, b )==ROLE_NOTAR && b->parent_slot==ULONG_MAX );
  FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, b ) && !rooted( repair, c ) && c->in_blk_treap );

  FD_TEST( fd_repair_blk_finalized( repair, 2UL, &cid, 0L )==c );
  FD_TEST( role( repair, c )==ROLE_FINAL && role( repair, b )==ROLE_FINAL );

  fd_repair_blk_parented( repair, 1UL, &B, 0UL, &root, 1U, 0L );
  FD_TEST( rooted( repair, b ) && rooted( repair, c ) );
  orphan_cnt( repair );
}

/* Notarizing C walks through its held parent P, which is itself
   orphaned, and creates P's parent X by the id P commits to. */

static void
test_ancestry_held_parent( void ) {
  fd_mr32_t     root   = hash( 0xEE ), mA = hash( 0xA1 ), mP = hash( 0xD1 ), mC = hash( 0xC1 ), X = hash( 0xB0 );
  fd_repair_t * repair = setup();
  ulong         one    = 1UL, two = 2UL, three = 3UL;
  shred0  ( repair, 1UL, 0UL, &root, &mA );
  complete( repair, 1UL, 0UL, 0U, 1, &mA );
  shred0  ( repair, 2UL, 1UL, &X, &mP );
  complete( repair, 2UL, 1UL, 0U, 1, &mP );
  fd_repair_blk_t * p = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  fd_mr32_t         pid = p->dmr;
  shred0  ( repair, 3UL, 2UL, &pid, &mC );
  complete( repair, 3UL, 2UL, 0U, 1, &mC );
  fd_repair_blk_t * c = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, p ) && p->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, c ) && !rooted( repair, p ) );

  fd_mr32_t cid = c->dmr;
  fd_repair_blk_notarized( repair, 3UL, &cid );
  fd_repair_blk_t * x = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  while( x && memcmp( &x->dmr, &X, sizeof(fd_mr32_t) ) ) x = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( x, NULL, repair->blk_pool );
  FD_TEST( x && p->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) && c->parent==fd_repair_blk_pool_idx( repair->blk_pool, p ) );

  fd_repair_blk_parented( repair, 1UL, &X, 0UL, &root, 1U, 0L );
  FD_TEST( rooted( repair, x ) && rooted( repair, p ) && rooted( repair, c ) );
  orphan_cnt( repair );
}

/* C's shred 0 arrives before any of slot 1, which seeds slot 1's empty
   eager placeholder, with no dmr for C to link under.  Notarizing C
   creates the named parent B and links C under it.  Turbine then
   completes slot 1 as B, which merges into the eager blk and connects
   C. */

static void
test_ancestry_eager_merge( void ) {
  fd_mr32_t root = hash( 0xEE ), m1 = hash( 0x11 ), mC = hash( 0xC1 );

  fd_repair_t * ref = setup_in( scratch ); /* slot 1's id, as turbine will compute it */
  shred0  ( ref, 1UL, 0UL, &root, &m1 );
  complete( ref, 1UL, 0UL, 0U, 1, &m1 );
  ulong     one = 1UL, two = 2UL;
  fd_mr32_t B   = fd_repair_blk_map_ele_query( ref->blk_map, &one, NULL, ref->blk_pool )->dmr;

  fd_repair_t * repair = setup();
  shred0  ( repair, 2UL, 1UL, &B, &mC );
  complete( repair, 2UL, 1UL, 0U, 1, &mC );
  fd_repair_blk_t * c  = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  fd_repair_blk_t * e1 = fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool );
  FD_TEST( e1 && is_eager( repair, e1 ) && !memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) && e1->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( c->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, c ) );

  fd_mr32_t cid = c->dmr;
  fd_repair_blk_notarized( repair, 2UL, &cid );
  fd_repair_blk_t const * b = fd_repair_blk_pool_ele_const( repair->blk_pool, c->parent );
  FD_TEST( b && b!=e1 && !memcmp( &b->dmr, &B, sizeof(fd_mr32_t) ) && e1->child==fd_repair_blk_pool_idx_null( repair->blk_pool ) );

  shred0  ( repair, 1UL, 0UL, &root, &m1 );
  complete( repair, 1UL, 0UL, 0U, 1, &m1 );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==e1 && !fd_repair_blk_map_ele_next_const( e1, NULL, repair->blk_pool ) );
  FD_TEST( !memcmp( &e1->dmr, &B, sizeof(fd_mr32_t) ) && role( repair, e1 )==ROLE_NOTAR );
  FD_TEST( c->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) && rooted( repair, e1 ) && rooted( repair, c ) );
  orphan_cnt( repair );
}

/* L names N in slot 3, whose rooted eager placeholder E3 has no dmr,
   so L waits unlinked, then N shows up and takes L, under T, under X,
   which has no ancestry.  X dies and is held: the walk from L passes N
   and T unchanged and stops at X, the same blk, not a re-created one. */

static void
test_ancestry_two_relinks( void ) {
  fd_mr32_t     root   = hash( 0xEE ), mA = hash( 0xA1 ), mT = hash( 0xD1 ), mE = hash( 0xE1 ), mL = hash( 0xC1 );
  fd_mr32_t     X      = hash( 0xB0 ), N = hash( 0x30 );
  fd_repair_t * repair = setup();
  ulong         two    = 2UL, four = 4UL;

  shred0  ( repair, 1UL, 0UL, &root, &mA ); /* slot 1 holds A, so T's X is not held */
  complete( repair, 1UL, 0UL, 0U, 1, &mA );
  shred0  ( repair, 2UL, 1UL, &X, &mT );
  complete( repair, 2UL, 1UL, 0U, 1, &mT );
  fd_repair_blk_t * t   = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  fd_mr32_t         tid = t->dmr;

  shred0( repair, 3UL, 0UL, &root, &mE ); /* E3, rooted and unfinished */
  shred0( repair, 4UL, 3UL, &N, &mL );    /* L waits for N */
  complete( repair, 4UL, 3UL, 0U, 1, &mL );
  fd_repair_blk_t * l = fd_repair_blk_map_ele_query( repair->blk_map, &four, NULL, repair->blk_pool );
  FD_TEST( l->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !rooted( repair, l ) );

  fd_repair_blk_t * n = fd_repair_blk_notarized( repair, 3UL, &N );
  FD_TEST( n && l->parent==fd_repair_blk_pool_idx( repair->blk_pool, n ) && !rooted( repair, l ) );
  fd_repair_blk_parented ( repair, 3UL, &N, 2UL, &tid, 1U, 0L ); /* N under T, creating X under which T goes */
  ulong xidx = t->parent;
  FD_TEST( xidx!=fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  fd_repair_blk_dead     ( repair, 1UL, &X, 0U );           /* X dies and is held */
  FD_TEST( t->parent==xidx && !rooted( repair, t ) );

  fd_mr32_t lid = l->dmr;
  fd_repair_blk_notarized( repair, 4UL, &lid );
  FD_TEST( !rooted( repair, l ) && t->parent==xidx );
  orphan_cnt( repair );
}

/* T under X is part delivered when X dies.  X is held, so T stays
   linked and its remaining FEC set goes out as it completes, then L
   under it.  A notar cert on L walks to X instead of re-creating it: a
   fresh X would have consumed nothing while T had, and a reconsume
   would send T ahead of any of X.  Once the chain is connected a final
   cert on L walks it, links nothing and delivers nothing again. */

static void
test_ancestry_consume_top( void ) {
  fd_mr32_t     root   = hash( 0xEE ), X = hash( 0xB0 ), mX = hash( 0xB1 ), m20 = hash( 0x21 ), m21 = hash( 0x22 ), m30 = hash( 0x31 );
  fd_repair_t * repair = setup();
  ulong         two    = 2UL, three = 3UL;
  (void)root;

  fd_repair_blk_t * x = notar( repair, 1UL, 0xB0 );
  parented( repair, 1UL, 0xB0, 0UL, 0xEE, 1U );
  fecs    ( repair, 1UL, 0xB0, 1U );
  complete( repair, 1UL, 0UL, 0U, 1, &mX );
  expect( repair, x, 0U );

  shred0  ( repair, 2UL, 1UL, &X, &m20 );
  complete( repair, 2UL, 1UL, 0U, 0, &m20 );
  fd_repair_blk_t * t = fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool );
  expect( repair, t, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_blk_dead( repair, 1UL, &X, 0U );
  FD_TEST( t->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) && t->cons_fec_cnt==1U );
  complete( repair, 2UL, 1UL, 1U, 1, &m21 );
  expect( repair, t, 1U );
  FD_TEST( t->cons_fec_cnt==2U && fd_repair_deque_empty( repair->reasm_deque ) );
  fd_mr32_t tid = t->dmr;
  shred0  ( repair, 3UL, 2UL, &tid, &m30 );
  complete( repair, 3UL, 2UL, 0U, 1, &m30 );
  fd_repair_blk_t * l = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  FD_TEST( l->parent==fd_repair_blk_pool_idx( repair->blk_pool, t ) );
  expect( repair, l, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_mr32_t lid = l->dmr;
  repair->reconsume = 1;
  FD_TEST( !fd_repair_blk_notarized( repair, 3UL, &lid ) );
  FD_TEST( t->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) ); /* found, not re-created */
  FD_TEST( rooted( repair, l ) && fd_repair_deque_empty( repair->reasm_deque ) );

  FD_TEST( fd_repair_blk_finalized( repair, 3UL, &lid, 0L )==l );
  FD_TEST( role( repair, l )==ROLE_FINAL && role( repair, t )==ROLE_FINAL && role( repair, x )==ROLE_FINAL );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  orphan_cnt( repair );
}

/* T is final under X when replay kills X.  X stays slot 1's final blk
   with T under it, out of final_treap since replay has all of it.  X
   named again is found, not re-created, and slot 1 refuses another
   blk. */

static void
test_ancestry_relink_final( void ) {
  fd_mr32_t     X      = hash( 0xB0 ), other = hash( 0x99 ), T = hash( 0x20 );
  fd_repair_t * repair = setup();
  ulong         one    = 1UL;

  fd_repair_blk_t * x = notar( repair, 1UL, 0xB0 );
  parented( repair, 1UL, 0xB0, 0UL, 0xEE, 1U );
  fd_repair_blk_t * t = fd_repair_blk_finalized( repair, 2UL, &T, 0L );
  FD_TEST( t );
  parented( repair, 2UL, 0x20, 1UL, 0xB0, 1U );
  FD_TEST( t->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) && role( repair, x )==ROLE_FINAL && role( repair, t )==ROLE_FINAL );

  fd_repair_blk_dead( repair, 1UL, &X, 0U );
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==x && !x->in_blk_treap );
  FD_TEST( t->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) && role( repair, x )==ROLE_FINAL );
  FD_TEST( !orphan_cnt( repair ) );

  FD_TEST( !fd_repair_blk_notarized( repair, 1UL, &X ) );     /* found, not re-created */
  FD_TEST( !fd_repair_blk_notarized( repair, 1UL, &other ) ); /* the slot is settled */
  FD_TEST( fd_repair_blk_map_ele_query( repair->blk_map, &one, NULL, repair->blk_pool )==x && !fd_repair_blk_map_ele_next_const( x, NULL, repair->blk_pool ) );
  FD_TEST( role( repair, x )==ROLE_FINAL && t->parent==fd_repair_blk_pool_idx( repair->blk_pool, x ) );
  orphan_cnt( repair );
}

/* orphan_map through each transition.  Two blks of different slots
   name the same parent dmr before it is held and share a key; a header
   repeated does not insert twice; the parent appearing links both out;
   the parent dying keeps both linked and naming it again finds it; a
   skip of one's slot prunes it; a blk whose eager parent completes as
   what it named leaves through link_children; and the root passing the
   dead parent puts its remaining child back. */

static void
test_orphan_map( void ) {
  fd_mr32_t     root   = hash( 0xEE ), P = hash( 0x10 ), m2 = hash( 0x21 ), m3 = hash( 0x31 ), m1 = hash( 0x11 );
  fd_repair_t * repair = setup();
  ulong         two    = 2UL, three = 3UL;
  FD_TEST( !orphan_cnt( repair ) ); /* the root names no one */

  shred0( repair, 2UL, 1UL, &P, &m2 );
  FD_TEST( orphan_cnt( repair )==1UL );
  shred0( repair, 2UL, 1UL, &P, &m2 ); /* shred 0 again */
  FD_TEST( orphan_cnt( repair )==1UL );
  notar   ( repair, 3UL, 0x30 );
  parented( repair, 3UL, 0x30, 1UL, 0x10, 1U ); /* creates P, which links both */
  FD_TEST( !orphan_cnt( repair ) );
  fd_repair_blk_t * e2 = fd_repair_blk_map_ele_query( repair->blk_map, &two,   NULL, repair->blk_pool );
  fd_repair_blk_t * n3 = fd_repair_blk_map_ele_query( repair->blk_map, &three, NULL, repair->blk_pool );
  FD_TEST( e2->parent!=fd_repair_blk_pool_idx_null( repair->blk_pool ) && e2->parent==n3->parent );

  ulong pidx = e2->parent;
  fd_repair_blk_dead( repair, 1UL, &P, 0U ); /* P dies, both stay linked under it */
  FD_TEST( e2->parent==pidx && n3->parent==pidx && !orphan_cnt( repair ) );
  FD_TEST( !fd_repair_blk_notarized( repair, 1UL, &P ) ); /* found, not re-created */
  FD_TEST( e2->parent==pidx && n3->parent==pidx && !orphan_cnt( repair ) );

  fd_repair_slot_skipped( repair, 3UL ); /* n3 pruned while linked */
  FD_TEST( !orphan_cnt( repair ) && e2->parent==pidx );

  /* Slot 1's eager blk completes as a different dmr first: e2 keeps
     waiting.  A blk naming that dmr before it was computed links when
     it is. */

  fd_repair_t * pre = setup_in( scratch );
  shred0  ( pre, 1UL, 0UL, &root, &m1 );
  complete( pre, 1UL, 0UL, 0U, 1, &m1 );
  ulong     one = 1UL;
  fd_mr32_t d1  = fd_repair_blk_map_ele_query( pre->blk_map, &one, NULL, pre->blk_pool )->dmr;

  shred0( repair, 3UL, 1UL, &d1, &m3 ); /* slot 3 is skipped, refused */
  FD_TEST( !orphan_cnt( repair ) );
  shred0( repair, 4UL, 1UL, &d1, &m3 );
  FD_TEST( orphan_cnt( repair )==1UL );
  shred0  ( repair, 1UL, 0UL, &root, &m1 );
  FD_TEST( orphan_cnt( repair )==1UL ); /* no dmr yet */
  complete( repair, 1UL, 0UL, 0U, 1, &m1 );
  fd_repair_blk_t * e1 = fd_repair_blk_pool_ele( repair->blk_pool, repair->slot_meta[ one % repair->slot_max ].eager );
  FD_TEST( e1 && !memcmp( &e1->dmr, &d1, sizeof(fd_mr32_t) ) );
  FD_TEST( !orphan_cnt( repair ) ); /* slot 4 linked, e2 still under P */
  FD_TEST( e1->child!=fd_repair_blk_pool_idx_null( repair->blk_pool ) && fd_repair_blk_pool_ele( repair->blk_pool, e1->child )->slot==4UL );

  /* The root passes P: e2 is unlinked with its parent slot freed */

  fd_repair_root_advanced( repair, 1UL, &d1 );
  FD_TEST( orphan_cnt( repair )==1UL ); /* e2 names a freed P and stays an orphan, harmless */
  FD_TEST( fd_repair_orphan_map_ele_query( repair->orphan_map, &P, NULL, repair->blk_pool )==e2 );
  fd_repair_root_advanced( repair, 4UL, &fd_repair_blk_pool_ele( repair->blk_pool, e1->child )->dmr );
  FD_TEST( !orphan_cnt( repair ) );
}

/* The root left orphan_map when it became root but still names its
   parent.  The next root advance frees it and must not remove it again:
   X, an orphan under the same key, shares its chain and would be lost
   to a removal through the root's stale links. */

static void
test_orphan_map_root_advanced( void ) {
  fd_mr32_t     root   = hash( 0xEE ), A = hash( 0x10 ), B = hash( 0x20 );
  fd_repair_t * repair = setup();
  fd_repair_blk_t * a  = notar( repair, 1UL, 0x10 );
  parented( repair, 1UL, 0x10, 0UL, 0xEE, 1U );
  fd_repair_root_advanced( repair, 1UL, &A );
  FD_TEST( repair->root_blk==a && a->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && !memcmp( &a->parent_blk_mr, &root, sizeof(fd_mr32_t) ) );
  FD_TEST( !orphan_cnt( repair ) );

  fd_repair_blk_t * x = notar( repair, 3UL, 0x30 ); /* names the freed root, under A's old key */
  parented( repair, 3UL, 0x30, 0UL, 0xEE, 1U );
  FD_TEST( orphan_cnt( repair )==1UL && fd_repair_orphan_map_ele_query( repair->orphan_map, &root, NULL, repair->blk_pool )==x );

  fd_repair_blk_t * b = notar( repair, 2UL, 0x20 );
  parented( repair, 2UL, 0x20, 1UL, 0x10, 1U );
  fd_repair_root_advanced( repair, 2UL, &B );
  FD_TEST( repair->root_blk==b );
  FD_TEST( orphan_cnt( repair )==1UL && fd_repair_orphan_map_ele_query( repair->orphan_map, &root, NULL, repair->blk_pool )==x );
}

/* The root advances to a blk of slot 2 we don't hold while slot 2 has
   an eager and a notar blk.  Both are freed and the slot's meta, still
   live as the root's, must not name them: it has no eager or notar. */

static void
test_root_advanced_unheld( void ) {
  fd_mr32_t         m2     = hash( 0x21 ), other = hash( 0x2F );
  fd_repair_t *     repair = setup();
  fd_repair_blk_t * n      = notar( repair, 2UL, 0x20 );
  parented( repair, 2UL, 0x20, 1UL, 0x10, 1U );
  shred0( repair, 2UL, 1UL, &hash_null, &m2 );
  ulong                   two  = 2UL;
  fd_repair_slot_meta_t * meta = fd_repair_slot_meta( repair, 2UL );
  FD_TEST( meta->notar==fd_repair_blk_pool_idx( repair->blk_pool, n ) && meta->eager!=fd_repair_blk_pool_idx_null( repair->blk_pool ) );

  fd_repair_root_advanced( repair, 2UL, &other );
  FD_TEST( repair->root==2UL && !repair->root_blk );
  FD_TEST( !fd_repair_blk_map_ele_query( repair->blk_map, &two, NULL, repair->blk_pool ) );
  FD_TEST( !fd_repair_blk_pool_used( repair->blk_pool ) );
  FD_TEST( meta->slot==2UL && meta->eager==fd_repair_blk_pool_idx_null( repair->blk_pool ) && meta->notar==fd_repair_blk_pool_idx_null( repair->blk_pool ) && meta->final==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  orphan_cnt( repair );
}

/* A signed header names (1, H) though H is slot 3's dmr.  It arrives
   first, then H's blk is created in slot 3: the child stays an orphan,
   and a sibling orphan naming (3, H) correctly links.  Its FEC set is
   not consumed under a parent replay cannot pair with it. */

static void
test_orphan_map_slot_mismatch( void ) {
  fd_mr32_t     H      = hash( 0x30 ), m4 = hash( 0x41 ), m5 = hash( 0x51 );
  fd_repair_t * repair = setup();
  ulong         four   = 4UL, five = 5UL;

  shred0  ( repair, 4UL, 1UL, &H, &m4 ); /* names (1, H) */
  complete( repair, 4UL, 1UL, 0U, 1, &m4 );
  shred0  ( repair, 5UL, 3UL, &H, &m5 ); /* names (3, H) */
  complete( repair, 5UL, 3UL, 0U, 1, &m5 );
  fd_repair_blk_t * e4 = fd_repair_blk_map_ele_query( repair->blk_map, &four, NULL, repair->blk_pool );
  fd_repair_blk_t * e5 = fd_repair_blk_map_ele_query( repair->blk_map, &five, NULL, repair->blk_pool );
  FD_TEST( orphan_cnt( repair )==2UL );

  fd_repair_blk_t * h = fd_repair_blk_notarized( repair, 3UL, &H );
  FD_TEST( h && e5->parent==fd_repair_blk_pool_idx( repair->blk_pool, h ) );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( orphan_cnt( repair )==1UL && fd_repair_orphan_map_ele_query( repair->orphan_map, &H, NULL, repair->blk_pool )==e4 );
  FD_TEST( h->child==fd_repair_blk_pool_idx( repair->blk_pool, e5 ) && e5->sibling==fd_repair_blk_pool_idx_null( repair->blk_pool ) );

  parented( repair, 3UL, 0x30, 0UL, 0xEE, 1U );
  fecs    ( repair, 3UL, 0x30, 1U );
  fd_mr32_t m3 = hash( 0x31 ); complete( repair, 3UL, 0UL, 0U, 1, &m3 );
  expect( repair, h,  0U );
  expect( repair, e5, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) && !e4->cons_fec_cnt );
  orphan_cnt( repair );
}

/* The first data shred of each FEC set past FEC set 0 is parsed for
   an UpdateParent, kept on the FEC set, also for a FEC set only a notar
   blk holds. */

static int
has_up( fd_repair_fec_t const * fec ) {
  return fec->update_parent.new_parent_slot!=ULONG_MAX;
}

static void
test_fec_update_parent( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );
  fd_mr32_t     m0 = hash( 0x30 ), m1 = hash( 0x31 ), m2 = hash( 0x32 );
  shred0( repair, 4UL, 3UL, &hash_null, &m0 );
  shred_up( repair, 4UL, 3UL, 1U, 0, 0UL, &root, &m1 );
  shred_up( repair, 4UL, 3UL, 2U, 1, 0UL, &root, &m2 );

  fd_repair_blk_t const * e4 = fd_repair_blk_pool_ele_const( repair->blk_pool, repair->slot_meta[ 4UL % repair->slot_max ].eager );
  fd_repair_fec_t const * f0 = fd_repair_fec_pool_ele_const( repair->fec_pool, e4->fecs[ 0 ] );
  fd_repair_fec_t const * f1 = fd_repair_fec_pool_ele_const( repair->fec_pool, e4->fecs[ 1 ] );
  fd_repair_fec_t const * f2 = fd_repair_fec_pool_ele_const( repair->fec_pool, e4->fecs[ 2 ] );
  FD_TEST( !has_up( f0 ) ); /* the header */
  FD_TEST( !has_up( f1 ) ); /* an entry batch */
  FD_TEST(  has_up( f2 ) && f2->update_parent.new_parent_slot==0UL && !memcmp( &f2->update_parent.new_parent_block_id, &root, sizeof(fd_mr32_t) ) );

  /* A FEC set only a notar blk holds keeps it, though the eager blk of
     an invalidated slot ignores the shred. */

  fd_mr32_t m5 = hash( 0x50 );
  fd_mr20_t k5; memcpy( k5.uc, hash( 0x52 ).uc, sizeof(fd_mr20_t) );
  fd_repair_slot_invalidated( repair, 5UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  FD_TEST( fd_repair_blk_notarized( repair, 5UL, &m5 ) );
  fd_repair_fec_t const * n2 = fd_repair_fec_notarized( repair, 5UL, &m5, 2U*FD_FEC_SHRED_CNT, &k5, 0L );
  FD_TEST( n2 && !has_up( n2 ) );
  fd_mr32_t r5 = hash( 0x52 );
  shred_up( repair, 5UL, 4UL, 2U, 1, 4UL, &m5, &r5 );
  FD_TEST( has_up( n2 ) && n2->update_parent.new_parent_slot==4UL );

  fd_repair_fini( repair );
}

/* last_dc inserts the last data shred of FEC set fec_idx of (slot,
   parent_slot) under merkle root mr, ending a data batch if dc. */

static void
last_dc( fd_repair_t *     repair,
         ulong             slot,
         ulong             parent_slot,
         uint              fec_idx,
         int               dc,
         fd_mr32_t const * mr ) {
  fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
  shred->slot            = slot;
  shred->idx             = fec_idx*FD_FEC_SHRED_CNT + FD_FEC_SHRED_CNT - 1U;
  shred->fec_set_idx     = fec_idx*FD_FEC_SHRED_CNT;
  shred->data.parent_off = (ushort)( slot-parent_slot );
  shred->data.flags      = dc ? FD_SHRED_DATA_FLAG_DATA_COMPLETE : 0;
  fd_repair_shred_insert( repair, shred, mr, 0, 0L );
}

static fd_repair_blk_t const *
eager_of( fd_repair_t const * repair,
          ulong               slot ) {
  return fd_repair_blk_pool_ele_const( repair->blk_pool, repair->slot_meta[ slot % repair->slot_max ].eager );
}

static fd_repair_blk_t const *
eager_req( fd_repair_t const * repair,
           ulong               slot ) {
  fd_repair_blk_t const * blk = eager_of( repair, slot );
  FD_TEST( blk );
  return blk;
}

/* An UpdateParent at the head of FEC set k, after FEC set k-1 ends in
   DATA_COMPLETE, reparents the eager blk from the header's parent to
   the one it names, whichever of the two is known last.  Later shreds
   still carry the header's parent offset and are accepted, and a late
   shred 0 does not undo it. */

static void
test_update_parent_reparent( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );

  /* DATA_COMPLETE first.  The header names (3, 0x33), not held, so the
     blk is an orphan until the UpdateParent names the root. */

  fd_mr32_t p3 = hash( 0x33 ), a0 = hash( 0x40 ), a1 = hash( 0x41 ), a2 = hash( 0x42 ), a3 = hash( 0x43 );
  shred0( repair, 4UL, 3UL, &p3, &a0 );
  fd_repair_blk_t const * e4 = eager_of( repair, 4UL );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && orphan_cnt( repair )==1UL );
  shred_up( repair, 4UL, 3UL, 1U, 0, 0UL, &root, &a1 );
  last_dc ( repair, 4UL, 3UL, 1U, 1, &a1 );
  FD_TEST( e4->parent_slot==3UL && !e4->init_fec_cnt );
  shred_up( repair, 4UL, 3UL, 2U, 1, 0UL, &root, &a2 );
  FD_TEST( e4->parent_slot==0UL && !memcmp( &e4->parent_blk_mr, &root, sizeof(fd_mr32_t) ) && e4->init_fec_cnt==2U );
  FD_TEST( rooted( repair, e4 ) && orphan_cnt( repair )==0UL );
  shred_up( repair, 4UL, 3UL, 3U, 0, 0UL, &root, &a3 ); /* parent offset still names slot 3 */
  FD_TEST( !repair->slot_meta[ 4UL % repair->slot_max ].invalidated && e4->fecs[ 3 ]!=fd_repair_fec_pool_idx_null( repair->fec_pool ) );
  shred0( repair, 4UL, 3UL, &p3, &a0 );
  FD_TEST( e4->parent_slot==0UL && !memcmp( &e4->parent_blk_mr, &root, sizeof(fd_mr32_t) ) && rooted( repair, e4 ) );

  /* UpdateParent first, then the last shred of FEC set k-1: without
     DATA_COMPLETE it is entry data, with it the blk reparents. */

  fd_mr32_t p11 = hash( 0x55 ), b0 = hash( 0x60 ), b1 = hash( 0x61 ), b2 = hash( 0x62 );
  shred0  ( repair, 12UL, 11UL, &p11, &b0 );
  shred_up( repair, 12UL, 11UL, 2U, 1, 0UL, &root, &b2 );
  fd_repair_blk_t const * e6 = eager_of( repair, 12UL );
  FD_TEST( e6->parent_slot==11UL && !e6->init_fec_cnt );
  shred_up( repair, 12UL, 11UL, 1U, 0, 0UL, &root, &b1 );
  last_dc ( repair, 12UL, 11UL, 1U, 0, &b1 );
  FD_TEST( e6->parent_slot==11UL && !e6->init_fec_cnt );
  last_dc ( repair, 12UL, 11UL, 1U, 1, &b1 );
  FD_TEST( e6->parent_slot==0UL && e6->init_fec_cnt==2U && rooted( repair, e6 ) && orphan_cnt( repair )==0UL );

  /* A new parent that is not held: the blk waits in orphan_map under
     it, and the new parent slot gets an eager blk to repair. */

  fd_mr32_t p7 = hash( 0x77 ), p2 = hash( 0x22 ), c0 = hash( 0x80 ), c1 = hash( 0x81 ), c2 = hash( 0x82 );
  shred0  ( repair, 8UL, 7UL, &p7, &c0 );
  shred_up( repair, 8UL, 7UL, 1U, 0, 0UL, &root, &c1 );
  last_dc ( repair, 8UL, 7UL, 1U, 1, &c1 );
  shred_up( repair, 8UL, 7UL, 2U, 1, 2UL, &p2, &c2 );
  fd_repair_blk_t const * e8 = eager_of( repair, 8UL );
  FD_TEST( e8->parent_slot==2UL && !memcmp( &e8->parent_blk_mr, &p2, sizeof(fd_mr32_t) ) && e8->init_fec_cnt==2U );
  FD_TEST( e8->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && orphan_cnt( repair )==1UL ); /* the seeded parent blks name nothing yet */
  FD_TEST( fd_repair_orphan_map_ele_query_const( repair->orphan_map, &p2, NULL, repair->blk_pool )==e8 );
  FD_TEST( repair->slot_meta[ 2UL % repair->slot_max ].eager!=fd_repair_blk_pool_idx_null( repair->blk_pool ) );

  fd_repair_fini( repair );
}

/* children returns the number of blks linked under blk and whether
   child is one of them. */

static ulong
children( fd_repair_t const *     repair,
          fd_repair_blk_t const * blk,
          fd_repair_blk_t const * child,
          int *                   found ) {
  fd_repair_blk_t const * pool = repair->blk_pool;
  ulong                   null = fd_repair_blk_pool_idx_null( pool );
  ulong                   cnt  = 0UL;
  *found = 0;
  for( ulong c=blk->child; c!=null; c=fd_repair_blk_pool_ele_const( pool, c )->sibling ) {
    *found |= fd_repair_blk_pool_ele_const( pool, c )==child;
    cnt++;
  }
  return cnt;
}

/* Two complete eager blks chain root <- 1 <- 2.  Slot 4, the first slot
   of its leader window, starts on 2 as the optimistic parent, then an
   UpdateParent at FEC set 2 names 1.  The blk moves from 2's children
   to 1's, and 2 is left childless. */

static void
test_update_parent_eager_chain( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );
  fd_mr32_t     m10   = hash( 0x11 ), m20 = hash( 0x21 );
  fd_mr32_t     m40   = hash( 0x41 ), m41 = hash( 0x42 ), m42 = hash( 0x43 ), m43 = hash( 0x44 );
  ulong         one   = 1UL, two = 2UL;

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  fd_repair_blk_t const * e1 = fd_repair_blk_map_ele_query_const( repair->blk_map, &one, NULL, repair->blk_pool );
  shred0  ( repair, 2UL, 1UL, &e1->dmr, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  fd_repair_blk_t const * e2 = fd_repair_blk_map_ele_query_const( repair->blk_map, &two, NULL, repair->blk_pool );
  FD_TEST( memcmp( &e1->dmr, &hash_null, sizeof(fd_mr32_t) ) && memcmp( &e2->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  FD_TEST( rooted( repair, e2 ) && e2->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  expect( repair, e1, 0U );
  expect( repair, e2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  /* Slot 4 starts on 2. */

  shred0  ( repair, 4UL, 2UL, &e2->dmr, &m40 );
  fd_repair_blk_t const * e4 = eager_of( repair, 4UL );
  int found;
  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, e2 ) && e4->parent_slot==2UL && !e4->init_fec_cnt );
  FD_TEST( children( repair, e2, e4, &found )==1UL && found );
  FD_TEST( children( repair, e1, e4, &found )==1UL && !found );

  /* FEC set 1 ends the data batch, FEC set 2 is the UpdateParent. */

  shred_up( repair, 4UL, 2UL, 1U, 0, 0UL, &root, &m41 );
  last_dc ( repair, 4UL, 2UL, 1U, 1, &m41 );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, e2 ) && !e4->init_fec_cnt );
  shred_up( repair, 4UL, 2UL, 2U, 1, 1UL, &e1->dmr, &m42 );

  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  FD_TEST( e4->parent_slot==1UL && !memcmp( &e4->parent_blk_mr, &e1->dmr, sizeof(fd_mr32_t) ) );
  FD_TEST( e4->init_fec_cnt==2U && e4->init_parent_slot==2UL );
  FD_TEST( children( repair, e2, e4, &found )==0UL && !found );
  FD_TEST( children( repair, e1, e4, &found )==2UL &&  found ); /* e2 and e4 */
  FD_TEST( rooted( repair, e4 ) && orphan_cnt( repair )==0UL );

  /* Later shreds still name slot 2 in their parent offset. */

  shred_up( repair, 4UL, 2UL, 3U, 0, 0UL, &root, &m43 );
  FD_TEST( !repair->slot_meta[ 4UL % repair->slot_max ].invalidated && e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, e1 ) );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_fini( repair );
}

/* invalidated returns whether slot's eager blk was given up on. */

static int
invalidated( fd_repair_t const * repair,
             ulong               slot ) {
  return repair->slot_meta[ slot % repair->slot_max ].invalidated;
}

/* up_blk builds slot's eager blk: shred 0 names (hdr_slot, hdr_mr), FEC
   set k-1 ends in DATA_COMPLETE and FEC set k is an UpdateParent naming
   (up_slot, up_mr).  FEC set j has merkle root hash( b+j ).  Returns
   the eager blk. */

static fd_repair_blk_t const *
up_blk( fd_repair_t *     repair,
        ulong             slot,
        ulong             hdr_slot,
        fd_mr32_t const * hdr_mr,
        uint              k,
        ulong             up_slot,
        fd_mr32_t const * up_mr,
        uchar             b ) {
  fd_mr32_t m0 = hash( b ), mk1 = hash( (uchar)( b+k-1U ) ), mk = hash( (uchar)( b+k ) );
  shred0( repair, slot, hdr_slot, hdr_mr, &m0 );
  if( k>1U ) shred_up( repair, slot, hdr_slot, k-1U, 0, 0UL, hdr_mr, &mk1 );
  last_dc ( repair, slot, hdr_slot, k-1U, 1, &mk1 );
  shred_up( repair, slot, hdr_slot, k, 1, up_slot, up_mr, &mk );
  return eager_req( repair, slot );
}

/* Group 1: the UpdateParent names a blk not held yet. */

static void
test_up_target_arrives_eager( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );
  fd_mr32_t     m10   = hash( 0x11 ), m20 = hash( 0x21 );

  /* Slot 2's dmr, computed by a scratch repair. */

  fd_repair_t * pre = setup_in( scratch );
  shred0  ( pre, 1UL, 0UL, &root, &m10 );
  complete( pre, 1UL, 0UL, 0U, 1, &m10 );
  ulong one = 1UL, two = 2UL;
  fd_mr32_t d1 = fd_repair_blk_map_ele_query_const( pre->blk_map, &one, NULL, pre->blk_pool )->dmr;
  shred0  ( pre, 2UL, 1UL, &d1, &m20 );
  complete( pre, 2UL, 1UL, 0U, 1, &m20 );
  fd_mr32_t d2 = fd_repair_blk_map_ele_query_const( pre->blk_map, &two, NULL, pre->blk_pool )->dmr;

  /* Slot 4 starts on (3, p3), the UpdateParent names (2, d2), neither
     held. */

  fd_mr32_t p3 = hash( 0x33 );
  fd_repair_blk_t const * e4 = up_blk( repair, 4UL, 3UL, &p3, 2U, 2UL, &d2, 0x40 );
  FD_TEST( e4->init_fec_cnt==2U && e4->parent_slot==2UL && e4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );
  FD_TEST( fd_repair_orphan_map_ele_query_const( repair->orphan_map, &d2, NULL, repair->blk_pool )==e4 );
  FD_TEST( eager_of( repair, 2UL ) );

  /* Slots 1 and 2 arrive on turbine, 2's dmr is d2. */

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  shred0  ( repair, 2UL, 1UL, &d1, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  fd_repair_blk_t const * e2 = eager_req( repair, 2UL );
  FD_TEST( !memcmp( &e2->dmr, &d2, sizeof(fd_mr32_t) ) );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, e2 ) && rooted( repair, e4 ) && orphan_cnt( repair )==0UL );
  FD_TEST( !invalidated( repair, 4UL ) );
  fd_repair_fini( repair );
}

static void
test_up_target_arrives_notar( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );
  fd_mr32_t     x     = hash( 0x20 );

  fd_mr32_t p3 = hash( 0x33 );
  fd_repair_blk_t const * e4 = up_blk( repair, 4UL, 3UL, &p3, 2U, 2UL, &x, 0x40 );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && orphan_cnt( repair )==1UL );
  (void)root;
  fd_repair_blk_t * n2 = notar( repair, 2UL, 0x20 );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, n2 ) );
  FD_TEST( !invalidated( repair, 4UL ) );
  fd_repair_fini( repair );
}

/* The duplicate switch: the UpdateParent names another version of the
   header's parent slot. */

static void
test_up_target_same_slot( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );
  fd_mr32_t     a     = hash( 0x2A ), b = hash( 0x2B );

  fd_repair_blk_t * n2a = notar( repair, 2UL, 0x2A );
  parented( repair, 2UL, 0x2A, 0UL, 0xEE, 1U );
  fd_repair_blk_t const * e4 = up_blk( repair, 4UL, 2UL, &a, 2U, 2UL, &b, 0x40 );
  FD_TEST( e4->init_fec_cnt==2U && e4->parent_slot==2UL && !memcmp( &e4->parent_blk_mr, &b, sizeof(fd_mr32_t) ) );
  int found;
  FD_TEST( !children( repair, n2a, e4, &found ) && !found );
  FD_TEST( fd_repair_orphan_map_ele_query_const( repair->orphan_map, &b, NULL, repair->blk_pool )==e4 );

  fd_repair_blk_t * n2b = notar( repair, 2UL, 0x2B );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, n2b ) );
  FD_TEST( !invalidated( repair, 4UL ) );
  (void)root;
  fd_repair_fini( repair );
}

/* Group 2: the header's parent is not held. */

static void
test_up_orig_parent_missing( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );
  fd_mr32_t     m10   = hash( 0x11 ), m20 = hash( 0x21 );

  /* The header names (2, d2), slot 2 has not arrived.  The UpdateParent
     names the root. */

  fd_repair_t * pre = setup_in( scratch );
  shred0  ( pre, 1UL, 0UL, &root, &m10 );
  complete( pre, 1UL, 0UL, 0U, 1, &m10 );
  ulong one = 1UL, two = 2UL;
  fd_mr32_t d1 = fd_repair_blk_map_ele_query_const( pre->blk_map, &one, NULL, pre->blk_pool )->dmr;
  shred0  ( pre, 2UL, 1UL, &d1, &m20 );
  complete( pre, 2UL, 1UL, 0U, 1, &m20 );
  fd_mr32_t d2 = fd_repair_blk_map_ele_query_const( pre->blk_map, &two, NULL, pre->blk_pool )->dmr;

  fd_mr32_t m40 = hash( 0x40 );
  shred0( repair, 4UL, 2UL, &d2, &m40 );
  fd_repair_blk_t const * e4 = eager_of( repair, 4UL );
  FD_TEST( fd_repair_orphan_map_ele_query_const( repair->orphan_map, &d2, NULL, repair->blk_pool )==e4 );
  FD_TEST( eager_of( repair, 2UL ) ); /* seeded by the header */

  fd_mr32_t m41 = hash( 0x41 ), m42 = hash( 0x42 );
  shred_up( repair, 4UL, 2UL, 1U, 0, 0UL, &root, &m41 );
  last_dc ( repair, 4UL, 2UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 2UL, 2U, 1, 0UL, &root, &m42 );
  FD_TEST( e4->init_fec_cnt==2U && rooted( repair, e4 ) && !e4->orphan_req );
  FD_TEST( !fd_repair_orphan_map_ele_query_const( repair->orphan_map, &d2, NULL, repair->blk_pool ) && orphan_cnt( repair )==0UL );

  /* Slot 2 arrives and completes with dmr d2: slot 4 is not linked under
     it again. */

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  shred0  ( repair, 2UL, 1UL, &d1, &m20 );
  complete( repair, 2UL, 1UL, 0U, 1, &m20 );
  fd_repair_blk_t const * e2 = eager_req( repair, 2UL );
  FD_TEST( !memcmp( &e2->dmr, &d2, sizeof(fd_mr32_t) ) );
  int found;
  FD_TEST( !children( repair, e2, e4, &found ) && !found );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, repair->root_blk ) );
  fd_repair_fini( repair );
}

static void
test_up_orig_parent_skipped( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE ), p2 = hash( 0x22 );
  fd_mr32_t     m40   = hash( 0x40 ), m41 = hash( 0x41 ), m42 = hash( 0x42 );

  shred0( repair, 4UL, 2UL, &p2, &m40 );
  fd_repair_slot_skipped( repair, 2UL );
  FD_TEST( !eager_of( repair, 2UL ) );
  shred_up( repair, 4UL, 2UL, 1U, 0, 0UL, &root, &m41 );
  last_dc ( repair, 4UL, 2UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 2UL, 2U, 1, 0UL, &root, &m42 );
  fd_repair_blk_t const * e4 = eager_of( repair, 4UL );
  FD_TEST( e4->init_fec_cnt==2U && rooted( repair, e4 ) && orphan_cnt( repair )==0UL );
  FD_TEST( !eager_of( repair, 2UL ) );

  /* A skipped new parent slot is not seeded either. */

  fd_mr32_t p6 = hash( 0x66 ), m80 = hash( 0x80 ), m81 = hash( 0x81 ), m82 = hash( 0x82 );
  fd_repair_slot_skipped( repair, 6UL );
  shred0  ( repair, 8UL, 7UL, &root, &m80 );
  shred_up( repair, 8UL, 7UL, 1U, 0, 0UL, &root, &m81 );
  last_dc ( repair, 8UL, 7UL, 1U, 1, &m81 );
  shred_up( repair, 8UL, 7UL, 2U, 1, 6UL, &p6, &m82 );
  FD_TEST( eager_of( repair, 8UL )->init_fec_cnt==2U && !eager_of( repair, 6UL ) );
  fd_repair_fini( repair );
}

/* Group 3: blks discovered through fd_repair_blk_notarized. */

static void
test_up_eager_dmr( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE ), p2 = hash( 0x22 );

  /* Slot 4 starts on (2, p2) and moves to the root, then completes. */

  fd_repair_blk_t const * e4 = up_blk( repair, 4UL, 2UL, &p2, 2U, 0UL, &root, 0x40 );
  fd_mr32_t m40 = hash( 0x40 ), m41 = hash( 0x41 ), m42 = hash( 0x42 );
  complete( repair, 4UL, 2UL, 0U, 0, &m40 );
  complete( repair, 4UL, 2UL, 1U, 0, &m41 );
  complete( repair, 4UL, 2UL, 2U, 1, &m42 );
  FD_TEST( memcmp( &e4->dmr, &hash_null, sizeof(fd_mr32_t) ) );

  /* The same FEC roots under a header naming the root directly. */

  fd_repair_t * pre = setup_in( scratch );
  shred0  ( pre, 4UL, 0UL, &root, &m40 );
  complete( pre, 4UL, 0UL, 0U, 0, &m40 );
  complete( pre, 4UL, 0UL, 1U, 0, &m41 );
  complete( pre, 4UL, 0UL, 2U, 1, &m42 );
  FD_TEST( !memcmp( &e4->dmr, &eager_req( pre, 4UL )->dmr, sizeof(fd_mr32_t) ) );
  fd_repair_fini( repair );
}

/* notar_up gives the notar blk (slot, dmr) FEC sets 0..k by id under
   merkle roots hash( b+j ), the shreds that make FEC set k-1 end in
   DATA_COMPLETE and FEC set k an UpdateParent naming (up_slot, up_mr). */

static void
notar_up( fd_repair_t *     repair,
          ulong             slot,
          uchar             dmr,
          ulong             hdr_slot,
          uint              k,
          ulong             up_slot,
          fd_mr32_t const * up_mr,
          uchar             b ) {
  fd_mr32_t id = hash( dmr );
  for( uint j=0U; j<=k; j++ ) {
    fd_mr32_t mr = hash( (uchar)( b+j ) );
    fd_mr20_t key; memcpy( key.uc, mr.uc, sizeof(fd_mr20_t) );
    FD_TEST( fd_repair_fec_notarized( repair, slot, &id, j*FD_FEC_SHRED_CNT, &key, 0L ) );
  }
  fd_mr32_t mk1 = hash( (uchar)( b+k-1U ) ), mk = hash( (uchar)( b+k ) );
  last_dc ( repair, slot, hdr_slot, k-1U, 1, &mk1 );
  shred_up( repair, slot, hdr_slot, k, 1, up_slot, up_mr, &mk );
}

static void
test_up_notar_only( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );

  /* Slot 4 is invalidated, its notar blk is proven to sit on the root
     and its shreds name slot 2 as the optimistic parent. */

  fd_repair_slot_invalidated( repair, 4UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fd_repair_blk_t * n4 = notar( repair, 4UL, 0x4D );
  parented( repair, 4UL, 0x4D, 0UL, 0xEE, 3U );
  FD_TEST( rooted( repair, n4 ) && !n4->init_fec_cnt );
  notar_up( repair, 4UL, 0x4D, 2UL, 2U, 0UL, &root, 0x40 );
  FD_TEST( n4->init_fec_cnt==2U && rooted( repair, n4 ) && n4->parent_slot==0UL );
  fd_repair_fini( repair );
}

static void
test_up_notar_parented_late( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );

  fd_repair_slot_invalidated( repair, 4UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fd_repair_blk_t * n4 = notar( repair, 4UL, 0x4D );
  notar_up( repair, 4UL, 0x4D, 2UL, 2U, 0UL, &root, 0x40 );
  FD_TEST( n4->init_fec_cnt==2U && n4->parent_slot==ULONG_MAX );
  parented( repair, 4UL, 0x4D, 0UL, 0xEE, 3U );
  FD_TEST( n4->init_fec_cnt==2U && rooted( repair, n4 ) );
  fd_repair_fini( repair );
}

/* The shreds that make FEC set 1 end in DATA_COMPLETE and FEC set 2 an
   UpdateParent arrive before the FecSetRoot proofs that attach those
   FEC sets to the notar blk.  Shred insert runs detection while the
   notar blk does not hold them yet, so attaching each cached FEC set
   must rerun it, whichever of the two is attached last, and nothing
   of the prefix may be consumed. */

static void
test_up_notar_proofs_after_shreds( int up_last ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE );
  fd_mr32_t     id    = hash( 0x4D );

  /* Turbine (the eager blk of slot 4) caches the FEC sets, so the slot
     must not be invalidated. */
  fd_repair_blk_t * n4 = notar( repair, 4UL, 0x4D );
  parented( repair, 4UL, 0x4D, 0UL, 0xEE, 3U );
  FD_TEST( rooted( repair, n4 ) );

  fd_mr32_t m41 = hash( 0x41 ), m42 = hash( 0x42 );
  last_dc ( repair, 4UL, 2UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 2UL, 2U, 1, 0UL, &root, &m42 );
  FD_TEST( !n4->init_fec_cnt ); /* the notar blk holds neither FEC set yet */

  fd_repair_deque_remove_all( repair->reasm_deque );
  for( uint i=0U; i<3U; i++ ) {
    uint      j  = up_last ? i : (uint[]){ 0U, 2U, 1U }[ i ]; /* FEC set 2 attached last, or FEC set 1 */
    fd_mr32_t mr = hash( (uchar)( 0x40+j ) );
    fd_mr20_t key; memcpy( key.uc, mr.uc, sizeof(fd_mr20_t) );
    fd_repair_fec_notarized( repair, 4UL, &id, j*FD_FEC_SHRED_CNT, &key, 0L );
  }
  FD_TEST( n4->init_fec_cnt==2U && n4->cons_fec_cnt>=2U );

  /* FEC set 0 completed while attaching, but it is the prefix. */
  while( !fd_repair_deque_empty( repair->reasm_deque ) ) FD_TEST( fd_repair_deque_pop_head( repair->reasm_deque ).fec_idx>=2U );
  fd_repair_fini( repair );
}

/* Version A, notar with an UpdateParent to the root, and version B,
   turbine, still on its header's parent, share FEC set 0.  B, an
   orphan, must not take A's parent. */

static void
test_up_consume_merge_equivocation( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE ), p2 = hash( 0x22 );
  fd_mr32_t     m40   = hash( 0x40 );

  shred0  ( repair, 4UL, 2UL, &p2, &m40 );
  complete( repair, 4UL, 2UL, 0U, 0, &m40 );
  fd_repair_blk_t const * b4 = eager_of( repair, 4UL );
  FD_TEST( b4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) );

  fd_repair_blk_t * a4 = notar( repair, 4UL, 0x4A );
  fd_mr20_t k0; memcpy( k0.uc, m40.uc, sizeof(fd_mr20_t) );
  FD_TEST( fd_repair_fec_notarized( repair, 4UL, &a4->dmr, 0U, &k0, 0L ) );
  parented( repair, 4UL, 0x4A, 0UL, 0xEE, 3U );
  FD_TEST( rooted( repair, a4 ) );
  FD_TEST( b4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && b4->parent_slot==2UL && !memcmp( &b4->parent_blk_mr, &p2, sizeof(fd_mr32_t) ) );
  (void)root;
  fd_repair_fini( repair );
}

/* Group 4: multiple UpdateParents and the rules. */

static void
test_up_multiple( void ) {
  fd_mr32_t root = hash( 0xEE ), p2 = hash( 0x22 ), p1 = hash( 0x11 );

  /* In order: k=2 then k=3. */

  fd_repair_t * repair = setup();
  fd_repair_blk_t const * e4 = up_blk( repair, 4UL, 2UL, &p2, 2U, 0UL, &root, 0x40 );
  FD_TEST( e4->init_fec_cnt==2U && !invalidated( repair, 4UL ) );
  fd_mr32_t m42 = hash( 0x42 ), m43 = hash( 0x43 );
  last_dc ( repair, 4UL, 2UL, 2U, 1, &m42 );
  shred_up( repair, 4UL, 2UL, 3U, 1, 1UL, &p1, &m43 );
  FD_TEST( invalidated( repair, 4UL ) );
  fd_repair_fini( repair );

  /* Reverse: k=3 is confirmed first, then k=2. */

  repair = setup();
  fd_mr32_t m40 = hash( 0x40 ), m41 = hash( 0x41 );
  shred0  ( repair, 4UL, 2UL, &p2, &m40 );
  shred_up( repair, 4UL, 2UL, 2U, 1, 0UL, &root, &m42 );
  last_dc ( repair, 4UL, 2UL, 2U, 1, &m42 );
  shred_up( repair, 4UL, 2UL, 3U, 1, 1UL, &p1, &m43 );
  FD_TEST( eager_of( repair, 4UL )->init_fec_cnt==3U && !invalidated( repair, 4UL ) );
  shred_up( repair, 4UL, 2UL, 1U, 0, 0UL, &root, &m41 );
  last_dc ( repair, 4UL, 2UL, 1U, 1, &m41 );
  FD_TEST( invalidated( repair, 4UL ) );
  fd_repair_fini( repair );
}

static void
test_up_duplicate_and_decoy( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE ), p2 = hash( 0x22 ), p1 = hash( 0x11 );

  /* The marker shred and the DATA_COMPLETE shred again. */

  fd_repair_blk_t const * e4 = up_blk( repair, 4UL, 2UL, &p2, 2U, 0UL, &root, 0x40 );
  fd_mr32_t m41 = hash( 0x41 ), m42 = hash( 0x42 );
  shred_up( repair, 4UL, 2UL, 2U, 1, 0UL, &root, &m42 );
  last_dc ( repair, 4UL, 2UL, 1U, 1, &m41 );
  FD_TEST( e4->init_fec_cnt==2U && !invalidated( repair, 4UL ) && rooted( repair, e4 ) );

  /* Marker bytes at k=1 after a FEC set without DATA_COMPLETE are entry
     data, the real one is at k=2. */

  fd_mr32_t m80 = hash( 0x80 ), m81 = hash( 0x81 ), m82 = hash( 0x82 );
  shred0  ( repair, 8UL, 2UL, &p2, &m80 );
  last_dc ( repair, 8UL, 2UL, 0U, 0, &m80 );
  shred_up( repair, 8UL, 2UL, 1U, 1, 1UL, &p1, &m81 );
  last_dc ( repair, 8UL, 2UL, 1U, 1, &m81 );
  shred_up( repair, 8UL, 2UL, 2U, 1, 0UL, &root, &m82 );
  fd_repair_blk_t const * e8 = eager_of( repair, 8UL );
  FD_TEST( e8->init_fec_cnt==2U && e8->parent_slot==0UL && !invalidated( repair, 8UL ) );
  fd_repair_fini( repair );
}

static void
test_up_rules( void ) {
  fd_mr32_t root = hash( 0xEE ), p2 = hash( 0x22 ), p3 = hash( 0x33 );

  /* Not the first slot of its leader window. */

  fd_repair_t * repair = setup();
  up_blk( repair, 5UL, 2UL, &p2, 2U, 0UL, &root, 0x50 );
  FD_TEST( invalidated( repair, 5UL ) );
  fd_repair_fini( repair );

  /* A parent newer than the header's. */

  repair = setup();
  up_blk( repair, 4UL, 2UL, &p2, 2U, 3UL, &p3, 0x40 );
  FD_TEST( invalidated( repair, 4UL ) );
  fd_repair_fini( repair );

  /* A null parent block id. */

  repair = setup();
  up_blk( repair, 4UL, 2UL, &p2, 2U, 1UL, &hash_null, 0x40 );
  FD_TEST( invalidated( repair, 4UL ) );
  fd_repair_fini( repair );

  /* The header's own parent, shred 0 first. */

  repair = setup();
  up_blk( repair, 4UL, 2UL, &p2, 2U, 2UL, &p2, 0x40 );
  FD_TEST( invalidated( repair, 4UL ) );
  fd_repair_fini( repair );

  /* The header's own parent, shred 0 last. */

  repair = setup();
  fd_mr32_t m40 = hash( 0x40 ), m41 = hash( 0x41 ), m42 = hash( 0x42 );
  shred_up( repair, 4UL, 2UL, 1U, 0, 0UL, &root, &m41 );
  last_dc ( repair, 4UL, 2UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 2UL, 2U, 1, 2UL, &p2, &m42 );
  FD_TEST( !invalidated( repair, 4UL ) && eager_of( repair, 4UL )->init_fec_cnt==2U );
  shred0  ( repair, 4UL, 2UL, &p2, &m40 );
  FD_TEST( invalidated( repair, 4UL ) );
  fd_repair_fini( repair );

  /* An UpdateParent in place of the header. */

  repair = setup();
  uchar buf[ FD_SHRED_MIN_SZ ] __attribute__((aligned(8UL))); memset( buf, 0, sizeof(buf) );
  uchar * ser = buf+FD_SHRED_DATA_HEADER_SZ; ulong off = 0UL;
  FD_STORE( ulong,  ser+off, 0UL );                             off += sizeof(ulong);
  FD_STORE( ushort, ser+off, (ushort)1 );                       off += sizeof(ushort);
  ser[ off ] = (uchar)FD_BLOCK_MARKER_KIND_UPDATE_PARENT;       off += sizeof(uchar);
  FD_STORE( ushort, ser+off, (ushort)FD_UPDATE_PARENT_SER_SZ ); off += sizeof(ushort);
  ser[ off ] = (uchar)1;                                        off += sizeof(uchar);
  FD_STORE( ulong,  ser+off, 0UL );                             off += sizeof(ulong);
  memcpy( ser+off, root.uc, sizeof(fd_mr32_t) );                off += sizeof(fd_mr32_t);
  fd_shred_t * shred = (fd_shred_t *)buf;
  shred->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 6 );
  shred->slot            = 4UL;
  shred->data.parent_off = 2;
  shred->data.size       = (ushort)( FD_SHRED_DATA_HEADER_SZ+off );
  fd_repair_shred_insert( repair, shred, &m40, 0, 0L );
  FD_TEST( invalidated( repair, 4UL ) );
  fd_repair_fini( repair );
}

/* A parent below the root, with the root advanced to 1. */

static void
test_up_below_root( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE ), m10 = hash( 0x11 ), p3 = hash( 0x33 );
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  fd_mr32_t d1 = eager_req( repair, 1UL )->dmr;
  fd_repair_root_advanced( repair, 1UL, &d1 );
  FD_TEST( repair->root==1UL );
  up_blk( repair, 4UL, 3UL, &p3, 2U, 0UL, &root, 0x40 );
  FD_TEST( invalidated( repair, 4UL ) );
  fd_repair_fini( repair );
}

/* drain pops the reasm deque into out, returns the count. */

static ulong
drain( fd_repair_t *       repair,
       fd_repair_deque_t * out,
       ulong               max ) {
  ulong cnt = 0UL;
  while( !fd_repair_deque_empty( repair->reasm_deque ) ) {
    fd_repair_deque_t o = fd_repair_deque_pop_head( repair->reasm_deque );
    FD_TEST( cnt<max );
    out[ cnt++ ] = o;
  }
  return cnt;
}

/* order_setup builds root <- 1 <- 3, both delivered, and slot 2 by id
   on 1 with 2 FEC sets, the first complete and delivered: N2 is partly
   consumed.  Returns N2, d3 in *d3 and the notar id in *d2. */

static fd_repair_blk_t *
order_setup( fd_repair_t * repair,
             fd_mr32_t *   d2,
             fd_mr32_t *   d3 ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m20 = hash( 0x21 ), m21 = hash( 0x22 ), m30 = hash( 0x31 );
  fd_mr20_t k20; memcpy( k20.uc, m20.uc, sizeof(fd_mr20_t) );
  fd_mr20_t k21; memcpy( k21.uc, m21.uc, sizeof(fd_mr20_t) );
  *d2 = hash( 0x2D );

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  fd_mr32_t d1 = eager_req( repair, 1UL )->dmr;

  fd_repair_slot_invalidated( repair, 2UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L ); /* N2 alone carries slot 2 */
  fd_repair_blk_t * n2 = fd_repair_blk_notarized( repair, 2UL, d2 );
  fd_repair_blk_parented ( repair, 2UL, d2, 1UL, &d1, 2U, 0L );
  fd_repair_fec_notarized( repair, 2UL, d2, 0U,               &k20, 0L );
  fd_repair_fec_notarized( repair, 2UL, d2, FD_FEC_SHRED_CNT, &k21, 0L );
  complete( repair, 2UL, 1UL, 0U, 0, &m20 );
  FD_TEST( n2->cons_fec_cnt==1U && n2->cmpl_fec_cnt==2U );

  shred0  ( repair, 3UL, 1UL, &d1, &m30 );
  complete( repair, 3UL, 1UL, 0U, 1, &m30 );
  *d3 = eager_req( repair, 3UL )->dmr;

  fd_repair_deque_t out[ 8 ];
  drain( repair, out, 8UL );
  return n2;
}

/* The optimistic prefix of slot 4 went out on slot 3, then the
   UpdateParent at FEC set 2 names N2, partly consumed.  FEC set 2 waits
   for N2's last FEC set. */

static void
test_up_waits_for_new_parent( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     d2, d3;
  fd_repair_blk_t * n2 = order_setup( repair, &d2, &d3 );
  fd_mr32_t m40 = hash( 0x41 ), m41 = hash( 0x42 ), m42 = hash( 0x43 ), m21 = hash( 0x22 );

  shred0  ( repair, 4UL, 3UL, &d3, &m40 );
  complete( repair, 4UL, 3UL, 0U, 0, &m40 );
  complete( repair, 4UL, 3UL, 1U, 0, &m41 );
  last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );
  fd_repair_blk_t const * e4 = eager_req( repair, 4UL );
  expect( repair, e4, 0U ); expect( repair, e4, 1U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) && e4->cons_fec_cnt==2U );

  shred_up( repair, 4UL, 3UL, 2U, 1, 2UL, &d2, &m42 );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, n2 ) && e4->init_fec_cnt==2U && e4->cons_fec_cnt==2U );
  complete( repair, 4UL, 3UL, 2U, 1, &m42 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) ); /* N2 still owes FEC set 1 */

  complete( repair, 2UL, 1UL, 1U, 1, &m21 );
  expect( repair, n2, 1U );
  expect( repair, e4, 2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  fd_repair_fini( repair );
}

/* The prefix went out only in part, FEC set 0 of 2: FEC set 1 is never
   delivered, the stream starts at FEC set 2 once N2 is done. */

static void
test_up_skips_rest_of_prefix( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     d2, d3;
  fd_repair_blk_t * n2 = order_setup( repair, &d2, &d3 );
  fd_mr32_t m40 = hash( 0x41 ), m41 = hash( 0x42 ), m42 = hash( 0x43 ), m21 = hash( 0x22 );

  shred0  ( repair, 4UL, 3UL, &d3, &m40 );
  complete( repair, 4UL, 3UL, 0U, 0, &m40 );
  fd_repair_blk_t const * e4 = eager_req( repair, 4UL );
  expect( repair, e4, 0U );
  FD_TEST( e4->cons_fec_cnt==1U );

  last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 3UL, 2U, 1, 2UL, &d2, &m42 );
  FD_TEST( e4->init_fec_cnt==2U && e4->cons_fec_cnt==2U );
  complete( repair, 4UL, 3UL, 1U, 0, &m41 );
  complete( repair, 4UL, 3UL, 2U, 1, &m42 );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  complete( repair, 2UL, 1UL, 1U, 1, &m21 );
  expect( repair, n2, 1U );
  expect( repair, e4, 2U ); /* not FEC set 1 */
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  fd_repair_fini( repair );
}

/* The UpdateParent names a blk not held, cons_fec_cnt 0.  When it is
   held but partly consumed, the stream still waits for it. */

static void
test_up_orphan_then_partial_parent( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE ), p3 = hash( 0x33 ), d2 = hash( 0x2D );
  fd_mr32_t     m10   = hash( 0x11 ), m20 = hash( 0x21 ), m21 = hash( 0x22 );
  fd_mr20_t     k20; memcpy( k20.uc, m20.uc, sizeof(fd_mr20_t) );
  fd_mr20_t     k21; memcpy( k21.uc, m21.uc, sizeof(fd_mr20_t) );
  fd_mr32_t     m40 = hash( 0x41 ), m41 = hash( 0x42 ), m42 = hash( 0x43 );

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  fd_mr32_t d1 = eager_req( repair, 1UL )->dmr;
  fd_repair_deque_t out[ 8 ];
  drain( repair, out, 8UL );

  shred0  ( repair, 4UL, 3UL, &p3, &m40 );
  last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 3UL, 2U, 1, 2UL, &d2, &m42 );
  complete( repair, 4UL, 3UL, 0U, 0, &m40 );
  complete( repair, 4UL, 3UL, 1U, 0, &m41 );
  complete( repair, 4UL, 3UL, 2U, 1, &m42 );
  fd_repair_blk_t const * e4 = eager_req( repair, 4UL );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx_null( repair->blk_pool ) && e4->init_fec_cnt==2U && e4->cons_fec_cnt==2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  fd_repair_slot_invalidated( repair, 2UL, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, 0L );
  fd_repair_blk_t * n2 = fd_repair_blk_notarized( repair, 2UL, &d2 );
  FD_TEST( e4->parent==fd_repair_blk_pool_idx( repair->blk_pool, n2 ) );
  fd_repair_blk_parented ( repair, 2UL, &d2, 1UL, &d1, 2U, 0L );
  fd_repair_fec_notarized( repair, 2UL, &d2, 0U,               &k20, 0L );
  fd_repair_fec_notarized( repair, 2UL, &d2, FD_FEC_SHRED_CNT, &k21, 0L );
  complete( repair, 2UL, 1UL, 0U, 0, &m20 );
  expect( repair, n2, 0U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  complete( repair, 2UL, 1UL, 1U, 1, &m21 );
  expect( repair, n2, 1U );
  expect( repair, e4, 2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  fd_repair_fini( repair );
}

/* A redelivery after the reparent resends slot 4 from FEC set 2, after
   its new ancestry, never its prefix. */

static void
test_up_reconsume( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE ), p3 = hash( 0x33 );
  fd_mr32_t     m10   = hash( 0x11 ), m40 = hash( 0x41 ), m41 = hash( 0x42 ), m42 = hash( 0x43 ), m43 = hash( 0x44 ), m44 = hash( 0x45 );

  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  fd_repair_blk_t const * e1 = eager_req( repair, 1UL );
  fd_mr32_t d1 = e1->dmr;
  expect( repair, e1, 0U );

  shred0  ( repair, 4UL, 3UL, &p3, &m40 );
  last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 3UL, 2U, 1, 1UL, &d1, &m42 );
  complete( repair, 4UL, 3UL, 0U, 0, &m40 );
  complete( repair, 4UL, 3UL, 1U, 0, &m41 );
  complete( repair, 4UL, 3UL, 2U, 0, &m42 );
  fd_repair_blk_t const * e4 = eager_req( repair, 4UL );
  expect( repair, e4, 2U );
  complete( repair, 4UL, 3UL, 3U, 0, &m43 );
  expect( repair, e4, 3U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );

  repair->reconsume = 1;
  complete( repair, 4UL, 3UL, 4U, 1, &m44 );
  expect( repair, e1, 0U );
  expect( repair, e4, 2U ); expect( repair, e4, 3U ); expect( repair, e4, 4U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  fd_repair_fini( repair );
}

/* Slots 8 and 4 both wait in orphan_map under (3, p3), 4 inserted last
   so it heads the chain.  4's UpdateParent names the root, held: 4 is
   linked and 8 still waits under p3, orphan_map intact. */

static void
test_up_orphan_map_neighbour( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root  = hash( 0xEE ), p3 = hash( 0x33 );
  fd_mr32_t     m80   = hash( 0x80 ), m40 = hash( 0x41 ), m41 = hash( 0x42 ), m42 = hash( 0x43 );

  shred0( repair, 8UL, 3UL, &p3, &m80 );
  shred0( repair, 4UL, 3UL, &p3, &m40 );
  fd_repair_blk_t const * e8 = eager_req( repair, 8UL );
  fd_repair_blk_t const * e4 = eager_req( repair, 4UL );
  FD_TEST( orphan_cnt( repair )==2UL );

  last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 3UL, 2U, 1, 0UL, &root, &m42 );
  FD_TEST( e4->init_fec_cnt==2U && rooted( repair, e4 ) );
  FD_TEST( orphan_cnt( repair )==1UL ); /* verifies orphan_map and that e8 is found under p3 */
  FD_TEST( fd_repair_orphan_map_ele_query_const( repair->orphan_map, &p3, NULL, repair->blk_pool )==e8 );
  fd_repair_fini( repair );
}

/* FEC set k, the UpdateParent, is never delivered on the old parent:
   it can only go out once FEC sets k-1 and k are complete, which needs
   the last shred of k-1 and shred 32k, and those two inserts confirm
   the marker first.  Replay relies on this (see
   test_process_rotor_fec_optimistic_bank).  Every arrival order of the
   four shreds and two completions that matter is tried. */

static void
test_up_never_sends_marker_fec_early( void ) {
  /* 0: shred 32k (UpdateParent), 1: last shred of k-1 (DATA_COMPLETE),
     2: FEC set k-1 completes, 3: FEC set k completes.  2 needs 1, 3
     needs 0. */
  static int const orders[][ 4 ] = {
    { 0, 1, 2, 3 }, { 0, 1, 3, 2 }, { 0, 3, 1, 2 },
    { 1, 0, 2, 3 }, { 1, 0, 3, 2 }, { 1, 2, 0, 3 },
  };
  for( ulong o=0UL; o<sizeof(orders)/sizeof(orders[0]); o++ ) {
    fd_repair_t * repair = setup();
    fd_mr32_t     root  = hash( 0xEE ), m10 = hash( 0x11 ), m30 = hash( 0x31 );
    fd_mr32_t     m40   = hash( 0x41 ), m41 = hash( 0x42 ), m42 = hash( 0x43 );

    shred0  ( repair, 1UL, 0UL, &root, &m10 );
    complete( repair, 1UL, 0UL, 0U, 1, &m10 );
    fd_mr32_t d1 = eager_req( repair, 1UL )->dmr;
    shred0  ( repair, 3UL, 1UL, &d1, &m30 );
    complete( repair, 3UL, 1UL, 0U, 1, &m30 );
    fd_mr32_t d3 = eager_req( repair, 3UL )->dmr;
    fd_repair_deque_t out[ 16 ];
    drain( repair, out, 16UL );

    /* Slot 4 on 3, FEC set 0 delivered, the UpdateParent at FEC set 2
       names 1. */
    shred0  ( repair, 4UL, 3UL, &d3, &m40 );
    complete( repair, 4UL, 3UL, 0U, 0, &m40 );
    fd_repair_blk_t const * e4 = eager_req( repair, 4UL );
    expect( repair, e4, 0U );

    for( ulong i=0UL; i<4UL; i++ ) {
      switch( orders[ o ][ i ] ) {
      case 0: shred_up( repair, 4UL, 3UL, 2U, 1, 1UL, &d1, &m42 ); break;
      case 1: last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );           break;
      case 2: { /* its last shred is the DATA_COMPLETE one */
        fd_shred_t shred[1]; memset( shred, 0, sizeof(fd_shred_t) );
        shred->slot            = 4UL;
        shred->idx             = 2U*FD_FEC_SHRED_CNT - 1U;
        shred->data.parent_off = 1;
        shred->data.flags      = FD_SHRED_DATA_FLAG_DATA_COMPLETE;
        fd_repair_fec_complete( repair, shred, &m41, 0, 0U, 0U, 0U, 0U, 0U, 0U, 0L );
        break;
      }
      case 3: complete( repair, 4UL, 3UL, 2U, 1, &m42 );           break;
      }
      ulong cnt = drain( repair, out, 16UL );
      for( ulong j=0UL; j<cnt; j++ ) {
        if( out[ j ].blk_idx!=fd_repair_blk_pool_idx( repair->blk_pool, e4 ) ) continue;
        if( out[ j ].fec_idx==1U ) FD_TEST( !e4->init_fec_cnt );                            /* the prefix only goes out before the marker is known */
        if( out[ j ].fec_idx==2U ) FD_TEST( e4->init_fec_cnt==2U && e4->parent_slot==1UL ); /* FEC set k only on the new parent */
      }
    }
    FD_TEST( e4->init_fec_cnt==2U && e4->cons_fec_cnt==3U && e4->parent_slot==1UL );
    fd_repair_fini( repair );
  }
}

/* SLOT_DEAD for the turbine version of the first slot of a leader
   window.  The leader may cut the optimistic prefix off anywhere, since
   it is building an UpdateParent, so replay killing it is not the end of
   the block: the slot is invalidated only when the stream that died is
   the one after a confirmed UpdateParent.  latest_fec_idx is the
   highest FEC set the dead bank held, not necessarily the one that
   failed. */

/* up_dead_setup: slot 4 on slot 3, FEC set 0 delivered, its eager blk
   returned.  The UpdateParent, once confirmed, is at FEC set 2 naming
   slot 1. */

static fd_repair_blk_t const *
up_dead_setup( fd_repair_t * repair,
               fd_mr32_t *   d1 ) {
  fd_mr32_t root = hash( 0xEE ), m10 = hash( 0x11 ), m30 = hash( 0x31 ), m40 = hash( 0x41 );
  shred0  ( repair, 1UL, 0UL, &root, &m10 );
  complete( repair, 1UL, 0UL, 0U, 1, &m10 );
  *d1 = eager_req( repair, 1UL )->dmr;
  shred0  ( repair, 3UL, 1UL, d1, &m30 );
  complete( repair, 3UL, 1UL, 0U, 1, &m30 );
  fd_mr32_t d3 = eager_req( repair, 3UL )->dmr;
  fd_repair_deque_t out[ 8 ];
  drain( repair, out, 8UL );
  shred0  ( repair, 4UL, 3UL, &d3, &m40 );
  complete( repair, 4UL, 3UL, 0U, 0, &m40 );
  fd_repair_blk_t const * e4 = eager_req( repair, 4UL );
  expect( repair, e4, 0U );
  return e4;
}

/* The prefix dies before the marker is known: not invalidated, and the
   block goes on to replay from the UpdateParent on the new parent. */

static void
test_up_dead_prefix_then_marker( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     d1;
  fd_repair_blk_t const * e4 = up_dead_setup( repair, &d1 );
  fd_mr32_t m41 = hash( 0x42 ), m42 = hash( 0x43 );

  fd_repair_blk_dead( repair, 4UL, &hash_null, 0U );
  FD_TEST( !invalidated( repair, 4UL ) && e4->eager && e4->in_blk_treap );

  last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 3UL, 2U, 1, 1UL, &d1, &m42 );
  FD_TEST( e4->init_fec_cnt==2U && e4->parent_slot==1UL );
  complete( repair, 4UL, 3UL, 1U, 0, &m41 );
  complete( repair, 4UL, 3UL, 2U, 1, &m42 );
  expect( repair, e4, 2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) && !invalidated( repair, 4UL ) );
  fd_repair_fini( repair );
}

/* The prefix dies and the slot completes without an UpdateParent: still
   not invalidated by repair.  Replay's bank is dead, so the block is never
   completed or voted on, and it is only kept for repair. */

static void
test_up_dead_prefix_no_marker( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     d1;
  fd_repair_blk_t const * e4 = up_dead_setup( repair, &d1 );
  fd_mr32_t m41 = hash( 0x42 );

  fd_repair_blk_dead( repair, 4UL, &hash_null, 0U );
  complete( repair, 4UL, 3UL, 1U, 1, &m41 );
  FD_TEST( !invalidated( repair, 4UL ) && !e4->init_fec_cnt && memcmp( &e4->dmr, &hash_null, sizeof(fd_mr32_t) ) );
  fd_repair_fini( repair );
}

/* The stream after the UpdateParent dies: the block itself is invalid,
   so the slot is invalidated. */

static void
test_up_dead_after_marker( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     d1;
  fd_repair_blk_t const * e4 = up_dead_setup( repair, &d1 );
  fd_mr32_t m41 = hash( 0x42 ), m42 = hash( 0x43 );

  last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 3UL, 2U, 1, 1UL, &d1, &m42 );
  complete( repair, 4UL, 3UL, 1U, 0, &m41 );
  complete( repair, 4UL, 3UL, 2U, 0, &m42 );
  expect( repair, e4, 2U );

  fd_repair_blk_dead( repair, 4UL, &hash_null, 2U*FD_FEC_SHRED_CNT );
  FD_TEST( invalidated( repair, 4UL ) && !e4->eager && !e4->in_blk_treap );
  fd_repair_fini( repair );
}

/* The old stream's bank dies after the marker is confirmed, eg. the
   prefix FEC set it held last failed while the new stream was already
   on its way: ignored. */

static void
test_up_dead_old_stream_late( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     d1;
  fd_repair_blk_t const * e4 = up_dead_setup( repair, &d1 );
  fd_mr32_t m41 = hash( 0x42 ), m42 = hash( 0x43 );

  last_dc ( repair, 4UL, 3UL, 1U, 1, &m41 );
  shred_up( repair, 4UL, 3UL, 2U, 1, 1UL, &d1, &m42 );
  FD_TEST( e4->init_fec_cnt==2U );

  fd_repair_blk_dead( repair, 4UL, &hash_null, 0U );
  FD_TEST( !invalidated( repair, 4UL ) && e4->eager );
  complete( repair, 4UL, 3UL, 1U, 0, &m41 );
  complete( repair, 4UL, 3UL, 2U, 1, &m42 );
  expect( repair, e4, 2U );
  FD_TEST( fd_repair_deque_empty( repair->reasm_deque ) );
  fd_repair_fini( repair );
}

/* A slot that is not the first of its leader window can have no
   UpdateParent, so its turbine version is invalidated on SLOT_DEAD as
   before. */

static void
test_up_dead_not_window_start( void ) {
  fd_repair_t * repair = setup();
  fd_mr32_t     root = hash( 0xEE ), m50 = hash( 0x51 );
  shred0  ( repair, 5UL, 0UL, &root, &m50 );
  complete( repair, 5UL, 0UL, 0U, 0, &m50 );
  fd_repair_blk_t const * e5 = eager_req( repair, 5UL );
  expect( repair, e5, 0U );

  fd_repair_blk_dead( repair, 5UL, &hash_null, 0U );
  FD_TEST( invalidated( repair, 5UL ) && !e5->eager );
  fd_repair_fini( repair );
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
  test_fec_reconsume_incomplete();
  test_blk_dead();
  test_blk_dead_renamed();
  test_blk_dead_minority_fork();
  test_orphan_stops();
  test_eqvoc_invalidates();
  test_fec_alias_refused();
  test_repair_blk_treap();
  test_blk_treap_freed();
  test_blk_treap_promote();
  test_blk_treap_order();
  test_eager_bit();
  test_twin_merge();
  test_twin_merge_ahead();
  test_telemetry();
  test_telemetry_cancelled();
  test_telemetry_meta();
  test_telemetry_final_src();
  test_notarized_shreds_build_eager();
  test_genesis();
  test_raised_blk_max();
  test_skipped_not_consumed();
  test_complete_below_rcvd();
  test_invalidated_after_whole();
  test_eager_out_of_order();
  test_complete_again();
  test_notar_out_of_order();
  test_shared_fec();
  test_notarized_complete_fec();
  test_fec_update_parent();
  test_update_parent_reparent();
  test_update_parent_eager_chain();
  test_up_target_arrives_eager();
  test_up_target_arrives_notar();
  test_up_target_same_slot();
  test_up_orig_parent_missing();
  test_up_orig_parent_skipped();
  test_up_eager_dmr();
  test_up_notar_only();
  test_up_notar_parented_late();
  test_up_notar_proofs_after_shreds( 1 );
  test_up_notar_proofs_after_shreds( 0 );
  test_up_consume_merge_equivocation();
  test_up_multiple();
  test_up_duplicate_and_decoy();
  test_up_rules();
  test_up_below_root();
  test_up_waits_for_new_parent();
  test_up_skips_rest_of_prefix();
  test_up_orphan_then_partial_parent();
  test_up_reconsume();
  test_up_orphan_map_neighbour();
  test_up_never_sends_marker_fec_early();
  test_up_dead_prefix_then_marker();
  test_up_dead_prefix_no_marker();
  test_up_dead_after_marker();
  test_up_dead_old_stream_late();
  test_up_dead_not_window_start();
  test_eager_invalidated();
  test_finalize_other();
  test_finalize_moves_child();
  test_final_before_turbine();
  test_eqvoc_links_waiting();
  test_invalidated_unlinked();
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
  test_ancestry_held_orphan();
  test_ancestry_held_parent();
  test_ancestry_eager_merge();
  test_ancestry_two_relinks();
  test_ancestry_consume_top();
  test_ancestry_relink_final();
  test_orphan_map();
  test_orphan_map_root_advanced();
  test_root_advanced_unheld();
  test_orphan_map_slot_mismatch();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
