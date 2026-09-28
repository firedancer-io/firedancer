#include "fd_chainer.h"

/* The chainer does not verify merkle proofs (fd_repair does that), so
   the merkle roots below are fabricated.  block_ids computed by the chainer are only ever checked for
   non-zero-ness, for round-tripping through
   fd_chainer_slot_version_query, or against a second identical
   computation.

   fd_chainer_verify runs after every mutation. */

#define ELE_MAX (64UL)

/* a [development.bench.max_shreds_per_block] value used by the bench configs */
#define BENCH_SHRED_MAX (4UL*FD_SHRED_BLK_MAX)

/* mkhash returns a distinct, deterministic, never-zero hash for n. */

static fd_hash_t
mkhash( ulong n ) {
  fd_hash_t h;
  memset( h.uc, 0, sizeof(fd_hash_t) );
  for( ulong i=0UL; i<8UL; i++ ) h.uc[ i ] = (uchar)( n>>(i*8UL) );
  h.uc[ 8 ] = 0xa5; /* never all zero -- zero block_id means "unknown" */
  return h;
}

/* The rotor chainer supports the full 30K-slot Alpenglow admission
   window with compact FEC bookkeeping. */

static void
test_fec_pool_layout( void ) {
  ulong const fec_max = 30000UL * FD_CHAINER_SLOT_VER_MAX * FD_FEC_BLK_MAX;
  FD_TEST( fec_max<(ulong)UINT_MAX       );
  FD_TEST( fec_max<fd_fec_pool_idx_null( NULL ) );
  FD_TEST( fec_max<fd_fec_map_ele_max()   );
  FD_TEST( sizeof(fd_chainer_fec_t)==80UL );
  FD_TEST( sizeof(((fd_chainer_fec_t *)NULL)->slot)==sizeof(uint) );
  FD_TEST( sizeof(((fd_chainer_fec_t *)NULL)->data_idxs)==sizeof(uint) );

  ulong chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  FD_TEST( fd_fec_map_footprint( chain_cnt )<=(512UL<<20)+64UL );

  /* bench limits: uint pool idxs (fd_chainer_fec, out_ele) still fit */
  ulong const bench_fec_max = 30000UL * FD_CHAINER_SLOT_VER_MAX * (BENCH_SHRED_MAX/FD_FEC_SHRED_CNT);
  FD_TEST( bench_fec_max<(ulong)UINT_MAX     );
  FD_TEST( bench_fec_max<fd_fec_map_ele_max() );

  /* footprint validates max_shreds_per_block and scales with it */
  FD_TEST( !fd_chainer_footprint( ELE_MAX, 0UL                     ) );
  FD_TEST( !fd_chainer_footprint( ELE_MAX, FD_FEC_SHRED_CNT+1UL    ) );
  FD_TEST( !fd_chainer_footprint( ELE_MAX, (1UL<<28)+FD_FEC_SHRED_CNT ) );
  FD_TEST( !fd_chainer_footprint( 30000UL, 1UL<<28 ) ); /* 30000*7*2^23 FEC elements do not fit uint indices */
  FD_TEST(  fd_chainer_footprint( 30000UL, BENCH_SHRED_MAX ) );
  FD_TEST(  fd_chainer_footprint( ELE_MAX, FD_SHRED_BLK_MAX )<fd_chainer_footprint( ELE_MAX, BENCH_SHRED_MAX ) );
}

/* slotv_at returns the `ord`-th version of slot in CREATION order (ord 0
   is the first version created -- the turbine version in the usual case
   where a turbine shred/FEC lands before any notar-fallback cert), or
   NULL.  Slotvs are keyed by slot in a MAP_MULTI whose chain is
   newest-first, so creation order is the reverse of iteration order. */

static fd_chainer_slotv_t *
slotv_at( fd_chainer_t * chainer, ulong slot, ulong ord ) {
  fd_chainer_slotv_t     * slotv_pool = chainer->slotv_pool;
  fd_slotv_map_t * slotv_map  = chainer->slotv_map;
  fd_chainer_slotv_t * list[ FD_CHAINER_SLOT_VER_MAX ];
  ulong n = 0UL;
  for( ulong i = fd_slotv_map_idx_query( slotv_map, &slot, ULONG_MAX, slotv_pool );
             i != ULONG_MAX;
             i = fd_slotv_map_idx_next_const( i, ULONG_MAX, slotv_pool ) ) {
    list[ n++ ] = fd_slotv_pool_ele( slotv_pool, i );
  }
  if( ord>=n ) return NULL;
  return list[ n-1UL-ord ]; /* reverse iteration -> creation order */
}

/* slotv_shred_cnt returns the number of data shreds slotv has, summed
   over the FECs it owns. */

static ulong
slotv_shred_cnt( fd_chainer_t *             chainer,
                 fd_chainer_slotv_t const * slotv ) {
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;
  uint const *       fecs     = fd_chainer_slotv_fecs( chainer, slotv );
  ulong              cnt      = 0UL;
  for( ulong k=0UL; k<chainer->fec_blk_max; k++ ) {
    uint idx = fecs[ k ];
    if( idx==UINT_MAX ) continue;
    cnt += (ulong)fd_uint_popcnt( fd_chainer_fec_data_idxs( chainer, fd_fec_pool_ele( fec_pool, (ulong)idx ) ) );
  }
  return cnt;
}

/* fec_at returns the FEC the ord-th (creation-order) version of slot owns
   at fec_set_idx, or NULL. */

static fd_chainer_fec_t *
fec_at( fd_chainer_t * chainer, ulong slot, uint fec_set_idx, ulong ord ) {
  fd_chainer_slotv_t * slotv = slotv_at( chainer, slot, ord );
  if( FD_UNLIKELY( !slotv ) ) return NULL;
  return fd_chainer_fec_query( chainer, slot, fec_set_idx, &slotv->block_id );
}

static fd_chainer_t *
setup_sized( fd_wksp_t * wksp, ulong ele_max, ulong max_shreds_per_block ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_chainer_align(), fd_chainer_footprint( ele_max, max_shreds_per_block ), 1UL );
  FD_TEST( mem );
  fd_chainer_t * chainer = fd_chainer_join( fd_chainer_new( mem, ele_max, max_shreds_per_block, 42UL ) );
  FD_TEST( chainer );
  FD_TEST( chainer->fec_blk_max==max_shreds_per_block/FD_FEC_SHRED_CNT );
  FD_TEST( !fd_chainer_verify( chainer ) ); /* an empty chainer is consistent */
  return chainer;
}

static fd_chainer_t *
setup( fd_wksp_t * wksp ) {
  return setup_sized( wksp, ELE_MAX, FD_SHRED_BLK_MAX );
}

/* teardown does not verify: some subtests deliberately end on a
   known-broken state. */

static void
teardown( fd_chainer_t * chainer ) {
  fd_wksp_free_laddr( chainer );
}

/* test_rx_tick is the arrival tick handed to every chainer insert in
   these tests.  Tests that care about the reception timestamps bump it
   between steps; the rest leave it alone. */

static long test_rx_tick = 1L;

/* fec_complete wraps fd_chainer_fec_complete and returns its rejected
   flag (0 accepted, 1 rejected), which is what these tests check. */

/* fec_rooted_at is fec_at restricted to entries that know their root:
   a version now holds a rootless placeholder at every set of a known
   tip, so "no entry" and "no root" are different questions. */

static fd_chainer_fec_t *
fec_rooted_at( fd_chainer_t * chainer, ulong slot, uint fec_set_idx, ulong ord ) {
  fd_chainer_fec_t * fec = fec_at( chainer, slot, fec_set_idx, ord );
  return ( fec && !fd_hash_check_zero( &fec->merkle_root ) ) ? fec : NULL;
}

/* root_known reports whether a version's entry at this set knows its
   merkle root.  The entry itself may exist as a rootless placeholder
   as soon as the set count is known, so existence no longer implies a
   root. */

static int
root_known( fd_chainer_t * chainer, ulong slot, uint fec_set_idx, fd_hash_t const * block_id ) {
  fd_chainer_fec_t const * fec = fd_chainer_fec_query( chainer, slot, fec_set_idx, block_id );
  return fec && !fd_hash_check_zero( &fec->merkle_root );
}

/* has_work is the per-version stand-in for the old repair worklist:
   the eager/notar treaps hold sets, so a version has work when any of
   its sets is still on one. */

static int
has_work( fd_chainer_t * chainer, fd_chainer_slotv_t const * slotv ) {
  uint const * fecs = fd_chainer_slotv_fecs( chainer, slotv );
  for( uint k=0U; k<chainer->fec_blk_max; k++ ) {
    if( FD_UNLIKELY( fecs[ k ]!=UINT_MAX && fd_fec_pool_ele( chainer->fec_pool, fecs[ k ] )->treap ) ) return 1;
  }
  return 0;
}

static int
fec_complete( fd_chainer_t * chainer, ulong slot, uint fec_set_idx, int slot_complete, int data_complete, int is_leader, fd_hash_t * mr ) {
  return fd_chainer_fec_complete( chainer, slot, fec_set_idx, slot_complete, data_complete, is_leader, test_rx_tick, mr );
}

/* feed_fec_src drives one FEC set through the chainer the way the shred
   tile does: a shred_insert per shred, then one fec_insert once the set
   is complete.  Parent information rides on the first shred only (pass
   AG_UNKNOWN_SLOT to leave the parent unknown), the same way the shred
   tile only learns the parent from the shred header.  src is the
   provenance every shred of the set is delivered with.  Returns the
   fd_chainer_fec_complete return code (0 accepted, 1 rejected). */

static int
feed_fec_src( fd_chainer_t *    chainer,
              ulong             slot,
              uint              fec_set_idx,
              int               slot_complete,
              int               src,
              fd_hash_t const * mr,
              ulong             parent_slot,
              fd_hash_t const * parent_block_id ) {
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    int last = ( i==(uint)FD_FEC_SHRED_CNT-1U );
    fd_chainer_shred_insert( chainer, slot, fec_set_idx+i, slot_complete && last, src, test_rx_tick, mr,
                             i ? AG_UNKNOWN_SLOT : parent_slot,
                             i ? NULL            : parent_block_id );
    FD_TEST( !fd_chainer_verify( chainer ) );
  }
  fd_hash_t mr_ = *mr;
  int rc = fec_complete( chainer, slot, fec_set_idx, slot_complete, slot_complete, 0, &mr_ );
  FD_TEST( !fd_chainer_verify( chainer ) );
  return rc;
}

/* feed_fec is feed_fec_src for the usual all-turbine set. */

static int
feed_fec( fd_chainer_t *    chainer,
          ulong             slot,
          uint              fec_set_idx,
          int               slot_complete,
          fd_hash_t const * mr,
          ulong             parent_slot,
          fd_hash_t const * parent_block_id ) {
  return feed_fec_src( chainer, slot, fec_set_idx, slot_complete, FD_CHAINER_SRC_TURBINE, mr, parent_slot, parent_block_id );
}

/* One delivered FEC, identified the way replay sees it: (slot,
   fec_set_idx) position and the FEC set's merkle root. */

typedef struct { ulong slot; uint fec_set_idx; fd_hash_t mr; } out_rec_t;

/* drain_out pops the chainer's entire out_queue into recs in delivery
   (FIFO) order, decoding each fd_fec_pool index back to its position and
   root, and returns the count.  Empties the queue. */

static ulong
drain_out( fd_chainer_t * chainer, out_rec_t * recs, ulong recs_max ) {
  out_ele_t * out_queue = chainer->out_queue;
  fd_chainer_fec_t * fec_pool  = chainer->fec_pool;
  ulong cnt = 0UL;
  while( !out_queue_empty( out_queue ) ) {
    out_ele_t out_ele = out_queue_pop_head( out_queue );
    fd_chainer_fec_t * fec = fd_fec_pool_ele( fec_pool, out_ele.fec_idx );
    FD_TEST( cnt<recs_max );
    recs[ cnt ].slot        = fec->slot;
    recs[ cnt ].fec_set_idx = fec->fec_set_idx;
    recs[ cnt ].mr          = fec->merkle_root;
    cnt++;
  }
  return cnt;
}

/* expect_out drains the out_queue and asserts it matches exp[0..exp_cnt)
   exactly, in order. */

static void
expect_out( fd_chainer_t * chainer, out_rec_t const * exp, ulong exp_cnt ) {
  out_rec_t recs[ 64 ];
  ulong cnt = drain_out( chainer, recs, 64UL );
  if( FD_UNLIKELY( cnt!=exp_cnt ) ) {
    FD_LOG_WARNING(( "out_queue cnt=%lu exp=%lu", cnt, exp_cnt ));
    for( ulong i=0UL; i<cnt; i++ ) FD_LOG_WARNING(( "  got[%lu] slot=%lu fec=%u mr=%02x", i, recs[i].slot, recs[i].fec_set_idx, recs[i].mr.uc[0] ));
  }
  FD_TEST( cnt==exp_cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    FD_TEST( recs[ i ].slot       ==exp[ i ].slot        );
    FD_TEST( recs[ i ].fec_set_idx==exp[ i ].fec_set_idx );
    FD_TEST( fd_hash_eq( &recs[ i ].mr, &exp[ i ].mr )   );
  }
}

/* (a) A single-version turbine block: shreds and FEC completions arrive
   in order, the shred bitmap and the buffered / complete / delivered
   indices advance, and the block_id is finalized once the block is
   whole. */

static void
test_basic( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 10UL, &bid0 );
  FD_TEST( !fd_chainer_verify( chainer ) );

  FD_TEST( chainer->root==10UL );
  FD_TEST( fd_chainer_highest_repaired_slot( chainer )==10UL );

  fd_chainer_slotv_t * root = fd_chainer_slot_query( chainer, 10UL );
  FD_TEST( root==slotv_at( chainer, 10UL, 0UL ) );
  FD_TEST( fd_hash_eq( &root->block_id, &bid0 ) );
  FD_TEST( root->connected );
  FD_TEST( root->complete_idx==0U && root->buffered_idx==0U && root->delivered_idx==0U );

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );

  /* first FEC set of slot 11, shred by shred */

  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    fd_chainer_shred_insert( chainer, 11UL, i, 0, FD_CHAINER_SRC_TURBINE, test_rx_tick, &r0, i ? AG_UNKNOWN_SLOT : 10UL, i ? NULL : &bid0 );
    FD_TEST( !fd_chainer_verify( chainer ) );

    fd_chainer_slotv_t * slotv = slotv_at( chainer, 11UL, 0UL );
    FD_TEST( slotv );                                          /* created on the first shred */
    FD_TEST( fd_chainer_shred_test( chainer, slotv, i  ) );
    FD_TEST( slotv_shred_cnt( chainer, slotv )==i+1UL );
    FD_TEST( slotv->buffered_idx==i );                         /* contiguous from 0 */
    FD_TEST( slotv->complete_idx==UINT_MAX );                  /* tip still unknown */
  }

  fd_chainer_slotv_t * s11 = slotv_at( chainer, 11UL, 0UL );
  FD_TEST( s11->parent_slot==10UL );
  FD_TEST( fd_hash_eq( &s11->parent_block_id, &bid0 ) );
  FD_TEST( s11->connected );                  /* parent is the root */
  FD_TEST( has_work( chainer, s11 ) );        /* still has shreds to request */
  FD_TEST( s11->buffered_fec_idx==UINT_MAX ); /* no FEC completion yet */
  FD_TEST( s11->delivered_idx   ==UINT_MAX );
  /* the FEC is born on the first shred now, but is not completed until
     fd_chainer_fec_complete marks it reconstructable */
  fd_chainer_fec_t * pre0 = fec_at( chainer, 11UL, 0U, 0UL );
  FD_TEST( pre0 && !pre0->complete );
  FD_TEST( fd_hash_check_zero( &s11->block_id ) );

  /* FEC completion for set 0 */

  fd_hash_t mr = r0;
  FD_TEST( !fec_complete( chainer, 11UL, 0U, 0, 0, 0, &mr ) );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_fec_t * f0 = fec_at( chainer, 11UL, 0U, 0UL );
  FD_TEST( f0 );
  FD_TEST( fd_hash_eq( &f0->merkle_root, &r0 ) );
  FD_TEST( f0->complete && !f0->slot_complete );
  FD_TEST( s11->buffered_fec_idx==31U );
  FD_TEST( s11->delivered_idx   ==31U ); /* delivered: parent (the root) is delivered */
  /* Set 0 completed, but the tip is still unknown, so it stays
     enrolled as the block's "there is more past the tip" token -- the
     thing that keeps HighestShred going out. */
  FD_TEST( has_work( chainer, s11 ) );
  FD_TEST( fd_hash_check_zero( &s11->block_id ) );

  /* second and last FEC set */

  fd_chainer_shred_insert( chainer, 11UL, 63U, 1, FD_CHAINER_SRC_TURBINE, test_rx_tick, &r1, 10UL, &bid0 );
  FD_TEST( s11->complete_idx==63U && s11->delivered_idx==31U );
  FD_TEST( f0->treap ); /* learning the tip and parent does not release set 0 */
  FD_TEST( !fd_chainer_verify( chainer ) );
  FD_TEST( !feed_fec( chainer, 11UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL ) );

  FD_TEST( s11->complete_idx    ==63U );
  FD_TEST( s11->buffered_idx    ==63U );
  FD_TEST( s11->buffered_fec_idx==63U );
  FD_TEST( s11->delivered_idx   ==63U );
  FD_TEST( slotv_shred_cnt( chainer, s11 )==64UL );
  FD_TEST( !has_work( chainer, s11 ) ); /* whole block -> no work left */
  FD_TEST( fd_chainer_highest_repaired_slot( chainer )==11UL );

  fd_chainer_fec_t * f1 = fec_at( chainer, 11UL, 32U, 0UL );
  FD_TEST( f1 );
  FD_TEST( fd_hash_eq( &f1->merkle_root, &r1 ) );
  FD_TEST( f1->slot_complete && f1->complete );

  /* the whole block has a block_id, and it round-trips */

  FD_TEST( !fd_hash_check_zero( &s11->block_id ) );
  fd_hash_t bid11 = s11->block_id;
  FD_TEST( fd_chainer_slot_version_query( chainer, 11UL, &bid11 )==s11 );
  FD_TEST( !fd_chainer_slot_version_query( chainer, 11UL, &r0    ) );

  /* the block_id is a pure function of the block: rebuilding the same
     block in a second chainer must produce the same id */

  fd_chainer_t * other = setup( wksp );
  fd_chainer_init( other, 10UL, &bid0 );
  FD_TEST( !feed_fec( other, 11UL, 0U,  0, &r0, 10UL,            &bid0 ) );
  FD_TEST( !feed_fec( other, 11UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( fd_hash_eq( &slotv_at( other, 11UL, 0UL )->block_id, &bid11 ) );
  FD_TEST( !fd_chainer_verify( other ) );
  teardown( other );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: basic single-version turbine block" ));
}

/* (b) Two versions of a slot whose FEC sets 0..k carry the same merkle
   root and diverge after: the shared prefix must be recorded against
   both versions, so the notar-fallback version does not re-repair
   shreds we already hold. */

static void
test_shared_prefix( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 20UL, &bid0 );

  fd_hash_t r0  = mkhash( 1UL );
  fd_hash_t r1  = mkhash( 2UL );
  fd_hash_t r2a = mkhash( 3UL );
  fd_hash_t r2b = mkhash( 4UL );

  /* turbine's block for slot 21: three FEC sets, complete */

  FD_TEST( !feed_fec( chainer, 21UL, 0U,  0, &r0,  20UL,            &bid0 ) );
  FD_TEST( !feed_fec( chainer, 21UL, 32U, 0, &r1,  AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( chainer, 21UL, 64U, 1, &r2a, AG_UNKNOWN_SLOT, NULL  ) );

  fd_chainer_slotv_t * v0 = slotv_at( chainer, 21UL, 0UL );
  FD_TEST( v0->complete_idx==95U && v0->buffered_idx==95U && v0->delivered_idx==95U );
  FD_TEST( !fd_hash_check_zero( &v0->block_id ) );
  fd_hash_t bid_v0 = v0->block_id;

  /* a notar-fallback cert names a different block for slot 21 */

  fd_hash_t bidX = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 21UL, bidX );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_slotv_t * v1 = slotv_at( chainer, 21UL, 1UL );
  FD_TEST( v1 );
  FD_TEST( fd_chainer_slot_version_query( chainer, 21UL, &bidX )==v1 );
  FD_TEST( v1->slot==21UL );

  /* getParentAndFecCount response: three FEC sets, parent is the root */

  fd_chainer_verified_parent_fec_count( chainer, 21UL, &bidX, 3U, 20UL, &bid0 );
  FD_TEST( fd_chainer_slot_version_query( chainer, 20UL, &bid0 ) ); /* returns the parent version */
  FD_TEST( !fd_chainer_verify( chainer ) );
  FD_TEST( v1->complete_idx==95U );
  FD_TEST( v1->parent_slot ==20UL );
  FD_TEST( v1->connected );

  /* getFecRoot responses for the shared prefix.  Both roots are already
     complete under version 0, so version 1 must pick up those shreds
     without any repair. */

  fd_hash_t mr = r0;
  fd_chainer_verified_hash_insert( chainer, 21UL, &bidX, 0U, mr.uc );
  FD_TEST( !fd_chainer_verify( chainer ) );
  mr = r1;
  fd_chainer_verified_hash_insert( chainer, 21UL, &bidX, 32U, mr.uc );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_fec_t * v1f0 = fec_at( chainer, 21UL, 0U,  1UL );
  fd_chainer_fec_t * v1f1 = fec_at( chainer, 21UL, 32U, 1UL );
  FD_TEST( v1f0 && v1f0->complete && fd_hash_eq( &v1f0->merkle_root, &r0 ) );
  FD_TEST( v1f1 && v1f1->complete && fd_hash_eq( &v1f1->merkle_root, &r1 ) );

  /* both versions hold the shared shreds */

  for( uint i=0U; i<64U; i++ ) {
    FD_TEST( fd_chainer_shred_test( chainer, v0, i  ) );
    FD_TEST( fd_chainer_shred_test( chainer, v1, i  ) );
  }
  FD_TEST( v1->buffered_idx    ==63U );
  FD_TEST( v1->buffered_fec_idx==63U );
  FD_TEST( v1->delivered_idx   ==63U );

  /* the version's roots are recorded at exactly the expected positions */

  FD_TEST( !root_known( chainer, 21UL, 64U, &bidX ) ); /* placeholder exists, root not learned yet */
  FD_TEST( !fd_chainer_fec_query( chainer, 21UL, 0U,  &r0   ) ); /* unknown version */
  fd_chainer_fec_t * v0f2 = fd_chainer_fec_query( chainer, 21UL, 64U, &bid_v0 );
  FD_TEST( v0f2 && fd_hash_eq( &v0f2->merkle_root, &r2a ) );     /* version 0 */

  /* getFecRoot response for the diverging set: no version holds this
     root, so a sentinel is created and its shreds must be repaired */

  mr = r2b;
  fd_chainer_verified_hash_insert( chainer, 21UL, &bidX, 64U, mr.uc );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_fec_t * v1f2 = fec_at( chainer, 21UL, 64U, 1UL );
  FD_TEST( v1f2 && !v1f2->complete && fd_hash_eq( &v1f2->merkle_root, &r2b ) );
  FD_TEST( v1f2->slot_complete );          /* last set of the cert's fec_set_cnt */
  FD_TEST( v1->buffered_fec_idx==63U );    /* an incomplete FEC must not extend the prefix */
  FD_TEST( v1->delivered_idx   ==63U );    /* nor be delivered */
  FD_TEST( has_work( chainer, v1 ) );                 /* new incomplete FEC -> requestable work */
  FD_TEST( !fd_chainer_shred_test( chainer, v1, 64U  ) );

  /* repair fills the diverging set.  Only version 1 records it, and
     version 0 keeps its own root for that set. */

  FD_TEST( !feed_fec( chainer, 21UL, 64U, 1, &r2b, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( v1f2->complete );
  for( uint i=64U; i<96U; i++ ) FD_TEST( fd_chainer_shred_test( chainer, v1, i  ) );
  FD_TEST( v1->buffered_idx    ==95U );
  FD_TEST( v1->buffered_fec_idx==95U );
  FD_TEST( v1->delivered_idx   ==95U );
  FD_TEST( fd_hash_eq( &fec_at( chainer, 21UL, 64U, 0UL )->merkle_root, &r2a ) );
  FD_TEST( fd_hash_eq( &v0->block_id, &bid_v0 ) ); /* version 0 untouched */

  FD_TEST( !fd_hash_check_zero( &v1->block_id ) );
  FD_TEST(  fd_hash_eq( &v1->block_id, &bidX    ) ); /* nt clobbered */
  FD_TEST( !fd_hash_eq( &v1->block_id, &bid_v0  ) ); /* different block than version 0 */
  FD_TEST(  fd_chainer_slot_version_query( chainer, 21UL, &bidX ) );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: shared prefix across two versions" ));
}

/* (c) A notar-fallback cert for a block that is still in flight from
   turbine.  We cannot compute the in-flight block's id yet, so we cannot
   tell the cert names the same block: a redundant slotv is created by
   design, and the turbine version is abandoned -- it may be the same
   block the cert version is repairing, and delivering both would hand
   replay two banks for the same {slot, block_id}.  The structure must
   stay consistent. */

static void
test_notar_fallback_in_flight( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 30UL, &bid0 );

  fd_hash_t r0 = mkhash( 1UL );
  FD_TEST( !feed_fec( chainer, 31UL, 0U, 0, &r0, 30UL, &bid0 ) );

  fd_chainer_slotv_t * v0 = slotv_at( chainer, 31UL, 0UL );
  FD_TEST( v0->complete_idx==UINT_MAX );          /* still in flight */
  FD_TEST( fd_hash_check_zero( &v0->block_id ) ); /* so no block_id yet */

  fd_hash_t bidY = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 31UL, bidY );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_slotv_t * v1 = slotv_at( chainer, 31UL, 1UL );
  FD_TEST( v1 && v1!=v0 );
  FD_TEST( fd_chainer_slot_version_query( chainer, 31UL, &bidY )==v1 );
  FD_TEST( fd_hash_eq( &v1->block_id, &bidY ) );

  /* the redundant version starts empty: nothing is shared with version
     0 until a getFecRoot response proves the roots match */

  FD_TEST( v1->complete_idx    ==UINT_MAX );
  FD_TEST( v1->buffered_idx    ==UINT_MAX );
  FD_TEST( v1->buffered_fec_idx==UINT_MAX );
  FD_TEST( v1->delivered_idx   ==UINT_MAX );
  FD_TEST( v1->parent_slot     ==AG_UNKNOWN_SLOT );
  FD_TEST( !v1->connected );
  FD_TEST( v1->parent_slot==AG_UNKNOWN_SLOT ); /* ancestry still unknown */
  FD_TEST( slotv_shred_cnt( chainer, v1 )==0UL );
  FD_TEST( !fec_rooted_at( chainer, 31UL, 0U, 1UL ) );

  /* version 0 keeps its data but is abandoned: off the worklists, and
     it will never deliver or finalize a block_id */

  FD_TEST( v0->buffered_idx==31U && v0->buffered_fec_idx==31U );
  FD_TEST( fec_at( chainer, 31UL, 0U, 0UL ) );
  FD_TEST( fd_hash_check_zero( &v0->block_id ) );
  FD_TEST( !has_work( chainer, v0 ) );

  /* a repeat of the same cert is a no-op -- no third version */

  ulong slotv_free = fd_slotv_pool_free( slotv_pool );
  fd_chainer_verified_block_insert( chainer, 31UL, bidY );
  FD_TEST( !fd_chainer_verify( chainer ) );
  FD_TEST( fd_slotv_pool_free( slotv_pool )==slotv_free );
  FD_TEST( !slotv_at( chainer, 31UL, 2UL ) );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: notar-fallback for an in-flight turbine block" ));
}

/* (d) A getFecRoot sentinel lands before turbine reaches that FEC set.
   Shreds update that known root without adding entries to the abandoned
   turbine version. */

static void
test_sentinel_before_turbine( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 40UL, &bid0 );

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );

  /* turbine has set 0 of slot 41 only */

  FD_TEST( !feed_fec( chainer, 41UL, 0U, 0, &r0, 40UL, &bid0 ) );
  fd_chainer_slotv_t * v0 = slotv_at( chainer, 41UL, 0UL );
  FD_TEST( v0->buffered_idx==31U && v0->buffered_fec_idx==31U );

  /* a notar-fallback cert arrives, and its getFecRoot response for set 1
     names the root turbine is about to deliver (the versions share that
     FEC set) */

  fd_hash_t bidZ = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 41UL, bidZ );
  FD_TEST( !fd_chainer_verify( chainer ) );
  fd_chainer_verified_parent_fec_count( chainer, 41UL, &bidZ, 2U, 40UL, &bid0 );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_hash_t mr = r1;
  fd_chainer_verified_hash_insert( chainer, 41UL, &bidZ, 32U, mr.uc );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_slotv_t * v1 = slotv_at( chainer, 41UL, 1UL );
  FD_TEST( v1 && v1->complete_idx==63U );
  fd_chainer_fec_t * v1f1 = fec_at( chainer, 41UL, 32U, 1UL );
  FD_TEST( v1f1 && !v1f1->complete && fd_hash_eq( &v1f1->merkle_root, &r1 ) );
  ulong fec_used = fd_fec_pool_used( chainer->fec_pool );

  /* turbine now delivers set 1 of slot 41 with that same root */

  FD_TEST( !feed_fec( chainer, 41UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( v0->buffered_idx == 31U );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==fec_used );

  FD_TEST( v1f1->complete );
  for( uint i=32U; i<64U; i++ ) FD_TEST( fd_chainer_shred_test( chainer, v1, i  ) );
  FD_TEST( v1->buffered_fec_idx==UINT_MAX ); /* still missing set 0's getFecRoot */
  FD_TEST( v1->delivered_idx   ==UINT_MAX );

  FD_TEST( !fec_at( chainer, 41UL, 32U, 0UL ) );
  for( uint i=32U; i<64U; i++ ) FD_TEST( !fd_chainer_shred_test( chainer, v0, i ) );
  FD_TEST( v0->complete_idx==UINT_MAX );
  FD_TEST( !has_work( chainer, v0 ) );

  /* Only set 0, queued before abandonment, reached replay. */

  FD_TEST( v0->delivered_idx==31U );
  FD_TEST( v0->buffered_fec_idx==31U );
  FD_TEST( fd_hash_check_zero( &v0->block_id ) );
  out_rec_t exp[] = { { 41UL, 0U, r0 } };
  expect_out( chainer, exp, 1UL );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: getFecRoot sentinel before turbine" ));
}

/* (e) After a notar-fallback abandons turbine, an unknown root cannot
   create new FEC entries.  Once a verified root arrives, the same
   shreds and completion update the named version. */

static void
test_turbine_shred_after_notar_fallback( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 50UL, &bid0 );

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );

  FD_TEST( !feed_fec( chainer, 51UL, 0U, 0, &r0, 50UL, &bid0 ) );
  fd_chainer_slotv_t * v0 = slotv_at( chainer, 51UL, 0UL );
  FD_TEST( v0->buffered_idx==31U );

  /* notar-fallback cert -> version 1 exists, but no getFecRoot response
     has arrived for set 1 */

  fd_hash_t bidY = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 51UL, bidY );
  FD_TEST( !fd_chainer_verify( chainer ) );
  FD_TEST( slotv_at( chainer, 51UL, 1UL ) );
  ulong fec_used = fd_fec_pool_used( chainer->fec_pool );

  /* turbine delivers set 1 of the honest block */

  for( uint i=32U; i<64U; i++ ) {
    fd_chainer_shred_insert( chainer, 51UL, i, i==63U, FD_CHAINER_SRC_TURBINE, test_rx_tick, &r1, AG_UNKNOWN_SLOT, NULL );
    FD_TEST( !fd_chainer_verify( chainer ) );
  }
  fd_hash_t mr = r1;
  int rc = fec_complete( chainer, 51UL, 32U, 1, 1, 0, &mr );

  FD_TEST( rc==1 );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==fec_used );
  FD_TEST( !fec_at( chainer, 51UL, 32U, 0UL ) );
  FD_TEST( !has_work( chainer, v0 ) );
  for( uint i=32U; i<64U; i++ ) FD_TEST( !fd_chainer_shred_test( chainer, v0, i ) );
  FD_TEST( v0->complete_idx==UINT_MAX && v0->buffered_idx==31U );

  FD_TEST( v0->delivered_idx==31U );
  FD_TEST( v0->buffered_fec_idx==31U );
  FD_TEST( fd_hash_check_zero( &v0->block_id ) );
  out_rec_t exp[] = { { 51UL, 0U, r0 } };
  expect_out( chainer, exp, 1UL );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_verified_parent_fec_count( chainer, 51UL, &bidY, 2U, 50UL, &bid0 );
  fd_chainer_verified_hash_insert( chainer, 51UL, &bidY, 0U, r0.uc );
  fd_chainer_verified_hash_insert( chainer, 51UL, &bidY, 32U, r1.uc );
  FD_TEST( !feed_fec( chainer, 51UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL ) );
  fd_chainer_slotv_t * v1 = fd_chainer_slot_version_query( chainer, 51UL, &bidY );
  FD_TEST( v1->delivered_idx==63U && !has_work( chainer, v1 ) );
  FD_TEST( !has_work( chainer, v0 ) && !fec_at( chainer, 51UL, 32U, 0UL ) );
  out_rec_t named[] = { { 51UL, 0U, r0 }, { 51UL, 32U, r1 } };
  expect_out( chainer, named, 2UL );
  FD_TEST( !fd_chainer_verify( chainer ) );

  teardown( chainer );
  FD_LOG_NOTICE(( "pass: turbine shred after notar-fallback" ));
}

/* (f) Rooting and pruning: everything below the new root goes away and
   nothing leaks out of either pool. */

static void
test_publish( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_chainer_fec_t   * fec_pool   = chainer->fec_pool;

  ulong slotv_free0 = fd_slotv_pool_free( slotv_pool );
  ulong fec_free0   = fd_fec_pool_free  ( fec_pool   );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 60UL, &bid0 );

  /* slot 61: two FEC sets, chained to the root */

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );
  FD_TEST( !feed_fec( chainer, 61UL, 0U,  0, &r0, 60UL,            &bid0 ) );
  FD_TEST( !feed_fec( chainer, 61UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL  ) );
  fd_hash_t bid61 = slotv_at( chainer, 61UL, 0UL )->block_id;
  FD_TEST( !fd_hash_check_zero( &bid61 ) );

  /* slot 62: two FEC sets, chained to 61 */

  fd_hash_t r2 = mkhash( 3UL );
  fd_hash_t r3 = mkhash( 4UL );
  FD_TEST( !feed_fec( chainer, 62UL, 0U,  0, &r2, 61UL,            &bid61 ) );
  FD_TEST( !feed_fec( chainer, 62UL, 32U, 1, &r3, AG_UNKNOWN_SLOT, NULL   ) );
  FD_TEST( slotv_at( chainer, 62UL, 0UL )->delivered_idx==63U ); /* chain delivered */
  FD_TEST( fd_chainer_highest_repaired_slot( chainer )==62UL );

  FD_TEST( fd_slotv_pool_free( slotv_pool )==slotv_free0-3UL ); /* 60, 61, 62 */
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0  -4UL ); /* 4 FEC sets */

  /* drain the out queue */
  out_ele_t * out_queue = chainer->out_queue;
  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }

  fd_chainer_publish( chainer, 62UL, NULL, NULL );
  FD_TEST( !fd_chainer_verify( chainer ) );

  FD_TEST( chainer->root==62UL );
  FD_TEST( !slotv_at( chainer, 60UL, 0UL ) );
  FD_TEST( !slotv_at( chainer, 61UL, 0UL ) );
  FD_TEST( !fd_chainer_slot_query( chainer, 61UL ) );
  FD_TEST( !fec_rooted_at( chainer, 61UL, 0U,  0UL ) );
  FD_TEST( !fec_rooted_at( chainer, 61UL, 32U, 0UL ) );

  fd_chainer_slotv_t * s62 = slotv_at( chainer, 62UL, 0UL );
  FD_TEST( s62 && s62->connected );
  /* the rooted slot's FEC data is never needed again, so publish releases
     it and clears the slotv's fec[] */
  FD_TEST( !fec_rooted_at( chainer, 62UL, 0U,  0UL ) );
  FD_TEST( !fec_rooted_at( chainer, 62UL, 32U, 0UL ) );

  /* no leaks: only slot 62's slotv survives; every FEC set is released */

  FD_TEST( fd_slotv_pool_free( slotv_pool )==slotv_free0-1UL );
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0        );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: publish prunes below the root without leaking" ));
}

/* (f, continued) Publishing past a block with more than 1024 shreds. */

static void
test_publish_large_block( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_chainer_fec_t   * fec_pool   = chainer->fec_pool;

  ulong slotv_free0 = fd_slotv_pool_free( slotv_pool );
  ulong fec_free0   = fd_fec_pool_free  ( fec_pool   );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 70UL, &bid0 );

  /* slot 71: 64 FEC sets = 2048 shreds */

  ulong fec_set_cnt = 64UL;
  for( ulong f=0UL; f<fec_set_cnt; f++ ) {
    fd_hash_t r = mkhash( 1000UL+f );
    FD_TEST( !feed_fec( chainer, 71UL, (uint)( f*FD_FEC_SHRED_CNT ), f==fec_set_cnt-1UL, &r,
                        f ? AG_UNKNOWN_SLOT : 70UL, f ? NULL : &bid0 ) );
  }
  fd_chainer_slotv_t * s71 = slotv_at( chainer, 71UL, 0UL );
  FD_TEST( s71->complete_idx==2047U && s71->buffered_idx==2047U && s71->delivered_idx==2047U );
  FD_TEST( !fd_hash_check_zero( &s71->block_id ) );
  fd_hash_t bid71 = s71->block_id;

  /* slot 72, so there is something to publish to */

  fd_hash_t r = mkhash( 2000UL );
  FD_TEST( !feed_fec( chainer, 72UL, 0U, 1, &r, 71UL, &bid71 ) );

  FD_TEST( fd_slotv_pool_free( slotv_pool )==slotv_free0-3UL );             /* 70, 71, 72 */
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0-fec_set_cnt-1UL );   /* 64 + 1 */

  /* drain the out queue */
  out_ele_t * out_queue = chainer->out_queue;
  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }
  fd_chainer_publish( chainer, 72UL, NULL, NULL );

  FD_TEST( chainer->root==72UL );
  FD_TEST( !slotv_at( chainer, 70UL, 0UL ) );
  FD_TEST( !slotv_at( chainer, 71UL, 0UL ) );
  FD_TEST( fd_slotv_pool_free( slotv_pool )==slotv_free0-1UL ); /* slotvs do not leak */
  FD_TEST( !fec_rooted_at( chainer, 71UL, 0U, 0UL ) );

  /* Nothing leaks above the old 1024-shred clamp: publish releases a
     slot's FECs via the fec map, so block size no longer bounds what it
     can release. */

  FD_TEST( fd_fec_pool_free( fec_pool )==fec_free0 ); /* every set released, root FECs included */
  FD_TEST( !fec_rooted_at( chainer, 71UL, 1024U, 0UL ) );
  FD_TEST( !fec_rooted_at( chainer, 71UL, 2016U, 0UL ) );
  FD_TEST( !fd_chainer_verify( chainer ) );

  teardown( chainer );
  FD_LOG_NOTICE(( "pass: publish past a >1024 shred block" ));
}

/* (f, continued) Rooting a non-v0 canonical version: the new root's
   version 0 is non-canonical and gets pruned along with the slot's FEC
   list, so the root survives without a version 0.  A subsequent publish
   over that v0-less root must still work -- the root is the one slot
   exempt from the "every slot has a version 0" invariant. */

static void
test_publish_noncanonical_v0( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_chainer_fec_t   * fec_pool   = chainer->fec_pool;

  ulong slotv_free0 = fd_slotv_pool_free( slotv_pool );
  ulong fec_free0   = fd_fec_pool_free  ( fec_pool   );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 60UL, &bid0 );

  /* slot 61 version 0: complete turbine block chained to the root */

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );
  FD_TEST( !feed_fec( chainer, 61UL, 0U,  0, &r0, 60UL,            &bid0 ) );
  FD_TEST( !feed_fec( chainer, 61UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL  ) );

  /* a notar-fallback cert names a different block for slot 61 */

  fd_hash_t bidX = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 61UL, bidX );
  FD_TEST( !fd_chainer_verify( chainer ) );
  fd_chainer_slotv_t * v1 = slotv_at( chainer, 61UL, 1UL );
  FD_TEST( v1 );

  /* root the notar-fallback version: v0 is non-canonical and gets
     pruned, taking the slot's whole FEC list with it */

  out_ele_t * out_queue = chainer->out_queue;
  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }
  fd_chainer_publish( chainer, 61UL, &bidX, NULL );
  FD_TEST( !fd_chainer_verify( chainer ) ); /* a root without a version 0 is legal */

  FD_TEST( chainer->root==61UL );
  FD_TEST( fd_chainer_slot_version_query( chainer, 61UL, &bidX )==v1 ); /* canonical survives */
  FD_TEST( slotv_at( chainer, 61UL, 0UL )==v1 ); /* the sole surviving version */
  FD_TEST( !slotv_at( chainer, 61UL, 1UL ) );    /* turbine was pruned */
  FD_TEST( v1->connected );

  FD_TEST( !fec_rooted_at( chainer, 61UL, 0U,  0UL ) );
  FD_TEST( !fec_rooted_at( chainer, 61UL, 32U, 0UL ) );
  FD_TEST( fd_slotv_pool_free( slotv_pool )==slotv_free0-1UL ); /* only v1 of 61 */
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0        ); /* all FECs released */

  /* slot 62 chains to the v0-less root, then publishes over it */

  fd_hash_t r2 = mkhash( 3UL );
  FD_TEST( !feed_fec( chainer, 62UL, 0U, 1, &r2, 61UL, &bidX ) );
  FD_TEST( slotv_at( chainer, 62UL, 0UL )->connected );

  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }
  fd_chainer_publish( chainer, 62UL, NULL, NULL );
  FD_TEST( !fd_chainer_verify( chainer ) );

  FD_TEST( chainer->root==62UL );
  FD_TEST( !slotv_at( chainer, 61UL, 1UL ) );
  FD_TEST( fd_slotv_pool_free( slotv_pool )==slotv_free0-1UL ); /* only 62's v0 */
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0        ); /* rooted slot's FEC released too */

  teardown( chainer );
  FD_LOG_NOTICE(( "pass: publish roots a non-v0 canonical version" ));
}

/* (g) All FD_CHAINER_SLOT_VER_MAX versions of a slot: one turbine block
   plus three notar-fallbacks, the protocol maximum. */

static void
test_versions_full( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 80UL, &bid0 );

  fd_hash_t r0 = mkhash( 1UL );
  FD_TEST( !feed_fec( chainer, 81UL, 0U, 0, &r0, 80UL, &bid0 ) ); /* version 0 */
  FD_TEST( slotv_at( chainer, 81UL, 0UL ) );

  for( ulong v=1UL; v<FD_CHAINER_SLOT_VER_MAX; v++ ) {
    fd_hash_t bid = mkhash( 200UL+v );
    fd_chainer_verified_block_insert( chainer, 81UL, bid );
    FD_TEST( !fd_chainer_verify( chainer ) );

    fd_chainer_slotv_t * slotv = slotv_at( chainer, 81UL, v );
    FD_TEST( slotv );
    FD_TEST( fd_hash_eq( &slotv->block_id, &bid ) );
    FD_TEST( fd_chainer_slot_version_query( chainer, 81UL, &bid )==slotv ); /* dense scan finds it */
  }

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: all %d versions of a slot", FD_CHAINER_SLOT_VER_MAX ));
}

/* (f) FECs are keyed by the 20-byte root prefix.  A getFecRoot sentinel
   holds the zero-padded prefix; a shred carrying the full root resolves
   to the same entry and fills the full root in place -- nothing tells
   shred_insert which version the shred was repaired for.  Two cases:
   the sentinel is created first and shreds fill it, and the full-root
   FEC already exists when a later version learns the set by prefix
   (that version joins the existing FEC and, if it is complete, its
   completion is replayed for the version). */

static void
test_prefix_key( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 40UL, &bid0 );

  /* full roots with a non-zero tail, so the padded prefix differs */
  fd_hash_t r0 = mkhash( 1UL ); r0.uc[ 24 ] = 0x5a;
  fd_hash_t r1 = mkhash( 2UL ); r1.uc[ 25 ] = 0x3c;
  fd_hash_t p0 = {0}; memcpy( p0.uc, r0.uc, FD_SHRED_MERKLE_NODE_SZ );
  fd_hash_t p1 = {0}; memcpy( p1.uc, r1.uc, FD_SHRED_MERKLE_NODE_SZ );

  /* a notar-fallback version of slot 41 learns both roots by prefix */
  fd_hash_t bidZ = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 41UL, bidZ );
  fd_chainer_verified_parent_fec_count( chainer, 41UL, &bidZ, 2U, 40UL, &bid0 );
  fd_chainer_verified_hash_insert( chainer, 41UL, &bidZ, 0U,  p0.uc );
  fd_chainer_verified_hash_insert( chainer, 41UL, &bidZ, 32U, p1.uc );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_slotv_t * vZ = fd_chainer_slot_version_query( chainer, 41UL, &bidZ );
  fd_chainer_fec_t *   s0 = fd_chainer_fec_query( chainer, 41UL, 0U,  &bidZ );
  fd_chainer_fec_t *   s1 = fd_chainer_fec_query( chainer, 41UL, 32U, &bidZ );
  FD_TEST( vZ && s0 && s1 );
  FD_TEST( fd_hash_eq( &s0->merkle_root, &p0 ) && !s0->complete );
  FD_TEST( fd_hash_eq( &s1->merkle_root, &p1 ) && !s1->complete );
  ulong fec_used = fd_fec_pool_used( chainer->fec_pool );

  /* Case 1: repaired shreds arrive with the full root, no version named.
     Set 0 completes; set 1 gets a single shred.  Both sentinels take
     the full root in place: same entries, no new FEC. */

  FD_TEST( !feed_fec( chainer, 41UL, 0U, 0, &r0, 40UL, &bid0 ) );
  fd_chainer_shred_insert( chainer, 41UL, 35U, 0, FD_CHAINER_SRC_TURBINE, test_rx_tick, &r1, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( !fd_chainer_verify( chainer ) );

  FD_TEST( fd_chainer_fec_query( chainer, 41UL, 0U,  &bidZ )==s0 );
  FD_TEST( fd_chainer_fec_query( chainer, 41UL, 32U, &bidZ )==s1 );
  FD_TEST( fd_hash_eq( &s0->merkle_root, &r0 ) && s0->complete );
  FD_TEST( fd_hash_eq( &s1->merkle_root, &r1 ) );
  for( uint i=0U; i<32U; i++ ) FD_TEST( fd_chainer_shred_test( chainer, vZ, i ) );
  FD_TEST(  fd_chainer_shred_test( chainer, vZ, 35U ) );
  FD_TEST( !fd_chainer_shred_test( chainer, vZ, 36U ) );
  FD_TEST( vZ->buffered_idx==31U );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==fec_used );
  FD_TEST( !fd_chainer_turbine_slotv_query( chainer, 41UL ) );

  /* Case 2: a second notar-fallback version learns set 0 by prefix
     after the full root is already held.  The padded root finds the
     complete FEC directly: no new FEC, the version joins it and its
     completion is replayed, so the version gets the set (complete)
     without any shreds. */

  fd_hash_t bidY = mkhash( 300UL );
  fd_chainer_verified_block_insert( chainer, 41UL, bidY );
  fd_chainer_verified_parent_fec_count( chainer, 41UL, &bidY, 2U, 40UL, &bid0 );
  fd_chainer_verified_hash_insert( chainer, 41UL, &bidY, 0U, p0.uc );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_slotv_t * vY = fd_chainer_slot_version_query( chainer, 41UL, &bidY );
  FD_TEST( vY );
  /* Y holds its own entry for the set, not Z's, but it carries the
     same root and adopts the completion Z already drove. */
  fd_chainer_fec_t * y0 = fd_chainer_fec_query( chainer, 41UL, 0U, &bidY );
  FD_TEST( y0 && y0!=s0 );
  FD_TEST( fd_chainer_fec_query( chainer, 41UL, 0U, &bidZ )==s0 );  /* Z keeps its own */
  FD_TEST( fd_hash_eq( &s0->merkle_root, &r0 ) );                   /* full root kept, not clobbered by the prefix */
  FD_TEST( fd_hash_eq( &y0->merkle_root, &r0 ) && y0->complete );   /* Y's copy mirrors it */
  FD_TEST( !y0->root );                                             /* Z's entry is the one keyed in the map */
  for( uint i=0U; i<32U; i++ ) FD_TEST( fd_chainer_shred_test( chainer, vY, i ) );
  FD_TEST( vY->buffered_idx==31U );

  ulong used_y = fd_fec_pool_used( chainer->fec_pool );
  fd_chainer_shred_insert( chainer, 41UL, 3U, 0, FD_CHAINER_SRC_TURBINE, test_rx_tick, &r0, AG_UNKNOWN_SLOT, NULL ); /* a duplicate of a shred we hold: no-op */
  FD_TEST( !fd_chainer_verify( chainer ) );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==used_y );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: FECs keyed by 20-byte root prefix" ));
}

/* Turbine equivocation without a sentinel: a second root for a FEC set
   we already have is dropped, and the FEC set keeps its first-seen
   root. */

static void
test_equivocation_drop( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 90UL, &bid0 );

  fd_hash_t r0    = mkhash( 1UL );
  fd_hash_t r0dup = mkhash( 2UL );
  FD_TEST( !feed_fec( chainer, 91UL, 0U, 0, &r0, 90UL, &bid0 ) );

  fd_chainer_slotv_t * v0 = slotv_at( chainer, 91UL, 0UL );
  ulong fec_free = fd_fec_pool_free( fec_pool );

  /* a different root for the same FEC set, with no sentinel authorizing
     it -> rejected, and neither the shred bits nor the recorded root
     change */

  FD_TEST( feed_fec( chainer, 91UL, 0U, 0, &r0dup, AG_UNKNOWN_SLOT, NULL )==1 );
  FD_TEST( fd_fec_pool_free( fec_pool )==fec_free );
  FD_TEST( fd_hash_eq( &fec_at( chainer, 91UL, 0U, 0UL )->merkle_root, &r0 ) );
  FD_TEST( !fec_rooted_at( chainer, 91UL, 0U, 1UL ) );
  FD_TEST( v0->buffered_idx==31U );
  FD_TEST( slotv_shred_cnt( chainer, v0 )==32UL );

  /* a duplicate completion of the same root is idempotent */

  FD_TEST( !feed_fec( chainer, 91UL, 0U, 0, &r0, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( fd_fec_pool_free( fec_pool )==fec_free );
  FD_TEST( v0->buffered_idx==31U && v0->buffered_fec_idx==31U );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: turbine equivocation without a sentinel is dropped" ));
}

/* fd_chainer_verify is this harness's main safety net, so check that it
   is not vacuous: break each invariant it is supposed to catch, confirm
   it reports, and restore. */

static void
test_verify_detects( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_chainer_slotv_t     * slotv_pool = chainer->slotv_pool;
  fd_slotv_map_t * slotv_map  = chainer->slotv_map;

  FD_TEST( fd_chainer_verify( NULL ) );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 110UL, &bid0 );

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );
  FD_TEST( !feed_fec( chainer, 111UL, 0U,  0, &r0, 110UL,           &bid0 ) );
  FD_TEST( !feed_fec( chainer, 111UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL  ) );

  fd_chainer_slotv_t * s = slotv_at( chainer, 111UL, 0UL );
  FD_TEST( s->complete_idx==63U );

  /* header */

  chainer->magic ^= 1UL; FD_TEST( fd_chainer_verify( chainer ) ); chainer->magic ^= 1UL;

  /* shred index ordering */

  s->buffered_idx  = 64U; FD_TEST( fd_chainer_verify( chainer ) ); s->buffered_idx  = 63U;
  s->delivered_idx = 95U; FD_TEST( fd_chainer_verify( chainer ) ); s->delivered_idx = 63U;
  FD_TEST( !fd_chainer_verify( chainer ) );

  /* nothing may live below the root */

  chainer->root = 111UL; FD_TEST( fd_chainer_verify( chainer ) ); chainer->root = 110UL;
  FD_TEST( !fd_chainer_verify( chainer ) );

  /* extra notar-fallback versions are legal; removing one just leaves a
     slot with fewer versions, which is not a defect. */

  fd_hash_t bidA = mkhash( 200UL );
  fd_hash_t bidB = mkhash( 201UL );
  fd_chainer_verified_block_insert( chainer, 111UL, bidA );
  fd_chainer_verified_block_insert( chainer, 111UL, bidB );
  FD_TEST( !fd_chainer_verify( chainer ) );

  fd_chainer_slotv_t * v1 = fd_chainer_slot_version_query( chainer, 111UL, &bidA );
  FD_TEST( v1 && fd_chainer_slot_version_query( chainer, 111UL, &bidB ) );

  FD_TEST( fd_slotv_map_ele_remove_fast( slotv_map, v1, slotv_pool )==v1 );
  FD_TEST( !fd_chainer_verify( chainer ) ); /* a hole at a version is not a defect */

  fd_slotv_map_ele_insert( slotv_map, v1, slotv_pool );
  FD_TEST( !fd_chainer_verify( chainer ) );

  /* a slot's FECs must be owned by some version present in the map;
     removing the version that owns them leaves them claimed by nobody. */

  FD_TEST( fd_slotv_map_ele_remove_fast( slotv_map, s, slotv_pool )==s );
  FD_TEST( fd_chainer_verify( chainer ) );
  fd_slotv_map_ele_insert( slotv_map, s, slotv_pool );
  FD_TEST( !fd_chainer_verify( chainer ) );

  teardown( chainer );
  FD_LOG_NOTICE(( "pass: fd_chainer_verify detects broken invariants" ));
}

/* Output order under equivocation: when a second version of a slot
   diverges in the MIDDLE, delivering that version must re-emit the whole
   block from FEC set 0 -- the shared prefix included -- so replay always
   receives a contiguous block starting at set 0, not just the diverging
   tail.  Here version 0 (turbine) completes first; the notar-fallback
   version 1 shares sets 0,32 and diverges at 64,96,128. */

static void
test_output_order_redeliver( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 50UL, &bid0 );

  fd_hash_t A  = mkhash( 1UL ); /* set 0   (shared)             */
  fd_hash_t B  = mkhash( 2UL ); /* set 32  (shared)             */
  fd_hash_t C0 = mkhash( 3UL ); /* set 64  version 0            */
  fd_hash_t D0 = mkhash( 4UL ); /* set 96  version 0            */
  fd_hash_t E0 = mkhash( 5UL ); /* set 128 version 0            */
  fd_hash_t C1 = mkhash( 6UL ); /* set 64  version 1 (diverges) */
  fd_hash_t D1 = mkhash( 7UL ); /* set 96  version 1            */
  fd_hash_t E1 = mkhash( 8UL ); /* set 128 version 1            */

  /* version 0 (turbine): full 5-set block, completes first */
  FD_TEST( !feed_fec( chainer, 51UL, 0U,   0, &A,  50UL,            &bid0 ) );
  FD_TEST( !feed_fec( chainer, 51UL, 32U,  0, &B,  AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( chainer, 51UL, 64U,  0, &C0, AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( chainer, 51UL, 96U,  0, &D0, AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( chainer, 51UL, 128U, 1, &E0, AG_UNKNOWN_SLOT, NULL  ) );

  /* version 0 delivered the whole block, in order, from set 0 */
  out_rec_t exp0[] = {
    { 51UL, 0U, A }, { 51UL, 32U, B }, { 51UL, 64U, C0 }, { 51UL, 96U, D0 }, { 51UL, 128U, E0 },
  };
  expect_out( chainer, exp0, 5UL );

  /* a notar-fallback cert names a different block for slot 51 */
  fd_hash_t bidX = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 51UL, bidX );
  fd_chainer_verified_parent_fec_count( chainer, 51UL, &bidX, 5U, 50UL, &bid0 );

  /* shared prefix: sets 0,32 match version 0 and deliver without repair */
  fd_hash_t mr;
  mr = A; fd_chainer_verified_hash_insert( chainer, 51UL, &bidX, 0U,  mr.uc );
  mr = B; fd_chainer_verified_hash_insert( chainer, 51UL, &bidX, 32U, mr.uc );

  /* diverging tail: sets 64,96,128 are new roots -> sentinels, then repaired */
  mr = C1; fd_chainer_verified_hash_insert( chainer, 51UL, &bidX, 64U,  mr.uc );
  mr = D1; fd_chainer_verified_hash_insert( chainer, 51UL, &bidX, 96U,  mr.uc );
  mr = E1; fd_chainer_verified_hash_insert( chainer, 51UL, &bidX, 128U, mr.uc );
  FD_TEST( !fd_chainer_verify( chainer ) );

  FD_TEST( !feed_fec( chainer, 51UL, 64U,  0, &C1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( !feed_fec( chainer, 51UL, 96U,  0, &D1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( !feed_fec( chainer, 51UL, 128U, 1, &E1, AG_UNKNOWN_SLOT, NULL ) );

  /* THE INVARIANT: version 1 re-delivered the ENTIRE block from set 0 --
     shared prefix (A,B) re-emitted ahead of the diverging tail
     (C1,D1,E1) -- even though the equivocation point is at set 64. */
  out_rec_t exp1[] = {
    { 51UL, 0U, A }, { 51UL, 32U, B }, { 51UL, 64U, C1 }, { 51UL, 96U, D1 }, { 51UL, 128U, E1 },
  };
  expect_out( chainer, exp1, 5UL );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: output order re-delivers full block from set 0 (equivocation mid-slot)" ));
}

/* Same invariant, but version 1's diverging FEC sets ARRIVE OUT OF ORDER
   (set 96 is repaired before set 64).  Filling 96 while 64 is still a
   hole must not deliver anything; once 64 lands, the whole block is
   re-delivered from set 0, in order.  Version 0 is fully complete first
   so it owns its own roots at every position (no first-seen-wins
   interaction with version 1's roots). */

static void
test_output_order_out_of_order( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 60UL, &bid0 );

  fd_hash_t A  = mkhash( 1UL ); /* set 0  (shared)             */
  fd_hash_t B  = mkhash( 2UL ); /* set 32 (shared)             */
  fd_hash_t C0 = mkhash( 3UL ); /* set 64 version 0            */
  fd_hash_t D0 = mkhash( 4UL ); /* set 96 version 0            */
  fd_hash_t C1 = mkhash( 6UL ); /* set 64 version 1 (diverges) */
  fd_hash_t D1 = mkhash( 7UL ); /* set 96 version 1            */

  /* version 0 (turbine): full 4-set block, completes first and owns its
     own root at every position */
  FD_TEST( !feed_fec( chainer, 61UL, 0U,  0, &A,  60UL,            &bid0 ) );
  FD_TEST( !feed_fec( chainer, 61UL, 32U, 0, &B,  AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( chainer, 61UL, 64U, 0, &C0, AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( chainer, 61UL, 96U, 1, &D0, AG_UNKNOWN_SLOT, NULL  ) );
  out_rec_t exp0[] = { { 61UL, 0U, A }, { 61UL, 32U, B }, { 61UL, 64U, C0 }, { 61UL, 96U, D0 } };
  expect_out( chainer, exp0, 4UL );

  /* notar-fallback version 1 shares 0,32 and diverges at 64,96 */
  fd_hash_t bidX = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 61UL, bidX );
  fd_chainer_verified_parent_fec_count( chainer, 61UL, &bidX, 4U, 60UL, &bid0 );

  fd_hash_t mr;
  mr = A;  fd_chainer_verified_hash_insert( chainer, 61UL, &bidX, 0U,  mr.uc );
  mr = B;  fd_chainer_verified_hash_insert( chainer, 61UL, &bidX, 32U, mr.uc );
  mr = C1; fd_chainer_verified_hash_insert( chainer, 61UL, &bidX, 64U, mr.uc );
  mr = D1; fd_chainer_verified_hash_insert( chainer, 61UL, &bidX, 96U, mr.uc );

  /* the shared prefix (0,32) delivered when its roots were recorded */
  fd_chainer_slotv_t * v1 = slotv_at( chainer, 61UL, 1UL );
  FD_TEST( v1->delivered_idx==63U );

  /* OUT OF ORDER: repair fills set 96 before set 64.  Set 64 is still a
     hole, so nothing new may be delivered. */
  FD_TEST( !feed_fec( chainer, 61UL, 96U, 1, &D1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( v1->delivered_idx==63U ); /* 96 buffered but held: 64 missing */

  /* set 64 lands: 64 then 96 deliver, in order */
  FD_TEST( !feed_fec( chainer, 61UL, 64U, 0, &C1, AG_UNKNOWN_SLOT, NULL ) );

  /* THE INVARIANT: version 1 re-delivered the whole block from set 0, in
     order -- shared prefix (A,B) ahead of the diverging tail (C1,D1) --
     even though set 96 arrived before set 64. */
  out_rec_t exp1[] = { { 61UL, 0U, A }, { 61UL, 32U, B }, { 61UL, 64U, C1 }, { 61UL, 96U, D1 } };
  expect_out( chainer, exp1, 4UL );

  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: output order out-of-order FEC arrival re-delivers from set 0" ));
}

/* Per-block shred limit is a runtime value.  The shred tile's resolver
   bounds every position by the same limit before it reaches the
   chainer, which asserts it; the last legal position must work. */

static void
test_shred_limit( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 10UL, &bid0 );

  uint const shred_max = (uint)FD_SHRED_BLK_MAX;

  /* the last legal position is accepted */
  fd_hash_t rL = mkhash( 2UL );
  FD_TEST( !feed_fec( chainer, 11UL, shred_max-(uint)FD_FEC_SHRED_CNT, 1, &rL, 10UL, &bid0 ) );
  fd_chainer_slotv_t * v0 = slotv_at( chainer, 11UL, 0UL );
  FD_TEST( v0 && v0->complete_idx==shred_max-1U );
  FD_TEST(  fd_chainer_shred_test( chainer, v0, shred_max-1U ) );
  FD_TEST( !fd_chainer_shred_test( chainer, v0, shred_max    ) ); /* beyond the limit: never present */
  FD_TEST( !fd_chainer_shred_test( chainer, v0, UINT_MAX     ) );
  FD_TEST( slotv_shred_cnt( chainer, v0 )==FD_FEC_SHRED_CNT );
  FD_TEST( !fd_chainer_fec_query( chainer, 11UL, shred_max, &v0->block_id ) );
  FD_TEST( !fd_chainer_verify( chainer ) );
  FD_TEST( slotv_shred_cnt( chainer, v0 )==FD_FEC_SHRED_CNT );

  /* a getParentAndFecCount naming exactly the limit connects the version */
  fd_hash_t bidX = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 11UL, bidX );
  fd_chainer_slotv_t * v1 = fd_chainer_slot_version_query( chainer, 11UL, &bidX );
  FD_TEST( v1 && v1->complete_idx==UINT_MAX && v1->parent_slot==AG_UNKNOWN_SLOT );
  fd_chainer_verified_parent_fec_count( chainer, 11UL, &bidX, (uint)FD_FEC_BLK_MAX, 10UL, &bid0 );
  FD_TEST( fd_chainer_slot_version_query( chainer, 10UL, &bid0 ) ); /* returns the parent version */
  FD_TEST( v1->complete_idx==shred_max-1U && v1->connected );
  FD_TEST( !fd_chainer_verify( chainer ) );

  teardown( chainer );
  FD_LOG_NOTICE(( "pass: the last legal shred position and FEC count are accepted" ));
}

/* Under bench limits a block holds 4x the FEC sets: the per-version FEC
   table is sized at runtime, so positions above FD_FEC_BLK_MAX are
   owned per version, shared, equivocated and pruned like any other. */

static void
test_bench_shred_limit( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup_sized( wksp, 8UL, BENCH_SHRED_MAX );
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_chainer_fec_t   * fec_pool   = chainer->fec_pool;
  ulong slotv_free0 = fd_slotv_pool_free( slotv_pool );
  ulong fec_free0   = fd_fec_pool_free  ( fec_pool   );

  uint const shred_max = (uint)BENCH_SHRED_MAX;
  uint const last      = shred_max-(uint)FD_FEC_SHRED_CNT; /* fec_set_idx of the last FEC set */
  FD_TEST( last>=FD_SHRED_BLK_MAX );                        /* beyond the production limit */

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 10UL, &bid0 );

  /* turbine version of slot 11: set 0 and the last set */
  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t rA = mkhash( 2UL );
  FD_TEST( !feed_fec( chainer, 11UL, 0U,   0, &r0, 10UL,            &bid0 ) );
  FD_TEST( !feed_fec( chainer, 11UL, last, 1, &rA, AG_UNKNOWN_SLOT, NULL  ) );
  fd_chainer_slotv_t * v0 = slotv_at( chainer, 11UL, 0UL );
  FD_TEST( v0->complete_idx==shred_max-1U && v0->buffered_idx==31U );
  FD_TEST( slotv_shred_cnt( chainer, v0 )==2UL*FD_FEC_SHRED_CNT );
  for( uint i=last; i<shred_max; i++ ) FD_TEST( fd_chainer_shred_test( chainer, v0, i ) );
  FD_TEST( !fd_chainer_shred_test( chainer, v0, shred_max ) );
  FD_TEST( fd_hash_eq( &fec_at( chainer, 11UL, last, 0UL )->merkle_root, &rA ) );
  FD_TEST( !fd_chainer_verify( chainer ) );

  /* a second version shares set 0 but equivocates on the last set:
     each version's row holds its own root at the high position */
  fd_hash_t bidX = mkhash( 200UL );
  fd_hash_t rB   = mkhash( 3UL );
  fd_chainer_verified_block_insert( chainer, 11UL, bidX );
  fd_chainer_verified_parent_fec_count( chainer, 11UL, &bidX, shred_max/(uint)FD_FEC_SHRED_CNT, 10UL, &bid0 );
  fd_hash_t mr;
  mr = r0; fd_chainer_verified_hash_insert( chainer, 11UL, &bidX, 0U,   mr.uc );
  mr = rB; fd_chainer_verified_hash_insert( chainer, 11UL, &bidX, last, mr.uc );
  FD_TEST( !fd_chainer_verify( chainer ) );
  fd_chainer_slotv_t * v1 = slotv_at( chainer, 11UL, 1UL );
  FD_TEST( v1->complete_idx==shred_max-1U && v1->delivered_idx==31U );
  FD_TEST( !feed_fec( chainer, 11UL, last, 1, &rB, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( fd_hash_eq( &fec_at( chainer, 11UL, last, 0UL )->merkle_root, &rA ) );
  FD_TEST( fd_hash_eq( &fec_at( chainer, 11UL, last, 1UL )->merkle_root, &rB ) );
  FD_TEST( fd_chainer_slotv_fecs( chainer, v0 )[ last/FD_FEC_SHRED_CNT ]!=fd_chainer_slotv_fecs( chainer, v1 )[ last/FD_FEC_SHRED_CNT ] );
  /* entries are private, so the versions hold distinct elements for
     the set they share -- same root, different pool index */
  FD_TEST( fd_chainer_slotv_fecs( chainer, v0 )[ 0 ]!=fd_chainer_slotv_fecs( chainer, v1 )[ 0 ] );
  FD_TEST( fd_hash_eq( &fec_at( chainer, 11UL, 0U, 0UL )->merkle_root, &fec_at( chainer, 11UL, 0U, 1UL )->merkle_root ) );
  for( uint i=last; i<shred_max; i++ ) FD_TEST( fd_chainer_shred_test( chainer, v1, i ) );
  FD_TEST( !fd_chainer_verify( chainer ) );

  /* publish past it: the prune walks the whole runtime-sized row */
  fd_hash_t r12 = mkhash( 4UL );
  FD_TEST( !feed_fec( chainer, 12UL, 0U, 1, &r12, 11UL, &bidX ) );
  /* Entries are private per version and a known set count pre-creates
     a placeholder per set, so the outstanding count is no longer a
     small fixed number.  The invariant that matters is that publish
     gives every one of them back, checked below. */
  FD_TEST( fd_fec_pool_free( fec_pool )<fec_free0 );
  out_ele_t * out_queue = chainer->out_queue;
  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }
  fd_chainer_publish( chainer, 12UL, NULL, NULL );
  FD_TEST( !fd_chainer_verify( chainer ) );
  FD_TEST( !fd_chainer_slot_query( chainer, 11UL ) );
  FD_TEST( fd_slotv_pool_free( slotv_pool )==slotv_free0-1UL );
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0        );

  teardown( chainer );
  FD_LOG_NOTICE(( "pass: bench shred limit owns/shares/prunes FEC sets above FD_FEC_BLK_MAX" ));
}

/* Set 0 remains enrolled until the final FEC is delivered, including
   when metadata is already known and a completed tail waits on a
   parent or a missing middle set. */

static void
test_token_release_on_delivery( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_hash_t root = mkhash( 100UL ), parent_id = mkhash( 101UL ), child_id = mkhash( 102UL );
  fd_hash_t p0 = mkhash( 1UL ), p1 = mkhash( 2UL );
  fd_hash_t c0 = mkhash( 3UL ), c1 = mkhash( 4UL ), c2 = mkhash( 5UL );
  fd_chainer_init( chainer, 10UL, &root );

  fd_chainer_verified_block_insert( chainer, 11UL, parent_id );
  fd_chainer_verified_parent_fec_count( chainer, 11UL, &parent_id, 2U, 10UL, &root );
  fd_chainer_verified_hash_insert( chainer, 11UL, &parent_id, 0U,  p0.uc );
  fd_chainer_verified_hash_insert( chainer, 11UL, &parent_id, 32U, p1.uc );
  FD_TEST( !feed_fec( chainer, 11UL, 0U, 0, &p0, 10UL, &root ) );
  fd_chainer_slotv_t * parent = fd_chainer_slot_version_query( chainer, 11UL, &parent_id );
  fd_chainer_fec_t * parent_token = fd_chainer_fec_query( chainer, 11UL, 0U, &parent_id );
  FD_TEST( parent->delivered_idx==31U && parent_token->treap );
  out_rec_t parent_prefix[] = { { 11UL, 0U, p0 } };
  expect_out( chainer, parent_prefix, 1UL );

  fd_chainer_verified_block_insert( chainer, 12UL, child_id );
  fd_chainer_verified_parent_fec_count( chainer, 12UL, &child_id, 3U, 11UL, &parent_id );
  fd_chainer_verified_hash_insert( chainer, 12UL, &child_id, 0U,  c0.uc );
  fd_chainer_verified_hash_insert( chainer, 12UL, &child_id, 32U, c1.uc );
  fd_chainer_verified_hash_insert( chainer, 12UL, &child_id, 64U, c2.uc );
  FD_TEST( !feed_fec( chainer, 12UL, 0U, 0, &c0, 11UL, &parent_id ) );
  fd_chainer_slotv_t * child = fd_chainer_slot_version_query( chainer, 12UL, &child_id );
  fd_chainer_fec_t * child_token = fd_chainer_fec_query( chainer, 12UL, 0U, &child_id );
  FD_TEST( child->connected && child->delivered_idx==UINT_MAX && child_token->treap );

  /* Repeated metadata and completion of the final set cannot release
     the token while delivery is still blocked. */
  fd_chainer_verified_parent_fec_count( chainer, 12UL, &child_id, 3U, 11UL, &parent_id );
  FD_TEST( child_token->treap );
  FD_TEST( !feed_fec( chainer, 12UL, 64U, 1, &c2, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( child->delivered_idx==UINT_MAX && child_token->treap );
  FD_TEST( !fd_chainer_fec_query( chainer, 12UL, 64U, &child_id )->treap );
  FD_TEST( out_queue_empty( chainer->out_queue ) );

  /* Completing the parent releases only its token.  The child delivers
     its prefix, then waits for set 32 with its own token still enrolled. */
  FD_TEST( !feed_fec( chainer, 11UL, 32U, 1, &p1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( parent->delivered_idx==63U && !parent_token->treap );
  FD_TEST( child->delivered_idx==31U && child_token->treap );
  out_rec_t cascade[] = { { 11UL, 32U, p1 }, { 12UL, 0U, c0 } };
  expect_out( chainer, cascade, 2UL );

  FD_TEST( !feed_fec( chainer, 12UL, 32U, 0, &c1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( child->delivered_idx==95U && !child_token->treap );
  FD_TEST( !has_work( chainer, child ) );
  out_rec_t tail[] = { { 12UL, 32U, c1 }, { 12UL, 64U, c2 } };
  expect_out( chainer, tail, 2UL );
  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: set 0 is released only after the slot's final FEC is delivered" ));
}

/* Named-only slots require a verified root before accepting shreds.
   Known roots cannot create eager state or be reused at another position. */

static void
test_shred_admission( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_hash_t root = mkhash( 100UL ), bid = mkhash( 101UL );
  fd_hash_t mr = mkhash( 1UL ), eager_mr = mkhash( 2UL ), tail_mr = mkhash( 3UL );
  fd_chainer_init( chainer, 10UL, &root );
  fd_chainer_verified_block_insert( chainer, 11UL, bid );
  fd_chainer_slotv_t * named = fd_chainer_slot_version_query( chainer, 11UL, &bid );
  FD_TEST( named && !fd_chainer_turbine_slotv_query( chainer, 11UL ) );
  ulong fec_used = fd_fec_pool_used( chainer->fec_pool );
  ulong slotv_used = fd_slotv_pool_used( chainer->slotv_pool );

  FD_TEST( feed_fec( chainer, 11UL, 64U, 1, &mr, 10UL, &root )==1 );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==fec_used );
  FD_TEST( fd_slotv_pool_used( chainer->slotv_pool )==slotv_used );
  FD_TEST( named->parent_slot==AG_UNKNOWN_SLOT && named->complete_idx==UINT_MAX );
  FD_TEST( named->buffered_idx==UINT_MAX && !named->metrics.first_shred_ts );
  FD_TEST( !named->metrics.turbine_cnt && !named->metrics.recovered_cnt );
  FD_TEST( !root_known( chainer, 11UL, 0U, &bid ) );

  /* The sentinel admits this root; the known-root path still learns
     parent information and updates reception and prefix bookkeeping. */
  fd_chainer_verified_hash_insert( chainer, 11UL, &bid, 0U, mr.uc );
  fd_chainer_shred_insert( chainer, 11UL, 0U, 0, FD_CHAINER_SRC_TURBINE, 10L, &mr, 10UL, &root );
  fd_chainer_fec_t * fec = fd_chainer_fec_query( chainer, 11UL, 0U, &bid );
  FD_TEST( fec->root && fec->data_idxs==1U && named->buffered_idx==0U );
  FD_TEST( named->parent_slot==10UL && named->connected && fd_hash_eq( &named->parent_block_id, &root ) );
  FD_TEST( named->metrics.turbine_cnt==1U && named->metrics.first_shred_ts==10L );

  /* A map hit at the wrong slot or FEC index is rejected before any
     allocation, bitmap update, or completion. */
  FD_TEST( feed_fec( chainer, 12UL, 0U, 1, &mr, 10UL, &root )==1 );
  FD_TEST( feed_fec( chainer, 11UL, 32U, 1, &mr, 10UL, &root )==1 );
  FD_TEST( !fd_chainer_slot_query( chainer, 12UL ) );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==fec_used );
  FD_TEST( fd_slotv_pool_used( chainer->slotv_pool )==slotv_used );
  FD_TEST( fec->data_idxs==1U && !fec->complete && !fec->slot_complete );
  FD_TEST( named->buffered_idx==0U && named->complete_idx==UINT_MAX );
  FD_TEST( named->metrics.turbine_cnt==1U && !named->metrics.recovered_cnt );

  fd_chainer_shred_insert( chainer, 11UL, 31U, 1, FD_CHAINER_SRC_REPAIR, 20L, &mr, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( named->complete_idx==31U && named->metrics.repair_cnt==1U );
  FD_TEST( !fd_chainer_fec_complete( chainer, 11UL, 0U, 1, 1, 0, 30L, &mr ) );
  FD_TEST( named->buffered_idx==31U && named->delivered_idx==31U );
  FD_TEST( named->metrics.recovered_cnt==30U && named->metrics.last_shred_ts==30L );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==fec_used );
  FD_TEST( fd_slotv_pool_used( chainer->slotv_pool )==slotv_used );
  FD_TEST( !fd_chainer_turbine_slotv_query( chainer, 11UL ) );
  out_rec_t named_out[] = { { 11UL, 0U, mr } };
  expect_out( chainer, named_out, 1UL );

  /* A new slot can still create turbine state.  Once finalized, it
     accepts known-root duplicates but cannot grow an unknown tail. */
  FD_TEST( !feed_fec( chainer, 13UL, 0U, 1, &eager_mr, 10UL, &root ) );
  fd_chainer_slotv_t * turbine = fd_chainer_turbine_slotv_query( chainer, 13UL );
  FD_TEST( turbine && !fd_hash_check_zero( &turbine->block_id ) );
  out_rec_t eager_out[] = { { 13UL, 0U, eager_mr } };
  expect_out( chainer, eager_out, 1UL );
  fec_used = fd_fec_pool_used( chainer->fec_pool );
  slotv_used = fd_slotv_pool_used( chainer->slotv_pool );
  FD_TEST( !feed_fec( chainer, 13UL, 0U, 1, &eager_mr, 10UL, &root ) );
  FD_TEST( feed_fec( chainer, 13UL, 32U, 1, &tail_mr, AG_UNKNOWN_SLOT, NULL )==1 );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==fec_used );
  FD_TEST( fd_slotv_pool_used( chainer->slotv_pool )==slotv_used );
  FD_TEST( turbine->complete_idx==31U && turbine->delivered_idx==31U && !has_work( chainer, turbine ) );
  FD_TEST( out_queue_empty( chainer->out_queue ) );
  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: known-root shred admission and eager creation" ));
}

/* Parent discovery must respect the root and require a named version.
   An existing turbine version must not hide a different parent block id. */

static void
test_parent_admission( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_hash_t root = mkhash( 100UL ), parent = mkhash( 200UL ), zero = {0};
  fd_chainer_init( chainer, 10UL, &root );

  ulong parents[] = { 9UL, 10UL, 12UL };
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_hash_t mr = mkhash( 300UL+i );
    fd_hash_t const * id = i==2UL ? &zero : &parent;
    fd_chainer_shred_insert( chainer, 20UL+i, 0U, 0, FD_CHAINER_SRC_TURBINE, 1L, &mr, parents[i], id );
    FD_TEST( !fd_chainer_slot_version_query( chainer, parents[i], id ) );
    FD_TEST( !fd_chainer_verify( chainer ) );
  }

  fd_hash_t mr_parent = mkhash( 400UL ), mr_child = mkhash( 401UL );
  fd_chainer_shred_insert( chainer, 15UL, 0U, 0, FD_CHAINER_SRC_TURBINE, 1L, &mr_parent, 10UL, &root );
  fd_chainer_slotv_t * turbine = fd_chainer_turbine_slotv_query( chainer, 15UL );
  FD_TEST( turbine );
  fd_chainer_shred_insert( chainer, 25UL, 0U, 0, FD_CHAINER_SRC_TURBINE, 1L, &mr_child, 15UL, &parent );
  fd_chainer_slotv_t * ancestor = fd_chainer_slot_version_query( chainer, 15UL, &parent );
  FD_TEST( ancestor && ancestor!=turbine );
  FD_TEST( fd_hash_check_zero( &turbine->block_id ) && !has_work( chainer, turbine ) );
  fd_chainer_fec_t * fec0 = fd_chainer_fec_query( chainer, 15UL, 0U, &parent );
  FD_TEST( fec0 && fec0->treap );
  FD_TEST( !fd_chainer_verify( chainer ) );

  ulong free_cnt = fd_slotv_pool_free( chainer->slotv_pool );
  fd_chainer_shred_insert( chainer, 25UL, 0U, 0, FD_CHAINER_SRC_TURBINE, 2L, &mr_child, 15UL, &parent );
  FD_TEST( fd_slotv_pool_free( chainer->slotv_pool )==free_cnt );
  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: parent discovery admission and exact version lookup" ));
}

static void
test_slot_inval( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_hash_t root = mkhash( 100UL ), bid = mkhash( 101UL );
  fd_hash_t r0 = mkhash( 1UL ), r1 = mkhash( 2UL ), r2 = mkhash( 3UL ), r3 = mkhash( 4UL );
  fd_chainer_init( chainer, 10UL, &root );
  fd_chainer_slot_inval( chainer, 10UL );
  fd_chainer_slot_inval( chainer, 11UL );
  FD_TEST( !fd_chainer_slot_query( chainer, 11UL ) );
  FD_TEST( !feed_fec( chainer, 11UL, 0U, 0, &r0, 10UL, &root ) );
  fd_chainer_shred_insert( chainer, 11UL, 32U, 0, FD_CHAINER_SRC_TURBINE, 1L, &r1, AG_UNKNOWN_SLOT, NULL );
  fd_chainer_slotv_t * v = fd_chainer_turbine_slotv_query( chainer, 11UL );
  ulong used = fd_fec_pool_used( chainer->fec_pool );
  FD_TEST( out_queue_cnt( chainer->out_queue )==1UL && has_work( chainer, v ) );
  fd_chainer_slot_inval( chainer, 11UL );
  fd_chainer_slot_inval( chainer, 11UL );
  FD_TEST( fd_chainer_turbine_slotv_query( chainer, 11UL )==v && !has_work( chainer, v ) );
  FD_TEST( fd_fec_pool_used( chainer->fec_pool )==used && out_queue_cnt( chainer->out_queue )==1UL );
  /* Treap removal does not change admission or delivery eligibility. */
  fd_chainer_shred_insert( chainer, 11UL, 64U, 0, FD_CHAINER_SRC_TURBINE, 1L, &r2, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( fec_at( chainer, 11UL, 64U, 0UL )->treap );
  FD_TEST( !fec_at( chainer, 11UL, 0U, 0UL )->treap );
  FD_TEST( !fec_complete( chainer, 11UL, 32U, 0, 1, 0, &r1 ) );
  FD_TEST( fec_at( chainer, 11UL, 32U, 0UL )->complete );
  FD_TEST( v->delivered_idx==63U && v->buffered_fec_idx==63U && fd_hash_check_zero( &v->block_id ) );
  FD_TEST( !fec_complete( chainer, 11UL, 64U, 1, 1, 0, &r2 ) );
  FD_TEST( v->delivered_idx==95U && !fd_hash_check_zero( &v->block_id ) && !has_work( chainer, v ) );
  out_rec_t expected[] = { {11UL,0U,r0}, {11UL,32U,r1}, {11UL,64U,r2} };
  expect_out( chainer, expected, 3UL );

  fd_chainer_verified_block_insert( chainer, 11UL, bid );
  fd_chainer_verified_parent_fec_count( chainer, 11UL, &bid, 3U, 10UL, &root );
  fd_chainer_verified_hash_insert( chainer, 11UL, &bid, 0U, r0.uc );
  fd_chainer_verified_hash_insert( chainer, 11UL, &bid, 32U, r1.uc );
  fd_chainer_verified_hash_insert( chainer, 11UL, &bid, 64U, r2.uc );
  fd_chainer_slotv_t * named = fd_chainer_slot_version_query( chainer, 11UL, &bid );
  FD_TEST( named->delivered_idx==95U && v->delivered_idx==95U );
  expect_out( chainer, expected, 3UL );

  /* A derived turbine version waiting for its parent is not eager. */
  FD_TEST( !feed_fec( chainer, 13UL, 0U, 1, &r3, 12UL, &bid ) );
  fd_chainer_slotv_t * complete = fd_chainer_turbine_slotv_query( chainer, 13UL );
  FD_TEST( !fd_hash_check_zero( &complete->block_id ) && has_work( chainer, complete ) );
  fd_chainer_slot_inval( chainer, 13UL );
  FD_TEST( has_work( chainer, complete ) );
  FD_TEST( !fd_chainer_verify( chainer ) );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: invalidation removes current repair work without gating admission or delivery" ));
}

static void
test_blk_final( fd_wksp_t * wksp ) {
  fd_chainer_t * chainer = setup( wksp );
  fd_hash_t root = mkhash( 100UL ), bid = mkhash( 101UL ), loser = mkhash( 102UL );
  fd_hash_t r0 = mkhash( 1UL ), r1 = mkhash( 2UL ), r2 = mkhash( 3UL );
  fd_chainer_init( chainer, 10UL, &root );
  FD_TEST( !feed_fec( chainer, 11UL, 0U, 0, &r0, 10UL, &root ) );
  fd_chainer_shred_insert( chainer, 11UL, 32U, 0, FD_CHAINER_SRC_TURBINE, 1L, &r1, AG_UNKNOWN_SLOT, NULL );
  fd_chainer_verified_block_insert( chainer, 11UL, bid );
  fd_chainer_verified_parent_fec_count( chainer, 11UL, &bid, 2U, 10UL, &root );
  fd_chainer_verified_hash_insert( chainer, 11UL, &bid, 0U, r0.uc );
  fd_chainer_verified_hash_insert( chainer, 11UL, &bid, 32U, r1.uc );
  fd_chainer_verified_block_insert( chainer, 11UL, loser );
  fd_chainer_verified_parent_fec_count( chainer, 11UL, &loser, 1U, 10UL, &root );
  fd_chainer_verified_hash_insert( chainer, 11UL, &loser, 0U, r2.uc );
  FD_TEST( !fec_complete( chainer, 11UL, 0U, 1, 1, 0, &r2 ) );
  fd_chainer_slotv_t * final = fd_chainer_slot_version_query( chainer, 11UL, &bid );
  fd_chainer_fec_t * f0 = fd_chainer_fec_query( chainer, 11UL, 0U, &bid );
  fd_chainer_fec_t * f1 = fd_chainer_fec_query( chainer, 11UL, 32U, &bid );
  FD_TEST( !f0->root && !f1->root && out_queue_cnt( chainer->out_queue )==3UL );

  void * store_mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( 16UL, 64UL, 0UL, 0UL, 0UL ), 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( store_mem, 16UL, 64UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 42UL ) );
  fd_store_map_t map[1];
  FD_TEST( store && fd_store_map_ljoin( store, map ) );
  fd_store_fec_t * stored;
  FD_TEST( !fd_store_insert( store, map, &r0, &stored ) );
  FD_TEST( !fd_store_insert( store, map, &r2, &stored ) );
  fd_chainer_blk_final( chainer, 11UL, &bid, store );
  FD_TEST( final->final && fd_slotv_pool_used( chainer->slotv_pool )==2UL && fd_fec_pool_used( chainer->fec_pool )==2UL );
  FD_TEST( !fd_chainer_turbine_slotv_query( chainer, 11UL ) && !fd_chainer_slot_version_query( chainer, 11UL, &loser ) );
  FD_TEST( f0->root && f0->data_idxs==UINT_MAX && f0->complete && f0->treap );
  FD_TEST( f1->root && f1->data_idxs==1U && !f1->complete && f1->treap );
  FD_TEST( fd_fec_map_ele_query( chainer->fec_map, &r0, NULL, chainer->fec_pool )==f0 );
  FD_TEST( fd_fec_map_ele_query( chainer->fec_map, &r1, NULL, chainer->fec_pool )==f1 );
  FD_TEST( !fd_fec_map_ele_query( chainer->fec_map, &r2, NULL, chainer->fec_pool ) );
  FD_TEST( fd_store_query( map, &r0 ) && !fd_store_query( map, &r2 ) );
  FD_TEST( out_queue_cnt( chainer->out_queue )==1UL );
  FD_TEST( out_queue_peek_head( chainer->out_queue )->slotv_idx==fd_slotv_pool_idx( chainer->slotv_pool, final ) );
  out_rec_t prefix[] = { {11UL,0U,r0} };
  expect_out( chainer, prefix, 1UL );
  fd_chainer_blk_final( chainer, 11UL, &bid, store );
  fd_chainer_blk_final( chainer, 11UL, &loser, store );
  FD_TEST( !fd_chainer_verified_block_insert( chainer, 11UL, loser ) );
  fd_chainer_verified_parent_fec_count( chainer, 11UL, &loser, 1U, 10UL, &root );
  fd_chainer_verified_hash_insert( chainer, 11UL, &loser, 0U, r2.uc );
  FD_TEST( fd_slotv_pool_used( chainer->slotv_pool )==2UL && final->final );
  FD_TEST( !fec_complete( chainer, 11UL, 32U, 1, 1, 0, &r1 ) );
  FD_TEST( final->delivered_idx==63U && !has_work( chainer, final ) );
  out_rec_t tail[] = { {11UL,32U,r1} };
  expect_out( chainer, tail, 1UL );

  /* Parent discovery cannot recreate a pruned competing version. */
  fd_hash_t child = mkhash( 103UL ), child_mr = mkhash( 4UL );
  fd_chainer_shred_insert( chainer, 12UL, 0U, 0, FD_CHAINER_SRC_TURBINE, 1L, &child_mr, 11UL, &loser );
  fd_chainer_verified_block_insert( chainer, 12UL, child );
  fd_chainer_verified_parent_fec_count( chainer, 12UL, &child, 1U, 11UL, &loser );
  FD_TEST( !fd_chainer_slot_version_query( chainer, 11UL, &loser ) );

  /* Unknown final replaces even a slot at its version limit. */
  for( ulong i=0UL; i<FD_CHAINER_SLOT_VER_MAX; i++ ) fd_chainer_verified_block_insert( chainer, 20UL, mkhash( 200UL+i ) );
  fd_hash_t fresh = mkhash( 300UL );
  fd_chainer_blk_final( chainer, 20UL, &fresh, NULL );
  fd_chainer_slotv_t * new_final = fd_chainer_slot_version_query( chainer, 20UL, &fresh );
  FD_TEST( new_final && new_final->final && has_work( chainer, new_final ) );
  FD_TEST( !fd_chainer_slot_version_query( chainer, 20UL, &(fd_hash_t){0} ) );
  FD_TEST( !fd_chainer_verify( chainer ) );
  fd_store_remove( store, map, &r0 );
  fd_wksp_free_laddr( store_mem );
  teardown( chainer );
  FD_LOG_NOTICE(( "pass: finality prunes siblings, transfers shared roots, and rejects stale events" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_fec_pool_layout();
  test_slot_inval                        ( wksp );
  test_blk_final                         ( wksp );
  test_shred_admission                   ( wksp );
  test_parent_admission                  ( wksp );
  test_basic                             ( wksp );
  test_token_release_on_delivery         ( wksp );
  test_shared_prefix                     ( wksp );
  test_notar_fallback_in_flight          ( wksp );
  test_sentinel_before_turbine           ( wksp );
  test_turbine_shred_after_notar_fallback( wksp );
  test_prefix_key                        ( wksp );
  test_output_order_redeliver            ( wksp );
  test_output_order_out_of_order         ( wksp );
  test_publish                           ( wksp );
  test_publish_large_block               ( wksp );
  test_publish_noncanonical_v0           ( wksp );
  test_versions_full                     ( wksp );
  test_equivocation_drop                 ( wksp );
  test_verify_detects                    ( wksp );
  test_shred_limit                       ( wksp );
  test_bench_shred_limit                 ( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
