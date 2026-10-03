#include "fd_rotor.h"

/* The rotor does not verify merkle proofs (fd_repair does that), so
   the merkle roots below are fabricated.  block_ids computed by the rotor are only ever checked for
   non-zero-ness, for round-tripping through
   fd_rotor_slot_version_query, or against a second identical
   computation.

   fd_rotor_verify runs after every mutation. */

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

/* The rotor rotor supports the full 30K-slot Alpenglow admission
   window with compact FEC bookkeeping. */

static void
test_fec_pool_layout( void ) {
  ulong const fec_max = 30000UL * FD_ROTOR_SLOT_VER_MAX * FD_FEC_BLK_MAX;
  FD_TEST( fec_max<(ulong)UINT_MAX       );
  FD_TEST( fec_max<fd_fec_pool_idx_null( NULL ) );
  FD_TEST( fec_max<fd_fec_map_ele_max()   );
  FD_TEST( sizeof(fd_rotor_fec_t)==88UL );
  FD_TEST( sizeof(((fd_rotor_fec_t *)NULL)->slot)==sizeof(uint) );
  FD_TEST( sizeof(((fd_rotor_fec_t *)NULL)->data_idxs)==sizeof(uint) );

  ulong chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  FD_TEST( fd_fec_map_footprint( chain_cnt )<=(512UL<<20)+64UL );

  /* bench limits: uint pool idxs (fd_rotor_fec, out_ele) still fit */
  ulong const bench_fec_max = 30000UL * FD_ROTOR_SLOT_VER_MAX * (BENCH_SHRED_MAX/FD_FEC_SHRED_CNT);
  FD_TEST( bench_fec_max<(ulong)UINT_MAX     );
  FD_TEST( bench_fec_max<fd_fec_map_ele_max() );

  /* footprint validates max_shreds_per_block and scales with it */
  FD_TEST( !fd_rotor_footprint( ELE_MAX, 0UL                     ) );
  FD_TEST( !fd_rotor_footprint( ELE_MAX, FD_FEC_SHRED_CNT+1UL    ) );
  FD_TEST( !fd_rotor_footprint( ELE_MAX, (1UL<<28)+FD_FEC_SHRED_CNT ) );
  FD_TEST( !fd_rotor_footprint( 30000UL, 1UL<<28 ) ); /* 30000*7*2^23 FEC elements do not fit uint indices */
  FD_TEST(  fd_rotor_footprint( 30000UL, BENCH_SHRED_MAX ) );
  FD_TEST(  fd_rotor_footprint( ELE_MAX, FD_SHRED_BLK_MAX )<fd_rotor_footprint( ELE_MAX, BENCH_SHRED_MAX ) );
}

/* block_at returns the `ord`-th version of slot in CREATION order (ord 0
   is the first version created -- the turbine version in the usual case
   where a turbine shred/FEC lands before any notar-fallback cert), or
   NULL.  Blocks are keyed by slot in a MAP_MULTI whose chain is
   newest-first, so creation order is the reverse of iteration order. */

static fd_rotor_blk_t *
block_at( fd_rotor_t * rotor, ulong slot, ulong ord ) {
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_block_map_t * block_map  = rotor->block_map;
  fd_rotor_blk_t * list[ FD_ROTOR_SLOT_VER_MAX ];
  ulong            n          = 0UL;
  for( ulong i = fd_block_map_idx_query( block_map, &slot, ULONG_MAX, block_pool );
             i != ULONG_MAX;
             i = fd_block_map_idx_next_const( i, ULONG_MAX, block_pool ) ) {
    list[ n++ ] = fd_block_pool_ele( block_pool, i );
  }
  if( ord>=n ) return NULL;
  return list[ n-1UL-ord ]; /* reverse iteration -> creation order */
}

/* block_shred_cnt returns the number of data shreds block has, summed
   over the FECs it owns. */

static ulong
block_shred_cnt( fd_rotor_t *           rotor,
                 fd_rotor_blk_t const * block ) {
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  uint const     * fecs     = fd_rotor_block_fecs( rotor, block );
  ulong            cnt      = 0UL;
  for( ulong k=0UL; k<rotor->fec_blk_max; k++ ) {
    uint idx = fecs[ k ];
    if( idx==UINT_MAX ) continue;
    cnt += (ulong)fd_uint_popcnt( fd_fec_pool_ele( fec_pool, (ulong)idx )->data_idxs );
  }
  return cnt;
}

/* fec_at returns the FEC the ord-th (creation-order) version of slot owns
   at fec_set_idx, or NULL. */

static fd_rotor_fec_t *
fec_at( fd_rotor_t * rotor, ulong slot, uint fec_set_idx, ulong ord ) {
  fd_rotor_blk_t * block = block_at( rotor, slot, ord );
  if( FD_UNLIKELY( !block ) ) return NULL;
  return fd_rotor_fec_query( rotor, slot, fec_set_idx, &block->block_id );
}

static fd_rotor_t *
setup_sized( fd_wksp_t * wksp, ulong ele_max, ulong max_shreds_per_block ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_rotor_align(), fd_rotor_footprint( ele_max, max_shreds_per_block ), 1UL );
  FD_TEST( mem );
  fd_rotor_t * rotor = fd_rotor_join( fd_rotor_new( mem, ele_max, max_shreds_per_block, 42UL ) );
  FD_TEST( rotor );
  FD_TEST( rotor->fec_blk_max==max_shreds_per_block/FD_FEC_SHRED_CNT );
  FD_TEST( !fd_rotor_verify( rotor ) ); /* an empty rotor is consistent */
  return rotor;
}

static fd_rotor_t *
setup( fd_wksp_t * wksp ) {
  return setup_sized( wksp, ELE_MAX, FD_SHRED_BLK_MAX );
}

/* teardown does not verify: some subtests deliberately end on a
   known-broken state. */

static void
teardown( fd_rotor_t * rotor ) {
  fd_wksp_free_laddr( rotor );
}

/* test_rx_tick is the arrival tick handed to every rotor insert in
   these tests.  Tests that care about the reception timestamps bump it
   between steps; the rest leave it alone. */

static long test_rx_tick = 1L;

/* fec_complete wraps fd_rotor_fec_complete and returns its rejected
   flag (0 accepted, 1 rejected), which is what these tests check. */

static int
fec_complete( fd_rotor_t * rotor, ulong slot, uint fec_set_idx, int slot_complete, int data_complete, int is_leader, fd_hash_t * mr ) {
  int rejected;
  fd_rotor_fec_complete( rotor, slot, fec_set_idx, slot_complete, data_complete, is_leader, test_rx_tick, mr, &rejected, NULL );
  return rejected;
}

/* feed_fec_src drives one FEC set through the rotor the way the shred
   tile does: a shred_insert per shred, then one fec_insert once the set
   is complete.  Parent information rides on the first shred only (pass
   AG_UNKNOWN_SLOT to leave the parent unknown), the same way the shred
   tile only learns the parent from the shred header.  src is the
   provenance every shred of the set is delivered with.  Returns the
   fd_rotor_fec_complete return code (0 accepted, 1 rejected). */

static int
feed_fec_src( fd_rotor_t *      rotor,
              ulong             slot,
              uint              fec_set_idx,
              int               slot_complete,
              int               src,
              fd_hash_t const * mr,
              ulong             parent_slot,
              fd_hash_t const * parent_block_id ) {
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    int last = ( i==(uint)FD_FEC_SHRED_CNT-1U );
    fd_rotor_shred_insert( rotor, slot, fec_set_idx+i, slot_complete && last, src, test_rx_tick, mr, 1,
                           i ? AG_UNKNOWN_SLOT : parent_slot,
                           i ? NULL            : parent_block_id );
    FD_TEST( !fd_rotor_verify( rotor ) );
  }
  fd_hash_t mr_ = *mr;
  int rc = fec_complete( rotor, slot, fec_set_idx, slot_complete, slot_complete, 0, &mr_ );
  FD_TEST( !fd_rotor_verify( rotor ) );
  return rc;
}

/* feed_fec is feed_fec_src for the usual all-turbine set. */

static int
feed_fec( fd_rotor_t *      rotor,
          ulong             slot,
          uint              fec_set_idx,
          int               slot_complete,
          fd_hash_t const * mr,
          ulong             parent_slot,
          fd_hash_t const * parent_block_id ) {
  return feed_fec_src( rotor, slot, fec_set_idx, slot_complete, FD_ROTOR_SRC_TURBINE, mr, parent_slot, parent_block_id );
}

/* One delivered FEC, identified the way replay sees it: (slot,
   fec_set_idx) position and the FEC set's merkle root. */

typedef struct { ulong slot; uint fec_set_idx; fd_hash_t mr; } out_rec_t;

/* drain_out pops the rotor's entire out_queue into recs in delivery
   (FIFO) order, decoding each fd_fec_pool index back to its position and
   root, and returns the count.  Empties the queue. */

static ulong
drain_out( fd_rotor_t * rotor, out_rec_t * recs, ulong recs_max ) {
  out_ele_t      * out_queue = rotor->out_queue;
  fd_rotor_fec_t * fec_pool  = rotor->fec_pool;
  ulong            cnt       = 0UL;
  while( !out_queue_empty( out_queue ) ) {
    out_ele_t out_ele = out_queue_pop_head( out_queue );
    fd_rotor_fec_t * fec = fd_fec_pool_ele( fec_pool, out_ele.fec_idx );
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
expect_out( fd_rotor_t * rotor, out_rec_t const * exp, ulong exp_cnt ) {
  out_rec_t recs[ 64 ];
  ulong cnt = drain_out( rotor, recs, 64UL );
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
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 10UL, &bid0, NULL, NULL );
  FD_TEST( !fd_rotor_verify( rotor ) );

  FD_TEST( rotor->root==10UL );
  FD_TEST( fd_rotor_highest_repaired_slot( rotor )==10UL );

  fd_rotor_blk_t * root = fd_rotor_slot_query( rotor, 10UL );
  FD_TEST( root==block_at( rotor, 10UL, 0UL ) );
  FD_TEST( fd_hash_eq( &root->block_id, &bid0 ) );
  FD_TEST( root->connected );
  FD_TEST( root->complete_idx==0U && root->buffered_idx==0U && root->delivered_idx==0U );

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );

  /* first FEC set of slot 11, shred by shred */

  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    fd_rotor_shred_insert( rotor, 11UL, i, 0, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r0, 1, i ? AG_UNKNOWN_SLOT : 10UL, i ? NULL : &bid0 );
    FD_TEST( !fd_rotor_verify( rotor ) );

    fd_rotor_blk_t * block = block_at( rotor, 11UL, 0UL );
    FD_TEST( block );                                          /* created on the first shred */
    FD_TEST( fd_rotor_shred_test( rotor, block, i  ) );
    FD_TEST( block_shred_cnt( rotor, block )==i+1UL );
    FD_TEST( block->buffered_idx==i );                         /* contiguous from 0 */
    FD_TEST( block->complete_idx==UINT_MAX );                  /* tip still unknown */
  }

  fd_rotor_blk_t * s11 = block_at( rotor, 11UL, 0UL );
  FD_TEST( s11->parent_slot==10UL );
  FD_TEST( fd_hash_eq( &s11->parent_block_id, &bid0 ) );
  FD_TEST( s11->connected );                  /* parent is the root */
  FD_TEST( s11->buffered_fec_idx==UINT_MAX ); /* no FEC completion yet */
  FD_TEST( s11->delivered_idx   ==UINT_MAX );
  /* the FEC is born on the first shred now, but is not completed until
     fd_rotor_fec_complete marks it reconstructable */
  fd_rotor_fec_t * pre0 = fec_at( rotor, 11UL, 0U, 0UL );
  FD_TEST( pre0 && !pre0->complete );
  FD_TEST( fd_hash_check_zero( &s11->block_id ) );

  /* FEC completion for set 0 */

  fd_hash_t mr = r0;
  FD_TEST( !fec_complete( rotor, 11UL, 0U, 0, 0, 0, &mr ) );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_fec_t * f0 = fec_at( rotor, 11UL, 0U, 0UL );
  FD_TEST( f0 );
  FD_TEST( fd_hash_eq( &f0->merkle_root, &r0 ) );
  FD_TEST( f0->complete && !f0->slot_complete );
  FD_TEST( s11->buffered_fec_idx==31U );
  FD_TEST( s11->delivered_idx   ==31U ); /* delivered: parent (the root) is delivered */
  FD_TEST( fd_hash_check_zero( &s11->block_id ) );

  /* second and last FEC set */

  FD_TEST( !feed_fec( rotor, 11UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL ) );

  FD_TEST( s11->complete_idx    ==63U );
  FD_TEST( s11->buffered_idx    ==63U );
  FD_TEST( s11->buffered_fec_idx==63U );
  FD_TEST( s11->delivered_idx   ==63U );
  FD_TEST( block_shred_cnt( rotor, s11 )==64UL );
  FD_TEST( fd_rotor_highest_repaired_slot( rotor )==11UL );

  fd_rotor_fec_t * f1 = fec_at( rotor, 11UL, 32U, 0UL );
  FD_TEST( f1 );
  FD_TEST( fd_hash_eq( &f1->merkle_root, &r1 ) );
  FD_TEST( f1->slot_complete && f1->complete );

  /* the whole block has a block_id, and it round-trips */

  FD_TEST( !fd_hash_check_zero( &s11->block_id ) );
  fd_hash_t bid11 = s11->block_id;
  FD_TEST( fd_rotor_slot_version_query( rotor, 11UL, &bid11 )==s11 );
  FD_TEST( !fd_rotor_slot_version_query( rotor, 11UL, &r0    ) );

  /* the block_id is a pure function of the block: rebuilding the same
     block in a second rotor must produce the same id */

  fd_rotor_t * other = setup( wksp );
  fd_rotor_init( other, 10UL, &bid0, NULL, NULL );
  FD_TEST( !feed_fec( other, 11UL, 0U,  0, &r0, 10UL,            &bid0 ) );
  FD_TEST( !feed_fec( other, 11UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( fd_hash_eq( &block_at( other, 11UL, 0UL )->block_id, &bid11 ) );
  FD_TEST( !fd_rotor_verify( other ) );
  teardown( other );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: basic single-version turbine block" ));
}

/* (b) Two versions of a slot whose FEC sets 0..k carry the same merkle
   root and diverge after: the shared prefix must be recorded against
   both versions, so the notar-fallback version does not re-repair
   shreds we already hold. */

static void
test_shared_prefix( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 20UL, &bid0, NULL, NULL );

  fd_hash_t r0  = mkhash( 1UL );
  fd_hash_t r1  = mkhash( 2UL );
  fd_hash_t r2a = mkhash( 3UL );
  fd_hash_t r2b = mkhash( 4UL );

  /* turbine's block for slot 21: three FEC sets, complete */

  FD_TEST( !feed_fec( rotor, 21UL, 0U,  0, &r0,  20UL,            &bid0 ) );
  FD_TEST( !feed_fec( rotor, 21UL, 32U, 0, &r1,  AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( rotor, 21UL, 64U, 1, &r2a, AG_UNKNOWN_SLOT, NULL  ) );

  fd_rotor_blk_t * v0 = block_at( rotor, 21UL, 0UL );
  FD_TEST( v0->complete_idx==95U && v0->buffered_idx==95U && v0->delivered_idx==95U );
  FD_TEST( !fd_hash_check_zero( &v0->block_id ) );
  fd_hash_t bid_v0 = v0->block_id;

  /* a notar-fallback cert names a different block for slot 21 */

  fd_hash_t bidX = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 21UL, bidX, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_blk_t * v1 = block_at( rotor, 21UL, 1UL );
  FD_TEST( v1 );
  FD_TEST( fd_rotor_slot_version_query( rotor, 21UL, &bidX )==v1 );
  FD_TEST( v1->slot==21UL );

  /* getParentAndFecCount response: three FEC sets, parent is the root */

  FD_TEST( !v1->metrics.first_meta_ts );
  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 21UL, &bidX, 3U, 20UL, &bid0, 100L )==fd_rotor_slot_version_query( rotor, 20UL, &bid0 ) ); /* returns the parent version */
  FD_TEST( v1->metrics.first_meta_ts==100L ); /* stamped by the first metadata response */
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( v1->complete_idx==95U );
  FD_TEST( v1->parent_slot ==20UL );
  FD_TEST( v1->connected );

  /* getFecRoot responses for the shared prefix.  Both roots are already
     complete under version 0, so version 1 must pick up those shreds
     without any repair. */

  fd_hash_t mr = r0;
  fd_rotor_verified_hash_insert( rotor, 21UL, &bidX, 0U, mr.uc, 200L );
  FD_TEST( v1->metrics.first_meta_ts==100L ); /* later responses do not restamp */
  FD_TEST( !fd_rotor_verify( rotor ) );
  mr = r1;
  fd_rotor_verified_hash_insert( rotor, 21UL, &bidX, 32U, mr.uc, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_fec_t * v1f0 = fec_at( rotor, 21UL, 0U,  1UL );
  fd_rotor_fec_t * v1f1 = fec_at( rotor, 21UL, 32U, 1UL );
  FD_TEST( v1f0 && v1f0->complete && fd_hash_eq( &v1f0->merkle_root, &r0 ) );
  FD_TEST( v1f1 && v1f1->complete && fd_hash_eq( &v1f1->merkle_root, &r1 ) );

  /* both versions hold the shared shreds */

  for( uint i=0U; i<64U; i++ ) {
    FD_TEST( fd_rotor_shred_test( rotor, v0, i  ) );
    FD_TEST( fd_rotor_shred_test( rotor, v1, i  ) );
  }
  FD_TEST( v1->buffered_idx    ==63U );
  FD_TEST( v1->buffered_fec_idx==63U );
  FD_TEST( v1->delivered_idx   ==63U );

  /* the version's roots are recorded at exactly the expected positions */

  FD_TEST( !fd_rotor_fec_query( rotor, 21UL, 64U, &bidX ) ); /* no root yet */
  FD_TEST( !fd_rotor_fec_query( rotor, 21UL, 0U,  &r0   ) ); /* unknown version */
  fd_rotor_fec_t * v0f2 = fd_rotor_fec_query( rotor, 21UL, 64U, &bid_v0 );
  FD_TEST( v0f2 && fd_hash_eq( &v0f2->merkle_root, &r2a ) );     /* version 0 */

  /* getFecRoot response for the diverging set: no version holds this
     root, so a sentinel is created and its shreds must be repaired */

  mr = r2b;
  fd_rotor_verified_hash_insert( rotor, 21UL, &bidX, 64U, mr.uc, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_fec_t * v1f2 = fec_at( rotor, 21UL, 64U, 1UL );
  FD_TEST( v1f2 && !v1f2->complete && fd_hash_eq( &v1f2->merkle_root, &r2b ) );
  FD_TEST( v1f2->slot_complete );          /* last set of the cert's fec_set_cnt */
  FD_TEST( v1->buffered_fec_idx==63U );    /* an incomplete FEC must not extend the prefix */
  FD_TEST( v1->delivered_idx   ==63U );    /* nor be delivered */
  FD_TEST( !fd_rotor_shred_test( rotor, v1, 64U  ) );

  /* repair fills the diverging set.  Only version 1 records it, and
     version 0 keeps its own root for that set. */

  FD_TEST( !feed_fec( rotor, 21UL, 64U, 1, &r2b, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( v1f2->complete );
  for( uint i=64U; i<96U; i++ ) FD_TEST( fd_rotor_shred_test( rotor, v1, i  ) );
  FD_TEST( v1->buffered_idx    ==95U );
  FD_TEST( v1->buffered_fec_idx==95U );
  FD_TEST( v1->delivered_idx   ==95U );
  FD_TEST( fd_hash_eq( &fec_at( rotor, 21UL, 64U, 0UL )->merkle_root, &r2a ) );
  FD_TEST( fd_hash_eq( &v0->block_id, &bid_v0 ) ); /* version 0 untouched */

  FD_TEST( !fd_hash_check_zero( &v1->block_id ) );
  FD_TEST(  fd_hash_eq( &v1->block_id, &bidX    ) ); /* nt clobbered */
  FD_TEST( !fd_hash_eq( &v1->block_id, &bid_v0  ) ); /* different block than version 0 */
  FD_TEST(  fd_rotor_slot_version_query( rotor, 21UL, &bidX ) );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: shared prefix across two versions" ));
}

/* (c) A notar-fallback cert for a block that is still in flight from
   turbine.  We cannot compute the in-flight block's id yet, so we cannot
   tell the cert names the same block: a redundant block is created by
   design, and the turbine version is abandoned -- it may be the same
   block the cert version is repairing, and delivering both would hand
   replay two banks for the same {slot, block_id}.  The structure must
   stay consistent. */

static void
test_notar_fallback_in_flight( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );
  fd_rotor_blk_t * block_pool = rotor->block_pool;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 30UL, &bid0, NULL, NULL );

  fd_hash_t r0 = mkhash( 1UL );
  FD_TEST( !feed_fec( rotor, 31UL, 0U, 0, &r0, 30UL, &bid0 ) );

  fd_rotor_blk_t * v0 = block_at( rotor, 31UL, 0UL );
  FD_TEST( v0->complete_idx==UINT_MAX );          /* still in flight */
  FD_TEST( fd_hash_check_zero( &v0->block_id ) ); /* so no block_id yet */

  fd_hash_t bidY = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 31UL, bidY, 123L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_blk_t * v1 = block_at( rotor, 31UL, 1UL );
  FD_TEST( v1 && v1!=v0 );
  FD_TEST( fd_rotor_slot_version_query( rotor, 31UL, &bidY )==v1 );
  FD_TEST( fd_hash_eq( &v1->block_id, &bidY ) );

  /* the redundant version starts empty: nothing is shared with version
     0 until a getFecRoot response proves the roots match */

  FD_TEST( v1->complete_idx    ==UINT_MAX );
  FD_TEST( v1->buffered_idx    ==UINT_MAX );
  FD_TEST( v1->buffered_fec_idx==UINT_MAX );
  FD_TEST( v1->delivered_idx   ==UINT_MAX );
  FD_TEST( v1->parent_slot     ==AG_UNKNOWN_SLOT );
  FD_TEST( !v1->connected );
  FD_TEST( block_shred_cnt( rotor, v1 )==0UL );
  FD_TEST( !fec_at( rotor, 31UL, 0U, 1UL ) );

  /* version 0 keeps its data but is abandoned: it will never deliver
     or finalize a block_id */

  FD_TEST( v0->buffered_idx==31U && v0->buffered_fec_idx==31U );
  FD_TEST( fec_at( rotor, 31UL, 0U, 0UL ) );
  FD_TEST( v0->abandoned && v0->metrics.abandoned_ts==123L );
  FD_TEST( !v1->metrics.abandoned_ts );

  /* a repeat of the same cert is a no-op -- no third version */

  ulong block_free = fd_block_pool_free( block_pool );
  fd_rotor_verified_block_insert( rotor, 31UL, bidY, 456L );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( fd_block_pool_free( block_pool )==block_free );
  FD_TEST( v0->metrics.abandoned_ts==123L );
  FD_TEST( !block_at( rotor, 31UL, 2UL ) );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: notar-fallback for an in-flight turbine block" ));
}

/* (d) A getFecRoot sentinel lands before turbine reaches that FEC set,
   and turbine then delivers the set with the same root.  Version 0 (the
   turbine block) genuinely contains that FEC set, so it must end up with
   its own entry and shred bits. */

static void
test_sentinel_before_turbine( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 40UL, &bid0, NULL, NULL );

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );

  /* turbine has set 0 of slot 41 only */

  FD_TEST( !feed_fec( rotor, 41UL, 0U, 0, &r0, 40UL, &bid0 ) );
  fd_rotor_blk_t * v0 = block_at( rotor, 41UL, 0UL );
  FD_TEST( v0->buffered_idx==31U && v0->buffered_fec_idx==31U );

  /* a notar-fallback cert arrives, and its getFecRoot response for set 1
     names the root turbine is about to deliver (the versions share that
     FEC set) */

  fd_hash_t bidZ = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 41UL, bidZ, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 41UL, &bidZ, 2U, 40UL, &bid0, 0L ) );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_hash_t mr = r1;
  fd_rotor_verified_hash_insert( rotor, 41UL, &bidZ, 32U, mr.uc, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_blk_t * v1 = block_at( rotor, 41UL, 1UL );
  FD_TEST( v1 && v1->complete_idx==63U );
  fd_rotor_fec_t * v1f1 = fec_at( rotor, 41UL, 32U, 1UL );
  FD_TEST( v1f1 && !v1f1->complete && fd_hash_eq( &v1f1->merkle_root, &r1 ) );

  /* turbine now delivers set 1 of slot 41 with that same root */

  FD_TEST( !feed_fec( rotor, 41UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( v0->buffered_idx == 63U );

  FD_TEST( v1f1->complete );
  for( uint i=32U; i<64U; i++ ) FD_TEST( fd_rotor_shred_test( rotor, v1, i  ) );
  FD_TEST( v1->buffered_fec_idx==UINT_MAX ); /* still missing set 0's getFecRoot */
  FD_TEST( v1->delivered_idx   ==UINT_MAX );

  /* The turbine version gets the shared FEC set too.  Keying the FEC map
     by root made "does this version hold this root" a per-version
     question, and fd_rotor_fec_complete now joins the turbine version to
     the entry the sentinel created rather than short-circuiting on it. */

  fd_rotor_fec_t * v0f1 = fec_at( rotor, 41UL, 32U, 0UL );
  FD_TEST( v0f1 );
  FD_TEST( v0f1->complete );
  FD_TEST( fd_hash_eq( &v0f1->merkle_root, &r1 ) );
  for( uint i=32U; i<64U; i++ ) FD_TEST( fd_rotor_shred_test( rotor, v0, i  ) );
  FD_TEST( v0->complete_idx    ==63U );
  FD_TEST( v0->buffered_idx    ==63U );

  /* The cert abandoned version 0, so even though the turbine block is
     whole its FEC prefix is not extended, its block_id never finalizes,
     and its slot-complete FEC is not delivered.  Only set 0 -- queued
     before the cert arrived -- ever reached replay. */

  FD_TEST( v0->abandoned );
  FD_TEST( v0->buffered_fec_idx==31U );
  FD_TEST( fd_hash_check_zero( &v0->block_id ) );
  out_rec_t exp[] = { { 41UL, 0U, r0 } };
  expect_out( rotor, exp, 1UL );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: getFecRoot sentinel before turbine" ));
}

/* (e) Turbine keeps delivering the honest block after a notar-fallback
   cert created a version 1 for the slot, for a FEC set that has no
   sentinel.  The shred belongs to the turbine block and must be recorded
   against version 0. */

static void
test_turbine_shred_after_notar_fallback( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 50UL, &bid0, NULL, NULL );

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );

  FD_TEST( !feed_fec( rotor, 51UL, 0U, 0, &r0, 50UL, &bid0 ) );
  fd_rotor_blk_t * v0 = block_at( rotor, 51UL, 0UL );
  FD_TEST( v0->buffered_idx==31U );

  /* notar-fallback cert -> version 1 exists, but no getFecRoot response
     has arrived for set 1 */

  fd_hash_t bidY = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 51UL, bidY, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( block_at( rotor, 51UL, 1UL ) );

  /* turbine delivers set 1 of the honest block */

  for( uint i=32U; i<64U; i++ ) {
    fd_rotor_shred_insert( rotor, 51UL, i, i==63U, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r1, 1, AG_UNKNOWN_SLOT, NULL );
    FD_TEST( !fd_rotor_verify( rotor ) );
  }
  fd_hash_t mr = r1;
  int rc = fec_complete( rotor, 51UL, 32U, 1, 1, 0, &mr );

  /* The honest block's shreds are still accepted.  The old guard dropped
     any shred whose root no version held as soon as a second version
     existed; the turbine version now always takes them, so the FEC-level
     and shred-level bookkeeping stay in agreement. */

  FD_TEST( !rc );
  for( uint i=32U; i<64U; i++ ) FD_TEST( fd_rotor_shred_test( rotor, v0, i  ) );
  FD_TEST( v0->complete_idx    ==63U );
  FD_TEST( v0->buffered_idx    ==63U );

  /* But the cert abandoned version 0: the FEC prefix is not extended,
     the block_id never finalizes, and the whole block -- possibly the
     very one the cert version is repairing -- is not delivered under
     the turbine version.  Only set 0, queued before the cert arrived,
     ever reached replay. */

  FD_TEST( v0->abandoned );
  FD_TEST( v0->buffered_fec_idx==31U );
  FD_TEST( fd_hash_check_zero( &v0->block_id ) );
  out_rec_t exp[] = { { 51UL, 0U, r0 } };
  expect_out( rotor, exp, 1UL );
  FD_TEST( !fd_rotor_verify( rotor ) );

  teardown( rotor );
  FD_LOG_NOTICE(( "pass: turbine shred after notar-fallback" ));
}

/* (e, continued) A turbine block invalidated because its shred-0 block
   header was rejected.  Like a cert-abandoned block it keeps taking
   shreds but never extends its FEC prefix, finalizes or delivers.  A
   slot with no turbine version yet gets an abandoned one, so shreds
   that arrive later cannot start a live version.  Only the turbine
   version is touched, and a later notarized block id for the slot still
   builds its own version, which reuses the turbine data whose roots it
   learns and delivers under the cert's id. */

static void
test_invalidate( fd_wksp_t * wksp ) {
  fd_rotor_t     * rotor      = setup( wksp );
  fd_rotor_blk_t * block_pool = rotor->block_pool;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 90UL, &bid0, NULL, NULL );

  /* a slot with no turbine version: an abandoned one is created, and
     shreds that arrive after land on it rather than a new version */

  fd_hash_t r9 = mkhash( 9UL );
  ulong block_free = fd_block_pool_free( block_pool );
  fd_rotor_invalidate( rotor, 92UL, test_rx_tick, ABANDON_REASON_INVALID_BLOCK_HEADER );
  FD_TEST( !fd_rotor_verify( rotor ) );
  fd_rotor_blk_t * v9 = fd_rotor_turbine_block_query( rotor, 92UL );
  FD_TEST( v9 && v9->abandoned && v9->parent_slot==AG_UNKNOWN_SLOT );
  FD_TEST( v9->metrics.abandoned_reason==ABANDON_REASON_INVALID_BLOCK_HEADER );
  FD_TEST( fd_block_pool_free( block_pool )==block_free-1UL );

  for( uint i=1U; i<FD_FEC_SHRED_CNT; i++ ) {
    FD_TEST( !fd_rotor_shred_insert( rotor, 92UL, i, 0, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r9, 1, AG_UNKNOWN_SLOT, NULL ) );
  }
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( block_at( rotor, 92UL, 0UL )==v9 && !block_at( rotor, 92UL, 1UL ) );
  FD_TEST( v9->abandoned && fd_rotor_shred_test( rotor, v9, 1U ) );
  FD_TEST( fd_block_pool_free( block_pool )==block_free-1UL );
  block_free = fd_block_pool_free( block_pool );

  /* turbine streams set 0 of slot 91 without shred 0 (its header was
     rejected), so the parent stays unknown, then it is invalidated */

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );
  for( uint i=1U; i<FD_FEC_SHRED_CNT; i++ ) {
    fd_rotor_shred_insert( rotor, 91UL, i, 0, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r0, 1, AG_UNKNOWN_SLOT, NULL );
  }
  fd_rotor_blk_t * v0 = block_at( rotor, 91UL, 0UL );
  FD_TEST( v0 && v0->turbine && !v0->abandoned );
  FD_TEST( v0->parent_slot==AG_UNKNOWN_SLOT );

  fd_rotor_invalidate( rotor, 91UL, test_rx_tick, ABANDON_REASON_INVALID_BLOCK_HEADER );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( v0->abandoned );
  FD_TEST( fd_rotor_turbine_block_query( rotor, 91UL )==v0 );
  FD_TEST( fd_block_pool_free( block_pool )==block_free-1UL ); /* marked, not freed */

  /* the rest of the block still lands, but nothing is delivered, the
     FEC prefix does not move and no block_id is derived */

  fd_hash_t mr = r0;
  FD_TEST( !fec_complete( rotor, 91UL, 0U, 0, 0, 0, &mr ) );
  FD_TEST( !feed_fec( rotor, 91UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( v0->complete_idx==63U && v0->buffered_idx==63U );
  FD_TEST( v0->buffered_fec_idx==UINT_MAX );
  FD_TEST( v0->delivered_idx   ==UINT_MAX );
  FD_TEST( fd_hash_check_zero( &v0->block_id ) );
  expect_out( rotor, NULL, 0UL );

  /* a notarized block id for the slot gets a version of its own, which
     the invalidation does not reach */

  fd_hash_t bidN = mkhash( 200UL );
  FD_TEST( fd_rotor_verified_block_insert( rotor, 91UL, bidN, 0L ) );
  FD_TEST( !fd_rotor_verify( rotor ) );
  fd_rotor_blk_t * v1 = fd_rotor_slot_version_query( rotor, 91UL, &bidN );
  FD_TEST( v1 && v1!=v0 && !v1->turbine && !v1->abandoned );

  fd_rotor_invalidate( rotor, 91UL, test_rx_tick, ABANDON_REASON_INVALID_BLOCK_HEADER );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( !v1->abandoned );

  /* its metadata names roots turbine already completed, so it picks up
     both sets without repair and delivers them in order */

  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 91UL, &bidN, 2U, 90UL, &bid0, 0L ) );
  FD_TEST( v1->connected );
  mr = r0; fd_rotor_verified_hash_insert( rotor, 91UL, &bidN, 0U,  mr.uc, 0L );
  mr = r1; fd_rotor_verified_hash_insert( rotor, 91UL, &bidN, 32U, mr.uc, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( v1->complete_idx==63U && v1->buffered_fec_idx==63U );
  FD_TEST( v1->delivered_idx==63U );
  FD_TEST( fd_hash_eq( &v1->block_id, &bidN ) );
  FD_TEST( fd_rotor_highest_repaired_slot( rotor )==91UL );
  out_rec_t exp[] = { { 91UL, 0U, r0 }, { 91UL, 32U, r1 } };
  expect_out( rotor, exp, 2UL );

  /* the invalidated version is still abandoned and rooting the
     notarized version prunes it */

  FD_TEST( v0->abandoned && fd_hash_check_zero( &v0->block_id ) );
  fd_rotor_publish( rotor, 91UL, &bidN, NULL );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( !fd_rotor_turbine_block_query( rotor, 91UL ) );
  FD_TEST( fd_rotor_slot_version_query( rotor, 91UL, &bidN )==v1 );

  teardown( rotor );
  FD_LOG_NOTICE(( "pass: invalidated turbine block, later notarized version delivers" ));
}

/* (e, continued) A turbine block whose data shreds disagree on
   parent_off is abandoned on the first disagreeing shred: it never
   completes a FEC, finalizes or delivers.  Shreds without a header
   (parent_off 0, as from FEC completion) are not compared. */

static void
test_parent_off_mismatch( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 90UL, &bid0, NULL, NULL );

  fd_hash_t r0 = mkhash( 1UL );
  fd_rotor_shred_insert( rotor, 91UL, 0U, 0, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r0, 1, 90UL, &bid0 );
  fd_rotor_blk_t * v0 = block_at( rotor, 91UL, 0UL );
  FD_TEST( v0 && v0->turbine && !v0->abandoned && v0->parent_off==1 );

  for( uint i=1U; i<FD_FEC_SHRED_CNT-1U; i++ ) {
    fd_rotor_shred_insert( rotor, 91UL, i, 0, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r0, i==5U ? 0 : 1, AG_UNKNOWN_SLOT, NULL );
  }
  FD_TEST( !v0->abandoned );

  fd_rotor_shred_insert( rotor, 91UL, FD_FEC_SHRED_CNT-1U, 0, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r0, 2, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( v0->abandoned );
  FD_TEST( v0->metrics.abandoned_reason==ABANDON_REASON_PARENT_OFF_MISMATCH );
  FD_TEST( v0->parent_off==1 );

  fd_hash_t mr = r0;
  FD_TEST( !fec_complete( rotor, 91UL, 0U, 1, 1, 0, &mr ) );
  FD_TEST( v0->buffered_fec_idx==UINT_MAX && v0->delivered_idx==UINT_MAX );
  FD_TEST( fd_hash_check_zero( &v0->block_id ) );
  expect_out( rotor, NULL, 0UL );

  teardown( rotor );
  FD_LOG_NOTICE(( "pass: parent_off mismatch abandons the turbine version" ));
}

/* (f) Rooting and pruning: everything below the new root goes away and
   nothing leaks out of either pool. */

static void
test_publish( fd_wksp_t * wksp ) {
  fd_rotor_t     * rotor      = setup( wksp );
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_rotor_fec_t * fec_pool   = rotor->fec_pool;

  ulong block_free0 = fd_block_pool_free( block_pool );
  ulong fec_free0   = fd_fec_pool_free  ( fec_pool   );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 60UL, &bid0, NULL, NULL );

  /* slot 61: two FEC sets, chained to the root */

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );
  FD_TEST( !feed_fec( rotor, 61UL, 0U,  0, &r0, 60UL,            &bid0 ) );
  FD_TEST( !feed_fec( rotor, 61UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL  ) );
  fd_hash_t bid61 = block_at( rotor, 61UL, 0UL )->block_id;
  FD_TEST( !fd_hash_check_zero( &bid61 ) );

  /* slot 62: two FEC sets, chained to 61 */

  fd_hash_t r2 = mkhash( 3UL );
  fd_hash_t r3 = mkhash( 4UL );
  FD_TEST( !feed_fec( rotor, 62UL, 0U,  0, &r2, 61UL,            &bid61 ) );
  FD_TEST( !feed_fec( rotor, 62UL, 32U, 1, &r3, AG_UNKNOWN_SLOT, NULL   ) );
  FD_TEST( block_at( rotor, 62UL, 0UL )->delivered_idx==63U ); /* chain delivered */
  FD_TEST( fd_rotor_highest_repaired_slot( rotor )==62UL );

  FD_TEST( fd_block_pool_free( block_pool )==block_free0-3UL ); /* 60, 61, 62 */
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0  -4UL ); /* 4 FEC sets */

  /* drain the out queue */
  out_ele_t * out_queue = rotor->out_queue;
  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }

  fd_rotor_publish( rotor, 62UL, NULL, NULL );
  FD_TEST( !fd_rotor_verify( rotor ) );

  FD_TEST( rotor->root==62UL );
  FD_TEST( !block_at( rotor, 60UL, 0UL ) );
  FD_TEST( !block_at( rotor, 61UL, 0UL ) );
  FD_TEST( !fd_rotor_slot_query( rotor, 61UL ) );
  FD_TEST( !fec_at( rotor, 61UL, 0U,  0UL ) );
  FD_TEST( !fec_at( rotor, 61UL, 32U, 0UL ) );

  fd_rotor_blk_t * s62 = block_at( rotor, 62UL, 0UL );
  FD_TEST( s62 && s62->connected );
  /* the rooted slot's FEC data is never needed again, so publish releases
     it and clears the block's fec[] */
  FD_TEST( !fec_at( rotor, 62UL, 0U,  0UL ) );
  FD_TEST( !fec_at( rotor, 62UL, 32U, 0UL ) );

  /* no leaks: only slot 62's block survives; every FEC set is released */

  FD_TEST( fd_block_pool_free( block_pool )==block_free0-1UL );
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0        );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: publish prunes below the root without leaking" ));
}

/* (f, continued) Publishing past a block with more than 1024 shreds. */

static void
test_publish_large_block( fd_wksp_t * wksp ) {
  fd_rotor_t     * rotor      = setup( wksp );
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_rotor_fec_t * fec_pool   = rotor->fec_pool;

  ulong block_free0 = fd_block_pool_free( block_pool );
  ulong fec_free0   = fd_fec_pool_free  ( fec_pool   );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 70UL, &bid0, NULL, NULL );

  /* slot 71: 64 FEC sets = 2048 shreds */

  ulong fec_set_cnt = 64UL;
  for( ulong f=0UL; f<fec_set_cnt; f++ ) {
    fd_hash_t r = mkhash( 1000UL+f );
    FD_TEST( !feed_fec( rotor, 71UL, (uint)( f*FD_FEC_SHRED_CNT ), f==fec_set_cnt-1UL, &r,
                        f ? AG_UNKNOWN_SLOT : 70UL, f ? NULL : &bid0 ) );
  }
  fd_rotor_blk_t * s71 = block_at( rotor, 71UL, 0UL );
  FD_TEST( s71->complete_idx==2047U && s71->buffered_idx==2047U && s71->delivered_idx==2047U );
  FD_TEST( !fd_hash_check_zero( &s71->block_id ) );
  fd_hash_t bid71 = s71->block_id;

  /* slot 72, so there is something to publish to */

  fd_hash_t r = mkhash( 2000UL );
  FD_TEST( !feed_fec( rotor, 72UL, 0U, 1, &r, 71UL, &bid71 ) );

  FD_TEST( fd_block_pool_free( block_pool )==block_free0-3UL );             /* 70, 71, 72 */
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0-fec_set_cnt-1UL );   /* 64 + 1 */

  /* drain the out queue */
  out_ele_t * out_queue = rotor->out_queue;
  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }
  fd_rotor_publish( rotor, 72UL, NULL, NULL );

  FD_TEST( rotor->root==72UL );
  FD_TEST( !block_at( rotor, 70UL, 0UL ) );
  FD_TEST( !block_at( rotor, 71UL, 0UL ) );
  FD_TEST( fd_block_pool_free( block_pool )==block_free0-1UL ); /* blocks do not leak */
  FD_TEST( !fec_at( rotor, 71UL, 0U, 0UL ) );

  /* Nothing leaks above the old 1024-shred clamp: publish releases a
     slot's FECs via the fec map, so block size no longer bounds what it
     can release. */

  FD_TEST( fd_fec_pool_free( fec_pool )==fec_free0 ); /* every set released, root FECs included */
  FD_TEST( !fec_at( rotor, 71UL, 1024U, 0UL ) );
  FD_TEST( !fec_at( rotor, 71UL, 2016U, 0UL ) );
  FD_TEST( !fd_rotor_verify( rotor ) );

  teardown( rotor );
  FD_LOG_NOTICE(( "pass: publish past a >1024 shred block" ));
}

/* (f, continued) Rooting a non-v0 canonical version: the new root's
   version 0 is non-canonical and gets pruned along with the slot's FEC
   list, so the root survives without a version 0.  A subsequent publish
   over that v0-less root must still work -- the root is the one slot
   exempt from the "every slot has a version 0" invariant. */

static void
test_publish_noncanonical_v0( fd_wksp_t * wksp ) {
  fd_rotor_t     * rotor      = setup( wksp );
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_rotor_fec_t * fec_pool   = rotor->fec_pool;

  ulong block_free0 = fd_block_pool_free( block_pool );
  ulong fec_free0   = fd_fec_pool_free  ( fec_pool   );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 60UL, &bid0, NULL, NULL );

  /* slot 61 version 0: complete turbine block chained to the root */

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );
  FD_TEST( !feed_fec( rotor, 61UL, 0U,  0, &r0, 60UL,            &bid0 ) );
  FD_TEST( !feed_fec( rotor, 61UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL  ) );

  /* a notar-fallback cert names a different block for slot 61 */

  fd_hash_t bidX = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 61UL, bidX, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );
  fd_rotor_blk_t * v1 = block_at( rotor, 61UL, 1UL );
  FD_TEST( v1 );

  /* root the notar-fallback version: v0 is non-canonical and gets
     pruned, taking the slot's whole FEC list with it */

  out_ele_t * out_queue = rotor->out_queue;
  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }
  fd_rotor_publish( rotor, 61UL, &bidX, NULL );
  FD_TEST( !fd_rotor_verify( rotor ) ); /* a root without a version 0 is legal */

  FD_TEST( rotor->root==61UL );
  FD_TEST( fd_rotor_slot_version_query( rotor, 61UL, &bidX )==v1 ); /* canonical survives */
  FD_TEST( block_at( rotor, 61UL, 0UL )==v1 ); /* the sole surviving version */
  FD_TEST( !block_at( rotor, 61UL, 1UL ) );    /* turbine was pruned */
  FD_TEST( v1->connected );

  FD_TEST( !fec_at( rotor, 61UL, 0U,  0UL ) );
  FD_TEST( !fec_at( rotor, 61UL, 32U, 0UL ) );
  FD_TEST( fd_block_pool_free( block_pool )==block_free0-1UL ); /* only v1 of 61 */
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0        ); /* all FECs released */

  /* slot 62 chains to the v0-less root, then publishes over it */

  fd_hash_t r2 = mkhash( 3UL );
  FD_TEST( !feed_fec( rotor, 62UL, 0U, 1, &r2, 61UL, &bidX ) );
  FD_TEST( block_at( rotor, 62UL, 0UL )->connected );

  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }
  fd_rotor_publish( rotor, 62UL, NULL, NULL );
  FD_TEST( !fd_rotor_verify( rotor ) );

  FD_TEST( rotor->root==62UL );
  FD_TEST( !block_at( rotor, 61UL, 1UL ) );
  FD_TEST( fd_block_pool_free( block_pool )==block_free0-1UL ); /* only 62's v0 */
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0        ); /* rooted slot's FEC released too */

  teardown( rotor );
  FD_LOG_NOTICE(( "pass: publish roots a non-v0 canonical version" ));
}

/* (g) All FD_ROTOR_SLOT_VER_MAX versions of a slot: one turbine block
   plus three notar-fallbacks, the protocol maximum. */

static void
test_versions_full( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 80UL, &bid0, NULL, NULL );

  fd_hash_t r0 = mkhash( 1UL );
  FD_TEST( !feed_fec( rotor, 81UL, 0U, 0, &r0, 80UL, &bid0 ) ); /* version 0 */
  FD_TEST( block_at( rotor, 81UL, 0UL ) );

  for( ulong v=1UL; v<FD_ROTOR_SLOT_VER_MAX; v++ ) {
    fd_hash_t bid = mkhash( 200UL+v );
    fd_rotor_verified_block_insert( rotor, 81UL, bid, 0L );
    FD_TEST( !fd_rotor_verify( rotor ) );

    fd_rotor_blk_t * block = block_at( rotor, 81UL, v );
    FD_TEST( block );
    FD_TEST( fd_hash_eq( &block->block_id, &bid ) );
    FD_TEST( fd_rotor_slot_version_query( rotor, 81UL, &bid )==block ); /* dense scan finds it */
  }

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: all %d versions of a slot", FD_ROTOR_SLOT_VER_MAX ));
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
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 40UL, &bid0, NULL, NULL );

  /* full roots with a non-zero tail, so the padded prefix differs */
  fd_hash_t r0 = mkhash( 1UL ); r0.uc[ 24 ] = 0x5a;
  fd_hash_t r1 = mkhash( 2UL ); r1.uc[ 25 ] = 0x3c;
  fd_hash_t p0 = {0}; memcpy( p0.uc, r0.uc, FD_SHRED_MERKLE_NODE_SZ );
  fd_hash_t p1 = {0}; memcpy( p1.uc, r1.uc, FD_SHRED_MERKLE_NODE_SZ );

  /* a notar-fallback version of slot 41 learns both roots by prefix */
  fd_hash_t bidZ = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 41UL, bidZ, 0L );
  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 41UL, &bidZ, 2U, 40UL, &bid0, 0L ) );
  fd_rotor_verified_hash_insert( rotor, 41UL, &bidZ, 0U,  p0.uc, 0L );
  fd_rotor_verified_hash_insert( rotor, 41UL, &bidZ, 32U, p1.uc, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_blk_t * vZ = fd_rotor_slot_version_query( rotor, 41UL, &bidZ );
  fd_rotor_fec_t * s0 = fd_rotor_fec_query( rotor, 41UL, 0U,  &bidZ );
  fd_rotor_fec_t * s1 = fd_rotor_fec_query( rotor, 41UL, 32U, &bidZ );
  FD_TEST( vZ && s0 && s1 );
  FD_TEST( fd_hash_eq( &s0->merkle_root, &p0 ) && !s0->complete );
  FD_TEST( fd_hash_eq( &s1->merkle_root, &p1 ) && !s1->complete );
  ulong fec_used = fd_fec_pool_used( rotor->fec_pool );

  /* A verified getFecRoot answer for a set the version already holds
     changes nothing but still stamps the first metadata arrival. */

  FD_TEST( !vZ->metrics.first_meta_ts );
  FD_TEST( !fd_rotor_verified_hash_insert( rotor, 41UL, &bidZ, 0U, p0.uc, 300L ) );
  FD_TEST( vZ->metrics.first_meta_ts==300L );
  FD_TEST( fd_rotor_fec_query( rotor, 41UL, 0U, &bidZ )==s0 && fd_fec_pool_used( rotor->fec_pool )==fec_used );

  /* Case 1: repaired shreds arrive with the full root, no version named.
     Set 0 completes; set 1 gets a single shred.  Both sentinels take
     the full root in place: same entries, no new FEC. */

  FD_TEST( !feed_fec( rotor, 41UL, 0U, 0, &r0, 40UL, &bid0 ) );
  fd_rotor_shred_insert( rotor, 41UL, 35U, 0, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r1, 1, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( !fd_rotor_verify( rotor ) );

  FD_TEST( fd_rotor_fec_query( rotor, 41UL, 0U,  &bidZ )==s0 );
  FD_TEST( fd_rotor_fec_query( rotor, 41UL, 32U, &bidZ )==s1 );
  FD_TEST( fd_hash_eq( &s0->merkle_root, &r0 ) && s0->complete );
  FD_TEST( fd_hash_eq( &s1->merkle_root, &r1 ) );
  for( uint i=0U; i<32U; i++ ) FD_TEST( fd_rotor_shred_test( rotor, vZ, i ) );
  FD_TEST(  fd_rotor_shred_test( rotor, vZ, 35U ) );
  FD_TEST( !fd_rotor_shred_test( rotor, vZ, 36U ) );
  FD_TEST( vZ->buffered_idx==31U );
  FD_TEST( fd_fec_pool_used( rotor->fec_pool )==fec_used ); /* turbine version joined the same entries */

  /* Case 2: a second notar-fallback version learns set 0 by prefix
     after the full root is already held.  The padded root finds the
     complete FEC directly: no new FEC, the version joins it and its
     completion is replayed, so the version gets the set (complete)
     without any shreds. */

  fd_hash_t bidY = mkhash( 300UL );
  fd_rotor_verified_block_insert( rotor, 41UL, bidY, 0L );
  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 41UL, &bidY, 2U, 40UL, &bid0, 0L ) );
  fd_rotor_verified_hash_insert( rotor, 41UL, &bidY, 0U, p0.uc, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_blk_t * vY = fd_rotor_slot_version_query( rotor, 41UL, &bidY );
  FD_TEST( vY );
  FD_TEST( fd_rotor_fec_query( rotor, 41UL, 0U, &bidY )==s0 );  /* joined the full-root FEC */
  FD_TEST( fd_rotor_fec_query( rotor, 41UL, 0U, &bidZ )==s0 );  /* Z still owns it */
  FD_TEST( fd_hash_eq( &s0->merkle_root, &r0 ) );                   /* full root kept, not clobbered by the prefix */
  FD_TEST( fd_fec_pool_used( rotor->fec_pool )==fec_used );       /* no sentinel created */
  for( uint i=0U; i<32U; i++ ) FD_TEST( fd_rotor_shred_test( rotor, vY, i ) );
  FD_TEST( vY->buffered_idx==31U );

  fd_rotor_shred_insert( rotor, 41UL, 3U, 0, FD_ROTOR_SRC_TURBINE, test_rx_tick, &r0, 1, AG_UNKNOWN_SLOT, NULL ); /* a duplicate of a shred we hold: no-op */
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( fd_fec_pool_used( rotor->fec_pool )==fec_used );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: FECs keyed by 20-byte root prefix" ));
}

/* Turbine equivocation without a sentinel: a second root for a FEC set
   we already have is dropped, and the FEC set keeps its first-seen
   root. */

static void
test_equivocation_drop( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 90UL, &bid0, NULL, NULL );

  fd_hash_t r0    = mkhash( 1UL );
  fd_hash_t r0dup = mkhash( 2UL );
  FD_TEST( !feed_fec( rotor, 91UL, 0U, 0, &r0, 90UL, &bid0 ) );

  fd_rotor_blk_t * v0 = block_at( rotor, 91UL, 0UL );
  ulong fec_free = fd_fec_pool_free( fec_pool );

  /* a different root for the same FEC set, with no sentinel authorizing
     it -> rejected, and neither the shred bits nor the recorded root
     change */

  FD_TEST( feed_fec( rotor, 91UL, 0U, 0, &r0dup, AG_UNKNOWN_SLOT, NULL )==1 );
  FD_TEST( fd_fec_pool_free( fec_pool )==fec_free );
  FD_TEST( fd_hash_eq( &fec_at( rotor, 91UL, 0U, 0UL )->merkle_root, &r0 ) );
  FD_TEST( !fec_at( rotor, 91UL, 0U, 1UL ) );
  FD_TEST( v0->buffered_idx==31U );
  FD_TEST( block_shred_cnt( rotor, v0 )==32UL );

  /* a duplicate completion of the same root is idempotent */

  FD_TEST( !feed_fec( rotor, 91UL, 0U, 0, &r0, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( fd_fec_pool_free( fec_pool )==fec_free );
  FD_TEST( v0->buffered_idx==31U && v0->buffered_fec_idx==31U );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: turbine equivocation without a sentinel is dropped" ));
}

/* fd_rotor_verify is this harness's main safety net, so check that it
   is not vacuous: break each invariant it is supposed to catch, confirm
   it reports, and restore. */

static void
test_verify_detects( fd_wksp_t * wksp ) {
  fd_rotor_t     * rotor      = setup( wksp );
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_block_map_t * block_map  = rotor->block_map;

  FD_TEST( fd_rotor_verify( NULL ) );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 110UL, &bid0, NULL, NULL );

  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t r1 = mkhash( 2UL );
  FD_TEST( !feed_fec( rotor, 111UL, 0U,  0, &r0, 110UL,           &bid0 ) );
  FD_TEST( !feed_fec( rotor, 111UL, 32U, 1, &r1, AG_UNKNOWN_SLOT, NULL  ) );

  fd_rotor_blk_t * s = block_at( rotor, 111UL, 0UL );
  FD_TEST( s->complete_idx==63U );

  /* header */

  rotor->magic ^= 1UL; FD_TEST( fd_rotor_verify( rotor ) ); rotor->magic ^= 1UL;

  /* shred index ordering */

  s->buffered_idx  = 64U; FD_TEST( fd_rotor_verify( rotor ) ); s->buffered_idx  = 63U;
  s->delivered_idx = 95U; FD_TEST( fd_rotor_verify( rotor ) ); s->delivered_idx = 63U;
  FD_TEST( !fd_rotor_verify( rotor ) );

  /* nothing may live below the root */

  rotor->root = 111UL; FD_TEST( fd_rotor_verify( rotor ) ); rotor->root = 110UL;
  FD_TEST( !fd_rotor_verify( rotor ) );

  /* extra notar-fallback versions are legal; removing one just leaves a
     slot with fewer versions, which is not a defect. */

  fd_hash_t bidA = mkhash( 200UL );
  fd_hash_t bidB = mkhash( 201UL );
  fd_rotor_verified_block_insert( rotor, 111UL, bidA, 0L );
  fd_rotor_verified_block_insert( rotor, 111UL, bidB, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  fd_rotor_blk_t * v1 = fd_rotor_slot_version_query( rotor, 111UL, &bidA );
  FD_TEST( v1 && fd_rotor_slot_version_query( rotor, 111UL, &bidB ) );

  FD_TEST( fd_block_map_ele_remove_fast( block_map, v1, block_pool )==v1 );
  FD_TEST( !fd_rotor_verify( rotor ) ); /* a hole at a version is not a defect */

  fd_block_map_ele_insert( block_map, v1, block_pool );
  FD_TEST( !fd_rotor_verify( rotor ) );

  /* a slot's FECs must be owned by some version present in the map;
     removing the version that owns them leaves them claimed by nobody. */

  FD_TEST( fd_block_map_ele_remove_fast( block_map, s, block_pool )==s );
  FD_TEST( fd_rotor_verify( rotor ) );
  fd_block_map_ele_insert( block_map, s, block_pool );
  FD_TEST( !fd_rotor_verify( rotor ) );

  teardown( rotor );
  FD_LOG_NOTICE(( "pass: fd_rotor_verify detects broken invariants" ));
}

/* Output order under equivocation: when a second version of a slot
   diverges in the MIDDLE, delivering that version must re-emit the whole
   block from FEC set 0 -- the shared prefix included -- so replay always
   receives a contiguous block starting at set 0, not just the diverging
   tail.  Here version 0 (turbine) completes first; the notar-fallback
   version 1 shares sets 0,32 and diverges at 64,96,128. */

static void
test_output_order_redeliver( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 50UL, &bid0, NULL, NULL );

  fd_hash_t A  = mkhash( 1UL ); /* set 0   (shared)             */
  fd_hash_t B  = mkhash( 2UL ); /* set 32  (shared)             */
  fd_hash_t C0 = mkhash( 3UL ); /* set 64  version 0            */
  fd_hash_t D0 = mkhash( 4UL ); /* set 96  version 0            */
  fd_hash_t E0 = mkhash( 5UL ); /* set 128 version 0            */
  fd_hash_t C1 = mkhash( 6UL ); /* set 64  version 1 (diverges) */
  fd_hash_t D1 = mkhash( 7UL ); /* set 96  version 1            */
  fd_hash_t E1 = mkhash( 8UL ); /* set 128 version 1            */

  /* version 0 (turbine): full 5-set block, completes first */
  FD_TEST( !feed_fec( rotor, 51UL, 0U,   0, &A,  50UL,            &bid0 ) );
  FD_TEST( !feed_fec( rotor, 51UL, 32U,  0, &B,  AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( rotor, 51UL, 64U,  0, &C0, AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( rotor, 51UL, 96U,  0, &D0, AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( rotor, 51UL, 128U, 1, &E0, AG_UNKNOWN_SLOT, NULL  ) );

  /* version 0 delivered the whole block, in order, from set 0 */
  out_rec_t exp0[] = {
    { 51UL, 0U, A }, { 51UL, 32U, B }, { 51UL, 64U, C0 }, { 51UL, 96U, D0 }, { 51UL, 128U, E0 },
  };
  expect_out( rotor, exp0, 5UL );

  /* a notar-fallback cert names a different block for slot 51 */
  fd_hash_t bidX = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 51UL, bidX, 0L );
  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 51UL, &bidX, 5U, 50UL, &bid0, 0L ) );

  /* shared prefix: sets 0,32 match version 0 and deliver without repair */
  fd_hash_t mr;
  mr = A; fd_rotor_verified_hash_insert( rotor, 51UL, &bidX, 0U,  mr.uc, 0L );
  mr = B; fd_rotor_verified_hash_insert( rotor, 51UL, &bidX, 32U, mr.uc, 0L );

  /* diverging tail: sets 64,96,128 are new roots -> sentinels, then repaired */
  mr = C1; fd_rotor_verified_hash_insert( rotor, 51UL, &bidX, 64U,  mr.uc, 0L );
  mr = D1; fd_rotor_verified_hash_insert( rotor, 51UL, &bidX, 96U,  mr.uc, 0L );
  mr = E1; fd_rotor_verified_hash_insert( rotor, 51UL, &bidX, 128U, mr.uc, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );

  FD_TEST( !feed_fec( rotor, 51UL, 64U,  0, &C1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( !feed_fec( rotor, 51UL, 96U,  0, &D1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( !feed_fec( rotor, 51UL, 128U, 1, &E1, AG_UNKNOWN_SLOT, NULL ) );

  /* THE INVARIANT: version 1 re-delivered the ENTIRE block from set 0 --
     shared prefix (A,B) re-emitted ahead of the diverging tail
     (C1,D1,E1) -- even though the equivocation point is at set 64. */
  out_rec_t exp1[] = {
    { 51UL, 0U, A }, { 51UL, 32U, B }, { 51UL, 64U, C1 }, { 51UL, 96U, D1 }, { 51UL, 128U, E1 },
  };
  expect_out( rotor, exp1, 5UL );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
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
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 60UL, &bid0, NULL, NULL );

  fd_hash_t A  = mkhash( 1UL ); /* set 0  (shared)             */
  fd_hash_t B  = mkhash( 2UL ); /* set 32 (shared)             */
  fd_hash_t C0 = mkhash( 3UL ); /* set 64 version 0            */
  fd_hash_t D0 = mkhash( 4UL ); /* set 96 version 0            */
  fd_hash_t C1 = mkhash( 6UL ); /* set 64 version 1 (diverges) */
  fd_hash_t D1 = mkhash( 7UL ); /* set 96 version 1            */

  /* version 0 (turbine): full 4-set block, completes first and owns its
     own root at every position */
  FD_TEST( !feed_fec( rotor, 61UL, 0U,  0, &A,  60UL,            &bid0 ) );
  FD_TEST( !feed_fec( rotor, 61UL, 32U, 0, &B,  AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( rotor, 61UL, 64U, 0, &C0, AG_UNKNOWN_SLOT, NULL  ) );
  FD_TEST( !feed_fec( rotor, 61UL, 96U, 1, &D0, AG_UNKNOWN_SLOT, NULL  ) );
  out_rec_t exp0[] = { { 61UL, 0U, A }, { 61UL, 32U, B }, { 61UL, 64U, C0 }, { 61UL, 96U, D0 } };
  expect_out( rotor, exp0, 4UL );

  /* notar-fallback version 1 shares 0,32 and diverges at 64,96 */
  fd_hash_t bidX = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 61UL, bidX, 0L );
  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 61UL, &bidX, 4U, 60UL, &bid0, 0L ) );

  fd_hash_t mr;
  mr = A;  fd_rotor_verified_hash_insert( rotor, 61UL, &bidX, 0U,  mr.uc, 0L );
  mr = B;  fd_rotor_verified_hash_insert( rotor, 61UL, &bidX, 32U, mr.uc, 0L );
  mr = C1; fd_rotor_verified_hash_insert( rotor, 61UL, &bidX, 64U, mr.uc, 0L );
  mr = D1; fd_rotor_verified_hash_insert( rotor, 61UL, &bidX, 96U, mr.uc, 0L );

  /* the shared prefix (0,32) delivered when its roots were recorded */
  fd_rotor_blk_t * v1 = block_at( rotor, 61UL, 1UL );
  FD_TEST( v1->delivered_idx==63U );

  /* OUT OF ORDER: repair fills set 96 before set 64.  Set 64 is still a
     hole, so nothing new may be delivered. */
  FD_TEST( !feed_fec( rotor, 61UL, 96U, 1, &D1, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( v1->delivered_idx==63U ); /* 96 buffered but held: 64 missing */

  /* set 64 lands: 64 then 96 deliver, in order */
  FD_TEST( !feed_fec( rotor, 61UL, 64U, 0, &C1, AG_UNKNOWN_SLOT, NULL ) );

  /* THE INVARIANT: version 1 re-delivered the whole block from set 0, in
     order -- shared prefix (A,B) ahead of the diverging tail (C1,D1) --
     even though set 96 arrived before set 64. */
  out_rec_t exp1[] = { { 61UL, 0U, A }, { 61UL, 32U, B }, { 61UL, 64U, C1 }, { 61UL, 96U, D1 } };
  expect_out( rotor, exp1, 4UL );

  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: output order out-of-order FEC arrival re-delivers from set 0" ));
}

/* Per-block shred limit is a runtime value.  The shred tile's resolver
   bounds every position by the same limit before it reaches the
   rotor, which asserts it; the last legal position must work. */

static void
test_shred_limit( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 10UL, &bid0, NULL, NULL );

  uint const shred_max = (uint)FD_SHRED_BLK_MAX;

  /* the last legal position is accepted */
  fd_hash_t rL = mkhash( 2UL );
  FD_TEST( !feed_fec( rotor, 11UL, shred_max-(uint)FD_FEC_SHRED_CNT, 1, &rL, 10UL, &bid0 ) );
  fd_rotor_blk_t * v0 = block_at( rotor, 11UL, 0UL );
  FD_TEST( v0 && v0->complete_idx==shred_max-1U );
  FD_TEST(  fd_rotor_shred_test( rotor, v0, shred_max-1U ) );
  FD_TEST( !fd_rotor_shred_test( rotor, v0, shred_max    ) ); /* beyond the limit: never present */
  FD_TEST( !fd_rotor_shred_test( rotor, v0, UINT_MAX     ) );
  FD_TEST( block_shred_cnt( rotor, v0 )==FD_FEC_SHRED_CNT );
  FD_TEST( !fd_rotor_fec_query( rotor, 11UL, shred_max, &v0->block_id ) );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( block_shred_cnt( rotor, v0 )==FD_FEC_SHRED_CNT );

  /* a getParentAndFecCount naming exactly the limit connects the version */
  fd_hash_t bidX = mkhash( 200UL );
  fd_rotor_verified_block_insert( rotor, 11UL, bidX, 0L );
  fd_rotor_blk_t * v1 = fd_rotor_slot_version_query( rotor, 11UL, &bidX );
  FD_TEST( v1 && v1->complete_idx==UINT_MAX && v1->parent_slot==AG_UNKNOWN_SLOT );
  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 11UL, &bidX, (uint)FD_FEC_BLK_MAX, 10UL, &bid0, 0L )==fd_rotor_slot_version_query( rotor, 10UL, &bid0 ) ); /* returns the parent version */
  FD_TEST( v1->complete_idx==shred_max-1U && v1->connected );
  FD_TEST( !fd_rotor_verify( rotor ) );

  teardown( rotor );
  FD_LOG_NOTICE(( "pass: the last legal shred position and FEC count are accepted" ));
}

/* Under bench limits a block holds 4x the FEC sets: the per-version FEC
   table is sized at runtime, so positions above FD_FEC_BLK_MAX are
   owned per version, shared, equivocated and pruned like any other. */

static void
test_bench_shred_limit( fd_wksp_t * wksp ) {
  fd_rotor_t     * rotor       = setup_sized( wksp, 8UL, BENCH_SHRED_MAX );
  fd_rotor_blk_t * block_pool  = rotor->block_pool;
  fd_rotor_fec_t * fec_pool    = rotor->fec_pool;
  ulong            block_free0 = fd_block_pool_free( block_pool );
  ulong            fec_free0   = fd_fec_pool_free  ( fec_pool   );

  uint const shred_max = (uint)BENCH_SHRED_MAX;
  uint const last      = shred_max-(uint)FD_FEC_SHRED_CNT; /* fec_set_idx of the last FEC set */
  FD_TEST( last>=FD_SHRED_BLK_MAX );                        /* beyond the production limit */

  fd_hash_t bid0 = mkhash( 100UL );
  fd_rotor_init( rotor, 10UL, &bid0, NULL, NULL );

  /* turbine version of slot 11: set 0 and the last set */
  fd_hash_t r0 = mkhash( 1UL );
  fd_hash_t rA = mkhash( 2UL );
  FD_TEST( !feed_fec( rotor, 11UL, 0U,   0, &r0, 10UL,            &bid0 ) );
  FD_TEST( !feed_fec( rotor, 11UL, last, 1, &rA, AG_UNKNOWN_SLOT, NULL  ) );
  fd_rotor_blk_t * v0 = block_at( rotor, 11UL, 0UL );
  FD_TEST( v0->complete_idx==shred_max-1U && v0->buffered_idx==31U );
  FD_TEST( block_shred_cnt( rotor, v0 )==2UL*FD_FEC_SHRED_CNT );
  for( uint i=last; i<shred_max; i++ ) FD_TEST( fd_rotor_shred_test( rotor, v0, i ) );
  FD_TEST( !fd_rotor_shred_test( rotor, v0, shred_max ) );
  FD_TEST( fd_hash_eq( &fec_at( rotor, 11UL, last, 0UL )->merkle_root, &rA ) );
  FD_TEST( !fd_rotor_verify( rotor ) );

  /* a second version shares set 0 but equivocates on the last set:
     each version's row holds its own root at the high position */
  fd_hash_t bidX = mkhash( 200UL );
  fd_hash_t rB   = mkhash( 3UL );
  fd_rotor_verified_block_insert( rotor, 11UL, bidX, 0L );
  FD_TEST( fd_rotor_verified_parent_fec_count( rotor, 11UL, &bidX, shred_max/(uint)FD_FEC_SHRED_CNT, 10UL, &bid0, 0L ) );
  fd_hash_t mr;
  mr = r0; fd_rotor_verified_hash_insert( rotor, 11UL, &bidX, 0U,   mr.uc, 0L );
  mr = rB; fd_rotor_verified_hash_insert( rotor, 11UL, &bidX, last, mr.uc, 0L );
  FD_TEST( !fd_rotor_verify( rotor ) );
  fd_rotor_blk_t * v1 = block_at( rotor, 11UL, 1UL );
  FD_TEST( v1->complete_idx==shred_max-1U && v1->delivered_idx==31U );
  FD_TEST( !feed_fec( rotor, 11UL, last, 1, &rB, AG_UNKNOWN_SLOT, NULL ) );
  FD_TEST( fd_hash_eq( &fec_at( rotor, 11UL, last, 0UL )->merkle_root, &rA ) );
  FD_TEST( fd_hash_eq( &fec_at( rotor, 11UL, last, 1UL )->merkle_root, &rB ) );
  FD_TEST( fd_rotor_block_fecs( rotor, v0 )[ last/FD_FEC_SHRED_CNT ]!=fd_rotor_block_fecs( rotor, v1 )[ last/FD_FEC_SHRED_CNT ] );
  FD_TEST( fd_rotor_block_fecs( rotor, v0 )[ 0 ]==fd_rotor_block_fecs( rotor, v1 )[ 0 ] );
  for( uint i=last; i<shred_max; i++ ) FD_TEST( fd_rotor_shred_test( rotor, v1, i ) );
  FD_TEST( !fd_rotor_verify( rotor ) );

  /* publish past it: the prune walks the whole runtime-sized row */
  fd_hash_t r12 = mkhash( 4UL );
  FD_TEST( !feed_fec( rotor, 12UL, 0U, 1, &r12, 11UL, &bidX ) );
  FD_TEST( fd_fec_pool_free( fec_pool )==fec_free0-4UL ); /* r0, rA, rB, r12 */
  out_ele_t * out_queue = rotor->out_queue;
  while( !out_queue_empty( out_queue ) ) { out_queue_pop_head( out_queue ); }
  fd_rotor_publish( rotor, 12UL, NULL, NULL );
  FD_TEST( !fd_rotor_verify( rotor ) );
  FD_TEST( !fd_rotor_slot_query( rotor, 11UL ) );
  FD_TEST( fd_block_pool_free( block_pool )==block_free0-1UL );
  FD_TEST( fd_fec_pool_free  ( fec_pool   )==fec_free0        );

  teardown( rotor );
  FD_LOG_NOTICE(( "pass: bench shred limit owns/shares/prunes FEC sets above FD_FEC_BLK_MAX" ));
}

/* Reception follows the resolver attempt, independently of synthetic
   recovered inserts and metadata replay into another block version. */
struct fec_reception_prune_ctx {
  fd_rotor_t * rotor;
  uint reports;
};

static void
check_fec_reception_prune( void * ctx_, fd_rotor_blk_t const * block ) {
  struct fec_reception_prune_ctx * ctx = ctx_;
  if( block->slot!=11UL ) return;
  fd_rotor_fec_t const * fec = fd_rotor_fec_query( ctx->rotor, block->slot, 32U, &block->block_id );
  FD_TEST( fec );
  FD_TEST( fd_fec_map_ele_query_const( ctx->rotor->fec_map, &fec->merkle_root, NULL, ctx->rotor->fec_pool )==fec );
  FD_TEST( fec->metrics.data_received==1U && fec->metrics.repair_received==1U );
  FD_TEST( fec->metrics.parity_received==(1U<<31) );
  FD_TEST( fec->metrics.first_shred_ts==200L && fec->metrics.completed_ts==210L );
  ctx->reports++;
}

static void
test_fec_reception( fd_wksp_t * wksp ) {
  fd_rotor_t * rotor = setup( wksp );
  fd_hash_t    root  = mkhash( 900UL );
  fd_hash_t    mr    = mkhash( 901UL );
  fd_rotor_init( rotor, 10UL, &root, NULL, NULL );

  /* Coding shreds are ignored until the FEC exists. */
  fd_rotor_code_shred_insert( rotor, 11UL, 32U, 31U, 100L, &mr );
  FD_TEST( !fd_rotor_slot_query( rotor, 11UL ) );
  fd_rotor_blk_t * v = fd_rotor_shred_insert( rotor, 11UL, 32U, 0, FD_ROTOR_SRC_REPAIR, 110L, &mr, 1, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( v && v->turbine );
  fd_rotor_fec_t * fec = fec_at( rotor, 11UL, 32U, 0UL );
  FD_TEST( fec && fec->data_idxs==1U && !fec->metrics.parity_received );
  fd_rotor_code_shred_insert( rotor, 11UL, 32U, 31U, 120L, &mr );
  FD_TEST( fec->metrics.parity_received==(1U<<31) );
  FD_TEST( fec->metrics.first_shred_ts==110L && !fec->metrics.completed_ts );
  FD_TEST( v->metrics.parity_cnt==1U && v->metrics.turbine_cnt==1U );
  FD_TEST( !fd_rotor_verify( rotor ) );

  /* Start again after eviction.  Refetched bits describe this attempt;
     the block-level counts retain the earlier delivery. */
  fd_rotor_fec_evicted( rotor, 11UL, 32U, &mr );
  FD_TEST( !fec->data_idxs && !fec->metrics.data_received && !fec->metrics.parity_received && !fec->metrics.repair_received );
  FD_TEST( !fec->metrics.first_shred_ts && !fec->metrics.completed_ts );
  FD_TEST( fec->metrics.last_shred_src==FD_ROTOR_SRC_TURBINE );
  fd_rotor_code_shred_insert( rotor, 11UL, 32U, 31U, 200L, &mr );
  fd_rotor_shred_insert( rotor, 11UL, 32U, 0, FD_ROTOR_SRC_REPAIR, 210L, &mr, 1, AG_UNKNOWN_SLOT, NULL );
  fd_rotor_code_shred_insert( rotor, 11UL, 32U, 31U, 220L, &mr ); /* duplicate */
  fd_rotor_shred_insert( rotor, 11UL, 32U, 0, FD_ROTOR_SRC_TURBINE, 230L, &mr, 1, AG_UNKNOWN_SLOT, NULL ); /* duplicate */
  FD_TEST( fec->metrics.last_shred_src==FD_ROTOR_SRC_REPAIR );
  FD_TEST( v->metrics.parity_cnt==2U && v->metrics.repair_cnt==2U );
  fd_rotor_shred_insert( rotor, 11UL, 33U, 0, FD_ROTOR_SRC_RECOVERED, 210L, &mr, 1, AG_UNKNOWN_SLOT, NULL );
  fd_rotor_fec_complete( rotor, 11UL, 32U, 0, 1, 0, 210L, &mr, NULL, NULL );
  FD_TEST( fec->data_idxs==UINT_MAX );
  FD_TEST( fec->metrics.data_received==1U && fec->metrics.repair_received==1U );
  FD_TEST( fec->metrics.parity_received==(1U<<31) );
  FD_TEST( fec->metrics.last_shred_src==FD_ROTOR_SRC_REPAIR );
  FD_TEST( fec->metrics.first_shred_ts==200L && fec->metrics.completed_ts==210L );
  FD_TEST( v->metrics.recovered_cnt==31U );

  uchar saved[ sizeof(fec->metrics) ];
  memcpy( saved, &fec->metrics, sizeof(saved) );
  fd_rotor_shred_insert( rotor, 11UL, 34U, 0, FD_ROTOR_SRC_TURBINE, 300L, &mr, 1, AG_UNKNOWN_SLOT, NULL );
  fd_rotor_code_shred_insert( rotor, 11UL, 32U, 30U, 310L, &mr );
  fd_rotor_fec_complete( rotor, 11UL, 32U, 0, 1, 0, 320L, &mr, NULL, NULL );
  FD_TEST( !memcmp( saved, &fec->metrics, sizeof(saved) ) );

  fd_hash_t bid = mkhash( 902UL );
  fd_rotor_verified_block_insert( rotor, 11UL, bid, 0L );
  fd_rotor_verified_hash_insert( rotor, 11UL, &bid, 32U, mr.uc, 0L );
  FD_TEST( fd_rotor_fec_query( rotor, 11UL, 32U, &bid )==fec );
  FD_TEST( !memcmp( saved, &fec->metrics, sizeof(saved) ) );
  FD_TEST( !fd_rotor_verify( rotor ) );

  /* Leader sets are produced, not received or recovered. */
  fd_hash_t leader_mr = mkhash( 903UL );
  fd_rotor_fec_complete( rotor, 12UL, 0U, 0, 1, 1, 400L, &leader_mr, NULL, NULL );
  fd_rotor_fec_t * leader = fec_at( rotor, 12UL, 0U, 0UL );
  fd_rotor_blk_t * lv = fd_rotor_turbine_block_query( rotor, 12UL );
  FD_TEST( leader && leader->data_idxs==UINT_MAX );
  FD_TEST( !leader->metrics.data_received && !leader->metrics.parity_received && !leader->metrics.repair_received );
  FD_TEST( leader->metrics.first_shred_ts==400L && leader->metrics.completed_ts==400L );
  FD_TEST( leader->metrics.last_shred_src==FD_ROTOR_SRC_LEADER );
  FD_TEST( !lv->metrics.turbine_cnt && !lv->metrics.repair_cnt && !lv->metrics.recovered_cnt );
  FD_TEST( !fd_rotor_verify( rotor ) );

  struct fec_reception_prune_ctx prune_ctx = { .rotor = rotor };
  rotor->block_event_fn  = check_fec_reception_prune;
  rotor->block_event_ctx = &prune_ctx;
  fd_rotor_publish( rotor, 12UL, NULL, NULL );
  FD_TEST( prune_ctx.reports==2U );
  FD_TEST( !fd_rotor_verify( rotor ) );

  /* Reusing a freed FEC pool entry must not leak reception state. */
  fd_hash_t reused_mr = mkhash( 904UL );
  fd_rotor_shred_insert( rotor, 13UL, 0U, 0, FD_ROTOR_SRC_TURBINE, 500L, &reused_mr, 1, AG_UNKNOWN_SLOT, NULL );
  fd_rotor_code_shred_insert( rotor, 13UL, 0U, 5U, 500L, &reused_mr );
  fd_rotor_fec_t * reused = fec_at( rotor, 13UL, 0U, 0UL );
  FD_TEST( reused && reused->metrics.data_received==1U && !reused->metrics.repair_received );
  FD_TEST( reused->metrics.parity_received==(1U<<5) );
  FD_TEST( reused->metrics.first_shred_ts==500L && !reused->metrics.completed_ts );
  FD_TEST( reused->metrics.last_shred_src==FD_ROTOR_SRC_TURBINE );
  FD_TEST( !fd_rotor_verify( rotor ) );
  teardown( rotor );
  FD_LOG_NOTICE(( "pass: FEC reception survives recovery, duplicates and sharing; resets on eviction" ));
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
  test_fec_reception                     ( wksp );
  test_basic                             ( wksp );
  test_shared_prefix                     ( wksp );
  test_notar_fallback_in_flight          ( wksp );
  test_sentinel_before_turbine           ( wksp );
  test_turbine_shred_after_notar_fallback( wksp );
  test_invalidate                        ( wksp );
  test_parent_off_mismatch               ( wksp );
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
