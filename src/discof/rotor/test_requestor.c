#include "fd_requestor.h"
#include "../repair/fd_repair.h"

/* The requestor is driven against a real chainer, the way the tile
   drives it: the chainer is fed shreds and metadata, a walk of a block
   is started, and the requests it yields plus the rung it ends on are
   checked against what that block is missing. */

#define ELE_MAX (16UL)
#define REQ_MAX (128UL)

static fd_hash_t const ZERO = {0};

static fd_hash_t
mkhash( ulong n ) {
  fd_hash_t h = {0};
  memcpy( h.uc, &n, sizeof(ulong) );
  h.uc[ 31 ] = 0x5a; /* never all-zero */
  return h;
}

static fd_chainer_t *
chainer_setup( fd_wksp_t * wksp ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_chainer_align(), fd_chainer_footprint( ELE_MAX, FD_SHRED_BLK_MAX ), 1UL );
  FD_TEST( mem );
  fd_chainer_t * chainer = fd_chainer_join( fd_chainer_new( mem, ELE_MAX, FD_SHRED_BLK_MAX, 42UL ) );
  FD_TEST( chainer );
  return chainer;
}

/* drain_chainer discards delivered FECs so the fixture never overflows
   the out_queue. */

static void
drain_chainer( fd_chainer_t * chainer ) {
  while( !out_queue_empty( chainer->out_queue ) ) out_queue_pop_head( chainer->out_queue );
}

/* shred inserts one turbine shred.  parent_slot is AG_UNKNOWN_SLOT for
   a shred that carries no parent info. */

static void
shred( fd_chainer_t * chainer, ulong slot, uint idx, int slot_complete, fd_hash_t const * mr, ulong parent_slot, fd_hash_t const * parent_bid ) {
  fd_chainer_shred_insert( chainer, slot, idx, slot_complete, FD_CHAINER_SRC_TURBINE, 0L, mr, parent_slot, parent_bid );
  drain_chainer( chainer );
}

/* hash_insert lands a getFecRoot sentinel for a verified block. */

static void
hash_insert( fd_chainer_t * chainer, ulong slot, fd_hash_t * block_id, uint fec_set_idx, fd_hash_t * mr ) {
  fd_chainer_verified_hash_insert( chainer, slot, block_id, fec_set_idx, mr->uc );
  drain_chainer( chainer );
}

/* fec_complete marks a whole FEC set reconstructable. */

static void
fec_complete( fd_chainer_t * chainer, ulong slot, uint fec_set_idx, int slot_complete, fd_hash_t const * mr ) {
  fd_hash_t m = *mr;
  int rejected;
  fd_chainer_fec_complete( chainer, slot, fec_set_idx, slot_complete, slot_complete, 0, 0L, &m, &rejected );
  FD_TEST( !rejected );
  drain_chainer( chainer );
}

/* advance cranks the walk once; the block a terminal code names lands
   in walked_slot / walked_block_id. */

static ulong     walked_slot;
static fd_hash_t walked_block_id;

static int
advance( fd_requestor_t * r, fd_chainer_t *       chainer, fd_rotor_request_t * req ) {
  return fd_requestor_block_advance( r, chainer, req, &walked_slot, &walked_block_id );
}

static fd_requestor_t *
requestor_setup( void ) {
  static uchar mem[ 256 ] __attribute__((aligned(128UL)));
  FD_TEST( fd_requestor_footprint()<=sizeof(mem) );
  fd_requestor_t * r = fd_requestor_join( fd_requestor_new( mem ) );
  FD_TEST( r );
  fd_rotor_request_t req[1];
  FD_TEST( advance( r, NULL, req )==FD_REQUESTOR_ADVANCE_IDLE ); /* nothing started */
  return r;
}

/* run_walk walks {slot, block_id} to the end against an unchanging
   chainer, collects every request into reqs (up to REQ_MAX) and
   returns the terminal code, asserting it is reported exactly once. */

static int
run_walk( fd_requestor_t * r, fd_chainer_t * chainer, ulong slot, fd_hash_t const * block_id, fd_rotor_request_t * reqs, ulong * req_cnt ) {
  fd_requestor_block_start( r, slot, block_id );
  walked_slot = ULONG_MAX;

  ulong cnt = 0UL;
  int   result;
  fd_rotor_request_t req[1];
  while( ( result = advance( r, chainer, req ) )==FD_REQUESTOR_ADVANCE_REQUEST ) {
    FD_TEST( cnt<REQ_MAX );
    FD_TEST( req->slot==slot );
    reqs[ cnt++ ] = *req;
  }
  if( result==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT ) { /* carries the walk's one metadata request, after any fills */
    FD_TEST( cnt<REQ_MAX && req->slot==slot );
    reqs[ cnt++ ] = *req;
  }
  FD_TEST( result==FD_REQUESTOR_ADVANCE_DONE || result==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT || result==FD_REQUESTOR_ADVANCE_REQUESTED );
  FD_TEST( walked_slot==slot && fd_hash_eq( &walked_block_id, block_id ) ); /* the terminal code names the walked block */
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_IDLE ); /* reported once */
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_IDLE ); /* and stays idle */

  FD_TEST( ( result==FD_REQUESTOR_ADVANCE_DONE )==( cnt==0UL ) );
  FD_TEST( result!=FD_REQUESTOR_ADVANCE_REQUESTED_PARENT || cnt>=1UL );

  *req_cnt = cnt;
  return result;
}

static void
expect_req( fd_rotor_request_t const * req, uint kind, uint idx, fd_hash_t const * block_id, fd_hash_t const * fec_root ) {
  FD_TEST( req->kind==kind );
  FD_TEST( req->idx==idx );
  FD_TEST( fd_hash_eq( &req->block_id, block_id ? block_id : &ZERO ) );
  /* A getFecRoot response carries only the 20-byte root prefix, so the
     root the chainer hands back is compared over that prefix. */
  FD_TEST( !memcmp( req->fec_root.uc, ( fec_root ? fec_root : &ZERO )->uc, FD_SHRED_MERKLE_NODE_SZ ) );
}

/* Turbine block: while the tip is unknown a bounded blind fill past
   the buffered prefix, then HighestShred; once the tip is known a fill
   walk that requests exactly the missing shreds past the buffered
   prefix, then DONE once nothing is missing. */

static void
test_turbine( fd_wksp_t * wksp ) {
  fd_chainer_t *   chainer = chainer_setup( wksp );
  fd_requestor_t * r       = requestor_setup();
  fd_rotor_request_t reqs[ REQ_MAX ]; ulong cnt;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 10UL, &bid0 );
  drain_chainer( chainer );

  /* slot 11: first FEC set complete, tip unknown -> blind fill of the
     next FD_REQUESTOR_ORPHAN_FILL_MAX positions past the prefix, then
     HighestShred */
  fd_hash_t r0 = mkhash( 1UL ), r1 = mkhash( 2UL );
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) shred( chainer, 11UL, i, 0, &r0, i ? AG_UNKNOWN_SLOT : 10UL, i ? NULL : &bid0 );
  fec_complete( chainer, 11UL, 0U, 0, &r0 );
  FD_TEST( run_walk( r, chainer, 11UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT );
  FD_TEST( cnt==FD_REQUESTOR_ORPHAN_FILL_MAX+1UL );
  for( uint i=0U; i<FD_REQUESTOR_ORPHAN_FILL_MAX; i++ ) expect_req( &reqs[ i ], FD_REPAIR_KIND_SHRED, FD_FEC_SHRED_CNT+i, NULL, NULL );
  expect_req( &reqs[ FD_REQUESTOR_ORPHAN_FILL_MAX ], FD_REPAIR_KIND_HIGHEST_SHRED, 0U, NULL, NULL );

  /* second set arrives with holes at 40 and 50 and the slot-complete
     flag on 63: tip known, fill walk asks for exactly the holes */
  for( uint i=32U; i<64U; i++ ) if( i!=40U && i!=50U ) shred( chainer, 11UL, i, i==63U, &r1, AG_UNKNOWN_SLOT, NULL );
  fd_chainer_slotv_t const * s11 = fd_chainer_slot_version_query( chainer, 11UL, &ZERO );
  FD_TEST( s11 && s11->complete_idx==63U && s11->buffered_idx==39U );
  FD_TEST( run_walk( r, chainer, 11UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED );
  FD_TEST( cnt==2UL );
  expect_req( &reqs[ 0 ], FD_REPAIR_KIND_SHRED, 40U, NULL, NULL );
  expect_req( &reqs[ 1 ], FD_REPAIR_KIND_SHRED, 50U, NULL, NULL );

  /* the holes arrive: nothing missing -> DONE with no requests */
  shred( chainer, 11UL, 40U, 0, &r1, AG_UNKNOWN_SLOT, NULL );
  shred( chainer, 11UL, 50U, 0, &r1, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( run_walk( r, chainer, 11UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_DONE );
  FD_TEST( cnt==0UL );

  /* completing the set finalizes the block_id: the old key is gone and
     resolves to DONE, the new key has nothing to request */
  fec_complete( chainer, 11UL, 32U, 1, &r1 );
  FD_TEST( !fd_chainer_slot_version_query( chainer, 11UL, &ZERO ) );
  s11 = fd_chainer_turbine_slotv_query( chainer, 11UL );
  FD_TEST( s11 && !fd_hash_check_zero( &s11->block_id ) && fd_chainer_slotv_complete( s11 ) );
  FD_TEST( run_walk( r, chainer, 11UL, &ZERO,          reqs, &cnt )==FD_REQUESTOR_ADVANCE_DONE && cnt==0UL );
  FD_TEST( run_walk( r, chainer, 11UL, &s11->block_id, reqs, &cnt )==FD_REQUESTOR_ADVANCE_DONE && cnt==0UL );

  FD_LOG_NOTICE(( "pass: turbine block ladder" ));
}

/* Ancestry rungs: a turbine block whose parent is known but absent
   asks Orphan, after filling at most FD_REQUESTOR_ORPHAN_FILL_MAX of
   its own shreds; one whose parent is unknown asks for shred 0. */

static void
test_ancestry( fd_wksp_t * wksp ) {
  fd_chainer_t *   chainer = chainer_setup( wksp );
  fd_requestor_t * r       = requestor_setup();
  fd_rotor_request_t reqs[ REQ_MAX ]; ulong cnt;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 10UL, &bid0 );
  drain_chainer( chainer );

  /* slot 20 names parent 15, which we do not have, and its tip is
     unknown: blind fill of 1..FD_REQUESTOR_ORPHAN_FILL_MAX, then Orphan */
  fd_hash_t bid15 = mkhash( 150UL ), r20 = mkhash( 20UL );
  shred( chainer, 20UL, 0U, 0, &r20, 15UL, &bid15 );
  FD_TEST( run_walk( r, chainer, 20UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT );
  FD_TEST( cnt==FD_REQUESTOR_ORPHAN_FILL_MAX+1UL );
  for( uint i=0U; i<FD_REQUESTOR_ORPHAN_FILL_MAX; i++ ) expect_req( &reqs[ i ], FD_REPAIR_KIND_SHRED, i+1U, NULL, NULL );
  expect_req( &reqs[ FD_REQUESTOR_ORPHAN_FILL_MAX ], FD_REPAIR_KIND_ORPHAN, 0U, NULL, NULL );

  /* slot 21 arrived mid-block: parent unknown -> shred 0 */
  fd_hash_t r21 = mkhash( 21UL );
  shred( chainer, 21UL, 5U, 0, &r21, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( run_walk( r, chainer, 21UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT );
  FD_TEST( cnt==1UL ); expect_req( &reqs[ 0 ], FD_REPAIR_KIND_SHRED, 0U, NULL, NULL );

  /* slot 22 names absent parent 15 and knows its tip, set well past
     two budgets: the walk fills the first FD_REQUESTOR_ORPHAN_FILL_MAX
     holes, then Orphan.  One root per FEC set the shreds touch. */
#define M   FD_REQUESTOR_ORPHAN_FILL_MAX
#define TIP ( 2U*M + 2U )
  fd_hash_t r22[ TIP/FD_FEC_SHRED_CNT + 1U ];
  for( uint k=0U; k<TIP/FD_FEC_SHRED_CNT+1U; k++ ) r22[ k ] = mkhash( 2200UL + k );
  shred( chainer, 22UL, 0U,  0, &r22[ 0 ],                    15UL,            &bid15 );
  shred( chainer, 22UL, TIP, 1, &r22[ TIP/FD_FEC_SHRED_CNT ], AG_UNKNOWN_SLOT, NULL   );
  fd_chainer_slotv_t const * s22 = fd_chainer_slot_version_query( chainer, 22UL, &ZERO );
  FD_TEST( s22 && s22->complete_idx==TIP );
  FD_TEST( run_walk( r, chainer, 22UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT );
  FD_TEST( cnt==M+1UL );
  for( uint i=0U; i<M; i++ ) expect_req( &reqs[ i ], FD_REPAIR_KIND_SHRED, i+1U, NULL, NULL );
  expect_req( &reqs[ M ], FD_REPAIR_KIND_ORPHAN, 0U, NULL, NULL );

  /* holes 1..M land: the next walk asks for M+1..2M, then Orphan again */
  for( uint i=1U; i<=M; i++ ) shred( chainer, 22UL, i, 0, &r22[ i/FD_FEC_SHRED_CNT ], AG_UNKNOWN_SLOT, NULL );
  FD_TEST( run_walk( r, chainer, 22UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT );
  FD_TEST( cnt==M+1UL );
  expect_req( &reqs[ 0 ],   FD_REPAIR_KIND_SHRED, M+1U,   NULL, NULL );
  expect_req( &reqs[ M-1 ], FD_REPAIR_KIND_SHRED, 2U*M,   NULL, NULL );
  expect_req( &reqs[ M ],   FD_REPAIR_KIND_ORPHAN, 0U,    NULL, NULL );

  /* the parent shows up under the block_id the child names: the fill
     is no longer bounded and no Orphan is asked: M+1..TIP-1 */
  FD_TEST( fd_chainer_verified_block_insert( chainer, 15UL, bid15 ) );
  drain_chainer( chainer );
  FD_TEST( run_walk( r, chainer, 22UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED );
  FD_TEST( cnt==TIP-M-1UL );
  expect_req( &reqs[ 0 ],     FD_REPAIR_KIND_SHRED, M+1U,   NULL, NULL );
  expect_req( &reqs[ cnt-1 ], FD_REPAIR_KIND_SHRED, TIP-1U, NULL, NULL );
#undef TIP
#undef M

  /* block_id_only suppresses every positional rung: nothing to ask */
  fd_requestor_set_block_id_only( r, 1 );
  FD_TEST( run_walk( r, chainer, 20UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_DONE && cnt==0UL );
  FD_TEST( run_walk( r, chainer, 21UL, &ZERO, reqs, &cnt )==FD_REQUESTOR_ADVANCE_DONE && cnt==0UL );
  fd_requestor_set_block_id_only( r, 0 );

  FD_LOG_NOTICE(( "pass: ancestry rungs" ));
}

/* Verified block: ParentAndFecSetCount until parent and count are
   known, FecSetRoot for every set without an entry, then
   ShredForBlockId for every missing shred of sets whose sentinel has
   landed, keyed by that sentinel's root. */

static void
test_verified( fd_wksp_t * wksp ) {
  fd_chainer_t *   chainer = chainer_setup( wksp );
  fd_requestor_t * r       = requestor_setup();
  fd_rotor_request_t reqs[ REQ_MAX ]; ulong cnt;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 10UL, &bid0 );
  drain_chainer( chainer );

  fd_hash_t bid12 = mkhash( 200UL );
  fd_chainer_verified_block_insert( chainer, 12UL, bid12 );
  drain_chainer( chainer );

  /* nothing known: ask for parent and count */
  FD_TEST( run_walk( r, chainer, 12UL, &bid12, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT );
  FD_TEST( cnt==1UL ); expect_req( &reqs[ 0 ], AG_REPAIR_KIND_PARENT_FEC_COUNT, 0U, &bid12, NULL );

  /* response: 2 FEC sets, parent is the root -> ask for both roots */
  FD_TEST(  fd_chainer_verified_parent_fec_count( chainer, 12UL, &bid12, 2U, 10UL, &bid0 ) ); /* the root exists: nothing created */
  drain_chainer( chainer );
  FD_TEST( run_walk( r, chainer, 12UL, &bid12, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED );
  FD_TEST( cnt==2UL );
  expect_req( &reqs[ 0 ], AG_REPAIR_KIND_FEC_ROOT, 0U,  &bid12, NULL );
  expect_req( &reqs[ 1 ], AG_REPAIR_KIND_FEC_ROOT, 32U, &bid12, NULL );

  /* sentinel for set 0 lands: 32 block-id shred requests keyed by its
     root, and the root of set 1 again */
  fd_hash_t root0 = mkhash( 3UL );
  fd_hash_t m = root0; hash_insert( chainer, 12UL, &bid12, 0U, &m );
  FD_TEST( run_walk( r, chainer, 12UL, &bid12, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED );
  FD_TEST( cnt==33UL );
  for( uint i=0U; i<32U; i++ ) expect_req( &reqs[ i ], AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, i, &bid12, &root0 );
  expect_req( &reqs[ 32 ], AG_REPAIR_KIND_FEC_ROOT, 32U, &bid12, NULL );

  /* some shreds of set 0 arrive: only the rest are asked for */
  for( uint i=0U; i<32U; i++ ) if( i%3U ) shred( chainer, 12UL, i, 0, &root0, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( run_walk( r, chainer, 12UL, &bid12, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED );
  FD_TEST( cnt==11UL+1UL );
  for( uint i=0U, k=0U; i<32U; i++ ) if( !(i%3U) ) { expect_req( &reqs[ k ], AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, i, &bid12, &root0 ); k++; }
  expect_req( &reqs[ 11 ], AG_REPAIR_KIND_FEC_ROOT, 32U, &bid12, NULL );

  /* block_id_only changes nothing for a verified block */
  fd_requestor_set_block_id_only( r, 1 );
  FD_TEST( run_walk( r, chainer, 12UL, &bid12, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED && cnt==12UL );
  fd_requestor_set_block_id_only( r, 0 );

  FD_LOG_NOTICE(( "pass: verified block ladder" ));
}

/* A block that is gone or at or below the root ends its
   walk at once with DONE; one that goes away mid-walk ends the walk
   with DONE too. */

static void
test_gone( fd_wksp_t * wksp ) {
  fd_chainer_t *   chainer = chainer_setup( wksp );
  fd_requestor_t * r       = requestor_setup();
  fd_rotor_request_t reqs[ REQ_MAX ]; ulong cnt;

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 10UL, &bid0 );
  drain_chainer( chainer );

  fd_hash_t bidX = mkhash( 999UL );
  FD_TEST( run_walk( r, chainer, 99UL, &bidX, reqs, &cnt )==FD_REQUESTOR_ADVANCE_DONE && cnt==0UL ); /* never existed */
  FD_TEST( run_walk( r, chainer, 10UL, &bid0, reqs, &cnt )==FD_REQUESTOR_ADVANCE_DONE && cnt==0UL ); /* the root */
  FD_TEST( run_walk( r, chainer,  5UL, &bid0, reqs, &cnt )==FD_REQUESTOR_ADVANCE_DONE && cnt==0UL ); /* below the root */

  /* a votor block of the same slot does not disturb the turbine block:
     both are walked on their own */
  fd_hash_t r13 = mkhash( 13UL ), bid13 = mkhash( 130UL );
  shred( chainer, 13UL, 0U, 0, &r13, 10UL, &bid0 );
  FD_TEST(  fd_chainer_verified_block_insert( chainer, 13UL, bid13 ) ); /* created */
  FD_TEST( !fd_chainer_verified_block_insert( chainer, 13UL, bid13 ) ); /* already there */
  drain_chainer( chainer );
  FD_TEST( run_walk( r, chainer, 13UL, &ZERO,  reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT ); /* HighestShred */
  FD_TEST( run_walk( r, chainer, 13UL, &bid13, reqs, &cnt )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT ); /* ParentAndFecSetCount */

  /* a sibling appearing mid-walk does not disturb the walk either */
  fd_hash_t r14 = mkhash( 14UL ), bid14 = mkhash( 140UL );
  for( uint i=0U; i<32U; i++ ) shred( chainer, 14UL, i, 0, &r14, i ? AG_UNKNOWN_SLOT : 10UL, i ? NULL : &bid0 );
  fd_chainer_slotv_t * s14 = fd_chainer_slot_version_query( chainer, 14UL, &ZERO );
  s14->complete_idx = 63U; /* as if HighestShred had answered */
  fd_rotor_request_t req[1];
  fd_requestor_block_start( r, 14UL, &ZERO );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUEST && req->kind==FD_REPAIR_KIND_SHRED && req->idx==32U );
  fd_chainer_verified_block_insert( chainer, 14UL, bid14 );
  drain_chainer( chainer );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUEST && req->kind==FD_REPAIR_KIND_SHRED && req->idx==33U );

  /* rooted mid-walk: same */
  fd_hash_t r15 = mkhash( 15UL );
  shred( chainer, 15UL, 0U, 0, &r15, 10UL, &bid0 );
  fd_requestor_block_start( r, 15UL, &ZERO );
  drain_chainer( chainer );
  fd_chainer_publish( chainer, 15UL, NULL, NULL );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_DONE );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_IDLE );

  /* a metadata walk is one crank: the request and the terminal code
     arrive together, and a new start replaces the walk cleanly */
  fd_hash_t r16 = mkhash( 16UL );
  shred( chainer, 16UL, 5U, 0, &r16, AG_UNKNOWN_SLOT, NULL );
  fd_requestor_block_start( r, 16UL, &ZERO );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUESTED_PARENT && req->kind==FD_REPAIR_KIND_SHRED && req->idx==0U );
  FD_TEST( walked_slot==16UL );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_IDLE );
  fd_requestor_block_start( r, 99UL, &bidX );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_DONE ); /* the new walk */
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_IDLE );

  FD_LOG_NOTICE(( "pass: gone and rooted blocks" ));
}

/* The chainer keeps moving while a block is walked: every next reads
   it fresh, so a shred that landed since the last request is not
   asked for, a sentinel that landed turns a FecSetRoot into shred
   requests, and the cursor never goes behind the buffered prefix. */

static void
test_moving( fd_wksp_t * wksp ) {
  fd_chainer_t *   chainer = chainer_setup( wksp );
  fd_requestor_t * r       = requestor_setup();

  fd_hash_t bid0 = mkhash( 100UL );
  fd_chainer_init( chainer, 10UL, &bid0 );
  drain_chainer( chainer );

  /* slot 11 with a known tip and holes at 40, 50, 60 */
  fd_hash_t r0 = mkhash( 1UL ), r1 = mkhash( 2UL );
  for( uint i=0U;  i<32U; i++ ) shred( chainer, 11UL, i, 0, &r0, i ? AG_UNKNOWN_SLOT : 10UL, i ? NULL : &bid0 );
  for( uint i=32U; i<64U; i++ ) if( i!=40U && i!=50U && i!=60U ) shred( chainer, 11UL, i, i==63U, &r1, AG_UNKNOWN_SLOT, NULL );

  /* 50 arrives after 40 was asked: 60 is next */
  fd_rotor_request_t req[1];
  fd_requestor_block_start( r, 11UL, &ZERO );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUEST && req->kind==FD_REPAIR_KIND_SHRED && req->idx==40U );
  shred( chainer, 11UL, 50U, 0, &r1, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUEST && req->kind==FD_REPAIR_KIND_SHRED && req->idx==60U );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUESTED );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_IDLE );

  /* verified slot 12 with 2 sets and no sentinels: the root of set 0
     is asked; its sentinel lands before the next call, so the walk
     goes on to the root of set 1 (the cursor already passed set 0) */
  fd_hash_t bid12 = mkhash( 200UL ), root0 = mkhash( 3UL );
  fd_chainer_verified_block_insert( chainer, 12UL, bid12 );
  drain_chainer( chainer );
  FD_TEST(  fd_chainer_verified_parent_fec_count( chainer, 12UL, &bid12, 2U, 10UL, &bid0 ) );
  drain_chainer( chainer );
  fd_requestor_block_start( r, 12UL, &bid12 );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUEST && req->kind==AG_REPAIR_KIND_FEC_ROOT && req->idx==0U );
  fd_hash_t m = root0; hash_insert( chainer, 12UL, &bid12, 0U, &m );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUEST && req->kind==AG_REPAIR_KIND_FEC_ROOT && req->idx==32U );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUESTED );

  /* a fresh walk picks up set 0's shreds under its sentinel root */
  fd_requestor_block_start( r, 12UL, &bid12 );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUEST && req->kind==AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID && req->idx==0U && !memcmp( req->fec_root.uc, root0.uc, FD_SHRED_MERKLE_NODE_SZ ) );

  /* the buffered prefix grows mid-walk: the cursor jumps past it */
  for( uint i=0U; i<32U; i++ ) shred( chainer, 12UL, i, 0, &root0, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( fd_chainer_slot_version_query( chainer, 12UL, &bid12 )->buffered_idx==31U );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUEST && req->kind==AG_REPAIR_KIND_FEC_ROOT && req->idx==32U );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_REQUESTED );
  FD_TEST( advance( r, chainer, req )==FD_REQUESTOR_ADVANCE_IDLE );

  FD_LOG_NOTICE(( "pass: walk reads the chainer fresh on every request" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "normal"                 );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 16384UL                  );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_turbine ( wksp );
  test_ancestry( wksp );
  test_verified( wksp );
  test_gone    ( wksp );
  test_moving  ( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
