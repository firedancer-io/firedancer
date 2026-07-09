#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "fd_execrp.h"
#include "fd_sched.h"
#include "../../ballet/sha256/fd_sha256.h"

#define TEST_EXEC_CNT         4UL
#define TEST_ROOT_SLOT        1000UL
#define TEST_ROOT_TICK_HEIGHT 5000UL

static void
hash_from_seed( fd_hash_t * out,
                ulong       seed ) {
  for( ulong i=0UL; i<4UL; i++ ) out->ul[ i ] = seed ^ (0x9e3779b97f4a7c15UL * (i+1UL));
}

/* repeat_hash is fd_sha256_hash( fd_sha256_hash(  ... start ) )
   repeated cnt times. */
static void
repeat_hash( fd_hash_t *       out,
             fd_hash_t const * start,
             ulong             cnt ) {
  uchar cur[ 32 ];
  fd_memcpy( cur, start->hash, 32UL );
  for( ulong i=0UL; i<cnt; i++ ) fd_sha256_hash( cur, 32UL, cur );
  fd_memcpy( out->hash, cur, 32UL );
}

static void
encode_tick_block( uchar *           encoded,
                   ulong *           encoded_sz,
                   fd_hash_t const * start_poh,
                   ulong const *     tick_hashcnt,
                   ulong             tick_cnt ) {
  FD_STORE( ulong, encoded, tick_cnt );
  ulong cursor = sizeof(ulong);

  fd_hash_t prev_hash[ 1 ];
  fd_memcpy( prev_hash, start_poh, sizeof(fd_hash_t) );

  for( ulong i=0UL; i<tick_cnt; i++ ) {
    fd_hash_t end_hash[ 1 ];
    repeat_hash( end_hash, prev_hash, tick_hashcnt[ i ] );

    fd_microblock_hdr_t hdr = {
      .hash_cnt = tick_hashcnt[ i ],
      .txn_cnt  = 0UL
    };
    fd_memcpy( hdr.hash, end_hash->hash, sizeof(fd_hash_t) );
    fd_memcpy( encoded + cursor, &hdr, sizeof(fd_microblock_hdr_t) );
    cursor += sizeof(fd_microblock_hdr_t);
    fd_memcpy( prev_hash, end_hash, sizeof(fd_hash_t) );
  }

  *encoded_sz = cursor;
}

static void
run_bad_tick_case( fd_hash_t const * start_poh,
                   ulong const *     tick_hashcnt,
                   ulong             tick_cnt,
                   ulong             max_tick_height,
                   ulong             hashes_per_tick,
                   int               expect_mark_dead,
                   int               expect_poh_fail ) {
  /* This test only needs the root, the parent, the child under test, and
     one spare slot. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 4UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, TEST_EXEC_CNT ) );
  FD_TEST( sched );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  uchar encoded[ sizeof(ulong) + 4UL*sizeof(fd_microblock_hdr_t) ] = {0};
  ulong encoded_sz = 0UL;
  encode_tick_block( encoded, &encoded_sz, start_poh, tick_hashcnt, tick_cnt );

  fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
  store_fec->data_sz       = encoded_sz;
  store_fec->shred_offs[0] = (uint)encoded_sz;

  fd_sched_fec_t fec[ 1 ] = {{
    .bank_idx          = 2UL,
    .parent_bank_idx   = 1UL,
    .slot              = TEST_ROOT_SLOT + 1UL,
    .parent_slot       = TEST_ROOT_SLOT,
    .fec               = store_fec,
    .data              = encoded,
    .shred_cnt         = 1U,
    .is_last_in_batch  = 1U,
    .is_last_in_block  = 1U,
    .is_first_in_block = 1U
  }};
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, max_tick_height, hashes_per_tick, start_poh );

  fd_sched_task_t task[ 1 ];
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  FD_TEST( task->block_start->bank_idx==2UL );
  FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );

  int seen_mark_dead = 0;
  int seen_poh_fail  = 0;
  for(;;) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    if( FD_UNLIKELY( !fd_sched_task_next_ready( sched, task ) ) ) break;
    switch( task->task_type ) {
      case FD_SCHED_TT_MARK_DEAD:
        FD_TEST( task->mark_dead->bank_idx==2UL );
        seen_mark_dead = 1;
        break;
      case FD_SCHED_TT_POH_HASH: {
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->mblk_idx = task->poh_hash->mblk_idx;
        msg->hashcnt  = task->poh_hash->hashcnt;
        repeat_hash( msg->hash, task->poh_hash->hash, task->poh_hash->hashcnt );
        int rc = fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg );
        if( FD_UNLIKELY( rc==-1 ) ) seen_poh_fail = 1;
        else                        FD_TEST( rc==0 );
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task_type %lu in bad tick case", task->task_type ));
    }
  }

  FD_TEST( seen_mark_dead==expect_mark_dead );
  FD_TEST( seen_poh_fail ==expect_poh_fail  );
  FD_TEST( fd_sched_is_drained( sched ) );
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

static void
run_bad_tick_cases( void ) {
  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x4d85f12e7a9b3105UL );

  {
    ulong tick_hashcnt[ 1 ] = { 1UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 1UL, TEST_ROOT_TICK_HEIGHT + 2UL, 1UL, 1, 0 );
  }

  {
    ulong tick_hashcnt[ 2 ] = { 1UL, 1UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 2UL, TEST_ROOT_TICK_HEIGHT + 1UL, 1UL, 0, 1 );
  }

  {
    ulong tick_hashcnt[ 2 ] = { 1UL, 2UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 2UL, TEST_ROOT_TICK_HEIGHT + 2UL, 2UL, 0, 1 );
  }
}

static void
run_lane_policy_case( void ) {
  /* This test only needs the root and a handful of synthetic branches. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 8UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, TEST_EXEC_CNT ) );
  FD_TEST( sched );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );
  FD_TEST( fd_sched_is_drained( sched ) );
  (void)fd_sched_can_ingest_cnt( sched );

  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x91b53d8a74f2c601UL );

  for( ulong bank_idx=2UL; bank_idx<=5UL; bank_idx++ ) {
    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );

    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = bank_idx,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT + bank_idx - 1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .shred_cnt         = 1U,
      .is_last_in_batch  = 0U,
      .is_last_in_block  = 0U,
      .is_first_in_block = 1U
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx + 1UL, 1UL, start_poh );

    fd_sched_task_t task[ 1 ];
    FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
    FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
    FD_TEST( task->block_start->bank_idx==bank_idx );
    FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
    FD_TEST( fd_sched_is_drained( sched ) );
  }

  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "staged_bitset 15," ) );

  {
    ulong bank_idx = 6UL;
    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );

    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = bank_idx,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT + bank_idx - 1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .shred_cnt         = 1U,
      .is_last_in_batch  = 0U,
      .is_last_in_block  = 0U,
      .is_first_in_block = 1U
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx + 1UL, 1UL, start_poh );
  }

  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 6, staged_bitset 1," ) );
  FD_TEST( strstr( state, "block_added_staged_cnt 4," ) );
  FD_TEST( strstr( state, "block_added_unstaged_cnt 1," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 1," ) );
  FD_TEST( strstr( state, "block_demoted_cnt 4," ) );
  FD_TEST( strstr( state, "lane_promoted_cnt 1," ) );
  FD_TEST( strstr( state, "lane_demoted_cnt 4," ) );

  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  FD_TEST( task->block_start->bank_idx==6UL );
  FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
  FD_TEST( fd_sched_is_drained( sched ) );

  state = fd_sched_get_state_cstr( sched );
  /* Block 6 finished its start-of-block work but, being an empty
     partial block, has nothing more to dispatch, so it is deactivated
     (active_bank_idx==ULONG_MAX) while staying staged on its lane
     (staged_bitset 1). */
  char expect_active[ 64 ];
  fd_cstr_printf( expect_active, sizeof(expect_active), NULL, "active_idx %lu, staged_bitset 1,", ULONG_MAX );
  FD_TEST( strstr( state, expect_active ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  run_lane_policy_case();
  run_bad_tick_cases();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
