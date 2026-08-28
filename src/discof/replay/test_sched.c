#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "fd_execrp.h"
#include "fd_sched.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/txn/fd_txn_generate.h"

#define TEST_EXEC_CNT         4UL
#define TEST_ROOT_SLOT        1000UL
#define TEST_ROOT_TICK_HEIGHT 5000UL

static void
test_sched_footprint( void ) {
  /* Retain the per-block saving from compact shred lengths under the
     default scheduler sizing. */
  FD_TEST( fd_sched_footprint( 65536UL, 2048UL )==1122030976UL );
}

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

static ulong
build_shred_test_txn( uchar * payload ) {
  fd_pubkey_t payer[ 1 ];
  fd_pubkey_t program[ 1 ];
  fd_memset( payer->uc,   0x11, sizeof(fd_pubkey_t) );
  fd_memset( program->uc, 0x22, sizeof(fd_pubkey_t) );

  fd_txn_accounts_t accounts = {
    .signature_cnt         = 1U,
    .readonly_signed_cnt   = 0U,
    .readonly_unsigned_cnt = 1U,
    .acct_cnt              = 2U,
    .signers_w             = payer,
    .signers_r             = NULL,
    .non_signers_w         = NULL,
    .non_signers_r         = program,
  };

  uchar meta[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_memset( meta, 0, sizeof(meta) );
  fd_txn_base_generate( meta, payload, 1UL, &accounts, NULL );

  uchar instr_acct = 0U;
  uchar instr_data = 0x5aU;
  return fd_txn_add_instr( meta, payload, 1U, &instr_acct, 1UL, &instr_data, 1UL );
}

static void
run_interleaved_fec_residual_case( void ) {
  ulong footprint = fd_sched_footprint( FD_SCHED_MIN_DEPTH, 4UL );
  void * mem = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, FD_SCHED_MIN_DEPTH, 4UL, TEST_EXEC_CNT, 0 ) );
  FD_TEST( sched );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  uchar txn_payload[ FD_TXN_MTU ];
  ulong txn_sz = build_shred_test_txn( txn_payload );
  uint signature_tag[ 2 ] = { 0x12345678U, 0x9abcdef0U };

  uchar encoded[ 2 ][ 8192 ];
  ulong encoded_sz[ 2 ];
  ulong split_off[ 2 ];
  fd_hash_t start_poh[ 2 ];

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_hash_t tx_mblk_hash[ 1 ];
    fd_hash_t tick_hash[ 1 ];
    hash_from_seed( start_poh+i, 0x459db07a9f2c0321UL+i );
    hash_from_seed( tx_mblk_hash, 0x9e33470a182d6cbfUL+i );
    repeat_hash( tick_hash, tx_mblk_hash, 1UL );

    ulong cursor = 0UL;
    FD_STORE( ulong, encoded[ i ]+cursor, 2UL );
    cursor += sizeof(ulong);
    fd_microblock_hdr_t tx_hdr = {
      .hash_cnt = 1UL,
      .txn_cnt  = 1UL,
    };
    fd_memcpy( tx_hdr.hash, tx_mblk_hash->hash, sizeof(fd_hash_t) );
    fd_memcpy( encoded[ i ]+cursor, &tx_hdr, sizeof(tx_hdr) );
    cursor += sizeof(tx_hdr);

    uchar tagged_txn[ FD_TXN_MTU ];
    fd_memcpy( tagged_txn, txn_payload, txn_sz );
    FD_STORE( uint, tagged_txn+1UL, signature_tag[ i ] );
    split_off[ i ] = cursor+txn_sz/2UL;
    fd_memcpy( encoded[ i ]+cursor, tagged_txn, txn_sz );
    cursor += txn_sz;

    fd_microblock_hdr_t tick_hdr = {
      .hash_cnt = 1UL,
      .txn_cnt  = 0UL,
    };
    fd_memcpy( tick_hdr.hash, tick_hash->hash, sizeof(fd_hash_t) );
    fd_memcpy( encoded[ i ]+cursor, &tick_hdr, sizeof(tick_hdr) );
    cursor += sizeof(tick_hdr);
    encoded_sz[ i ] = cursor;
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    store_fec->data_sz         = split_off[ i ];
    store_fec->shred_offs[ 0 ] = (uint)split_off[ i ];
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = 2UL+i,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT+1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .data              = encoded[ i ],
      .shred_cnt         = 1U,
      .is_first_in_block = 1U,
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    fd_sched_set_poh_params( sched, 2UL+i, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 2UL, start_poh+i );
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    store_fec->data_sz         = encoded_sz[ i ]-split_off[ i ];
    ulong txn_rem = txn_sz-txn_sz/2UL;
    if( !i ) {
      store_fec->shred_offs[ 0 ] = (uint)(txn_rem/2UL);
      store_fec->shred_offs[ 1 ] = (uint)txn_rem;
      store_fec->shred_offs[ 2 ] = (uint)store_fec->data_sz;
    } else {
      store_fec->shred_offs[ 0 ] = (uint)store_fec->data_sz;
    }
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx         = 2UL+i,
      .parent_bank_idx  = 1UL,
      .slot             = TEST_ROOT_SLOT+1UL,
      .parent_slot      = TEST_ROOT_SLOT,
      .fec              = store_fec,
      .data             = encoded[ i ]+split_off[ i ],
      .shred_cnt        = (uint)(i ? 1UL : 3UL),
      .is_last_in_batch = 1U,
      .is_last_in_block = 1U,
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
  }

  ulong txn_exec_cnt = 0UL;
  for( ulong step=0UL; step<100UL; step++ ) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

    fd_sched_task_t task[ 1 ];
    if( !fd_sched_task_next_ready( sched, task ) ) break;
    switch( task->task_type ) {
      case FD_SCHED_TT_BLOCK_START:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_BLOCK_END:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_TXN_EXEC: {
        fd_txn_p_t * txn = fd_sched_get_txn( sched, task->txn_exec->txn_idx );
        FD_TEST( task->txn_exec->bank_idx==2UL || task->txn_exec->bank_idx==3UL );
        FD_TEST( FD_LOAD( uint, txn->payload+1UL )==signature_tag[ task->txn_exec->bank_idx-2UL ] );
        FD_TEST( txn->start_shred_idx==0U );
        FD_TEST( txn->end_shred_idx==fd_ushort_if( task->txn_exec->bank_idx==2UL, 2U, 1U ) );
        txn_exec_cnt++;
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC, task->txn_exec->txn_idx, task->txn_exec->exec_idx, NULL ) );
        break;
      }
      case FD_SCHED_TT_TXN_SIGVERIFY:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_SIGVERIFY, task->txn_sigverify->txn_idx, task->txn_sigverify->exec_idx, NULL ) );
        break;
      case FD_SCHED_TT_POH_HASH: {
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->mblk_idx = task->poh_hash->mblk_idx;
        msg->hashcnt  = task->poh_hash->hashcnt;
        repeat_hash( msg->hash, task->poh_hash->hash, task->poh_hash->hashcnt );
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) );
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task type %lu in interleaved FEC test", task->task_type ));
    }
  }
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  FD_TEST( txn_exec_cnt==2UL );
  FD_TEST( fd_sched_is_drained( sched ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

static void
run_bad_tick_case( fd_hash_t const * start_poh,
                   ulong const *     tick_hashcnt,
                   ulong             tick_cnt,
                   ulong             max_tick_height,
                   ulong             hashes_per_tick,
                   int               is_last_in_block,
                   int               expect_mark_dead,
                   int               expect_poh_fail,
                   int               expect_dead_reason ) {
  /* This test only needs the root, the parent, the child under test, and
     one spare slot. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 4UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, TEST_EXEC_CNT, 0 ) );
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
    .is_last_in_block  = !!is_last_in_block,
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
        if( FD_UNLIKELY( rc!=FD_SCHED_DEAD_REASON_NONE ) ) seen_poh_fail = 1;
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task_type %lu in bad tick case", task->task_type ));
    }
  }

  FD_TEST( seen_mark_dead==expect_mark_dead );
  FD_TEST( seen_poh_fail ==expect_poh_fail  );
  FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==expect_dead_reason );
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
    run_bad_tick_case( start_poh, tick_hashcnt, 1UL, TEST_ROOT_TICK_HEIGHT + 2UL, 1UL, 1, 1, 0, FD_SCHED_DEAD_REASON_TOO_FEW_TICKS );
  }

  {
    ulong tick_hashcnt[ 2 ] = { 1UL, 1UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 2UL, TEST_ROOT_TICK_HEIGHT + 1UL, 1UL, 1, 0, 1, FD_SCHED_DEAD_REASON_TOO_MANY_TICKS );
  }

  {
    ulong tick_hashcnt[ 1 ] = { 1UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 1UL, TEST_ROOT_TICK_HEIGHT + 1UL, 1UL, 0, 0, 1, FD_SCHED_DEAD_REASON_INVALID_LAST_TICK );
  }

  {
    ulong tick_hashcnt[ 2 ] = { 1UL, 2UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 2UL, TEST_ROOT_TICK_HEIGHT + 2UL, 2UL, 1, 0, 1, FD_SCHED_DEAD_REASON_WRONG_HASHES_PER_TICK );
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
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, TEST_EXEC_CNT, 0 ) );
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


/* Ingest a single empty FEC set to bring a new live block into the fork
   tree as a child of parent_bank_idx.  Returns fd_sched_fec_ingest's
   verdict: 0 when the block landed under a lineage that is already
   going down, which is the path the replay tile reads the dead reason
   and discarded flavor back out on. */
static int
add_live_block( fd_sched_t * sched,
                ulong        bank_idx,
                ulong        parent_bank_idx,
                ulong        slot,
                ulong        parent_slot ) {
  fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );

  fd_sched_fec_t fec[ 1 ] = {{
    .bank_idx          = bank_idx,
    .parent_bank_idx   = parent_bank_idx,
    .slot              = slot,
    .parent_slot       = parent_slot,
    .fec               = store_fec,
    .shred_cnt         = 1U,
    .is_last_in_batch  = 0U,
    .is_last_in_block  = 0U,
    .is_first_in_block = 1U
  }};
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  return fd_sched_fec_ingest( sched, fec );
}

static fd_sched_t *
new_sched( fd_rng_t * rng, void ** mem_out, ulong block_cnt_max ) {
  ulong depth     = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong footprint = fd_sched_footprint( depth, block_cnt_max );
  void * mem      = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, TEST_EXEC_CNT, 0 ) );
  FD_TEST( sched );
  *mem_out = mem;
  return sched;
}

/* A block given up on without fault keeps a clean dead reason and
   raises the discarded flag, and blocks that later arrive under it
   inherit that flavor rather than looking ruled-invalid.  A block ruled
   invalid stays un-discarded, so the flag never masks a verdict. */
static void
run_abandon_flavor_case( void ) {
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  /* Discarded lineage: eviction, then two generations arriving under
     it.  Both must come back DEAD_ANCESTOR and discarded. */
  {
    void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL );
    fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );
    FD_TEST( add_live_block( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT ) );

    fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_DISCARDED );
    /* The block the discard was called on went down on its own, so it
       must not pick up its live parent's flavor. */
    FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_NONE );
    FD_TEST( fd_sched_block_is_discarded( sched, 2UL )==1 );

    FD_TEST( !add_live_block( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL ) );
    FD_TEST( fd_sched_get_dead_reason( sched, 3UL )==FD_SCHED_DEAD_REASON_DEAD_ANCESTOR );
    FD_TEST( fd_sched_block_is_discarded( sched, 3UL )==1 );

    FD_TEST( !add_live_block( sched, 4UL, 3UL, TEST_ROOT_SLOT+3UL, TEST_ROOT_SLOT+2UL ) );
    FD_TEST( fd_sched_get_dead_reason( sched, 4UL )==FD_SCHED_DEAD_REASON_DEAD_ANCESTOR );
    FD_TEST( fd_sched_block_is_discarded( sched, 4UL )==1 );

    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
  }

  /* Invalid lineage: the replay tile owns the specific reason, so the
     scheduler records none of its own, and nothing is discarded. */
  {
    void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL );
    fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );
    FD_TEST( add_live_block( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT ) );

    fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_INVALID );
    FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_NONE );
    FD_TEST( fd_sched_block_is_discarded( sched, 2UL )==0 );

    FD_TEST( !add_live_block( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL ) );
    FD_TEST( fd_sched_get_dead_reason( sched, 3UL )==FD_SCHED_DEAD_REASON_DEAD_ANCESTOR );
    FD_TEST( fd_sched_block_is_discarded( sched, 3UL )==0 );

    /* Discarding a block that is already going down must not relabel
       it.  The scheduler records no reason for a ruling the replay tile
       made, so dead_reason alone cannot tell this apart from a block
       that is still healthy. */
    fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_DISCARDED );
    FD_TEST( fd_sched_block_is_discarded( sched, 2UL )==0 );
    FD_TEST( fd_sched_block_is_discarded( sched, 3UL )==0 );

    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
  }
}

/* A minority fork loses the fork race rather than violating the
   protocol, so a root notify discards it.  A fork already going down
   for a fault of its own keeps that flavor. */
static void
run_root_notify_flavor_case( void ) {
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );
  /* The fork consensus picks.  Rooting requires a fully replayed block,
     which add_done synthesizes. */
  fd_sched_block_add_done( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL );

  /* Minority fork, still live, with a descendant. */
  FD_TEST( add_live_block( sched, 3UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT ) );
  FD_TEST( add_live_block( sched, 4UL, 3UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL ) );

  /* Minority fork already ruled invalid by the replay tile before the
     root moved. */
  FD_TEST( add_live_block( sched, 5UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT ) );
  fd_sched_block_abandon( sched, 5UL, FD_SCHED_ABANDON_INVALID );

  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  fd_sched_root_notify( sched, 2UL );

  /* The live minority fork is discarded, and its descendant inherits. */
  FD_TEST( fd_sched_get_dead_reason( sched, 3UL )==FD_SCHED_DEAD_REASON_NONE );
  FD_TEST( fd_sched_block_is_discarded( sched, 3UL )==1 );
  FD_TEST( fd_sched_get_dead_reason( sched, 4UL )==FD_SCHED_DEAD_REASON_DEAD_ANCESTOR );
  FD_TEST( fd_sched_block_is_discarded( sched, 4UL )==1 );

  /* The already-invalid fork is not relabeled by losing the race. */
  FD_TEST( fd_sched_get_dead_reason( sched, 5UL )==FD_SCHED_DEAD_REASON_NONE );
  FD_TEST( fd_sched_block_is_discarded( sched, 5UL )==0 );

  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
}

/* A block that already went down keeps the flavor it went down with
   when an ancestor is abandoned later.  The replay tile's rulings are
   the load-bearing case: sched records no dead reason for them, so only
   dying tells them apart from a healthy block. */
static void
run_late_ancestor_discard_case( void ) {
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );
  fd_sched_block_add_done( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL ); /* the fork consensus picks */

  /* A live minority fork with a child on it. */
  FD_TEST( add_live_block( sched, 3UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT ) );
  FD_TEST( add_live_block( sched, 4UL, 3UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL ) );

  /* The replay tile rules the child invalid. */
  fd_sched_block_abandon( sched, 4UL, FD_SCHED_ABANDON_INVALID );
  FD_TEST( fd_sched_get_dead_reason( sched, 4UL )==FD_SCHED_DEAD_REASON_NONE );
  FD_TEST( fd_sched_block_is_discarded( sched, 4UL )==0 );

  /* Only now does the still-live ancestor lose the fork race. */
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  fd_sched_root_notify( sched, 2UL );

  /* The ancestor is discarded. */
  FD_TEST( fd_sched_get_dead_reason( sched, 3UL )==FD_SCHED_DEAD_REASON_NONE );
  FD_TEST( fd_sched_block_is_discarded( sched, 3UL )==1 );

  /* The child is not relabeled by it. */
  FD_TEST( fd_sched_get_dead_reason( sched, 4UL )==FD_SCHED_DEAD_REASON_NONE );
  FD_TEST( fd_sched_block_is_discarded( sched, 4UL )==0 );

  /* And a block arriving under the child reports the lineage it really
     died of, an invalid one, not the ancestor's discard. */
  FD_TEST( !add_live_block( sched, 5UL, 4UL, TEST_ROOT_SLOT+3UL, TEST_ROOT_SLOT+2UL ) );
  FD_TEST( fd_sched_get_dead_reason( sched, 5UL )==FD_SCHED_DEAD_REASON_DEAD_ANCESTOR );
  FD_TEST( fd_sched_block_is_discarded( sched, 5UL )==0 );

  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_sched_footprint();
  run_lane_policy_case();
  run_bad_tick_cases();
  run_interleaved_fec_residual_case();
  run_abandon_flavor_case();
  run_root_notify_flavor_case();
  run_late_ancestor_discard_case();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
