#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "fd_execrp.h"
#include "fd_sched.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"
#include "../../flamenco/runtime/fd_runtime_const.h"

#define TEST_EXEC_CNT         4UL
#define TEST_ROOT_SLOT        1000UL
#define TEST_ROOT_TICK_HEIGHT 5000UL
/* The flag-off footprint is the pre-LtHash 1761648896 plus 32 bytes
   of counters per block and 2176 bytes of new fd_sched_t fields, mostly
   the per-tile records.  The flag-on footprint adds the depth reserve,
   the lane maps, the hash pool, the deltas and the pseudo-transaction
   links. */
#define TEST_SCHED_FOOTPRINT      (1761716608UL)
#define TEST_LTHASH_OOB_FOOTPRINT (2185021824UL)

static void
test_sched_footprint( void ) {
  FD_LOG_NOTICE(( "footprint lthash_oob=0 %lu lthash_oob=1 %lu",
                  fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 ),
                  fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 1 ) ));
  /* Retain the savings from compact shred lengths and 4992-byte
     transactions under the default scheduler sizing. */
  FD_TEST( fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 )==TEST_SCHED_FOOTPRINT );
  /* Only the shred length array scales with the shred limit. */
  FD_TEST( fd_sched_footprint( 65536UL, 2048UL, 4UL*FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 )==TEST_SCHED_FOOTPRINT+2048UL*3UL*FD_SHRED_BLK_MAX*sizeof(ushort) );
  FD_TEST( fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, 5UL*FD_MAX_TXN_PER_SLOT, 0 )==TEST_SCHED_FOOTPRINT );
  FD_TEST( !fd_sched_footprint( 65536UL, 2048UL, 0UL, FD_MAX_TXN_PER_SLOT, 0 ) );
  FD_TEST( !fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, 0UL, 0 ) );
  /* Out-of-band LtHash inflates the depth by the pseudo-transaction
     reserve and adds the entry maps, hash pool, per-block deltas and
     pseudo-transaction links. */
  FD_TEST( fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 1 )==TEST_LTHASH_OOB_FOOTPRINT );
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
  ulong footprint = fd_sched_footprint( FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 );
  void * mem = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, 0, 0 ) );
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
    FD_TEST( split_off[ i ]<=USHORT_MAX );
    store_fec->data_sz       = (uint)split_off[ i ];
    store_fec->shred_sz[ 0 ] = (ushort)split_off[ i ];
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
    store_fec->data_sz = (uint)(encoded_sz[ i ]-split_off[ i ]);
    ulong txn_rem = txn_sz-txn_sz/2UL;
    if( !i ) {
      FD_TEST( txn_rem<=USHORT_MAX );
      FD_TEST( store_fec->data_sz>=txn_rem );
      FD_TEST( store_fec->data_sz-(uint)txn_rem<=USHORT_MAX );
      store_fec->shred_sz[ 0 ] = (ushort)(txn_rem/2UL);
      store_fec->shred_sz[ 1 ] = (ushort)(txn_rem-txn_rem/2UL);
      store_fec->shred_sz[ 2 ] = (ushort)(store_fec->data_sz-(uint)txn_rem);
    } else {
      FD_TEST( store_fec->data_sz<=USHORT_MAX );
      store_fec->shred_sz[ 0 ] = (ushort)store_fec->data_sz;
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
        msg->cnt = task->poh_hash->cnt;
        for( ulong i=0UL; i<task->poh_hash->cnt; i++ ) {
          repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
        }
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
                   int               alpenglow,
                   int               expect_mark_dead,
                   int               expect_poh_fail,
                   int               expect_dead_reason ) {
  /* This test only needs the root, the parent, the child under test, and
     one spare slot. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 4UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, alpenglow, 0 ) );
  FD_TEST( sched );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  uchar encoded[ sizeof(ulong) + 4UL*sizeof(fd_microblock_hdr_t) ] = {0};
  ulong encoded_sz = 0UL;
  encode_tick_block( encoded, &encoded_sz, start_poh, tick_hashcnt, tick_cnt );

  fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
  FD_TEST( encoded_sz<=USHORT_MAX );
  store_fec->data_sz       = (uint)encoded_sz;
  store_fec->shred_sz[ 0 ] = (ushort)encoded_sz;

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
      case FD_SCHED_TT_BLOCK_END: /* only reached when the block is valid */
        FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_POH_HASH: {
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->cnt = task->poh_hash->cnt;
        for( ulong i=0UL; i<task->poh_hash->cnt; i++ ) {
          repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
        }
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



/* Alpenglow block structure cases.  Each component is its own FEC set
   (one batch per FEC set, as sched assumes).  Markers are serialized
   with fd_block_marker_ser, which emits the whole zero-microblock
   batch; a tick is a one-microblock batch chained from the running
   PoH. */

#define AG_COMP_HEADER        (0)
#define AG_COMP_FOOTER        (1)
#define AG_COMP_UPDATE_PARENT (2)
#define AG_COMP_TICK          (3) /* alpentick: one hash */
#define AG_COMP_TICK_0HASH    (4) /* tick declaring zero hashes: invalid under Alpenglow */
#define AG_COMP_TICK_2HASH    (5) /* tick declaring two hashes: invalid under Alpenglow */

/* AG_SPLIT( comp, cut ) is comp delivered as two FEC sets of the same
   batch, the first holding the leading cut bytes. */
#define AG_SPLIT( comp, cut ) ((comp) | (int)((cut)<<8))

static ulong
encode_ag_component( uchar *     out,
                     int         comp,
                     fd_hash_t * prev_hash ) {
  fd_block_marker_t marker[1];
  fd_memset( marker, 0, sizeof(fd_block_marker_t) );
  switch( comp ) {
  case AG_COMP_HEADER:
    marker->kind               = FD_BLOCK_MARKER_KIND_HEADER;
    marker->header.parent_slot = TEST_ROOT_SLOT;
    return fd_block_marker_ser( marker, out );
  case AG_COMP_FOOTER:
    marker->kind = FD_BLOCK_MARKER_KIND_FOOTER;
    return fd_block_marker_ser( marker, out );
  case AG_COMP_UPDATE_PARENT: {
    /* fd_block_marker_ser only produces headers and footers (nothing
       Firedancer emits is an UpdateParent), so lay the wire format out
       by hand: preamble (entry_cnt=0, version=1, tag, length) then a
       V1 payload (version=1, new_parent_slot, new_parent_block_id). */
    ulong off = 0UL;
    FD_STORE( ulong,  out+off, 0UL );                                  off += sizeof(ulong);
    FD_STORE( ushort, out+off, (ushort)1 );                            off += sizeof(ushort);
    out[ off ] = (uchar)FD_BLOCK_MARKER_KIND_UPDATE_PARENT;            off += sizeof(uchar);
    FD_STORE( ushort, out+off, (ushort)FD_UPDATE_PARENT_SER_SZ );      off += sizeof(ushort);
    out[ off ] = (uchar)1;                                             off += sizeof(uchar);
    FD_STORE( ulong,  out+off, TEST_ROOT_SLOT );                       off += sizeof(ulong);
    fd_memset( out+off, 0, sizeof(fd_hash_t) );                        off += sizeof(fd_hash_t);
    return off;
  }
  case AG_COMP_TICK:
  case AG_COMP_TICK_0HASH:
  case AG_COMP_TICK_2HASH: {
    ulong hash_cnt = comp==AG_COMP_TICK ? 1UL : comp==AG_COMP_TICK_0HASH ? 0UL : 2UL;
    FD_STORE( ulong, out, 1UL );
    fd_hash_t end_hash[ 1 ];
    repeat_hash( end_hash, prev_hash, hash_cnt );
    fd_microblock_hdr_t hdr = { .hash_cnt = hash_cnt, .txn_cnt = 0UL };
    fd_memcpy( hdr.hash, end_hash->hash, sizeof(fd_hash_t) );
    fd_memcpy( out+sizeof(ulong), &hdr, sizeof(fd_microblock_hdr_t) );
    fd_memcpy( prev_hash, end_hash, sizeof(fd_hash_t) );
    return sizeof(ulong)+sizeof(fd_microblock_hdr_t);
  }
  default:
    FD_LOG_ERR(( "bad component %d", comp ));
  }
}

/* Feeds the components as consecutive FEC sets.  If expect_ingest_ok is
   0, some FEC ingest must fail and the block must carry
   expect_dead_reason.  Otherwise every ingest succeeds and the block is
   driven to completion, ending with expect_dead_reason (NONE for a
   valid block). */
static void
run_ag_structure_case( fd_hash_t const * start_poh,
                       int const *       comps,
                       ulong             comp_cnt,
                       int               expect_ingest_ok,
                       int               expect_dead_reason ) {
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 4UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, 1 /* alpenglow */, 0 ) );
  FD_TEST( sched );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  static uchar          encoded  [ 8 ][ FD_BLOCK_MARKER_SER_MAX ] __attribute__((aligned(64)));
  static fd_store_fec_t store_fec[ 16 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  FD_TEST( comp_cnt<=8UL );

  fd_hash_t prev_hash[ 1 ];
  fd_memcpy( prev_hash, start_poh, sizeof(fd_hash_t) );

  int   ingest_ok = 1;
  ulong fec_cnt   = 0UL;
  for( ulong i=0UL; i<comp_cnt && ingest_ok; i++ ) {
    ulong sz  = encode_ag_component( encoded[ i ], comps[ i ]&0xff, prev_hash );
    ulong cut = (ulong)comps[ i ]>>8;
    FD_TEST( sz && sz<=USHORT_MAX );
    for( ulong off=0UL, n; off<sz && ingest_ok; off+=n ) {
      n = (cut && cut<sz && !off) ? cut : sz-off;
      int last = off+n==sz;
      fd_store_fec_t * sf = store_fec+fec_cnt++;
      fd_memset( sf, 0, sizeof(fd_store_fec_t) );
      sf->data_sz     = (uint)n;
      sf->shred_sz[0] = (ushort)n;
      fd_sched_fec_t fec[ 1 ] = {{
        .bank_idx          = 2UL,
        .parent_bank_idx   = 1UL,
        .slot              = TEST_ROOT_SLOT + 1UL,
        .parent_slot       = TEST_ROOT_SLOT,
        .fec               = sf,
        .data              = encoded[ i ]+off,
        .shred_cnt         = 1U,
        .is_last_in_batch  = !!last,
        .is_last_in_block  = last && i==comp_cnt-1UL,
        .is_first_in_block = !i && !off,
      }};
      FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
      ingest_ok = !!fd_sched_fec_ingest( sched, fec );
      if( FD_LIKELY( ingest_ok && !i && !off ) ) {
        fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 1UL, start_poh );
      }
    }
  }
  FD_TEST( ingest_ok==expect_ingest_ok );

  if( FD_LIKELY( ingest_ok ) ) {
    fd_sched_task_t task[ 1 ];
    for(;;) {
      while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
      if( FD_UNLIKELY( !fd_sched_task_next_ready( sched, task ) ) ) break;
      switch( task->task_type ) {
        case FD_SCHED_TT_BLOCK_START:
          FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
          break;
        case FD_SCHED_TT_BLOCK_END:
          FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
          break;
        case FD_SCHED_TT_MARK_DEAD:
          FD_TEST( task->mark_dead->bank_idx==2UL );
          break;
        case FD_SCHED_TT_POH_HASH: {
          fd_execrp_poh_hash_done_msg_t msg[ 1 ];
          msg->cnt = task->poh_hash->cnt;
          for( ulong i=0UL; i<task->poh_hash->cnt; i++ ) repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
          fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg );
          break;
        }
        default:
          FD_LOG_ERR(( "unexpected task_type %lu in alpenglow structure case", task->task_type ));
      }
    }
  }

  FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==expect_dead_reason );
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

static void
run_ag_structure_cases( void ) {
  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x2b7e151628aed2a6UL );

  /* header | footer | alpentick: valid. */
  { int c[] = { AG_COMP_HEADER, AG_COMP_FOOTER, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 3UL, 1, FD_SCHED_DEAD_REASON_NONE ); }

  /* A footer split across FEC sets parses like an unsplit one, at every
     cut. */
  { uchar buf[ FD_BLOCK_MARKER_SER_MAX ] __attribute__((aligned(64)));
    ulong footer_sz = encode_ag_component( buf, AG_COMP_FOOTER, NULL );
    for( ulong cut=1UL; cut<footer_sz; cut++ ) {
      int c[] = { AG_COMP_HEADER, AG_SPLIT( AG_COMP_FOOTER, cut ), AG_COMP_TICK };
      run_ag_structure_case( start_poh, c, 3UL, 1, FD_SCHED_DEAD_REASON_NONE );
    } }

  /* Every Alpenglow entry advances exactly one hash.  A zero-hash
     alpentick would verify trivially against the parent's PoH and hand
     the leader control of the blockhash; agave rejects it, so must we,
     and at ingest.  More than one hash is just as invalid. */
  { int c[] = { AG_COMP_HEADER, AG_COMP_FOOTER, AG_COMP_TICK_0HASH };
    run_ag_structure_case( start_poh, c, 3UL, 0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT ); }
  { int c[] = { AG_COMP_HEADER, AG_COMP_FOOTER, AG_COMP_TICK_2HASH };
    run_ag_structure_case( start_poh, c, 3UL, 0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT ); }

  /* No header before the footer. */
  { int c[] = { AG_COMP_FOOTER, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 2UL, 0, FD_SCHED_DEAD_REASON_MISSING_PARENT_MARKER ); }

  /* No header before entries. */
  { int c[] = { AG_COMP_TICK, AG_COMP_FOOTER, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 3UL, 0, FD_SCHED_DEAD_REASON_MISSING_PARENT_MARKER ); }

  /* Two headers. */
  { int c[] = { AG_COMP_HEADER, AG_COMP_HEADER, AG_COMP_FOOTER, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 4UL, 0, FD_SCHED_DEAD_REASON_MULTIPLE_BLOCK_HEADERS ); }

  /* Two footers. */
  { int c[] = { AG_COMP_HEADER, AG_COMP_FOOTER, AG_COMP_FOOTER, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 4UL, 0, FD_SCHED_DEAD_REASON_MULTIPLE_BLOCK_FOOTERS ); }

  /* Anything after the alpentick. */
  { int c[] = { AG_COMP_HEADER, AG_COMP_FOOTER, AG_COMP_TICK, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 4UL, 0, FD_SCHED_DEAD_REASON_ENTRY_AFTER_BLOCK_FOOTER ); }

  /* No footer at all: the layout is final once the last FEC lands, so
     that ingest is what fails. */
  { int c[] = { AG_COMP_HEADER, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 2UL, 0, FD_SCHED_DEAD_REASON_MISSING_BLOCK_FOOTER ); }

  /* UpdateParent before the header or after the footer.  A valid
     position aborts (unhandled reparent) and cannot be tested here. */
  { int c[] = { AG_COMP_UPDATE_PARENT, AG_COMP_FOOTER, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 3UL, 0, FD_SCHED_DEAD_REASON_SPURIOUS_UPDATE_PARENT ); }
  { int c[] = { AG_COMP_HEADER, AG_COMP_FOOTER, AG_COMP_UPDATE_PARENT, AG_COMP_TICK };
    run_ag_structure_case( start_poh, c, 4UL, 0, FD_SCHED_DEAD_REASON_SPURIOUS_UPDATE_PARENT ); }
}

/* Regression: the per-tick hash bound at ingest (TICK_HASHES_OVERFLOW_
   INGEST) must apply to vanilla blocks but not to Alpenglow blocks.
   agave's verify_ticks returns early for Alpenglow, and every
   Alpenglow entry is pinned to exactly one hash, so the cumulative
   hash count between ticks is just the entry count and grows past
   FD_RUNTIME_MAX_HASHES_PER_TICK in a valid block.

   Ingests a batch of entry_cnt single-transaction microblocks, each
   declaring hash_cnt 1, except that microblock bad_idx (if not
   ULONG_MAX) declares bad_hash_cnt.  Transactions keep the microblocks
   from being ticks, which would reset the cumulative count. */
static void
run_many_entries_case( int   alpenglow,
                       ulong entry_cnt,
                       ulong bad_idx,
                       ulong bad_hash_cnt,
                       int   expect_ingest_ok,
                       int   expect_dead_reason ) {
  ulong depth         = 1UL<<17;
  ulong block_cnt_max = 4UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, alpenglow, 0 ) );
  FD_TEST( sched );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  uchar txn_payload[ FD_TXN_MTU ];
  ulong txn_sz = build_shred_test_txn( txn_payload );

  ulong  stream_sz = sizeof(ulong)+entry_cnt*(sizeof(fd_microblock_hdr_t)+txn_sz);
  uchar * stream   = malloc( stream_sz );
  FD_TEST( stream );
  FD_STORE( ulong, stream, entry_cnt );
  ulong cursor = sizeof(ulong);
  for( ulong i=0UL; i<entry_cnt; i++ ) {
    fd_microblock_hdr_t hdr = { .hash_cnt = i==bad_idx ? bad_hash_cnt : 1UL, .txn_cnt = 1UL };
    fd_memcpy( stream+cursor, &hdr, sizeof(hdr) );  cursor += sizeof(hdr);
    fd_memcpy( stream+cursor, txn_payload, txn_sz ); cursor += txn_sz;
  }
  FD_TEST( cursor==stream_sz );

  static uchar          marker_buf[ FD_BLOCK_MARKER_SER_MAX ] __attribute__((aligned(64)));
  static fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_hash_t prev_hash[ 1 ]; hash_from_seed( prev_hash, 0x5eedUL );

  int   ingest_ok = 1;
  uint  first     = 1U;
  ulong off       = 0UL;

  if( alpenglow ) {
    ulong sz = encode_ag_component( marker_buf, AG_COMP_HEADER, prev_hash );
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    store_fec->data_sz     = (uint)sz;
    store_fec->shred_sz[0] = (ushort)sz;
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx = 2UL, .parent_bank_idx = 1UL,
      .slot = TEST_ROOT_SLOT+1UL, .parent_slot = TEST_ROOT_SLOT,
      .fec = store_fec, .data = marker_buf, .shred_cnt = 1U,
      .is_last_in_batch = 1U, .is_first_in_block = 1U,
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    first = 0U;
  }

  /* Feed the batch in max sized FEC sets so residual handling across
     FEC boundaries gets exercised too. */
  while( off<stream_sz ) {
    ulong sz = fd_ulong_min( stream_sz-off, 63985UL );
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    store_fec->data_sz     = (uint)sz;
    store_fec->shred_sz[0] = (ushort)sz;
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx = 2UL, .parent_bank_idx = 1UL,
      .slot = TEST_ROOT_SLOT+1UL, .parent_slot = TEST_ROOT_SLOT,
      .fec = store_fec, .data = stream+off, .shred_cnt = 1U,
      .is_last_in_batch = off+sz==stream_sz,
      .is_first_in_block = !!first,
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    int ok = !!fd_sched_fec_ingest( sched, fec );
    if( FD_LIKELY( first ) ) {
      fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, alpenglow ? 1UL : 2UL, prev_hash );
    }
    first = 0U;
    off  += sz;
    if( FD_UNLIKELY( !ok ) ) { ingest_ok = 0; break; }
  }
  if( ingest_ok!=expect_ingest_ok ) FD_LOG_ERR(( "ag %d cnt %lu bad_idx %lu: ingest_ok %d dead %d", alpenglow, entry_cnt, bad_idx, ingest_ok, fd_sched_get_dead_reason( sched, 2UL ) ));
  FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==expect_dead_reason );

  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
  free( stream );
}

static void
run_many_entries_cases( void ) {
  ulong lim = FD_RUNTIME_MAX_HASHES_PER_TICK;
  FD_TEST( FD_SCHED_MAX_MBLK_PER_SLOT>lim+1000UL );
  FD_TEST( FD_MAX_TXN_PER_SLOT>90000UL );

  /* Vanilla: exactly the limit is fine, one more is rejected at
     ingest.  This is the boundary the Alpenglow exemption must not
     move. */
  run_many_entries_case( 0, lim,     ULONG_MAX, 0UL, 1, FD_SCHED_DEAD_REASON_NONE );
  run_many_entries_case( 0, lim+1UL, ULONG_MAX, 0UL, 0, FD_SCHED_DEAD_REASON_TICK_HASHES_OVERFLOW_INGEST );

  /* Alpenglow: the same entry counts are valid, well past the limit. */
  run_many_entries_case( 1, lim,      ULONG_MAX, 0UL, 1, FD_SCHED_DEAD_REASON_NONE );
  run_many_entries_case( 1, lim+1UL,  ULONG_MAX, 0UL, 1, FD_SCHED_DEAD_REASON_NONE );
  run_many_entries_case( 1, 90000UL,  ULONG_MAX, 0UL, 1, FD_SCHED_DEAD_REASON_NONE );

  /* Alpenglow still pins every entry to one hash, deep into a long
     batch: this is what bounds PoH work now that the cumulative check
     is gone.  Neither a huge nor a zero hash count gets through. */
  run_many_entries_case( 1, lim+100UL, lim+50UL, 2UL,       0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT );
  run_many_entries_case( 1, lim+100UL, lim+50UL, ULONG_MAX, 0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT );
  run_many_entries_case( 1, lim+100UL, lim+50UL, 0UL,       0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT );
  run_many_entries_case( 1, 10UL,      0UL,      lim+1UL,   0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT );
}

static void
run_bad_tick_cases( void ) {
  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x4d85f12e7a9b3105UL );

  {
    ulong tick_hashcnt[ 1 ] = { 1UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 1UL, TEST_ROOT_TICK_HEIGHT + 2UL, 1UL, 0, 1, 0, FD_SCHED_DEAD_REASON_TOO_FEW_TICKS );
  }

  {
    ulong tick_hashcnt[ 2 ] = { 1UL, 1UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 2UL, TEST_ROOT_TICK_HEIGHT + 1UL, 1UL, 0, 0, 1, FD_SCHED_DEAD_REASON_TOO_MANY_TICKS );
  }

  {
    ulong tick_hashcnt[ 2 ] = { 1UL, 2UL };
    run_bad_tick_case( start_poh, tick_hashcnt, 2UL, TEST_ROOT_TICK_HEIGHT + 2UL, 2UL, 0, 0, 1, FD_SCHED_DEAD_REASON_WRONG_HASHES_PER_TICK );
  }
}

static void
run_poh_spread_case( ulong tick_cnt,
                     ulong hashes_per_tick ) {
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 4UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, 0, 0 ) );
  FD_TEST( sched );

  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x7c1e5d3a9b204f6dUL );
  ulong tick_hashcnt[ 8 ];
  FD_TEST( tick_cnt<=8UL );
  for( ulong i=0UL; i<tick_cnt; i++ ) tick_hashcnt[ i ] = hashes_per_tick;

  uchar encoded[ sizeof(ulong) + 8UL*sizeof(fd_microblock_hdr_t) ] = {0};
  ulong encoded_sz = 0UL;
  encode_tick_block( encoded, &encoded_sz, start_poh, tick_hashcnt, tick_cnt );

  fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
  FD_TEST( encoded_sz<=USHORT_MAX );
  store_fec->data_sz       = (uint)encoded_sz;
  store_fec->shred_sz[ 0 ] = (ushort)encoded_sz;

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
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+tick_cnt, hashes_per_tick, start_poh );

  fd_sched_task_t task[ 1 ];
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );

  /* All exec tiles are idle and the block is fully ingested, so no
     tile is held back for transaction execution. */
  ulong min_cnt      = fd_sha256_simd_lane_min();
  ulong lane_cnt     = fd_sha256_simd_lane_max();
  ulong expect_cnt   = fd_ulong_min( (tick_cnt+TEST_EXEC_CNT-1UL)/TEST_EXEC_CNT, lane_cnt );
  if( expect_cnt<min_cnt ) expect_cnt = 1UL; /* below the kernel's SIMD floor, batching is pointless */
  ulong expect_tasks = fd_ulong_min( tick_cnt, TEST_EXEC_CNT );
  /* If the lane width is too narrow to fit every tick in one round
     (e.g. width 1 on non-AVX-512 x86), a round dispatches at most
     TEST_EXEC_CNT*expect_cnt microblocks and the rest wait. */
  int   overflow     = tick_cnt>TEST_EXEC_CNT*expect_cnt;

  ulong round_cnt = 0UL;
  int   saw_end   = 0;
  for(;;) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

    /* Drain every dispatchable PoH task for this round without
       completing any, so the whole batch of ticks is in flight at
       once. */
    fd_sched_task_t in_flight[ TEST_EXEC_CNT ];
    ulong in_flight_cnt = 0UL;
    ulong tile_mask     = 0UL;
    ulong mblk_cnt      = 0UL;
    while( fd_sched_task_next_ready( sched, task ) ) {
      if( task->task_type==FD_SCHED_TT_BLOCK_END ) {
        FD_TEST( !in_flight_cnt );
        FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
        saw_end = 1;
        break;
      }
      FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH );
      FD_TEST( in_flight_cnt<TEST_EXEC_CNT );
      FD_TEST( task->poh_hash->cnt<=expect_cnt );
      FD_TEST( task->poh_hash->exec_idx<TEST_EXEC_CNT );
      FD_TEST( !fd_ulong_extract_bit( tile_mask, (int)task->poh_hash->exec_idx ) );
      tile_mask = fd_ulong_set_bit( tile_mask, (int)task->poh_hash->exec_idx );
      mblk_cnt += task->poh_hash->cnt;
      in_flight[ in_flight_cnt++ ] = *task;
    }
    if( saw_end ) break;

    if( !overflow ) {
      FD_TEST( in_flight_cnt==expect_tasks );
      FD_TEST( mblk_cnt==tick_cnt );
    } else {
      FD_TEST( in_flight_cnt>=1UL );
      FD_TEST( mblk_cnt<=TEST_EXEC_CNT*expect_cnt );
    }
    round_cnt++;

    for( ulong t=0UL; t<in_flight_cnt; t++ ) {
      fd_sched_poh_hash_t * ph = in_flight[ t ].poh_hash;
      fd_execrp_poh_hash_done_msg_t msg[ 1 ];
      msg->cnt = ph->cnt;
      for( ulong i=0UL; i<ph->cnt; i++ ) {
        repeat_hash( msg->hash+i, ph->hash+i, ph->hashcnt );
      }
      FD_TEST( 0==fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, ph->exec_idx, msg ) );
    }
  }

  /* Each tick needs more than one maximally sized task, so the spread
     must have survived at least one re-dispatch of partially hashed
     ticks. */
  FD_TEST( round_cnt>=2UL );
  FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_NONE );
  FD_TEST( fd_sched_is_drained( sched ) );
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

static void
run_poh_spread_cases( void ) {
  /* Fewer ticks than tiles: exactly one tick per task, one task per
     tile. */
  run_poh_spread_case( 1UL, 9000UL );
  run_poh_spread_case( 3UL, 9000UL );
  run_poh_spread_case( TEST_EXEC_CNT, 9000UL );
  /* More ticks than tiles: at most ceil( tick_cnt/tile_cnt ) per task,
     clamped to the SIMD lane width (so exactly one per task on builds
     with a serial fallback), still using every tile. */
  run_poh_spread_case( 6UL, 9000UL );
  run_poh_spread_case( 8UL, 9000UL );
}

static void
run_lane_policy_case( void ) {
  /* This test only needs the root and a handful of synthetic branches. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 8UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, 0, 0 ) );
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
new_sched( fd_rng_t * rng, void ** mem_out, ulong block_cnt_max, int lthash_oob ) {
  ulong depth     = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong footprint = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, lthash_oob );
  void * mem      = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, 0, lthash_oob ) );
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
    void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL, 0 );
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
    void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL, 0 );
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

  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL, 0 );

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
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL, 0 );

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

/* The per-block shred and transaction limits are runtime values.  A
   block declaring more transactions than the limit is ruled invalid,
   and shred lengths past the first FEC land in the block's own slice of
   the shred length array. */
/* A microblock whose header declares hash_cnt==1 and at least one
   transaction has nothing left for PoH to hash.  It still dispatches,
   as a degenerate zero-hashcnt task, so that it retires through
   fd_sched_task_done and the block gets deactivated there.  Here such a
   microblock is the only queued work, and it lands in mixin waiting on
   transactions the FEC stream hasn't delivered yet, so the block is
   exhausted the moment the task retires. */
static void
run_zero_hashcnt_mblk_case( void ) {
  ulong footprint = fd_sched_footprint( FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 );
  void * mem = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, 0, 0 ) );
  FD_TEST( sched );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  uchar txn_payload[ FD_TXN_MTU ];
  ulong txn_sz = build_shred_test_txn( txn_payload );

  fd_hash_t start_poh[ 1 ];
  fd_hash_t mblk_hash[ 1 ];
  hash_from_seed( start_poh, 0x6d1f4c9a3b57e802UL );
  hash_from_seed( mblk_hash, 0xc40a97e5182b6d3fUL );

  /* First FEC: a complete single-transaction microblock.  The block
     declares more microblocks than this, so it stays incomplete. */
  uchar fec0[ 4096 ];
  ulong fec0_sz = 0UL;
  FD_STORE( ulong, fec0, 3UL );
  fec0_sz += sizeof(ulong);
  fd_microblock_hdr_t hdr_a = { .hash_cnt = 1UL, .txn_cnt = 1UL };
  fd_memcpy( hdr_a.hash, mblk_hash->hash, sizeof(fd_hash_t) );
  fd_memcpy( fec0+fec0_sz, &hdr_a, sizeof(hdr_a) );
  fec0_sz += sizeof(hdr_a);
  fd_memcpy( fec0+fec0_sz, txn_payload, txn_sz );
  fec0_sz += txn_sz;

  fd_store_fec_t store_fec0[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec0, 0, sizeof(fd_store_fec_t) );
  store_fec0->data_sz         = (uint)fec0_sz;
  store_fec0->shred_sz[ 0 ]   = (ushort)fec0_sz;
  fd_sched_fec_t fec[ 1 ] = {{
    .bank_idx          = 2UL,
    .parent_bank_idx   = 1UL,
    .slot              = TEST_ROOT_SLOT+1UL,
    .parent_slot       = TEST_ROOT_SLOT,
    .fec               = store_fec0,
    .data              = fec0,
    .shred_cnt         = 1U,
    .is_first_in_block = 1U,
  }};
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+4UL, 64UL, start_poh );

  /* Drain everything the first FEC made available. */
  ulong exec_cnt = 0UL;
  ulong poh_task_cnt = 0UL;
  for( ulong step=0UL; step<100UL; step++ ) {
    fd_sched_task_t task[ 1 ];
    if( !fd_sched_task_next_ready( sched, task ) ) break;
    switch( task->task_type ) {
      case FD_SCHED_TT_BLOCK_START:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_TXN_EXEC:
        exec_cnt++;
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC, task->txn_exec->txn_idx, task->txn_exec->exec_idx, NULL ) );
        break;
      case FD_SCHED_TT_TXN_SIGVERIFY:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_SIGVERIFY, task->txn_sigverify->txn_idx, task->txn_sigverify->exec_idx, NULL ) );
        break;
      case FD_SCHED_TT_POH_HASH: {
        poh_task_cnt++;
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->cnt = task->poh_hash->cnt;
        for( ulong i=0UL; i<task->poh_hash->cnt; i++ ) repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) );
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task type %lu draining first FEC", task->task_type ));
    }
  }
  FD_TEST( exec_cnt==1UL );
  /* The microblock had nothing to hash, but still went out as a task. */
  FD_TEST( poh_task_cnt==1UL );

  /* Second FEC: a microblock header declaring two transactions, but
     only a fragment of the first.  No transaction gets parsed out, so
     the only new work is a microblock with nothing left to hash. */
  uchar fec1[ 4096 ];
  ulong fec1_sz = 0UL;
  fd_microblock_hdr_t hdr_b = { .hash_cnt = 1UL, .txn_cnt = 2UL };
  fd_memcpy( hdr_b.hash, mblk_hash->hash, sizeof(fd_hash_t) );
  fd_memcpy( fec1+fec1_sz, &hdr_b, sizeof(hdr_b) );
  fec1_sz += sizeof(hdr_b);
  fd_memcpy( fec1+fec1_sz, txn_payload, txn_sz/2UL );
  fec1_sz += txn_sz/2UL;

  fd_store_fec_t store_fec1[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec1, 0, sizeof(fd_store_fec_t) );
  store_fec1->data_sz         = (uint)fec1_sz;
  store_fec1->shred_sz[ 0 ]   = (ushort)fec1_sz;
  fec->fec               = store_fec1;
  fec->data              = fec1;
  fec->is_first_in_block = 0U;
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );

  /* The microblock dispatches with nothing to hash, and retiring it
     exhausts the block.  Deactivation happens in fd_sched_task_done, so
     the scheduler simply parks and idles until more of the block shows
     up. */
  fd_sched_task_t task[ 1 ];
  FD_TEST( fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH );
  FD_TEST( task->poh_hash->cnt==1UL );
  FD_TEST( !task->poh_hash->hashcnt );
  {
    fd_execrp_poh_hash_done_msg_t msg[ 1 ];
    msg->cnt = task->poh_hash->cnt;
    for( ulong i=0UL; i<task->poh_hash->cnt; i++ ) repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
    FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) );
  }
  FD_TEST( !fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_is_drained( sched ) );

  /* Parked, not lost.  Delivering the rest of the transaction has to
     bring the block back and get it replaying again. */
  uchar fec2[ 4096 ];
  ulong fec2_sz = txn_sz-txn_sz/2UL;
  fd_memcpy( fec2, txn_payload+txn_sz/2UL, fec2_sz );

  fd_store_fec_t store_fec2[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec2, 0, sizeof(fd_store_fec_t) );
  store_fec2->data_sz         = (uint)fec2_sz;
  store_fec2->shred_sz[ 0 ]   = (ushort)fec2_sz;
  fec->fec  = store_fec2;
  fec->data = fec2;
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );

  FD_TEST( fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_TXN_EXEC );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC, task->txn_exec->txn_idx, task->txn_exec->exec_idx, NULL ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

static void
run_runtime_limit_case( void ) {
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 4UL;

  /* Shred limit: a 3 shred block under a limit of 3 fits across two FEC
     sets, and a sibling block gets its own shred slice. */
  {
    ulong footprint = fd_sched_footprint( depth, block_cnt_max, 3UL, FD_MAX_TXN_PER_SLOT, 0 );
    void * mem = aligned_alloc( fd_sched_align(), footprint );
    FD_TEST( mem );
    fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, 3UL, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, 0, 0 ) );
    FD_TEST( sched );
    fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = 2UL,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT+1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .shred_cnt         = 2U,
      .is_first_in_block = 1U
    }};
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    FD_TEST( fd_sched_get_shred_cnt( sched, 2UL )==2U );

    fec->is_first_in_block = 0U;
    fec->shred_cnt         = 1U;
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    FD_TEST( fd_sched_get_shred_cnt( sched, 2UL )==3U );

    fec->bank_idx          = 3UL;
    fec->shred_cnt         = 3U;
    fec->is_first_in_block = 1U;
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
    FD_TEST( fd_sched_get_shred_cnt( sched, 3UL )==3U );

    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
  }

  /* Transaction limit: a microblock header declaring more transactions
     than the limit allows rules the block invalid at ingest. */
  {
    ulong footprint = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, 1UL, 0 );
    void * mem = aligned_alloc( fd_sched_align(), footprint );
    FD_TEST( mem );
    fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, 1UL, TEST_EXEC_CNT, 0, 0 ) );
    FD_TEST( sched );
    fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

    uchar encoded[ sizeof(ulong)+sizeof(fd_microblock_hdr_t) ] = {0};
    FD_STORE( ulong, encoded, 1UL );
    fd_microblock_hdr_t hdr = { .hash_cnt = 1UL, .txn_cnt = 2UL };
    fd_memcpy( encoded+sizeof(ulong), &hdr, sizeof(hdr) );

    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    FD_TEST( sizeof(encoded)<=USHORT_MAX );
    store_fec->data_sz       = (uint)sizeof(encoded);
    store_fec->shred_sz[ 0 ] = (ushort)sizeof(encoded);
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = 2UL,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT+1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .data              = encoded,
      .shred_cnt         = 1U,
      .is_first_in_block = 1U
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( !fd_sched_fec_ingest( sched, fec ) );
    FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_TOO_MANY_TXNS );

    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
  }

  /* Microblock limit scales with the shred limit: under 2x shreds a
     batch declaring more microblocks than the 1x limit is accepted,
     one declaring more than the 2x limit rules the block invalid. */
  for( ulong mblk_cnt=FD_SCHED_MAX_MBLK_PER_SLOT+1UL; mblk_cnt<=2UL*FD_SCHED_MAX_MBLK_PER_SLOT+1UL; mblk_cnt+=FD_SCHED_MAX_MBLK_PER_SLOT ) {
    ulong footprint = fd_sched_footprint( depth, block_cnt_max, 2UL*FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 0 );
    void * mem = aligned_alloc( fd_sched_align(), footprint );
    FD_TEST( mem );
    fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, 2UL*FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT, 0, 0 ) );
    FD_TEST( sched );
    fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

    uchar encoded[ sizeof(ulong) ] = {0};
    FD_STORE( ulong, encoded, mblk_cnt );

    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    FD_TEST( sizeof(encoded)<=USHORT_MAX );
    store_fec->data_sz       = (uint)sizeof(encoded);
    store_fec->shred_sz[ 0 ] = (ushort)sizeof(encoded);
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = 2UL,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT+1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .data              = encoded,
      .shred_cnt         = 1U,
      .is_first_in_block = 1U
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    int too_many = mblk_cnt>2UL*FD_SCHED_MAX_MBLK_PER_SLOT;
    FD_TEST( (!fd_sched_fec_ingest( sched, fec ))==too_many );
    FD_TEST( (fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_TOO_MANY_MICROBLOCKS)==too_many );

    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
  }
}

/* Out-of-band LtHash.  The exec tiles' hash values are synthetic: a
   value is derived from the account, the task kind and a version.  A
   subtraction's version is 0, the parent's value.  An addition's
   version is the number of writes to the account completed so far in
   the block, so an addition applied before the account's last write
   leaves a trace in the delta unless it is undone, and a test knows
   the exact delta a block must end with. */

#define TEST_LTHASH_ACCT_MAX (8UL)
#define TEST_LTHASH_BANK_MAX (8UL)

static void
fake_hash( fd_lthash_value_t *    out,
           fd_acct_addr_t const * acct,
           int                    is_add,
           ulong                  version ) {
  ulong seed = FD_LOAD( ulong, acct->b ) ^ fd_ulong_if( is_add, 0x5a5a5a5a5a5a5a5aUL, 0UL ) ^ (version*0x9e3779b97f4a7c15UL);
  for( ulong i=0UL; i<FD_LTHASH_LEN_BYTES/sizeof(ulong); i++ ) {
    seed = fd_ulong_hash( seed ^ i );
    FD_STORE( ulong, out->bytes+i*sizeof(ulong), seed );
  }
}

struct test_lthash_acct {
  fd_acct_addr_t acct;
  ulong          sub_cnt  [ TEST_LTHASH_BANK_MAX ]; /* subtractions handed out for the account, per bank */
  ulong          add_cnt  [ TEST_LTHASH_BANK_MAX ]; /* additions handed out, per bank */
  ulong          write_cnt[ TEST_LTHASH_BANK_MAX ]; /* writes completed so far, per bank: the version of its next addition */
};
typedef struct test_lthash_acct test_lthash_acct_t;

struct test_lthash_ctx {
  test_lthash_acct_t     acct[ TEST_LTHASH_ACCT_MAX ];
  ulong                  acct_cnt;
  fd_lthash_value_t      handed[ 1 ];     /* every ADD value handed to sched minus every SUB value */
  fd_lthash_value_t      delta[ 1 ];      /* fd_sched_lthash_delta read when BLOCK_END was handed out */
  int                    delta_seen;
  ulong                  step;
  ulong                  last_lthash_step[ TEST_LTHASH_BANK_MAX ]; /* step of the bank's last LtHash completion */
  ulong                  block_end_step  [ TEST_LTHASH_BANK_MAX ]; /* step BLOCK_END was handed out for the bank */
  ulong                  sub_cnt;
  ulong                  add_cnt;
  ulong                  txn_exec_cnt;
  ulong                  block_end_cnt;
  fd_acct_addr_t const * late_alts;       /* writable lookup table accounts handed back, as the exec tile would,
                                             with every lookup table transaction */
  ulong                  late_alt_cnt;
};
typedef struct test_lthash_ctx test_lthash_ctx_t;

static test_lthash_acct_t *
lthash_acct( test_lthash_ctx_t *    ctx,
             fd_acct_addr_t const * acct ) {
  for( ulong i=0UL; i<ctx->acct_cnt; i++ ) {
    if( !memcmp( ctx->acct[ i ].acct.b, acct->b, sizeof(fd_acct_addr_t) ) ) return ctx->acct+i;
  }
  FD_TEST( ctx->acct_cnt<TEST_LTHASH_ACCT_MAX );
  test_lthash_acct_t * a = ctx->acct+ctx->acct_cnt++;
  fd_memset( a, 0, sizeof(test_lthash_acct_t) );
  a->acct = *acct;
  return a;
}

/* Records a write to acct in bank_idx: the account's next addition
   hashes a later version. */
static void
lthash_write( test_lthash_ctx_t *    ctx,
              ulong                  bank_idx,
              fd_acct_addr_t const * acct ) {
  FD_TEST( bank_idx<TEST_LTHASH_BANK_MAX );
  lthash_acct( ctx, acct )->write_cnt[ bank_idx ]++;
}

/* The value a tile would return for an LtHash task handed out now: the
   parent's version for a subtraction, the account's current version
   in the bank for an addition. */
static void
lthash_task_value( test_lthash_ctx_t *     ctx,
                   fd_sched_task_t const * task,
                   fd_lthash_value_t *     v ) {
  int   is_add   = task->task_type==FD_SCHED_TT_LTHASH_ADD;
  ulong bank_idx = task->lthash->bank_idx;
  FD_TEST( bank_idx<TEST_LTHASH_BANK_MAX );
  test_lthash_acct_t * a = lthash_acct( ctx, &task->lthash->acct );
  fake_hash( v, &task->lthash->acct, is_add, is_add ? a->write_cnt[ bank_idx ] : 0UL );
}

/* Completes an LtHash task with value v and records what was handed. */
static void
lthash_complete( fd_sched_t *            sched,
                 fd_sched_task_t const * task,
                 test_lthash_ctx_t *     ctx,
                 fd_lthash_value_t *     v ) {
  int   is_add   = task->task_type==FD_SCHED_TT_LTHASH_ADD;
  ulong bank_idx = task->lthash->bank_idx;
  FD_TEST( bank_idx<TEST_LTHASH_BANK_MAX );
  test_lthash_acct_t * a = lthash_acct( ctx, &task->lthash->acct );
  if( is_add ) { a->add_cnt[ bank_idx ]++; ctx->add_cnt++; fd_lthash_add( ctx->handed, v ); }
  else         { a->sub_cnt[ bank_idx ]++; ctx->sub_cnt++; fd_lthash_sub( ctx->handed, v ); }
  ctx->last_lthash_step[ bank_idx ] = ++ctx->step;
  FD_TEST( 0==fd_sched_task_done( sched, task->task_type, is_add ? task->lthash->ptxn_idx : ULONG_MAX, task->lthash->exec_idx, v ) );
}

/* Completes a transaction the way the replay tile would: its writable
   static accounts count as written, and a lookup table transaction
   also writes ctx->late_alts, which it hands back as done data. */
static void
lthash_complete_txn( fd_sched_t *            sched,
                     fd_sched_task_t const * task,
                     test_lthash_ctx_t *     ctx ) {
  ulong bank_idx = task->txn_exec->bank_idx;
  ulong txn_idx  = task->txn_exec->txn_idx;
  fd_txn_p_t * txn_p = fd_sched_get_txn( sched, txn_idx );
  FD_TEST( txn_p );
  fd_txn_t const *       txn   = TXN( txn_p );
  fd_acct_addr_t const * addrs = fd_txn_get_acct_addrs( txn, txn_p->payload );
  for( ushort i=0; i<txn->acct_addr_cnt; i++ ) {
    if( fd_txn_is_writable( txn, i ) ) lthash_write( ctx, bank_idx, addrs+i );
  }
  fd_sched_txn_alts_t alts[ 1 ] = {{ .cnt = ctx->late_alt_cnt, .addrs = ctx->late_alts }};
  void * data = NULL;
  if( txn->addr_table_lookup_cnt ) {
    for( ulong i=0UL; i<alts->cnt; i++ ) lthash_write( ctx, bank_idx, alts->addrs+i );
    data = alts;
  }
  ctx->txn_exec_cnt++;
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC, txn_idx, task->txn_exec->exec_idx, data ) );
}

/* Completes one task the way the replay tile would, with synthetic
   results, and records what was handed out. */
static void
lthash_drive_task( fd_sched_t *        sched,
                   fd_sched_task_t *   task,
                   test_lthash_ctx_t * ctx ) {
  switch( task->task_type ) {
    case FD_SCHED_TT_BLOCK_START:
      ctx->step++;
      FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
      break;
    case FD_SCHED_TT_BLOCK_END: {
      /* The delta is read before BLOCK_END is completed, as the replay
         tile does, because completion frees it. */
      ulong bank_idx = task->block_end->bank_idx;
      FD_TEST( bank_idx<TEST_LTHASH_BANK_MAX );
      fd_lthash_value_t const * delta = fd_sched_lthash_delta( sched, bank_idx );
      if( delta ) {
        fd_memcpy( ctx->delta, delta, sizeof(fd_lthash_value_t) );
        ctx->delta_seen = 1;
      }
      ctx->block_end_step[ bank_idx ] = ++ctx->step;
      ctx->block_end_cnt++;
      FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
      break;
    }
    case FD_SCHED_TT_TXN_EXEC:
      ctx->step++;
      lthash_complete_txn( sched, task, ctx );
      break;
    case FD_SCHED_TT_TXN_SIGVERIFY:
      ctx->step++;
      FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_SIGVERIFY, task->txn_sigverify->txn_idx, task->txn_sigverify->exec_idx, NULL ) );
      break;
    case FD_SCHED_TT_POH_HASH: {
      ctx->step++;
      fd_execrp_poh_hash_done_msg_t msg[ 1 ];
      msg->cnt = task->poh_hash->cnt;
      for( ulong i=0UL; i<task->poh_hash->cnt; i++ ) {
        repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
      }
      FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) );
      break;
    }
    case FD_SCHED_TT_LTHASH_SUB:
    case FD_SCHED_TT_LTHASH_ADD: {
      fd_lthash_value_t v[ 1 ];
      lthash_task_value( ctx, task, v );
      lthash_complete( sched, task, ctx, v );
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected task type %lu", task->task_type ));
  }
}

/* Hands out and completes tasks until the scheduler has nothing more. */
static void
lthash_drive( fd_sched_t *        sched,
              test_lthash_ctx_t * ctx,
              ulong               max_steps ) {
  for( ulong i=0UL; i<max_steps; i++ ) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_task_t task[ 1 ];
    if( !fd_sched_task_next_ready( sched, task ) ) break;
    lthash_drive_task( sched, task, ctx );
  }
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
}

/* Like lthash_drive, but the first task of hold_type is not completed:
   it stays on its tile, is copied to held along with the value its
   tile would return (computed now, since the account's version may
   move on while it is held), and the drive stops.  Returns 1 if a
   task was held. */
static int
lthash_drive_hold( fd_sched_t *        sched,
                   test_lthash_ctx_t * ctx,
                   ulong               max_steps,
                   ulong               hold_type,
                   fd_sched_task_t *   held,
                   fd_lthash_value_t * held_value ) {
  for( ulong i=0UL; i<max_steps; i++ ) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_task_t task[ 1 ];
    if( !fd_sched_task_next_ready( sched, task ) ) break;
    if( task->task_type==hold_type ) {
      *held = *task;
      if( hold_type==FD_SCHED_TT_LTHASH_SUB || hold_type==FD_SCHED_TT_LTHASH_ADD ) lthash_task_value( ctx, task, held_value );
      return 1;
    }
    lthash_drive_task( sched, task, ctx );
  }
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  return 0;
}

/* Legacy transaction with payer as the writable signer, writable_cnt
   writable non-signers and a read-only program, so a test chooses the
   accounts whose LtHash a block owes. */
static ulong
build_lthash_test_txn( uchar *             payload,
                       fd_pubkey_t const * payer,
                       fd_pubkey_t const * writables,
                       ulong               writable_cnt,
                       uchar               sig_tag ) {
  fd_pubkey_t program[ 1 ];
  fd_memset( program->uc, 0x22, sizeof(fd_pubkey_t) );

  fd_txn_accounts_t accounts = {
    .signature_cnt         = 1U,
    .readonly_signed_cnt   = 0U,
    .readonly_unsigned_cnt = 1U,
    .acct_cnt              = (ushort)(2UL+writable_cnt),
    .signers_w             = payer,
    .signers_r             = NULL,
    .non_signers_w         = writables,
    .non_signers_r         = program,
  };

  uchar meta[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_memset( meta, 0, sizeof(meta) );
  fd_txn_base_generate( meta, payload, 1UL, &accounts, NULL );

  uchar instr_acct = 0U;
  uchar instr_data = 0x5aU;
  ulong sz = fd_txn_add_instr( meta, payload, (uchar)(1UL+writable_cnt), &instr_acct, 1UL, &instr_data, 1UL );
  payload[ 1 ] = sig_tag; /* distinct signatures */
  return sz;
}

/* Version 0 transaction with payer as the writable signer, a read-only
   program and one address lookup table naming alt_writable_cnt
   writable accounts.  The table is never resolved in these tests
   (lookup table resolution is bypassed), so the scheduler inserts the
   transaction serializing and flags it FD_SCHED_TXN_ALT_UNRESOLVED. */
static ulong
build_lthash_v0_txn( uchar *             payload,
                     fd_pubkey_t const * payer,
                     ulong               alt_writable_cnt,
                     uchar               sig_tag ) {
  ulong i = 0UL;
  payload[ i++ ] = 1;                                          /* signature count */
  fd_memset( payload+i, 0, FD_TXN_SIGNATURE_SZ );
  payload[ i+1UL ] = sig_tag;                                  /* distinct signatures */
  i += FD_TXN_SIGNATURE_SZ;
  payload[ i++ ] = 0x80;                                       /* version 0 */
  payload[ i++ ] = 1;                                          /* required signatures */
  payload[ i++ ] = 0;                                          /* read-only signed */
  payload[ i++ ] = 1;                                          /* read-only unsigned */
  payload[ i++ ] = 2;                                          /* static accounts */
  fd_memcpy( payload+i, payer->uc, sizeof(fd_pubkey_t) ); i += sizeof(fd_pubkey_t);
  fd_memset( payload+i, 0x22, sizeof(fd_pubkey_t) );      i += sizeof(fd_pubkey_t); /* program */
  fd_memset( payload+i, 0x33, FD_TXN_BLOCKHASH_SZ );      i += FD_TXN_BLOCKHASH_SZ; /* recent blockhash */
  payload[ i++ ] = 1;                                          /* instruction count */
  payload[ i++ ] = 1;                                          /*   program index */
  payload[ i++ ] = 1;                                          /*   account count */
  payload[ i++ ] = 2;                                          /*   the first lookup table account */
  payload[ i++ ] = 1;                                          /*   data length */
  payload[ i++ ] = 0x5a;
  payload[ i++ ] = 1;                                          /* lookup table count */
  fd_memset( payload+i, 0x44, sizeof(fd_pubkey_t) );      i += sizeof(fd_pubkey_t); /* table address */
  payload[ i++ ] = (uchar)alt_writable_cnt;                    /*   writable indices */
  for( ulong j=0UL; j<alt_writable_cnt; j++ ) payload[ i++ ] = (uchar)j;
  payload[ i++ ] = 0;                                          /*   read-only indices */
  return i;
}

/* One entry batch: a microblock holding the transactions if there are
   any, then a tick if with_tick.  Every microblock advances one hash.
   The entry hash is arbitrary (the tests bypass its verification) but
   the tick's is verified, so it is derived from the entry's claimed
   hash, which every batch of a block shares. */
static ulong
encode_lthash_batch( uchar *               encoded,
                     uchar const * const * txn,
                     ulong const *         txn_sz,
                     ulong                 txn_cnt,
                     int                   with_tick ) {
  fd_hash_t h[ 1 ];
  fd_hash_t tick_h[ 1 ];
  hash_from_seed( h, 0x7c1d2e3f4a5b6c7dUL );
  repeat_hash( tick_h, h, 1UL );

  ulong cursor = 0UL;
  FD_STORE( ulong, encoded+cursor, (ulong)(txn_cnt>0UL)+(ulong)!!with_tick );
  cursor += sizeof(ulong);

  if( txn_cnt ) {
    fd_microblock_hdr_t tx_hdr = { .hash_cnt = 1UL, .txn_cnt = txn_cnt };
    fd_memcpy( tx_hdr.hash, h->hash, sizeof(fd_hash_t) );
    fd_memcpy( encoded+cursor, &tx_hdr, sizeof(tx_hdr) );
    cursor += sizeof(tx_hdr);
    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_memcpy( encoded+cursor, txn[ i ], txn_sz[ i ] );
      cursor += txn_sz[ i ];
    }
  }

  if( with_tick ) {
    fd_microblock_hdr_t tick_hdr = { .hash_cnt = 1UL, .txn_cnt = 0UL };
    fd_memcpy( tick_hdr.hash, tick_h->hash, sizeof(fd_hash_t) );
    fd_memcpy( encoded+cursor, &tick_hdr, sizeof(tick_hdr) );
    cursor += sizeof(tick_hdr);
  }
  return cursor;
}

/* Ingests one FEC set that ends a batch. */
static void
ingest_lthash_fec( fd_sched_t * sched,
                   ulong        bank_idx,
                   ulong        parent_bank_idx,
                   ulong        slot,
                   ulong        parent_slot,
                   uchar *      data,
                   ulong        sz,
                   int          first,
                   int          last ) {
  fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
  FD_TEST( sz<=USHORT_MAX );
  store_fec->data_sz       = (uint)sz;
  store_fec->shred_sz[ 0 ] = (ushort)sz;

  fd_sched_fec_t fec[ 1 ] = {{
    .bank_idx          = bank_idx,
    .parent_bank_idx   = parent_bank_idx,
    .slot              = slot,
    .parent_slot       = parent_slot,
    .fec               = store_fec,
    .data              = data,
    .shred_cnt         = 1U,
    .is_last_in_batch  = 1U,
    .is_last_in_block  = last  ? 1U : 0U,
    .is_first_in_block = first ? 1U : 0U,
  }};
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );
}

static void
lthash_test_keys( fd_pubkey_t * acct_a,
                  fd_pubkey_t * acct_b ) {
  fd_memset( acct_a->uc, 0xa1, sizeof(fd_pubkey_t) );
  fd_memset( acct_b->uc, 0xb2, sizeof(fd_pubkey_t) );
}

/* The expected delta of a bank that wrote the given accounts: each
   account's final version minus the parent's. */
static void
lthash_expected_delta( fd_lthash_value_t *  out,
                       test_lthash_ctx_t *  ctx,
                       ulong                bank_idx,
                       fd_pubkey_t const *  acct,
                       ulong                acct_cnt ) {
  fd_lthash_zero( out );
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    fd_acct_addr_t const * a = fd_type_pun_const( acct+i );
    fd_lthash_value_t v[ 1 ];
    fake_hash( v, a, 1, lthash_acct( ctx, a )->write_cnt[ bank_idx ] ); fd_lthash_add( out, v );
    fake_hash( v, a, 0, 0UL );                                           fd_lthash_sub( out, v );
  }
}

/* The LtHash tasks handed out for acct in bank_idx. */
static void
lthash_check_acct( test_lthash_ctx_t * ctx,
                   ulong               bank_idx,
                   fd_pubkey_t const * acct,
                   ulong               sub_cnt,
                   ulong               add_cnt,
                   ulong               write_cnt ) {
  test_lthash_acct_t * a = lthash_acct( ctx, fd_type_pun_const( acct ) );
  FD_TEST( a->sub_cnt[ bank_idx ]==sub_cnt && a->add_cnt[ bank_idx ]==add_cnt && a->write_cnt[ bank_idx ]==write_cnt );
}

/* With lthash_oob set, one staged block with T1 writing A and T2
   writing A and B gets exactly one subtraction and one addition per
   distinct account, the delta equals the handed values, and BLOCK_END
   comes after the last LtHash task.  With it clear, the same block
   produces no LtHash task at all. */
static void
run_lthash_basic_case( int lthash_oob ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, lthash_oob );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL,   0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, acct+1, 1UL, 0x02 );
  uchar const * txns[ 2 ] = { t1, t2 };
  ulong txn_sz[ 2 ] = { t1_sz, t2_sz };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 2UL, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x6d2f1a8b3c4e5f60UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 2UL, start_poh );

  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  lthash_drive( sched, ctx, 1000UL );

  FD_TEST( fd_sched_is_drained( sched ) );
  FD_TEST( ctx->txn_exec_cnt==2UL );
  FD_TEST( ctx->block_end_cnt==1UL );
  if( lthash_oob ) {
    FD_TEST( ctx->acct_cnt==2UL && ctx->sub_cnt==2UL && ctx->add_cnt==2UL ); /* no account other than A and B */
    lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 2UL );
    lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
    FD_TEST( ctx->delta_seen );
    FD_TEST( !fd_lthash_is_zero( ctx->delta ) );
    FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
    fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
    FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
    FD_TEST( ctx->last_lthash_step[ 2 ] && ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
    char * state = fd_sched_get_state_cstr( sched );
    FD_TEST( strstr( state, "lthash_sub_cnt 2, lthash_add_cnt 2, lthash_spec_cnt 0," ) );
    FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  } else {
    FD_TEST( ctx->acct_cnt==2UL && !ctx->sub_cnt && !ctx->add_cnt ); /* A and B were written, nothing was hashed */
    FD_TEST( !ctx->delta_seen );
    FD_TEST( !fd_sched_lthash_delta( sched, 2UL ) );
  }

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* A subtraction and an addition are on the tiles when the block is
   abandoned.  Their results come back without effect, the tiles are
   freed, and the block is released once the last one lands, whichever
   kind that is. */
static void
run_lthash_abandon_in_flight_case( int last_is_add ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL, 0UL, 0x01 );
  uchar const * txns[ 1 ] = { t1 };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, &t1_sz, 1UL, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x0b1c2d3e4f506172UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 2UL, start_poh );

  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  lthash_drive_task( sched, task, ctx );

  /* Hold T1 and the subtraction of A on their tiles; complete the PoH
     and sigverify tasks as they come.  The addition of A is pending
     behind T1 and cannot surface yet. */
  fd_sched_task_t pending[ 2 ];
  ulong pending_cnt = 0UL;
  for(;;) {
    if( !fd_sched_task_next_ready( sched, task ) ) break;
    if( task->task_type==FD_SCHED_TT_POH_HASH || task->task_type==FD_SCHED_TT_TXN_SIGVERIFY ) {
      lthash_drive_task( sched, task, ctx );
      continue;
    }
    FD_TEST( task->task_type==FD_SCHED_TT_TXN_EXEC || task->task_type==FD_SCHED_TT_LTHASH_SUB );
    FD_TEST( pending_cnt<2UL );
    pending[ pending_cnt++ ] = *task;
  }
  FD_TEST( pending_cnt==2UL );
  ulong exec_at = fd_ulong_if( pending[ 0 ].task_type==FD_SCHED_TT_TXN_EXEC, 0UL, 1UL );
  ulong sub_at  = 1UL-exec_at;
  FD_TEST( pending[ exec_at ].task_type==FD_SCHED_TT_TXN_EXEC && pending[ sub_at ].task_type==FD_SCHED_TT_LTHASH_SUB );
  FD_TEST( !memcmp( pending[ sub_at ].lthash->acct.b, acct[ 0 ].uc, sizeof(fd_acct_addr_t) ) );

  /* Completing T1 readies the addition, which takes a free tile.  With
     both hashes out, nothing else can be handed out: BLOCK_END waits
     on them. */
  lthash_drive_task( sched, pending+exec_at, ctx );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD );
  FD_TEST( !memcmp( task->lthash->acct.b, acct[ 0 ].uc, sizeof(fd_acct_addr_t) ) );
  FD_TEST( task->lthash->ptxn_idx & FD_RDISP_LTHASH_PSEUDO_TXN );
  pending[ exec_at ] = *task;
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );

  fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_INVALID );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX ); /* still in flight */

  /* Land the subtraction and the addition in the requested order.
     Each completion is accepted. */
  ulong add_at = exec_at;
  lthash_drive_task( sched, pending+fd_ulong_if( last_is_add, sub_at, add_at ), ctx );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  lthash_drive_task( sched, pending+fd_ulong_if( last_is_add, add_at, sub_at ), ctx );

  /* The last result released the block and every tile is idle again. */
  FD_TEST( fd_sched_pruned_block_next( sched )==2UL );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  FD_TEST( fd_sched_is_drained( sched ) );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( ctx->sub_cnt==1UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "block_abandoned_cnt 1," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* A partial head block subtracts A early and speculates its addition,
   is demoted when every lane is squatted and an unstaged block needs
   one, and is promoted back when its last FEC set arrives.  Demotion
   rolls its LtHash progress back, so after promotion it re-derives: A
   is subtracted again, but the delta holds exactly one subtraction and
   one addition per account, at the final version. */
static void
run_lthash_demote_promote_case( void ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL,   0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, acct+1, 1UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL, 0 );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x91b53d8a74f2c601UL );
  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );

  /* Block 2 takes lane 0 with T1: BLOCK_START, T1, PoH, sigverify, the
     early subtraction of A, then, alone in its lane with nothing left
     to do, a speculative addition of A before it runs dry. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 3UL, start_poh );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 1UL );
  FD_TEST( fd_sched_is_drained( sched ) );

  /* Blocks 3-5 squat the other lanes. */
  for( ulong bank_idx=3UL; bank_idx<=5UL; bank_idx++ ) {
    FD_TEST( add_live_block( sched, bank_idx, 1UL, TEST_ROOT_SLOT+bank_idx-1UL, TEST_ROOT_SLOT ) );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 1UL, start_poh );
    lthash_drive( sched, ctx, 100UL );
  }
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "staged_bitset 15," ) );

  /* Block 6 finds no lane, so every demotable lane is demoted, block 2
     among them, and block 6 is promoted. */
  FD_TEST( add_live_block( sched, 6UL, 1UL, TEST_ROOT_SLOT+5UL, TEST_ROOT_SLOT ) );
  fd_sched_set_poh_params( sched, 6UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 1UL, start_poh );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 6, staged_bitset 1," ) );
  FD_TEST( strstr( state, "block_demoted_cnt 4," ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && ctx->add_cnt==1UL );

  /* Block 2's last FEC set, with T2 writing A and B, promotes it back
     into a free lane.  It drains, re-subtracts A, subtracts B, adds
     both and ends. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 3," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 2," ) );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==2UL && ctx->sub_cnt==3UL && ctx->add_cnt==3UL );
  lthash_check_acct( ctx, 2UL, acct,   2UL, 2UL, 2UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  FD_TEST( ctx->delta_seen );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  /* The rolled back subtraction and speculative addition of A were
     handed out but are not in the delta. */
  FD_TEST( !fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_spec_cnt 1, lthash_undo_cnt 0, lthash_drop_cnt 0," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* Writes the dispatcher did not see through a transaction: start-of-
   block processing reports them with fd_sched_block_start_writes while
   BLOCK_START is outstanding.  A is also written by T1; S by nothing
   else.  Mode 0: the block is still receiving FEC sets, so A is in the
   lane set (nothing to do) and S enters it; both are speculated once
   the subtractions are done, and the tick that ends the block finds
   nothing left to drain.  Mode 1: the block drained before
   BLOCK_START, so A had been popped: its addition goes stale and a
   re-drain pops A and S again.  Mode 2: a child with T3 writing A is
   staged behind the block, which is therefore not insert-ready, and
   the additions come from fd_rdisp_add_extra_pseudo_txn: a replacement
   for A, whose last reference is the child's T3, and an immediately
   READY one for S.  Mode 3: like mode 2 but the child's T3 writes D,
   so A's last reference is still the block's own drained
   pseudo-transaction, which the dispatcher hands back and the
   registration keeps.  Mode 4: S enters the set at registration and
   the block's last FEC set, with T2 writing S, arrives before any
   transaction is dispatched; S's one addition comes after T2.  Every
   mode ends with exactly one subtraction and one addition per account
   of the block; in modes 2 and 3 the child then speculates its own
   payer. */
static void
run_lthash_block_start_writes_case( int mode ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 3 ]; /* A, S, D */
  lthash_test_keys( acct, acct+1 );
  fd_memset( acct[ 2 ].uc, 0xd4, sizeof(fd_pubkey_t) );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,   NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+1, NULL, 0UL, 0x02 );
  uchar const * txns[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded[ 8192 ];
  uchar encoded2[ 8192 ];
  uchar encoded_tick[ 8192 ];
  int   first_is_last = mode!=0 && mode!=4;
  ulong sz      = encode_lthash_batch( encoded,      txns,  &t1_sz, 1UL, first_is_last );
  ulong sz2     = encode_lthash_batch( encoded2,     txns2, &t2_sz, 1UL, 1             );
  ulong tick_sz = encode_lthash_batch( encoded_tick, NULL,  NULL,   0UL, 1             );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x3a4b5c6d7e8f9011UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, first_is_last );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, fd_ulong_if( mode==4, 3UL, 2UL ), start_poh );

  int child = mode==2 || mode==3;
  fd_pubkey_t const * child_payer = acct+fd_ulong_if( mode==2, 0UL, 2UL );
  if( child ) {
    uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, child_payer, NULL, 0UL, 0x03 );
    uchar const * txns3[ 1 ] = { t3 };
    uchar encoded3[ 8192 ]; ulong sz3 = encode_lthash_batch( encoded3, txns3, &t3_sz, 1UL, 0 );
    ingest_lthash_fec( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL, encoded3, sz3, 1, 0 );
    fd_sched_set_poh_params( sched, 3UL, TEST_ROOT_TICK_HEIGHT+1UL, TEST_ROOT_TICK_HEIGHT+2UL, 2UL, start_poh );
    char * state = fd_sched_get_state_cstr( sched );
    FD_TEST( strstr( state, "active_idx 2, staged_bitset 1," ) );
  }

  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==2UL );
  fd_sched_block_start_writes( sched, 2UL, fd_type_pun_const( acct ), 2UL );
  lthash_write( ctx, 2UL, fd_type_pun_const( acct   ) );
  lthash_write( ctx, 2UL, fd_type_pun_const( acct+1 ) );
  lthash_drive_task( sched, task, ctx );
  if( mode==4 ) {
    /* The last FEC set arrives after start-of-block processing and
       before any transaction is dispatched: T2 writes S, which the
       registration already put in the lane set, so its parse reports
       no first-writer bit for S. */
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  }
  lthash_drive( sched, ctx, 100UL );

  if( mode==0 ) {
    /* Both subtractions ran, then both additions were speculated, then
       the block ran dry waiting for its last FEC set.  The tick ends
       it. */
    FD_TEST( !ctx->block_end_cnt && ctx->add_cnt==2UL && ctx->sub_cnt==2UL );
    FD_TEST( fd_sched_is_drained( sched ) );
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded_tick, tick_sz, 0, 1 );
    lthash_drive( sched, ctx, 100UL );
  }

  FD_TEST( ctx->txn_exec_cnt==fd_ulong_if( child || mode==4, 2UL, 1UL ) ); /* the child's T3 runs after the block ends */
  FD_TEST( ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==fd_ulong_if( mode==3, 3UL, 2UL ) );
  FD_TEST( ctx->sub_cnt==fd_ulong_if( child, 3UL, 2UL ) && ctx->add_cnt==fd_ulong_if( child, 3UL, 2UL ) );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 2UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, fd_ulong_if( mode==4, 2UL, 1UL ) ); /* in mode 4, S's one addition comes after T2 */
  if( child ) lthash_check_acct( ctx, 3UL, child_payer, 1UL, 1UL, 1UL ); /* speculated by the child once it is alone in the lane */
  FD_TEST( ctx->delta_seen );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  if( !child ) FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_start_reg_cnt 2," ) );
  /* In modes 1 and 2 the addition A got at the drain was stale by the
     time it surfaced; in mode 3 it was kept. */
  FD_TEST( strstr( state, mode==1||mode==2 ? "lthash_drop_cnt 1,"  : "lthash_drop_cnt 0,"  ) );
  FD_TEST( strstr( state, mode==2 ? "lthash_extra_cnt 2," : mode==3 ? "lthash_extra_cnt 1," : "lthash_extra_cnt 0," ) );
  FD_TEST( strstr( state, mode==0 ? "lthash_spec_cnt 2," : mode==1||mode==4 ? "lthash_spec_cnt 0," : "lthash_spec_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_undo_cnt 0," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* Re-speculation after a stop.  Three FEC sets.  FEC1 (not last): T1
   writes A; after T1 the block speculates A, the next pop finds the
   lane set empty, speculation stops and the block, with nothing in
   flight, is deactivated: next_ready returns 0 while the block stays
   the lane head, undrained.  FEC2 (not last): T2 writes B; its parse
   bit lifts the stop, and after T2 the block speculates B and stops
   again.  FEC3 (last): T3 writes A; the applied guess for A is undone
   and A is added again after T3, while B's guess stands.  The delta is
   exact over {A, B}; the handed values also hold the undone guess. */
static void
run_lthash_respeculate_case( void ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 2 ]; /* A, B */
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,   NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+1, NULL, 0UL, 0x02 );
  uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, acct,   NULL, 0UL, 0x03 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar const * txns3[ 1 ] = { t3 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL, 0 );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL, 0 );
  uchar encoded3[ 8192 ]; ulong sz3 = encode_lthash_batch( encoded3, txns3, &t3_sz, 1UL, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x7a8b9cadbecfd0e1UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 4UL, start_poh );

  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  lthash_drive( sched, ctx, 100UL );

  /* The guess for A was hashed, then the set ran dry: with nothing in
     flight the block was deactivated, still the lane head and not
     drained. */
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 1UL );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_is_drained( sched ) );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 18446744073709551615, staged_bitset 1, staged_head_idx[0] 2," ) );
  FD_TEST( strstr( state, "fec_eos 0," ) );
  FD_TEST( strstr( state, "lthash_drained 0, lthash_spec_stop 1," ) );
  FD_TEST( strstr( state, "lthash_spec_cnt 1, lthash_undo_cnt 0, lthash_drop_cnt 0," ) );

  /* FEC2 revives the block: T2 runs, B is speculated, and the block
     runs dry again. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 0 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->sub_cnt==2UL && ctx->add_cnt==2UL && !ctx->block_end_cnt );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_is_drained( sched ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_drained 0, lthash_spec_stop 1," ) );
  FD_TEST( strstr( state, "lthash_spec_cnt 2, lthash_undo_cnt 0, lthash_drop_cnt 0," ) );

  /* FEC3: T3 writes A again, so the guess for A is undone and A is
     added once more after T3; B's guess stands. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded3, sz3, 0, 1 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==3UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==2UL && ctx->sub_cnt==2UL && ctx->add_cnt==3UL );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 2UL, 2UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  FD_TEST( ctx->delta_seen );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  fd_lthash_value_t guess[ 1 ]; fake_hash( guess, fd_type_pun_const( acct ), 1, 1UL );
  fd_lthash_add( expected, guess );
  FD_TEST( !fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( fd_lthash_eq( ctx->handed, expected ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_sub_cnt 2, lthash_add_cnt 3, lthash_spec_cnt 2, lthash_undo_cnt 1, lthash_drop_cnt 0," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* A speculative addition that is PENDING behind its writer when the
   account is written again.  T1 writes A and is held on its tile; the
   block speculates A, but the guess waits on T1 and no addition is
   handed out.  FEC2, with T2 writing A, arrives before T1 completes:
   T2's parse bit clears the guess's ticket and frees its slot.  Once
   T1 completes the stale guess surfaces and is completed without
   hashing; A is added once, after T2, at the final version.  With
   fec2_last, FEC2 ends the block and the drain pops A again;
   otherwise the block speculates A again after T2, runs dry, and an
   empty last FEC set ends it. */
static void
run_lthash_pending_rewrite_case( int fec2_last ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, NULL, 0UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL, 0 );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL, fec2_last );
  uchar encoded3[ 8192 ]; ulong sz3 = encode_lthash_batch( encoded3, NULL,  NULL,   0UL, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x4c5d6e7f8091a2b3UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 3UL, start_poh );

  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t held[ 1 ]; fd_lthash_value_t unused[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, held, unused ) );
  /* PoH, sigverify and the subtraction run around T1.  The speculative
     pop happens, but the guess is PENDING behind T1. */
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && !ctx->txn_exec_cnt );
  FD_TEST( !fd_sched_is_drained( sched ) );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_spec_cnt 1, lthash_undo_cnt 0, lthash_drop_cnt 0," ) );
  FD_TEST( strstr( state, "add_created_cnt 1, add_surfaced_cnt 0, add_done_cnt 0" ) );

  /* T2 arrives while the guess is pending.  Its PoH and sigverify
     run; T2 itself waits on T1. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, fec2_last );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( !ctx->txn_exec_cnt && !ctx->add_cnt && !ctx->block_end_cnt );

  /* T1 completes: the stale guess surfaces and is completed without
     hashing, then T2 runs and A is added at version 2. */
  lthash_drive_task( sched, held, ctx );
  lthash_drive( sched, ctx, 100UL );
  if( !fec2_last ) {
    FD_TEST( ctx->txn_exec_cnt==2UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
    FD_TEST( fd_sched_is_drained( sched ) );
    state = fd_sched_get_state_cstr( sched );
    FD_TEST( strstr( state, "lthash_spec_cnt 2, lthash_undo_cnt 0, lthash_drop_cnt 1," ) );
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded3, sz3, 0, 1 );
    lthash_drive( sched, ctx, 100UL );
  }

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 2UL );
  FD_TEST( ctx->delta_seen );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) ); /* nothing was hashed in vain */
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, fec2_last ? "lthash_sub_cnt 1, lthash_add_cnt 1, lthash_spec_cnt 1, lthash_undo_cnt 0, lthash_drop_cnt 1,"
                                    : "lthash_sub_cnt 1, lthash_add_cnt 1, lthash_spec_cnt 2, lthash_undo_cnt 0, lthash_drop_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* Two lookup table transactions in one drained block.  S1 and S2 are
   version 0 transactions whose tables cannot be resolved at parse
   (resolution is bypassed), so both are inserted serializing, and both
   hand back X as a writable lookup table account on completion.  S1's
   registration queues X's subtraction and drains an addition, which
   the serializing S2 walls off; S2's registration makes that addition
   stale and drains another.  X ends with exactly one subtraction and
   one hashed addition, after S2, at the final version; P1 and P2 are
   the payers. */
static void
run_lthash_two_late_alt_case( void ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_set_bypass_alut_resolution( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 3 ]; /* P1, P2, X */
  fd_memset( acct[ 0 ].uc, 0xc3, sizeof(fd_pubkey_t) );
  fd_memset( acct[ 1 ].uc, 0xc4, sizeof(fd_pubkey_t) );
  fd_memset( acct[ 2 ].uc, 0xd4, sizeof(fd_pubkey_t) );
  fd_acct_addr_t late[ 1 ]; /* X */
  fd_memcpy( late[ 0 ].b, acct[ 2 ].uc, sizeof(fd_acct_addr_t) );
  uchar s1[ FD_TXN_MTU ]; ulong s1_sz = build_lthash_v0_txn( s1, acct,   1UL, 0x01 );
  uchar s2[ FD_TXN_MTU ]; ulong s2_sz = build_lthash_v0_txn( s2, acct+1, 1UL, 0x02 );
  uchar const * txns[ 2 ] = { s1, s2 };
  ulong txn_sz[ 2 ] = { s1_sz, s2_sz };
  uchar encoded[ 8192 ]; ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 2UL, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x6e7f8091a2b3c4d5UL );
  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  ctx->late_alts    = late;
  ctx->late_alt_cnt = 1UL;
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 2UL, start_poh );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==3UL && ctx->sub_cnt==3UL && ctx->add_cnt==3UL );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 2UL, acct+2, 1UL, 1UL, 2UL );
  FD_TEST( ctx->delta_seen );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 3UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "alut_serializing_cnt 2," ) );
  FD_TEST( strstr( state, "lthash_late_reg_cnt 2," ) );
  FD_TEST( strstr( state, "lthash_spec_cnt 0, lthash_undo_cnt 0, lthash_drop_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* Speculation.  Block 2's first FEC set has T1 writing A and is not
   the last.  Once T1, PoH, sigverify and the subtraction of A are done
   nothing is in flight, yet the block, alone in its lane and still
   receiving FEC sets, stays active and guesses that A's last write has
   happened: an addition of A at version 1 is handed out and applied,
   and only then does the block run dry.  The second FEC set, with T2
   writing A, proves the guess wrong: the addition is undone through
   its hash slot and A is added again after T2.  The delta is exactly
   -sub(A)+add(A,2); the handed values also hold add(A,1).  With
   hold_writer, T1 is still on its tile when the block speculates: the
   pseudo-transaction is created but not READY, speculation pauses, and
   the addition surfaces once T1 completes. */
static void
run_lthash_speculate_case( int hold_writer ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, NULL, 0UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL, 0 );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x5e6f708192a3b4c5UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 3UL, start_poh );

  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  if( hold_writer ) {
    fd_sched_task_t held[ 1 ]; fd_lthash_value_t unused[ 1 ];
    FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, held, unused ) );
    /* PoH, sigverify and the subtraction run around T1.  The
       speculative pop happens too, but its addition waits on T1. */
    lthash_drive( sched, ctx, 100UL );
    FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && !ctx->txn_exec_cnt );
    char * state = fd_sched_get_state_cstr( sched );
    FD_TEST( strstr( state, "lthash_spec_cnt 1," ) );
    FD_TEST( !fd_sched_is_drained( sched ) );
    lthash_drive_task( sched, held, ctx );
  }
  lthash_drive( sched, ctx, 100UL );

  /* The guess was hashed before the block ran dry. */
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 1UL );
  FD_TEST( fd_sched_is_drained( sched ) ); /* nothing left to guess at until the next FEC set */
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_spec_cnt 1, lthash_undo_cnt 0, lthash_drop_cnt 0," ) );

  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==2UL );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 2UL, 2UL );
  FD_TEST( ctx->delta_seen );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  /* The handed values hold the undone guess on top of the delta. */
  fd_lthash_value_t guess[ 1 ]; fake_hash( guess, fd_type_pun_const( acct ), 1, 1UL );
  fd_lthash_add( expected, guess );
  FD_TEST( !fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( fd_lthash_eq( ctx->handed, expected ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_sub_cnt 1, lthash_add_cnt 2, lthash_spec_cnt 1, lthash_undo_cnt 1, lthash_drop_cnt 0," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* A speculative addition still on its tile when its account is written
   again.  T2's bit at parse clears the addition's ticket and frees its
   slot; T2 itself waits on the dispatched pseudo-transaction, which
   the none-READY check tolerates; the result is dropped on arrival and
   never touches the delta; A is added again after T2. */
static void
run_lthash_spec_result_dropped_case( void ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, NULL, 0UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL, 0 );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x19d2e3f4a5b6c7d8UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 3UL, start_poh );

  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t held[ 1 ]; fd_lthash_value_t held_value[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_LTHASH_ADD, held, held_value ) );
  FD_TEST( !memcmp( held->lthash->acct.b, acct[ 0 ].uc, sizeof(fd_acct_addr_t) ) );
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && !ctx->add_cnt );

  /* T2 arrives while the guess is on the tile.  Its PoH and sigverify
     run; T2 waits on the pseudo-transaction. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==1UL && !ctx->add_cnt && !ctx->block_end_cnt );

  /* The stale result lands and is dropped. */
  lthash_complete( sched, held, ctx, held_value );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_spec_cnt 1, lthash_undo_cnt 0, lthash_drop_cnt 1," ) );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==2UL );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 2UL, 2UL );
  FD_TEST( ctx->delta_seen );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  fd_lthash_value_t guess[ 1 ]; fake_hash( guess, fd_type_pun_const( acct ), 1, 1UL );
  FD_TEST( fd_lthash_eq( held_value, guess ) );
  fd_lthash_add( expected, guess );
  FD_TEST( !fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( fd_lthash_eq( ctx->handed, expected ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_sub_cnt 1, lthash_add_cnt 2, lthash_spec_cnt 1, lthash_undo_cnt 0, lthash_drop_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

/* Late registration.  S is a version 0 transaction whose lookup table
   cannot be resolved at parse (resolution is bypassed), so it is
   inserted serializing with FD_SCHED_TXN_ALT_UNRESOLVED and the
   dispatcher knows none of its lookup table accounts.  Completing S
   hands back {A, X} as its writable lookup table accounts, as the exec
   tile would.  T1 is a legacy transaction writing A, nothing else
   writes X, and S's payer P is a static write.  Without speculate, T1
   and S arrive in one FEC set: A's drained addition predates S, so the
   registration makes it stale (completed without hashing) and a new
   one follows S.  With speculate, T1 arrives first and A's addition is
   speculated and applied before S arrives; the registration undoes it.
   Either way A, P and X each end with exactly one subtraction and one
   hashed addition at the final version. */
static void
run_lthash_late_alt_case( int speculate ) {
  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL, 1 );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_set_bypass_alut_resolution( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_pubkey_t acct[ 3 ]; /* A, P, X */
  fd_memset( acct[ 0 ].uc, 0xa1, sizeof(fd_pubkey_t) );
  fd_memset( acct[ 1 ].uc, 0xc3, sizeof(fd_pubkey_t) );
  fd_memset( acct[ 2 ].uc, 0xd4, sizeof(fd_pubkey_t) );
  fd_acct_addr_t late[ 2 ]; /* A, X */
  fd_memcpy( late[ 0 ].b, acct[ 0 ].uc, sizeof(fd_acct_addr_t) );
  fd_memcpy( late[ 1 ].b, acct[ 2 ].uc, sizeof(fd_acct_addr_t) );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,   NULL, 0UL, 0x01 );
  uchar s [ FD_TXN_MTU ]; ulong s_sz  = build_lthash_v0_txn(   s,  acct+1, 2UL,       0x02 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x2c3d4e5f60718293UL );
  test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  ctx->late_alts    = late;
  ctx->late_alt_cnt = 2UL;

  if( !speculate ) {
    uchar const * txns[ 2 ] = { t1, s };
    ulong txn_sz[ 2 ] = { t1_sz, s_sz };
    uchar encoded[ 8192 ]; ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 2UL, 1 );
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
    fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 2UL, start_poh );
  } else {
    uchar const * txns1[ 1 ] = { t1 };
    uchar const * txns2[ 1 ] = { s };
    uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL, 0 );
    uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &s_sz,  1UL, 1 );
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
    fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, 3UL, start_poh );
    lthash_drive( sched, ctx, 100UL );
    FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
    lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 1UL );
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  }
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==3UL && ctx->sub_cnt==3UL && ctx->add_cnt==fd_ulong_if( speculate, 4UL, 3UL ) );
  lthash_check_acct( ctx, 2UL, acct,   1UL, fd_ulong_if( speculate, 2UL, 1UL ), 2UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 2UL, acct+2, 1UL, 1UL, 1UL );
  FD_TEST( ctx->delta_seen );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 3UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  if( speculate ) {
    fd_lthash_value_t guess[ 1 ]; fake_hash( guess, fd_type_pun_const( acct ), 1, 1UL );
    fd_lthash_add( expected, guess );
  }
  FD_TEST( fd_lthash_eq( ctx->handed, expected ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "alut_serializing_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_late_reg_cnt 2," ) );
  FD_TEST( strstr( state, speculate ? "lthash_spec_cnt 1, lthash_undo_cnt 1, lthash_drop_cnt 0," : "lthash_spec_cnt 0, lthash_undo_cnt 0, lthash_drop_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_sched_footprint();
  run_lane_policy_case();
  run_bad_tick_cases();
  run_ag_structure_cases();
  run_many_entries_cases();
  run_poh_spread_cases();
  run_interleaved_fec_residual_case();
  run_abandon_flavor_case();
  run_root_notify_flavor_case();
  run_late_ancestor_discard_case();
  run_runtime_limit_case();
  run_zero_hashcnt_mblk_case();
  run_lthash_basic_case( 1 );
  run_lthash_basic_case( 0 );
  run_lthash_abandon_in_flight_case( 1 );
  run_lthash_abandon_in_flight_case( 0 );
  run_lthash_demote_promote_case();
  run_lthash_block_start_writes_case( 0 );
  run_lthash_block_start_writes_case( 1 );
  run_lthash_block_start_writes_case( 2 );
  run_lthash_block_start_writes_case( 3 );
  run_lthash_block_start_writes_case( 4 );
  run_lthash_speculate_case( 0 );
  run_lthash_speculate_case( 1 );
  run_lthash_spec_result_dropped_case();
  run_lthash_late_alt_case( 0 );
  run_lthash_late_alt_case( 1 );
  run_lthash_respeculate_case();
  run_lthash_pending_rewrite_case( 1 );
  run_lthash_pending_rewrite_case( 0 );
  run_lthash_two_late_alt_case();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
