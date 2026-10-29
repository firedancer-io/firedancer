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

static void
test_sched_footprint( void ) {
  /* Retain the savings from compact shred lengths and 4992-byte
     transactions under the default scheduler sizing. */
  FD_TEST( fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT )==1692837120UL );
  /* Only the shred length array scales with the shred limit. */
  FD_TEST( fd_sched_footprint( 65536UL, 2048UL, 4UL*FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT )==1692837120UL+2048UL*3UL*FD_SHRED_BLK_MAX*sizeof(ushort) );
  FD_TEST( fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, 5UL*FD_MAX_TXN_PER_SLOT )==1692837120UL );
  FD_TEST( !fd_sched_footprint( 65536UL, 2048UL, 0UL, FD_MAX_TXN_PER_SLOT ) );
  FD_TEST( !fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, 0UL ) );
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
#define AG_COMP_TICK_BADHASH  (6) /* one-hash tick whose end hash does not chain */

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
  case AG_COMP_TICK_2HASH:
  case AG_COMP_TICK_BADHASH: {
    ulong hash_cnt = comp==AG_COMP_TICK_0HASH ? 0UL : comp==AG_COMP_TICK_2HASH ? 2UL : 1UL;
    FD_STORE( ulong, out, 1UL );
    fd_hash_t end_hash[ 1 ];
    repeat_hash( end_hash, prev_hash, hash_cnt );
    if( comp==AG_COMP_TICK_BADHASH ) end_hash->uc[ 0 ] ^= 1;
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

/* Ingests comp as a single FEC set of block bank_idx (slot
   TEST_ROOT_SLOT+1 under bank 1).  Returns fd_sched_fec_ingest's
   verdict. */
static int
ingest_ag_component( fd_sched_t * sched,
                     ulong        bank_idx,
                     int          comp,
                     fd_hash_t *  prev_hash,
                     int          first,
                     int          last ) {
  uchar buf[ FD_BLOCK_MARKER_SER_MAX ] __attribute__((aligned(64)));
  ulong sz = encode_ag_component( buf, comp, prev_hash );
  fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
  store_fec->data_sz       = (uint)sz;
  store_fec->shred_sz[ 0 ] = (ushort)sz;
  fd_sched_fec_t fec[ 1 ] = {{
    .bank_idx          = bank_idx,
    .parent_bank_idx   = 1UL,
    .slot              = TEST_ROOT_SLOT+1UL,
    .parent_slot       = TEST_ROOT_SLOT,
    .fec               = store_fec,
    .data              = buf,
    .shred_cnt         = 1U,
    .is_last_in_batch  = 1U,
    .is_last_in_block  = !!last,
    .is_first_in_block = !!first,
  }};
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  return fd_sched_fec_ingest( sched, fec );
}

static void
run_interleaved_fec_tasks( fd_sched_t * sched, uint const * signature_tag, ulong * txn_exec_cnt ) {
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
        FD_TEST( txn->end_shred_idx==fd_ushort_if( task->txn_exec->bank_idx==2UL, 3U, 2U ) );
        (*txn_exec_cnt)++;
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
}

static void
run_interleaved_fec_residual_case( void ) {
  ulong footprint = fd_sched_footprint( FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  void * mem = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT ) );
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
  fd_hash_t tx_mblk_hash[ 2 ];

  for( ulong i=0UL; i<2UL; i++ ) {
    hash_from_seed( start_poh+i, 0x459db07a9f2c0321UL+i );
    hash_from_seed( tx_mblk_hash+i, 0x9e33470a182d6cbfUL+i );

    ulong cursor = 0UL;
    FD_STORE( ulong, encoded[ i ]+cursor, 1UL );
    cursor += sizeof(ulong);
    fd_microblock_hdr_t tx_hdr = {
      .hash_cnt = 1UL,
      .txn_cnt  = 1UL,
    };
    fd_memcpy( tx_hdr.hash, tx_mblk_hash[ i ].hash, sizeof(fd_hash_t) );
    fd_memcpy( encoded[ i ]+cursor, &tx_hdr, sizeof(tx_hdr) );
    cursor += sizeof(tx_hdr);

    uchar tagged_txn[ FD_TXN_MTU ];
    fd_memcpy( tagged_txn, txn_payload, txn_sz );
    FD_STORE( uint, tagged_txn+1UL, signature_tag[ i ] );
    split_off[ i ] = cursor+txn_sz/2UL;
    fd_memcpy( encoded[ i ]+cursor, tagged_txn, txn_sz );
    cursor += txn_sz;
    encoded_sz[ i ] = cursor;
  }

  fd_hash_t poh[ 2 ];
  for( ulong i=0UL; i<2UL; i++ ) {
    poh[ i ] = start_poh[ i ];
    FD_TEST( ingest_ag_component( sched, 2UL+i, AG_COMP_HEADER, poh+i, 1, 0 ) );
    fd_sched_set_poh_params( sched, 2UL+i, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh+i );
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
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
  }

  /* Only the first half of each txn has arrived, so both blocks wait
     on the network after BLOCK_START. */
  ulong txn_exec_cnt = 0UL;
  run_interleaved_fec_tasks( sched, signature_tag, &txn_exec_cnt );
  long wait_until = fd_log_wallclock()+1000000L;
  while( fd_log_wallclock()<wait_until ) FD_SPIN_PAUSE();

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    store_fec->data_sz = (uint)(encoded_sz[ i ]-split_off[ i ]);
    if( !i ) {
      FD_TEST( store_fec->data_sz<=USHORT_MAX );
      store_fec->shred_sz[ 0 ] = (ushort)(store_fec->data_sz/2U);
      store_fec->shred_sz[ 1 ] = (ushort)(store_fec->data_sz-store_fec->data_sz/2U);
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
      .shred_cnt        = (uint)(i ? 1UL : 2UL),
      .is_last_in_batch = 1U,
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    FD_TEST( fd_sched_fec_ingest( sched, fec ) );
  }

  /* PoH bypass skips the mixin compare only, so the alpentick chains
     from the claimed transaction microblock hash. */
  for( ulong i=0UL; i<2UL; i++ ) {
    poh[ i ] = tx_mblk_hash[ i ];
    FD_TEST( ingest_ag_component( sched, 2UL+i, AG_COMP_FOOTER, poh+i, 0, 0 ) );
    FD_TEST( ingest_ag_component( sched, 2UL+i, AG_COMP_TICK,   poh+i, 0, 1 ) );
  }

  run_interleaved_fec_tasks( sched, signature_tag, &txn_exec_cnt );
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  FD_TEST( txn_exec_cnt==2UL );
  FD_TEST( fd_sched_is_drained( sched ) );

  /* Both blocks wait on the network, but only one block is tracked at
     a time: block 2's interval closes when block 3 starts, and block 3
     covers the ~1ms wait.  Intervals are emitted in order and must not
     overlap, and the network wait is counted once. */
  fd_sched_slot_state_t states[ FD_SCHED_SLOT_STATE_MAX ];
  ulong state_cnt = fd_sched_slot_states_drain( sched, states );
  long  network_ticks = 0L;
  long  min_wait      = (long)( 500000.0*fd_tempo_tick_per_ns( NULL ) );
  FD_TEST( state_cnt );
  for( ulong i=0UL; i<state_cnt; i++ ) {
    FD_TEST( states[ i ].slot==TEST_ROOT_SLOT+1UL );
    FD_TEST( states[ i ].end_tick>=states[ i ].start_tick );
    if( i ) FD_TEST( states[ i ].start_tick>=states[ i-1UL ].end_tick );
    if( states[ i ].state==FD_SCHED_SLOT_STATE_BLOCKED_NETWORK ) network_ticks += states[ i ].end_tick-states[ i ].start_tick;
  }
  FD_TEST( network_ticks>=min_wait );
  FD_TEST( network_ticks<=states[ state_cnt-1UL ].end_tick-states[ 0 ].start_tick );
  FD_TEST( !fd_sched_slot_states_drain( sched, states ) );

  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
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
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT ) );
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
        fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
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

  /* An alpentick that does not chain from the running PoH. */
  { int c[] = { AG_COMP_HEADER, AG_COMP_FOOTER, AG_COMP_TICK_BADHASH };
    run_ag_structure_case( start_poh, c, 3UL, 1, FD_SCHED_DEAD_REASON_TICK_HASH_MISMATCH ); }

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
/* More than FD_RUNTIME_MAX_HASHES_PER_TICK entries, each with one
   transaction, exceed the production limits. */
#define MANY_ENTRIES_MAX_SHREDS (2UL*FD_SHRED_BLK_MAX)
#define MANY_ENTRIES_MAX_TXN    (2UL*FD_MAX_TXN_PER_SLOT)

static void
run_many_entries_case( ulong entry_cnt,
                       ulong bad_idx,
                       ulong bad_hash_cnt,
                       int   expect_ingest_ok,
                       int   expect_dead_reason ) {
  /* Each entry keeps one txn and one microblock live; the extra 2048
     covers the ~1420 free microblocks FEC admission may need. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, entry_cnt+2048UL );
  ulong block_cnt_max = 4UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max, MANY_ENTRIES_MAX_SHREDS, MANY_ENTRIES_MAX_TXN );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, MANY_ENTRIES_MAX_SHREDS, MANY_ENTRIES_MAX_TXN, TEST_EXEC_CNT ) );
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

  {
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
      fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, prev_hash );
    }
    first = 0U;
    off  += sz;
    if( FD_UNLIKELY( !ok ) ) { ingest_ok = 0; break; }
  }
  if( ingest_ok!=expect_ingest_ok ) FD_LOG_ERR(( "cnt %lu bad_idx %lu: ingest_ok %d dead %d", entry_cnt, bad_idx, ingest_ok, fd_sched_get_dead_reason( sched, 2UL ) ));
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
  FD_TEST( MANY_ENTRIES_MAX_TXN>90000UL );

  /* Entry counts are valid well past FD_RUNTIME_MAX_HASHES_PER_TICK */
  run_many_entries_case( lim,      ULONG_MAX, 0UL, 1, FD_SCHED_DEAD_REASON_NONE );
  run_many_entries_case( lim+1UL,  ULONG_MAX, 0UL, 1, FD_SCHED_DEAD_REASON_NONE );
  run_many_entries_case( 90000UL,  ULONG_MAX, 0UL, 1, FD_SCHED_DEAD_REASON_NONE );

  /* Every entry is pinned to one hash, deep into a long batch: this is
     what bounds PoH work.  Neither a huge nor a zero hash count gets
     through. */
  run_many_entries_case( lim+100UL, lim+50UL, 2UL,       0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT );
  run_many_entries_case( lim+100UL, lim+50UL, ULONG_MAX, 0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT );
  run_many_entries_case( lim+100UL, lim+50UL, 0UL,       0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT );
  run_many_entries_case( 10UL,      0UL,      lim+1UL,   0, FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT );
}

static void
run_lane_policy_case( void ) {
  /* This test only needs the root and a handful of synthetic branches. */
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 8UL;
  ulong footprint     = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  void * mem          = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT ) );
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
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx + 1UL, start_poh );

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
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx, TEST_ROOT_TICK_HEIGHT + bank_idx + 1UL, start_poh );
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
  ulong footprint = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  void * mem      = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT ) );
  FD_TEST( sched );
  *mem_out = mem;
  return sched;
}

/* Footer cert verify tasks hold a block that reached BLOCK_END: the
   claimed tiles stay busy, the block is not done, and its child does
   not start until the last cert task is done.  An abandon while they
   run drains the block on the last one. */
static void
run_cert_verify_case( int abandon ) {
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x3c5a7e9b1d2f4086UL );
  fd_hash_t poh[ 1 ] = { *start_poh };
  FD_TEST( ingest_ag_component( sched, 2UL, AG_COMP_HEADER, poh, 1, 0 ) );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  FD_TEST( ingest_ag_component( sched, 2UL, AG_COMP_FOOTER, poh, 0, 0 ) );
  FD_TEST( ingest_ag_component( sched, 2UL, AG_COMP_TICK,   poh, 0, 1 ) );

  fd_sched_task_t task[ 1 ];
  for(;;) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    FD_TEST( fd_sched_task_next_ready( sched, task ) );
    if( task->task_type==FD_SCHED_TT_BLOCK_END ) break;
    if( task->task_type==FD_SCHED_TT_BLOCK_START ) {
      FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
      continue;
    }
    FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH );
    fd_execrp_poh_hash_done_msg_t msg[ 1 ];
    msg->cnt = task->poh_hash->cnt;
    for( ulong i=0UL; i<msg->cnt; i++ ) repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
    FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) );
  }
  FD_TEST( fd_sched_pruned_block_next( sched )==2UL );

  ulong tiles = fd_sched_cert_dispatch( sched, 2UL, 2UL );
  FD_TEST( fd_ulong_popcnt( tiles )==2 );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
  FD_TEST( add_live_block( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL ) );
  FD_TEST( !fd_sched_task_next_ready( sched, task ) ); /* child waits, no CRIT */
  FD_TEST( !fd_sched_is_drained( sched ) );

  if( abandon ) fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_INVALID );
  int t0 = fd_ulong_find_lsb( tiles );
  int t1 = fd_ulong_find_msb( tiles );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_CERT_VERIFY, ULONG_MAX, (ulong)t0, NULL ) );
  FD_TEST( !fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_CERT_VERIFY, ULONG_MAX, (ulong)t1, NULL ) );
  if( abandon ) {
    FD_TEST( fd_sched_pruned_block_next( sched )==3UL ); /* the child only, 2 released at BLOCK_END */
    FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
    FD_TEST( !fd_sched_task_next_ready( sched, task ) );
    FD_TEST( fd_sched_is_drained( sched ) );
  } else {
    FD_TEST( fd_sched_task_next_ready( sched, task ) );
    FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==3UL );
  }
  fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
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
  ulong footprint = fd_sched_footprint( FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  void * mem = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng[ 1 ]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT ) );
  FD_TEST( sched );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  uchar txn_payload[ FD_TXN_MTU ];
  ulong txn_sz = build_shred_test_txn( txn_payload );

  fd_hash_t start_poh[ 1 ];
  fd_hash_t mblk_hash[ 1 ];
  hash_from_seed( start_poh, 0x6d1f4c9a3b57e802UL );
  hash_from_seed( mblk_hash, 0xc40a97e5182b6d3fUL );

  FD_TEST( ingest_ag_component( sched, 2UL, AG_COMP_HEADER, start_poh, 1, 0 ) );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  /* First entry FEC: a complete single-transaction microblock.  The
     batch declares more microblocks than this, so it stays
     incomplete. */
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
  }};
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );

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
  fec->fec  = store_fec1;
  fec->data = fec1;
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

/* The replay tile gives up on a block whose transaction task it just
   took and will not execute: it abandons the block with the task in
   flight, then retires the task.  Nothing more of the block or of its
   child comes out, and both are released once the task is retired.
   Run for an exec task and for a sigverify task. */
static void
run_abandon_in_flight_case( ulong task_type ) {
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 8UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_hash_t start_poh[ 1 ];
  fd_hash_t mblk_hash[ 1 ];
  hash_from_seed( start_poh, 0x6d1f4c9a3b57e802UL );
  hash_from_seed( mblk_hash, 0xc40a97e5182b6d3fUL );
  FD_TEST( ingest_ag_component( sched, 2UL, AG_COMP_HEADER, start_poh, 1, 0 ) );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  /* One microblock with two transactions from different payers, so the
     second does not queue behind the first.  The batch declares more
     microblocks, so the block stays open. */
  uchar txn_payload[ FD_TXN_MTU ];
  ulong txn_sz = build_shred_test_txn( txn_payload );
  uchar txn_meta[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  FD_TEST( fd_txn_parse( txn_payload, txn_sz, txn_meta, NULL ) );
  uchar fec0[ 4096 ];
  ulong fec0_sz = 0UL;
  FD_STORE( ulong, fec0, 3UL );
  fec0_sz += sizeof(ulong);
  fd_microblock_hdr_t hdr = { .hash_cnt = 1UL, .txn_cnt = 2UL };
  fd_memcpy( hdr.hash, mblk_hash->hash, sizeof(fd_hash_t) );
  fd_memcpy( fec0+fec0_sz, &hdr, sizeof(hdr) );
  fec0_sz += sizeof(hdr);
  fd_memcpy( fec0+fec0_sz, txn_payload, txn_sz );
  fec0_sz += txn_sz;
  txn_payload[ ((fd_txn_t *)txn_meta)->acct_addr_off ] ^= 1;
  fd_memcpy( fec0+fec0_sz, txn_payload, txn_sz );
  fec0_sz += txn_sz;

  fd_store_fec_t store_fec0[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec0, 0, sizeof(fd_store_fec_t) );
  store_fec0->data_sz       = (uint)fec0_sz;
  store_fec0->shred_sz[ 0 ] = (ushort)fec0_sz;
  fd_sched_fec_t fec[ 1 ] = {{
    .bank_idx        = 2UL,
    .parent_bank_idx = 1UL,
    .slot            = TEST_ROOT_SLOT+1UL,
    .parent_slot     = TEST_ROOT_SLOT,
    .fec             = store_fec0,
    .data            = fec0,
    .shred_cnt       = 1U,
  }};
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );
  FD_TEST( add_live_block( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL ) );

  /* Run tasks until one of the wanted kind comes out, and hold it. */
  fd_sched_task_t task[ 1 ];
  for(;;) {
    FD_TEST( fd_sched_task_next_ready( sched, task ) );
    if( task->task_type==task_type ) break;
    switch( task->task_type ) {
      case FD_SCHED_TT_BLOCK_START:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_TXN_EXEC:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC, task->txn_exec->txn_idx, task->txn_exec->exec_idx, NULL ) );
        break;
      case FD_SCHED_TT_TXN_SIGVERIFY:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_SIGVERIFY, task->txn_sigverify->txn_idx, task->txn_sigverify->exec_idx, NULL ) );
        break;
      case FD_SCHED_TT_POH_HASH: {
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->cnt = task->poh_hash->cnt;
        for( ulong i=0UL; i<task->poh_hash->cnt; i++ ) repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) );
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task type %lu", task->task_type ));
    }
  }
  ulong txn_idx  = task_type==FD_SCHED_TT_TXN_EXEC ? task->txn_exec->txn_idx  : task->txn_sigverify->txn_idx;
  ulong exec_idx = task_type==FD_SCHED_TT_TXN_EXEC ? task->txn_exec->exec_idx : task->txn_sigverify->exec_idx;

  fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_DISCARDED );
  FD_TEST( !fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX ); /* held while the task is out */

  FD_TEST( !fd_sched_task_done( sched, task_type, txn_idx, exec_idx, NULL ) );
  ulong first  = fd_sched_pruned_block_next( sched );
  ulong second = fd_sched_pruned_block_next( sched );
  FD_TEST( ( first==2UL && second==3UL ) || ( first==3UL && second==2UL ) );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  FD_TEST( !fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_is_drained( sched ) );

  fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
}

/* A transaction entry whose claimed hash does not match the mixin rules
   the block dead when its PoH task retires. */
static void
run_entry_hash_mismatch_case( void ) {
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  void * mem; fd_sched_t * sched = new_sched( rng, &mem, 4UL );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

  fd_hash_t start_poh[ 1 ];
  hash_from_seed( start_poh, 0x1f83d9abfb41bd6bUL );
  fd_hash_t poh[ 1 ] = { *start_poh };
  FD_TEST( ingest_ag_component( sched, 2UL, AG_COMP_HEADER, poh, 1, 0 ) );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  uchar txn_payload[ FD_TXN_MTU ];
  ulong txn_sz = build_shred_test_txn( txn_payload );
  uchar entry[ 4096 ];
  ulong entry_sz = 0UL;
  FD_STORE( ulong, entry, 1UL );                                entry_sz += sizeof(ulong);
  fd_microblock_hdr_t hdr = { .hash_cnt = 1UL, .txn_cnt = 1UL };
  hash_from_seed( (fd_hash_t *)hdr.hash, 0x5be0cd19137e2179UL ); /* not the mixin */
  fd_memcpy( entry+entry_sz, &hdr, sizeof(hdr) );               entry_sz += sizeof(hdr);
  fd_memcpy( entry+entry_sz, txn_payload, txn_sz );             entry_sz += txn_sz;

  fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
  fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
  store_fec->data_sz       = (uint)entry_sz;
  store_fec->shred_sz[ 0 ] = (ushort)entry_sz;
  fd_sched_fec_t fec[ 1 ] = {{
    .bank_idx         = 2UL,
    .parent_bank_idx  = 1UL,
    .slot             = TEST_ROOT_SLOT+1UL,
    .parent_slot      = TEST_ROOT_SLOT,
    .fec              = store_fec,
    .data             = entry,
    .shred_cnt        = 1U,
    .is_last_in_batch = 1U,
  }};
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );

  int poh_dead = 0;
  fd_sched_task_t task[ 1 ];
  for(;;) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    if( !fd_sched_task_next_ready( sched, task ) ) break;
    switch( task->task_type ) {
      case FD_SCHED_TT_BLOCK_START:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_TXN_EXEC:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC, task->txn_exec->txn_idx, task->txn_exec->exec_idx, NULL ) );
        break;
      case FD_SCHED_TT_TXN_SIGVERIFY:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_SIGVERIFY, task->txn_sigverify->txn_idx, task->txn_sigverify->exec_idx, NULL ) );
        break;
      case FD_SCHED_TT_POH_HASH: {
        FD_TEST( !task->poh_hash->hashcnt ); /* txn microblock: mixin only */
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->cnt = task->poh_hash->cnt;
        for( ulong i=0UL; i<msg->cnt; i++ ) msg->hash[ i ] = task->poh_hash->hash[ i ];
        if( fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) ) poh_dead = 1;
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task type %lu in entry hash mismatch case", task->task_type ));
    }
  }
  FD_TEST( poh_dead );
  FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH );
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

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
    ulong footprint = fd_sched_footprint( depth, block_cnt_max, 3UL, FD_MAX_TXN_PER_SLOT );
    void * mem = aligned_alloc( fd_sched_align(), footprint );
    FD_TEST( mem );
    fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, 3UL, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT ) );
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
    ulong footprint = fd_sched_footprint( depth, block_cnt_max, FD_SHRED_BLK_MAX, 1UL );
    void * mem = aligned_alloc( fd_sched_align(), footprint );
    FD_TEST( mem );
    fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, FD_SHRED_BLK_MAX, 1UL, TEST_EXEC_CNT ) );
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
    fd_hash_t poh[ 1 ] = {{{ 0 }}};
    FD_TEST( ingest_ag_component( sched, 2UL, AG_COMP_HEADER, poh, 1, 0 ) );
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = 2UL,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT+1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .data              = encoded,
      .shred_cnt         = 1U,
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
    ulong footprint = fd_sched_footprint( depth, block_cnt_max, 2UL*FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
    void * mem = aligned_alloc( fd_sched_align(), footprint );
    FD_TEST( mem );
    fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, 2UL*FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, TEST_EXEC_CNT ) );
    FD_TEST( sched );
    fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );

    uchar encoded[ sizeof(ulong) ] = {0};
    FD_STORE( ulong, encoded, mblk_cnt );

    fd_store_fec_t store_fec[ 1 ] __attribute__((aligned(alignof(fd_store_fec_t))));
    fd_memset( store_fec, 0, sizeof(fd_store_fec_t) );
    FD_TEST( sizeof(encoded)<=USHORT_MAX );
    store_fec->data_sz       = (uint)sizeof(encoded);
    store_fec->shred_sz[ 0 ] = (ushort)sizeof(encoded);
    fd_hash_t poh[ 1 ] = {{{ 0 }}};
    FD_TEST( ingest_ag_component( sched, 2UL, AG_COMP_HEADER, poh, 1, 0 ) );
    fd_sched_fec_t fec[ 1 ] = {{
      .bank_idx          = 2UL,
      .parent_bank_idx   = 1UL,
      .slot              = TEST_ROOT_SLOT+1UL,
      .parent_slot       = TEST_ROOT_SLOT,
      .fec               = store_fec,
      .data              = encoded,
      .shred_cnt         = 1U,
    }};
    FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
    int too_many = mblk_cnt>2UL*FD_SCHED_MAX_MBLK_PER_SLOT;
    FD_TEST( (!fd_sched_fec_ingest( sched, fec ))==too_many );
    FD_TEST( (fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_TOO_MANY_MICROBLOCKS)==too_many );

    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_delete( fd_sched_leave( sched ) ); free( mem );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_sched_footprint();
  run_lane_policy_case();
  run_ag_structure_cases();
  run_many_entries_cases();
  run_interleaved_fec_residual_case();
  run_abandon_flavor_case();
  run_root_notify_flavor_case();
  run_late_ancestor_discard_case();
  run_runtime_limit_case();
  run_zero_hashcnt_mblk_case();
  run_entry_hash_mismatch_case();
  run_cert_verify_case( 0 );
  run_cert_verify_case( 1 );
  run_abandon_in_flight_case( FD_SCHED_TT_TXN_EXEC );
  run_abandon_in_flight_case( FD_SCHED_TT_TXN_SIGVERIFY );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
