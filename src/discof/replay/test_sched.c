#include <stdarg.h>
#include <stdio.h>
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
#define TEST_WKSP_TAG         1UL

static fd_wksp_t * test_wksp;

/* new_sched_ext returns a scheduler of the given dimensions with the
   root block, TEST_ROOT_SLOT at bank index 1, added as done.  Its
   memory comes from the test workspace and goes back with
   delete_sched. */
static fd_sched_t *
new_sched_ext( ulong depth,
               ulong block_cnt_max,
               ulong max_shreds_per_block,
               ulong max_txn_per_slot ) {
  static fd_rng_t rng[ 1 ];
  fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  ulong footprint = fd_sched_footprint( depth, block_cnt_max, max_shreds_per_block, max_txn_per_slot );
  FD_TEST( footprint );
  void * mem = fd_wksp_alloc_laddr( test_wksp, fd_sched_align(), footprint, TEST_WKSP_TAG );
  FD_TEST( mem );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, depth, block_cnt_max, max_shreds_per_block, max_txn_per_slot, TEST_EXEC_CNT ) );
  FD_TEST( sched );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, TEST_ROOT_SLOT );
  return sched;
}

/* new_sched is new_sched_ext at the production limits, and
   deep enough for fd_sched_can_ingest_cnt to count one worst-case FEC
   set, whose 1334 microblock descriptors outnumber the 478
   transactions it could hold. */
static fd_sched_t *
new_sched( ulong block_cnt_max ) {
  return new_sched_ext( fd_ulong_max( FD_SCHED_MIN_DEPTH, 2048UL ), block_cnt_max, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
}

static void
delete_sched( fd_sched_t * sched ) {
  fd_wksp_free_laddr( fd_sched_delete( fd_sched_leave( sched ) ) );
}

/* The footprint covers the dispatcher's account budget for the lane
   sets, one lane map per lane, the hash pool, the deltas and the batch
   records, which scale with FD_SCHED_LTHASH_BATCH_MAX, so it is pinned
   at the default width only. */
#define TEST_SCHED_FOOTPRINT (1981664384UL)

static void
test_sched_footprint( void ) {
  FD_LOG_NOTICE(( "footprint %lu", fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT ) ));
  if( FD_SCHED_LTHASH_BATCH_MAX==32UL ) {
    /* Retain the savings from compact shred lengths and 4992-byte
       transactions under the default scheduler sizing. */
    FD_TEST( fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT )==TEST_SCHED_FOOTPRINT );
    /* Only the shred length array scales with the shred limit. */
    FD_TEST( fd_sched_footprint( 65536UL, 2048UL, 4UL*FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT )==TEST_SCHED_FOOTPRINT+2048UL*3UL*FD_SHRED_BLK_MAX*sizeof(ushort) );
    FD_TEST( fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, 5UL*FD_MAX_TXN_PER_SLOT )==TEST_SCHED_FOOTPRINT );
  }
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
      case FD_SCHED_TT_LTHASH_SUB:
      case FD_SCHED_TT_LTHASH_ADD: {
        fd_lthash_value_t v[ 1 ]; fd_lthash_zero( v );
        FD_TEST( !fd_sched_task_done( sched, task->task_type, ULONG_MAX, task->lthash->exec_idx, v ) );
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task type %lu in interleaved FEC test", task->task_type ));
    }
  }
}

static void
run_interleaved_fec_residual_case( void ) {
  fd_sched_t * sched = new_sched_ext( FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  fd_sched_set_bypass_poh_verify( sched, 1 );

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

  delete_sched( sched );
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
  fd_sched_t * sched = new_sched_ext( fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL ), 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );

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

  delete_sched( sched );
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
  fd_sched_t * sched = new_sched_ext( depth, block_cnt_max, MANY_ENTRIES_MAX_SHREDS, MANY_ENTRIES_MAX_TXN );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  uchar txn_payload[ FD_TXN_MTU ];
  ulong txn_sz = build_shred_test_txn( txn_payload );

  ulong  stream_sz = sizeof(ulong)+entry_cnt*(sizeof(fd_microblock_hdr_t)+txn_sz);
  uchar * stream   = fd_wksp_alloc_laddr( test_wksp, 64UL, stream_sz, TEST_WKSP_TAG );
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
  delete_sched( sched );
  fd_wksp_free_laddr( stream );
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

/* Hands out and completes tasks of tick-only blocks until the
   scheduler hands out nothing, or BLOCK_START for stop_bank_idx, which
   is left outstanding.  Returns 1 in the latter case. */
static int
drive_ticks_until_start( fd_sched_t * sched,
                         ulong        stop_bank_idx ) {
  fd_sched_task_t task[ 1 ];
  for(;;) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    if( !fd_sched_task_next_ready( sched, task ) ) return 0;
    switch( task->task_type ) {
      case FD_SCHED_TT_BLOCK_START:
        if( task->block_start->bank_idx==stop_bank_idx ) return 1;
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_BLOCK_END:
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_POH_HASH: {
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->cnt = task->poh_hash->cnt;
        for( ulong i=0UL; i<msg->cnt; i++ ) repeat_hash( msg->hash+i, task->poh_hash->hash+i, task->poh_hash->hashcnt );
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) );
        break;
      }
      default: FD_LOG_ERR(( "unexpected task type %lu", task->task_type ));
    }
  }
}

/* A block given up on without fault keeps a clean dead reason and
   raises the discarded flag, and blocks that later arrive under it
   inherit that flavor rather than looking ruled-invalid.  A block ruled
   invalid stays un-discarded, so the flag never masks a verdict. */
static void
run_abandon_flavor_case( void ) {
  /* Discarded lineage: eviction, then two generations arriving under
     it.  Both must come back DEAD_ANCESTOR and discarded. */
  {
    fd_sched_t * sched = new_sched( 8UL );
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
    delete_sched( sched );
  }

  /* Invalid lineage: the replay tile owns the specific reason, so the
     scheduler records none of its own, and nothing is discarded. */
  {
    fd_sched_t * sched = new_sched( 8UL );
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
    delete_sched( sched );
  }
}

/* A minority fork loses the fork race rather than violating the
   protocol, so a root notify discards it.  A fork already going down
   for a fault of its own keeps that flavor. */
static void
run_root_notify_flavor_case( void ) {
  fd_sched_t * sched = new_sched( 8UL );

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
  delete_sched( sched );
}

/* A block that already went down keeps the flavor it went down with
   when an ancestor is abandoned later.  The replay tile's rulings are
   the load-bearing case: sched records no dead reason for them, so only
   dying tells them apart from a healthy block. */
static void
run_late_ancestor_discard_case( void ) {
  fd_sched_t * sched = new_sched( 8UL );

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
  delete_sched( sched );
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
  fd_sched_t * sched = new_sched_ext( FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  fd_sched_set_bypass_poh_verify( sched, 1 );

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
      case FD_SCHED_TT_LTHASH_SUB:
      case FD_SCHED_TT_LTHASH_ADD: {
        fd_lthash_value_t v[ 1 ]; fd_lthash_zero( v );
        FD_TEST( !fd_sched_task_done( sched, task->task_type, ULONG_MAX, task->lthash->exec_idx, v ) );
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

  delete_sched( sched );
}

/* A transaction entry whose claimed hash does not match the mixin rules
   the block dead when its PoH task retires. */
static void
run_entry_hash_mismatch_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );

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
      case FD_SCHED_TT_LTHASH_SUB:
      case FD_SCHED_TT_LTHASH_ADD: {
        fd_lthash_value_t v[ 1 ]; fd_lthash_zero( v );
        FD_TEST( !fd_sched_task_done( sched, task->task_type, ULONG_MAX, task->lthash->exec_idx, v ) );
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected task type %lu in entry hash mismatch case", task->task_type ));
    }
  }
  FD_TEST( poh_dead );
  FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH );
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  delete_sched( sched );
}

static void
run_runtime_limit_case( void ) {
  ulong depth         = fd_ulong_max( FD_SCHED_MIN_DEPTH, 512UL );
  ulong block_cnt_max = 4UL;

  /* Shred limit: a 3 shred block under a limit of 3 fits across two FEC
     sets, and a sibling block gets its own shred slice. */
  {
    fd_sched_t * sched = new_sched_ext( depth, block_cnt_max, 3UL, FD_MAX_TXN_PER_SLOT );

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
    delete_sched( sched );
  }

  /* Transaction limit: a microblock header declaring more transactions
     than the limit allows rules the block invalid at ingest. */
  {
    fd_sched_t * sched = new_sched_ext( depth, block_cnt_max, FD_SHRED_BLK_MAX, 1UL );

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
    delete_sched( sched );
  }

  /* Microblock limit scales with the shred limit: under 2x shreds a
     batch declaring more microblocks than the 1x limit is accepted,
     one declaring more than the 2x limit rules the block invalid. */
  for( ulong mblk_cnt=FD_SCHED_MAX_MBLK_PER_SLOT+1UL; mblk_cnt<=2UL*FD_SCHED_MAX_MBLK_PER_SLOT+1UL; mblk_cnt+=FD_SCHED_MAX_MBLK_PER_SLOT ) {
    fd_sched_t * sched = new_sched_ext( depth, block_cnt_max, 2UL*FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );

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
    delete_sched( sched );
  }
}

/* Out-of-band LtHash.  The exec tiles' hash values are synthetic.  A
   value is derived from the account, the task kind and a version.  A
   subtraction's version is 0, the parent's value.  An addition's
   version is the number of writes to the account completed so far in
   the block, so an addition applied before the account's last write
   leaves a trace in the delta unless it is undone, and a test knows
   the exact delta a block must end with.

   The blocks are Alpenglow blocks: a header marker, entry batches and a
   footer marker, each its own FEC set, and the alpentick after the
   footer.  Every entry claims the hash seeded by
   TEST_LTHASH_ENTRY_SEED, which the cases bypass verifying, and the
   alpentick chains from it, which is verified.  A call of
   ingest_lthash_fec ingests one entry batch, preceded by the header
   when it is the block's first and followed by the footer and the
   alpentick when it is the block's last, and the cases call that the
   block's first, next or last FEC set. */

#define TEST_LTHASH_ACCT_MAX   (2048UL)
#define TEST_LTHASH_BANK_MAX   (8UL)
#define TEST_LTHASH_ENTRY_SEED (0x7c1d2e3f4a5b6c7dUL)

/* The drain cases use wide blocks.  A wide transaction is a legacy
   transaction writing the most accounts one fits in FD_TXN_MTU, and a
   wide block holds enough of them that its accounts span three drain
   chunks. */
#define TEST_WIDE_TXN_ACCT_CNT (34UL)
#define TEST_WIDE_TXN_CNT      ((2UL*FD_SCHED_LTHASH_DRAIN_CHUNK)/TEST_WIDE_TXN_ACCT_CNT+1UL)
#define TEST_WIDE_ACCT_CNT     (TEST_WIDE_TXN_CNT*TEST_WIDE_TXN_ACCT_CNT)
#define TEST_WIDE_CHUNK_CNT    ((TEST_WIDE_ACCT_CNT+FD_SCHED_LTHASH_DRAIN_CHUNK-1UL)/FD_SCHED_LTHASH_DRAIN_CHUNK)
#define TEST_WIDE_BLOCK_SZ     (sizeof(ulong)+sizeof(fd_microblock_hdr_t)+TEST_WIDE_TXN_CNT*FD_TXN_MTU)
FD_STATIC_ASSERT( TEST_WIDE_CHUNK_CNT==3UL, wide_block_drains_in_three_chunks );

/* The batch cases are laid out for four exec tiles and batches of a few
   accounts with transactions in flight. */
FD_STATIC_ASSERT( FD_SCHED_LTHASH_BATCH_BUSY_MAX>=8UL,                        batch_cases_fit_the_busy_cap  );
FD_STATIC_ASSERT( FD_SCHED_LTHASH_BATCH_BUSY_MAX+3UL<=TEST_WIDE_TXN_ACCT_CNT, batch_cap_case_txn_fits       );
FD_STATIC_ASSERT( FD_SCHED_LTHASH_BATCH_MAX+2UL<=TEST_WIDE_TXN_ACCT_CNT,      batch_held_tail_case_txn_fits );
FD_STATIC_ASSERT( FD_SCHED_LTHASH_BATCH_MAX/3UL+1UL<=TEST_WIDE_TXN_ACCT_CNT,  batch_case_txn_fits           );

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
  ulong          write_cnt[ TEST_LTHASH_BANK_MAX ]; /* writes completed so far, per bank, the version of its next addition */
};
typedef struct test_lthash_acct test_lthash_acct_t;

struct test_lthash_ctx {
  test_lthash_acct_t     acct[ TEST_LTHASH_ACCT_MAX ];
  ulong                  acct_cnt;
  fd_lthash_value_t      handed[ 1 ];     /* every ADD value handed to sched minus every SUB value */
  fd_lthash_value_t      delta[ 1 ];      /* fd_sched_lthash_delta read when BLOCK_END was handed out */
  ulong                  step;
  ulong                  last_lthash_step[ TEST_LTHASH_BANK_MAX ]; /* step of the bank's last LtHash completion */
  ulong                  block_end_step  [ TEST_LTHASH_BANK_MAX ]; /* step BLOCK_END was handed out for the bank */
  ulong                  sub_cnt;        /* accounts subtracted */
  ulong                  add_cnt;        /* accounts added */
  ulong                  sub_task_cnt;   /* subtraction tasks completed, each a batch of accounts */
  ulong                  add_task_cnt;   /* addition tasks completed */
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

/* Whether the state string contains the formatted needle. */
__attribute__((format(printf,2,3)))
static int
lthash_state_has( fd_sched_t * sched,
                  char const * fmt, ... ) {
  char needle[ 512 ];
  va_list ap;
  va_start( ap, fmt );
  int len = vsnprintf( needle, sizeof(needle), fmt, ap );
  va_end( ap );
  FD_TEST( len>=0 && (ulong)len<sizeof(needle) );
  return !!strstr( fd_sched_get_state_cstr( sched ), needle );
}

/* Whether the state string's line of block bank_idx contains the
   formatted needle.  The active block's line comes first and one line
   per lane head follows, so the active block may have two identical
   lines. */
__attribute__((format(printf,3,4)))
static int
lthash_block_line_has( fd_sched_t * sched,
                       ulong        bank_idx,
                       char const * fmt, ... ) {
  char needle[ 512 ];
  va_list ap;
  va_start( ap, fmt );
  int len = vsnprintf( needle, sizeof(needle), fmt, ap );
  va_end( ap );
  FD_TEST( len>=0 && (ulong)len<sizeof(needle) );
  char prefix[ 32 ];
  fd_cstr_printf( prefix, sizeof(prefix), NULL, "block idx %lu, ", bank_idx );
  char * line = strstr( fd_sched_get_state_cstr( sched ), prefix );
  FD_TEST( line );
  char * end   = strchr( line, '\n' );
  char * found = strstr( line, needle );
  FD_TEST( end );
  return found && found<end;
}

/* Whether the state string's line of block bank_idx shows a drain of
   its acct_cnt accounts, each with an entry and a queued subtraction,
   with pop_cnt chunks popped.  The block is draining unless that is
   the whole set. */
static int
lthash_block_drain_line_has( fd_sched_t * sched,
                             ulong        bank_idx,
                             ulong        acct_cnt,
                             ulong        pop_cnt ) {
  ulong created = fd_ulong_min( acct_cnt, pop_cnt*FD_SCHED_LTHASH_DRAIN_CHUNK );
  return lthash_block_line_has( sched, bank_idx, "lthash_in_flight_cnt 0, sub_queued_cnt %lu, sub_in_flight_cnt 0, sub_applied_cnt 0, add_owed_cnt %lu, add_created_cnt %lu, add_surfaced_cnt 0, add_done_cnt 0, add_applied_cnt 0, add_undone_cnt 0,", acct_cnt, acct_cnt-created, created )
      && lthash_block_line_has( sched, bank_idx, "lthash_drained %d, lthash_draining %d", created==acct_cnt, created<acct_cnt );
}

/* Polls a scheduler that has nothing to hand out until block bank_idx,
   whose acct_cnt accounts had pop_cnt chunks of their drain popped, is
   drained.  Each poll pops one chunk. */
static void
lthash_poll_drain( fd_sched_t * sched,
                   ulong        bank_idx,
                   ulong        acct_cnt,
                   ulong        pop_cnt ) {
  fd_sched_task_t task[ 1 ];
  for( ; pop_cnt*FD_SCHED_LTHASH_DRAIN_CHUNK<acct_cnt; pop_cnt++ ) {
    FD_TEST( lthash_block_drain_line_has( sched, bank_idx, acct_cnt, pop_cnt ) );
    FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  }
  FD_TEST( lthash_block_drain_line_has( sched, bank_idx, acct_cnt, pop_cnt ) );
}

/* Records a write to acct in bank_idx, after which the account's next
   addition hashes a later version. */
static void
lthash_write( test_lthash_ctx_t *    ctx,
              ulong                  bank_idx,
              fd_acct_addr_t const * acct ) {
  FD_TEST( bank_idx<TEST_LTHASH_BANK_MAX );
  lthash_acct( ctx, acct )->write_cnt[ bank_idx ]++;
}

/* The value a tile would return for an LtHash task handed out now.  It
   is the sum over the task's accounts of the parent's version for a
   subtraction, or of the account's current version in the bank for an
   addition. */
static void
lthash_task_value( test_lthash_ctx_t *     ctx,
                   fd_sched_task_t const * task,
                   fd_lthash_value_t *     v ) {
  int   is_add   = task->task_type==FD_SCHED_TT_LTHASH_ADD;
  ulong bank_idx = task->lthash->bank_idx;
  FD_TEST( bank_idx<TEST_LTHASH_BANK_MAX );
  FD_TEST( task->lthash->cnt && task->lthash->cnt<=FD_SCHED_LTHASH_BATCH_MAX );
  fd_lthash_zero( v );
  for( ulong i=0UL; i<task->lthash->cnt; i++ ) {
    fd_acct_addr_t const * acct = task->lthash->accts+i;
    test_lthash_acct_t *   a    = lthash_acct( ctx, acct );
    fd_lthash_value_t h[ 1 ];
    fake_hash( h, acct, is_add, is_add ? a->write_cnt[ bank_idx ] : 0UL );
    fd_lthash_add( v, h );
  }
}

/* Completes an LtHash task with value v and records what was handed,
   per account and per task. */
static void
lthash_complete( fd_sched_t *            sched,
                 fd_sched_task_t const * task,
                 test_lthash_ctx_t *     ctx,
                 fd_lthash_value_t *     v ) {
  int   is_add   = task->task_type==FD_SCHED_TT_LTHASH_ADD;
  ulong bank_idx = task->lthash->bank_idx;
  FD_TEST( bank_idx<TEST_LTHASH_BANK_MAX );
  for( ulong i=0UL; i<task->lthash->cnt; i++ ) {
    test_lthash_acct_t * a = lthash_acct( ctx, task->lthash->accts+i );
    if( is_add ) { a->add_cnt[ bank_idx ]++; ctx->add_cnt++; }
    else         { a->sub_cnt[ bank_idx ]++; ctx->sub_cnt++; }
  }
  if( is_add ) { ctx->add_task_cnt++; fd_lthash_add( ctx->handed, v ); }
  else         { ctx->sub_task_cnt++; fd_lthash_sub( ctx->handed, v ); }
  ctx->last_lthash_step[ bank_idx ] = ++ctx->step;
  FD_TEST( 0==fd_sched_task_done( sched, task->task_type, ULONG_MAX, task->lthash->exec_idx, v ) );
}

/* Completes a transaction the way the replay tile would.  Its writable
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
         tile does, because completion frees it.  A block ends only once
         its lane set is drained. */
      ulong bank_idx = task->block_end->bank_idx;
      FD_TEST( bank_idx<TEST_LTHASH_BANK_MAX );
      FD_TEST( lthash_block_line_has( sched, bank_idx, "lthash_drained 1," ) );
      fd_memcpy( ctx->delta, fd_sched_lthash_delta( sched, bank_idx ), sizeof(fd_lthash_value_t) );
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

/* Hands out and completes tasks until the scheduler has nothing
   more. */
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

/* Like lthash_drive, but the first task of hold_type is not completed.
   It stays on its tile and is copied to held, along with the value its
   tile would return, and the drive stops.  The value is computed now
   because the account's version may move on while the task is held.
   Returns 1 if a task was held. */
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

/* Hands out and completes tasks with throwaway results and no account
   bookkeeping until the scheduler hands out nothing, for blocks too
   wide for test_lthash_ctx_t to track. */
static void
drive_untracked( fd_sched_t * sched,
                 ulong        max_steps ) {
  for( ulong i=0UL; i<max_steps; i++ ) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    fd_sched_task_t task[ 1 ];
    if( !fd_sched_task_next_ready( sched, task ) ) break;
    switch( task->task_type ) {
      case FD_SCHED_TT_BLOCK_START:   FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START,   ULONG_MAX,                    ULONG_MAX,                     NULL ) ); break;
      case FD_SCHED_TT_BLOCK_END:     FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END,     ULONG_MAX,                    ULONG_MAX,                     NULL ) ); break;
      case FD_SCHED_TT_TXN_EXEC:      FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC,      task->txn_exec->txn_idx,      task->txn_exec->exec_idx,      NULL ) ); break;
      case FD_SCHED_TT_TXN_SIGVERIFY: FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_SIGVERIFY, task->txn_sigverify->txn_idx, task->txn_sigverify->exec_idx, NULL ) ); break;
      case FD_SCHED_TT_POH_HASH: {
        fd_execrp_poh_hash_done_msg_t msg[ 1 ];
        msg->cnt = task->poh_hash->cnt;
        for( ulong j=0UL; j<msg->cnt; j++ ) repeat_hash( msg->hash+j, task->poh_hash->hash+j, task->poh_hash->hashcnt );
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, task->poh_hash->exec_idx, msg ) );
        break;
      }
      case FD_SCHED_TT_LTHASH_SUB:
      case FD_SCHED_TT_LTHASH_ADD: {
        fd_lthash_value_t v[ 1 ]; fd_lthash_zero( v );
        FD_TEST( !fd_sched_task_done( sched, task->task_type, ULONG_MAX, task->lthash->exec_idx, v ) );
        break;
      }
      default: FD_LOG_ERR(( "unexpected task type %lu", task->task_type ));
    }
  }
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
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
   writable accounts.  The cases bypass lookup table resolution, so the
   scheduler inserts the transaction serializing and flags it
   FD_SCHED_TXN_ALT_UNRESOLVED. */
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

/* One entry batch, a microblock holding the transactions and advancing
   one hash to the claimed entry hash. */
static ulong
encode_lthash_batch( uchar *               encoded,
                     uchar const * const * txn,
                     ulong const *         txn_sz,
                     ulong                 txn_cnt ) {
  FD_TEST( txn_cnt );
  fd_hash_t h[ 1 ]; hash_from_seed( h, TEST_LTHASH_ENTRY_SEED );

  ulong cursor = 0UL;
  FD_STORE( ulong, encoded+cursor, 1UL );
  cursor += sizeof(ulong);
  fd_microblock_hdr_t hdr = { .hash_cnt = 1UL, .txn_cnt = txn_cnt };
  fd_memcpy( hdr.hash, h->hash, sizeof(fd_hash_t) );
  fd_memcpy( encoded+cursor, &hdr, sizeof(hdr) );
  cursor += sizeof(hdr);
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_memcpy( encoded+cursor, txn[ i ], txn_sz[ i ] );
    cursor += txn_sz[ i ];
  }
  return cursor;
}

/* Ingests one FEC set holding a whole batch of block bank_idx and
   returns the scheduler's verdict, 0 if the FEC set ruled the block
   invalid. */
static int
try_ingest_lthash_component( fd_sched_t * sched,
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
  return fd_sched_fec_ingest( sched, fec );
}

/* Ingests the header marker as block bank_idx's first FEC set and
   returns the scheduler's verdict. */
static int
try_ingest_lthash_header( fd_sched_t * sched,
                          ulong        bank_idx,
                          ulong        parent_bank_idx,
                          ulong        slot,
                          ulong        parent_slot ) {
  uchar header[ FD_BLOCK_MARKER_SER_MAX ] __attribute__((aligned(64)));
  ulong header_sz = encode_ag_component( header, AG_COMP_HEADER, NULL );
  return try_ingest_lthash_component( sched, bank_idx, parent_bank_idx, slot, parent_slot, header, header_sz, 1, 0 );
}

/* Ingests the footer marker and then the alpentick, chaining from
   prev_hash, as block bank_idx's last FEC sets and returns the
   scheduler's verdict. */
static int
try_ingest_lthash_end( fd_sched_t *      sched,
                       ulong             bank_idx,
                       ulong             parent_bank_idx,
                       ulong             slot,
                       ulong             parent_slot,
                       fd_hash_t const * prev_hash ) {
  uchar footer[ FD_BLOCK_MARKER_SER_MAX ] __attribute__((aligned(64)));
  ulong footer_sz = encode_ag_component( footer, AG_COMP_FOOTER, NULL );
  if( !try_ingest_lthash_component( sched, bank_idx, parent_bank_idx, slot, parent_slot, footer, footer_sz, 0, 0 ) ) return 0;
  fd_hash_t hash[ 1 ]; *hash = *prev_hash;
  uchar tick[ sizeof(ulong)+sizeof(fd_microblock_hdr_t) ];
  ulong tick_sz = encode_ag_component( tick, AG_COMP_TICK, hash );
  return try_ingest_lthash_component( sched, bank_idx, parent_bank_idx, slot, parent_slot, tick, tick_sz, 0, 1 );
}

/* Ingests the FEC sets of block bank_idx's next components: the header
   if first, the entry batch at data if sz is nonzero, and the footer
   and the alpentick, chaining from the entry hash, if last.  Returns
   0 as soon as one of them rules the block invalid, 1 otherwise. */
static int
try_ingest_lthash_fec( fd_sched_t * sched,
                       ulong        bank_idx,
                       ulong        parent_bank_idx,
                       ulong        slot,
                       ulong        parent_slot,
                       uchar *      data,
                       ulong        sz,
                       int          first,
                       int          last ) {
  if( first && !try_ingest_lthash_header( sched, bank_idx, parent_bank_idx, slot, parent_slot ) ) return 0;
  if( sz && !try_ingest_lthash_component( sched, bank_idx, parent_bank_idx, slot, parent_slot, data, sz, 0, 0 ) ) return 0;
  if( !last ) return 1;
  fd_hash_t h[ 1 ]; hash_from_seed( h, TEST_LTHASH_ENTRY_SEED );
  return try_ingest_lthash_end( sched, bank_idx, parent_bank_idx, slot, parent_slot, h );
}

/* Ingests the FEC sets of block bank_idx's next components, which must
   all be accepted. */
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
  FD_TEST( try_ingest_lthash_fec( sched, bank_idx, parent_bank_idx, slot, parent_slot, data, sz, first, last ) );
}

/* Ingests block bank_idx whole as a header, a footer and the alpentick,
   which chains from start_poh, the parent's end hash. */
static void
ingest_lthash_tick_block( fd_sched_t *      sched,
                          ulong             bank_idx,
                          ulong             parent_bank_idx,
                          ulong             slot,
                          ulong             parent_slot,
                          fd_hash_t const * start_poh ) {
  FD_TEST( try_ingest_lthash_header( sched, bank_idx, parent_bank_idx, slot, parent_slot ) );
  FD_TEST( try_ingest_lthash_end( sched, bank_idx, parent_bank_idx, slot, parent_slot, start_poh ) );
}

static void
lthash_test_keys( fd_pubkey_t * acct_a,
                  fd_pubkey_t * acct_b ) {
  fd_memset( acct_a->uc, 0xa1, sizeof(fd_pubkey_t) );
  fd_memset( acct_b->uc, 0xb2, sizeof(fd_pubkey_t) );
}

/* The expected delta of a bank that wrote the given accounts, each
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

/* Checks the subtractions, additions and writes recorded for acct in
   bank_idx. */
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

/* The out-of-band LtHash counters.  Fields a designated initializer
   leaves out are expected to be zero. */
struct test_lthash_metrics {
  ulong parsed_writable, first_write, coalesced, add_created, spec, entry, sub_dispatched, sub_task, sub_applied, add_surfaced,
        add_surfaced_stale, add_dispatched, add_task, add_dispatched_stale, add_batch_held, add_batch_wait_idle, add_applied, add_undone, spec_applied, spec_stale, frozen;
  uint  start_reg, late_reg, demote_reg, spec_given_up, pool_full, spec_yield,
        discarded_add_owed, discarded_add_pending, discarded_add_held, discarded_sub_queued, discarded_sub_applied, discarded_add_applied,
        inband_add_owed, inband_sub_queued;
};
typedef struct test_lthash_metrics test_lthash_metrics_t;

static void
lthash_check_metrics( fd_sched_t *                  sched,
                      test_lthash_metrics_t const * m ) {
  char expected[ 1536 ];
  fd_cstr_printf( expected, sizeof(expected), NULL,
                  "lthash_parsed_writable_cnt %lu, lthash_start_reg_cnt %u, lthash_late_reg_cnt %u, lthash_demote_reg_cnt %u, lthash_first_write_cnt %lu, lthash_coalesced_cnt %lu, lthash_entry_cnt %lu, lthash_sub_dispatched_cnt %lu, lthash_sub_task_cnt %lu, lthash_sub_applied_cnt %lu, lthash_add_created_cnt %lu, lthash_spec_cnt %lu, lthash_add_surfaced_cnt %lu, lthash_add_surfaced_stale_cnt %lu, lthash_add_dispatched_cnt %lu, lthash_add_task_cnt %lu, lthash_add_dispatched_stale_cnt %lu, lthash_add_batch_held_cnt %lu, lthash_add_batch_wait_idle_cnt %lu, lthash_add_applied_cnt %lu, lthash_add_undone_cnt %lu, lthash_spec_applied_cnt %lu, lthash_spec_stale_cnt %lu, lthash_spec_given_up_cnt %u, lthash_pool_full_cnt %u, lthash_spec_yield_cnt %u, lthash_frozen_cnt %lu, lthash_discarded_add_owed_cnt %u, lthash_discarded_add_pending_cnt %u, lthash_discarded_add_held_cnt %u, lthash_discarded_add_applied_cnt %u, lthash_discarded_sub_queued_cnt %u, lthash_discarded_sub_applied_cnt %u, lthash_inband_add_owed_cnt %u, lthash_inband_sub_queued_cnt %u,",
                  m->parsed_writable, m->start_reg, m->late_reg, m->demote_reg, m->first_write, m->coalesced, m->entry, m->sub_dispatched, m->sub_task, m->sub_applied, m->add_created, m->spec, m->add_surfaced, m->add_surfaced_stale, m->add_dispatched, m->add_task, m->add_dispatched_stale, m->add_batch_held, m->add_batch_wait_idle, m->add_applied, m->add_undone, m->spec_applied, m->spec_stale, m->spec_given_up, m->pool_full, m->spec_yield, m->frozen, m->discarded_add_owed, m->discarded_add_pending, m->discarded_add_held, m->discarded_add_applied, m->discarded_sub_queued, m->discarded_sub_applied, m->inband_add_owed, m->inband_sub_queued );
  char const * state = fd_sched_get_state_cstr( sched );
  if( FD_UNLIKELY( !strstr( state, expected ) ) ) FD_LOG_ERR(( "LtHash metrics mismatch, expected\n  %s in\n  %s", expected, state ));
}

/* One staged block with T1 writing A and T2 writing A and B gets
   exactly one subtraction and one addition per distinct account, the
   delta equals the handed values, and BLOCK_END comes after the last
   LtHash task. */
static void
run_lthash_basic_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL,   0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, acct+1, 1UL, 0x02 );
  uchar const * txns[ 2 ] = { t1, t2 };
  ulong txn_sz[ 2 ] = { t1_sz, t2_sz };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 2UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x6d2f1a8b3c4e5f60UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  lthash_drive( sched, ctx, 1000UL );

  FD_TEST( fd_sched_is_drained( sched ) );
  FD_TEST( ctx->txn_exec_cnt==2UL );
  FD_TEST( ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==2UL && ctx->sub_cnt==2UL && ctx->add_cnt==2UL ); /* no account other than A and B */
  lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 2UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  FD_TEST( !fd_lthash_is_zero( ctx->delta ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( ctx->last_lthash_step[ 2 ] && ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  /* T2's write of A rode on T1's pending pop. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=3UL, .first_write=2UL, .coalesced=1UL, .add_created=2UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=1UL, .sub_applied=2UL, .add_surfaced=2UL, .add_dispatched=2UL, .add_task=1UL, .add_applied=2UL, .frozen=2UL } );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* A subtraction and an addition are on the tiles when the block is
   abandoned.  Their results come back without effect, the tiles are
   freed, and the block is released once the last one lands, whichever
   kind that is. */
static void
run_lthash_abandon_in_flight_case( int last_is_add ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL, 0UL, 0x01 );
  uchar const * txns[ 1 ] = { t1 };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, &t1_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x0b1c2d3e4f506172UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  lthash_drive_task( sched, task, ctx );

  /* Hold T1 and the subtraction of A on their tiles, and complete the
     PoH and sigverify tasks as they come.  The addition of A is
     pending behind T1 and cannot surface yet. */
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
  FD_TEST( pending[ sub_at ].lthash->cnt==1UL && !memcmp( pending[ sub_at ].lthash->accts[ 0 ].b, acct[ 0 ].uc, sizeof(fd_acct_addr_t) ) );

  /* Completing T1 readies the addition, which takes a free tile.  With
     both hashes out, nothing else can be handed out, and BLOCK_END
     waits on them. */
  lthash_drive_task( sched, pending+exec_at, ctx );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD );
  FD_TEST( task->lthash->cnt==1UL && !memcmp( task->lthash->accts[ 0 ].b, acct[ 0 ].uc, sizeof(fd_acct_addr_t) ) );
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
  /* Both results landed in the delta before the block was released,
     and went with it. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=1UL, .first_write=1UL, .add_created=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=1UL, .add_dispatched=1UL, .add_task=1UL, .add_applied=1UL, .discarded_sub_applied=1UL, .discarded_add_applied=1UL } );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "block_abandoned_cnt 1," ) );

  delete_sched( sched );
}

/* A partial head block subtracts A early and speculates its addition,
   is demoted when every lane is squatted and a new block needs one,
   and is promoted back when its last FEC set arrives.  Demotion
   rolls its LtHash progress back, so after promotion it re-derives.
   A is subtracted again, but the delta holds exactly one subtraction
   and one addition per account, at the final version. */
static void
run_lthash_demote_promote_case( void ) {
  fd_sched_t * sched = new_sched( 8UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL,   0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, acct+1, 1UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x91b53d8a74f2c601UL );
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );

  /* Block 2 takes lane 0 with T1 and runs BLOCK_START, T1, PoH,
     sigverify and the early subtraction of A.  Then, alone in its lane
     with nothing left to do, it speculates an addition of A before it
     runs dry. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 1UL );
  FD_TEST( fd_sched_is_drained( sched ) );

  /* Blocks 3-5 squat the other lanes with their headers. */
  for( ulong bank_idx=3UL; bank_idx<=5UL; bank_idx++ ) {
    ingest_lthash_fec( sched, bank_idx, 1UL, TEST_ROOT_SLOT+bank_idx-1UL, TEST_ROOT_SLOT, NULL, 0UL, 1, 0 );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
    lthash_drive( sched, ctx, 100UL );
  }
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "staged_bitset 15," ) );

  /* Block 6 finds no lane free but every head idle, so it takes the
     lowest lane, block 2's, whose map is cleared as block 6 claims it.
     Block 2 goes unstaged with its progress rolled back. */
  ingest_lthash_fec( sched, 6UL, 1UL, TEST_ROOT_SLOT+5UL, TEST_ROOT_SLOT, NULL, 0UL, 1, 0 );
  fd_sched_set_poh_params( sched, 6UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 6, staged_bitset 15," ) );
  FD_TEST( strstr( state, "staged_head_idx[0] 6, staged_head_idx[1] 3," ) );
  FD_TEST( strstr( state, "block_demoted_cnt 1," ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && ctx->add_cnt==1UL );

  /* Block 2's last FEC set, with T2 writing A and B, lands unstaged.
     No lane is free and every head is idle, so the four squatters are
     demoted and block 2 is promoted onto lane 0.  It drains,
     re-subtracts A, subtracts B, adds both and ends. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 1," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 1, block_demoted_cnt 5," ) );
  FD_TEST( strstr( state, "txn_promoted_cnt 1," ) );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==2UL && ctx->sub_cnt==3UL && ctx->add_cnt==3UL );
  lthash_check_acct( ctx, 2UL, acct,   2UL, 2UL, 2UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  /* The rolled back subtraction and speculative addition of A were
     handed out but are not in the delta. */
  FD_TEST( !fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  /* Demotion discarded A's subtraction and guessed addition and put A
     back into the set, where T2's write then found it. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=3UL, .demote_reg=1UL, .first_write=3UL, .coalesced=1UL, .add_created=3UL, .spec=1UL, .entry=3UL, .sub_dispatched=3UL, .sub_task=2UL, .sub_applied=3UL, .add_surfaced=3UL, .add_dispatched=3UL, .add_task=2UL, .add_applied=3UL, .spec_applied=1UL, .frozen=2UL, .discarded_sub_applied=1UL, .discarded_add_applied=1UL } );

  delete_sched( sched );
}

/* Out-of-band hashing is reserved per block when it commits, at its
   first drain or its BLOCK_START.  With room for one block, block 2
   takes it.  Block 3, a fork off the root, starts in band.  Its writer
   leaves the dispatcher's set, it owes no subtraction or addition, and
   it ends with an empty delta.  Block 2's end frees the reservation
   and block 4 hashes out of band again. */
static void
run_lthash_inband_fallback_case( void ) {
  fd_sched_t * sched = new_sched( 8UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_set_lthash_oob_block_max( sched, 1UL );

  fd_pubkey_t acct[ 3 ];
  uchar       encoded[ 3 ][ 8192 ];
  ulong       sz[ 3 ];
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( acct[ i ].uc, 0xd1+(int)i, sizeof(fd_pubkey_t) );
    uchar txn[ FD_TXN_MTU ]; ulong txn_sz = build_lthash_test_txn( txn, acct+i, NULL, 0UL, (uchar)(0x20UL+i) );
    uchar const * txns[ 1 ] = { txn };
    sz[ i ] = encode_lthash_batch( encoded[ i ], txns, &txn_sz, 1UL );
  }
  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x3b8e1f6a9c2d4705UL );
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];

  /* Block 2 takes the one reservation at its BLOCK_START and runs T1,
     a subtraction and a speculative addition. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded[ 0 ], sz[ 0 ], 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==2UL && !task->block_start->lthash_inband );
  lthash_drive_task( sched, task, ctx );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL );
  FD_TEST( lthash_block_line_has( sched, 2UL, "lthash_mode_picked 1, lthash_inband 0," ) );

  /* Block 3 finds no reservation at its BLOCK_START.  The writer T2
     declared leaves the dispatcher's set and the lane map.  T2 runs
     with no LtHash task and the switch is counted. */
  ingest_lthash_fec( sched, 3UL, 1UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT, encoded[ 1 ], sz[ 1 ], 1, 0 );
  fd_sched_set_poh_params( sched, 3UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  FD_TEST( lthash_block_line_has( sched, 3UL, "add_owed_cnt 1," ) );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==3UL && task->block_start->lthash_inband );
  FD_TEST( lthash_block_line_has( sched, 3UL, "add_owed_cnt 0," ) );
  FD_TEST( lthash_block_line_has( sched, 3UL, "lthash_mode_picked 1, lthash_inband 1," ) );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=2UL, .entry=2UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_created=1UL, .spec=1UL, .add_surfaced=1UL, .add_dispatched=1UL, .add_task=1UL, .add_applied=1UL, .spec_applied=1UL, .inband_add_owed=1UL, .inband_sub_queued=1UL } );
  FD_TEST( lthash_state_has( sched, "lthash_inband_block_cnt 1," ) );
  lthash_drive_task( sched, task, ctx );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL );

  /* Block 3's last FEC set ends it with an empty delta.  Block 2's
     ends it out of band and frees the reservation. */
  ingest_lthash_fec( sched, 3UL, 1UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT, NULL, 0UL, 0, 1 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->block_end_cnt==1UL && ctx->block_end_step[ 3 ] && fd_lthash_is_zero( ctx->delta ) );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, NULL, 0UL, 0, 1 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->block_end_cnt==2UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );

  /* Block 4 takes the freed reservation. */
  ingest_lthash_fec( sched, 4UL, 1UL, TEST_ROOT_SLOT+3UL, TEST_ROOT_SLOT, encoded[ 2 ], sz[ 2 ], 1, 0 );
  fd_sched_set_poh_params( sched, 4UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==4UL && !task->block_start->lthash_inband );
  lthash_drive_task( sched, task, ctx );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==3UL && ctx->sub_cnt==2UL && ctx->add_cnt==2UL );

  delete_sched( sched );
}

/* Writes the dispatcher did not see through a transaction.  Start-of-
   block processing reports them with fd_sched_block_start_writes while
   BLOCK_START is outstanding.  A is also written by T1, and S by
   nothing else.  In mode 0 the block is still receiving FEC sets, so A
   is in the lane set with nothing to do and S enters it.  Both are
   speculated once the subtractions are done, and the tick that ends
   the block finds nothing left to drain.  In mode 1 the block drained
   before BLOCK_START, so A had been popped.  Its addition goes stale
   and a re-drain pops A and S again.  In mode 2 a child with T3
   writing A has taken the next lane meanwhile.  The block, alone on
   its own lane, stays insert ready, so the registrations re-drain as
   in mode 1, and the child speculates on A once it runs.  In mode 3 S
   enters the set at registration and the block's last FEC set, with
   T2 writing S, arrives before any transaction is dispatched.  S's one
   addition comes after T2.  Every mode ends with exactly one
   subtraction and one addition per account of the block.  In mode 2
   the child then speculates on A again. */
static void
run_lthash_block_start_writes_case( int mode ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ]; /* A, S */
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,   NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+1, NULL, 0UL, 0x02 );
  uchar const * txns[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded[ 8192 ];
  uchar encoded2[ 8192 ];
  int   first_is_last = mode!=0 && mode!=3;
  ulong sz  = encode_lthash_batch( encoded,  txns,  &t1_sz, 1UL );
  ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x3a4b5c6d7e8f9011UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, first_is_last );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  int child = mode==2;
  if( child ) {
    uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, acct, NULL, 0UL, 0x03 );
    uchar const * txns3[ 1 ] = { t3 };
    uchar encoded3[ 8192 ]; ulong sz3 = encode_lthash_batch( encoded3, txns3, &t3_sz, 1UL );
    ingest_lthash_fec( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL, encoded3, sz3, 1, 0 );
    fd_sched_set_poh_params( sched, 3UL, TEST_ROOT_TICK_HEIGHT+1UL, TEST_ROOT_TICK_HEIGHT+2UL, start_poh );
    char * state = fd_sched_get_state_cstr( sched );
    FD_TEST( strstr( state, "active_idx 2, staged_bitset 3," ) );
  }

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==2UL );
  fd_sched_block_start_writes( sched, 2UL, fd_type_pun_const( acct ), 2UL );
  lthash_write( ctx, 2UL, fd_type_pun_const( acct   ) );
  lthash_write( ctx, 2UL, fd_type_pun_const( acct+1 ) );
  lthash_drive_task( sched, task, ctx );
  if( mode==3 ) {
    /* The last FEC set arrives after start-of-block processing and
       before any transaction is dispatched.  T2 writes S, which the
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
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, NULL, 0UL, 0, 1 );
    lthash_drive( sched, ctx, 100UL );
  }

  FD_TEST( ctx->txn_exec_cnt==fd_ulong_if( child || mode==3, 2UL, 1UL ) ); /* the child's T3 runs after the block ends */
  FD_TEST( ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==2UL );
  FD_TEST( ctx->sub_cnt==fd_ulong_if( child, 3UL, 2UL ) && ctx->add_cnt==fd_ulong_if( child, 3UL, 2UL ) );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 2UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, fd_ulong_if( mode==3, 2UL, 1UL ) ); /* in mode 3, S's one addition comes after T2 */
  if( child ) lthash_check_acct( ctx, 3UL, acct, 1UL, 1UL, 1UL ); /* speculated by the child once it runs */
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  if( !child ) FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  /* In modes 1 and 2 the addition A got at the drain was stale by the
     time it surfaced and the re-drain created another.  In mode 2 the
     child's own speculation is in the totals.  In modes 0 and 3 the
     registration of A, and in mode 3 T2's write of S, found the
     account in the set.  S's addition is READY from the start in mode
     1 and together with A's in mode 3, but the dispatcher hands out the
     READY transactions first, so the block's additions go out in one
     batch after its last transaction and no batch is held. */
  test_lthash_metrics_t const expected_metrics[ 4 ] = {
    { .parsed_writable=1UL, .start_reg=2UL, .first_write=2UL, .coalesced=1UL, .add_created=2UL, .spec=2UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=1UL, .sub_applied=2UL, .add_surfaced=2UL, .add_dispatched=2UL, .add_task=2UL, .add_applied=2UL, .spec_applied=2UL, .frozen=2UL },
    { .parsed_writable=1UL, .start_reg=2UL, .first_write=3UL, .add_created=3UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=1UL, .sub_applied=2UL, .add_surfaced=3UL, .add_surfaced_stale=1UL, .add_dispatched=2UL, .add_task=1UL, .add_applied=2UL, .frozen=2UL },
    { .parsed_writable=2UL, .start_reg=2UL, .first_write=4UL, .add_created=4UL, .spec=1UL, .entry=3UL, .sub_dispatched=3UL, .sub_task=2UL, .sub_applied=3UL, .add_surfaced=4UL, .add_surfaced_stale=1UL, .add_dispatched=3UL, .add_task=2UL, .add_applied=3UL, .spec_applied=1UL, .frozen=2UL },
    { .parsed_writable=2UL, .start_reg=2UL, .first_write=2UL, .coalesced=2UL, .add_created=2UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=1UL, .sub_applied=2UL, .add_surfaced=2UL, .add_dispatched=2UL, .add_task=1UL, .add_applied=2UL, .frozen=2UL },
  };
  lthash_check_metrics( sched, expected_metrics+mode );

  delete_sched( sched );
}

/* Re-speculation after a stop, over three FEC sets.  FEC1, not the
   last, has T1 writing A.  After T1 the block speculates A.  The next
   pop finds the lane set empty, so speculation stops and the block,
   with nothing in flight, is deactivated.  A poll then hands out
   nothing while the block stays the lane head, undrained.  FEC2, not
   the last either, has T2 writing B.  Its parse bit lifts the stop,
   and after T2 the block speculates B and stops again.  FEC3, the
   last, has T3 writing A.  The applied guess for A is undone and A is
   added again after T3, while B's guess stands.  The delta is exact
   over A and B, and the handed values also hold the undone guess. */
static void
run_lthash_respeculate_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ]; /* A, B */
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,   NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+1, NULL, 0UL, 0x02 );
  uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, acct,   NULL, 0UL, 0x03 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar const * txns3[ 1 ] = { t3 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL );
  uchar encoded3[ 8192 ]; ulong sz3 = encode_lthash_batch( encoded3, txns3, &t3_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x7a8b9cadbecfd0e1UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  lthash_drive( sched, ctx, 100UL );

  /* The guess for A was hashed, then the set ran dry.  With nothing in
     flight the block was deactivated, still the lane head and not
     drained. */
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 1UL );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_is_drained( sched ) );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 18446744073709551615, staged_bitset 1, staged_head_idx[0] 2," ) );
  FD_TEST( strstr( state, "fec_eos 0," ) );
  FD_TEST( strstr( state, "add_owed_cnt 0," ) && strstr( state, "lthash_drained 0, lthash_draining 0" ) );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=1UL, .first_write=1UL, .add_created=1UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=1UL, .add_dispatched=1UL, .add_task=1UL, .add_applied=1UL, .spec_applied=1UL } );

  /* FEC2 revives the block: T2 runs, B is speculated, and the block
     runs dry again. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 0 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->sub_cnt==2UL && ctx->add_cnt==2UL && !ctx->block_end_cnt );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_is_drained( sched ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "add_owed_cnt 0," ) && strstr( state, "lthash_drained 0, lthash_draining 0" ) );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=2UL, .add_created=2UL, .spec=2UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=2UL, .sub_applied=2UL, .add_surfaced=2UL, .add_dispatched=2UL, .add_task=2UL, .add_applied=2UL, .spec_applied=2UL } );

  /* FEC3 has T3 writing A again, so the guess for A is undone and A is
     added once more after T3.  B's guess stands. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded3, sz3, 0, 1 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==3UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==2UL && ctx->sub_cnt==2UL && ctx->add_cnt==3UL );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 2UL, 2UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  fd_lthash_value_t guess[ 1 ]; fake_hash( guess, fd_type_pun_const( acct ), 1, 1UL );
  fd_lthash_add( expected, guess );
  FD_TEST( !fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( fd_lthash_eq( ctx->handed, expected ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  /* T3's write of A undid the applied guess.  The drain added A again. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=3UL, .first_write=3UL, .add_created=3UL, .spec=2UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=2UL, .sub_applied=2UL, .add_surfaced=3UL, .add_dispatched=3UL, .add_task=3UL, .add_applied=3UL, .add_undone=1UL, .spec_applied=2UL, .frozen=2UL } );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* A speculative addition that is PENDING behind its writer when the
   account is written again.  T1 writes A and is held on its tile.  The
   block speculates A, but the guess waits on T1 and no addition is
   handed out.  FEC2, with T2 writing A, arrives before T1 completes,
   and T2's parse bit clears the guess's ticket and frees its slot.
   Once T1 completes the stale guess surfaces and is completed without
   hashing.  A is added once, after T2, at the final version.  With
   fec2_last, FEC2 ends the block and the drain pops A again.
   Otherwise the block speculates A again after T2, runs dry, and an
   empty last FEC set ends it. */
static void
run_lthash_pending_rewrite_case( int fec2_last ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, NULL, 0UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x4c5d6e7f8091a2b3UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t held[ 1 ]; fd_lthash_value_t unused[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, held, unused ) );
  /* PoH, sigverify and the subtraction run around T1.  The speculative
     pop happens, but the guess is PENDING behind T1. */
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && !ctx->txn_exec_cnt );
  FD_TEST( !fd_sched_is_drained( sched ) );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=1UL, .first_write=1UL, .add_created=1UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL } );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "sub_queued_cnt 0, sub_in_flight_cnt 0, sub_applied_cnt 1, add_owed_cnt 0, add_created_cnt 1, add_surfaced_cnt 0, add_done_cnt 0, add_applied_cnt 0, add_undone_cnt 0" ) );

  /* T2 arrives while the guess is pending.  Its PoH and sigverify
     run, and T2 itself waits on T1. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, fec2_last );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( !ctx->txn_exec_cnt && !ctx->add_cnt && !ctx->block_end_cnt );

  /* T1 completes.  The stale guess surfaces and is completed without
     hashing, then T2 runs and A is added at version 2. */
  lthash_drive_task( sched, held, ctx );
  lthash_drive( sched, ctx, 100UL );
  if( !fec2_last ) {
    FD_TEST( ctx->txn_exec_cnt==2UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
    FD_TEST( fd_sched_is_drained( sched ) );
    /* The first guess surfaced stale.  The second was applied. */
    lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=2UL, .add_created=2UL, .spec=2UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=2UL, .add_surfaced_stale=1UL, .add_dispatched=1UL, .add_task=1UL, .add_applied=1UL, .spec_stale=1UL, .spec_applied=1UL } );
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, NULL, 0UL, 0, 1 );
    lthash_drive( sched, ctx, 100UL );
  }

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 2UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) ); /* nothing was hashed in vain */
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  /* With fec2_last the second addition came from the drain, otherwise
     from a second guess. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=2UL, .add_created=2UL, .spec=fd_ulong_if( fec2_last, 1UL, 2UL ), .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=2UL, .add_surfaced_stale=1UL, .add_dispatched=1UL, .add_task=1UL, .add_applied=1UL, .spec_stale=1UL, .spec_applied=fd_ulong_if( fec2_last, 0UL, 1UL ), .frozen=1UL } );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* Two lookup table transactions in one drained block.  S1 and S2 are
   version 0 transactions whose tables cannot be resolved at parse,
   since resolution is bypassed, so both are inserted serializing, and
   both hand back X as a writable lookup table account on completion.
   S1's registration queues X's subtraction and drains an addition,
   which the serializing S2 walls off.  S2's registration makes that
   addition stale and drains another.  X ends with exactly one
   subtraction and one hashed addition, after S2, at the final version.
   P1 and P2 are the payers. */
static void
run_lthash_two_late_alt_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_set_bypass_alut_resolution( sched, 1 );

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
  uchar encoded[ 8192 ]; ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 2UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x6e7f8091a2b3c4d5UL );
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  ctx->late_alts    = late;
  ctx->late_alt_cnt = 1UL;
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==3UL && ctx->sub_cnt==3UL && ctx->add_cnt==3UL );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 2UL, acct+2, 1UL, 1UL, 2UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 3UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "alut_serializing_cnt 2," ) );
  /* The payers are the only writes the parser could hand over.  Each
     registration of X entered the set and was drained.  S2's made S1's
     addition stale. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .late_reg=2UL, .first_write=4UL, .add_created=4UL, .entry=3UL, .sub_dispatched=3UL, .sub_task=1UL, .sub_applied=3UL, .add_surfaced=4UL, .add_surfaced_stale=1UL, .add_dispatched=3UL, .add_task=1UL, .add_applied=3UL, .frozen=3UL } );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* Speculation.  Block 2's first FEC set has T1 writing A and is not
   the last.  Once T1, PoH, sigverify and the subtraction of A are done
   nothing is in flight, yet the block, alone in its lane and still
   receiving FEC sets, stays active and guesses that A's last write has
   happened.  An addition of A at version 1 is handed out and applied,
   and only then does the block run dry.  The second FEC set, with T2
   writing A, proves the guess wrong.  The addition is undone through
   its hash slot and A is added again after T2.  The delta is exactly
   -sub(A)+add(A,2), and the handed values also hold add(A,1).  With
   hold_writer, T1 is still on its tile when the block speculates.  The
   pseudo transaction is created but not READY, speculation pauses, and
   the addition surfaces once T1 completes. */
static void
run_lthash_speculate_case( int hold_writer ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, NULL, 0UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x5e6f708192a3b4c5UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  if( hold_writer ) {
    fd_sched_task_t held[ 1 ]; fd_lthash_value_t unused[ 1 ];
    FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, held, unused ) );
    /* PoH, sigverify and the subtraction run around T1.  The
       speculative pop happens too, but its addition waits on T1. */
    lthash_drive( sched, ctx, 100UL );
    FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && !ctx->txn_exec_cnt );
    lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=1UL, .first_write=1UL, .add_created=1UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL } );
    FD_TEST( !fd_sched_is_drained( sched ) );
    lthash_drive_task( sched, held, ctx );
  }
  lthash_drive( sched, ctx, 100UL );

  /* The guess was hashed before the block ran dry. */
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 1UL );
  FD_TEST( fd_sched_is_drained( sched ) ); /* nothing left to guess at until the next FEC set */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=1UL, .first_write=1UL, .add_created=1UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=1UL, .add_dispatched=1UL, .add_task=1UL, .add_applied=1UL, .spec_applied=1UL } );

  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==2UL );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 2UL, 2UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  /* The handed values hold the undone guess on top of the delta. */
  fd_lthash_value_t guess[ 1 ]; fake_hash( guess, fd_type_pun_const( acct ), 1, 1UL );
  fd_lthash_add( expected, guess );
  FD_TEST( !fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( fd_lthash_eq( ctx->handed, expected ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  /* T2's write undid the applied guess.  The drain added A again. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=2UL, .add_created=2UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=2UL, .add_dispatched=2UL, .add_task=2UL, .add_applied=2UL, .add_undone=1UL, .spec_applied=1UL, .frozen=1UL } );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* A speculative addition still on its tile when its account is written
   again.  T2's bit at parse clears the addition's ticket and frees its
   slot.  T2 itself waits on the dispatched pseudo transaction, which
   the none-READY check tolerates.  The result is dropped on arrival and
   never touches the delta, and A is added again after T2. */
static void
run_lthash_spec_result_dropped_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, NULL, 0UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x19d2e3f4a5b6c7d8UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t held[ 1 ]; fd_lthash_value_t held_value[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_LTHASH_ADD, held, held_value ) );
  /* A speculative addition is alone in its task. */
  FD_TEST( held->lthash->cnt==1UL && !memcmp( held->lthash->accts[ 0 ].b, acct[ 0 ].uc, sizeof(fd_acct_addr_t) ) );
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && !ctx->add_cnt );

  /* T2 arrives while the guess is on the tile.  Its PoH and sigverify
     run, and T2 waits on the pseudo transaction. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==1UL && !ctx->add_cnt && !ctx->block_end_cnt );

  /* The stale result lands and is dropped. */
  lthash_complete( sched, held, ctx, held_value );
  /* The guess was on a tile when T2's write made it stale.  The
     replacement from the drain waits behind T2. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=2UL, .add_created=2UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=1UL, .add_dispatched=1UL, .add_task=1UL, .add_dispatched_stale=1UL, .spec_stale=1UL } );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==1UL && ctx->sub_cnt==1UL && ctx->add_cnt==2UL );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 2UL, 2UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  fd_lthash_value_t guess[ 1 ]; fake_hash( guess, fd_type_pun_const( acct ), 1, 1UL );
  FD_TEST( fd_lthash_eq( held_value, guess ) );
  fd_lthash_add( expected, guess );
  FD_TEST( !fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( fd_lthash_eq( ctx->handed, expected ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=2UL, .add_created=2UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=2UL, .add_dispatched=2UL, .add_task=2UL, .add_dispatched_stale=1UL, .add_applied=1UL, .spec_stale=1UL, .frozen=1UL } );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* A speculative addition that waited on its writer surfaces when the
   idle rule would not let it onto a tile.  T1's completion leaves one
   idle tile while the other three hold PoH and sigverify tasks, and
   no transaction is in flight.  The speculation is given up.  A goes
   back as written and the surfaced pseudo transaction is completed
   without hashing.  The last FEC set's drain adds A the regular way,
   so A is hashed once each way and the handed values equal the
   delta. */
static void
run_lthash_spec_given_up_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ];
  lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,   NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+1, NULL, 0UL, 0x02 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x5e6f708192a3b4c5UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t held_t1[ 1 ]; fd_sched_task_t held_t2[ 1 ]; fd_sched_task_t held[ 3 ]; fd_lthash_value_t unused[ 1 ];
  /* T1 on its tile and its PoH task on a second.  Sigverify and the
     subtraction run on the other two, and then the block speculates on
     A, whose pseudo transaction waits on T1. */
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, held_t1, unused ) );
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_POH_HASH, held,    unused ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && !ctx->txn_exec_cnt );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=1UL, .first_write=1UL, .add_created=1UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL } );

  /* T2, writing B, runs and completes while T1 is still out.  Its PoH
     and sigverify tasks take the last two idle tiles. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 0 );
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC,      held_t2, unused ) );
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_POH_HASH,      held+1,  unused ) );
  lthash_drive_task( sched, held_t2, ctx );
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_SIGVERIFY, held+2,  unused ) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );

  /* T1 completes.  The addition surfaces with one idle tile and no
     transaction in flight, so it is given up. */
  lthash_drive_task( sched, held_t1, ctx );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->sub_cnt==1UL && !ctx->add_cnt );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=3UL, .add_created=1UL, .spec=1UL, .entry=2UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .add_surfaced=1UL, .spec_given_up=1U } );

  for( ulong i=0UL; i<3UL; i++ ) lthash_drive_task( sched, held+i, ctx );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, NULL, 0UL, 0, 1 );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==2UL && ctx->sub_cnt==2UL && ctx->add_cnt==2UL );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) ); /* nothing speculative was hashed */
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=3UL, .add_created=3UL, .spec=1UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=2UL, .sub_applied=2UL, .add_surfaced=3UL, .add_dispatched=2UL, .add_task=1UL, .add_applied=2UL, .spec_given_up=1U, .frozen=2UL } );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* A speculative addition that surfaces once the block is complete is
   given up whatever the idle tiles, and its addition is created again
   on the spot.  T1, writing A, is held on its tile and the block
   speculates on A behind it.  The last FEC set, T2 writing B and the
   tick, completes the block.  Its drain adds B the regular way and T2
   runs to its end.  With child set, block 3 has taken the next lane
   meanwhile, and block 2, alone on its own, stays insert ready.  T1's
   completion surfaces A's speculation with three idle tiles.  It is
   given up, A goes back into the set, a re-drain creates its addition
   again behind every transaction, it is hashed once, and the handed
   values equal the delta. */
static void
run_lthash_spec_given_up_complete_case( int child ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 3 ]; /* A, B, and C written in block 3 */
  lthash_test_keys( acct, acct+1 );
  fd_memset( acct[ 2 ].uc, 0xd4, sizeof(fd_pubkey_t) );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,   NULL, 0UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+1, NULL, 0UL, 0x02 );
  uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, acct+2, NULL, 0UL, 0x03 );
  uchar const * txns1[ 1 ] = { t1 };
  uchar const * txns2[ 1 ] = { t2 };
  uchar const * txns3[ 1 ] = { t3 };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &t2_sz, 1UL );
  uchar encoded3[ 8192 ]; ulong sz3 = encode_lthash_batch( encoded3, txns3, &t3_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x6f708192a3b4c5d6UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  /* T1 on its tile.  The rest of the first FEC set runs, and then the
     block speculates on A, behind T1. */
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t held_t1[ 1 ]; fd_lthash_value_t unused[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, held_t1, unused ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && !ctx->txn_exec_cnt );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=1UL, .first_write=1UL, .add_created=1UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL } );

  /* The last FEC set completes the block.  Its drain adds B, T2 runs
     and completes and B is hashed, while A's speculation still waits
     on T1. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 1 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==2UL && ctx->add_cnt==1UL && !ctx->block_end_cnt );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=2UL, .add_created=2UL, .spec=1UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=2UL, .sub_applied=2UL, .add_surfaced=1UL, .add_dispatched=1UL, .add_task=1UL, .add_applied=1UL } );
  if( child ) {
    ingest_lthash_fec( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL, encoded3, sz3, 1, 1 );
    fd_sched_set_poh_params( sched, 3UL, TEST_ROOT_TICK_HEIGHT+1UL, TEST_ROOT_TICK_HEIGHT+2UL, start_poh );
    char * state = fd_sched_get_state_cstr( sched );
    FD_TEST( strstr( state, "active_idx 2, staged_bitset 3," ) );
  }

  /* T1 completes and A's speculation surfaces with three idle tiles
     and the block complete.  It is given up, A's addition is created
     again, hashed, and block 2 ends.  With child, block 3 follows. */
  lthash_drive_task( sched, held_t1, ctx );
  lthash_drive( sched, ctx, 100UL );

  ulong c = (ulong)!!child;
  FD_TEST( ctx->txn_exec_cnt==2UL+c && ctx->block_end_cnt==1UL+c );
  FD_TEST( ctx->acct_cnt==2UL+c && ctx->sub_cnt==2UL+c && ctx->add_cnt==2UL+c );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  if( child ) lthash_check_acct( ctx, 3UL, acct+2, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ];
  if( !child ) lthash_expected_delta( expected, ctx, 2UL, acct,   2UL );
  else         lthash_expected_delta( expected, ctx, 3UL, acct+2, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  if( !child ) FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) ); /* nothing speculative was hashed */
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL+c, .first_write=3UL+c, .add_created=3UL+c, .spec=1UL, .entry=2UL+c, .sub_dispatched=2UL+c, .sub_task=2UL+c, .sub_applied=2UL+c, .add_surfaced=3UL+c, .add_dispatched=2UL+c, .add_task=2UL+c, .add_applied=2UL+c, .frozen=2UL+c, .spec_given_up=1U } );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* Late registration.  S is a version 0 transaction whose lookup table
   cannot be resolved at parse, since resolution is bypassed, so it is
   inserted serializing with FD_SCHED_TXN_ALT_UNRESOLVED and the
   dispatcher knows none of its lookup table accounts.  Completing S
   hands back A and X as its writable lookup table accounts, as the
   exec tile would.  T1 is a legacy transaction writing A, nothing else
   writes X, and S's payer P is a static write.  Without speculate, T1
   and S arrive in one FEC set.  A's drained addition predates S, so
   the registration makes it stale, completed without hashing, and a
   new one follows S.  With speculate, T1 arrives first and A's
   addition is speculated and applied before S arrives, and the
   registration undoes it.  Either way A, P and X each end with exactly
   one subtraction and one hashed addition at the final version. */
static void
run_lthash_late_alt_case( int speculate ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_set_bypass_alut_resolution( sched, 1 );

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
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  ctx->late_alts    = late;
  ctx->late_alt_cnt = 2UL;

  if( !speculate ) {
    uchar const * txns[ 2 ] = { t1, s };
    ulong txn_sz[ 2 ] = { t1_sz, s_sz };
    uchar encoded[ 8192 ]; ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 2UL );
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
    fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  } else {
    uchar const * txns1[ 1 ] = { t1 };
    uchar const * txns2[ 1 ] = { s };
    uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, &t1_sz, 1UL );
    uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, &s_sz,  1UL );
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
    fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
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
  /* S's registration of A undid the applied guess, or made the drained
     addition stale.  X entered the set at registration. */
  lthash_check_metrics( sched, speculate ? &(test_lthash_metrics_t){ .parsed_writable=2UL, .late_reg=2UL, .first_write=4UL, .add_created=4UL, .spec=1UL, .entry=3UL, .sub_dispatched=3UL, .sub_task=2UL, .sub_applied=3UL, .add_surfaced=4UL, .add_dispatched=4UL, .add_task=2UL, .add_applied=4UL, .add_undone=1UL, .spec_applied=1UL, .frozen=3UL }
                                        : &(test_lthash_metrics_t){ .parsed_writable=2UL, .late_reg=2UL, .first_write=4UL, .add_created=4UL, .entry=3UL, .sub_dispatched=3UL, .sub_task=1UL, .sub_applied=3UL, .add_surfaced=4UL, .add_surfaced_stale=1UL, .add_dispatched=3UL, .add_task=1UL, .add_applied=3UL, .frozen=3UL } );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* Ingests one block of three transactions, each writing per_txn
   distinct accounts, in one entry batch, so the block drains at
   ingest and owes 3*per_txn subtractions and as many additions.
   Hands out and completes BLOCK_START. */
static void
lthash_batch_setup( fd_sched_t *        sched,
                    test_lthash_ctx_t * ctx,
                    fd_pubkey_t *       acct,
                    ulong               per_txn ) {
  fd_sched_set_bypass_poh_verify( sched, 1 );

  for( ulong i=0UL; i<3UL*per_txn; i++ ) fd_memset( acct[ i ].uc, (int)(0xa1UL+i), sizeof(fd_pubkey_t) );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,             acct+1,             per_txn-1UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+per_txn,     acct+per_txn+1UL,   per_txn-1UL, 0x02 );
  uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, acct+2UL*per_txn, acct+2UL*per_txn+1UL, per_txn-1UL, 0x03 );
  uchar const * txns[ 3 ] = { t1, t2, t3 };
  ulong txn_sz[ 3 ] = { t1_sz, t2_sz, t3_sz };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 3UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x3d4e5f60718293a4UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  lthash_drive_task( sched, task, ctx );
}

/* Every account of lthash_batch_setup got one subtraction and one
   addition, the delta is what the tiles returned, and BLOCK_END came
   after the last LtHash task. */
static void
lthash_batch_check( fd_sched_t *        sched,
                    test_lthash_ctx_t * ctx,
                    fd_pubkey_t const * acct,
                    ulong               acct_cnt ) {
  FD_TEST( ctx->txn_exec_cnt==3UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==acct_cnt && ctx->sub_cnt==acct_cnt && ctx->add_cnt==acct_cnt );
  for( ulong i=0UL; i<acct_cnt; i++ ) lthash_check_acct( ctx, 2UL, acct+i, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, acct_cnt );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 0," ) );
}

/* Batching to the cap.  The three transactions are held on their
   tiles, so the subtractions queue up, and with one tile idle they
   wait, since a hash batch takes a tile only when two are idle.
   Completing the transactions together makes every addition READY in
   one poll with no transaction in flight, so the cap is the full width
   and they go out as a full batch at once and the rest when the queue
   runs dry.  The subtractions then go out the same way. */
static void
run_lthash_batch_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  /* One account more than a full batch, spread over the three
     transactions. */
  ulong const per_txn  = FD_SCHED_LTHASH_BATCH_MAX/3UL+1UL;
  ulong const acct_cnt = 3UL*per_txn;
  fd_pubkey_t acct[ 3UL*(FD_SCHED_LTHASH_BATCH_MAX/3UL+1UL) ];
  static test_lthash_ctx_t ctx[ 1 ];
  lthash_batch_setup( sched, ctx, acct, per_txn );
  ulong task_cnt = (acct_cnt+FD_SCHED_LTHASH_BATCH_MAX-1UL)/FD_SCHED_LTHASH_BATCH_MAX;

  fd_sched_task_t task[ 1 ];
  fd_sched_task_t held[ 3 ];
  ulong held_cnt = 0UL;
  while( fd_sched_task_next_ready( sched, task ) ) {
    if( task->task_type==FD_SCHED_TT_TXN_EXEC ) {
      FD_TEST( held_cnt<3UL );
      held[ held_cnt++ ] = *task;
      continue;
    }
    FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH || task->task_type==FD_SCHED_TT_TXN_SIGVERIFY );
    lthash_drive_task( sched, task, ctx );
  }
  FD_TEST( held_cnt==3UL );
  FD_TEST( !ctx->sub_cnt && !ctx->add_cnt );

  for( ulong i=0UL; i<3UL; i++ ) lthash_drive_task( sched, held+i, ctx );
  for(;;) {
    FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
    if(      task->task_type==FD_SCHED_TT_LTHASH_ADD ) FD_TEST( !ctx->sub_cnt && task->lthash->cnt==fd_ulong_min( acct_cnt-ctx->add_cnt, FD_SCHED_LTHASH_BATCH_MAX ) );
    else if( task->task_type==FD_SCHED_TT_LTHASH_SUB ) FD_TEST( ctx->add_cnt==acct_cnt && task->lthash->cnt==fd_ulong_min( acct_cnt-ctx->sub_cnt, FD_SCHED_LTHASH_BATCH_MAX ) );
    else break;
    lthash_drive_task( sched, task, ctx );
  }
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_END );
  FD_TEST( ctx->add_cnt==acct_cnt && ctx->add_task_cnt==task_cnt );
  FD_TEST( ctx->sub_cnt==acct_cnt && ctx->sub_task_cnt==task_cnt );
  lthash_drive_task( sched, task, ctx );
  lthash_drive( sched, ctx, 100UL );

  lthash_batch_check( sched, ctx, acct, acct_cnt );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=acct_cnt, .first_write=acct_cnt, .add_created=acct_cnt, .entry=acct_cnt, .sub_dispatched=acct_cnt, .sub_task=task_cnt, .sub_applied=acct_cnt, .add_surfaced=acct_cnt, .add_dispatched=acct_cnt, .add_task=task_cnt, .add_applied=acct_cnt, .frozen=acct_cnt } );

  delete_sched( sched );
}

/* Whether the transaction task's fee payer, its first account, is
   acct. */
static int
txn_task_payer_is( fd_sched_t *            sched,
                   fd_sched_task_t const * task,
                   fd_pubkey_t const *     acct ) {
  fd_txn_p_t * txn_p = fd_sched_get_txn( sched, task->txn_exec->txn_idx );
  FD_TEST( txn_p );
  fd_acct_addr_t const * addrs = fd_txn_get_acct_addrs( TXN( txn_p ), txn_p->payload );
  return !memcmp( addrs->b, acct->uc, sizeof(fd_acct_addr_t) );
}

/* Index in tasks of the transaction task whose fee payer is acct. */
static ulong
txn_task_with_payer( fd_sched_t *            sched,
                     fd_sched_task_t const * tasks,
                     ulong                   task_cnt,
                     fd_pubkey_t const *     acct ) {
  for( ulong i=0UL; i<task_cnt; i++ ) if( txn_task_payer_is( sched, tasks+i, acct ) ) return i;
  FD_LOG_ERR(( "no transaction task with the given payer" ));
}

/* Whether the LtHash task carries acct. */
static int
lthash_task_has_acct( fd_sched_task_t const * task,
                      fd_pubkey_t const *     acct ) {
  for( ulong i=0UL; i<task->lthash->cnt; i++ ) {
    if( !memcmp( task->lthash->accts[ i ].b, acct->uc, sizeof(fd_acct_addr_t) ) ) return 1;
  }
  return 0;
}

/* Hands out the three transactions of a six-account block from
   lthash_batch_setup, lets PoH and the first two sigverify tasks run
   on the fourth tile and keeps the third there, then completes the
   first transaction.  Its two additions are READY with nothing else
   READY, so the poll batches them, but only the completed transaction's
   tile is idle and a hash batch needs two, so the batch is held.  That
   is the hold a block sees in practice, and the one the dependent
   cases need.  The other hold, a transaction released by a stale
   addition completed inside the poll, is covered by
   run_lthash_batch_held_behind_txn_case.
   Returns the two transactions and then the sigverify task still on
   their tiles in on_tile, and the completed transaction's payer, one
   of the two held accounts, in held_acct. */
static void
lthash_batch_hold( fd_sched_t *        sched,
                   test_lthash_ctx_t * ctx,
                   fd_sched_task_t *   on_tile,
                   fd_acct_addr_t *    held_acct ) {
  fd_sched_task_t task[ 1 ];
  fd_sched_task_t first[ 1 ];
  ulong txn_cnt = 0UL, sigverify_cnt = 0UL;
  for(;;) {
    FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
    if( task->task_type==FD_SCHED_TT_TXN_EXEC ) {
      FD_TEST( txn_cnt<3UL );
      if( !txn_cnt ) *first = *task;
      else           on_tile[ txn_cnt-1UL ] = *task;
      txn_cnt++;
      continue;
    }
    FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH || task->task_type==FD_SCHED_TT_TXN_SIGVERIFY );
    if( task->task_type==FD_SCHED_TT_TXN_SIGVERIFY && ++sigverify_cnt==3UL ) break;
    lthash_drive_task( sched, task, ctx );
  }
  FD_TEST( txn_cnt==3UL );
  on_tile[ 2 ] = *task;
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) ); /* every tile is busy */

  fd_txn_p_t * txn_p = fd_sched_get_txn( sched, first->txn_exec->txn_idx );
  *held_acct = fd_txn_get_acct_addrs( TXN( txn_p ), txn_p->payload )[ 0 ];
  lthash_drive_task( sched, first, ctx );

  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_held_cnt 0, lthash_add_batch_wait_idle_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 2," ) );
  FD_TEST( !ctx->sub_cnt && !ctx->add_cnt );
}

/* A held batch goes out once a second tile is idle.  The sigverify
   task completes, and the next call finds nothing READY and two idle
   tiles and hands out the held batch, carrying the completed
   transaction's two accounts, the only ones written so far.  The other
   two transactions then complete together, so their four additions go
   out as one batch, and the subtractions, which waited for a bubble
   all along, follow. */
static void
run_lthash_batch_held_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_pubkey_t acct[ 6 ];
  static test_lthash_ctx_t ctx[ 1 ];
  lthash_batch_setup( sched, ctx, acct, 2UL );
  fd_sched_task_t on_tile[ 3 ]; fd_acct_addr_t held_acct[ 1 ];
  lthash_batch_hold( sched, ctx, on_tile, held_acct );

  lthash_drive_task( sched, on_tile+2, ctx );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD && task->lthash->cnt==2UL );
  FD_TEST( lthash_acct( ctx, task->lthash->accts   )->write_cnt[ 2 ]==1UL );
  FD_TEST( lthash_acct( ctx, task->lthash->accts+1 )->write_cnt[ 2 ]==1UL );
  FD_TEST( memcmp( task->lthash->accts, task->lthash->accts+1, sizeof(fd_acct_addr_t) ) );
  FD_TEST( lthash_task_has_acct( task, fd_type_pun_const( held_acct ) ) );
  lthash_drive_task( sched, task, ctx );
  FD_TEST( ctx->add_cnt==2UL && ctx->add_task_cnt==1UL );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 0," ) );

  lthash_drive_task( sched, on_tile,   ctx );
  lthash_drive_task( sched, on_tile+1, ctx );
  lthash_drive( sched, ctx, 100UL );
  lthash_batch_check( sched, ctx, acct, 6UL );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=6UL, .first_write=6UL, .add_created=6UL, .entry=6UL, .sub_dispatched=6UL, .sub_task=1UL, .sub_applied=6UL, .add_surfaced=6UL, .add_dispatched=6UL, .add_task=2UL, .add_batch_wait_idle=1UL, .add_applied=6UL, .frozen=6UL } );

  delete_sched( sched );
}

/* Abandon releases a held batch.  The held pseudo transactions are
   completed in the dispatcher and the batch dropped right away, so the
   block is released as soon as the tasks still on their tiles land. */
static void
run_lthash_batch_abandon_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_pubkey_t acct[ 6 ];
  static test_lthash_ctx_t ctx[ 1 ];
  lthash_batch_setup( sched, ctx, acct, 2UL );
  fd_sched_task_t on_tile[ 3 ]; fd_acct_addr_t held_acct[ 1 ];
  lthash_batch_hold( sched, ctx, on_tile, held_acct );

  fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_INVALID );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 0," ) );
  FD_TEST( strstr( state, "lthash_discarded_add_held_cnt 2," ) );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX ); /* tasks are still on their tiles */
  fd_sched_task_t task[ 1 ];
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );

  for( ulong i=0UL; i<3UL; i++ ) lthash_drive_task( sched, on_tile+i, ctx );
  FD_TEST( fd_sched_pruned_block_next( sched )==2UL );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  FD_TEST( fd_sched_is_drained( sched ) );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( ctx->txn_exec_cnt==3UL && !ctx->sub_cnt && !ctx->add_cnt && !ctx->block_end_cnt );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=6UL, .first_write=6UL, .add_created=6UL, .entry=6UL, .add_surfaced=2UL, .add_batch_wait_idle=1UL, .discarded_add_pending=4U, .discarded_add_held=2U, .discarded_sub_queued=6U } );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "block_abandoned_cnt 1," ) );

  delete_sched( sched );
}

/* A subtraction batch and the transaction in flight with it land in
   either order.  The three transactions chain through A, so only the
   first is on a tile, the lowest, when the four subtractions go out to
   the highest idle tile.  Each completion is accepted and the block
   ends with the same delta. */
static void
run_lthash_batch_completion_order_case( int batch_first ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 4 ]; /* A, the payer of all three, then B, C, D */
  for( ulong i=0UL; i<4UL; i++ ) fd_memset( acct[ i ].uc, (int)(0xc1UL+0x0dUL*i), sizeof(fd_pubkey_t) );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, acct+1, 1UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct, acct+2, 1UL, 0x02 );
  uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, acct, acct+3, 1UL, 0x03 );
  uchar const * txns[ 3 ] = { t1, t2, t3 };
  ulong txn_sz[ 3 ] = { t1_sz, t2_sz, t3_sz };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 3UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x2c3d4e5f60718293UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  lthash_drive_task( sched, task, ctx );

  /* Hold the first transaction and the subtraction batch on their
     tiles.  Complete the PoH and sigverify tasks as they come. */
  fd_sched_task_t txn[ 1 ]; int txn_held = 0;
  fd_sched_task_t sub[ 1 ]; int sub_held = 0;
  fd_lthash_value_t sub_value[ 1 ];
  while( fd_sched_task_next_ready( sched, task ) ) {
    if( task->task_type==FD_SCHED_TT_TXN_EXEC ) {
      FD_TEST( !txn_held && txn_task_payer_is( sched, task, acct ) );
      *txn = *task;
      txn_held = 1;
      continue;
    }
    if( task->task_type==FD_SCHED_TT_LTHASH_SUB ) {
      FD_TEST( !sub_held && task->lthash->cnt==4UL );
      *sub = *task;
      sub_held = 1;
      lthash_task_value( ctx, task, sub_value );
      continue;
    }
    FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH || task->task_type==FD_SCHED_TT_TXN_SIGVERIFY );
    lthash_drive_task( sched, task, ctx );
  }
  FD_TEST( txn_held && sub_held );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0x7," ) );

  if( batch_first ) lthash_complete( sched, sub, ctx, sub_value );
  lthash_drive_task( sched, txn, ctx );
  if( !batch_first ) lthash_complete( sched, sub, ctx, sub_value );
  lthash_drive( sched, ctx, 100UL );

  FD_TEST( ctx->txn_exec_cnt==3UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==4UL && ctx->sub_cnt==4UL && ctx->add_cnt==4UL );
  lthash_check_acct( ctx, 2UL, acct, 1UL, 1UL, 3UL );
  for( ulong i=1UL; i<4UL; i++ ) lthash_check_acct( ctx, 2UL, acct+i, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 4UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  /* The second and third transactions each come out ahead of the
     additions READY with them, so all four additions go out in one
     batch after the third completes. */
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=6UL, .first_write=4UL, .coalesced=2UL, .add_created=4UL, .entry=4UL, .sub_dispatched=4UL, .sub_task=1UL, .sub_applied=4UL, .add_surfaced=4UL, .add_dispatched=4UL, .add_task=1UL, .add_applied=4UL, .frozen=4UL } );

  delete_sched( sched );
}

/* Transactions first and bubble-sized batches, on four tiles.  T1
   writes A and B, T2 C and D, T3 E and F, T4 A and G, so it waits on
   T1, and T5 G and H, so it waits on T4, all in one FEC set.  With T1,
   T2 and T3 on three tiles nothing is READY and one tile is idle, so
   the eight queued subtractions wait.  When T1 completes, T4 and B's
   addition are READY together and T4 goes first.  B's addition is then
   batched but held, one tile being idle.  When T4 completes, T5 and
   A's addition are READY and T5 goes out ahead of the held batch, which
   then grows to two and is held again.  When T2 completes, C and D
   join the batch, two tiles are idle, and the batch of four goes out,
   followed by the eight subtractions as one task, within the cap on
   batches with transactions in flight.  Every account ends with one
   subtraction and one addition. */
static void
run_lthash_bubble_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 8 ]; /* A to H */
  for( ulong i=0UL; i<8UL; i++ ) fd_memset( acct[ i ].uc, (int)(0xa1UL+0x0bUL*i), sizeof(fd_pubkey_t) );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,   acct+1, 1UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+2, acct+3, 1UL, 0x02 );
  uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, acct+4, acct+5, 1UL, 0x03 );
  uchar t4[ FD_TXN_MTU ]; ulong t4_sz = build_lthash_test_txn( t4, acct,   acct+6, 1UL, 0x04 );
  uchar t5[ FD_TXN_MTU ]; ulong t5_sz = build_lthash_test_txn( t5, acct+6, acct+7, 1UL, 0x05 );
  uchar const * txns[ 5 ] = { t1, t2, t3, t4, t5 };
  ulong txn_sz[ 5 ] = { t1_sz, t2_sz, t3_sz, t4_sz, t5_sz };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 5UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x4e5f60718293a4b5UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  lthash_drive_task( sched, task, ctx );

  /* T1, T2 and T3 take three tiles.  PoH and sigverify use the fourth
     and complete.  The subtractions need two idle tiles and wait. */
  fd_sched_task_t held[ 3 ];
  ulong held_cnt = 0UL;
  while( fd_sched_task_next_ready( sched, task ) ) {
    if( task->task_type==FD_SCHED_TT_TXN_EXEC ) {
      FD_TEST( held_cnt<3UL );
      held[ held_cnt++ ] = *task;
      continue;
    }
    FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH || task->task_type==FD_SCHED_TT_TXN_SIGVERIFY );
    lthash_drive_task( sched, task, ctx );
  }
  FD_TEST( held_cnt==3UL && !ctx->sub_cnt && !ctx->add_cnt );
  ulong t1_i = txn_task_with_payer( sched, held, 3UL, acct   );
  ulong t2_i = txn_task_with_payer( sched, held, 3UL, acct+2 );
  ulong t3_i = txn_task_with_payer( sched, held, 3UL, acct+4 );

  /* T1 completes.  T4 and B's addition are READY, and T4 goes first.
     B's addition is then batched, but one idle tile is not enough. */
  lthash_drive_task( sched, held+t1_i, ctx );
  fd_sched_task_t t4_task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, t4_task ) );
  FD_TEST( t4_task->task_type==FD_SCHED_TT_TXN_EXEC && txn_task_payer_is( sched, t4_task, acct ) );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_add_batch_held_cnt 0, lthash_add_batch_wait_idle_cnt 1," ) );
  FD_TEST( !ctx->add_cnt );

  /* T4 completes.  T5 and A's addition are READY, and T5 goes out
     ahead of the held batch, which then takes A and is held again. */
  lthash_drive_task( sched, t4_task, ctx );
  fd_sched_task_t t5_task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, t5_task ) );
  FD_TEST( t5_task->task_type==FD_SCHED_TT_TXN_EXEC && txn_task_payer_is( sched, t5_task, acct+6 ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 1," ) );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 2," ) );
  FD_TEST( strstr( state, "lthash_add_batch_held_cnt 0, lthash_add_batch_wait_idle_cnt 2," ) );
  FD_TEST( !ctx->add_cnt );

  /* T2 completes.  C and D join the batch and two tiles are idle, so
     the batch goes out as B, A, C, D, and then the eight subtractions
     as one task. */
  lthash_drive_task( sched, held+t2_i, ctx );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD && task->lthash->cnt==4UL );
  FD_TEST( !memcmp( task->lthash->accts[ 0 ].b, acct[ 1 ].uc, sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( task->lthash->accts[ 1 ].b, acct[ 0 ].uc, sizeof(fd_acct_addr_t) ) );
  FD_TEST( lthash_task_has_acct( task, acct+2 ) && lthash_task_has_acct( task, acct+3 ) );
  lthash_drive_task( sched, task, ctx );
  FD_TEST( ctx->add_cnt==4UL && ctx->add_task_cnt==1UL );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_SUB && task->lthash->cnt==8UL );
  lthash_drive_task( sched, task, ctx );
  FD_TEST( ctx->sub_cnt==8UL && ctx->sub_task_cnt==1UL );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );

  /* T3 and T5 complete, and the last four additions go out together. */
  lthash_drive_task( sched, held+t3_i, ctx );
  lthash_drive_task( sched, t5_task, ctx );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==5UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==8UL && ctx->sub_cnt==8UL && ctx->add_cnt==8UL && ctx->sub_task_cnt==1UL && ctx->add_task_cnt==2UL );
  for( ulong i=0UL; i<8UL; i++ ) lthash_check_acct( ctx, 2UL, acct+i, 1UL, 1UL, (i==0UL||i==6UL) ? 2UL : 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 8UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=10UL, .first_write=8UL, .coalesced=2UL, .add_created=8UL, .entry=8UL, .sub_dispatched=8UL, .sub_task=1UL, .sub_applied=8UL, .add_surfaced=8UL, .add_dispatched=8UL, .add_task=2UL, .add_batch_wait_idle=2UL, .add_applied=8UL, .frozen=8UL } );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 0," ) );

  delete_sched( sched );
}

/* The batch cap.  T1 writes three accounts more than the cap on
   batches with transactions in flight and T2 two, both on tiles at
   once.  The subtractions go out as a capped batch and five, and when
   T1 completes its additions go out as a capped batch and three.  T2's
   two follow once it completes. */
static void
run_lthash_batch_cap_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  ulong const cap      = FD_SCHED_LTHASH_BATCH_BUSY_MAX;
  ulong const t1_cnt   = cap+3UL;
  ulong const acct_cnt = t1_cnt+2UL;
  fd_pubkey_t acct[ FD_SCHED_LTHASH_BATCH_BUSY_MAX+5UL ]; /* T1's, then T2's two */
  for( ulong i=0UL; i<acct_cnt; i++ ) fd_memset( acct[ i ].uc, (int)(0x61UL+i), sizeof(fd_pubkey_t) );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,        acct+1UL,        t1_cnt-1UL, 0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+t1_cnt, acct+t1_cnt+1UL, 1UL,        0x02 );
  uchar const * txns[ 2 ] = { t1, t2 };
  ulong txn_sz[ 2 ] = { t1_sz, t2_sz };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 2UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x60718293a4b5c6d7UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  lthash_drive_task( sched, task, ctx );

  /* Both transactions stay on their tiles.  PoH and sigverify complete,
     then the subtractions go out as a capped batch and five. */
  fd_sched_task_t held[ 2 ];
  ulong held_cnt = 0UL;
  ulong sub_sz[ 2 ]; ulong sub_task_cnt = 0UL;
  while( fd_sched_task_next_ready( sched, task ) ) {
    if( task->task_type==FD_SCHED_TT_TXN_EXEC ) {
      FD_TEST( held_cnt<2UL );
      held[ held_cnt++ ] = *task;
      continue;
    }
    if( task->task_type==FD_SCHED_TT_LTHASH_SUB ) {
      FD_TEST( sub_task_cnt<2UL );
      sub_sz[ sub_task_cnt++ ] = task->lthash->cnt;
    } else {
      FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH || task->task_type==FD_SCHED_TT_TXN_SIGVERIFY );
    }
    lthash_drive_task( sched, task, ctx );
  }
  FD_TEST( held_cnt==2UL && sub_task_cnt==2UL && sub_sz[ 0 ]==cap && sub_sz[ 1 ]==5UL );
  FD_TEST( ctx->sub_cnt==acct_cnt && !ctx->add_cnt );

  /* T1 completes with T2 in flight, so its additions go out as a
     capped batch and then three. */
  lthash_drive_task( sched, held+txn_task_with_payer( sched, held, 2UL, acct ), ctx );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD && task->lthash->cnt==cap );
  lthash_drive_task( sched, task, ctx );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD && task->lthash->cnt==3UL );
  lthash_drive_task( sched, task, ctx );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( ctx->add_cnt==t1_cnt && ctx->add_task_cnt==2UL );

  lthash_drive_task( sched, held+txn_task_with_payer( sched, held, 2UL, acct+t1_cnt ), ctx );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==2UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==acct_cnt && ctx->sub_cnt==acct_cnt && ctx->add_cnt==acct_cnt && ctx->sub_task_cnt==2UL && ctx->add_task_cnt==3UL );
  for( ulong i=0UL; i<acct_cnt; i++ ) lthash_check_acct( ctx, 2UL, acct+i, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, acct_cnt );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=acct_cnt, .first_write=acct_cnt, .add_created=acct_cnt, .entry=acct_cnt, .sub_dispatched=acct_cnt, .sub_task=2UL, .sub_applied=acct_cnt, .add_surfaced=acct_cnt, .add_dispatched=acct_cnt, .add_task=3UL, .add_applied=acct_cnt, .frozen=acct_cnt } );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 0," ) );

  delete_sched( sched );
}

/* The stranded batch.  T1 and T3 write two accounts each and T2 two
   more than a full batch, all in one FEC set, on four tiles.  T1 and
   T3 complete first and their additions go out as two batches that
   stay on their tiles.  T2, the last transaction, completes with two
   tiles idle and no transaction in flight, so the poll fills a full
   batch, which goes out at once, and the next poll pops the last two
   with one idle tile and holds them.  Every addition is now surfaced
   and nothing else of the block is queued, so the poll runs only
   because a batch is held.  Without that the held batch would never be
   looked at again, the block could never end, and the scheduler would
   find no task in flight once the tiles drained. */
static void
run_lthash_batch_held_tail_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  ulong const t2_cnt   = FD_SCHED_LTHASH_BATCH_MAX+2UL;
  ulong const acct_cnt = t2_cnt+4UL;
  fd_pubkey_t acct[ FD_SCHED_LTHASH_BATCH_MAX+6UL ]; /* T1: 0, 1; T2: 2 on; T3: the last two */
  for( ulong i=0UL; i<acct_cnt; i++ ) fd_memset( acct[ i ].uc, (int)(0x50UL+i), sizeof(fd_pubkey_t) );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,              acct+1UL,          1UL,        0x01 );
  uchar t2[ FD_TXN_MTU ]; ulong t2_sz = build_lthash_test_txn( t2, acct+2UL,          acct+3UL,          t2_cnt-1UL, 0x02 );
  uchar t3[ FD_TXN_MTU ]; ulong t3_sz = build_lthash_test_txn( t3, acct+acct_cnt-2UL, acct+acct_cnt-1UL, 1UL,        0x03 );
  FD_TEST( t2_sz<=FD_TXN_MTU );
  uchar const * txns[ 3 ] = { t1, t2, t3 };
  ulong txn_sz[ 3 ] = { t1_sz, t2_sz, t3_sz };
  uchar encoded[ 8192 ];
  ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 3UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x5f60718293a4b5c6UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  lthash_drive_task( sched, task, ctx );

  /* The three transactions take three tiles.  PoH and sigverify use
     the fourth and complete. */
  fd_sched_task_t held[ 3 ];
  ulong held_cnt = 0UL;
  while( fd_sched_task_next_ready( sched, task ) ) {
    if( task->task_type==FD_SCHED_TT_TXN_EXEC ) {
      FD_TEST( held_cnt<3UL );
      held[ held_cnt++ ] = *task;
      continue;
    }
    FD_TEST( task->task_type==FD_SCHED_TT_POH_HASH || task->task_type==FD_SCHED_TT_TXN_SIGVERIFY );
    lthash_drive_task( sched, task, ctx );
  }
  FD_TEST( held_cnt==3UL && !ctx->sub_cnt && !ctx->add_cnt );
  ulong t1_i = txn_task_with_payer( sched, held, 3UL, acct              );
  ulong t2_i = txn_task_with_payer( sched, held, 3UL, acct+2UL          );
  ulong t3_i = txn_task_with_payer( sched, held, 3UL, acct+acct_cnt-2UL );

  /* T1 and T3 complete.  Their additions go out, two to a batch, and
     stay on their tiles. */
  fd_sched_task_t on_tile[ 3 ]; fd_lthash_value_t on_tile_value[ 3 ];
  ulong on_tile_cnt = 0UL;
  for( ulong r=0UL; r<2UL; r++ ) {
    lthash_drive_task( sched, held+(r ? t3_i : t1_i), ctx );
    FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
    FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD && task->lthash->cnt==2UL );
    lthash_task_value( ctx, task, on_tile_value+on_tile_cnt );
    on_tile[ on_tile_cnt++ ] = *task;
    FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  }
  FD_TEST( !ctx->add_cnt );

  /* T2 completes with two tiles idle.  A full batch goes out at once,
     and the last two additions are popped and held. */
  lthash_drive_task( sched, held+t2_i, ctx );
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD && task->lthash->cnt==FD_SCHED_LTHASH_BATCH_MAX );
  lthash_task_value( ctx, task, on_tile_value+on_tile_cnt );
  on_tile[ on_tile_cnt++ ] = *task;
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 2," ) );
  FD_TEST( lthash_state_has( sched, "add_created_cnt %lu, add_surfaced_cnt %lu, add_done_cnt 0,", acct_cnt, acct_cnt ) );
  FD_TEST( strstr( state, "lthash_add_batch_held_cnt 0, lthash_add_batch_wait_idle_cnt 1," ) );
  /* Still nothing with one tile idle, and the batch is still polled. */
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_held_cnt 0, lthash_add_batch_wait_idle_cnt 2," ) );

  /* The batches on the tiles complete.  The held batch goes out as
     soon as two tiles are idle, and the block ends. */
  for( ulong i=0UL; i<on_tile_cnt; i++ ) lthash_complete( sched, on_tile+i, ctx, on_tile_value+i );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==3UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==acct_cnt && ctx->sub_cnt==acct_cnt && ctx->add_cnt==acct_cnt );
  for( ulong i=0UL; i<acct_cnt; i++ ) lthash_check_acct( ctx, 2UL, acct+i, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, acct_cnt );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=acct_cnt, .first_write=acct_cnt, .add_created=acct_cnt, .entry=acct_cnt, .sub_dispatched=acct_cnt, .sub_task=2UL, .sub_applied=acct_cnt, .add_surfaced=acct_cnt, .add_dispatched=acct_cnt, .add_task=4UL, .add_batch_wait_idle=2UL, .add_applied=acct_cnt, .frozen=acct_cnt } );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 0," ) );

  delete_sched( sched );
}

/* The other hold, a transaction released by a stale addition completed
   inside the poll.  FEC set 1 carries T0 and T0', both writing X.  T0
   completes and T0' goes out, and with nothing queued the block
   speculates on X, the only account it owes, so the speculative
   addition scores X after two writes.  FEC set 2 carries T1 writing X,
   which makes the speculative addition stale and waits on it, and T2
   writing Y.  FEC set 3 ends the block and drains an addition of X
   after T1 and one of Y after T2.  T2 and T0' complete, and the poll
   finds Y's addition and X's stale one READY, Y's first since Y has
   one write to X's two.  It batches Y, completes X's stale addition on
   the spot, which releases T1, and T1 comes out ahead of the batch,
   which is held.  Y's addition goes out alone once nothing is READY,
   and X's second addition after T1. */
static void
run_lthash_batch_held_behind_txn_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ 2 ]; /* X, Y */
  lthash_test_keys( acct, acct+1 );
  uchar t0 [ FD_TXN_MTU ]; ulong t0_sz  = build_lthash_test_txn( t0,  acct,   NULL, 0UL, 0x01 );
  uchar t0p[ FD_TXN_MTU ]; ulong t0p_sz = build_lthash_test_txn( t0p, acct,   NULL, 0UL, 0x02 );
  uchar t1 [ FD_TXN_MTU ]; ulong t1_sz  = build_lthash_test_txn( t1,  acct,   NULL, 0UL, 0x03 );
  uchar t2 [ FD_TXN_MTU ]; ulong t2_sz  = build_lthash_test_txn( t2,  acct+1, NULL, 0UL, 0x04 );
  uchar const * txns1[ 2 ] = { t0, t0p }; ulong txn_sz1[ 2 ] = { t0_sz, t0p_sz };
  uchar const * txns2[ 2 ] = { t1, t2  }; ulong txn_sz2[ 2 ] = { t1_sz, t2_sz  };
  uchar encoded1[ 8192 ]; ulong sz1 = encode_lthash_batch( encoded1, txns1, txn_sz1, 2UL );
  uchar encoded2[ 8192 ]; ulong sz2 = encode_lthash_batch( encoded2, txns2, txn_sz2, 2UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x1b2c3d4e5f607182UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded1, sz1, 1, 0 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  /* T0 stays on its tile while PoH, sigverify and X's subtraction run.
     Speculation waits for the queue to empty, so it starts once T0
     completes and T0' is on its tile, and the speculative addition
     lands behind T0'. */
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t t0_task[ 1 ]; fd_lthash_value_t unused[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, t0_task, unused ) );
  FD_TEST( txn_task_payer_is( sched, t0_task, acct ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && !ctx->txn_exec_cnt );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=1UL, .coalesced=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL } );
  lthash_drive_task( sched, t0_task, ctx );
  fd_sched_task_t t0p_task[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, t0p_task, unused ) );
  FD_TEST( txn_task_payer_is( sched, t0p_task, acct ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && ctx->txn_exec_cnt==1UL );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=2UL, .first_write=1UL, .coalesced=1UL, .add_created=1UL, .spec=1UL, .entry=1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL } );

  /* T1 makes the speculation stale and waits on it.  T2 goes out and
     stays on its tile.  The block ends and the remaining additions are
     drained, X's behind T1 and Y's behind T2. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 0, 0 );
  fd_sched_task_t t2_task[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, t2_task, unused ) );
  FD_TEST( txn_task_payer_is( sched, t2_task, acct+1 ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==2UL && !ctx->add_cnt && ctx->txn_exec_cnt==1UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, NULL, 0UL, 0, 1 );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( !ctx->add_cnt && ctx->txn_exec_cnt==1UL );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "add_created_cnt 3, add_surfaced_cnt 0, add_done_cnt 0," ) );

  /* T2 and T0' complete.  The poll batches Y's addition, completes
     the stale speculation, and hands out the released T1 ahead of the
     batch. */
  lthash_drive_task( sched, t2_task, ctx );
  lthash_drive_task( sched, t0p_task, ctx );
  fd_sched_task_t t1_task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, t1_task ) );
  FD_TEST( t1_task->task_type==FD_SCHED_TT_TXN_EXEC && txn_task_payer_is( sched, t1_task, acct ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 1," ) );
  FD_TEST( strstr( state, "lthash_add_batch_held_cnt 1, lthash_add_batch_wait_idle_cnt 0," ) );
  FD_TEST( strstr( state, "add_created_cnt 3, add_surfaced_cnt 2, add_done_cnt 1," ) );
  FD_TEST( !ctx->add_cnt );

  /* Nothing is READY behind the held batch, so it goes out, alone. */
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_LTHASH_ADD && task->lthash->cnt==1UL );
  FD_TEST( lthash_task_has_acct( task, acct+1 ) );
  lthash_drive_task( sched, task, ctx );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );

  lthash_drive_task( sched, t1_task, ctx );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->txn_exec_cnt==4UL && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==2UL && ctx->sub_cnt==2UL && ctx->add_cnt==2UL );
  lthash_check_acct( ctx, 2UL, acct,   1UL, 1UL, 3UL );
  lthash_check_acct( ctx, 2UL, acct+1, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, 2UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) ); /* the stale speculation was never hashed */
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=4UL, .first_write=3UL, .coalesced=1UL, .add_created=3UL, .spec=1UL, .entry=2UL, .sub_dispatched=2UL, .sub_task=2UL, .sub_applied=2UL, .add_surfaced=3UL, .add_surfaced_stale=1UL, .add_dispatched=2UL, .add_task=2UL, .add_batch_held=1UL, .add_applied=2UL, .spec_stale=1UL, .frozen=2UL } );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 0," ) );

  delete_sched( sched );
}

/* Builds txn_cnt legacy transactions writing TEST_WIDE_TXN_ACCT_CNT
   distinct accounts each, acct[ 0 ] on, tagged so that the sets of
   different blocks are disjoint. */
static void
build_lthash_wide_txns( fd_pubkey_t * acct,
                        uchar      (* txn)[ FD_TXN_MTU ],
                        ulong *       txn_sz,
                        ulong         txn_cnt,
                        uchar         tag ) {
  for( ulong i=0UL; i<TEST_WIDE_TXN_ACCT_CNT*txn_cnt; i++ ) {
    fd_memset( acct[ i ].uc, 0x5a, sizeof(fd_pubkey_t) );
    acct[ i ].uc[ 0 ] = (uchar)(i&0xffUL);
    acct[ i ].uc[ 1 ] = (uchar)(i>>8);
    acct[ i ].uc[ 2 ] = tag;
  }
  for( ulong t=0UL; t<txn_cnt; t++ ) {
    txn_sz[ t ] = build_lthash_test_txn( txn[ t ], acct+TEST_WIDE_TXN_ACCT_CNT*t, acct+TEST_WIDE_TXN_ACCT_CNT*t+1UL, TEST_WIDE_TXN_ACCT_CNT-1UL, (uchar)(tag+t) );
    FD_TEST( txn_sz[ t ]<=FD_TXN_MTU );
  }
}

/* One entry batch of the transactions [t0,t0+cnt) of txn. */
static ulong
encode_lthash_wide_block( uchar *       encoded,
                          uchar      (* txn)[ FD_TXN_MTU ],
                          ulong const * txn_sz,
                          ulong         t0,
                          ulong         cnt ) {
  uchar const * ptr[ 32 ];
  FD_TEST( cnt<=32UL );
  for( ulong t=0UL; t<cnt; t++ ) ptr[ t ] = txn[ t0+t ];
  return encode_lthash_batch( encoded, ptr, txn_sz+t0, cnt );
}

/* Hands out block 2's tasks with its one transaction T0 held on its
   tile and completes the others, PoH, sigverify and its subtraction,
   as they come, until a call hands out nothing.  The calls that get as
   far as a hash batch each pop a chunk of a drain pending on another
   lane, see lthash_drain_chunk. */
static void
lthash_run_block_2_with_t0_held( fd_sched_t *        sched,
                                 test_lthash_ctx_t * ctx,
                                 fd_sched_task_t *   t0_task ) {
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==2UL );
  lthash_drive_task( sched, task, ctx );
  int held = 0;
  while( fd_sched_task_next_ready( sched, task ) ) {
    if( task->task_type==FD_SCHED_TT_TXN_EXEC ) {
      FD_TEST( !held );
      *t0_task = *task;
      held = 1;
    } else {
      lthash_drive_task( sched, task, ctx );
    }
  }
  FD_TEST( held && !ctx->block_end_cnt );
}

/* A drain over several calls on a lane that is not active.  Block 3,
   the child of the one-transaction block 2, takes a lane of its own and
   holds a wide block.  As a lane head it gets an entry and a queued
   subtraction for every account at parse.  Its last FEC set pops the
   first FD_SCHED_LTHASH_DRAIN_CHUNK accounts at ingest and leaves the
   block draining.  Nothing waits on the drain, and block 4, the child
   of block 3, takes a third lane.  Block 2's calls that get as far as a
   hash batch pop the rest of block 3's set a chunk at a time, so block
   3 is drained before block 2 ends, and every account of blocks 2, 3
   and 4 ends with exactly one subtraction and one addition. */
static void
run_lthash_drain_chunk_case( void ) {
  fd_sched_t * sched = new_sched( 5UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ TEST_WIDE_ACCT_CNT+2UL ]; /* the wide block's accounts, then T0's payer and T5's payer */
  uchar txn[ TEST_WIDE_TXN_CNT ][ FD_TXN_MTU ]; ulong txn_sz[ TEST_WIDE_TXN_CNT ];
  build_lthash_wide_txns( acct, txn, txn_sz, TEST_WIDE_TXN_CNT, 0x10 );
  fd_pubkey_t * payer0 = acct+TEST_WIDE_ACCT_CNT;
  fd_pubkey_t * payer5 = acct+TEST_WIDE_ACCT_CNT+1UL;
  fd_memset( payer0->uc, 0xc3, sizeof(fd_pubkey_t) );
  fd_memset( payer5->uc, 0xd4, sizeof(fd_pubkey_t) );
  uchar t0[ FD_TXN_MTU ]; ulong t0_sz = build_lthash_test_txn( t0, payer0, NULL, 0UL, 0x01 );
  uchar t5[ FD_TXN_MTU ]; ulong t5_sz = build_lthash_test_txn( t5, payer5, NULL, 0UL, 0x02 );
  uchar const * txns2[ 1 ] = { t0 };
  uchar const * txns4[ 1 ] = { t5 };
  uchar encoded2[ 8192 ];              ulong sz2 = encode_lthash_batch( encoded2, txns2, &t0_sz, 1UL );
  uchar encoded3[ TEST_WIDE_BLOCK_SZ ]; ulong sz3 = encode_lthash_wide_block( encoded3, txn, txn_sz, 0UL, TEST_WIDE_TXN_CNT );
  uchar encoded4[ 8192 ];              ulong sz4 = encode_lthash_batch( encoded4, txns4, &t5_sz, 1UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x8293a4b5c6d7e8f9UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  FD_TEST( fd_sched_can_ingest_cnt( sched ) );
  ingest_lthash_fec( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL, encoded3, sz3, 1, 1 );
  fd_sched_set_poh_params( sched, 3UL, TEST_ROOT_TICK_HEIGHT+1UL, TEST_ROOT_TICK_HEIGHT+2UL, start_poh );

  /* Block 3 is the head of lane 1 with an entry per account and the
     first chunk popped, and nothing waits on its drain. */
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 3," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 1," ) );
  FD_TEST( lthash_block_drain_line_has( sched, 3UL, TEST_WIDE_ACCT_CNT, 1UL ) );
  FD_TEST( fd_sched_can_ingest_cnt( sched ) && !fd_sched_fec_waits_for_lane( sched, 3UL, 1 ) );

  /* Block 2 runs with T0 held on its tile and drains block 3 along the
     way. */
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t t0_task[ 1 ];
  lthash_run_block_2_with_t0_held( sched, ctx, t0_task );
  FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 3," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 0," ) );
  FD_TEST( lthash_block_drain_line_has( sched, 3UL, TEST_WIDE_ACCT_CNT, TEST_WIDE_CHUNK_CNT ) );

  /* Block 4 takes the third lane, and everything runs to its end. */
  ingest_lthash_fec( sched, 4UL, 3UL, TEST_ROOT_SLOT+3UL, TEST_ROOT_SLOT+2UL, encoded4, sz4, 1, 1 );
  fd_sched_set_poh_params( sched, 4UL, TEST_ROOT_TICK_HEIGHT+2UL, TEST_ROOT_TICK_HEIGHT+3UL, start_poh );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 7," ) );
  lthash_drive_task( sched, t0_task, ctx );
  lthash_drive( sched, ctx, 2000UL );

  ulong acct_cnt = TEST_WIDE_ACCT_CNT+2UL;
  FD_TEST( ctx->txn_exec_cnt==TEST_WIDE_TXN_CNT+2UL && ctx->block_end_cnt==3UL );
  FD_TEST( ctx->acct_cnt==acct_cnt && ctx->sub_cnt==acct_cnt && ctx->add_cnt==acct_cnt );
  for( ulong i=0UL; i<TEST_WIDE_ACCT_CNT; i++ ) lthash_check_acct( ctx, 3UL, acct+i, 1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 2UL, payer0, 1UL, 1UL, 1UL );
  lthash_check_acct( ctx, 4UL, payer5, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 4UL, payer5, 1UL );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( lthash_state_has( sched, "lthash_entry_cnt %lu, lthash_sub_dispatched_cnt %lu,", acct_cnt, acct_cnt ) );
  FD_TEST( lthash_state_has( sched, "lthash_add_created_cnt %lu, lthash_spec_cnt 0,", acct_cnt ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lane_wait_cnt 0\n" ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 0," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* A head drains its own set, and BLOCK_END waits for it.  Block 2,
   alone in its lane, holds a wide block in one FEC set.  As the lane
   head it got an entry and a queued subtraction for every account at
   parse, so each pop of its drain only installs a ticket.  The ingest
   pops the first chunk and leaves the block draining, which makes no
   block wait.  Its transactions are held on the tiles, so every further
   call hands out nothing and pops another chunk, until the set is
   empty after more than one call.  The transactions then complete and
   the block ends with exactly one subtraction and one addition per
   account. */
static void
run_lthash_drain_end_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ TEST_WIDE_ACCT_CNT ];
  uchar txn[ TEST_WIDE_TXN_CNT ][ FD_TXN_MTU ]; ulong txn_sz[ TEST_WIDE_TXN_CNT ];
  build_lthash_wide_txns( acct, txn, txn_sz, TEST_WIDE_TXN_CNT, 0x10 );
  uchar encoded[ TEST_WIDE_BLOCK_SZ ]; ulong sz = encode_lthash_wide_block( encoded, txn, txn_sz, 0UL, TEST_WIDE_TXN_CNT );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x93a4b5c6d7e8f901UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  /* Every account has its entry, the first chunk took its tickets, and
     the block is draining and active. */
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 1," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 1," ) );
  FD_TEST( lthash_block_drain_line_has( sched, 2UL, TEST_WIDE_ACCT_CNT, 1UL ) );
  FD_TEST( fd_sched_can_ingest_cnt( sched ) && !fd_sched_fec_waits_for_lane( sched, 2UL, 1 ) );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START );
  lthash_drive_task( sched, task, ctx );

  /* The transactions take the tiles.  The call that hands out nothing
     pops a chunk, and so does each call after it until the set is
     empty. */
  fd_sched_task_t held[ TEST_EXEC_CNT ];
  ulong held_cnt = 0UL;
  while( fd_sched_task_next_ready( sched, task ) ) {
    FD_TEST( task->task_type==FD_SCHED_TT_TXN_EXEC && held_cnt<TEST_EXEC_CNT );
    held[ held_cnt++ ] = *task;
  }
  FD_TEST( held_cnt==fd_ulong_min( TEST_WIDE_TXN_CNT, TEST_EXEC_CNT ) );
  lthash_poll_drain( sched, 2UL, TEST_WIDE_ACCT_CNT, 2UL );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_draining_cnt 0," ) );
  FD_TEST( strstr( state, "lane_wait_cnt 0\n" ) );
  FD_TEST( !ctx->sub_cnt && !ctx->add_cnt );

  for( ulong i=0UL; i<held_cnt; i++ ) lthash_drive_task( sched, held+i, ctx );
  lthash_drive( sched, ctx, 2000UL );
  FD_TEST( ctx->txn_exec_cnt==TEST_WIDE_TXN_CNT && ctx->block_end_cnt==1UL );
  FD_TEST( ctx->acct_cnt==TEST_WIDE_ACCT_CNT && ctx->sub_cnt==TEST_WIDE_ACCT_CNT && ctx->add_cnt==TEST_WIDE_ACCT_CNT );
  for( ulong i=0UL; i<TEST_WIDE_ACCT_CNT; i++ ) lthash_check_acct( ctx, 2UL, acct+i, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 2UL, acct, TEST_WIDE_ACCT_CNT );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( fd_lthash_eq( ctx->delta, ctx->handed ) );
  FD_TEST( ctx->block_end_step[ 2 ]>ctx->last_lthash_step[ 2 ] );
  FD_TEST( lthash_state_has( sched, "lthash_entry_cnt %lu, lthash_sub_dispatched_cnt %lu,", TEST_WIDE_ACCT_CNT, TEST_WIDE_ACCT_CNT ) );
  FD_TEST( lthash_state_has( sched, "lthash_add_created_cnt %lu, lthash_spec_cnt 0,", TEST_WIDE_ACCT_CNT ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );
  FD_TEST( strstr( state, "lthash_add_batch_cnt 0," ) );

  delete_sched( sched );
}

/* A lane switch in the middle of a drain.  Block 2 holds a bare tick,
   and block 3, a wide block and its child, takes the next lane with an
   entry per account at parse and the first chunk of its set popped at
   ingest.  The call that hands out block 2's BLOCK_END first pops a
   second chunk of block 3's set, so the switch activates block 3 with
   part of its set left.  With its transactions held on the tiles, the
   calls after that pop the rest, and the block ends with exactly one
   subtraction and one addition per account. */
static void
run_lthash_drain_switch_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ TEST_WIDE_ACCT_CNT ];
  uchar txn[ TEST_WIDE_TXN_CNT ][ FD_TXN_MTU ]; ulong txn_sz[ TEST_WIDE_TXN_CNT ];
  build_lthash_wide_txns( acct, txn, txn_sz, TEST_WIDE_TXN_CNT, 0x10 );
  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x60718293a4b5c6d7UL );
  uchar encoded3[ TEST_WIDE_BLOCK_SZ ]; ulong sz3 = encode_lthash_wide_block( encoded3, txn, txn_sz, 0UL, TEST_WIDE_TXN_CNT );

  ingest_lthash_tick_block( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, start_poh );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  ingest_lthash_fec( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL, encoded3, sz3, 1, 1 );
  fd_sched_set_poh_params( sched, 3UL, TEST_ROOT_TICK_HEIGHT+1UL, TEST_ROOT_TICK_HEIGHT+2UL, start_poh );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 3," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 1," ) );

  /* Block 2 runs through: its BLOCK_START, its PoH task, and the call
     that hands out its BLOCK_END, which pops a chunk first.  Its end
     releases lane 0 and activates block 3, whose BLOCK_START is handed
     out in start. */
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t start[ 1 ]; fd_lthash_value_t unused[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, start ) );
  FD_TEST( start->task_type==FD_SCHED_TT_BLOCK_START && start->block_start->bank_idx==2UL );
  lthash_drive_task( sched, start, ctx );
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_BLOCK_START, start, unused ) );
  FD_TEST( start->block_start->bank_idx==3UL );
  FD_TEST( ctx->block_end_cnt==1UL && !ctx->sub_cnt && !ctx->add_cnt );

  /* Block 3 is active mid-drain, with two chunks popped. */
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 3, staged_bitset 2," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 1," ) );
  FD_TEST( lthash_block_drain_line_has( sched, 3UL, TEST_WIDE_ACCT_CNT, 2UL ) );
  FD_TEST( fd_sched_can_ingest_cnt( sched ) && !fd_sched_fec_waits_for_lane( sched, 3UL, 1 ) );
  lthash_drive_task( sched, start, ctx );

  /* The transactions take the tiles.  The call that hands out nothing
     pops the third chunk, straight into tickets, and any call after it
     pops the rest. */
  fd_sched_task_t task[ 1 ];
  fd_sched_task_t held[ TEST_EXEC_CNT ];
  ulong held_cnt = 0UL;
  while( fd_sched_task_next_ready( sched, task ) ) {
    FD_TEST( task->task_type==FD_SCHED_TT_TXN_EXEC && held_cnt<TEST_EXEC_CNT );
    held[ held_cnt++ ] = *task;
  }
  FD_TEST( held_cnt==fd_ulong_min( TEST_WIDE_TXN_CNT, TEST_EXEC_CNT ) );
  lthash_poll_drain( sched, 3UL, TEST_WIDE_ACCT_CNT, 3UL );
  FD_TEST( !ctx->sub_cnt && !ctx->add_cnt );

  for( ulong i=0UL; i<held_cnt; i++ ) lthash_drive_task( sched, held+i, ctx );
  lthash_drive( sched, ctx, 2000UL );
  FD_TEST( ctx->txn_exec_cnt==TEST_WIDE_TXN_CNT && ctx->block_end_cnt==2UL );
  FD_TEST( ctx->acct_cnt==TEST_WIDE_ACCT_CNT && ctx->sub_cnt==TEST_WIDE_ACCT_CNT && ctx->add_cnt==TEST_WIDE_ACCT_CNT );
  for( ulong i=0UL; i<TEST_WIDE_ACCT_CNT; i++ ) lthash_check_acct( ctx, 3UL, acct+i, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 3UL, acct, TEST_WIDE_ACCT_CNT );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  FD_TEST( ctx->block_end_step[ 3 ]>ctx->last_lthash_step[ 3 ] );
  FD_TEST( lthash_state_has( sched, "lthash_entry_cnt %lu, lthash_sub_dispatched_cnt %lu,", TEST_WIDE_ACCT_CNT, TEST_WIDE_ACCT_CNT ) );
  FD_TEST( lthash_state_has( sched, "lthash_add_created_cnt %lu, lthash_spec_cnt 0,", TEST_WIDE_ACCT_CNT ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lane_wait_cnt 0\n" ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 0," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* A child of a dying block needs no lane, and a dying block's draining
   child goes down with it at once.  Block 2 runs with T0 held on its
   tile and everything else of it completed, then block 3, a wide block
   and its child, takes the next lane and is left draining by its
   ingest.  Abandoning block 2 deactivates it while T0 keeps it staged,
   and takes block 3, which has nothing in flight, out of the dispatcher
   right away, drain and all.  Blocks 5, 6 and 7, bare ticks, then fill
   the other lanes, the first of them active and the others waiting for
   their turn, so a first FEC set behind the root waits, while one
   behind the dying block 2 does not.  Ingested, it is added dead
   without a lane.  T0's completion then releases block 2 and the ticks
   run. */
static void
run_lthash_dying_parent_case( void ) {
  fd_sched_t * sched = new_sched( 8UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_pubkey_t acct[ TEST_WIDE_ACCT_CNT+1UL ]; /* the wide block's accounts, then T0's payer */
  uchar txn[ TEST_WIDE_TXN_CNT ][ FD_TXN_MTU ]; ulong txn_sz[ TEST_WIDE_TXN_CNT ];
  build_lthash_wide_txns( acct, txn, txn_sz, TEST_WIDE_TXN_CNT, 0x10 );
  fd_pubkey_t * payer0 = acct+TEST_WIDE_ACCT_CNT;
  fd_memset( payer0->uc, 0xc3, sizeof(fd_pubkey_t) );
  uchar t0[ FD_TXN_MTU ]; ulong t0_sz = build_lthash_test_txn( t0, payer0, NULL, 0UL, 0x01 );
  uchar const * txns2[ 1 ] = { t0 };
  uchar encoded2[ 8192 ];              ulong sz2 = encode_lthash_batch( encoded2, txns2, &t0_sz, 1UL );
  uchar encoded3[ TEST_WIDE_BLOCK_SZ ]; ulong sz3 = encode_lthash_wide_block( encoded3, txn, txn_sz, 0UL, TEST_WIDE_TXN_CNT );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0xb5c6d7e8f9011223UL );
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  /* T0 stays on its tile while PoH, sigverify and its subtraction run;
     its addition is pending behind it. */
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_sched_task_t t0_task[ 1 ]; fd_lthash_value_t unused[ 1 ];
  FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, t0_task, unused ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->sub_cnt==1UL && !ctx->add_cnt && !ctx->txn_exec_cnt );

  /* Block 3 takes lane 1 and its ingest leaves it draining. */
  ingest_lthash_fec( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL, encoded3, sz3, 1, 1 );
  fd_sched_set_poh_params( sched, 3UL, TEST_ROOT_TICK_HEIGHT+1UL, TEST_ROOT_TICK_HEIGHT+2UL, start_poh );
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 3," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 1," ) );
  FD_TEST( lthash_block_drain_line_has( sched, 3UL, TEST_WIDE_ACCT_CNT, 1UL ) );

  /* Abandoning block 2 leaves no block active and takes block 3 out. */
  fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_INVALID );
  FD_TEST( fd_sched_pruned_block_next( sched )==3UL );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 18446744073709551615, staged_bitset 1," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 0," ) );
  FD_TEST( strstr( state, "block_abandoned_cnt 1," ) );

  /* Blocks 5 to 7 fill the other lanes.  Block 5 is activated at once
     and blocks 6 and 7 wait for their turn, so no lane can be given
     up.  A first FEC set behind the root waits for a lane.  One behind
     the dying block 2 does not, and ingested it is added dead. */
  for( ulong bank_idx=5UL; bank_idx<=7UL; bank_idx++ ) {
    ingest_lthash_tick_block( sched, bank_idx, 1UL, TEST_ROOT_SLOT+bank_idx-1UL, TEST_ROOT_SLOT, start_poh );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  }
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 5, staged_bitset 15," ) );
  FD_TEST( fd_sched_fec_waits_for_lane( sched, 1UL, 1 ) && !fd_sched_fec_waits_for_lane( sched, 2UL, 1 ) );
  FD_TEST( !try_ingest_lthash_fec( sched, 4UL, 2UL, TEST_ROOT_SLOT+3UL, TEST_ROOT_SLOT+1UL, NULL, 0UL, 1, 0 ) );
  FD_TEST( fd_sched_get_dead_reason( sched, 4UL )==FD_SCHED_DEAD_REASON_DEAD_ANCESTOR );
  FD_TEST( fd_sched_pruned_block_next( sched )==4UL );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "staged_bitset 15," ) );
  FD_TEST( strstr( state, "block_added_dead_ood_cnt 1," ) );
  FD_TEST( strstr( state, "lane_wait_cnt 1\n" ) );

  /* T0's completion releases block 2 and its lane, and the ticks run
     to their end. */
  lthash_drive_task( sched, t0_task, ctx );
  FD_TEST( fd_sched_pruned_block_next( sched )==2UL );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 5, staged_bitset 14," ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( fd_sched_is_drained( sched ) );
  fd_sched_task_t task[ 1 ];
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->sub_cnt==1UL && !ctx->add_cnt && ctx->block_end_cnt==3UL );
  /* Block 3 went down with its first chunk of additions created and
     the rest owed, and block 2 with T0's. */
  ulong chunk = FD_SCHED_LTHASH_DRAIN_CHUNK;
  lthash_check_metrics( sched, &(test_lthash_metrics_t){ .parsed_writable=TEST_WIDE_ACCT_CNT+1UL, .first_write=TEST_WIDE_ACCT_CNT+1UL, .add_created=chunk+1UL, .entry=TEST_WIDE_ACCT_CNT+1UL, .sub_dispatched=1UL, .sub_task=1UL, .sub_applied=1UL, .discarded_add_owed=(uint)(TEST_WIDE_ACCT_CNT-chunk), .discarded_add_pending=(uint)(chunk+1UL), .discarded_sub_queued=(uint)TEST_WIDE_ACCT_CNT, .discarded_sub_applied=1U } );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "staged_bitset 0," ) );
  FD_TEST( strstr( state, "block_removed_cnt 3," ) );
  FD_TEST( strstr( state, "block_abandoned_cnt 2," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 0," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* The active block's drain comes first, see lthash_find_draining_block.
   Block 2, three wide transactions, runs on lane 0 to its end.  Its
   child X, block 3 with one transaction more than a wide block, takes
   lane 1, because an empty block holds lane 0 until X is in, and is
   left draining and active.  Its first transactions are held on the
   four tiles, and the call that finds no idle tile pops X's second
   chunk.  Y, block 4 with 36 wide transactions in three FEC sets, the
   child of X, then takes lane 0, below X, and its last FEC set leaves
   it draining too.  The next calls, again with no idle tile, pop X's
   remaining chunks and none of Y's, where lowest lane first would have
   drained Y and left X waiting on it.  X's transactions then complete,
   X ends, Y runs, and every account of the three blocks ends with one
   subtraction and one addition. */
static void
run_lthash_drain_active_first_case( void ) {
  fd_sched_t * sched = new_sched( 8UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  ulong const x_txn_cnt  = TEST_WIDE_TXN_CNT+1UL;
  ulong const x_acct_cnt = x_txn_cnt*TEST_WIDE_TXN_ACCT_CNT;
  ulong const y_txn_cnt  = 36UL;
  ulong const y_acct_cnt = y_txn_cnt*TEST_WIDE_TXN_ACCT_CNT;
  static fd_pubkey_t acct2[ 3UL*TEST_WIDE_TXN_ACCT_CNT                   ]; static uchar txn2[ 3UL                   ][ FD_TXN_MTU ]; ulong txn2_sz[ 3UL                   ];
  static fd_pubkey_t acct3[ (TEST_WIDE_TXN_CNT+1UL)*TEST_WIDE_TXN_ACCT_CNT ]; static uchar txn3[ TEST_WIDE_TXN_CNT+1UL ][ FD_TXN_MTU ]; ulong txn3_sz[ TEST_WIDE_TXN_CNT+1UL ];
  static fd_pubkey_t acct4[ 36UL*TEST_WIDE_TXN_ACCT_CNT                  ]; static uchar txn4[ 36UL                  ][ FD_TXN_MTU ]; ulong txn4_sz[ 36UL                  ];
  build_lthash_wide_txns( acct2, txn2, txn2_sz, 3UL,       0x10 );
  build_lthash_wide_txns( acct3, txn3, txn3_sz, x_txn_cnt, 0x20 );
  build_lthash_wide_txns( acct4, txn4, txn4_sz, y_txn_cnt, 0x40 );
  static uchar encoded2 [ TEST_WIDE_BLOCK_SZ+FD_TXN_MTU ]; ulong sz2  = encode_lthash_wide_block( encoded2,  txn2, txn2_sz, 0UL,  3UL       );
  static uchar encoded3 [ TEST_WIDE_BLOCK_SZ+FD_TXN_MTU ]; ulong sz3  = encode_lthash_wide_block( encoded3,  txn3, txn3_sz, 0UL,  x_txn_cnt );
  static uchar encoded4a[ 24576 ];                         ulong sz4a = encode_lthash_wide_block( encoded4a, txn4, txn4_sz, 0UL,  12UL      );
  static uchar encoded4b[ 24576 ];                         ulong sz4b = encode_lthash_wide_block( encoded4b, txn4, txn4_sz, 12UL, 12UL      );
  static uchar encoded4c[ 24576 ];                         ulong sz4c = encode_lthash_wide_block( encoded4c, txn4, txn4_sz, 24UL, 12UL      );

  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0xb5c6d7e8f9011223UL );

  /* Block 2 runs on lane 0 to its end. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded2, sz2, 1, 1 );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  lthash_drive( sched, ctx, 2000UL );
  FD_TEST( ctx->block_end_cnt==1UL && ctx->txn_exec_cnt==3UL && ctx->sub_cnt==3UL*TEST_WIDE_TXN_ACCT_CNT && ctx->add_cnt==3UL*TEST_WIDE_TXN_ACCT_CNT );
  FD_TEST( strstr( fd_sched_get_state_cstr( sched ), "staged_bitset 0," ) );

  /* A block of just a header under the root holds lane 0 while X
     arrives, so X takes lane 1, and X's ingest pops its first chunk.
     Giving the empty block up frees lane 0 and makes X active. */
  ingest_lthash_fec( sched, 5UL, 1UL, TEST_ROOT_SLOT+4UL, TEST_ROOT_SLOT, NULL, 0UL, 1, 0 );
  ingest_lthash_fec( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL, encoded3, sz3, 1, 1 );
  fd_sched_set_poh_params( sched, 3UL, TEST_ROOT_TICK_HEIGHT+1UL, TEST_ROOT_TICK_HEIGHT+2UL, start_poh );
  FD_TEST( strstr( fd_sched_get_state_cstr( sched ), "active_idx 5, staged_bitset 3," ) );
  fd_sched_block_abandon( sched, 5UL, FD_SCHED_ABANDON_DISCARDED );
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 3, staged_bitset 2," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 1," ) );
  FD_TEST( lthash_block_drain_line_has( sched, 3UL, x_acct_cnt, 1UL ) );

  /* Four of X's transactions are held on the tiles.  The call that
     finds no idle tile pops X's second chunk. */
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==3UL );
  lthash_drive_task( sched, task, ctx );
  fd_sched_task_t held[ TEST_EXEC_CNT ]; ulong held_cnt = 0UL;
  while( fd_sched_task_next_ready( sched, task ) ) {
    FD_TEST( task->task_type==FD_SCHED_TT_TXN_EXEC && held_cnt<TEST_EXEC_CNT );
    held[ held_cnt++ ] = *task;
  }
  FD_TEST( held_cnt==TEST_EXEC_CNT );
  FD_TEST( lthash_block_drain_line_has( sched, 3UL, x_acct_cnt, 2UL ) );

  /* Y takes lane 0, below X, and its last FEC set leaves it draining. */
  ingest_lthash_fec( sched, 4UL, 3UL, TEST_ROOT_SLOT+3UL, TEST_ROOT_SLOT+2UL, encoded4a, sz4a, 1, 0 );
  fd_sched_set_poh_params( sched, 4UL, TEST_ROOT_TICK_HEIGHT+2UL, TEST_ROOT_TICK_HEIGHT+3UL, start_poh );
  ingest_lthash_fec( sched, 4UL, 3UL, TEST_ROOT_SLOT+3UL, TEST_ROOT_SLOT+2UL, encoded4b, sz4b, 0, 0 );
  ingest_lthash_fec( sched, 4UL, 3UL, TEST_ROOT_SLOT+3UL, TEST_ROOT_SLOT+2UL, encoded4c, sz4c, 0, 1 );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 3, staged_bitset 3," ) );
  FD_TEST( strstr( state, "staged_head_idx[0] 4, staged_head_idx[1] 3," ) );
  FD_TEST( strstr( state, "lthash_draining_cnt 2," ) );
  FD_TEST( lthash_block_drain_line_has( sched, 4UL, y_acct_cnt, 1UL ) );

  /* The next calls pop X's remaining chunks and leave Y alone. */
  for( ulong pop_cnt=2UL; pop_cnt*FD_SCHED_LTHASH_DRAIN_CHUNK<x_acct_cnt; pop_cnt++ ) {
    FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );
    FD_TEST( lthash_block_drain_line_has( sched, 3UL, x_acct_cnt, pop_cnt+1UL ) );
    FD_TEST( lthash_block_drain_line_has( sched, 4UL, y_acct_cnt, 1UL ) );
  }
  FD_TEST( strstr( fd_sched_get_state_cstr( sched ), "lthash_draining_cnt 1," ) );

  /* X's held transactions complete.  An empty call from here on pops a
     chunk of Y's set, so a few are expected and a thousand in a row
     would be a stall. */
  for( ulong i=0UL; i<held_cnt; i++ ) lthash_drive_task( sched, held+i, ctx );
  ulong idle_run = 0UL;
  for( ulong polls=0UL; polls<100000UL && ctx->block_end_cnt<3UL; polls++ ) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    if( fd_sched_task_next_ready( sched, task ) ) { lthash_drive_task( sched, task, ctx ); idle_run = 0UL; continue; }
    FD_TEST( ++idle_run<1000UL );
  }
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  ulong acct_cnt = 3UL*TEST_WIDE_TXN_ACCT_CNT+x_acct_cnt+y_acct_cnt;
  FD_TEST( ctx->block_end_cnt==3UL && ctx->txn_exec_cnt==3UL+x_txn_cnt+y_txn_cnt );
  FD_TEST( ctx->acct_cnt==acct_cnt && ctx->sub_cnt==acct_cnt && ctx->add_cnt==acct_cnt );
  for( ulong i=0UL; i<3UL*TEST_WIDE_TXN_ACCT_CNT; i++ ) lthash_check_acct( ctx, 2UL, acct2+i, 1UL, 1UL, 1UL );
  for( ulong i=0UL; i<x_acct_cnt;                  i++ ) lthash_check_acct( ctx, 3UL, acct3+i, 1UL, 1UL, 1UL );
  for( ulong i=0UL; i<y_acct_cnt;                  i++ ) lthash_check_acct( ctx, 4UL, acct4+i, 1UL, 1UL, 1UL );
  fd_lthash_value_t expected[ 1 ]; lthash_expected_delta( expected, ctx, 4UL, acct4, y_acct_cnt );
  FD_TEST( fd_lthash_eq( ctx->delta, expected ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "lthash_draining_cnt 0," ) );
  FD_TEST( strstr( state, "staged_bitset 0," ) );
  FD_TEST( strstr( state, "lthash_ready_bitset[ 0 ] 0xf," ) );

  delete_sched( sched );
}

/* A first FEC set waits while any lane head has work in hand, and
   promotion stages one block per lane.  Blocks 2 to 5, bare ticks under
   the root, take the four lanes.  Block 2 is kept in flight on its PoH
   task and the others have yet to start, so every head has work and a
   first FEC set has to wait.  Block 6, under the root, finds no lane.
   Lanes are not capacity, so the ingest check passes, and a caller that
   does not ask about lanes gets it unstaged, no head being idle to give
   up its lane.  Its child block 7 joins it unstaged without waiting.
   Once the four lane blocks have ended the chain is promoted, block 6
   first and alone, and block 7 only once block 6 is done and its lane
   is free again. */
static void
run_lane_wait_and_promotion_case( void ) {
  fd_sched_t * sched = new_sched( 8UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x4d6f8a1c3e5b7092UL );
  fd_hash_t poh6[ 1 ];      repeat_hash( poh6, start_poh, 1UL ); /* block 6's end hash, the start of block 7 */

  for( ulong bank_idx=2UL; bank_idx<=5UL; bank_idx++ ) {
    ingest_lthash_tick_block( sched, bank_idx, 1UL, TEST_ROOT_SLOT+bank_idx-1UL, TEST_ROOT_SLOT, start_poh );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  }
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 15," ) );

  /* Block 2 runs up to its PoH task, which stays on its tile. */
  fd_sched_task_t task[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==2UL );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
  fd_sched_task_t poh2[ 1 ];
  FD_TEST( 1UL==fd_sched_task_next_ready( sched, poh2 ) );
  FD_TEST( poh2->task_type==FD_SCHED_TT_POH_HASH && poh2->poh_hash->bank_idx==2UL );
  FD_TEST( 0UL==fd_sched_task_next_ready( sched, task ) );

  /* Block 6 would need a lane and none is free.  Ingested anyway it is
     unstaged, and block 7 joins it unstaged without waiting. */
  FD_TEST( fd_sched_can_ingest_cnt( sched ) );
  FD_TEST( fd_sched_fec_waits_for_lane( sched, 1UL, 1 ) && fd_sched_fec_waits_for_lane( sched, ULONG_MAX, 1 ) );
  ingest_lthash_tick_block( sched, 6UL, 1UL, TEST_ROOT_SLOT+5UL, TEST_ROOT_SLOT, start_poh );
  fd_sched_set_poh_params( sched, 6UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  ingest_lthash_tick_block( sched, 7UL, 6UL, TEST_ROOT_SLOT+6UL, TEST_ROOT_SLOT+5UL, poh6 );
  fd_sched_set_poh_params( sched, 7UL, TEST_ROOT_TICK_HEIGHT+1UL, TEST_ROOT_TICK_HEIGHT+2UL, poh6 );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 15," ) );
  FD_TEST( strstr( state, "block_added_staged_cnt 4, block_added_unstaged_cnt 2," ) );
  FD_TEST( strstr( state, "lane_wait_cnt 2\n" ) );

  /* The lane blocks end one after another.  Only when the last lane
     frees up is the chain promoted, block 6 alone. */
  fd_execrp_poh_hash_done_msg_t msg[ 1 ];
  msg->cnt = poh2->poh_hash->cnt;
  for( ulong i=0UL; i<msg->cnt; i++ ) repeat_hash( msg->hash+i, poh2->poh_hash->hash+i, poh2->poh_hash->hashcnt );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_POH_HASH, ULONG_MAX, poh2->poh_hash->exec_idx, msg ) );
  FD_TEST( drive_ticks_until_start( sched, 6UL ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 6, staged_bitset 1," ) );
  FD_TEST( strstr( state, "block_removed_cnt 4," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 1, block_demoted_cnt 0," ) );
  FD_TEST( strstr( state, "lane_promoted_cnt 1, lane_demoted_cnt 0," ) );

  /* Block 7 follows once block 6 is done. */
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
  FD_TEST( drive_ticks_until_start( sched, 7UL ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 7, staged_bitset 1," ) );
  FD_TEST( strstr( state, "block_removed_cnt 5," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 2, block_demoted_cnt 0," ) );
  FD_TEST( strstr( state, "lane_promoted_cnt 2, lane_demoted_cnt 0," ) );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
  FD_TEST( !drive_ticks_until_start( sched, ULONG_MAX ) );
  FD_TEST( fd_sched_is_drained( sched ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "block_removed_cnt 6," ) );

  delete_sched( sched );
}

/* A first FEC set waits while any lane head has work in hand, and once
   every head is idle it takes the lane of one of them.  Blocks 2 to 5,
   just their headers under the root, take the four lanes with their
   BLOCK_START pending, which is work, so a first FEC set waits.  Each
   starts and, with nothing more to do, is deactivated, until every head
   is idle and the wait is over.  Block 6, a one-transaction block under
   the root, is let in and gets the lane of block 2, which goes
   unstaged.  Block 6 ends, block 2's last FEC set lands unstaged with
   one transaction, and block 2 is promoted into the free lane with that
   one transaction.  The other three complete in their lanes. */
static void
run_lane_wait_idle_handover_case( void ) {
  fd_sched_t * sched = new_sched( 8UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x5e7f9a2b4c6d8e01UL );
  fd_pubkey_t acct[ 2 ]; lthash_test_keys( acct, acct+1 );
  uchar txn[ 5 ][ FD_TXN_MTU ]; ulong txn_sz[ 5 ]; uchar const * txns[ 5 ];
  uchar encoded[ 5 ][ 2048 ]; ulong sz[ 5 ];
  for( ulong i=0UL; i<5UL; i++ ) {
    txn_sz[ i ] = build_lthash_test_txn( txn[ i ], acct, acct+1, 1UL, (uchar)(0x10UL+i) );
    txns[ i ]   = txn[ i ];
    sz[ i ]     = encode_lthash_batch( encoded[ i ], txns+i, txn_sz+i, 1UL );
  }

  for( ulong bank_idx=2UL; bank_idx<=5UL; bank_idx++ ) {
    ingest_lthash_fec( sched, bank_idx, 1UL, TEST_ROOT_SLOT+bank_idx-1UL, TEST_ROOT_SLOT, NULL, 0UL, 1, 0 );
    fd_sched_set_poh_params( sched, bank_idx, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  }
  char * state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 15," ) );
  FD_TEST( fd_sched_fec_waits_for_lane( sched, 1UL, 1 ) && fd_sched_fec_waits_for_lane( sched, ULONG_MAX, 1 ) );

  /* Every block starts and is deactivated idle, and the wait is over. */
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  lthash_drive( sched, ctx, 100UL );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 18446744073709551615, staged_bitset 15," ) );
  FD_TEST( strstr( state, "deactivate_no_txn_cnt 4," ) );
  FD_TEST( !fd_sched_fec_waits_for_lane( sched, 1UL, 1 ) && !fd_sched_fec_waits_for_lane( sched, ULONG_MAX, 1 ) );

  /* Block 6 takes block 2's lane and runs to its end. */
  ingest_lthash_fec( sched, 6UL, 1UL, TEST_ROOT_SLOT+5UL, TEST_ROOT_SLOT, encoded[ 4 ], sz[ 4 ], 1, 1 );
  fd_sched_set_poh_params( sched, 6UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 6, staged_bitset 15," ) );
  FD_TEST( strstr( state, "staged_head_idx[0] 6, staged_head_idx[1] 3," ) );
  FD_TEST( strstr( state, "block_added_staged_cnt 5, block_added_unstaged_cnt 0," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 0, block_demoted_cnt 1," ) );
  FD_TEST( strstr( state, "lane_promoted_cnt 0, lane_demoted_cnt 1," ) );
  FD_TEST( strstr( state, "lane_wait_cnt 2\n" ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->block_end_cnt==1UL && ctx->txn_exec_cnt==1UL );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 18446744073709551615, staged_bitset 14," ) );

  /* Block 2's last FEC set lands unstaged, and the block is promoted
     into the free lane with its one transaction. */
  ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded[ 0 ], sz[ 0 ], 0, 1 );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "active_idx 2, staged_bitset 15," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 1, block_demoted_cnt 1," ) );
  FD_TEST( strstr( state, "txn_promoted_cnt 1," ) );
  lthash_drive( sched, ctx, 100UL );
  FD_TEST( ctx->block_end_cnt==2UL && ctx->txn_exec_cnt==2UL );

  /* The other three complete in their lanes and run to their end. */
  for( ulong bank_idx=3UL; bank_idx<=5UL; bank_idx++ ) {
    ingest_lthash_fec( sched, bank_idx, 1UL, TEST_ROOT_SLOT+bank_idx-1UL, TEST_ROOT_SLOT, encoded[ bank_idx-2UL ], sz[ bank_idx-2UL ], 0, 1 );
  }
  lthash_drive( sched, ctx, 1000UL );
  FD_TEST( ctx->block_end_cnt==5UL && ctx->txn_exec_cnt==5UL );
  FD_TEST( fd_sched_is_drained( sched ) );
  state = fd_sched_get_state_cstr( sched );
  FD_TEST( strstr( state, "block_removed_cnt 5," ) );
  FD_TEST( strstr( state, "block_promoted_cnt 1, block_demoted_cnt 1," ) );
  FD_TEST( strstr( state, "lane_promoted_cnt 1, lane_demoted_cnt 1," ) );
  FD_TEST( strstr( state, "txn_promoted_cnt 1," ) );

  delete_sched( sched );
}

/* Footer cert verify tasks hold a block that reached BLOCK_END.  The
   claimed tiles stay busy, the block is not done, and its child does
   not start until the last cert task is done.  An abandon while they
   run takes the child, alone on its own lane with nothing in flight,
   down at once and drains the block on the last one. */
static void
run_cert_verify_case( int abandon ) {
  fd_sched_t * sched = new_sched( 8UL );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x3c5a7e9b1d2f4086UL );
  ingest_lthash_tick_block( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, start_poh );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

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
  ingest_lthash_fec( sched, 3UL, 2UL, TEST_ROOT_SLOT+2UL, TEST_ROOT_SLOT+1UL, NULL, 0UL, 1, 0 );
  FD_TEST( !fd_sched_task_next_ready( sched, task ) ); /* child waits, no CRIT */
  FD_TEST( !fd_sched_is_drained( sched ) );

  if( abandon ) {
    fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_INVALID );
    FD_TEST( fd_sched_pruned_block_next( sched )==3UL ); /* the child only, 2 released at BLOCK_END */
    FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  }
  int t0 = fd_ulong_find_lsb( tiles );
  int t1 = fd_ulong_find_msb( tiles );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_CERT_VERIFY, ULONG_MAX, (ulong)t0, NULL ) );
  FD_TEST( !fd_sched_task_next_ready( sched, task ) );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_CERT_VERIFY, ULONG_MAX, (ulong)t1, NULL ) );
  if( abandon ) {
    FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
    FD_TEST( !fd_sched_task_next_ready( sched, task ) );
    FD_TEST( fd_sched_is_drained( sched ) );
  } else {
    FD_TEST( fd_sched_task_next_ready( sched, task ) );
    FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==3UL );
  }
  delete_sched( sched );
}

/* Footer cert tasks of a block that is abandoned while they are on
   their tiles count as busy tiles in exec_busy_check, like any other
   task of a dying block.  Block 2, an empty block under the root,
   reaches BLOCK_END and has two cert tasks on tiles.  In the first
   variant the first cert fails, and the replay tile abandons the block
   before it completes that task, so one cert stays on its tile.  In
   the second variant consensus roots the done leader block 4 instead,
   and block 2 goes down as a minority fork with both certs on their
   tiles.  Either way the block with a transaction, 3 under the root or
   5 under block 4, is activated next, and its first dispatch
   reconciles the busy tiles with the dying block's in-flight tasks.
   The remaining certs then complete, block 2 drains, and the other
   block ends. */
static void
run_cert_dying_dispatch_case( int root_notify ) {
  fd_sched_t * sched = new_sched( 8UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );

  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x3c5a7e9b1d2f4086UL );
  ingest_lthash_tick_block( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, start_poh );
  fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  ulong txn_bank = 3UL, txn_parent = 1UL, txn_parent_slot = TEST_ROOT_SLOT;
  if( root_notify ) {
    fd_sched_block_add_done( sched, 4UL, 1UL, TEST_ROOT_SLOT+2UL );
    txn_bank = 5UL; txn_parent = 4UL; txn_parent_slot = TEST_ROOT_SLOT+2UL;
  }
  fd_pubkey_t acct[ 2 ]; lthash_test_keys( acct, acct+1 );
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct, acct+1, 1UL, 0x01 );
  uchar const * txns[ 1 ] = { t1 };
  uchar encoded3[ 8192 ]; ulong sz3 = encode_lthash_batch( encoded3, txns, &t1_sz, 1UL );
  ingest_lthash_fec( sched, txn_bank, txn_parent, TEST_ROOT_SLOT+3UL, txn_parent_slot, encoded3, sz3, 1, 1 );
  fd_sched_set_poh_params( sched, txn_bank, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );

  /* Block 2 runs to BLOCK_END and gets its two cert tasks. */
  fd_sched_task_t task[ 1 ];
  static test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
  for(;;) {
    while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}
    FD_TEST( fd_sched_task_next_ready( sched, task ) );
    if( task->task_type==FD_SCHED_TT_BLOCK_END ) break;
    FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START || task->task_type==FD_SCHED_TT_POH_HASH );
    lthash_drive_task( sched, task, ctx );
  }
  FD_TEST( task->block_end->bank_idx==2UL );
  FD_TEST( fd_sched_pruned_block_next( sched )==2UL );
  ulong tiles = fd_sched_cert_dispatch( sched, 2UL, 2UL );
  FD_TEST( fd_ulong_popcnt( tiles )==2 );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX, NULL ) );
  int t0 = fd_ulong_find_lsb( tiles );
  int t1_tile = fd_ulong_find_msb( tiles );

  if( !root_notify ) {
    fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_INVALID );
    FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_CERT_VERIFY, ULONG_MAX, (ulong)t0, NULL ) );
  } else {
    fd_sched_root_notify( sched, 4UL );
  }
  while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

  /* The other block starts and dispatches its transaction while the
     dying block's remaining cert tasks are on their tiles. */
  FD_TEST( fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==txn_bank );
  lthash_drive_task( sched, task, ctx );
  FD_TEST( fd_sched_task_next_ready( sched, task ) );
  FD_TEST( task->task_type==FD_SCHED_TT_TXN_EXEC && task->txn_exec->bank_idx==txn_bank );
  lthash_drive_task( sched, task, ctx );

  if( root_notify ) FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_CERT_VERIFY, ULONG_MAX, (ulong)t0, NULL ) );
  FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_CERT_VERIFY, ULONG_MAX, (ulong)t1_tile, NULL ) );
  lthash_drive( sched, ctx, 1000UL );
  FD_TEST( ctx->txn_exec_cnt==1UL && ctx->block_end_cnt==1UL );
  FD_TEST( fd_sched_is_drained( sched ) );
  delete_sched( sched );
}

/* A block whose transactions declare more writable accounts than a
   valid block can afford is ruled invalid, where the dispatcher or the
   lane map would otherwise run out of room and abort.  The bound is
   lowered to two wide transactions' worth of accounts, or for the late
   registration sites to one wide transaction's, a payer and five more.
   The count is of declared accounts, a write lock each, so a
   transaction rewriting the accounts the block already has counts in
   full.

   In site 0, T0 writes a wide transaction's accounts and T1 the same,
   which reaches the bound exactly, and T4 with one account is refused.
   In site 1, the block enters unstaged behind four lanes with work,
   takes T0 and T1 there, is promoted with its count intact once the
   four blocks complete, and T4 is refused.  In sites 2 and 3, S is a
   lookup table transaction with ten writable table accounts that
   cannot be resolved at parse, so S is charged for them only when it
   registers them at completion.  Under the bound, S's payer and T0's
   accounts fit.  In site 2 ten registrations do not, so completing S
   rules the block invalid, which fd_sched_task_done reports.  In site
   3 S registers five accounts, two of them T0's, which fit exactly and
   count in full while the lane map gains three. */
static void
run_lthash_writer_bound_case( int site ) {
  fd_sched_t * sched = new_sched( 8UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_set_bypass_alut_resolution( sched, 1 );
  ulong const wide_cnt = TEST_WIDE_TXN_ACCT_CNT;
  ulong const bound    = site<2 ? 2UL*wide_cnt : wide_cnt+1UL+5UL;
  fd_sched_set_lthash_txn_writers_max( sched, bound );
  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x6a1b2c3d4e5f7081UL );

  /* T0 and T1 write the first wide transaction's accounts.  T4 writes
     only payer, which is S's payer in sites 2 and 3, and S's lookup
     table accounts and the payers of the four blocks of site 1 follow
     it. */
  static fd_pubkey_t acct[ 3UL*TEST_WIDE_TXN_ACCT_CNT ]; static uchar wide[ 3 ][ FD_TXN_MTU ]; ulong wide_sz[ 3 ];
  build_lthash_wide_txns( acct, wide, wide_sz, 3UL, 0x10 );
  fd_pubkey_t const * payer = acct+2UL*wide_cnt;
  fd_pubkey_t const * extra = payer+1UL;
  uchar t1[ FD_TXN_MTU ]; ulong t1_sz = build_lthash_test_txn( t1, acct,  acct+1UL, wide_cnt-1UL, 0x21 );
  uchar t4[ FD_TXN_MTU ]; ulong t4_sz = build_lthash_test_txn( t4, payer, NULL,     0UL,          0x24 );
  uchar const * txns01[ 2 ] = { wide[ 0 ], t1 }; ulong txn01_sz[ 2 ] = { wide_sz[ 0 ], t1_sz };
  uchar encoded01[ 4096 ]; ulong sz01 = encode_lthash_batch( encoded01, txns01, txn01_sz, 2UL );
  uchar const * txns4[ 1 ] = { t4 }; uchar encoded4[ 2048 ]; ulong sz4 = encode_lthash_batch( encoded4, txns4, &t4_sz, 1UL );

  ulong bank_idx = fd_ulong_if( site==1, 6UL, 2UL );
  ulong slot     = TEST_ROOT_SLOT+bank_idx-1UL;
  if( site==0 ) {
    ingest_lthash_fec( sched, 2UL, 1UL, slot, TEST_ROOT_SLOT, encoded01, sz01, 1, 0 );
    fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
    /* T1's writes coalesced into T0's, and the count is of write locks
       all the same. */
    FD_TEST( lthash_block_line_has( sched, 2UL, "lthash_writable_cnt %lu,", bound ) );
    FD_TEST( lthash_state_has( sched, "lthash_first_write_cnt %lu, lthash_coalesced_cnt %lu, lthash_entry_cnt %lu,", wide_cnt, wide_cnt, wide_cnt ) );
  } else if( site==1 ) {
    /* Blocks 2 to 5 hold the lanes with a transaction each to run. */
    uchar busy[ 4 ][ FD_TXN_MTU ]; ulong busy_sz[ 4 ]; uchar const * busy_txns[ 4 ]; uchar encoded_busy[ 4 ][ 2048 ]; ulong busy_enc_sz[ 4 ];
    for( ulong b=0UL; b<4UL; b++ ) {
      busy_sz[ b ]     = build_lthash_test_txn( busy[ b ], extra+b, NULL, 0UL, (uchar)(0x40UL+b) );
      busy_txns[ b ]   = busy[ b ];
      busy_enc_sz[ b ] = encode_lthash_batch( encoded_busy[ b ], busy_txns+b, busy_sz+b, 1UL );
      ingest_lthash_fec( sched, 2UL+b, 1UL, TEST_ROOT_SLOT+1UL+b, TEST_ROOT_SLOT, encoded_busy[ b ], busy_enc_sz[ b ], 1, 0 );
      fd_sched_set_poh_params( sched, 2UL+b, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
    }
    FD_TEST( strstr( fd_sched_get_state_cstr( sched ), "active_idx 2, staged_bitset 15," ) );
    FD_TEST( fd_sched_fec_waits_for_lane( sched, 1UL, 1 ) );
    ingest_lthash_fec( sched, 6UL, 1UL, slot, TEST_ROOT_SLOT, encoded01, sz01, 1, 0 );
    fd_sched_set_poh_params( sched, 6UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
    FD_TEST( strstr( fd_sched_get_state_cstr( sched ), "block_added_unstaged_cnt 1," ) );
    /* The four blocks end and block 6 is promoted to a freed lane. */
    for( ulong b=0UL; b<4UL; b++ ) ingest_lthash_fec( sched, 2UL+b, 1UL, TEST_ROOT_SLOT+1UL+b, TEST_ROOT_SLOT, NULL, 0UL, 0, 1 );
    drive_untracked( sched, 10000UL );
    FD_TEST( strstr( fd_sched_get_state_cstr( sched ), "block_promoted_cnt 1," ) );
    FD_TEST( lthash_block_line_has( sched, 6UL, "lthash_writable_cnt %lu,", bound ) );
  } else {
    fd_acct_addr_t late[ 10 ];
    for( ulong i=0UL; i<10UL; i++ ) fd_memcpy( late[ i ].b, extra[ i ].uc, sizeof(fd_acct_addr_t) );
    if( site==3 ) {
      /* Two of the five are T0's. */
      fd_memcpy( late[ 0 ].b, acct[ 1 ].uc, sizeof(fd_acct_addr_t) );
      fd_memcpy( late[ 1 ].b, acct[ 2 ].uc, sizeof(fd_acct_addr_t) );
    }
    uchar s[ FD_TXN_MTU ]; ulong s_sz = build_lthash_v0_txn( s, payer, 10UL, 0x31 );
    uchar const * txns[ 2 ] = { s, wide[ 0 ] }; ulong txn_sz[ 2 ] = { s_sz, wide_sz[ 0 ] };
    uchar encoded[ 4096 ]; ulong sz = encode_lthash_batch( encoded, txns, txn_sz, 2UL );
    ingest_lthash_fec( sched, 2UL, 1UL, slot, TEST_ROOT_SLOT, encoded, sz, 1, 0 );
    fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
    FD_TEST( lthash_block_line_has( sched, 2UL, "lthash_writable_cnt %lu,", wide_cnt+1UL ) );
    /* S, serializing, is the first transaction handed out. */
    test_lthash_ctx_t ctx[ 1 ]; fd_memset( ctx, 0, sizeof(test_lthash_ctx_t) );
    fd_sched_task_t held[ 1 ]; fd_lthash_value_t held_value[ 1 ];
    FD_TEST( lthash_drive_hold( sched, ctx, 100UL, FD_SCHED_TT_TXN_EXEC, held, held_value ) );
    FD_TEST( held->txn_exec->bank_idx==2UL && TXN( fd_sched_get_txn( sched, held->txn_exec->txn_idx ) )->addr_table_lookup_cnt==1 );
    fd_sched_txn_alts_t alts[ 1 ] = {{ .cnt = site==2 ? 10UL : 5UL, .addrs = late }};
    int res = fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC, held->txn_exec->txn_idx, held->txn_exec->exec_idx, alts );
    if( site==2 ) {
      FD_TEST( res==FD_SCHED_DEAD_REASON_TOO_MANY_WRITABLE_ACCOUNTS );
      FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_TOO_MANY_WRITABLE_ACCOUNTS );
      drive_untracked( sched, 1000UL );
      FD_TEST( fd_sched_is_drained( sched ) );
      char * state = fd_sched_get_state_cstr( sched );
      FD_TEST( strstr( state, "block_bad_cnt 1," ) && strstr( state, "lthash_late_reg_cnt 0," ) );
    } else {
      FD_TEST( !res );
      FD_TEST( lthash_block_line_has( sched, 2UL, "lthash_writable_cnt %lu,", bound ) );
      FD_TEST( strstr( fd_sched_get_state_cstr( sched ), "lthash_late_reg_cnt 5," ) );
      ingest_lthash_fec( sched, 2UL, 1UL, slot, TEST_ROOT_SLOT, NULL, 0UL, 0, 1 );
      drive_untracked( sched, 10000UL );
      FD_TEST( fd_sched_is_drained( sched ) );
      char * state = fd_sched_get_state_cstr( sched );
      FD_TEST( strstr( state, "block_bad_cnt 0," ) && lthash_state_has( sched, "lthash_frozen_cnt %lu,", wide_cnt+1UL+3UL ) );
    }
    delete_sched( sched );
    return;
  }

  /* T4's one account does not fit. */
  FD_TEST( !try_ingest_lthash_fec( sched, bank_idx, 1UL, slot, TEST_ROOT_SLOT, encoded4, sz4, 0, 1 ) );
  FD_TEST( fd_sched_get_dead_reason( sched, bank_idx )==FD_SCHED_DEAD_REASON_TOO_MANY_WRITABLE_ACCOUNTS );
  drive_untracked( sched, 1000UL );
  FD_TEST( fd_sched_is_drained( sched ) );
  FD_TEST( strstr( fd_sched_get_state_cstr( sched ), "block_bad_cnt 1," ) );
  delete_sched( sched );
}

/* The production bound, end to end.  Start-of-block processing writes
   its whole budget of distinct accounts.  Then wide transactions, in
   FEC sets of 16, are parsed and run until one would put the block
   over FD_SCHED_LTHASH_TXN_WRITERS_MAX.  That FEC set is refused and
   the block ruled invalid, with the lane map holding one entry per
   account seen, within the capacity of the lane. */
static void
run_lthash_writer_bound_full_case( void ) {
  fd_sched_t * sched = new_sched( 4UL );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_hash_t start_poh[ 1 ]; hash_from_seed( start_poh, 0x7b2c3d4e5f607182UL );

  ulong const wide_cnt    = TEST_WIDE_TXN_ACCT_CNT;
  ulong const txn_per_fec = 16UL;
  ulong const txn_max     = FD_SCHED_LTHASH_TXN_WRITERS_MAX/wide_cnt; /* transactions that fit */
  static fd_pubkey_t acct[ TEST_WIDE_TXN_ACCT_CNT*16UL ]; static uchar txn[ 16UL ][ FD_TXN_MTU ]; ulong txn_sz[ 16UL ]; uchar const * txns[ 16UL ];
  static uchar encoded[ 24576 ];
  for( ulong fec_idx=0UL; ; fec_idx++ ) {
    for( ulong t=0UL; t<txn_per_fec; t++ ) {
      ulong n = fec_idx*txn_per_fec+t;
      /* Transaction n writes its own run of accounts, distinct from the
         start-of-block accounts by the byte after the index. */
      for( ulong i=0UL; i<wide_cnt; i++ ) { fd_memset( acct[ wide_cnt*t+i ].uc, 0x5a, sizeof(fd_pubkey_t) ); FD_STORE( ulong, acct[ wide_cnt*t+i ].uc, wide_cnt*n+i ); }
      txn_sz[ t ] = build_lthash_test_txn( txn[ t ], acct+wide_cnt*t, acct+wide_cnt*t+1UL, wide_cnt-1UL, 0 );
      FD_STORE( uint, txn[ t ]+1UL, (uint)n ); /* distinct signatures */
      txns[ t ] = txn[ t ];
    }
    ulong sz = encode_lthash_batch( encoded, txns, txn_sz, txn_per_fec );
    if( fec_idx==txn_max/txn_per_fec ) {
      FD_TEST( lthash_block_line_has( sched, 2UL, "lthash_writable_cnt %lu,", wide_cnt*fec_idx*txn_per_fec ) );
      FD_TEST( !try_ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, 0, 0 ) );
      break;
    }
    ingest_lthash_fec( sched, 2UL, 1UL, TEST_ROOT_SLOT+1UL, TEST_ROOT_SLOT, encoded, sz, fec_idx==0UL, 0 );
    if( fec_idx==0UL ) {
      fd_sched_set_poh_params( sched, 2UL, TEST_ROOT_TICK_HEIGHT, TEST_ROOT_TICK_HEIGHT+1UL, start_poh );
      fd_sched_task_t task[ 1 ];
      FD_TEST( fd_sched_task_next_ready( sched, task ) && task->task_type==FD_SCHED_TT_BLOCK_START && task->block_start->bank_idx==2UL );
      fd_pubkey_t * start = fd_wksp_alloc_laddr( test_wksp, alignof(fd_pubkey_t), FD_SCHED_LTHASH_START_WRITES_MAX*sizeof(fd_pubkey_t), TEST_WKSP_TAG );
      FD_TEST( start );
      for( ulong i=0UL; i<FD_SCHED_LTHASH_START_WRITES_MAX; i++ ) { fd_memset( start[ i ].uc, 0x5b, sizeof(fd_pubkey_t) ); FD_STORE( ulong, start[ i ].uc, i ); }
      fd_sched_block_start_writes( sched, 2UL, fd_type_pun_const( start ), FD_SCHED_LTHASH_START_WRITES_MAX );
      fd_wksp_free_laddr( start );
      FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX, NULL ) );
    }
    drive_untracked( sched, 100000UL );
  }
  FD_TEST( fd_sched_get_dead_reason( sched, 2UL )==FD_SCHED_DEAD_REASON_TOO_MANY_WRITABLE_ACCOUNTS );
  drive_untracked( sched, 100000UL );
  FD_TEST( fd_sched_is_drained( sched ) );
  FD_TEST( lthash_state_has( sched, "txn_parsed_cnt %lu,", txn_max ) );
  FD_TEST( lthash_state_has( sched, "lthash_start_reg_cnt %lu,", FD_SCHED_LTHASH_START_WRITES_MAX ) );
  FD_TEST( lthash_state_has( sched, "lthash_entry_cnt %lu,", FD_SCHED_LTHASH_START_WRITES_MAX+wide_cnt*txn_max ) && FD_SCHED_LTHASH_START_WRITES_MAX+wide_cnt*txn_max<=FD_RDISP_MAX_WRITERS_PER_BLOCK );
  FD_TEST( lthash_state_has( sched, "block_bad_cnt 1," ) );
  delete_sched( sched );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 4UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  test_wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( test_wksp );

  test_sched_footprint();
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
  run_cert_dying_dispatch_case( 0 );
  run_cert_dying_dispatch_case( 1 );
  run_lane_wait_and_promotion_case();
  run_lane_wait_idle_handover_case();
  run_lthash_basic_case();
  run_lthash_abandon_in_flight_case( 1 );
  run_lthash_abandon_in_flight_case( 0 );
  run_lthash_demote_promote_case();
  run_lthash_inband_fallback_case();
  run_lthash_block_start_writes_case( 0 );
  run_lthash_block_start_writes_case( 1 );
  run_lthash_block_start_writes_case( 2 );
  run_lthash_block_start_writes_case( 3 );
  run_lthash_speculate_case( 0 );
  run_lthash_speculate_case( 1 );
  run_lthash_spec_result_dropped_case();
  run_lthash_spec_given_up_case();
  run_lthash_spec_given_up_complete_case( 0 );
  run_lthash_spec_given_up_complete_case( 1 );
  run_lthash_late_alt_case( 0 );
  run_lthash_late_alt_case( 1 );
  run_lthash_respeculate_case();
  run_lthash_pending_rewrite_case( 1 );
  run_lthash_pending_rewrite_case( 0 );
  run_lthash_two_late_alt_case();
  run_lthash_batch_case();
  run_lthash_batch_held_case();
  run_lthash_batch_abandon_case();
  run_lthash_batch_completion_order_case( 0 );
  run_lthash_batch_completion_order_case( 1 );
  run_lthash_bubble_case();
  run_lthash_batch_cap_case();
  run_lthash_batch_held_tail_case();
  run_lthash_batch_held_behind_txn_case();
  run_lthash_drain_chunk_case();
  run_lthash_drain_end_case();
  run_lthash_drain_switch_case();
  run_lthash_dying_parent_case();
  run_lthash_drain_active_first_case();
  run_lthash_writer_bound_case( 0 );
  run_lthash_writer_bound_case( 1 );
  run_lthash_writer_bound_case( 2 );
  run_lthash_writer_bound_case( 3 );
  run_lthash_writer_bound_full_case();

  fd_wksp_delete_anonymous( test_wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
