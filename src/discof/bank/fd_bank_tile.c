#include "fd_bank_err.h"

#include "../../disco/tiles.h"
#include "generated/fd_bank_tile_seccomp.h"
#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/pack/fd_pack_rebate_sum.h"
#include "../../disco/metrics/generated/fd_metrics_bank.h"
#include "../../disco/metrics/generated/fd_metrics_enums.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_bank.h"

typedef struct {
  ulong kind_id;

  fd_blake3_t * blake3;
  void * bmtree;

  ulong _bank_idx;
  ulong _pack_idx;
  ulong _txn_idx;
  int _is_bundle;

  ulong * busy_fseq;

  fd_wksp_t * pack_in_mem;
  ulong       pack_in_chunk0;
  ulong       pack_in_wmark;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  fd_wksp_t * rebate_mem;
  ulong       rebate_chunk0;
  ulong       rebate_wmark;
  ulong       rebate_chunk;
  ulong       rebates_for_slot;
  fd_pack_rebate_sum_t rebater[ 1 ];

  fd_banks_t * banks;
  fd_spad_t *  exec_spad;

  fd_funk_t      funk[1];
  fd_progcache_t progcache[1];

  fd_exec_txn_ctx_t txn_ctx[1];

  struct {
    ulong txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_CNT ];
  } metrics;
} fd_bank_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_bank_ctx_t ),   sizeof( fd_bank_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, FD_BLAKE3_ALIGN,            FD_BLAKE3_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN,     FD_BMTREE_COMMIT_FOOTPRINT(0) );
  l = FD_LAYOUT_APPEND( l, FD_SPAD_ALIGN,              FD_SPAD_FOOTPRINT( FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT ) );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),        fd_txncache_footprint( tile->bank.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_bank_ctx_t * ctx ) {
  FD_MCNT_ENUM_COPY( BANKF, TRANSACTION_RESULT, ctx->metrics.txn_result );
}

static int
before_frag( fd_bank_ctx_t * ctx,
             ulong           in_idx,
             ulong           seq,
             ulong           sig ) {
  (void)in_idx;
  (void)seq;

  /* Pack also outputs "leader slot done" which we can ignore. */
  if( FD_UNLIKELY( fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_MICROBLOCK ) ) return 1;

  ulong target_bank_kind_id = fd_disco_poh_sig_bank_tile( sig );
  if( FD_UNLIKELY( target_bank_kind_id!=ctx->kind_id ) ) return 1;

  return 0;
}

static inline void
during_frag( fd_bank_ctx_t * ctx,
             ulong           in_idx FD_PARAM_UNUSED,
             ulong           seq    FD_PARAM_UNUSED,
             ulong           sig    FD_PARAM_UNUSED,
             ulong           chunk,
             ulong           sz,
             ulong           ctl    FD_PARAM_UNUSED ) {

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->pack_in_mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  if( FD_UNLIKELY( chunk<ctx->pack_in_chunk0 || chunk>ctx->pack_in_wmark || sz>USHORT_MAX ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->pack_in_chunk0, ctx->pack_in_wmark ));

  fd_memcpy( dst, src, sz-sizeof(fd_microblock_bank_trailer_t) );
  fd_microblock_bank_trailer_t * trailer = (fd_microblock_bank_trailer_t *)( src+sz-sizeof(fd_microblock_bank_trailer_t) );
  ctx->_bank_idx  = trailer->bank_idx;
  ctx->_pack_idx  = trailer->pack_idx;
  ctx->_txn_idx   = trailer->pack_txn_idx;
  ctx->_is_bundle = trailer->is_bundle;
}

static void
hash_transactions( void *       mem,
                   fd_txn_p_t * txns,
                   ulong        txn_cnt,
                   uchar *      mixin ) {
  fd_bmtree_commit_t * bmtree = fd_bmtree_commit_init( mem, 32UL, 1UL, 0UL );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * _txn = txns + i;
    if( FD_UNLIKELY( !(_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) continue;

    fd_txn_t * txn = TXN(_txn);
    for( ulong j=0; j<txn->signature_cnt; j++ ) {
      fd_bmtree_node_t node[1];
      fd_bmtree_hash_leaf( node, _txn->payload+txn->signature_off+64UL*j, 64UL, 1UL );
      fd_bmtree_commit_append( bmtree, node, 1UL );
    }
  }
  uchar * root = fd_bmtree_commit_fini( bmtree );
  fd_memcpy( mixin, root, 32UL );
}

static inline void
handle_microblock( fd_bank_ctx_t *     ctx,
                   ulong               seq,
                   ulong               sig,
                   ulong               sz,
                   ulong               begin_tspub,
                   fd_stem_context_t * stem ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  ulong slot = fd_disco_poh_sig_slot( sig );
  ulong txn_cnt = (sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t);

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, ctx->_bank_idx );
  FD_TEST( bank );
  ulong bank_slot = fd_bank_slot_get( bank );
  FD_TEST( bank_slot==slot );

  fd_acct_addr_t const * writable_alt[ MAX_TXN_PER_MICROBLOCK ] = { NULL };

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)( dst + (i*sizeof(fd_txn_p_t)) );
    fd_exec_txn_ctx_t * txn_ctx = ctx->txn_ctx;

    txn->flags &= ~FD_TXN_P_FLAGS_SANITIZE_SUCCESS;

    uint requested_exec_plus_acct_data_cus = txn->pack_cu.requested_exec_plus_acct_data_cus;
    uint non_execution_cus                 = txn->pack_cu.non_execution_cus;

    /* Assume failure, set below if success.  If it doesn't land in the
       block, rebate the non-execution CUs too. */
    txn->bank_cu.actual_consumed_cus = 0U;
    txn->bank_cu.rebated_cus = requested_exec_plus_acct_data_cus + non_execution_cus;

    FD_SPAD_FRAME_BEGIN( ctx->exec_spad ) {

    int err = fd_runtime_prepare_and_execute_txn( ctx->banks, ctx->_bank_idx, txn_ctx, txn, NULL );
    if( FD_UNLIKELY( !(txn_ctx->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
      ctx->metrics.txn_result[ fd_bank_err_from_runtime_err( err ) ]++;
      continue;
    }

    /* The account keys in the transaction context are laid out such
       that first the non-alt accounts are laid out, then the writable
       alt accounts, and finally the read-only alt accounts. */
    fd_txn_t * txn_descriptor = TXN( &txn_ctx->txn );
    writable_alt[ i ] = fd_type_pun_const( txn_ctx->account_keys+txn_descriptor->acct_addr_cnt );

    txn->flags |= FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    txn->flags &= ~FD_TXN_P_FLAGS_EXECUTE_SUCCESS;

    /* Stash the result in the flags value so that pack can inspect it. */
    /* TODO: Need to translate the err to a hacky Frankendancer style err
             that pack and GUI expect ... */
    txn->flags = (txn->flags & 0x00FFFFFFU) | ((uint)(-err)<<24);

    ctx->metrics.txn_result[ fd_bank_err_from_runtime_err( err ) ]++;

    uint actual_execution_cus = (uint)(txn_ctx->compute_budget_details.compute_unit_limit - txn_ctx->compute_budget_details.compute_meter);
    uint actual_acct_data_cus = (uint)(txn_ctx->loaded_accounts_data_size_cost);

    int is_simple_vote = 0;
    if( FD_UNLIKELY( is_simple_vote = fd_txn_is_simple_vote_transaction( TXN(txn), txn->payload ) ) ) {
      /* Simple votes are charged fixed amounts of compute regardless of
         the real cost they incur.  Unclear what cost is returned by
         fd_execute txn, however, so we override it here. */
      actual_execution_cus = FD_PACK_VOTE_DEFAULT_COMPUTE_UNITS;
      actual_acct_data_cus = 0U;
    }

    /* FeesOnly transactions are transactions that failed to load
       before they even reach the VM stage. They have zero execution
       cost but do charge for the account data they are able to load.
       FeesOnly votes are charged the fixed voe cost. */
    txn->bank_cu.rebated_cus = requested_exec_plus_acct_data_cus - ( actual_execution_cus + actual_acct_data_cus );
    txn->bank_cu.actual_consumed_cus = non_execution_cus + actual_execution_cus + actual_acct_data_cus;

    /* TXN_P_FLAGS_EXECUTE_SUCCESS means that it should be included in
       the block.  It's a bit of a misnomer now that there are fee-only
       transactions. */
    FD_TEST( txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS );
    txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;

    /* The VM will stop executing and fail an instruction immediately if
       it exceeds its requested CUs.  A transaction which requests less
       account data than it actually consumes will fail in the account
       loading stage. */
    if( FD_UNLIKELY( actual_execution_cus+actual_acct_data_cus>requested_exec_plus_acct_data_cus ) ) {
      FD_LOG_HEXDUMP_WARNING(( "txn", txn->payload, txn->payload_sz ));
      FD_LOG_ERR(( "Actual CUs unexpectedly exceeded requested amount. actual_execution_cus (%u) actual_acct_data_cus "
                   "(%u) requested_exec_plus_acct_data_cus (%u) is_simple_vote (%i) exec_failed (%i)",
                   actual_execution_cus, actual_acct_data_cus, requested_exec_plus_acct_data_cus, is_simple_vote,
                   err ));
    }

    /* Commit must succeed so no failure path.  Once commit is called,
       the transactions MUST be mixed into the PoH otherwise we will
       fork and diverge, so the link from here til PoH mixin must be
       completely reliable with nothing dropped.

       fd_runtime_finalize_txn checks if the transaction fits into the
       block with the cost tracker.  If it doesn't fit, flags is set to
       zero.  A key invariant of the leader pipeline is that pack
       ensures all transactions must fit already, so it is a fatal error
       if that happens.  We cannot reject the transaction here as there
       would be no way to undo the partially applied changes to the bank
       in finalize anyway. */
    fd_runtime_finalize_txn( ctx->txn_ctx->funk, ctx->txn_ctx->progcache, txn_ctx->status_cache, txn_ctx->xid, txn_ctx, bank, NULL );

    } FD_SPAD_FRAME_END;

    if( FD_UNLIKELY( !txn_ctx->flags ) ) {
      fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_locking_modify( bank );
      fd_hash_t * signature = (fd_hash_t *)((uchar *)txn_ctx->txn.payload + TXN( &txn_ctx->txn )->signature_off);
      int res = fd_cost_tracker_calculate_cost_and_add( cost_tracker, txn_ctx );
      FD_LOG_HEXDUMP_WARNING(( "txn", txn->payload, txn->payload_sz ));
      FD_LOG_CRIT(( "transaction %s failed to fit into block despite pack guaranteeing it would "
                    "(res=%d) [block_cost=%lu, vote_cost=%lu, allocated_accounts_data_size=%lu, "
                    "block_cost_limit=%lu, vote_cost_limit=%lu, account_cost_limit=%lu]",
                    FD_BASE58_ENC_32_ALLOCA( signature->uc ), res, cost_tracker->block_cost, cost_tracker->vote_cost,
                    cost_tracker->allocated_accounts_data_size,
                    cost_tracker->block_cost_limit, cost_tracker->vote_cost_limit,
                    cost_tracker->account_cost_limit ));
    }

    FD_TEST( txn_ctx->flags );
  }

  /* Indicate to pack tile we are done processing the transactions so
     it can pack new microblocks using these accounts. */
  fd_fseq_update( ctx->busy_fseq, seq );

  /* Prepare the rebate */
  fd_pack_rebate_sum_add_txn( ctx->rebater, (fd_txn_p_t const *)dst, writable_alt, txn_cnt );

  /* Now produce the merkle hash of the transactions for inclusion
     (mixin) to the PoH hash.  This is done on the bank tile because
     it shards / scales horizontally here, while PoH does not. */
  fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)( dst + txn_cnt*sizeof(fd_txn_p_t) );
  hash_transactions( ctx->bmtree, (fd_txn_p_t*)dst, txn_cnt, trailer->hash );
  trailer->pack_txn_idx = ctx->_txn_idx;
  trailer->tips = 0UL;

  long tickcount                 = fd_tickcount();
  long microblock_start_ticks    = fd_frag_meta_ts_decomp( begin_tspub, tickcount );
  long microblock_duration_ticks = fd_long_max(tickcount - microblock_start_ticks, 0L);

  // TODO: Execution timestamps
  long tx_start_ticks       = 0L; //(long)out_timestamps[ 0 ];
  long tx_load_end_ticks    = 0L; //(long)out_timestamps[ 1 ];
  long tx_end_ticks         = 0L; //(long)out_timestamps[ 2 ];
  long tx_preload_end_ticks = 0L; //(long)out_timestamps[ 3 ];

  trailer->txn_start_pct       = (uchar)(((double)(tx_start_ticks       - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
  trailer->txn_load_end_pct    = (uchar)(((double)(tx_load_end_ticks    - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
  trailer->txn_end_pct         = (uchar)(((double)(tx_end_ticks         - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
  trailer->txn_preload_end_pct = (uchar)(((double)(tx_preload_end_ticks - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);

  /* MAX_MICROBLOCK_SZ - (MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t)) == 64
     so there's always 64 extra bytes at the end to stash the hash. */
  FD_STATIC_ASSERT( MAX_MICROBLOCK_SZ-(MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t))>=sizeof(fd_microblock_trailer_t), poh_shred_mtu );
  FD_STATIC_ASSERT( MAX_MICROBLOCK_SZ-(MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t))>=sizeof(fd_microblock_bank_trailer_t), poh_shred_mtu );

  /* We have a race window with the GUI, where if the slot is ending it
     will snap these metrics to draw the waterfall, but see them outdated
     because housekeeping hasn't run.  For now just update them here, but
     PoH should eventually flush the pipeline before ending the slot. */
  metrics_write( ctx );

  ulong bank_sig = fd_disco_bank_sig( slot, ctx->_pack_idx );

  /* We always need to publish, even if there are no successfully executed
     transactions so the PoH tile can keep an accurate count of microblocks
     it has seen. */
  ulong new_sz = txn_cnt*sizeof(fd_txn_p_t) + sizeof(fd_microblock_trailer_t);
  fd_stem_publish( stem, 0UL, bank_sig, ctx->out_chunk, new_sz, 0UL, 0UL, (ulong)fd_frag_meta_ts_comp( tickcount ) );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, new_sz, ctx->out_chunk0, ctx->out_wmark );
}

static inline void
handle_bundle( fd_bank_ctx_t *     ctx,
               ulong               seq,
               ulong               sig,
               ulong               sz,
               ulong               begin_tspub,
               fd_stem_context_t * stem ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_txn_p_t * txns = (fd_txn_p_t *)dst;

  ulong slot = fd_disco_poh_sig_slot( sig );
  ulong txn_cnt = (sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t);

  fd_acct_addr_t const * writable_alt[ MAX_TXN_PER_MICROBLOCK ] = { NULL };

  int execution_success = 1;
  int transaction_err[ MAX_TXN_PER_MICROBLOCK ];
  for( ulong i=0UL; i<txn_cnt; i++ ) transaction_err[ i ] = 40; /* Pack interprets this as BUNDLE_PEER due to Frankendancer*/

  uint actual_execution_cus [   MAX_TXN_PER_MICROBLOCK ] = { 0U };
  uint actual_acct_data_cus [   MAX_TXN_PER_MICROBLOCK ] = { 0U };
  ulong out_timestamps      [ 4*MAX_TXN_PER_MICROBLOCK ] = { 0U };
  ulong tips                [   MAX_TXN_PER_MICROBLOCK ] = { 0U };

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = txns+i;

    fd_exec_txn_ctx_t txn_ctx[ 1 ]; // TODO ... bank manager ?
    txn->flags &= ~(FD_TXN_P_FLAGS_SANITIZE_SUCCESS | FD_TXN_P_FLAGS_EXECUTE_SUCCESS);
    int err = fd_runtime_prepare_and_execute_txn( NULL, ULONG_MAX, txn_ctx, txn, NULL ); /* TODO ... */

    transaction_err[ i ] = err;
    if( FD_UNLIKELY( err ) ) {
      execution_success = 0;
      break;
    }

    /* The account keys in the transaction context are laid out such
       that first the non-alt accounts are laid out, then the writable
       alt accounts, and finally the read-only alt accounts. */
    fd_txn_t * txn_descriptor = TXN( &txn_ctx->txn );
    for( ushort i=txn_descriptor->acct_addr_cnt; i<txn_descriptor->acct_addr_cnt+txn_descriptor->addr_table_adtl_writable_cnt; i++ ) {
      writable_alt[ i ] = fd_type_pun_const( &txn_ctx->account_keys[ i ] );
    }

    txn->flags |= FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    actual_execution_cus[ i ] = (uint)(txn_ctx->compute_budget_details.compute_unit_limit - txn_ctx->compute_budget_details.compute_meter);
    actual_acct_data_cus[ i ] = (uint)(txn_ctx->loaded_accounts_data_size);
    (void)tips; // TODO: GUI, report tips
    (void)out_timestamps; // TODO: GUI, report timestamps
  }

  for( ulong i=0UL; i<txn_cnt; i++ ) ctx->metrics.txn_result[ fd_bank_err_from_runtime_err( transaction_err[ i ] ) ]++;

  if( FD_LIKELY( execution_success ) ) {
    for( ulong i=0UL; i<txn_cnt; i++ ) {
      txns[ i ].flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
      txns[ i ].flags = (txns[ i ].flags & 0x00FFFFFFU); /* Clear error bits to indicate success */
    }
  } else {
    /* If any transaction fails in a bundle ... they all fail */
    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_txn_p_t * txn = txns+i;

      if( FD_UNLIKELY( !(txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) ) ) continue;
      txn->flags &= ~FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
      txn->flags = (txn->flags & 0x00FFFFFFU) | ((uint)(-transaction_err[ i ])<<24);
    }
  }

  /* Indicate to pack tile we are done processing the transactions so
     it can pack new microblocks using these accounts. */
  fd_fseq_update( ctx->busy_fseq, seq );

  uint consumed_cus[ MAX_TXN_PER_MICROBLOCK ] = { 0U };

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = txns+i;

    uint requested_exec_plus_acct_data_cus = txn->pack_cu.requested_exec_plus_acct_data_cus;
    uint non_execution_cus                 = txn->pack_cu.non_execution_cus;

    if( FD_UNLIKELY( fd_txn_is_simple_vote_transaction( TXN(txns + i), txns[ i ].payload ) ) ) {
      /* Although bundles dont typically contain simple votes, we want
        to charge them correctly anyways. */
      consumed_cus[ i ] = FD_PACK_VOTE_DEFAULT_COMPUTE_UNITS;
    } else {
      /* Note that some transactions will have 0 consumed cus because
         they were never actually executed, due to an earlier
         transaction failing. */
      consumed_cus[ i ] = actual_execution_cus[ i ] + actual_acct_data_cus[ i ];
    }

    /* Assume failure, set below if success.  If it doesn't land in the
       block, rebate the non-execution CUs too. */
    txn->bank_cu.rebated_cus = requested_exec_plus_acct_data_cus + non_execution_cus;

    /* We want to include consumed CUs for failed bundles for
       monitoring, even though they aren't included in the block.  This
       is safe because the poh tile first checks if a txn is included in
       the block before counting its "actual_consumed_cus" towards the
       block tally. */
    txn->bank_cu.actual_consumed_cus = non_execution_cus + consumed_cus[ i ];

    if( FD_LIKELY( execution_success ) ) {
      if( FD_UNLIKELY( consumed_cus[ i ] > requested_exec_plus_acct_data_cus ) ) {
        FD_LOG_HEXDUMP_WARNING(( "txn", txn->payload, txn->payload_sz ));
        FD_LOG_ERR(( "transaction %lu in bundle consumed %u CUs > requested %u CUs", i, consumed_cus[ i ], requested_exec_plus_acct_data_cus ));
      }

      txn->bank_cu.actual_consumed_cus = non_execution_cus + consumed_cus[ i ];
      txn->bank_cu.rebated_cus = requested_exec_plus_acct_data_cus - consumed_cus[ i ];
    }
  }

  fd_pack_rebate_sum_add_txn( ctx->rebater, txns, writable_alt, txn_cnt );

  /* We need to publish each transaction separately into its own
     microblock, so make a temporary copy on the stack so we can move
     all the data around. */
  fd_txn_p_t bundle_txn_temp[ 5UL ];
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    bundle_txn_temp[ i ] = txns[ i ];
  }

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    fd_memcpy( dst, bundle_txn_temp+i, sizeof(fd_txn_p_t) );

    fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)( dst+sizeof(fd_txn_p_t) );
    hash_transactions( ctx->bmtree, (fd_txn_p_t*)dst, 1UL, trailer->hash );
    trailer->pack_txn_idx = ctx->_txn_idx + i;
    trailer->tips = tips[ i ];

    ulong bank_sig = fd_disco_bank_sig( slot, ctx->_pack_idx+i );

    long tickcount                 = fd_tickcount();
    long microblock_start_ticks    = fd_frag_meta_ts_decomp( begin_tspub, tickcount );
    long microblock_duration_ticks = fd_long_max(tickcount - microblock_start_ticks, 0L);

    long tx_start_ticks       = (long)out_timestamps[ 4*i + 0 ];
    long tx_load_end_ticks    = (long)out_timestamps[ 4*i + 1 ];
    long tx_end_ticks         = (long)out_timestamps[ 4*i + 2 ];
    long tx_preload_end_ticks = (long)out_timestamps[ 4*i + 3 ];

    trailer->txn_start_pct       = (uchar)(((double)(tx_start_ticks       - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
    trailer->txn_load_end_pct    = (uchar)(((double)(tx_load_end_ticks    - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
    trailer->txn_end_pct         = (uchar)(((double)(tx_end_ticks         - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
    trailer->txn_preload_end_pct = (uchar)(((double)(tx_preload_end_ticks - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);

    ulong new_sz = sizeof(fd_txn_p_t) + sizeof(fd_microblock_trailer_t);
    fd_stem_publish( stem, 0UL, bank_sig, ctx->out_chunk, new_sz, 0UL, 0UL, (ulong)fd_frag_meta_ts_comp( tickcount ) );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, new_sz, ctx->out_chunk0, ctx->out_wmark );
  }

  metrics_write( ctx );
}

static inline void
after_frag( fd_bank_ctx_t *     ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx;

  ulong slot = fd_disco_poh_sig_slot( sig );
  if( FD_UNLIKELY( slot!=ctx->rebates_for_slot ) ) {
    /* If pack has already moved on to a new slot, the rebates are no
       longer useful. */
    fd_pack_rebate_sum_clear( ctx->rebater );
    ctx->rebates_for_slot = slot;
  }

  if( FD_UNLIKELY( ctx->_is_bundle ) ) handle_bundle( ctx, seq, sig, sz, tspub, stem );
  else                                 handle_microblock( ctx, seq, sig, sz, tspub, stem );

  /* TODO: Use fancier logic to coalesce rebates e.g. and move this to
     after_credit */
  ulong written_sz = 0UL;
  while( 0UL!=(written_sz=fd_pack_rebate_sum_report( ctx->rebater, fd_chunk_to_laddr( ctx->rebate_mem, ctx->rebate_chunk ) )) ) {
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, 1UL, slot, ctx->rebate_chunk, written_sz, 0UL, tsorig, tspub );
    ctx->rebate_chunk = fd_dcache_compact_next( ctx->rebate_chunk, written_sz, ctx->rebate_chunk0, ctx->rebate_wmark );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bank_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bank_ctx_t ),   sizeof( fd_bank_ctx_t ) );
  void * blake3       = FD_SCRATCH_ALLOC_APPEND( l, FD_BLAKE3_ALIGN,            FD_BLAKE3_FOOTPRINT );
  void * bmtree       = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN,     FD_BMTREE_COMMIT_FOOTPRINT(0) );
  void * exec_spad    = FD_SCRATCH_ALLOC_APPEND( l, FD_SPAD_ALIGN,              FD_SPAD_FOOTPRINT( FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT ) );
  void * _txncache    = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),        fd_txncache_footprint( tile->bank.max_live_slots ) );
  void * pc_scratch   = FD_SCRATCH_ALLOC_APPEND( l, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT );

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ctx->kind_id   = tile->kind_id;
  ctx->blake3    = NONNULL( fd_blake3_join( fd_blake3_new( blake3 ) ) );
  ctx->bmtree    = NONNULL( bmtree );
  ctx->exec_spad = NONNULL( fd_spad_join( fd_spad_new( exec_spad, FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT ) ) );

  NONNULL( fd_pack_rebate_sum_join( fd_pack_rebate_sum_new( ctx->rebater ) ) );
  ctx->rebates_for_slot  = 0UL;

  void * shfunk = fd_topo_obj_laddr( topo, tile->bank.funk_obj_id );
  FD_TEST( shfunk );
  fd_funk_t * funk = fd_funk_join( ctx->funk, shfunk );
  FD_TEST( funk );

  void * shprogcache = fd_topo_obj_laddr( topo, tile->bank.progcache_obj_id );
  FD_TEST( shprogcache );
  fd_progcache_t * progcache = fd_progcache_join( ctx->progcache, shprogcache, pc_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT );
  FD_TEST( progcache );

  NONNULL( fd_exec_txn_ctx_join( fd_exec_txn_ctx_new( ctx->txn_ctx ), ctx->exec_spad, fd_wksp_containing( exec_spad ) ) );
  ctx->txn_ctx->bank_hash_cmp = NULL; /* TODO - do we need this? */
  ctx->txn_ctx->spad          = ctx->exec_spad;
  ctx->txn_ctx->spad_wksp     = fd_wksp_containing( exec_spad );
  *(ctx->txn_ctx->funk)       = *funk;
  *(ctx->txn_ctx->_progcache) = *progcache;
  ctx->txn_ctx->progcache     = ctx->txn_ctx->_progcache;

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->bank.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  fd_txncache_t * txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( txncache );
  ctx->txn_ctx->status_cache = txncache;

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ctx->banks = NONNULL( fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) ) );

  ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", tile->kind_id );
  FD_TEST( busy_obj_id!=ULONG_MAX );
  ctx->busy_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
  if( FD_UNLIKELY( !ctx->busy_fseq ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", tile->kind_id ));

  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  ctx->pack_in_mem = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0UL ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_in_chunk0 = fd_dcache_compact_chunk0( ctx->pack_in_mem, topo->links[ tile->in_link_id[ 0UL ] ].dcache );
  ctx->pack_in_wmark  = fd_dcache_compact_wmark ( ctx->pack_in_mem, topo->links[ tile->in_link_id[ 0UL ] ].dcache, topo->links[ tile->in_link_id[ 0UL ] ].mtu );

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;


  ctx->rebate_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 1 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->rebate_chunk0 = fd_dcache_compact_chunk0( ctx->rebate_mem, topo->links[ tile->out_link_id[ 1 ] ].dcache );
  ctx->rebate_wmark  = fd_dcache_compact_wmark ( ctx->rebate_mem, topo->links[ tile->out_link_id[ 1 ] ].dcache, topo->links[ tile->out_link_id[ 1 ] ].mtu );
  ctx->rebate_chunk  = ctx->rebate_chunk0;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_bank_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_bank_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

/* For a bundle, one bundle might burst into at most 5 separate PoH mixins, since the
   microblocks cannot be conflicting. */

#define STEM_BURST (5UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_bank_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_bank_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_bank = {
  .name                     = "bank",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
