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
#include "../../flamenco/runtime/fd_acc_pool.h"
#include "../../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../../flamenco/progcache/fd_progcache_user.h"
#include "../../flamenco/log_collector/fd_log_collector.h"

struct fd_bank_out {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_bank_out fd_bank_out_t;

struct fd_bank_ctx {
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

  fd_bank_out_t out_poh[1];
  fd_bank_out_t out_pack[1];

  ulong rebates_for_slot;
  int enable_rebates;
  fd_pack_rebate_sum_t rebater[ 1 ];

  fd_banks_t banksl_join[1];
  fd_banks_t * banks;

  fd_accdb_user_t accdb[1];
  fd_progcache_t  progcache[1];

  fd_runtime_t runtime[1];

  /* For bundle execution, we need to execute each transaction against
     a separate transaction context and a set of accounts, but the exec
     stack can be reused.  We will also use these same memory regions
     for non-bundle execution. */
  fd_txn_in_t  txn_in[ FD_PACK_MAX_TXN_PER_BUNDLE ];
  fd_txn_out_t txn_out[ FD_PACK_MAX_TXN_PER_BUNDLE ];

  fd_log_collector_t log_collector[ 1 ];

  struct {
    ulong txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_CNT ];
    ulong txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_CNT ];
  } metrics;
};

typedef struct fd_bank_ctx fd_bank_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_bank_ctx_t ),   sizeof( fd_bank_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, FD_BLAKE3_ALIGN,            FD_BLAKE3_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN,     FD_BMTREE_COMMIT_FOOTPRINT(0) );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),        fd_txncache_footprint( tile->bank.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_bank_ctx_t * ctx ) {
  FD_MCNT_ENUM_COPY( BANKF, TRANSACTION_RESULT, ctx->metrics.txn_result );
  FD_MCNT_ENUM_COPY( BANKF, TRANSACTION_LANDED, ctx->metrics.txn_landed );
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
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_poh->mem, ctx->out_poh->chunk );

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
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_poh->mem, ctx->out_poh->chunk );

  ulong slot = fd_disco_poh_sig_slot( sig );
  ulong txn_cnt = (sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t);

  fd_bank_t bank[1];
  FD_TEST( fd_banks_bank_query( bank, ctx->banks, ctx->_bank_idx ) );
  ulong bank_slot = fd_bank_slot_get( bank );
  FD_TEST( bank_slot==slot );

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t *   txn     = (fd_txn_p_t *)( dst + (i*sizeof(fd_txn_p_t)) );
    fd_txn_in_t *  txn_in  = &ctx->txn_in[ 0 ];
    fd_txn_out_t * txn_out = &ctx->txn_out[ 0 ];

    uint requested_exec_plus_acct_data_cus = txn->pack_cu.requested_exec_plus_acct_data_cus;
    uint non_execution_cus                 = txn->pack_cu.non_execution_cus;

    /* Assume failure, set below if success.  If it doesn't land in the
       block, rebate the non-execution CUs too. */
    txn->bank_cu.actual_consumed_cus = 0U;
    txn->bank_cu.rebated_cus = requested_exec_plus_acct_data_cus + non_execution_cus;
    txn->flags &= ~FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    txn->flags &= ~FD_TXN_P_FLAGS_EXECUTE_SUCCESS;

    txn_in->bundle.is_bundle = 0;
    txn_in->txn              = txn;

    fd_runtime_prepare_and_execute_txn( ctx->runtime, bank, txn_in, txn_out );

    /* Stash the result in the flags value so that pack can inspect it. */
    txn->flags = (txn->flags & 0x00FFFFFFU) | ((uint)(-txn_out->err.txn_err)<<24);

    if( FD_UNLIKELY( !txn_out->err.is_committable ) ) {
      FD_TEST( !txn_out->err.is_fees_only );
      fd_runtime_cancel_txn( ctx->runtime, txn_out );
      if( FD_LIKELY( ctx->enable_rebates ) ) fd_pack_rebate_sum_add_txn( ctx->rebater, txn, NULL, 1UL );
      ctx->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_UNLANDED_IDX ]++;
      ctx->metrics.txn_result[ fd_bank_err_from_runtime_err( txn_out->err.txn_err ) ]++;
      continue;
    }

    if( FD_UNLIKELY( txn_out->err.is_fees_only ) ) ctx->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_FEES_ONLY_IDX ]++;
    else if( FD_UNLIKELY( txn_out->err.txn_err ) ) ctx->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_FAILED_IDX    ]++;
    else                                           ctx->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_SUCCESS_IDX   ]++;

    /* TXN_P_FLAGS_EXECUTE_SUCCESS means that it should be included in
       the block.  It's a bit of a misnomer now that there are fee-only
       transactions. */
    txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS | FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    ctx->metrics.txn_result[ fd_bank_err_from_runtime_err( txn_out->err.txn_err ) ]++;

    /* Commit must succeed so no failure path.  Once commit is called,
       the transactions MUST be mixed into the PoH otherwise we will
       fork and diverge, so the link from here til PoH mixin must be
       completely reliable with nothing dropped.

       fd_runtime_commit_txn checks if the transaction fits into the
       block with the cost tracker.  If it doesn't fit, flags is set to
       zero.  A key invariant of the leader pipeline is that pack
       ensures all transactions must fit already, so it is a fatal error
       if that happens.  We cannot reject the transaction here as there
       would be no way to undo the partially applied changes to the bank
       in finalize anyway. */
    fd_runtime_commit_txn( ctx->runtime, bank, txn_out );

    if( FD_UNLIKELY( !txn_out->err.is_committable ) ) {
      /* If the transaction failed to fit into the block, we need to
         updated the transaction flag with the error code. */
      txn->flags = (txn->flags & 0x00FFFFFFU) | ((uint)(-txn_out->err.txn_err)<<24);
      fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_locking_modify( bank );
      uchar * signature = (uchar *)txn_in->txn->payload + TXN( txn_in->txn )->signature_off;
      int err = fd_cost_tracker_try_add_cost( cost_tracker, txn_out );
      FD_LOG_HEXDUMP_WARNING(( "txn", txn->payload, txn->payload_sz ));
      FD_BASE58_ENCODE_64_BYTES( signature, signature_b58 );
      FD_LOG_CRIT(( "transaction %s failed to fit into block despite pack guaranteeing it would "
                    "(res=%d) [block_cost=%lu, vote_cost=%lu, allocated_accounts_data_size=%lu, "
                    "block_cost_limit=%lu, vote_cost_limit=%lu, account_cost_limit=%lu]",
                    signature_b58, err, cost_tracker->block_cost, cost_tracker->vote_cost,
                    cost_tracker->allocated_accounts_data_size,
                    cost_tracker->block_cost_limit, cost_tracker->vote_cost_limit,
                    cost_tracker->account_cost_limit ));
    }

    uint actual_execution_cus = (uint)(txn_out->details.compute_budget.compute_unit_limit - txn_out->details.compute_budget.compute_meter);
    uint actual_acct_data_cus = (uint)(txn_out->details.txn_cost.transaction.loaded_accounts_data_size_cost);

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
    txn->bank_cu.rebated_cus         = requested_exec_plus_acct_data_cus - (actual_execution_cus + actual_acct_data_cus);
    txn->bank_cu.actual_consumed_cus = non_execution_cus + actual_execution_cus + actual_acct_data_cus;

    /* The account keys in the transaction context are laid out such
       that first the non-alt accounts are laid out, then the writable
       alt accounts, and finally the read-only alt accounts. */
    fd_txn_t * txn_descriptor = TXN( txn_in->txn );
    fd_acct_addr_t const * writable_alt = fd_type_pun_const( txn_out->accounts.keys+txn_descriptor->acct_addr_cnt );
    if( FD_LIKELY( ctx->enable_rebates ) ) fd_pack_rebate_sum_add_txn( ctx->rebater, txn, &writable_alt, 1UL );

    /* The VM will stop executing and fail an instruction immediately if
       it exceeds its requested CUs.  A transaction which requests less
       account data than it actually consumes will fail in the account
       loading stage. */
    if( FD_UNLIKELY( actual_execution_cus+actual_acct_data_cus>requested_exec_plus_acct_data_cus ) ) {
      FD_LOG_HEXDUMP_WARNING(( "txn", txn->payload, txn->payload_sz ));
      FD_LOG_ERR(( "Actual CUs unexpectedly exceeded requested amount. actual_execution_cus (%u) actual_acct_data_cus "
                   "(%u) requested_exec_plus_acct_data_cus (%u) is_simple_vote (%i) exec_failed (%i)",
                   actual_execution_cus, actual_acct_data_cus, requested_exec_plus_acct_data_cus, is_simple_vote,
                   txn_out->err.txn_err ));
    }

  }

  /* Indicate to pack tile we are done processing the transactions so
     it can pack new microblocks using these accounts. */
  fd_fseq_update( ctx->busy_fseq, seq );

  /* Now produce the merkle hash of the transactions for inclusion
     (mixin) to the PoH hash.  This is done on the bank tile because
     it shards / scales horizontally here, while PoH does not. */
  fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)( dst + txn_cnt*sizeof(fd_txn_p_t) );
  hash_transactions( ctx->bmtree, (fd_txn_p_t*)dst, txn_cnt, trailer->hash );
  trailer->pack_txn_idx = ctx->_txn_idx;
  trailer->tips         = ctx->txn_out[ 0 ].details.tips;

  long tickcount                 = fd_tickcount();
  long microblock_start_ticks    = fd_frag_meta_ts_decomp( begin_tspub, tickcount );
  long microblock_duration_ticks = fd_long_max(tickcount - microblock_start_ticks, 0L);

  long tx_preload_end_ticks = fd_long_if( ctx->txn_out[ 0 ].details.prep_start_timestamp!=LONG_MAX,   ctx->txn_out[ 0 ].details.prep_start_timestamp,   microblock_start_ticks );
  long tx_start_ticks       = fd_long_if( ctx->txn_out[ 0 ].details.load_start_timestamp!=LONG_MAX,   ctx->txn_out[ 0 ].details.load_start_timestamp,   tx_preload_end_ticks   );
  long tx_load_end_ticks    = fd_long_if( ctx->txn_out[ 0 ].details.exec_start_timestamp!=LONG_MAX,   ctx->txn_out[ 0 ].details.exec_start_timestamp,   tx_start_ticks         );
  long tx_end_ticks         = fd_long_if( ctx->txn_out[ 0 ].details.commit_start_timestamp!=LONG_MAX, ctx->txn_out[ 0 ].details.commit_start_timestamp, tx_load_end_ticks      );

  trailer->txn_preload_end_pct = (uchar)(((double)(tx_preload_end_ticks - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
  trailer->txn_start_pct       = (uchar)(((double)(tx_start_ticks       - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
  trailer->txn_load_end_pct    = (uchar)(((double)(tx_load_end_ticks    - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
  trailer->txn_end_pct         = (uchar)(((double)(tx_end_ticks         - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);

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
  fd_stem_publish( stem, ctx->out_poh->idx, bank_sig, ctx->out_poh->chunk, new_sz, 0UL, (ulong)fd_frag_meta_ts_comp( microblock_start_ticks ), (ulong)fd_frag_meta_ts_comp( tickcount ) );
  ctx->out_poh->chunk = fd_dcache_compact_next( ctx->out_poh->chunk, new_sz, ctx->out_poh->chunk0, ctx->out_poh->wmark );
}

static inline void
handle_bundle( fd_bank_ctx_t *     ctx,
               ulong               seq,
               ulong               sig,
               ulong               sz,
               ulong               begin_tspub,
               fd_stem_context_t * stem ) {

  fd_txn_p_t * txns = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->out_poh->mem, ctx->out_poh->chunk );

  ulong slot = fd_disco_poh_sig_slot( sig );
  ulong txn_cnt = (sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t);

  fd_bank_t bank[1];
  FD_TEST( fd_banks_bank_query( bank, ctx->banks, ctx->_bank_idx ) );
  FD_TEST( bank );
  ulong bank_slot = fd_bank_slot_get( bank );
  FD_TEST( bank_slot==slot );

  fd_acct_addr_t const * writable_alt[ MAX_TXN_PER_MICROBLOCK ] = { NULL };
  ulong                  tips        [ MAX_TXN_PER_MICROBLOCK ] = { 0U };

  int execution_success = 1;

  /* Every transaction in the bundle should be executed in order against
     different transaciton contexts. */
  for( ulong i=0UL; i<txn_cnt; i++ ) {

    fd_txn_p_t *   txn     = &txns[ i ];
    fd_txn_in_t *  txn_in  = &ctx->txn_in[ i ];
    fd_txn_out_t * txn_out = &ctx->txn_out[ i ];

    txn->flags &= ~FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    txn->flags &= ~FD_TXN_P_FLAGS_EXECUTE_SUCCESS;

    if( execution_success==0 ) {
      txn->flags = (txn->flags & 0x00FFFFFFU) | ((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24);
      continue;
    }

    txn_in->txn              = txn;
    txn_in->bundle.is_bundle = 1;

    fd_runtime_prepare_and_execute_txn( ctx->runtime, bank, txn_in, txn_out );
    txn->flags = (txn->flags & 0x00FFFFFFU) | ((uint)(-txn_out->err.txn_err)<<24);
    if( FD_UNLIKELY( !txn_out->err.is_committable || txn_out->err.txn_err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      execution_success = 0;
      continue;
    }

    writable_alt[i] = fd_type_pun_const( txn_out->accounts.keys+TXN( txn_in->txn )->acct_addr_cnt );
  }

  /* If all of the transactions in the bundle executed successfully, we
     can commit the transactions in order.  At this point, we cann also
     accumulate unused CUs to the rebate.  Otherwise, if any transaction
     fails, we need to exclude all the bundle transcations and rebate
     all of the CUs. */
  if( FD_LIKELY( execution_success ) ) {
    for( ulong i=0UL; i<txn_cnt; i++ ) {

      fd_txn_in_t *  txn_in  = &ctx->txn_in[ i ];
      fd_txn_out_t * txn_out = &ctx->txn_out[ i ];
      uchar *        signature = (uchar *)txn_in->txn->payload + TXN( txn_in->txn )->signature_off;

      fd_runtime_commit_txn( ctx->runtime, bank, txn_out );
      if( FD_UNLIKELY( !txn_out->err.is_committable ) ) {
        txns[ i ].flags = (txns[ i ].flags & 0x00FFFFFFU) | ((uint)(-txn_out->err.txn_err)<<24);
        fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_locking_modify( bank );
        int err = fd_cost_tracker_try_add_cost( cost_tracker, txn_out );
        FD_LOG_HEXDUMP_WARNING(( "txn", txns[ i ].payload, txns[ i ].payload_sz ));
        FD_BASE58_ENCODE_64_BYTES( signature, signature_b58 );
        FD_LOG_CRIT(( "transaction %s failed to fit into block despite pack guaranteeing it would "
                      "(res=%d) [block_cost=%lu, vote_cost=%lu, allocated_accounts_data_size=%lu, "
                      "block_cost_limit=%lu, vote_cost_limit=%lu, account_cost_limit=%lu]",
                      signature_b58, err, cost_tracker->block_cost, cost_tracker->vote_cost,
                      cost_tracker->allocated_accounts_data_size,
                      cost_tracker->block_cost_limit, cost_tracker->vote_cost_limit,
                      cost_tracker->account_cost_limit ));
      }

      uint actual_execution_cus = (uint)(txn_out->details.compute_budget.compute_unit_limit - txn_out->details.compute_budget.compute_meter);
      uint actual_acct_data_cus = (uint)(txn_out->details.txn_cost.transaction.loaded_accounts_data_size_cost);
      if( FD_UNLIKELY( fd_txn_is_simple_vote_transaction( TXN( &txns[ i ] ), txns[ i ].payload ) ) ) {
        actual_execution_cus = FD_PACK_VOTE_DEFAULT_COMPUTE_UNITS;
        actual_acct_data_cus = 0U;
      }

      uint requested_exec_plus_acct_data_cus = txns[ i ].pack_cu.requested_exec_plus_acct_data_cus;
      uint non_execution_cus                 = txns[ i ].pack_cu.non_execution_cus;
      txns[ i ].bank_cu.rebated_cus          = requested_exec_plus_acct_data_cus - (actual_execution_cus + actual_acct_data_cus);
      txns[ i ].bank_cu.actual_consumed_cus  = non_execution_cus + actual_execution_cus + actual_acct_data_cus;
      txns[ i ].flags                       |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS | FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
      tips[ i ]                              = txn_out->details.tips;
    }
  } else {
    for( ulong i=0UL; i<txn_cnt; i++ ) {

      /* If the bundle peer flag is not set, that means the transaction
         was at least partially sanitized/setup.  We have to cancel
         these txns as they will not be included in the block. */
      if( !(txns[ i ].flags % ((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24)) ) {
        fd_runtime_cancel_txn( ctx->runtime, &ctx->txn_out[ i ] );
      }

      uint requested_exec_plus_acct_data_cus = txns[ i ].pack_cu.requested_exec_plus_acct_data_cus;
      uint non_execution_cus                 = txns[ i ].pack_cu.non_execution_cus;
      txns[ i ].bank_cu.actual_consumed_cus  = 0U;
      txns[ i ].bank_cu.rebated_cus          = requested_exec_plus_acct_data_cus + non_execution_cus;
      tips[ i ]                              = 0UL;
      txns[ i ].flags = fd_uint_if( !!(txns[ i ].flags>>24), txns[ i ].flags, txns[ i ].flags | ((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24) );
    }
  }

  if( FD_LIKELY( ctx->enable_rebates ) ) fd_pack_rebate_sum_add_txn( ctx->rebater, txns, writable_alt, txn_cnt );

  /* Indicate to pack tile we are done processing the transactions so
     it can pack new microblocks using these accounts. */
  fd_fseq_update( ctx->busy_fseq, seq );

  /* We need to publish each transaction separately into its own
     microblock, so make a temporary copy on the stack so we can move
     all the data around. */
  fd_txn_p_t bundle_txn_temp[ 5UL ];
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    bundle_txn_temp[ i ] = txns[ i ];
  }

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_poh->mem, ctx->out_poh->chunk );
    fd_memcpy( dst, bundle_txn_temp+i, sizeof(fd_txn_p_t) );

    fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)( dst+sizeof(fd_txn_p_t) );
    hash_transactions( ctx->bmtree, (fd_txn_p_t*)dst, 1UL, trailer->hash );
    trailer->pack_txn_idx = ctx->_txn_idx + i;
    trailer->tips         = tips[ i ];

    ulong bank_sig = fd_disco_bank_sig( slot, ctx->_pack_idx+i );

    long tickcount                 = fd_tickcount();
    long microblock_start_ticks    = fd_frag_meta_ts_decomp( begin_tspub, tickcount );
    long microblock_duration_ticks = fd_long_max(tickcount - microblock_start_ticks, 0L);

    long tx_preload_end_ticks = fd_long_if( ctx->txn_out[ i ].details.prep_start_timestamp!=LONG_MAX,   ctx->txn_out[ i ].details.prep_start_timestamp,   microblock_start_ticks );
    long tx_start_ticks       = fd_long_if( ctx->txn_out[ i ].details.load_start_timestamp!=LONG_MAX,   ctx->txn_out[ i ].details.load_start_timestamp,   tx_preload_end_ticks   );
    long tx_load_end_ticks    = fd_long_if( ctx->txn_out[ i ].details.exec_start_timestamp!=LONG_MAX,   ctx->txn_out[ i ].details.exec_start_timestamp,   tx_start_ticks         );
    long tx_end_ticks         = fd_long_if( ctx->txn_out[ i ].details.commit_start_timestamp!=LONG_MAX, ctx->txn_out[ i ].details.commit_start_timestamp, tx_load_end_ticks      );

    trailer->txn_preload_end_pct = (uchar)(((double)(tx_preload_end_ticks - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
    trailer->txn_start_pct       = (uchar)(((double)(tx_start_ticks       - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
    trailer->txn_load_end_pct    = (uchar)(((double)(tx_load_end_ticks    - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);
    trailer->txn_end_pct         = (uchar)(((double)(tx_end_ticks         - microblock_start_ticks) * (double)UCHAR_MAX) / (double)microblock_duration_ticks);

    ulong new_sz = sizeof(fd_txn_p_t) + sizeof(fd_microblock_trailer_t);
    fd_stem_publish( stem, ctx->out_poh->idx, bank_sig, ctx->out_poh->chunk, new_sz, 0UL, (ulong)fd_frag_meta_ts_comp( microblock_start_ticks ), (ulong)fd_frag_meta_ts_comp( tickcount ) );
    ctx->out_poh->chunk = fd_dcache_compact_next( ctx->out_poh->chunk, new_sz, ctx->out_poh->chunk0, ctx->out_poh->wmark );
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
    if( FD_LIKELY( ctx->enable_rebates ) ) fd_pack_rebate_sum_clear( ctx->rebater );
    ctx->rebates_for_slot = slot;
  }

  if( FD_UNLIKELY( ctx->_is_bundle ) ) handle_bundle( ctx, seq, sig, sz, tspub, stem );
  else                                 handle_microblock( ctx, seq, sig, sz, tspub, stem );

  /* TODO: Use fancier logic to coalesce rebates e.g. and move this to
     after_credit */
  if( FD_LIKELY( ctx->enable_rebates ) ) {
    ulong written_sz = 0UL;
    while( 0UL!=(written_sz=fd_pack_rebate_sum_report( ctx->rebater, fd_chunk_to_laddr( ctx->out_pack->mem, ctx->out_pack->chunk ) )) ) {
      ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
      fd_stem_publish( stem, ctx->out_pack->idx, slot, ctx->out_pack->chunk, written_sz, 0UL, tsorig, tspub );
      ctx->out_pack->chunk = fd_dcache_compact_next( ctx->out_pack->chunk, written_sz, ctx->out_pack->chunk0, ctx->out_pack->wmark );
    }
  }
}

static inline fd_bank_out_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_bank_out_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0 };

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_bank_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bank_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_bank_ctx_t),     sizeof(fd_bank_ctx_t) );
  void * blake3       = FD_SCRATCH_ALLOC_APPEND( l, FD_BLAKE3_ALIGN,            FD_BLAKE3_FOOTPRINT );
  void * bmtree       = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN,     FD_BMTREE_COMMIT_FOOTPRINT(0) );
  void * _txncache    = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),        fd_txncache_footprint( tile->bank.max_live_slots ) );
  void * pc_scratch   = FD_SCRATCH_ALLOC_APPEND( l, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT );

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ctx->kind_id   = tile->kind_id;
  ctx->blake3    = NONNULL( fd_blake3_join( fd_blake3_new( blake3 ) ) );
  ctx->bmtree    = NONNULL( bmtree );

  NONNULL( fd_pack_rebate_sum_join( fd_pack_rebate_sum_new( ctx->rebater ) ) );
  ctx->rebates_for_slot  = 0UL;

  void * shfunk = fd_topo_obj_laddr( topo, tile->bank.funk_obj_id );
  FD_TEST( shfunk );
  fd_accdb_user_t * accdb = fd_accdb_user_v1_init( ctx->accdb, shfunk );
  FD_TEST( accdb );

  void * shprogcache = fd_topo_obj_laddr( topo, tile->bank.progcache_obj_id );
  FD_TEST( shprogcache );
  fd_progcache_t * progcache = fd_progcache_join( ctx->progcache, shprogcache, pc_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT );
  FD_TEST( progcache );

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->bank.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  fd_txncache_t * txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( txncache );


  fd_acc_pool_t * acc_pool = fd_acc_pool_join( fd_topo_obj_laddr( topo, tile->bank.acc_pool_obj_id ) );
  FD_TEST( acc_pool );

  for( ulong i=0UL; i<FD_PACK_MAX_TXN_PER_BUNDLE; i++ ) {
    ctx->txn_in[ i ].bundle.prev_txn_cnt = i;
    for( ulong j=0UL; j<i; j++ ) ctx->txn_in[ i ].bundle.prev_txn_outs[ j ] = &ctx->txn_out[ j ];
  }

  ctx->runtime->accdb                    = accdb;
  ctx->runtime->funk                     = fd_accdb_user_v1_funk( accdb );
  ctx->runtime->progcache                = progcache;
  ctx->runtime->status_cache             = txncache;
  ctx->runtime->acc_pool                 = acc_pool;

  ctx->runtime->log.log_collector        = ctx->log_collector;
  ctx->runtime->log.enable_log_collector = 0;
  ctx->runtime->log.capture_ctx          = NULL;
  ctx->runtime->log.dumping_mem          = NULL;
  ctx->runtime->log.tracing_mem          = NULL;

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  FD_TEST( banks_obj_id!=ULONG_MAX );

  ctx->banks = NONNULL( fd_banks_join( ctx->banksl_join, fd_topo_obj_laddr( topo, banks_obj_id ), NULL ) );

  ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", tile->kind_id );
  FD_TEST( busy_obj_id!=ULONG_MAX );
  ctx->busy_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
  if( FD_UNLIKELY( !ctx->busy_fseq ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", tile->kind_id ));

  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  ctx->pack_in_mem = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0UL ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_in_chunk0 = fd_dcache_compact_chunk0( ctx->pack_in_mem, topo->links[ tile->in_link_id[ 0UL ] ].dcache );
  ctx->pack_in_wmark  = fd_dcache_compact_wmark ( ctx->pack_in_mem, topo->links[ tile->in_link_id[ 0UL ] ].dcache, topo->links[ tile->in_link_id[ 0UL ] ].mtu );

  *ctx->out_poh = out1( topo, tile, "bank_poh" ); FD_TEST( ctx->out_poh->idx!=ULONG_MAX );
  *ctx->out_pack = out1( topo, tile, "bank_pack" );

  ctx->enable_rebates = ctx->out_pack->idx!=ULONG_MAX;
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
