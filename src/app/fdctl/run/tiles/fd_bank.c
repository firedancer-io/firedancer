#include "tiles.h"

#include "../../../../ballet/pack/fd_pack.h"
#include "../../../../ballet/blake3/fd_blake3.h"
#include "../../../../ballet/bmtree/fd_bmtree.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../disco/bank/fd_bank_abi.h"
#include "../../../../disco/metrics/generated/fd_metrics_bank.h"
#include "../../../../util/alloc/fd_alloc.h"

typedef struct {
  ulong kind_id;

  fd_blake3_t * blake3;
  void * bmtree;

  uchar * txn_abi_mem;
  uchar * txn_sidecar_mem;

  void const * _bank;
  ulong * bank_busy;

  fd_wksp_t * pack_in_mem;
  ulong       pack_in_chunk0;
  ulong       pack_in_wmark;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  struct {
    ulong slot_acquire[ 3 ];

    ulong txn_load_address_lookup_tables[ 6 ];
    ulong txn_load[ 38 ];
    ulong txn_executing[ 38 ];
    ulong txn_executed[ 38 ];
  } metrics;
} fd_bank_ctx_t;

static fd_alloc_t * fd_bank_alloc_ctx;

#define CALLED_FROM_RUST

CALLED_FROM_RUST void *
fd_ext_alloc_malloc( ulong align, ulong sz ) {
  while( FD_UNLIKELY( !FD_VOLATILE_CONST( fd_bank_alloc_ctx ) ) ) FD_SPIN_PAUSE();
  return fd_alloc_malloc( fd_bank_alloc_ctx, align, sz );
}

CALLED_FROM_RUST void
fd_ext_alloc_free( void * data ) {
  fd_alloc_free( fd_bank_alloc_ctx, data );
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_bank_ctx_t ), sizeof( fd_bank_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, FD_ALLOC_ALIGN, FD_ALLOC_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BLAKE3_ALIGN, FD_BLAKE3_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  l = FD_LAYOUT_APPEND( l, FD_BANK_ABI_TXN_ALIGN, MAX_TXN_PER_MICROBLOCK*FD_BANK_ABI_TXN_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BANK_ABI_TXN_ALIGN, FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR_MAX );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  if( FD_LIKELY( tile->kind_id==0UL ) ) {
    /* The Agave status cache is allocated out of a Firedancer workspace
       for performance reasons, but if we run out of memory it will
       crash the validator.
    
       Let SLOT_cnt be the number of slots that are alive in the cache,
           TXN_avg  be the average number of transactions in a slot
      
       The material parts of the status cache memory layout are
       as follows...

        [ SLOT_cnt * TXN_avg * 72 bytes ] -- for the status cache
        [ SLOT_cnt * 2 * TXN_avg * 64 bytes ] -- for the delta map

       The SLOT_cnt is in some sense bounded by the size of the cache
       history which is set at 300.  The TXN_avg is bounded by the speed
       of the system, which can do at most ~81k TPS due to current
       consensus limits.

       This gives us around ~4.5 GiB.  For Firedancer, we aim to handle
       over 1M TPS, which gives a TXN_avg of ~2^19 ~ 524,288.  This
       requires around ~30GiB on the conservative side. */
    return 64UL*(1024UL*1024UL*1024UL);
  } else {
    return 0UL;
  }
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_bank_ctx_t ) );
}

static inline void
metrics_write( void * _ctx ) {
  fd_bank_ctx_t * ctx = (fd_bank_ctx_t *)_ctx;

  FD_MCNT_ENUM_COPY( BANK_TILE, SLOT_ACQUIRE,  ctx->metrics.slot_acquire );

  FD_MCNT_ENUM_COPY( BANK_TILE, TRANSACTION_LOAD_ADDRESS_TABLES, ctx->metrics.txn_load_address_lookup_tables );
  FD_MCNT_ENUM_COPY( BANK_TILE, TRANSACTION_LOAD,  ctx->metrics.txn_load );
  FD_MCNT_ENUM_COPY( BANK_TILE, TRANSACTION_EXECUTING,  ctx->metrics.txn_executing );
  FD_MCNT_ENUM_COPY( BANK_TILE, TRANSACTION_EXECUTED,  ctx->metrics.txn_executed );

}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;

  fd_bank_ctx_t * ctx = (fd_bank_ctx_t *)_ctx;

  if( FD_UNLIKELY( fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_MICROBLOCK ) ) {
    /* Pack also outputs "leader slot done" which we can ignore. */
    *opt_filter = 1;
    return;
  }

  ulong target_bank_idx = fd_disco_poh_sig_bank_tile( sig );
  if( FD_UNLIKELY( target_bank_idx!=ctx->kind_id ) ) {
    *opt_filter = 1;
    return;
  }
}

extern void * fd_ext_bank_pre_balance_info( void const * bank, void * txns, ulong txn_cnt );
extern void * fd_ext_bank_load_and_execute_txns( void const * bank, void * txns, ulong txn_cnt, int * out_load_results, int * out_executing_results, int * out_executed_results );
extern void   fd_ext_bank_commit_txns( void const * bank, void const * txns, ulong txn_cnt , void * load_and_execute_output, void * pre_balance_info );
extern void   fd_ext_bank_release_thunks( void * load_and_execute_output );
extern void   fd_ext_bank_release_pre_balance_info( void * pre_balance_info );

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_bank_ctx_t * ctx = (fd_bank_ctx_t *)_ctx;

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->pack_in_mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  if( FD_UNLIKELY( chunk<ctx->pack_in_chunk0 || chunk>ctx->pack_in_wmark || sz>USHORT_MAX ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->pack_in_chunk0, ctx->pack_in_wmark ));

  fd_memcpy( dst, src, sz-sizeof(fd_microblock_bank_trailer_t) );
  fd_microblock_bank_trailer_t * trailer = (fd_microblock_bank_trailer_t *)( src+sz-sizeof(fd_microblock_bank_trailer_t) );
  ctx->_bank = trailer->bank;
}

static void
hash_transactions( void *       mem,
                   fd_txn_p_t * txns,
                   ulong        txn_cnt,
                   uchar *      mixin ) {
  fd_bmtree_commit_t * bmtree = fd_bmtree_commit_init( mem, 32UL, 1UL, 0UL );
  for( ulong i=0; i<txn_cnt; i++ ) {
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
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)opt_chunk;
  (void)opt_tsorig;
  (void)opt_filter;

  fd_bank_ctx_t * ctx = (fd_bank_ctx_t *)_ctx;

  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  ulong txn_cnt = (*opt_sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t);

  ulong sanitized_txn_cnt = 0UL;
  ulong sidecar_footprint_bytes = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)( dst + (i*sizeof(fd_txn_p_t)) );

    void * abi_txn = ctx->txn_abi_mem + (sanitized_txn_cnt*FD_BANK_ABI_TXN_FOOTPRINT);
    void * abi_txn_sidecar = ctx->txn_sidecar_mem + sidecar_footprint_bytes;

    int result = fd_bank_abi_txn_init( abi_txn, abi_txn_sidecar, ctx->_bank, ctx->blake3, txn->payload, txn->payload_sz, TXN(txn), !!(txn->flags & FD_TXN_P_FLAGS_IS_SIMPLE_VOTE) );
    ctx->metrics.txn_load_address_lookup_tables[ result ]++;
    if( FD_UNLIKELY( result!=FD_BANK_ABI_TXN_INIT_SUCCESS ) ) continue;

    txn->flags |= FD_TXN_P_FLAGS_SANITIZE_SUCCESS;

    fd_txn_t * txn1 = TXN(txn);
    sidecar_footprint_bytes += FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR( txn1->acct_addr_cnt, txn1->addr_table_adtl_cnt, txn1->instr_cnt, txn1->addr_table_lookup_cnt );
    sanitized_txn_cnt++;
  }

  /* Just because a transaction was executed doesn't mean it succeeded,
     but all executed transactions get committed. */
  int load_results[ MAX_TXN_PER_MICROBLOCK ] = {0};
  int executing_results[ MAX_TXN_PER_MICROBLOCK ] = {0};
  int executed_results[ MAX_TXN_PER_MICROBLOCK ] = {0};

  void * pre_balance_info = fd_ext_bank_pre_balance_info( ctx->_bank, ctx->txn_abi_mem, sanitized_txn_cnt );

  void * load_and_execute_output = fd_ext_bank_load_and_execute_txns( ctx->_bank,
                                                                      ctx->txn_abi_mem,
                                                                      sanitized_txn_cnt,
                                                                      load_results,
                                                                      executing_results,
                                                                      executed_results );

  ulong sanitized_idx = 0UL;
  for( ulong i=0; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)( dst + (i*sizeof(fd_txn_p_t)) );
    if( FD_UNLIKELY( !(txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) ) ) continue;

    sanitized_idx++;
    ctx->metrics.txn_load[ load_results[ sanitized_idx-1 ] ]++;
    if( FD_UNLIKELY( load_results[ sanitized_idx-1 ] ) ) continue;

    ctx->metrics.txn_executing[ executing_results[ sanitized_idx-1 ] ]++;
    if( FD_UNLIKELY( executing_results[ sanitized_idx-1 ] ) ) continue;

    ctx->metrics.txn_executed[ executed_results[ sanitized_idx-1 ] ]++;
    txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  }

  /* Commit must succeed so no failure path.  This function takes
      ownership of the load_and_execute_output and pre_balance_info heap
      allocations and will free them before it returns.  They should not
      be reused.  Once commit is called, the transactions MUST be mixed
      into the PoH otherwise we will fork and diverge, so the link from
      here til PoH mixin must be completely reliable with nothing dropped. */
  fd_ext_bank_commit_txns( ctx->_bank, ctx->txn_abi_mem, sanitized_txn_cnt, load_and_execute_output, pre_balance_info );
  pre_balance_info        = NULL;
  load_and_execute_output = NULL;

  /* Indicate to pack tile we are done processing the transactions so it
     can pack new microblocks using these accounts.  DO NOT USE THE
     SANITIZED TRANSACTIONS AFTER THIS POINT, THEY ARE NOT LONGER VALID. */
  fd_fseq_update( ctx->bank_busy, seq );

  /* Now produce the merkle hash of the transactions for inclusion
     (mixin) to the PoH hash.  This is done on the bank tile because
     it shards / scales horizontally here, while PoH does not. */
  fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)( dst + txn_cnt*sizeof(fd_txn_p_t) );
  hash_transactions( ctx->bmtree, (fd_txn_p_t*)dst, txn_cnt, trailer->hash );

  /* MAX_MICROBLOCK_SZ - (MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t)) == 64
     so there's always 64 extra bytes at the end to stash the hash. */
  FD_STATIC_ASSERT( MAX_MICROBLOCK_SZ-(MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t))>=sizeof(fd_microblock_trailer_t), poh_shred_mtu );
  FD_STATIC_ASSERT( MAX_MICROBLOCK_SZ-(MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t))>=sizeof(fd_microblock_bank_trailer_t), poh_shred_mtu );

  /* We always need to publish, even if there are no successfully executed
     transactions so the PoH tile can keep an accurate count of microblocks
     it has seen. */
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = txn_cnt*sizeof(fd_txn_p_t) + sizeof(fd_microblock_trailer_t);
  fd_mux_publish( mux, *opt_sig, ctx->out_chunk, sz, 0UL, 0UL, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bank_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bank_ctx_t ), sizeof( fd_bank_ctx_t ) );
  void * alloc = FD_SCRATCH_ALLOC_APPEND( l, FD_ALLOC_ALIGN, FD_ALLOC_FOOTPRINT );
  void * blake3 = FD_SCRATCH_ALLOC_APPEND( l, FD_BLAKE3_ALIGN, FD_BLAKE3_FOOTPRINT );
  void * bmtree = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN,           FD_BMTREE_COMMIT_FOOTPRINT(0)      );
  ctx->txn_abi_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_BANK_ABI_TXN_ALIGN, MAX_TXN_PER_MICROBLOCK*FD_BANK_ABI_TXN_FOOTPRINT );
  ctx->txn_sidecar_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_BANK_ABI_TXN_ALIGN, FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR_MAX );

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ctx->kind_id = tile->kind_id;
  ctx->blake3 = NONNULL( fd_blake3_join( fd_blake3_new( blake3 ) ) );
  ctx->bmtree = NONNULL( bmtree );
  ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", tile->kind_id );
  FD_TEST( busy_obj_id!=ULONG_MAX );
  ctx->bank_busy = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
  if( FD_UNLIKELY( !ctx->bank_busy ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", tile->kind_id ));

  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  if( FD_LIKELY( !tile->kind_id ) ) {
    FD_VOLATILE(fd_bank_alloc_ctx) = NONNULL( fd_alloc_join( fd_alloc_new( alloc, 9999 ), 0 ) );
  }

  ctx->pack_in_mem = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0UL ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_in_chunk0 = fd_dcache_compact_chunk0( ctx->pack_in_mem, topo->links[ tile->in_link_id[ 0UL ] ].dcache );
  ctx->pack_in_wmark  = fd_dcache_compact_wmark ( ctx->pack_in_mem, topo->links[ tile->in_link_id[ 0UL ] ].dcache, topo->links[ tile->in_link_id[ 0UL ] ].mtu );

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;
}

static long
lazy( fd_topo_tile_t * tile ) {
  (void)tile;
  /* See explanation in fd_pack */
  return 128L * 300L;
}

fd_topo_run_tile_t fd_tile_bank = {
  .name                     = "bank",
  .mux_flags                = FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .mux_metrics_write        = metrics_write,
  .lazy                     = lazy,
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = NULL,
  .unprivileged_init        = unprivileged_init,
};
