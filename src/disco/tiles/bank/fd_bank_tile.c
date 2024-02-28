#include "fd_bank_tile.h"

#include "../../bank/fd_bank_abi.h"
#include "../../metrics/generated/fd_metrics_bank.h"
#include "../../../ballet/pack/fd_pack.h"
#include "../../../ballet/blake3/fd_blake3.h"

extern void * fd_ext_bank_pre_balance_info( void const * bank, void * txns, ulong txn_cnt );
extern void * fd_ext_bank_load_and_execute_txns( void const * bank, void * txns, ulong txn_cnt, int * out_load_results, int * out_executing_results, int * out_executed_results );
extern void   fd_ext_bank_release( void const * bank );
extern void   fd_ext_bank_release_thunks( void * load_and_execute_output );
extern void   fd_ext_bank_release_pre_balance_info( void * pre_balance_info );

FD_FN_CONST ulong
fd_bank_tile_align( void ) {
  return FD_BANK_TILE_ALIGN;
}

FD_FN_PURE ulong
fd_bank_tile_footprint( void const * args ) {
  (void)args;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_bank_tile_t ), sizeof( fd_bank_tile_t ) );
  l = FD_LAYOUT_APPEND( l, FD_BLAKE3_ALIGN, FD_BLAKE3_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BANK_ABI_TXN_ALIGN, MAX_TXN_PER_MICROBLOCK*FD_BANK_ABI_TXN_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BANK_ABI_TXN_ALIGN, FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR_MAX );
  return FD_LAYOUT_FINI( l, fd_bank_tile_align() );
}

static inline void
metrics_write( void * _ctx ) {
  fd_bank_tile_t * ctx = (fd_bank_tile_t *)_ctx;

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

  fd_bank_tile_t * ctx = (fd_bank_tile_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->poh_in_idx ) ) {
    if( FD_LIKELY( fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_BECAME_LEADER ) ) {
      /* Ignore PoH microblocks send to shredder, we only want to know
         about leadership transitions. */
      *opt_filter = 1;
      return;
    }
  }

  if( FD_LIKELY( in_idx==ctx->pack_in_idx ) ) {
    ulong target_bank_idx = fd_disco_poh_sig_bank_tile( sig );
    if( FD_UNLIKELY( target_bank_idx!=ctx->tidx ) ) {
      *opt_filter = 1;
      return;
    }
  }
}

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

  fd_bank_tile_t * ctx = (fd_bank_tile_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->poh_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->poh_in_chunk0 || chunk>ctx->poh_in_wmark || sz!=sizeof(fd_became_leader_t) ) ) {
      FD_LOG_WARNING(( "seq=%lu sig=%lx. pkt_type=%lu", seq, sig, fd_disco_poh_sig_pkt_type( sig ) ));
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->poh_in_chunk0, ctx->poh_in_wmark ));
    }

    fd_memcpy( &ctx->leader_frag, fd_chunk_to_laddr( ctx->poh_in_mem, chunk ), sizeof(fd_became_leader_t) );
  } else {
    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->pack_in_mem, chunk );
    uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

    if( FD_UNLIKELY( chunk<ctx->pack_in_chunk0 || chunk>ctx->pack_in_wmark || sz>USHORT_MAX ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->pack_in_chunk0, ctx->pack_in_wmark ));

    fd_memcpy( dst, src, sz );
  }
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

  fd_bank_tile_t * ctx = (fd_bank_tile_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->poh_in_idx ) ) {
    if( FD_LIKELY( ctx->leader_bank ) ) fd_ext_bank_release( ctx->leader_bank );
    ctx->leader_bank_slot = fd_disco_poh_sig_slot( *opt_sig );
    ctx->leader_bank = ctx->leader_frag.bank;
    return;
  }

  ulong slot = fd_disco_poh_sig_slot( *opt_sig );
  if( FD_UNLIKELY( ctx->leader_bank_slot!=slot ) ) {
    fd_fseq_update( ctx->bank_busy, seq );
    FD_LOG_WARNING(( "bank tile got a microblock for slot %lu but it had bank for %lu", slot, ctx->leader_bank_slot ));
    return;
  }

  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  ulong txn_cnt = *opt_sz/sizeof(fd_txn_p_t);

  ulong sanitized_txn_cnt = 0UL;
  ulong sidecar_footprint_bytes = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)( dst + (i*sizeof(fd_txn_p_t)) );

    void * abi_txn = ctx->txn_abi_mem + (sanitized_txn_cnt*FD_BANK_ABI_TXN_FOOTPRINT);
    void * abi_txn_sidecar = ctx->txn_sidecar_mem + sidecar_footprint_bytes;

    int result = fd_bank_abi_txn_init( abi_txn, abi_txn_sidecar, ctx->leader_bank, ctx->blake3, txn->payload, txn->payload_sz, TXN(txn), !!(txn->flags & FD_TXN_P_FLAGS_IS_SIMPLE_VOTE) );
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

  void * pre_balance_info = fd_ext_bank_pre_balance_info( ctx->leader_bank, ctx->txn_abi_mem, sanitized_txn_cnt );

  void * load_and_execute_output = fd_ext_bank_load_and_execute_txns( ctx->leader_bank,
                                                                      ctx->txn_abi_mem,
                                                                      sanitized_txn_cnt,
                                                                      load_results,
                                                                      executing_results,
                                                                      executed_results );

  ulong sanitized_idx = 0UL;
  int publish_microblock = 0;
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
    publish_microblock = 1;
  }

  if( FD_UNLIKELY( !publish_microblock ) ) {
    /* No valid transactions so no microblock to publish. */
    fd_ext_bank_release_thunks( load_and_execute_output ); /* Thunks are still alive on the Rust heap. */
    fd_ext_bank_release_pre_balance_info( pre_balance_info );
    fd_fseq_update( ctx->bank_busy, seq );
    return;
  }

  /* There is a pretty gross hack here.  We need to publish the
     sanitized transaction buffer and sidecar data to the PoH tile and
     make sure the lifetime is long enough.  Normally that would mean
     putting it in the outgoing dcache, but there's two problems,

      (1) The size might overflow USHORT_MAX (the max for an mline) and
          we would need to encode it weirdly.
      (2) It requires copies and figuring out how to be smart about some
          code that's temporary anyway.

    Instead, we just pass a pointer to the sanitized transaction buffer
    and sidecar.  This works because these tiles are part of Solana Labs
    so they share an address space, and because the internal bank buffer
    object won't be written since PoH has to release the
    pseudo-account-lock (the "busy" flag) before this bank will be
    reused and overwrite that buffer anyway. */

  /* MAX_MICROBLOCK_SZ - (MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t)) == 64
     so there's always 64 extra bytes at the end to stash the pointer. */
  FD_STATIC_ASSERT( MAX_MICROBLOCK_SZ-(MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t))>=sizeof(fd_microblock_trailer_t), poh_shred_mtu );

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = txn_cnt*sizeof(fd_txn_p_t) + sizeof(fd_microblock_trailer_t);
  fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)( dst + txn_cnt*sizeof(fd_txn_p_t) );
  trailer->abi_txns = ctx->txn_abi_mem;
  trailer->load_and_execute_output = load_and_execute_output;
  trailer->pre_balance_info = pre_balance_info;
  trailer->busy_seq = seq;
  fd_mux_publish( mux, *opt_sig, ctx->out_chunk, sz, 0UL, 0UL, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sz, ctx->out_chunk0, ctx->out_wmark );
}

fd_bank_tile_t *
fd_bank_tile_join( void *                      shbank,
                   void const *                args,
                   fd_bank_tile_topo_t const * topo ) {
  (void)args;

  FD_SCRATCH_ALLOC_INIT( l, shbank );
  fd_bank_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bank_tile_t ), sizeof( fd_bank_tile_t ) );
  void * blake3 = FD_SCRATCH_ALLOC_APPEND( l, FD_BLAKE3_ALIGN, FD_BLAKE3_FOOTPRINT );
  ctx->txn_abi_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_BANK_ABI_TXN_ALIGN, MAX_TXN_PER_MICROBLOCK*FD_BANK_ABI_TXN_FOOTPRINT );
  ctx->txn_sidecar_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_BANK_ABI_TXN_ALIGN, FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR_MAX );

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ctx->leader_bank = NULL;
  ctx->leader_bank_slot = ULONG_MAX;

  ctx->tidx = topo->tidx;
  ctx->blake3 = NONNULL( fd_blake3_join( fd_blake3_new( blake3 ) ) );
  ctx->bank_busy = topo->bank_busy;
  if( FD_UNLIKELY( !ctx->bank_busy ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", topo->tidx ));

  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  ctx->poh_in_idx = topo->poh_in_idx;
  ctx->pack_in_idx = topo->pack_in_idx;

  ctx->pack_in_mem = topo->pack_in_wksp;
  ctx->pack_in_chunk0 = fd_dcache_compact_chunk0( ctx->pack_in_mem, topo->pack_in_dcache );
  ctx->pack_in_wmark  = fd_dcache_compact_wmark ( ctx->pack_in_mem, topo->pack_in_dcache, topo->pack_in_mtu );

  ctx->poh_in_mem = topo->poh_in_wksp;
  ctx->poh_in_chunk0 = fd_dcache_compact_chunk0( ctx->poh_in_mem, topo->poh_in_dcache );
  ctx->poh_in_wmark  = fd_dcache_compact_wmark ( ctx->poh_in_mem, topo->poh_in_dcache, topo->poh_in_mtu );

  ctx->out_mem    = topo->out_wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->out_dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->out_dcache, topo->out_mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  return ctx;
}

void
fd_bank_tile_run( fd_bank_tile_t *        ctx,
                  fd_cnc_t *              cnc,
                  ulong                   in_cnt,
                  fd_frag_meta_t const ** in_mcache,
                  ulong **                in_fseq,
                  fd_frag_meta_t *        mcache,
                  ulong                   out_cnt,
                  ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .before_frag         = before_frag,
    .during_frag         = during_frag,
    .after_frag          = after_frag,
    .metrics_write       = metrics_write,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}
