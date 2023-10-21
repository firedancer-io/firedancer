#include "tiles.h"

#include "../../../../ballet/pack/fd_pack.h"

#include <linux/unistd.h>

/* fd_pack is responsible for taking verified transactions, and
   arranging them into "microblocks" (groups) of transactions to
   be executed serially.  It can try to do clever things so that
   multiple microblocks can execute in parallel, if they don't
   write to the same accounts. */

#define BLOCK_DURATION_NS (400UL*1000UL*1000UL)

/* About 1.5 kB on the stack */
#define FD_PACK_PACK_MAX_OUT (16UL)

#define MAX_TXN_PER_MICROBLOCK (MAX_MICROBLOCK_SZ/sizeof(fd_txn_p_t))

/* in bytes.  Defined this way to use the size field of mcache */
#define MAX_MICROBLOCK_SZ USHORT_MAX

/* 1.5 M cost units, enough for 1 max size transaction */
const ulong CUS_PER_MICROBLOCK = 1500000UL;

const float VOTE_FRACTION = 0.75;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_pack_in_ctx_t;

typedef struct {
  fd_pack_t *  pack;
  fd_txn_p_t * cur_slot;

  long block_duration_ticks;
  long block_end;

  fd_pack_in_ctx_t in[ 32 ];

  ulong    out_cnt;
  ulong *  out_busy[ FD_PACK_PACK_MAX_OUT ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_pack_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  ulong scratch_top = 0UL;
  SCRATCH_ALLOC( alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );
  SCRATCH_ALLOC( fd_rng_align(),           fd_rng_footprint() );
  SCRATCH_ALLOC( fd_pack_align(), fd_pack_footprint( tile->pack.max_pending_transactions,
                                                     tile->pack.bank_tile_count,
                                                     MAX_TXN_PER_MICROBLOCK ) );
  return fd_ulong_align_up( scratch_top, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_pack_ctx_t ) );
}

static inline void
before_credit( void * _ctx,
               fd_mux_context_t * mux ) {
  (void)mux;

  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  if( FD_UNLIKELY( ctx->cur_slot ) ) {
    /* If we were overrun while processing a frag from an in, then cur_slot
       is left dangling and not cleaned up, so clean it up here (by returning
       the slot to the pool of free slots). */
    fd_pack_insert_txn_cancel( ctx->pack, ctx->cur_slot );
    ctx->cur_slot = NULL;
  }

  /* Are we ready to end the block? */

  long now = fd_tickcount();
  if( FD_UNLIKELY( (now-ctx->block_end)>=0L ) ) {
    fd_pack_end_block( ctx->pack );
    ctx->block_end += ctx->block_duration_ticks;
  }
}

static inline void
after_credit( void *             _ctx,
              fd_mux_context_t * mux ) {
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  /* Is it time to schedule the next microblock? For each banking
     thread, if it's not busy... */
  for( ulong i=0UL; i<ctx->out_cnt; i++ ) {
    if( FD_LIKELY( fd_fseq_query( ctx->out_busy[i] ) == *mux->seq ) ) { /* optimize for the case we send a microblock */
      fd_pack_microblock_complete( ctx->pack, i );

      void * microblock_dst = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
      ulong schedule_cnt = fd_pack_schedule_next_microblock( ctx->pack, CUS_PER_MICROBLOCK, VOTE_FRACTION, i, microblock_dst );
      if( FD_LIKELY( schedule_cnt ) ) {
        ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
        ulong chunk  = ctx->out_chunk;
        ulong msg_sz = schedule_cnt*sizeof(fd_txn_p_t);

        /* publish with sig=i, banks will filter to only handle frags with their own sig idx */
        fd_mux_publish( mux, i, chunk, msg_sz, 0, 0UL, tspub );

        ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, msg_sz, ctx->out_chunk0, ctx->out_wmark );
      }
    }
  }
}

/* At this point, we have started receiving frag seq with details in
    mline at time now.  Speculatively processs it here. */

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  ctx->cur_slot              = fd_pack_insert_txn_init( ctx->pack );

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk );

  ulong payload_sz;
  /* There are two senders, one (dedup tile) which has already parsed the
     transaction, and one (gossip vote receiver in Solana Labs) which has
     not.  In either case, the transaction has already been verified.

     The dedup tile sets sig to 0, while the gossip receiver sets sig to
     1 so they can be distinguished. */

  if( FD_LIKELY( !sig ) ) {
    /* Assume that the dcache entry is:
          Payload ....... (payload_sz bytes)
          0 or 1 byte of padding (since alignof(fd_txn) is 2)
          fd_txn ....... (size computed by fd_txn_footprint)
          payload_sz  (2B)
      mline->sz includes all three fields and the padding */
    payload_sz = *(ushort*)(dcache_entry + sz - sizeof(ushort));
    uchar    const * payload = dcache_entry;
    fd_txn_t const * txn     = (fd_txn_t const *)( dcache_entry + fd_ulong_align_up( payload_sz, 2UL ) );
    fd_memcpy( ctx->cur_slot->payload, payload, payload_sz                                                     );
    fd_memcpy( TXN(ctx->cur_slot),     txn,     fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
    ctx->cur_slot->payload_sz = payload_sz;
  } else {
    /* Here there is just a transaction payload, so it needs to be
       parsed.  We can parse right out into the pack structure. */
    payload_sz = sz;
    fd_memcpy( ctx->cur_slot->payload, dcache_entry, sz );
    ulong txn_t_sz = fd_txn_parse( ctx->cur_slot->payload, sz, TXN(ctx->cur_slot), NULL );
    if( FD_UNLIKELY( !txn_t_sz ) ) {
      FD_LOG_WARNING(( "fd_txn_parse failed for gossiped vote" ));
      fd_pack_insert_txn_cancel( ctx->pack, ctx->cur_slot );
      *opt_filter = 1;
      return;
    }
    ctx->cur_slot->payload_sz = payload_sz;
  }

#if DETAILED_LOGGING
  FD_LOG_NOTICE(( "Pack got a packet. Payload size: %lu, txn footprint: %lu", payload_sz,
        fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt )
      ));
#endif
}

/* After the transaction has been fully received, and we know we were
   not overrun while reading it, check if it's a duplicate of a prior
   transaction. */

static inline void
after_frag( void *             _ctx,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_filter;
  (void)mux;

  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  fd_pack_insert_txn_fini( ctx->pack, ctx->cur_slot );
  ctx->cur_slot = NULL;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  ulong out_cnt = fd_topo_link_consumer_cnt( topo, &topo->links[ tile->out_link_id_primary ] );

  if( FD_UNLIKELY( !out_cnt ) ) FD_LOG_ERR(( "pack tile connects to no banking tiles" ));
  if( FD_UNLIKELY( out_cnt>FD_PACK_PACK_MAX_OUT ) ) FD_LOG_ERR(( "pack tile connects to too many banking tiles" ));
  if( FD_UNLIKELY( out_cnt!=tile->pack.bank_tile_count ) ) FD_LOG_ERR(( "pack tile connects to %lu banking tiles, but tile->pack.bank_tile_count is %lu", out_cnt, tile->pack.bank_tile_count ));

  ulong pack_footprint = fd_pack_footprint( tile->pack.max_pending_transactions, out_cnt, MAX_TXN_PER_MICROBLOCK );

  ulong scratch_top = (ulong)scratch;
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t*)SCRATCH_ALLOC( alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );
  fd_rng_t *      rng = fd_rng_join( fd_rng_new( SCRATCH_ALLOC( fd_rng_align(), fd_rng_footprint() ), 0U, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_new failed" ));

  ctx->pack = fd_pack_join( fd_pack_new( SCRATCH_ALLOC( fd_pack_align(), pack_footprint ), tile->pack.max_pending_transactions, out_cnt, MAX_TXN_PER_MICROBLOCK, rng ) );
  if( FD_UNLIKELY( !ctx->pack ) ) FD_LOG_ERR(( "fd_pack_new failed" ));

  ctx->cur_slot = NULL;
  ctx->block_duration_ticks = (long)(fd_tempo_tick_per_ns( NULL ) * (double)BLOCK_DURATION_NS);
  ctx->block_end = fd_tickcount() + ctx->block_duration_ticks;
  ctx->out_cnt  = out_cnt;

  for( ulong i=0; i<out_cnt; i++ ) {
    ctx->out_busy[ i ] = tile->extra[ i ];
    if( FD_UNLIKELY( !ctx->out_busy[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));
  }

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ link->wksp_id ];

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
  }

  ctx->out_mem    = topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  FD_LOG_INFO(( "packing blocks of at most %lu transactions to %lu bank tiles", MAX_TXN_PER_MICROBLOCK, out_cnt ));

  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static long allow_syscalls[] = {
  __NR_write, /* logging */
  __NR_fsync, /* logging, WARNING and above fsync immediately */
};

static ulong
allow_fds( void * scratch,
           ulong  out_fds_cnt,
           int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  return 2;
}

fd_tile_config_t fd_tile_pack = {
  .mux_flags           = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                   = 1UL,
  .mux_ctx             = mux_ctx,
  .mux_before_credit   = before_credit,
  .mux_after_credit    = after_credit,
  .mux_during_frag     = during_frag,
  .mux_after_frag      = after_frag,
  .allow_syscalls_cnt  = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls      = allow_syscalls,
  .allow_fds           = allow_fds,
  .scratch_align       = scratch_align,
  .scratch_footprint   = scratch_footprint,
  .privileged_init     = NULL,
  .unprivileged_init   = unprivileged_init,
};
