#include "fd_pack.h"

#include "../mux/fd_mux.h"

#define BLOCK_DURATION_NS (400UL*1000UL*1000UL)

/* About 1.5 kB on the stack */
#define FD_PACK_PACK_MAX_OUT (16UL)

/* 1.5 M cost units, enough for 1 max size transaction */
const ulong CUS_PER_MICROBLOCK = 1500000UL;

const float VOTE_FRACTION = 0.75;

typedef struct {
  fd_pack_t *  pack;
  fd_txn_p_t * cur_slot;

  long block_duration_ticks;
  long block_end;

  fd_pack_in_ctx_t * in;

  ulong    out_cnt;
  ulong ** out_busy;

  void * out_wksp;
  ulong  out_chunk0;
  ulong  out_wmark;
  ulong  out_chunk;
} fd_pack_ctx_t;

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
      FD_LOG_WARNING(( "out_busy[%lu] is %lu, expected %lu", i, fd_fseq_query( ctx->out_busy[i] ), *mux->seq ));
      fd_pack_microblock_complete( ctx->pack, i );

      void * microblock_dst = fd_chunk_to_laddr( ctx->out_wksp, ctx->out_chunk );
      ulong schedule_cnt = fd_pack_schedule_next_microblock( ctx->pack, CUS_PER_MICROBLOCK, VOTE_FRACTION, i, microblock_dst );
      if( FD_LIKELY( schedule_cnt ) ) {
        ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
        ulong chunk  = ctx->out_chunk;
        ulong msg_sz = schedule_cnt*sizeof(fd_txn_p_t);

        /* publish with sig=i, banks will filter to only handle frags with their own sig idx */
        fd_mux_publish( mux, i, chunk, msg_sz, 0, 0UL, tspub );

        ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, msg_sz, ctx->out_chunk0, ctx->out_wmark );
      }
    } else {
      FD_LOG_WARNING(( "out_busy[%lu] is %lu, expected %lu", i, fd_fseq_query( ctx->out_busy[i] ), *mux->seq ));
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
  (void)sig;
  (void)opt_filter;

  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>=ctx->in[ in_idx ].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu)", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  ctx->cur_slot              = fd_pack_insert_txn_init( ctx->pack );

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[in_idx].wksp, chunk );
  /* Assume that the dcache entry is:
        Payload ....... (payload_sz bytes)
        0 or 1 byte of padding (since alignof(fd_txn) is 2)
        fd_txn ....... (size computed by fd_txn_footprint)
        payload_sz  (2B)
    mline->sz includes all three fields and the padding */
  ulong payload_sz = *(ushort*)(dcache_entry + sz - sizeof(ushort));
  uchar    const * payload = dcache_entry;
  fd_txn_t const * txn     = (fd_txn_t const *)( dcache_entry + fd_ulong_align_up( payload_sz, 2UL ) );
  fd_memcpy( ctx->cur_slot->payload, payload, payload_sz                                                     );
  fd_memcpy( TXN(ctx->cur_slot),     txn,     fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
  ctx->cur_slot->payload_sz = payload_sz;
  ctx->cur_slot->meta = sig;

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
after_frag( void * _ctx,
            ulong * opt_sig,
            ulong * opt_chunk,
            ulong * opt_sz,
            int *   opt_filter ) {
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_filter;

  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  fd_pack_insert_txn_fini( ctx->pack, ctx->cur_slot );
  ctx->cur_slot = NULL;
}

int
fd_pack_tile( fd_cnc_t *              cnc,
              ulong                   pid,
              ulong                   in_cnt,
              fd_frag_meta_t const ** in_mcache,
              ulong **                in_fseq,
              uchar const **          in_dcache,
              fd_pack_t *             pack,
              fd_frag_meta_t *        mcache,
              uchar *                 dcache,
              ulong                   out_cnt,
              ulong **                out_fseq,
              ulong **                out_busy,
              ulong                   cr_max,
              long                    lazy,
              fd_rng_t *              rng,
              void *                  scratch ) {
  fd_pack_ctx_t ctx[1];

  fd_mux_callbacks_t callbacks[1] = { 0 };
  callbacks->before_credit = before_credit;
  callbacks->after_credit  = after_credit;
  callbacks->during_frag   = during_frag;
  callbacks->after_frag    = after_frag;

  ulong scratch_top = (ulong)scratch;

  do {
    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }
    if( FD_UNLIKELY( !pack ) ) { FD_LOG_WARNING(( "NULL pack" )); return 1; }
    if( FD_UNLIKELY( out_cnt>FD_PACK_PACK_MAX_OUT ) ) { FD_LOG_WARNING(( "pack tile connects to too many banking tiles" )); return 1; }
    for( ulong i=0; i<in_cnt; i++ ) {
      if( FD_UNLIKELY( !in_dcache[i] ) ) { FD_LOG_WARNING(( "NULL in_dcache[%lu]", i )); return 1; }
    }
    for( ulong i=0; i<out_cnt; i++ ) {
      if( FD_UNLIKELY( !out_busy[i] ) ) { FD_LOG_WARNING(( "NULL out_busy[%lu]", i )); return 1; }
    }

    ctx->pack = pack;
    ctx->cur_slot = NULL;

    ctx->block_duration_ticks = (long)(fd_tempo_tick_per_ns( NULL ) * (double)BLOCK_DURATION_NS);
    ctx->block_end = fd_tickcount() + ctx->block_duration_ticks;

    ctx->in = (fd_pack_in_ctx_t*)SCRATCH_ALLOC( alignof(fd_pack_in_ctx_t), in_cnt*sizeof(fd_pack_in_ctx_t) );
    for( ulong i=0; i<in_cnt; i++ ) {
      if( FD_UNLIKELY( !in_dcache[i] ) ) { FD_LOG_WARNING(( "NULL in_dcache[%lu]", i )); return 1; }
      if( FD_UNLIKELY( !fd_dcache_compact_is_safe( fd_wksp_containing( in_dcache[i] ), in_dcache[i], FD_TPU_DCACHE_MTU, fd_mcache_depth( in_mcache[i] ) ) ) ) {
        FD_LOG_WARNING(( "in_dcache[%lu] not compatible with wksp base and mcache depth", i ));
        return 1;
      }
      ctx->in[i].wksp   = fd_wksp_containing( in_dcache[i] );
      ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].wksp, in_dcache[i] );
      ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].wksp, in_dcache[i], FD_TPU_DCACHE_MTU );
    }

    ctx->out_cnt  = out_cnt;
    ctx->out_busy = out_busy;

    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( fd_wksp_containing( dcache ), dcache, MAX_MICROBLOCK_SZ, fd_mcache_depth( mcache ) ) ) ) {
      FD_LOG_WARNING(( "dcache not compatible with wksp base and mcache depth" ));
      return 1;
    }
    ctx->out_wksp   = fd_wksp_containing( dcache );
    ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_wksp, dcache );
    ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_wksp, dcache, MAX_MICROBLOCK_SZ );
    ctx->out_chunk  = ctx->out_chunk0;
  } while(0);

  return fd_mux_tile( cnc,
                      pid,
                      FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
                      in_cnt,
                      in_mcache,
                      in_fseq,
                      mcache,
                      out_cnt,
                      out_fseq,
                      cr_max,
                      lazy,
                      rng,
                      (void*)fd_ulong_align_up( scratch_top, FD_MUX_TILE_SCRATCH_ALIGN ),
                      ctx,
                      callbacks );
}
