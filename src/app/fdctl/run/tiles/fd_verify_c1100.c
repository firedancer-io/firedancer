#include "../../../../disco/tiles.h"
#include "fd_verify_c1100.h"

#include "generated/verify_c1100_seccomp.h"

#include "../../../../disco/quic/fd_tpu.h"

#include <linux/unistd.h>


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <limits.h>


uchar * ibuf_ele( fd_verify_ctx_t * ctx, uint i ) {
  return ctx->ibuf + i*IBUF_ELE_SZ;
}

uchar * ibuf_curr( fd_verify_ctx_t * ctx) {
  return ctx->ibuf + ctx->ibuf_cnt*IBUF_ELE_SZ;
}

void ibuf_advance( fd_verify_ctx_t * ctx ) {
  ctx->ibuf_cnt++;
}

void ibuf_next( fd_verify_ctx_t * ctx , uchar ** p ) {
  *p = ctx->ibuf + ctx->ibuf_cnt*IBUF_ELE_SZ;
  ctx->ibuf_cnt++;
}

int ibuf_poll_needed( fd_verify_ctx_t * ctx ) {
  long now = fd_tickcount();
  if( FD_UNLIKELY( ctx->ibuf_cnt == IBUF_SZ || (now-ctx->then)>=IBUF_TICKER_NS ) ) {
    ctx->then = now;
    return 1;
  }
  return 0;
}

void poll_and_publish( fd_verify_ctx_t * ctx, fd_mux_context_t * mux ) {
  /* no work needed */
  if( FD_UNLIKELY( ctx->ibuf_cnt == 0 ) ) {
    return;
  }

  if( FD_UNLIKELY( ctx->ibuf_cnt > IBUF_SZ ) ) {
    FD_LOG_CRIT(( "overrun %u", ctx->ibuf_cnt ));
  }

  // C1100 backpressure work here

  // c1100_verify_backpressure( ctx->c1100 );

  // uint bp;
  // for( uint i=0; i<C1100_MAX_TRIES; i++ ) {
  //   bp=c1100_verify_backpressure( ctx->c1100 );
  //   if( FD_UNLIKELY( bp != 0 ) ) {
  //     break;
  //   }
  // }

  // if( FD_UNLIKELY( bp == 0 ) ) {
  //   FD_LOG_WARNING(( "C1100_MAX_TRIES exceeded" ));
  //   ctx->ibuf_cnt = 0;
  //   return;
  // }

  for( uint i=0; i<ctx->ibuf_cnt; i++ ) {
    ulong payload_sz = ctx->payload_sz[i];
    ulong txnt_off   = fd_ulong_align_up( payload_sz, 2UL );

    /* Ensure sufficient space to store trailer */

    long txnt_maxsz = (long)FD_TPU_DCACHE_MTU -
                      (long)txnt_off -
                      (long)sizeof(ushort);
    if( FD_UNLIKELY( txnt_maxsz<(long)FD_TXN_MAX_SZ ) ) FD_LOG_ERR(( "got malformed txn (sz %lu) does not fit in dcache", payload_sz ));

    // uchar const * txn   = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    uchar const * txn   = ibuf_ele( ctx, i );
    fd_txn_t *    txn_t = (fd_txn_t *)((ulong)txn + txnt_off);

    /* Parse transaction */

    ulong txn_t_sz = fd_txn_parse( txn, payload_sz, txn_t, NULL );
    if( FD_UNLIKELY( !txn_t_sz ) ) {
      continue;
    }

    /* Write payload_sz */

    /* fd_txn_parse always returns a multiple of 2 so this sz is
      correctly aligned. */
    ushort * payload_sz_p = (ushort *)( (ulong)txn_t + txn_t_sz );
    *payload_sz_p = (ushort)payload_sz;

    /* End of message */

    ulong new_sz = ( (ulong)payload_sz_p + sizeof(ushort) ) - (ulong)txn;
    if( FD_UNLIKELY( new_sz>FD_TPU_DCACHE_MTU ) ) {
      FD_LOG_CRIT(( "memory corruption detected (txn_sz=%lu txn_t_sz=%lu)",
                    payload_sz, txn_t_sz ));
    }

    ulong txn_sig;
    int res = fd_txn_verify( ctx, txn, (ushort)payload_sz, txn_t, &txn_sig );
    if( FD_UNLIKELY( res!=FD_TXN_VERIFY_SUCCESS ) ) {
      continue;
    }

    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

    uchar * ptr   = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    fd_memcpy( ptr, ibuf_ele( ctx, i), new_sz );

    fd_mux_publish( mux, txn_sig, ctx->out_chunk, new_sz, 0UL, 0, tspub );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, new_sz, ctx->out_chunk0, ctx->out_wmark );
  }

  ctx->ibuf_cnt = 0;
}


/* The verify tile is a wrapper around the mux tile, that also verifies
   incoming transaction signatures match the data being signed.
   Non-matching transactions are filtered out of the frag stream. */

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_TCACHE_ALIGN;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(), fd_tcache_footprint( VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  for( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_sha512_align(), fd_sha512_footprint() );
  }
  l = FD_LAYOUT_APPEND( l, 32, 1UL<<30 );
  l = FD_LAYOUT_APPEND( l, 32, IBUF_ELE_SZ * IBUF_SZ );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_verify_ctx_t ) );
}

static void
before_credit( void * _ctx, fd_mux_context_t * mux ) {
  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;
  if( FD_UNLIKELY( ibuf_poll_needed( ctx ) ) ) {
    poll_and_publish( ctx, mux );
  }
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;
  (void)sig;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;
  if( FD_LIKELY( (seq % ctx->round_robin_cnt) != ctx->round_robin_idx ) ) *opt_filter = 1;
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( void * _ctx,
             ulong in_idx,
             ulong seq,
             ulong sig,
             ulong chunk,
             ulong sz,
             int * opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz>FD_TPU_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = ibuf_curr( ctx );

  fd_memcpy( dst, src, sz );
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
  (void)seq;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_tsorig;
  (void)opt_filter;

  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)_ctx;
  ctx->payload_sz[ ctx->ibuf_cnt ] = *opt_sz;
  ibuf_advance( ctx );

  if( FD_UNLIKELY( ibuf_poll_needed( ctx ) ) ) {
    poll_and_publish( ctx, mux );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( FD_SCRATCH_ALLOC_APPEND( l, FD_TCACHE_ALIGN, FD_TCACHE_FOOTPRINT( VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) ), VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  for ( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    ctx->sha[i] = sha;
  }

  ctx->tcache_depth   = fd_tcache_depth       ( tcache );
  ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];

    if( FD_UNLIKELY( link->is_reasm ) ) {
      fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->reasm_obj_id ].wksp_id ];
      ctx->in[i].mem = link_wksp->wksp;
      ctx->in[i].chunk0 = fd_laddr_to_chunk( ctx->in[i].mem, link->reasm );
      ctx->in[i].wmark  = ctx->in[i].chunk0 + (link->depth+link->burst-1) * FD_TPU_REASM_CHUNK_MTU;
    } else {
      fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      ctx->in[i].mem = link_wksp->wksp;
      ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
      ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    }
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  if( FD_UNLIKELY( tile->kind_id == 0 ) ) {
    ulong * dma_region = (ulong *)ctx->buf;
    for (uint i = 0; i < 1024; i ++) {
        uint off = i * 2048 / 8;
        for (uint j = 0; j < 256; j ++)
            dma_region[off+j] = 0xabcdeffe0000000FL + (i << 16) + (j << 8);
        dma_region[off+4] = 0x5e00000000000000; // udp len
    }
    FD_LOG_NOTICE(( "dma addr: %lx", ctx->dma_addr ));
    c1100_verify_set_dma( ctx->c1100, ctx->dma_addr );
    uint32_t size = 32*8;
    c1100_verify_packet_ed25519( ctx->c1100, 0, size );
    c1100_verify_packet_ed25519( ctx->c1100, 2048, size );

    for( uint bp=c1100_verify_backpressure( ctx->c1100 ); bp != 0; bp=c1100_verify_backpressure( ctx->c1100 ) ) {
      FD_LOG_NOTICE(( "results %x", bp ));
    }
    FD_LOG_NOTICE(( "results %x", c1100_verify_backpressure( ctx->c1100 ) ));
    FD_LOG_NOTICE(( "results %x", c1100_verify_deserializer( ctx->c1100 ) ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  ctx->buf = FD_SCRATCH_ALLOC_APPEND( l, 32, 1UL<<30 );
  ctx->ibuf = FD_SCRATCH_ALLOC_APPEND( l, 32, IBUF_ELE_SZ * IBUF_SZ );
  ctx->ibuf_cnt = 0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->kind_id = tile->kind_id;
  if( FD_UNLIKELY( ctx->kind_id == 0 ) ) {
    FD_TEST( c1100_init( ctx->c1100, tile->verify.pcie_device ) == 0 );
    ctx->dma_addr = _wd_get_phys( ctx->buf );
  }
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_verify_c1100( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_verify_c1100_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  fd_verify_ctx_t * ctx = (fd_verify_ctx_t *)scratch;
  uint bar_cnt = 0;
  if( FD_UNLIKELY( ctx->kind_id == 0 ) ) {
    bar_cnt = c1100_bar_count( ctx->c1100 );
  }

  if( FD_UNLIKELY( out_fds_cnt < 2+bar_cnt ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  for( uint i=0; i<bar_cnt; i++ ) out_fds[ out_cnt++ ] = ctx->c1100->bm[i].fd;
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_verify = {
  .name                     = "verify",
  .mux_flags                = FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_credit        = before_credit,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
