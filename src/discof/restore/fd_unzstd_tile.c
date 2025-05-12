#include "../../disco/topo/fd_topo.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "fd_restore_base.h"
#include "stream/fd_stream_ctx.h"
#include "stream/fd_stream_writer.h"
#include <errno.h>
#include <unistd.h>

#define NAME "unzstd"
#define ZSTD_WINDOW_SZ (33554432UL)
#define ZSTD_FRAME_SZ 16384UL
#define LINK_IN_MAX 1

struct fd_unzstd_tile {
  fd_stream_frag_meta_ctx_t in_state; /* input mcache context */
  fd_zstd_dstream_t *       dstream;  /* zstd decompress reader */
  fd_stream_writer_t *      writer;   /* stream writer object */
};

typedef struct fd_unzstd_tile fd_unzstd_tile_t;

FD_FN_PURE static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_unzstd_tile_t), fd_zstd_dstream_align() );
}

FD_FN_PURE static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_unzstd_tile_t), sizeof(fd_unzstd_tile_t)         );
  l = FD_LAYOUT_APPEND( l, fd_zstd_dstream_align(),   fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ) );
  l = FD_LAYOUT_APPEND( l, fd_stream_writer_align(), fd_stream_writer_footprint() );
  return l;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_unzstd_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_unzstd_tile_t), sizeof(fd_unzstd_tile_t) );
  void * zstd_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_zstd_dstream_align(), fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ) );
  void * writer_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_stream_writer_align(), fd_stream_writer_footprint() );

  void * out_dcache = fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ) );
  FD_TEST( out_dcache );

  fd_memset( ctx, 0, sizeof(fd_unzstd_tile_t) );

  ctx->in_state.in_buf = (uchar const *)topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->dstream         = fd_zstd_dstream_new( zstd_mem, ZSTD_WINDOW_SZ );
  ctx->writer          = fd_stream_writer_new( writer_mem, topo, tile, 0, ZSTD_WINDOW_SZ, 512UL, 2UL );

  fd_zstd_dstream_reset( ctx->dstream );
}

static void
during_housekeeping( fd_unzstd_tile_t * ctx ) {
  (void)ctx;
}

static int
on_stream_frag( void *                        _ctx,
                fd_stream_reader_t *          reader FD_PARAM_UNUSED,
                fd_stream_frag_meta_t const * frag,
                ulong *                       sz ) {
  fd_unzstd_tile_t * ctx = fd_type_pun(_ctx);
  uchar const * chunk0             = ctx->in_state.in_buf + frag->loff;
  uchar const * chunk_start        = chunk0 + ctx->in_state.in_skip;
  uchar const * chunk_end          = chunk0 + frag->sz;
  uchar const * cur                = chunk_start;
  ulong         total_decompressed = 0UL;
  int           consume_frag       = 0;

  for(;;) {
    uchar const * prev = cur;

    if( cur==chunk_end ) {
      /* Done with frag */
      fd_stream_writer_publish( ctx->writer, total_decompressed );
      ctx->in_state.in_skip = 0UL;
      consume_frag          = 1;
      break;
    }

    /* get write pointers into dcache buffer */
    uchar * buf_write_start = fd_stream_writer_get_write_ptr( ctx->writer );
    uchar * out             = buf_write_start;
    ulong dst_max           = fd_stream_writer_get_avail_bytes( ctx->writer );
    uchar * out_end         = buf_write_start + dst_max;

    if( dst_max==0 ) {
      /* we are blocked by downstream */
      fd_stream_writer_publish( ctx->writer, total_decompressed );
      break;
    }


    /* fd_zstd_dstream_read updates chunk_start and out */
    int zstd_err = fd_zstd_dstream_read( ctx->dstream, &cur, chunk_end, &out, out_end, NULL );
    if( FD_UNLIKELY( zstd_err>0) ) {
      FD_LOG_ERR(( "fd_zstd_dstream_read failed" ));
      break;
    }

    /* accumulate decompressed bytes */
    ulong decompress_sz  = (ulong)out - (ulong)buf_write_start;
    total_decompressed  += decompress_sz;

    /* accumulate consumed bytes */
    ulong consumed_sz      = (ulong)cur - (ulong)prev;
    ctx->in_state.in_skip += consumed_sz;

    fd_stream_writer_advance( ctx->writer, decompress_sz );
  }

  *sz = (ulong)cur - (ulong)chunk_start;
  return consume_frag;
}

static void
fd_unzstd_in_update( fd_stream_reader_t * in ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( in->base.fseq[0] ) = in->base.seq;
  FD_VOLATILE( in->base.fseq[1] ) = in->goff;
  FD_COMPILER_MFENCE();

  ulong volatile * metrics = fd_metrics_link_in( fd_metrics_base_tl, in->base.idx );

  uint * accum = in->base.accum;
  ulong a0 = accum[0]; ulong a1 = accum[1]; ulong a2 = accum[2];
  ulong a3 = accum[3]; ulong a4 = accum[4]; ulong a5 = accum[5];
  FD_COMPILER_MFENCE();
  metrics[0] += a0;    metrics[1] += a1;    metrics[2] += a2;
  metrics[3] += a3;    metrics[4] += a4;    metrics[5] += a5;
  FD_COMPILER_MFENCE();
  accum[0] = 0U;       accum[1] = 0U;       accum[2] = 0U;
  accum[3] = 0U;       accum[4] = 0U;       accum[5] = 0U;
}

__attribute__((noreturn)) static void
fd_unzstd_shutdown( void ) {
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  /* FIXME set final sequence number */
  FD_COMPILER_MFENCE();
  FD_LOG_INFO(( "Finished parsing snapshot" ));

  for(;;) pause();
}

static void
fd_unzstd_poll_shutdown( fd_stream_ctx_t *      stream_ctx,
                          ulong const volatile * shutdown_signal ) {
  ulong const in_seq_max = FD_VOLATILE_CONST( *shutdown_signal );
  if( FD_UNLIKELY( in_seq_max == stream_ctx->in[ 0 ].base.seq && in_seq_max != 0) ) {
    FD_LOG_WARNING(( "zstd shutting down! in_seq_max is %lu in[0].base.seq is %lu",
                     in_seq_max, stream_ctx->in[0].base.seq));
    fd_unzstd_shutdown();
  }
}

__attribute__((noinline)) static void
fd_unzstd_run1(
  fd_unzstd_tile_t *         ctx,
  fd_stream_ctx_t *          stream_ctx ) {

  FD_LOG_INFO(( "Running unzstd tile" ));

  /* run loop init */
  ulong const volatile * restrict shutdown_signal = fd_mcache_seq_laddr_const( stream_ctx->in[0].base.mcache->f ) + 3;
  fd_stream_writer_init_flow_control_credits( ctx->writer );
  fd_stream_ctx_init_run_loop( stream_ctx );

  for(;;) {
    if( FD_UNLIKELY( fd_stream_ticks_is_housekeeping_time( stream_ctx->ticks ) ) ) {
      ulong event_idx = fd_event_map_get_event( stream_ctx->event_map );

      if( FD_LIKELY( event_idx<stream_ctx->cons_cnt ) ) { /* receive credits */
        ulong cons_idx = event_idx;
  
        /* Receive flow control credits from this out. */
        fd_stream_writer_receive_flow_control_credits( ctx->writer, cons_idx );

        fd_unzstd_poll_shutdown( stream_ctx, shutdown_signal );

      } else if( event_idx>stream_ctx->cons_cnt) { /* send credits */
        ulong in_idx = event_idx - stream_ctx->cons_cnt - 1UL;
        fd_unzstd_in_update( &stream_ctx->in[ in_idx ] );
      }
      else { /* event_idx==cons_cnt, housekeeping event */

        /* Update metrics counters to external viewers */
        fd_stream_metrics_update_external( stream_ctx->metrics,
                                           stream_ctx->ticks->now,
                                           NULL,
                                           ctx );
        /* Recalculate flow control credits */
        ulong slowest_cons = ULONG_MAX;
        fd_stream_writer_update_flow_control_credits( ctx->writer,
                                                      &slowest_cons );
        fd_stream_ctx_update_cons_slow( stream_ctx,
                                        slowest_cons );
        during_housekeeping( ctx );
      }
      fd_stream_ctx_housekeeping_advance( stream_ctx );
    }

    /* Check if we are backpressured, otherwise poll */
    if( FD_UNLIKELY( fd_stream_writer_is_backpressured( ctx->writer ) ) ) {
      fd_stream_ctx_process_backpressure( stream_ctx );
    } else {
      fd_stream_ctx_poll( stream_ctx, ctx, on_stream_frag );
    }
  }
}

static void
fd_unzstd_run( fd_topo_t * topo,
               fd_topo_tile_t * tile ) {
  fd_unzstd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong in_cnt           = fd_topo_tile_producer_cnt( topo, tile );
  ulong cons_cnt         = fd_topo_tile_reliable_consumer_cnt( topo, tile );

  void * ctx_mem = fd_alloca( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_scratch_footprint( in_cnt, cons_cnt ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile, in_cnt, cons_cnt );
  fd_unzstd_run1( ctx,
                  stream_ctx );
}

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_snapshot_restore_Unzstd = {
  .name              = "Unzstd",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = fd_unzstd_run,
};
#endif