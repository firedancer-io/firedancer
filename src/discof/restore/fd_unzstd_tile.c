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
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  fd_unzstd_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_unzstd_tile_t), sizeof(fd_unzstd_tile_t) );
  void * zstd_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_zstd_dstream_align(), fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ) );

  void * out_dcache = fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ) );
  FD_TEST( out_dcache );

  fd_memset( ctx, 0, sizeof(fd_unzstd_tile_t) );

  ctx->in_state.in_buf = (uchar const *)topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->dstream         = fd_zstd_dstream_new( zstd_mem, ZSTD_WINDOW_SZ );

  fd_zstd_dstream_reset( ctx->dstream );
}

static void
fd_unzstd_init_from_stream_ctx( void * _ctx,
                                fd_stream_ctx_t * stream_ctx ) {
  fd_unzstd_tile_t * ctx = fd_type_pun(_ctx);

  /* join writer */
  ctx->writer = fd_stream_writer_join( &stream_ctx->writers[0] );
  fd_stream_writer_set_frag_sz_max( ctx->writer, ZSTD_FRAME_SZ );
}

__attribute__((noreturn)) static void
fd_unzstd_shutdown( fd_unzstd_tile_t * ctx ) {
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  fd_stream_writer_notify_shutdown( ctx->writer );
  FD_COMPILER_MFENCE();

  for(;;) pause();
}

static void
fd_unzstd_poll_shutdown( fd_stream_ctx_t *      stream_ctx,
                         fd_unzstd_tile_t *     ctx ) {
  ulong shutdown_seq = fd_stream_reader_poll_shutdown( stream_ctx->in_ptrs[0] );
  if( FD_UNLIKELY( shutdown_seq ) ) {
    FD_LOG_WARNING(( "zstd shutting down! in_seq_max is %lu in[0].base.seq is %lu",
                     shutdown_seq, stream_ctx->in[0].base.seq));
    fd_unzstd_shutdown( ctx );
  }
}

static void
during_housekeeping( void * _ctx,
                     fd_stream_ctx_t * stream_ctx ) {
  fd_unzstd_tile_t * ctx = fd_type_pun(_ctx);
  fd_unzstd_poll_shutdown( stream_ctx, ctx );
}

static int
on_stream_frag( void *                        _ctx,
                fd_stream_reader_t *          reader FD_PARAM_UNUSED,
                fd_stream_frag_meta_t const * frag,
                ulong *                       sz ) {
  fd_unzstd_tile_t * ctx = fd_type_pun(_ctx);

  /* Don't do anything if backpressured */
  if( FD_UNLIKELY( fd_stream_writer_is_backpressured( ctx->writer ) ) ) {
    return 0;
  }

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

__attribute__((noinline)) static void
fd_unzstd_run1(
  fd_unzstd_tile_t *         ctx,
  fd_stream_ctx_t *          stream_ctx ) {

  FD_LOG_INFO(( "Running unzstd tile" ));

  fd_stream_ctx_run( stream_ctx,
                     ctx,
                     fd_unzstd_init_from_stream_ctx,
                     fd_unzstd_in_update,
                     during_housekeeping,
                     NULL,
                     NULL,
                     on_stream_frag );
}

static void
fd_unzstd_run( fd_topo_t * topo,
               fd_topo_tile_t * tile ) {
  fd_unzstd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong in_cnt           = fd_topo_tile_producer_cnt( topo, tile );
  ulong out_cnt          = tile->out_cnt;

  void * ctx_mem = fd_alloca( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_scratch_footprint( in_cnt, out_cnt ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile, in_cnt, out_cnt );
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

#undef NAME
