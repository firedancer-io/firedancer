#include "../../disco/topo/fd_topo.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "fd_restore_base.h"
#include "stream/fd_stream_ctx.h"
#include "stream/fd_stream_writer.h"
#include <unistd.h> /* pause */

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

  /* There's only one writer */
  ctx->writer = fd_stream_writer_join( stream_ctx->writers[0] );
  FD_TEST( ctx->writer );
  fd_stream_writer_set_frag_sz_max( ctx->writer, ZSTD_FRAME_SZ );
}

__attribute__((noreturn)) static void
fd_unzstd_shutdown( fd_unzstd_tile_t * ctx ) {
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  fd_stream_writer_close( ctx->writer );
  FD_COMPILER_MFENCE();

  for(;;) pause();
}

static void
fd_unzstd_poll_shutdown( fd_stream_ctx_t *  stream_ctx,
                         fd_unzstd_tile_t * ctx ) {
  ulong const volatile * in_sync = stream_ctx->in_ptrs[ 0 ]->in_sync;
  if( FD_LIKELY( !FD_VOLATILE_CONST( in_sync[ 2 ] ) ) ) return;

  FD_LOG_WARNING(( "zstd shutting down! in_seq_max is %lu in[0].base.seq is %lu",
                    FD_VOLATILE_CONST( in_sync[ 0 ] ), stream_ctx->in[0].base.seq ));
  fd_unzstd_shutdown( ctx );
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

  /* Input */
  uchar const * in_chunk0      = ctx->in_state.in_buf + frag->loff;
  uchar const * in_chunk_start = in_chunk0 + ctx->in_state.in_skip;
  uchar const * in_chunk_end   = in_chunk0 + frag->sz;
  uchar const * in_cur         = in_chunk_start;
  int           in_consume     = 0;

  /* Output */
  uchar * const out     = fd_stream_writer_prepare( ctx->writer );
  uchar * const out_end = out + fd_stream_writer_publish_sz_max( ctx->writer );
  uchar *       out_cur = out;

  while( out_cur<out_end ) {
    uchar const * in_prev = in_cur;

    if( in_cur==in_chunk_end ) {
      /* Done with frag */
      ctx->in_state.in_skip = 0UL;
      in_consume            = 1;
      break;
    }

    /* fd_zstd_dstream_read updates chunk_start and out */
    int zstd_err = fd_zstd_dstream_read( ctx->dstream, &in_cur, in_chunk_end, &out_cur, out_end, NULL );
    if( FD_UNLIKELY( zstd_err>0 ) ) {
      FD_LOG_ERR(( "fd_zstd_dstream_read failed" ));
      break;
    }

    /* accumulate consumed bytes */
    ulong consumed_sz      = (ulong)in_cur - (ulong)in_prev;
    ctx->in_state.in_skip += consumed_sz;
  }

  fd_stream_writer_publish( ctx->writer, (ulong)out_cur-(ulong)out, 0UL );

  *sz = (ulong)in_cur - (ulong)in_chunk_start;
  return in_consume;
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
  void * ctx_mem = fd_alloca_check( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_footprint( topo, tile ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile );
  FD_TEST( stream_ctx );
  fd_unzstd_run1( ctx, stream_ctx );
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
