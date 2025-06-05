#include "../../disco/topo/fd_topo.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "fd_restore_base.h"
#include "stream/fd_stream_ctx.h"
#include "stream/fd_stream_reader.h"
#include "stream/fd_stream_writer.h"
#include <unistd.h> /* pause */

#define NAME "SnapDc"
#define ZSTD_WINDOW_SZ (33554432UL)
#define ZSTD_FRAME_SZ 8*1024*1024UL
#define LINK_IN_MAX 1

#define SNAP_DC_STATUS_WAITING 0UL
#define SNAP_DC_STATUS_FULL    1UL
#define SNAP_DC_STATUS_INC     2UL
#define SNAP_DC_STATUS_DONE    3UL

struct fd_snapdc_tile {
  fd_stream_frag_meta_ctx_t in_state; /* input mcache context */
  fd_zstd_dstream_t *       dstream;  /* zstd decompress reader */
  fd_stream_writer_t *      writer;   /* stream writer object */
  struct {

    struct {
      ulong compressed_bytes_read;
      ulong decompressed_bytes_read;
      ulong decompressed_bytes_total;
    } full;

    struct {
      ulong compressed_bytes_read;
      ulong decompressed_bytes_read;
      ulong decompressed_bytes_total;
    } incremental;

    ulong status;
  } metrics;
};
typedef struct fd_snapdc_tile fd_snapdc_tile_t;

FD_FN_PURE static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snapdc_tile_t), fd_zstd_dstream_align() );
}

FD_FN_PURE static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapdc_tile_t), sizeof(fd_snapdc_tile_t)         );
  l = FD_LAYOUT_APPEND( l, fd_zstd_dstream_align(),   fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
fd_snapdc_set_status( fd_snapdc_tile_t * ctx,
                      ulong              status ) {
  ctx->metrics.status = status;
  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( SNAPDC, STATUS, status );
  FD_COMPILER_MFENCE();
}

static void
fd_snapdc_accumulate_metrics( fd_snapdc_tile_t * ctx,
                              ulong              compressed_bytes_read,
                              ulong              decompressed_bytes_read ) {
  if( ctx->metrics.status == SNAP_DC_STATUS_FULL ) {
    ctx->metrics.full.compressed_bytes_read   += compressed_bytes_read;
    ctx->metrics.full.decompressed_bytes_read += decompressed_bytes_read;
  } else if( ctx->metrics.status == SNAP_DC_STATUS_INC ) {
    ctx->metrics.incremental.compressed_bytes_read   += compressed_bytes_read;
    ctx->metrics.incremental.decompressed_bytes_read += decompressed_bytes_read;
  } else {
    FD_LOG_ERR(("snapdc: unexpected status"));
  }
}

static void
metrics_write( void * _ctx ) {
  fd_snapdc_tile_t * ctx = fd_type_pun( _ctx );
  FD_MGAUGE_SET( SNAPDC, FULL_COMPRESSED_BYTES_READ, ctx->metrics.full.compressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, FULL_DECOMPRESSED_BYTES_READ, ctx->metrics.full.decompressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, FULL_DECOMPRESSED_BYTES_TOTAL, ctx->metrics.full.decompressed_bytes_total );

  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_COMPRESSED_BYTES_READ, ctx->metrics.incremental.compressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_READ, ctx->metrics.incremental.decompressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_TOTAL, ctx->metrics.incremental.decompressed_bytes_total );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  fd_snapdc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapdc_tile_t), sizeof(fd_snapdc_tile_t) );
  void * zstd_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_zstd_dstream_align(), fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ) );

  void * out_dcache = fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ) );
  FD_TEST( out_dcache );

  fd_memset( ctx, 0, sizeof(fd_snapdc_tile_t) );

  ctx->in_state.in_buf = (uchar const *)topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->dstream         = fd_zstd_dstream_new( zstd_mem, ZSTD_WINDOW_SZ );

  fd_zstd_dstream_reset( ctx->dstream );
  fd_snapdc_set_status( ctx, SNAP_DC_STATUS_FULL );
}

static void
fd_snapdc_init_from_stream_ctx( void * _ctx,
                                fd_stream_ctx_t * stream_ctx ) {
  fd_snapdc_tile_t * ctx = fd_type_pun(_ctx);

  /* There's only one writer */
  ctx->writer = fd_stream_writer_join( stream_ctx->writers[0] );
  FD_TEST( ctx->writer );
  fd_stream_writer_set_frag_sz_max( ctx->writer, ZSTD_FRAME_SZ );
}

__attribute__((noreturn)) static void
fd_snapdc_shutdown( void ) {
  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_COMPILER_MFENCE();

  FD_LOG_INFO(("snapdc: shutting down"));

  for(;;) pause();
}

static void
fd_snapdc_on_file_complete( fd_snapdc_tile_t *   ctx,
                            fd_stream_reader_t * reader ) {
  if( ctx->metrics.status == SNAP_DC_STATUS_FULL ) {
    FD_LOG_INFO(("snapdc: done decompressing full snapshot, now decompressing incremental snapshot"));
    fd_snapdc_set_status( ctx, SNAP_DC_STATUS_INC );

    /* notify downstream consumer */
    fd_stream_writer_notify( ctx->writer,
                             fd_frag_meta_ctl( 0UL, 0, 1, 0 ) );

    /* reset */
    fd_zstd_dstream_reset( ctx->dstream );
    fd_stream_writer_reset_stream( ctx->writer );
    fd_stream_reader_reset_stream( reader );

  } else if( ctx->metrics.status == SNAP_DC_STATUS_INC ) {
    FD_LOG_INFO(("snapdc: done decompressing incremental snapshot"));
    fd_snapdc_set_status( ctx, SNAP_DC_STATUS_DONE );
    fd_stream_writer_notify( ctx->writer,
                             fd_frag_meta_ctl( 0UL, 0, 1, 0 ) );
    fd_snapdc_shutdown();

  } else {
    FD_LOG_ERR(("snapdc: unexpected status"));
  }
}

static int
on_stream_frag( void *                        _ctx,
                fd_stream_reader_t *          reader,
                fd_stream_frag_meta_t const * frag,
                ulong *                       sz ) {
  fd_snapdc_tile_t * ctx = fd_type_pun(_ctx);

  /* poll file complete notification */
  if( FD_UNLIKELY( fd_frag_meta_ctl_eom( frag->ctl ) ) ) {
    fd_snapdc_on_file_complete( ctx, reader );
    *sz = frag->sz;
    return 1;
  }

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
      FD_LOG_ERR(( "snapdc: fd_zstd_dstream_read failed on seq %lu", reader->base.seq ));
      break;
    }

    /* accumulate consumed bytes */
    ulong consumed_sz      = (ulong)in_cur - (ulong)in_prev;
    ctx->in_state.in_skip += consumed_sz;
  }

  ulong decompressed_bytes = (ulong)out_cur-(ulong)out;
  ulong consumed_bytes     = (ulong)in_cur - (ulong)in_chunk_start;
  fd_stream_writer_publish( ctx->writer, decompressed_bytes, 0UL );
  fd_snapdc_accumulate_metrics( ctx, consumed_bytes, decompressed_bytes );

  *sz = (ulong)in_cur - (ulong)in_chunk_start;
  return in_consume;
}

static void
fd_snapdc_in_update( fd_stream_reader_t * in ) {
  fd_stream_reader_update_upstream( in );
}

__attribute__((noinline)) static void
fd_snapdc_run1(
  fd_snapdc_tile_t *         ctx,
  fd_stream_ctx_t *          stream_ctx ) {

  FD_LOG_INFO(( "Running snapdc tile" ));

  fd_stream_ctx_run( stream_ctx,
                     ctx,
                     fd_snapdc_init_from_stream_ctx,
                     fd_snapdc_in_update,
                     NULL,
                     metrics_write,
                     NULL,
                     on_stream_frag );
}

static void
fd_snapdc_run( fd_topo_t * topo,
               fd_topo_tile_t * tile ) {
  fd_snapdc_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  void * ctx_mem = fd_alloca_check( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_footprint( topo, tile ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile );
  FD_TEST( stream_ctx );
  fd_snapdc_run1( ctx, stream_ctx );
}

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_snapshot_restore_SnapDc = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = fd_snapdc_run,
};
#endif

#undef NAME
