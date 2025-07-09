#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "utils/fd_snapshot_messages_internal.h"

#include <unistd.h> /* pause */

#define NAME "snapdc"
#define SNAPDC_WRITE_MAX ( USHORT_MAX )
#define ZSTD_WINDOW_SZ (1UL<<25UL) /* 32MiB */
#define SNAPDC_BURST_MAX ( 200UL )

/* The snapdc tile is a state machine that decompresses the full and
   optionally incremental snapshot byte stream that it receives from the
   snaprd tile.

   snaprd may send a retry notification, which causes snapdc to reset
   its decompressor state and byte stream while staying in the same
   state.

   snaprd may also send a reset notification, which causes snapdc to
   reset itself and transition back to DECOMPRESSING_FULL. */

/* The initial state is waiting for an incoming compressed
   byte stream of the full snapshot. */
#define FD_SNAPDC_STATE_WAITING                   (0)

/* snapdc transitions to DECOMPRESSING_FULL once it starts decompressing
   the full snapshot byte stream.  It remains in this state as long
   as it has not received a end-of-stream notification from
   snaprd. */
#define FD_SNAPDC_STATE_DECOMPRESSING_FULL        (1)

/* snapdc transitions to decompressing the incremental snapshot byte
   stream when it receives a end-of-stream notification from
   snaprd.  snapdc waits in this state indefinitely if there are no
   incoming incremental snapshot stream bytes. */
#define FD_SNAPDC_STATE_DECOMPRESSING_INCREMENTAL (2)

/* The terminal state of snapdc.  It transitions to DONE when it
   receives a tagged end-of-message notification from snaprd. */
#define FD_SNAPDC_STATE_DONE                      (3)

struct fd_snapdc_tile {
  int state;

  fd_zstd_dstream_t * dstream;

  struct {
    fd_wksp_t *  wksp;
    ulong        chunk0;
    ulong        wmark;
    ulong        mtu;
    ulong        _chunk;
  } in;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
  } out;

  struct {

    struct {
      ulong compressed_bytes_read;
      ulong decompressed_bytes_read;

      /* TODO: how to get this? zstd header does not have the frame
         content sz field populated. */
      ulong decompressed_bytes_total;
    } full;

    struct {
      ulong compressed_bytes_read;
      ulong decompressed_bytes_read;
      ulong decompressed_bytes_total;
    } incremental;

  } metrics;
};
typedef struct fd_snapdc_tile fd_snapdc_tile_t;

/* TODO: this should be a commom tile helper that all tiles can use. */
__attribute__((noreturn)) static void
fd_snapdc_shutdown( void ) {
  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_COMPILER_MFENCE();

  FD_LOG_INFO(("snapdc: shutting down"));

  for(;;) pause();
}

static void
fd_snapdc_accumulate_metrics( fd_snapdc_tile_t * ctx,
                              ulong              compressed_bytes,
                              ulong              decompressed_bytes ) {
  if( FD_LIKELY( ctx->state==FD_SNAPDC_STATE_DECOMPRESSING_FULL ) ) {
    ctx->metrics.full.compressed_bytes_read   += compressed_bytes;
    ctx->metrics.full.decompressed_bytes_read += decompressed_bytes;
  } else if( FD_LIKELY( ctx->state==FD_SNAPDC_STATE_DECOMPRESSING_INCREMENTAL ) ) {
    ctx->metrics.incremental.compressed_bytes_read   += compressed_bytes;
    ctx->metrics.incremental.decompressed_bytes_read += decompressed_bytes;
  }
}

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
metrics_write( fd_snapdc_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPDC, FULL_COMPRESSED_BYTES_READ,    ctx->metrics.full.compressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, FULL_DECOMPRESSED_BYTES_READ,  ctx->metrics.full.decompressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, FULL_DECOMPRESSED_BYTES_TOTAL, ctx->metrics.full.decompressed_bytes_total );

  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_COMPRESSED_BYTES_READ,    ctx->metrics.incremental.compressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_READ,  ctx->metrics.incremental.decompressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_TOTAL, ctx->metrics.incremental.decompressed_bytes_total );

  FD_MGAUGE_SET( SNAPDC, STATE, (ulong)(ctx->state) );
}

static inline void
handle_control_frag( fd_snapdc_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_FINI: {
      ctx->state = FD_SNAPDC_STATE_DONE;
      fd_stem_publish( stem,
                       0UL,
                       FD_SNAPSHOT_MSG_CTRL_FINI,
                       0UL,
                       0UL,
                       0UL,
                       0UL,
                       0UL );
      fd_snapdc_shutdown();
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_FULL_DONE: {
      /* Received a notification from snaprd indicating that the full
         snapshot byte stream is done, and now we are waiting for the
         incremental snapshot byte stream. */
      FD_TEST( ctx->state==FD_SNAPDC_STATE_DECOMPRESSING_FULL );
      ctx->state = FD_SNAPDC_STATE_DECOMPRESSING_INCREMENTAL;
      fd_stem_publish( stem,
                       0UL,
                       FD_SNAPSHOT_MSG_CTRL_FULL_DONE,
                       ctx->out.chunk,
                       0UL,
                       0UL,
                       0UL,
                       0UL );
      fd_zstd_dstream_reset( ctx->dstream );
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_RETRY: {
      /* Received a retry notification from snaprd indicating that the
         current snapshot byte stream is restarting. */
      fd_stem_publish( stem,
                       0UL,
                       FD_SNAPSHOT_MSG_CTRL_RETRY,
                       ctx->out.chunk,
                       0UL,
                       0UL,
                       0UL,
                       0UL );
      fd_zstd_dstream_reset( ctx->dstream );
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_ABANDON: {
      /* Received an abandon notification from snaprd indicating that
         a full snapshot byte stream is next. */
      ctx->state = FD_SNAPDC_STATE_WAITING;
      fd_stem_publish( stem,
                      0UL,
                      FD_SNAPSHOT_MSG_CTRL_ABANDON,
                      0UL,
                      0UL,
                      0UL,
                      0UL,
                      0UL );
      fd_zstd_dstream_reset( ctx->dstream );
      break;
    }
    default:
      FD_LOG_ERR(( "snapdc: unexpected sig %lu", sig ));
  }
}

static inline void
handle_data_frag( fd_snapdc_tile_t *  ctx,
                  fd_stem_context_t * stem,
                  ulong               chunk,
                  ulong               sz ) {
  FD_TEST( ctx->state==FD_SNAPDC_STATE_DECOMPRESSING_FULL ||
           ctx->state==FD_SNAPDC_STATE_DECOMPRESSING_INCREMENTAL );
  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  /* Input */
  uchar const * in_chunk_start = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
  uchar const * in_chunk_end   = in_chunk_start + sz;
  uchar const * in_cur         = in_chunk_start;

  ulong num_produced_frags = 0UL;

  while( in_cur<in_chunk_end ) {
    /* Output */
    uchar * const out     = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
    uchar * const out_end = out + SNAPDC_WRITE_MAX;
    uchar *       out_cur = out;

    /* produce full MTU sized frags by repeatedly calling dstream_read
       until output buffer is full. */
    while( out_cur<out_end ) {

      if( in_cur==in_chunk_end ) {
        break;
      }

      /* fd_zstd_dstream_read advances in_cur and out */
      int zstd_err = fd_zstd_dstream_read( ctx->dstream,
                                          &in_cur,
                                          in_chunk_end,
                                          &out_cur,
                                          out_end,
                                          NULL );
      if( FD_UNLIKELY( zstd_err>0 ) ) FD_LOG_CRIT(( "snapdc: fd_zstd_dstream_read failed" ));
    }

    ulong decompressed_bytes = (ulong)out_cur-(ulong)out;
    ulong consumed_bytes     = (ulong)in_cur - (ulong)in_chunk_start;

    if( FD_LIKELY( decompressed_bytes ) ) {
      fd_stem_publish( stem,
        0UL,
        FD_SNAPSHOT_MSG_DATA,
        ctx->out.chunk,
        decompressed_bytes,
        0UL,
        0UL,
        0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk,
                                               decompressed_bytes,
                                               ctx->out.chunk0,
                                               ctx->out.wmark );
      num_produced_frags++;
    }

    fd_snapdc_accumulate_metrics( ctx, consumed_bytes, decompressed_bytes );
  }

  FD_TEST( num_produced_frags<=SNAPDC_BURST_MAX );
}

static void
during_frag( fd_snapdc_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig,
             ulong              chunk,
             ulong              sz,
             ulong              ctl ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)ctl;

  /* We can't get overrun here, so it's valid to read the chunk data out
     in after_frag. */
  ctx->in._chunk = chunk;
}


static inline void
after_frag( fd_snapdc_tile_t *  ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)tsorig;
  (void)tspub;

  if( FD_UNLIKELY( ctx->state==FD_SNAPDC_STATE_WAITING ) ) ctx->state = FD_SNAPDC_STATE_DECOMPRESSING_FULL;

  if( FD_LIKELY( sz>0 ) ) handle_data_frag( ctx, stem, ctx->in._chunk, sz );
  else                    handle_control_frag( ctx, stem, sig );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapdc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapdc_tile_t), sizeof(fd_snapdc_tile_t) );
  void * zstd_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_zstd_dstream_align(),   fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ) );

  ctx->state   = FD_SNAPDC_STATE_WAITING;
  ctx->dstream = fd_zstd_dstream_new( zstd_mem, ZSTD_WINDOW_SZ );
  FD_TEST( ctx->dstream );

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  fd_topo_link_t * writer_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->out.wksp   = topo->workspaces[ topo->objs[ writer_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0 = fd_dcache_compact_chunk0( ctx->out.wksp, writer_link->dcache );
  ctx->out.wmark  = fd_dcache_compact_wmark ( ctx->out.wksp, writer_link->dcache, writer_link->mtu );
  ctx->out.chunk  = ctx->out.chunk0;

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp                   = in_wksp->wksp;;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;


  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu",
                 scratch_top - (ulong)scratch - scratch_footprint( tile ),
                 scratch_top,
                 (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST SNAPDC_BURST_MAX
#define STEM_LAZY  1e3L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapdc_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapdc_tile_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapdc = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

#undef NAME
