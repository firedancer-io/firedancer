#include "utils/fd_ssctrl.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#define NAME "snapdc"

#define ZSTD_WINDOW_SZ (1UL<<25UL) /* 32MiB */

/* The snapdc tile is a state machine that decompresses the full and
   optionally incremental snapshot byte stream that it receives from the
   snaprd tile.

   snaprd may send a reset notification, which causes snapdc to reset
   its decompressor state to waiting for either the full or incremental
   snapshot respectively. */

#define FD_SNAPDC_STATE_DECOMPRESSING (0) /* We are in the process of decompressing a valid stream */
#define FD_SNAPDC_STATE_FINISHING     (1) /* The frame has been fully decompressed, we are waiting to make sure the snapshot has no more data */
#define FD_SNAPDC_STATE_MALFORMED     (2) /* The decompression stream is malformed, we are waiting for a reset notification */
#define FD_SNAPDC_STATE_DONE          (3) /* The decompression stream is done, the tile is waiting for a shutdown message */
#define FD_SNAPDC_STATE_SHUTDOWN      (4) /* The tile is done, been told to shut down, and has likely already exited */

struct fd_snapdc_tile {
  int full;
  int state;

  ZSTD_DCtx * zstd;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       frag_pos;
  } in;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } out;

  struct {
    struct {
      ulong compressed_bytes_read;
      ulong decompressed_bytes_read;
    } full;

    struct {
      ulong compressed_bytes_read;
      ulong decompressed_bytes_read;
    } incremental;
  } metrics;
};
typedef struct fd_snapdc_tile fd_snapdc_tile_t;

FD_FN_PURE static ulong
scratch_align( void ) {
  return alignof(fd_snapdc_tile_t);
}

FD_FN_PURE static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapdc_tile_t), sizeof(fd_snapdc_tile_t)                   );
  l = FD_LAYOUT_APPEND( l, 32UL,                      ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline int
should_shutdown( fd_snapdc_tile_t * ctx ) {
  return ctx->state==FD_SNAPDC_STATE_SHUTDOWN;
}

static void
metrics_write( fd_snapdc_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPDC, FULL_COMPRESSED_BYTES_READ,    ctx->metrics.full.compressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, FULL_DECOMPRESSED_BYTES_READ,  ctx->metrics.full.decompressed_bytes_read );

  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_COMPRESSED_BYTES_READ,    ctx->metrics.incremental.compressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_READ,  ctx->metrics.incremental.decompressed_bytes_read );

  FD_MGAUGE_SET( SNAPDC, STATE, (ulong)(ctx->state) );
}

static inline void
transition_malformed( fd_snapdc_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPDC_STATE_MALFORMED;
  ctx->in.frag_pos = 0UL;
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_MALFORMED, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline void
handle_control_frag( fd_snapdc_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig ) {
  /* 1. Pass the control message downstream to the next consumer. */
  fd_stem_publish( stem, 0UL, sig, ctx->out.chunk, 0UL, 0UL, 0UL, 0UL );
  ulong error = ZSTD_DCtx_reset( ctx->zstd, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( error ) ) ) FD_LOG_ERR(( "ZSTD_DCtx_reset failed (%lu-%s)", error, ZSTD_getErrorName( error ) ));

  /* 2. Check if the control message is actually valid given the state
        machine, and if not, return a malformed message to the sender. */
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_RESET_FULL:
      ctx->state = FD_SNAPDC_STATE_DECOMPRESSING;
      ctx->full = 1;
      ctx->metrics.full.compressed_bytes_read   = 0UL;
      ctx->metrics.full.decompressed_bytes_read = 0UL;
      ctx->metrics.incremental.compressed_bytes_read   = 0UL;
      ctx->metrics.incremental.decompressed_bytes_read = 0UL;
      break;
    case FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL:
      ctx->state = FD_SNAPDC_STATE_DECOMPRESSING;
      ctx->full = 0;
      ctx->metrics.full.compressed_bytes_read   = 0UL;
      ctx->metrics.full.decompressed_bytes_read = 0UL;
      ctx->metrics.incremental.compressed_bytes_read   = 0UL;
      ctx->metrics.incremental.decompressed_bytes_read = 0UL;
      break;
    case FD_SNAPSHOT_MSG_CTRL_EOF_FULL:
      FD_TEST( ctx->full );
      if( FD_UNLIKELY( ctx->state==FD_SNAPDC_STATE_MALFORMED ) ) break;
      else if( FD_UNLIKELY( ctx->state==FD_SNAPDC_STATE_DECOMPRESSING ) ) {
        transition_malformed( ctx, stem );
        break;
      }
      ctx->state = FD_SNAPDC_STATE_DECOMPRESSING;
      ctx->full = 0;
      break;
    case FD_SNAPSHOT_MSG_CTRL_DONE:
      if( FD_UNLIKELY( ctx->state==FD_SNAPDC_STATE_MALFORMED ) ) break;
      else if( FD_UNLIKELY( ctx->state==FD_SNAPDC_STATE_DECOMPRESSING ) ) {
        transition_malformed( ctx, stem );
        break;
      }
      ctx->state = FD_SNAPDC_STATE_DONE;
      break;
    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_TEST( ctx->state==FD_SNAPDC_STATE_DONE );
      ctx->state = FD_SNAPDC_STATE_SHUTDOWN;
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      break;
    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }

  /* 3. Acknowledge the control message, so the sender knows we received
        it.  We must acknowledge after handling the control frag, because
        if it causes us to generate a malformed transition, that must be
        sent back to the snaprd controller before the acknowledgement. */
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_ACK, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline int
handle_data_frag( fd_snapdc_tile_t *  ctx,
                  fd_stem_context_t * stem,
                  ulong               chunk,
                  ulong               sz ) {
  FD_TEST( ctx->state!=FD_SNAPDC_STATE_DONE );

  if( FD_UNLIKELY( ctx->state==FD_SNAPDC_STATE_MALFORMED ) ) return 0;

  if( FD_UNLIKELY( ctx->state==FD_SNAPDC_STATE_FINISHING ) ) {
    /* We thought the snapshot was finished (we already read the full
       frame) and then we got another data fragment from the reader.
       This means the snapshot has extra padding or garbage on the end,
       which we don't trust so just abandon it completely. */
    transition_malformed( ctx, stem );
    return 0;
  }

  FD_TEST( ctx->state==FD_SNAPDC_STATE_DECOMPRESSING );
  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu && sz>=ctx->in.frag_pos );

  uchar const * data = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

  uchar const * in  = data+ctx->in.frag_pos;
  uchar * out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
  ulong in_consumed = 0UL, out_produced = 0UL;
  ulong error = ZSTD_decompressStream_simpleArgs( ctx->zstd,
                                                  out,
                                                  ctx->out.mtu,
                                                  &out_produced,
                                                  in,
                                                  sz-ctx->in.frag_pos,
                                                  &in_consumed );
  if( FD_UNLIKELY( ZSTD_isError( error ) ) ) {
    transition_malformed( ctx, stem );
    return 0;
  }

  if( FD_LIKELY( out_produced ) ) {
    fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out.chunk, out_produced, 0UL, 0UL, 0UL );
    ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, out_produced, ctx->out.chunk0, ctx->out.wmark );
  }

  ctx->in.frag_pos += in_consumed;
  FD_TEST( ctx->in.frag_pos<=sz );

  if( FD_LIKELY( ctx->full ) ) {
    ctx->metrics.full.compressed_bytes_read   += in_consumed;
    ctx->metrics.full.decompressed_bytes_read += out_produced;
  } else {
    ctx->metrics.incremental.compressed_bytes_read   += in_consumed;
    ctx->metrics.incremental.decompressed_bytes_read += out_produced;
  }

  if( FD_UNLIKELY( !error ) ) {
    if( FD_UNLIKELY( ctx->in.frag_pos!=sz ) ) {
      /* Zstandard finished decoding the snapshot frame (the whole
         snapshot is a single frame), but, the fragment we got from
         the snapshot reader has not been fully consumed, so there is
         some trailing padding or garbage at the end of the snapshot.

         This is not valid under the snapshot format and indicates a
         problem so we abandon the snapshot. */
      transition_malformed( ctx, stem );
      return 0;
    }

    ctx->state = FD_SNAPDC_STATE_FINISHING;
  }

  int maybe_more_output = out_produced==ctx->out.mtu || ctx->in.frag_pos<sz;
  if( FD_LIKELY( !maybe_more_output ) ) ctx->in.frag_pos = 0UL;
  return maybe_more_output;
}

static inline int
returnable_frag( fd_snapdc_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  FD_TEST( ctx->state!=FD_SNAPDC_STATE_SHUTDOWN );

  if( FD_LIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_data_frag( ctx, stem, chunk, sz );
  else                                                handle_control_frag( ctx,stem, sig );

  return 0;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapdc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapdc_tile_t), sizeof(fd_snapdc_tile_t) );
  void * _zstd           = FD_SCRATCH_ALLOC_APPEND( l, 32UL,                      ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ ) );

  ctx->full = 1;
  ctx->state = FD_SNAPDC_STATE_DECOMPRESSING;
  ctx->zstd = ZSTD_initStaticDStream( _zstd, ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ ) );
  FD_TEST( ctx->zstd );
  FD_TEST( ctx->zstd==_zstd );

  ctx->in.frag_pos = 0UL;
  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=2UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2", tile->out_cnt ));

  fd_topo_link_t * writer_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->out.wksp   = topo->workspaces[ topo->objs[ writer_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0 = fd_dcache_compact_chunk0( ctx->out.wksp, writer_link->dcache );
  ctx->out.wmark  = fd_dcache_compact_wmark ( ctx->out.wksp, writer_link->dcache, writer_link->mtu );
  ctx->out.chunk  = ctx->out.chunk0;
  ctx->out.mtu    = writer_link->mtu;

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

#define STEM_BURST 3UL /* For control fragments, one downstream clone, one acknowledgement, and one malformed message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapdc_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapdc_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapdc = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

#undef NAME
