#include "utils/fd_ssctrl.h"
#include "utils/fd_zstd_frame.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"

#include "generated/fd_snapdc_tile_seccomp.h"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#define NAME "snapdc"

#define ZSTD_WINDOW_SZ (1UL<<25UL) /* 32MiB */

/* The snapdc tile is a state machine that decompresses the full and
   optionally incremental snapshot byte stream that it receives from the
   snapld tile.  In the event that the snapshot is already uncompressed,
   this tile simply copies the stream to the next tile in the pipeline. */

struct fd_snapdc_tile {
  uint full    : 1;
  uint is_zstd : 1;
  uint dirty   : 1;  /* in the middle of a frame? */
  int state;

  ulong tile_idx;
  ulong tile_count;
  ulong frame_idx;

  ZSTD_DCtx *      zstd;
  fd_zstd_frame_t zstd_frame[1];

  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       frag_pos;
  } in;

  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } out;

  struct {
    struct {
      ulong compressed_bytes_read;
      ulong decompressed_bytes_written;
    } full;

    struct {
      ulong compressed_bytes_read;
      ulong decompressed_bytes_written;
    } incremental;
  } metrics;
};
typedef struct fd_snapdc_tile fd_snapdc_tile_t;

FD_FN_PURE static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snapdc_tile_t), 32UL );
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
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static void
metrics_write( fd_snapdc_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPDC, FULL_COMPRESSED_BYTES_READ,              ctx->metrics.full.compressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, FULL_DECOMPRESSED_BYTES_WRITTEN,         ctx->metrics.full.decompressed_bytes_written );

  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_COMPRESSED_BYTES_READ,       ctx->metrics.incremental.compressed_bytes_read );
  FD_MGAUGE_SET( SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_WRITTEN,  ctx->metrics.incremental.decompressed_bytes_written );

  FD_MGAUGE_SET( SNAPDC, STATE,                                   (ulong)(ctx->state) );
}

static void
transition_malformed( fd_snapdc_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) return;
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline void
handle_control_frag( fd_snapdc_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig,
                     ulong               chunk,
                     ulong               sz ) {
  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_LOAD_COMPLETE ) ) return;

  /* All control messages except META reset the decompression stream */
  if( FD_UNLIKELY( sig!=FD_SNAPSHOT_MSG_META ) ) {
    ulong error = ZSTD_DCtx_reset( ctx->zstd, ZSTD_reset_session_only );
    if( FD_UNLIKELY( ZSTD_isError( error ) ) ) FD_LOG_ERR(( "ZSTD_DCtx_reset failed (%lu-%s)", error, ZSTD_getErrorName( error ) ));
  }

  if( ctx->state==FD_SNAPSHOT_STATE_ERROR && sig!=FD_SNAPSHOT_MSG_CTRL_FAIL ) {
    /* Control messages move along the snapshot load pipeline.  Since
       error conditions can be triggered by any tile in the pipeline,
       it is possible to be in error state and still receive otherwise
       valid messages.  Only a fail message can revert this. */
    return;
  };

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_META ) ) {
    /* Forward META to snapin so it can update the advertised
       slot/hash for redirect-based downloads. */
    FD_TEST( sz<=ctx->out.mtu );
    void * dst = fd_chunk_to_laddr( ctx->out.mem, ctx->out.chunk );
    fd_memcpy( dst, fd_chunk_to_laddr_const( ctx->in.mem, chunk ), sz );
    fd_stem_publish( stem, 0UL, sig, ctx->out.chunk, sz, 0UL, 0UL, 0UL );
    ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, ctx->out.mtu, ctx->out.chunk0, ctx->out.wmark );
    return;
  }

  int forward_msg = 1;

  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      FD_TEST( sz==sizeof(fd_ssctrl_init_t) );
      fd_ssctrl_init_t const * msg = fd_chunk_to_laddr_const( ctx->in.mem, chunk );
      ctx->full = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      ctx->is_zstd = !!msg->zstd;
      ctx->dirty       = 0;
      ctx->frame_idx   = 0UL;
      ctx->in.frag_pos = 0UL;
      FD_TEST( fd_zstd_frame_new( ctx->zstd_frame ) );
      if( ctx->full ) {
        ctx->metrics.full.compressed_bytes_read      = 0UL;
        ctx->metrics.full.decompressed_bytes_written = 0UL;
      } else {
        ctx->metrics.incremental.compressed_bytes_read      = 0UL;
        ctx->metrics.incremental.decompressed_bytes_written = 0UL;
      }
      fd_ssctrl_init_t * msg_out = fd_chunk_to_laddr( ctx->out.mem, ctx->out.chunk );
      fd_memcpy( msg_out, msg, sz );
      fd_stem_publish( stem, 0UL, sig, ctx->out.chunk, sz, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, ctx->out.mtu, ctx->out.chunk0, ctx->out.wmark );
      forward_msg = 0; // we forward the control message in the `fd_ssctrl_init_t` message
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FINI: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
      ctx->state = FD_SNAPSHOT_STATE_FINISHING;
      if( FD_UNLIKELY( ctx->is_zstd && ctx->dirty ) ) {
        FD_LOG_WARNING(( "encountered end-of-file in the middle of a compressed frame for %s snapshot",
                         ctx->full ? "full" : "incremental" ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_ERROR: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FAIL: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;
    }

    default: {
      FD_LOG_ERR(( "unexpected control frag %s (%lu) in state %s (%lu)",
                   fd_ssctrl_msg_ctrl_str( sig ), sig,
                   fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
      break;
    }
  }

  /* Forward the control message down the pipeline */
  if( FD_LIKELY( forward_msg ) ) {
    fd_stem_publish( stem, 0UL, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
  }
}

static inline void
finish_frame( fd_snapdc_tile_t * ctx ) {
  ctx->dirty = 0;
  ctx->frame_idx++;
  FD_TEST( fd_zstd_frame_new( ctx->zstd_frame ) );
}

/* Reads until the end of the current frame (or the end of the frag, if
   that comes earlier).  Returns 1 if bytes from the next frame remain
   and stem must reprocess this frag. */
static inline int
skip_unowned_frame( fd_snapdc_tile_t *  ctx,
                    fd_stem_context_t * stem,
                    uchar const *       data,
                    ulong               sz ) {
  FD_TEST( ctx->frame_idx%ctx->tile_count!=ctx->tile_idx );
  FD_TEST( ctx->dirty || ctx->in.frag_pos<sz );
  ctx->dirty = 1;

  ulong skipped = 0UL;
  int scan_result = fd_zstd_frame_advance( ctx->zstd_frame, data+ctx->in.frag_pos, sz-ctx->in.frag_pos, &skipped );
  switch( scan_result ) {
    case FD_ZSTD_FRAME_ERR: {
      transition_malformed( ctx, stem );
      return 0;
    }
    case FD_ZSTD_FRAME_MORE: {
      /* Current frame spans until the end of the frag, so we can move
         onto the next frag. */
      FD_TEST( skipped==sz-ctx->in.frag_pos );
      ctx->in.frag_pos = 0UL;
      return 0;
    }
    case FD_ZSTD_FRAME_END: {
      /* A frame ends within this frag.  If the frame end coincides with
         the frag end, wait for the next frag, otherwise reprocess
         the next frame in this frag. */
      FD_TEST( skipped && skipped<=sz-ctx->in.frag_pos );
      ctx->in.frag_pos += skipped;
      finish_frame( ctx );

      if( FD_UNLIKELY( ctx->in.frag_pos==sz ) ) {
        ctx->in.frag_pos = 0UL;
        return 0;
      }
      return 1;
    }
    default: FD_LOG_ERR(( "unexpected zstd frame scan result %d", scan_result ));
  }
}

/* Decompresses up to a single frame's data.  Returns 1 if the current
   frag needs to be reprocessed. */
static inline int
process_owned_frame( fd_snapdc_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     uchar const *       data,
                     ulong               sz ) {
  FD_TEST( ctx->frame_idx%ctx->tile_count==ctx->tile_idx );
  FD_TEST( ctx->dirty || ctx->in.frag_pos<sz );
  ctx->dirty = 1;

  uchar * out          = fd_chunk_to_laddr( ctx->out.mem, ctx->out.chunk );
  ulong   in_sz        = sz-ctx->in.frag_pos;
  ulong   in_consumed  = 0UL;
  ulong   out_produced = 0UL;
  ulong frame_res = ZSTD_decompressStream_simpleArgs(
      ctx->zstd,
      out,
      ctx->out.mtu,
      &out_produced,
      data+ctx->in.frag_pos,
      in_sz,
      &in_consumed );
  if( FD_UNLIKELY( ZSTD_isError( frame_res ) ) ) {
    FD_LOG_WARNING(( "error while decompressing %s snapshot (%u-%s)",
                     ctx->full ? "full" : "incremental",
                     ZSTD_getErrorCode( frame_res ), ZSTD_getErrorName( frame_res ) ));
    transition_malformed( ctx, stem );
    return 0;
  }

  ctx->in.frag_pos += in_consumed;
  FD_TEST( ctx->in.frag_pos<=sz );

  if( FD_LIKELY( ctx->full ) ) {
    ctx->metrics.full.compressed_bytes_read      += in_consumed;
    ctx->metrics.full.decompressed_bytes_written += out_produced;
  } else {
    ctx->metrics.incremental.compressed_bytes_read      += in_consumed;
    ctx->metrics.incremental.decompressed_bytes_written += out_produced;
  }

  int frame_complete = !frame_res;
  if( FD_UNLIKELY( !frame_complete && !in_consumed && !out_produced ) ) {
    if( FD_LIKELY( ctx->in.frag_pos==sz ) ) {
      /* No progress with exhausted input means zstd needs the next frag */
      ctx->in.frag_pos = 0UL;
    } else {
      /* No progress with remaining input would retry forever */
      transition_malformed( ctx, stem );
    }
    return 0;
  }

  if( FD_LIKELY( out_produced || frame_complete ) ) {
    ulong out_ctl = fd_frag_meta_ctl( 0UL, 0, frame_complete, 0 );
    fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out.chunk, out_produced, out_ctl, 0UL, 0UL );
    ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, out_produced, ctx->out.chunk0, ctx->out.wmark );
  }

  if( FD_UNLIKELY( frame_complete ) ) {
    finish_frame( ctx );

    /* If there are unconsumed bytes in the frag, reprocess the next
       frame in this frag. */
    if( FD_LIKELY( ctx->in.frag_pos<sz ) ) {
      return 1;
    }

    ctx->in.frag_pos = 0UL;
    return 0;
  }

  /* Reprocess the current frag while input remains, or when a full
     output buffer may have left decompressed bytes buffered inside
     zstd. */
  if( FD_UNLIKELY( ctx->in.frag_pos<sz || out_produced==ctx->out.mtu ) ) {
    return 1;
  }

  ctx->in.frag_pos = 0UL;
  return 0;
}

static inline int
handle_data_frag( fd_snapdc_tile_t *  ctx,
                  fd_stem_context_t * stem,
                  ulong               chunk,
                  ulong               sz ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) {
    /* Ignore all data frags after observing an error in the stream until
       we receive fail & init control messages to restart processing. */
    return 0;
  }
  if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
    FD_LOG_ERR(( "received unexpected data frag in state %s (%lu)",
                 fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
  }

  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu && sz>=ctx->in.frag_pos );
  uchar const * data = fd_chunk_to_laddr_const( ctx->in.mem, chunk );

  if( FD_UNLIKELY( !ctx->is_zstd ) ) {
    if( FD_UNLIKELY( ctx->tile_idx!=0UL ) ) return 0;
    FD_TEST( ctx->in.frag_pos<sz );
    uchar const * in  = data+ctx->in.frag_pos;
    uchar *       out = fd_chunk_to_laddr( ctx->out.mem, ctx->out.chunk );
    ulong cpy = fd_ulong_min( sz-ctx->in.frag_pos, ctx->out.mtu );
    fd_memcpy( out, in, cpy );
    fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out.chunk, cpy, 0UL, 0UL, 0UL );
    ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, cpy, ctx->out.chunk0, ctx->out.wmark );

    if( FD_LIKELY( ctx->full ) ) {
      ctx->metrics.full.compressed_bytes_read      += cpy;
      ctx->metrics.full.decompressed_bytes_written += cpy;
    } else {
      ctx->metrics.incremental.compressed_bytes_read      += cpy;
      ctx->metrics.incremental.decompressed_bytes_written += cpy;
    }

    ctx->in.frag_pos += cpy;
    FD_TEST( ctx->in.frag_pos<=sz );
    if( FD_UNLIKELY( ctx->in.frag_pos<sz ) ) return 1;
    ctx->in.frag_pos = 0UL;
    return 0;
  }

  if( ctx->frame_idx%ctx->tile_count!=ctx->tile_idx ) {
    return skip_unowned_frame( ctx, stem, data, sz );
  }

  return process_owned_frame( ctx, stem, data, sz );
}

static inline int
returnable_frag( fd_snapdc_tile_t *  ctx,
                 ulong               in_idx FD_PARAM_UNUSED,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_LIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) {
    return handle_data_frag( ctx, stem, chunk, sz );
  } else {
    handle_control_frag( ctx, stem, sig, chunk, sz );
  }

  return 0;
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_snapdc_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snapdc_tile_instr_cnt;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapdc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapdc_tile_t), sizeof(fd_snapdc_tile_t) );
  void * _zstd           = FD_SCRATCH_ALLOC_APPEND( l, 32UL,                      ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ ) );

  ctx->state      = FD_SNAPSHOT_STATE_IDLE;
  ctx->tile_idx   = tile->kind_id;
  ctx->tile_count = fd_topo_tile_name_cnt( topo, NAME );
  FD_TEST( ctx->tile_count && ctx->tile_count<=FD_SNAPDC_TILE_MAX );
  FD_TEST( ctx->tile_idx<ctx->tile_count );

  ctx->zstd = ZSTD_initStaticDStream( _zstd, ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ ) );
  FD_TEST( ctx->zstd );
  FD_TEST( ctx->zstd==_zstd );

  ctx->dirty       = 0;
  ctx->frame_idx   = 0UL;
  ctx->in.frag_pos = 0UL;
  FD_TEST( fd_zstd_frame_new( ctx->zstd_frame ) );
  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  fd_topo_link_t const * snapin_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  FD_TEST( 0==strcmp( snapin_link->name, "snapdc_in" ) );
  ctx->out.mem    = topo->workspaces[ topo->objs[ snapin_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0 = fd_dcache_compact_chunk0( ctx->out.mem, snapin_link->dcache );
  ctx->out.wmark  = fd_dcache_compact_wmark ( ctx->out.mem, snapin_link->dcache, snapin_link->mtu );
  ctx->out.chunk  = ctx->out.chunk0;
  ctx->out.mtu    = snapin_link->mtu;

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.mem                    = in_wksp->wksp;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.mem, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.mem, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu",
                 scratch_top - (ulong)scratch - scratch_footprint( tile ),
                 scratch_top,
                 (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST 1UL

#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapdc_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapdc_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapdc = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
