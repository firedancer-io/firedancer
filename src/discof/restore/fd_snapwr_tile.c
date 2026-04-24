#define _GNU_SOURCE
#include "utils/fd_ssctrl.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"

#include "../../disco/topo/fd_topo.h"

#include "generated/fd_snapwr_tile_seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define NAME "snapwr"

#define FD_SNAPWR_WRITE_BUF_SZ  (8UL<<20)   /* 8MiB */
#define FD_SNAPWR_PARTITION_SZ  (1UL<<35UL) /* 32 GiB */

struct fd_snapwr_out {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};

typedef struct fd_snapwr_out fd_snapwr_out_t;

struct fd_snapwr_tile {
  int full;
  int state;

  ulong accounts_off;
  ulong flush_off;

  uchar * write_buf;
  ulong   write_buf_used;

  ulong seed;

  fd_ssparse_t * ssparse;
  fd_ssmanifest_parser_t * manifest_parser;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       pos;
  } in;

  fd_snapwr_out_t ct_out;

  struct {
    ulong full_bytes_read;
    ulong incremental_bytes_read;
  } metrics;

  fd_snapshot_manifest_t manifest[1];
};

typedef struct fd_snapwr_tile fd_snapwr_tile_t;

static inline int
should_shutdown( fd_snapwr_tile_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return 512UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapwr_tile_t),    sizeof(fd_snapwr_tile_t)         );
  l = FD_LAYOUT_APPEND( l, fd_ssparse_align(),           fd_ssparse_footprint( 1UL<<24 )  );
  l = FD_LAYOUT_APPEND( l, fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );
  l = FD_LAYOUT_APPEND( l, 1UL,                          FD_SNAPWR_WRITE_BUF_SZ           );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
transition_malformed( fd_snapwr_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) return;
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, ctx->ct_out.idx, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static void
buffer_flush( fd_snapwr_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->write_buf_used ) ) return;

  ulong sz  = ctx->write_buf_used;
  ulong off = ctx->flush_off;
  ulong bytes_written = 0UL;
  while( bytes_written<sz ) {
    long res = pwrite( 123461, ctx->write_buf+bytes_written, sz-bytes_written, (long)(off+bytes_written) );
    if( FD_UNLIKELY( -1==res ) ) FD_LOG_ERR(( "error writing to disk (%d-%s)", errno, fd_io_strerror( errno ) ));
    bytes_written += (ulong)res;
  }
  ctx->flush_off      += sz;
  ctx->write_buf_used  = 0UL;
}

static void
buffer_write( fd_snapwr_tile_t * ctx,
              uchar const *      data,
              ulong              sz ) {
  ctx->accounts_off += sz;
  while( sz ) {
    ulong avail = FD_SNAPWR_WRITE_BUF_SZ - ctx->write_buf_used;
    ulong n     = fd_ulong_min( sz, avail );
    fd_memcpy( ctx->write_buf + ctx->write_buf_used, data, n );
    ctx->write_buf_used += n;
    data += n;
    sz   -= n;
    if( FD_UNLIKELY( ctx->write_buf_used==FD_SNAPWR_WRITE_BUF_SZ ) ) buffer_flush( ctx );
  }
}

static void
buffer_skip( fd_snapwr_tile_t * ctx,
             ulong              sz ) {
  buffer_flush( ctx );
  ctx->accounts_off += sz;
  ctx->flush_off    += sz;
}

static void
process_account_header( fd_snapwr_tile_t *            ctx,
                        fd_ssparse_advance_result_t * result ) {
  /* Ensure header+data does not cross a partition boundary.  If it
     would, pad with zeros so the account starts at the next one. */
  ulong account_sz    = 68UL + (ulong)result->account_header.data_len;
  ulong cur_boundary  = ctx->accounts_off / FD_SNAPWR_PARTITION_SZ;
  ulong end_boundary  = (ctx->accounts_off + account_sz - 1UL) / FD_SNAPWR_PARTITION_SZ;
  if( FD_UNLIKELY( cur_boundary!=end_boundary ) ) {
    ulong next = (cur_boundary + 1UL) * FD_SNAPWR_PARTITION_SZ;
    buffer_skip( ctx, next - ctx->accounts_off );
  }

  uchar data[ 68UL ];
  fd_memcpy( data, result->account_header.pubkey, 32UL );
  fd_memcpy( data+32UL, &result->account_header.data_len, 4UL );
  fd_memcpy( data+36UL, result->account_header.owner, 32UL );
  buffer_write( ctx, data, 68UL );
}

static void
process_account_data( fd_snapwr_tile_t *            ctx,
                      fd_ssparse_advance_result_t * result ) {
  buffer_write( ctx, result->account_data.data, result->account_data.data_sz );
}

static int
handle_data_frag( fd_snapwr_tile_t *  ctx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) ) {
    FD_LOG_WARNING(( "received unexpected data frag while in state %s (%lu)",
                     fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state  ));
    transition_malformed( ctx, stem );
    return 0;
  }
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) {
    /* Ignore all data frags after observing an error in the stream until
       we receive fail & init control messages to restart processing. */
    return 0;
  }
  if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
    FD_LOG_ERR(( "received data frag during invalid state %s (%lu)",
                 fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
  }

  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  for(;;) {
    if( FD_UNLIKELY( sz-ctx->in.pos==0UL ) ) break;

    uchar const * data = (uchar const *)fd_chunk_to_laddr_const( ctx->in.wksp, chunk ) + ctx->in.pos;

    fd_ssparse_advance_result_t result[1];
    int res = fd_ssparse_advance( ctx->ssparse, data, sz-ctx->in.pos, result );
    switch( res ) {
      case FD_SSPARSE_ADVANCE_ERROR:
        FD_LOG_WARNING(( "error while parsing snapshot stream" ));
        transition_malformed( ctx, stem );
        return 0;
      case FD_SSPARSE_ADVANCE_AGAIN:
        break;
      case FD_SSPARSE_ADVANCE_MANIFEST: {
        int res = fd_ssmanifest_parser_consume( ctx->manifest_parser,
                                                result->manifest.data,
                                                result->manifest.data_sz,
                                                result->manifest.acc_vec_map,
                                                result->manifest.acc_vec_pool );
        if( FD_UNLIKELY( res==FD_SSMANIFEST_PARSER_ADVANCE_ERROR ) ) {
          FD_LOG_WARNING(( "error while parsing snapshot manifest" ));
          transition_malformed( ctx, stem );
          return 0;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_STATUS_CACHE:
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER:
        process_account_header( ctx, result );
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
        process_account_data( ctx, result );
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_BATCH:
        FD_TEST( 0 );
        break;
      case FD_SSPARSE_ADVANCE_DONE:
        buffer_flush( ctx );
        ctx->state = FD_SNAPSHOT_STATE_FINISHING;
        break;
      default:
        FD_LOG_ERR(( "unexpected fd_ssparse_advance result %d", res ));
        break;
    }

    ctx->in.pos += result->bytes_consumed;
    if( FD_LIKELY( ctx->full ) ) ctx->metrics.full_bytes_read        += result->bytes_consumed;
    else                         ctx->metrics.incremental_bytes_read += result->bytes_consumed;
  }

  int reprocess_frag = ctx->in.pos<sz;
  if( FD_LIKELY( !reprocess_frag ) ) ctx->in.pos = 0UL;
  return reprocess_frag;
}

static void
handle_control_frag( fd_snapwr_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig ) {
  if( ctx->state==FD_SNAPSHOT_STATE_ERROR && sig!=FD_SNAPSHOT_MSG_CTRL_FAIL ) {
    /* Control messages move along the snapshot load pipeline.  Since
       error conditions can be triggered by any tile in the pipeline,
       it is possible to be in error state and still receive otherwise
       valid messages.  Only a fail message can revert this. */
    return;
  };

  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      ctx->full = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      fd_ssparse_reset( ctx->ssparse );
      fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );

      if( sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL ) {
        ctx->metrics.full_bytes_read        = 0UL;
        ctx->metrics.incremental_bytes_read = 0UL;
      } else {
        ctx->metrics.incremental_bytes_read = 0UL;
      }
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_FINI: {
      /* This is a special case: handle_data_frag must have already
         processed FD_SSPARSE_ADVANCE_DONE and moved the state into
         FD_SNAPSHOT_STATE_FINISHING. */
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_FINISHING;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      break;
    }

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
      FD_LOG_ERR((( "TODO: UNIMPLEMENTED: snapshot load failure handling (TODO: reset accdb to last known good state, etc)" )));
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

  fd_stem_publish( stem, ctx->ct_out.idx, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline int
returnable_frag( fd_snapwr_tile_t *  ctx,
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

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_data_frag( ctx, chunk, sz, stem );
  else                                           handle_control_frag( ctx, stem, sig );

  return 0;
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "invalid out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }
  out_fds[ out_cnt++ ] = 123461; /* accounts db */

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;

  populate_sock_filter_policy_fd_snapwr_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)123461 );
  return sock_filter_policy_fd_snapwr_tile_instr_cnt;
}

static inline fd_snapwr_out_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = fd_topo_find_tile_out_link( topo, tile, name, 0UL );

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_snapwr_out_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0, .mtu = 0 };

  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_snapwr_out_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX, .mtu = mtu };

  void * mem   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, mtu );
  return (fd_snapwr_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0, .mtu = mtu };
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_snapwr_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapwr_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapwr_tile_t),    sizeof(fd_snapwr_tile_t)          );
  void * _ssparse         = FD_SCRATCH_ALLOC_APPEND( l, fd_ssparse_align(),           fd_ssparse_footprint( 1UL<<24UL ) );
  void * _manifest_parser = FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint()  );
  void * _write_buf       = FD_SCRATCH_ALLOC_APPEND( l, 1UL,                          FD_SNAPWR_WRITE_BUF_SZ            );

  ctx->full = 1;
  ctx->state = FD_SNAPSHOT_STATE_IDLE;

  ctx->accounts_off    = 0UL;
  ctx->flush_off       = 0UL;
  ctx->write_buf       = _write_buf;
  ctx->write_buf_used  = 0UL;

  ctx->ssparse = fd_ssparse_new( _ssparse, 1UL<<24UL, ctx->seed );
  FD_TEST( ctx->ssparse );
  fd_ssparse_batch_enable( ctx->ssparse, 0 );

  ctx->manifest_parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( _manifest_parser ) );
  FD_TEST( ctx->manifest_parser );

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->in_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1", tile->in_cnt ));
  ctx->ct_out = out1( topo, tile, "snapwr_ct" );
  if( FD_UNLIKELY( ctx->ct_out.idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `" NAME "` missing required out link `snapin_ct`" ));

  fd_ssparse_reset( ctx->ssparse );
  fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  FD_TEST( 0==strcmp( in_link->name, "snapdc_in" ) );
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp   = in_wksp->wksp;
  ctx->in.chunk0 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu    = in_link->mtu;
  ctx->in.pos    = 0UL;
}

#define STEM_BURST 1UL

#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapwr_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapwr_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapwr = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
