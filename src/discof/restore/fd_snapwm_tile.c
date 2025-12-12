#include "fd_snapwm_tile_private.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_vinyl_io_wd.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"

#define NAME "snapwm"

/* The snapwm tile is a state machine that parses and loads a full
   and optionally an incremental snapshot.  It is responsible for
   loading accounts into vinyl database. */

struct fd_blockhash_entry {
  fd_hash_t blockhash;

  struct {
    ulong prev;
    ulong next;
  } map;
};

typedef struct fd_blockhash_entry fd_blockhash_entry_t;

#define MAP_NAME                           blockhash_map
#define MAP_KEY                            blockhash
#define MAP_KEY_T                          fd_hash_t
#define MAP_ELE_T                          fd_blockhash_entry_t
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed)             (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

static inline int
should_shutdown( fd_snapwm_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN ) ) {
    FD_LOG_NOTICE(( "loaded %.1fM accounts from snapshot in %.3f seconds", (double)ctx->metrics.accounts_inserted/1e6, (double)(fd_log_wallclock()-ctx->boot_timestamp)/1e9 ));
  }
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapwm_tile_t),      sizeof(fd_snapwm_tile_t)                             );
  l = FD_LAYOUT_APPEND( l, fd_vinyl_io_wd_align(), fd_vinyl_io_wd_footprint( tile->snapwm.snapwr_depth ) );
  l = FD_LAYOUT_APPEND( l, fd_vinyl_io_mm_align(), fd_vinyl_io_mm_footprint( FD_SNAPIN_IO_SPAD_MAX     ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_snapwm_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPIN, FULL_BYTES_READ,        ctx->metrics.full_bytes_read );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );
  FD_MGAUGE_SET( SNAPIN, ACCOUNTS_INSERTED,      ctx->metrics.accounts_inserted );
  FD_MGAUGE_SET( SNAPIN, STATE, (ulong)ctx->state );
}

static void
transition_malformed( fd_snapwm_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, ctx->out_ct_idx, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static int
handle_data_frag( fd_snapwm_tile_t *  ctx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) ) {
    transition_malformed( ctx, stem );
    return 0;
  }
  else if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) {
    /* Ignore all data frags after observing an error in the stream until
       we receive fail & init control messages to restart processing. */
    return 0;
  }
  else if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
    FD_LOG_ERR(( "invalid state for data frag %d", ctx->state ));
  }

  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  fd_snapwm_process_account( ctx, chunk, sz );

  return 0;
}

static void
handle_control_frag( fd_snapwm_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig ) {
  FD_LOG_WARNING(( "*** snapwm received sig %lu", sig ));                      
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      ctx->full = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      if( sig==FD_SNAPSHOT_MSG_CTRL_INIT_INCR ) {
        fd_snapwm_vinyl_txn_begin( ctx );
      }
      fd_snapwm_vinyl_wd_init( ctx );
      break;

    case FD_SNAPSHOT_MSG_CTRL_FAIL:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;

      fd_snapwm_vinyl_wd_fini( ctx );
      if( ctx->vinyl.txn_active ) {
        fd_snapwm_vinyl_txn_cancel( ctx );
      }
      break;

    case FD_SNAPSHOT_MSG_CTRL_NEXT: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;

      fd_snapwm_vinyl_wd_fini( ctx );
      if( ctx->vinyl.txn_active ) {
        fd_snapwm_vinyl_txn_commit( ctx );
      }
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;

      fd_snapwm_vinyl_wd_fini( ctx );
      if( ctx->vinyl.txn_active ) {
        fd_snapwm_vinyl_txn_commit( ctx );
      }
      /* TODO verify_slot_deltas_with_slot_history( ctx ) */
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      fd_snapwm_vinyl_shutdown( ctx );
      break;

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      fd_snapwm_vinyl_wd_fini( ctx );
      if( ctx->vinyl.txn_active ) {
        fd_snapwm_vinyl_txn_cancel( ctx );
      }
      break;

    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }

  /* Forward the control message down the pipeline */
  fd_stem_publish( stem, ctx->out_ct_idx, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline int
returnable_frag( fd_snapwm_tile_t *  ctx,
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

  /* TODO also support FD_SNAPSHOT_HASH_MSG_EXPECTED */
  ctx->stem = stem;
  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_data_frag( ctx, chunk, sz, stem );
  else                                           handle_control_frag( ctx, stem, sig );
  ctx->stem = NULL;

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
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  return fd_snapwm_vinyl_seccomp( out_cnt, out );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_snapwm_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_snapwm_tile_t) );
  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );

  if( !tile->snapwm.lthash_disabled ) {
    FD_LOG_WARNING(( "lthash verficiation for vinyl not yet implemented" ));
    tile->snapwm.lthash_disabled = 1;
  }

  fd_snapwm_vinyl_privileged_init( ctx, topo, tile );
}

static inline fd_snapwm_out_link_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = fd_topo_find_tile_out_link( topo, tile, name, 0UL );

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_snapwm_out_link_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0, .mtu = 0 };

  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_snapwm_out_link_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX, .mtu = mtu };

  void * mem   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, mtu );
  return (fd_snapwm_out_link_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0, .mtu = mtu };
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapwm_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapwm_tile_t), sizeof(fd_snapwm_tile_t)                              );
  void *           _io_wd = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_wd_align(),    fd_vinyl_io_wd_footprint( tile->snapwm.snapwr_depth ) );
  void *           _io_mm = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_mm_align(),    fd_vinyl_io_mm_footprint( FD_SNAPIN_IO_SPAD_MAX     ) );

  ctx->full = 1;
  ctx->state = FD_SNAPSHOT_STATE_IDLE;
  ctx->lthash_disabled = tile->snapwm.lthash_disabled;

  ctx->boot_timestamp = fd_log_wallclock();

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));
  if( FD_UNLIKELY( tile->in_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1", tile->in_cnt ));

  ulong out_link_ct_idx = fd_topo_find_tile_out_link( topo, tile, "snapwm_ct", 0UL );
  if( out_link_ct_idx==ULONG_MAX ) out_link_ct_idx = fd_topo_find_tile_out_link( topo, tile, "snapwm_ls", 0UL );
  if( FD_UNLIKELY( out_link_ct_idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `" NAME "` missing required out link `snapwm_ct` or `snapwm_ls`" ));
  fd_topo_link_t * snapwm_out_link = &topo->links[ tile->out_link_id[ out_link_ct_idx ] ];
  ctx->out_ct_idx = out_link_ct_idx;

  if( 0==strcmp( snapwm_out_link->name, "snapwm_ls" ) ) {
    ctx->hash_out = out1( topo, tile, "snapwm_ls" );
  }

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  FD_TEST( 0==strcmp( in_link->name, "snapin_wm" ) );
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp                   = in_wksp->wksp;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;
  ctx->in.pos                    = 0UL;

  fd_snapwm_vinyl_unprivileged_init( ctx, topo, tile, _io_mm, _io_wd );
}

/* Control fragments can result in one extra publish to forward the
   message down the pipeline, in addition to the result / malformed
   message. Can send one duplicate account message as well. */
#define STEM_BURST 3UL /* TODO needs adjustment */

#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapwm_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapwm_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapwm = {
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
