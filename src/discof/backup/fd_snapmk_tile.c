#define _GNU_SOURCE
#include "fd_snapmk.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../funk/fd_funk.h"
#include "../../util/pod/fd_pod.h"
#include <errno.h>
#include <fcntl.h>

/* Funk rooted record iterator (thread-safe) */

#define CHAIN_MAX (4096UL) /* ought to be enough */

struct fd_snapmk {
  fd_funk_t funk[1];

  uint state;
  fd_funk_scan_t scan[1];

  ulong out_meta_idx;
  ulong out_cnt;
  ulong out_ready; /* bit set */

  ulong in_idle_cnt;

  ulong chain;
  ulong chain1;

  fd_snapmk_batch_t * batch  [ FD_TOPO_MAX_TILE_OUT_LINKS ];
  ushort              in_kind[ FD_TOPO_MAX_TILE_IN_LINKS  ];
};
typedef struct fd_snapmk fd_snapmk_t;

#define IN_KIND_REPLAY 1

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_snapmk_t) );

  char const * out_path = "/data/r/firedancer/snapout.zst";
  int fd = open( out_path, O_CREAT|O_WRONLY|O_TRUNC, 0644 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed: %s", out_path, fd_io_strerror( errno ) ));
  }

  long dt = -fd_log_wallclock();
  fallocate( fd, 0, 0, 1UL<<32 );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "fallocate took %g sec", (double)dt/1e9 ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ctx->state = SNAPMK_STATE_IDLE;

  ulong funk_obj_id;  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ) )!=ULONG_MAX );
  ulong locks_obj_id; FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ) )!=ULONG_MAX );
  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, funk_obj_id ), fd_topo_obj_laddr( topo, locks_obj_id ) ) );

  for( ulong i=0UL; i < tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( link->name, "replay_out" ) ) {
      FD_TEST( !ctx->in_kind[ i ] );
      ctx->in_kind[ i ] = IN_KIND_REPLAY;
    } else {
      FD_LOG_ERR(( "Unexpected input link \"%s\"", link->name ));
    }
  }

  FD_TEST( tile->out_cnt >= 2 );
  FD_TEST( tile->out_cnt <= SNAPZP_TILE_MAX );
  ctx->out_cnt = tile->out_cnt - 1UL;
  for( ulong i=0UL; i < tile->out_cnt - 1; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( 0!=strcmp( link->name, "snapmk_zp" ) ) {
      FD_LOG_ERR(( "Unexpected output link \"%s\"", link->name ));
    }
    FD_TEST( link->mcache );
    ctx->batch[ i ] = link->dcache;
  }
  ctx->out_meta_idx = tile->out_cnt - 1UL;
  if( 0!=strcmp( topo->links[ tile->out_link_id[ ctx->out_meta_idx ] ].name, "snapmk_replay" ) ) {
    FD_LOG_ERR(( "Unexpected output link \"%s\"", topo->links[ tile->out_link_id[ ctx->out_meta_idx ] ].name ));
  }
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_snapmk_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

/* Output stream format
   - snapmk produces multiple independent byte streams of uncompressed
     snapshot data
   - each stream is an unterminated .tar stream (no 512-byte EOF record)
   - each stream is sent to a snapzp tile (for compression and writing)
   - output streams are chopped up into fragment sequences and sent over
     tango (mcache/dcache)
   - each frag sequence begins with ctl.som=1 and ends with ctl.eom=1
   - a frag sequence is aligned to tar stream boundaries
   - each frag carries up to 2^16 bytes data

   Output stream logic
   - uses dcache allocators
   - links are reliable
   - backpressure on each link is tracked separately
   - each produce burst can create multiple frags
   - when an output link is backpressured, switches to the next
   - links are prioritized by index (link 0 has highest priority) */

static void
update_flow_control( fd_snapmk_t *             ctx,
                     fd_stem_context_t const * stem ) {
  ulong out_ready = 0UL;
  for( ulong i=0UL; i < ctx->out_cnt; i++ ) {
    out_ready |= fd_ulong_if( !!stem->cr_avail[ i ], 1UL<<i, 0UL );
  }
  ctx->out_ready = out_ready;
}

/* check_credit is called every run loop iteration */

static void
check_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               charge_busy,
              int *               is_backpressured ) {
  (void)stem; (void)is_backpressured;
  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
    if( ctx->in_idle_cnt++ > 128 ) fd_log_sleep( (long)1e6 );
    *charge_busy = 0;
    *is_backpressured = 0;
    break;
  case SNAPMK_STATE_ACCOUNTS:
    *is_backpressured = 0;
    if( FD_UNLIKELY( !ctx->out_ready ) ) {
      update_flow_control( ctx, stem );
      if( FD_UNLIKELY( !ctx->out_ready ) ) {
        *is_backpressured = 1;
        return;
      }
    }
    break;
  }
}

/* after_credit is called if we can publish at least one frag */

static void
after_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;
  switch( ctx->state ) {
  case SNAPMK_STATE_ACCOUNTS: {
    int out_idx = fd_ulong_find_lsb( ctx->out_ready );
    ulong seq = stem->seqs[ out_idx ];
    ctx->scan->batch = ctx->batch[ out_idx ] + (seq & (stem->depths[ out_idx ]-1));
    fd_funk_scan_refill( ctx->scan, ctx->chain );
    fd_stem_publish( stem, (ulong)out_idx, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
    _Bool blocked = !stem->cr_avail[ out_idx ];
    ctx->out_ready &= blocked ? ~fd_ulong_mask_bit( out_idx ) : ULONG_MAX;
    ctx->chain += FUNK_SCAN_PARA;
    if( FD_UNLIKELY( ctx->chain >= ctx->chain1 ) ) {
      ctx->state = SNAPMK_STATE_ACCOUNTS_FLUSH;
      break;
    }
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_ACCOUNTS_FLUSH: {
    FD_COMPILER_MFENCE();
    ulong ctl = fd_frag_meta_ctl( SNAPMK_ORIG_DONE, 0, 1, 0 );
    fd_stem_publish( stem, ctx->out_meta_idx, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
    ctx->state = SNAPMK_STATE_IDLE;
    FD_LOG_NOTICE(( "Snapshot creation finished" ));
    break;
  }
  }
}

static void
snap_begin( fd_snapmk_t * ctx ) {
  if( FD_UNLIKELY( ctx->state != SNAPMK_STATE_IDLE ) ) {
    FD_LOG_ERR(( "invariant violation: snapshot creation requested state is %u", ctx->state ));
    return;
  }
  ctx->state = SNAPMK_STATE_ACCOUNTS;
  ctx->chain = 0UL;
  ctx->chain1 = fd_ulong_align_dn( fd_funk_rec_map_chain_cnt( ctx->funk->rec_map ), FUNK_SCAN_PARA );
  fd_funk_scan_init( ctx->scan, ctx->funk );
  FD_LOG_NOTICE(( "Snapshot creation started" ));
}

static int
returnable_frag( fd_snapmk_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq; (void)chunk; (void)sz; (void)ctl; (void)tsorig; (void)tspub; (void)stem;
  ctx->in_idle_cnt = 0UL;
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY:
    switch( sig ) {
    case REPLAY_SIG_SNAP_CREATE:
      snap_begin( ctx );
      break;
    default:
      break;
    }
    break;
  default:
    FD_LOG_CRIT(( "unexpected msg from link %lu with sig %lu", in_idx, sig ));
  }
  return 0;
}

static void
metrics_write( fd_snapmk_t * ctx ) {
  FD_MGAUGE_SET( SNAPMK, ACTIVE, ctx->state!=SNAPMK_STATE_IDLE );
}

#define STEM_BURST 1UL
#define STEM_LAZY  8700UL
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapmk_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapmk_t)
#define STEM_CALLBACK_CHECK_CREDIT    check_credit
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapmk = {
  .name                     = "snapmk",
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
