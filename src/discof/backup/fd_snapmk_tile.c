#include "fd_snapmk.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../funk/fd_funk.h"
#include "../../util/pod/fd_pod.h"
#include "fd_funk_scan.h"
//#include "../../util/archive/fd_tar.h"

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

  struct {
    ulong accounts_processed;
  } metrics;

  ushort in_kind[ FD_TOPO_MAX_TILE_IN_LINKS  ];
};
typedef struct fd_snapmk fd_snapmk_t;

#define IN_KIND_REPLAY 1

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_snapmk_t) );
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

static inline void
fd_mcache_publish_if( fd_frag_meta_t * mcache,
                      ulong            depth,
                      ulong            seq,
                      ulong            sig,
                      ulong            chunk,
                      ulong            sz,
                      ulong            ctl,
                      ulong            tsorig,
                      ulong            tspub,
                      _Bool            pub ) {
  fd_frag_meta_t * meta_dst = mcache + fd_mcache_line_idx( seq, depth );
  fd_frag_meta_t dummy[1];
  fd_frag_meta_t * meta = pub ? meta_dst : dummy;
  __m256i meta_avx = fd_frag_meta_avx( seq, sig, chunk, sz, ctl, tsorig, tspub );
  FD_VOLATILE( meta->avx ) = meta_avx;
}

__attribute__((noinline)) static void
send_account_frags( fd_snapmk_t *       ctx,
                    fd_stem_context_t * stem ) {
  int out_idx = fd_ulong_find_lsb( ctx->out_ready );
  ulong burst_max = stem->cr_avail[ out_idx ];
  if( FD_UNLIKELY( burst_max<FUNK_SCAN_PARA ) ) {
    ctx->out_ready = fd_ulong_clear_bit( ctx->out_ready, out_idx );
    return;
  };
  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong depth = stem->depths[ out_idx ];
  ulong seq = stem->seqs[ out_idx ];
  ulong * cr_availp = &stem->cr_avail[ out_idx ];
  ulong pub_cnt = 0UL;
  ulong seqa[ FUNK_SCAN_PARA ];
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ){
    _Bool skip = ctx->scan->val_gaddr[ i ]==ULONG_MAX;
    seqa[ i ] = seq;
    seq = fd_seq_inc( seq, !skip );
    pub_cnt += !skip;
  }
  ulong ctl = fd_frag_meta_ctl( SNAPMK_ORIG_ACCOUNT, 0, 0, 0 );
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ){
    _Bool skip = ctx->scan->val_gaddr[ i ]==ULONG_MAX;
    ulong rec_idx   = ctx->scan->rec_idx  [ i ];
    ulong val_gaddr = ctx->scan->val_gaddr[ i ];
    uint  data_sz   = ctx->scan->data_sz  [ i ];

    /* Send frag */
    fd_mcache_publish_if( mcache, depth, seqa[ i ], val_gaddr, 0UL, 0UL, ctl, rec_idx, data_sz, !skip );
  }
  *cr_availp -= pub_cnt;
  *stem->min_cr_avail = fd_ulong_min( *cr_availp, *stem->min_cr_avail );
  stem->seqs[ out_idx ] = seq;
  ctx->metrics.accounts_processed += pub_cnt;
}

/* after_credit is called if we can publish at least one frag */

static void
after_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;
  switch( ctx->state ) {
  case SNAPMK_STATE_ACCOUNTS:
    fd_funk_scan_refill( ctx->scan );
    if( FD_UNLIKELY( ctx->scan->batch_idx >= ctx->scan->batch_cnt ) ) {
      ctx->state = SNAPMK_STATE_ACCOUNTS_FLUSH;
      FD_LOG_NOTICE(( "DONE" ));
      break;
    }
    ctx->scan->batch_idx = FUNK_SCAN_PARA;
    send_account_frags( ctx, stem );
    *charge_busy = 1;
    break;
  case SNAPMK_STATE_ACCOUNTS_FLUSH: {
    FD_COMPILER_MFENCE();
    ulong ctl = fd_frag_meta_ctl( SNAPMK_ORIG_DONE, 0, 1, 0 );
    fd_stem_publish( stem, ctx->out_meta_idx, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
    ctx->state = SNAPMK_STATE_IDLE;
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
  fd_funk_scan_init( ctx->scan, ctx->funk, 0UL, ULONG_MAX );
  FD_LOG_NOTICE(( "START" ));
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
  FD_MGAUGE_SET( SNAPMK, ACTIVE,             ctx->state!=SNAPMK_STATE_IDLE );
  FD_MCNT_SET  ( SNAPMK, ACCOUNTS_PROCESSED, ctx->metrics.accounts_processed );
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
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
