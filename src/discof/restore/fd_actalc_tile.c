#include "fd_restore_base.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_acc_mgr.h" /* FD_ACC_SZ_MAX */
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"

#define LINK_IN_MAX 1UL
#define BURST       1UL

struct fd_actalc_tile {
  fd_solana_account_stored_meta_t acc_meta;

  /* Stream input */

  uchar const * in_base;
  uchar         in_buf[ 16 ];
  ulong         in_skip;

  /* Funk database */

  fd_funk_t    funk[1];
  fd_alloc_t * alloc;
  uint         db_full : 1;

  /* Account output */

  fd_stream_frag_meta_t * out_mcache;

  ulong out_seq_max;
  ulong out_seq;
  ulong out_cnt;
  ulong out_depth;

  /* Metrics */

  struct {
    ulong alloc_cnt;
    ulong cum_alloc_sz;
  } metrics;
};

typedef struct fd_actalc_tile fd_actalc_tile_t;

struct fd_actalc_in {
  fd_stream_frag_meta_t const * mcache;
  uint                          depth;
  uint                          idx;
  ulong                         seq;
  ulong                         goff;
  fd_stream_frag_meta_t const * mline;
  ulong volatile * restrict     fseq;
  uint                          accum[6];
};

typedef struct fd_actalc_in fd_actalc_in_t;

static ulong
scratch_align( void ) {
  return alignof(fd_actalc_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_actalc_tile_t);
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `ActAlc` tile" ));

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `FileRd` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `FileRd` has %lu outs, expected 1", tile->out_cnt ));
  /* FIXME check link names */

  fd_actalc_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_actalc_tile_t) );

  /* Join stream input */

  FD_TEST( fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ) ) );
  ctx->in_base = (uchar const *)topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->in_skip = 0UL;

  /* Join funk database */

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->actalc.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }
  ctx->alloc = fd_funk_alloc( ctx->funk );

  /* Join account output */

  ctx->out_mcache  = fd_type_pun( topo->links[ tile->out_link_id[ 0 ] ].mcache );
  ctx->out_seq_max = 0UL;
  ctx->out_seq     = 0UL;
  ctx->out_depth   = fd_mcache_depth( ctx->out_mcache->f );
}

static void
during_housekeeping( fd_actalc_tile_t * ctx ) {
  (void)ctx;
}

static void
metrics_write( fd_actalc_tile_t * ctx ) {
  (void)ctx;
}

static void
allocate_account( fd_actalc_tile_t * ctx,
                  ulong              seq,
                  ulong              acc_data_sz ) {
  (void)seq;
  if( FD_UNLIKELY( acc_data_sz > FD_ACC_SZ_MAX ) ) {
    FD_LOG_ERR(( "account data size (%lu) exceeds max (%lu) (possible memory corruption?)", acc_data_sz, FD_ACC_SZ_MAX ));
  }

  ulong rec_sz = sizeof(fd_account_meta_t)+acc_data_sz;

  void * buf = fd_alloc_malloc( ctx->alloc, 1UL, rec_sz );
  if( FD_UNLIKELY( !buf ) ) {
    FD_LOG_WARNING(( "Database full after inserting %lu records totalling %.3f GiB: fd_alloc_malloc(align=1,sz=%lu) failed",
                     ctx->metrics.alloc_cnt, (double)ctx->metrics.cum_alloc_sz/(double)(1UL<<30), rec_sz ));
    ctx->db_full = 1;
    return;
  }
  ctx->metrics.alloc_cnt++;
  ctx->metrics.cum_alloc_sz += rec_sz;
}

#include <unistd.h>

static void
on_stream_frag( fd_actalc_tile_t *            ctx,
                fd_stream_frag_meta_t const * meta ) {
  ulong const seq  = meta->seq;
  ulong const loff = meta->loff;
  ulong const sz   = meta->sz;
  ulong const ctl  = meta->ctl;
  int   const som  = fd_frag_meta_ctl_som( ctl ); /* first frag of account? */

  /* Are we already done with this account? */
  if( FD_UNLIKELY( !som && !ctx->in_skip ) ) return;

  /* Read bytes 8-16 of each account header (data_len) */
  ulong const   want_sz = 16UL;
  uchar const * frag    = ctx->in_base + loff;

  /* Unfragmented fast path */
  if( FD_LIKELY( som && sz>=want_sz ) ) {
    ulong const acc_data_sz = FD_LOAD( ulong, frag+8 );
    allocate_account( ctx, seq, acc_data_sz );
    return;
  }

  /* Slow path: Recover from fragmentation */
  if( FD_UNLIKELY( ctx->in_skip >= want_sz ) ) FD_LOG_CRIT(( "invariant violation: in_skip (%lu) > want_sz (%lu)", ctx->in_skip, want_sz ));
  ulong const chunk0  = ctx->in_skip;
  ulong const rem_sz  = want_sz-chunk0;
  ulong const read_sz = fd_ulong_min( rem_sz, sz );
  if( FD_UNLIKELY( !read_sz ) ) return;
  fd_memcpy( ctx->in_buf+chunk0, frag, read_sz );
  ctx->in_skip += read_sz;
  if( FD_LIKELY( ctx->in_skip == want_sz ) ) {
    ulong const acc_data_sz = FD_LOAD( ulong, ctx->in_buf+8 );
    allocate_account( ctx, seq, acc_data_sz );
    ctx->in_skip = 0UL;
  }
}

/* fd_actalc_in_update gets called periodically synchronize flow control
   credits back to the stream producer.  Also updates link in metrics. */

static void
fd_actalc_in_update( fd_actalc_in_t * in ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( in->fseq[0] ) = in->seq;
  FD_VOLATILE( in->fseq[1] ) = in->goff;
  FD_COMPILER_MFENCE();

  ulong volatile * metrics = fd_metrics_link_in( fd_metrics_base_tl, in->idx );

  uint * accum = in->accum;
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
fd_actalc_run1(
    fd_actalc_tile_t *         ctx,
    ulong                      in_cnt,
    fd_actalc_in_t *           in,         /* [in_cnt] */
    ulong                      out_cnt,
    fd_frag_meta_t **          out_mcache, /* [out_cnt] */
    ulong *                    out_depth,  /* [out_cnt] */
    ulong *                    out_seq,    /* [out_cnt] */
    ulong                      cons_cnt,
    ushort * restrict          event_map,  /* [1+in_cnt+cons_cnt] */
    ulong *                    cons_out,   /* [cons_cnt] */
    ulong **                   cons_fseq,  /* [cons_cnt] */
    ulong volatile ** restrict cons_slow,  /* [cons_cnt] */
    ulong * restrict           cons_seq,   /* [cons_cnt] */
    long                       lazy,
    fd_rng_t *                 rng
) {
  /* in frag stream state */
  ulong in_seq;

  /* out flow control state */
  ulong cr_avail;

  /* housekeeping state */
  ulong event_cnt;
  ulong event_seq;
  ulong async_min;

  /* performance metrics */
  ulong metric_in_backp;
  ulong metric_backp_cnt;
  ulong metric_regime_ticks[9];

  metric_in_backp  = 1UL;
  metric_backp_cnt = 0UL;
  memset( metric_regime_ticks, 0, sizeof( metric_regime_ticks ) );

  /* in frag stream init */

  in_seq = 0UL; /* First in to poll */

  ulong min_in_depth = (ulong)LONG_MAX;
  for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {
    fd_actalc_in_t * this_in = &in[ in_idx ];
    ulong depth = fd_mcache_depth( this_in->mcache->f );
    min_in_depth = fd_ulong_min( min_in_depth, depth );
  }

  /* out frag stream init */

  cr_avail = 0UL;

  ulong const burst = BURST;

  ulong cr_max = fd_ulong_if( !out_cnt, 128UL, ULONG_MAX );

  for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
    if( FD_UNLIKELY( !out_mcache[ out_idx ] ) ) FD_LOG_ERR(( "NULL out_mcache[%lu]", out_idx ));

    out_depth[ out_idx ] = fd_mcache_depth( out_mcache[ out_idx ] );
    out_seq[ out_idx ] = 0UL;

    cr_max = fd_ulong_min( cr_max, out_depth[ out_idx ] );
  }

  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    if( FD_UNLIKELY( !cons_fseq[ cons_idx ] ) ) FD_LOG_ERR(( "NULL cons_fseq[%lu]", cons_idx ));
    cons_slow[ cons_idx ] = (ulong*)(fd_metrics_link_out( fd_metrics_base_tl, cons_idx ) + FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF);
    cons_seq [ cons_idx ] = fd_fseq_query( cons_fseq[ cons_idx ] );
  }

  ulong * out_sync = fd_mcache_seq_laddr( out_mcache[0] );

  /* housekeeping init */

  // if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
  lazy = 1e3L;
  FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

  /* Initial event sequence */

  event_cnt = in_cnt + 1UL + cons_cnt;
  event_seq = 0UL;
  event_map[ event_seq++ ] = (ushort)cons_cnt;
  for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {
    event_map[ event_seq++ ] = (ushort)(in_idx+cons_cnt+1UL);
  }
  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    event_map[ event_seq++ ] = (ushort)cons_idx;
  }
  event_seq = 0UL;

  async_min = fd_tempo_async_min( lazy, event_cnt, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy %lu %lu", (ulong)lazy, event_cnt ));

  FD_LOG_INFO(( "Running snapshot parser" ));
  FD_MGAUGE_SET( TILE, STATUS, 1UL );
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* Do housekeeping at a low rate in the background */
    ulong housekeeping_ticks = 0UL;
    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      ulong event_idx = (ulong)event_map[ event_seq ];

      if( FD_LIKELY( event_idx<cons_cnt ) ) { /* cons fctl for cons cons_idx */

        /* Receive flow control credits. */
        ulong cons_idx = event_idx;
        cons_seq[ cons_idx ] = fd_fseq_query( cons_fseq[ cons_idx ] );

      } else if( FD_LIKELY( event_idx>cons_cnt ) ) { /* in fctl for in in_idx */

        /* Send flow control credits and drain flow control diagnostics. */
        ulong in_idx = event_idx - cons_cnt - 1UL;
        fd_actalc_in_update( &in[ in_idx ] );

      } else { /* event_idx==cons_cnt, housekeeping event */

        /* Send synchronization info */
        FD_COMPILER_MFENCE();
        FD_VOLATILE( out_sync[0] ) = ctx->out_seq;
        FD_VOLATILE( out_sync[1] ) = ctx->out_cnt;
        FD_COMPILER_MFENCE();

        /* Update metrics counters to external viewers */
        FD_COMPILER_MFENCE();
        FD_MGAUGE_SET( TILE, HEARTBEAT,                 (ulong)now );
        FD_MGAUGE_SET( TILE, IN_BACKPRESSURE,           metric_in_backp );
        FD_MCNT_INC  ( TILE, BACKPRESSURE_COUNT,        metric_backp_cnt );
        FD_MCNT_ENUM_COPY( TILE, REGIME_DURATION_NANOS, metric_regime_ticks );
        metrics_write( ctx );
        FD_COMPILER_MFENCE();
        metric_backp_cnt = 0UL;

        /* Receive flow control credits */
        if( FD_LIKELY( cr_avail<cr_max ) ) {
          ulong slowest_cons = ULONG_MAX;
          cr_avail = cr_max;
          for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
            ulong cons_cr_avail = (ulong)fd_long_max( (long)cr_max-fd_long_max( fd_seq_diff( out_seq[ cons_out[ cons_idx ] ], cons_seq[ cons_idx ] ), 0L ), 0L );
            slowest_cons = fd_ulong_if( cons_cr_avail<cr_avail, cons_idx, slowest_cons );
            cr_avail     = fd_ulong_min( cons_cr_avail, cr_avail );
          }
          ctx->out_seq_max = ctx->out_seq + cr_avail;

          if( FD_LIKELY( slowest_cons!=ULONG_MAX ) ) {
            FD_COMPILER_MFENCE();
            (*cons_slow[ slowest_cons ]) += metric_in_backp;
            FD_COMPILER_MFENCE();
          }
        }

        during_housekeeping( ctx );

      }

      /* Select which event to do next (randomized round robin) and
         reload the housekeeping timer. */

      event_seq++;
      if( FD_UNLIKELY( event_seq>=event_cnt ) ) {
        event_seq = 0UL;

        ulong  swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)event_cnt );
        ushort map_tmp        = event_map[ swap_idx ];
        event_map[ swap_idx ] = event_map[ 0        ];
        event_map[ 0        ] = map_tmp;

        if( FD_LIKELY( in_cnt>1UL ) ) {
          swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)in_cnt );
          fd_actalc_in_t in_tmp;
          in_tmp         = in[ swap_idx ];
          in[ swap_idx ] = in[ 0        ];
          in[ 0        ] = in_tmp;
        }
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
      long next = fd_tickcount();
      housekeeping_ticks = (ulong)(next - now);
      now = next;
    }

    /* Check if we are backpressured. */

    if( FD_UNLIKELY( ctx->db_full || cr_avail<burst ) ) {
      metric_backp_cnt += (ulong)!metric_in_backp;
      metric_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      metric_regime_ticks[2] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[5] += (ulong)(next - now);
      now = next;
      continue;
    }
    metric_in_backp = 0UL;

    /* Select which in to poll next (randomized round robin) */

    if( FD_UNLIKELY( !in_cnt ) ) {
      metric_regime_ticks[0] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[3] += (ulong)(next - now);
      now = next;
      continue;
    }

    ulong prefrag_ticks = 0UL;

    fd_actalc_in_t * this_in = &in[ in_seq ];
    in_seq++;
    if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */

    /* Check if this in has any new fragments to mux */

    ulong                         this_in_seq   = this_in->seq;
    fd_stream_frag_meta_t const * this_in_mline = this_in->mline;

    ulong seq_found = fd_frag_meta_seq_query( this_in_mline->f );

    long diff = fd_seq_diff( this_in_seq, seq_found );
    if( FD_UNLIKELY( diff ) ) {
      ulong * housekeeping_regime = &metric_regime_ticks[0];
      ulong * prefrag_regime = &metric_regime_ticks[3];
      ulong * finish_regime = &metric_regime_ticks[6];
      if( FD_UNLIKELY( diff<0L ) ) {
        this_in->seq = seq_found;
        housekeeping_regime = &metric_regime_ticks[1];
        prefrag_regime = &metric_regime_ticks[4];
        finish_regime = &metric_regime_ticks[7];
        this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF ]++;
        this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] += (uint)(-diff);
      }

      /* Don't bother with spin as polling multiple locations */
      *housekeeping_regime += housekeeping_ticks;
      *prefrag_regime += prefrag_ticks;
      long next = fd_tickcount();
      *finish_regime += (ulong)(next - now);
      now = next;
      continue;
    }

    FD_COMPILER_MFENCE();
    fd_stream_frag_meta_t meta = FD_VOLATILE_CONST( *this_in_mline );
    on_stream_frag( ctx, &meta );

    this_in->accum[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ] += (uint)meta.sz;

    ulong seq_test = fd_frag_meta_seq_query( this_in_mline->f );
    if( FD_UNLIKELY( fd_seq_ne( seq_test, seq_found ) ) ) {
      FD_LOG_ERR(( "Overrun while reading from input %lu: seq_found=%lu seq_test=%lu", in_seq, seq_found, seq_test ));
    }

    /* Windup for the next in poll and accumulate diagnostics */

    this_in_seq    = fd_seq_inc( this_in_seq, 1UL );
    this_in->seq   = this_in_seq;
    this_in->goff  = meta.goff + meta.sz;
    this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );

    this_in->accum[ FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF ]++;

    metric_regime_ticks[1] += housekeeping_ticks;
    metric_regime_ticks[4] += prefrag_ticks;
    long next = fd_tickcount();
    metric_regime_ticks[7] += (ulong)(next - now);
    now = next;
  }
}

static void
fd_actalc_run( fd_topo_t *      topo,
               fd_topo_tile_t * tile ) {
  fd_stream_frag_meta_t * in_mcache[ LINK_IN_MAX ];
  ulong *                 in_fseq  [ LINK_IN_MAX ];

  ulong polled_in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    in_mcache[ polled_in_cnt ] = fd_type_pun( topo->links[ tile->in_link_id[ i ] ].mcache );
    FD_TEST( in_mcache[ polled_in_cnt ] );
    in_fseq[ polled_in_cnt ]   = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ polled_in_cnt ] );
    polled_in_cnt += 1;
  }
  FD_TEST( polled_in_cnt<=LINK_IN_MAX );

  fd_frag_meta_t * out_mcache[ tile->out_cnt ];
  ulong            out_depth [ tile->out_cnt ];
  ulong            out_seq   [ tile->out_cnt ];
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    out_mcache[ i ] = topo->links[ tile->out_link_id[ i ] ].mcache;
    FD_TEST( out_mcache[ i ] );
    out_depth [ i ] = fd_mcache_depth( out_mcache[ i ] );
    out_seq   [ i ] = 0UL;
  }

  ulong   reliable_cons_cnt = 0UL;
  ulong   cons_out[ FD_TOPO_MAX_LINKS ];
  ulong * cons_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      for( ulong k=0UL; k<tile->out_cnt; k++ ) {
        if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
          cons_out[ reliable_cons_cnt ] = k;
          cons_fseq[ reliable_cons_cnt ] = consumer_tile->in_link_fseq[ j ];
          FD_TEST( cons_fseq[ reliable_cons_cnt ] );
          reliable_cons_cnt++;
          FD_TEST( reliable_cons_cnt<FD_TOPO_MAX_LINKS );
        }
      }
    }
  }

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 0, 0UL ) ) );

  fd_actalc_in_t polled_in[ polled_in_cnt ];
  for( ulong i=0UL; i<polled_in_cnt; i++ ) {
    fd_actalc_in_t * this_in = &polled_in[ i ];

    this_in->mcache = in_mcache[ i ];
    this_in->fseq   = in_fseq  [ i ];

    ulong depth    = fd_mcache_depth( this_in->mcache->f );
    if( FD_UNLIKELY( depth > UINT_MAX ) ) FD_LOG_ERR(( "in_mcache[%lu] too deep", i ));
    this_in->depth = (uint)depth;
    this_in->idx   = (uint)i;
    this_in->seq   = 0UL;
    this_in->goff  = 0UL;
    this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in->seq, this_in->depth );

    this_in->accum[0] = 0U; this_in->accum[1] = 0U; this_in->accum[2] = 0U;
    this_in->accum[3] = 0U; this_in->accum[4] = 0U; this_in->accum[5] = 0U;
  }

  fd_actalc_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ushort           event_map[ 1+reliable_cons_cnt ];
  ulong volatile * cons_slow[   reliable_cons_cnt ];
  ulong            cons_seq [   reliable_cons_cnt ];
  fd_actalc_run1( ctx, polled_in_cnt, polled_in, reliable_cons_cnt, out_mcache, out_depth, out_seq, reliable_cons_cnt, event_map, cons_out, cons_fseq, cons_slow, cons_seq, (ulong)10e3, rng );
}

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_snapshot_restore_ActAlc = {
  .name              = "ActAlc",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = fd_actalc_run,
};
#endif
