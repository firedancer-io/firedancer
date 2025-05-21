#include "fd_restore_base.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>

#define NAME "FileRd"

struct fd_filerd_tile {
  int fd;

  uchar * buf; /* dcache */
  ulong   buf_off;
  ulong   buf_sz;
  ulong   goff;
};

typedef struct fd_filerd_tile fd_filerd_tile_t;

static ulong
scratch_align( void ) {
  return alignof(fd_filerd_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_filerd_tile_t);
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_filerd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_memset( ctx, 0, sizeof(fd_filerd_tile_t) );

  if( FD_UNLIKELY( tile->in_cnt !=0UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 0",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  ctx->fd = open( tile->filerd.file_path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( ctx->fd<0 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_filerd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  void * out_dcache = fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ) );
  FD_TEST( out_dcache );

  ctx->buf     = out_dcache;
  ctx->buf_off = 0UL;
  ctx->buf_sz  = fd_dcache_data_sz( out_dcache );
  ctx->goff    = 0UL;
}

static void
during_housekeeping( fd_filerd_tile_t * ctx ) {
  (void)ctx;
}

static void
metrics_write( fd_filerd_tile_t * ctx ) {
  (void)ctx;
}

static void
close_file( fd_filerd_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->fd<0 ) ) return;
  if( FD_UNLIKELY( close( ctx->fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->fd = -1;
}

static void
after_credit( fd_filerd_tile_t *      ctx,
              fd_frag_stream_meta_t * out_mcache,
              ulong const             out_depth,
              ulong * restrict        out_seq,
              ulong * restrict        cr_frag_avail,
              ulong * restrict        cr_byte_avail,
              int * restrict          charge_busy_after ) {
  /* Assumes *cr_frag_avail>=2 */

  int fd = ctx->fd;
  if( FD_UNLIKELY( fd<0 ) ) return;

  if( FD_UNLIKELY( ctx->buf_off >= ctx->buf_sz ) ) {
    FD_LOG_CRIT(( "Buffer overflow (buf_off=%lu buf_sz=%lu)", ctx->buf_off, ctx->buf_sz ));
  }

  ulong const iov0_sz = fd_ulong_min( *cr_byte_avail, ctx->buf_sz - ctx->buf_off );
  struct iovec iov[2];
  iov[ 0 ].iov_base = ctx->buf + ctx->buf_off;
  iov[ 0 ].iov_len  = iov0_sz;
  iov[ 1 ].iov_base = ctx->buf;
  iov[ 1 ].iov_len  = fd_ulong_min( (ulong)fd_long_max( 0L, (long)*cr_byte_avail-(long)iov0_sz ), ctx->buf_off );

  long res = readv( fd, iov, 2 );
  if( FD_UNLIKELY( res<=0L ) ) {
    if( FD_UNLIKELY( res==0 ) ) {
      FD_LOG_INFO(( "Reached end of file" ));
      close_file( ctx );
      return;
    }
    if( FD_LIKELY( errno==EAGAIN ) ) return;
    FD_LOG_ERR(( "readv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    /* aborts app */
  }

  ulong sz = (ulong)res;
  cr_byte_avail[0] -= sz;
  *charge_busy_after = 1;

  ulong frag0_sz = fd_ulong_min( iov0_sz, sz );
  ulong frag1_sz = (ulong)res - frag0_sz;

  fd_mcache_publish_stream( out_mcache, out_depth, out_seq[0], ctx->goff, ctx->buf_off, frag0_sz );
  out_seq[0] = fd_seq_inc( out_seq[0], 1UL );
  cr_frag_avail[0]--;
  ctx->goff    += frag0_sz;
  ctx->buf_off += frag0_sz;
  if( ctx->buf_off >= ctx->buf_sz ) ctx->buf_off = 0UL; /* cmov */

  if( FD_UNLIKELY( frag1_sz ) ) {
    fd_mcache_publish_stream( out_mcache, out_depth, out_seq[0], ctx->goff, 0UL, frag1_sz );
    out_seq[0] = fd_seq_inc( out_seq[0], 1UL );
    cr_frag_avail[0]--;
    ctx->goff    += frag1_sz;
    ctx->buf_off += frag1_sz;
  }
}

/* run/run1 are a custom run loop based on fd_stem.c. */

__attribute__((noinline)) static void
fd_filerd_run1(
    fd_filerd_tile_t *         ctx,
    fd_frag_stream_meta_t *    out_mcache,
    void *                     out_dcache,
    ulong                      cons_cnt,
    ushort * restrict          event_map, /* cnt=1+cons_cnt */
    ulong ** restrict          cons_fseq, /* cnt=  cons_cnt  points to each consumer's fseq */
    ulong volatile ** restrict cons_slow, /* cnt=  cons_cnt  points to 'slow' metrics */
    ulong * restrict           cons_seq,  /* cnt=2*cons_cnt  cache of recent fseq observations */
    long                       lazy,
    fd_rng_t *                 rng
) {

  /* out flow control state */
  ulong    cr_byte_avail;  /* byte burst quota */
  ulong    cr_frag_avail;  /* frag burst quota */

  /* housekeeping state */
  ulong    event_cnt;
  ulong    event_seq;
  ulong    async_min; /* min number of ticks between a housekeeping event */

  /* performance metrics */
  ulong metric_in_backp;
  ulong metric_backp_cnt;
  ulong metric_regime_ticks[9];

  metric_in_backp  = 1UL;
  metric_backp_cnt = 0UL;
  memset( metric_regime_ticks, 0, sizeof( metric_regime_ticks ) );

  /* out frag stream init */

  cr_byte_avail = 0UL;
  cr_frag_avail = 0UL;

  ulong const out_depth = fd_mcache_depth( out_mcache->f );
  ulong       out_seq   = 0UL;

  ulong const out_bufsz = fd_dcache_data_sz( out_dcache );

  ulong const cr_byte_max = out_bufsz;
  ulong const cr_frag_max = out_depth;

  ulong const burst_byte = 512UL; /* don't producing frags smaller than this */
  ulong const burst_frag =   2UL;

  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    if( FD_UNLIKELY( !cons_fseq[ cons_idx ] ) ) FD_LOG_ERR(( "NULL cons_fseq[%lu]", cons_idx ));
    cons_slow[ cons_idx     ] = fd_metrics_link_out( fd_metrics_base_tl, cons_idx ) + FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF;
    cons_seq [ 2*cons_idx   ] = FD_VOLATILE_CONST( cons_fseq[ cons_idx ][0] );
    cons_seq [ 2*cons_idx+1 ] = FD_VOLATILE_CONST( cons_fseq[ cons_idx ][1] );
  }

  /* housekeeping init */

  if( lazy<=0L ) lazy = fd_tempo_lazy_default( out_depth );
  FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

  /* Initial event sequence */

  event_cnt = 1UL + cons_cnt;
  event_map[ 0 ] = (ushort)cons_cnt;
  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    event_map[ 1+cons_idx ] = (ushort)cons_idx;
  }
  event_seq = 0UL;

  async_min = fd_tempo_async_min( lazy, event_cnt, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy %lu %lu", (ulong)lazy, event_cnt ));

  FD_LOG_INFO(( "Running file reader" ));
  FD_MGAUGE_SET( TILE, STATUS, 1UL );
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* Do housekeeping at a low rate in the background */
    ulong housekeeping_ticks = 0UL;
    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      ulong event_idx = (ulong)event_map[ event_seq ];

      if( FD_LIKELY( event_idx<cons_cnt ) ) {
        ulong cons_idx = event_idx;

        /* Receive flow control credits from this out. */
        FD_COMPILER_MFENCE();
        cons_seq[ 2*cons_idx   ] = FD_VOLATILE_CONST( cons_fseq[ cons_idx ][0] );
        cons_seq[ 2*cons_idx+1 ] = FD_VOLATILE_CONST( cons_fseq[ cons_idx ][1] );
        FD_COMPILER_MFENCE();

      } else { /* event_idx==cons_cnt, housekeeping event */

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
        if( FD_LIKELY( cr_byte_avail<cr_byte_max || cr_frag_avail<cr_frag_max ) ) {
          ulong slowest_cons = ULONG_MAX;
          cr_frag_avail = cr_frag_max;
          cr_byte_avail = cr_byte_max;
          for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
            ulong cons_cr_frag_avail = (ulong)fd_long_max( (long)cr_frag_max-fd_long_max( fd_seq_diff( out_seq,   cons_seq[ 2*cons_idx   ] ), 0L ), 0L );
            ulong cons_cr_byte_avail = (ulong)fd_long_max( (long)cr_byte_max-fd_long_max( fd_seq_diff( ctx->goff, cons_seq[ 2*cons_idx+1 ] ), 0L ), 0L );
            slowest_cons  = fd_ulong_if( cons_cr_byte_avail<cr_byte_avail, cons_idx, slowest_cons );
            cr_frag_avail = fd_ulong_min( cons_cr_frag_avail, cr_frag_avail );
            cr_byte_avail = fd_ulong_min( cons_cr_byte_avail, cr_byte_avail );
          }

          if( FD_LIKELY( slowest_cons!=ULONG_MAX ) ) {
            FD_COMPILER_MFENCE();
            (*cons_slow[ slowest_cons ]) += metric_in_backp;
            FD_COMPILER_MFENCE();
          }
        }

        during_housekeeping( ctx );
      }

      event_seq++;
      if( FD_UNLIKELY( event_seq>=event_cnt ) ) {
        event_seq = 0UL;
        ulong  swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)event_cnt );
        ushort map_tmp        = event_map[ swap_idx ];
        event_map[ swap_idx ] = event_map[ 0        ];
        event_map[ 0        ] = map_tmp;
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
      long next = fd_tickcount();
      housekeeping_ticks = (ulong)(next - now);
      now = next;
    }

    /* Check if we are backpressured. */

    if( FD_UNLIKELY( cr_byte_avail<burst_byte || cr_frag_avail<burst_frag ) ) {
      metric_backp_cnt += (ulong)!metric_in_backp;
      metric_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      metric_regime_ticks[2] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[5] += (ulong)(next - now);
      now = next;
      continue;
    }

    int charge_busy_after = 0;
    after_credit( ctx, out_mcache, out_depth, &out_seq, &cr_frag_avail, &cr_byte_avail, &charge_busy_after );

    metric_regime_ticks[1] += housekeeping_ticks;
    long next = fd_tickcount();
    metric_regime_ticks[4] += (ulong)(next - now);
    now = next;
    continue;
  }
}

static void
fd_filerd_run( fd_topo_t *        topo,
               fd_topo_tile_t *   tile ) {
  fd_frag_stream_meta_t * out_mcache = fd_type_pun( topo->links[ tile->out_link_id[ 0 ] ].mcache );
  FD_TEST( out_mcache );

  ulong   reliable_cons_cnt = 0UL;
  ulong * cons_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[0] && consumer_tile->in_link_reliable[ j ] ) ) {
        cons_fseq[ reliable_cons_cnt ] = consumer_tile->in_link_fseq[ j ];
        FD_TEST( cons_fseq[ reliable_cons_cnt ] );
        reliable_cons_cnt++;
        FD_TEST( reliable_cons_cnt<FD_TOPO_MAX_LINKS );
      }
    }
  }

  /* FIXME rng seed should not be zero */
  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 0, 0UL ) ) );

  fd_filerd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ushort           event_map[ 1+reliable_cons_cnt ];
  ulong volatile * cons_slow[   reliable_cons_cnt ];
  ulong            cons_seq [ 2*reliable_cons_cnt ];
  fd_filerd_run1( ctx, out_mcache, ctx->buf, reliable_cons_cnt, event_map, cons_fseq, cons_slow, cons_seq, 0L, rng );
}

fd_topo_run_tile_t fd_tile_snapshot_restore_FileRd = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = fd_filerd_run,
};

#undef NAME
