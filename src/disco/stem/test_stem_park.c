/* A producer stem with a sleep object and no ins, parking on its
   NEXT_DEADLINE.  Checks what a park wake must do right away:

   - A park with nothing due arms no timer: it outlasts the park cap
     until a ring, and the mwaitx sweep ends it at the cap otherwise.

   - A park with a deadline sooner than the cap still ends on its own
     timer at that deadline.

   - Idle parks longer than async_min refresh the flow control credits
     on wake, but run the full housekeeping (metrics, heartbeat) only
     about once per lazy, not on every wake.

   - A backpressured tile resumes publishing as soon as its consumers
     return credits, without parking again on the stale count.

   - The stem stores the seq_mirror of an out it published blindly, and
     never touches the mirror of an out it did not publish (a link
     another client of the tile publishes, like a keyguard sign link),
     not on housekeeping, not on park and not on shutdown. */

#include "fd_stem.h"
#include "../metrics/fd_metrics.h"

#include <pthread.h>
#include <time.h>

#define DEPTH      (128UL)
#define CONS_CNT   (7UL)            /* event_cnt 8, so async_min ~lazy/8 */
#define BURST      (1UL)
#define LAZY       ((long)50e6)     /* parks of 1.5*async_min stay under the park cap */
#define IDLE_WAKES (30UL)
#define BP_PARKS   (3UL)
#define RING_NS    (3L*FD_SLEEP_PARK_CAP_NS) /* an untimed park must outlast the cap */

#define PHASE_FILL    (0)
#define PHASE_UNTIMED (1)
#define PHASE_SWEEP   (2)
#define PHASE_IDLE    (3)
#define PHASE_BP      (4)
#define PHASE_RESUME  (5)

/* What the mwaitx stand-in does with the next park it sees, one shot */

#define WAKER_NONE  (0)
#define WAKER_RING  (1) /* ring RING_NS after the tile parks */
#define WAKER_SWEEP (2) /* wake at the deadline the tile left in the sleep object */

struct test_ctx {
  int   phase;
  int   done;
  long  park_ticks;
  long  hk_ticks;
  long  cap_ticks;
  ulong pub_cnt;
  ulong hk_cnt;     /* METRICS_WRITE calls */
  ulong phase_calls;
  long  phase_t0;
  ulong ring0;
  ulong dead0;
  ulong idle_wakes;
  ulong idle_hk0;
  long  idle_t0;
  ulong heartbeat0;
  ulong bp_parks;
  ulong parks_after_return;
  ulong * cons_fseq[ CONS_CNT ];
};
typedef struct test_ctx test_ctx_t;

static test_ctx_t ctx;

static fd_sleep_t * sleep_obj;
static volatile int waker_mode;
static volatile int waker_done;

/* The waker thread doubles as the other publisher of link 1, which
   the stem holds as out 1 but never publishes.  It writes the link's
   mirror from its own progress; the stem must never clobber it. */

static ulong other_seq;

static void *
waker_thread( void * arg ) {
  (void)arg;
  while( !waker_done ) {
    int mode = waker_mode;
    other_seq++;
    FD_VOLATILE( sleep_obj->seq_mirror[ 1 ] ) = other_seq;
    FD_TEST( FD_VOLATILE_CONST( sleep_obj->seq_mirror[ 1 ] )==other_seq );
    FD_TEST( FD_VOLATILE_CONST( sleep_obj->seq_mirror[ 0 ] )<=FD_VOLATILE_CONST( ctx.pub_cnt ) );
    int parked = ( FD_VOLATILE_CONST( sleep_obj->parked_bits[ 0 ] ) & 1UL ) && !FD_VOLATILE_CONST( sleep_obj->tile[ 0 ].word );
    if( FD_LIKELY( mode==WAKER_NONE || !parked ) ) { FD_SPIN_PAUSE(); continue; }
    if( mode==WAKER_RING ) {
      struct timespec ts = { .tv_sec = RING_NS/(long)1e9, .tv_nsec = RING_NS%(long)1e9 };
      while( nanosleep( &ts, &ts ) ) {}
      FD_TEST( !FD_VOLATILE_CONST( sleep_obj->tile[ 0 ].word ) ); /* still parked: no timer fired */
      waker_mode = WAKER_NONE;
      fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_RING );
    } else if( (long)FD_VOLATILE_CONST( sleep_obj->tile[ 0 ].deadline )<=fd_tickcount() ) {
      waker_mode = WAKER_NONE;
      fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_DEADLINE );
    }
  }
  return NULL;
}

static void
consumers_catch_up( test_ctx_t * ctx ) {
  for( ulong i=0UL; i<CONS_CNT; i++ ) fd_fseq_update( ctx->cons_fseq[ i ], ctx->pub_cnt );
}

static int
should_shutdown( test_ctx_t * ctx ) {
  return ctx->done;
}

static void
metrics_write( test_ctx_t * ctx ) {
  ctx->hk_cnt++;
}

static long
next_deadline( test_ctx_t * ctx ) {
  if( ctx->phase==PHASE_UNTIMED || ctx->phase==PHASE_SWEEP ) return LONG_MAX; /* nothing due */
  if( ctx->phase==PHASE_BP ) {
    /* Parked on backpressure: return every credit on the last park */
    if( ++ctx->bp_parks==BP_PARKS ) {
      consumers_catch_up( ctx );
      ctx->phase = PHASE_RESUME;
    }
  } else if( ctx->phase==PHASE_RESUME ) {
    ctx->parks_after_return++;
  }
  return fd_tickcount() + ctx->park_ticks;
}

static void
after_credit( test_ctx_t *        ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  volatile ulong const * tile_metrics = fd_metrics_tl;
  ulong ring = tile_metrics[ FD_METRICS_COUNTER_TILE_UNPARK_RING_OFF     ];
  ulong dead = tile_metrics[ FD_METRICS_COUNTER_TILE_UNPARK_DEADLINE_OFF ];

  switch( ctx->phase ) {
  case PHASE_FILL:
    fd_stem_publish( stem, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
    ctx->pub_cnt++;
    *charge_busy = 1;
    if( ctx->pub_cnt==DEPTH/2UL ) {
      /* Credits come back while we are awake, only a refresh sees them */
      consumers_catch_up( ctx );
      ctx->phase       = PHASE_UNTIMED;
      ctx->phase_calls = 0UL;
      ctx->phase_t0    = fd_tickcount();
      ctx->ring0       = ring;
      ctx->dead0       = dead;
      waker_mode       = WAKER_RING;
    }
    break;

  case PHASE_UNTIMED:
    /* Transitions are busy so no park follows them: the first call of
       a phase parks (untimed), the second follows the wake */
    if( ++ctx->phase_calls<2UL ) break;
    FD_TEST( fd_tickcount()-ctx->phase_t0>=(long)((double)RING_NS*fd_tempo_tick_per_ns( NULL )) );
    FD_TEST( ring==ctx->ring0+1UL && dead==ctx->dead0 );
    FD_TEST( sleep_obj->tile[ 0 ].deadline<=(ulong)( ctx->phase_t0+2L*ctx->cap_ticks ) ); /* the cap was left for the sweep */
    ctx->phase       = PHASE_SWEEP;
    ctx->phase_calls = 0UL;
    ctx->phase_t0    = fd_tickcount();
    waker_mode       = WAKER_SWEEP;
    *charge_busy     = 1;
    break;

  case PHASE_SWEEP:
    /* Still nothing due: the sweep ends the park at the cap */
    if( ++ctx->phase_calls<2UL ) break;
    FD_TEST( fd_tickcount()-ctx->phase_t0>=ctx->cap_ticks );
    FD_TEST( fd_tickcount()-ctx->phase_t0<10L*ctx->cap_ticks );
    FD_TEST( ring==ctx->ring0+1UL && dead==ctx->dead0+1UL );
    FD_TEST( waker_mode==WAKER_NONE );
    ctx->phase      = PHASE_IDLE;
    ctx->idle_hk0   = ctx->hk_cnt;
    ctx->idle_t0    = fd_tickcount();
    ctx->heartbeat0 = tile_metrics[ FD_METRICS_GAUGE_TILE_HEARTBEAT_TIMESTAMP_NANOS_OFF ];
    *charge_busy    = 1;
    break;

  case PHASE_IDLE:
    /* Not busy, so each call after the first follows a park, now on
       the tile's own deadline: timed, nobody rings, ends at the
       deadline */
    if( ctx->idle_wakes ) {
      FD_TEST( stem->cr_avail[ 0 ]==DEPTH );
      FD_TEST( *stem->min_cr_avail==DEPTH );
      FD_TEST( ring==ctx->ring0+1UL && dead==ctx->dead0+1UL+ctx->idle_wakes );
    }
    if( ++ctx->idle_wakes>IDLE_WAKES ) {
      long  elapsed = fd_tickcount() - ctx->idle_t0;
      ulong hk      = ctx->hk_cnt - ctx->idle_hk0;
      FD_LOG_NOTICE(( "%lu idle wakes in %.1f ms ran %lu housekeepings (lazy %.1f ms)",
                      IDLE_WAKES, (double)elapsed/fd_tempo_tick_per_ns( NULL )/1e6, hk,
                      (double)ctx->hk_ticks/fd_tempo_tick_per_ns( NULL )/1e6 ));
      FD_TEST( elapsed>=(long)IDLE_WAKES*ctx->park_ticks );                       /* each park ran to its deadline */
      FD_TEST( elapsed< (long)IDLE_WAKES*ctx->cap_ticks  );                       /* and not to the cap */
      FD_TEST( hk<=IDLE_WAKES/2UL );                                             /* not on every wake */
      FD_TEST( hk>=(ulong)( elapsed/( 2L*( ctx->hk_ticks+ctx->park_ticks ) ) ) ); /* but about once per lazy */
      FD_TEST( tile_metrics[ FD_METRICS_GAUGE_TILE_HEARTBEAT_TIMESTAMP_NANOS_OFF ]>ctx->heartbeat0 );
      ctx->phase = PHASE_BP;
    }
    break;

  case PHASE_BP:
    /* Publish until out of credits, then the stem parks backpressured */
    fd_stem_publish( stem, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
    ctx->pub_cnt++;
    *charge_busy = 1;
    break;

  case PHASE_RESUME:
    /* The credit return must be seen by the wake that follows it */
    FD_TEST( stem->cr_avail[ 0 ]==DEPTH );
    FD_TEST( ctx->parks_after_return<=1UL ); /* one if that attempt was too close to its deadline to park */
    ctx->done = 1;
    break;
  }
}

#define STEM_BURST                    BURST
#define STEM_LAZY                     LAZY
#define STEM_CALLBACK_CONTEXT_TYPE    test_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(test_ctx_t)
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_NEXT_DEADLINE   next_deadline
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#include "fd_stem.c"

static uchar mcache_mem [ 2 ][ FD_MCACHE_FOOTPRINT( DEPTH, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar fseq_mem   [ CONS_CNT ][ FD_FSEQ_FOOTPRINT ]     __attribute__((aligned(FD_FSEQ_ALIGN)));
static uchar metrics_mem[ FD_METRICS_FOOTPRINT( 0UL ) ]       __attribute__((aligned(FD_METRICS_ALIGN)));
static uchar sleep_mem  [ sizeof(fd_sleep_t) ]                __attribute__((aligned(FD_SLEEP_ALIGN)));
static uchar scratch    [ 1UL<<16 ]                           __attribute__((aligned(128UL)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_metrics_register( fd_metrics_join( fd_metrics_new( metrics_mem, 0UL ) ) );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  ulong  async_min   = fd_tempo_async_min( LAZY, 1UL+CONS_CNT, (float)tick_per_ns );
  FD_TEST( async_min );
  memset( &ctx, 0, sizeof(ctx) );
  ctx.park_ticks = (long)( async_min + async_min/2UL );
  ctx.hk_ticks   = (long)( async_min*(1UL+CONS_CNT) );
  ctx.cap_ticks  = (long)( (double)FD_SLEEP_PARK_CAP_NS*tick_per_ns );
  FD_TEST( ctx.park_ticks<ctx.cap_ticks );

  fd_frag_meta_t * out_mcache[ 2 ] = {
    fd_mcache_join( fd_mcache_new( mcache_mem[ 0 ], DEPTH, 0UL, 0UL ) ),
    fd_mcache_join( fd_mcache_new( mcache_mem[ 1 ], DEPTH, 0UL, 0UL ) ),
  };
  FD_TEST( out_mcache[ 0 ] && out_mcache[ 1 ] );

  ulong            cons_out [ CONS_CNT ];
  ulong *          cons_fseq[ CONS_CNT ];
  volatile ulong * cons_slow[ CONS_CNT ];
  ulong            slow     [ CONS_CNT ] = {0};
  for( ulong i=0UL; i<CONS_CNT; i++ ) {
    cons_out [ i ] = 0UL;
    cons_fseq[ i ] = fd_fseq_join( fd_fseq_new( fseq_mem[ i ], 0UL ) );
    FD_TEST( cons_fseq[ i ] );
    cons_slow[ i ] = &slow[ i ];
    ctx.cons_fseq[ i ] = cons_fseq[ i ];
  }

  /* Only the waker thread rings us, and only when asked; otherwise
     parks end on their deadline */
  static ulong const out_link_id[ 2 ] = { 0UL, 1UL };
  sleep_obj = fd_sleep_join( fd_sleep_new( sleep_mem, tick_per_ns ) );
  FD_TEST( sleep_obj );
  fd_mcache_seq_update( fd_mcache_seq_laddr( out_mcache[ 1 ] ), 77UL ); /* the other publisher's progress */
  fd_stem_sleep_t sleep[ 1 ] = {{ .shmem = sleep_obj }};
  sleep->tile_id     = 0UL;
  sleep->out_link_id = out_link_id;

  pthread_t waker;
  FD_TEST( !pthread_create( &waker, NULL, waker_thread, NULL ) );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( stem_scratch_footprint( 0UL, 2UL, CONS_CNT )<=sizeof(scratch) );
  stem_run1( 0UL, NULL, NULL, 2UL, out_mcache, CONS_CNT, cons_out, cons_fseq, cons_slow, BURST, LAZY, rng, scratch, &ctx, sleep );

  waker_done = 1;
  FD_TEST( !pthread_join( waker, NULL ) );
  FD_TEST( ctx.done );
  FD_TEST( ctx.bp_parks==BP_PARKS );
  FD_TEST( slow[ 0 ]>=1UL ); /* backpressured wakes charge the slowest consumer */

  /* The shutdown flush published out 0 and left out 1 alone */
  FD_TEST( fd_mcache_seq_query( fd_mcache_seq_laddr( out_mcache[ 0 ] ) )==ctx.pub_cnt );
  FD_TEST( FD_VOLATILE_CONST( sleep_obj->seq_mirror[ 0 ] )==ctx.pub_cnt );
  FD_TEST( fd_mcache_seq_query( fd_mcache_seq_laddr( out_mcache[ 1 ] ) )==77UL );
  FD_TEST( FD_VOLATILE_CONST( sleep_obj->seq_mirror[ 1 ] )==other_seq );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
