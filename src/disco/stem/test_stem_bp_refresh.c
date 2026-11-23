/* A producer stem with no ins and one shallow reliable out, whose
   consumer (another thread) returns credits per frag.  The producer
   publishes many times the out depth.  It runs out of credits every
   DEPTH frags, and must see the returned credits right away instead of
   at its next housekeeping, which is how per frag credit returns (like
   execle and gui on pack_execle) are meant to work.

   - Spin: the consumer returns each frag as soon as it is published.
     Every backpressure episode must end without a housekeeping.

   - Park: the consumer returns a batch only once the producer is
     parked on backpressure, then rings it like fd_stem_credit_return.
     PREVENT_PARK always vetoes, like pack while skip_cnt>0: the veto is
     for idle parks, so the backpressured producer must still park, and
     resume on the ring, not on its timer. */

#include "fd_stem.h"
#include "../metrics/fd_metrics.h"

#include <pthread.h>

#define DEPTH    (16UL)
#define PUB_CNT  (4UL*DEPTH)
#define BURST    (1UL)
#define LAZY     ((long)400e6)   /* async_min ~100-200 ms: waiting for a housekeeping fails the test */
#define HOLD_NS  ((long)20e6)    /* park consumer: return credits anyway after this, so old code fails instead of hanging */

struct test_ctx {
  int   park;
  ulong pub_cnt;
  ulong refill_cnt;   /* times after_credit saw cr_avail grow, a refresh while backpressured */
  ulong last_cr;
  ulong hk_cnt;       /* METRICS_WRITE calls */
  ulong hk_done;      /* hk_cnt when the last frag was published */
  ulong prevent_cnt;  /* PREVENT_PARK calls */
  long  t0;
  long  t1;
  int   done;
};
typedef struct test_ctx test_ctx_t;

static test_ctx_t ctx;

static fd_frag_meta_t * out_mcache[ 1 ];
static ulong *          cons_fseq [ 1 ];
static fd_sleep_t *     sleep_obj;
static volatile int     cons_done;

/* The consumer, returning credits per frag (spin), or in a batch once
   the producer parks on backpressure (park). */

static void *
cons_thread( void * arg ) {
  (void)arg;
  ulong  seq     = 0UL;
  double tick_ns = fd_tempo_tick_per_ns( NULL );
  while( !cons_done ) {
    if( !FD_VOLATILE_CONST( ctx.park ) ) {
      fd_frag_meta_t const * mline = out_mcache[ 0 ] + fd_mcache_line_idx( seq, DEPTH );
      if( fd_seq_diff( fd_frag_meta_seq_query( mline ), seq )<0L ) { FD_SPIN_PAUSE(); continue; }
      seq++;
      fd_fseq_update( cons_fseq[ 0 ], seq );
      continue;
    }

    /* Wait for the producer to park on backpressure, or give up */
    long t0 = fd_tickcount();
    while( !cons_done && !( FD_VOLATILE_CONST( sleep_obj->credit_bits[ 0 ] ) & 1UL ) ) {
      if( (double)(fd_tickcount()-t0)>(double)HOLD_NS*tick_ns ) break;
      FD_SPIN_PAUSE();
    }
    if( cons_done ) break;
    ulong pub = fd_mcache_seq_query( fd_mcache_seq_laddr( out_mcache[ 0 ] ) ); /* flushed by the park */
    if( pub==fd_fseq_query( cons_fseq[ 0 ] ) ) { FD_SPIN_PAUSE(); continue; }
    fd_fseq_update( cons_fseq[ 0 ], pub );
    __atomic_thread_fence( __ATOMIC_SEQ_CST );
    if( FD_VOLATILE_CONST( sleep_obj->credit_bits[ 0 ] ) & 1UL ) fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_RING );
  }
  return NULL;
}

static int
should_shutdown( test_ctx_t * ctx ) {
  return ctx->done;
}

static void
metrics_write( test_ctx_t * ctx ) {
  ctx->hk_cnt++;
}

static int
prevent_park( test_ctx_t * ctx ) {
  ctx->prevent_cnt++;
  return 1;
}

static void
after_credit( test_ctx_t *        ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  if( ctx->pub_cnt<PUB_CNT ) {
    if( !ctx->pub_cnt ) ctx->t0 = fd_tickcount();
    ulong cr = stem->cr_avail[ 0 ];
    FD_TEST( cr>=BURST );
    if( ctx->pub_cnt && cr>ctx->last_cr ) ctx->refill_cnt++;
    fd_stem_publish( stem, 0UL, ctx->pub_cnt, 0UL, 0UL, 0UL, 0UL, 0UL );
    ctx->last_cr = stem->cr_avail[ 0 ];
    ctx->pub_cnt++;
    *charge_busy = 1;
    if( ctx->pub_cnt==PUB_CNT ) {
      ctx->t1      = fd_tickcount();
      ctx->hk_done = ctx->hk_cnt;
    }
    return;
  }
  ctx->done = fd_fseq_query( cons_fseq[ 0 ] )==PUB_CNT;
  *charge_busy = 1;
}

#define STEM_BURST                    BURST
#define STEM_LAZY                     LAZY
#define STEM_CALLBACK_CONTEXT_TYPE    test_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(test_ctx_t)
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_PREVENT_PARK    prevent_park
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#include "fd_stem.c"

static uchar mcache_mem [ FD_MCACHE_FOOTPRINT( DEPTH, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar fseq_mem   [ FD_FSEQ_FOOTPRINT ]                 __attribute__((aligned(FD_FSEQ_ALIGN)));
static uchar metrics_mem[ FD_METRICS_FOOTPRINT( 0UL ) ]       __attribute__((aligned(FD_METRICS_ALIGN)));
static uchar sleep_mem  [ sizeof(fd_sleep_t) ]                __attribute__((aligned(FD_SLEEP_ALIGN)));
static uchar scratch    [ 1UL<<16 ]                           __attribute__((aligned(128UL)));

static void
run( int park ) {
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  ulong  async_min   = fd_tempo_async_min( LAZY, 2UL, (float)tick_per_ns ); /* event_cnt: 1 cons + housekeeping */
  FD_TEST( async_min );

  out_mcache[ 0 ] = fd_mcache_join( fd_mcache_new( mcache_mem, DEPTH, 0UL, 0UL ) );
  cons_fseq [ 0 ] = fd_fseq_join( fd_fseq_new( fseq_mem, 0UL ) );
  FD_TEST( out_mcache[ 0 ] && cons_fseq[ 0 ] );

  memset( &ctx, 0, sizeof(ctx) );
  ctx.park = park;

  static ulong const out_link_id[ 1 ] = { 0UL };
  fd_stem_sleep_t sleep[ 1 ] = {{ .shmem = NULL }};
  if( park ) {
    sleep_obj = fd_sleep_join( fd_sleep_new( sleep_mem, tick_per_ns ) );
    FD_TEST( sleep_obj );
    sleep->shmem       = sleep_obj;
    sleep->tile_id     = 0UL;
    sleep->out_link_id = out_link_id;
  }

  volatile ulong const * tile_metrics = fd_metrics_tl;
  ulong ring0 = tile_metrics[ FD_METRICS_COUNTER_TILE_PARK_ATTEMPTED_RING_OFF     ];
  ulong dead0 = tile_metrics[ FD_METRICS_COUNTER_TILE_PARK_ATTEMPTED_DEADLINE_OFF ];
  ulong pend0 = tile_metrics[ FD_METRICS_COUNTER_TILE_PARK_ATTEMPTED_PENDING_OFF  ];

  cons_done = 0;
  pthread_t cons;
  FD_TEST( !pthread_create( &cons, NULL, cons_thread, NULL ) );

  ulong            cons_out [ 1 ] = { 0UL };
  ulong            slow     [ 1 ] = { 0UL };
  volatile ulong * cons_slow[ 1 ] = { slow };
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( stem_scratch_footprint( 0UL, 1UL, 1UL )<=sizeof(scratch) );
  stem_run1( 0UL, NULL, NULL, 1UL, out_mcache, 1UL, cons_out, cons_fseq, cons_slow, BURST, LAZY, rng, scratch, &ctx, sleep );

  cons_done = 1;
  FD_TEST( !pthread_join( cons, NULL ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  ulong ring = tile_metrics[ FD_METRICS_COUNTER_TILE_PARK_ATTEMPTED_RING_OFF     ] - ring0;
  ulong dead = tile_metrics[ FD_METRICS_COUNTER_TILE_PARK_ATTEMPTED_DEADLINE_OFF ] - dead0;
  ulong pend = tile_metrics[ FD_METRICS_COUNTER_TILE_PARK_ATTEMPTED_PENDING_OFF  ] - pend0;
  long  elapsed = ctx.t1 - ctx.t0;
  FD_LOG_NOTICE(( "%s: %lu frags through depth %lu in %.1f us (housekeeping >= %.1f ms), %lu refills, %lu housekeepings, parks: %lu ring %lu deadline %lu pending",
                  park ? "park" : "spin", PUB_CNT, DEPTH, (double)elapsed/tick_per_ns/1e3,
                  (double)(2UL*async_min)/tick_per_ns/1e6, ctx.refill_cnt, ctx.hk_done, ring, dead, pend ));

  /* Every DEPTH frags the producer ran dry and got credits back
     without a housekeeping (only the first one ran, at boot), in well
     under the earliest next one (2*async_min) */
  FD_TEST( ctx.done );
  FD_TEST( ctx.refill_cnt>=PUB_CNT/DEPTH-1UL );
  FD_TEST( ctx.hk_done==1UL );
  FD_TEST( elapsed<(long)async_min );
  FD_TEST( !slow[ 0 ] ); /* blame is still charged only at housekeeping */

  if( park ) {
    /* Parked on each episode despite PREVENT_PARK, and woken by the
       credit return (or saw it while parking) */
    FD_TEST( ctx.prevent_cnt>=PUB_CNT/DEPTH-1UL );
    FD_TEST( ring+pend>=PUB_CNT/DEPTH-1UL );
    FD_TEST( !dead );
  } else {
    /* Refreshes are rate limited to one per async_min/16, not one per
       spin: the consumer keeps up, so all but the first episode wait */
    FD_TEST( elapsed>=(long)( (PUB_CNT/DEPTH-2UL)*(async_min>>4) ) );
    FD_TEST( !ring && !dead && !pend );
  }

  fd_fseq_delete( fd_fseq_leave( cons_fseq[ 0 ] ) );
  fd_mcache_delete( fd_mcache_leave( out_mcache[ 0 ] ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_metrics_register( fd_metrics_join( fd_metrics_new( metrics_mem, 0UL ) ) );

  run( 0 );
  run( 1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
