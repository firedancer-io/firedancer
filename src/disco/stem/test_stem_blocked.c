/* A consumer stem whose head frag on in 0 is blocked (returnable_frag
   returns FD_STEM_FRAG_BLOCKED) until a frag on in 1 or its own
   deadline unblocks it.  Checks that:

   - It parks while blocked, retries the blocked frag at most once per
     park wake (here only the park cap ends a park), and the verifying
     sweep does not wake it for the blocked frag even though the
     producer mirror shows it.

   - A frag on another in wakes it, and it then retries and consumes
     the blocked frag.

   - A deadline (NEXT_DEADLINE) ends the park, and work done at the
     deadline unblocks the frag. */

#include "fd_stem.h"
#include "../metrics/fd_metrics.h"

#include <pthread.h>
#include <time.h>

#define DEPTH (128UL)
#define LAZY  ((long)1e6)
#define PACE_NS (5L*1000L*1000L)

struct test_ctx {
  volatile int   done;
  volatile int   capacity;      /* in 0's head may be consumed */
  volatile long  pace_deadline; /* LONG_MAX if none */
  volatile ulong attempts;      /* returnable_frag calls on in 0 */
  volatile ulong consumed0;
  volatile ulong consumed1;
};
typedef struct test_ctx test_ctx_t;

static test_ctx_t   ctx;
static fd_sleep_t * sleep_obj;
static volatile int waker_done;
static volatile ulong sweep_wakes;
static volatile ulong park_wakes;

static int
should_shutdown( test_ctx_t * ctx ) {
  return ctx->done;
}

static long
next_deadline( test_ctx_t * ctx ) {
  return ctx->pace_deadline;
}

static void
after_credit( test_ctx_t *        ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)stem; (void)opt_poll_in;
  if( FD_UNLIKELY( fd_tickcount()>=ctx->pace_deadline ) ) {
    ctx->pace_deadline = LONG_MAX;
    ctx->capacity      = 1;
    *charge_busy       = 1;
  }
}

static int
returnable_frag( test_ctx_t *        ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)chunk; (void)sz; (void)ctl; (void)tsorig; (void)tspub; (void)stem;
  if( in_idx==1UL ) {
    ctx->capacity = 1;
    ctx->consumed1++;
    return 0;
  }
  ctx->attempts++;
  if( !ctx->capacity ) return FD_STEM_FRAG_BLOCKED;
  ctx->capacity = 0;
  ctx->consumed0++;
  return 0;
}

#define STEM_BURST                    (1UL)
#define STEM_LAZY                     LAZY
#define STEM_CALLBACK_CONTEXT_TYPE    test_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(test_ctx_t)
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_NEXT_DEADLINE   next_deadline
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#include "fd_stem.c"

static uchar mcache_mem [ 2 ][ FD_MCACHE_FOOTPRINT( DEPTH, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar fseq_mem   [ 2 ][ FD_FSEQ_FOOTPRINT ]                 __attribute__((aligned(FD_FSEQ_ALIGN)));
static uchar metrics_mem[ FD_METRICS_FOOTPRINT( 2UL ) ]            __attribute__((aligned(FD_METRICS_ALIGN)));
static uchar sleep_mem  [ sizeof(fd_sleep_t) ]                     __attribute__((aligned(FD_SLEEP_ALIGN)));
static uchar scratch    [ 1UL<<16 ]                                __attribute__((aligned(128UL)));

static fd_frag_meta_t * in_mcache[ 2 ];
static ulong *          in_fseq  [ 2 ];
static ulong            in_pub   [ 2 ];

static int
tile_parked( void ) {
  return ( FD_VOLATILE_CONST( sleep_obj->parked_bits[ 0 ] ) & 1UL ) && !FD_VOLATILE_CONST( sleep_obj->tile[ 0 ].word );
}

/* The mwaitx stand-in: doorbell to wake, deadlines, and the sweep of
   seq_mirror against seq_snap */

static void *
waker_thread( void * arg ) {
  (void)arg;
  while( !waker_done ) {
    if( __atomic_exchange_n( &sleep_obj->doorbell[ 0 ], 0UL, __ATOMIC_ACQUIRE ) & 1UL ) {
      if( !FD_VOLATILE_CONST( sleep_obj->tile[ 0 ].word ) ) { park_wakes++; fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_RING ); }
    }
    if( tile_parked() ) {
      if( (long)FD_VOLATILE_CONST( sleep_obj->tile[ 0 ].deadline )<=fd_tickcount() ) {
        park_wakes++;
        fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_DEADLINE );
      } else {
        for( ulong i=0UL; i<2UL; i++ ) {
          if( fd_seq_lt( FD_VOLATILE_CONST( sleep_obj->seq_snap[ 0 ][ i ] ), FD_VOLATILE_CONST( sleep_obj->seq_mirror[ i ] ) ) ) {
            sweep_wakes++;
            park_wakes++;
            fd_sleep_wake_one( &sleep_obj->tile[ 0 ].word, FD_SLEEP_UNPARK_RING );
            break;
          }
        }
      }
    }
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 20000L };
    nanosleep( &ts, NULL );
  }
  return NULL;
}

/* Publish one frag on in i as its producer would: mcache, mirror, and
   ring the consumer if parked */

static void
publish( ulong i ) {
  ulong seq = in_pub[ i ]++;
  fd_mcache_publish( in_mcache[ i ], DEPTH, seq, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
  fd_mcache_seq_update( fd_mcache_seq_laddr( in_mcache[ i ] ), in_pub[ i ] );
  __atomic_store_n( &sleep_obj->seq_mirror[ i ], in_pub[ i ], __ATOMIC_RELEASE );
  fd_sleep_wake_t wake[ 1 ] = {{ .w = 0UL, .mask = 1UL }};
  fd_sleep_wake_check( sleep_obj, wake, 1UL );
}

static volatile ulong const * tile_metrics;

static void *
stem_thread( void * arg ) {
  fd_stem_sleep_t * sleep = (fd_stem_sleep_t *)arg;
  fd_metrics_register( fd_metrics_join( metrics_mem ) );
  tile_metrics = fd_metrics_tl;
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  stem_run1( 2UL, (fd_frag_meta_t const **)in_mcache, in_fseq, 0UL, NULL, 0UL, NULL, NULL, NULL, 1UL, LAZY, rng, scratch, &ctx, sleep );
  fd_rng_delete( fd_rng_leave( rng ) );
  return NULL;
}

static void
wait_for( volatile ulong const * v,
          ulong                  target ) {
  long t0 = fd_log_wallclock();
  while( *v<target ) {
    FD_TEST( fd_log_wallclock()-t0<(long)5e9 );
    FD_SPIN_PAUSE();
  }
}

static void
wait_parked( void ) {
  long t0 = fd_log_wallclock();
  while( !tile_parked() ) {
    FD_TEST( fd_log_wallclock()-t0<(long)5e9 );
    FD_SPIN_PAUSE();
  }
}

static void
nap_ms( long ms ) {
  struct timespec ts = { .tv_sec = ms/1000L, .tv_nsec = (ms%1000L)*1000000L };
  while( nanosleep( &ts, &ts ) ) {}
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  FD_TEST( fd_metrics_new( metrics_mem, 2UL ) );

  for( ulong i=0UL; i<2UL; i++ ) {
    in_mcache[ i ] = fd_mcache_join( fd_mcache_new( mcache_mem[ i ], DEPTH, 0UL, 0UL ) );
    in_fseq  [ i ] = fd_fseq_join( fd_fseq_new( fseq_mem[ i ], 0UL ) );
    FD_TEST( in_mcache[ i ] && in_fseq[ i ] );
  }

  sleep_obj = fd_sleep_join( fd_sleep_new( sleep_mem, tick_per_ns ) );
  FD_TEST( sleep_obj );
  fd_stem_sleep_t sleep[ 1 ] = {{ .shmem = sleep_obj }};
  sleep->tile_id = 0UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    sleep->in_link_id [ i ] = i;
    sleep->in_producer[ i ] = ULONG_MAX;
  }
  FD_TEST( stem_scratch_footprint( 2UL, 0UL, 0UL )<=sizeof(scratch) );

  memset( &ctx, 0, sizeof(ctx) );
  ctx.pace_deadline = LONG_MAX;

  /* The blocked frag is already published and mirrored */
  publish( 0UL );

  pthread_t waker, stem;
  FD_TEST( !pthread_create( &waker, NULL, waker_thread, NULL ) );
  FD_TEST( !pthread_create( &stem,  NULL, stem_thread,  sleep ) );

  /* Blocked: it parks, and stays parked across the park cap without
     retrying the frag or being swept awake for it */
  wait_for( &ctx.attempts, 1UL );
  wait_parked();
  nap_ms( 3L*FD_SLEEP_PARK_CAP_NS/1000000L );
  FD_TEST( !ctx.consumed0 );
  FD_TEST( !sweep_wakes );
  FD_TEST( park_wakes>=2UL );                 /* the cap ended parks, each re-parked */
  FD_TEST( park_wakes<=10UL );                /* and not a spin */
  FD_TEST( ctx.attempts<=park_wakes+1UL );    /* one retry per wake at most */
  FD_TEST( tile_metrics[ FD_METRICS_COUNTER_TILE_PARK_ATTEMPTED_DEADLINE_OFF ]>=2UL );

  /* A frag on in 1 wakes it, and it retries and consumes in 0 */
  publish( 1UL );
  wait_for( &ctx.consumed0, 1UL );
  FD_TEST( ctx.consumed1==1UL );
  FD_TEST( !sweep_wakes );

  /* Deadline: the next frag blocks, and the pacing deadline ends the
     park and unblocks it */
  wait_parked();
  long t0 = fd_tickcount();
  ctx.pace_deadline = t0 + (long)( (double)PACE_NS*tick_per_ns );
  ulong attempts0 = ctx.attempts;
  publish( 0UL );
  wait_for( &ctx.consumed0, 2UL );
  FD_TEST( fd_tickcount()-t0>=(long)( (double)PACE_NS*tick_per_ns ) );
  FD_TEST( ctx.attempts>=attempts0+2UL ); /* blocked, then consumed after the deadline */
  FD_TEST( ctx.attempts<=attempts0+3UL );
  FD_TEST( ctx.consumed1==1UL );
  FD_TEST( !sweep_wakes );

  ctx.done = 1;
  fd_sleep_ring( sleep_obj, 0UL );
  FD_TEST( !pthread_join( stem, NULL ) );
  waker_done = 1;
  FD_TEST( !pthread_join( waker, NULL ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
