#define _GNU_SOURCE

#include "fd_accdb.h"
#include "../../util/fd_util.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>

/* Measures only the T2 command body for root advancement and fork
   purge.  T1 prepares one zero-data account version per pubkey before
   submitting the command.  Reusing the same pubkeys each slot forces
   root cleanup to find superseded versions while keeping account data
   size out of this metadata-focused benchmark.

   Pin T1 and T2 to separate physical cores for repeatable results:

     bench_accdb_cleanup --t1-cpu 94 --t2-cpu 95 */

#define BENCH_CACHE_FOOTPRINT    (64UL<<20UL)
#define BENCH_CACHE_MIN_RESERVED (2UL)
#define BENCH_MAX_LIVE_SLOTS     (8UL)
#define BENCH_PARTITION_CNT      (64UL)
#define BENCH_PARTITION_SZ       (1UL<<30UL)

typedef struct {
  fd_accdb_t * t1;
  fd_accdb_t * t2;
  void *       t1_mem;
  void *       t2_mem;
  void *       shmem_mem;
  int          fd;
} bench_env_t;

static bench_env_t
bench_setup( ulong writes_per_slot ) {
  FD_TEST( writes_per_slot );
  FD_TEST( writes_per_slot<=(UINT_MAX-1024UL)/5UL );
  FD_TEST( writes_per_slot<=UINT_MAX/BENCH_MAX_LIVE_SLOTS-16UL );

  ulong max_accounts = 5UL*writes_per_slot + 1024UL;
  ulong max_writes   = writes_per_slot + 16UL;

  int fd = memfd_create( "accdb_cleanup_bench", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));

  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts,
                                              BENCH_MAX_LIVE_SLOTS,
                                              max_writes,
                                              BENCH_PARTITION_CNT,
                                              BENCH_CACHE_FOOTPRINT,
                                              BENCH_CACHE_MIN_RESERVED,
                                              2UL,
                                              0UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( shmem_mem,
                          max_accounts,
                          BENCH_MAX_LIVE_SLOTS,
                          max_writes,
                          BENCH_PARTITION_CNT,
                          BENCH_PARTITION_SZ,
                          BENCH_CACHE_FOOTPRINT,
                          BENCH_CACHE_MIN_RESERVED,
                          0,
                          42UL,
                          2UL,
                          0UL ) );
  FD_TEST( shmem );

  ulong accdb_fp = fd_accdb_footprint( BENCH_MAX_LIVE_SLOTS );
  FD_TEST( accdb_fp );
  void * t1_mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  void * t2_mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  FD_TEST( t1_mem );
  FD_TEST( t2_mem );
  fd_accdb_t * t1 = fd_accdb_join( fd_accdb_new( t1_mem, shmem, fd, 0UL, NULL ) );
  fd_accdb_t * t2 = fd_accdb_join( fd_accdb_new( t2_mem, shmem, fd, 0UL, NULL ) );
  FD_TEST( t1 );
  FD_TEST( t2 );

  return (bench_env_t){
    .t1        = t1,
    .t2        = t2,
    .t1_mem    = t1_mem,
    .t2_mem    = t2_mem,
    .shmem_mem = shmem_mem,
    .fd        = fd
  };
}

static void
bench_teardown( bench_env_t * env ) {
  free( env->shmem_mem );
  free( env->t1_mem );
  free( env->t2_mem );
  close( env->fd );
}

static void
pin_thread( ulong cpu ) {
  if( cpu==ULONG_MAX ) return;
  FD_TEST( cpu<CPU_SETSIZE );
  cpu_set_t set;
  CPU_ZERO( &set );
  CPU_SET( cpu, &set );
  FD_TEST( !pthread_setaffinity_np( pthread_self(), sizeof(set), &set ) );
}

static ulong
monotonic_raw( void ) {
  struct timespec ts;
  FD_TEST( !clock_gettime( CLOCK_MONOTONIC_RAW, &ts ) );
  return (ulong)ts.tv_sec*1000000000UL + (ulong)ts.tv_nsec;
}

typedef struct {
  fd_accdb_t *    accdb;
  pthread_t       thread;
  pthread_mutex_t lock;
  pthread_cond_t  cond;
  ulong           cpu;
  ulong           elapsed;
  int             request;
  int             done;
  int             stop;
} background_worker_t;

static void *
background_main( void * _worker ) {
  background_worker_t * worker = _worker;
  pin_thread( worker->cpu );

  FD_TEST( !pthread_mutex_lock( &worker->lock ) );
  for(;;) {
    while( !worker->request && !worker->stop )
      FD_TEST( !pthread_cond_wait( &worker->cond, &worker->lock ) );
    if( worker->stop ) break;
    worker->request = 0;
    FD_TEST( !pthread_mutex_unlock( &worker->lock ) );

    int charge_busy = 0;
    ulong then = monotonic_raw();
    fd_accdb_background( worker->accdb, &charge_busy );
    ulong now = monotonic_raw();
    FD_TEST( charge_busy );

    FD_TEST( !pthread_mutex_lock( &worker->lock ) );
    worker->elapsed = now-then;
    worker->done = 1;
    FD_TEST( !pthread_cond_signal( &worker->cond ) );
  }
  FD_TEST( !pthread_mutex_unlock( &worker->lock ) );
  return NULL;
}

static void
background_start( background_worker_t * worker,
                  fd_accdb_t *          accdb,
                  ulong                 cpu ) {
  *worker = (background_worker_t){
    .accdb = accdb,
    .cpu   = cpu
  };
  FD_TEST( !pthread_mutex_init( &worker->lock, NULL ) );
  FD_TEST( !pthread_cond_init( &worker->cond, NULL ) );
  FD_TEST( !pthread_create( &worker->thread, NULL, background_main, worker ) );
}

static ulong
background_run( background_worker_t * worker ) {
  FD_TEST( !pthread_mutex_lock( &worker->lock ) );
  FD_TEST( !worker->request );
  FD_TEST( !worker->done );
  worker->request = 1;
  FD_TEST( !pthread_cond_signal( &worker->cond ) );
  while( !worker->done )
    FD_TEST( !pthread_cond_wait( &worker->cond, &worker->lock ) );
  ulong elapsed = worker->elapsed;
  worker->done = 0;
  FD_TEST( !pthread_mutex_unlock( &worker->lock ) );
  return elapsed;
}

static void
background_stop( background_worker_t * worker ) {
  FD_TEST( !pthread_mutex_lock( &worker->lock ) );
  worker->stop = 1;
  FD_TEST( !pthread_cond_signal( &worker->cond ) );
  FD_TEST( !pthread_mutex_unlock( &worker->lock ) );
  FD_TEST( !pthread_join( worker->thread, NULL ) );
  FD_TEST( !pthread_cond_destroy( &worker->cond ) );
  FD_TEST( !pthread_mutex_destroy( &worker->lock ) );
}

static void
make_pubkey( uchar pubkey[ static 32 ],
             ulong idx ) {
  fd_memset( pubkey, 0, 32UL );
  fd_memcpy( pubkey, &idx, sizeof(ulong) );
}

static void
write_slot( fd_accdb_t *       accdb,
            fd_accdb_fork_id_t fork_id,
            ulong              writes_per_slot,
            ulong              slot ) {
  for( ulong i=0UL; i<writes_per_slot; i++ ) {
    uchar pubkey[ 32 ];
    make_pubkey( pubkey, i );

    uchar const * pubkeys[ 1 ] = { pubkey };
    int writable[ 1 ] = { 1 };
    fd_acc_t acc[ 1 ];
    fd_memset( acc, 0, sizeof(acc) );
    fd_accdb_acquire( accdb, fork_id, 1UL, pubkeys, writable, acc );
    acc[ 0 ].lamports = slot + 1UL;
    acc[ 0 ].data_len = 0UL;
    fd_memset( acc[ 0 ].owner, 0, sizeof(acc[ 0 ].owner) );
    acc[ 0 ].owner[ 0 ] = 1U;
    acc[ 0 ].commit = 1;
    fd_accdb_release( accdb, 1UL, acc );
  }
}

static int
cmp_ulong( void const * _a,
           void const * _b ) {
  ulong a = *(ulong const *)_a;
  ulong b = *(ulong const *)_b;
  return (a>b) - (a<b);
}

static void
report( char const * mode,
        ulong        writes_per_slot,
        ulong        warmup_cnt,
        ulong        sample_cnt,
        ulong *      samples ) {
  double sum = 0.0;
  for( ulong i=0UL; i<sample_cnt; i++ ) sum += (double)samples[ i ];
  qsort( samples, sample_cnt, sizeof(ulong), cmp_ulong );

  ulong rank50 = (sample_cnt/100UL)*50UL + ((sample_cnt%100UL)*50UL+99UL)/100UL;
  ulong rank95 = (sample_cnt/100UL)*95UL + ((sample_cnt%100UL)*95UL+99UL)/100UL;
  ulong p50 = samples[ rank50-1UL ];
  ulong p95 = samples[ rank95-1UL ];
  double mean = sum/(double)sample_cnt;

  FD_LOG_NOTICE(( "%s: writes/slot=%lu warmup=%lu samples=%lu", mode, writes_per_slot, warmup_cnt, sample_cnt ));
  FD_LOG_NOTICE(( "  mean %.0f ns  p50 %lu ns  p95 %lu ns", mean, p50, p95 ));
  FD_LOG_NOTICE(( "  mean %.2f ns/write  p50 %.2f ns/write  p95 %.2f ns/write",
                  mean/(double)writes_per_slot,
                  (double)p50/(double)writes_per_slot,
                  (double)p95/(double)writes_per_slot ));
}

static void
bench_root( ulong writes_per_slot,
            ulong warmup_cnt,
            ulong sample_cnt,
            ulong t2_cpu ) {
  bench_env_t env = bench_setup( writes_per_slot );
  ulong * samples = malloc( sample_cnt*sizeof(ulong) );
  FD_TEST( samples );
  background_worker_t worker[ 1 ];
  background_start( worker, env.t2, t2_cpu );

  fd_accdb_fork_id_t root = fd_accdb_attach_child(
      env.t1, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  write_slot( env.t1, root, writes_per_slot, 0UL );

  fd_accdb_fork_id_t prev = fd_accdb_attach_child( env.t1, root );
  write_slot( env.t1, prev, writes_per_slot, 1UL );

  /* Prime the old-root and deferred-free paths before any samples. */
  fd_accdb_fork_id_t cur = fd_accdb_attach_child( env.t1, prev );
  write_slot( env.t1, cur, writes_per_slot, 2UL );
  fd_accdb_advance_root( env.t1, prev );
  (void)background_run( worker );
  prev = cur;

  ulong iter_cnt = warmup_cnt + sample_cnt;
  for( ulong iter=0UL; iter<iter_cnt; iter++ ) {
    cur = fd_accdb_attach_child( env.t1, prev );
    write_slot( env.t1, cur, writes_per_slot, iter+3UL );

    fd_accdb_advance_root( env.t1, prev );
    ulong elapsed = background_run( worker );
    if( iter>=warmup_cnt ) samples[ iter-warmup_cnt ] = elapsed;
    prev = cur;
  }

  report( "root", writes_per_slot, warmup_cnt, sample_cnt, samples );
  background_stop( worker );
  free( samples );
  bench_teardown( &env );
}

static void
bench_purge( ulong writes_per_slot,
             ulong warmup_cnt,
             ulong sample_cnt,
             ulong t2_cpu ) {
  bench_env_t env = bench_setup( writes_per_slot );
  ulong * samples = malloc( sample_cnt*sizeof(ulong) );
  FD_TEST( samples );
  background_worker_t worker[ 1 ];
  background_start( worker, env.t2, t2_cpu );

  fd_accdb_fork_id_t root = fd_accdb_attach_child(
      env.t1, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  write_slot( env.t1, root, writes_per_slot, 0UL );

  /* Prime deferred reclamation before any samples. */
  fd_accdb_fork_id_t fork = fd_accdb_attach_child( env.t1, root );
  write_slot( env.t1, fork, writes_per_slot, 1UL );
  fd_accdb_purge( env.t1, fork );
  (void)background_run( worker );

  ulong iter_cnt = warmup_cnt + sample_cnt;
  for( ulong iter=0UL; iter<iter_cnt; iter++ ) {
    fork = fd_accdb_attach_child( env.t1, root );
    write_slot( env.t1, fork, writes_per_slot, iter+2UL );

    fd_accdb_purge( env.t1, fork );
    ulong elapsed = background_run( worker );
    if( iter>=warmup_cnt ) samples[ iter-warmup_cnt ] = elapsed;
  }

  report( "purge", writes_per_slot, warmup_cnt, sample_cnt, samples );
  background_stop( worker );
  free( samples );
  bench_teardown( &env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * mode = fd_env_strip_cmdline_cstr( &argc, &argv, "--mode", NULL, "both" );
  ulong writes_per_slot = fd_env_strip_cmdline_ulong( &argc, &argv, "--writes-per-slot", NULL, 10000UL );
  ulong warmup_cnt       = fd_env_strip_cmdline_ulong( &argc, &argv, "--warmup",         NULL,    10UL );
  ulong sample_cnt       = fd_env_strip_cmdline_ulong( &argc, &argv, "--samples",        NULL,    50UL );
  ulong t1_cpu           = fd_env_strip_cmdline_ulong( &argc, &argv, "--t1-cpu",         NULL, ULONG_MAX );
  ulong t2_cpu           = fd_env_strip_cmdline_ulong( &argc, &argv, "--t2-cpu",         NULL, ULONG_MAX );

  FD_TEST( writes_per_slot );
  FD_TEST( sample_cnt );
  FD_TEST( sample_cnt<=ULONG_MAX/sizeof(ulong) );
  FD_TEST( warmup_cnt<=ULONG_MAX-sample_cnt );
  pin_thread( t1_cpu );

  if( !strcmp( mode, "root" ) ) {
    bench_root( writes_per_slot, warmup_cnt, sample_cnt, t2_cpu );
  } else if( !strcmp( mode, "purge" ) ) {
    bench_purge( writes_per_slot, warmup_cnt, sample_cnt, t2_cpu );
  } else if( !strcmp( mode, "both" ) ) {
    bench_root ( writes_per_slot, warmup_cnt, sample_cnt, t2_cpu );
    bench_purge( writes_per_slot, warmup_cnt, sample_cnt, t2_cpu );
  } else {
    FD_LOG_ERR(( "unsupported --mode %s (expected root, purge, or both)", mode ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
