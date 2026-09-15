#define _GNU_SOURCE

#include "fd_accdb.h"
#include "../../util/fd_util.h"

#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* bench_accdb_scale: how the acquire/release hot path scales with the
   number of concurrent joins.

   Every thread is its own join on one shared accdb, writing to the
   same fork, the way the execle tiles do.  Each transaction acquires
   ro_cnt read-only accounts shared by every thread (the programs) and
   rw_cnt writable accounts from the thread's own slice (the token
   accounts), touches the writable ones and commits.  Nothing here
   conflicts on an account, so all that the threads share is the line
   allocator (free lists, stealing, lazy init) and the refcnt of the
   shared read-only lines.

   The sweep runs the same loop at each thread count and reports the
   per-thread cost of a transaction.  Flat is ideal; growth with the
   thread count is the allocator. */

static uchar dummy_owner[ 32 ] = { 0xEE };

#define BENCH_MAX_THREADS  (64UL)
#define BENCH_MAX_ACCTS    (64UL)

static void
make_pubkey( uchar pubkey[ static 32 ],
             ulong idx ) {
  fd_memset( pubkey, 0, 32UL );
  fd_memcpy( pubkey, &idx, sizeof(ulong) );
}

struct worker {
  fd_accdb_t *       accdb;
  fd_accdb_fork_id_t fork;
  ulong              idx;
  ulong              cpu;
  ulong              rw_cnt;
  ulong              ro_cnt;
  ulong              rw_base;   /* this thread's slice of writable accounts */
  ulong              rw_span;
  ulong              ro_span;   /* shared read-only accounts, from 0 */
  ulong              data_sz;   /* every write alternates between the two sizes when data_sz2 is set */
  ulong              data_sz2;
  ulong              seed;

  ulong              txn_cnt;
  long               busy_ns;   /* the loop, timed per 64 transactions */
};

typedef struct worker worker_t;

static int volatile go;
static int volatile stop;

static void *
worker_main( void * arg ) {
  worker_t * w = arg;
  if( w->cpu!=ULONG_MAX ) {
    cpu_set_t set;
    CPU_ZERO( &set );
    CPU_SET( w->cpu, &set );
    FD_TEST( !pthread_setaffinity_np( pthread_self(), sizeof(set), &set ) );
  }

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)w->seed, 0UL ) );

  uchar         pubkeys[ BENCH_MAX_ACCTS ][ 32 ];
  uchar const * pks    [ BENCH_MAX_ACCTS ];
  int           writable[ BENCH_MAX_ACCTS ];
  fd_acc_t      accs   [ BENCH_MAX_ACCTS ];
  ulong cnt = w->rw_cnt + w->ro_cnt;
  for( ulong i=0UL; i<cnt; i++ ) { pks[ i ] = pubkeys[ i ]; writable[ i ] = i<w->rw_cnt; }

  while( !go ) FD_SPIN_PAUSE();

  ulong txn_cnt = 0UL;
  long  busy_ns = 0L;
  while( !stop ) {
    long t0 = fd_log_wallclock();
    for( ulong b=0UL; b<64UL; b++ ) {
      /* Distinct writable accounts from our slice: consecutive from a
         random start, which never wraps into another thread's. */
      ulong start = w->rw_base + fd_rng_ulong_roll( rng, w->rw_span - w->rw_cnt );
      for( ulong i=0UL; i<w->rw_cnt; i++ ) make_pubkey( pubkeys[ i ], start+i );
      ulong ro_start = fd_rng_ulong_roll( rng, w->ro_span - w->ro_cnt + 1UL );
      for( ulong i=0UL; i<w->ro_cnt; i++ ) make_pubkey( pubkeys[ w->rw_cnt+i ], ro_start+i );
      memset( accs, 0, cnt*sizeof(fd_acc_t) );

      fd_accdb_acquire( w->accdb, w->fork, cnt, pks, writable, accs );
      for( ulong i=0UL; i<w->rw_cnt; i++ ) {
        accs[ i ].commit = 1;
        accs[ i ].data[ 0 ]++;
        if( w->data_sz2 ) accs[ i ].data_len = accs[ i ].data_len==w->data_sz ? w->data_sz2 : w->data_sz;
      }
      fd_accdb_release( w->accdb, cnt, accs );
    }
    busy_ns += fd_log_wallclock() - t0;
    txn_cnt += 64UL;
  }

  w->txn_cnt = txn_cnt;
  w->busy_ns = busy_ns;
  fd_rng_delete( fd_rng_leave( rng ) );
  return NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * threads_str = fd_env_strip_cmdline_cstr ( &argc, &argv, "--threads",  NULL, "1,2,4,8,16" );
  ulong duration_ns        = fd_env_strip_cmdline_ulong( &argc, &argv, "--duration", NULL, 3000000000UL );
  ulong rw_cnt             = fd_env_strip_cmdline_ulong( &argc, &argv, "--rw",       NULL, 2UL );
  ulong ro_cnt             = fd_env_strip_cmdline_ulong( &argc, &argv, "--ro",       NULL, 1UL );
  ulong ro_span            = fd_env_strip_cmdline_ulong( &argc, &argv, "--ro-span",  NULL, 4UL );
  ulong per_thread         = fd_env_strip_cmdline_ulong( &argc, &argv, "--per-thread", NULL, 512UL );
  ulong data_sz            = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-sz",  NULL, 165UL );
  ulong data_sz2           = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-sz2", NULL, 0UL );   /* alternate size per write, to change class */
  ulong cache_gib          = fd_env_strip_cmdline_ulong( &argc, &argv, "--cache-gib", NULL, 3UL );
  ulong cpu0               = fd_env_strip_cmdline_ulong( &argc, &argv, "--cpu0",     NULL, ULONG_MAX );
  uint  seed               = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",     NULL, 42U );

  FD_TEST( rw_cnt+ro_cnt<=BENCH_MAX_ACCTS );
  FD_TEST( rw_cnt && rw_cnt<per_thread );
  FD_TEST( ro_cnt<=ro_span );
  FD_TEST( data_sz<=(10UL<<20) && data_sz2<=(10UL<<20) );

  ulong thread_cnts[ BENCH_MAX_THREADS ];
  ulong sweep_cnt = 0UL;
  ulong max_threads = 0UL;
  for( char const * p=threads_str; *p; ) {
    char * end;
    ulong t = strtoul( p, &end, 10 );
    FD_TEST( end!=p && t && t<=BENCH_MAX_THREADS && sweep_cnt<BENCH_MAX_THREADS );
    thread_cnts[ sweep_cnt++ ] = t;
    max_threads = fd_ulong_max( max_threads, t );
    p = *end==',' ? end+1 : end;
  }

  /* Shared accounts first, then one slice per thread. */
  ulong account_cnt = ro_span + max_threads*per_thread;

  FD_LOG_NOTICE(( "accdb scale bench (threads=%s duration=%.1f s rw=%lu ro=%lu of %lu shared, %lu accounts of %lu B per thread, cache %lu GiB)",
                  threads_str, (double)duration_ns/1e9, rw_cnt, ro_cnt, ro_span, per_thread, data_sz, cache_gib ));

  int fd = memfd_create( "accdb_scale", 0 );
  FD_TEST( fd>=0 );

  ulong cache_fp     = cache_gib<<30;
  ulong min_reserved = fd_accdb_cache_min_reserved( 0 );
  ulong joiner_cnt   = max_threads+1UL;
  ulong max_live_slots = 4096UL;
  ulong writes_per_slot = account_cnt+4096UL;
  ulong partition_cnt = 8192UL;
  ulong partition_sz  = 1UL<<30;
  /* The index is sized from max_accounts; sized like mainnet so the
     sequential keys here spread over chains the way real ones do, and
     the chain walk stays out of the measurement (smaller sizes have
     measured up to 30 ns/txn slower). */
  ulong max_accounts  = 1200000000UL;
  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, writes_per_slot, partition_cnt, cache_fp, min_reserved, joiner_cnt, 0UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join( fd_accdb_shmem_new( shmem_mem, max_accounts, max_live_slots, writes_per_slot, partition_cnt, partition_sz, cache_fp, min_reserved, 0, 42UL, joiner_cnt, 0UL ) );
  FD_TEST( shmem );

  fd_accdb_t * joins[ BENCH_MAX_THREADS+1UL ];
  for( ulong i=0UL; i<joiner_cnt; i++ ) {
    void * mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( max_live_slots ) );
    FD_TEST( mem );
    joins[ i ] = fd_accdb_join( fd_accdb_new( mem, shmem, fd, 0UL, NULL ) );
    FD_TEST( joins[ i ] );
  }
  fd_accdb_t * accdb = joins[ max_threads ];

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t fork = fd_accdb_attach_child( accdb, root );

  FD_LOG_NOTICE(( "populating %lu accounts ...", account_cnt ));
  for( ulong i=0UL; i<account_cnt; i++ ) {
    uchar pubkey[ 32 ];
    make_pubkey( pubkey, i );
    uchar const * pks[1] = { pubkey };
    int wr[1] = { 1 };
    fd_acc_t acc[1];
    memset( acc, 0, sizeof(acc) );
    fd_accdb_acquire( accdb, fork, 1UL, pks, wr, acc );
    acc[0].lamports = i+1UL;
    acc[0].data_len = data_sz;
    memcpy( acc[0].owner, dummy_owner, 32UL );
    memset( acc[0].data, (uchar)i, data_sz );
    acc[0].commit = 1;
    fd_accdb_release( accdb, 1UL, acc );
  }

  worker_t  workers[ BENCH_MAX_THREADS ];
  pthread_t threads[ BENCH_MAX_THREADS ];
  double    single = 0.0;

  FD_LOG_NOTICE(( "  %7s %12s %12s %10s %10s", "threads", "txn/s", "ns/txn", "ns/acc", "scaling" ));
  for( ulong s=0UL; s<sweep_cnt; s++ ) {
    ulong T = thread_cnts[ s ];
    go = 0; stop = 0;
    for( ulong t=0UL; t<T; t++ ) {
      workers[ t ] = (worker_t){
        .accdb   = joins[ t ],
        .fork    = fork,
        .idx     = t,
        .cpu     = cpu0==ULONG_MAX ? ULONG_MAX : cpu0+t,
        .rw_cnt  = rw_cnt,
        .ro_cnt  = ro_cnt,
        .rw_base = ro_span + t*per_thread,
        .rw_span = per_thread,
        .ro_span = ro_span,
        .data_sz = data_sz,
        .data_sz2 = data_sz2,
        .seed    = seed + t,
      };
      FD_TEST( !pthread_create( threads+t, NULL, worker_main, workers+t ) );
    }
    /* Let them all reach the gate, then time a fixed window. */
    long t0 = fd_log_wallclock();
    while( fd_log_wallclock()-t0 < 50000000L ) FD_SPIN_PAUSE();
    FD_COMPILER_MFENCE();
    go = 1;
    t0 = fd_log_wallclock();
    while( fd_log_wallclock()-t0 < (long)duration_ns ) FD_SPIN_PAUSE();
    stop = 1;
    FD_COMPILER_MFENCE();

    ulong txn_cnt = 0UL;
    long  busy_ns = 0L;
    for( ulong t=0UL; t<T; t++ ) {
      FD_TEST( !pthread_join( threads[ t ], NULL ) );
      txn_cnt += workers[ t ].txn_cnt;
      busy_ns += workers[ t ].busy_ns;
    }
    double ns_per_txn = (double)busy_ns/(double)txn_cnt;
    if( !s ) single = ns_per_txn;
    FD_LOG_NOTICE(( "  %7lu %12.0f %12.0f %10.0f %9.2fx", T,
                    (double)txn_cnt/((double)duration_ns/1e9),
                    ns_per_txn,
                    ns_per_txn/(double)(rw_cnt+ro_cnt),
                    single/ns_per_txn ));
  }

  close( fd );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
