#define _GNU_SOURCE

#include "fd_accdb.h"
#include "../../util/fd_util.h"

#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* bench_accdb_mt: the accdb acquire/release hot path under many
   concurrent joins, the way exec tiles drive it.

   N worker threads, each with its own accdb join, run a transaction mix
   against one shared accdb on one fork: acquire read-only and writable
   accounts, mutate the writable ones, release with commit or revert.
   As the replay scheduler guarantees (fd_accdb.h), a writable acquire
   of an account never overlaps another acquire of it: each worker
   writes only its own partition of the accounts, and reads either its
   own partition, a shared range that is never written, or the shared
   hot read-only accounts.  A background thread runs
   fd_accdb_background.

   --accounts      total accounts (default 1M)
   --threads       worker thread counts to sweep, e.g. 1,4,8,15
                   (default 4); every step reuses the same accdb
   --duration      seconds per step (default 10)
   --cache-gib     cache size, fractional allowed (default 4); a
                   working set larger than the cache exercises CLOCK
                   eviction and write-back
   --cpu0          first CPU workers are pinned to (default 1; the
                   background thread runs on cpu0-1)
   --mix           "transfer" (1 RO + 2 RW accounts) or "mainnet" (the
                   account counts and failure rates of bench_accdb_txn's
                   mainnet mix); every account is BENCH_DATA_SZ bytes
   --ro-hot N      N read-only accounts shared by every thread: every
                   read-only acquire comes from them (as far as the
                   txn's read-only count allows), like a few hot
                   programs (default 0: off)
   --per-thread N  each thread writes its own N accounts (default 0:
                   the threads split --accounts); --accounts is then
                   ro-hot + max threads * N
   --data-sz2 B    every committed write alternates the account between
                   BENCH_DATA_SZ and B bytes, so each release changes
                   size class (default 0: off)
   --preset hot    transfer mix, 4 hot read-only accounts, 512 accounts
                   per thread, 3 GiB cache: everything stays cached, so
                   it measures only what the threads share

   Reports per step total txn/s, per-thread acquire+release ns/txn,
   throughput speedup over the first step (perfect scaling from 1
   thread reads as the thread count), acquire/release ns per account
   and reservation retries (acquire_failed). */

static uchar dummy_owner[ 32 ] = { 0xEE };

#define BENCH_DATA_SZ           (165UL)
#define BENCH_MAX_ACCTS_PER_TXN (64UL)
#define BENCH_MAX_THREADS       (64UL)
#define BENCH_MAX_LIVE_SLOTS    (64UL)
#define BENCH_PARTITION_CNT     (8192UL)
#define BENCH_PARTITION_SZ      (1UL<<30UL)
#define BENCH_MIN_RESERVED      (192UL)

/* Transaction archetype: ro_cnt read-only and rw_cnt writable
   accounts, picked with frequency weight (parts per 10000), reverted
   with probability fail (parts per 10000). */

struct txn_archetype {
  uint ro_cnt;
  uint rw_cnt;
  uint weight;
  uint fail;
};

typedef struct txn_archetype txn_archetype_t;

/* The account counts and failure rates of bench_accdb_txn's mainnet
   archetypes. */

static txn_archetype_t const MIX_MAINNET[] = {
  /* ro rw weight  fail */
  {  0,  1,   300,   25 },  /* single write */
  {  1,  2,  5930,   25 },  /* simple transfer/token op */
  {  2,  3,   330,  400 },  /* simple swap */
  {  4,  4,   370,  600 },  /* small DeFi */
  {  6,  6,   505,  700 },  /* medium DeFi / AMM */
  { 12, 12,  1354, 2700 },  /* complex DeFi */
  { 24, 24,   891, 3400 },  /* multi-hop DeFi */
  {  2, 48,   320, 1700 },  /* bulk operations */
};

static txn_archetype_t const MIX_TRANSFER[] = {
  /* ro rw weight  fail */
  {  1,  2, 10000,    0 },
};

#define MIX_MAINNET_CNT  (sizeof(MIX_MAINNET)/sizeof(MIX_MAINNET[0]))
#define MIX_TRANSFER_CNT (sizeof(MIX_TRANSFER)/sizeof(MIX_TRANSFER[0]))
#define MIX_MAX          (8UL)

/* Shared state, read by the workers.  Set before they start, except
   g_go and g_stop, which are only accessed with FD_VOLATILE. */

static txn_archetype_t const * g_mix;
static ulong                   g_mix_cnt;
static ulong                   g_accounts;
static ulong                   g_threads;
static ulong                   g_ro0;        /* accounts [g_ro0,g_accounts) are never written */
static ulong                   g_ro_hot;     /* accounts [0,g_ro_hot) are shared read-only */
static ulong                   g_per_thread;
static ulong                   g_data_sz2;
static ulong                   g_cpu0;
static fd_accdb_fork_id_t      g_fork;
static int                     g_go;
static int                     g_stop;

static void
make_pubkey( uchar pubkey[ static 32 ],
             ulong idx ) {
  fd_memset( pubkey, 0, 32UL );
  FD_STORE( ulong, pubkey,     idx                 );
  FD_STORE( ulong, pubkey+8UL, fd_ulong_hash( idx ) );
}

static void
pin_cpu( ulong cpu ) {
  cpu_set_t set;
  CPU_ZERO( &set );
  CPU_SET( cpu, &set );
  if( FD_UNLIKELY( pthread_setaffinity_np( pthread_self(), sizeof(set), &set ) ) ) FD_LOG_WARNING(( "could not pin to cpu %lu", cpu ));
}

struct __attribute__((aligned(64))) worker {
  ulong        idx;
  fd_accdb_t * accdb;

  ulong        txn_cnt;
  ulong        acc_cnt;
  long         acquire_ticks;
  long         release_ticks;
};

typedef struct worker worker_t;

static void *
worker_main( void * arg ) {
  worker_t * w = (worker_t *)arg;
  pin_cpu( g_cpu0+w->idx );

  fd_rng_t   _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)( 1000UL+w->idx ), 0UL ) );

  /* This worker writes [part0,part0+part). */
  ulong part  = g_per_thread ? g_per_thread : ( g_ro0-g_ro_hot )/g_threads;
  ulong part0 = g_ro_hot + w->idx*part;

  uint cumul[ MIX_MAX ];
  uint sum = 0U;
  for( ulong i=0UL; i<g_mix_cnt; i++ ) {
    sum       += g_mix[ i ].weight;
    cumul[ i ] = sum;
  }

  uchar         pubkeys [ BENCH_MAX_ACCTS_PER_TXN ][ 32 ];
  uchar const * pks     [ BENCH_MAX_ACCTS_PER_TXN ];
  ulong         ids     [ BENCH_MAX_ACCTS_PER_TXN ];
  int           writable[ BENCH_MAX_ACCTS_PER_TXN ];
  fd_acc_t      accs    [ BENCH_MAX_ACCTS_PER_TXN ];
  for( ulong i=0UL; i<BENCH_MAX_ACCTS_PER_TXN; i++ ) pks[ i ] = pubkeys[ i ];

  while( !FD_VOLATILE_CONST( g_go ) ) FD_SPIN_PAUSE();

  while( !FD_VOLATILE_CONST( g_stop ) ) {
    uint  r = fd_rng_uint( rng )%sum;
    ulong a = 0UL;
    while( r>=cumul[ a ] ) a++;
    txn_archetype_t const * arch = &g_mix[ a ];
    ulong rw_cnt = (ulong)arch->rw_cnt;
    ulong cnt    = rw_cnt + (ulong)arch->ro_cnt;

    /* Distinct accounts within a txn: writable ones from our
       partition, read-only ones from the hot set first, then the
       never-written range or our partition. */
    for( ulong i=0UL; i<cnt; i++ ) {
      ulong id;
      for(;;) {
        if(      i<rw_cnt                  ) id = part0 + fd_rng_ulong( rng )%part;
        else if( i-rw_cnt<g_ro_hot         ) id = fd_rng_ulong( rng )%g_ro_hot;
        else if( g_ro0<g_accounts &&
                 ( fd_rng_uint( rng )&1U ) ) id = g_ro0 + fd_rng_ulong( rng )%( g_accounts-g_ro0 );
        else                                 id = part0 + fd_rng_ulong( rng )%part;
        int dup = 0;
        for( ulong j=0UL; j<i; j++ ) dup |= ids[ j ]==id;
        if( FD_LIKELY( !dup ) ) break;
      }
      ids[ i ] = id;
      make_pubkey( pubkeys[ i ], id );
      writable[ i ] = i<rw_cnt;
    }
    memset( accs, 0, cnt*sizeof(fd_acc_t) );

    long tacq_start = fd_tickcount();
    fd_accdb_acquire( w->accdb, g_fork, cnt, pks, writable, accs );
    long tacq = fd_tickcount()-tacq_start;

    int commit = ( fd_rng_uint( rng )%10000U )>=arch->fail;
    for( ulong i=0UL; i<rw_cnt; i++ ) {
      accs[ i ].commit = commit;
      if( !commit ) continue;
      if( FD_LIKELY( accs[ i ].data && accs[ i ].data_len ) ) accs[ i ].data[ 0 ] ^= 1;
      if( g_data_sz2 ) accs[ i ].data_len = accs[ i ].data_len==g_data_sz2 ? BENCH_DATA_SZ : g_data_sz2;
    }

    long trel_start = fd_tickcount();
    fd_accdb_release( w->accdb, cnt, accs );
    long trel = fd_tickcount()-trel_start;

    w->txn_cnt++;
    w->acc_cnt += cnt;
    w->acquire_ticks += tacq;
    w->release_ticks += trel;
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  return NULL;
}

static void *
background_main( void * arg ) {
  fd_accdb_t * accdb = (fd_accdb_t *)arg;
  pin_cpu( g_cpu0 ? g_cpu0-1UL : 0UL );
  while( !FD_VOLATILE_CONST( g_stop ) ) {
    int charge_busy = 0;
    fd_accdb_background( accdb, &charge_busy );
    if( !charge_busy ) FD_SPIN_PAUSE();
  }
  return NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * preset = fd_env_strip_cmdline_cstr( &argc, &argv, "--preset", NULL, "" );
  int hot = !strcmp( preset, "hot" );
  if( FD_UNLIKELY( preset[0] && !hot ) ) FD_LOG_ERR(( "unknown --preset %s", preset ));

  g_accounts               = fd_env_strip_cmdline_ulong ( &argc, &argv, "--accounts",   NULL, 1000000UL           );
  char const * threads_str = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--threads",    NULL, "4"                 );
  ulong        duration_s  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--duration",   NULL, 10UL                );
  double       cache_gib   = fd_env_strip_cmdline_double( &argc, &argv, "--cache-gib",  NULL, hot ? 3.0   : 4.0   );
  g_cpu0                   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--cpu0",       NULL, 1UL                 );
  char const * mix         = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--mix",        NULL, "transfer"          );
  g_ro_hot                 = fd_env_strip_cmdline_ulong ( &argc, &argv, "--ro-hot",     NULL, hot ? 4UL   : 0UL   );
  g_per_thread             = fd_env_strip_cmdline_ulong ( &argc, &argv, "--per-thread", NULL, hot ? 512UL : 0UL   );
  g_data_sz2               = fd_env_strip_cmdline_ulong ( &argc, &argv, "--data-sz2",   NULL, 0UL                 );

  if(      !strcmp( mix, "mainnet"  ) ) { g_mix = MIX_MAINNET;  g_mix_cnt = MIX_MAINNET_CNT;  }
  else if( !strcmp( mix, "transfer" ) ) { g_mix = MIX_TRANSFER; g_mix_cnt = MIX_TRANSFER_CNT; }
  else FD_LOG_ERR(( "unknown --mix %s", mix ));
  FD_TEST( g_mix_cnt<=MIX_MAX );
  FD_TEST( g_data_sz2<=(10UL<<20UL) );

  ulong sweep[ BENCH_MAX_THREADS ];
  ulong sweep_cnt   = 0UL;
  ulong max_threads = 0UL;
  for( char const * p=threads_str; *p; ) {
    char * end;
    ulong  t = strtoul( p, &end, 10 );
    FD_TEST( end!=p && t && t<=BENCH_MAX_THREADS && sweep_cnt<BENCH_MAX_THREADS );
    sweep[ sweep_cnt++ ] = t;
    max_threads = fd_ulong_max( max_threads, t );
    p = *end==',' ? end+1 : end;
  }

  /* Each txn picks distinct accounts: its writable ones and the
     read-only ones beyond the hot set may all come from the worker's
     partition, so the partition must hold that many for every
     archetype (else the duplicate-rejection loop never ends). */
  ulong max_part_cnt = 0UL;
  for( ulong i=0UL; i<g_mix_cnt; i++ ) {
    ulong ro_cold = (ulong)g_mix[ i ].ro_cnt - fd_ulong_min( (ulong)g_mix[ i ].ro_cnt, g_ro_hot );
    max_part_cnt = fd_ulong_max( max_part_cnt, (ulong)g_mix[ i ].rw_cnt + ro_cold );
  }
  if( g_per_thread ) {
    /* Hot read-only accounts, then one partition per thread; no
       never-written range. */
    if( FD_UNLIKELY( g_per_thread<max_part_cnt ) ) FD_LOG_ERR(( "--per-thread %lu < %lu accounts some txn needs", g_per_thread, max_part_cnt ));
    g_accounts = g_ro_hot + max_threads*g_per_thread;
    g_ro0      = g_accounts;
  } else {
    g_ro0 = g_accounts - g_accounts/8UL;
    if( FD_UNLIKELY( g_ro0<=g_ro_hot || ( g_ro0-g_ro_hot )/max_threads<max_part_cnt ) )
      FD_LOG_ERR(( "--accounts %lu too small: partitions need %lu accounts each", g_accounts, max_part_cnt ));
  }

  int fd = memfd_create( "accdb_mt", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));

  ulong cache_fp     = (ulong)( cache_gib*(double)(1UL<<30UL) );
  ulong joiner_cnt   = max_threads+2UL;
  ulong max_accounts = 2UL*g_accounts;
  ulong writes       = g_accounts+4096UL;
  ulong shmem_fp     = fd_accdb_shmem_footprint( max_accounts, BENCH_MAX_LIVE_SLOTS, writes, BENCH_PARTITION_CNT,
                                                 cache_fp, BENCH_MIN_RESERVED, joiner_cnt, 0UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = mmap( NULL, shmem_fp, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0 );
  FD_TEST( shmem_mem!=MAP_FAILED );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( shmem_mem, max_accounts, BENCH_MAX_LIVE_SLOTS, writes, BENCH_PARTITION_CNT,
                          BENCH_PARTITION_SZ, cache_fp, BENCH_MIN_RESERVED, 0, 42UL, joiner_cnt, 0UL ) );
  FD_TEST( shmem );

  /* One join per worker, plus the background join (compaction). */
  fd_accdb_t * joins[ BENCH_MAX_THREADS+1UL ];
  for( ulong i=0UL; i<=max_threads; i++ ) {
    int    compaction = i==max_threads;
    void * mem        = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( BENCH_MAX_LIVE_SLOTS, compaction ) );
    FD_TEST( mem );
    joins[ i ] = fd_accdb_join( fd_accdb_new( mem, shmem, fd, 0UL, NULL, NULL, 0UL, compaction ) );
    FD_TEST( joins[ i ] );
  }
  fd_accdb_t * bg = joins[ max_threads ];

  /* Populate on a fork, root it (hot accounts are normally rooted), and
     run on a child. */
  fd_accdb_fork_id_t root = fd_accdb_attach_child( joins[ 0 ], (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  g_fork = fd_accdb_attach_child( joins[ 0 ], root );
  FD_LOG_NOTICE(( "populating %lu accounts ...", g_accounts ));
  for( ulong i=0UL; i<g_accounts; i++ ) {
    uchar pubkey[ 32 ];
    make_pubkey( pubkey, i );
    uchar const * pks[1] = { pubkey };
    int           wr [1] = { 1 };
    fd_acc_t      acc[1];
    memset( acc, 0, sizeof(acc) );
    fd_accdb_acquire( joins[ 0 ], g_fork, 1UL, pks, wr, acc );
    acc[0].lamports = i+1UL;
    acc[0].data_len = BENCH_DATA_SZ;
    memcpy( acc[0].owner, dummy_owner, 32UL );
    memset( acc[0].data, (uchar)i, BENCH_DATA_SZ );
    acc[0].commit = 1;
    fd_accdb_release( joins[ 0 ], 1UL, acc );
  }
  fd_accdb_advance_root( joins[ 0 ], g_fork );
  for( ulong i=0UL; i<64UL; i++ ) {
    int charge_busy = 0;
    fd_accdb_background( bg, &charge_busy );
  }
  g_fork = fd_accdb_attach_child( joins[ 0 ], g_fork );

  /* Ticks per ns, to convert the workers' tick counts. */
  long   cal_ns0     = fd_log_wallclock();
  long   cal_ticks0  = fd_tickcount();
  while( fd_log_wallclock()-cal_ns0<20000000L ) FD_SPIN_PAUSE();
  double tick_per_ns = (double)( fd_tickcount()-cal_ticks0 )/(double)( fd_log_wallclock()-cal_ns0 );

  worker_t * workers = aligned_alloc( alignof(worker_t), BENCH_MAX_THREADS*sizeof(worker_t) );
  FD_TEST( workers );
  pthread_t threads[ BENCH_MAX_THREADS ];
  double    tps0 = 0.0;

  for( ulong s=0UL; s<sweep_cnt; s++ ) {
    g_threads = sweep[ s ];
    FD_VOLATILE( g_go   ) = 0;
    FD_VOLATILE( g_stop ) = 0;

    ulong failed0 = 0UL;
    for( ulong i=0UL; i<g_threads; i++ ) failed0 += fd_accdb_metrics( joins[ i ] )->acquire_failed;

    pthread_t bg_thread;
    FD_TEST( !pthread_create( &bg_thread, NULL, background_main, bg ) );
    memset( workers, 0, g_threads*sizeof(worker_t) );
    for( ulong i=0UL; i<g_threads; i++ ) {
      workers[ i ].idx   = i;
      workers[ i ].accdb = joins[ i ];
      FD_TEST( !pthread_create( &threads[ i ], NULL, worker_main, &workers[ i ] ) );
    }

    long start = fd_log_wallclock();
    FD_VOLATILE( g_go ) = 1;
    while( fd_log_wallclock()-start<(long)duration_s*1000000000L ) usleep( 10000 );
    FD_VOLATILE( g_stop ) = 1;
    long elapsed = fd_log_wallclock()-start;
    for( ulong i=0UL; i<g_threads; i++ ) FD_TEST( !pthread_join( threads[ i ], NULL ) );
    FD_TEST( !pthread_join( bg_thread, NULL ) );

    ulong  txn_cnt       = 0UL;
    ulong  acc_cnt       = 0UL;
    ulong  failed        = 0UL;
    double acquire_ticks = 0.0;
    double release_ticks = 0.0;
    for( ulong i=0UL; i<g_threads; i++ ) {
      txn_cnt       += workers[ i ].txn_cnt;
      acc_cnt       += workers[ i ].acc_cnt;
      acquire_ticks += (double)workers[ i ].acquire_ticks;
      release_ticks += (double)workers[ i ].release_ticks;
      failed        += fd_accdb_metrics( joins[ i ] )->acquire_failed;
    }
    double secs   = (double)elapsed/1e9;
    double ns_txn = ( acquire_ticks+release_ticks )/tick_per_ns/(double)txn_cnt; /* per thread */
    double tps    = (double)txn_cnt/secs;
    if( !s ) tps0 = tps;
    FD_LOG_NOTICE(( "RESULT mix=%s threads=%lu accounts=%lu cache_gib=%.2f ro_hot=%lu per_thread=%lu data_sz2=%lu: "
                    "%.0f txn/s, per thread %.0f txn/s, %.0f ns/txn, scaling %.2fx, acquire %.0f ns/acc, release %.0f ns/acc, reserve retries %lu",
                    mix, g_threads, g_accounts, cache_gib, g_ro_hot, g_per_thread, g_data_sz2,
                    tps, tps/(double)g_threads, ns_txn, tps/tps0,
                    acquire_ticks/tick_per_ns/(double)acc_cnt, release_ticks/tick_per_ns/(double)acc_cnt, failed-failed0 ));
  }

  free( workers );
  for( ulong i=0UL; i<=max_threads; i++ ) free( joins[ i ] );
  munmap( shmem_mem, shmem_fp );
  close( fd );
  fd_halt();
  return 0;
}
