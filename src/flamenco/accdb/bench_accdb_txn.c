#define _GNU_SOURCE

#include "fd_accdb.h"
#include "../../util/fd_util.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* bench_accdb_txn: Simulate realistic mainnet transaction patterns
   against the accounts database in a tight loop.

   Each simulated transaction acquires a mix of read-only and read-write
   accounts, optionally mutates the writable ones, then releases with
   commit or revert based on measured mainnet failure rates.

   The transaction mix, account counts, data sizes, and commit/revert
   ratios are derived from a 1000-slot mainnet replay
   (slots 406545575-406546575, ~1.24M transactions).

   The benchmark pre-populates a pool of accounts with realistic sizes,
   then runs the acquire/release loop for a configurable duration,
   reporting aggregate throughput.

   This is NOT a full transaction execution benchmark — it purely
   measures the accounts database hot path (cache hits, acquire/release,
   commit/revert) under a realistic workload shape. */

static uchar dummy_owner[ 32 ] = { 0xEE };

/* Maximum data buffer for writes.  Writable accounts need staging
   space; we cap at a reasonable size for the benchmark. */
#define BENCH_MAX_DATA_SZ     (10UL<<20UL)  /* 10 MiB max */
#define BENCH_MAX_ACCTS_PER_TXN (64UL)
#define BENCH_CACHE_FOOTPRINT (16UL<<30UL)

/* Transaction archetype: a representative mix of account access
   patterns observed on mainnet.  Each archetype specifies:
     - ro_cnt / rw_cnt:  number of read-only / read-write accounts
     - ro_data_sz / rw_data_sz:  representative per-account data size
     - weight:  frequency in parts per 10000
     - fail_rate:  failure probability in parts per 10000

   Derived from the per-transaction histograms measured on
   mainnet-406545575-perf (1000 slots, 1.24M txns).  The archetypes
   cover ~99% of observed transactions. */

struct txn_archetype {
  uint ro_cnt;
  uint rw_cnt;
  uint ro_data_sz;  /* representative per-account read-only data size */
  uint rw_data_sz;  /* representative per-account read-write data size */
  uint weight;      /* parts per 10000 */
  uint fail_ppm;    /* failure rate in parts per 10000 */
};

/* Archetypes derived from the histogram data:

   ~62% of txns: 1 RO, 2 RW — simple transfers/token ops
     - RO: mostly <128 B (program accounts)
     - RW: mostly 165-500 B (token accounts)
     - Fail rate: ~0.25% of these (very low)

   ~3% of txns: 2 RO, 2-3 RW — token swaps (simple)
     - RO: 128-512 B
     - RW: 165-512 B
     - Fail rate: ~4%

   ~4% of txns: 4 RO, 4 RW — small DeFi interactions
     - RO: 128-1K
     - RW: 256-1K
     - Fail rate: ~6%

   ~5% of txns: 5-8 RO, 5-8 RW — medium DeFi/AMM swaps
     - RO: 1K-4K per account
     - RW: 512-2K per account
     - Fail rate: ~7%

   ~14% of txns: 12 RO, 12 RW — complex DeFi (Raydium, Orca, etc.)
     - RO: 8K per account (64K-128K total / ~12 accounts)
     - RW: 2K per account (16K-32K total / ~12 accounts)
     - Fail rate: ~27%

   ~9% of txns: 24 RO, 24 RW — very complex DeFi, multi-hop routes
     - RO: 8K per account (128K-256K total / ~24 accounts)
     - RW: 2K per account (32K-64K total / ~24 accounts)
     - Fail rate: ~34%

   ~4% of txns: 2 RO, 48 RW — bulk operations (token-2022, etc.)
     - RO: 128 B
     - RW: 165 B
     - Fail rate: ~17%
*/

static struct txn_archetype const TXN_ARCHETYPES[] = {
  /* ro rw  ro_sz  rw_sz  weight  fail */
  {  0,  1,     0,   165,    300,    25 },  /* single write (baseline) */
  {  1,  2,    82,   165,   5930,    25 },  /* simple transfer/token op */
  {  2,  3,   200,   300,    330,   400 },  /* simple swap */
  {  4,  4,   512,   512,    370,   600 },  /* small DeFi */
  {  6,  6,  2048,  1024,    505,   700 },  /* medium DeFi / AMM */
  { 12, 12,  8192,  2048,   1354,  2700 },  /* complex DeFi (12+12) */
  { 24, 24,  8192,  2048,    891,  3400 },  /* multi-hop DeFi (24+24) */
  {  2, 48,   128,   165,    320,  1700 },  /* bulk operations */
};

#define TXN_ARCHETYPE_CNT (sizeof(TXN_ARCHETYPES)/sizeof(TXN_ARCHETYPES[0]))

static void
make_pubkey( uchar pubkey[ static 32 ],
             ulong idx ) {
  fd_memset( pubkey, 0, 32UL );
  fd_memcpy( pubkey, &idx, sizeof(ulong) );
}

static fd_accdb_t *
bench_setup( int * out_fd,
             ulong max_accounts,
             ulong max_live_slots,
             ulong max_account_writes_per_slot,
             ulong partition_cnt,
             ulong partition_sz ) {
  int fd = memfd_create( "accdb_txn", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));
  *out_fd = fd;

  ulong cache_fp = BENCH_CACHE_FOOTPRINT;
  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots,
                                              max_account_writes_per_slot,
                                              partition_cnt, cache_fp, 640UL, 1UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( shmem_mem, max_accounts, max_live_slots,
                          max_account_writes_per_slot, partition_cnt,
                          partition_sz, cache_fp, 640UL, 42UL, 1UL ) );
  FD_TEST( shmem );

  ulong accdb_fp = fd_accdb_footprint( max_live_slots );
  FD_TEST( accdb_fp );
  void * accdb_mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  FD_TEST( accdb_mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( accdb_mem, shmem, fd, 0UL, NULL ) );
  FD_TEST( accdb );
  return accdb;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong account_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--accounts", NULL, 50000UL );
  ulong duration_ns = fd_env_strip_cmdline_ulong( &argc, &argv, "--duration", NULL, 15000000000UL );
  uint  seed        = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",     NULL, 42U );

  FD_LOG_NOTICE(( "accdb txn-pattern bench"
                  " (accounts=%lu duration=%.1f s seed=%u)",
                  account_cnt, (double)duration_ns/1e9, seed ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  FD_TEST( rng );

  /* Setup */
  int fd;
  ulong partition_sz  = 1UL<<30UL;
  ulong partition_cnt = 8192UL;
  fd_accdb_t * accdb = bench_setup( &fd,
                                    1200000000UL,
                                    4096UL,
                                    (uint)account_cnt + 4096U,
                                    partition_cnt,
                                    partition_sz );

  fd_accdb_fork_id_t root = fd_accdb_attach_child(
      accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t fork = fd_accdb_attach_child( accdb, root );

  /* Pre-populate accounts with a distribution of sizes matching
     mainnet.  Use a weighted mix: most accounts are 165 B (token
     accounts), with some larger ones for DeFi state. */
  FD_LOG_NOTICE(( "populating %lu accounts ...", account_cnt ));
  {
    /* Size distribution for populating: weight/1000, avg_sz */
    static const struct { uint weight; uint sz; } pop_dist[] = {
      { 650, 165 },   /* token accounts */
      { 200,  82 },   /* small / program-derived */
      {  50, 512 },   /* medium state */
      {  40, 2048 },  /* AMM pool state */
      {  40, 8192 },  /* large DeFi state (e.g. Raydium) */
      {  20, 165 },   /* misc */
    };
    ulong pop_dist_cnt = sizeof(pop_dist)/sizeof(pop_dist[0]);

    uchar pubkey[ 32 ];
    for( ulong i=0UL; i<account_cnt; i++ ) {
      make_pubkey( pubkey, i );

      /* Sample size from population distribution */
      uint r = fd_rng_uint( rng ) % 1000U;
      uint cumul = 0U;
      ulong sz = 165UL;
      for( ulong d=0UL; d<pop_dist_cnt; d++ ) {
        cumul += pop_dist[ d ].weight;
        if( r<cumul ) { sz = (ulong)pop_dist[ d ].sz; break; }
      }

      uchar const * pks[1] = { pubkey };
      int wr[1] = { 1 };
      fd_accdb_entry_t ent[1];
      memset( ent, 0, sizeof(ent) );
      fd_accdb_acquire( accdb, fork, 1UL, pks, wr, ent );
      ent[0].lamports = i + 1UL;
      ent[0].data_len = sz;
      memcpy( ent[0].owner, dummy_owner, 32UL );
      memset( ent[0].data, (uchar)(i & 0xFFUL), sz );
      ent[0].commit = 1;
      fd_accdb_release( accdb, 1UL, ent );
    }
  }

  /* Warm: touch every account once to ensure cache residency */
  {
    uchar pubkey[ 32 ];
    for( ulong i=0UL; i<account_cnt; i++ ) {
      make_pubkey( pubkey, i );
      uchar const * pks[1] = { pubkey };
      int wr[1] = { 0 };
      fd_accdb_entry_t ent[1];
      memset( ent, 0, sizeof(ent) );
      fd_accdb_acquire( accdb, fork, 1UL, pks, wr, ent );
      fd_accdb_release( accdb, 1UL, ent );
    }
  }

  FD_LOG_NOTICE(( "populated, starting txn-pattern loop" ));

  /* Baseline: single-account read-only acquire/release for
     comparison with the multi-account txn patterns below. */
  {
    ulong baseline_ops = 0UL;
    long  bl_start     = fd_log_wallclock();
    long  bl_stop      = bl_start + (long)(duration_ns / 5UL); /* 1/5 of total */
    uchar pk[ 32 ];
    while( fd_log_wallclock()<bl_stop ) {
      for( ulong b=0UL; b<1000UL; b++ ) {
        ulong idx = fd_rng_ulong( rng ) % account_cnt;
        make_pubkey( pk, idx );
        uchar const * pks[1] = { pk };
        int wr[1] = { 0 };
        fd_accdb_entry_t ent[1];
        memset( ent, 0, sizeof(ent) );
        fd_accdb_acquire( accdb, fork, 1UL, pks, wr, ent );
        fd_accdb_release( accdb, 1UL, ent );
        baseline_ops++;
      }
    }
    long bl_elapsed = fd_log_wallclock() - bl_start;
    FD_LOG_NOTICE(( "  baseline single-RO: %lu ops in %.3f s"
                    " (%.0f ops/s, %.0f ns/acc)",
                    baseline_ops,
                    (double)bl_elapsed / 1e9,
                    (double)baseline_ops / ( (double)bl_elapsed / 1e9 ),
                    (double)bl_elapsed / (double)baseline_ops ));
  }

  /* Compute cumulative weights for archetype selection */
  uint archetype_cumul[ TXN_ARCHETYPE_CNT ];
  {
    uint sum = 0U;
    for( ulong i=0UL; i<TXN_ARCHETYPE_CNT; i++ ) {
      sum += TXN_ARCHETYPES[ i ].weight;
      archetype_cumul[ i ] = sum;
    }
    /* Normalize: if weights don't sum to 10000 exactly, the last
       bucket catches the remainder. */
  }

  /* Pre-allocate per-txn arrays on the stack. */
  uchar   pubkeys_buf[ BENCH_MAX_ACCTS_PER_TXN ][ 32 ];
  uchar const * pubkey_ptrs[ BENCH_MAX_ACCTS_PER_TXN ];
  int     writable[ BENCH_MAX_ACCTS_PER_TXN ];
  fd_accdb_entry_t entries[ BENCH_MAX_ACCTS_PER_TXN ];

  /* Per-archetype counters for reporting */
  ulong arch_txn_cnt[ TXN_ARCHETYPE_CNT ];
  ulong arch_commit_cnt[ TXN_ARCHETYPE_CNT ];
  long  arch_ns[ TXN_ARCHETYPE_CNT ];
  memset( arch_txn_cnt,    0, sizeof(arch_txn_cnt) );
  memset( arch_commit_cnt, 0, sizeof(arch_commit_cnt) );
  memset( arch_ns,         0, sizeof(arch_ns) );

  ulong txn_cnt  = 0UL;
  long  start    = fd_log_wallclock();
  long  stop     = start + (long)duration_ns;

  while( fd_log_wallclock()<stop ) {
    /* Batch 100 txns between clock checks to amortize syscall */
    for( ulong b=0UL; b<100UL; b++ ) {

      /* 1. Pick a transaction archetype */
      uint r = fd_rng_uint( rng ) % 10000U;
      ulong arch_idx = 0UL;
      for( ulong i=0UL; i<TXN_ARCHETYPE_CNT; i++ ) {
        if( r<archetype_cumul[ i ] ) { arch_idx = i; break; }
      }
      struct txn_archetype const * arch = &TXN_ARCHETYPES[ arch_idx ];

      ulong total_cnt = (ulong)arch->ro_cnt + (ulong)arch->rw_cnt;

      /* 2. Pick unique random accounts for this txn.
            RW accounts come first, then RO accounts. */
      for( ulong i=0UL; i<total_cnt; i++ ) {
        ulong idx = fd_rng_ulong( rng ) % account_cnt;
        make_pubkey( pubkeys_buf[ i ], idx );
        pubkey_ptrs[ i ] = pubkeys_buf[ i ];
        writable[ i ] = ( i < (ulong)arch->rw_cnt ) ? 1 : 0;
      }
      memset( entries, 0, total_cnt * sizeof(fd_accdb_entry_t) );

      /* 3. Acquire */
      long t0 = fd_log_wallclock();
      fd_accdb_acquire( accdb, fork, total_cnt,
                        pubkey_ptrs, writable, entries );

      /* 4. Decide commit or revert */
      int do_commit = ( (fd_rng_uint( rng ) % 10000U) >= arch->fail_ppm );

      /* 5. For writable entries, set commit flag and touch data */
      for( ulong i=0UL; i<(ulong)arch->rw_cnt; i++ ) {
        entries[ i ].commit = do_commit;
        if( do_commit && entries[ i ].data ) {
          /* Touch a byte to simulate mutation */
          entries[ i ].data[ 0 ] ^= 0x01;
        }
      }

      /* 6. Release */
      fd_accdb_release( accdb, total_cnt, entries );
      long t1 = fd_log_wallclock();

      arch_txn_cnt[ arch_idx ]++;
      arch_commit_cnt[ arch_idx ] += (ulong)do_commit;
      arch_ns[ arch_idx ] += ( t1 - t0 );
      txn_cnt++;
    }
  }

  long elapsed = fd_log_wallclock() - start;
  double secs  = (double)elapsed / 1e9;

  /* Report per-archetype results */
  FD_LOG_NOTICE(( "--- bench_accdb_txn results"
                  " (%lu txns in %.3f s, %.0f txn/s) ---",
                  txn_cnt, secs, (double)txn_cnt / secs ));
  FD_LOG_NOTICE(( "  %-6s %4s %4s %7s %10s %8s %10s %10s %10s",
                  "Arch", "RO", "RW", "Wt%", "Txns", "Commit%",
                  "Txn/s", "ns/txn", "ns/acc" ));

  ulong total_commit = 0UL;
  ulong total_accts  = 0UL;
  for( ulong i=0UL; i<TXN_ARCHETYPE_CNT; i++ ) {
    if( !arch_txn_cnt[ i ] ) continue;
    total_commit += arch_commit_cnt[ i ];
    ulong accts_per_txn = (ulong)TXN_ARCHETYPES[ i ].ro_cnt
                        + (ulong)TXN_ARCHETYPES[ i ].rw_cnt;
    ulong arch_total_accts = arch_txn_cnt[ i ] * accts_per_txn;
    total_accts += arch_total_accts;
    double a_secs = (double)arch_ns[ i ] / 1e9;
    FD_LOG_NOTICE(( "  %-6lu %4u %4u %6.1f%% %10lu %7.2f%% %10.0f %10.0f %10.0f",
                    i,
                    TXN_ARCHETYPES[ i ].ro_cnt,
                    TXN_ARCHETYPES[ i ].rw_cnt,
                    (double)TXN_ARCHETYPES[ i ].weight / 100.0,
                    arch_txn_cnt[ i ],
                    100.0 * (double)arch_commit_cnt[ i ]
                          / (double)arch_txn_cnt[ i ],
                    (double)arch_txn_cnt[ i ] / a_secs,
                    (double)arch_ns[ i ]
                          / (double)arch_txn_cnt[ i ],
                    (double)arch_ns[ i ]
                          / (double)arch_total_accts ));
  }

  FD_LOG_NOTICE(( "  TOTAL: %lu txns, %.2f%% committed, "
                  "%.0f txn/s, %.0f ns/txn, %.0f ns/acc",
                  txn_cnt,
                  100.0 * (double)total_commit / (double)txn_cnt,
                  (double)txn_cnt / secs,
                  (double)elapsed / (double)txn_cnt,
                  (double)elapsed / (double)total_accts ));

  /* Compute mainnet-weighted average ns/acc from per-archetype
     measurements and the archetype weights. */
  {
    double weighted_ns_per_acc = 0.0;
    double weight_sum          = 0.0;
    for( ulong i=0UL; i<TXN_ARCHETYPE_CNT; i++ ) {
      if( !arch_txn_cnt[ i ] ) continue;
      ulong accts_per_txn = (ulong)TXN_ARCHETYPES[ i ].ro_cnt
                          + (ulong)TXN_ARCHETYPES[ i ].rw_cnt;
      double ns_per_acc = (double)arch_ns[ i ]
                        / (double)( arch_txn_cnt[ i ] * accts_per_txn );
      double w = (double)TXN_ARCHETYPES[ i ].weight;
      double accts_w = w * (double)accts_per_txn;
      weighted_ns_per_acc += ns_per_acc * accts_w;
      weight_sum          += accts_w;
    }
    if( weight_sum>0.0 ) {
      FD_LOG_NOTICE(( "  Mainnet-weighted avg: %.0f ns/acc"
                      " (weighted by archetype frequency"
                      " x accounts per txn)",
                      weighted_ns_per_acc / weight_sum ));
    }
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  close( fd );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
