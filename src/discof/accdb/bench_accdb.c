#define _GNU_SOURCE

#include "fd_accdb.h"
#include "../../util/fd_util.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* Account size distribution modeled from Solana mainnet snapshot data.
   ~996M accounts, ~285.5 GiB total.  The cumulative distribution
   function (CDF) is encoded as a table of (threshold, avg_size) pairs
   so we can sample sizes that match real-world distribution.

   Key characteristics:
     - 65% of accounts are 128-256 bytes (token accounts, 165 B)
     - 91% of accounts are <= 256 bytes
     - 99% of accounts are <= 1024 bytes
     - Tail goes up to 10 MiB

   Weights below are parts-per-thousand (permille).  They sum to
   1000 and are derived from the bin_cnt column of the histogram. */

struct size_bucket {
  uint weight;   /* permille (parts per 1000) */
  uint avg_size; /* representative size for this bucket */
};

static struct size_bucket const SIZE_DIST[] = {
  {  76,      0 },  /*   0 <= sz <=    0 :  7.6% */
  {  33,      1 },  /*   0 <  sz <=    1 :  0.3% (cumul  7.9%) — grouped small */
  {   5,      2 },  /*   1 <  sz <=    2 */
  {   4,      3 },  /*   2 <  sz <=    4 */
  {   2,      7 },  /*   4 <  sz <=    8 */
  {   8,     12 },  /*   8 <  sz <=   16 */
  {  31,     22 },  /*  16 <  sz <=   32 */
  {  27,     51 },  /*  32 <  sz <=   64 */
  { 113,     88 },  /*  64 <  sz <=  128 */
  { 653,    165 },  /* 128 <  sz <=  256 : 65.3% — token accounts */
  {  20,    347 },  /* 256 <  sz <=  512 */
  {  14,    638 },  /* 512 <  sz <= 1024 — kept small so bench runs fast */
  /*  remaining ~1.2% grouped into larger buckets, but omitted for
      benchmark speed.  We add the remaining weight to the 638 bucket
      above so weights sum to ~1000. */
};

#define SIZE_DIST_CNT (sizeof(SIZE_DIST)/sizeof(SIZE_DIST[0]))

static ulong
sample_account_size( fd_rng_t * rng ) {
  uint r = fd_rng_uint( rng ) % 1000U;
  uint cumul = 0U;
  for( ulong i=0UL; i<SIZE_DIST_CNT; i++ ) {
    cumul += SIZE_DIST[ i ].weight;
    if( r<cumul ) return (ulong)SIZE_DIST[ i ].avg_size;
  }
  return 165UL; /* fallback: token account */
}

/* Generate a random pubkey from an index.  The index is encoded into
   the first 8 bytes so that each index produces a unique pubkey, while
   the rest is zeroed for reproducibility. */
static void
make_pubkey( uchar pubkey[ static 32 ],
             ulong idx ) {
  fd_memset( pubkey, 0, 32UL );
  fd_memcpy( pubkey, &idx, sizeof(ulong) );
}

static uchar dummy_owner[ 32 ] = { 0xEE };

/* Maximum account data size used in the benchmark.  We cap at 1024
   to keep I/O reasonable; the long tail is rare on mainnet anyway. */
#define BENCH_MAX_DATA_SZ (1024UL)

static uchar data_buf[ BENCH_MAX_DATA_SZ ];

static fd_accdb_t *
bench_setup( int * out_fd,
             ulong max_accounts,
             ulong max_live_slots,
             ulong max_account_writes_per_slot,
             ulong partition_cnt,
             ulong partition_sz ) {
  int fd = memfd_create( "accdb_bench", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));
  *out_fd = fd;

  ulong fp = fd_accdb_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt );
  FD_TEST( fp );
  void * mem = aligned_alloc( fd_accdb_align(), fp );
  FD_TEST( mem );
  fd_accdb_t * accdb = fd_accdb_join(
    fd_accdb_new( mem, max_accounts, max_live_slots,
                  max_account_writes_per_slot, partition_cnt, partition_sz, 42UL ),
    fd );
  FD_TEST( accdb );
  return accdb;
}

/* ------------------------------------------------------------------ */

/* bench_write: Populate N accounts on a single fork, measuring write
   throughput.  Account sizes are sampled from the mainnet distribution
   so the I/O pattern is realistic. */
static void
bench_write( ulong   account_cnt,
             fd_rng_t * rng ) {
  int fd;
  ulong partition_sz = 1UL<<30UL;
  ulong partition_cnt = 1024UL;
  fd_accdb_t * accdb = bench_setup( &fd,
                                    account_cnt + 1024UL,
                                    64UL,
                                    (uint)account_cnt + 1024U,
                                    partition_cnt,
                                    partition_sz );

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t fork  = fd_accdb_attach_child( accdb, root );

  uchar pubkey[ 32 ];
  ulong total_bytes = 0UL;

  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<account_cnt; i++ ) {
    make_pubkey( pubkey, i );
    ulong sz = sample_account_size( rng );
    if( sz>BENCH_MAX_DATA_SZ ) sz = BENCH_MAX_DATA_SZ;
    fd_accdb_write( accdb, fork, pubkey, i+1UL,
                    sz ? data_buf : NULL, sz, dummy_owner );
    total_bytes += sz;
  }
  dt += fd_log_wallclock();

  double secs = (double)dt / 1e9;
  FD_LOG_NOTICE(( "bench_write: %lu accounts, %.2f MiB data in %.3f s "
                  "(%.0f accts/s, %.2f MiB/s, %.0f ns/write)",
                  account_cnt,
                  (double)total_bytes / (double)(1UL<<20UL),
                  secs,
                  (double)account_cnt / secs,
                  (double)total_bytes / (double)(1UL<<20UL) / secs,
                  (double)dt / (double)account_cnt ));

  close( fd );
}

/* ------------------------------------------------------------------ */

/* bench_read: Populate N accounts, then read them all back in random
   order, measuring read throughput. */
static void
bench_read( ulong   account_cnt,
            fd_rng_t * rng ) {
  int fd;
  ulong partition_sz = 1UL<<30UL;
  ulong partition_cnt = 1024UL;
  fd_accdb_t * accdb = bench_setup( &fd,
                                    account_cnt + 1024UL,
                                    64UL,
                                    (uint)account_cnt + 1024U,
                                    partition_cnt,
                                    partition_sz );

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t fork  = fd_accdb_attach_child( accdb, root );

  /* Populate */
  uchar pubkey[ 32 ];
  for( ulong i=0UL; i<account_cnt; i++ ) {
    make_pubkey( pubkey, i );
    ulong sz = sample_account_size( rng );
    if( sz>BENCH_MAX_DATA_SZ ) sz = BENCH_MAX_DATA_SZ;
    fd_accdb_write( accdb, fork, pubkey, i+1UL,
                    sz ? data_buf : NULL, sz, dummy_owner );
  }

  /* Read in random order */
  ulong  lamports;
  uchar  rdata[ BENCH_MAX_DATA_SZ ];
  ulong  data_len;
  uchar  owner[ 32 ];
  ulong  total_bytes = 0UL;
  ulong  found = 0UL;

  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<account_cnt; i++ ) {
    ulong idx = fd_rng_ulong( rng ) % account_cnt;
    make_pubkey( pubkey, idx );
    if( fd_accdb_read( accdb, fork, pubkey, &lamports,
                       rdata, &data_len, owner ) ) {
      total_bytes += data_len;
      found++;
    }
  }
  dt += fd_log_wallclock();

  double secs = (double)dt / 1e9;
  FD_LOG_NOTICE(( "bench_read:  %lu reads (%lu hit), %.2f MiB in %.3f s "
                  "(%.0f reads/s, %.2f MiB/s, %.0f ns/read)",
                  account_cnt, found,
                  (double)total_bytes / (double)(1UL<<20UL),
                  secs,
                  (double)account_cnt / secs,
                  (double)total_bytes / (double)(1UL<<20UL) / secs,
                  (double)dt / (double)account_cnt ));

  close( fd );
}

/* ------------------------------------------------------------------ */

/* bench_replay: Simulate a realistic replay workload.  Each slot
   consists of ~reads_per_slot read queries followed by
   ~writes_per_slot account updates, then the previous slot is
   rooted.  This mirrors actual replay where each transaction reads
   several accounts (programs, signers, state) before writing back
   a smaller set.

   On mainnet a typical slot has ~1200 transactions, each touching
   ~5-10 accounts for reads and ~2-4 for writes.  The default
   parameterization captures this: 1200 writes/slot with 4x as
   many reads.

   Timing is tracked separately for reads, writes, and rooting to
   identify bottlenecks. */
static void
bench_replay( ulong   slot_cnt,
              ulong   writes_per_slot,
              ulong   reads_per_slot,
              fd_rng_t * rng ) {
  int fd;
  ulong total_accounts = slot_cnt * writes_per_slot + 1024UL;
  ulong partition_sz  = 1UL<<30UL;
  ulong partition_cnt = 1024UL;
  ulong max_live      = 64UL;
  fd_accdb_t * accdb = bench_setup( &fd,
                                    total_accounts,
                                    max_live,
                                    writes_per_slot + 16UL,
                                    partition_cnt,
                                    partition_sz );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );

  uchar pubkey[ 32 ];

  /* We re-use a pool of pubkeys so that rooting has old versions to
     tombstone (realistic for hot accounts like token program,
     system program, fee payers, etc.). */
  ulong pubkey_pool_sz = writes_per_slot * 4UL;

  ulong total_reads       = 0UL;
  ulong total_read_hits   = 0UL;
  ulong total_writes      = 0UL;
  ulong total_write_bytes = 0UL;
  long  dt_read           = 0;
  long  dt_write          = 0;
  long  dt_root           = 0;

  uchar  rdata[ BENCH_MAX_DATA_SZ ];
  ulong  lamports;
  ulong  data_len;
  uchar  owner[ 32 ];

  long dt_total = -fd_log_wallclock();
  fd_accdb_fork_id_t prev = root;
  for( ulong s=0UL; s<slot_cnt; s++ ) {
    fd_accdb_fork_id_t cur = fd_accdb_attach_child( accdb, prev );

    /* --- reads (simulate transaction account loading) --- */
    long t0 = fd_log_wallclock();
    for( ulong r=0UL; r<reads_per_slot; r++ ) {
      ulong idx = fd_rng_ulong( rng ) % pubkey_pool_sz;
      make_pubkey( pubkey, idx );
      if( fd_accdb_read( accdb, cur, pubkey, &lamports,
                         rdata, &data_len, owner ) ) {
        total_read_hits++;
      }
      total_reads++;
    }
    long t1 = fd_log_wallclock();
    dt_read += (t1 - t0);

    /* --- writes (simulate transaction execution results) --- */
    for( ulong w=0UL; w<writes_per_slot; w++ ) {
      ulong idx = fd_rng_ulong( rng ) % pubkey_pool_sz;
      make_pubkey( pubkey, idx );
      ulong sz = sample_account_size( rng );
      if( sz>BENCH_MAX_DATA_SZ ) sz = BENCH_MAX_DATA_SZ;
      fd_accdb_write( accdb, cur, pubkey, (s*writes_per_slot + w)+1UL,
                      sz ? data_buf : NULL, sz, dummy_owner );
      total_write_bytes += sz;
      total_writes++;
    }
    long t2 = fd_log_wallclock();
    dt_write += (t2 - t1);

    /* --- root previous slot --- */
    if( FD_LIKELY( s>0UL ) ) {
      fd_accdb_advance_root( accdb, prev );
    }
    long t3 = fd_log_wallclock();
    dt_root += (t3 - t2);

    prev = cur;
  }
  dt_total += fd_log_wallclock();

  fd_accdb_metrics_t const * m = fd_accdb_metrics( accdb );

  double total_secs = (double)dt_total / 1e9;
  FD_LOG_NOTICE(( "bench_replay: %lu slots, %lu reads/slot, "
                  "%lu writes/slot, %.3f s total",
                  slot_cnt, reads_per_slot, writes_per_slot,
                  total_secs ));
  FD_LOG_NOTICE(( "  read:    %lu queries (%lu hits, %.1f%% hit rate), "
                  "%.0f reads/s, %.0f ns/read",
                  total_reads, total_read_hits,
                  total_reads ? 100.0*(double)total_read_hits/(double)total_reads : 0.0,
                  (double)total_reads / ((double)dt_read/1e9),
                  dt_read ? (double)dt_read/(double)total_reads : 0.0 ));
  FD_LOG_NOTICE(( "  write:   %lu writes, %.2f MiB, "
                  "%.0f writes/s, %.0f ns/write",
                  total_writes,
                  (double)total_write_bytes / (double)(1UL<<20UL),
                  (double)total_writes / ((double)dt_write/1e9),
                  dt_write ? (double)dt_write/(double)total_writes : 0.0 ));
  FD_LOG_NOTICE(( "  root:    %.0f ns/root, %.3f s total "
                  "(%lu slots rooted)",
                  slot_cnt>1UL ? (double)dt_root/(double)(slot_cnt-1UL) : 0.0,
                  (double)dt_root / 1e9,
                  slot_cnt>1UL ? slot_cnt-1UL : 0UL ));
  FD_LOG_NOTICE(( "  slot:    %.0f ns/slot (%.0f slots/s)",
                  (double)dt_total / (double)slot_cnt,
                  (double)slot_cnt / total_secs ));
  FD_LOG_NOTICE(( "  metrics: accounts_total=%lu disk_used=%.2f MiB "
                  "disk_alloc=%.2f MiB",
                  m->accounts_total,
                  (double)m->disk_used_bytes / (double)(1UL<<20UL),
                  (double)m->disk_allocated_bytes / (double)(1UL<<20UL) ));

  close( fd );
}

/* ------------------------------------------------------------------ */

/* bench_mixed: Mixed read-write workload.  Populate a base set of
   accounts, then run a workload that is read_pct% reads and the rest
   writes, simulating transaction execution that reads many accounts
   but updates fewer. */
static void
bench_mixed( ulong   base_cnt,
             ulong   op_cnt,
             uint    read_pct,
             fd_rng_t * rng ) {
  int fd;
  ulong partition_sz  = 1UL<<30UL;
  ulong partition_cnt = 1024UL;
  fd_accdb_t * accdb = bench_setup( &fd,
                                    base_cnt + op_cnt + 1024UL,
                                    64UL,
                                    (uint)(base_cnt + op_cnt) + 1024U,
                                    partition_cnt,
                                    partition_sz );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t fork = fd_accdb_attach_child( accdb, root );

  /* Populate base set */
  uchar pubkey[ 32 ];
  for( ulong i=0UL; i<base_cnt; i++ ) {
    make_pubkey( pubkey, i );
    ulong sz = sample_account_size( rng );
    if( sz>BENCH_MAX_DATA_SZ ) sz = BENCH_MAX_DATA_SZ;
    fd_accdb_write( accdb, fork, pubkey, i+1UL,
                    sz ? data_buf : NULL, sz, dummy_owner );
  }

  uchar  rdata[ BENCH_MAX_DATA_SZ ];
  ulong  lamports;
  ulong  data_len;
  uchar  owner[ 32 ];
  ulong  reads = 0UL;
  ulong  writes = 0UL;

  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<op_cnt; i++ ) {
    uint coin = fd_rng_uint( rng ) % 100U;
    ulong idx = fd_rng_ulong( rng ) % base_cnt;
    make_pubkey( pubkey, idx );
    if( coin < read_pct ) {
      fd_accdb_read( accdb, fork, pubkey, &lamports,
                     rdata, &data_len, owner );
      reads++;
    } else {
      ulong sz = sample_account_size( rng );
      if( sz>BENCH_MAX_DATA_SZ ) sz = BENCH_MAX_DATA_SZ;
      fd_accdb_write( accdb, fork, pubkey, i+1UL,
                      sz ? data_buf : NULL, sz, dummy_owner );
      writes++;
    }
  }
  dt += fd_log_wallclock();

  double secs = (double)dt / 1e9;
  FD_LOG_NOTICE(( "bench_mixed: %lu ops (%lu reads, %lu writes) in %.3f s "
                  "(%.0f ops/s, %.0f ns/op, read_pct=%u%%)",
                  op_cnt, reads, writes, secs,
                  (double)op_cnt / secs,
                  (double)dt / (double)op_cnt,
                  (uint)read_pct ));

  close( fd );
}

/* ------------------------------------------------------------------ */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong account_cnt     = fd_env_strip_cmdline_ulong( &argc, &argv, "--accounts",       NULL, 100000UL  );
  ulong slot_cnt        = fd_env_strip_cmdline_ulong( &argc, &argv, "--slots",           NULL,    100UL  );
  ulong writes_per_slot = fd_env_strip_cmdline_ulong( &argc, &argv, "--writes-per-slot", NULL,   1200UL  );
  ulong reads_per_slot  = fd_env_strip_cmdline_ulong( &argc, &argv, "--reads-per-slot",  NULL,   4800UL  );
  ulong mixed_ops       = fd_env_strip_cmdline_ulong( &argc, &argv, "--mixed-ops",       NULL, 200000UL  );
  uint  read_pct        = fd_env_strip_cmdline_uint ( &argc, &argv, "--read-pct",        NULL,      80U  );
  uint  seed            = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",            NULL,      42U  );

  FD_LOG_NOTICE(( "accdb benchmark (accounts=%lu slots=%lu wpslot=%lu "
                  "rpslot=%lu mixed_ops=%lu read_pct=%u seed=%u)",
                  account_cnt, slot_cnt, writes_per_slot, reads_per_slot,
                  mixed_ops, read_pct, seed ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  FD_TEST( rng );

  FD_LOG_NOTICE(( "--- write throughput ---" ));
  bench_write( account_cnt, rng );

  FD_LOG_NOTICE(( "--- read throughput ---" ));
  bench_read( account_cnt, rng );

  FD_LOG_NOTICE(( "--- replay simulation ---" ));
  bench_replay( slot_cnt, writes_per_slot, reads_per_slot, rng );

  FD_LOG_NOTICE(( "--- mixed read/write (%u%% reads) ---", read_pct ));
  bench_mixed( account_cnt, mixed_ops, read_pct, rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
