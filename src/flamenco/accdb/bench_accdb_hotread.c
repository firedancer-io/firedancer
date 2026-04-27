#define _GNU_SOURCE

#include "fd_accdb.h"
#include "../../util/fd_util.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* bench_accdb_hotread: populate a small set of accounts so they all fit
   in cache, then hammer acquire+release read-only in a tight loop for a
   fixed duration.  This isolates the hot-path cost of in-cache reads
   without any disk I/O, eviction, or write-back noise. */

static uchar dummy_owner[ 32 ] = { 0xEE };

#define BENCH_MAX_DATA_SZ  (256UL)   /* token-account sized */
#define BENCH_CACHE_FOOTPRINT (16UL<<30UL)

static uchar data_buf[ BENCH_MAX_DATA_SZ ];

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
  int fd = memfd_create( "accdb_hotread", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));
  *out_fd = fd;

  ulong cache_fp = BENCH_CACHE_FOOTPRINT;
  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, cache_fp, 640UL, 1UL );
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
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( accdb_mem, shmem, fd ) );
  FD_TEST( accdb );
  return accdb;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong account_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--accounts", NULL, 10000UL );
  ulong duration_ns = fd_env_strip_cmdline_ulong( &argc, &argv, "--duration", NULL, 15000000000UL ); /* 15 s */
  uint  seed        = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",     NULL, 42U );

  FD_LOG_NOTICE(( "accdb hot-read bench (accounts=%lu duration=%.1f s seed=%u)",
                  account_cnt, (double)duration_ns/1e9, seed ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  FD_TEST( rng );

  /* Setup */
  int fd;
  ulong partition_sz  = 1UL<<30UL;
  ulong partition_cnt = 1024UL;
  fd_accdb_t * accdb = bench_setup( &fd,
                                    account_cnt + 1024UL,
                                    64UL,
                                    (uint)account_cnt + 1024U,
                                    partition_cnt,
                                    partition_sz );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t fork = fd_accdb_attach_child( accdb, root );

  /* Populate accounts so they are all in cache */
  uchar pubkey[ 32 ];
  for( ulong i=0UL; i<account_cnt; i++ ) {
    make_pubkey( pubkey, i );
    ulong sz = 165UL; /* token account */

    uchar const * pks[1] = { pubkey };
    int wr[1] = { 1 };
    fd_accdb_entry_t ent[1];
    memset( ent, 0, sizeof(ent) );
    fd_accdb_acquire( accdb, fork, 1UL, pks, wr, ent );
    ent[0].lamports = i+1UL;
    ent[0].data_len = sz;
    memcpy( ent[0].owner, dummy_owner, 32UL );
    memcpy( ent[0].data, data_buf, sz );
    ent[0].commit = 1;
    fd_accdb_release( accdb, 1UL, ent );
  }

  /* Warm: read every account once to ensure cache residency */
  for( ulong i=0UL; i<account_cnt; i++ ) {
    make_pubkey( pubkey, i );
    uchar const * pks[1] = { pubkey };
    int wr[1] = { 0 };
    fd_accdb_entry_t ent[1];
    memset( ent, 0, sizeof(ent) );
    fd_accdb_acquire( accdb, fork, 1UL, pks, wr, ent );
    fd_accdb_release( accdb, 1UL, ent );
  }

  FD_LOG_NOTICE(( "populated %lu accounts, starting hot read loop", account_cnt ));

  /* Hot loop: read-only acquire+release for duration_ns */
  ulong ops   = 0UL;
  long  start = fd_log_wallclock();
  long  stop  = start + (long)duration_ns;

  while( fd_log_wallclock()<stop ) {
    /* Batch of 1000 to amortize the clock call */
    for( ulong b=0UL; b<1000UL; b++ ) {
      ulong idx = fd_rng_ulong( rng ) % account_cnt;
      make_pubkey( pubkey, idx );

      uchar const * pks[1] = { pubkey };
      int wr[1] = { 0 };
      fd_accdb_entry_t ent[1];
      memset( ent, 0, sizeof(ent) );
      fd_accdb_acquire( accdb, fork, 1UL, pks, wr, ent );
      fd_accdb_release( accdb, 1UL, ent );
      ops++;
    }
  }

  long elapsed = fd_log_wallclock() - start;
  double secs  = (double)elapsed / 1e9;

  FD_LOG_NOTICE(( "hot-read: %lu ops in %.3f s  (%.0f ops/s, %.0f ns/op)",
                  ops, secs,
                  (double)ops / secs,
                  (double)elapsed / (double)ops ));

  fd_rng_delete( fd_rng_leave( rng ) );
  close( fd );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
