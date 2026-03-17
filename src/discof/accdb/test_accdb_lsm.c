#define _GNU_SOURCE

#include "fd_accdb_lsm.h"
#include "../../util/fd_util.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static uchar pubkey0[ 32UL ]  = { 0 };
static uchar pubkey1[ 32UL ]  = { 1, 0 };

static uchar owner2[ 32UL ] = { 2, 0 };
static uchar owner3[ 32UL ] = { 3, 0 };

#define SENTINEL ((fd_accdb_fork_id_t){ .val = USHORT_MAX })

/* Disk metadata is packed: pubkey[32] + size(uint,4) = 36 */
#define META_SZ (36UL)

static fd_accdb_lsm_t *
test_setup( int * out_fd,
            ulong max_accounts,
            ulong max_live_slots,
            ulong max_account_writes_per_slot,
            ulong partition_cnt,
            ulong partition_sz ) {
  int fd = memfd_create( "accdb_test", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));
  *out_fd = fd;

  ulong fp = fd_accdb_lsm_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt );
  FD_TEST( fp );
  void * mem = aligned_alloc( fd_accdb_lsm_align(), fp );
  FD_TEST( mem );
  fd_accdb_lsm_t * accdb = fd_accdb_lsm_join( fd_accdb_lsm_new( mem, max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, partition_sz, 42UL ), fd );
  FD_TEST( accdb );
  return accdb;
}

void
test_basic( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t slot1 = fd_accdb_lsm_attach_child( accdb, root );

  FD_TEST( !fd_accdb_lsm_read( accdb, slot1, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !fd_accdb_lsm_read( accdb, slot1, pubkey1, NULL, NULL, NULL, owner ) );
  fd_accdb_lsm_write( accdb, slot1, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST( !fd_accdb_lsm_read( accdb, slot1, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( fd_accdb_lsm_read( accdb, slot1, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==1UL );
  FD_TEST( data_len==0UL );
  FD_TEST( !memcmp( owner, owner2, 32UL ) );

  close( fd );
}

void
test_fork_basic( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f1 = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_fork_id_t f2 = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_fork_id_t f3 = fd_accdb_lsm_attach_child( accdb, root );

  FD_TEST( !fd_accdb_lsm_read( accdb, f1, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !fd_accdb_lsm_read( accdb, f2, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !fd_accdb_lsm_read( accdb, f3, pubkey0, NULL, NULL, NULL, owner ) );

  fd_accdb_lsm_write( accdb, f1, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST(  fd_accdb_lsm_read( accdb, f1, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( !fd_accdb_lsm_read( accdb, f2, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( !fd_accdb_lsm_read( accdb, f3, pubkey1, &lamports, &d, &data_len, owner ) );

  fd_accdb_lsm_write( accdb, f2, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST(  fd_accdb_lsm_read( accdb, f1, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST(  fd_accdb_lsm_read( accdb, f2, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( !fd_accdb_lsm_read( accdb, f3, pubkey1, &lamports, &d, &data_len, owner ) );

  fd_accdb_fork_id_t f4 = fd_accdb_lsm_attach_child( accdb, f2 );
  fd_accdb_fork_id_t f5 = fd_accdb_lsm_attach_child( accdb, f3 );
  FD_TEST(  fd_accdb_lsm_read( accdb, f4, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( !fd_accdb_lsm_read( accdb, f5, pubkey1, &lamports, &d, &data_len, owner ) );

  close( fd );
}

void
test_root_forks( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f1 = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_fork_id_t f2 = fd_accdb_lsm_attach_child( accdb, root );

  fd_accdb_lsm_write( accdb, f2, pubkey1, 1UL, NULL, 0UL, owner2 );
  fd_accdb_lsm_write( accdb, f1, pubkey1, 2UL, NULL, 0UL, owner2 );
  fd_accdb_fork_id_t f3 = fd_accdb_lsm_attach_child( accdb, f1 );
  fd_accdb_lsm_write( accdb, f3, pubkey1, 3UL, NULL, 0UL, owner2 );

  FD_TEST( fd_accdb_lsm_read( accdb, f1, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==2UL );
  FD_TEST( fd_accdb_lsm_read( accdb, f2, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==1UL );
  FD_TEST( fd_accdb_lsm_read( accdb, f3, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==3UL );

  /* Root f2: f1 and f3 are on a competing fork and should be purged. */
  fd_accdb_lsm_advance_root( accdb, f2 );
  FD_TEST( fd_accdb_lsm_read( accdb, f2, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==1UL );

  close( fd );
}

static uchar big_data[ 10UL*(1UL<<20) ];

void
test_compact( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t slot1 = fd_accdb_lsm_attach_child( accdb, root );

  ulong acct_sz = 10UL*(1UL<<20UL);
  ulong rec_sz  = acct_sz + META_SZ;
  ulong writes_fit_in_partition = (1UL<<30UL) / rec_sz;

  for( ulong i=0UL; i<writes_fit_in_partition; i++ ) {
    fd_accdb_lsm_write( accdb, slot1, pubkey1, 1UL, big_data, acct_sz, owner2 );
  }
  fd_accdb_lsm_metrics_t const * metrics = fd_accdb_lsm_metrics( accdb );
  FD_TEST( metrics->accounts_total           == 1UL );
  FD_TEST( metrics->accounts_capacity        == 1024UL );
  FD_TEST( metrics->accounts_written         == writes_fit_in_partition );
  FD_TEST( metrics->disk_allocated_bytes     == (1UL<<30UL) );
  FD_TEST( metrics->disk_used_bytes          == 1UL*rec_sz );
  FD_TEST( metrics->in_compaction            == 0 );
  FD_TEST( metrics->compactions_requested    == 0UL );
  FD_TEST( metrics->compactions_completed    == 0UL );
  FD_TEST( metrics->accounts_relocated       == 0UL );
  FD_TEST( metrics->accounts_relocated_bytes == 0UL );
  FD_TEST( metrics->partitions_freed         == 0UL );

  /* One more write triggers a new partition and compaction of the
     old one (the freed tail exceeded 30% of partition_sz). */
  fd_accdb_lsm_write( accdb, slot1, pubkey1, 1UL, big_data, acct_sz, owner2 );
  FD_TEST( metrics->in_compaction            == 1 );

  while( metrics->in_compaction ) {
    int charge_busy = 0;
    fd_accdb_lsm_compact( accdb, &charge_busy );
  }

  FD_TEST( metrics->accounts_total           == 1UL );
  FD_TEST( metrics->compactions_requested    == 1UL );
  FD_TEST( metrics->compactions_completed    == 1UL );
  FD_TEST( metrics->accounts_relocated       == 0UL );
  FD_TEST( metrics->accounts_relocated_bytes == 0UL );
  FD_TEST( metrics->partitions_freed         == 1UL );

  close( fd );
}

/* Test that writing the same account multiple times on the same fork
   correctly updates the data each time and that reads return the
   latest version. */
void
test_overwrite_same_fork( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d[4];
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root  = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t slot1 = fd_accdb_lsm_attach_child( accdb, root );

  uchar data_a[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
  uchar data_b[4] = { 0x11, 0x22, 0x33, 0x44 };
  uchar data_c[2] = { 0xFF, 0xEE };

  fd_accdb_lsm_write( accdb, slot1, pubkey1, 100UL, data_a, 4UL, owner2 );
  FD_TEST( fd_accdb_lsm_read( accdb, slot1, pubkey1, &lamports, d, &data_len, owner ) );
  FD_TEST( lamports==100UL );
  FD_TEST( data_len==4UL );
  FD_TEST( !memcmp( d, data_a, 4UL ) );

  fd_accdb_lsm_write( accdb, slot1, pubkey1, 200UL, data_b, 4UL, owner3 );
  FD_TEST( fd_accdb_lsm_read( accdb, slot1, pubkey1, &lamports, d, &data_len, owner ) );
  FD_TEST( lamports==200UL );
  FD_TEST( data_len==4UL );
  FD_TEST( !memcmp( d, data_b, 4UL ) );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  fd_accdb_lsm_write( accdb, slot1, pubkey1, 300UL, data_c, 2UL, owner2 );
  FD_TEST( fd_accdb_lsm_read( accdb, slot1, pubkey1, &lamports, d, &data_len, owner ) );
  FD_TEST( lamports==300UL );
  FD_TEST( data_len==2UL );
  FD_TEST( !memcmp( d, data_c, 2UL ) );
  FD_TEST( !memcmp( owner, owner2, 32UL ) );

  fd_accdb_lsm_metrics_t const * metrics = fd_accdb_lsm_metrics( accdb );
  FD_TEST( metrics->accounts_total == 1UL );

  close( fd );
}

/* Test that multiple distinct accounts can coexist and be read back
   correctly on different forks. */
void
test_multiple_accounts( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  uchar pk_a[ 32UL ] = { 10 };
  uchar pk_b[ 32UL ] = { 20 };
  uchar pk_c[ 32UL ] = { 30 };

  fd_accdb_fork_id_t root  = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f1    = fd_accdb_lsm_attach_child( accdb, root );

  fd_accdb_lsm_write( accdb, f1, pk_a, 10UL, NULL, 0UL, owner2 );
  fd_accdb_lsm_write( accdb, f1, pk_b, 20UL, NULL, 0UL, owner2 );
  fd_accdb_lsm_write( accdb, f1, pk_c, 30UL, NULL, 0UL, owner3 );

  FD_TEST( fd_accdb_lsm_read( accdb, f1, pk_a, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==10UL );
  FD_TEST( fd_accdb_lsm_read( accdb, f1, pk_b, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==20UL );
  FD_TEST( fd_accdb_lsm_read( accdb, f1, pk_c, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==30UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  fd_accdb_lsm_metrics_t const * metrics = fd_accdb_lsm_metrics( accdb );
  FD_TEST( metrics->accounts_total == 3UL );

  close( fd );
}

/* Test advancing the root through a chain of slots: root->A->B->C,
   root each one in sequence, then verify the last is still readable. */
void
test_sequential_rooting( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t a = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_lsm_write( accdb, root, pubkey1, 1UL, NULL, 0UL, owner2 );
  fd_accdb_lsm_write( accdb, a, pubkey1, 2UL, NULL, 0UL, owner2 );

  fd_accdb_lsm_advance_root( accdb, a );

  fd_accdb_fork_id_t b = fd_accdb_lsm_attach_child( accdb, a );
  fd_accdb_lsm_write( accdb, b, pubkey1, 3UL, NULL, 0UL, owner2 );
  FD_TEST( fd_accdb_lsm_read( accdb, b, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==3UL );

  fd_accdb_lsm_advance_root( accdb, b );

  fd_accdb_fork_id_t c = fd_accdb_lsm_attach_child( accdb, b );
  FD_TEST( fd_accdb_lsm_read( accdb, c, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==3UL );

  fd_accdb_lsm_write( accdb, c, pubkey1, 4UL, NULL, 0UL, owner3 );
  FD_TEST( fd_accdb_lsm_read( accdb, c, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==4UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  close( fd );
}

/* Test purge: create a fork, write to it, purge it, and verify the
   account is no longer visible while accounts on the surviving fork
   remain. */
void
test_purge( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  uchar pk_a[ 32UL ] = { 0xA0 };
  uchar pk_b[ 32UL ] = { 0xB0 };

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t keep = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_fork_id_t drop = fd_accdb_lsm_attach_child( accdb, root );

  fd_accdb_lsm_write( accdb, keep, pk_a, 100UL, NULL, 0UL, owner2 );
  fd_accdb_lsm_write( accdb, drop, pk_b,  50UL, NULL, 0UL, owner2 );

  FD_TEST(  fd_accdb_lsm_read( accdb, keep, pk_a, &lamports, &d, &data_len, owner ) );
  FD_TEST(  fd_accdb_lsm_read( accdb, drop, pk_b, &lamports, &d, &data_len, owner ) );

  fd_accdb_lsm_purge( accdb, drop );

  /* The account on the kept fork should still be there. */
  FD_TEST( fd_accdb_lsm_read( accdb, keep, pk_a, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==100UL );

  fd_accdb_lsm_metrics_t const * metrics = fd_accdb_lsm_metrics( accdb );
  FD_TEST( metrics->accounts_total == 1UL );

  close( fd );
}

/* Test that child forks inherit writes from their parent (ancestor
   visibility) and that overwriting on the child does not affect the
   parent's view. */
void
test_child_inherits_parent( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root   = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t parent = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_lsm_write( accdb, parent, pubkey1, 10UL, NULL, 0UL, owner2 );

  fd_accdb_fork_id_t child = fd_accdb_lsm_attach_child( accdb, parent );

  /* Child can see parent's write */
  FD_TEST( fd_accdb_lsm_read( accdb, child, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==10UL );

  /* Overwrite on child */
  fd_accdb_lsm_write( accdb, child, pubkey1, 99UL, NULL, 0UL, owner3 );
  FD_TEST( fd_accdb_lsm_read( accdb, child, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==99UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  /* Parent still sees original */
  FD_TEST( fd_accdb_lsm_read( accdb, parent, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==10UL );
  FD_TEST( !memcmp( owner, owner2, 32UL ) );

  close( fd );
}

/* Build a deep linear chain (root -> s0 -> s1 -> ... -> s9), write
   the same account at every level with increasing lamports, then
   root halfway through the chain.  Verify that reads on deeper forks
   still see the correct ancestor value and that rooting cleans up
   correctly. */
void
test_deep_chain_rooting( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

# define DEPTH (10UL)
  fd_accdb_fork_id_t chain[ DEPTH ];

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  chain[ 0 ] = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_lsm_write( accdb, chain[ 0 ], pubkey1, 1UL, NULL, 0UL, owner2 );
  for( ulong i=1UL; i<DEPTH; i++ ) {
    chain[ i ] = fd_accdb_lsm_attach_child( accdb, chain[ i-1UL ] );
    fd_accdb_lsm_write( accdb, chain[ i ], pubkey1, i+1UL, NULL, 0UL, owner2 );
  }

  /* Each fork should see its own write. */
  for( ulong i=0UL; i<DEPTH; i++ ) {
    FD_TEST( fd_accdb_lsm_read( accdb, chain[ i ], pubkey1, &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==i+1UL );
  }

  /* Root through the first 5 levels. */
  for( ulong i=0UL; i<5UL; i++ ) {
    fd_accdb_lsm_advance_root( accdb, chain[ i ] );
  }

  /* Deeper forks still see their own values. */
  for( ulong i=5UL; i<DEPTH; i++ ) {
    FD_TEST( fd_accdb_lsm_read( accdb, chain[ i ], pubkey1, &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==i+1UL );
  }

  /* The rooted slot sees the value that was written on it. */
  FD_TEST( fd_accdb_lsm_read( accdb, chain[ 4 ], pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==5UL );

  /* Rooting should have tombstoned the versions from chain[0]..chain[3]
     (4 old versions removed).  The 5 remaining forks (chain[4]..chain[9])
     each still have one live entry, but they all share the same pubkey.
     However only chain[5]..chain[9] wrote separate entries (chain[4] is
     the new root and its entry persists).  The first rooting (chain[0])
     does not tombstone anything because root had no txns, so 4 versions
     are removed.  10 original - 4 tombstoned = 6. */
  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==6UL );

# undef DEPTH
  close( fd );
}

/* Create a wide fan-out: one parent with 16 sibling children, each
   writing the same pubkey with a unique lamports value.  Verify
   perfect fork isolation—each sibling reads only its own value. */
void
test_wide_fanout_isolation( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

# define SIBLINGS (16UL)
  fd_accdb_fork_id_t root   = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t parent = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_fork_id_t sibs[ SIBLINGS ];

  for( ulong i=0UL; i<SIBLINGS; i++ ) {
    sibs[ i ] = fd_accdb_lsm_attach_child( accdb, parent );
    fd_accdb_lsm_write( accdb, sibs[ i ], pubkey1, (i+1UL)*100UL, NULL, 0UL, owner2 );
  }

  /* Each sibling should read back exactly its own lamports. */
  for( ulong i=0UL; i<SIBLINGS; i++ ) {
    FD_TEST( fd_accdb_lsm_read( accdb, sibs[ i ], pubkey1, &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==(i+1UL)*100UL );
  }

  /* Parent should not see any of the children's writes. */
  FD_TEST( !fd_accdb_lsm_read( accdb, parent, pubkey1, &lamports, &d, &data_len, owner ) );

  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==SIBLINGS );

# undef SIBLINGS
  close( fd );
}

/* Purge a fork that has children and grandchildren.  Verify the
   entire subtree is recursively removed, while a sibling subtree
   survives. */
void
test_purge_deep_subtree( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  uchar pk_a[ 32UL ] = { 0xDA };
  uchar pk_b[ 32UL ] = { 0xDB };
  uchar pk_c[ 32UL ] = { 0xDC };

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t keep = fd_accdb_lsm_attach_child( accdb, root );
  fd_accdb_fork_id_t drop = fd_accdb_lsm_attach_child( accdb, root );

  /* Build a subtree under drop: drop -> child -> grandchild */
  fd_accdb_fork_id_t drop_child      = fd_accdb_lsm_attach_child( accdb, drop );
  fd_accdb_fork_id_t drop_grandchild = fd_accdb_lsm_attach_child( accdb, drop_child );

  fd_accdb_lsm_write( accdb, drop,            pk_a, 1UL, NULL, 0UL, owner2 );
  fd_accdb_lsm_write( accdb, drop_child,      pk_b, 2UL, NULL, 0UL, owner2 );
  fd_accdb_lsm_write( accdb, drop_grandchild, pk_c, 3UL, NULL, 0UL, owner2 );
  fd_accdb_lsm_write( accdb, keep,            pk_a, 9UL, NULL, 0UL, owner3 );

  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==4UL );

  fd_accdb_lsm_purge( accdb, drop );

  /* Only the account on the kept fork should remain. */
  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==1UL );
  FD_TEST( fd_accdb_lsm_read( accdb, keep, pk_a, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==9UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  close( fd );
}

/* Write an account on the root fork, then overwrite it on a child
   fork.  After rooting the child, verify accounts_total stays at 1
   (the older version is tombstoned by the rooting pass). */
void
test_root_tombstones_old_version( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t a    = fd_accdb_lsm_attach_child( accdb, root );

  fd_accdb_lsm_write( accdb, root, pubkey1, 10UL, NULL, 0UL, owner2 );
  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==1UL );

  fd_accdb_lsm_write( accdb, a, pubkey1, 20UL, NULL, 0UL, owner3 );
  /* Two index entries exist now: one for root, one for a. */
  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==2UL );

  fd_accdb_lsm_advance_root( accdb, a );

  /* After rooting, the older version on root should have been
     tombstoned, leaving exactly one live entry. */
  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==1UL );

  FD_TEST( fd_accdb_lsm_read( accdb, a, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==20UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  close( fd );
}

/* Populate many distinct accounts on a single fork to exercise the
   hash-chain logic (multiple accounts sharing the same chain bucket).
   Then verify every account can still be read back correctly. */
void
test_many_accounts_hash_chains( void ) {
  int fd;
  fd_accdb_lsm_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

# define N_ACCTS (200UL)

  fd_accdb_fork_id_t root = fd_accdb_lsm_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f    = fd_accdb_lsm_attach_child( accdb, root );

  uchar pks[ N_ACCTS ][ 32UL ];
  for( ulong i=0UL; i<N_ACCTS; i++ ) {
    fd_memset( pks[ i ], 0, 32UL );
    /* Spread keys across the first 4 bytes to create varied hashes. */
    pks[ i ][ 0 ] = (uchar)( i       & 0xFFUL);
    pks[ i ][ 1 ] = (uchar)((i>> 8UL)& 0xFFUL);
    pks[ i ][ 2 ] = (uchar)((i>>16UL)& 0xFFUL);
    pks[ i ][ 3 ] = (uchar)((i>>24UL)& 0xFFUL);

    fd_accdb_lsm_write( accdb, f, pks[ i ], i+1UL, NULL, 0UL, owner2 );
  }

  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==N_ACCTS );

  /* Read every account back and verify. */
  for( ulong i=0UL; i<N_ACCTS; i++ ) {
    FD_TEST( fd_accdb_lsm_read( accdb, f, pks[ i ], &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==i+1UL );
  }

  /* Overwrite the first 50 and verify again. */
  for( ulong i=0UL; i<50UL; i++ ) {
    fd_accdb_lsm_write( accdb, f, pks[ i ], (i+1UL)*1000UL, NULL, 0UL, owner3 );
  }

  FD_TEST( fd_accdb_lsm_metrics( accdb )->accounts_total==N_ACCTS );
  for( ulong i=0UL; i<50UL; i++ ) {
    FD_TEST( fd_accdb_lsm_read( accdb, f, pks[ i ], &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==(i+1UL)*1000UL );
    FD_TEST( !memcmp( owner, owner3, 32UL ) );
  }
  for( ulong i=50UL; i<N_ACCTS; i++ ) {
    FD_TEST( fd_accdb_lsm_read( accdb, f, pks[ i ], &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==i+1UL );
    FD_TEST( !memcmp( owner, owner2, 32UL ) );
  }

# undef N_ACCTS
  close( fd );
}

void
test_mainnet_footprint( void ) {
  /* Mainnet-scale parameters:
     max_accounts                = 1.2B   (current mainnet account count)
     max_live_slots              = 4096   (generous unrooted slot window)
     max_account_writes_per_slot = 321280 (FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT
                                           from fd_cost_tracker.h)

     Derivation: pack the block with txns each having max writable
     accounts (64) at minimum cost per txn:
       min_cost = FD_PACK_COST_PER_SIGNATURE + 64*FD_WRITE_LOCK_UNITS
                = 720 + 64*300 = 19920
       max_txns = floor(100000000 / 19920) = 5020
       max_distinct_writable = 5020 * 64 = 321280

     partition_cnt               = 8192
     partition_sz                = 1 GiB */
  ulong max_accounts                = 1200000000UL;
  ulong max_live_slots              = 4096UL;
  ulong max_account_writes_per_slot = 64UL * (100000000UL / (300UL*64UL + 720UL));
  ulong partition_cnt               = 8192UL;

  FD_TEST( max_account_writes_per_slot==321280UL );

  ulong fp = fd_accdb_lsm_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt );
  FD_TEST( fp );

  FD_LOG_NOTICE(( "mainnet footprint: %lu bytes (%.2f GiB)", fp, (double)fp/(double)(1UL<<30UL) ));
  FD_LOG_NOTICE(( "  max_accounts                = %lu",     max_accounts ));
  FD_LOG_NOTICE(( "  max_live_slots              = %lu",     max_live_slots ));
  FD_LOG_NOTICE(( "  max_account_writes_per_slot = %lu",     max_account_writes_per_slot ));
  FD_LOG_NOTICE(( "  partition_cnt               = %lu",     partition_cnt ));
  FD_LOG_NOTICE(( "  txn_pool_max                = %lu",     max_live_slots*max_account_writes_per_slot ));
  FD_LOG_NOTICE(( "  max disk file               = %lu GiB", partition_cnt*(1UL<<30UL)/(1UL<<30UL) ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "test_basic ..." ));
  test_basic();

  FD_LOG_NOTICE(( "test_fork_basic ..." ));
  test_fork_basic();

  FD_LOG_NOTICE(( "test_root_forks ..." ));
  test_root_forks();

  FD_LOG_NOTICE(( "test_compact ..." ));
  test_compact();

  FD_LOG_NOTICE(( "test_overwrite_same_fork ..." ));
  test_overwrite_same_fork();

  FD_LOG_NOTICE(( "test_multiple_accounts ..." ));
  test_multiple_accounts();

  FD_LOG_NOTICE(( "test_sequential_rooting ..." ));
  test_sequential_rooting();

  FD_LOG_NOTICE(( "test_purge ..." ));
  test_purge();

  FD_LOG_NOTICE(( "test_child_inherits_parent ..." ));
  test_child_inherits_parent();

  FD_LOG_NOTICE(( "test_deep_chain_rooting ..." ));
  test_deep_chain_rooting();

  FD_LOG_NOTICE(( "test_wide_fanout_isolation ..." ));
  test_wide_fanout_isolation();

  FD_LOG_NOTICE(( "test_purge_deep_subtree ..." ));
  test_purge_deep_subtree();

  FD_LOG_NOTICE(( "test_root_tombstones_old_version ..." ));
  test_root_tombstones_old_version();

  FD_LOG_NOTICE(( "test_many_accounts_hash_chains ..." ));
  test_many_accounts_hash_chains();

  FD_LOG_NOTICE(( "test_mainnet_footprint ..." ));
  test_mainnet_footprint();

  FD_LOG_NOTICE(( "success" ));
}
