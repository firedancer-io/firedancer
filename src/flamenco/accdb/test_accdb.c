#define _GNU_SOURCE

#include "fd_accdb.h"
#include "fd_accdb_cache.h"
#define FD_ACCDB_NO_FORK_ID
#include "fd_accdb_private.h"
#undef FD_ACCDB_NO_FORK_ID
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

/* Cache footprint for tests: must be large enough to cover the
   minimum FD_ACCDB_CACHE_MIN_RESERVED (1280) slots per class
   (class 7 is 10 MiB each). */
#define TEST_CACHE_FOOTPRINT (16UL<<30UL)

static fd_accdb_t *
test_setup( int * out_fd,
            ulong max_accounts,
            ulong max_live_slots,
            ulong max_account_writes_per_slot,
            ulong partition_cnt,
            ulong partition_sz ) {
  int fd = memfd_create( "accdb_test", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));
  *out_fd = fd;

  ulong cache_fp = TEST_CACHE_FOOTPRINT;
  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, cache_fp, 1UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( shmem_mem, max_accounts, max_live_slots,
                          max_account_writes_per_slot, partition_cnt,
                          partition_sz, cache_fp, 42UL, 1UL ) );
  FD_TEST( shmem );

  ulong accdb_fp = fd_accdb_footprint( max_live_slots );
  FD_TEST( accdb_fp );
  void * accdb_mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  FD_TEST( accdb_mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( accdb_mem, shmem, fd ) );
  FD_TEST( accdb );
  return accdb;
}

/* Process any pending advance_root / purge command submitted to the
   background tile.  Must be called after advance_root or purge in
   single-threaded tests so that the next T1 operation does not
   deadlock waiting for the command to complete. */
static void
drain_background( fd_accdb_t * accdb ) {
  int charge_busy = 0;
  fd_accdb_background( accdb, &charge_busy );
}

/* Helper: read a single account via acquire/release.  Returns 1 if
   the account exists (lamports!=0), 0 otherwise. */
static int
accdb_read( fd_accdb_t *       accdb,
            fd_accdb_fork_id_t fork_id,
            uchar const *      pubkey,
            ulong *            out_lamports,
            uchar *            out_data,
            ulong *            out_data_len,
            uchar *            out_owner ) {
  uchar const * pks[1] = { pubkey };
  int wr[1] = { 0 };
  fd_accdb_entry_t ent[1];
  memset( ent, 0, sizeof(ent) );
  fd_accdb_acquire( accdb, fork_id, 1UL, pks, wr, ent );
  int found = ent[0].lamports!=0UL;
  if( found ) {
    if( out_lamports ) *out_lamports = ent[0].lamports;
    if( out_data_len ) *out_data_len = ent[0].data_len;
    if( out_owner )    memcpy( out_owner, ent[0].owner, 32UL );
    if( out_data && ent[0].data && ent[0].data_len )
      memcpy( out_data, ent[0].data, ent[0].data_len );
  }
  fd_accdb_release( accdb, 1UL, ent );
  return found;
}

/* Helper: write a single account via acquire/release. */
static void
accdb_write( fd_accdb_t *       accdb,
             fd_accdb_fork_id_t fork_id,
             uchar const *      pubkey,
             ulong              lamports,
             uchar const *      data,
             ulong              data_len,
             uchar const *      owner ) {
  uchar const * pks[1] = { pubkey };
  int wr[1] = { 1 };
  fd_accdb_entry_t ent[1];
  memset( ent, 0, sizeof(ent) );
  fd_accdb_acquire( accdb, fork_id, 1UL, pks, wr, ent );
  ent[0].lamports = lamports;
  ent[0].data_len = data_len;
  memcpy( ent[0].owner, owner, 32UL );
  if( data_len && data ) memcpy( ent[0].data, data, data_len );
  ent[0].commit = 1;
  fd_accdb_release( accdb, 1UL, ent );
}

void
test_background_preevict_ignores_uninitialized_tail( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t slot1 = fd_accdb_attach_child( accdb, root );

  uchar owner[ 32UL ] = { 9, 0 };
  accdb_write( accdb, slot1, pubkey0, 1UL, NULL, 0UL, owner );

  ulong cache_used    [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_max     [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_reserved[ FD_ACCDB_CACHE_CLASS_CNT ];
  fd_accdb_cache_class_occupancy( accdb, cache_used, cache_max, cache_reserved );

  FD_TEST( cache_used[ 0UL ]==1UL );
  FD_TEST( cache_max[ 0UL ]>1UL );
  FD_TEST( fd_accdb_metrics( accdb )->accounts_preevicted==0UL );

  int charge_busy = 0;
  fd_accdb_background( accdb, &charge_busy );

  fd_accdb_cache_class_occupancy( accdb, cache_used, cache_max, cache_reserved );

  FD_TEST( cache_used[ 0UL ]==1UL );
  FD_TEST( fd_accdb_metrics( accdb )->accounts_preevicted==0UL );

  close( fd );
}

void
test_basic( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t slot1 = fd_accdb_attach_child( accdb, root );

  FD_TEST( !accdb_read( accdb, slot1, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !accdb_read( accdb, slot1, pubkey1, NULL, NULL, NULL, owner ) );
  accdb_write( accdb, slot1, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST( !accdb_read( accdb, slot1, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( accdb_read( accdb, slot1, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==1UL );
  FD_TEST( data_len==0UL );
  FD_TEST( !memcmp( owner, owner2, 32UL ) );

  close( fd );
}

void
test_missing_readonly_account_initializes_entry( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t slot1 = fd_accdb_attach_child( accdb, root );

  uchar missing_pubkey[ 32UL ] = { 0xAB };
  uchar zeros[ 32UL ]          = { 0 };
  uchar const * pks[ 1 ]       = { missing_pubkey };
  int wr[ 1 ]                  = { 0 };
  fd_accdb_entry_t ent[ 1 ];

  memset( ent, 0xA5, sizeof(ent) );
  fd_accdb_acquire( accdb, slot1, 1UL, pks, wr, ent );

  FD_TEST( !memcmp( ent[ 0 ].pubkey, missing_pubkey, 32UL ) );
  FD_TEST( !memcmp( ent[ 0 ].owner,  zeros,          32UL ) );
  FD_TEST( !memcmp( ent[ 0 ].prior_owner, zeros, 32UL ) );
  FD_TEST( ent[ 0 ].lamports==0UL );
  FD_TEST( ent[ 0 ].data_len==0UL );
  FD_TEST( ent[ 0 ].data==NULL );
  FD_TEST( ent[ 0 ].executable==0 );
  FD_TEST( ent[ 0 ].prior_lamports==0UL );
  FD_TEST( ent[ 0 ].prior_data_len==0UL );
  FD_TEST( ent[ 0 ].prior_data==NULL );
  FD_TEST( ent[ 0 ].prior_executable==0 );
  FD_TEST( ent[ 0 ]._writable==0 );
  FD_TEST( ent[ 0 ]._original_size_class==ULONG_MAX );
  FD_TEST( ent[ 0 ]._original_cache_idx==ULONG_MAX );

  fd_accdb_release( accdb, 1UL, ent );
  close( fd );
}

void
test_fork_basic( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f1 = fd_accdb_attach_child( accdb, root );
  fd_accdb_fork_id_t f2 = fd_accdb_attach_child( accdb, root );
  fd_accdb_fork_id_t f3 = fd_accdb_attach_child( accdb, root );

  FD_TEST( !accdb_read( accdb, f1, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !accdb_read( accdb, f2, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !accdb_read( accdb, f3, pubkey0, NULL, NULL, NULL, owner ) );

  accdb_write( accdb, f1, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST(  accdb_read( accdb, f1, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( !accdb_read( accdb, f2, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( !accdb_read( accdb, f3, pubkey1, &lamports, &d, &data_len, owner ) );

  accdb_write( accdb, f2, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST(  accdb_read( accdb, f1, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST(  accdb_read( accdb, f2, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( !accdb_read( accdb, f3, pubkey1, &lamports, &d, &data_len, owner ) );

  fd_accdb_fork_id_t f4 = fd_accdb_attach_child( accdb, f2 );
  fd_accdb_fork_id_t f5 = fd_accdb_attach_child( accdb, f3 );
  FD_TEST(  accdb_read( accdb, f4, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( !accdb_read( accdb, f5, pubkey1, &lamports, &d, &data_len, owner ) );

  close( fd );
}

void
test_root_forks( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f1 = fd_accdb_attach_child( accdb, root );
  fd_accdb_fork_id_t f2 = fd_accdb_attach_child( accdb, root );

  accdb_write( accdb, f2, pubkey1, 1UL, NULL, 0UL, owner2 );
  accdb_write( accdb, f1, pubkey1, 2UL, NULL, 0UL, owner2 );
  fd_accdb_fork_id_t f3 = fd_accdb_attach_child( accdb, f1 );
  accdb_write( accdb, f3, pubkey1, 3UL, NULL, 0UL, owner2 );

  FD_TEST( accdb_read( accdb, f1, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==2UL );
  FD_TEST( accdb_read( accdb, f2, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==1UL );
  FD_TEST( accdb_read( accdb, f3, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==3UL );

  /* Root f2: f1 and f3 are on a competing fork and should be purged. */
  fd_accdb_advance_root( accdb, f2 );
  drain_background( accdb );
  FD_TEST( accdb_read( accdb, f2, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==1UL );

  close( fd );
}

static uchar big_data[ 10UL*(1UL<<20) ];

void
test_compact( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t slot1 = fd_accdb_attach_child( accdb, root );

  ulong acct_sz = 10UL*(1UL<<20UL);
  ulong writes_fit_in_partition = (1UL<<30UL) / (acct_sz + META_SZ);

  /* Write-back model: committed data stays dirty in cache.  Repeated
     overwrites of the same account never touch disk, so disk_used_bytes
     remains 0 and the partition write-head does not advance. */
  for( ulong i=0UL; i<writes_fit_in_partition; i++ ) {
    accdb_write( accdb, slot1, pubkey1, 1UL, big_data, acct_sz, owner2 );
  }
  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_metrics( accdb );
  FD_TEST( metrics->accounts_total           == 1UL );
  FD_TEST( metrics->accounts_capacity        == 1024UL );
  FD_TEST( metrics->accounts_written         == writes_fit_in_partition );
  FD_TEST( metrics->disk_allocated_bytes     == 0UL );
  FD_TEST( metrics->disk_used_bytes          == 0UL );
  FD_TEST( metrics->in_compaction            == 0 );
  FD_TEST( metrics->compactions_requested    == 0UL );
  FD_TEST( metrics->compactions_completed    == 0UL );
  FD_TEST( metrics->accounts_relocated       == 0UL );
  FD_TEST( metrics->accounts_relocated_bytes == 0UL );
  FD_TEST( metrics->partitions_freed         == 0UL );

  close( fd );
}

/* Test that writing the same account multiple times on the same fork
   correctly updates the data each time and that reads return the
   latest version. */
void
test_overwrite_same_fork( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d[4];
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t slot1 = fd_accdb_attach_child( accdb, root );

  uchar data_a[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
  uchar data_b[4] = { 0x11, 0x22, 0x33, 0x44 };
  uchar data_c[2] = { 0xFF, 0xEE };

  accdb_write( accdb, slot1, pubkey1, 100UL, data_a, 4UL, owner2 );
  FD_TEST( accdb_read( accdb, slot1, pubkey1, &lamports, d, &data_len, owner ) );
  FD_TEST( lamports==100UL );
  FD_TEST( data_len==4UL );
  FD_TEST( !memcmp( d, data_a, 4UL ) );

  accdb_write( accdb, slot1, pubkey1, 200UL, data_b, 4UL, owner3 );
  FD_TEST( accdb_read( accdb, slot1, pubkey1, &lamports, d, &data_len, owner ) );
  FD_TEST( lamports==200UL );
  FD_TEST( data_len==4UL );
  FD_TEST( !memcmp( d, data_b, 4UL ) );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  accdb_write( accdb, slot1, pubkey1, 300UL, data_c, 2UL, owner2 );
  FD_TEST( accdb_read( accdb, slot1, pubkey1, &lamports, d, &data_len, owner ) );
  FD_TEST( lamports==300UL );
  FD_TEST( data_len==2UL );
  FD_TEST( !memcmp( d, data_c, 2UL ) );
  FD_TEST( !memcmp( owner, owner2, 32UL ) );

  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_metrics( accdb );
  FD_TEST( metrics->accounts_total == 1UL );

  close( fd );
}

/* Test that multiple distinct accounts can coexist and be read back
   correctly on different forks. */
void
test_multiple_accounts( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  uchar pk_a[ 32UL ] = { 10 };
  uchar pk_b[ 32UL ] = { 20 };
  uchar pk_c[ 32UL ] = { 30 };

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f1    = fd_accdb_attach_child( accdb, root );

  accdb_write( accdb, f1, pk_a, 10UL, NULL, 0UL, owner2 );
  accdb_write( accdb, f1, pk_b, 20UL, NULL, 0UL, owner2 );
  accdb_write( accdb, f1, pk_c, 30UL, NULL, 0UL, owner3 );

  FD_TEST( accdb_read( accdb, f1, pk_a, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==10UL );
  FD_TEST( accdb_read( accdb, f1, pk_b, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==20UL );
  FD_TEST( accdb_read( accdb, f1, pk_c, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==30UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_metrics( accdb );
  FD_TEST( metrics->accounts_total == 3UL );

  close( fd );
}

/* Test advancing the root through a chain of slots: root->A->B->C,
   root each one in sequence, then verify the last is still readable. */
void
test_sequential_rooting( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t a = fd_accdb_attach_child( accdb, root );
  accdb_write( accdb, root, pubkey1, 1UL, NULL, 0UL, owner2 );
  accdb_write( accdb, a, pubkey1, 2UL, NULL, 0UL, owner2 );

  fd_accdb_advance_root( accdb, a );
  drain_background( accdb );

  fd_accdb_fork_id_t b = fd_accdb_attach_child( accdb, a );
  accdb_write( accdb, b, pubkey1, 3UL, NULL, 0UL, owner2 );
  FD_TEST( accdb_read( accdb, b, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==3UL );

  fd_accdb_advance_root( accdb, b );
  drain_background( accdb );

  fd_accdb_fork_id_t c = fd_accdb_attach_child( accdb, b );
  FD_TEST( accdb_read( accdb, c, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==3UL );

  accdb_write( accdb, c, pubkey1, 4UL, NULL, 0UL, owner3 );
  FD_TEST( accdb_read( accdb, c, pubkey1, &lamports, &d, &data_len, owner ) );
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
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  uchar pk_a[ 32UL ] = { 0xA0 };
  uchar pk_b[ 32UL ] = { 0xB0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t keep = fd_accdb_attach_child( accdb, root );
  fd_accdb_fork_id_t drop = fd_accdb_attach_child( accdb, root );

  accdb_write( accdb, keep, pk_a, 100UL, NULL, 0UL, owner2 );
  accdb_write( accdb, drop, pk_b,  50UL, NULL, 0UL, owner2 );

  FD_TEST(  accdb_read( accdb, keep, pk_a, &lamports, &d, &data_len, owner ) );
  FD_TEST(  accdb_read( accdb, drop, pk_b, &lamports, &d, &data_len, owner ) );

  fd_accdb_purge( accdb, drop );
  drain_background( accdb );

  /* The account on the kept fork should still be there. */
  FD_TEST( accdb_read( accdb, keep, pk_a, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==100UL );

  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_metrics( accdb );
  FD_TEST( metrics->accounts_total == 1UL );

  close( fd );
}

/* Test that child forks inherit writes from their parent (ancestor
   visibility) and that overwriting on the child does not affect the
   parent's view. */
void
test_child_inherits_parent( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root   = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t parent = fd_accdb_attach_child( accdb, root );
  accdb_write( accdb, parent, pubkey1, 10UL, NULL, 0UL, owner2 );

  fd_accdb_fork_id_t child = fd_accdb_attach_child( accdb, parent );

  /* Child can see parent's write */
  FD_TEST( accdb_read( accdb, child, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==10UL );

  /* Overwrite on child */
  accdb_write( accdb, child, pubkey1, 99UL, NULL, 0UL, owner3 );
  FD_TEST( accdb_read( accdb, child, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==99UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  /* Parent still sees original */
  FD_TEST( accdb_read( accdb, parent, pubkey1, &lamports, &d, &data_len, owner ) );
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
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

# define DEPTH (10UL)
  fd_accdb_fork_id_t chain[ DEPTH ];

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  chain[ 0 ] = fd_accdb_attach_child( accdb, root );
  accdb_write( accdb, chain[ 0 ], pubkey1, 1UL, NULL, 0UL, owner2 );
  for( ulong i=1UL; i<DEPTH; i++ ) {
    chain[ i ] = fd_accdb_attach_child( accdb, chain[ i-1UL ] );
    accdb_write( accdb, chain[ i ], pubkey1, i+1UL, NULL, 0UL, owner2 );
  }

  /* Each fork should see its own write. */
  for( ulong i=0UL; i<DEPTH; i++ ) {
    FD_TEST( accdb_read( accdb, chain[ i ], pubkey1, &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==i+1UL );
  }

  /* Root through the first 5 levels. */
  for( ulong i=0UL; i<5UL; i++ ) {
    fd_accdb_advance_root( accdb, chain[ i ] );
    drain_background( accdb );
  }

  /* Deeper forks still see their own values. */
  for( ulong i=5UL; i<DEPTH; i++ ) {
    FD_TEST( accdb_read( accdb, chain[ i ], pubkey1, &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==i+1UL );
  }

  /* The rooted slot sees the value that was written on it. */
  FD_TEST( accdb_read( accdb, chain[ 4 ], pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==5UL );

  /* Rooting should have tombstoned the versions from chain[0]..chain[3]
     (4 old versions removed).  The 5 remaining forks (chain[4]..chain[9])
     each still have one live entry, but they all share the same pubkey.
     However only chain[5]..chain[9] wrote separate entries (chain[4] is
     the new root and its entry persists).  The first rooting (chain[0])
     does not tombstone anything because root had no txns, so 4 versions
     are removed.  10 original - 4 tombstoned = 6. */
  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==6UL );

# undef DEPTH
  close( fd );
}

/* Create a wide fan-out: one parent with 16 sibling children, each
   writing the same pubkey with a unique lamports value.  Verify
   perfect fork isolation-each sibling reads only its own value. */
void
test_wide_fanout_isolation( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

# define SIBLINGS (16UL)
  fd_accdb_fork_id_t root   = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t parent = fd_accdb_attach_child( accdb, root );
  fd_accdb_fork_id_t sibs[ SIBLINGS ];

  for( ulong i=0UL; i<SIBLINGS; i++ ) {
    sibs[ i ] = fd_accdb_attach_child( accdb, parent );
    accdb_write( accdb, sibs[ i ], pubkey1, (i+1UL)*100UL, NULL, 0UL, owner2 );
  }

  /* Each sibling should read back exactly its own lamports. */
  for( ulong i=0UL; i<SIBLINGS; i++ ) {
    FD_TEST( accdb_read( accdb, sibs[ i ], pubkey1, &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==(i+1UL)*100UL );
  }

  /* Parent should not see any of the children's writes. */
  FD_TEST( !accdb_read( accdb, parent, pubkey1, &lamports, &d, &data_len, owner ) );

  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==SIBLINGS );

# undef SIBLINGS
  close( fd );
}

/* Purge a fork that has children and grandchildren.  Verify the
   entire subtree is recursively removed, while a sibling subtree
   survives. */
void
test_purge_deep_subtree( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  uchar pk_a[ 32UL ] = { 0xDA };
  uchar pk_b[ 32UL ] = { 0xDB };
  uchar pk_c[ 32UL ] = { 0xDC };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t keep = fd_accdb_attach_child( accdb, root );
  fd_accdb_fork_id_t drop = fd_accdb_attach_child( accdb, root );

  /* Build a subtree under drop: drop -> child -> grandchild */
  fd_accdb_fork_id_t drop_child      = fd_accdb_attach_child( accdb, drop );
  fd_accdb_fork_id_t drop_grandchild = fd_accdb_attach_child( accdb, drop_child );

  accdb_write( accdb, drop,            pk_a, 1UL, NULL, 0UL, owner2 );
  accdb_write( accdb, drop_child,      pk_b, 2UL, NULL, 0UL, owner2 );
  accdb_write( accdb, drop_grandchild, pk_c, 3UL, NULL, 0UL, owner2 );
  accdb_write( accdb, keep,            pk_a, 9UL, NULL, 0UL, owner3 );

  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==4UL );

  fd_accdb_purge( accdb, drop );
  drain_background( accdb );

  /* Only the account on the kept fork should remain. */
  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==1UL );
  FD_TEST( accdb_read( accdb, keep, pk_a, &lamports, &d, &data_len, owner ) );
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
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t a    = fd_accdb_attach_child( accdb, root );

  accdb_write( accdb, root, pubkey1, 10UL, NULL, 0UL, owner2 );
  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==1UL );

  accdb_write( accdb, a, pubkey1, 20UL, NULL, 0UL, owner3 );
  /* Two index entries exist now: one for root, one for a. */
  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==2UL );

  fd_accdb_advance_root( accdb, a );
  drain_background( accdb );

  /* After rooting, the older version on root should have been
     tombstoned, leaving exactly one live entry. */
  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==1UL );

  FD_TEST( accdb_read( accdb, a, pubkey1, &lamports, &d, &data_len, owner ) );
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
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

# define N_ACCTS (200UL)

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f    = fd_accdb_attach_child( accdb, root );

  uchar pks[ N_ACCTS ][ 32UL ];
  for( ulong i=0UL; i<N_ACCTS; i++ ) {
    fd_memset( pks[ i ], 0, 32UL );
    /* Spread keys across the first 4 bytes to create varied hashes. */
    pks[ i ][ 0 ] = (uchar)( i       & 0xFFUL);
    pks[ i ][ 1 ] = (uchar)((i>> 8UL)& 0xFFUL);
    pks[ i ][ 2 ] = (uchar)((i>>16UL)& 0xFFUL);
    pks[ i ][ 3 ] = (uchar)((i>>24UL)& 0xFFUL);

    accdb_write( accdb, f, pks[ i ], i+1UL, NULL, 0UL, owner2 );
  }

  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==N_ACCTS );

  /* Read every account back and verify. */
  for( ulong i=0UL; i<N_ACCTS; i++ ) {
    FD_TEST( accdb_read( accdb, f, pks[ i ], &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==i+1UL );
  }

  /* Overwrite the first 50 and verify again. */
  for( ulong i=0UL; i<50UL; i++ ) {
    accdb_write( accdb, f, pks[ i ], (i+1UL)*1000UL, NULL, 0UL, owner3 );
  }

  FD_TEST( fd_accdb_metrics( accdb )->accounts_total==N_ACCTS );
  for( ulong i=0UL; i<50UL; i++ ) {
    FD_TEST( accdb_read( accdb, f, pks[ i ], &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==(i+1UL)*1000UL );
    FD_TEST( !memcmp( owner, owner3, 32UL ) );
  }
  for( ulong i=50UL; i<N_ACCTS; i++ ) {
    FD_TEST( accdb_read( accdb, f, pks[ i ], &lamports, &d, &data_len, owner ) );
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
     partition_sz                = 1 GiB
     cache_footprint             = 32 GiB */
  ulong max_accounts                = 1200000000UL;
  ulong max_live_slots              = 4096UL;
  ulong max_account_writes_per_slot = 64UL * (100000000UL / (300UL*64UL + 720UL));
  ulong partition_cnt               = 8192UL;
  ulong cache_footprint             = 32UL*(1UL<<30UL);

  FD_TEST( max_account_writes_per_slot==321280UL );

  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, cache_footprint, 1UL );
  FD_TEST( shmem_fp );

  ulong accdb_fp = fd_accdb_footprint( max_live_slots );
  FD_TEST( accdb_fp );

  /* Derived values for component breakdown */
  ulong txn_max   = max_live_slots * max_account_writes_per_slot;
  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );

  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];
  FD_TEST( fd_accdb_cache_class_cnt( cache_footprint, cache_class_max ) );

  ulong total_cache_slots = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) total_cache_slots += cache_class_max[c];

  ulong total = shmem_fp + accdb_fp;
  FD_LOG_NOTICE(( "mainnet footprint: %lu bytes (%.2f GiB)", total, (double)total/(double)(1UL<<30UL) ));
  FD_LOG_NOTICE(( "  shmem_footprint             = %lu bytes (%.2f GiB)", shmem_fp, (double)shmem_fp/(double)(1UL<<30UL) ));
  FD_LOG_NOTICE(( "  accdb_footprint             = %lu bytes (%.2f MiB)", accdb_fp, (double)accdb_fp/(double)(1UL<<20UL) ));
  FD_LOG_NOTICE(( "parameters:" ));
  FD_LOG_NOTICE(( "  max_accounts                = %lu",     max_accounts ));
  FD_LOG_NOTICE(( "  max_live_slots              = %lu",     max_live_slots ));
  FD_LOG_NOTICE(( "  max_account_writes_per_slot = %lu",     max_account_writes_per_slot ));
  FD_LOG_NOTICE(( "  partition_cnt               = %lu",     partition_cnt ));
  FD_LOG_NOTICE(( "  txn_pool_max                = %lu",     txn_max ));
  FD_LOG_NOTICE(( "  chain_cnt                   = %lu",     chain_cnt ));
  FD_LOG_NOTICE(( "  max disk file               = %lu GiB", partition_cnt*(1UL<<30UL)/(1UL<<30UL) ));
  FD_LOG_NOTICE(( "  cache_footprint             = %lu GiB", cache_footprint/(1UL<<30UL) ));
  FD_LOG_NOTICE(( "  total_cache_slots           = %lu",     total_cache_slots ));
  FD_LOG_NOTICE(( "cache class breakdown:" ));
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong class_bytes = cache_class_max[c] * fd_accdb_cache_slot_sz[c];
    FD_LOG_NOTICE(( "  class %lu: %lu slots x %lu B = %.2f GiB",
                    c, cache_class_max[c], fd_accdb_cache_slot_sz[c],
                    (double)class_bytes/(double)(1UL<<30UL) ));
  }
  FD_LOG_NOTICE(( "shmem_footprint breakdown (descending):" ));

  ulong descends_fp       = descends_set_footprint( max_live_slots );

  ulong sz_shmem_t        = sizeof(fd_accdb_shmem_t);
  ulong sz_fork_pool      = fork_pool_footprint();
  ulong sz_fork_shmem     = max_live_slots*sizeof(fd_accdb_fork_shmem_t);
  ulong sz_descends       = max_live_slots*descends_fp;
  ulong sz_chain          = chain_cnt*sizeof(uint);
  ulong sz_acc_pool_meta  = acc_pool_footprint();
  ulong sz_acc_pool       = max_accounts*sizeof(fd_accdb_acc_t);
  ulong sz_txn_pool_meta  = txn_pool_footprint();
  ulong sz_txn_pool       = txn_max*sizeof(fd_accdb_txn_t);
  ulong sz_part_pool      = partition_pool_footprint( partition_cnt );
  ulong sz_compact_dlists = FD_ACCDB_COMPACTION_LAYER_CNT*compaction_dlist_footprint();
  ulong sz_deferred_dlist = deferred_free_dlist_footprint();
  ulong sz_cache_regions  = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
    sz_cache_regions += cache_class_max[c]*fd_accdb_cache_slot_sz[c];

  ulong sum = sz_shmem_t + sz_fork_pool + sz_fork_shmem + sz_descends
            + sz_chain
            + sz_acc_pool_meta + sz_acc_pool
            + sz_txn_pool_meta + sz_txn_pool
            + sz_part_pool + sz_compact_dlists + sz_deferred_dlist
            + sz_cache_regions;

  struct { char const * name; ulong sz; } rows[] = {
    { "acc_pool",           sz_acc_pool       },
    { "cache regions",      sz_cache_regions  },
    { "txn_pool",           sz_txn_pool       },
    { "acc_map chains",     sz_chain          },
    { "descends_set",       sz_descends       },
    { "partition_pool",     sz_part_pool      },
    { "fork_shmem",         sz_fork_shmem     },
    { "fd_accdb_shmem_t",   sz_shmem_t       },
    { "fork_pool meta",     sz_fork_pool      },
    { "acc_pool meta",      sz_acc_pool_meta  },
    { "txn_pool meta",      sz_txn_pool_meta  },
    { "compaction_dlists",  sz_compact_dlists },
    { "deferred_free_dlist",sz_deferred_dlist },
  };
  ulong n_rows = sizeof(rows)/sizeof(rows[0]);

  /* Simple insertion sort descending */
  for( ulong i=1UL; i<n_rows; i++ ) {
    ulong key = rows[i].sz;
    char const * kn = rows[i].name;
    ulong j = i;
    while( j>0UL && rows[j-1UL].sz<key ) {
      rows[j] = rows[j-1UL];
      j--;
    }
    rows[j].sz   = key;
    rows[j].name = kn;
  }

  for( ulong i=0UL; i<n_rows; i++ ) {
    FD_LOG_NOTICE(( "  %-24s %15lu  (%7.2f GiB)",
                    rows[i].name, rows[i].sz,
                    (double)rows[i].sz/(double)(1UL<<30UL) ));
  }
  FD_LOG_NOTICE(( "  %-24s %15s   %s", "---", "---", "---" ));
  FD_LOG_NOTICE(( "  %-24s %15lu  (%7.2f GiB)", "sum (pre-align)",  sum,      (double)sum/(double)(1UL<<30UL) ));
  FD_LOG_NOTICE(( "  %-24s %15lu  (%7.2f GiB)", "shmem_footprint",  shmem_fp, (double)shmem_fp/(double)(1UL<<30UL) ));
  FD_LOG_NOTICE(( "background eviction watermarks:" ));
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong max_c    = cache_class_max[ c ];
    ulong floor_c  = fd_ulong_min( FD_ACCDB_CACHE_MIN_RESERVED, max_c );
    ulong headroom = ( max_c>floor_c ) ? ( max_c - floor_c ) : 0UL;
    ulong cap      = fd_ulong_min( 8192UL, (64UL<<20) / fd_accdb_cache_slot_sz[ c ] );
    ulong target   = fd_ulong_min( headroom/20UL, cap );
    ulong low      = target / 2UL;
    FD_LOG_NOTICE(( "  class %lu: target=%lu  low_water=%lu  "
                    "(max=%lu  reserved=%lu  headroom=%lu  cap=%lu)",
                    c, target, low, max_c, floor_c, headroom, cap ));
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "test_basic ..." ));
  test_basic();

  FD_LOG_NOTICE(( "test_background_preevict_ignores_uninitialized_tail ..." ));
  test_background_preevict_ignores_uninitialized_tail();

  FD_LOG_NOTICE(( "test_missing_readonly_account_initializes_entry ..." ));
  test_missing_readonly_account_initializes_entry();

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
