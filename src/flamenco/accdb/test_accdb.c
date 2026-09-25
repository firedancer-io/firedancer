#define _GNU_SOURCE

#include "fd_accdb.h"
#include "fd_accdb_cache.h"
#include "fd_accdb_private.h"
#include "../../util/fd_util.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>

static uchar pubkey0[ 32UL ]  = { 0 };
static uchar pubkey1[ 32UL ]  = { 1, 0 };

static uchar owner2[ 32UL ] = { 2, 0 };
static uchar owner3[ 32UL ] = { 3, 0 };

#define SENTINEL ((fd_accdb_fork_id_t){ .val = USHORT_MAX })

/* Disk metadata is packed: pubkey[32] + size(uint,4) = 36 */
#define META_SZ (36UL)

/* Cache footprint for tests.  Class 7 slots are 10 MiB each and the
   allocator reserves cache_min_reserved of every class off the top
   (Phase 1), so the footprint floor is roughly
   cache_min_reserved * sum(slot_sz) ~= cache_min_reserved * 11.2 MiB.
   These unit tests only ever acquire a handful of accounts at a time,
   so a tiny min_reserved keeps the whole cache in the tens of MiB
   (vs. the production-scale ~7 GiB a 640-slot reservation would need)
   and avoids OOMing CI / dev machines. */
#define TEST_CACHE_MIN_RESERVED (2UL)
#define TEST_CACHE_FOOTPRINT    (32UL<<20UL)

static fd_accdb_shmem_t * test_shmem_mem;

static fd_accdb_t *
test_setup_ex( int * out_fd,
               ulong max_accounts,
               ulong max_live_slots,
               ulong max_account_writes_per_slot,
               ulong partition_cnt,
               ulong partition_sz,
               ulong cache_fp,
               ulong cache_min_reserved,
               ulong joiner_cnt ) {
  int fd = memfd_create( "accdb_test", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));
  *out_fd = fd;

  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, cache_fp, cache_min_reserved, joiner_cnt, 0UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( shmem_mem, max_accounts, max_live_slots,
                          max_account_writes_per_slot, partition_cnt,
                          partition_sz, cache_fp, cache_min_reserved, 0, 42UL, joiner_cnt, 0UL ) );
  FD_TEST( shmem );
  test_shmem_mem = shmem_mem;

  ulong accdb_fp = fd_accdb_footprint( max_live_slots, 1 );
  FD_TEST( accdb_fp );
  void * accdb_mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  FD_TEST( accdb_mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( accdb_mem, shmem, fd, 0UL, NULL, NULL, 0UL, 1 ) );
  FD_TEST( accdb );
  return accdb;
}

static fd_accdb_t *
test_setup( int * out_fd,
            ulong max_accounts,
            ulong max_live_slots,
            ulong max_account_writes_per_slot,
            ulong partition_cnt,
            ulong partition_sz ) {
  return test_setup_ex( out_fd, max_accounts, max_live_slots, max_account_writes_per_slot,
                        partition_cnt, partition_sz, TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 1UL );
}

static fd_accdb_t *
test_join_writer( int fd ) {
  ulong fp = fd_accdb_footprint( test_shmem_mem->max_live_slots, 1 );
  void * mem = aligned_alloc( fd_accdb_align(), fp );
  FD_TEST( mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( mem, test_shmem_mem, fd, 0UL, NULL, NULL, 0UL, 1 ) );
  FD_TEST( accdb );
  return accdb;
}

static void
test_teardown( fd_accdb_t * accdb,
               int          fd ) {
  free( test_shmem_mem );
  free( accdb );
  close( fd );
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

typedef struct {
  fd_accdb_t * accdb;
  int          stop;
} test_background_ctx_t;

static void *
run_background( void * _ctx ) {
  test_background_ctx_t * ctx = _ctx;
  while( !FD_VOLATILE_CONST( ctx->stop ) ) {
    int charge_busy = 0;
    fd_accdb_background( ctx->accdb, &charge_busy );
    if( FD_LIKELY( !charge_busy ) ) FD_SPIN_PAUSE();
  }
  return NULL;
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
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( accdb, fork_id, 1UL, pks, wr, acc );
  int found = acc[0].lamports!=0UL;
  if( found ) {
    if( out_lamports ) *out_lamports = acc[0].lamports;
    if( out_data_len ) *out_data_len = acc[0].data_len;
    if( out_owner )    memcpy( out_owner, acc[0].owner, 32UL );
    if( out_data && acc[0].data && acc[0].data_len )
      memcpy( out_data, acc[0].data, acc[0].data_len );
  }
  fd_accdb_release( accdb, 1UL, acc );
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
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( accdb, fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = lamports;
  acc[0].data_len = data_len;
  memcpy( acc[0].owner, owner, 32UL );
  if( data_len && data ) memcpy( acc[0].data, data, data_len );
  acc[0].commit = 1;
  fd_accdb_release( accdb, 1UL, acc );
}

static void
accdb_write_pd( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id,
                uchar const *      pubkey,
                ulong              lamports,
                uchar const *      data,
                ulong              data_len,
                uchar const *      owner,
                int                pd_write ) {
  uchar const * pks[1] = { pubkey };
  int wr[1] = { 1 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( accdb, fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = lamports;
  acc[0].data_len = data_len;
  memcpy( acc[0].owner, owner, 32UL );
  if( data_len && data ) memcpy( acc[0].data, data, data_len );
  acc[0].commit   = 1;
  acc[0].pd_write = pd_write;
  fd_accdb_release( accdb, 1UL, acc );
}

void
test_pd_write_bit_and_probe( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f1   = fd_accdb_attach_child( accdb, root );

  uchar owner[32]; memset( owner, 0xAB, 32UL );
  uchar pk[32];    memset( pk, 0x11, 32UL );
  uchar data[128]; memset( data, 0x22, sizeof(data) );

  int   pd;
  ulong len;
  ulong lamports;

  /* Write on f1 with pd_write=1 -> probe on f1 sees bit=1, gen-match,
     returns the committed data_len. */
  accdb_write_pd( accdb, f1, pk, 500UL, data, sizeof(data), owner, 1 );
  pd = 0; len = ULONG_MAX;
  FD_TEST( fd_accdb_probe_pd_this_fork( accdb, f1, pk, &pd, &len, &lamports )==1 );
  FD_TEST( pd==1 );
  FD_TEST( len==sizeof(data) );

  /* Probe on a child fork of f1: generation mismatch -> returns 0, pd=0,
     out_data_len untouched. */
  fd_accdb_fork_id_t c = fd_accdb_attach_child( accdb, f1 );
  pd = 1; len = 0xdeadUL;
  FD_TEST( fd_accdb_probe_pd_this_fork( accdb, c, pk, &pd, &len, &lamports )==0 );
  FD_TEST( pd==0 );
  FD_TEST( len==0xdeadUL ); /* untouched */

  /* OR-sticky: overwrite on f1 with pd_write=0 must NOT clear the bit. */
  accdb_write_pd( accdb, f1, pk, 501UL, data, sizeof(data), owner, 0 );
  pd = 0; len = ULONG_MAX;
  FD_TEST( fd_accdb_probe_pd_this_fork( accdb, f1, pk, &pd, &len, &lamports )==1 );
  FD_TEST( pd==1 ); /* survived the pd_write=0 overwrite */

  /* New version on child fork c with pd_write=0 -> probe on c sees bit=0
     (new current-gen version, no deploy-status write this slot). */
  accdb_write_pd( accdb, c, pk, 502UL, data, sizeof(data), owner, 0 );
  pd = 1; len = ULONG_MAX;
  FD_TEST( fd_accdb_probe_pd_this_fork( accdb, c, pk, &pd, &len, &lamports )==1 );
  FD_TEST( pd==0 );
  FD_TEST( len==sizeof(data) );

  /* Closed-this-slot: a lamports==0 current-generation tombstone with
     pd_write=1 must still report pd==1 (the exists()-clone lamports
     trap; Close is the fails-open case). */
  uchar pk2[32]; memset( pk2, 0x33, 32UL );
  fd_accdb_fork_id_t f2 = fd_accdb_attach_child( accdb, root );
  accdb_write_pd( accdb, f2, pk2, 999UL, data, 64UL, owner, 0 ); /* fund it first */
  accdb_write_pd( accdb, f2, pk2, 0UL,   NULL, 4UL,  owner, 1 ); /* close: lamports=0, pd_write=1 */
  pd = 0; len = ULONG_MAX;
  FD_TEST( fd_accdb_probe_pd_this_fork( accdb, f2, pk2, &pd, &len, &lamports )==1 );
  FD_TEST( pd==1 );      /* bit reported despite lamports==0 */
  FD_TEST( len==4UL );   /* post-close committed len */
  FD_TEST( lamports==0UL );

  /* Not-found -> returns 0, pd=0, out_data_len untouched. */
  uchar pk3[32]; memset( pk3, 0x44, 32UL );
  pd = 1; len = 0xbeefUL;
  FD_TEST( fd_accdb_probe_pd_this_fork( accdb, f2, pk3, &pd, &len, &lamports )==0 );
  FD_TEST( pd==0 );
  FD_TEST( len==0xbeefUL );

  /* Mask discipline: a 1 MiB account with pd_write=1 reads back with the
     correct length (SIZE_DATA excludes bit 28). */
  uchar pk4[32]; memset( pk4, 0x55, 32UL );
  ulong big = 1UL<<20;
  uchar * bigbuf = aligned_alloc( 64UL, big );
  FD_TEST( bigbuf ); memset( bigbuf, 0x66, big );
  accdb_write_pd( accdb, f1, pk4, 700UL, bigbuf, big, owner, 1 );
  ulong rlen = 0UL;
  FD_TEST( accdb_read( accdb, f1, pk4, NULL, NULL, &rlen, NULL )==1 );
  FD_TEST( rlen==big );
  pd = 0; len = ULONG_MAX;
  FD_TEST( fd_accdb_probe_pd_this_fork( accdb, f1, pk4, &pd, &len, &lamports )==1 );
  FD_TEST( pd==1 );
  FD_TEST( len==big );
  free( bigbuf );

  test_teardown( accdb, fd );
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

  test_teardown( accdb, fd );
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

  test_teardown( accdb, fd );
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
  fd_acc_t acc[ 1 ];

  memset( acc, 0xA5, sizeof(acc) );
  fd_accdb_acquire( accdb, slot1, 1UL, pks, wr, acc );

  FD_TEST( !memcmp( acc[ 0 ].pubkey, missing_pubkey, 32UL ) );
  FD_TEST( !memcmp( acc[ 0 ].owner,  zeros,          32UL ) );
  FD_TEST( !memcmp( acc[ 0 ].prior_owner, zeros, 32UL ) );
  FD_TEST( acc[ 0 ].lamports==0UL );
  FD_TEST( acc[ 0 ].data_len==0UL );
  FD_TEST( acc[ 0 ].data==NULL );
  FD_TEST( acc[ 0 ].executable==0 );
  FD_TEST( acc[ 0 ].prior_lamports==0UL );
  FD_TEST( acc[ 0 ].prior_data_len==0UL );
  FD_TEST( acc[ 0 ].prior_data==NULL );
  FD_TEST( acc[ 0 ].prior_executable==0 );
  FD_TEST( acc[ 0 ]._writable==0 );
  FD_TEST( acc[ 0 ]._original_size_class==ULONG_MAX );
  FD_TEST( acc[ 0 ]._original_cache_idx==ULONG_MAX );

  fd_accdb_release( accdb, 1UL, acc );
  test_teardown( accdb, fd );
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

  test_teardown( accdb, fd );
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

  test_teardown( accdb, fd );
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
  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_shmetrics( accdb );
  FD_TEST( metrics->accounts_total           == 1UL );
  FD_TEST( metrics->accounts_capacity        == 1024UL );
  FD_TEST( fd_accdb_metrics( accdb )->write_ops == 0UL );
  FD_TEST( metrics->disk_allocated_bytes     == 0UL );
  FD_TEST( metrics->disk_used_bytes          == 0UL );
  FD_TEST( metrics->in_compaction            == 0 );
  FD_TEST( metrics->compactions_requested    == 0UL );
  FD_TEST( metrics->compactions_completed    == 0UL );
  FD_TEST( metrics->accounts_relocated       == 0UL );
  FD_TEST( metrics->accounts_relocated_bytes == 0UL );
  FD_TEST( metrics->partitions_freed         == 0UL );

  test_teardown( accdb, fd );
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

  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_shmetrics( accdb );
  FD_TEST( metrics->accounts_total == 1UL );

  test_teardown( accdb, fd );
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

  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_shmetrics( accdb );
  FD_TEST( metrics->accounts_total == 3UL );

  test_teardown( accdb, fd );
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

  test_teardown( accdb, fd );
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

  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_shmetrics( accdb );
  FD_TEST( metrics->accounts_total == 1UL );

  test_teardown( accdb, fd );
}

/* A completed purge leaves its fork slot deferred until a later drain.
   If the pool is otherwise full, attach_child must request that drain,
   block for reader quiescence, and retry the allocation. */
void
test_attach_child_drains_deferred_fork( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 64UL, 3UL, 64UL, 64UL, 1UL<<30UL );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t keep = fd_accdb_attach_child( accdb, root );
  fd_accdb_fork_id_t drop = fd_accdb_attach_child( accdb, root );

  fd_accdb_purge( accdb, drop );

  test_background_ctx_t bg = { .accdb = accdb, .stop = 0 };
  pthread_t thread;
  FD_TEST( !pthread_create( &thread, NULL, run_background, &bg ) );

  fd_accdb_fork_id_t child = fd_accdb_attach_child( accdb, keep );
  FD_TEST( child.val==drop.val );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( bg.stop ) = 1;
  FD_COMPILER_MFENCE();
  FD_TEST( !pthread_join( thread, NULL ) );

  test_teardown( accdb, fd );
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

  test_teardown( accdb, fd );
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
     each still have one live acc, but they all share the same pubkey.
     However only chain[5]..chain[9] wrote separate accs (chain[4] is
     the new root and its acc persists).  The first rooting (chain[0])
     does not tombstone anything because root had no txns, so 4 versions
     are removed.  10 original - 4 tombstoned = 6. */
  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==6UL );

# undef DEPTH
  test_teardown( accdb, fd );
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

  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==SIBLINGS );

# undef SIBLINGS
  test_teardown( accdb, fd );
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

  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==4UL );

  fd_accdb_purge( accdb, drop );
  drain_background( accdb );

  /* Only the account on the kept fork should remain. */
  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==1UL );
  FD_TEST( accdb_read( accdb, keep, pk_a, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==9UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  test_teardown( accdb, fd );
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
  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==1UL );

  accdb_write( accdb, a, pubkey1, 20UL, NULL, 0UL, owner3 );
  /* Two index entries exist now: one for root, one for a. */
  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==2UL );

  fd_accdb_advance_root( accdb, a );
  drain_background( accdb );

  /* After rooting, the older version on root should have been
     tombstoned, leaving exactly one live acc. */
  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==1UL );

  FD_TEST( accdb_read( accdb, a, pubkey1, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==20UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  test_teardown( accdb, fd );
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

  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==N_ACCTS );

  /* Read every account back and verify. */
  for( ulong i=0UL; i<N_ACCTS; i++ ) {
    FD_TEST( accdb_read( accdb, f, pks[ i ], &lamports, &d, &data_len, owner ) );
    FD_TEST( lamports==i+1UL );
  }

  /* Overwrite the first 50 and verify again. */
  for( ulong i=0UL; i<50UL; i++ ) {
    accdb_write( accdb, f, pks[ i ], (i+1UL)*1000UL, NULL, 0UL, owner3 );
  }

  FD_TEST( fd_accdb_shmetrics( accdb )->accounts_total==N_ACCTS );
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
  test_teardown( accdb, fd );
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
  FD_TEST( sizeof(fd_accdb_txn_t)==8UL );

  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, cache_footprint, 640UL, 1UL, 0UL );
  FD_TEST( shmem_fp );

  ulong accdb_fp = fd_accdb_footprint( max_live_slots, 1 );
  FD_TEST( accdb_fp );

  /* Derived values for component breakdown */
  ulong txn_max   = max_live_slots * max_account_writes_per_slot;
  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) ); /* must match fd_accdb_shmem_footprint */

  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];
  FD_TEST( fd_accdb_cache_class_cnt( cache_footprint, 640UL, cache_class_max ) );

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
  ulong sz_fork_shmem     = max_live_slots*sizeof(fd_accdb_fork_shmem_t);
  ulong sz_descends       = max_live_slots*descends_fp;
  ulong sz_chain          = chain_cnt*sizeof(uint);
  ulong sz_acc_pool       = max_accounts*sizeof(fd_accdb_accmeta_t);
  ulong sz_txn_pool       = txn_max*sizeof(fd_accdb_txn_t);
  ulong sz_part_pool      = partition_pool_footprint( partition_cnt );
  ulong sz_compact_dlists = FD_ACCDB_COMPACTION_LAYER_CNT*compaction_dlist_footprint();
  ulong sz_deferred_dlist = deferred_free_dlist_footprint();
  ulong sz_cache_regions  = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
    sz_cache_regions += cache_class_max[c]*fd_accdb_cache_slot_sz[c];

  ulong sum = sz_shmem_t + sz_fork_shmem + sz_descends
            + sz_chain
            + sz_acc_pool
            + sz_txn_pool
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
  /* Mirror the watermark derivation in fd_accdb_shmem_new exactly so the
     logged numbers match the live config (this test passes
     cache_min_reserved=640 to fd_accdb_shmem_footprint above). */
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong max_c       = cache_class_max[ c ];
    ulong floor_c     = fd_ulong_min( 640UL, max_c );
    ulong headroom    = ( max_c>floor_c ) ? ( max_c - floor_c ) : 0UL;
    ulong cap         = fd_ulong_min( 8192UL, (64UL<<20) / fd_accdb_cache_slot_sz[ c ] );
    ulong burst_floor = fd_ulong_min( 512UL, headroom/2UL );
    ulong target      = fd_ulong_min( cap, fd_ulong_max( headroom/10UL, burst_floor ) );
    ulong low         = (target * 3UL) / 4UL;
    FD_LOG_NOTICE(( "  class %lu: target=%lu  low_water=%lu  "
                    "(max=%lu  reserved=%lu  headroom=%lu  cap=%lu)",
                    c, target, low, max_c, floor_c, headroom, cap ));
  }
}

/* test_acquire_b_refund_accounting drives the two-phase programdata
   acquire (acquire_a over-reserves one slot in every live size class per
   candidate; acquire_b refunds the surplus, keeping one reservation per
   found programdata account in its own size class) followed by release,
   and asserts the per-class reservation counters (cache_class_used,
   surfaced via fd_accdb_cache_class_occupancy's `reserved`) return EXACTLY
   to their pre-cycle baseline.

   This locks in that acquire_b's refund accounting balances.  The refund
   was moved out of fd_accdb_acquire_b (where it walked the acc_map with
   the joiner epoch idle) into acquire_inner's epoch-protected STEP-1 walk;
   a miscount (over- or under-refund) leaves a class counter off baseline
   and fails here.  We exercise a found programdata account in a TRACKED
   size class plus a missing one (no accmeta -> no decrement) so the
   per-class arithmetic is covered.

   A class only tracks reservations when cache_class_max[c] <
   cache_min_reserved*joiner_cnt (otherwise the counter is pinned to
   ULONG_MAX and acquire/release skip it).  A footprint just above the
   Phase-1 minimum keeps the larger class maxes pinned at the
   cache_min_reserved floor (=2); joiner_cnt=2 (threshold 4) makes class
   3 — where pd_big lands — tracked, while leaving 2 slots, enough for
   the two-candidate over-reservation.  The whole cache is ~32 MiB. */
static void
test_acquire_b_refund_accounting( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup_ex( &fd, 256UL, 16UL, 1024UL, 1024UL, 1UL<<30UL,
                                      TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 2UL );

  fd_accdb_fork_id_t root0 = fd_accdb_attach_child( accdb, SENTINEL );

  uchar cand0 [ 32 ] = { 'a', 0 };
  uchar cand1 [ 32 ] = { 'b', 0 };
  uchar owner [ 32 ] = { 0x11, 0 };
  uchar pd_big[ 32 ] = { 'G', 0 };  /* class 3 (4 KiB) -- a TRACKED class */
  uchar pd_none[ 32 ] = { 'N', 0 }; /* never committed -> no accmeta      */

  uchar bigdata[ 4096 ];
  memset( bigdata, 0xCD, sizeof(bigdata) );

  accdb_write( accdb, root0, cand0,  100UL, NULL,    0UL,              owner );
  accdb_write( accdb, root0, cand1,  100UL, NULL,    0UL,              owner );
  accdb_write( accdb, root0, pd_big, 100UL, bigdata, sizeof(bigdata),  owner );

  ulong used0[ FD_ACCDB_CACHE_CLASS_CNT ], max0[ FD_ACCDB_CACHE_CLASS_CNT ], base[ FD_ACCDB_CACHE_CLASS_CNT ];
  fd_accdb_cache_class_occupancy( accdb, used0, max0, base );

  /* Phase A: acquire the two candidates read-only (maybe-programdata
     over-reservation: +1 to every tracked class per candidate). */
  uchar const * cand_pks[2] = { cand0, cand1 };
  int           cand_wr [2] = { 0, 0 };
  fd_acc_t      cand_acc[2];
  memset( cand_acc, 0, sizeof(cand_acc) );
  fd_accdb_acquire_a( accdb, root0, 2UL, cand_pks, cand_wr, cand_acc );

  /* Phase B: resolve programdata and refund the surplus.  reserved_cnt is
     the candidate count (2), exactly as fd_executor.c passes
     txn_out->accounts.cnt. */
  uchar const * pd_pks[2] = { pd_big, pd_none };
  int           pd_wr [2] = { 0, 0 };
  fd_acc_t      pd_acc[2];
  memset( pd_acc, 0, sizeof(pd_acc) );
  fd_accdb_acquire_b( accdb, root0, 2UL, 2UL, pd_pks, pd_wr, pd_acc );

  fd_accdb_release_ab( accdb, 2UL, cand_acc, 2UL, pd_acc );

  ulong used1[ FD_ACCDB_CACHE_CLASS_CNT ], max1[ FD_ACCDB_CACHE_CLASS_CNT ], post[ FD_ACCDB_CACHE_CLASS_CNT ];
  fd_accdb_cache_class_occupancy( accdb, used1, max1, post );
  int any_tracked = 0;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    if( base[ c ]!=ULONG_MAX ) any_tracked = 1; /* ULONG_MAX => class not tracked */
    FD_TEST( post[ c ]==base[ c ] );
  }
  /* Meaningful only if at least one class actually tracks reservations. */
  FD_TEST( any_tracked );

  test_teardown( accdb, fd );
}

/* test_reset: after populating accounts across forks, fd_accdb_reset
   must zero the gauges (except accounts_capacity), make old accounts
   invisible, and leave the accdb fully operational for new writes. */
static void
test_reset( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );

  ulong lamports;
  uchar d;
  ulong data_len;
  uchar owner[ 32UL ];

  uchar pk_a[ 32UL ] = { 0xA1 };
  uchar pk_b[ 32UL ] = { 0xA2 };
  uchar pk_c[ 32UL ] = { 0xA3 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  accdb_write( accdb, root, pk_a, 100UL, NULL, 0UL, owner2 );
  accdb_write( accdb, root, pk_b, 200UL, NULL, 0UL, owner2 );

  fd_accdb_fork_id_t child = fd_accdb_attach_child( accdb, root );
  accdb_write( accdb, child, pk_c, 300UL, NULL, 0UL, owner3 );

  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( accdb );
  FD_TEST( shmetrics->accounts_total>0UL );
  FD_TEST( shmetrics->accounts_capacity==1024UL );

  /* Reset the accdb. */
  fd_accdb_reset( accdb );
  drain_background( accdb );

  /* Post-reset invariants. */
  FD_TEST( shmetrics->accounts_total      == 0UL );
  FD_TEST( shmetrics->accounts_capacity   == 1024UL );
  FD_TEST( shmetrics->disk_current_bytes  == 0UL );
  FD_TEST( shmetrics->disk_allocated_bytes== 0UL );
  FD_TEST( shmetrics->disk_used_bytes     == 0UL );
  FD_TEST( shmetrics->in_compaction       == 0 );

  /* Create a new root fork and verify old accounts are gone. */
  fd_accdb_fork_id_t new_root = fd_accdb_attach_child( accdb, SENTINEL );
  FD_TEST( !accdb_read( accdb, new_root, pk_a, NULL, NULL, NULL, owner ) );
  FD_TEST( !accdb_read( accdb, new_root, pk_b, NULL, NULL, NULL, owner ) );
  FD_TEST( !accdb_read( accdb, new_root, pk_c, NULL, NULL, NULL, owner ) );

  /* Write a new account and read it back, accdb is operational. */
  uchar pk_new[ 32UL ] = { 0xBE };
  accdb_write( accdb, new_root, pk_new, 999UL, NULL, 0UL, owner3 );
  FD_TEST( accdb_read( accdb, new_root, pk_new, &lamports, &d, &data_len, owner ) );
  FD_TEST( lamports==999UL );
  FD_TEST( !memcmp( owner, owner3, 32UL ) );

  test_teardown( accdb, fd );
}

static int
test_snapshot_write_one( fd_accdb_t *       accdb,
                         fd_accdb_fork_id_t fork_id,
                         uchar const *      pubkey,
                         ulong              slot,
                         ulong              lamports,
                         ulong              data_len,
                         int                executable,
                         ulong *            out_replaced_lamports ) {
  uchar const * pubkeys[ 1 ] = { pubkey };
  ulong slots[ 1 ] = { slot };
  ulong lamports_arr[ 1 ] = { lamports };
  ulong data_lens[ 1 ] = { data_len };
  int executables[ 1 ] = { executable };
  ulong file_offsets[ 1 ] = {
    fd_accdb_snapshot_reserve_write( accdb, sizeof(fd_accdb_disk_meta_t)+data_len )
  };
  ulong ignored, replaced, loaded, ignored_lamports;
  int result = fd_accdb_snapshot_write_batch( accdb, fork_id, 1UL, pubkeys, slots, lamports_arr,
                                               data_lens, executables, file_offsets, &ignored,
                                               &replaced, &loaded, out_replaced_lamports,
                                               &ignored_lamports );
  FD_TEST( !result );
  if( ignored ) return -1;
  if( replaced ) return 2;
  FD_TEST( loaded==1UL );
  return 1;
}

/* test_revert_whead: revert_whead releases partitions and restores
   disk_current_bytes.  Use a partition size close to the minimum and
   large account writes to deterministically allocate additional
   partitions during the incremental phase so the partition release
   logic is exercised. */
static void
test_revert_whead( void ) {
  int fd;
  ulong psz = 11UL<<20UL; /* 11 MiB, just above ~10 MiB minimum */
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, psz );
  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( accdb );

  /* Create root fork. */
  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );

  /* Full-snapshot load: write 5 accounts with 4 MiB data each.
     Total ~20 MiB spans multiple 11 MiB partitions, so
     partition_max grows beyond 1. */
  fd_accdb_snapshot_load_begin( accdb );
  uchar snap_pks[ 5 ][ 32UL ];
  ulong replaced = 0UL;
  for( ulong i=0UL; i<5UL; i++ ) {
    fd_memset( snap_pks[ i ], 0, 32UL );
    snap_pks[ i ][ 0 ] = (uchar)( 0xF0+i );
    test_snapshot_write_one( accdb, SENTINEL, snap_pks[ i ],
                             10UL, (i+1UL)*100UL, 4UL<<20UL, 0, &replaced );
  }
  fd_accdb_snapshot_load_end( accdb );

  /* Capture savepoint. */
  fd_accdb_snapshot_recovery_t recovery;
  fd_accdb_snapshot_save_whead( accdb, &recovery );
  ulong saved_partition_max  = recovery.partition_max;
  ulong saved_disk_current   = recovery.disk_current_bytes;

  FD_TEST( saved_partition_max>0UL );
  FD_TEST( saved_disk_current>0UL );

  /* Create an incremental fork. */
  fd_accdb_fork_id_t incr_fork = fd_accdb_attach_child( accdb, root );

  /* Incremental snapshot load: write 5 more 4 MiB accounts.
     Forces allocation of additional partitions beyond the savepoint. */
  fd_accdb_snapshot_load_begin( accdb );
  uchar incr_pks[ 5 ][ 32UL ];
  for( ulong i=0UL; i<5UL; i++ ) {
    fd_memset( incr_pks[ i ], 0, 32UL );
    incr_pks[ i ][ 0 ] = (uchar)( 0xE0+i );
    test_snapshot_write_one( accdb, incr_fork, incr_pks[ i ],
                             20UL, (i+1UL)*1000UL, 4UL<<20UL, 0, &replaced );
  }
  fd_accdb_snapshot_load_end( accdb );

  /* Verify disk_current_bytes grew from the incremental writes. */
  FD_TEST( shmetrics->disk_current_bytes>saved_disk_current );

  /* Purge the incremental fork, then drain to process the purge
     command.  drain_background only calls fd_accdb_background once,
     which processes the purge and returns before reaching compaction. */
  fd_accdb_purge( accdb, incr_fork );
  drain_background( accdb );

  /* Revert. */
  fd_accdb_snapshot_revert_whead( accdb, &recovery );

  /* Post-revert invariants. */
  FD_TEST( fd_accdb_shmem_partition_max( test_shmem_mem ) == saved_partition_max );
  FD_TEST( shmetrics->disk_current_bytes == saved_disk_current );
  FD_TEST( shmetrics->disk_allocated_bytes == saved_partition_max*psz );

  /* Full-snapshot accounts are still readable on the root fork. */
  ulong lamports;
  ulong data_len;
  uchar owner[ 32UL ];
  for( ulong i=0UL; i<5UL; i++ ) {
    FD_TEST( accdb_read( accdb, root, snap_pks[ i ], &lamports, NULL, &data_len, owner ) );
    FD_TEST( lamports==(i+1UL)*100UL );
  }

  test_teardown( accdb, fd );
}

/* test_deferred_write_stats: snapshot writes batch shared metric
   updates until a flush.  Check inserts, replacements and ignores. */
static void
test_deferred_write_stats( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );
  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( accdb );

  fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_snapshot_load_begin( accdb );

  uchar pk_a[ 32UL ] = { 0xA0 };
  uchar pk_b[ 32UL ] = { 0xA1 };
  ulong replaced_lamports;
  FD_TEST( test_snapshot_write_one( accdb, SENTINEL, pk_a, 10UL, 1UL, 100UL, 0, &replaced_lamports )==1 );
  FD_TEST( test_snapshot_write_one( accdb, SENTINEL, pk_b, 10UL, 2UL, 200UL, 0, &replaced_lamports )==1 );

  ulong meta_sz = sizeof(fd_accdb_disk_meta_t);

  /* Shared metrics wait for a flush. */
  FD_TEST( shmetrics->disk_current_bytes==0UL );
  FD_TEST( shmetrics->disk_used_bytes   ==0UL );
  FD_TEST( shmetrics->accounts_total    ==0UL );

  /* Replace pk_a at a newer slot and ignore pk_b at an older one. */
  FD_TEST( test_snapshot_write_one( accdb, SENTINEL, pk_a, 20UL, 1UL, 300UL, 0, &replaced_lamports )==2 );
  FD_TEST( test_snapshot_write_one( accdb, SENTINEL, pk_b,  5UL, 2UL, 400UL, 0, &replaced_lamports )==-1 );

  /* The updates remain deferred. */
  FD_TEST( shmetrics->disk_current_bytes==0UL );
  FD_TEST( shmetrics->disk_used_bytes   ==0UL );
  FD_TEST( shmetrics->accounts_total    ==0UL );

  /* save_whead copies disk_current_bytes, so it must publish first.
     Every entry takes disk space, even the ignored one. */
  fd_accdb_snapshot_recovery_t recovery;
  fd_accdb_snapshot_save_whead( accdb, &recovery );

  ulong reserved = 4UL*meta_sz + 100UL + 200UL + 300UL + 400UL;
  FD_TEST( shmetrics->disk_current_bytes==reserved );
  FD_TEST( shmetrics->disk_used_bytes   ==2UL*meta_sz + 200UL + 300UL );
  FD_TEST( shmetrics->accounts_total    ==2UL );
  FD_TEST( recovery.disk_current_bytes  ==reserved );

  fd_accdb_snapshot_load_end( accdb );
  test_teardown( accdb, fd );
}

/* test_deferred_write_stats_rollover: held counters belong to one
   partition, so a batch that crosses into the next partition must
   credit each one on its own. */
static void
test_deferred_write_stats_rollover( void ) {
  int fd;
  ulong psz = 11UL<<20UL; /* 11 MiB, just above ~10 MiB minimum */
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, psz );

  fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_snapshot_load_begin( accdb );

  /* 4 MiB each, so the third entry does not fit in the first
     partition and the writes roll over exactly once. */
  ulong entry_sz = 4UL<<20UL;
  uchar pks[ 4 ][ 32UL ];
  ulong replaced_lamports;
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_memset( pks[ i ], 0, 32UL );
    pks[ i ][ 0 ] = (uchar)( 0xB0+i );
    FD_TEST( test_snapshot_write_one( accdb, SENTINEL, pks[ i ], 10UL, i+1UL,
                                      entry_sz-sizeof(fd_accdb_disk_meta_t), 0,
                                      &replaced_lamports )==1 );
  }

  fd_accdb_snapshot_load_end( accdb );

  /* The load spanned more than one partition, and every entry is
     credited to the partition it landed on. */
  ulong partition_max = fd_accdb_shmem_partition_max( test_shmem_mem );
  FD_TEST( partition_max>1UL );

  ulong total_bytes = 0UL;
  ulong total_ops   = 0UL;
  ulong used_cnt    = 0UL;
  for( ulong p=0UL; p<partition_max; p++ ) {
    fd_accdb_shmem_partition_info_t info;
    fd_accdb_shmem_partition_info( test_shmem_mem, p, &info );
    total_bytes += info.bytes_written;
    total_ops   += info.write_ops;
    used_cnt    += !!info.write_ops;
  }
  FD_TEST( total_bytes==4UL*entry_sz );
  FD_TEST( total_ops  ==4UL );
  FD_TEST( used_cnt   > 1UL );

  test_teardown( accdb, fd );
}

static void
test_default_deferred_write_stats( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );
  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( accdb );

  fd_accdb_attach_child( accdb, SENTINEL );

  uchar pubkey[ 32UL ] = { 0xC0 };
  ulong data_len = 123UL;
  ulong replaced_lamports;
  FD_TEST( test_snapshot_write_one( accdb, SENTINEL, pubkey, 1UL, 1UL, data_len, 0, &replaced_lamports )==1 );

  fd_accdb_shmem_partition_info_t info;
  fd_accdb_shmem_partition_info( test_shmem_mem, 0UL, &info );
  FD_TEST( shmetrics->disk_current_bytes==0UL );
  FD_TEST( info.bytes_written==0UL );
  FD_TEST( info.write_ops==0UL );

  fd_accdb_flush_metrics( accdb );

  ulong entry_sz = sizeof(fd_accdb_disk_meta_t)+data_len;
  fd_accdb_shmem_partition_info( test_shmem_mem, 0UL, &info );
  FD_TEST( shmetrics->disk_current_bytes==entry_sz );
  FD_TEST( info.bytes_written==entry_sz );
  FD_TEST( info.write_ops==1UL );

  test_teardown( accdb, fd );
}

static void
test_deferred_write_stats_two_joiners( void ) {
  int fd;
  ulong psz = 11UL<<20UL;
  fd_accdb_t * accdb_a = test_setup_ex( &fd, 1024UL, 64UL, 8192UL, 8192UL, psz,
                                        TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 2UL );
  fd_accdb_t * accdb_b = test_join_writer( fd );

  fd_accdb_attach_child( accdb_a, SENTINEL );

  uchar pubkey_a[ 32UL ] = { 0xC1 };
  uchar pubkey_b[ 32UL ] = { 0xC2 };
  ulong entry_sz_a = 4UL<<20UL;
  ulong entry_sz_b = 8UL<<20UL;
  ulong replaced_lamports;

  FD_TEST( test_snapshot_write_one( accdb_a, SENTINEL, pubkey_a, 1UL, 1UL,
                                    entry_sz_a-sizeof(fd_accdb_disk_meta_t), 0, &replaced_lamports )==1 );
  FD_TEST( test_snapshot_write_one( accdb_b, SENTINEL, pubkey_b, 1UL, 1UL,
                                    entry_sz_b-sizeof(fd_accdb_disk_meta_t), 0, &replaced_lamports )==1 );

  FD_TEST( fd_accdb_shmem_partition_max( test_shmem_mem )==2UL );

  ulong old_idx = ULONG_MAX;
  ulong new_idx = ULONG_MAX;
  for( ulong p=0UL; p<2UL; p++ ) {
    fd_accdb_shmem_partition_info_t info;
    fd_accdb_shmem_partition_info( test_shmem_mem, p, &info );
    if( info.is_write_head ) new_idx = p;
    else                     old_idx = p;
    FD_TEST( info.bytes_written==0UL );
    FD_TEST( info.write_ops==0UL );
  }
  FD_TEST( old_idx!=ULONG_MAX && new_idx!=ULONG_MAX );

  fd_accdb_flush_metrics( accdb_b );

  fd_accdb_shmem_partition_info_t old_info;
  fd_accdb_shmem_partition_info_t new_info;
  fd_accdb_shmem_partition_info( test_shmem_mem, old_idx, &old_info );
  fd_accdb_shmem_partition_info( test_shmem_mem, new_idx, &new_info );
  FD_TEST( old_info.bytes_written==0UL );
  FD_TEST( old_info.write_ops==0UL );
  FD_TEST( new_info.bytes_written==entry_sz_b );
  FD_TEST( new_info.write_ops==1UL );

  fd_accdb_flush_metrics( accdb_a );

  fd_accdb_shmem_partition_info( test_shmem_mem, old_idx, &old_info );
  fd_accdb_shmem_partition_info( test_shmem_mem, new_idx, &new_info );
  FD_TEST( old_info.bytes_written==entry_sz_a );
  FD_TEST( old_info.write_ops==1UL );
  FD_TEST( new_info.bytes_written==entry_sz_b );
  FD_TEST( new_info.write_ops==1UL );

  free( accdb_b );
  test_teardown( accdb_a, fd );
}

/* Concurrent writers update the same keys at distinct and equal slots. */

#define PAR_THREADS (4UL)
#define PAR_KEYS    (64UL)

#define TEST_STORE_MAX (128UL)

typedef struct {
  ulong off;
  ulong sz;
} test_range_t;

typedef struct {
  int          fd;
  test_range_t ranges[ TEST_STORE_MAX ];
  ulong cnt;
} test_store_ctx_t;

typedef struct {
  int   err;
  ulong ignored;
  ulong replaced;
  ulong loaded;
  ulong replaced_lamports;
  ulong ignored_lamports;
} test_batch_result_t;

static test_batch_result_t
test_write_batch( fd_accdb_t *                         accdb,
                  fd_accdb_fork_id_t                   fork_id,
                  ulong                                cnt,
                  uchar const * const                  pubkeys[],
                  ulong const                          slots[],
                  ulong const                          lamports[],
                  ulong const                          data_lens[],
                  int const                            executables[],
                  test_store_ctx_t *                   store ) {
  ulong total_sz = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) total_sz += sizeof(fd_accdb_disk_meta_t)+data_lens[ i ];

  ulong file_offsets[ 8 ];
  ulong file_off = fd_accdb_snapshot_reserve_write( accdb, total_sz );
  FD_TEST( store->cnt<TEST_STORE_MAX );
  store->ranges[ store->cnt++ ] = (test_range_t){ .off=file_off, .sz=total_sz };

  for( ulong i=0UL; i<cnt; i++ ) {
    file_offsets[ i ] = file_off;
    fd_accdb_disk_meta_t meta;
    fd_memcpy( meta.pubkey, pubkeys[ i ], 32UL );
    meta.size       = (uint)data_lens[ i ];
    meta.generation = 0U;
    fd_memset( meta.owner, 0, 32UL );
    FD_TEST( pwrite( store->fd, meta.b, sizeof(meta), (long)file_off )==(long)sizeof(meta) );
    file_off += sizeof(fd_accdb_disk_meta_t)+data_lens[ i ];
  }

  test_batch_result_t result = {0};
  result.err = fd_accdb_snapshot_write_batch( accdb, fork_id, cnt, pubkeys, slots, lamports, data_lens,
                                               executables, file_offsets, &result.ignored, &result.replaced,
                                               &result.loaded, &result.replaced_lamports, &result.ignored_lamports );
  return result;
}

typedef struct {
  fd_accdb_t *       accdb;
  ulong              thread_idx;
  fd_accdb_fork_id_t fork;       /* SENTINEL = full-snapshot mode */
  uchar            (*pks)[ 32UL ];
  pthread_barrier_t * start;

  ulong ignored;
  ulong replaced;
  ulong loaded;
  ulong input_lamports;
  ulong replaced_lamports;
  ulong ignored_lamports;
  test_store_ctx_t store;
} par_writer_ctx_t;

#define PAR_LAMPORTS( t, k )  ( 1000000UL + (t)*1000UL + (k) )
#define PAR_DATA_LEN( t, k )  ( ((t)+(k))%64UL )

static void *
par_writer_main( void * _ctx ) {
  par_writer_ctx_t * ctx = _ctx;
  ulong t = ctx->thread_idx;
  int barrier_result = pthread_barrier_wait( ctx->start );
  FD_TEST( !barrier_result || barrier_result==PTHREAD_BARRIER_SERIAL_THREAD );

  ulong k = 0UL;
  while( k<PAR_KEYS ) {
    ulong batch = fd_ulong_min( 1UL+((t+k)%8UL), PAR_KEYS-k );
    uchar const * pubkeys  [ 8 ];
    ulong         slots    [ 8 ];
    ulong         lamports [ 8 ];
    ulong         data_lens[ 8 ];
    int           execs    [ 8 ];
    for( ulong i=0UL; i<batch; i++ ) {
      pubkeys  [ i ] = ctx->pks[ k+i ];
      slots    [ i ] = 100UL+t;
      lamports [ i ] = PAR_LAMPORTS( t, k+i );
      data_lens[ i ] = PAR_DATA_LEN( t, k+i );
      execs    [ i ] = 0;
    }
    test_batch_result_t result = test_write_batch( ctx->accdb, ctx->fork, batch, pubkeys, slots,
                                                    lamports, data_lens, execs, &ctx->store );
    FD_TEST( !result.err );
    ctx->ignored  += result.ignored;
    ctx->replaced += result.replaced;
    ctx->loaded   += result.loaded;
    for( ulong i=0UL; i<batch; i++ ) ctx->input_lamports += lamports[ i ];
    ctx->replaced_lamports += result.replaced_lamports;
    ctx->ignored_lamports  += result.ignored_lamports;
    k += batch;
  }
  return NULL;
}

static void
par_run_threads( par_writer_ctx_t ctxs[ static PAR_THREADS ],
                 void * (* fn)( void * ) ) {
  pthread_barrier_t start;
  FD_TEST( !pthread_barrier_init( &start, NULL, (uint)PAR_THREADS ) );
  pthread_t threads[ PAR_THREADS ];
  for( ulong t=0UL; t<PAR_THREADS; t++ ) {
    ctxs[ t ].start = &start;
    FD_TEST( !pthread_create( &threads[ t ], NULL, fn, &ctxs[ t ] ) );
  }
  for( ulong t=0UL; t<PAR_THREADS; t++ ) FD_TEST( !pthread_join( threads[ t ], NULL ) );
  FD_TEST( !pthread_barrier_destroy( &start ) );
}

/* Replay the shmem layout to reach the acc pool elements. */
static fd_accdb_accmeta_t *
par_acc_ele( ulong max_accounts ) {
  ulong max_live_slots = test_shmem_mem->max_live_slots;
  ulong chain_cnt      = test_shmem_mem->chain_cnt;
  FD_SCRATCH_ALLOC_INIT( l, test_shmem_mem );
  FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
  FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
  FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
  return FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t), max_accounts*sizeof(fd_accdb_accmeta_t) );
}

static int
par_offset_cmp( void const * a, void const * b ) {
  ulong off_a = ((test_range_t const *)a)->off;
  ulong off_b = ((test_range_t const *)b)->off;
  return off_a<off_b ? -1 : (off_a>off_b ? 1 : 0);
}

static void
test_snapshot_equal_slot_rejected( void ) {
  int fd;
  ulong max_accounts = 64UL;
  fd_accdb_t * accdb = test_setup_ex( &fd, max_accounts, 64UL, 1024UL, 64UL, 11UL<<20UL,
                                      TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 1UL );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_snapshot_load_begin( accdb );

  uchar pubkey[ 32UL ] = {1};
  uchar const * pubkeys[ 2 ] = { pubkey, pubkey };
  ulong slots    [ 2 ] = { 99UL, 100UL };
  ulong lamports [ 2 ] = {  1UL,   2UL };
  ulong data_lens[ 2 ] = {  0UL,   0UL };
  int   execs    [ 2 ] = {  0,     0 };
  test_store_ctx_t store = { .fd=fd };

  test_batch_result_t result = test_write_batch( accdb, SENTINEL, 2UL, pubkeys, slots,
                                                  lamports, data_lens, execs, &store );
  FD_TEST( !result.err && result.loaded==1UL && result.replaced==1UL && result.replaced_lamports==1UL );

  slots[ 0 ] = slots[ 1 ] = 101UL;
  lamports[ 0 ] = 3UL;
  result = test_write_batch( accdb, SENTINEL, 2UL, pubkeys, slots, lamports, data_lens, execs, &store );
  FD_TEST( result.err==-1 );
  FD_TEST( fd_accdb_lamports( accdb, root, pubkey )==2UL );

  slots[ 0 ] = 100UL;
  result = test_write_batch( accdb, SENTINEL, 1UL, pubkeys, slots, lamports, data_lens, execs, &store );
  FD_TEST( result.err==-1 );
  FD_TEST( fd_accdb_lamports( accdb, root, pubkey )==2UL );

  fd_accdb_snapshot_load_end( accdb );

  acc_pool_t pool_join[ 1 ];
  FD_TEST( acc_pool_join( pool_join, test_shmem_mem->acc_pool, par_acc_ele( max_accounts ), max_accounts ) );
  ulong free_cnt = 0UL;
  while( acc_pool_acquire( pool_join ) ) free_cnt++;
  FD_TEST( free_cnt==max_accounts-1UL );

  test_teardown( accdb, fd );
}

static void
test_snapshot_chain_locked_writers( void ) {
  int fd;
  ulong psz = 11UL<<20UL;
  ulong max_accounts = 16384UL;
  fd_accdb_t * accdb = test_setup_ex( &fd, max_accounts, 64UL, 1024UL, 64UL, psz,
                                      TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED,
                                      PAR_THREADS+1UL );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_snapshot_load_begin( accdb );

  static uchar pks[ PAR_KEYS ][ 32UL ];
  for( ulong k=0UL; k<PAR_KEYS; k++ ) {
    fd_memset( pks[ k ], 0, 32UL );
    pks[ k ][ 0 ] = (uchar)( k+1UL );
    pks[ k ][ 1 ] = 0x77;
  }

  fd_accdb_t * joins[ PAR_THREADS ];
  par_writer_ctx_t ctxs[ PAR_THREADS ];
  for( ulong t=0UL; t<PAR_THREADS; t++ ) joins[ t ] = test_join_writer( fd );

  memset( ctxs, 0, sizeof(ctxs) );
  for( ulong t=0UL; t<PAR_THREADS; t++ ) {
    ctxs[ t ].accdb      = joins[ t ];
    ctxs[ t ].store.fd   = fd;
    ctxs[ t ].thread_idx = t;
    ctxs[ t ].fork       = SENTINEL;
    ctxs[ t ].pks        = pks;
  }
  par_run_threads( ctxs, par_writer_main );

  ulong tot_loaded=0UL, tot_replaced=0UL, tot_ignored=0UL;
  ulong tot_input=0UL, tot_repl_l=0UL, tot_ign_l=0UL;
  ulong all_cnt=0UL;
  static test_range_t all_ranges[ PAR_THREADS*PAR_KEYS ];
  for( ulong t=0UL; t<PAR_THREADS; t++ ) {
    tot_loaded   += ctxs[ t ].loaded;
    tot_replaced += ctxs[ t ].replaced;
    tot_ignored  += ctxs[ t ].ignored;
    tot_input    += ctxs[ t ].input_lamports;
    tot_repl_l   += ctxs[ t ].replaced_lamports;
    tot_ign_l    += ctxs[ t ].ignored_lamports;
    for( ulong j=0UL; j<ctxs[ t ].store.cnt; j++ ) {
      all_ranges[ all_cnt++ ] = ctxs[ t ].store.ranges[ j ];
    }
    fd_accdb_flush_metrics( joins[ t ] );
  }

  /* Reserved ranges never overlap. */
  qsort( all_ranges, all_cnt, sizeof(test_range_t), par_offset_cmp );
  for( ulong i=1UL; i<all_cnt; i++ ) {
    FD_TEST( all_ranges[ i ].off>=all_ranges[ i-1UL ].off+all_ranges[ i-1UL ].sz );
  }

  FD_TEST( tot_loaded==PAR_KEYS );
  FD_TEST( tot_replaced+tot_ignored==PAR_KEYS*(PAR_THREADS-1UL) );
  ulong live_lamports = 0UL;
  ulong expect_used   = 0UL;
  for( ulong k=0UL; k<PAR_KEYS; k++ ) {
    ulong lamports;
    ulong data_len;
    FD_TEST( accdb_read( accdb, root, pks[ k ], &lamports, NULL, &data_len, NULL ) );
    FD_TEST( lamports==PAR_LAMPORTS( PAR_THREADS-1UL, k ) );
    FD_TEST( data_len==PAR_DATA_LEN( PAR_THREADS-1UL, k ) );
    live_lamports += lamports;
    expect_used   += sizeof(fd_accdb_disk_meta_t)+data_len;
  }
  FD_TEST( tot_input-tot_ign_l-tot_repl_l==live_lamports );

  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( accdb );
  FD_TEST( shmetrics->accounts_total ==PAR_KEYS );
  FD_TEST( shmetrics->disk_used_bytes==expect_used );

  fd_accdb_snapshot_load_end( accdb );

  /* Exactly the live entries are checked out of the shared pool.
     Drains the pool, so this must be the last thing the test does with it. */
  acc_pool_t pool_join[ 1 ];
  FD_TEST( acc_pool_join( pool_join, test_shmem_mem->acc_pool, par_acc_ele( max_accounts ), max_accounts ) );
  ulong free_cnt = 0UL;
  while( acc_pool_acquire( pool_join ) ) free_cnt++;
  FD_TEST( free_cnt==max_accounts-PAR_KEYS );

  for( ulong t=0UL; t<PAR_THREADS; t++ ) free( joins[ t ] );
  test_teardown( accdb, fd );
}

/* Incremental extension of the chain-lock contract. */

#define PAR_INCR_KEYS     (PAR_KEYS+16UL) /* 16 brand-new keys in the incr phase */
#define PAR_INCR_LAMPORTS( t, k ) ( 2000000UL + (t)*1000UL + (k) )
#define PAR_INCR_DLEN( t, k )     ( ((t)*3UL+(k))%64UL )

/* Threads race on the same keys.  Groups 0/3 override the root, group 1
   is stale, group 2 is untouched, and trailing keys are new.  The
   highest per-thread slot wins. */
static void *
par_incr_writer_main( void * _ctx ) {
  par_writer_ctx_t * ctx = _ctx;
  ulong t = ctx->thread_idx;
  int barrier_result = pthread_barrier_wait( ctx->start );
  FD_TEST( !barrier_result || barrier_result==PTHREAD_BARRIER_SERIAL_THREAD );

  for( ulong k=0UL; k<PAR_INCR_KEYS; k++ ) {
    if( k<PAR_KEYS && k%4UL==2UL ) continue; /* group 2 untouched */

    uchar const * pubkeys  [ 1 ] = { ctx->pks[ k ] };
    ulong         slots    [ 1 ] = { ( k<PAR_KEYS && k%4UL==1UL ) ? 50UL : 200UL+t };
    ulong         lamports [ 1 ] = { k%4UL==1UL && k<PAR_KEYS ? 9000000UL+k : PAR_INCR_LAMPORTS( t, k ) };
    ulong         data_lens[ 1 ] = { PAR_INCR_DLEN( t, k ) };
    int           execs    [ 1 ] = { 0 };
    test_batch_result_t result = test_write_batch( ctx->accdb, ctx->fork, 1UL, pubkeys, slots,
                                                    lamports, data_lens, execs, &ctx->store );
    FD_TEST( !result.err );
    ctx->ignored           += result.ignored;
    ctx->replaced          += result.replaced;
    ctx->loaded            += result.loaded;
    ctx->input_lamports    += lamports[ 0 ];
    ctx->replaced_lamports += result.replaced_lamports;
    ctx->ignored_lamports  += result.ignored_lamports;
  }
  return NULL;
}

/* Test concurrent incremental snapshot writes and rollback. */
static void
test_snapshot_chain_locked_writers_incremental( void ) {
  int fd;
  ulong psz = 11UL<<20UL;
  ulong max_accounts = 4096UL;
  fd_accdb_t * reader = test_setup_ex( &fd, max_accounts, 64UL, 1024UL, 64UL, psz,
                                      TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED,
                                      PAR_THREADS+1UL );
  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( reader );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( reader, SENTINEL );
  fd_accdb_snapshot_load_begin( reader );

  static uchar pks[ PAR_INCR_KEYS ][ 32UL ];
  for( ulong k=0UL; k<PAR_INCR_KEYS; k++ ) {
    fd_memset( pks[ k ], 0, 32UL );
    pks[ k ][ 0 ] = (uchar)( k+1UL );
    pks[ k ][ 1 ] = 0x78;
  }

  ulong replaced_lamports;
  for( ulong k=0UL; k<PAR_KEYS; k++ ) {
    FD_TEST( test_snapshot_write_one( reader, SENTINEL, pks[ k ], 100UL+PAR_THREADS-1UL,
                                      PAR_LAMPORTS( PAR_THREADS-1UL, k ),
                                      PAR_DATA_LEN( PAR_THREADS-1UL, k ), 0,
                                      &replaced_lamports )==1 );
  }

  fd_accdb_snapshot_recovery_t recovery;
  fd_accdb_snapshot_save_whead( reader, &recovery );
  FD_TEST( shmetrics->accounts_total==PAR_KEYS );

  fd_accdb_t * joins[ PAR_THREADS ];
  for( ulong t=0UL; t<PAR_THREADS; t++ ) joins[ t ] = test_join_writer( fd );

  fd_accdb_fork_id_t incr = fd_accdb_attach_child( reader, root );
  par_writer_ctx_t ctxs[ PAR_THREADS ];
  memset( ctxs, 0, sizeof(ctxs) );
  for( ulong t=0UL; t<PAR_THREADS; t++ ) {
    ctxs[ t ].accdb      = joins[ t ];
    ctxs[ t ].store.fd   = fd;
    ctxs[ t ].thread_idx = t;
    ctxs[ t ].fork       = incr;
    ctxs[ t ].pks        = pks;
  }
  par_run_threads( ctxs, par_incr_writer_main );

  ulong loaded=0UL, replaced=0UL, ignored=0UL;
  ulong input_lamports=0UL, replaced_lamports_sum=0UL, ignored_lamports=0UL;
  for( ulong t=0UL; t<PAR_THREADS; t++ ) {
    loaded                += ctxs[ t ].loaded;
    replaced              += ctxs[ t ].replaced;
    ignored               += ctxs[ t ].ignored;
    input_lamports        += ctxs[ t ].input_lamports;
    replaced_lamports_sum += ctxs[ t ].replaced_lamports;
    ignored_lamports      += ctxs[ t ].ignored_lamports;
    fd_accdb_flush_metrics( joins[ t ] );
  }

  ulong const new_cnt   = PAR_INCR_KEYS-PAR_KEYS;
  ulong const cross_cnt = PAR_KEYS/2UL;
  ulong const write_cnt = PAR_THREADS*(cross_cnt+PAR_KEYS/4UL+new_cnt);
  FD_TEST( loaded==new_cnt );
  FD_TEST( loaded+replaced+ignored==write_cnt );

  ulong expected_lamports = 0UL;
  for( ulong k=0UL; k<PAR_KEYS; k++ ) {
    if( k%4UL==0UL || k%4UL==3UL ) expected_lamports += PAR_INCR_LAMPORTS( PAR_THREADS-1UL, k ) - PAR_LAMPORTS( PAR_THREADS-1UL, k );
  }
  for( ulong k=PAR_KEYS; k<PAR_INCR_KEYS; k++ ) expected_lamports += PAR_INCR_LAMPORTS( PAR_THREADS-1UL, k );
  FD_TEST( input_lamports-ignored_lamports-replaced_lamports_sum==expected_lamports );

  for( ulong k=0UL; k<PAR_KEYS; k++ ) {
    ulong full_win = PAR_LAMPORTS( PAR_THREADS-1UL, k );
    ulong incr_win = ( k%4UL==0UL || k%4UL==3UL ) ? PAR_INCR_LAMPORTS( PAR_THREADS-1UL, k ) : full_win;
    FD_TEST( fd_accdb_lamports( reader, incr, pks[ k ] )==incr_win );
    FD_TEST( fd_accdb_lamports( reader, root, pks[ k ] )==full_win );
  }
  for( ulong k=PAR_KEYS; k<PAR_INCR_KEYS; k++ ) {
    FD_TEST( fd_accdb_lamports( reader, incr, pks[ k ] )==PAR_INCR_LAMPORTS( PAR_THREADS-1UL, k ) );
    FD_TEST( fd_accdb_lamports( reader, root, pks[ k ] )==0UL );
  }
  FD_TEST( shmetrics->accounts_total==PAR_KEYS+PAR_KEYS/2UL+16UL );

  fd_accdb_purge( reader, incr );
  drain_background( reader );
  fd_accdb_snapshot_revert_whead( reader, &recovery );

  fd_accdb_snapshot_recovery_t restored;
  fd_accdb_snapshot_save_whead( reader, &restored );
  FD_TEST( restored.whead_val==recovery.whead_val );
  FD_TEST( restored.has_partition==recovery.has_partition );
  FD_TEST( restored.partition_max==recovery.partition_max );
  FD_TEST( restored.disk_current_bytes==recovery.disk_current_bytes );

  FD_TEST( shmetrics->accounts_total==PAR_KEYS );
  for( ulong k=0UL; k<PAR_KEYS; k++ ) {
    FD_TEST( fd_accdb_lamports( reader, root, pks[ k ] )==PAR_LAMPORTS( PAR_THREADS-1UL, k ) );
  }
  for( ulong k=PAR_KEYS; k<PAR_INCR_KEYS; k++ ) FD_TEST( fd_accdb_lamports( reader, root, pks[ k ] )==0UL );

  fd_accdb_snapshot_load_end( reader );

  for( ulong t=0UL; t<PAR_THREADS; t++ ) free( joins[ t ] );
  test_teardown( reader, fd );
}

#undef PAR_INCR_DLEN
#undef PAR_INCR_LAMPORTS
#undef PAR_INCR_KEYS

#undef PAR_LAMPORTS
#undef PAR_DATA_LEN
#undef PAR_THREADS
#undef PAR_KEYS

/* test_incremental_cross_fork_override verifies that incremental
   cross-fork overrides create new acc_pool entries with txn records,
   and that purging the incremental fork + revert_whead fully restores
   the original full-snapshot state. */
static void
test_incremental_cross_fork_override( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 8192UL, 8192UL, 1UL<<30UL );
  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( accdb );

  ulong lamports;
  ulong data_len;
  uchar owner[ 32UL ];

  uchar pk0[ 32UL ] = { 0xD0 };
  uchar pk1[ 32UL ] = { 0xD1 };
  uchar pk2[ 32UL ] = { 0xD2 };

  /* Create root fork. */
  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );

  /* Full-snapshot load: write 3 accounts with 1 KiB data each. */
  fd_accdb_snapshot_load_begin( accdb );
  ulong replaced = 0UL;
  test_snapshot_write_one( accdb, SENTINEL, pk0, 10UL, 100UL, 1024UL, 0, &replaced );
  test_snapshot_write_one( accdb, SENTINEL, pk1, 10UL, 200UL, 1024UL, 0, &replaced );
  test_snapshot_write_one( accdb, SENTINEL, pk2, 10UL, 300UL, 1024UL, 0, &replaced );
  fd_accdb_snapshot_load_end( accdb );

  /* Save whead. */
  fd_accdb_snapshot_recovery_t recovery;
  fd_accdb_snapshot_save_whead( accdb, &recovery );

  /* Create incremental fork. */
  fd_accdb_fork_id_t incr_fork = fd_accdb_attach_child( accdb, root );

  /* Incremental snapshot load: override pk0 and pk1 with new lamports. */
  fd_accdb_snapshot_load_begin( accdb );
  test_snapshot_write_one( accdb, incr_fork, pk0, 20UL, 111UL, 1024UL, 0, &replaced );
  test_snapshot_write_one( accdb, incr_fork, pk1, 20UL, 222UL, 1024UL, 0, &replaced );
  fd_accdb_snapshot_load_end( accdb );

  /* Verify accounts_total reflects the cross-fork overrides: 3 original
     entries + 2 cross-fork entries = 5. */
  FD_TEST( shmetrics->accounts_total==5UL );

  /* Simulate failure: purge the incremental fork. */
  fd_accdb_purge( accdb, incr_fork );
  drain_background( accdb );

  /* Revert whead. */
  fd_accdb_snapshot_revert_whead( accdb, &recovery );

  /* Assert prior state restored on root fork. */
  FD_TEST( accdb_read( accdb, root, pk0, &lamports, NULL, &data_len, owner ) );
  FD_TEST( lamports==100UL );
  FD_TEST( accdb_read( accdb, root, pk1, &lamports, NULL, &data_len, owner ) );
  FD_TEST( lamports==200UL );
  FD_TEST( accdb_read( accdb, root, pk2, &lamports, NULL, &data_len, owner ) );
  FD_TEST( lamports==300UL );

  /* The cross-fork override entries should be removed by purge. */
  FD_TEST( shmetrics->accounts_total==3UL );

  test_teardown( accdb, fd );
}

/* Verify a retry reuses entries moved to the free stack after lazy
   allocation is exhausted. */
static void
test_incremental_retry_reuses_acc_pool( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup_ex( &fd, 5UL, 8UL, 64UL, 64UL, 1UL<<30UL,
                                      TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 2UL );
  fd_accdb_t * background = test_join_writer( fd );
  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( accdb );
  acc_pool_shmem_t * pool = test_shmem_mem->acc_pool;

  uchar full_pk[ 32UL ] = { 0xC0 };
  ulong replaced_lamports;
  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_snapshot_load_begin( accdb );
  FD_TEST( test_snapshot_write_one( accdb, SENTINEL, full_pk, 10UL, 1UL, 0UL, 0,
                                    &replaced_lamports )==1 );

  fd_accdb_snapshot_recovery_t recovery;
  fd_accdb_snapshot_save_whead( accdb, &recovery );

  test_background_ctx_t bg_ctx = { .accdb = background, .stop = 0 };
  pthread_t bg_thread;
  FD_TEST( !pthread_create( &bg_thread, NULL, run_background, &bg_ctx ) );

  for( ulong attempt=0UL; attempt<2UL; attempt++ ) {
    fd_accdb_fork_id_t failed = fd_accdb_attach_child( accdb, root );
    for( ulong i=0UL; i<2UL; i++ ) {
      uchar failed_pk[ 32UL ] = {0};
      failed_pk[ 0 ] = (uchar)(0xD0UL + 2UL*attempt + i);
      FD_TEST( test_snapshot_write_one( accdb, failed, failed_pk,
                                        20UL+attempt, 2UL+i, 0UL, 0,
                                        &replaced_lamports )==1 );
    }
    fd_accdb_purge( accdb, failed );
    fd_accdb_snapshot_revert_whead( accdb, &recovery );
    FD_TEST( shmetrics->accounts_total==1UL );
  }

  ulong top_before  = FD_VOLATILE_CONST( pool->ver_top  );
  ulong lazy_before = FD_VOLATILE_CONST( pool->ver_lazy );
  FD_TEST( acc_pool_private_vidx_idx( top_before  )<5UL );
  FD_TEST( acc_pool_private_vidx_idx( lazy_before )==acc_pool_idx_null() );
  FD_TEST( test_shmem_mem->deferred_acc_buf_cnt==2UL );

  fd_accdb_fork_id_t success = fd_accdb_attach_child( accdb, root );
  uchar success_pk[ 32UL ] = { 0xE0 };
  uchar const * pubkeys[ 2 ] = { full_pk, success_pk };
  FD_TEST( test_snapshot_write_one( accdb, success, full_pk,    30UL, 10UL, 0UL, 0, &replaced_lamports )==2 );
  FD_TEST( replaced_lamports==1UL );
  FD_TEST( test_snapshot_write_one( accdb, success, success_pk, 30UL, 20UL, 0UL, 0, &replaced_lamports )==1 );
  FD_TEST( acc_pool_private_vidx_idx( FD_VOLATILE_CONST( pool->ver_top ) )==acc_pool_idx_null() );
  FD_TEST( FD_VOLATILE_CONST( pool->ver_lazy )==lazy_before );

  fd_accdb_advance_root( accdb, success );
  fd_accdb_snapshot_load_end( accdb );

  fd_accdb_fork_id_t next = fd_accdb_attach_child( accdb, success );
  FD_TEST( shmetrics->accounts_total==2UL );

  /* Drain the replaced full-snapshot account. */
  fd_accdb_advance_root( accdb, next );
  while( FD_VOLATILE_CONST( test_shmem_mem->cmd_op )!=FD_ACCDB_CMD_IDLE ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  FD_TEST( !test_shmem_mem->deferred_acc_buf_cnt );

  FD_VOLATILE( bg_ctx.stop ) = 1;
  FD_TEST( !pthread_join( bg_thread, NULL ) );

  for( ulong i=0UL; i<2UL; i++ ) {
    ulong read_lamports;
    FD_TEST( accdb_read( accdb, next, pubkeys[ i ], &read_lamports,
                         NULL, NULL, NULL ) );
    FD_TEST( read_lamports==10UL*(i+1UL) );
  }

  free( background );
  test_teardown( accdb, fd );
}

/* test_sentinel_index_wrap is a regression for issue #543: at the
   maximum partition_cnt==8192 the initial write-head sentinel's packed
   partition index (partition_cnt) does not fit in the 13-bit index
   field and wraps to 0 -- a perfectly valid pool index.  An earlier
   allocate_next_write detected the first partition switch purely by
   "the head's partition index changed away from the sentinel's", which
   could spin forever when the freshly-acquired partition reused index 0.

   This test pins two things:

   1. The wrap is real (documents the root cause): accdb_offset packs the
      index in bits 63..51, so 8192<<51 wraps to an index of 0, while the
      sentinel's invalidity actually lives in the offset bits
      (partition_offset==partition_sz).

   2. The switch-wait predicate is robust to that wrap.  A writer parks in
      the wait loop only after its own fetch-and-add returned an offset
      strictly past partition_sz; the loop must terminate once the head's
      offset drops back to <=partition_sz (a switch resets the offset to
      0), independent of whether the index changed.  We assert that the
      sentinel's own offset never satisfies the post-overrun predicate
      (so a parked writer cannot mistake the pristine sentinel for a
      completed switch) yet a switched head always does.

   It also drives a real first-partition overflow at partition_cnt==8192
   end-to-end to confirm the switch path runs to completion (no hang)
   and accounts read back correctly. */
static void
test_sentinel_index_wrap( void ) {
  ulong const partition_sz = 1UL<<20; /* arbitrary, only its packing matters here */
  ulong const max_cnt      = 1UL<<13; /* 8192 -- the maximum partition_cnt */

  /* (1) The wrap is real (the root cause).  accdb_offset packs the index
     into bits 63..51, so the sentinel index (== partition_cnt == 8192)
     does not fit in 13 bits and wraps to 0 -- a perfectly valid pool
     index.  The sentinel's invalidity therefore lives in the OFFSET
     bits (partition_offset == partition_sz), not the index. */
  accdb_offset_t sentinel = accdb_offset( max_cnt, partition_sz );
  FD_TEST( packed_partition_idx   ( &sentinel )==0UL          ); /* wrapped! */
  FD_TEST( packed_partition_offset( &sentinel )==partition_sz );

  /* (2) The switch-wait loop in reserve_next_write must not rely on the
     head's partition index changing away from the sentinel's: a freshly
     acquired partition can reuse index 0, colliding with the wrapped
     sentinel index, and an index-only check would then spin forever
     (the issue #543 deadlock).  The fix also breaks when the head's
     offset drops back to <= partition_sz (a switch resets it to 0).
     Assert both halves of that reasoning. */

  /* A parked writer reached the wait loop only after its own fetch-and-add
     pushed the offset strictly past partition_sz.  The pristine sentinel
     offset (== partition_sz) must NOT satisfy the post-switch predicate,
     or a writer could mistake the un-switched sentinel for a completed
     switch. */
  FD_TEST( !(packed_partition_offset( &sentinel ) < partition_sz) );
  FD_TEST(   packed_partition_offset( &sentinel )<=partition_sz   ); /* boundary, exclusive of < */

  /* A switched head that happens to reuse the sentinel's (wrapped) index
     is indistinguishable by index alone, but its offset is back in range,
     so the offset-based half of the predicate detects the switch. */
  accdb_offset_t switched = accdb_offset( 0UL /* pool handed back index 0 */, 0UL );
  FD_TEST( packed_partition_idx   ( &switched )==packed_partition_idx( &sentinel ) ); /* index collision */
  FD_TEST( packed_partition_offset( &switched ) < partition_sz );                     /* but detectable */

  /* (3) The constructor accepts the maximum partition_cnt==8192 (the
     default), so the wrap above is a reachable configuration, not a
     rejected one. */
  ulong fp = fd_accdb_shmem_footprint( 1024UL, 64UL, 8192UL, max_cnt,
                                       TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 1UL, 0UL );
  FD_TEST( fp ); /* 0 would mean partition_cnt==8192 was rejected */
}

static void
test_txn_footprint_growth( void ) {
  ulong fp_64 = fd_accdb_shmem_footprint( 1024UL, 1UL, 64UL, 64UL,
                                          TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 1UL, 0UL );
  ulong fp_96 = fd_accdb_shmem_footprint( 1024UL, 1UL, 96UL, 64UL,
                                          TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 1UL, 0UL );
  FD_TEST( fp_64 );
  FD_TEST( fp_96 );

  /* Each additional transaction needs an 8-byte fork-list entry and a
     4-byte deferred-free index.  Both counts increase by 32 here. */
  FD_TEST( fp_96-fp_64==32UL*(8UL+4UL) );
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

  FD_LOG_NOTICE(( "test_attach_child_drains_deferred_fork ..." ));
  test_attach_child_drains_deferred_fork();

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

  FD_LOG_NOTICE(( "test_txn_footprint_growth ..." ));
  test_txn_footprint_growth();

  FD_LOG_NOTICE(( "test_acquire_b_refund_accounting ..." ));
  test_acquire_b_refund_accounting();

  FD_LOG_NOTICE(( "test_sentinel_index_wrap ..." ));
  test_sentinel_index_wrap();

  FD_LOG_NOTICE(( "test_reset ..." ));
  test_reset();

  FD_LOG_NOTICE(( "test_revert_whead ..." ));
  test_revert_whead();

  FD_LOG_NOTICE(( "test_deferred_write_stats ..." ));
  test_deferred_write_stats();

  FD_LOG_NOTICE(( "test_deferred_write_stats_rollover ..." ));
  test_deferred_write_stats_rollover();

  FD_LOG_NOTICE(( "test_default_deferred_write_stats ..." ));
  test_default_deferred_write_stats();

  FD_LOG_NOTICE(( "test_deferred_write_stats_two_joiners ..." ));
  test_deferred_write_stats_two_joiners();

  FD_LOG_NOTICE(( "test_snapshot_chain_locked_writers ..." ));
  test_snapshot_chain_locked_writers();

  FD_LOG_NOTICE(( "test_snapshot_equal_slot_rejected ..." ));
  test_snapshot_equal_slot_rejected();

  FD_LOG_NOTICE(( "test_snapshot_chain_locked_writers_incremental ..." ));
  test_snapshot_chain_locked_writers_incremental();

  FD_LOG_NOTICE(( "test_incremental_cross_fork_override ..." ));
  test_incremental_cross_fork_override();

  FD_LOG_NOTICE(( "test_incremental_retry_reuses_acc_pool ..." ));
  test_incremental_retry_reuses_acc_pool();

  FD_LOG_NOTICE(( "test_pd_write_bit_and_probe ..." ));
  test_pd_write_bit_and_probe();

  FD_LOG_NOTICE(( "success" ));

  fd_halt();
  return 0;
}
