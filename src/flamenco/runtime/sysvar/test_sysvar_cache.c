#define _GNU_SOURCE

#include "fd_sysvar_cache.h"
#include "fd_sysvar_cache_private.h"
#include "test_sysvar_cache_util.h"
#include "../fd_system_ids.h"
#include "../fd_bank.h"
#include "../../accdb/fd_accdb.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define TEST_SYSVAR_SENTINEL ((fd_accdb_fork_id_t){ .val = USHORT_MAX })

/* Tiny accdb config sized to fit one root fork plus one child fork with
   a small handful of accounts (sysvars). */

#define TEST_SYSVAR_MAX_ACCOUNTS  (1024UL)
#define TEST_SYSVAR_MAX_LIVE_SLOTS  (16UL)
#define TEST_SYSVAR_WRITES_PER_SLOT (1024UL)
#define TEST_SYSVAR_PARTITION_CNT   (256UL)
#define TEST_SYSVAR_PARTITION_SZ    (1UL<<28UL)  /* 256 MiB */
#define TEST_SYSVAR_CACHE_FOOTPRINT (16UL<<30UL) /* 16 GiB sparse */

test_sysvar_cache_env_t *
test_sysvar_cache_env_create( test_sysvar_cache_env_t * env,
                              fd_wksp_t *               wksp ) {
  memset( env, 0, sizeof(test_sysvar_cache_env_t) );
  ulong const wksp_tag = 98UL;

  /* Create accdb backed by a memfd.  The shmem and join structures live
     outside the test wksp because the cache footprint exceeds the
     wksp's capacity (sparse mapping). */

  int accdb_fd = memfd_create( "accdb_test", 0 );
  if( FD_UNLIKELY( accdb_fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));

  ulong shmem_fp = fd_accdb_shmem_footprint( TEST_SYSVAR_MAX_ACCOUNTS,
                                             TEST_SYSVAR_MAX_LIVE_SLOTS,
                                             TEST_SYSVAR_WRITES_PER_SLOT,
                                             TEST_SYSVAR_PARTITION_CNT,
                                             TEST_SYSVAR_CACHE_FOOTPRINT,
                                             640UL, 1UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( shmem_mem, TEST_SYSVAR_MAX_ACCOUNTS,
                          TEST_SYSVAR_MAX_LIVE_SLOTS,
                          TEST_SYSVAR_WRITES_PER_SLOT,
                          TEST_SYSVAR_PARTITION_CNT,
                          TEST_SYSVAR_PARTITION_SZ,
                          TEST_SYSVAR_CACHE_FOOTPRINT,
                          640UL, 42UL, 1UL ) );
  FD_TEST( shmem );

  ulong join_fp = fd_accdb_footprint( TEST_SYSVAR_MAX_LIVE_SLOTS );
  FD_TEST( join_fp );
  void * join_mem = aligned_alloc( fd_accdb_align(), join_fp );
  FD_TEST( join_mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( join_mem, shmem, accdb_fd, 0UL, NULL ) );
  FD_TEST( accdb );

  /* Allocate a single bank in the test wksp. */

  fd_bank_t * bank = fd_wksp_alloc_laddr( wksp, alignof(fd_bank_t), sizeof(fd_bank_t), wksp_tag );
  FD_TEST( bank );
  memset( bank, 0, sizeof(fd_bank_t) );
  fd_rwlock_new( &bank->lthash_lock );

  /* Attach a single root fork.  All sysvar reads/writes will use this
     fork. */

  bank->accdb_fork_id = fd_accdb_attach_child( accdb, TEST_SYSVAR_SENTINEL );

  env->accdb_fd        = accdb_fd;
  env->accdb_shmem_mem = shmem_mem;
  env->accdb_join_mem  = join_mem;
  env->accdb           = accdb;
  env->bank            = bank;
  env->sysvar_cache    = fd_sysvar_cache_join( fd_sysvar_cache_new( &bank->f.sysvar_cache ) );

  return env;
}

void
test_sysvar_cache_env_destroy( test_sysvar_cache_env_t * env ) {
  FD_TEST( env );
  FD_TEST( fd_sysvar_cache_delete( fd_sysvar_cache_leave( env->sysvar_cache ) ) );
  fd_wksp_free_laddr( env->bank );
  /* The accdb has no leave/delete API; rely on process exit to reclaim
     the shmem and join allocations.  Match the cleanup pattern used by
     test_accdb.c. */
  free( env->accdb_join_mem );
  free( env->accdb_shmem_mem );
  close( env->accdb_fd );
  memset( env, 0, sizeof(test_sysvar_cache_env_t) );
}

static void
test_sysvar_map( void ) {
  sysvar_tbl_t const * s;

  s = sysvar_map_query( &fd_sysvar_clock_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_clock_IDX );

  s = sysvar_map_query( &fd_sysvar_epoch_rewards_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_epoch_rewards_IDX );

  s = sysvar_map_query( &fd_sysvar_epoch_schedule_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_epoch_schedule_IDX );

  s = sysvar_map_query( &fd_sysvar_last_restart_slot_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_last_restart_slot_IDX );

  s = sysvar_map_query( &fd_sysvar_recent_block_hashes_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_recent_hashes_IDX );

  s = sysvar_map_query( &fd_sysvar_rent_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_rent_IDX );

  s = sysvar_map_query( &fd_sysvar_slot_hashes_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_slot_hashes_IDX );

  s = sysvar_map_query( &fd_sysvar_slot_history_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_slot_history_IDX );

  s = sysvar_map_query( &fd_sysvar_stake_history_id, NULL );
  FD_TEST( s && s->desc_idx == FD_SYSVAR_stake_history_IDX );

  for( ulong j=0UL; j<256; j++ ) {
    fd_pubkey_t pk;
    for( ulong j=0UL; j<32UL; j++ ) pk.uc[j] = (uchar)j;
    FD_TEST( !sysvar_map_query( &pk, NULL ) );
  }
}

static fd_sysvar_cache_t sysvar_cache_[1];

static void
test_sysvar_cache_empty( void ) {
  /* Test new */
  FD_TEST( fd_sysvar_cache_new( NULL        )==NULL );
  FD_TEST( fd_sysvar_cache_new( (void *)1UL )==NULL ); /* misaligned */
  void * cache_mem = fd_sysvar_cache_new( sysvar_cache_ );
  FD_TEST( cache_mem==sysvar_cache_ );

  /* Test join */
  FD_TEST( fd_sysvar_cache_join( NULL        )==NULL );
  FD_TEST( fd_sysvar_cache_join( (void *)1UL )==NULL ); /* misaligned */
  ((fd_sysvar_cache_t *)cache_mem)->magic++;
  FD_TEST( fd_sysvar_cache_join( cache_mem   )==NULL ); /* bad magic */
  ((fd_sysvar_cache_t *)cache_mem)->magic--;
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( cache_mem );
  FD_TEST( cache );

  /* Test leave */
  FD_TEST( fd_sysvar_cache_leave( cache )==cache_mem );

  /* Test join_const */
  FD_TEST( fd_sysvar_cache_join_const( NULL        )==NULL );
  FD_TEST( fd_sysvar_cache_join_const( (void *)1UL )==NULL ); /* misaligned */
  ((fd_sysvar_cache_t *)cache_mem)->magic++;
  FD_TEST( fd_sysvar_cache_join_const( cache_mem   )==NULL ); /* bad magic */
  ((fd_sysvar_cache_t *)cache_mem)->magic--;
  fd_sysvar_cache_t const * cache1 = fd_sysvar_cache_join( cache_mem );
  FD_TEST( cache );

  /* Test is_valid */
  FD_TEST( !fd_sysvar_cache_clock_is_valid            ( cache1 ) );
  FD_TEST( !fd_sysvar_cache_epoch_rewards_is_valid    ( cache1 ) );
  FD_TEST( !fd_sysvar_cache_epoch_schedule_is_valid   ( cache1 ) );
  FD_TEST( !fd_sysvar_cache_last_restart_slot_is_valid( cache1 ) );
  FD_TEST( !fd_sysvar_cache_recent_hashes_is_valid    ( cache1 ) );
  FD_TEST( !fd_sysvar_cache_rent_is_valid             ( cache1 ) );
  FD_TEST( !fd_sysvar_cache_slot_hashes_is_valid      ( cache1 ) );
  FD_TEST( !fd_sysvar_cache_slot_history_is_valid     ( cache1 ) );
  FD_TEST( !fd_sysvar_cache_stake_history_is_valid    ( cache1 ) );

  /* Test query */
  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    ulong sz = 0x1234;
    FD_TEST( fd_sysvar_cache_data_query( cache1, &fd_sysvar_key_tbl[ i ], &sz )==NULL );
    FD_TEST( sz==0UL );
  }
  do {
    fd_pubkey_t pubkey = { .ul={9} };
    ulong sz = 0x1234;
    FD_TEST( fd_sysvar_cache_data_query( cache1, &pubkey, &sz )==NULL );
    FD_TEST( sz==0UL );
  } while(0);

  /* Test sysvar read accessors */
  fd_sol_sysvar_clock_t clock;
  FD_TEST( !fd_sysvar_cache_clock_read( cache1, &clock ) );
  fd_sysvar_epoch_rewards_t epoch_rewards;
  FD_TEST( !fd_sysvar_cache_epoch_rewards_read( cache1, &epoch_rewards ) );
  fd_epoch_schedule_t epoch_schedule;
  FD_TEST( !fd_sysvar_cache_epoch_schedule_read( cache1, &epoch_schedule ) );
  FD_TEST( fd_sysvar_cache_last_restart_slot_read( cache1 )==NULL );
  fd_rent_t rent;
  FD_TEST( !fd_sysvar_cache_rent_read( cache1, &rent ) );

  /* Test sysvar join accessors */
  FD_TEST( !fd_sysvar_cache_slot_hashes_join_const  ( cache1 ) );
  FD_TEST( !fd_sysvar_cache_stake_history_join_const( cache1 ) );

  /* Test leave_const */
  FD_TEST( fd_sysvar_cache_leave_const( cache1 )==cache_mem );

  /* Test delete */
  FD_TEST( fd_sysvar_cache_delete( NULL      )==NULL );
  ((fd_sysvar_cache_t *)cache_mem)->magic++;
  FD_TEST( fd_sysvar_cache_delete( cache_mem )==NULL ); /* bad magic */
  ((fd_sysvar_cache_t *)cache_mem)->magic--;
  FD_TEST( fd_sysvar_cache_delete( cache_mem )==sysvar_cache_ );
}

/* sysvar_inject places a serialized sysvar into the sysvar cache,
   bypassing the database (which does not exist for the below unit tests) */

static int
sysvar_inject( fd_sysvar_cache_t * cache,
               ulong               idx,
               uchar const *       data,
               ulong               data_sz ) {
  if( FD_UNLIKELY( idx>=FD_SYSVAR_CACHE_ENTRY_CNT ) ) FD_LOG_CRIT(( "Invalid sysvar idx %lu", idx ));
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  FD_TEST( data_sz <= pos->data_max );
  fd_memcpy( (uchar *)cache+pos->data_off, data, data_sz );
  desc->data_sz = (uint)data_sz;
  desc->flags   = 0;
  return fd_sysvar_obj_restore( cache, desc, pos );
}

static void
test_sysvar_cache_read( void ) {
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( fd_sysvar_cache_new( sysvar_cache_ ) );

  FD_TEST( fd_sysvar_cache_clock_is_valid( cache )==0 );
  cache->desc[ FD_SYSVAR_clock_IDX ] = (fd_sysvar_desc_t) {
    .flags   = FD_SYSVAR_FLAG_VALID,
    .data_sz = FD_SYSVAR_CLOCK_BINCODE_SZ
  };

  /* Restore real clock sysvar account observed on-chain */
  static uchar const data[] = {
    0xef, 0x04, 0x28, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x55, 0x95, 0x7d, 0x68, 0x00, 0x00, 0x00, 0x00,
    0x35, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x36, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x87, 0x3a, 0x7f, 0x68, 0x00, 0x00, 0x00, 0x00
  };
  FD_TEST( sysvar_inject( cache, FD_SYSVAR_clock_IDX, data, sizeof(data) )==0 );
  FD_TEST( fd_sysvar_cache_clock_is_valid( cache )==1 );
  ulong copy_sz = 0x95959595UL;
  uchar const * copy = fd_sysvar_cache_data_query( cache, &fd_sysvar_clock_id, &copy_sz );
  FD_TEST( copy_sz==sizeof(data) && fd_memeq( data, copy, sizeof(data) ) );
  fd_sol_sysvar_clock_t clock_copy = fd_sysvar_cache_clock_read_nofail( cache );
  FD_TEST( clock_copy.slot                  == 0x152804efUL );
  FD_TEST( clock_copy.epoch_start_timestamp == 0x687d9555UL );
  FD_TEST( clock_copy.epoch                 == 0x00000335UL );
  FD_TEST( clock_copy.leader_schedule_epoch == 0x00000336UL );
  FD_TEST( clock_copy.unix_timestamp        == 0x687f3a87UL );

  /* Restore invalid sysvar */
  static uchar const invalid[] = { 1,2,3 };
  FD_TEST( sysvar_inject( cache, FD_SYSVAR_clock_IDX, invalid, sizeof(invalid) )==EINVAL );
  FD_TEST( fd_sysvar_cache_clock_is_valid( cache )==0 );

  fd_sysvar_cache_delete( fd_sysvar_cache_leave( cache ) );
}

static void
test_sysvar_cache( void ) {
  test_sysvar_map();
  test_sysvar_cache_empty();
  test_sysvar_cache_read();
}
