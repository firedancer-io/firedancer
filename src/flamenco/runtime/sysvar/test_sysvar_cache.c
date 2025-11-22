#include "fd_sysvar_cache.h"
#include "fd_sysvar_cache_private.h"
#include "test_sysvar_cache_util.h"
#include "../fd_system_ids.h"
#include "../fd_bank.h"
#include "../../accdb/fd_accdb_admin.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include <errno.h>

test_sysvar_cache_env_t *
test_sysvar_cache_env_create( test_sysvar_cache_env_t * env,
                              fd_wksp_t *               wksp ) {
  memset( env, 0, sizeof(test_sysvar_cache_env_t) );
  ulong const funk_tag  = 99UL; /* unique */
  ulong const wksp_tag  = 98UL; /* arbitrary */
  ulong const funk_seed = 17UL; /* arbitrary */
  ulong const txn_max   =  2UL;
  ulong const rec_max   = 32UL;

  void * funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), funk_tag );
  FD_TEST( funk_mem );
  FD_TEST( fd_funk_new( funk_mem, funk_tag, funk_seed, txn_max, rec_max ) );
  fd_accdb_user_t * accdb = fd_accdb_user_v1_init( env->accdb, funk_mem );
  FD_TEST( accdb );

  fd_bank_t * bank = fd_wksp_alloc_laddr( wksp, alignof(fd_bank_t), sizeof(fd_bank_t), wksp_tag );

  env->shfunk       = funk_mem;
  env->bank         = bank;
  env->xid          = (fd_funk_txn_xid_t) { .ul={ 0UL, 0UL } };
  env->sysvar_cache = fd_sysvar_cache_join( fd_sysvar_cache_new( bank->non_cow.sysvar_cache ) );

  fd_accdb_admin_t admin[1];
  FD_TEST( fd_accdb_admin_join( admin, funk_mem ) );
  fd_accdb_attach_child( admin, fd_funk_last_publish( admin->funk ), &env->xid );
  fd_accdb_admin_leave( admin, NULL );

  return env;
}

void
test_sysvar_cache_env_destroy( test_sysvar_cache_env_t * env ) {
  FD_TEST( env );
  FD_TEST( fd_sysvar_cache_delete( fd_sysvar_cache_leave( env->sysvar_cache ) ) );
  fd_wksp_free_laddr( env->bank );
  fd_accdb_user_fini( env->accdb );
  fd_funk_delete_fast( env->shfunk );
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
  fd_sol_sysvar_last_restart_slot_t last_restart_slot;
  FD_TEST( !fd_sysvar_cache_last_restart_slot_read( cache1, &last_restart_slot ) );
  fd_rent_t rent;
  FD_TEST( !fd_sysvar_cache_rent_read( cache1, &rent ) );

  /* Test sysvar join accessors */
  FD_TEST( !fd_sysvar_cache_slot_history_join_const ( cache1 ) );
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
