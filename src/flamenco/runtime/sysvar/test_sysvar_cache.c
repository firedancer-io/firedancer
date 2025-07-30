#include "fd_sysvar_cache_private.h"
#include "../fd_system_ids.h"

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

static void
test_sysvar_cache( void ) {
  test_sysvar_map();
}
