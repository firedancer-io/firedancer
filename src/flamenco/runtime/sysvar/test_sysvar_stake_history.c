#include "fd_sysvar_stake_history.h"
#include "../../types/fd_types.h"
#include "test_sysvar_cache_util.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../../accdb/fd_accdb_impl_v1.h"

FD_IMPORT_BINARY( example_stake_history, "src/flamenco/runtime/sysvar/test_sysvar_stake_history.bin" );

static void
test_sysvar_stake_history_bounds( void ) {
  FD_TEST( example_stake_history_sz==FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = {
    .data    = example_stake_history,
    .dataend = example_stake_history + example_stake_history_sz
  };
  ulong obj_sz = 0UL;
  FD_TEST( fd_stake_history_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_STAKE_HISTORY_FOOTPRINT );
  FD_TEST( fd_stake_history_align()==FD_SYSVAR_STAKE_HISTORY_ALIGN );
}

static void
test_sysvar_stake_history_update( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );
  FD_TEST( fd_sysvar_cache_stake_history_is_valid( env->sysvar_cache )==0 );

  /* Cannot create any sysvar without the rent sysvar */
  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  fd_bank_rent_set( env->bank, rent );

  /* Stake History update requires epoch schedule */
  fd_epoch_schedule_t const schedule = {
    .slots_per_epoch             = 432000,
    .leader_schedule_slot_offset = 432000,
    .warmup                      =      0,
    .first_normal_epoch          =      0,
    .first_normal_slot           =      0
  };
  fd_bank_epoch_schedule_set( env->bank, schedule );

  /* Update should be a no-op if not at the epoch boundary */
  fd_bank_slot_set( env->bank, 3UL );
  fd_bank_parent_slot_set( env->bank, 2UL );
  fd_epoch_stake_history_entry_pair_t const entry0 = {
    .epoch = 1UL, .entry = {
      .effective    = 0x111UL,
      .activating   = 0x222UL,
      .deactivating = 0x333UL,
    }
  };
  fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, &env->xid, NULL, &entry0 );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );
  FD_TEST( fd_sysvar_cache_stake_history_is_valid( env->sysvar_cache )==1 );

  fd_bank_slot_set( env->bank, 432000UL );
  fd_bank_parent_slot_set( env->bank, 431999UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, &env->xid, NULL, &entry0 );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );
  FD_TEST( fd_sysvar_cache_stake_history_is_valid( env->sysvar_cache )==1 );

  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_stake_history_id, &sz );
    FD_TEST( data && sz==FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  }

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history( fd_wksp_t * wksp ) {
  test_sysvar_stake_history_bounds();
  test_sysvar_stake_history_update( wksp );
}
