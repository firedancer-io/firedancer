#include "fd_sysvar_stake_history.h"
#include "fd_sysvar_cache.h"
#include "test_sysvar_cache_util.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../../accdb/fd_accdb_impl_v1.h"

FD_IMPORT_BINARY( example_stake_history, "src/flamenco/runtime/sysvar/test_sysvar_stake_history.bin" );

static void
test_sysvar_stake_history_bounds( void ) {
  FD_TEST( example_stake_history_sz==FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  FD_TEST( fd_sysvar_stake_history_validate( example_stake_history, example_stake_history_sz ) );

  fd_stake_history_t view[1];
  FD_TEST( fd_sysvar_stake_history_view( view, example_stake_history, example_stake_history_sz ) );
  FD_TEST( view->len <= FD_SYSVAR_STAKE_HISTORY_CAP );
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
  env->bank->f.rent = rent;

  /* Stake History update requires epoch schedule */
  fd_epoch_schedule_t const schedule = {
    .slots_per_epoch             = 432000,
    .leader_schedule_slot_offset = 432000,
    .warmup                      =      0,
    .first_normal_epoch          =      0,
    .first_normal_slot           =      0
  };
  env->bank->f.epoch_schedule = schedule;

  fd_stake_history_entry_t const entry0 = {
    .epoch        = 1UL,
    .effective    = 0x111UL,
    .activating   = 0x222UL,
    .deactivating = 0x333UL,
  };
  fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, &env->xid, NULL, &entry0 );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );
  FD_TEST( fd_sysvar_cache_stake_history_is_valid( env->sysvar_cache )==1 );

  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_stake_history_id, &sz );
    FD_TEST( data && sz==FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );

    fd_stake_history_t view[1];
    FD_TEST( fd_sysvar_stake_history_view( view, data, sz ) );
    FD_TEST( view->len==1UL );

    fd_stake_history_entry_t const * e = fd_sysvar_stake_history_query( view, 1UL );
    FD_TEST( e );
    FD_TEST( e->epoch==1UL );
    FD_TEST( e->effective==0x111UL );
    FD_TEST( e->activating==0x222UL );
    FD_TEST( e->deactivating==0x333UL );

    FD_TEST( !fd_sysvar_stake_history_query( view, 999UL ) );
  }

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history( fd_wksp_t * wksp ) {
  test_sysvar_stake_history_bounds();
  test_sysvar_stake_history_update( wksp );
}
