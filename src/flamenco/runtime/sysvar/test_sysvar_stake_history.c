#include "fd_sysvar_stake_history.h"
#include "../../types/fd_types.h"
#include "test_sysvar_cache_util.h"
#include "../fd_system_ids.h"

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
  fd_bank_rent_set( env->slot_ctx->bank, rent );

  /* Stake History update requires epoch schedule */
  fd_epoch_schedule_t const schedule = {
    .slots_per_epoch             = 432000,
    .leader_schedule_slot_offset = 432000,
    .warmup                      =      0,
    .first_normal_epoch          =      0,
    .first_normal_slot           =      0
  };
  fd_bank_epoch_schedule_set( env->slot_ctx->bank, schedule );

  /* Update should be a no-op if not at the epoch boundary */
  static uchar spad_mem[ FD_SPAD_FOOTPRINT( 1<<17 ) ] __attribute__((aligned(FD_SPAD_ALIGN)));
  fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem, 1<<17 ) );
  fd_spad_push( spad );
  fd_bank_slot_set( env->slot_ctx->bank, 3 );
  fd_bank_parent_slot_set( env->slot_ctx->bank, 2 );
  fd_epoch_stake_history_entry_pair_t const entry0 = {
    .epoch = 1UL, .entry = {
      .effective    = 0x111UL,
      .activating   = 0x222UL,
      .deactivating = 0x333UL,
    }
  };
  fd_sysvar_stake_history_init( env->slot_ctx );
  fd_sysvar_stake_history_update( env->slot_ctx, &entry0 );
  fd_sysvar_cache_restore( env->slot_ctx );
  FD_TEST( fd_sysvar_cache_stake_history_is_valid( env->sysvar_cache )==1 );

  fd_bank_slot_set( env->slot_ctx->bank, 432000 );
  fd_bank_parent_slot_set( env->slot_ctx->bank, 431999 );
  fd_sysvar_stake_history_update( env->slot_ctx, &entry0 );
  fd_sysvar_cache_restore( env->slot_ctx );
  FD_TEST( fd_sysvar_cache_stake_history_is_valid( env->sysvar_cache )==1 );

  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_stake_history_id, &sz );
    FD_TEST( data && sz==FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  }

  test_sysvar_cache_env_destroy( env );
  fd_spad_pop( spad );
  fd_spad_delete( fd_spad_leave( spad ) );
}

static void
test_sysvar_stake_history( fd_wksp_t * wksp ) {
  test_sysvar_stake_history_bounds();
  test_sysvar_stake_history_update( wksp );
}
