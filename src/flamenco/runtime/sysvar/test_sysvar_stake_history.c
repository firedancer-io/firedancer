#include "fd_sysvar_stake_history.h"
#include "fd_sysvar_cache.h"
#include "test_sysvar_cache_util.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"
#include "../../accdb/fd_accdb.h"
#include "fd_sysvar_rent.h"

FD_IMPORT_BINARY( example_stake_history, "src/flamenco/runtime/sysvar/test_sysvar_stake_history.bin" );

static void
test_sysvar_stake_history_bounds( void ) {
  FD_TEST( example_stake_history_sz==FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  FD_TEST( fd_sysvar_stake_history_validate( example_stake_history, example_stake_history_sz ) );

  fd_stake_history_t view[1];
  FD_TEST( fd_sysvar_stake_history_view( view, example_stake_history, example_stake_history_sz ) );
  FD_TEST( view->len <= FD_SYSVAR_STAKE_HISTORY_CAP );
}

static fd_rent_t
test_stake_history_rent( void ) {
  return (fd_rent_t) {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
}

static fd_stake_history_entry_t
test_stake_history_entry( ulong epoch ) {
  return (fd_stake_history_entry_t) {
    .epoch        = epoch,
    .effective    = epoch + 0x1000UL,
    .activating   = epoch + 0x2000UL,
    .deactivating = epoch + 0x3000UL
  };
}

static void
test_stake_history_env_setup( test_sysvar_cache_env_t * env,
                              fd_wksp_t *               wksp ) {
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );
  env->bank->f.rent = test_stake_history_rent();
}

static void
write_stake_history_account( test_sysvar_cache_env_t * env,
                             void const *              data,
                             ulong                     data_sz,
                             ulong                     lamports ) {
  fd_accdb_svm_write( env->bank, env->accdb, NULL,
                      &fd_sysvar_stake_history_id, &fd_sysvar_owner_id,
                      data, data_sz, lamports, 0 );
}

static void
read_stake_history_view( test_sysvar_cache_env_t * env,
                         fd_acc_t *                acc,
                         fd_stake_history_t *      view ) {
  *acc = fd_accdb_read_one( env->accdb, env->bank->accdb_fork_id, fd_sysvar_stake_history_id.uc );
  FD_TEST( acc->lamports );
  FD_TEST( acc->data_len==FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  FD_TEST( fd_sysvar_stake_history_view( view, acc->data, acc->data_len ) );
}

static void
test_sysvar_stake_history_update( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  test_stake_history_env_setup( env, wksp );
  FD_TEST( fd_sysvar_cache_stake_history_is_valid( env->sysvar_cache )==0 );

  fd_stake_history_entry_t const entry0 = {
    .epoch        = 1UL,
    .effective    = 0x111UL,
    .activating   = 0x222UL,
    .deactivating = 0x333UL,
  };
  fd_sysvar_stake_history_init( env->bank, env->accdb, NULL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &entry0 );
  FD_TEST( fd_sysvar_cache_restore( env->bank, env->accdb ) );
  FD_TEST( fd_sysvar_cache_stake_history_is_valid( env->sysvar_cache )==1 );

  env->bank->f.slot = 432000UL;
  env->bank->f.parent_slot = 431999UL;
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &entry0 );
  FD_TEST( fd_sysvar_cache_restore( env->bank, env->accdb ) );
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
test_sysvar_stake_history_update_grows_small_account( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  test_stake_history_env_setup( env, wksp );

  ulong data = 0UL;
  write_stake_history_account( env, &data, sizeof(ulong), 1UL );

  fd_stake_history_entry_t const entry = test_stake_history_entry( 42UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &entry );

  fd_acc_t acc[1];
  fd_stake_history_t view[1];
  read_stake_history_view( env, acc, view );

  FD_TEST( acc->lamports==fd_rent_exempt_minimum_balance( &env->bank->f.rent, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ) );
  FD_TEST( view->len==1UL );
  FD_TEST( fd_sysvar_stake_history_query( view, 42UL ) );
  FD_TEST( fd_sysvar_stake_history_query( view, 42UL )->effective==entry.effective );

  fd_accdb_unread_one( env->accdb, acc );
  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history_update_truncates_large_account( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  test_stake_history_env_setup( env, wksp );

  uchar data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ+sizeof(fd_stake_history_entry_t) ];
  fd_memset( data, 0xAB, sizeof(data) );
  FD_STORE( ulong, data, FD_SYSVAR_STAKE_HISTORY_CAP+1UL );
  fd_stake_history_entry_t * entries = fd_type_pun( data+8UL );
  for( ulong i=0UL; i<FD_SYSVAR_STAKE_HISTORY_CAP+1UL; i++ ) entries[i] = test_stake_history_entry( 1000UL-i );
  write_stake_history_account( env, data, sizeof(data), 1UL );

  fd_stake_history_entry_t const entry = test_stake_history_entry( 2000UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &entry );

  fd_acc_t acc[1];
  fd_stake_history_t view[1];
  read_stake_history_view( env, acc, view );

  FD_TEST( acc->lamports==fd_rent_exempt_minimum_balance( &env->bank->f.rent, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ) );
  FD_TEST( view->len==FD_SYSVAR_STAKE_HISTORY_CAP );
  FD_TEST( view->entries[0].epoch==2000UL );
  FD_TEST( view->entries[1].epoch==1000UL );
  FD_TEST( view->entries[FD_SYSVAR_STAKE_HISTORY_CAP-1UL].epoch==490UL );
  FD_TEST( fd_sysvar_stake_history_query( view, 2000UL ) );
  FD_TEST( fd_sysvar_stake_history_query( view, 2000UL )->effective==entry.effective );
  FD_TEST( !fd_sysvar_stake_history_query( view, 489UL ) );

  fd_accdb_unread_one( env->accdb, acc );
  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history_update_tops_low_balance( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  test_stake_history_env_setup( env, wksp );

  uchar data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_memset( data, 0, sizeof(data) );
  write_stake_history_account( env, data, sizeof(data), 1UL );

  fd_stake_history_entry_t const entry = test_stake_history_entry( 7UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &entry );

  fd_acc_t acc[1];
  fd_stake_history_t view[1];
  read_stake_history_view( env, acc, view );

  FD_TEST( acc->lamports==fd_rent_exempt_minimum_balance( &env->bank->f.rent, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ) );
  FD_TEST( view->len==1UL );
  FD_TEST( fd_sysvar_stake_history_query( view, 7UL ) );

  fd_accdb_unread_one( env->accdb, acc );
  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history_update_replaces_existing_epoch( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  test_stake_history_env_setup( env, wksp );

  uchar data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_memset( data, 0, sizeof(data) );
  FD_STORE( ulong, data, 3UL );
  fd_stake_history_entry_t * entries = fd_type_pun( data+8UL );
  entries[0] = test_stake_history_entry( 3UL );
  entries[1] = test_stake_history_entry( 2UL );
  entries[2] = test_stake_history_entry( 1UL );
  write_stake_history_account( env, data, sizeof(data),
                               fd_rent_exempt_minimum_balance( &env->bank->f.rent, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ) );

  fd_stake_history_entry_t replacement = {
    .epoch        = 2UL,
    .effective    = 0x5555UL,
    .activating   = 0xaaaaUL,
    .deactivating = 0xffffUL
  };
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &replacement );

  fd_acc_t acc[1];
  fd_stake_history_t view[1];
  read_stake_history_view( env, acc, view );

  FD_TEST( view->len==3UL );
  FD_TEST( view->entries[0].epoch==3UL );
  FD_TEST( view->entries[1].epoch==2UL );
  FD_TEST( view->entries[2].epoch==1UL );
  fd_stake_history_entry_t const * e = fd_sysvar_stake_history_query( view, 2UL );
  FD_TEST( e );
  FD_TEST( e->effective==0x5555UL );
  FD_TEST( e->activating==0xaaaaUL );
  FD_TEST( e->deactivating==0xffffUL );

  fd_accdb_unread_one( env->accdb, acc );
  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history_update_inserts_descending( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  test_stake_history_env_setup( env, wksp );

  fd_sysvar_stake_history_init( env->bank, env->accdb, NULL );

  fd_stake_history_entry_t entry;
  entry = test_stake_history_entry( 1UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &entry );
  entry = test_stake_history_entry( 3UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &entry );
  entry = test_stake_history_entry( 2UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &entry );

  fd_acc_t acc[1];
  fd_stake_history_t view[1];
  read_stake_history_view( env, acc, view );

  FD_TEST( view->len==3UL );
  FD_TEST( view->entries[0].epoch==3UL );
  FD_TEST( view->entries[1].epoch==2UL );
  FD_TEST( view->entries[2].epoch==1UL );
  FD_TEST( fd_sysvar_stake_history_query( view, 3UL ) );
  FD_TEST( fd_sysvar_stake_history_query( view, 2UL ) );
  FD_TEST( fd_sysvar_stake_history_query( view, 1UL ) );

  fd_accdb_unread_one( env->accdb, acc );
  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history_update_at_capacity( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  test_stake_history_env_setup( env, wksp );

  uchar data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_memset( data, 0, sizeof(data) );
  FD_STORE( ulong, data, FD_SYSVAR_STAKE_HISTORY_CAP );
  fd_stake_history_entry_t * entries = fd_type_pun( data+8UL );
  for( ulong i=0UL; i<FD_SYSVAR_STAKE_HISTORY_CAP; i++ ) entries[i] = test_stake_history_entry( 1000UL-i );
  write_stake_history_account( env, data, sizeof(data),
                               fd_rent_exempt_minimum_balance( &env->bank->f.rent, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ) );

  fd_stake_history_entry_t newest = test_stake_history_entry( 2000UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &newest );

  fd_acc_t acc[1];
  fd_stake_history_t view[1];
  read_stake_history_view( env, acc, view );

  FD_TEST( view->len==FD_SYSVAR_STAKE_HISTORY_CAP );
  FD_TEST( view->entries[0].epoch==2000UL );
  FD_TEST( view->entries[1].epoch==1000UL );
  FD_TEST( view->entries[FD_SYSVAR_STAKE_HISTORY_CAP-1UL].epoch==490UL );
  FD_TEST( !fd_sysvar_stake_history_query( view, 489UL ) );

  fd_accdb_unread_one( env->accdb, acc );

  fd_stake_history_entry_t too_old = test_stake_history_entry( 1UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &too_old );

  read_stake_history_view( env, acc, view );
  FD_TEST( view->len==FD_SYSVAR_STAKE_HISTORY_CAP );
  FD_TEST( view->entries[0].epoch==2000UL );
  FD_TEST( view->entries[FD_SYSVAR_STAKE_HISTORY_CAP-1UL].epoch==490UL );
  FD_TEST( !fd_sysvar_stake_history_query( view, 1UL ) );

  fd_accdb_unread_one( env->accdb, acc );
  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history_update_zeros_trailing( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  test_stake_history_env_setup( env, wksp );

  /* Write an account with 3 entries and garbage in the trailing area */
  uchar data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_memset( data, 0xAB, sizeof(data) );
  FD_STORE( ulong, data, 3UL );
  fd_stake_history_entry_t * entries = fd_type_pun( data+8UL );
  entries[0] = test_stake_history_entry( 9UL );
  entries[1] = test_stake_history_entry( 5UL );
  entries[2] = test_stake_history_entry( 1UL );
  write_stake_history_account( env, data, sizeof(data),
                               fd_rent_exempt_minimum_balance( &env->bank->f.rent, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ) );

  fd_stake_history_entry_t insert = test_stake_history_entry( 7UL );
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &insert );

  fd_acc_t acc[1];
  fd_stake_history_t view[1];
  read_stake_history_view( env, acc, view );

  FD_TEST( view->len==4UL );
  ulong used = 8UL + 4UL * sizeof(fd_stake_history_entry_t);
  uchar const * raw = acc->data;
  for( ulong i=used; i<FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ; i++ ) {
    FD_TEST( raw[i]==0 );
  }

  fd_accdb_unread_one( env->accdb, acc );
  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_stake_history( fd_wksp_t * wksp ) {
  test_sysvar_stake_history_bounds();
  test_sysvar_stake_history_update( wksp );
  test_sysvar_stake_history_update_grows_small_account( wksp );
  test_sysvar_stake_history_update_truncates_large_account( wksp );
  test_sysvar_stake_history_update_tops_low_balance( wksp );
  test_sysvar_stake_history_update_replaces_existing_epoch( wksp );
  test_sysvar_stake_history_update_inserts_descending( wksp );
  test_sysvar_stake_history_update_at_capacity( wksp );
  test_sysvar_stake_history_update_zeros_trailing( wksp );
}
