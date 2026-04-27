#include "test_sysvar_cache_util.h"
#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar_cache.h"
#include "../fd_system_ids.h"

FD_IMPORT_BINARY( example_slot_hashes, "src/flamenco/runtime/sysvar/test_sysvar_slot_hashes.bin" );

static void
test_sysvar_slot_hashes_validate_and_view( void ) {
  FD_TEST( example_slot_hashes_sz==FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
  FD_TEST( fd_sysvar_slot_hashes_validate( example_slot_hashes, example_slot_hashes_sz ) );

  fd_slot_hashes_t view[1];
  FD_TEST( fd_sysvar_slot_hashes_view( view, example_slot_hashes, example_slot_hashes_sz ) );
  FD_TEST( view->cnt==FD_SYSVAR_SLOT_HASHES_CAP );

  FD_TEST( !fd_sysvar_slot_hashes_validate( NULL, 0 ) );
  FD_TEST( !fd_sysvar_slot_hashes_validate( example_slot_hashes, 4 ) );

  uchar overflow_data[8];
  FD_STORE( ulong, overflow_data, ULONG_MAX );
  FD_TEST( !fd_sysvar_slot_hashes_validate( overflow_data, sizeof(overflow_data) ) );

  uchar short_data[16] = {0};
  FD_STORE( ulong, short_data, 2UL );
  FD_TEST( !fd_sysvar_slot_hashes_validate( short_data, sizeof(short_data) ) );
  FD_TEST( !fd_sysvar_slot_hashes_view( view, short_data, sizeof(short_data) ) );
}

static void
test_sysvar_slot_hashes_init( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );

  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  env->bank->f.rent = rent;

  fd_sysvar_slot_hashes_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );
  FD_TEST( fd_sysvar_cache_slot_hashes_is_valid( env->sysvar_cache ) );

  ulong sz = 0UL;
  uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_hashes_id, &sz );
  FD_TEST( data && sz==FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
  FD_TEST( FD_LOAD( ulong, data )==0UL );

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_slot_hashes_update( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );

  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  env->bank->f.rent = rent;

  /* update on missing account triggers init + insert */
  fd_hash_t hash0 = { .ul={ 0xaaUL, 0xbbUL, 0xccUL, 0xddUL } };
  env->bank->f.parent_slot = 100UL;
  env->bank->f.bank_hash   = hash0;
  fd_sysvar_slot_hashes_update( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );

  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_hashes_id, &sz );
    FD_TEST( data );
    fd_slot_hashes_t view[1];
    FD_TEST( fd_sysvar_slot_hashes_view( view, data, sz ) );
    FD_TEST( view->cnt==1UL );
    FD_TEST( view->elems[0].slot==100UL );
    FD_TEST( fd_hash_eq( &view->elems[0].hash, &hash0 ) );
  }

  /* add a second entry */
  fd_hash_t hash1 = { .ul={ 0x11UL, 0x22UL, 0x33UL, 0x44UL } };
  env->bank->f.parent_slot = 101UL;
  env->bank->f.bank_hash   = hash1;
  fd_sysvar_slot_hashes_update( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );

  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_hashes_id, &sz );
    FD_TEST( data );
    fd_slot_hashes_t view[1];
    FD_TEST( fd_sysvar_slot_hashes_view( view, data, sz ) );
    FD_TEST( view->cnt==2UL );
    FD_TEST( view->elems[0].slot==101UL );
    FD_TEST( fd_hash_eq( &view->elems[0].hash, &hash1 ) );
    FD_TEST( view->elems[1].slot==100UL );
    FD_TEST( fd_hash_eq( &view->elems[1].hash, &hash0 ) );
  }

  /* update existing entry (same parent_slot, different hash) */
  fd_hash_t hash0_new = { .ul={ 0xeeUL, 0xffUL, 0x00UL, 0x11UL } };
  env->bank->f.parent_slot = 101UL;
  env->bank->f.bank_hash   = hash0_new;
  fd_sysvar_slot_hashes_update( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );

  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_hashes_id, &sz );
    FD_TEST( data );
    fd_slot_hashes_t view[1];
    FD_TEST( fd_sysvar_slot_hashes_view( view, data, sz ) );
    FD_TEST( view->cnt==2UL );
    FD_TEST( view->elems[0].slot==101UL );
    FD_TEST( fd_hash_eq( &view->elems[0].hash, &hash0_new ) );
    FD_TEST( view->elems[1].slot==100UL );
    FD_TEST( fd_hash_eq( &view->elems[1].hash, &hash0 ) );
  }

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_slot_hashes_eviction( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );

  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  env->bank->f.rent = rent;

  /* Fill to capacity */
  fd_sysvar_slot_hashes_init( env->bank, env->accdb, &env->xid, NULL );
  for( ulong i=0UL; i<FD_SYSVAR_SLOT_HASHES_CAP; i++ ) {
    env->bank->f.parent_slot    = i;
    env->bank->f.bank_hash.ul[0] = i + 1UL;
    fd_sysvar_slot_hashes_update( env->bank, env->accdb, &env->xid, NULL );
  }

  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );
  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_hashes_id, &sz );
    FD_TEST( data );
    fd_slot_hashes_t view[1];
    FD_TEST( fd_sysvar_slot_hashes_view( view, data, sz ) );
    FD_TEST( view->cnt==FD_SYSVAR_SLOT_HASHES_CAP );
    FD_TEST( view->elems[0].slot==FD_SYSVAR_SLOT_HASHES_CAP-1UL );
    FD_TEST( view->elems[FD_SYSVAR_SLOT_HASHES_CAP-1UL].slot==0UL );
  }

  /* One more triggers eviction of oldest (slot 0) */
  env->bank->f.parent_slot      = 999UL;
  env->bank->f.bank_hash.ul[0]  = 0xdeadUL;
  fd_sysvar_slot_hashes_update( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );

  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_hashes_id, &sz );
    FD_TEST( data );
    fd_slot_hashes_t view[1];
    FD_TEST( fd_sysvar_slot_hashes_view( view, data, sz ) );
    FD_TEST( view->cnt==FD_SYSVAR_SLOT_HASHES_CAP );
    FD_TEST( view->elems[0].slot==999UL );
    FD_TEST( view->elems[0].hash.ul[0]==0xdeadUL );
    FD_TEST( view->elems[1].slot==FD_SYSVAR_SLOT_HASHES_CAP-1UL );
    FD_TEST( view->elems[FD_SYSVAR_SLOT_HASHES_CAP-1UL].slot==1UL );
  }

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_slot_hashes( fd_wksp_t * wksp ) {
  test_sysvar_slot_hashes_validate_and_view();
  test_sysvar_slot_hashes_init    ( wksp );
  test_sysvar_slot_hashes_update  ( wksp );
  test_sysvar_slot_hashes_eviction( wksp );
}
