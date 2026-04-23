#include "test_sysvar_cache_util.h"
#include "fd_sysvar_slot_history.h"
#include "fd_sysvar.h"
#include "fd_sysvar_base.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include <stdlib.h>

FD_IMPORT_BINARY( example_slot_history, "src/flamenco/runtime/sysvar/test_sysvar_slot_history.bin" );

#define BITS_PER_BLOCK (64UL)
#define BLOCKS_LEN     (FD_SLOT_HISTORY_MAX_ENTRIES / BITS_PER_BLOCK)
#define HEADER_SZ      (9UL)  /* has_bits + blocks_len */
#define FOOTER_SZ      (16UL) /* bits_len + next_slot */
#define MIN_SZ         (HEADER_SZ + FOOTER_SZ)

static void
test_sysvar_slot_history_validate( void ) {
  FD_TEST( !fd_sysvar_slot_history_validate( NULL, 0 ) );
  FD_TEST( !fd_sysvar_slot_history_validate( example_slot_history, 0 ) );
  FD_TEST( !fd_sysvar_slot_history_validate( example_slot_history, 24 ) );

  FD_TEST( example_slot_history_sz==FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  FD_TEST(  fd_sysvar_slot_history_validate( example_slot_history, example_slot_history_sz ) );
  FD_TEST(  fd_sysvar_slot_history_validate( example_slot_history, example_slot_history_sz+8UL ) );
  FD_TEST( !fd_sysvar_slot_history_validate( example_slot_history, example_slot_history_sz-1UL ) );

  static uchar bad_has_bits[ 25 ] = { 2 };
  FD_TEST( !fd_sysvar_slot_history_validate( bad_has_bits, sizeof(bad_has_bits) ) );

  static uchar empty[ MIN_SZ ] = { 1, 0,0,0,0,0,0,0,0, };
  FD_TEST(  fd_sysvar_slot_history_validate( empty, sizeof(empty) ) );
  FD_TEST( !fd_sysvar_slot_history_validate( empty, sizeof(empty)-1UL ) );

  static uchar overflow[ 25 ] = { 1, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff };
  FD_TEST( !fd_sysvar_slot_history_validate( overflow, sizeof(overflow) ) );

  static uchar near_overflow[ 25 ] = { 1, 0xfe,0xff,0xff,0xff, 0xff,0xff,0xff,0x1f };
  FD_TEST( !fd_sysvar_slot_history_validate( near_overflow, sizeof(near_overflow) ) );
}

static void
test_sysvar_slot_history_view( void ) {
  fd_slot_history_view_t view[1];
  FD_TEST( fd_sysvar_slot_history_view( view, example_slot_history, example_slot_history_sz )==view );
  FD_TEST( view->blocks_len == BLOCKS_LEN                  );
  FD_TEST( view->bits_len   == FD_SLOT_HISTORY_MAX_ENTRIES );
  FD_TEST( view->bits       == example_slot_history + HEADER_SZ );
  FD_TEST( view->next_slot  == 0x152820f4UL );

  FD_TEST( fd_sysvar_slot_history_view( view, example_slot_history, 0       )==NULL );
  FD_TEST( fd_sysvar_slot_history_view( view, example_slot_history, MIN_SZ-1 )==NULL );

  static uchar empty[ MIN_SZ ] = {
    1, 0,0,0,0,0,0,0,0,
    /* bits_len   */ 0,0,0,0,0,0,0,0,
    /* next_slot  */ 0,0,0,0,0,0,0,0,
  };
  FD_TEST( fd_sysvar_slot_history_view( view, empty, sizeof(empty) )==view );
  FD_TEST( view->blocks_len == 0UL );
  FD_TEST( view->bits_len   == 0UL );
  FD_TEST( view->next_slot  == 0UL );
}

static void
test_sysvar_slot_history_find_slot( void ) {
  fd_slot_history_view_t view[1];
  FD_TEST( fd_sysvar_slot_history_view( view, example_slot_history, example_slot_history_sz ) );
  ulong const newest = view->next_slot - 1UL;

  FD_TEST( fd_sysvar_slot_history_find_slot( view, newest+1UL )==FD_SLOT_HISTORY_SLOT_FUTURE );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, ULONG_MAX  )==FD_SLOT_HISTORY_SLOT_FUTURE );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, newest     )==FD_SLOT_HISTORY_SLOT_FOUND  );

  ulong oldest_kept = view->next_slot - FD_SLOT_HISTORY_MAX_ENTRIES;
  FD_TEST( fd_sysvar_slot_history_find_slot( view, oldest_kept-1UL )==FD_SLOT_HISTORY_SLOT_TOO_OLD );

  static uchar empty[ MIN_SZ ] = {
    1, 0,0,0,0,0,0,0,0,
    /* bits_len   */ 0,0,0,0,0,0,0,0,
    /* next_slot  */ 1,0,0,0,0,0,0,0,
  };
  fd_slot_history_view_t empty_view[1];
  FD_TEST( fd_sysvar_slot_history_view( empty_view, empty, sizeof(empty) ) );
  FD_TEST( fd_sysvar_slot_history_find_slot( empty_view, 0UL )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
}

static void
make_slot_history( uchar  out[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ],
                   ulong  set_slot,
                   ulong  next_slot ) {
  fd_memset( out, 0, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  out[0] = 1;
  FD_STORE( ulong, out+1, BLOCKS_LEN );
  if( set_slot < next_slot ) {
    ulong block_idx = (set_slot/BITS_PER_BLOCK) % BLOCKS_LEN;
    uchar * word = out + HEADER_SZ + block_idx*sizeof(ulong);
    FD_STORE( ulong, word, FD_LOAD( ulong, word ) | (1UL << (set_slot%BITS_PER_BLOCK)) );
  }
  uchar * footer = out + HEADER_SZ + BLOCKS_LEN*sizeof(ulong);
  FD_STORE( ulong, footer,     FD_SLOT_HISTORY_MAX_ENTRIES );
  FD_STORE( ulong, footer+8UL, next_slot                   );
}

static void
test_sysvar_slot_history_find_slot_synthetic( void ) {
  uchar * data = malloc( FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  FD_TEST( data );
  fd_slot_history_view_t view[1];

  make_slot_history( data, 100UL, 101UL );
  FD_TEST( fd_sysvar_slot_history_view( view, data, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 100UL )==FD_SLOT_HISTORY_SLOT_FOUND     );
  FD_TEST( fd_sysvar_slot_history_find_slot( view,  99UL )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 101UL )==FD_SLOT_HISTORY_SLOT_FUTURE    );

  ulong const big_slot = FD_SLOT_HISTORY_MAX_ENTRIES + 5UL;
  make_slot_history( data, big_slot, big_slot+1UL );
  FD_TEST( fd_sysvar_slot_history_view( view, data, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, big_slot     )==FD_SLOT_HISTORY_SLOT_FOUND     );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 6UL          )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 5UL          )==FD_SLOT_HISTORY_SLOT_TOO_OLD  );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, big_slot+1UL )==FD_SLOT_HISTORY_SLOT_FUTURE   );

  free( data );
}

static void
test_sysvar_slot_history_init( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );
  FD_TEST( !fd_sysvar_cache_slot_history_is_valid( env->sysvar_cache ) );

  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  env->bank->f.rent = rent;
  env->bank->f.slot = 1234UL;

  fd_sysvar_slot_history_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );
  FD_TEST( fd_sysvar_cache_slot_history_is_valid( env->sysvar_cache ) );

  ulong sz = 0UL;
  uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_history_id, &sz );
  FD_TEST( data && sz==FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );

  fd_slot_history_view_t view[1];
  FD_TEST( fd_sysvar_slot_history_view( view, data, sz ) );
  FD_TEST( view->next_slot==1235UL );
  FD_TEST( view->bits_len ==FD_SLOT_HISTORY_MAX_ENTRIES );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 1234UL )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 1235UL )==FD_SLOT_HISTORY_SLOT_FUTURE   );

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_slot_history_update( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );

  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  env->bank->f.rent = rent;

  env->bank->f.slot = 100UL;
  fd_sysvar_slot_history_init  ( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_slot_history_update( env->bank, env->accdb, &env->xid, NULL );
  env->bank->f.slot = 101UL;
  fd_sysvar_slot_history_update( env->bank, env->accdb, &env->xid, NULL );
  env->bank->f.slot = 105UL;
  fd_sysvar_slot_history_update( env->bank, env->accdb, &env->xid, NULL );

  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );
  FD_TEST( fd_sysvar_cache_slot_history_is_valid( env->sysvar_cache ) );

  ulong sz = 0UL;
  uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_history_id, &sz );
  FD_TEST( data && sz==FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );

  fd_slot_history_view_t view[1];
  FD_TEST( fd_sysvar_slot_history_view( view, data, sz ) );
  FD_TEST( view->next_slot==106UL );

  FD_TEST( fd_sysvar_slot_history_find_slot( view, 100UL )==FD_SLOT_HISTORY_SLOT_FOUND     );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 101UL )==FD_SLOT_HISTORY_SLOT_FOUND     );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 102UL )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 103UL )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 104UL )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 105UL )==FD_SLOT_HISTORY_SLOT_FOUND     );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 106UL )==FD_SLOT_HISTORY_SLOT_FUTURE    );

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_slot_history_update_large_gap( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );

  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  env->bank->f.rent = rent;

  env->bank->f.slot = 100UL;
  fd_sysvar_slot_history_init  ( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_slot_history_update( env->bank, env->accdb, &env->xid, NULL );

  ulong new_slot = 100UL + FD_SLOT_HISTORY_MAX_ENTRIES + 500UL;
  env->bank->f.slot = new_slot;
  fd_sysvar_slot_history_update( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );

  ulong sz = 0UL;
  uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_history_id, &sz );
  FD_TEST( data && sz==FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );

  fd_slot_history_view_t view[1];
  FD_TEST( fd_sysvar_slot_history_view( view, data, sz ) );
  FD_TEST( view->next_slot == new_slot + 1UL );

  FD_TEST( fd_sysvar_slot_history_find_slot( view, new_slot     )==FD_SLOT_HISTORY_SLOT_FOUND     );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, new_slot+1UL )==FD_SLOT_HISTORY_SLOT_FUTURE    );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, 100UL        )==FD_SLOT_HISTORY_SLOT_TOO_OLD   );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, new_slot-1UL )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );

  ulong oldest_kept = new_slot + 1UL - FD_SLOT_HISTORY_MAX_ENTRIES;
  FD_TEST( fd_sysvar_slot_history_find_slot( view, oldest_kept     )==FD_SLOT_HISTORY_SLOT_NOT_FOUND );
  FD_TEST( fd_sysvar_slot_history_find_slot( view, oldest_kept-1UL )==FD_SLOT_HISTORY_SLOT_TOO_OLD   );

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_slot_history_update_zero_blocks( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );

  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  env->bank->f.rent = rent;

  /* Write a minimal slot history sysvar with bits_bitvec_len=0 */
  uchar data[ MIN_SZ ] = {
    1, 0,0,0,0,0,0,0,0,
    /* bits_len   */ 0,0,0,0,0,0,0,0,
    /* next_slot  */ 1,0,0,0,0,0,0,0,
  };
  fd_sysvar_account_update( env->bank, env->accdb, &env->xid, NULL,
                            &fd_sysvar_slot_history_id, data, sizeof(data) );

  env->bank->f.slot = 42UL;
  fd_sysvar_slot_history_update( env->bank, env->accdb, &env->xid, NULL );

  /* Verify data unchanged (update was a no-op) */
  fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );
  ulong sz = 0UL;
  uchar const * out = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_slot_history_id, &sz );
  FD_TEST( out && sz==sizeof(data) );
  FD_TEST( 0==memcmp( out, data, sizeof(data) ) );

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_slot_history( fd_wksp_t * wksp ) {
  test_sysvar_slot_history_validate           ();
  test_sysvar_slot_history_view               ();
  test_sysvar_slot_history_find_slot          ();
  test_sysvar_slot_history_find_slot_synthetic();
  test_sysvar_slot_history_init               ( wksp );
  test_sysvar_slot_history_update             ( wksp );
  test_sysvar_slot_history_update_large_gap   ( wksp );
  test_sysvar_slot_history_update_zero_blocks ( wksp );
}
