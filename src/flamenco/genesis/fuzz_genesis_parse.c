#include "fd_genesis_parse.h"
#include "../runtime/fd_runtime_const.h"
#include <assert.h>
#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  fd_log_level_stderr_set(4);
  atexit( fd_halt );
  return 0;
}

static void
genesis_accounts_check( fd_genesis_t const * genesis,
                        uchar const *        bin,
                        ulong                bin_sz ) {
  ulong prev_off = 0UL;

  assert( genesis->account_cnt<=genesis->account_max );
  for( ulong i=0UL; i<genesis->account_cnt; i++ ) {
    ulong pubkey_off = genesis->account[ i ].pubkey_off;
    ulong owner_off  = genesis->account[ i ].owner_off;

    assert( pubkey_off >= prev_off );
    ulong data_off; assert( !__builtin_uaddl_overflow( pubkey_off, 48UL, &data_off ) );
    ulong end_off;  assert( !__builtin_uaddl_overflow( owner_off,  41UL, &end_off  ) );
    assert( data_off <= end_off );
    assert( end_off  <= bin_sz  );
    prev_off = end_off;

    ulong data_len = FD_LOAD( ulong, bin+pubkey_off+40UL );
    assert( data_len<=FD_RUNTIME_ACC_SZ_MAX );
    assert( pubkey_off+48UL+data_len==owner_off );
  }

  assert( genesis->builtin_cnt<=FD_GENESIS_BUILTIN_MAX_COUNT );
  for( ulong i=0UL; i<genesis->builtin_cnt; i++ ) {
    ulong data_len_off = genesis->builtin[ i ].data_len_off;
    ulong pubkey_off   = genesis->builtin[ i ].pubkey_off;

    assert( data_len_off >= prev_off );
    ulong data_off; assert( !__builtin_uaddl_overflow( data_len_off, 8UL, &data_off ) );
    assert( data_off <= bin_sz );
    ulong data_len = FD_LOAD( ulong, bin+data_len_off );
    assert( data_len<=FD_RUNTIME_ACC_SZ_MAX );
    assert( data_off+data_len==pubkey_off );
    ulong end_off; assert( !__builtin_uaddl_overflow( pubkey_off, 32UL, &end_off ) );
    assert( end_off <= bin_sz );
    prev_off = end_off;
  }
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  ulong          account_max = fd_genesis_account_max( size );
  void *         mem         = aligned_alloc( FD_GENESIS_ALIGN, fd_genesis_footprint( account_max ) );
  if( FD_UNLIKELY( !mem ) ) return 0;
  fd_genesis_t * genesis     = fd_genesis_new( mem, account_max );
  assert( genesis );
  if( !fd_genesis_parse( genesis, data, size ) ) { free( mem ); return 0; }

  /* In the genesis, the only two fields that are not fixed size are the
     accounts and the built-in accounts.  The offsets and bounds of each
     of the accounts are checked here. */
  genesis_accounts_check( genesis, data, size );
  free( mem );
  return 0;
}
