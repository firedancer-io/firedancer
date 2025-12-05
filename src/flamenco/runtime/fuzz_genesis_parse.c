#include "fd_genesis_parse.h"
#include "fd_runtime_const.h"
#include <assert.h>
#include <stdlib.h>

static uchar genesis_buf[ FD_GENESIS_MAX_MESSAGE_SIZE ] __attribute__((aligned(alignof(fd_genesis_t))));

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  fd_log_level_stderr_set(4);
  atexit( fd_halt );
  return 0;
}

static int
genesis_accounts_check( uchar * genesis_buf,
                        ulong   genesis_sz ) {

  fd_genesis_t * genesis                = fd_type_pun( genesis_buf );
  ulong          lowest_expected_offset = sizeof(fd_genesis_t);

  if( FD_UNLIKELY( genesis->accounts_len>FD_GENESIS_ACCOUNT_MAX_COUNT ) ) return 0;
  for( ulong i=0UL; i<genesis->accounts_len; i++ ) {
    ulong account_off = genesis->accounts_off[ i ];
    if( FD_UNLIKELY( account_off>genesis_sz ) )             return 0;
    if( FD_UNLIKELY( account_off<lowest_expected_offset ) ) return 0;

    fd_genesis_account_t * account = fd_type_pun( genesis_buf+account_off );
    if( FD_UNLIKELY( account->meta.dlen>FD_RUNTIME_ACC_SZ_MAX ) ) return 0;

    ulong next_offset = account_off+sizeof(fd_genesis_account_t)+account->meta.dlen;
    if( FD_UNLIKELY( next_offset<lowest_expected_offset ) ) return 0;
    lowest_expected_offset = next_offset;
  }

  if( FD_UNLIKELY( genesis->builtin_len>FD_GENESIS_BUILTIN_MAX_COUNT ) ) return 0;
  for( ulong i=0UL; i<genesis->builtin_len; i++ ) {
    ulong builtin_off = genesis->builtin_off[ i ];
    if( FD_UNLIKELY( builtin_off>genesis_sz ) )             return 0;
    if( FD_UNLIKELY( builtin_off<lowest_expected_offset ) ) return 0;

    fd_genesis_account_t * builtin = fd_type_pun( genesis_buf+builtin_off );
    if( FD_UNLIKELY( builtin->meta.dlen>FD_RUNTIME_ACC_SZ_MAX ) ) return 0;

    ulong next_offset = builtin_off+sizeof(fd_genesis_account_t)+builtin->meta.dlen;
    if( FD_UNLIKELY( next_offset<lowest_expected_offset ) ) return 0;
    lowest_expected_offset = next_offset;
  }

  if( FD_UNLIKELY( lowest_expected_offset>genesis_sz  ) ) return 0;
  return 1;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  ulong genesis_sz = 0UL;
  if( !fd_genesis_parse( data, size, &genesis_sz, genesis_buf ) ) return 0;
  if( FD_UNLIKELY( genesis_sz>FD_GENESIS_MAX_MESSAGE_SIZE ) ) return 0;

  /* In the genesis, the only two fields that are not fixed size are the
     accounts and the built-in accounts.  The offsets and bounds of each
     of the accounts are checked here. */
  assert( genesis_accounts_check( genesis_buf, genesis_sz ) );

  return 0;
}
