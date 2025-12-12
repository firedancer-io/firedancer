#include "fd_backtest_shredcap.h"
#include "../../ballet/base58/fd_base58.h"
#include <stdio.h>
#include <stdlib.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * shredcap   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--shredcap",   NULL, NULL );
  ulong        start_slot = fd_env_strip_cmdline_ulong( &argc, &argv, "--start_slot", NULL, 0UL  );
  if( FD_UNLIKELY( !shredcap ) ) FD_LOG_ERR(( "missing --shredcap" ));

  void * mem = aligned_alloc( fd_backtest_shredcap_align(), fd_backtest_shredcap_footprint() );
  FD_TEST( mem );
  fd_backtest_shredcap_t * db = fd_backtest_shredcap_new( mem, shredcap );
  fd_backtest_shredcap_init( db, start_slot );

  for(;;) {
    ulong root_slot;
    ulong shred_cnt;
    int root_ok = fd_backtest_shredcap_next_root_slot( db, &root_slot, &shred_cnt );
    if( !root_ok ) break;
    FD_BASE58_ENCODE_32_BYTES( fd_backtest_shredcap_bank_hash( db, root_slot ), bank_hash_b58 );
    printf( "root_slot=%lu shred_cnt=%5lu bank_hash=%s\n", root_slot, shred_cnt, bank_hash_b58 );
    for( ulong i=0UL; i<shred_cnt; i++ ) {
      FD_TEST( !!fd_backtest_shredcap_shred( db, root_slot, i ) );
    }
  }

  free( mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
