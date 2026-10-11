#include "fd_keyguard.h"

#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  /* Suppress warning log */
  fd_log_level_logfile_set( 4 );
  fd_log_level_stderr_set( 4 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  ulong res[ FD_KEYGUARD_SIGN_TYPE_CNT ];
  for( ulong i=0UL; i<FD_KEYGUARD_SIGN_TYPE_CNT; i++ ) {
    res[ i ] = fd_keyguard_payload_match( data, size, (int)i );
  }
  fd_keyguard_authority_t authority = {0};
  for( ulong i=0UL; i<FD_KEYGUARD_SIGN_TYPE_CNT; i++ ) {
    if( !res[ i ] ) continue;
    for( int role=0; role<FD_KEYGUARD_ROLE_CNT; role++ ) {
      (void)fd_keyguard_payload_authorize( &authority, data, size, role, (int)i );
    }
  }
  return 0;
}
