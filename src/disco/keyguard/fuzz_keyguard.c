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

static int
role_from_payload( int payload_lg_type ) {
  switch( payload_lg_type ) {
  case FD_KEYGUARD_PAYLOAD_LG_TXN:
    return FD_KEYGUARD_ROLE_TXSEND;
  case FD_KEYGUARD_PAYLOAD_LG_TLS_CV:
    return FD_KEYGUARD_ROLE_VOTOR;
  case FD_KEYGUARD_PAYLOAD_LG_GOSSIP:
  case FD_KEYGUARD_PAYLOAD_LG_PRUNE:
  case FD_KEYGUARD_PAYLOAD_LG_PING:
  case FD_KEYGUARD_PAYLOAD_LG_PONG:
    return FD_KEYGUARD_ROLE_GOSSIP;
  case FD_KEYGUARD_PAYLOAD_LG_REPAIR:
    return FD_KEYGUARD_ROLE_REPAIR;
  case FD_KEYGUARD_PAYLOAD_LG_SHRED:
    return FD_KEYGUARD_ROLE_LEADER;
  case FD_KEYGUARD_PAYLOAD_LG_BUNDLE:
    return FD_KEYGUARD_ROLE_BUNDLE;
  case FD_KEYGUARD_PAYLOAD_LG_EVENT:
    return FD_KEYGUARD_ROLE_EVENT;
  default:
    return -1;
  }
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
    ulong r = res[ i ];
    while( r ) {
      int bit = fd_ulong_find_lsb( r );
      r &= ~(1UL<<bit);
      int role = role_from_payload( bit );
      if( role==-1 ) continue;
      (void)fd_keyguard_payload_authorize( &authority, data, size, role, (int)i );
      if( bit==FD_KEYGUARD_PAYLOAD_LG_TXN ) {
        (void)fd_keyguard_payload_authorize( &authority, data, size, FD_KEYGUARD_ROLE_BUNDLE_CRANK, (int)i );
      }
    }
  }
  return 0;
}
