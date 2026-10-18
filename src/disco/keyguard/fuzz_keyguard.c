#include "fd_keyguard.h"
#include "../../waltz/tls/fd_tls.h"

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

  /* The sign tile checks the failover signing domain, so the failov role
     signs only the admission proof or a CertificateVerify. */
  for( ulong i=0UL; i<FD_KEYGUARD_SIGN_TYPE_CNT; i++ ) {
    if( !fd_keyguard_payload_authorize( &authority, data, size, FD_KEYGUARD_ROLE_FAILOV, (int)i ) ) continue;
    int proof = size==FD_KEYGUARD_FAILOVER_PROOF_SZ &&
                ( fd_memeq( data, FD_KEYGUARD_FAILOVER_CLIENT_DOMAIN, FD_KEYGUARD_FAILOVER_DOMAIN_SZ ) ||
                  fd_memeq( data, FD_KEYGUARD_FAILOVER_SERVER_DOMAIN, FD_KEYGUARD_FAILOVER_DOMAIN_SZ ) );
    int cv    = size==FD_TLS_CV_SIGN_SZ &&
                ( fd_memeq( data, fd_tls13_cli_sign_prefix, sizeof(fd_tls13_cli_sign_prefix) ) ||
                  fd_memeq( data, fd_tls13_srv_sign_prefix, sizeof(fd_tls13_srv_sign_prefix) ) );
    FD_TEST( i==FD_KEYGUARD_SIGN_TYPE_ED25519 && ( proof || cv ) );
  }
  return 0;
}
