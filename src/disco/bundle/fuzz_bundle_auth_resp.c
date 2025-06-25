#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "fd_bundle_auth.h"

#include <stdlib.h>

/* At least one byte is required for an operation selector */
#define MIN_INPUT_SIZE (1)

int LLVMFuzzerInitialize( int *argc, char ***argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );

  fd_boot( argc, argv );

  atexit( fd_halt );

  fd_log_level_core_set( 4 );
  fd_log_level_stderr_set( 4 );
  fd_log_level_logfile_set( 4 );

  return 0;
}

int LLVMFuzzerTestOneInput( const uchar *data, ulong size ) {
  if( size < MIN_INPUT_SIZE ) {
    return 0;
  }

  uchar const op = data[ 0 ] & 0x3U;
  uchar const *payload = data+1;
  ulong payload_sz = size-1UL;

  fd_bundle_auther_t auther = {0};
  fd_bundle_auther_t *pAuther = fd_bundle_auther_init( &auther );

  int rc = 0;

  switch ( op ) {
    case 0:
      fd_bundle_auther_handle_request_fail( pAuther );
      break;
    case 1:
      rc = fd_bundle_auther_handle_challenge_resp( pAuther, payload, payload_sz );
      if( rc ) {
        FD_TEST( pAuther->state==FD_BUNDLE_AUTH_STATE_REQ_TOKENS );
      } else {
        FD_TEST( pAuther->state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
      }
      break;
    case 2:
      rc = fd_bundle_auther_handle_tokens_resp( pAuther, payload, payload_sz );
      if( rc ) {
        FD_TEST( pAuther->state==FD_BUNDLE_AUTH_STATE_DONE_WAIT );
      } else {
        FD_TEST( pAuther->state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
      }
      break;
    case 3:
      pAuther->state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
      fd_bundle_auther_reset( pAuther );
      FD_TEST( pAuther->state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
      break;
  }

  FD_TEST( pAuther->state<=FD_BUNDLE_AUTH_STATE_DONE_WAIT );
  FD_TEST( pAuther->needs_poll<=1 );
  FD_TEST( pAuther->access_token_sz<=sizeof(pAuther->access_token) );

  (void) rc; /* suppress unused-var warning when assertions are off */

  return 0;
}
