#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>

#include "fd_grpc_codec.h"

int
LLVMFuzzerInitialize( int *argc,
                      char ***argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void) atexit( fd_halt );
  fd_log_level_core_set( 4 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const *data,
                        ulong        size ) {
  fd_grpc_resp_hdrs_t resp_hdrs;
  resp_hdrs.h2_status = 0U;
  fd_h2_hdr_matcher_t matcher[1];
  FD_TEST( fd_h2_hdr_matcher_init( matcher, 1UL )==matcher );
  int rc = fd_grpc_h2_read_response_hdrs( &resp_hdrs, matcher, data, size );

  /* Accept only the two documented outcomes */
  FD_TEST( (rc==FD_H2_SUCCESS) | (rc==FD_H2_ERR_PROTOCOL) );

  if( rc==FD_H2_SUCCESS ) {
    /* Header fields must be in valid ranges on success */
    FD_TEST( resp_hdrs.grpc_status<=FD_GRPC_STATUS_UNAUTHENTICATED );
    FD_TEST( resp_hdrs.grpc_msg_len<=sizeof(resp_hdrs.grpc_msg));
  }

  return 0;
}
