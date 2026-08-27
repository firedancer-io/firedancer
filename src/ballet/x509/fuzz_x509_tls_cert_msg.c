#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_x509_verify.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  static fd_x509_ca_store_t empty_ca_store;
  int verify_result = fd_x509_verify_tls_cert_msg(
      data, data_sz,
      &empty_ca_store,
      NULL, 0UL, 1577836800L );
  FD_COMPILER_UNPREDICTABLE( verify_result );
  FD_COMPILER_MFENCE();
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
