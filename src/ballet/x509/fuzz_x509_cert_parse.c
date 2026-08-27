#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_x509.h"

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
  fd_x509_cert_info_t info;
  int parse_result = fd_x509_cert_parse( data, data_sz, &info );
  FD_COMPILER_UNPREDICTABLE( parse_result );
  FD_COMPILER_MFENCE();
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
