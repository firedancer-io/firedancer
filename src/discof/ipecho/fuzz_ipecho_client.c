#include "fd_ipecho_client_private.h"
#include "../../util/fd_util.h"

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <assert.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  ushort shred_version;
  fd_ipecho_client_parse_response( data, size, &shred_version );
  return 0;
}
