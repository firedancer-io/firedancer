#include <stddef.h>
#include <stdlib.h>

#include "../../../util/fd_util.h"
#include "../fd_quic_common.h"
#include "../fd_quic_config.h"
#include "fd_quic_transport_params.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fd_quic_transport_params_t out;
  fd_quic_decode_transport_params( &out, data, size );
  return 0;
}
