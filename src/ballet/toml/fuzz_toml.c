#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_toml.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  fd_log_level_logfile_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data_,
                        ulong         size ) {
  char const * data = (char const *)data_;
  uchar scratch[128];
  uchar pod_data[256];
  uchar * pod = fd_pod_join( fd_pod_new( pod_data, sizeof(pod_data) ) );
  fd_toml_parse( data, size, pod, scratch, sizeof(scratch) );
  fd_pod_delete( fd_pod_leave( pod ) );
  return 0;
}
