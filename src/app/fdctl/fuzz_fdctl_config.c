#include "config_parse.h"
#include "../../ballet/toml/fd_toml.h"
#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"

#include <assert.h>
#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_logfile_set( 4 );
  fd_log_level_stderr_set( 4 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  static uchar pod_mem[ 1UL<<16 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  static uchar scratch[ 4096 ];
  (void)fd_toml_parse( data, size, pod, scratch, sizeof(scratch) );

  static config_t config = {0};
  fdctl_pod_to_cfg( &config, pod );
  return 0;
}
