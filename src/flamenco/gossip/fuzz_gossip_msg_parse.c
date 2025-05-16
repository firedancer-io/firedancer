#include "fd_gossip_private.h"
#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  fd_log_level_stderr_set(4);
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size>=1232UL ) ) return -1;

  fd_gossip_view_t view[1];
  fd_gossip_msg_parse( view, data, size );

  return 0;
}
