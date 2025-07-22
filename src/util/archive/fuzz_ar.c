#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_ar.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set( 4 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  FILE * file = fmemopen( (void *)data, size, "r" );
  FD_TEST( file );

  fd_ar_read_init( file );

  fd_ar_meta_t meta[1];
  for( int i=0; i<8; i++ ) {
    fd_ar_read_next( file, meta );
  }

  FD_TEST( !fclose( file ) );
  return 0;
}
