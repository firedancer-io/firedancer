#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../fd_util.h"
#include "fd_csv.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  FILE * file;
  if( FD_UNLIKELY( size==0UL ) )
    file = fopen( "/dev/null", "rb" );
  else
    file = fmemopen( (void *)data, size, "rb" );
  if( FD_UNLIKELY( !file ) )
    FD_LOG_ERR(( "fmemopen() failed: %s", strerror( errno ) ));

# define COLS (3UL)
  char * cols[ COLS ];

  int err = fd_csv_read_record( cols, COLS, ',', '"', file );
  if( FD_UNLIKELY( err==0 ) ) {
    /* strlen() on cols should not read OOB */
    for( ulong i=0UL; i<COLS; i++ ) {
      ulong col_len = strlen( cols[i] );
      __asm__ volatile("" : : "g"(col_len) : "memory");
    }
  }

# undef COLS

  FD_TEST( 0==fclose( file ) );
  return 0;
}
