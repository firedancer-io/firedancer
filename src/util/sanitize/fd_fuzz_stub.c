#include "fd_fuzz.h"
#include "../fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* fd_fuzz_stub.c is a stub fuzz harness for build targets without an
   actual fuzz engine.  This harness mocks the libFuzzer command-line
   and can regression test against existing input files.  It cannot,
   however, do any actual fuzz exploration. */

static int
i_am_a_stub( void ) {
  fputs( "FAIL: No fuzz engine.\n"
         "\n"
         "This fuzz target was compiled without a fuzz engine.\n"
         "You can still re-run individual test cases like so:\n"
         "  <prog> path/to/file1 path/to/file2 ...\n"
         "\n"
         "Hint: Compile with CC=clang EXTRAS=fuzz to build with the libFuzzer engine.\n",
         stderr );
  return 1;
}

extern int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv );

extern int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz );

int
main( int     argc,
      char ** argv ) {
  /* fd_boot is typically called by the target, so we don't call it here. */

  if( argc<=1 ) return i_am_a_stub();

  LLVMFuzzerInitialize( &argc, &argv );

  for( int i=1; i<argc; i++ ) {
    if( argv[i][0] == '-' ) continue;

    fprintf( stderr, "Running: %s\n", argv[i] );

    int file = open( argv[i], O_RDONLY );
    if( FD_UNLIKELY( file<0 ) ) {
      FD_LOG_ERR(( "open(%s) failed (%d-%s)", argv[i], errno, fd_io_strerror( errno ) ));
      return 1;
    }

    struct stat st;
    if( FD_UNLIKELY( 0!=fstat( file, &st ) ) ) {
      FD_LOG_ERR(( "fstat(%d) failed (%d-%s)", file, errno, fd_io_strerror( errno ) ));
      return 1;
    }

    if( st.st_mode == S_IFDIR )
      return i_am_a_stub();
    ulong file_sz = (ulong)st.st_size;

    uchar * buf = malloc( file_sz );
    if( !buf )
      FD_LOG_ERR(( "FAIL: Out of memory (failed to malloc %lu bytes)", file_sz ));

    ulong actual_read_sz;
    int read_err = fd_io_read( file, buf, file_sz, file_sz, &actual_read_sz );
    close( file );
    if( FD_UNLIKELY( read_err ) ) {
      free( buf );
      FD_LOG_ERR(( "fd_io_read(%d,%lu) failed (%d-%s)", file, file_sz, errno, fd_io_strerror( errno ) ));
      return 1;
    }

    LLVMFuzzerTestOneInput( buf, actual_read_sz );
    fprintf( stderr, "Executed %s\n", argv[i] );

    free( buf );
  }

  return 0;
}
