#include "fd_fuzz.h"
#include "../fd_util.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
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

__attribute__((weak))
ulong
LLVMFuzzerMutate( uchar * data,
                  ulong   data_sz,
                  ulong   max_sz ) {
  (void)data; (void)data_sz; (void)max_sz;
  return 0UL;
}

static int
execute( int file ) {
  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( file, &st ) ) ) {
    FD_LOG_ERR(( "fstat(%d) failed (%d-%s)", file, errno, fd_io_strerror( errno ) ));
    return errno;
  }
  if( st.st_mode & S_IFDIR ) return EISDIR;
  if( !( st.st_mode & S_IFREG ) ) return EBADF;

  ulong file_sz = (ulong)st.st_size;

  uchar * buf = malloc( file_sz );
  if( !buf ) {
    FD_LOG_ERR(( "FAIL: Out of memory (failed to malloc %lu bytes)", file_sz ));
  }

  ulong actual_read_sz;
  int read_err = fd_io_read( file, buf, file_sz, file_sz, &actual_read_sz );
  if( FD_UNLIKELY( read_err ) ) {
    FD_LOG_ERR(( "fd_io_read(%d,%lu) failed (%d-%s)", file, file_sz, errno, fd_io_strerror( errno ) ));
    return 1;
  }

  LLVMFuzzerTestOneInput( buf, actual_read_sz );
  free( buf );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  /* fd_boot is typically called by the target, so we don't call it here. */

  if( argc<=1 ) return i_am_a_stub();

  LLVMFuzzerInitialize( &argc, &argv );

  for( int i=1; i<argc; i++ ) {
    if( argv[i][0] == '-' ) continue;

    int file0 = open( argv[i], O_RDONLY );
    if( FD_UNLIKELY( file0<0 ) ) {
      FD_LOG_ERR(( "open(%s) failed (%d-%s)", argv[i], errno, fd_io_strerror( errno ) ));
    }

    int err = execute( file0 );
    if( err==EISDIR ) {

      DIR * dir = fdopendir( file0 );
      if( FD_UNLIKELY( !dir ) ) {
        FD_LOG_ERR(( "fdopendir(%d) failed (%d-%s)", file0, errno, fd_io_strerror( errno ) ));
      }
      for(;;) {
        errno = 0;
        struct dirent * ent = readdir( dir );
        if( !ent ) {
          if( FD_UNLIKELY( errno ) ) {
            FD_LOG_ERR(( "readdir(%d) failed (%d-%s)", file0, errno, fd_io_strerror( errno ) ));
          }
          break;
        }
        int file1 = openat( file0, ent->d_name, O_RDONLY );
        if( FD_UNLIKELY( file1<0 ) ) {
          FD_LOG_ERR(( "openat(%s/%s) failed (%d-%s)", argv[i], ent->d_name, errno, fd_io_strerror( errno ) ));
        }
        if( 0==execute( file1 ) ) {
          fprintf( stderr, "Executed %s/%s\n", argv[i], ent->d_name );
        }
        close( file1 );
      }
      closedir( dir );
      continue;

    } else if( FD_UNLIKELY( err ) ) {

      fprintf( stderr, "Failed to execute %s", argv[i] );

    } else {

      fprintf( stderr, "Executed %s\n", argv[i] );

    }

    close( file0 );
  }

  return 0;
}
