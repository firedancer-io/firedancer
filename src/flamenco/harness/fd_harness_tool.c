#include "fd_harness.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <secp256k1.h>


int
main( int argc, char ** argv ) {
  (void)argc;
  (void)argv;

  FD_LOG_WARNING(("HELLO"));

  char path[312] = "/data/ibhatt/instr-3M6ubN9DGkdiXsEavgLCjYQUmY5ee1adTByiQteeSbDxJL9nUuUqJWMiUwiL59oCJ6uSz1Fr6SQSsJUSK4fc3MKh-00.pb.bin";

  int file = open( path, O_RDONLY );
  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( file, &st ) ) ) {
    FD_LOG_WARNING(( "fstat(%s): %s", path, fd_io_strerror( errno ) ));
    return 0;
  }
  ulong file_sz = (ulong)st.st_size;
  uchar * buf = malloc( file_sz );
  FD_TEST( 0==fd_io_read( file, buf, file_sz, file_sz, &file_sz ) );
  FD_TEST( 0==close( file ) );


  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  fd_harness_exec_instr( buf, file_sz );

  return 0;

}
