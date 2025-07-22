#include "fd_util.h"

#include <stdlib.h>
#include <stdint.h>

int
LLVMFuzzerInitialize( int *argc,
                      char ***argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void) atexit( fd_halt );
  fd_log_level_core_set( 1 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const *data,
                        ulong        size ) {
  ulong metadata_size = sizeof(ulong);
  if ( size < metadata_size ) {
    return 0;
  }

  ulong seed = FD_LOAD( ulong, data );
  size -= metadata_size;
  uchar *content = (uchar*)data + metadata_size;
  uchar *dst = malloc( size );
  if ( dst == NULL ) {
    return 0;
  }

  fd_hash_memcpy( seed, dst, content, size );
  fd_hash( seed, content, size );
  free( dst );

  return 0;
}
