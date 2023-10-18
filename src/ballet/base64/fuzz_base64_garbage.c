#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_base64.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

#define get_encoded_len(bytes) ( ( ( ( bytes*4UL + 2UL) / 3UL ) + 3UL ) & ~3UL )
#define MAX_DATA_SZ 4096UL
#define MAX_ENCODED_SZ ( get_encoded_len( MAX_DATA_SZ )+1UL )

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size > MAX_ENCODED_SZ ) ) return -1;

  uchar decoded[ MAX_DATA_SZ ];
  int decoded_sz = fd_base64_decode( ( const char * ) data, decoded );
  if( FD_UNLIKELY( decoded_sz>=0 ) ) {
    __builtin_trap();
  }

  return 0;
}
