#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_hex.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

/* checks if given encoding of sz chars is valid, sz must be even
   returns sz on success, index of first invalid char on failure */
static inline ulong
check_hex_encoding( char const * enc, ulong sz  ) {
  ulong i;
  for( i=0; i<sz; i++ ) {
    char c = enc[i];
    if( c>='0' && c<='9' ) continue;
    if( c>='a' && c<='f' ) continue;
    if( c>='A' && c<='F' ) continue;
    return i;
  }
  return sz;
}

#define MAX_DATA_SZ 4096UL
#define MAX_DECODED_SZ ( MAX_DATA_SZ / 2UL )

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size > MAX_DATA_SZ ) ) return -1;
  char const * encoded = ( char  const * ) data;

  size = size & ~1UL; /* ignore last char of encoding if size is odd */

  uchar decoded[ MAX_DECODED_SZ ];
  ulong decoded_sz = fd_hex_decode( decoded, encoded, size/2UL );

  if( FD_UNLIKELY( decoded_sz!=( check_hex_encoding( encoded, size )/2UL ) ) ) {
    __builtin_trap();
  }

  return 0;
}
