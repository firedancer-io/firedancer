#include "fd_ip4.h"
#include "../fd_util.h"

int
fd_cstr_to_ip4_addr( char const * s,
                     uint *       out ) {

  char _s[ 16 ];
  strncpy( _s, s, 15 );
  _s[ 15 ] = '\0';

  char *tok[ 4 ];
  if( FD_UNLIKELY( fd_cstr_tokenize( tok, 4UL, _s, '.' )!=4UL ) )
    return 0;

  uchar x[ 4 ];
  x[ 0 ] = fd_cstr_to_uchar( tok[ 0 ] );
  x[ 1 ] = fd_cstr_to_uchar( tok[ 1 ] );
  x[ 2 ] = fd_cstr_to_uchar( tok[ 2 ] );
  x[ 3 ] = fd_cstr_to_uchar( tok[ 3 ] );

  *out = ( x[3] | (x[2]<<8) | (x[1]<<16) | (x[0]<<24) );
  return 1;
}
