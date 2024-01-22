#include "fd_hex.h"

/* FIXME use LUT instead? */
static inline int
fd_hex_unhex( int c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+0xa;
  if( c>='A' && c<='F' ) return c-'A'+0xa;
  return -1;
}

/* TODO: add AVX version */

ulong
fd_hex_decode( void *       _dst,
               char const * hex,
               ulong        sz ) {

  uchar * dst = _dst;

  ulong i;
  for( i=0; i<sz; i++ ) {
    int hi = fd_hex_unhex( *hex++ );
    int lo = fd_hex_unhex( *hex++ );
    if( FD_UNLIKELY( (hi<0) | (lo<0) ) ) return i;
    *dst++ = (uchar)( ((uint)hi<<4) | (uint)lo );
  }

  return i;
}

