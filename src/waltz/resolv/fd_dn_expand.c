#include "fd_resolv.h"

int
fd_dn_expand( uchar const * base,
              uchar const * end,
              uchar const * src,
              char *        dest,
              int           space ) {
  uchar const * p = src;
  char * dbegin = dest;
  int len = -1;
  if( p==end || space <= 0 ) return -1;
  char * dend = dest + (space > 254 ? 254 : space);
  /* detect reference loop using an iteration counter */
  for( int i=0; i < end-base; i+=2 ) {
    /* loop invariants: p<end, dest<dend */
    if( *p & 0xc0 ) {
      if( p+1==end ) return -1;
      int j = ((p[0] & 0x3f) << 8) | p[1];
      if( len < 0 ) len = (int)( p+2-src );
      if( j >= end-base ) return -1;
      p = base+j;
    } else if( *p ) {
      if( dest != dbegin ) *dest++ = '.';
      int j = *p++;
      if( j >= end-p || j >= dend-dest ) return -1;
      while( j-- ) *dest++ = (char)( *p++ );
    } else {
      *dest = 0;
      if( len < 0 ) len = (int)( p+1-src );
      return len;
    }
  }
  return -1;
}
