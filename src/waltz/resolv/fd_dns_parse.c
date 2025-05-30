#include "fd_lookup.h"

int
fd_dns_parse(
    uchar const * r,
    int           rlen,
    int (* callback)(
        void *,
        int,
        void const *,
        int,
        void const *,
        int
    ),
    void * ctx
) {
  int qdcount, ancount;
  int len;

  if( rlen<12   ) return -1;
  if( (r[3]&15) ) return 0;
  uchar const * p = r+12;
  qdcount = r[4]*256 + r[5];
  ancount = r[6]*256 + r[7];
  while( qdcount-- ) {
    while( p-r < rlen && *p-1U < 127 ) p++;
    if( p>r+rlen-6 )
      return -1;
    p += 5 + !!*p;
  }
  while( ancount-- ) {
    while( p-r < rlen && *p-1U < 127 ) p++;
    if( p>r+rlen-12 )
      return -1;
    p += 1 + !!*p;
    len = p[8]*256 + p[9];
    if( len+10 > r+rlen-p ) return -1;
    if( callback( ctx, p[1], p+10, len, r, rlen ) < 0 ) return -1;
    p += 10 + len;
  }
  return 0;
}
