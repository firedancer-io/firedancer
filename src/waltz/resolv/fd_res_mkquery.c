#include "fd_resolv.h"
#include "../../util/log/fd_log.h" /* fd_tickcount() support */
#include <string.h>

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wsign-conversion"

int
fd_res_mkquery( int           op,
                char const *  dname,
                int           class,
                int           type,
                uchar *       buf,
                int           buflen ) {
  size_t l = strnlen( dname, 255 );

  if( l && dname[l-1]=='.' ) l--;
  if( l && dname[l-1]=='.' ) return -1;
  int n = 17+l+!!l;
  if( l>253 || buflen<n || op>15u || class>255u || type>255u )
    return -1;

  /* Construct query template - ID will be filled later */
  uchar q[280];
  memset( q, 0, n );
  q[2] = op*8 + 1;
  q[3] = 32; /* AD */
  q[5] = 1;
  memcpy( (char *)q+13, dname, l );
  int i, j;
  for( i=13; q[i]; i=j+1 ) {
    for( j=i; q[j] && q[j] != '.'; j++ );
    if( j-i-1u > 62u ) return -1;
    q[i-1] = j-i;
  }
  q[i+1] = type;
  q[i+3] = class;

  /* Make a reasonably unpredictable id */
  ulong ts = fd_ulong_hash( (ulong)fd_tickcount() );
  q[0] = (uchar)( ts    );
  q[1] = (uchar)( ts>>8 );

  memcpy( buf, q, n );
  return n;
}
