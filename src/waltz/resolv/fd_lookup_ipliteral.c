#define _GNU_SOURCE /* inet_aton */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../../util/cstr/fd_cstr.h"
#include "fd_lookup.h"

int
fd_lookup_ipliteral( struct address buf[ static 1 ],
                     char const *   name,
                     int            family ) {
  struct in_addr a4;
  struct in6_addr a6;
  if( inet_aton( name, &a4 ) > 0 ) {
    if( family == AF_INET6 ) /* wrong family */
      return FD_EAI_NODATA;
    memcpy( &buf[0].addr, &a4, sizeof(a4) );
    buf[0].family = AF_INET;
    buf[0].scopeid = 0;
    return 1;
  }

  char tmp[64];
  char *p = strchr( name, '%' ), *z;
  ulong scopeid = 0;
  if( p && p-name < 64 ) {
    memcpy( tmp, name, (ulong)( p-name ) );
    tmp[p-name] = 0;
    name = tmp;
  }

  if( inet_pton( AF_INET6, name, &a6 ) <= 0 )
    return 0;
  if( family == AF_INET ) /* wrong family */
    return FD_EAI_NODATA;

  memcpy( &buf[0].addr, &a6, sizeof a6 );
  buf[0].family = AF_INET6;
  if( p ) {
    if( fd_isdigit( *++p ) ) scopeid = strtoul( p, &z, 10 );
    else z = p-1;
    if( *z ) {
      if( !IN6_IS_ADDR_LINKLOCAL(&a6) &&
          !IN6_IS_ADDR_MC_LINKLOCAL(&a6) )
        return FD_EAI_NONAME;
      scopeid = if_nametoindex( p );
      if( !scopeid ) return FD_EAI_NONAME;
    }
    if( scopeid > UINT_MAX ) return FD_EAI_NONAME;
  }
  buf[0].scopeid = (uint)scopeid;
  return 1;
}
