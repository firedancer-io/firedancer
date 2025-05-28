#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "fd_netdb.h"
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <endian.h>
#include "fd_lookup.h"
#include "../../util/io/fd_io.h"

int
fd_getaddrinfo( char const * restrict          host,
                fd_addrinfo_t const * restrict hint,
                fd_addrinfo_t ** restrict      res,
                void **                        pout,
                ulong                          out_max ) {
  int family = AF_UNSPEC;
  int flags = 0;

  if( !host ) return FD_EAI_NONAME;

  if( hint ) {
    family = hint->ai_family;
    flags = hint->ai_flags;

    int const mask = FD_AI_PASSIVE | FD_AI_NUMERICHOST | FD_AI_V4MAPPED | FD_AI_ALL;
    if( (flags & mask)!=flags )
      return FD_EAI_BADFLAGS;

    switch( family ) {
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      break;
    default:
      return FD_EAI_FAMILY;
    }
  }

  struct address addrs[ MAXADDRS ];
  char canon[ 256 ];
  int const naddrs = fd_lookup_name( addrs, canon, host, family, flags );
  if( naddrs < 0 ) return naddrs;

  int const nais = naddrs;
  int const canon_len = (int)strlen( canon );

  ulong alloc_sz = (ulong)nais * sizeof(struct aibuf) + (ulong)canon_len + 1;
  if( FD_UNLIKELY( !pout ) ) return FD_EAI_MEMORY;
  if( FD_UNLIKELY( out_max<alloc_sz ) ) return FD_EAI_MEMORY;
  struct aibuf * out = *pout;
  *pout = (void *)( (ulong)out + alloc_sz );

  char * outcanon;
  if( canon_len ) {
    outcanon = (void *)&out[nais];
    memcpy( outcanon, canon, (ulong)canon_len+1 );
  } else {
    outcanon = 0;
  }

  int i, k;
  for( k=i=0; i<naddrs; i++ ) for ( int j=0; j<1; j++, k++ ) {
    out[k].slot = (short)k;
    out[k].ai = (fd_addrinfo_t) {
      .ai_family = addrs[i].family,
      .ai_addrlen = addrs[i].family == AF_INET
        ? sizeof(struct sockaddr_in)
        : sizeof(struct sockaddr_in6),
      .ai_addr = (void *)&out[k].sa,
      .ai_canonname = outcanon
    };
    if( k ) out[k-1].ai.ai_next = &out[k].ai;
    switch( addrs[i].family ) {
    case AF_INET:
      out[k].sa.sin.sin_family = AF_INET;
      memcpy( &out[k].sa.sin.sin_addr, &addrs[i].addr, 4 );
      break;
    case AF_INET6:
      out[k].sa.sin6.sin6_family = AF_INET6;
      out[k].sa.sin6.sin6_scope_id = addrs[i].scopeid;
      memcpy( &out[k].sa.sin6.sin6_addr, &addrs[i].addr, 16 );
      break;
    }
  }
  out[0].ref = (short)nais;
  *res = &out->ai;
  return 0;
}

char const *
fd_gai_strerror( int gai ) {
  if( gai<=FD_EAI_SYSTEM ) {
    int err = gai-FD_EAI_SYSTEM;
    return fd_io_strerror( err );
  }
  switch( gai ) {
  case FD_EAI_BADFLAGS:  return "bad flags";
  case FD_EAI_NONAME:    return "not found";
  case FD_EAI_AGAIN:     return "temporary failure";
  case FD_EAI_FAIL:      return "permanent failure";
  case FD_EAI_NODATA:    return "no data";
  case FD_EAI_FAMILY:    return "unsupported address family";
  case FD_EAI_MEMORY:    return "out of memory";
  default:               return "unknown error";
  }
}
