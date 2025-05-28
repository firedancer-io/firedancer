#define _GNU_SOURCE
#include "fd_netdb.h"
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../util/net/fd_ip4.h"

static void
test_gai( char const * host ) {
  static uchar scratch[ 2048 ];

  puts( host );
  fd_addrinfo_t * res;
  void * pscratch = &scratch;
  int eai = fd_getaddrinfo( host, NULL, &res, &pscratch, sizeof(scratch) );
  if( FD_UNLIKELY( eai!=0 ) ) {
    printf( "  FAIL: %i-%s\n", eai, fd_gai_strerror( eai ) );
    return;
  }

  while( res ) {
    struct sockaddr * ai_addr = res->ai_addr;
    switch( ai_addr->sa_family ) {
    case AF_INET: {
      struct sockaddr_in * in4 = fd_type_pun( ai_addr );
      printf( "  " FD_IP4_ADDR_FMT "\n", FD_IP4_ADDR_FMT_ARGS( in4->sin_addr.s_addr ) );
      break;
    }
    case AF_INET6: {
      char str[ 512 ];
      struct sockaddr_in6 * in6 = fd_type_pun( ai_addr );
      printf( "  %s\n", inet_ntop( ai_addr->sa_family, &in6->sin6_addr, str, sizeof(str) ) );
      break;
    }
    }
    res = res->ai_next;
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_netdb_open_fds( NULL );
  for( int i=1; i<argc; i++ ) {
    test_gai( argv[i] );
  }
  return 0;
}
