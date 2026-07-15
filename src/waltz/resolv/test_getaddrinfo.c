#define _GNU_SOURCE
#include "fd_netdb.h"
#include "fd_adns.h"
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../util/net/fd_ip4.h"
#include "../../util/log/fd_log.h"

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

static void
test_adns( char const * const * names,
           ulong                name_cnt ) {
  static uchar shmem[ 1<<20 ] __attribute__((aligned(64)));
  FD_TEST( fd_adns_footprint( name_cnt )<=sizeof(shmem) );
  fd_adns_t * adns = fd_adns_join( fd_adns_new( shmem, name_cnt ) );
  FD_TEST( adns );

  for( ulong i=0UL; i<name_cnt; i++ ) FD_TEST( !fd_adns_resolve( adns, names[ i ], i ) );

  ulong done = 0UL;
  long  deadline = fd_log_wallclock()+15L*1000L*1000L*1000L;
  while( done<name_cnt ) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now>deadline ) ) break;
    fd_adns_result_t res[ 1 ];
    while( fd_adns_advance( adns, now, res ) ) {
      printf( "%s\n", names[ res->req_id ] );
      if( FD_UNLIKELY( res->err ) ) printf( "  FAIL: %i-%s\n", res->err, fd_gai_strerror( res->err ) );
      for( ulong j=0UL; j<res->addr_cnt; j++ )
        printf( "  " FD_IP4_ADDR_FMT "\n", FD_IP4_ADDR_FMT_ARGS( res->addrs[ j ] ) );
      done++;
    }
  }
  printf( "adns: %lu/%lu completed\n", done, name_cnt );
}

int
main( int     argc,
      char ** argv ) {
  fd_netdb_open_fds( NULL );
  if( argc>1 && 0==strcmp( argv[1], "--adns" ) ) {
    test_adns( (char const * const *)&argv[2], (ulong)( argc-2 ) );
    return 0;
  }
  for( int i=1; i<argc; i++ ) {
    test_gai( argv[i] );
  }
  return 0;
}
