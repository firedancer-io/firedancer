#include "fd_dns_resolve.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Manual test (needs network + resolv.conf):
     test_dns_resolve host:port [host:port ...] */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong peer_cnt = fd_ulong_min( (ulong)( argc-1 ), FD_DNS_RESOLVE_PEERS_MAX );
  static char peers[ FD_DNS_RESOLVE_PEERS_MAX ][ 262UL ];
  for( ulong i=0UL; i<peer_cnt; i++ ) fd_cstr_ncpy( peers[ i ], argv[ 1+i ], sizeof(peers[ i ]) );

  fd_ip4_port_t out[ FD_DNS_RESOLVE_PEERS_MAX ];
  long t0 = fd_log_wallclock();
  fd_dns_resolve_peers( peers[ 0 ], sizeof(peers[ 0 ]), peer_cnt, "gossip.entrypoints", out );
  long t1 = fd_log_wallclock();

  for( ulong i=0UL; i<peer_cnt; i++ )
    printf( "%s -> " FD_IP4_ADDR_FMT ":%hu\n", peers[ i ], FD_IP4_ADDR_FMT_ARGS( out[ i ].addr ), fd_ushort_bswap( out[ i ].port ) );
  printf( "elapsed %.1f ms\n", (double)( t1-t0 )/1e6 );

  /* No stray fds may survive (callers enter a sandbox next) */
  ulong fd_cnt = 0UL;
  for( int fd=3; fd<1024; fd++ ) {
    char path[ 64 ], target[ 256 ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/self/fd/%d", fd ) );
    long sz = readlink( path, target, sizeof(target)-1UL );
    if( FD_LIKELY( sz<0L ) ) continue;
    target[ sz ] = '\0';
    if( FD_UNLIKELY( strstr( target, "/fd/" ) ) ) continue; /* readlink dirfd itself */
    if( FD_UNLIKELY( !strncmp( target, "/tmp/fd-", 8UL ) ) ) continue; /* logfile */
    FD_LOG_WARNING(( "stray fd %d -> %s", fd, target ));
    fd_cnt++;
  }
  FD_TEST( !fd_cnt );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
