#define _GNU_SOURCE
#include "fd_dns_resolve.h"
#include "../shred/fd_shred_dest_resolver.h"
#include "../../waltz/resolv/fd_lookup.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* With no arguments, exercises the maximum peer count and a mixed
   literal/hostname shred destination list.  Manual DNS test:
     test_dns_resolve host:port [host:port ...] */

static int
memfd_with( char const * data ) {
  int fd = memfd_create( "test_dns_resolve", 0 );
  FD_TEST( fd>=0 );
  ulong data_sz = strlen( data );
  ulong write_sz;
  FD_TEST( !fd_io_write( fd, data, data_sz, data_sz, &write_sz ) && write_sz==data_sz );
  return fd;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  (void)fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, 0UL );
  (void)fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 0UL );
  (void)fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, NULL );

  if( argc==1 ) {
    fd_etc_resolv_conf_fd = memfd_with( "nameserver 127.0.0.1\n" );
    fd_etc_hosts_fd       = memfd_with( "198.51.100.2 shred-a\n198.51.100.4 shred-b\n" );

    static char endpoints[ FD_DNS_RESOLVE_PEERS_MAX ][ FD_HOSTPORT_BUF_MAX ];
    for( ulong i=0UL; i<FD_DNS_RESOLVE_PEERS_MAX; i++ ) {
      char const * host = i==16UL ? "010.0.0.1" : (i&1UL ? "shred-a" : "shred-b");
      FD_TEST( fd_cstr_printf_check( endpoints[ i ], sizeof(endpoints[ i ]), NULL, "%s:%lu", host, 10000UL+i ) );
    }

    fd_shred_dest_weighted_t dests[ FD_DNS_RESOLVE_PEERS_MAX ] = {0};
    fd_shred_resolve_additional_destinations( (char const (*)[ FD_HOSTPORT_BUF_MAX ])endpoints,
                                              FD_DNS_RESOLVE_PEERS_MAX, "test.shred_destinations", dests );
    for( ulong i=0UL; i<FD_DNS_RESOLVE_PEERS_MAX; i++ ) {
      uint expected_ip = i==16UL ? FD_IP4_ADDR( 10, 0, 0, 1 ) : (i&1UL ? FD_IP4_ADDR( 198, 51, 100, 2 ) : FD_IP4_ADDR( 198, 51, 100, 4 ));
      FD_TEST( dests[ i ].ip4==expected_ip && dests[ i ].port==(ushort)(10000UL+i) );
    }
    fd_netdb_close_fds();
  } else {
    ulong peer_cnt = fd_ulong_min( (ulong)( argc-1 ), FD_DNS_RESOLVE_PEERS_MAX );
    static char peers[ FD_DNS_RESOLVE_PEERS_MAX ][ FD_HOSTPORT_BUF_MAX ];
    for( ulong i=0UL; i<peer_cnt; i++ ) fd_cstr_ncpy( peers[ i ], argv[ 1+i ], sizeof(peers[ i ]) );

    fd_ip4_port_t out[ FD_DNS_RESOLVE_PEERS_MAX ];
    long t0 = fd_log_wallclock();
    fd_dns_resolve_peers( peers[ 0 ], sizeof(peers[ 0 ]), peer_cnt, "gossip.entrypoints", out );
    long t1 = fd_log_wallclock();
    for( ulong i=0UL; i<peer_cnt; i++ )
      printf( "%s -> " FD_IP4_ADDR_FMT ":%hu\n", peers[ i ], FD_IP4_ADDR_FMT_ARGS( out[ i ].addr ), fd_ushort_bswap( out[ i ].port ) );
    printf( "elapsed %.1f ms\n", (double)( t1-t0 )/1e6 );
  }

  /* No stray fds may survive (callers enter a sandbox next) */
  ulong fd_cnt = 0UL;
  for( int fd=3; fd<1024; fd++ ) {
    char path[ 64 ], target[ 256 ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/self/fd/%d", fd ) );
    long sz = readlink( path, target, sizeof(target)-1UL );
    if( FD_LIKELY( sz<0L ) ) continue;
    target[ sz ] = '\0';
    if( fd==fd_log_private_logfile_fd() ) continue;
    FD_LOG_WARNING(( "stray fd %d -> %s", fd, target ));
    fd_cnt++;
  }
  FD_TEST( !fd_cnt );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
