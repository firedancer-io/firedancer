#define _GNU_SOURCE
#include "fd_dns_resolve.h"
#include "../shred/fd_shred_dest_resolver.h"
#include "../../waltz/resolv/fd_lookup.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <dirent.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* With no arguments, exercises the maximum peer count and a mixed
   literal/hostname shred destination list.  Manual DNS test:
     test_dns_resolve host:port [host:port ...] */

/* Bound the number of open fds, not the descriptor numbers. */
#define TEST_FD_CNT_MAX (1024UL)

static ulong
snapshot_fds( int fds[ static TEST_FD_CNT_MAX ] ) {
  DIR * dir = opendir( "/proc/self/fd" );
  FD_TEST( dir );
  int snapshot_fd = dirfd( dir );
  FD_TEST( snapshot_fd>=0 );
  ulong fd_cnt = 0UL;
  for(;;) {
    errno = 0;
    struct dirent * entry = readdir( dir );
    if( !entry ) {
      FD_TEST( !errno );
      break;
    }
    if( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) continue;
    char * end;
    long fd = strtol( entry->d_name, &end, 10 );
    FD_TEST( end!=entry->d_name && !*end && fd>=0L && fd<INT_MAX );
    if( fd==snapshot_fd ) continue;
    FD_TEST( fd_cnt<TEST_FD_CNT_MAX );
    fds[ fd_cnt++ ] = (int)fd;
  }
  FD_TEST( !closedir( dir ) );
  return fd_cnt;
}

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

  /* The test launcher may leave pipes open.  Preserve its descriptors
     and fd_boot's logfile while checking resolver-owned fd cleanup. */
  int initial_fds[ TEST_FD_CNT_MAX ];
  ulong initial_fd_cnt = snapshot_fds( initial_fds );

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

  /* No resolver-owned fds may survive (callers enter a sandbox next). */
  int final_fds[ TEST_FD_CNT_MAX ];
  ulong final_fd_cnt = snapshot_fds( final_fds );
  ulong stray_fd_cnt = 0UL;
  for( ulong i=0UL; i<final_fd_cnt; i++ ) {
    int fd = final_fds[ i ];
    int found = 0;
    for( ulong j=0UL; j<initial_fd_cnt; j++ ) found |= fd==initial_fds[ j ];
    if( found ) continue;
    char path[ 64 ], target[ 256 ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/self/fd/%d", fd ) );
    long sz = readlink( path, target, sizeof(target)-1UL );
    FD_TEST( sz>=0L );
    target[ sz ] = '\0';
    FD_LOG_WARNING(( "stray fd %d -> %s", fd, target ));
    stray_fd_cnt++;
  }
  FD_TEST( !stray_fd_cnt && final_fd_cnt==initial_fd_cnt );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
