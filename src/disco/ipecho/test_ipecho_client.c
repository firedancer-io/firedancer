#include "fd_ipecho_client.h"

#include "../../util/net/fd_net_headers.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  void * _client = aligned_alloc( FD_IPECHO_CLIENT_ALIGN, fd_ipecho_client_footprint() );
  FD_TEST( _client );
  fd_ipecho_client_t * client = fd_ipecho_client_join( fd_ipecho_client_new( _client ) );
  FD_TEST( client );

  fd_ip4_port_t localhost = (fd_ip4_port_t){ .addr = FD_IP4_ADDR(127,0,0,1), .port = fd_ushort_bswap( 12008 ) };
  int epoll_fd = epoll_create1( 0 );
  if( FD_UNLIKELY( -1==epoll_fd ) ) FD_LOG_ERR(( "epoll_create1 failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_ipecho_client_init( client, &localhost, 1UL, epoll_fd );
  // fd_ip4_port_t anza1 = { .addr = FD_IP4_ADDR(35,203,170,30), .port = fd_ushort_bswap( 8001 ) };
  // fd_ipecho_client_init( client, &anza1, 1UL, epoll_fd );

  for(;;) {
    ushort shred_version = 0;
    int _charge_busy;
    int err = fd_ipecho_client_poll( client, fd_log_wallclock(), &shred_version, &_charge_busy );
    if( FD_UNLIKELY( -1==err ) ) FD_LOG_ERR(( "couldn't get shred version" ));
    if( FD_UNLIKELY( !err) ) {
      // FD_TEST( shred_version==32 );
      FD_LOG_NOTICE(( "passed shred version is %hu", shred_version ));
      break;
    }
    struct epoll_event ev;
    if( FD_UNLIKELY( -1==epoll_wait( epoll_fd, &ev, 1, 100 ) && errno!=EINTR ) ) FD_LOG_ERR(( "epoll_wait failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}
