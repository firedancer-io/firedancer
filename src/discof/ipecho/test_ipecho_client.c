#include "fd_ipecho_client.h"

#include "../../util/net/fd_net_headers.h"
#include "../../util/fd_util.h"

#include <stdlib.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  void * _client = aligned_alloc( FD_IPECHO_CLIENT_ALIGN, fd_ipecho_client_footprint() );
  FD_TEST( _client );
  fd_ipecho_client_t * client = fd_ipecho_client_join( fd_ipecho_client_new( _client ) );
  FD_TEST( client );

  fd_ip4_port_t localhost = (fd_ip4_port_t){ .addr = FD_IP4_ADDR(127,0,0,1), .port = fd_ushort_bswap( 12008 ) };
  fd_ipecho_client_init( client, &localhost, 1UL );
  // fd_ip4_port_t anza1 = { .addr = FD_IP4_ADDR(35,203,170,30), .port = fd_ushort_bswap( 8001 ) };
  // fd_ipecho_client_init( client, &anza1, 1UL );

  for(;;) {
    ushort shred_version = 0;
    int _charge_busy;
    int err = fd_ipecho_client_poll( client, &shred_version, &_charge_busy );
    if( FD_UNLIKELY( -1==err ) ) FD_LOG_ERR(( "couldn't get shred version" ));
    if( FD_UNLIKELY( !err) ) {
      // FD_TEST( shred_version==32 );
      FD_LOG_NOTICE(( "passed shred version is %hu", shred_version ));
      break;
    }
  }
}
