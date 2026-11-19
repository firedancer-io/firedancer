#include "fd_net_tile.h"
#include "../topo/fd_topo.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Distinct configuration bytes give the listen ports distinct values
     without enumerating the protocols here. */
  fd_topo_net_tile_t net;
  for( ulong i=0UL; i<sizeof(net); i++ ) ((uchar *)&net)[ i ] = (uchar)( i+1UL );
  fd_net_rx_proto_t protos[ FD_NET_RX_PROTO_CNT ];
  fd_net_rx_protos_list( protos, &net );

  /* With distinct configured ports, fd_net_rx_protos_list must return a
     one-to-one mapping between listen ports and protocol ids. */
  for( ulong i=0UL; i<FD_NET_RX_PROTO_CNT; i++ ) {
    FD_TEST( protos[ i ].listen_port );
    for( ulong j=0UL; j<i; j++ ) {
      FD_TEST( protos[ i ].proto_id   !=protos[ j ].proto_id    );
      FD_TEST( protos[ i ].listen_port!=protos[ j ].listen_port );
    }
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
