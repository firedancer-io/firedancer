#include "fd_net_tile.h"
#include "../topo/fd_topob.h"
#include "../topo/fd_topob_layout.h"

static fd_topo_t topo[1];

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_topob_new( topo, "socktest" ) );
  fd_topob_wksp( topo, "net" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topo_tile_t * net = fd_topob_tile( topo, "net", "net", "metric_in", 27UL, 0, 0, 0 );
  fd_topo_tile_t * quic = fd_topob_tile( topo, "quic", "net", "metric_in", 29UL, 0, 0, 0 );
  fd_topo_tile_t * netlnk = fd_topob_tile( topo, "netlnk", "net", "metric_in", 30UL, 0, 0, 0 );
  fd_topob_link( topo, "net_quic", "net", 128UL, FD_NET_MTU, 64UL );
  fd_topob_link( topo, "net_netlnk", "net", 128UL, FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "net", 0UL, "net_quic", 0UL );
  fd_topob_tile_out( topo, "net", 0UL, "net_netlnk", 0UL );
  fd_topob_tile_in( topo, "quic", 0UL, "net", "net_quic", 0UL, 1, 1 );
  fd_topob_tile_in( topo, "netlnk", 0UL, "net", "net_netlnk", 0UL, 0, 1 );
  net->net.legacy_transaction_listen_port = 9000U;
  net->net.repair_serve_listen_port = 9002U; /* configured but no link */
  fd_topos_sock_lo( topo, net );
  FD_TEST( topo->tile_cnt==4UL && topo->link_cnt==3UL );
  fd_topo_tile_t * sock = &topo->tiles[3];
  FD_TEST( !strcmp( sock->name, "sock" ) && sock->sock.only_recv_lo && !sock->in_cnt );
  FD_TEST( sock_lo_net_tile_id( sock )==net->id && sock->out_cnt==1UL );
  FD_TEST( sock->net.legacy_transaction_listen_port==9000U && sock->net.repair_serve_listen_port==9002U );
  FD_TEST( quic->in_cnt==2UL && netlnk->in_cnt==1UL );
  FD_TEST( quic->in_link_id[0]!=quic->in_link_id[1] && quic->in_link_id[1]==sock->out_link_id[0] );
  FD_TEST( quic->in_link_reliable[1] && quic->in_link_poll[1] );
  FD_TEST( fd_topob_tile_priority_type( sock )==FD_TOPOB_PRIORITY_FLOATING );
  for( int floats=0; floats<=1; floats++ ) {
    net->floats=floats; sock_lo_set_affinity( topo );
    FD_TEST( sock->cpu_idx==27UL && sock->floats==floats );
  }
  FD_LOG_NOTICE(( "pass: one RX-only loopback socket tile, shared net0 affinity, existing RX consumers only" ));
  fd_halt();
  return 0;
}
