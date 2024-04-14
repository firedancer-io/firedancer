#include "fdctl.h"

#include "configure/configure.h"

configure_stage_t * STAGES[ CONFIGURE_STAGE_COUNT ] = {
  &hugetlbfs,
  &sysctl,
  &xdp,
  &xdp_leftover,
  &ethtool,
  &workspace,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
};

extern fd_topo_run_tile_t fd_tile_net;
extern fd_topo_run_tile_t fd_tile_netmux;
extern fd_topo_run_tile_t fd_tile_quic;
extern fd_topo_run_tile_t fd_tile_verify;
extern fd_topo_run_tile_t fd_tile_dedup;
extern fd_topo_run_tile_t fd_tile_pack;
extern fd_topo_run_tile_t fd_tile_bank;
extern fd_topo_run_tile_t fd_tile_poh;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_store;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_metric;

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_net,
  &fd_tile_netmux,
  &fd_tile_quic,
  &fd_tile_verify,
  &fd_tile_dedup,
  &fd_tile_pack,
  &fd_tile_bank,
  &fd_tile_poh,
  &fd_tile_shred,
  &fd_tile_store,
  &fd_tile_sign,
  &fd_tile_metric,
  NULL,
};

int
main( int     argc,
      char ** argv ) {
  main1( argc, argv );
}
