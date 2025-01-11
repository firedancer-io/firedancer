#include "fdctl.h"

#include "configure/configure.h"

configure_stage_t * STAGES[ CONFIGURE_STAGE_COUNT ] = {
  &fd_cfg_stage_hugetlbfs,
  &fd_cfg_stage_sysctl,
  &fd_cfg_stage_ethtool_channels,
  &fd_cfg_stage_ethtool_gro,
  &fd_cfg_stage_ethtool_loopback,
  NULL,
  NULL,
  NULL,
  NULL,
};

extern fd_topo_run_tile_t fd_tile_net;
extern fd_topo_run_tile_t fd_tile_quic;
extern fd_topo_run_tile_t fd_tile_bundle;
extern fd_topo_run_tile_t fd_tile_verify;
extern fd_topo_run_tile_t fd_tile_dedup;
extern fd_topo_run_tile_t fd_tile_resolv;
extern fd_topo_run_tile_t fd_tile_pack;
extern fd_topo_run_tile_t fd_tile_bank;
extern fd_topo_run_tile_t fd_tile_poh;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_store;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_metric;
extern fd_topo_run_tile_t fd_tile_cswtch;
extern fd_topo_run_tile_t fd_tile_gui;
extern fd_topo_run_tile_t fd_tile_plugin;
extern fd_topo_run_tile_t fd_tile_blackhole;

#ifdef FD_HAS_NO_AGAVE
extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_repair;
extern fd_topo_run_tile_t fd_tile_store_int;
extern fd_topo_run_tile_t fd_tile_replay;
extern fd_topo_run_tile_t fd_tile_replay_thread;
extern fd_topo_run_tile_t fd_tile_batch;
extern fd_topo_run_tile_t fd_tile_batch_thread;
extern fd_topo_run_tile_t fd_tile_poh_int;
extern fd_topo_run_tile_t fd_tile_sender;
extern fd_topo_run_tile_t fd_tile_eqvoc;
extern fd_topo_run_tile_t fd_tile_rpcserv;
#endif

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_net,
  &fd_tile_quic,
  &fd_tile_bundle,
  &fd_tile_verify,
  &fd_tile_dedup,
  &fd_tile_resolv,
  &fd_tile_pack,
  &fd_tile_bank,
  &fd_tile_poh,
  &fd_tile_shred,
  &fd_tile_store,
  &fd_tile_sign,
  &fd_tile_metric,
  &fd_tile_cswtch,
  &fd_tile_gui,
  &fd_tile_plugin,
  &fd_tile_blackhole,
#ifdef FD_HAS_NO_AGAVE
  &fd_tile_gossip,
  &fd_tile_repair,
  &fd_tile_store_int,
  &fd_tile_replay,
  &fd_tile_replay_thread,
  &fd_tile_batch,
  &fd_tile_batch_thread,
  &fd_tile_poh_int,
  &fd_tile_sender,
  &fd_tile_eqvoc,
  &fd_tile_rpcserv,
#endif
  NULL,
};

int
main( int     argc,
      char ** argv ) {
  main1( argc, argv );
}

/* Kind of a hack for now, we sometimes want to view bench generation
   in the monitor binary, but it's not part of the production binary. */

void
add_bench_topo( fd_topo_t  * topo,
                char const * affinity,
                ulong        benchg_tile_cnt,
                ulong        benchs_tile_cnt,
                ulong        accounts_cnt,
                int          transaction_mode,
                float        contending_fraction,
                float        cu_price_spread,
                ulong        conn_cnt,
                ushort       send_to_port,
                uint         send_to_ip_addr,
                ushort       rpc_port,
                uint         rpc_ip_addr,
                int          no_quic ) {
  (void)topo;
  (void)affinity;
  (void)benchg_tile_cnt;
  (void)benchs_tile_cnt;
  (void)accounts_cnt;
  (void)transaction_mode;
  (void)contending_fraction;
  (void)cu_price_spread;
  (void)conn_cnt;
  (void)send_to_port;
  (void)send_to_ip_addr;
  (void)rpc_port;
  (void)rpc_ip_addr;
  (void)no_quic;
}
