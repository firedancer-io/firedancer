#include "topology.h"
#include "config.h"
#include "../shared/boot/fd_boot.h"
#include "../shared/commands/configure/configure.h"

char const * FD_APP_NAME    = "Firedancer";
char const * FD_BINARY_NAME = "firedancer";

extern fd_topo_obj_callbacks_t fd_obj_cb_mcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_dcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_fseq;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_opaque;
extern fd_topo_obj_callbacks_t fd_obj_cb_dbl_buf;
extern fd_topo_obj_callbacks_t fd_obj_cb_neigh4_hmap;
extern fd_topo_obj_callbacks_t fd_obj_cb_fib4;
extern fd_topo_obj_callbacks_t fd_obj_cb_keyswitch;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;
extern fd_topo_obj_callbacks_t fd_obj_cb_runtime_pub;
extern fd_topo_obj_callbacks_t fd_obj_cb_store;
extern fd_topo_obj_callbacks_t fd_obj_cb_fec_sets;
extern fd_topo_obj_callbacks_t fd_obj_cb_txncache;
extern fd_topo_obj_callbacks_t fd_obj_cb_exec_spad;
extern fd_topo_obj_callbacks_t fd_obj_cb_banks;
extern fd_topo_obj_callbacks_t fd_obj_cb_funk;
extern fd_topo_obj_callbacks_t fd_obj_cb_bank_hash_cmp;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
  &fd_obj_cb_mcache,
  &fd_obj_cb_dcache,
  &fd_obj_cb_fseq,
  &fd_obj_cb_metrics,
  &fd_obj_cb_opaque,
  &fd_obj_cb_dbl_buf,
  &fd_obj_cb_neigh4_hmap,
  &fd_obj_cb_fib4,
  &fd_obj_cb_keyswitch,
  &fd_obj_cb_tile,
  &fd_obj_cb_runtime_pub,
  &fd_obj_cb_store,
  &fd_obj_cb_fec_sets,
  &fd_obj_cb_txncache,
  &fd_obj_cb_exec_spad,
  &fd_obj_cb_banks,
  &fd_obj_cb_funk,
  &fd_obj_cb_bank_hash_cmp,
  NULL,
};

configure_stage_t * STAGES[] = {
  &fd_cfg_stage_hugetlbfs,
  &fd_cfg_stage_sysctl,
  &fd_cfg_stage_hyperthreads,
  &fd_cfg_stage_ethtool_channels,
  &fd_cfg_stage_ethtool_gro,
  &fd_cfg_stage_ethtool_loopback,
  &fd_cfg_stage_snapshots,
  NULL,
};


extern fd_topo_run_tile_t fd_tile_net;
extern fd_topo_run_tile_t fd_tile_netlnk;
extern fd_topo_run_tile_t fd_tile_sock;
extern fd_topo_run_tile_t fd_tile_quic;
extern fd_topo_run_tile_t fd_tile_verify;
extern fd_topo_run_tile_t fd_tile_dedup;
extern fd_topo_run_tile_t fd_tile_pack;
extern fd_topo_run_tile_t fd_tile_resolv;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_metric;
extern fd_topo_run_tile_t fd_tile_cswtch;
extern fd_topo_run_tile_t fd_tile_gui;
extern fd_topo_run_tile_t fd_tile_plugin;
extern fd_topo_run_tile_t fd_tile_bundle;

extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_repair;
extern fd_topo_run_tile_t fd_tile_replay;
extern fd_topo_run_tile_t fd_tile_execor;
extern fd_topo_run_tile_t fd_tile_writer;
extern fd_topo_run_tile_t fd_tile_poh;
extern fd_topo_run_tile_t fd_tile_send;
extern fd_topo_run_tile_t fd_tile_tower;
extern fd_topo_run_tile_t fd_tile_rpcserv;

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_net,
  &fd_tile_netlnk,
  &fd_tile_sock,
  &fd_tile_quic,
  &fd_tile_verify,
  &fd_tile_dedup,
  &fd_tile_pack,
  &fd_tile_resolv,
  &fd_tile_shred,
  &fd_tile_sign,
  &fd_tile_metric,
  &fd_tile_cswtch,
  &fd_tile_gui,
  &fd_tile_plugin,
  &fd_tile_bundle,
  &fd_tile_gossip,
  &fd_tile_repair,
  &fd_tile_replay,
  &fd_tile_execor,
  &fd_tile_writer,
  &fd_tile_poh,
  &fd_tile_send,
  &fd_tile_tower,
  &fd_tile_rpcserv,
  NULL,
};

extern action_t fd_action_run;
extern action_t fd_action_run1;
extern action_t fd_action_configure;
extern action_t fd_action_monitor;
extern action_t fd_action_keys;
extern action_t fd_action_ready;
extern action_t fd_action_mem;
extern action_t fd_action_netconf;
extern action_t fd_action_set_identity;
extern action_t fd_action_help;
extern action_t fd_action_version;

action_t * ACTIONS[] = {
  &fd_action_run,
  &fd_action_run1,
  &fd_action_configure,
  &fd_action_monitor,
  &fd_action_keys,
  &fd_action_ready,
  &fd_action_mem,
  &fd_action_netconf,
  &fd_action_set_identity,
  &fd_action_help,
  &fd_action_version,
  NULL,
};

int
main( int     argc,
      char ** argv ) {
  return fd_main( argc, argv, 1, (char const *)firedancer_default_config, firedancer_default_config_sz, fd_topo_initialize );
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
                int          no_quic,
                int          reserve_agave_cores ) {
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
  (void)reserve_agave_cores;
}
