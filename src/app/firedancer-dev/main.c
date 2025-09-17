#include "main.h"
#include "../firedancer/topology.h"
#include "../firedancer/config.h"
#include "../shared_dev/boot/fd_dev_boot.h"
#include "../shared/fd_action.h"
#include "../shared/commands/configure/configure.h"

char const * FD_APP_NAME    = "Firedancer";
char const * FD_BINARY_NAME = "firedancer-dev";

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
  &fd_cfg_stage_kill,
  &fd_cfg_stage_netns,
  &fd_cfg_stage_hugetlbfs,
  &fd_cfg_stage_normalpage,
  &fd_cfg_stage_sysctl,
  &fd_cfg_stage_ethtool_channels,
  &fd_cfg_stage_ethtool_offloads,
  &fd_cfg_stage_ethtool_loopback,
  &fd_cfg_stage_irq_affinity,
  &fd_cfg_stage_keys,
  &fd_cfg_stage_genesis,
  &fd_cfg_stage_snapshots,
  NULL,
};


extern fd_topo_run_tile_t fd_tile_net;
extern fd_topo_run_tile_t fd_tile_netlnk;
extern fd_topo_run_tile_t fd_tile_sock;
extern fd_topo_run_tile_t fd_tile_quic;
extern fd_topo_run_tile_t fd_tile_verify;
extern fd_topo_run_tile_t fd_tile_dedup;
extern fd_topo_run_tile_t fd_tile_resolv;
extern fd_topo_run_tile_t fd_tile_pack;
extern fd_topo_run_tile_t fd_tile_bank;
extern fd_topo_run_tile_t fd_tile_poh;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_metric;
extern fd_topo_run_tile_t fd_tile_cswtch;
extern fd_topo_run_tile_t fd_tile_gui;
extern fd_topo_run_tile_t fd_tile_plugin;
extern fd_topo_run_tile_t fd_tile_bencho;
extern fd_topo_run_tile_t fd_tile_benchg;
extern fd_topo_run_tile_t fd_tile_benchs;
extern fd_topo_run_tile_t fd_tile_bundle;
extern fd_topo_run_tile_t fd_tile_pktgen;
extern fd_topo_run_tile_t fd_tile_udpecho;
extern fd_topo_run_tile_t fd_tile_genesi;
extern fd_topo_run_tile_t fd_tile_ipecho;

extern fd_topo_run_tile_t fd_tile_gossvf;
extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_repair;
extern fd_topo_run_tile_t fd_tile_replay;
extern fd_topo_run_tile_t fd_tile_execor;
extern fd_topo_run_tile_t fd_tile_send;
extern fd_topo_run_tile_t fd_tile_tower;
extern fd_topo_run_tile_t fd_tile_rpcserv;
extern fd_topo_run_tile_t fd_tile_backtest;
extern fd_topo_run_tile_t fd_tile_archiver_feeder;
extern fd_topo_run_tile_t fd_tile_archiver_writer;
extern fd_topo_run_tile_t fd_tile_archiver_playback;
extern fd_topo_run_tile_t fd_tile_shredcap;

extern fd_topo_run_tile_t fd_tile_snapct;
extern fd_topo_run_tile_t fd_tile_snapld;
extern fd_topo_run_tile_t fd_tile_snapdc;
extern fd_topo_run_tile_t fd_tile_snapin;

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_net,
  &fd_tile_netlnk,
  &fd_tile_sock,
  &fd_tile_quic,
  &fd_tile_verify,
  &fd_tile_dedup,
  &fd_tile_resolv,
  &fd_tile_pack,
  &fd_tile_bank,
  &fd_tile_shred,
  &fd_tile_sign,
  &fd_tile_metric,
  &fd_tile_cswtch,
  &fd_tile_gui,
  &fd_tile_plugin,
  &fd_tile_bencho,
  &fd_tile_benchg,
  &fd_tile_benchs,
  &fd_tile_bundle,
  &fd_tile_gossvf,
  &fd_tile_gossip,
  &fd_tile_repair,
  &fd_tile_replay,
  &fd_tile_execor,
  &fd_tile_poh,
  &fd_tile_send,
  &fd_tile_tower,
  &fd_tile_rpcserv,
  &fd_tile_archiver_feeder,
  &fd_tile_archiver_writer,
  &fd_tile_archiver_playback,
  &fd_tile_shredcap,
#if FD_HAS_ROCKSDB
  &fd_tile_backtest,
#endif
  &fd_tile_bencho,
  &fd_tile_benchg,
  &fd_tile_benchs,
  &fd_tile_pktgen,
  &fd_tile_udpecho,
  &fd_tile_snapct,
  &fd_tile_snapld,
  &fd_tile_snapdc,
  &fd_tile_snapin,
  &fd_tile_genesi,
  &fd_tile_ipecho,
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
extern action_t fd_action_version;
extern action_t fd_action_bench;
extern action_t fd_action_bundle_client;
extern action_t fd_action_dev;
extern action_t fd_action_dump;
extern action_t fd_action_flame;
extern action_t fd_action_help;
extern action_t fd_action_metrics;
extern action_t fd_action_load;
extern action_t fd_action_pktgen;
extern action_t fd_action_quic_trace;
extern action_t fd_action_txn;
extern action_t fd_action_udpecho;
extern action_t fd_action_wksp;
extern action_t fd_action_gossip;
extern action_t fd_action_sim;
extern action_t fd_action_backtest;
extern action_t fd_action_snapshot_load;
extern action_t fd_action_repair;
extern action_t fd_action_shred_version;
extern action_t fd_action_ipecho_server;
extern action_t fd_action_send_test;
extern action_t fd_action_gossip_dump;
extern action_t fd_action_watch;

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
  &fd_action_metrics,
  &fd_action_version,
  &fd_action_bench,
  &fd_action_bundle_client,
  &fd_action_dev,
  &fd_action_dump,
  &fd_action_flame,
  &fd_action_load,
  &fd_action_pktgen,
  &fd_action_quic_trace,
  &fd_action_txn,
  &fd_action_udpecho,
  &fd_action_wksp,
  &fd_action_gossip,
  &fd_action_sim,
  &fd_action_backtest,
  &fd_action_snapshot_load,
  &fd_action_repair,
  &fd_action_shred_version,
  &fd_action_ipecho_server,
  &fd_action_send_test,
  &fd_action_gossip_dump,
  &fd_action_watch,
  NULL,
};

int
main( int     argc,
      char ** argv ) {
  fd_config_file_t _default = fd_config_file_default();
  fd_config_file_t testnet = fd_config_file_testnet();
  fd_config_file_t devnet = fd_config_file_devnet();
  fd_config_file_t mainnet = fd_config_file_mainnet();

  fd_config_file_t * configs[] = {
    &_default,
    &testnet,
    &devnet,
    &mainnet,
    NULL
  };

  return fd_dev_main( argc, argv, 1, configs, fd_topo_initialize );
}
