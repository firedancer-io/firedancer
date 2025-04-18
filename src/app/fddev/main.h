#ifndef HEADER_fd_src_app_fddev_main_h
#define HEADER_fd_src_app_fddev_main_h

#include "../fdctl/topology.h"
#include "../fdctl/config.h"
#include "../shared_dev/boot/fd_dev_boot.h"
#include "../shared/commands/configure/configure.h"

char const * FD_APP_NAME    = "Frankendancer";
char const * FD_BINARY_NAME = "fddev";

extern fd_topo_obj_callbacks_t fd_obj_cb_mcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_dcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_cnc;
extern fd_topo_obj_callbacks_t fd_obj_cb_fseq;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_opaque;
extern fd_topo_obj_callbacks_t fd_obj_cb_dbl_buf;
extern fd_topo_obj_callbacks_t fd_obj_cb_neigh4_hmap;
extern fd_topo_obj_callbacks_t fd_obj_cb_fib4;
extern fd_topo_obj_callbacks_t fd_obj_cb_keyswitch;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
  &fd_obj_cb_mcache,
  &fd_obj_cb_dcache,
  &fd_obj_cb_cnc,
  &fd_obj_cb_fseq,
  &fd_obj_cb_metrics,
  &fd_obj_cb_opaque,
  &fd_obj_cb_dbl_buf,
  &fd_obj_cb_neigh4_hmap,
  &fd_obj_cb_fib4,
  &fd_obj_cb_keyswitch,
  &fd_obj_cb_tile,
  NULL,
};

extern configure_stage_t fd_cfg_stage_kill;
extern configure_stage_t fd_cfg_stage_netns;
extern configure_stage_t fd_cfg_stage_genesis;
extern configure_stage_t fd_cfg_stage_keys;
extern configure_stage_t fd_cfg_stage_blockstore;

configure_stage_t * STAGES[] = {
  &fd_cfg_stage_kill,
  &fd_cfg_stage_netns,
  &fd_cfg_stage_hugetlbfs,
  &fd_cfg_stage_sysctl,
  &fd_cfg_stage_hyperthreads,
  &fd_cfg_stage_ethtool_channels,
  &fd_cfg_stage_ethtool_gro,
  &fd_cfg_stage_ethtool_loopback,
  &fd_cfg_stage_keys,
  &fd_cfg_stage_genesis,
  &fd_cfg_stage_blockstore,
  NULL,
};

extern fd_topo_run_tile_t fd_tile_net;
extern fd_topo_run_tile_t fd_tile_netlnk;
extern fd_topo_run_tile_t fd_tile_sock;
extern fd_topo_run_tile_t fd_tile_quic;
extern fd_topo_run_tile_t fd_tile_bundle;
extern fd_topo_run_tile_t fd_tile_verify;
extern fd_topo_run_tile_t fd_tile_dedup;
extern fd_topo_run_tile_t fd_tile_pack;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_metric;
extern fd_topo_run_tile_t fd_tile_cswtch;
extern fd_topo_run_tile_t fd_tile_gui;
extern fd_topo_run_tile_t fd_tile_plugin;
extern fd_topo_run_tile_t fd_tile_bencho;
extern fd_topo_run_tile_t fd_tile_benchg;
extern fd_topo_run_tile_t fd_tile_benchs;
extern fd_topo_run_tile_t fd_tile_pktgen;
extern fd_topo_run_tile_t fd_tile_resolv;
extern fd_topo_run_tile_t fd_tile_poh;
extern fd_topo_run_tile_t fd_tile_bank;
extern fd_topo_run_tile_t fd_tile_store;

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_net,
  &fd_tile_netlnk,
  &fd_tile_sock,
  &fd_tile_quic,
  &fd_tile_bundle,
  &fd_tile_verify,
  &fd_tile_dedup,
  &fd_tile_pack,
  &fd_tile_shred,
  &fd_tile_sign,
  &fd_tile_metric,
  &fd_tile_cswtch,
  &fd_tile_gui,
  &fd_tile_plugin,
  &fd_tile_bencho,
  &fd_tile_benchg,
  &fd_tile_benchs,
  &fd_tile_pktgen,
  &fd_tile_resolv,
  &fd_tile_poh,
  &fd_tile_bank,
  &fd_tile_store,
  NULL,
};

extern action_t fd_action_run;
extern action_t fd_action_run1;
extern action_t fd_action_run_agave;
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
extern action_t fd_action_dev1;
extern action_t fd_action_dump;
extern action_t fd_action_flame;
extern action_t fd_action_help;
extern action_t fd_action_load;
extern action_t fd_action_pktgen;
extern action_t fd_action_quic_trace;
extern action_t fd_action_txn;
extern action_t fd_action_wksp;

action_t * ACTIONS[] = {
  &fd_action_run,
  &fd_action_run1,
  &fd_action_run_agave,
  &fd_action_configure,
  &fd_action_monitor,
  &fd_action_keys,
  &fd_action_ready,
  &fd_action_mem,
  &fd_action_netconf,
  &fd_action_set_identity,
  &fd_action_help,
  &fd_action_version,
  &fd_action_bench,
  &fd_action_bundle_client,
  &fd_action_dev,
  &fd_action_dev1,
  &fd_action_dump,
  &fd_action_flame,
  &fd_action_load,
  &fd_action_pktgen,
  &fd_action_quic_trace,
  &fd_action_txn,
  &fd_action_wksp,
  NULL,
};

#endif /* HEADER_fd_src_app_fddev_main_h */
