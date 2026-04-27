/* The forktest topology exercises offline replay with full consensus.
Constructed using a full topology which is pruned down. */

#define _GNU_SOURCE
#include "../../../firedancer/topology.h"
#include "../../../shared/fd_action.h"
#include "../../../shared/commands/configure/configure.h"
#include "../../../shared/commands/run/run.h"
#include "../../../shared/commands/watch/watch.h"
#include "../../../../ballet/lthash/fd_lthash.h"
#include "../../../../discof/replay/fd_execrp.h"
#include "../../../../discof/genesis/fd_genesi_tile.h"
#include "../../../../discof/tower/fd_tower_tile.h"
#include "../../../../discof/replay/fd_replay_tile.h"
#include "../../../../disco/shred/fd_shred_tile.h"
#include "../../../../disco/shred/fd_rnonce_ss.h"
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/pack/fd_pack_cost.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/pod/fd_pod_format.h"
#include "../../../../util/tile/fd_tile_private.h"
#include "../../../../discof/restore/utils/fd_ssctrl.h"
#include "../../../../discof/restore/utils/fd_ssmsg.h"
#include "../../../../flamenco/progcache/fd_progcache_admin.h"
#include "../../../../flamenco/runtime/fd_acc_pool.h"
#include "../../../../flamenco/accdb/fd_accdb_lineage.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../discof/backtest/fd_backtest_src.h"

#include <errno.h>
#include <unistd.h> /* pause(2) */
#include <fcntl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

extern configure_stage_t fd_cfg_stage_keys;

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_snapshots;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_keys;
  args.configure.stages[ stage_idx++ ] = NULL;

  return args;
}

static void
forktest_perm( args_t *         args FD_PARAM_UNUSED,
               fd_cap_chk_t *   chk,
               config_t const * config ) {
  args_t c_args = configure_args();
  configure_cmd_perm( &c_args, chk, config );
  run_cmd_perm( NULL, chk, config );
}

static ushort
forktest_recover_expected_shred_version( config_t const * config ) {
  fd_backtest_src_opts_t opts = {
    .path   = config->firedancer.development.ledger_input.path,
    .format = config->firedancer.development.ledger_input.format,
  };

  uchar buf[ FD_SHRED_MAX_SZ ];
  ulong shred_sz = fd_backtest_src_first_shred( &opts, buf, sizeof(buf) );
  if( FD_UNLIKELY( !shred_sz ) ) FD_LOG_ERR(( "unable to recover shred version from `%s`", opts.path ));

  fd_shred_t const * shred = fd_shred_parse( buf, shred_sz );
  if( FD_UNLIKELY( !shred ) ) FD_LOG_ERR(( "unable to parse first shred from `%s`", opts.path ));

  FD_LOG_INFO(( "Recovered expected shred version %hu", shred->version ));
  return shred->version;
}

static void
forktest_topo( config_t * config ) {

  if( FD_UNLIKELY( !config->consensus.expected_shred_version ) ) {
    config->consensus.expected_shred_version = forktest_recover_expected_shred_version( config );
  }

  config->development.sandbox  = 0;
  config->development.no_clone = 1;

  ulong shred_tile_cnt  = config->layout.shred_tile_count;

  ulong execrp_tile_cnt = config->firedancer.layout.execrp_tile_count;
  ulong sign_tile_cnt   = config->firedancer.layout.sign_tile_count;
  ulong lta_tile_cnt    = config->firedancer.layout.snapshot_hash_tile_count;

  int snapshots_enabled = !!config->gossip.entrypoints_cnt;
  int snapshot_lthash_disabled = config->development.snapshots.disable_lthash_verification;

  fd_topo_t * topo = fd_topob_new( &config->topo, config->name );

  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  /*             topo, name */
  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "shred"  );
  fd_topob_wksp( topo, "replay" );
  fd_topob_wksp( topo, "execrp" );
  fd_topob_wksp( topo, "tower"  );
  fd_topob_wksp( topo, "sign"   )->core_dump_level = FD_TOPO_CORE_DUMP_LEVEL_NEVER;

  fd_topob_wksp( topo, "metric_in"    );

  fd_topob_wksp( topo, "net_shred"    );

  fd_topob_wksp( topo, "gossip_out"    );

  fd_topob_wksp( topo, "shred_out"     );
  fd_topob_wksp( topo, "replay_epoch"  );
  fd_topob_wksp( topo, "replay_execrp" );
  fd_topob_wksp( topo, "replay_out"    );
  fd_topob_wksp( topo, "tower_out"     );

  fd_topob_wksp( topo, "funk"          )->core_dump_level = FD_TOPO_CORE_DUMP_LEVEL_FULL;
  fd_topob_wksp( topo, "funk_locks"    )->core_dump_level = FD_TOPO_CORE_DUMP_LEVEL_FULL;
  fd_topob_wksp( topo, "progcache"     );
  fd_topob_wksp( topo, "fec_sets"      );
  fd_topob_wksp( topo, "txncache"      );
  fd_topob_wksp( topo, "banks"         );
  fd_topob_wksp( topo, "store"         )->core_dump_level = FD_TOPO_CORE_DUMP_LEVEL_FULL;
  fd_topob_wksp( topo, "rnonce"        );

  fd_topob_wksp( topo, "shred_sign"    );
  fd_topob_wksp( topo, "sign_shred"    );

  if( FD_UNLIKELY( !snapshots_enabled ) ) {
    fd_topob_wksp( topo, "genesi" );
    fd_topob_wksp( topo, "genesi_out" );
  }

  fd_topob_wksp( topo, "execrp_replay" );

  if( FD_LIKELY( snapshots_enabled ) ) {
    fd_topob_wksp( topo, "snapct"      );
    fd_topob_wksp( topo, "snapld"      );
    fd_topob_wksp( topo, "snapdc"      );
    fd_topob_wksp( topo, "snapin"      );
    fd_topob_wksp( topo, "snapct_ld"   );
    fd_topob_wksp( topo, "snapld_dc"   );
    fd_topob_wksp( topo, "snapdc_in"   );
    if( snapshot_lthash_disabled ) {
      fd_topob_wksp( topo, "snapin_ct" );
    } else {
      fd_topob_wksp( topo, "snapla"    );
      fd_topob_wksp( topo, "snapls"    );
      fd_topob_wksp( topo, "snapla_ls" );
      fd_topob_wksp( topo, "snapin_ls" );
      fd_topob_wksp( topo, "snapls_ct" );
    }

    fd_topob_wksp( topo, "snapin_manif" );
    fd_topob_wksp( topo, "snapct_repr"  );
  }

  fd_topob_wksp( topo, "forkt" );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  ulong shred_depth = 65536UL; /* from fdctl/topology.c shred_store link. MAKE SURE TO KEEP IN SYNC. */

  /*                                  topo, link_name,       wksp_name,       depth,                                    mtu,                           burst */
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",     "net_shred",     32768UL,                                  FD_NET_MTU,                    1UL );

  if( FD_LIKELY( snapshots_enabled ) ) {
  /* TODO: Revisit the depths of all the snapshot links */
    /**/               fd_topob_link( topo, "snapct_ld",     "snapct_ld",     128UL,                                    sizeof(fd_ssctrl_init_t),      1UL );
    /**/               fd_topob_link( topo, "snapld_dc",     "snapld_dc",     16384UL,                                  USHORT_MAX,                    1UL );
    /**/               fd_topob_link( topo, "snapdc_in",     "snapdc_in",     16384UL,                                  USHORT_MAX,                    1UL );

    /**/               fd_topob_link( topo, "snapin_manif",  "snapin_manif",  4UL,                                      sizeof(fd_snapshot_manifest_t),1UL );
    /**/               fd_topob_link( topo, "snapct_repr",   "snapct_repr",   128UL,                                    0UL,                           1UL )->permit_no_consumers = 1; /* TODO: wire in repair later */

    if( snapshot_lthash_disabled ) {
      /**/             fd_topob_link( topo, "snapin_ct",    "snapin_ct",    128UL,                                    0UL,                           1UL );
    } else {
      FOR(lta_tile_cnt) fd_topob_link( topo, "snapla_ls",    "snapla_ls",   128UL,                                    sizeof(fd_lthash_value_t),     1UL );
      /**/              fd_topob_link( topo, "snapin_ls",    "snapin_ls",   256UL,                                    sizeof(fd_snapshot_full_account_t), 1UL );
      /**/              fd_topob_link( topo, "snapls_ct",    "snapls_ct",   128UL,                                    0UL,                           1UL );
    }
  }

  if( FD_UNLIKELY( !snapshots_enabled ) ) {
    /**/               fd_topob_link( topo, "genesi_out",    "genesi_out",    1UL,                                      FD_GENESIS_TILE_MTU,           1UL );
  }

  /**/                 fd_topob_link( topo, "gossip_out",    "gossip_out",    65536UL*4UL,                              sizeof(fd_gossip_update_message_t), 1UL ); /* TODO: Unclear where this depth comes from ... fix */

  /**/                 fd_topob_link( topo, "replay_epoch",  "replay_epoch",  128UL,                                    FD_EPOCH_OUT_MTU,              1UL ); /* TODO: This should be 2 but requires fixing STEM_BURST */
  /**/                 fd_topob_link( topo, "replay_out",    "replay_out",    65536UL,                                  sizeof(fd_replay_message_t),   1UL );
                       fd_topob_link( topo, "replay_execrp", "replay_execrp", 16384UL,                                  sizeof(fd_execrp_task_msg_t),  1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",    "shred_sign",    128UL,                                    32UL,                          1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",    "sign_shred",    128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_out",     "shred_out",     shred_depth,                              sizeof(fd_shred_message_t),    3UL ); /* TODO: Pretty sure burst of 3 is incorrect here */
  /**/                 fd_topob_link( topo, "tower_out",     "tower_out",     16384UL,                                  sizeof(fd_tower_msg_t),        2UL ); /* conf + slot_done. see explanation in fd_tower_tile.h for link_depth */

  FOR(execrp_tile_cnt) fd_topob_link( topo, "execrp_replay", "execrp_replay", 16384UL,                                  sizeof(fd_execrp_task_done_msg_t), 1UL );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  int is_auto_affinity = !strcmp( config->firedancer.development.forktest.affinity, "auto" );

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( config->firedancer.development.forktest.affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [development.forktest.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  fd_topob_link( topo, "net_shred", "net_shred", config->net.ingress_buffer_size, FD_NET_MTU, 1UL );

  /*                                  topo, tile_name, tile_wksp, metrics_wksp, cpu_idx,                       is_agave, uses_id_keyswitch, uses_av_keyswitch */
  /**/                 fd_topob_tile( topo, "metric",  "metric",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0,                 0 );

  if( FD_LIKELY( snapshots_enabled ) ) {
    /**/               fd_topob_tile( topo, "snapct", "snapct", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0,                 0 )->allow_shutdown = 1;
    /**/               fd_topob_tile( topo, "snapld", "snapld", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0,                 0 )->allow_shutdown = 1;
    /**/               fd_topob_tile( topo, "snapdc", "snapdc", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0,                 0 )->allow_shutdown = 1;
    /**/               fd_topob_tile( topo, "snapin", "snapin", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0,                 0 )->allow_shutdown = 1;

    if( snapshot_lthash_disabled ) {
      /* nothing to do here */
    } else {
      FOR(lta_tile_cnt)  fd_topob_tile( topo, "snapla", "snapla", "metric_in", tile_to_cpu[ topo->tile_cnt ],  0,      0,                 0 )->allow_shutdown = 1;
      /**/               fd_topob_tile( topo, "snapls", "snapls", "metric_in", tile_to_cpu[ topo->tile_cnt ],  0,      0,                 0 )->allow_shutdown = 1;
    }
  }

  if( FD_UNLIKELY( !snapshots_enabled ) ) {
    /**/               fd_topob_tile( topo, "genesi",  "genesi",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0,                 0 )->allow_shutdown = 1;
  }

  FOR(shred_tile_cnt)  fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1,                 0 );
  /**/                 fd_topob_tile( topo, "replay",  "replay",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1,                 0 );
  FOR(execrp_tile_cnt) fd_topob_tile( topo, "execrp",  "execrp",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0,                 0 );
  /**/                 fd_topob_tile( topo, "tower",   "tower",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1,                 1 );

  FOR(sign_tile_cnt)   fd_topob_tile( topo, "sign",    "sign",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1,               1 );

  fd_topob_tile( topo, "forkt", "forkt", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0, 0 );

  /*                                        topo, tile_name, tile_kind_id, fseq_wksp,   link_name,       link_kind_id, reliable,            polled */
  FOR(shred_tile_cnt) fd_topob_tile_in (    topo, "shred",   i,            "metric_in", "net_shred",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt) fd_topos_tile_in_net( topo,                          "metric_in", "shred_net",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  if( FD_UNLIKELY( !snapshots_enabled ) ) {
    /**/               fd_topob_tile_out(   topo, "genesi", 0UL,                        "genesi_out",    0UL                                                );
  }

  /**/                 fd_topob_tile_in (   topo, "forkt", 0UL,            "metric_in", "replay_epoch",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "forkt", 0UL,                         "gossip_out",    0UL                                                );
  /**/                 fd_topob_tile_in (   topo, "forkt", 0UL,            "metric_in", "tower_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "forkt", 0UL,            "metric_in", "replay_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  if( FD_LIKELY( snapshots_enabled ) ) {
                      fd_topob_tile_in (    topo, "snapct",  0UL,          "metric_in", "snapld_dc",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                      fd_topob_tile_out(    topo, "snapct",  0UL,                       "snapct_ld",     0UL                                                );
                      fd_topob_tile_out(    topo, "snapct",  0UL,                       "snapct_repr",   0UL                                                );

    if( snapshot_lthash_disabled ) {
      /**/            fd_topob_tile_out(    topo, "snapin",  0UL,                       "snapin_ct",    0UL                                            );
      /**/            fd_topob_tile_in (    topo, "snapct",  0UL,          "metric_in", "snapin_ct",    0UL,      FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    } else {
      /**/              fd_topob_tile_out(  topo, "snapin",  0UL,                       "snapin_ls",    0UL                                            );
      FOR(lta_tile_cnt) fd_topob_tile_in(   topo, "snapla",  i,            "metric_in", "snapdc_in",    0UL,      FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      FOR(lta_tile_cnt) fd_topob_tile_out(  topo, "snapla",  i,                         "snapla_ls",    i                                              );
      /**/              fd_topob_tile_in(   topo, "snapls",  0UL,          "metric_in", "snapin_ls",    0UL,      FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      FOR(lta_tile_cnt) fd_topob_tile_in(   topo, "snapls",  0UL,          "metric_in", "snapla_ls",    i,        FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      /**/              fd_topob_tile_out(  topo, "snapls",  0UL,                       "snapls_ct",    0UL                                            );
      /**/              fd_topob_tile_in (  topo, "snapct",  0UL,          "metric_in", "snapls_ct",    0UL,      FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    }

    /**/              fd_topob_tile_in (    topo, "snapld",  0UL,          "metric_in", "snapct_ld",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/              fd_topob_tile_out(    topo, "snapld",  0UL,                       "snapld_dc",     0UL                                                );

    /**/              fd_topob_tile_in (    topo, "snapdc",  0UL,          "metric_in", "snapld_dc",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/              fd_topob_tile_out(    topo, "snapdc",  0UL,                       "snapdc_in",     0UL                                                );

                      fd_topob_tile_in (    topo, "snapin",  0UL,          "metric_in", "snapdc_in",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                      fd_topob_tile_out(    topo, "snapin",  0UL,                       "snapin_manif",  0UL                                                );
  }

  if( FD_UNLIKELY( !snapshots_enabled ) ) {
    /**/               fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "genesi_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_out",    0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_epoch",  0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_execrp", 0UL                                                );
  FOR(execrp_tile_cnt) fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "execrp_replay", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "tower_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  if( FD_LIKELY( snapshots_enabled ) ) {
                       fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "snapin_manif",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  FOR(execrp_tile_cnt) fd_topob_tile_in (   topo, "execrp",  i,            "metric_in", "replay_execrp", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(execrp_tile_cnt) fd_topob_tile_out(   topo, "execrp",  i,                         "execrp_replay", i                                                  );

  /**/                 fd_topob_tile_in (   topo, "tower",   0UL,          "metric_in", "replay_epoch",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "tower",   0UL,          "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "tower",   0UL,          "metric_in", "replay_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(    topo, "tower",   0UL,          "metric_in", "shred_out",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(    topo, "replay",  0UL,          "metric_in", "shred_out",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "tower",   0UL,                       "tower_out",     0UL                                                );

  FOR(shred_tile_cnt)    fd_topob_tile_in ( topo, "shred",   i,            "metric_in", "replay_epoch",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)    fd_topob_tile_in ( topo, "shred",   i,            "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)    fd_topob_tile_out( topo, "shred",   i,                         "shred_out",     i                                                  );
  FOR(shred_tile_cnt)    fd_topob_tile_in ( topo, "shred",   i,            "metric_in", "tower_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)    fd_topob_tile_out( topo, "shred",   i,                         "shred_net",     i                                                  );

  /*                                        topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in (   topo, "sign",    0UL,          "metric_in", "shred_sign",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out(   topo, "shred",   i,                         "shred_sign",   i                                                    );
    /**/               fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "sign_shred",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out(   topo, "sign",    0UL,                       "sign_shred",   i                                                    );
  }

  fd_topob_tile_out( topo, "forkt", 0UL, "net_shred", 0UL );
  FOR(shred_tile_cnt) fd_topob_tile_in( topo, "forkt", 0UL, "metric_in", "shred_net", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  if( FD_LIKELY( !is_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt<topo->tile_cnt ) )
      FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [development.forktest.affinity] only provides for %lu cores. "
                   "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                   "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                   topo->tile_cnt, affinity_tile_cnt ));
    if( FD_UNLIKELY( affinity_tile_cnt>topo->tile_cnt ) )
      FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [development.forktest.affinity] provides for %lu cores. "
                       "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                       "individual tile counts in the [layout] section of the configuration file.",
                       topo->tile_cnt, affinity_tile_cnt ));
  } else {
    ushort blocklist_cores[ FD_TILE_MAX ];
    topo->blocklist_cores_cnt = fd_tile_private_cpus_parse( config->layout.blocklist_cores, blocklist_cores );
    if( FD_UNLIKELY( topo->blocklist_cores_cnt>FD_TILE_MAX ) ) {
      FD_LOG_ERR(( "The CPU string in the configuration file under [layout.blocklist_cores] specifies more CPUs than Firedancer can use. "
                    "You should reduce the number of CPUs in the excluded cores string." ));
    }

    for( ulong i=0UL; i<topo->blocklist_cores_cnt; i++ ) {
      /* Since we use fd_tile_private_cpus_parse() like for affinity, the user
         may input a string containing `f`. That's parsed correctly, but it's
         meaningless for blocklisted cores, so we reject it here.  */
      if( FD_UNLIKELY( blocklist_cores[ i ]==USHORT_MAX ) ) {
        FD_LOG_ERR(( "The CPU string in the configuration file under [layout.blocklist_cores] contains invalid values: `f`. "
                      "You should fix the excluded cores string." ));
      }
      topo->blocklist_cores_cpu_idx[ i ] = blocklist_cores[ i ];
    }
  }

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );

  /* Repair and shred share a secret they use to generate the nonces.
     It's not super security sensitive, but for good hygiene, we make it
     an object. */
  if( 1 /* just restrict the scope for these variables in this big function */ ) {
    fd_topo_obj_t * rnonce_ss_obj = fd_topob_obj( topo, "rnonce_ss", "rnonce" );
    for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
      fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
      fd_topob_tile_uses( topo, shred_tile, rnonce_ss_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    }
    FD_TEST( fd_pod_insertf_ulong( topo->props, rnonce_ss_obj->id, "rnonce_ss" ) );
  }

  setup_topo_funk( topo,
      config->firedancer.accounts.max_accounts,
      config->firedancer.runtime.max_live_slots,
      config->firedancer.accounts.file_size_gib );
  ulong funk_obj_id;       FD_TEST( (funk_obj_id       = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ))!=ULONG_MAX );
  ulong funk_locks_obj_id; FD_TEST( (funk_locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ))!=ULONG_MAX );
  fd_topo_obj_t * funk_obj       = &topo->objs[ funk_obj_id       ];
  fd_topo_obj_t * funk_locks_obj = &topo->objs[ funk_locks_obj_id ];

  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "tower", 0UL  ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i   ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], funk_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "tower", 0UL  ) ], funk_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i   ) ], funk_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_live_slots, config->firedancer.runtime.max_fork_width, config->development.bench.larger_max_cost_per_block );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "tower",  0UL ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i   ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  if( FD_UNLIKELY( config->firedancer.runtime.concurrent_account_limit<FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_TX ) ) {
    FD_LOG_ERR(( "concurrent_account_limit is less than the minimum required for transaction execution: %lu < %lu", config->firedancer.runtime.concurrent_account_limit, FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_TX ));
  }
  if( FD_UNLIKELY( config->firedancer.runtime.max_live_slots<32UL ) ) {
    FD_LOG_ERR(( "max_live_slots must be >= 32 in order to support tower rooting" ));
  }
  if( FD_UNLIKELY( config->firedancer.runtime.max_live_slots>FD_ACCDB_MAX_DEPTH_MAX ) ) {
    FD_LOG_ERR(( "max_live_slots (%lu) exceeds compile-time limit FD_ACCDB_MAX_DEPTH_MAX (%lu)",
                 config->firedancer.runtime.max_live_slots, FD_ACCDB_MAX_DEPTH_MAX ));
  }

  fd_topo_obj_t * acc_pool_obj = setup_topo_acc_pool( topo, config->firedancer.runtime.concurrent_account_limit );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp",   i   ) ], acc_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, acc_pool_obj->id, "acc_pool" ) );

  setup_topo_progcache( topo, "progcache",
      fd_progcache_est_rec_max( config->firedancer.runtime.program_cache.heap_size_mib<<20,
                                config->firedancer.runtime.program_cache.mean_cache_entry_size ),
      config->firedancer.runtime.max_live_slots,
      config->firedancer.runtime.program_cache.heap_size_mib<<20 );
  ulong progcache_obj_id; FD_TEST( (progcache_obj_id = fd_pod_query_ulong( topo->props, "progcache", ULONG_MAX ))!=ULONG_MAX );
  fd_topo_obj_t * progcache_obj = &topo->objs[ progcache_obj_id ];

  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], progcache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i   ) ], progcache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  ulong fec_set_cnt = 2UL*shred_depth + config->tiles.shred.max_pending_shred_sets + 6UL;
  ulong fec_sets_sz = fec_set_cnt*sizeof(fd_fec_set_t); /* mirrors # of dcache entires in frankendancer */
  fd_topo_obj_t * fec_sets_obj = setup_topo_fec_sets( topo, "fec_sets", shred_tile_cnt*fec_sets_sz );
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  FD_TEST( fd_pod_insertf_ulong( topo->props, fec_sets_obj->id, "fec_sets" ) );

  ulong store_fec_max = config->firedancer.runtime.max_live_slots * FD_FEC_BLK_MAX + (shred_depth * shred_tile_cnt) + 1;

  ulong store_fec_data_max = fd_ulong_if( config->firedancer.runtime.fixed_fec_sets, 31840UL, 63985UL );
  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", store_fec_max, (uint)shred_tile_cnt, store_fec_data_max );
  FOR(shred_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache", config->firedancer.runtime.max_live_slots, FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  if( FD_LIKELY( snapshots_enabled ) ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  if( FD_UNLIKELY( !snapshots_enabled ) ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "genesi", 0UL ) ], funk_obj,       FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "genesi", 0UL ) ], funk_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  if( FD_LIKELY( snapshots_enabled ) ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], funk_obj,       FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], funk_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  fd_pod_insert_int( topo->props, "sandbox", config->development.sandbox ? 1 : 0 );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_configure_tile( &topo->tiles[ i ], config );
  }

  fd_topob_finish( topo, CALLBACKS );
}

static void
forktest_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  args->forktest.no_watch = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch" );
}

static void
forktest_fn( args_t *   args,
             config_t * config ) {
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  initialize_workspaces( config );
  initialize_stacks( config );

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( &config->topo );

  ulong rnonce_ss_id = fd_pod_queryf_ulong( config->topo.props, ULONG_MAX, "rnonce_ss" );
  FD_TEST( rnonce_ss_id!=ULONG_MAX );
  void * shared_rnonce = fd_topo_obj_laddr( &config->topo, rnonce_ss_id );
  ulong * nonce_initialized = (ulong *)(sizeof(fd_rnonce_ss_t)+(uchar *)shared_rnonce);
  FD_TEST( fd_rng_secure( shared_rnonce, sizeof(fd_rnonce_ss_t) ) );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *nonce_initialized ) = 1UL;

  args_t watch_args;
  int pipefd[2];
  if( !args->forktest.no_watch ) {
    if( FD_UNLIKELY( pipe2( pipefd, O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    watch_args.watch.drain_output_fd = pipefd[0];
    if( FD_UNLIKELY( -1==dup2( pipefd[1], STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( pipefd[1] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );
  if( args->forktest.no_watch ) {
    for(;;) pause();
  } else {
    watch_cmd_fn( &watch_args, config );
  }
}

action_t fd_action_forktest = {
  .name = "forktest",
  .args = forktest_cmd_args,
  .fn   = forktest_fn,
  .perm = forktest_perm,
  .topo = forktest_topo,
  .is_local_cluster = 1
};
