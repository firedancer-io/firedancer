/* Firedancer topology used for testing the full validator. 
   Associated test script: test-firedancer.sh */
#include "topos.h"
#include "../tiles/tiles.h"
#include "../../config.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../util/tile/fd_tile_private.h"
#include <sys/sysinfo.h>

static ulong
parse_snapshot_slot( char const * snapshot, char const * incremental ) {
  char const * str = strlen( incremental ) > 0 ? incremental : snapshot;
  ulong str_len = strlen( str );
  char const * end_ptr = &str[str_len - 1];

  while( end_ptr > str && *end_ptr != '-') end_ptr--;

  if( end_ptr == str ) FD_LOG_ERR(("Could not parse snapshot slot out of snapshot file %s", str));

  char const * start_ptr = (end_ptr - 1);
  while( start_ptr > str && *start_ptr != '-') start_ptr--;

  if( start_ptr++ == str ) FD_LOG_ERR(("Could not parse snapshot slot out of snapshot file %s", str));
  char *eptr;
  return strtoul(start_ptr, &eptr, 10);
}

void
fd_topo_firedancer( config_t * _config ) { 
  config_t * config = (config_t *)_config;
  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };

  /*             topo, name */
  fd_topob_wksp( topo, "net_shred" );
  fd_topob_wksp( topo, "net_gossip" );
  fd_topob_wksp( topo, "net_repair" );
  fd_topob_wksp( topo, "shred_storei" );
  fd_topob_wksp( topo, "stake_out"    );
  fd_topob_wksp( topo, "metric_in"    );

  fd_topob_wksp( topo, "poh_shred" );

  fd_topob_wksp( topo, "shred_sign" );
  fd_topob_wksp( topo, "sign_shred" );
  
  fd_topob_wksp( topo, "gossip_sign" );
  fd_topob_wksp( topo, "sign_gossip" );

  fd_topob_wksp( topo, "crds_shred" );
  fd_topob_wksp( topo, "gossip_repai" );
  fd_topob_wksp( topo, "gossip_pack" );

  fd_topob_wksp( topo, "store_repair" );
  fd_topob_wksp( topo, "repair_store" );

  fd_topob_wksp( topo, "store_replay" );
  fd_topob_wksp( topo, "replay_poh" );

  fd_topob_wksp( topo, "net"        );
  fd_topob_wksp( topo, "shred"      );
  fd_topob_wksp( topo, "storei"      );
  fd_topob_wksp( topo, "sign"       );
  fd_topob_wksp( topo, "repair"     );
  fd_topob_wksp( topo, "gossip"     );
  fd_topob_wksp( topo, "metric"     );
  fd_topob_wksp( topo, "replay"     );
  fd_topob_wksp( topo, "bhole"      );
  fd_topob_wksp( topo, "bstore"     );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /*                                  topo, link_name,      wksp_name,      is_reasm, depth,                                    mtu,                           burst */
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_gossip",   "net_gossip",   0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_repair",   "net_repair",   0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );

  FOR(net_tile_cnt)    fd_topob_link( topo, "net_shred",    "net_shred",    0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );

  /**/                 fd_topob_link( topo, "stake_out",    "stake_out",    0,        128UL,                                    32UL + 40200UL * 40UL,         1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_storei", "shred_storei", 0,        65536UL,                                  4UL*FD_SHRED_STORE_MTU,        4UL+config->tiles.shred.max_pending_shred_sets );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   0,        128UL,                                    32UL,                          1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   0,        128UL,                                    64UL,                          1UL );

  /**/                 fd_topob_link( topo, "gossip_sign",  "gossip_sign",  0,        128UL,                                    2048UL,                        1UL );
  /**/                 fd_topob_link( topo, "sign_gossip",  "sign_gossip",  0,        128UL,                                    64UL,                          1UL );
  /* gossip_pack could be FD_TPU_MTU for now, since txns are not parsed, but better to just share one size for all the ins of pack */
  /**/                 fd_topob_link( topo, "gossip_pack",  "gossip_pack",  0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,             1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "crds_shred",   "crds_shred",   0,        128UL,                                    8UL  + 40200UL * 38UL,         1UL );
  /**/                 fd_topob_link( topo, "gossip_repai", "gossip_repai", 0,        128UL,                                    40200UL * 38UL, 1UL );
  /**/                 fd_topob_link( topo, "gossip_net",   "net_gossip",   0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );

  /**/                 fd_topob_link( topo, "store_repair", "store_repair", 0,        128UL,                                    64UL * 32768UL,                16UL  );
  /**/                 fd_topob_link( topo, "repair_store", "repair_store", 0,        128UL,                                    FD_SHRED_MAX_SZ,               128UL );
  /**/                 fd_topob_link( topo, "repair_net",   "net_repair",   0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL   );
  /**/                 fd_topob_link( topo, "store_replay", "store_replay", 0,        128UL,                                    8UL + 32UL + 8192UL * 2104UL,  16UL  );
  /**/                 fd_topob_link( topo, "replay_poh",   "replay_poh",   0,        128UL,                                    128UL*1024UL*1024UL,           16UL  );

  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    0,        128UL,                                    FD_NET_MTU,                    1UL   );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX; /* Unassigned tiles will be floating. */
  ulong affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=65535 && parsed_tile_to_cpu[ i ]>=get_nprocs() ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                   "only has %d CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], get_nprocs() ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==65535, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  /*                                  topo, tile_name, tile_wksp, cnc_wksp,    metrics_wksp, cpu_idx,                       is_labs, out_link,       out_link_kind_id */
  FOR(net_tile_cnt)    fd_topob_tile( topo, "net",     "net",     "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  FOR(shred_tile_cnt)  fd_topob_tile( topo, "shred",   "shred",   "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "shred_storei", i   );
  /**/                 fd_topob_tile( topo, "gossip",  "gossip",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "gossip_net",   0UL );
  /**/                 fd_topob_tile( topo, "repair",  "repair",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "repair_store",   0UL );
  /**/                 fd_topob_tile( topo, "storei",  "storei",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                 fd_topob_tile( topo, "replay",  "replay",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "stake_out",    0UL );
  /**/                 fd_topob_tile( topo, "bhole",   "bhole",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                 fd_topob_tile( topo, "sign",    "sign",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                 fd_topob_tile( topo, "metric",  "metric",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );


  /* Create a shared blockstore to be used by store and replay. */
  fd_topo_obj_t * blockstore_obj = fd_topob_obj_concrete( topo, "blockstore", "bstore", fd_blockstore_align(), fd_blockstore_footprint(), 32UL*1024UL*1024UL*1024UL );
  fd_topo_tile_t * store_tile = &topo->tiles[ fd_topo_find_tile( topo, "store", 0UL ) ];
  fd_topo_tile_t * replay_tile = &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ];
  fd_topob_tile_uses( topo, store_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_obj->id, "blockstore" ) );

  if( FD_UNLIKELY( affinity_tile_cnt<topo->tile_cnt ) ) {
    FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                 "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                 "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                 topo->tile_cnt, affinity_tile_cnt ));
  }
  if( FD_UNLIKELY( affinity_tile_cnt>topo->tile_cnt ) ) {
    FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                     "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                     "individual tile counts in the [layout] section of the configuration file.",
                     topo->tile_cnt, affinity_tile_cnt ));
  }

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  FOR(net_tile_cnt) for( ulong j=0UL; j<shred_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "net",     i,            "metric_in", "shred_net",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",     i,                         "net_shred",    i                                                  );

  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "net",     i,            "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "net",     i,            "metric_in", "repair_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */


  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "net_shred",     j,            FD_TOPOB_UNRELIABLE,   FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "poh_shred",     0UL,          FD_TOPOB_UNRELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "stake_out",     0UL,          FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "crds_shred",    0UL,          FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_net",     i                                                  );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "shred_storei",  i,            FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );
  
  /**/                 fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "repair_store",  0UL,          FD_TOPOB_UNRELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "repair",  0UL,                        "repair_net",   0UL                                                  );  
  /**/                 fd_topob_tile_out( topo, "storei",  0UL,                       "store_repair",  0UL                                                  );  
  /**/                 fd_topob_tile_out( topo, "storei",  0UL,                       "store_replay",  0UL                                                  );  
  /**/                 fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "stake_out",     0UL,          FD_TOPOB_UNRELIABLE,   FD_TOPOB_POLLED );



  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by the mux, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "shred_sign",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "shred",  i,                          "shred_sign",    i                                                    );
    /**/               fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "sign_shred",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",    i                                                    );
  }
  
  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",     i,                          "net_gossip",   i                                                    );
  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "gossip",   0UL,          "metric_in", "net_gossip",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "crds_shred",   0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_repai", 0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_pack",  0UL                                                  );
  /**/                 fd_topob_tile_in(  topo, "sign",     0UL,          "metric_in", "gossip_sign",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_sign",  0UL                                                  );
  /**/                 fd_topob_tile_in(  topo, "gossip",   0UL,          "metric_in", "sign_gossip",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out( topo, "sign",     0UL,                       "sign_gossip",  0UL                                                  );

  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",     i,                         "net_repair",    i                                                    );
  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "net_repair",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "gossip_repai",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "stake_out",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "store_repair",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  
  /**/                 fd_topob_tile_in(  topo, "replay",  0UL,          "metric_in", "store_replay",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                        "replay_poh",   0UL                                                  );

  /**/                 fd_topob_tile_in(  topo, "bhole",  0UL,           "metric_in", "gossip_pack",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "bhole",  0UL,           "metric_in", "replay_poh",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_out( topo, "bhole",  0UL,                        "poh_shred",     0UL                                                  );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    if( FD_UNLIKELY( !strcmp( tile->name, "net" ) ) ) {
      strncpy( tile->net.app_name,     config->name,                sizeof(tile->net.app_name) );
      strncpy( tile->net.interface,    config->tiles.net.interface, sizeof(tile->net.interface) );
      memcpy(  tile->net.src_mac_addr, config->tiles.net.mac_addr,  6UL );

      tile->net.xdp_aio_depth                  = config->tiles.net.xdp_aio_depth;
      tile->net.xdp_rx_queue_size              = config->tiles.net.xdp_rx_queue_size;
      tile->net.xdp_tx_queue_size              = config->tiles.net.xdp_tx_queue_size;
      tile->net.src_ip_addr                    = config->tiles.net.ip_addr;
      tile->net.shred_listen_port              = config->tiles.shred.shred_listen_port;
      tile->net.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->net.legacy_transaction_listen_port = config->tiles.quic.regular_transaction_listen_port;
      tile->net.gossip_listen_port             = config->gossip.port;
      tile->net.repair_intake_listen_port      = config->tiles.repair.repair_intake_listen_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "netmux" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ) ) {
      fd_memcpy( tile->shred.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->shred.identity_key_path, config->consensus.identity_path, sizeof(tile->shred.identity_key_path) );

      tile->shred.depth                  = topo->links[ tile->out_link_id_primary ].depth;
      tile->shred.ip_addr                = config->tiles.net.ip_addr;
      tile->shred.fec_resolver_depth     = config->tiles.shred.max_pending_shred_sets;
      tile->shred.expected_shred_version = config->consensus.expected_shred_version;
      tile->shred.shred_listen_port      = config->tiles.shred.shred_listen_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "storei" ) ) ) {
      strncpy( tile->store_int.identity_key_path, config->consensus.identity_path, sizeof(tile->store_int.identity_key_path) );
      tile->store_int.snapshot_slot = parse_snapshot_slot( config->tiles.replay.snapshot, config->tiles.replay.incremental );
    } else if( FD_UNLIKELY( !strcmp( tile->name, "gossip" ) ) ) {

      if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.gossip.peer_ip_addr, &tile->gossip.entrypoint_ip_addr ) ) ) {
        FD_LOG_ERR(( "configuration specifies invalid gossip peer IP address `%s`", config->tiles.gossip.peer_ip_addr ));
      }
      tile->gossip.entrypoint_port = config->tiles.gossip.peer_port;
      tile->gossip.ip_addr = config->tiles.net.ip_addr;
      memcpy( tile->gossip.src_mac_addr, config->tiles.net.mac_addr, 6UL );
      strncpy( tile->gossip.identity_key_path, config->consensus.identity_path, sizeof(tile->gossip.identity_key_path) );
      tile->gossip.gossip_listen_port =  config->gossip.port;
      tile->gossip.tvu_port = config->tiles.shred.shred_listen_port;
      tile->gossip.tvu_fwd_port = config->tiles.shred.shred_listen_port;
      tile->gossip.expected_shred_version = config->consensus.expected_shred_version;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "repair" ) ) ) {
      tile->repair.repair_intake_listen_port =  config->tiles.repair.repair_intake_listen_port;
      tile->repair.repair_serve_listen_port =   config->tiles.repair.repair_serve_listen_port;
      tile->repair.ip_addr = config->tiles.net.ip_addr;

      memcpy( tile->repair.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->repair.identity_key_path, config->consensus.identity_path, sizeof(tile->repair.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "replay" ) )) {
      strncpy( tile->replay.snapshot, config->tiles.replay.snapshot, sizeof(tile->replay.snapshot) );
      strncpy( tile->replay.incremental, config->tiles.replay.incremental, sizeof(tile->replay.incremental) );
      tile->replay.snapshot_slot = parse_snapshot_slot( config->tiles.replay.snapshot, config->tiles.replay.incremental );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "bhole" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {
      strncpy( tile->sign.identity_key_path, config->consensus.identity_path, sizeof(tile->sign.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) {
      tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

    } else {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }
  }

  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
  config->topo = *topo;
}
