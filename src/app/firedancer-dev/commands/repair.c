/* The repair command spawns a smaller topology for profiling the repair
   tile.  This is a standalone application, and it can be run in mainnet,
   testnet and/or a private cluster. */

#include "../../../disco/net/fd_net_tile.h"
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/topo/fd_cpu_topo.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../util/tile/fd_tile_private.h"

#include "../../firedancer/topology.h"
#include "../../firedancer/topology.c"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h"
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"

#include <unistd.h> /* pause */

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static ulong
link_permit_no_producers( fd_topo_t * topo, char * link_name ) {
  ulong found = 0UL;
  for( ulong link_i = 0UL; link_i < topo->link_cnt; link_i++ ) {
    if( !strcmp( topo->links[ link_i ].name, link_name ) ) {
      topo->links[ link_i ].permit_no_producers = 1;
      found++;
    }
  }
  return found;
}

static ulong
link_permit_no_consumers( fd_topo_t * topo, char * link_name ) {
  ulong found = 0UL;
  for( ulong link_i = 0UL; link_i < topo->link_cnt; link_i++ ) {
    if( !strcmp( topo->links[ link_i ].name, link_name ) ) {
      topo->links[ link_i ].permit_no_consumers = 1;
      found++;
    }
  }
  return found;
}

/* repair_topo is a subset of "src/app/firedancer/topology.c" at commit
   0d8386f4f305bb15329813cfe4a40c3594249e96, slightly modified to work
   as a repair profiler.  TODO ideally, one should invoke the firedancer
   topology first, and exclude the parts that are not needed, instead of
   manually generating new topologies for every command.  This would
   also guarantee that the profiler is replicating (as close as possible)
   the full topology. */
static void
repair_topo( config_t * config ) {
  resolve_gossip_entrypoints( config );

  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong sign_tile_cnt   = config->firedancer.layout.sign_tile_count;
  ulong gossvf_tile_cnt = config->firedancer.layout.gossvf_tile_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  /*             topo, name */
  fd_topob_wksp( topo, "metric_in"    );
  fd_topob_wksp( topo, "net_shred"    );
  fd_topob_wksp( topo, "gossip_net"   );
  fd_topob_wksp( topo, "net_repair"   );
  fd_topob_wksp( topo, "net_quic"     );

  fd_topob_wksp( topo, "shred_repair" );
  fd_topob_wksp( topo, "stake_out"    );

  fd_topob_wksp( topo, "poh_shred"    );

  fd_topob_wksp( topo, "shred_sign"   );
  fd_topob_wksp( topo, "sign_shred"   );

  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_wksp( topo, "sign_gossip"  );

  fd_topob_wksp( topo, "ipecho_out"   );

  fd_topob_wksp( topo, "gossvf_gossi" );
  fd_topob_wksp( topo, "gossip_gossv" );

  fd_topob_wksp( topo, "gossip_out"   );

  fd_topob_wksp( topo, "repair_sign"  );
  fd_topob_wksp( topo, "sign_repair"  );

  fd_topob_wksp( topo, "repair_repla" );
  fd_topob_wksp( topo, "send_txns"    );

  fd_topob_wksp( topo, "shred"        );
  fd_topob_wksp( topo, "sign"         );
  fd_topob_wksp( topo, "repair"       );
  fd_topob_wksp( topo, "ipecho"       );
  fd_topob_wksp( topo, "gossvf"       );
  fd_topob_wksp( topo, "gossip"       );
  fd_topob_wksp( topo, "metric"       );
  fd_topob_wksp( topo, "fec_sets"     );
  fd_topob_wksp( topo, "snap_out"     );

  fd_topob_wksp( topo, "slot_fseqs"   ); /* fseqs for marked slots eg. turbine slot */

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  ulong pending_fec_shreds_depth = fd_ulong_min( fd_ulong_pow2_up( config->tiles.shred.max_pending_shred_sets * FD_REEDSOL_DATA_SHREDS_MAX ), USHORT_MAX + 1 /* dcache max */ );

  /*                                  topo, link_name,      wksp_name,      depth,                                    mtu,                           burst */
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );

  /**/                 fd_topob_link( topo, "stake_out",    "stake_out",    128UL,                                    40UL + 40200UL * 40UL,         1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   128UL,                                    32UL,                          1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   128UL,                                    64UL,                          1UL );

  /**/                 fd_topob_link( topo, "gossip_sign",  "gossip_sign",  128UL,                                    2048UL,                        1UL );
  /**/                 fd_topob_link( topo, "sign_gossip",  "sign_gossip",  128UL,                                    64UL,                          1UL );
  /**/                 fd_topob_link( topo, "gossip_out",   "gossip_out",   65536UL*4UL,                              2048UL,                        1UL );

  /**/                 fd_topob_link( topo, "ipecho_out",   "ipecho_out",   4UL,                                      0UL,                           1UL );

  FOR(gossvf_tile_cnt) fd_topob_link( topo, "gossvf_gossi", "gossvf_gossi", config->net.ingress_buffer_size,          sizeof(fd_gossip_view_t)+FD_NET_MTU, 1UL );
  /**/                 fd_topob_link( topo, "gossip_gossv", "gossip_gossv", 65536UL*4UL,                              sizeof(fd_gossip_ping_update_t), 1UL );

  /**/                 fd_topob_link( topo, "gossip_net",   "gossip_net",   65536UL*4UL,                              FD_NET_MTU,                    1UL );

  /**/                 fd_topob_link( topo, "repair_net",   "net_repair",   config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_repair", "shred_repair", pending_fec_shreds_depth,                 FD_SHRED_REPAIR_MTU,           2UL /* at most 2 msgs per after_frag */ );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "repair_shred", "shred_repair", pending_fec_shreds_depth,                 sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "ping_sign",    "repair_sign",  128UL,                                    2048UL,                        1UL );
  /**/                 fd_topob_link( topo, "sign_ping",    "sign_repair",  128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );
  FOR(sign_tile_cnt-1) fd_topob_link( topo, "repair_sign",  "repair_sign",  128UL,                                    2048UL,                        1UL );
  FOR(sign_tile_cnt-1) fd_topob_link( topo, "sign_repair",  "sign_repair",  1024UL,                                   sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "repair_repla", "repair_repla", 65536UL,                                  sizeof(fd_reasm_fec_t),    1UL );
  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    16384UL,                                  USHORT_MAX,                    1UL );

  /**/                 fd_topob_link( topo, "send_txns",    "send_txns",    128UL,                                    FD_TXN_MTU,                    1UL );

  /**/                 fd_topob_link( topo, "snap_out",     "snap_out",     2UL,                                      sizeof(fd_snapshot_manifest_t), 1UL );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  int is_auto_affinity = !strcmp( config->layout.affinity, "auto" );
  int is_bench_auto_affinity = !strcmp( config->development.bench.affinity, "auto" );

  if( FD_UNLIKELY( is_auto_affinity != is_bench_auto_affinity ) ) {
    FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] and [development.bench.affinity] must all be set to 'auto' or all be set to a specific CPU affinity string." ));
  }

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                  "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                  "in the system.",
                  parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  fd_topos_net_tiles( topo, config->layout.net_tile_count, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );

  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_gossvf", i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_repair", i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_quic",   i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_shred",  i, config->net.ingress_buffer_size );

  /*                                              topo, tile_name, tile_wksp, metrics_wksp, cpu_idx,                       is_agave, uses_keyswitch */
  FOR(shred_tile_cnt)              fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  FOR(sign_tile_cnt)               fd_topob_tile( topo, "sign",    "sign",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                             fd_topob_tile( topo, "metric",  "metric",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                             fd_topob_tile( topo, "ipecho",  "ipecho",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(gossvf_tile_cnt)             fd_topob_tile( topo, "gossvf",  "gossvf",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                             fd_topob_tile( topo, "gossip",  "gossip",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  fd_topo_tile_t * repair_tile =   fd_topob_tile( topo, "repair",  "repair",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  /* Setup a shared wksp object for fec sets. */

  ulong shred_depth = 65536UL; /* from fdctl/topology.c shred_store link. MAKE SURE TO KEEP IN SYNC. */
  ulong fec_set_cnt = shred_depth + config->tiles.shred.max_pending_shred_sets + 4UL;
  ulong fec_sets_sz = fec_set_cnt*sizeof(fd_shred34_t)*4; /* mirrors # of dcache entires in frankendancer */
  fd_topo_obj_t * fec_sets_obj = setup_topo_fec_sets( topo, "fec_sets", shred_tile_cnt*fec_sets_sz );
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile,  fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  fd_topob_tile_uses( topo, repair_tile, fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fec_sets_obj->id, "fec_sets" ) );

  /* There's another special fseq that's used to communicate the shred
    version from the Agave boot path to the shred tile. */
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "gossip", 0UL ) ];
  fd_topob_tile_uses( topo, poh_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /* root_slot is an fseq marking the validator's current Tower root. */

  fd_topo_obj_t * root_slot_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, root_slot_obj->id, "root_slot" ) );

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  }
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );

  if( FD_LIKELY( !is_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt<topo->tile_cnt ) )
      FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                  "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                  "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                  topo->tile_cnt, affinity_tile_cnt ));
    if( FD_UNLIKELY( affinity_tile_cnt>topo->tile_cnt ) )
      FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                      "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                      "individual tile counts in the [layout] section of the configuration file.",
                      topo->tile_cnt, affinity_tile_cnt ));
  }

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  for( ulong j=0UL; j<shred_tile_cnt; j++ )
                  fd_topos_tile_in_net(  topo,                          "metric_in", "shred_net",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong j=0UL; j<quic_tile_cnt; j++ )
                  fd_topos_tile_in_net(  topo,                          "metric_in", "quic_net",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  /**/                 fd_topob_tile_in(  topo, "gossip",  0UL,          "metric_in", "send_txns",    0UL,          FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /**/             fd_topos_tile_in_net(  topo,                          "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/             fd_topos_tile_in_net(  topo,                          "metric_in", "repair_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  /**/                 fd_topob_tile_out( topo, "ipecho", 0UL,                        "ipecho_out",   0UL                                                   );

  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "net_shred",     j,            FD_TOPOB_UNRELIABLE,   FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "poh_shred",     0UL,          FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "stake_out",     0UL,          FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_repair",  i                                                    );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_net",     i                                                    );
  FOR(shred_tile_cnt)  fd_topob_tile_in ( topo, "shred",  i,             "metric_in", "ipecho_out",    0UL,          FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );

  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in",  "repair_shred", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  /**/                 fd_topob_tile_out( topo, "repair",  0UL,                       "repair_net",    0UL                                                  );

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

  FOR(gossvf_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "net_gossvf",   j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(gossvf_tile_cnt) fd_topob_tile_out( topo, "gossvf",   i,                         "gossvf_gossi", i                                                    );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "gossip_gossv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );


  /**/                 fd_topob_tile_in ( topo, "gossip",   0UL,          "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_net",   0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_out",   0UL                                                  );
  /**/                 fd_topob_tile_in ( topo, "gossip",   0UL,          "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossip",   0UL,          "metric_in", "gossvf_gossi", i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_gossv", 0UL                                                  );
  /**/                 fd_topob_tile_in(  topo, "sign",     0UL,          "metric_in", "gossip_sign",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_sign",  0UL                                                  );
  /**/                 fd_topob_tile_in(  topo, "gossip",   0UL,          "metric_in", "sign_gossip",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out( topo, "sign",     0UL,                       "sign_gossip",  0UL                                                  );

  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "net_repair",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "stake_out",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
                       fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "snap_out",      0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "shred_repair",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  /**/                 fd_topob_tile_in(  topo, "sign",   0UL,         "metric_in",  "ping_sign",    0UL,    FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "repair", 0UL,                       "ping_sign",    0UL                                            );
  /**/                 fd_topob_tile_out( topo, "repair", 0UL,                       "repair_repla", 0UL                                            );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "repair", 0UL,                       "repair_shred", i                                              );
  /**/                 fd_topob_tile_out( topo, "sign",   0UL,                       "sign_ping",    0UL                                            );

  FOR(sign_tile_cnt-1) fd_topob_tile_out( topo, "repair", 0UL,                        "repair_sign",  i                                              );
  FOR(sign_tile_cnt-1) fd_topob_tile_in ( topo, "sign",   i+1,           "metric_in", "repair_sign",  i,      FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(sign_tile_cnt-1) fd_topob_tile_out( topo, "sign",   i+1,                        "sign_repair",  i                                              );
  FOR(sign_tile_cnt-1) fd_topob_tile_in ( topo, "repair", 0UL,           "metric_in", "sign_repair",  i,      FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_in ( topo, "repair", 0UL,           "metric_in", "sign_ping",    0UL,    FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );

  if( 1 ) {
    fd_topob_wksp( topo, "scap" );

    fd_topob_wksp( topo, "repair_scap" );
    fd_topob_wksp( topo, "replay_scap" );

    fd_topo_tile_t * scap_tile = fd_topob_tile( topo, "scap", "scap", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    fd_topob_link( topo, "repair_scap", "repair_scap", 128UL, FD_SLICE_MAX_WITH_HEADERS, 1UL );
    fd_topob_link( topo, "replay_scap", "replay_scap", 128UL, sizeof(fd_hash_t)+sizeof(ulong), 1UL );

    fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "repair_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    for( ulong j=0UL; j<net_tile_cnt; j++ ) {
      fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "net_shred", j, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    }
    for( ulong j=0UL; j<shred_tile_cnt; j++ ) {
      fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "shred_repair", j, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    }
    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "gossip_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "repair_scap", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "replay_scap", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_tile_uses( topo, scap_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_out( topo, "scap", 0UL, "stake_out", 0UL );
    fd_topob_tile_out( topo, "scap", 0UL, "snap_out",  0UL );
  }

  FD_TEST( link_permit_no_producers( topo, "quic_net"     ) == quic_tile_cnt );
  FD_TEST( link_permit_no_producers( topo, "poh_shred"    ) == 1UL           );
  FD_TEST( link_permit_no_producers( topo, "send_txns"    ) == 1UL           );
  FD_TEST( link_permit_no_producers( topo, "repair_scap"  ) == 1UL           );
  FD_TEST( link_permit_no_producers( topo, "replay_scap"  ) == 1UL           );

  FD_TEST( link_permit_no_consumers( topo, "net_quic"     ) == quic_tile_cnt );
  FD_TEST( link_permit_no_consumers( topo, "repair_repla" ) == 1UL           );

  config->tiles.send.send_src_port = 0; /* disable send */

  FOR(net_tile_cnt) fd_topos_net_tile_finish( topo, i );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( !fd_topo_configure_tile( tile, config ) ) {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }
  }

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );

  fd_topob_finish( topo, CALLBACKS );

  config->topo = *topo;
}

extern int * fd_log_private_shared_lock;

void
repair_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {

  if( FD_UNLIKELY( !*pargc ) ) FD_LOG_ERR(( "usage: repair --manifest-path <manifest_path>" ));

  char const * manifest_path = fd_env_strip_cmdline_cstr( pargc, pargv, "--manifest-path", NULL, "unknonw" );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->repair.manifest_path ), manifest_path, sizeof(args->repair.manifest_path)-1UL ) );

  FD_LOG_NOTICE(( "repair manifest_path %s", args->repair.manifest_path ));
}

static char *
fmt_count( char buf[ static 64 ], ulong count ) {
  char tmp[ 64 ];
  if( FD_LIKELY( count<1000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%lu", count ) );
  else if( FD_LIKELY( count<1000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f K", (double)count/1000.0 ) );
  else if( FD_LIKELY( count<1000000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f M", (double)count/1000000.0 ) );

  FD_TEST( fd_cstr_printf_check( buf, 64UL, NULL, "%12s", tmp ) );
  return buf;
}

static void
print_histogram_buckets( volatile ulong * metrics,
                         ulong offset,
                         int converter,
                         double histmin,
                         double histmax,
                         char * title ) {
  fd_histf_t hist[1];

  /* Create histogram structure only to get bucket edges for display */
  if( FD_LIKELY( converter == FD_METRICS_CONVERTER_SECONDS ) ) {
    /* For SLOT_COMPLETE_TIME: min=0.2, max=2.0 seconds */
    FD_TEST( fd_histf_new( hist, fd_metrics_convert_seconds_to_ticks( histmin ), fd_metrics_convert_seconds_to_ticks( histmax ) ) );
  } else if( FD_LIKELY( converter == FD_METRICS_CONVERTER_NONE ) ) {
    /* For non-time histograms, we'd need the actual min/max values */
    FD_TEST( fd_histf_new( hist, (ulong)histmin, (ulong)histmax ) );
  } else {
    FD_LOG_ERR(( "unknown converter %i", converter ));
  }

  printf( " +---------------------+--------------------+--------------+\n" );
  printf( " | %-19s |                    | Count        |\n", title );
  printf( " +---------------------+--------------------+--------------+\n" );

  ulong total_count = 0;
  for( ulong k = 0; k < FD_HISTF_BUCKET_CNT; k++ ) {
    ulong bucket_count = metrics[ offset + k ];
    total_count += bucket_count;
  }

  for( ulong k = 0; k < FD_HISTF_BUCKET_CNT; k++ ) {
    /* Get individual bucket count directly from metrics array */
    ulong bucket_count = metrics[ offset + k ];

    char * le_str;
    char le_buf[ 64 ];
    if( FD_UNLIKELY( k == FD_HISTF_BUCKET_CNT - 1UL ) ) {
      le_str = "+Inf";
    } else {
      ulong edge = fd_histf_right( hist, k );
      if( FD_LIKELY( converter == FD_METRICS_CONVERTER_SECONDS ) ) {
        double edgef = fd_metrics_convert_ticks_to_seconds( edge - 1 );
        FD_TEST( fd_cstr_printf_check( le_buf, sizeof( le_buf ), NULL, "%.3f", edgef ) );
      } else {
        FD_TEST( fd_cstr_printf_check( le_buf, sizeof( le_buf ), NULL, "%.3f", (double)(edge - 1) / 1000000.0 ) );
      }
      le_str = le_buf;
    }

    char count_buf[ 64 ];
    fmt_count( count_buf, bucket_count );

    /* Create visual bar - scale to max 20 characters */
    char bar_buf[ 22 ];
    if( bucket_count > 0 && total_count > 0 ) {
      ulong bar_length = (bucket_count * 22UL) / total_count;
      if( bar_length == 0 ) bar_length = 1;
      for( ulong i = 0; i < bar_length; i++ ) { bar_buf[ i ] = '|'; }
      bar_buf[ bar_length ] = '\0';
    } else {
      bar_buf[ 0 ] = '\0';
    }

    printf( " | %-19s | %-18s | %s |\n", le_str, bar_buf, count_buf );
  }

  /* Print sum and total count */
  char sum_buf[ 64 ];
  char avg_buf[ 64 ];
  if( FD_LIKELY( converter == FD_METRICS_CONVERTER_SECONDS ) ) {
    double sumf = fd_metrics_convert_ticks_to_seconds( metrics[ offset + FD_HISTF_BUCKET_CNT ] );
    FD_TEST( fd_cstr_printf_check( sum_buf, sizeof( sum_buf ), NULL, "%.6f", sumf ) );
    double avg = sumf / (double)total_count;
    FD_TEST( fd_cstr_printf_check( avg_buf, sizeof( avg_buf ), NULL, "%.6f", avg ) );
  } else {
    FD_TEST( fd_cstr_printf_check( sum_buf, sizeof( sum_buf ), NULL, "%lu", metrics[ offset + FD_HISTF_BUCKET_CNT ] ));
  }

  printf( " +---------------------+--------------------+---------------+\n" );
  printf( " | Sum: %-14s | Count: %-11lu | Avg: %-8s |\n", sum_buf, total_count, avg_buf );
  printf( " +---------------------+--------------------+---------------+\n" );
}



static void
repair_cmd_fn( args_t *   args,
               config_t * config ) {

  FD_LOG_NOTICE(( "Repair profiler topo" ));

  memset( &config->topo, 0, sizeof(config->topo) );
  repair_topo( config );

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles[ i ];
    if( FD_UNLIKELY( !strcmp( tile->name, "scap" ) ) ) {
      /* This is not part of the config, and it must be set manually
         on purpose as a safety mechanism. */
      tile->shredcap.enable_publish_stake_weights = 1;
      strncpy( tile->shredcap.manifest_path, args->repair.manifest_path, PATH_MAX );
    }
  }

  FD_LOG_NOTICE(( "Repair profiler init" ));
  fd_topo_print_log( 1, &config->topo );

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  for( ulong i=0UL; STAGES[ i ]; i++ ) {
    configure_args.configure.stages[ i ] = STAGES[ i ];
  }
  configure_cmd_fn( &configure_args, config );
  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_xdp_fds_t fds = fd_topo_install_xdp( &config->topo, config->net.bind_address_parsed );
    (void)fds;
  }

  run_firedancer_init( config, 1, 0 );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_fill( &config->topo );

  ulong repair_tile_idx = fd_topo_find_tile( &config->topo, "repair", 0UL );
  FD_TEST( repair_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * repair_tile = &config->topo.tiles[ repair_tile_idx ];

  ulong shred_tile_idx = fd_topo_find_tile( &config->topo, "shred", 0UL );
  FD_TEST( shred_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * shred_tile = &config->topo.tiles[ shred_tile_idx ];

  volatile ulong * shred_metrics = fd_metrics_tile( shred_tile->metrics );
  FD_TEST( shred_metrics );

  volatile ulong * repair_metrics = fd_metrics_tile( repair_tile->metrics );
  FD_TEST( repair_metrics );

  FD_LOG_NOTICE(( "Repair profiler run" ));

  ulong shred_repair_link_idx = fd_topo_find_link( &config->topo, "shred_repair", 0UL );
  FD_TEST( shred_repair_link_idx!=ULONG_MAX );
  fd_topo_link_t * shred_repair_link = &config->topo.links[ shred_repair_link_idx ];
  FD_TEST( shred_repair_link );
  fd_frag_meta_t * shred_repair_mcache = shred_repair_link->mcache;

  ulong turbine_slot0 = 0;

  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, fdctl_tile_run );
  for(;;) { /* collect metrics */

    if( FD_UNLIKELY( !turbine_slot0 ) ) {
      fd_frag_meta_t * frag = &shred_repair_mcache[1]; /* hack to get first frag */
      if ( frag->sz > 0 ) {
        turbine_slot0 = fd_disco_shred_repair_shred_sig_slot( frag->sig );
        FD_LOG_NOTICE(("turbine_slot0: %lu", turbine_slot0));
      }
    }

    char buf2[ 64 ];
    ulong rcvd = shred_metrics [ MIDX( COUNTER, SHRED,  SHRED_REPAIR_RCV ) ];
    ulong sent = repair_metrics[ MIDX( COUNTER, REPAIR, SHRED_REPAIR_REQ ) ];
    printf(" Requests received: (%lu/%lu) %.1f%% \n", rcvd, sent, (double)rcvd / (double)sent * 100.0 );
    printf( " +---------------+--------------+\n" );
    printf( " | Request Type  | Count        |\n" );
    printf( " +---------------+--------------+\n" );
    printf( " | Orphan        | %s |\n", fmt_count( buf2, repair_metrics[ MIDX( COUNTER, REPAIR, SENT_PKT_TYPES_NEEDED_ORPHAN         ) ] ) );
    printf( " | HighestWindow | %s |\n", fmt_count( buf2, repair_metrics[ MIDX( COUNTER, REPAIR, SENT_PKT_TYPES_NEEDED_HIGHEST_WINDOW ) ] ) );
    printf( " | Index         | %s |\n", fmt_count( buf2, repair_metrics[ MIDX( COUNTER, REPAIR, SENT_PKT_TYPES_NEEDED_WINDOW         ) ] ) );
    printf( " +---------------+--------------+\n" );

    print_histogram_buckets( repair_metrics,
                             MIDX( HISTOGRAM, REPAIR, RESPONSE_LATENCY ),
                             FD_METRICS_CONVERTER_NONE,
                             FD_METRICS_HISTOGRAM_REPAIR_RESPONSE_LATENCY_MIN,
                             FD_METRICS_HISTOGRAM_REPAIR_RESPONSE_LATENCY_MAX,
                             "Response Latency" );

    printf(" Repaired slots: %lu/%lu  (slots behind: %lu)\n", repair_metrics[ MIDX( COUNTER, REPAIR, REPAIRED_SLOTS ) ], turbine_slot0, turbine_slot0 - repair_metrics[ MIDX( COUNTER, REPAIR, REPAIRED_SLOTS ) ] );
    /* Print histogram buckets similar to Prometheus format */
    print_histogram_buckets( repair_metrics,
                             MIDX( HISTOGRAM, REPAIR, SLOT_COMPLETE_TIME ),
                             FD_METRICS_CONVERTER_SECONDS,
                             FD_METRICS_HISTOGRAM_REPAIR_SLOT_COMPLETE_TIME_MIN,
                             FD_METRICS_HISTOGRAM_REPAIR_SLOT_COMPLETE_TIME_MAX,
                             "Slot Complete Time" );

    printf( " Repair Peers: %lu\n", repair_metrics[ MIDX( COUNTER, REPAIR, REQUEST_PEERS ) ] );

    printf("\n");
    fflush( stdout );

    sleep( 1 );
  }
}

action_t fd_action_repair = {
  .name = "repair",
  .args = repair_cmd_args,
  .fn   = repair_cmd_fn,
  .perm = dev_cmd_perm,
};
