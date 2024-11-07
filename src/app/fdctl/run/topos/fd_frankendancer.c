#include "../../fdctl.h"

#include "../../../../disco/tiles.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../util/tile/fd_tile_private.h"
#include "../../../../util/shmem/fd_shmem_private.h"

void
fd_topo_initialize( config_t * config ) {
  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  ulong resolv_tile_cnt = config->layout.resolv_tile_count;
  ulong bank_tile_cnt   = config->layout.bank_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };

  /*             topo, name */
  fd_topob_wksp( topo, "net_quic"     );
  fd_topob_wksp( topo, "net_shred"    );
  fd_topob_wksp( topo, "quic_verify"  );
  fd_topob_wksp( topo, "verify_dedup" );
  fd_topob_wksp( topo, "dedup_resolv" );
  fd_topob_wksp( topo, "resolv_pack"  );
  fd_topob_wksp( topo, "pack_bank"    );
  fd_topob_wksp( topo, "bank_poh"     );
  fd_topob_wksp( topo, "bank_busy"    );
  fd_topob_wksp( topo, "poh_shred"    );
  fd_topob_wksp( topo, "gossip_dedup" );
  fd_topob_wksp( topo, "shred_store"  );
  fd_topob_wksp( topo, "stake_out"    );
  fd_topob_wksp( topo, "metric_in"    );

  fd_topob_wksp( topo, "shred_sign"   );
  fd_topob_wksp( topo, "sign_shred"   );

  fd_topob_wksp( topo, "net"          );
  fd_topob_wksp( topo, "quic"         );
  fd_topob_wksp( topo, "verify"       );
  fd_topob_wksp( topo, "dedup"        );
  fd_topob_wksp( topo, "resolv"       );
  fd_topob_wksp( topo, "pack"         );
  fd_topob_wksp( topo, "bank"         );
  fd_topob_wksp( topo, "poh"          );
  fd_topob_wksp( topo, "shred"        );
  fd_topob_wksp( topo, "store"        );
  fd_topob_wksp( topo, "sign"         );
  fd_topob_wksp( topo, "metric"       );
  fd_topob_wksp( topo, "cswtch"       );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /*                                  topo, link_name,      wksp_name,      is_reasm, depth,                                    mtu,                    burst */
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_quic",     "net_quic",     0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_shred",    "net_shred",    0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  1,        config->tiles.verify.receive_buffer_size, 0UL,                    config->tiles.quic.txn_reassembly_count );
  FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", 0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /* gossip_dedup could be FD_TPU_MTU, since txns are not parsed, but better to just share one size for all the ins of dedup */
  /**/                 fd_topob_link( topo, "gossip_dedup", "gossip_dedup", 0,        2048UL,                                   FD_TPU_DCACHE_MTU,      1UL );
  /* dedup_pack is large currently because pack can encounter stalls when running at very high throughput rates that would
     otherwise cause drops. */
  /**/                 fd_topob_link( topo, "dedup_resolv", "dedup_resolv", 0,        65536UL,                                  FD_TPU_DCACHE_MTU,      1UL );
  FOR(resolv_tile_cnt) fd_topob_link( topo, "resolv_pack",  "resolv_pack",  0,        65536UL,                                  FD_TPU_RESOLVED_DCACHE_MTU, 1UL );
  /**/                 fd_topob_link( topo, "stake_out",    "stake_out",    0,        128UL,                                    40UL + 40200UL * 40UL,  1UL );
  /* pack_bank is shared across all banks, so if one bank stalls due to complex transactions, the buffer neeeds to be large so that
     other banks can keep proceeding. */
  /**/                 fd_topob_link( topo, "pack_bank",    "pack_bank",    0,        65536UL,                                  USHORT_MAX,             1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "bank_poh",     "bank_poh",     0,        128UL,                                    USHORT_MAX,             1UL );
  /**/                 fd_topob_link( topo, "poh_pack",     "bank_poh",     0,        128UL,                                    sizeof(fd_became_leader_t), 1UL );
  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    0,        16384UL,                                  USHORT_MAX,             1UL );
  /**/                 fd_topob_link( topo, "crds_shred",   "poh_shred",    0,        128UL,                                    8UL  + 40200UL * 38UL,  1UL );
  /**/                 fd_topob_link( topo, "replay_resol", "bank_poh",     0,        128UL,                                    sizeof(fd_completed_bank_t), 1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_store",  "shred_store",  0,        16384UL,                                  4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   0,        128UL,                                    32UL,                   1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   0,        128UL,                                    64UL,                   1UL );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  int is_auto_affinity = !strcmp( config->layout.affinity, "auto" );
  int is_agave_auto_affinity = !strcmp( config->layout.agave_affinity, "auto" );
  int is_bench_auto_affinity = !strcmp( config->development.bench.affinity, "auto" );

  if( FD_UNLIKELY( is_auto_affinity != is_agave_auto_affinity ||
                   is_auto_affinity != is_bench_auto_affinity ) ) {
    FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity], [layout.agave_affinity], and [development.bench.affinity] must all be set to 'auto' or all be set to a specific CPU affinity string." ));
  }

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=fd_numa_cpu_cnt() ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], fd_numa_cpu_cnt() ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  /*                                  topo, tile_name, tile_wksp, metrics_wksp, cpu_idx,                       is_agave */
  FOR(net_tile_cnt)    fd_topob_tile( topo, "net",     "net",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
  FOR(quic_tile_cnt)   fd_topob_tile( topo, "quic",    "quic",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
  FOR(verify_tile_cnt) fd_topob_tile( topo, "verify",  "verify",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
  /**/                 fd_topob_tile( topo, "dedup",   "dedup",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
  FOR(resolv_tile_cnt) fd_topob_tile( topo, "resolv",  "resolv",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1 );
  /**/                 fd_topob_tile( topo, "pack",    "pack",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
  FOR(bank_tile_cnt)   fd_topob_tile( topo, "bank",    "bank",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1 );
  /**/                 fd_topob_tile( topo, "poh",     "poh",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1 );
  FOR(shred_tile_cnt)  fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
  /**/                 fd_topob_tile( topo, "store",   "store",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1 );
  /**/                 fd_topob_tile( topo, "sign",    "sign",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
  /**/                 fd_topob_tile( topo, "metric",  "metric",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
  /**/                 fd_topob_tile( topo, "cswtch",  "cswtch",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );

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

    if( FD_LIKELY( strcmp( "", config->layout.agave_affinity ) ) ) {
      ushort agave_cpu[ FD_TILE_MAX ];
      ulong agave_cpu_cnt = fd_tile_private_cpus_parse( config->layout.agave_affinity, agave_cpu );

      for( ulong i=0UL; i<agave_cpu_cnt; i++ ) {
        if( FD_UNLIKELY( agave_cpu[ i ]>=fd_numa_cpu_cnt() ) )
          FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.agave_affinity] specifies a CPU index of %hu, but the system "
                       "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                       "in the system.",
                       agave_cpu[ i ], fd_numa_cpu_cnt() ));

        for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
          fd_topo_tile_t * tile = &topo->tiles[ j ];
          if( tile->cpu_idx==agave_cpu[ i ] ) FD_LOG_WARNING(( "Tile `%s:%lu` is already assigned to CPU %hu, but the CPU is also assigned to Agave. "
                                                               "This may cause contention between the two tiles.", tile->name, tile->kind_id, agave_cpu[ i ] ));
        }

        if( FD_UNLIKELY( topo->agave_affinity_cnt>FD_TILE_MAX ) ) {
          FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.agave_affinity] specifies more CPUs than Firedancer can use. "
                        "You should either reduce the number of CPUs in the affinity string." ));
        }
        topo->agave_affinity_cpu_idx[ topo->agave_affinity_cnt++ ] = agave_cpu[ i ];
      }
    }
  }

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  FOR(net_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "net",     i,            "metric_in", "quic_net",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt) for( ulong j=0UL; j<shred_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "net",     i,            "metric_in", "shred_net",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",     i,                         "net_quic",     i                                                  );
  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",     i,                         "net_shred",    i                                                  );

  FOR(quic_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "quic",    i,            "metric_in", "net_quic",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_verify",  i                                                  );
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_net",     i                                                  );
  /* All verify tiles read from all QUIC tiles, packets are round robin. */
  FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "verify",  i,            "metric_in", "quic_verify",  j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
  FOR(verify_tile_cnt) fd_topob_tile_out( topo, "verify",  i,                         "verify_dedup", i                                                  );
  /* Declare the single gossip link before the variable length verify-dedup links so we could have a compile-time index to the gossip link. */
  /**/                 fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "gossip_dedup", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "verify_dedup", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "dedup",   0UL,                       "dedup_resolv", 0UL                                                );
  FOR(resolv_tile_cnt) fd_topob_tile_in(  topo, "resolv",  i,            "metric_in", "dedup_resolv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_in(  topo, "resolv",  i,            "metric_in", "replay_resol", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_out( topo, "resolv",  i,                         "resolv_pack",  i                                                  );
  /**/                 fd_topob_tile_in(  topo, "pack",    0UL,          "metric_in", "resolv_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /* The PoH to pack link is reliable, and must be.  The fragments going
     across here are "you became leader" which pack must respond to
     by publishing microblocks, otherwise the leader TPU will hang
     forever.

     It's marked as unreliable since otherwise we have a reliable credit
     loop which will also starve the pack tile.  This is OK because we
     will never send more than one leader message until the pack tile
     must acknowledge it with a packing done frag, so there will be at
     most one in flight at any time. */
  /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "poh_pack",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
                       fd_topob_tile_out( topo, "pack",   0UL,                        "pack_bank",    0UL                                                );
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "bank",   i,             "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(bank_tile_cnt)   fd_topob_tile_out( topo, "bank",   i,                          "bank_poh",     i                                                  );
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  if( FD_LIKELY( config->tiles.pack.use_consumed_cus ) )
    FOR(bank_tile_cnt) fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "bank_poh",     i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "poh_shred",    0UL                                                );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "poh_pack",     0UL                                                );
  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "net_shred",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "poh_shred",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "crds_shred",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_store",  i                                                  );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_net",    i                                                  );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "store",  0UL,           "metric_in", "shred_store",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by the mux, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "shred_sign",     i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "shred",  i,                          "shred_sign",     i                                                  );
    /**/               fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "sign_shred",     i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",     i                                                  );
  }

  /* PoH tile represents the Agave address space, so it's
     responsible for publishing Agave provided data to
     these links. */
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "gossip_dedup", 0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "stake_out",    0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "crds_shred",   0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "replay_resol", 0UL                                                );

  /* For now the only plugin consumer is the GUI */
  int plugins_enabled = config->tiles.gui.enabled;
  if( FD_LIKELY( plugins_enabled ) ) {
    fd_topob_wksp( topo, "plugin_in"    );
    fd_topob_wksp( topo, "plugin_out"   );
    fd_topob_wksp( topo, "plugin"       );

    /**/                 fd_topob_link( topo, "plugin_out",   "plugin_out",   0,        128UL,                                    8UL+40200UL*(58UL+12UL*34UL), 1UL );
    /**/                 fd_topob_link( topo, "replay_plugi", "plugin_in",    0,        128UL,                                    4098*8UL,               1UL );
    /**/                 fd_topob_link( topo, "gossip_plugi", "plugin_in",    0,        128UL,                                    8UL+40200UL*(58UL+12UL*34UL), 1UL );
    /**/                 fd_topob_link( topo, "poh_plugin",   "plugin_in",    0,        128UL,                                    16UL,                   1UL );
    /**/                 fd_topob_link( topo, "startp_plugi", "plugin_in",    0,        128UL,                                    56UL,                   1UL );
    /**/                 fd_topob_link( topo, "votel_plugin", "plugin_in",    0,        128UL,                                    8UL,                    1UL );

    /**/                 fd_topob_tile( topo, "plugin",  "plugin",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );

    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "replay_plugi", 0UL                                                  );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "gossip_plugi", 0UL                                                  );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "poh_plugin",   0UL                                                  );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "startp_plugi", 0UL                                                  );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "votel_plugin", 0UL                                                  );
    /**/                 fd_topob_tile_out( topo, "plugin", 0UL,                        "plugin_out", 0UL                                                    );

    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "replay_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "gossip_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "poh_plugin",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "startp_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "votel_plugin", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  if( FD_LIKELY( config->tiles.gui.enabled ) ) {
    fd_topob_wksp( topo, "gui"          );
    /**/                 fd_topob_tile( topo, "gui",     "gui",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0 );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "plugin_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

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

    if( FD_LIKELY( strcmp( "", config->layout.agave_affinity ) ) ) {
      ushort agave_cpu[ FD_TILE_MAX ];
      ulong agave_cpu_cnt = fd_tile_private_cpus_parse( config->layout.agave_affinity, agave_cpu );

      for( ulong i=0UL; i<agave_cpu_cnt; i++ ) {
        if( FD_UNLIKELY( agave_cpu[ i ]>=fd_numa_cpu_cnt() ) )
          FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.agave_affinity] specifies a CPU index of %hu, but the system "
                       "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                       "in the system.",
                       agave_cpu[ i ], fd_numa_cpu_cnt() ));

        for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
          fd_topo_tile_t * tile = &topo->tiles[ j ];
          if( tile->cpu_idx==agave_cpu[ i ] ) FD_LOG_WARNING(( "Tile `%s:%lu` is already assigned to CPU %hu, but the CPU is also assigned to Agave. "
                                                               "This may cause contention between the two tiles.", tile->name, tile->kind_id, agave_cpu[ i ] ));
        }

        if( FD_UNLIKELY( topo->agave_affinity_cnt>FD_TILE_MAX ) ) {
          FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.agave_affinity] specifies more CPUs than Firedancer can use. "
                        "You should either reduce the number of CPUs in the affinity string." ));
        }
        topo->agave_affinity_cpu_idx[ topo->agave_affinity_cnt++ ] = agave_cpu[ i ];
      }
    }
  }

  /* There is a special fseq that sits between the pack, bank, and poh
     tiles to indicate when the bank/poh tiles are done processing a
     microblock.  Pack uses this to determine when to "unlock" accounts
     that it marked as locked because they were being used. */

  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );

    fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
    fd_topo_tile_t * pack_tile = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
    fd_topob_tile_uses( topo, poh_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, pack_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  /* There's another special fseq that's used to communicate the shred
     version from the Agave boot path to the shred tile. */
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
  fd_topob_tile_uses( topo, poh_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  }
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    if( FD_UNLIKELY( !strcmp( tile->name, "net" ) ) ) {
      strncpy( tile->net.interface,    config->tiles.net.interface, sizeof(tile->net.interface) );
      memcpy(  tile->net.src_mac_addr, config->tiles.net.mac_addr,  6UL );

      tile->net.xdp_aio_depth     = config->tiles.net.xdp_aio_depth;
      tile->net.xdp_rx_queue_size = config->tiles.net.xdp_rx_queue_size;
      tile->net.xdp_tx_queue_size = config->tiles.net.xdp_tx_queue_size;
      tile->net.src_ip_addr       = config->tiles.net.ip_addr;
      tile->net.zero_copy         = !!strcmp( config->tiles.net.xdp_mode, "skb" ); /* disable zc for skb */
      fd_memset( tile->net.xdp_mode, 0, 4 );
      fd_memcpy( tile->net.xdp_mode, config->tiles.net.xdp_mode, strnlen( config->tiles.net.xdp_mode, 3 ) );  /* GCC complains about strncpy */

      tile->net.shred_listen_port              = config->tiles.shred.shred_listen_port;
      tile->net.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->net.legacy_transaction_listen_port = config->tiles.quic.regular_transaction_listen_port;

      /* multihome support */
      ulong multi_cnt = tile->net.multihome_ip_addrs_cnt = config->tiles.net.multihome_ip_addrs_cnt;
      for( ulong j = 0; j < multi_cnt; ++j ) {
        tile->net.multihome_ip_addrs[j] = config->tiles.net.multihome_ip4_addrs[j];
      }
    } else if( FD_UNLIKELY( !strcmp( tile->name, "quic" ) ) ) {
      fd_memcpy( tile->quic.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->quic.identity_key_path, config->consensus.identity_path, sizeof(tile->quic.identity_key_path) );

      tile->quic.depth                          = topo->links[ tile->out_link_id[ 0 ] ].depth;
      tile->quic.reasm_cnt                      = config->tiles.quic.txn_reassembly_count;
      tile->quic.max_concurrent_connections     = config->tiles.quic.max_concurrent_connections;
      tile->quic.max_concurrent_handshakes      = config->tiles.quic.max_concurrent_handshakes;
      tile->quic.max_inflight_quic_packets      = config->tiles.quic.max_inflight_quic_packets;
      tile->quic.ip_addr                        = config->tiles.net.ip_addr;
      tile->quic.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->quic.idle_timeout_millis            = config->tiles.quic.idle_timeout_millis;
      tile->quic.ack_delay_millis               = config->tiles.quic.ack_delay_millis;
      tile->quic.retry                          = config->tiles.quic.retry;
      tile->quic.max_concurrent_streams_per_connection = config->tiles.quic.max_concurrent_streams_per_connection;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "verify" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "dedup" ) ) ) {
      tile->dedup.tcache_depth = config->tiles.dedup.signature_cache_size;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "resolv" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "pack" ) ) ) {
      strncpy( tile->pack.identity_key_path, config->consensus.identity_path, sizeof(tile->pack.identity_key_path) );

      tile->pack.max_pending_transactions      = config->tiles.pack.max_pending_transactions;
      tile->pack.bank_tile_count               = config->layout.bank_tile_count;
      tile->pack.larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
      tile->pack.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
      tile->pack.use_consumed_cus              = config->tiles.pack.use_consumed_cus;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "bank" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "poh" ) ) ) {
      strncpy( tile->poh.identity_key_path, config->consensus.identity_path, sizeof(tile->poh.identity_key_path) );

      tile->poh.plugins_enabled = plugins_enabled;
      tile->poh.bank_cnt = config->layout.bank_tile_count;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ) ) {
      fd_memcpy( tile->shred.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->shred.identity_key_path, config->consensus.identity_path, sizeof(tile->shred.identity_key_path) );

      tile->shred.depth                         = topo->links[ tile->out_link_id[ 0 ] ].depth;
      tile->shred.ip_addr                       = config->tiles.net.ip_addr;
      tile->shred.fec_resolver_depth            = config->tiles.shred.max_pending_shred_sets;
      tile->shred.expected_shred_version        = config->consensus.expected_shred_version;
      tile->shred.shred_listen_port             = config->tiles.shred.shred_listen_port;
      tile->shred.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "store" ) ) ) {
      tile->store.disable_blockstore_from_slot = config->development.bench.disable_blockstore_from_slot;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {
      strncpy( tile->sign.identity_key_path, config->consensus.identity_path, sizeof(tile->sign.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) {
      if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &tile->metric.prometheus_listen_addr ) ) )
        FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
      tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "cswtch" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "gui" ) ) ) {
      if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.gui.gui_listen_address, &tile->gui.listen_addr ) ) )
        FD_LOG_ERR(( "failed to parse gui listen address `%s`", config->tiles.gui.gui_listen_address ));
      tile->gui.listen_port = config->tiles.gui.gui_listen_port;
      tile->gui.is_voting = strcmp( config->consensus.vote_account_path, "" );
      strncpy( tile->gui.cluster, config->cluster, sizeof(tile->gui.cluster) );
      strncpy( tile->gui.identity_key_path, config->consensus.identity_path, sizeof(tile->gui.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "plugin" ) ) ) {

    } else {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }
  }

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo );

  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
  config->topo = *topo;
}
