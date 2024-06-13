/* Firedancer topology used for testing the full validator.
   Associated test script: test_firedancer.sh */
#include "topos.h"
#include "../../fdctl.h"
#include "../../../../disco/tiles.h"
#include "../../fdctl.h"
#include "../../config.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../funk/fd_funk.h"
#include "../../../../util/tile/fd_tile_private.h"
#include <sys/sysinfo.h>
#include "../tiles/fd_replay_notif.h"

void
fd_topo_firedancer( config_t * _config ) {
  config_t * config = (config_t *)_config;

  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;

  ulong replay_tpool_thread_count = config->tiles.replay.tpool_thread_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };

  /*             topo, name */
  fd_topob_wksp( topo, "net_shred"  );
  fd_topob_wksp( topo, "net_gossip" );
  fd_topob_wksp( topo, "net_repair" );
  fd_topob_wksp( topo, "net_quic"   );

  fd_topob_wksp( topo, "quic_verify"  );
  fd_topob_wksp( topo, "verify_dedup" );
  fd_topob_wksp( topo, "dedup_pack"   );

  fd_topob_wksp( topo, "shred_storei" );
  fd_topob_wksp( topo, "stake_out"    );
  fd_topob_wksp( topo, "metric_in"    );

  fd_topob_wksp( topo, "poh_shred" );

  fd_topob_wksp( topo, "quic_sign" );
  fd_topob_wksp( topo, "sign_quic" );

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
  fd_topob_wksp( topo, "replay_notif" );
  fd_topob_wksp( topo, "bank_busy"  );
  fd_topob_wksp( topo, "pack_replay"  );

  fd_topob_wksp( topo, "net"        );
  fd_topob_wksp( topo, "quic"       );
  fd_topob_wksp( topo, "verify"     );
  fd_topob_wksp( topo, "dedup"      );
  fd_topob_wksp( topo, "shred"      );
  fd_topob_wksp( topo, "pack"       );
  fd_topob_wksp( topo, "storei"     );
  fd_topob_wksp( topo, "sign"       );
  fd_topob_wksp( topo, "repair"     );
  fd_topob_wksp( topo, "gossip"     );
  fd_topob_wksp( topo, "metric"     );
  fd_topob_wksp( topo, "replay"     );
  fd_topob_wksp( topo, "thread"     );
  fd_topob_wksp( topo, "bhole"      );
  fd_topob_wksp( topo, "bstore"     );
  fd_topob_wksp( topo, "funk"       );
  fd_topob_wksp( topo, "pohi"       );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /*                                  topo, link_name,      wksp_name,      is_reasm, depth,                                    mtu,                           burst */
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_gossip",   "net_gossip",   0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_repair",   "net_repair",   0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_quic",     "net_quic",     0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_shred",    "net_shred",    0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,                    1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  1,        config->tiles.verify.receive_buffer_size, 0UL,                           config->tiles.quic.txn_reassembly_count );
  FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", 0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,             1UL );
  /**/                 fd_topob_link( topo, "dedup_pack",   "dedup_pack",   0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,             1UL );

  /**/                 fd_topob_link( topo, "stake_out",    "stake_out",    0,        128UL,                                    32UL + 40200UL * 40UL,         1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_storei", "shred_storei", 0,        65536UL,                                  4UL*FD_SHRED_STORE_MTU,        4UL+config->tiles.shred.max_pending_shred_sets );

  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_sign",    "quic_sign",    0,        128UL,                                    130UL,                         1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "sign_quic",    "sign_quic",    0,        128UL,                                    64UL,                          1UL );
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
  /**/                 fd_topob_link( topo, "store_replay", "store_replay", 0,        128UL,                                    FD_SHRED_MAX_PER_SLOT * FD_SHRED_MAX_SZ, 16UL  );
  /**/                 fd_topob_link( topo, "replay_poh",   "replay_poh",   0,        128UL,                                    128UL*1024UL*1024UL,           16UL  );
  /**/                 fd_topob_link( topo, "replay_notif", "replay_notif", 0,        FD_REPLAY_NOTIF_DEPTH,                    FD_REPLAY_NOTIF_MTU,           1UL   );

  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    0,        128UL,                                    FD_NET_MTU,                    1UL   );
  /**/                 fd_topob_link( topo, "pack_replay",  "pack_replay",  0,        128UL,                                    USHORT_MAX,                    1UL   );
  /**/                 fd_topob_link( topo, "poh_pack",     "replay_poh",   0,        128UL,                                    sizeof(fd_became_leader_t),    1UL   );

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

  /*                                              topo, tile_name, tile_wksp, cnc_wksp,    metrics_wksp, cpu_idx,                       is_labs, out_link,       out_link_kind_id */
  FOR(net_tile_cnt)                fd_topob_tile( topo, "net",     "net",     "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  FOR(quic_tile_cnt)               fd_topob_tile( topo, "quic",    "quic",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "quic_verify",  i   );
  FOR(verify_tile_cnt)             fd_topob_tile( topo, "verify",  "verify",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "verify_dedup", i   );
  /**/                             fd_topob_tile( topo, "dedup",   "dedup",   "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "dedup_pack",   0UL );
  FOR(shred_tile_cnt)              fd_topob_tile( topo, "shred",   "shred",   "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "shred_storei", i   );
  /**/                             fd_topob_tile( topo, "gossip",  "gossip",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "gossip_net",   0UL );
  /**/                             fd_topob_tile( topo, "repair",  "repair",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "repair_store", 0UL );
  /**/                             fd_topob_tile( topo, "storei",  "storei",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                             fd_topob_tile( topo, "replay",  "replay",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "stake_out",    0UL );
  /* These thread tiles must be defined immediately after the replay tile.  We subtract one because the replay tile acts as a thread in the tpool as well. */
  FOR(replay_tpool_thread_count-1) fd_topob_tile( topo, "thread",  "thread",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                             fd_topob_tile( topo, "bhole",   "bhole",   "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                             fd_topob_tile( topo, "sign",    "sign",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                             fd_topob_tile( topo, "metric",  "metric",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                             fd_topob_tile( topo, "pack",    "pack",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "pack_replay",  0UL );
  /**/                             fd_topob_tile( topo, "pohi",    "pohi",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "poh_shred",    0UL );

  fd_topo_tile_t * store_tile  = &topo->tiles[ fd_topo_find_tile( topo, "storei",  0UL ) ];
  fd_topo_tile_t * replay_tile = &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ];
  fd_topo_tile_t * repair_tile = &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ];

  /* Create a shared blockstore to be used by store and replay. */
  fd_topo_obj_t * blockstore_obj = fd_topob_obj_concrete( topo, "blockstore", "bstore", fd_blockstore_align(), fd_blockstore_footprint(), 32UL * FD_SHMEM_GIGANTIC_PAGE_SZ );
  fd_topob_tile_uses( topo, store_tile,  blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, repair_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_obj->id, "blockstore" ) );

  /* Create a shared blockstore to be used by replay. */
  fd_topo_obj_t * funk_obj = fd_topob_obj_concrete( topo, "funk", "funk", fd_funk_align(), fd_funk_footprint(), config->tiles.replay.funk_sz_gb * FD_SHMEM_GIGANTIC_PAGE_SZ );
  fd_topob_tile_uses( topo, replay_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  FD_TEST( fd_pod_insertf_ulong( topo->props, funk_obj->id, "funk" ) );

  fd_topo_tile_t * pack_tile = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
  fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );
  fd_topob_tile_uses( topo, replay_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, pack_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", 0UL ) );

  /* There's another special fseq that's used to communicate the shred
     version from the Solana Labs boot path to the shred tile. */
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "gossip", 0UL ) ];
  fd_topob_tile_uses( topo, poh_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_tile_uses( topo, store_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  }
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );

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
  
  FOR(net_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "net",     i,            "metric_in", "quic_net",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "quic",    i,            "metric_in", "net_quic",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_net",     i                                                  );
  /* All verify tiles read from all QUIC tiles, packets are round robin. */
  FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "verify",  i,            "metric_in", "quic_verify",  j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
  FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "verify_dedup", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "net",     i,            "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "net",     i,            "metric_in", "repair_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",     i,                         "net_quic",    i                                                  );

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
  for( ulong i=0UL; i<quic_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "quic_sign",      i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "quic",     i,                        "quic_sign",      i                                                  );
    /**/               fd_topob_tile_in(  topo, "quic",     i,           "metric_in", "sign_quic",      i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_quic",      i                                                  );
  }

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "shred_sign",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "shred",  i,                          "shred_sign",    i                                                    );
    /**/               fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "sign_shred",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",    i                                                    );
  }

  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",      i,                         "net_gossip",   i                                                    );
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
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                       "replay_poh",    0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                      "replay_notif",   0UL                                                  );
  /**/                 fd_topob_tile_in(  topo, "replay",  0UL,          "metric_in", "pack_replay",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "gossip_pack",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "bhole",  0UL,           "metric_in", "replay_notif",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "pohi",  0UL,            "metric_in", "replay_poh",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "pohi",  0UL,            "metric_in", "stake_out",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  
  /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "dedup_pack",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "pohi",  0UL,            "metric_in", "pack_replay",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "poh_pack",      0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
                       fd_topob_tile_out( topo, "pohi",   0UL,                        "poh_pack",      0UL                                                );

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
      tile->net.zero_copy                      = !!strcmp( config->tiles.net.xdp_mode, "skb" ); /* disable zc for skb */

      tile->net.shred_listen_port              = config->tiles.shred.shred_listen_port;
      tile->net.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->net.legacy_transaction_listen_port = config->tiles.quic.regular_transaction_listen_port;
      tile->net.gossip_listen_port             = config->gossip.port;
      tile->net.repair_intake_listen_port      = config->tiles.repair.repair_intake_listen_port;
      tile->net.repair_serve_listen_port       = config->tiles.repair.repair_serve_listen_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "netmux" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "quic" ) ) ) {
      fd_memcpy( tile->quic.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->quic.identity_key_path, config->consensus.identity_path, sizeof(tile->quic.identity_key_path) );

      tile->quic.depth                          = topo->links[ tile->out_link_id_primary ].depth;
      tile->quic.reasm_cnt                      = config->tiles.quic.txn_reassembly_count;
      tile->quic.max_concurrent_connections     = config->tiles.quic.max_concurrent_connections;
      tile->quic.max_concurrent_handshakes      = config->tiles.quic.max_concurrent_handshakes;
      tile->quic.max_inflight_quic_packets      = config->tiles.quic.max_inflight_quic_packets;
      tile->quic.tx_buf_size                    = config->tiles.quic.tx_buf_size;
      tile->quic.ip_addr                        = config->tiles.net.ip_addr;
      tile->quic.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->quic.idle_timeout_millis            = config->tiles.quic.idle_timeout_millis;
      tile->quic.retry                          = config->tiles.quic.retry;
      tile->quic.max_concurrent_streams_per_connection = config->tiles.quic.max_concurrent_streams_per_connection;
      tile->quic.stream_pool_cnt                = config->tiles.quic.stream_pool_cnt;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "verify" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "dedup" ) ) ) {
      tile->dedup.tcache_depth = config->tiles.dedup.signature_cache_size;

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
    } else if( FD_UNLIKELY( !strcmp( tile->name, "gossip" ) ) ) {
      tile->gossip.ip_addr = config->tiles.net.ip_addr;
      memcpy( tile->gossip.src_mac_addr, config->tiles.net.mac_addr, 6UL );
      strncpy( tile->gossip.identity_key_path, config->consensus.identity_path, sizeof(tile->gossip.identity_key_path) );
      tile->gossip.gossip_listen_port =  config->gossip.port;
      FD_TEST( config->gossip.port == config->tiles.gossip.gossip_listen_port );
      tile->gossip.tvu_port = config->tiles.shred.shred_listen_port;
      tile->gossip.tvu_fwd_port = config->tiles.shred.shred_listen_port + 6;
      tile->gossip.expected_shred_version = config->consensus.expected_shred_version;
      tile->gossip.tpu_port = config->tiles.quic.regular_transaction_listen_port;
      tile->gossip.tpu_vote_port = config->tiles.quic.regular_transaction_listen_port;
      FD_TEST( config->tiles.gossip.entrypoints_cnt == config->tiles.gossip.peer_ports_cnt );
      tile->gossip.entrypoints_cnt = config->tiles.gossip.entrypoints_cnt;
      for (ulong i=0UL; i<config->tiles.gossip.entrypoints_cnt; i++) {
        if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.gossip.entrypoints[i], &tile->gossip.entrypoints[i] ) ) ) {
          FD_LOG_ERR(( "configuration specifies invalid gossip peer IP address `%s`", config->tiles.gossip.entrypoints[i] ));
        }
        tile->gossip.entrypoint_ports[i] = (ushort)config->tiles.gossip.peer_ports[i];
      }

    } else if( FD_UNLIKELY( !strcmp( tile->name, "repair" ) ) ) {
      tile->repair.repair_intake_listen_port =  config->tiles.repair.repair_intake_listen_port;
      tile->repair.repair_serve_listen_port =   config->tiles.repair.repair_serve_listen_port;
      tile->repair.ip_addr = config->tiles.net.ip_addr;

      memcpy( tile->repair.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->repair.identity_key_path, config->consensus.identity_path, sizeof(tile->repair.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "replay" ) )) {
      strncpy( tile->replay.snapshot, config->tiles.replay.snapshot, sizeof(tile->replay.snapshot) );
      strncpy( tile->replay.incremental, config->tiles.replay.incremental, sizeof(tile->replay.incremental) );
      strncpy( tile->replay.capture, config->tiles.replay.capture, sizeof(tile->replay.capture) );
      tile->replay.snapshot_slot = ULONG_MAX; /* Determine when we load the snapshot */
      tile->replay.tpool_thread_count =  config->tiles.replay.tpool_thread_count;

      tile->replay.pages     = config->tiles.replay.funk_sz_gb;
      tile->replay.txn_max   = config->tiles.replay.funk_txn_max;
      tile->replay.index_max = config->tiles.replay.funk_rec_max;

      if( FD_UNLIKELY( tile->replay.tpool_thread_count == 0 || tile->replay.tpool_thread_count>FD_TILE_MAX ) )
        FD_LOG_ERR(( "bad tpool_thread_count %lu", tile->replay.tpool_thread_count ));
    } else if( FD_UNLIKELY( !strcmp( tile->name, "bhole" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {
      strncpy( tile->sign.identity_key_path, config->consensus.identity_path, sizeof(tile->sign.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) {
      tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "thread" ) ) ) {
      /* Nothing for now */
    } else if( FD_UNLIKELY( !strcmp( tile->name, "pack" ) ) ) {
      strncpy( tile->pack.identity_key_path, config->consensus.identity_path, sizeof(tile->pack.identity_key_path) );

      tile->pack.max_pending_transactions      = config->tiles.pack.max_pending_transactions;
      tile->pack.bank_tile_count               = config->layout.bank_tile_count;
      tile->pack.larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
      tile->pack.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
    } else if( FD_UNLIKELY( !strcmp( tile->name, "pohi" ) ) ) {
      strncpy( tile->poh.identity_key_path, config->consensus.identity_path, sizeof(tile->poh.identity_key_path) );

      tile->poh.bank_cnt = config->layout.bank_tile_count;
    } else {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }
  }

  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );

  const char * snapshot = config->tiles.replay.snapshot;
  if ( strncmp(snapshot, "wksp:", 5) == 0 ) {
    /* Make the funk workspace match the parameters used to create the
       checkpoint. This is a bit nonintuitive because of the way
       fd_topo_create_workspace works. */
    uint seed;
    ulong part_max;
    ulong data_max;
    int err = fd_wksp_restore_preview( snapshot+5, &seed, &part_max, &data_max );
    if( err ) FD_LOG_ERR(( "unable to restore %s: error %d", snapshot, err ));
    fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ funk_obj->id ].wksp_id ];
    wksp->part_max = part_max;
    wksp->known_footprint = 0;
    wksp->total_footprint = data_max;
    ulong page_sz = FD_SHMEM_GIGANTIC_PAGE_SZ;
    wksp->page_sz = page_sz;
    ulong footprint = fd_wksp_footprint( part_max, data_max );
    wksp->page_cnt = footprint / page_sz;
  }

  config->topo = *topo;
}
