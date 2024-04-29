#include "topos.h"
#include "../tiles/tiles.h"
#include "../../config.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../util/tile/fd_tile_private.h"
#include <sys/sysinfo.h>


void
topo_configure_frankendancer( config_t * config ) { 
  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  ulong bank_tile_cnt   = config->layout.bank_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;

  fd_topo_t * topo = fd_topob_new( &config->topo, config->name );

  /*             topo, name */
  fd_topob_wksp( topo, "net_quic" );
  fd_topob_wksp( topo, "net_shred" );
  fd_topob_wksp( topo, "quic_verify"  );
  fd_topob_wksp( topo, "verify_dedup" );
  fd_topob_wksp( topo, "dedup_pack"   );
  fd_topob_wksp( topo, "pack_bank"    );
  fd_topob_wksp( topo, "bank_poh"     );
  fd_topob_wksp( topo, "bank_busy"    );
  fd_topob_wksp( topo, "poh_shred"    );
  fd_topob_wksp( topo, "shred_store"  );
  fd_topob_wksp( topo, "stake_out"    );
  fd_topob_wksp( topo, "metric_in"    );

  fd_topob_wksp( topo, "quic_sign"  );
  fd_topob_wksp( topo, "sign_quic"  );
  fd_topob_wksp( topo, "shred_sign" );
  fd_topob_wksp( topo, "sign_shred" );

  fd_topob_wksp( topo, "net"    );
  fd_topob_wksp( topo, "quic"   );
  fd_topob_wksp( topo, "verify" );
  fd_topob_wksp( topo, "dedup"  );
  fd_topob_wksp( topo, "pack"   );
  fd_topob_wksp( topo, "bank"   );
  fd_topob_wksp( topo, "poh"    );
  fd_topob_wksp( topo, "shred"  );
  fd_topob_wksp( topo, "store"  );
  fd_topob_wksp( topo, "sign"   );
  fd_topob_wksp( topo, "metric" );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /*                                  topo, link_name,      wksp_name,      is_reasm, depth,                                    mtu,                    burst */
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_quic",     "net_quic",     0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(net_tile_cnt)    fd_topob_link( topo, "net_shred",    "net_shred",    0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    0,        config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  1,        config->tiles.verify.receive_buffer_size, 0UL,                    config->tiles.quic.txn_reassembly_count );
  FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", 0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /**/                 fd_topob_link( topo, "dedup_pack",   "dedup_pack",   0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /* gossip_pack could be FD_TPU_MTU for now, since txns are not parsed, but better to just share one size for all the ins of pack */
  /**/                 fd_topob_link( topo, "gossip_pack",  "dedup_pack",   0,        config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /**/                 fd_topob_link( topo, "stake_out",    "stake_out",    0,        128UL,                                    32UL + 40200UL * 40UL,  1UL );
  /**/                 fd_topob_link( topo, "pack_bank",    "pack_bank",    0,        128UL,                                    USHORT_MAX,             1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "bank_poh",     "bank_poh",     0,        128UL,                                    USHORT_MAX,             1UL );
  /**/                 fd_topob_link( topo, "poh_pack",     "bank_poh",     0,        128UL,                                    sizeof(fd_became_leader_t), 1UL );
  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    0,        16384UL,                                  USHORT_MAX,             1UL );
  /**/                 fd_topob_link( topo, "crds_shred",   "poh_shred",    0,        128UL,                                    8UL  + 40200UL * 38UL,  1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_store",  "shred_store",  0,        65536UL,                                  4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );

  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_sign",    "quic_sign",    0,        128UL,                                    130UL,                  1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "sign_quic",    "sign_quic",    0,        128UL,                                    64UL,                   1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   0,        128UL,                                    32UL,                   1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   0,        128UL,                                    64UL,                   1UL );

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
  FOR(quic_tile_cnt)   fd_topob_tile( topo, "quic",    "quic",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "quic_verify",  i   );
  FOR(verify_tile_cnt) fd_topob_tile( topo, "verify",  "verify",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "verify_dedup", i   );
  /**/                 fd_topob_tile( topo, "dedup",   "dedup",   "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "dedup_pack",   0UL );
  /**/                 fd_topob_tile( topo, "pack",    "pack",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "pack_bank",    0UL );
  FOR(bank_tile_cnt)   fd_topob_tile( topo, "bank",    "bank",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1,       "bank_poh",     i   );
  /**/                 fd_topob_tile( topo, "poh",     "poh",     "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1,       "poh_shred",    0UL );
  FOR(shred_tile_cnt)  fd_topob_tile( topo, "shred",   "shred",   "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       "shred_store",  i   );
  /**/                 fd_topob_tile( topo, "store",   "store",   "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1,       NULL,           0UL );
  /**/                 fd_topob_tile( topo, "sign",    "sign",    "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                 fd_topob_tile( topo, "metric",  "metric",  "metric_in", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );

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

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  FOR(net_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "net",     i,            "metric_in", "quic_net",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt) for( ulong j=0UL; j<shred_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "net",     i,            "metric_in", "shred_net",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",     i,                         "net_quic",     i                                                  );
  FOR(net_tile_cnt)    fd_topob_tile_out( topo, "net",     i,                         "net_shred",    i                                                  );

  FOR(quic_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "quic",    i,            "metric_in", "net_quic",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_net",     i                                                  );
  /* All verify tiles read from all QUIC tiles, packets are round robin. */
  FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "verify",  i,            "metric_in", "quic_verify",  j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
  FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "verify_dedup", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "pack",    0UL,          "metric_in", "dedup_pack",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "pack",    0UL,          "metric_in", "gossip_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
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
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "bank",   i,             "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                       fd_topob_tile_out( topo, "poh",    0UL,                        "poh_pack",     0UL                                                );
  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "net_shred",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "poh_shred",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "crds_shred",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)
                       fd_topob_tile_out( topo, "shred",  i,                          "shred_net",    i                                                  );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "store",  0UL,           "metric_in", "shred_store",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

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
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "shred_sign",     i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "shred",  i,                          "shred_sign",     i                                                    );
    /**/               fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "sign_shred",     i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",     i                                                    );
  }

  /* PoH tile represents the Solana Labs address space, so it's
     responsible for publishing Solana Labs provided data to
     these links. */
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "gossip_pack",  0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "stake_out",    0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "crds_shred",   0UL                                                  );

  /* There is a special fseq that sits between the pack, bank, an poh
     tiles to indicate when the bank/poh tiles are done processing a
     microblock.  Pack uses this to determine when to "unlock" accounts
     that it marked as locked because they were being used. */

  for( ulong i=0UL; i<bank_tile_cnt; i++ ) { 
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );

    fd_topo_tile_t * bank_tile = &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ];
    fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
    fd_topo_tile_t * pack_tile = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
    fd_topob_tile_uses( topo, bank_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, poh_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, pack_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  /* There's another special fseq that's used to communicate the shred
     version from the Solana Labs boot path to the shred tile. */
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
      strncpy( tile->net.app_name,     config->name,                sizeof(tile->net.app_name) );
      strncpy( tile->net.interface,    config->tiles.net.interface, sizeof(tile->net.interface) );
      memcpy(  tile->net.src_mac_addr, config->tiles.net.mac_addr,  6UL );

      tile->net.xdp_aio_depth     = config->tiles.net.xdp_aio_depth;
      tile->net.xdp_rx_queue_size = config->tiles.net.xdp_rx_queue_size;
      tile->net.xdp_tx_queue_size = config->tiles.net.xdp_tx_queue_size;
      tile->net.src_ip_addr       = config->tiles.net.ip_addr;
      tile->net.shred_listen_port = config->tiles.shred.shred_listen_port;
      tile->net.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->net.legacy_transaction_listen_port = config->tiles.quic.regular_transaction_listen_port;

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

    } else if( FD_UNLIKELY( !strcmp( tile->name, "pack" ) ) ) {
      strncpy( tile->pack.identity_key_path, config->consensus.identity_path, sizeof(tile->pack.identity_key_path) );

      tile->pack.max_pending_transactions      = config->tiles.pack.max_pending_transactions;
      tile->pack.bank_tile_count               = config->layout.bank_tile_count;
      tile->pack.larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
      tile->pack.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "bank" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "poh" ) ) ) {
      strncpy( tile->poh.identity_key_path, config->consensus.identity_path, sizeof(tile->poh.identity_key_path) );

      tile->poh.bank_cnt = config->layout.bank_tile_count;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ) ) {
      fd_memcpy( tile->shred.src_mac_addr, config->tiles.net.mac_addr, 6 );
      strncpy( tile->shred.identity_key_path, config->consensus.identity_path, sizeof(tile->shred.identity_key_path) );

      tile->shred.depth                  = topo->links[ tile->out_link_id_primary ].depth;
      tile->shred.ip_addr                = config->tiles.net.ip_addr;
      tile->shred.fec_resolver_depth     = config->tiles.shred.max_pending_shred_sets;
      tile->shred.expected_shred_version = config->consensus.expected_shred_version;
      tile->shred.shred_listen_port      = config->tiles.shred.shred_listen_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "store" ) ) ) {

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

fd_topo_config_t fd_topo_frankendancer = {
  .configure = topo_configure_frankendancer
};
