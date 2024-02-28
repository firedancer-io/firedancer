#include "fdctl.h"

#include "../../disco/topo/fd_topo_builder.h"
#include "../../util/tile/fd_tile_private.h"

#define INDEX_FLOAT   (ULONG_MAX)

#define UNRELIABLE    (0)
#define RELIABLE      (1)

#define UNPOLLED      (0)
#define POLLED        (1)

static ulong
obj_align( uchar const * pod, char const * id ) {
  (void)pod; (void)id;
  return 0UL;
}

static ulong
obj_footprint( uchar const * pod, char const * id ) {
  (void)pod; (void)id;
  return 0UL;
}

void
topo_initialize( config_t * config ) {
  uchar * pod = config->pod;

  fd_pod_new( pod, sizeof( config->pod ) );

  /*                        pod, name,           loose_sz */
  fd_topo_builder_add_wksp( pod, "netmux_inout", 0UL );
  fd_topo_builder_add_wksp( pod, "quic_verify",  0UL );
  fd_topo_builder_add_wksp( pod, "verify_dedup", 0UL );
  fd_topo_builder_add_wksp( pod, "dedup_pack",   0UL );
  fd_topo_builder_add_wksp( pod, "pack_bank",    0UL );
  fd_topo_builder_add_wksp( pod, "bank_poh",     0UL );
  fd_topo_builder_add_wksp( pod, "bank_busy",    0UL );
  fd_topo_builder_add_wksp( pod, "poh_shred",    0UL );
  fd_topo_builder_add_wksp( pod, "shred_store",  0UL );
  fd_topo_builder_add_wksp( pod, "stake_out",    0UL );
  fd_topo_builder_add_wksp( pod, "metric_in",    0UL );
  fd_topo_builder_add_wksp( pod, "quic_sign",    0UL );
  fd_topo_builder_add_wksp( pod, "sign_quic",    0UL );
  fd_topo_builder_add_wksp( pod, "shred_sign",   0UL );
  fd_topo_builder_add_wksp( pod, "sign_shred",   0UL );
  fd_topo_builder_add_wksp( pod, "net",          0UL );
  fd_topo_builder_add_wksp( pod, "netmux",       0UL );
  fd_topo_builder_add_wksp( pod, "quic",         0UL );
  fd_topo_builder_add_wksp( pod, "verify",       0UL );
  fd_topo_builder_add_wksp( pod, "dedup",        0UL );
  fd_topo_builder_add_wksp( pod, "pack",         0UL );
  fd_topo_builder_add_wksp( pod, "bank",         0UL );
  fd_topo_builder_add_wksp( pod, "poh",          0UL );
  fd_topo_builder_add_wksp( pod, "shred",        0UL );
  fd_topo_builder_add_wksp( pod, "store",        0UL );
  fd_topo_builder_add_wksp( pod, "sign",         0UL );
  fd_topo_builder_add_wksp( pod, "metric",       0UL );

  /*                         pod, number of links,                  wksp,           name,           depth,                                    reasm, mtu,                    burst */
  fd_topo_builder_add_links( pod, config->layout.net_tile_count,    "netmux_inout", "net_netmux",   config->tiles.net.send_buffer_size,       0,     FD_NET_MTU,             1UL );
  fd_topo_builder_add_links( pod, 1,                                "netmux_inout", "netmux_out",   config->tiles.net.send_buffer_size,       0,     0UL,                    1UL );
  fd_topo_builder_add_links( pod, config->layout.verify_tile_count, "netmux_inout", "quic_netmux",  config->tiles.net.send_buffer_size,       0,     FD_NET_MTU,             1UL );
  fd_topo_builder_add_links( pod, 1,                                "netmux_inout", "shred_netmux", config->tiles.net.send_buffer_size,       0,     FD_NET_MTU,             1UL );
  /* QUIC to verify has a reassembly buffer rather than a dcache attached to the link. */
  fd_topo_builder_add_links( pod, config->layout.verify_tile_count, "quic_verify",  "quic_verify",  config->tiles.verify.receive_buffer_size, 1,     0UL,                    config->tiles.quic.txn_reassembly_count );
  fd_topo_builder_add_links( pod, config->layout.verify_tile_count, "verify_dedup", "verify_dedup", config->tiles.verify.receive_buffer_size, 0,     FD_TPU_DCACHE_MTU,      1UL );
  fd_topo_builder_add_links( pod, 1,                                "dedup_pack",   "dedup_pack",   config->tiles.verify.receive_buffer_size, 0,     FD_TPU_DCACHE_MTU,      1UL );
  /* Gossip to pack could be FD_TPU_MTU for now, since txns are not parsed, but better to just share one size for all the ins of pack */
  fd_topo_builder_add_links( pod, 1,                                "dedup_pack",   "gossip_pack",  config->tiles.verify.receive_buffer_size, 0,     FD_TPU_DCACHE_MTU,      1UL );
  fd_topo_builder_add_links( pod, 1,                                "stake_out",    "stake_out",    128UL,                                    0,     32UL + 40200UL * 40UL,  1UL );
  fd_topo_builder_add_links( pod, 1,                                "pack_bank",    "pack_bank",    128UL,                                    0,     USHORT_MAX,             1UL );
  fd_topo_builder_add_links( pod, config->layout.bank_tile_count,   "bank_poh",     "bank_poh",     128UL,                                    0,     USHORT_MAX,             1UL );
  fd_topo_builder_add_links( pod, 1,                                "poh_shred",    "poh_shred",    128UL,                                    0,     USHORT_MAX,             1UL );
  fd_topo_builder_add_links( pod, 1,                                "poh_shred",    "crds_shred",   128UL,                                    0,     8UL  + 40200UL * 38UL,  1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  fd_topo_builder_add_links( pod, 1,                                "shred_store",  "shred_store",  128UL,                                    0,     4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  fd_topo_builder_add_links( pod, config->layout.verify_tile_count, "quic_sign",    "quic_sign",    128UL,                                    0,     130UL,                  1UL );
  fd_topo_builder_add_links( pod, config->layout.verify_tile_count, "sign_quic",    "sign_quic",    128UL,                                    0,     64UL,                   1UL );
  fd_topo_builder_add_links( pod, 1,                                "shred_sign",   "shred_sign",   128UL,                                    0,     32UL,                   1UL );
  fd_topo_builder_add_links( pod, 1,                                "sign_shred",   "sign_shred",   128UL,                                    0,     64UL,                   1UL );

  ushort tile_to_cpu[ FD_TOPO_TILE_MAX ];
  fd_tile_private_cpus_parse( config->layout.affinity, tile_to_cpu );

  /*                         pod, number of tiles,                  wksp,     name,     primary out,    indexer,     is solana labs, affinity */
  fd_topo_builder_add_tiles( pod, config->layout.net_tile_count,    "net",    "net",    "net_netmux",   0UL,         0,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, 1UL,                              "netmux", "netmux", "netmux_out",   0UL,         0,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, config->layout.verify_tile_count, "quic",   "quic",   "quic_verify",  INDEX_FLOAT, 0,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, config->layout.verify_tile_count, "verify", "verify", "verify_dedup", INDEX_FLOAT, 0,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, 1UL,                              "dedup",  "dedup",  "dedup_pack",   0UL,         0,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, 1UL,                              "pack",   "pack",   "pack_bank",    0UL,         0,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, config->layout.bank_tile_count,   "bank",   "bank",   "bank_poh",     INDEX_FLOAT, 1,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, 1UL,                              "poh",    "poh",    "poh_shred",    0UL,         1,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, 1UL,                              "shred",  "shred",  "shred_store",  0UL,         0,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, 1UL,                              "store",  "store",  NULL,           0UL,         1,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, 1UL,                              "sign",   "sign",   NULL,           0UL,         0,              tile_to_cpu );
  fd_topo_builder_add_tiles( pod, 1UL,                              "metric", "metric", NULL,           0UL,         0,              tile_to_cpu );

/* All fseqs go into the metrics workspace.  You might want to put these
   in the link workspace itself, but then tiles would need to map input
   workspaces as read/write to update the fseq so it's not good for
   security.  Instead, it's better to just place them all in another
   workspace.  We use metrics because it's already taking up a page in
   the TLB and writable by everyone anyway. */

  /*                             pod, number of ins,                    wksp,        tile,     indexer,     link,           indexer,       reliable,   polled */
  fd_topo_builder_add_tile_ins(  pod, config->layout.net_tile_count,    "metric_in", "net",    INDEX_FLOAT, "netmux_out",   0UL,           UNRELIABLE, POLLED );
  fd_topo_builder_add_tile_ins(  pod, config->layout.net_tile_count,    "metric_in", "netmux", 0UL,         "net_netmux",   INDEX_FLOAT,   UNRELIABLE, POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  fd_topo_builder_add_tile_ins(  pod, config->layout.verify_tile_count, "metric_in", "netmux", 0UL,         "quic_netmux",  INDEX_FLOAT,   UNRELIABLE, POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "netmux", 0UL,         "shred_netmux", 0UL,           UNRELIABLE, POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  fd_topo_builder_add_tile_ins(  pod, config->layout.verify_tile_count, "metric_in", "quic",   INDEX_FLOAT, "netmux_out",   0UL,           UNRELIABLE, POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  fd_topo_builder_add_tile_outs( pod, config->layout.verify_tile_count,              "quic",   INDEX_FLOAT, "quic_netmux",  INDEX_FLOAT                       );
  fd_topo_builder_add_tile_ins(  pod, config->layout.verify_tile_count, "metric_in", "verify", INDEX_FLOAT, "quic_verify",  INDEX_FLOAT,   UNRELIABLE, POLLED ); /* No reliable consumers, verify tiles may be overrun */
  fd_topo_builder_add_tile_ins(  pod, config->layout.verify_tile_count, "metric_in", "dedup",  0UL,         "verify_dedup", INDEX_FLOAT,   RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "pack",   0UL,         "dedup_pack",   0UL,           RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "pack",   0UL,         "gossip_pack",  0UL,           RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "pack",   0UL,         "stake_out",    0UL,           RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "pack",   0UL,         "poh_shred",    0UL,           RELIABLE,   POLLED );
  /* These pack to bank links are reliable, but they are flow controlled
     by the busy flag that sits between them.  We don't mark them
     reliable here because it creates a reliable link loop (poh -> pack
     -> bank) which leads to credit starvation. */
  fd_topo_builder_add_tile_ins(  pod, config->layout.bank_tile_count,   "metric_in", "bank",   INDEX_FLOAT, "pack_bank",    0UL,           UNRELIABLE, POLLED );
  /* Same as above. */
  fd_topo_builder_add_tile_ins(  pod, config->layout.bank_tile_count,   "metric_in", "bank",   INDEX_FLOAT, "poh_shred",    0UL,           UNRELIABLE, POLLED );
  fd_topo_builder_add_tile_ins(  pod, config->layout.bank_tile_count,   "metric_in", "poh",    0UL,         "bank_poh",     INDEX_FLOAT,   RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "poh",    0UL,         "stake_out",    0UL,           RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "shred",  0UL,         "netmux_out",   0UL,           UNRELIABLE, POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "shred",  0UL,         "poh_shred",    0UL,           RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "shred",  0UL,         "stake_out",    0UL,           RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "shred",  0UL,         "crds_shred",   0UL,           RELIABLE,   POLLED );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "store",  0UL,         "shred_store",  0UL,           RELIABLE,   POLLED );
  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by the mux, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */
  fd_topo_builder_add_tile_ins(  pod, config->layout.verify_tile_count, "metric_in", "sign",   0UL,         "quic_sign",  INDEX_FLOAT, UNRELIABLE, POLLED   );
  fd_topo_builder_add_tile_outs( pod, config->layout.verify_tile_count,              "quic",   INDEX_FLOAT, "quic_sign",  INDEX_FLOAT                       );
  fd_topo_builder_add_tile_ins(  pod, config->layout.verify_tile_count, "metric_in", "quic",   INDEX_FLOAT, "sign_quic",  INDEX_FLOAT, UNRELIABLE, UNPOLLED );
  fd_topo_builder_add_tile_outs( pod, config->layout.verify_tile_count,              "sign",   0UL,         "sign_quic",  INDEX_FLOAT                       );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "sign",   0UL,         "shred_sign", 0UL,         UNRELIABLE, POLLED   );
  fd_topo_builder_add_tile_outs( pod, 1UL,                                           "shred",  0UL,         "shred_sign", 0UL    );
  fd_topo_builder_add_tile_ins(  pod, 1UL,                              "metric_in", "shred",  0UL,         "sign_shred", 0UL,         UNRELIABLE, UNPOLLED );
  fd_topo_builder_add_tile_outs( pod, 1UL,                                           "sign",   0UL,         "sign_shred", 0UL    );
  /* PoH tile represents the Solana Labs address space, so it's
     responsible for publishing Solana Labs provided data to
     these links. */
  fd_topo_builder_add_tile_outs( pod, 1UL,                                           "poh",    0UL,         "gossip_pack", 0UL   );
  fd_topo_builder_add_tile_outs( pod, 1UL,                                           "poh",    0UL,         "stake_out",   0UL   );
  fd_topo_builder_add_tile_outs( pod, 1UL,                                           "poh",    0UL,         "crds_shred",  0UL   );

  fd_topo_wksp_layout( pod, obj_align, obj_footprint );
}
