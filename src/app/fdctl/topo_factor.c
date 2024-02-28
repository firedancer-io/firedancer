#include "fdctl.h"

#include "../../disco/topo/fd_topo_build.h"

#define INDEX_FLOAT   (ULONG_MAX)
#define INDEX_ALL     (ULONG_MAX-1UL)

#define UNRELIABLE    (0)
#define RELIABLE      (1)

#define UNPOLLED      (0)
#define POLLED        (1)

static inline void
fdctl_topo_predefine_links( fd_topo_t *      topo,
                            config_t const * config ) {
  /*                            topo, wksp,           name,           depth,                                    mtu,                    burst */
  fd_topo_builder_define_link(  topo, "netmux_inout", "net_netmux",   config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  fd_topo_builder_define_link(  topo, "netmux_inout", "netmux_out",   config->tiles.net.send_buffer_size,       0UL,                    1UL );
  fd_topo_builder_define_link(  topo, "netmux_inout", "quic_netmux",  config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  fd_topo_builder_define_link(  topo, "netmux_inout", "shred_netmux", config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  /* QUIC to verify has a reassembly buffer rather than a dcache attached to the link. */
  fd_topo_builder_define_reasm( topo, "quic_verify",  "quic_verify",  config->tiles.verify.receive_buffer_size, 0UL,                    config->tiles.quic.txn_reassembly_count );
  fd_topo_builder_define_link(  topo, "verify_dedup", "verify_dedup", config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  fd_topo_builder_define_link(  topo, "dedup_pack",   "dedup_pack",   config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /* Gossip to pack could be FD_TPU_MTU for now, since txns are not parsed, but better to just share one size for all the ins of pack */
  fd_topo_builder_define_link(  topo, "dedup_pack",   "gossip_pack",  config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  fd_topo_builder_define_link(  topo, "stake_out",    "stake_out",    128UL,                                    32UL + 40200UL * 40UL,  1UL );
  fd_topo_builder_define_link(  topo, "pack_bank",    "pack_bank",    128UL,                                    USHORT_MAX,             1UL );
  fd_topo_builder_define_link(  topo, "bank_poh",     "bank_poh",     128UL,                                    USHORT_MAX,             1UL );
  fd_topo_builder_define_link(  topo, "poh_shred",    "poh_shred",    128UL,                                    USHORT_MAX,             1UL );
  fd_topo_builder_define_link(  topo, "poh_shred",    "crds_shred",   128UL,                                    8UL  + 40200UL * 38UL,  1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  fd_topo_builder_define_link(  topo, "shred_store",  "shred_store",  128UL,                                    4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  fd_topo_builder_define_link(  topo, "quic_sign",    "quic_sign",    128UL,                                    130UL,                  1UL );
  fd_topo_builder_define_link(  topo, "sign_quic",    "sign_quic",    128UL,                                    64UL,                   1UL );
  fd_topo_builder_define_link(  topo, "shred_sign",   "shred_sign",   128UL,                                    32UL,                   1UL );
  fd_topo_builder_define_link(  topo, "sign_shred",   "sign_shred",   128UL,                                    64UL,                   1UL );
}

static inline void
fdctl_topo_predefine_tiles( fd_topo_t *      topo,
                            config_t const * config ) {
  /*                           topo, wksp,     name,     primary out,    is solana labs */
  fd_topo_builder_define_tile( topo, "net",    "net",    "net_netmux",   0 );
  fd_topo_builder_define_tile( topo, "netmux", "netmux", "netmux_out",   0 );
  fd_topo_builder_define_tile( topo, "quic",   "quic",   "quic_verify",  0 );
  fd_topo_builder_define_tile( topo, "verify", "verify", "verify_dedup", 0 );
  fd_topo_builder_define_tile( topo, "dedup",  "dedup",  "dedup_pack",   0 );
  fd_topo_builder_define_tile( topo, "pack",   "pack",   "pack_bank",    0 );
  fd_topo_builder_define_tile( topo, "bank",   "bank",   "bank_poh",     1 );
  fd_topo_builder_define_tile( topo, "poh",    "poh",    "poh_shred",    1 );
  fd_topo_builder_define_tile( topo, "shred",  "shred",  "shred_store",  0 );
  fd_topo_builder_define_tile( topo, "store",  "store",  NULL,           1 );
  fd_topo_builder_define_tile( topo, "sign",   "sign",   NULL,           0 );
  fd_topo_builder_define_tile( topo, "metric", "metric", NULL,           0 );
}

static inline void
fdctl_topo_add_networking( fd_topo_t * topo,
                           ulong       net_tile_cnt ) {
  /*                     topo, name,     tile count */
  fd_topo_builder_tiles( topo, "net",    net_tile_cnt  );
  fd_topo_builder_tiles( topo, "netmux", 1UL           );
  fd_topo_builder_tiles( topo, "netmux", 1UL           );

  /*                        topo, tile,     link,         indexer,   reliable,   polled */
  fd_topo_builder_tile_ins( topo, "net",    "netmux_out", 0UL,       UNRELIABLE, POLLED );
  fd_topo_builder_tile_ins( topo, "netmux", "net_netmux", INDEX_ALL, UNRELIABLE, POLLED );
}

static inline void
fdctl_topo_add_sign_quic( fd_topo_t * topo ) {
  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by the mux, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */

  /*                     topo, tile,   tile count */
  fd_topo_builder_tiles( topo, "sign", 1UL );

  /*                         topo, tile,   link,         indexer,     reliable,   polled */
  fd_topo_builder_tile_ins(  topo, "sign", "quic_sign",  INDEX_ALL,   UNRELIABLE, POLLED   );
  fd_topo_builder_tile_ins(  topo, "quic", "sign_quic",  INDEX_FLOAT, UNRELIABLE, UNPOLLED );

  /*                         topo, tile,   link */
  fd_topo_builder_tile_outs( topo, "quic", "quic_sign" );
  fd_topo_builder_tile_outs( topo, "sign", "sign_quic" );
}

static inline void
fdctl_topo_add_sign_shred( fd_topo_t * topo ) {
  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by the mux, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */

  /*                     topo, tile,   tile count */
  fd_topo_builder_tiles( topo, "sign", 1UL );

  /*                         topo, tile,    link,         indexer,     reliable,   polled */
  fd_topo_builder_tile_ins(  topo, "sign",  "shred_sign",  INDEX_ALL,   UNRELIABLE, POLLED   );
  fd_topo_builder_tile_ins(  topo, "shred", "sign_shred",  INDEX_FLOAT, UNRELIABLE, UNPOLLED );

  /*                         topo, tile,    link */
  fd_topo_builder_tile_outs( topo, "shred", "shred_sign" );
  fd_topo_builder_tile_outs( topo, "sign",  "sign_shred" );
}

static inline void
fdctl_topo_add_leader_tpu( fd_topo_t * topo,
                           ulong       verify_tile_cnt,
                           ulong       bank_tile_cnt ) {
  fdctl_topo_add_sign_quic( topo );

  /*                     topo, tile,     tile count */
  fd_topo_builder_tiles( topo, "quic",   verify_tile_cnt );
  fd_topo_builder_tiles( topo, "verify", verify_tile_cnt );
  fd_topo_builder_tiles( topo, "dedup",  1UL             );
  fd_topo_builder_tiles( topo, "pack",   1UL             );
  fd_topo_builder_tiles( topo, "bank",   bank_tile_cnt   );
  fd_topo_builder_tiles( topo, "poh",    1UL             );

  /*                        topo, tile,     link,           indexer,     reliable,   polled */
  fd_topo_builder_tile_ins( topo, "netmux", "quic_netmux",  INDEX_ALL,   UNRELIABLE, POLLED );
  fd_topo_builder_tile_ins( topo, "quic",   "netmux_out",   0UL,         UNRELIABLE, POLLED );
  fd_topo_builder_tile_ins( topo, "verify", "quic_verify",  INDEX_FLOAT, UNRELIABLE, POLLED );
  fd_topo_builder_tile_ins( topo, "dedup",  "verify_dedup", INDEX_FLOAT, RELIABLE,   POLLED );
  fd_topo_builder_tile_ins( topo, "pack",   "dedup_pack",   0UL,         RELIABLE,   POLLED );
  fd_topo_builder_tile_ins( topo, "pack",   "gossip_pack",  0UL,         RELIABLE,   POLLED );
  fd_topo_builder_tile_ins( topo, "pack",   "stake_out",    0UL,         RELIABLE,   POLLED );
  fd_topo_builder_tile_ins( topo, "pack",   "poh_shred",    0UL,         RELIABLE,   POLLED );
  /* These pack to bank links are reliable, but they are flow controlled
     by the busy flag that sits between them.  We don't mark them
     reliable here because it creates a reliable link loop (poh -> pack
     -> bank) which leads to credit starvation. */
  fd_topo_builder_tile_ins( topo, "bank",   "pack_bank",    0UL,         UNRELIABLE, POLLED );
  /* Same as above. */
  fd_topo_builder_tile_ins( topo, "bank", "poh_shred",      0UL,         UNRELIABLE, POLLED );
  fd_topo_builder_tile_ins( topo, "poh",  "bank_poh",       INDEX_ALL,   RELIABLE,   POLLED );
  fd_topo_builder_tile_ins( topo, "poh",  "stake_out",      0UL,         RELIABLE,   POLLED );

  /*                         topo, tile,   link */
  fd_topo_builder_tile_outs( topo, "quic", "quic_netmux" );
}

static inline void
fdctl_topo_add_shredder( fd_topo_t * topo ) {
  fdctl_topo_add_sign_shred( topo );

  /*                     topo, name     tile count */
  fd_topo_builder_tiles( topo, "shred", 1UL );
  fd_topo_builder_tiles( topo, "store", 1UL );

  /*                      topo, tile,     link,           indexer, reliable,   polled */
  fd_topo_build_tile_ins( topo, "netmux", "shred_netmux", 0UL,     UNRELIABLE, POLLED );
  fd_topo_build_tile_ins( topo, "shred",  "netmux_out",   0UL,     UNRELIABLE, POLLED );

  fd_topo_build_tile_ins( topo, "shred",  "poh_shred",    0UL,     RELIABLE,   POLLED );
  fd_topo_build_tile_ins( topo, "shred",  "stake_out",    0UL,     RELIABLE,   POLLED );
  fd_topo_build_tile_ins( topo, "shred",  "crds_shred",   0UL,     RELIABLE,   POLLED );

  fd_topo_build_tile_ins( topo, "store",  "shred_store",  0UL,     RELIABLE,   POLLED );

  /*                         topo, tile,   link */
  fd_topo_builder_tile_outs( topo, "shred", "shred_netmux" );
}

static inline void
fdctl_topo_add_metrics( fd_topo_t * topo ) {
  /*                     topo, name      tile count */
  fd_topo_builder_tiles( topo, "metric", 1UL );
}


/* fdctl_topo_initialize initializes the provided topology structure from the
   user configuration. */
static fd_topo_t
fdctl_topo_initialize( config_t const * config ) {
  fd_topo_t topo[1] = {0};

  fdctl_topo_predefine_links( topo, config );
  fdctl_topo_predefine_tiles( topo, config );

  fdctl_topo_add_networking( topo, config->layout.net_tile_count );
  fdctl_topo_add_leader_tpu( topo, config->layout.verify_tile_count, config->layout.bank_tile_count );
  fdctl_topo_add_shredder( topo );
  fdctl_topo_add_metrics( topo );
}
