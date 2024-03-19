#include "../../config.h"
#include "topo_util.h"


void
fd_topo_tvu( config_t * config ) {
  fd_topo_t * topo = &config->topo;

  /* Static configuration of all workspaces in the topology.  Workspace
     sizing will be determined dynamically at runtime based on how much
     space will be allocated from it. */
  ulong wksp_cnt = 0;

  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NETMUX_INOUT }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_QUIC_VERIFY  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_VERIFY_DEDUP }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_DEDUP_PACK   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_PACK_BANK    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_BANK_POH     }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_BANK_BUSY    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_POH_SHRED    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SHRED_STORE  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_STAKE_OUT    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_METRIC_IN    }; wksp_cnt++;

  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_QUIC_SIGN    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SIGN_QUIC    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SHRED_SIGN   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SIGN_SHRED   }; wksp_cnt++;

  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NET    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NETMUX }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_QUIC   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_VERIFY }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_DEDUP  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_PACK   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_BANK   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_POH    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SHRED  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_EXT_STORE  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SIGN  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_METRIC }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_TVU    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_GOSSIP_SIGN  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SIGN_GOSSIP  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_REPAIR_SIGN  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SIGN_REPAIR  }; wksp_cnt++;

  topo->wksp_cnt = wksp_cnt;

  /* Static listing of all links in the topology. */
  ulong link_cnt = 0;

  LINK( config->layout.net_tile_count,    FD_TOPO_LINK_KIND_NET_TO_NETMUX,   FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( config->layout.verify_tile_count, FD_TOPO_LINK_KIND_QUIC_TO_NETMUX,  FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_SHRED_TO_NETMUX, FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( config->layout.verify_tile_count, FD_TOPO_LINK_KIND_QUIC_TO_VERIFY,  FD_TOPO_WKSP_KIND_QUIC_VERIFY,  config->tiles.verify.receive_buffer_size, 0UL,                    config->tiles.quic.txn_reassembly_count );
  LINK( 1,                                FD_TOPO_LINK_KIND_TVU_TO_NETMUX,   FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( config->layout.verify_tile_count, FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP, FD_TOPO_WKSP_KIND_VERIFY_DEDUP, config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_DEDUP_TO_PACK,   FD_TOPO_WKSP_KIND_DEDUP_PACK,   config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  /* FD_TOPO_LINK_KIND_GOSSIP_TO_PACK could be FD_TPU_MTU for now, since txns are not parsed, but better to just share one size for all the ins of pack */
  LINK( 1,                                FD_TOPO_LINK_KIND_GOSSIP_TO_PACK,  FD_TOPO_WKSP_KIND_DEDUP_PACK,   config->tiles.verify.receive_buffer_size, FD_TPU_DCACHE_MTU,      1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_STAKE_TO_OUT,    FD_TOPO_WKSP_KIND_STAKE_OUT,    128UL,                                    32UL + 40200UL * 40UL,  1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_PACK_TO_BANK,    FD_TOPO_WKSP_KIND_PACK_BANK,    128UL,                                    USHORT_MAX,             1UL );
  LINK( config->layout.bank_tile_count,   FD_TOPO_LINK_KIND_BANK_TO_POH,     FD_TOPO_WKSP_KIND_BANK_POH,     128UL,                                    USHORT_MAX,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_POH_TO_SHRED,    FD_TOPO_WKSP_KIND_POH_SHRED,    128UL,                                    USHORT_MAX,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_CRDS_TO_SHRED,   FD_TOPO_WKSP_KIND_POH_SHRED,    128UL,                                    8UL  + 40200UL * 38UL,  1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  LINK( 1,                                FD_TOPO_LINK_KIND_SHRED_TO_EXT_STORE,  FD_TOPO_WKSP_KIND_SHRED_STORE,  128UL,                                    4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );

  LINK( config->layout.verify_tile_count, FD_TOPO_LINK_KIND_QUIC_TO_SIGN,    FD_TOPO_WKSP_KIND_QUIC_SIGN,    128UL,                                    130UL,                  1UL );
  LINK( config->layout.verify_tile_count, FD_TOPO_LINK_KIND_SIGN_TO_QUIC,    FD_TOPO_WKSP_KIND_SIGN_QUIC,    128UL,                                    64UL,                   1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_SHRED_TO_SIGN,   FD_TOPO_WKSP_KIND_SHRED_SIGN,   128UL,                                    32UL,                   1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_SIGN_TO_SHRED,   FD_TOPO_WKSP_KIND_SIGN_SHRED,   128UL,                                    64UL,                   1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_GOSSIP_TO_SIGN,  FD_TOPO_WKSP_KIND_GOSSIP_SIGN,  128UL,                                    2048UL,                 1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_SIGN_TO_GOSSIP,  FD_TOPO_WKSP_KIND_SIGN_GOSSIP,  128UL,                                    64UL,                   1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_REPAIR_TO_SIGN,  FD_TOPO_WKSP_KIND_REPAIR_SIGN,  128UL,                                    2048UL,                 1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_SIGN_TO_REPAIR,  FD_TOPO_WKSP_KIND_SIGN_REPAIR,  128UL,                                    64UL,                   1UL );

  topo->link_cnt = link_cnt;

  ulong tile_cnt = 0UL;


  TILE( config->layout.net_tile_count,    FD_TOPO_TILE_KIND_NET,    FD_TOPO_WKSP_KIND_NET,    fd_topo_find_link( topo, FD_TOPO_LINK_KIND_NET_TO_NETMUX,   i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_NETMUX, FD_TOPO_WKSP_KIND_NETMUX, fd_topo_find_link( topo, FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   i ) );
  TILE( config->layout.verify_tile_count, FD_TOPO_TILE_KIND_QUIC,   FD_TOPO_WKSP_KIND_QUIC,   fd_topo_find_link( topo, FD_TOPO_LINK_KIND_QUIC_TO_VERIFY,  i ) );
  TILE( config->layout.verify_tile_count, FD_TOPO_TILE_KIND_VERIFY, FD_TOPO_WKSP_KIND_VERIFY, fd_topo_find_link( topo, FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP, i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_DEDUP,  FD_TOPO_WKSP_KIND_DEDUP,  fd_topo_find_link( topo, FD_TOPO_LINK_KIND_DEDUP_TO_PACK,   i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_PACK,   FD_TOPO_WKSP_KIND_PACK,   fd_topo_find_link( topo, FD_TOPO_LINK_KIND_PACK_TO_BANK,    i ) );
  TILE( config->layout.bank_tile_count,   FD_TOPO_TILE_KIND_BANK,   FD_TOPO_WKSP_KIND_BANK,   fd_topo_find_link( topo, FD_TOPO_LINK_KIND_BANK_TO_POH,     i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_POH,    FD_TOPO_WKSP_KIND_POH,    fd_topo_find_link( topo, FD_TOPO_LINK_KIND_POH_TO_SHRED,    i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_SHRED,  FD_TOPO_WKSP_KIND_SHRED,  fd_topo_find_link( topo, FD_TOPO_LINK_KIND_SHRED_TO_EXT_STORE,  i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_EXT_STORE,  FD_TOPO_WKSP_KIND_EXT_STORE,  ULONG_MAX                                                       );
  TILE( 1,                                FD_TOPO_TILE_KIND_SIGN,   FD_TOPO_WKSP_KIND_SIGN,   ULONG_MAX                                                       );
  TILE( 1,                                FD_TOPO_TILE_KIND_METRIC, FD_TOPO_WKSP_KIND_METRIC, ULONG_MAX                                                       );
  TILE( 1,                                FD_TOPO_TILE_KIND_TVU,    FD_TOPO_WKSP_KIND_TVU,    fd_topo_find_link( topo, FD_TOPO_LINK_KIND_TVU_TO_NETMUX,   i ) );

  /* TODO: LML we need to replace all the special cases introduced by this PR for a partially managed tpool and spawned pthreads in TVU. */
  /*       When we define the tiles in this topology the FD_TOPO_TILE_KIND_TVU_THREAD tiles ***MUST*** be defined last                   */
  /*       because in tiles/fd_tvu.c we blindly assume the last tvu_unmanaged_cpus tiles are the FD_TOPO_TILE_KIND_TVU_THREAD tiles.      */
  for( ulong i=0; i< config->tiles.tvu.tcnt; i++ ) {
    topo->tiles[ tile_cnt ] = (fd_topo_tile_t){ .id                  = tile_cnt,
                                                .kind                = FD_TOPO_TILE_KIND_TVU_THREAD,
                                                .kind_id             = i,
                                                .wksp_id             = FD_TOPO_WKSP_KIND_TVU,
                                                .in_cnt              = 0,
                                                .out_link_id_primary = 255,
                                                .out_cnt             = 0 };
    tile_cnt++;
  }

  topo->tile_cnt = tile_cnt;


  for( ulong i=0; i<config->layout.net_tile_count; i++ )    TILE_IN(  FD_TOPO_TILE_KIND_NET,    i,   FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   0UL, 0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.net_tile_count; i++ )    TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_NET_TO_NETMUX,   i,   0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_QUIC_TO_NETMUX,  i,   0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_SHRED_TO_NETMUX, 0UL, 0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_IN(  FD_TOPO_TILE_KIND_QUIC,   i,   FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   0UL, 0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_OUT( FD_TOPO_TILE_KIND_QUIC,   i,   FD_TOPO_LINK_KIND_QUIC_TO_NETMUX,  i      );
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_IN(  FD_TOPO_TILE_KIND_VERIFY, i,   FD_TOPO_LINK_KIND_QUIC_TO_VERIFY,  i,   0, 1 ); /* No reliable consumers, verify tiles may be overrun */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) TILE_IN(  FD_TOPO_TILE_KIND_DEDUP,  0UL, FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP, i,   1, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_PACK,   0UL, FD_TOPO_LINK_KIND_DEDUP_TO_PACK,   0UL, 1, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_PACK,   0UL, FD_TOPO_LINK_KIND_GOSSIP_TO_PACK,  0UL, 1, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_PACK,   0UL, FD_TOPO_LINK_KIND_STAKE_TO_OUT,    0UL, 1, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_PACK,   0UL, FD_TOPO_LINK_KIND_POH_TO_SHRED,    0UL, 1, 1 );
  /* These pack to bank links are reliable, but they are flow controlled
     by the busy flag that sits between them.  We don't mark them
     reliable here because it creates a reliable link loop (poh -> pack
     -> bank) which leads to credit starvation. */
  for( ulong i=0; i<config->layout.bank_tile_count; i++ )   TILE_IN(  FD_TOPO_TILE_KIND_BANK,   i,   FD_TOPO_LINK_KIND_PACK_TO_BANK,    0UL, 0, 1 );
  /* Same as above. */
  for( ulong i=0; i<config->layout.bank_tile_count; i++ )   TILE_IN(  FD_TOPO_TILE_KIND_BANK,   i,   FD_TOPO_LINK_KIND_POH_TO_SHRED,    0UL, 0, 1 );
  for( ulong i=0; i<config->layout.bank_tile_count; i++ )   TILE_IN(  FD_TOPO_TILE_KIND_POH,    0UL, FD_TOPO_LINK_KIND_BANK_TO_POH,     i,   1, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_POH,    0UL, FD_TOPO_LINK_KIND_STAKE_TO_OUT,    0UL, 1, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   0UL, 0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_POH_TO_SHRED,    0UL, 1, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_STAKE_TO_OUT,    0UL, 1, 1 );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_CRDS_TO_SHRED,   0UL, 1, 1 );
  /**/                                                      TILE_OUT( FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_SHRED_TO_NETMUX, 0UL    );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_EXT_STORE,  0UL, FD_TOPO_LINK_KIND_SHRED_TO_EXT_STORE,  0UL, 1, 1 );

  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by the mux, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
    /**/                                                    TILE_IN(  FD_TOPO_TILE_KIND_SIGN,   0UL, FD_TOPO_LINK_KIND_QUIC_TO_SIGN,      i, 0, 1 );
    /**/                                                    TILE_OUT( FD_TOPO_TILE_KIND_QUIC,     i, FD_TOPO_LINK_KIND_QUIC_TO_SIGN,      i    );
    /**/                                                    TILE_IN(  FD_TOPO_TILE_KIND_QUIC,     i, FD_TOPO_LINK_KIND_SIGN_TO_QUIC,      i, 0, 0 );
    /**/                                                    TILE_OUT( FD_TOPO_TILE_KIND_SIGN,   0UL, FD_TOPO_LINK_KIND_SIGN_TO_QUIC,      i    );
  }

  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SIGN,   0UL, FD_TOPO_LINK_KIND_SHRED_TO_SIGN,   0UL, 0, 1 );
  /**/                                                      TILE_OUT( FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_SHRED_TO_SIGN,   0UL    );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SHRED,  0UL, FD_TOPO_LINK_KIND_SIGN_TO_SHRED,   0UL, 0, 0 );
  /**/                                                      TILE_OUT( FD_TOPO_TILE_KIND_SIGN,   0UL, FD_TOPO_LINK_KIND_SIGN_TO_SHRED,   0UL    );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_TVU,    0UL, FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   0UL, 0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_TVU_TO_NETMUX,   0UL, 0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SIGN,   0UL, FD_TOPO_LINK_KIND_GOSSIP_TO_SIGN,  0UL, 0, 1 );
  /**/                                                      TILE_OUT( FD_TOPO_TILE_KIND_TVU,    0UL, FD_TOPO_LINK_KIND_GOSSIP_TO_SIGN,  0UL    );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_TVU,    0UL, FD_TOPO_LINK_KIND_SIGN_TO_GOSSIP,  0UL, 0, 0 );
  /**/                                                      TILE_OUT( FD_TOPO_TILE_KIND_SIGN, 0UL, FD_TOPO_LINK_KIND_SIGN_TO_GOSSIP,  0UL    );

  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_SIGN,   0UL, FD_TOPO_LINK_KIND_REPAIR_TO_SIGN,  0UL, 0, 1 );
  /**/                                                      TILE_OUT( FD_TOPO_TILE_KIND_TVU,    0UL, FD_TOPO_LINK_KIND_REPAIR_TO_SIGN,  0UL    );
  /**/                                                      TILE_IN(  FD_TOPO_TILE_KIND_TVU,    0UL, FD_TOPO_LINK_KIND_SIGN_TO_REPAIR,  0UL, 0, 0 );
  /**/                                                      TILE_OUT( FD_TOPO_TILE_KIND_SIGN, 0UL, FD_TOPO_LINK_KIND_SIGN_TO_REPAIR,  0UL    );

}
