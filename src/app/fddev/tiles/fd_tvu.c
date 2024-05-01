#include "../../fdctl/run/tiles/tiles.h"
#include "../../fdctl/utility.h"

#include "../../../disco/tvu/fd_tvu.h"

// #include "generated/tvu_seccomp.h"

#include <linux/unistd.h>
#include "../../../flamenco/fd_flamenco.h"

fd_wksp_t *     g_wksp = NULL;
char            g_repair_peer_id[ FD_BASE58_ENCODED_32_SZ ];
char            g_repair_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_gossip_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_my_gossip_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_my_repair_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_tvu_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_tvu_fwd_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_load[ PATH_MAX ];
char            g_snapshot[ PATH_MAX ];
char            g_incremental_snapshot[ PATH_MAX ];
char            g_solcap_path[ PATH_MAX ];
char            g_solcap_txns[ PATH_MAX ]; // "true" is the default
char            g_validate_snapshot[ 22 ];
char            g_check_hash[ 22 ];
char            g_shred_cap[ PATH_MAX ];
uint            g_page_cnt;
ushort          g_gossip_listen_port;
ushort          g_repair_listen_port;
ushort          g_tvu_port;
ushort          g_tvu_fwd_port;
ushort          g_rpc_listen_port;
ulong           g_tcnt;
ulong           g_txn_max;

/* Inspired from tiles/fd_shred.c */
fd_wksp_t *     g_net_in;
ulong           g_chunk;
ulong           g_wmark;

fd_frag_meta_t * g_net_out_mcache;
ulong *          g_net_out_sync;
ulong            g_net_out_depth;
ulong            g_net_out_seq;

fd_wksp_t * g_net_out_mem;
ulong       g_net_out_chunk0;
ulong       g_net_out_wmark;
ulong       g_net_out_chunk;

/* Includes Ethernet, IP, UDP headers */
ulong g_shred_buffer_sz;
uchar g_shred_buffer[ FD_NET_MTU ];
ulong g_gossip_buffer_sz;
uchar g_gossip_buffer[ FD_NET_MTU ];
ulong g_repair_buffer_sz;
uchar g_repair_buffer[ FD_NET_MTU ];
ulong g_tvu_buffer_sz;
uchar g_tvu_buffer[ FD_NET_MTU ];
ulong g_tvu_fwd_buffer_sz;
uchar g_tvu_fwd_buffer[ FD_NET_MTU ];

fd_topo_link_t * g_sign_in = NULL;
fd_topo_link_t * g_sign_out = NULL;
uchar const * g_identity_key = NULL;

fd_runtime_ctx_t  runtime_ctx;

typedef struct {
  int socket_fd;
} fd_tvu_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  FD_LOG_NOTICE(( "loose_footprint: %lu", tile->tvu.page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ ));
  return tile->tvu.page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  FD_LOG_NOTICE(( "scratch_footprint: %lu", 4096UL ));
  return 4096UL;
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_tvu_ctx_t ) );
}

#include "../../../util/tile/fd_tile_private.h"
/* Temporary hack until we get the tiles right */
void tpool_boot( ushort first_cpu, ulong tcnt ) {
  ushort tile_to_cpu[ FD_TILE_MAX ];
  for( ushort i=0; i<tcnt; i++ ) {
    tile_to_cpu[ i ] = (ushort)(first_cpu+i);
  }
  fd_tile_private_boot( tile_to_cpu, tcnt );
}

void
privileged_init( fd_topo_t * topo, fd_topo_tile_t * tile, void * scratch ) {
  g_wksp = topo->workspaces[ 0 ].wksp;
  strncpy( g_repair_peer_id, tile->tvu.repair_peer_id, sizeof(g_repair_peer_id) );
  strncpy( g_repair_peer_addr, tile->tvu.repair_peer_addr, sizeof(g_repair_peer_addr) );
  strncpy( g_gossip_peer_addr, tile->tvu.gossip_peer_addr, sizeof(g_gossip_peer_addr) );
  strncpy( g_my_gossip_addr, tile->tvu.my_gossip_addr, sizeof(g_my_gossip_addr) );
  strncpy( g_my_repair_addr, tile->tvu.my_repair_addr, sizeof(g_my_repair_addr) );
  strncpy( g_tvu_addr, tile->tvu.tvu_addr, sizeof(g_tvu_addr) );
  strncpy( g_tvu_fwd_addr, tile->tvu.tvu_fwd_addr, sizeof(g_tvu_fwd_addr) );
  strncpy( g_load, tile->tvu.load, sizeof(g_load) );
  strncpy( g_shred_cap, tile->tvu.shred_cap, sizeof(g_shred_cap) );
  strncpy( g_snapshot, tile->tvu.snapshot, sizeof(g_snapshot) );
  strncpy( g_incremental_snapshot, tile->tvu.incremental_snapshot, sizeof(g_incremental_snapshot) );
  strncpy( g_solcap_path, tile->tvu.solcap_path, sizeof(g_solcap_path) );
  strncpy( g_solcap_txns, tile->tvu.solcap_txns, sizeof(g_solcap_txns) );
  strncpy( g_validate_snapshot, tile->tvu.validate_snapshot, sizeof(g_validate_snapshot) );
  strncpy( g_check_hash, tile->tvu.check_hash, sizeof(g_check_hash) );
  g_page_cnt = tile->tvu.page_cnt;
  g_gossip_listen_port = tile->tvu.gossip_listen_port;
  g_repair_listen_port = tile->tvu.repair_listen_port;
  g_tvu_port = tile->tvu.tvu_port;
  g_tvu_fwd_port = tile->tvu.tvu_fwd_port;
  g_rpc_listen_port = tile->tvu.rpc_listen_port;
  g_tcnt           = tile->tvu.tcnt;
  g_txn_max        = tile->tvu.txn_max;

  FD_TEST( g_gossip_listen_port!=0 );
  FD_TEST( g_repair_listen_port!=0 );
  FD_TEST( g_tvu_port!=0 );
  FD_TEST( g_tvu_fwd_port!=0 );
  FD_TEST( g_rpc_listen_port!=0 );
  FD_TEST( g_tcnt != 0 );
  FD_TEST( g_txn_max != 0 );

  tpool_boot( (ushort)(topo->tile_cnt-g_tcnt), g_tcnt );

  uchar const * identity_key = load_key_into_protected_memory( tile->tvu.identity_key_path, /* pubkey only: */ 0 );
  g_identity_key = identity_key;

  g_sign_in = &topo->links[ tile->in_link_id[ 0 ] ];
  g_sign_out = &topo->links[ tile->out_link_id[ 0 ] ];

  (void)topo;
  (void)tile;
  (void)scratch;
}

void
unprivileged_init( fd_topo_t * topo, fd_topo_tile_t * tile, void * scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;
}

fd_topo_run_tile_t fd_tile_tvu = {
  .name                     = "tvu",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = NULL,
  .mux_during_frag          = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};

// static void
// doit( void ) {
//   while( 1 ) {
//     FD_LOG_NOTICE(( "loopin.." ));
//     fd_log_sleep( 1000000000UL );
//   }
// }

static int
doit( void ) {
  fd_flamenco_boot(NULL, NULL);
  memset(&runtime_ctx, 0, sizeof(runtime_ctx));

  fd_replay_t * replay = NULL;
  fd_exec_slot_ctx_t * slot_ctx = NULL;

  fd_keyguard_client_t keyguard_client[1];
  if( fd_keyguard_client_join(
        fd_keyguard_client_new( keyguard_client,
                                g_sign_out->mcache,
                                g_sign_out->dcache,
                                g_sign_in->mcache,
                                g_sign_in->dcache ) ) == NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }
  memcpy(runtime_ctx.private_key, g_identity_key, 32);
  // FD_LOG_WARNING(("Identity key %32J", runtime_ctx.private_key));
  memcpy(runtime_ctx.public_key.uc, g_identity_key + 32UL, 32);
  fd_runtime_args_t args = {
    .gossip_peer_addr     = g_gossip_peer_addr,
    .my_gossip_addr       = g_my_gossip_addr,
    .my_repair_addr       = g_my_repair_addr,
    .repair_peer_addr     = g_repair_peer_addr,
    .repair_peer_id       = g_repair_peer_id,
    .tvu_addr             = g_tvu_addr,
    .tvu_fwd_addr         = g_tvu_fwd_addr,
    .load                 = g_load,
    .shred_cap            = g_shred_cap,
    .snapshot             = g_snapshot,
    .incremental_snapshot = g_incremental_snapshot,
    .validate_snapshot    = g_validate_snapshot,
    .check_hash           = g_check_hash,
    .capture_fpath        = g_solcap_path,
    .capture_txns         = g_solcap_txns,
    .allocator            = "libc",
    .index_max            = ULONG_MAX,
    .page_cnt             = g_page_cnt,
    .tcnt                 = g_tcnt,
    .txn_max              = g_txn_max,
    .rpc_port             = g_rpc_listen_port,
  };
  fd_tvu_gossip_deliver_arg_t gossip_deliver_arg = { 0 };
  fd_tvu_main_setup( &runtime_ctx,
                     &replay,
                     &slot_ctx,
                     keyguard_client,
                     1,
                     g_wksp,
                     &args,
                     &gossip_deliver_arg );
  if( runtime_ctx.blowup ) FD_LOG_ERR(( "blowup" ));

  /**********************************************************************/
  /* Tile                                                               */
  /**********************************************************************/

  if( fd_tvu_main( &runtime_ctx,
                   &args,
                   replay,
                   slot_ctx ) ) {
    return 1;
  }

  fd_tvu_main_teardown( &runtime_ctx, replay );
  
  return 0;
}

int
fd_tvu(      fd_cnc_t *              cnc,
             ulong                   flags,
             ulong                   in_cnt,
             fd_frag_meta_t const ** in_mcache,
             ulong **                in_fseq,
             fd_frag_meta_t *        mcache,
             ulong                   out_cnt,
             ulong **                _out_fseq,
             ulong                   burst,
             ulong                   cr_max,
             long                    lazy,
             fd_rng_t *              rng,
             void *                  scratch,
             void *                  ctx,
             fd_mux_callbacks_t *    callbacks ) {
  (void)cnc;
  (void)flags;
  (void)in_cnt;
  (void)in_mcache;
  (void)in_fseq;
  (void)mcache;
  (void)out_cnt;
  (void)_out_fseq;
  (void)burst;
  (void)cr_max;
  (void)lazy;
  (void)rng;
  (void)scratch;
  (void)ctx;
  (void)callbacks;
  doit();
  return 0;
}
