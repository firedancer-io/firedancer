#include "../../fdctl/run/tiles/tiles.h"

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
loose_footprint( fd_topo_tile_t *tile ) {
  (void)tile;
  return 500 * FD_SHMEM_GIGANTIC_PAGE_SZ;
//   return tile->tvu.page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return 4096UL;
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_tvu_ctx_t ) );
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
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .privileged_init          = NULL,
  .unprivileged_init        = NULL,
};

static void
doit( void ) {
  while( 1 ) {
    FD_LOG_NOTICE(( "loopin.." ));
    fd_log_sleep( 1000000000UL );
  }
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
