#include "tiles.h"

#include "../../../../flamenco/runtime/fd_tvu.h"

#include "generated/tvu_seccomp.h"

#include <linux/unistd.h>

fd_wksp_t * g_wksp = NULL;
char        g_repair_peer_id[ FD_BASE58_ENCODED_32_SZ ];
char        g_repair_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char        g_gossip_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char        g_snapshot[ PATH_MAX ];
uint        g_page_cnt;
ushort      g_rpc_port = 12000;

static int
doit() {
  fd_valloc_t valloc = fd_libc_alloc_virtual();
  fd_runtime_ctx_t fd_runtime_ctx;
  tvu_main_setup( &fd_runtime_ctx,
                  valloc,
                  g_wksp,
                  NULL,
                  NULL,
                  g_gossip_peer_addr,
                  NULL,
                  NULL,
                  ":0",
                  ":0",
                  g_snapshot,
                  ULONG_MAX,
                  g_page_cnt,
                  1,
                  1000, // TODO: LML add --txnmax to default.toml
                  g_rpc_port );
  if( fd_runtime_ctx.blowup ) FD_LOG_ERR(( "blowup" ));

  /**********************************************************************/
  /* Tile                                                               */
  /**********************************************************************/

  if( tvu_main( fd_runtime_ctx.gossip,
                &fd_runtime_ctx.gossip_config,
                &fd_runtime_ctx.repair_ctx,
                &fd_runtime_ctx.repair_config,
                &fd_runtime_ctx.stopflag,
                g_repair_peer_id,
                g_repair_peer_addr ) ) {
    return 1;
  }
  return 0;
}

int
fd_tvu_tile( fd_cnc_t *              cnc,
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

typedef struct {
  int socket_fd;
} fd_tvu_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t *tile ) {
  return tile->tvu.page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t *tile ) {
  (void)tile;
  return 4096UL;
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_tvu_ctx_t ) );
}

static void
during_frag( void * ctx,
             ulong  in_idx,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)ctx;
  (void)in_idx;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)opt_filter;
}

static void
after_frag( void *             ctx,
            ulong              in_idx,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)ctx;
  (void)in_idx;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_filter;
  (void)mux;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  g_wksp = topo->workspaces[ tile->wksp_id ].wksp;
  // struct fd_wksp_usage usage;
  // fd_wksp_usage( g_wksp, 1, 1, &usage );
  // fd_wksp_reset( g_wksp, 0 );
  // fd_wksp_rebuild( g_wksp, 0 );

  strncpy( g_repair_peer_id, tile->tvu.repair_peer_id, sizeof(g_repair_peer_id) );
  strncpy( g_repair_peer_addr, tile->tvu.repair_peer_addr, sizeof(g_repair_peer_addr) );
  strncpy( g_gossip_peer_addr, tile->tvu.gossip_peer_addr, sizeof(g_gossip_peer_addr) );
  strncpy( g_snapshot, tile->tvu.snapshot, sizeof(g_snapshot) );
  g_page_cnt = tile->tvu.page_cnt;
  (void)topo;
  (void)tile;
  (void)scratch;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_tvu( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_tvu_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_tile_config_t fd_tile_tvu = {
  .mux_flags                = FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
