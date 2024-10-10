#define _GNU_SOURCE

#include "../../../../disco/tiles.h"

#include "../../../../choreo/fd_choreo.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/repair/fd_repair.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../util/fd_util.h"
#include "generated/eqvoc_seccomp.h"

#include <arpa/inet.h>
#include <linux/unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../../../disco/fd_disco.h"
#include "../../../../disco/keyguard/fd_keyguard.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/store/fd_store.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/runtime/fd_runtime.h"
#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"

#include "../../../../util/net/fd_net_headers.h"

#define SCRATCH_MAX   ( 4UL /*KiB*/ << 10 )
#define SCRATCH_DEPTH ( 4UL ) /* 4 scratch frames */

struct fd_eqvoc_tile_ctx {
  fd_pubkey_t identity_key[1];

  fd_stake_ci_t *            stake_ci;
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;

  ulong       contact_in_idx;
  fd_wksp_t * contact_in_mem;
  ulong       contact_in_chunk0;
  ulong       contact_in_wmark;

  fd_shred_t  shred;

  ulong       shred_net_in_idx;
  fd_wksp_t * shred_net_in_mem;
  ulong       shred_net_in_chunk0;
  ulong       shred_net_in_wmark;
};
typedef struct fd_eqvoc_tile_ctx fd_eqvoc_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 0UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  /* clang-format off */
  ulong l = FD_LAYOUT_INIT;
  l       = FD_LAYOUT_APPEND( l, alignof(fd_eqvoc_tile_ctx_t), sizeof(fd_eqvoc_tile_ctx_t) );
  l       = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),          fd_stake_ci_footprint() );
  // l       = FD_LAYOUT_APPEND( l, fd_eqvoc_align(),             fd_eqvoc_footprint( FD_EQVOC_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void *)fd_ulong_align_up( (ulong)scratch, alignof( fd_eqvoc_tile_ctx_t ) );
}

static inline void
handle_new_cluster_contact_info( fd_eqvoc_tile_ctx_t * ctx, uchar const * buf, ulong buf_sz ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = buf_sz;

  if( dest_cnt >= MAX_SHRED_DESTS )
    FD_LOG_ERR( ( "Cluster nodes had %lu destinations, which was more than the max of %lu",
                  dest_cnt,
                  MAX_SHRED_DESTS ) );

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header );
  fd_shred_dest_weighted_t *   dests    = fd_stake_ci_dest_add_init( ctx->stake_ci );

  ctx->new_dest_ptr = dests;
  ctx->new_dest_cnt = dest_cnt;

  for( ulong i = 0UL; i < dest_cnt; i++ ) {
    memcpy( dests[i].pubkey.uc, in_dests[i].pubkey, 32UL );
    dests[i].ip4  = in_dests[i].ip4_addr;
    dests[i].port = in_dests[i].udp_port;
  }
}

static inline void
finalize_new_cluster_contact_info( fd_eqvoc_tile_ctx_t * ctx ) {
  fd_stake_ci_dest_add_fini( ctx->stake_ci, ctx->new_dest_cnt );
}

static void
during_frag( void *           _ctx,
             ulong            in_idx,
             ulong seq        FD_PARAM_UNUSED,
             ulong sig        FD_PARAM_UNUSED,
             ulong            chunk,
             ulong            sz,
             int * opt_filter FD_PARAM_UNUSED ) {
  fd_eqvoc_tile_ctx_t * ctx = (fd_eqvoc_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx == ctx->contact_in_idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->contact_in_chunk0 || chunk > ctx->contact_in_wmark ) ) {
      FD_LOG_ERR( ( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                    chunk,
                    sz,
                    ctx->contact_in_chunk0,
                    ctx->contact_in_wmark ) );
    }

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->contact_in_mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry, sz );
  } else if ( FD_UNLIKELY( in_idx == ctx->shred_net_in_idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->shred_net_in_chunk0 || chunk > ctx->shred_net_in_wmark ) ) {
      FD_LOG_ERR( ( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                    chunk,
                    sz,
                    ctx->shred_net_in_chunk0,
                    ctx->shred_net_in_wmark ) );
    }

    uchar * packet = fd_chunk_to_laddr( ctx->shred_net_in_mem, chunk );
    // memcpy( packet + sizeof(fd_net_hdrs_t), packet, sizeof(fd_shred_t) );
    fd_shred_t * shred = (fd_shred_t *)(packet + sizeof(fd_net_hdrs_t));
    memcpy( &ctx->shred, shred, sizeof(fd_shred_t) );
  }
}

static void
after_frag( void *                 _ctx,
            ulong                  in_idx,
            ulong seq              FD_PARAM_UNUSED,
            ulong * opt_sig        FD_PARAM_UNUSED,
            ulong * opt_chunk      FD_PARAM_UNUSED,
            ulong * opt_sz         FD_PARAM_UNUSED,
            ulong * opt_tsorig     FD_PARAM_UNUSED,
            int * opt_filter       FD_PARAM_UNUSED,
            fd_mux_context_t * mux FD_PARAM_UNUSED ) {
  fd_eqvoc_tile_ctx_t * ctx = (fd_eqvoc_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx == ctx->contact_in_idx ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  }

  FD_LOG_DEBUG(( "got shred %lu %u", ctx->shred.slot, ctx->shred.idx ));
}

static void
privileged_init( fd_topo_t * topo FD_PARAM_UNUSED, fd_topo_tile_t * tile, void * scratch ) {

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_eqvoc_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l,
                                                       alignof( fd_eqvoc_tile_ctx_t ),
                                                       sizeof( fd_eqvoc_tile_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->eqvoc.identity_key_path, "" ) ) )
    FD_LOG_ERR( ( "identity_key_path not set" ) );

  ctx->identity_key[0] = *(fd_pubkey_t const *)
                             fd_type_pun_const( fd_keyload_load( tile->eqvoc.identity_key_path,
                                                                 /* pubkey only: */ 1 ) );
}

static void
unprivileged_init( fd_topo_t * topo, fd_topo_tile_t * tile, void * scratch ) {
  fd_flamenco_boot( NULL, NULL );

  if( FD_UNLIKELY( tile->out_link_id_primary != ULONG_MAX ) )
    FD_LOG_ERR( ( "eqvoc has a primary output link" ) );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_eqvoc_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l,
                                                       alignof( fd_eqvoc_tile_ctx_t ),
                                                       sizeof( fd_eqvoc_tile_ctx_t ) );

  ctx->stake_ci = fd_stake_ci_join(
      fd_stake_ci_new( FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() ),
                       ctx->identity_key ) );

  ctx->contact_in_idx = fd_topo_find_tile_in_link( topo, tile, "gossip_voter", 0 );
  FD_TEST( ctx->contact_in_idx != ULONG_MAX );
  fd_topo_link_t * contact_in_link = &topo->links[tile->in_link_id[ctx->contact_in_idx]];
  ctx->contact_in_mem = topo->workspaces[topo->objs[contact_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->contact_in_chunk0 = fd_dcache_compact_chunk0( ctx->contact_in_mem, contact_in_link->dcache );
  ctx->contact_in_wmark  = fd_dcache_compact_wmark( ctx->contact_in_mem,
                                                   contact_in_link->dcache,
                                                   contact_in_link->mtu );

  ctx->shred_net_in_idx = fd_topo_find_tile_in_link( topo, tile, "shred_net", 0 );
  FD_TEST( ctx->shred_net_in_idx != ULONG_MAX );
  fd_topo_link_t * shred_net_in_link = &topo->links[tile->in_link_id[ctx->shred_net_in_idx]];
  ctx->shred_net_in_mem = topo->workspaces[topo->objs[shred_net_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->shred_net_in_chunk0 = fd_dcache_compact_chunk0( ctx->shred_net_in_mem, shred_net_in_link->dcache );
  ctx->shred_net_in_wmark  = fd_dcache_compact_wmark( ctx->shred_net_in_mem,
                                                   shred_net_in_link->dcache,
                                                   shred_net_in_link->mtu );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR( ( "scratch overflow %lu %lu %lu",
                  scratch_top - (ulong)scratch - scratch_footprint( tile ),
                  scratch_top,
                  (ulong)scratch + scratch_footprint( tile ) ) );
  }
}

static ulong
populate_allowed_seccomp( void * scratch       FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_eqvoc( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_eqvoc_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch FD_PARAM_UNUSED, ulong out_fds_cnt, int * out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR( ( "out_fds_cnt %lu", out_fds_cnt ) );

  ulong out_cnt      = 0;
  out_fds[out_cnt++] = 2; /* stderr */
  if( FD_LIKELY( -1 != fd_log_private_logfile_fd() ) )
    out_fds[out_cnt++] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_eqvoc = {
    .name                     = "eqvoc",
    .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
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
