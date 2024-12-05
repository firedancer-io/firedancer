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

  fd_gossip_duplicate_shred_t duplicate_shred;
  uchar duplicate_shred_chunk[FD_EQVOC_PROOF_CHUNK_MAX];

  ulong       gossip_in_idx;
  fd_wksp_t * gossip_in_mem;
  ulong       gossip_in_chunk0;
  ulong       gossip_in_wmark;

  fd_shred_t  shred;

  ulong       shred_net_in_idx;
  fd_wksp_t * shred_net_in_mem;
  ulong       shred_net_in_chunk0;
  ulong       shred_net_in_wmark;

  ulong seed;
  fd_eqvoc_t * eqvoc;
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
  l       = FD_LAYOUT_APPEND( l, fd_eqvoc_align(),             fd_eqvoc_footprint( 1 << 10, 1 << 10 ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
}

static inline void
handle_new_cluster_contact_info( fd_eqvoc_tile_ctx_t * ctx, uchar const * buf, ulong buf_sz ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = buf_sz;

  if( dest_cnt >= MAX_SHRED_DESTS )
    FD_LOG_ERR(( "Cluster nodes had %lu destinations, which was more than the max of %lu",
                  dest_cnt,
                  MAX_SHRED_DESTS ));

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
during_frag( fd_eqvoc_tile_ctx_t * ctx,
             ulong                 in_idx,
             ulong                 seq,
             ulong                 sig,
             ulong                 chunk,
             ulong                 sz ) {
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( in_idx == ctx->contact_in_idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->contact_in_chunk0 || chunk > ctx->contact_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                    chunk,
                    sz,
                    ctx->contact_in_chunk0,
                    ctx->contact_in_wmark ));
    }

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->contact_in_mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry, sz );
  } else if( FD_UNLIKELY( in_idx == ctx->gossip_in_idx ) ) {
    uchar * packet = fd_chunk_to_laddr( ctx->gossip_in_mem, chunk );
    memcpy( &ctx->duplicate_shred, packet, FD_GOSSIP_DUPLICATE_SHRED_FOOTPRINT );
    memcpy( ctx->duplicate_shred_chunk, packet + FD_GOSSIP_DUPLICATE_SHRED_FOOTPRINT, ctx->duplicate_shred.chunk_len );
    ctx->duplicate_shred.chunk = ctx->duplicate_shred_chunk;
  } else if ( FD_UNLIKELY( in_idx == ctx->shred_net_in_idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->shred_net_in_chunk0 || chunk > ctx->shred_net_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                    chunk,
                    sz,
                    ctx->shred_net_in_chunk0,
                    ctx->shred_net_in_wmark ));
    }

    uchar * packet = fd_chunk_to_laddr( ctx->shred_net_in_mem, chunk );
    // memcpy( packet + sizeof(fd_net_hdrs_t), packet, sizeof(fd_shred_t) );
    fd_shred_t * shred = (fd_shred_t *)(packet + sizeof(fd_net_hdrs_t));
    memcpy( &ctx->shred, shred, sizeof(fd_shred_t) );
  }
}

static void
after_frag( fd_eqvoc_tile_ctx_t * ctx,
            ulong                 in_idx,
            ulong                 seq,
            ulong                 sig,
            ulong                 sz,
            ulong                 tsorig,
            fd_stem_context_t *   stem ) {
  (void)seq;
  (void)sig;
  (void)sz;
  (void)tsorig;
  (void)stem;

  if( FD_UNLIKELY( in_idx == ctx->contact_in_idx ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  } else if ( FD_UNLIKELY( in_idx == ctx->gossip_in_idx ) ) {
    fd_gossip_duplicate_shred_t * chunk = &ctx->duplicate_shred;
    ulong slot = ctx->duplicate_shred.slot;
    fd_pubkey_t const * from = &chunk->from;

    fd_eqvoc_proof_t * proof = fd_eqvoc_proof_query( ctx->eqvoc, slot, from );
    if( FD_UNLIKELY( !proof ) ) {

      if( FD_UNLIKELY( chunk->chunk_index == chunk->num_chunks - 1 ) ) {
        FD_LOG_WARNING(( "received last proof chunk first. unable to determine chunk len. ignoring." ));
        return;
      }

      proof = fd_eqvoc_proof_insert( ctx->eqvoc, slot, from );
      fd_pubkey_t const * leader = fd_epoch_leaders_get( ctx->eqvoc->leaders, slot );
      fd_eqvoc_proof_init( proof, leader, chunk->wallclock, chunk->num_chunks, chunk->chunk_len, ctx->eqvoc->bmtree_mem );
    }
    fd_eqvoc_proof_chunk_insert( proof, chunk );
    if( FD_UNLIKELY( fd_eqvoc_proof_complete( proof ) ) ) {
      int rc = fd_eqvoc_proof_verify( proof );
      FD_LOG_NOTICE(( "proof verify %d", rc ));
      fd_eqvoc_proof_remove( ctx->eqvoc, &proof->key );
    }

    return;
  }
  // } else if ( FD_UNLIKELY( in_idx == ctx->shred_net_in_idx ) ) {
  //   FD_LOG_NOTICE(( "got shred %lu %u", ctx->shred.slot, ctx->shred.idx ));
  // } else {
  //   FD_LOG_WARNING(( "unexpected in_idx %lu", in_idx ));
  // }

}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_eqvoc_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l,
                                                       alignof( fd_eqvoc_tile_ctx_t ),
                                                       sizeof( fd_eqvoc_tile_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->eqvoc.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[0] = *(fd_pubkey_t const *)
                             fd_type_pun_const( fd_keyload_load( tile->eqvoc.identity_key_path,
                                                                 /* pubkey only: */ 1 ) );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->seed, sizeof(ulong), 0 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_eqvoc_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_eqvoc_tile_ctx_t ), sizeof( fd_eqvoc_tile_ctx_t ) );
  void * stake_ci_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  void * eqvoc_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_align(), fd_eqvoc_footprint( 1 << 10, 1 << 10 ) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu",
                  scratch_top - (ulong)scratch - scratch_footprint( tile ),
                  scratch_top,
                  (ulong)scratch + scratch_footprint( tile )) );
  }

  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( stake_ci_mem, ctx->identity_key ) );
  ctx->eqvoc    = fd_eqvoc_join( fd_eqvoc_new( eqvoc_mem, 1 << 10, 1 << 10, 0 ) );

  ctx->contact_in_idx = fd_topo_find_tile_in_link( topo, tile, "gossip_voter", 0 );
  FD_TEST( ctx->contact_in_idx != ULONG_MAX );
  fd_topo_link_t * contact_in_link = &topo->links[tile->in_link_id[ctx->contact_in_idx]];
  ctx->contact_in_mem = topo->workspaces[topo->objs[contact_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->contact_in_chunk0 = fd_dcache_compact_chunk0( ctx->contact_in_mem, contact_in_link->dcache );
  ctx->contact_in_wmark  = fd_dcache_compact_wmark( ctx->contact_in_mem, contact_in_link->dcache, contact_in_link->mtu );

  ctx->gossip_in_idx = fd_topo_find_tile_in_link( topo, tile, "gossip_eqvoc", 0 );
  FD_TEST( ctx->gossip_in_idx != ULONG_MAX );
  fd_topo_link_t * gossip_in_link = &topo->links[tile->in_link_id[ctx->gossip_in_idx]];
  ctx->gossip_in_mem = topo->workspaces[topo->objs[gossip_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->gossip_in_chunk0 = fd_dcache_compact_chunk0( ctx->gossip_in_mem, gossip_in_link->dcache );
  ctx->gossip_in_wmark  = fd_dcache_compact_wmark( ctx->gossip_in_mem, gossip_in_link->dcache, gossip_in_link->mtu );

  ctx->shred_net_in_idx = fd_topo_find_tile_in_link( topo, tile, "shred_net", 0 );
  FD_TEST( ctx->shred_net_in_idx != ULONG_MAX );
  fd_topo_link_t * shred_net_in_link = &topo->links[tile->in_link_id[ctx->shred_net_in_idx]];
  ctx->shred_net_in_mem = topo->workspaces[topo->objs[shred_net_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->shred_net_in_chunk0 = fd_dcache_compact_chunk0( ctx->shred_net_in_mem, shred_net_in_link->dcache );
  ctx->shred_net_in_wmark  = fd_dcache_compact_wmark( ctx->shred_net_in_mem, shred_net_in_link->dcache, shred_net_in_link->mtu );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_eqvoc( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_eqvoc_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_eqvoc_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_eqvoc_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_eqvoc = {
    .name                     = "eqvoc",
    .loose_footprint          = loose_footprint,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
