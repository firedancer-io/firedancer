#define _GNU_SOURCE

#include "../../disco/topo/fd_topo.h"
#include "generated/fd_tower_tile_seccomp.h"

#include "../../choreo/fd_choreo.h"

#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "../../funk/fd_funk_filemap.h"

#include "../../flamenco/runtime/fd_runtime.h"

#define SCRATCH_MAX   ( 4UL /*KiB*/ << 10 )
#define SCRATCH_DEPTH ( 4UL ) /* 4 scratch frames */


struct fd_tower_tile_ctx {
  fd_pubkey_t identity_key[1];

  fd_stake_ci_t *            stake_ci;
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;

  ulong       replay_in_idx;

  ulong       contact_in_idx;
  fd_wksp_t * contact_in_mem;
  ulong       contact_in_chunk0;
  ulong       contact_in_wmark;

  fd_gossip_duplicate_shred_t duplicate_shred;

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

  fd_funk_t * funk;

  fd_epoch_t * epoch;
  fd_tower_t * tower;
  fd_forks_t * forks;
  fd_ghost_t * ghost;

  ulong root;
  fd_tower_t * scratch;
};
typedef struct fd_tower_tile_ctx fd_tower_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_tower_tile_ctx_t), sizeof(fd_tower_tile_ctx_t)            ),
      fd_stake_ci_align(),          fd_stake_ci_footprint()                ),
      fd_epoch_align(),             fd_epoch_footprint( FD_VOTER_MAX )     ),
      fd_forks_align(),             fd_forks_footprint( FD_BLOCK_MAX )     ),
      fd_ghost_align(),             fd_ghost_footprint( FD_BLOCK_MAX )     ),
      fd_tower_align(),             fd_tower_footprint()                   ), /* our tower */
      fd_tower_align(),             fd_tower_footprint()                   ), /* scratch */
    scratch_align() );
}

// static void epoch_init( fd_tower_tile_ctx_t * ctx ) {
//   fd_funk_t *       funk    = ctx->funk;
//   fd_funk_txn_map_t txn_map = fd_funk_txn_map( ctx->funk, fd_funk_wksp( ctx->funk ) );

//   fd_funk_rec_key_t id  = fd_runtime_epoch_bank_key();
//   fd_funk_rec_query_t   query[1];
//   fd_funk_rec_t const * rec = fd_funk_rec_query_try( ctx->funk, NULL, &id, query );
//   void *                val = fd_funk_val( rec, fd_funk_wksp( ctx->funk ) );

//   uint magic = *(uint*)val;
//   FD_TEST( magic==FD_RUNTIME_ENC_BINCODE );

//   fd_bincode_decode_ctx_t epoch_bank_decode_ctx = {
//     .data    = (uchar*)val + sizeof(uint),
//     .dataend = (uchar*)val + fd_funk_val_sz( rec ),
//   };

//   fd_epoch_bank_t epoch_bank;
//   fd_epoch_bank_decode( &epoch_bank, &epoch_bank_decode_ctx );

//   fd_epoch_t *    epoch = ctx->epoch;
//   fd_funk_txn_t * txn   = fd_funk_txn_query( &xid, &txn_map );
// }

// static void
// during_frag( fd_tower_tile_ctx_t * ctx,
//              ulong                 in_idx,
//              ulong                 seq FD_PARAM_UNUSED,
//              ulong                 sig,
//              ulong                 chunk,
//              ulong                 sz,
//              ulong                 ctl FD_PARAM_UNUSED ) {

//   FD_LOG_NOTICE(( "tower got msg %lu", in_idx ));
//   if( FD_UNLIKELY( in_idx == ctx->gossip_in_idx ) ) {
//     uchar * packet = fd_chunk_to_laddr( ctx->gossip_in_mem, chunk );
//     memcpy( &ctx->duplicate_shred, packet, FD_GOSSIP_DUPLICATE_SHRED_FOOTPRINT );
//     FD_TEST( ctx->duplicate_shred.chunk_len <= sizeof(ctx->duplicate_shred_chunk) );
//     memcpy( ctx->duplicate_shred_chunk, packet + FD_GOSSIP_DUPLICATE_SHRED_FOOTPRINT, ctx->duplicate_shred.chunk_len );
//     ctx->duplicate_shred.chunk = ctx->duplicate_shred_chunk;
//   } else if ( FD_UNLIKELY( in_idx == ctx->shred_net_in_idx ) ) {
//     if( FD_UNLIKELY( chunk < ctx->shred_net_in_chunk0 || chunk > ctx->shred_net_in_wmark ) ) {
//       FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
//                     chunk,
//                     sz,
//                     ctx->shred_net_in_chunk0,
//                     ctx->shred_net_in_wmark ));
//     }

//     FD_LOG_NOTICE(( "tower got shred" ));
//     uchar const * packet = fd_chunk_to_laddr_const( ctx->shred_net_in_mem, chunk );
//     fd_shred_t * shred = (fd_shred_t *)( packet + fd_disco_netmux_sig_hdr_sz( sig ) );
//     memcpy( &ctx->shred, shred, sizeof(fd_shred_t) );
//   }
// }

static void
after_frag( fd_tower_tile_ctx_t * ctx,
            ulong                 in_idx,
            FD_PARAM_UNUSED ulong                 seq,
            ulong                 sig,
            FD_PARAM_UNUSED ulong                 sz,
            FD_PARAM_UNUSED ulong                 tsorig,
            FD_PARAM_UNUSED ulong                 tspub,
            FD_PARAM_UNUSED fd_stem_context_t *   stem ) {

  if( FD_LIKELY( in_idx == ctx->replay_in_idx ) ) {
    ulong slot        = sig << 32;
    ulong parent_slot = fd_ulong_extract_lsb( sig, 32 );

    if( FD_UNLIKELY( (uint)parent_slot==UINT_MAX ) ) {
      fd_epoch_init( ctx->epoch, /* TODO bank mgr epoch bank */ )
      fd_ghost_init( ctx->ghost, slot );
      fd_tower_from_vote_acc( ctx->tower, ctx->funk, snapshot_fork->slot_ctx->funk_txn, &key );
      fd_tower_print( ctx->tower, ctx->root );
      return;
    }

    fd_ghost_node_t const * ghost_node = fd_ghost_insert( ctx->ghost, parent_slot, slot );
    FD_TEST( ghost_node );

    // ulong prev_confirmed = ctx->forks->confirmed;
    // ulong prev_finalized = ctx->forks->finalized;
    fd_forks_update( ctx->forks, ctx->epoch, ctx->funk, ctx->ghost, slot );

    fd_forks_print( ctx->forks );
    fd_ghost_print( ctx->ghost, ctx->epoch, fd_ghost_root( ctx->ghost ) );
    fd_tower_print( ctx->tower, ctx->root );

    fd_funk_txn_xid_t txn_xid   = { .ul = { slot, slot } };
    fd_funk_txn_map_t txn_map   = fd_funk_txn_map( ctx->funk, fd_funk_wksp( ctx->funk ) );
    fd_funk_txn_t *   funk_txn  = fd_funk_txn_query( &txn_xid, &txn_map );
    ulong             vote_slot = fd_tower_vote_slot( ctx->tower, ctx->epoch, ctx->funk, funk_txn, ctx->ghost, ctx->scratch );

    if( FD_UNLIKELY( vote_slot == FD_SLOT_NULL )) return; /* nothing to vote on */
    FD_TEST( fd_forks_query_const( ctx->forks, vote_slot ) );
    ulong root = fd_tower_vote( ctx->tower, vote_slot );
    if( FD_LIKELY( root != FD_SLOT_NULL ) ) ctx->root = root; /* optimize for full tower (replay is keeping up) */
    // send_tower_sync( ctx );
    // ctx->metrics.last_voted_slot = vote_slot;
  }




  // if( FD_UNLIKELY( in_idx == ctx->contact_in_idx ) ) {
  //   finalize_new_cluster_contact_info( ctx );
  //   return;
  // } else if ( FD_UNLIKELY( in_idx == ctx->gossip_in_idx ) ) {
  //   // fd_gossip_duplicate_shred_t * chunk = &ctx->duplicate_shred;
  //   // ulong slot = ctx->duplicate_shred.slot;
  //   // fd_pubkey_t const * from = &chunk->from;

  //   // fd_tower_proof_t * proof = fd_tower_proof_query( ctx->tower, slot, from );
  //   // if( FD_UNLIKELY( !proof ) ) {

  //   //   if( FD_UNLIKELY( chunk->chunk_index == chunk->num_chunks - 1 ) ) {
  //   //     FD_LOG_WARNING(( "received last proof chunk first. unable to determine chunk len. ignoring." ));
  //   //     return;
  //   //   }

  //   //   proof = fd_tower_proof_insert( ctx->tower, slot, from );
  //   //   fd_pubkey_t const * leader = fd_epoch_leaders_get( ctx->tower->leaders, slot );
  //   //   fd_tower_proof_init( proof, leader, chunk->wallclock, chunk->num_chunks, chunk->chunk_len, ctx->tower->bmtree_mem );
  //   // }
  //   // fd_tower_proof_chunk_insert( proof, chunk );
  //   // if( FD_UNLIKELY( fd_tower_proof_complete( proof ) ) ) {
  //   //   int rc = fd_tower_proof_verify( proof );
  //   //   FD_LOG_NOTICE(( "proof verify %d", rc ));
  //   //   fd_tower_proof_remove( ctx->tower, &proof->key );
  //   // }

  //   return;
  // } else if ( FD_UNLIKELY( in_idx == ctx->shred_net_in_idx ) ) {


  // } else {
  //   FD_LOG_WARNING(( "tower got unexpected in_idx %lu", in_idx ));
  // }
  // // } else if ( FD_UNLIKELY( in_idx == ctx->shred_net_in_idx ) ) {
  // //   FD_LOG_NOTICE(( "got shred %lu %u", ctx->shred.slot, ctx->shred.idx ));
  // // } else {
  // //   FD_LOG_WARNING(( "unexpected in_idx %lu", in_idx ));
  // // }

}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_ctx_t), sizeof(fd_tower_tile_ctx_t)        );
  void * stake_ci_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),          fd_stake_ci_footprint()            );
  void * epoch_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(),             fd_epoch_footprint( FD_VOTER_MAX ) );
  void * forks_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(),             fd_forks_footprint( FD_BLOCK_MAX ) );
  void * ghost_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),             fd_ghost_footprint( FD_BLOCK_MAX ) );
  void * tower_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),             fd_tower_footprint()               );
  void * scratch_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),             fd_tower_footprint()               );
  ulong scratch_top         = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align()                                                  );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu",
                  scratch_top - (ulong)scratch - scratch_footprint( tile ),
                  scratch_top,
                  (ulong)scratch + scratch_footprint( tile )) );
  }

  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( stake_ci_mem, ctx->identity_key ) );

  ctx->epoch   = fd_epoch_join( fd_epoch_new( epoch_mem, FD_VOTER_MAX       ) );
  ctx->forks   = fd_forks_join( fd_forks_new( forks_mem, FD_BLOCK_MAX, 42UL ) );
  ctx->ghost   = fd_ghost_join( fd_ghost_new( ghost_mem, 42UL, FD_BLOCK_MAX ) );
  ctx->tower   = fd_tower_join( fd_tower_new( tower_mem                     ) );
  ctx->scratch = fd_tower_join( fd_tower_new( scratch_mem                   ) );

  ctx->funk = fd_funk_open_file( tile->exec.funk_file, 1UL, 0UL, 0UL, 0UL, 0UL, FD_FUNK_READONLY, NULL );
  FD_TEST( ctx->funk );

  ctx->replay_in_idx = fd_topo_find_tile_in_link( topo, tile, "replay_tower", 0 );
  FD_TEST( ctx->replay_in_idx != ULONG_MAX );
  FD_LOG_NOTICE(( "replay_in_idx %lu", ctx->replay_in_idx ));

  ctx->contact_in_idx = fd_topo_find_tile_in_link( topo, tile, "gossip_voter", 0 );
  FD_TEST( ctx->contact_in_idx != ULONG_MAX );
  fd_topo_link_t * contact_in_link = &topo->links[tile->in_link_id[ctx->contact_in_idx]];
  ctx->contact_in_mem = topo->workspaces[topo->objs[contact_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->contact_in_chunk0 = fd_dcache_compact_chunk0( ctx->contact_in_mem, contact_in_link->dcache );
  ctx->contact_in_wmark  = fd_dcache_compact_wmark( ctx->contact_in_mem, contact_in_link->dcache, contact_in_link->mtu );

  ctx->gossip_in_idx = fd_topo_find_tile_in_link( topo, tile, "gossip_tower", 0 );
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

  populate_sock_filter_policy_fd_tower_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_tower_tile_instr_cnt;
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

#define STEM_CALLBACK_CONTEXT_TYPE  fd_tower_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_tower_tile_ctx_t)
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_tower = {
    .name                     = "tower",
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
