#include <string.h>
#define _GNU_SOURCE

#include "../../disco/tiles.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "generated/fd_tower_tile_seccomp.h"

#define SENDER_OUT_IDX (0UL)

struct fd_tower_tile_ctx {
  ulong  replay_tower_in_idx;
  ulong  tile_cnt;
  ulong  tile_idx;

  fd_wksp_t * replay_in_mem;
  ulong       replay_in_chunk0;
  ulong       replay_in_wmark;

  fd_wksp_t * sender_out_mem;
  ulong       sender_out_chunk0;
  ulong       sender_out_wmark;
  ulong       sender_out_chunk;

  int   vote;
  fd_pubkey_t vote_acc[1];
  fd_pubkey_t validator_identity[1];
  fd_pubkey_t vote_authority[1];

  ulong * poh;
  ulong * root;
  fd_tower_t * tower;

  /* updated in during_frag and processed in after_frag */
  fd_hash_t bank_hash[1];
  fd_hash_t block_hash[1];
  fd_spad_t * vote_spad;
};
typedef struct fd_tower_tile_ctx fd_tower_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  /* clang-format off */
  ulong l = FD_LAYOUT_INIT;
  l       = FD_LAYOUT_APPEND( l, alignof(fd_tower_tile_ctx_t), sizeof(fd_tower_tile_ctx_t) );
  l       = FD_LAYOUT_APPEND( l, fd_spad_align(), FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT );
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
}

static void
during_frag( fd_tower_tile_ctx_t * ctx,
             ulong                in_idx,
             ulong                seq FD_PARAM_UNUSED,
             ulong                sig FD_PARAM_UNUSED,
             ulong                chunk,
             ulong                sz,
             ulong                ctl FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( in_idx == ctx->replay_tower_in_idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->replay_in_chunk0 || chunk > ctx->replay_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                    chunk,
                    sz,
                    ctx->replay_in_chunk0,
                    ctx->replay_in_wmark ));
    }

    /* Process the incoming tower fragment */
    FD_TEST( sz == 2*sizeof(fd_hash_t) );
    uchar * src = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
    memcpy( ctx->block_hash, src, sizeof(fd_hash_t) );
    memcpy( ctx->bank_hash, src + sizeof(fd_hash_t), sizeof(fd_hash_t) );
  }
}

static void
send_tower_sync( fd_tower_tile_ctx_t * ctx,
                 fd_stem_context_t   * stem ) {
  if( FD_UNLIKELY( !ctx->vote ) ) return;
  FD_LOG_NOTICE( ( "sending tower sync" ) );

  /* Build a vote state update based on current tower votes. */

  fd_txn_p_t * txn = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->sender_out_mem, ctx->sender_out_chunk );
  fd_tower_to_vote_txn( ctx->tower,
                        fd_fseq_query( ctx->root ),
                        ctx->bank_hash,
                        ctx->block_hash,
                        ctx->validator_identity,
                        ctx->vote_authority,
                        ctx->vote_acc,
                        txn,
                        ctx->vote_spad );

  /* TODO: Can use a smaller size, adjusted for payload length */
  ulong msg_sz = sizeof( fd_txn_p_t );
  fd_stem_publish( stem, SENDER_OUT_IDX, 1, ctx->sender_out_chunk, msg_sz, 0, 0, 0 );
  ctx->sender_out_chunk = fd_dcache_compact_next( ctx->sender_out_chunk,
                                                  msg_sz,
                                                  ctx->sender_out_chunk0,
                                                  ctx->sender_out_wmark );

  /* Dump the latest sent tower into the tower checkpoint file */
  //if( FD_LIKELY( ctx->tower_checkpt_fileno > 0 ) ) fd_restart_tower_checkpt( vote_bank_hash, ctx->tower, ctx->ghost, ctx->root, ctx->tower_checkpt_fileno );
}

/* lets w/out funk/blockstore/fork, we need to recieve the vote slot, and hashes using sig and over mcache dcache. */

static void
after_frag( fd_tower_tile_ctx_t * ctx FD_PARAM_UNUSED,
            ulong                in_idx FD_PARAM_UNUSED,
            ulong                seq,
            ulong                sig,
            ulong                sz,
            ulong                tsorig,
            ulong                tspub,
            fd_stem_context_t *  stem ) {
  (void)seq;
  (void)sz;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  ulong vote_slot = fd_disco_replay_tower_sig_slot(sig);

  /**********************************************************************/
  /* Consensus: send out a new vote by calling send_tower_sync          */
  /**********************************************************************/

  if( FD_UNLIKELY( ctx->vote && fd_fseq_query( ctx->poh ) == ULONG_MAX ) ) {
    /* Only proceed with voting if we're caught up. */

    FD_LOG_WARNING(( "still catching up. not voting." ));
  } else {
    //if( FD_UNLIKELY( !ctx->is_caught_up ) ) {
    //  ctx->is_caught_up = 1;
    //}

    /* Proceed according to how local and cluster are synchronized. */

    if( FD_LIKELY( vote_slot != FD_SLOT_NULL ) ) {

      /* Invariant check: the vote_slot must be in the frontier */

      //FD_TEST( fd_forks_query_const( ctx->forks, vote_slot ) );

      /* Vote locally */
      FD_LOG_NOTICE(("WE VOTE POW"));
      ulong root = fd_tower_vote( ctx->tower, vote_slot );
      FD_MGAUGE_SET( REPLAY, LAST_VOTED_SLOT, vote_slot );

      fd_tower_print( ctx->tower, root );

      /* Update to a new root, if there is one. */

      if ( FD_LIKELY ( root != FD_SLOT_NULL ) ) fd_fseq_update( ctx->root, root ); /* optimize for full tower (replay is keeping up) */
    }

    /* Send our updated tower to the cluster. */

    send_tower_sync( ctx, stem );
  }
}

static void
privileged_init( fd_topo_t *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile FD_PARAM_UNUSED ) {
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_ctx_t), sizeof(fd_tower_tile_ctx_t) );
  void * spad_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->tile_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->tile_idx = tile->kind_id;

  ctx->replay_tower_in_idx = fd_topo_find_tile_in_link( topo, tile, "replay_tower", ctx->tile_idx );
  FD_TEST( ctx->replay_tower_in_idx != ULONG_MAX );
  fd_topo_link_t * replay_tower_in_link = &topo->links[tile->in_link_id[ctx->replay_tower_in_idx]];
  ctx->replay_in_mem = topo->workspaces[topo->objs[replay_tower_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_tower_in_link->dcache );
  ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem,
                                                   replay_tower_in_link->dcache,
                                                   replay_tower_in_link->mtu );

  fd_topo_link_t * sender_out = &topo->links[ tile->out_link_id[ SENDER_OUT_IDX ] ];
  ctx->sender_out_mem         = topo->workspaces[ topo->objs[ sender_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->sender_out_chunk0      = fd_dcache_compact_chunk0( ctx->sender_out_mem, sender_out->dcache );
  ctx->sender_out_wmark       = fd_dcache_compact_wmark ( ctx->sender_out_mem, sender_out->dcache, sender_out->mtu );
  ctx->sender_out_chunk       = ctx->sender_out_chunk0;

  ctx->vote = tile->tower.vote;
  memcpy( ctx->validator_identity, fd_keyload_load( tile->tower.identity_key_path, 1 ), sizeof(fd_pubkey_t) );
  *ctx->vote_authority = *ctx->validator_identity; /* FIXME */
  memcpy( ctx->vote_acc, fd_keyload_load( tile->tower.vote_account_path, 1 ), sizeof(fd_pubkey_t) );

  /**********************************************************************/
  /* poh_slot fseq                                                     */
  /**********************************************************************/

  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ctx->poh = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );

  /**********************************************************************/
  /* tower                                                              */
  /**********************************************************************/

  ulong tower_obj_id = fd_pod_query_ulong( topo->props, "tower", ULONG_MAX );
  FD_TEST( tower_obj_id!=ULONG_MAX );
  ctx->tower = fd_tower_join( fd_topo_obj_laddr( topo, tower_obj_id ));

  ulong tower_root_obj_id = fd_pod_query_ulong( topo->props, "tower_root", ULONG_MAX );
  FD_TEST( tower_root_obj_id!=ULONG_MAX );
  ctx->root = fd_fseq_join( fd_topo_obj_laddr( topo, tower_root_obj_id ) );
  FD_TEST( ULONG_MAX==fd_fseq_query( ctx->root ) );

  /**********************************************************************/
  /* spad                                                               */
  /**********************************************************************/

  ctx->vote_spad = fd_spad_join( fd_spad_new( spad_mem, FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT ) );

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

#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_tower = {
    .name                     = "tower",
    .loose_footprint          = 0UL,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
