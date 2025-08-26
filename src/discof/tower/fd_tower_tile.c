#define _GNU_SOURCE

#include "../../disco/tiles.h"
#include "generated/fd_tower_tile_seccomp.h"

#include "../../choreo/fd_choreo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../flamenco/fd_flamenco_base.h"

#define LOGGING 0

#define IN_KIND_GOSSIP ( 0)
#define IN_KIND_REPLAY ( 1)
#define IN_KIND_SNAP   ( 2)
#define MAX_IN_LINKS   (16)

#define SIGN_OUT_IDX (0)

#define VOTER_FOOTPRINT ( 40UL ) /* serialized footprint */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

typedef struct {
  fd_pubkey_t identity_key[1];
  fd_pubkey_t vote_acc[1];
  ulong       seed;

  uchar    in_kind [ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  ulong       root_out_idx;
  fd_wksp_t * root_out_mem;
  ulong       root_out_chunk0;
  ulong       root_out_wmark;
  ulong       root_out_chunk;

  ulong       send_out_idx;
  fd_wksp_t * send_out_mem;
  ulong       send_out_chunk0;
  ulong       send_out_wmark;
  ulong       send_out_chunk;

  fd_epoch_t * epoch;
  fd_ghost_t * ghost;
  fd_tower_t * tower;

  ulong root;
  ulong processed; /* highest processed slot (replayed & counted votes) */
  ulong confirmed; /* highest confirmed slot (2/3 of stake has voted) */
  ulong finalized; /* highest finalized slot (2/3 of stake has rooted) */

  fd_gossip_duplicate_shred_t duplicate_shred;
  fd_gossip_vote_t            vote;
  uchar *                     epoch_voters_buf;
  fd_lockout_offset_t         lockouts[FD_TOWER_VOTE_MAX];
  fd_replay_slot_info_t       replay_slot_info;
  ulong                       replay_towers_cnt;
  fd_replay_tower_t           replay_towers[FD_REPLAY_TOWER_VOTE_ACC_MAX];
  fd_tower_t *                vote_towers[FD_REPLAY_TOWER_VOTE_ACC_MAX];
  fd_pubkey_t                 vote_keys[FD_REPLAY_TOWER_VOTE_ACC_MAX];
  int                         replay_out_eom;
  fd_snapshot_manifest_t      snapshot_manifest;
} ctx_t;

static void
update_ghost( ctx_t * ctx ) {
  fd_epoch_t * epoch = ctx->epoch;
  fd_ghost_t * ghost = ctx->ghost;

  fd_voter_t * epoch_voters = fd_epoch_voters( epoch );
  for( ulong i = 0; i < ctx->replay_towers_cnt; i++ ) {
    fd_replay_tower_t const * replay_tower = &ctx->replay_towers[i];
    fd_pubkey_t const *       pubkey       = &replay_tower->key;
    fd_voter_state_t const *  voter_state  = (fd_voter_state_t *)fd_type_pun_const( replay_tower->vote_acc_data );
    fd_tower_t *              tower        = ctx->vote_towers[i];

    /* Look up the voter for this vote account */
    fd_voter_t * voter = fd_epoch_voters_query( epoch_voters, *pubkey, NULL );
    if( FD_UNLIKELY( !voter ) ) {
      /* This means that the cached list of epoch voters is not in sync with the list passed
         through from replay. This likely means that we have crossed an epoch boundary and the
         epoch_voter list has not been updated.

         TODO: update the set of account in epoch_voter's to match the list received from replay,
               so that epoch_voters is correct across epoch boundaries. */
      FD_LOG_CRIT(( "[%s] voter %s was not in epoch voters", __func__, FD_BASE58_ENC_32_ALLOCA(pubkey) ));
      continue;
    }

    voter->stake = replay_tower->stake; /* update the voters stake */

    if( FD_UNLIKELY( fd_voter_state_cnt( voter_state ) == 0 ) ) continue; /* skip voters with no votes */

    ulong vote = fd_tower_votes_peek_tail( tower )->slot; /* peek last vote from the tower */
    ulong root = fd_voter_state_root( voter_state );

    /* Only process votes for slots >= root. */
    if( FD_LIKELY( vote != FD_SLOT_NULL && vote >= fd_ghost_root( ghost )->slot ) ) {
      fd_ghost_ele_t const * ele = fd_ghost_query_const( ghost, fd_ghost_hash( ghost, vote ) );

      /* It is an invariant violation if the vote slot is not in ghost.
         These votes come from replay ie. on-chain towers stored in vote
         accounts which implies every vote slot must have been processed
         by the vote program (ie. replayed) and therefore in ghost. */

      if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "[%s] voter %s's vote slot %lu was not in ghost", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), vote ));
      fd_ghost_replay_vote( ghost, voter, &ele->key );
      double pct = (double)ele->replay_stake / (double)epoch->total_stake;
      if( FD_UNLIKELY( pct > FD_CONFIRMED_PCT ) ) ctx->confirmed = fd_ulong_max( ctx->confirmed, ele->slot );
    }

    /* Check if this voter's root >= ghost root. We can't process roots
       before our own root because it was already pruned. */

    if( FD_LIKELY( root != FD_SLOT_NULL && root >= fd_ghost_root( ghost )->slot ) ) {
      fd_ghost_ele_t const * ele = fd_ghost_query( ghost, fd_ghost_hash( ghost, root ) );

      /* Error if the node's root slot is not in ghost. This is an
         invariant violation, because we know their tower must be on the
         same fork as this current one that we're processing, and so by
         definition their root slot must be in our ghost (ie. we can't
         have rooted past it or be on a different fork). */

      if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "[%s] voter %s's root slot %lu was not in ghost", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), root ));

      fd_ghost_rooted_vote( ghost, voter, root );
      double pct = (double)ele->rooted_stake / (double)epoch->total_stake;
      if( FD_UNLIKELY( pct > FD_FINALIZED_PCT ) ) ctx->finalized = fd_ulong_max( ctx->finalized, ele->slot );
    }
  }
}

static void
after_frag_replay( ctx_t * ctx, fd_replay_slot_info_t * slot_info, ulong tsorig, fd_stem_context_t * stem ) {
  /* If we have not received any votes, something is wrong. */
  if( FD_UNLIKELY( !ctx->replay_towers_cnt ) ) {
    FD_LOG_WARNING(( "No vote states received from replay. No votes will be sent"));
    return;
  }

  /* Parse the replay vote towers */
  for( ulong i = 0; i < ctx->replay_towers_cnt; i++ ) {
    fd_tower_votes_remove_all( ctx->vote_towers[i] );
    fd_tower_from_vote_acc_data( ctx->replay_towers[i].vote_acc_data, ctx->vote_towers[i] );
    ctx->vote_keys[i] = ctx->replay_towers[i].key;

    /* If this is our vote account, and our tower has not been initialized, initialize it with our vote state */
    if( FD_UNLIKELY( fd_tower_votes_empty( ctx->tower ) &&
      memcmp( &ctx->vote_keys[i], ctx->vote_acc, sizeof(fd_pubkey_t) ) == 0 ) ) {
      fd_tower_from_vote_acc_data( ctx->replay_towers[i].vote_acc_data, ctx->tower );
    }
  }

  /* Update ghost with the vote account states received from replay. */
  fd_ghost_ele_t  const * ghost_ele  = fd_ghost_insert( ctx->ghost, &slot_info->parent_block_id, slot_info->slot, &slot_info->block_id, ctx->epoch->total_stake );
  FD_TEST( ghost_ele );
  update_ghost( ctx );

  /* Find the lowest vote slot to vote on. */
  ulong vote_slot = fd_tower_vote_slot(
    ctx->tower,
    ctx->epoch,
    ctx->vote_keys,
    ctx->vote_towers,
    ctx->replay_towers_cnt,
    ctx->ghost );
  if( FD_UNLIKELY( vote_slot == FD_SLOT_NULL ) ) return; /* nothing to vote on */

  ulong root = fd_tower_vote( ctx->tower, vote_slot );
  if( FD_LIKELY( root != FD_SLOT_NULL ) ) {
    fd_hash_t const * root_block_id = fd_ghost_hash( ctx->ghost, root );
    if( FD_UNLIKELY( !root_block_id ) ) {
      FD_LOG_WARNING(( "Lowest vote slot %lu is not in ghost, skipping publish", root ));
    } else {
      fd_ghost_publish( ctx->ghost, root_block_id );
      uchar * chunk  = fd_chunk_to_laddr( ctx->root_out_mem, ctx->root_out_chunk );
      memcpy( chunk, root_block_id, sizeof(fd_hash_t) );
      fd_stem_publish( stem, ctx->root_out_idx, root, ctx->root_out_chunk, sizeof(fd_hash_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
      ctx->root_out_chunk = fd_dcache_compact_next( ctx->root_out_chunk, sizeof(fd_hash_t), ctx->root_out_chunk0, ctx->root_out_wmark );
    }
    ctx->root = root;
  }

  /* Send our updated tower to the cluster. */

  fd_txn_p_t * vote_txn = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->send_out_mem, ctx->send_out_chunk );
  fd_tower_to_vote_txn( ctx->tower, ctx->root, ctx->lockouts, &slot_info->bank_hash, &slot_info->block_hash, ctx->identity_key, ctx->identity_key, ctx->vote_acc, vote_txn );
  FD_TEST( !fd_tower_votes_empty( ctx->tower ) );
  FD_TEST( vote_txn->payload_sz > 0UL );
  fd_stem_publish( stem, ctx->send_out_idx, vote_slot, ctx->send_out_chunk, sizeof(fd_txn_p_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );

# if LOGGING
  fd_ghost_print( ctx->ghost, ctx->epoch->total_stake, fd_ghost_root( ctx->ghost ) );
  fd_tower_print( ctx->tower, ctx->root );
# endif
}

static void
after_frag_snap( ctx_t                  * ctx,
                 ulong                    sig,
                 fd_snapshot_manifest_t * manifest ) {
  if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) return;
  fd_hash_t manifest_block_id = { .ul = { 0xf17eda2ce7b1d } }; /* FIXME manifest_block_id */
  fd_ghost_init( ctx->ghost, manifest->slot, &manifest_block_id );

  fd_voter_t * epoch_voters = fd_epoch_voters( ctx->epoch );
  for(ulong i = 0; i< manifest->vote_accounts_len; i++) {
    if( FD_UNLIKELY( manifest->vote_accounts[i].stake == 0 ) ) continue;
    fd_pubkey_t const * pubkey = (fd_pubkey_t const *)fd_type_pun_const( manifest->vote_accounts[i].vote_account_pubkey );
#   if FD_EPOCH_USE_HANDHOLDING
    FD_TEST( !fd_epoch_voters_query( epoch_voters, *pubkey, NULL ) );
    FD_TEST( fd_epoch_voters_key_cnt( epoch_voters ) < fd_epoch_voters_key_max( epoch_voters ) );
#   endif
    fd_voter_t * voter = fd_epoch_voters_insert( epoch_voters, *pubkey );
#   if FD_EPOCH_USE_HANDHOLDING
    FD_TEST( 0==memcmp( voter->key.uc, pubkey->uc, sizeof(fd_pubkey_t) ) );
    FD_TEST( fd_epoch_voters_query( epoch_voters, voter->key, NULL ) );
#   endif
    voter->stake             = manifest->vote_accounts[i].stake;
    voter->replay_vote.slot  = FD_SLOT_NULL;
    voter->gossip_vote.slot  = FD_SLOT_NULL;
    voter->rooted_vote.slot  = FD_SLOT_NULL;
    ctx->epoch->total_stake += voter->stake;
    // FD_LOG_NOTICE(( "inserting %s %lu", FD_BASE58_ENC_32_ALLOCA( voter->key.uc ), voter->stake ));
  }
}

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
    FD_LAYOUT_INIT,
      alignof(ctx_t),   sizeof(ctx_t)                                       ),
      fd_epoch_align(), fd_epoch_footprint( FD_REPLAY_TOWER_VOTE_ACC_MAX )  ),
      fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX )                  ),
      fd_tower_align(), fd_tower_footprint()                                ), /* our tower */
      128UL,            VOTER_FOOTPRINT * FD_REPLAY_TOWER_VOTE_ACC_MAX      ), /* epoch voters */
      fd_tower_align(), fd_tower_footprint() * FD_REPLAY_TOWER_VOTE_ACC_MAX ), /* vote towers */
    scratch_align() );
}

static inline int
before_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq     FD_PARAM_UNUSED,
             ulong   sig ) {
  if( ctx->in_kind[in_idx]==IN_KIND_GOSSIP ){
    return sig!=FD_GOSSIP_UPDATE_TAG_VOTE &&
           sig!=FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED;
  }
  return 0;
}

static void
during_frag( ctx_t * ctx,
             ulong   in_idx FD_PARAM_UNUSED,
             ulong   seq    FD_PARAM_UNUSED,
             ulong   sig    FD_PARAM_UNUSED,
             ulong   chunk,
             ulong   sz     FD_PARAM_UNUSED,
             ulong   ctl    FD_PARAM_UNUSED ) {
  uint          in_kind     = ctx->in_kind[in_idx];
  uchar const * chunk_laddr = fd_chunk_to_laddr( ctx->in_links[in_idx].mem, chunk );
  switch( in_kind ) {
  case IN_KIND_GOSSIP: {                                                                                 break; }
  case IN_KIND_REPLAY: {
    if(      FD_UNLIKELY( sig==FD_REPLAY_SIG_SLOT_INFO  ) ) memcpy( &ctx->replay_slot_info,      chunk_laddr, sizeof(fd_replay_slot_info_t)      );
    else if( FD_LIKELY(   sig==FD_REPLAY_SIG_VOTE_STATE ) ) {
      if( FD_UNLIKELY( fd_frag_meta_ctl_som( ctl ) ) ) ctx->replay_towers_cnt = 0;
      if( FD_UNLIKELY( ctx->replay_towers_cnt >= FD_REPLAY_TOWER_VOTE_ACC_MAX ) ) FD_LOG_ERR(( "tower received more vote states than expected" ));
      memcpy( &ctx->replay_towers[ctx->replay_towers_cnt++], chunk_laddr, sizeof(fd_replay_tower_t) );
      ctx->replay_out_eom = fd_frag_meta_ctl_eom( ctl );
    }
    else FD_LOG_ERR(( "unexpected replay message sig %lu", sig ));
    break;
  }
  case IN_KIND_SNAP:   {
    if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) memcpy( &ctx->snapshot_manifest, chunk_laddr, sizeof(fd_snapshot_manifest_t) );
    break;
  }
  default: FD_LOG_ERR(( "unexpected input kind %u", in_kind ));
  }
}

static void
after_frag( ctx_t *             ctx,
            ulong               in_idx,
            ulong               seq     FD_PARAM_UNUSED,
            ulong               sig,
            ulong               sz      FD_PARAM_UNUSED,
            ulong               tsorig,
            ulong               tspub   FD_PARAM_UNUSED,
            fd_stem_context_t * stem ) {
  uint in_kind = ctx->in_kind[in_idx];
  switch( in_kind ) {
  case IN_KIND_GOSSIP: {                                                               break; }
  case IN_KIND_REPLAY: {
    /* Do nothing until we have received the eom message, indicating all the vote states have been received. */
    if( FD_UNLIKELY( sig == FD_REPLAY_SIG_VOTE_STATE && ctx->replay_out_eom ) ) after_frag_replay( ctx, &ctx->replay_slot_info, tsorig, stem );
    break;
  }
  case IN_KIND_SNAP:   { after_frag_snap  ( ctx, sig, &ctx->snapshot_manifest       ); break; }
  default: FD_LOG_ERR(( "Unexpected input kind %u", in_kind ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx            = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),   sizeof(ctx_t)                                       );
  void * epoch_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(), fd_epoch_footprint( FD_REPLAY_TOWER_VOTE_ACC_MAX )  );
  void * ghost_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX )                  );
  void * tower_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(), fd_tower_footprint()                                );
  void * voter_mem       = FD_SCRATCH_ALLOC_APPEND( l, 128UL,            VOTER_FOOTPRINT * FD_REPLAY_TOWER_VOTE_ACC_MAX      );
  uchar * vote_tower_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(), fd_tower_footprint() * FD_REPLAY_TOWER_VOTE_ACC_MAX );
  ulong scratch_top      = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align()                                                       );
  FD_TEST( scratch_top == (ulong)scratch + scratch_footprint( tile ) );

  ctx->epoch   = fd_epoch_join( fd_epoch_new( epoch_mem, FD_REPLAY_TOWER_VOTE_ACC_MAX ) );
  ctx->ghost   = fd_ghost_join( fd_ghost_new( ghost_mem, FD_BLOCK_MAX, 42UL         ) );
  ctx->tower   = fd_tower_join( fd_tower_new( tower_mem                             ) );

  for( ulong i = 0; i < FD_REPLAY_TOWER_VOTE_ACC_MAX; i++ ) {
    ctx->vote_towers[i] = fd_tower_join( fd_tower_new( vote_tower_mem + ( i * fd_tower_footprint() ) ) );
  }
  ctx->replay_out_eom    = 0;
  ctx->replay_towers_cnt = 0;

  ctx->epoch_voters_buf = voter_mem;

  memcpy( ctx->identity_key->uc, fd_keyload_load( tile->tower.identity_key_path, 1 ), sizeof(fd_pubkey_t) );

  if( FD_UNLIKELY( !fd_base58_decode_32( tile->tower.vote_acc_path, ctx->vote_acc->uc ) ) ) {
    const uchar * vote_key = fd_keyload_load( tile->tower.vote_acc_path, 1 );
    memcpy( ctx->vote_acc->uc, vote_key, sizeof(fd_pubkey_t) );
  }

  if( FD_UNLIKELY( tile->in_cnt > MAX_IN_LINKS ) ) FD_LOG_ERR(( "repair tile has too many input links" ));

  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if(        0==strcmp( link->name, "gossip_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_GOSSIP;
    } else if( 0==strcmp( link->name, "replay_tower" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_REPLAY;
    } else if( 0==strcmp( link->name, "snap_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SNAP;
    } else {
      FD_LOG_ERR(( "tower tile has unexpected input link %s", link->name ));
    }
    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;
  }

  ctx->root_out_idx = fd_topo_find_tile_out_link( topo, tile, "root_out", 0 );
  FD_TEST( ctx->root_out_idx!= ULONG_MAX );
  fd_topo_link_t * root_out = &topo->links[ tile->out_link_id[ ctx->root_out_idx ] ];
  ctx->root_out_mem         = topo->workspaces[ topo->objs[ root_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->root_out_chunk0      = fd_dcache_compact_chunk0( ctx->root_out_mem, root_out->dcache );
  ctx->root_out_wmark       = fd_dcache_compact_wmark ( ctx->root_out_mem, root_out->dcache, root_out->mtu );
  ctx->root_out_chunk       = ctx->root_out_chunk0;
  FD_TEST( fd_dcache_compact_is_safe( ctx->root_out_mem, root_out->dcache, root_out->mtu, root_out->depth ) );

  ctx->send_out_idx = fd_topo_find_tile_out_link( topo, tile, "tower_send", 0 );
  FD_TEST( ctx->send_out_idx!=ULONG_MAX );
  fd_topo_link_t * send_out = &topo->links[ tile->out_link_id[ ctx->send_out_idx ] ];
  ctx->send_out_mem         = topo->workspaces[ topo->objs[ send_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->send_out_chunk0      = fd_dcache_compact_chunk0( ctx->send_out_mem, send_out->dcache );
  ctx->send_out_wmark       = fd_dcache_compact_wmark ( ctx->send_out_mem, send_out->dcache, send_out->mtu );
  ctx->send_out_chunk       = ctx->send_out_chunk0;
  FD_TEST( fd_dcache_compact_is_safe( ctx->send_out_mem, send_out->dcache, send_out->mtu, send_out->depth ) );
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

#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
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
