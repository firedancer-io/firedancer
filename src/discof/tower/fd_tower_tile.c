#define _GNU_SOURCE

#include "../../choreo/fd_choreo.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/topo/fd_topo.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "generated/fd_tower_tile_seccomp.h"

#define IN_KIND_GOSSIP ( 0)
#define IN_KIND_REPLAY ( 1)
#define IN_KIND_STAKE  ( 2)
#define IN_KIND_SIGN   ( 3)
#define MAX_IN_LINKS   (16)

#define SIGN_OUT_IDX (0)

#define VOTER_MAX       ( 4096UL )
#define VOTER_FOOTPRINT ( 40UL ) /* serialized footprint */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

typedef struct {
  fd_pubkey_t       identity_key[1];
  fd_pubkey_t       vote_acc[1];
  fd_funk_rec_key_t funk_key;
  ulong             seed;

  uchar    in_kind [MAX_IN_LINKS];
  in_ctx_t in_links[MAX_IN_LINKS];

  ulong replay_out_idx;

  ulong       send_out_idx;
  fd_wksp_t * send_out_mem;
  ulong       send_out_chunk0;
  ulong       send_out_wmark;
  ulong       send_out_chunk;

  /* If there are forks across an epoch boundary, then there can be multiple versions
     of the epoch_stakes in the epoch until the forks resolve, i.e. the first root
     in the new epoch. Tower needs to keep track of all the vote_account & stakes per
     fork until the forks resolve. */

  fd_epoch_t * * epoch_versions;
  fd_epoch_t * epoch; /* The current working version of the epoch */

  fd_ghost_t * ghost;
  fd_tower_t * tower;

  ulong        root;
  ulong        processed; /* highest processed slot (replayed & counted votes) */
  ulong        confirmed; /* highest confirmed slot (2/3 of stake has voted) */
  ulong        finalized; /* highest finalized slot (2/3 of stake has rooted) */

  fd_hash_t                   bank_hash;   /* bank hash of the slot received from replay */
  fd_hash_t                   block_hash;  /* last microblock header hash of slot received from replay */
  fd_hash_t                   slot_hash;   /* hash_id of the slot received from replay (block id)*/
  fd_hash_t                   parent_hash; /* parent hash_id of the slot received from replay */

  fd_gossip_duplicate_shred_t duplicate_shred;
  uchar                       duplicate_shred_chunk[FD_EQVOC_PROOF_CHUNK_SZ];

  int stake_weight_received; /* terrible hack around the fact that stake weights publishes twice every epoch transition, and we only want to read the first */

  struct {
    ulong epoch;
    ulong staked_cnt;
    ulong start_slot;
    ulong slot_cnt;
    ulong excluded_stake;
    ulong vote_keyed_lsched;
  } stake_weight_meta;

  uchar *                     epoch_voters_buf;
  char                        funk_file[PATH_MAX];
  fd_funk_t                   funk[1];
  fd_gossip_vote_t            gossip_vote;
  fd_lockout_offset_t         lockouts[FD_TOWER_VOTE_MAX];
  fd_tower_t *                scratch;
  uchar *                     vote_ix_buf;
} ctx_t;

static void
update_epoch( ctx_t * ctx, ulong sz ) {
  FD_LOG_NOTICE(( "updating epoch with stake weights sz: %lu", sz ));
  fd_voter_t * epoch_voters = fd_epoch_voters( ctx->epoch );
  ctx->epoch->total_stake   = 0;

  ulong off = 0;
  while( FD_LIKELY( off < sz ) ) {
    fd_vote_stake_weight_t * voter_stake = (fd_vote_stake_weight_t *)fd_type_pun( ctx->epoch_voters_buf + off );
    off += sizeof(fd_vote_stake_weight_t);

#   if FD_EPOCH_USE_HANDHOLDING
    FD_LOG_NOTICE(( "pubkey: %s", FD_BASE58_ENC_32_ALLOCA(&voter_stake->vote_key) ));
    FD_TEST( !fd_epoch_voters_query( epoch_voters, voter_stake->vote_key, NULL ) );
    FD_TEST( fd_epoch_voters_key_cnt( epoch_voters ) < fd_epoch_voters_key_max( epoch_voters ) );
#   endif

    fd_voter_t * voter = fd_epoch_voters_insert( epoch_voters, voter_stake->vote_key );
    voter->rec.uc[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_FUNK_KEY_TYPE_ACC;

#   if FD_EPOCH_USE_HANDHOLDING
    FD_TEST( 0 == memcmp( &voter->key, &voter_stake->vote_key, sizeof(fd_pubkey_t) ) );
    FD_TEST( fd_epoch_voters_query( epoch_voters, voter->key, NULL ) );
#   endif

    voter->stake            = voter_stake->stake;
    voter->replay_vote.slot = FD_SLOT_NULL;
    voter->gossip_vote.slot = FD_SLOT_NULL;
    voter->rooted_vote.slot = FD_SLOT_NULL;

    ctx->epoch->total_stake += voter_stake->stake;
  }
}

static void
update_ghost( ctx_t * ctx, fd_funk_txn_t * txn ) {
  fd_funk_t *  funk  = ctx->funk;
  fd_epoch_t * epoch = ctx->epoch;
  fd_ghost_t * ghost = ctx->ghost;

  fd_voter_t * epoch_voters = fd_epoch_voters( epoch );
  for( ulong i = 0; i < fd_epoch_voters_slot_cnt( epoch_voters ); i++ ) {
    if( FD_LIKELY( fd_epoch_voters_key_inval( epoch_voters[i].key ) ) ) continue /* most slots are empty */;

    /* TODO we can optimize this funk query to only check through the
       last slot on this fork this function was called on. currently
       rec_query_global traverses all the way back to the root. */

    fd_voter_t *             voter = &epoch_voters[i];

    /* Fetch the vote account's vote slot and root slot from the vote
       account, re-trying if there is a Funk conflict. */

    ulong vote = FD_SLOT_NULL;
    ulong root = FD_SLOT_NULL;

    for(;;) {
      fd_funk_rec_query_t   query;
      fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, txn, &voter->rec, NULL, &query );
      if( FD_UNLIKELY( !rec ) ) break;
      fd_voter_state_t const * state = fd_voter_state( funk, rec );
      if( FD_UNLIKELY( !state ) ) break;
      vote = fd_voter_state_vote( state );
      root = fd_voter_state_root( state );
      if( FD_LIKELY( fd_funk_rec_query_test( &query ) == FD_FUNK_SUCCESS ) ) break;
    }

    /* Only process votes for slots >= root. Ghost requires vote slot
        to already exist in the ghost tree. */
    if( FD_LIKELY( vote != FD_SLOT_NULL && vote >= fd_ghost_root( ghost )->slot ) ) {
      /* Check if it has crossed the equivocation safety and optimistic
         confirmation thresholds. */

      fd_ghost_ele_t const * ele = fd_ghost_query_const( ghost, fd_ghost_hash( ghost, vote ) );

      /* Error if the node's vote slot is not in ghost. This is an
         invariant violation, because we know their tower must be on the
         same fork as this current one that we're processing, and so by
         definition their vote slot must be in our ghost (ie. we can't
         have rooted past it or be on a different fork). */

      if( FD_UNLIKELY( !ele ) ) FD_LOG_ERR(( "[%s] voter %s's vote slot %lu was not in ghost", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), vote ));

      fd_ghost_replay_vote( ghost, voter, &ele->key );
      double pct = (double)ele->replay_stake / (double)epoch->total_stake;
      if( FD_UNLIKELY( pct > FD_CONFIRMED_PCT ) ) ctx->confirmed = fd_ulong_max( ctx->confirmed, ele->slot );
    }

    /* Check if this voter's root >= ghost root. We can't process
        other voters' roots that precede the ghost root. */

    if( FD_LIKELY( root != FD_SLOT_NULL && root >= fd_ghost_root( ghost )->slot ) ) {
      fd_ghost_ele_t const * ele = fd_ghost_query( ghost, fd_ghost_hash( ghost, root ) );

      /* Error if the node's root slot is not in ghost. This is an
         invariant violation, because we know their tower must be on the
         same fork as this current one that we're processing, and so by
         definition their root slot must be in our ghost (ie. we can't
         have rooted past it or be on a different fork). */

      if( FD_UNLIKELY( !ele ) ) FD_LOG_ERR(( "[%s] voter %s's root slot %lu was not in ghost", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), root ));

      fd_ghost_rooted_vote( ghost, voter, root );
      double pct = (double)ele->rooted_stake / (double)epoch->total_stake;
      if( FD_UNLIKELY( pct > FD_FINALIZED_PCT ) ) ctx->finalized = fd_ulong_max( ctx->finalized, ele->slot );
    }
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
      alignof(ctx_t),      sizeof(ctx_t)                      ),
      fd_epoch_align(),    fd_epoch_footprint( FD_VOTER_MAX ) ),
      fd_ghost_align(),    fd_ghost_footprint( FD_BLOCK_MAX ) ),
      fd_tower_align(),    fd_tower_footprint()               ), /* our tower */
      fd_tower_align(),    fd_tower_footprint()               ), /* scratch */
      128UL,               VOTER_FOOTPRINT * VOTER_MAX        ), /* scratch */
    scratch_align() );
}

static int
before_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig ) {
  if( FD_UNLIKELY( ctx->in_kind[in_idx]==IN_KIND_STAKE ) ) {
    return sig == STAKE_CI_NEXT_EPOCH; /* Only process stake messages for current epoch*/
  }
  return 0;
}
static void
during_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig,
             ulong   chunk,
             ulong   sz,
             ulong   ctl FD_PARAM_UNUSED ) {
  uint             in_kind = ctx->in_kind[in_idx];
  in_ctx_t const * in_ctx  = &ctx->in_links[in_idx];
  switch( in_kind ) {

    case IN_KIND_GOSSIP: {
      uchar const * chunk_laddr = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
      switch(sig) {
        case fd_crds_data_enum_vote: {
          memcpy( &ctx->vote_ix_buf[0], chunk_laddr, sz );
          break;
        }
        case fd_crds_data_enum_duplicate_shred: {
          memcpy( &ctx->duplicate_shred, chunk_laddr, sizeof(fd_gossip_duplicate_shred_t) );
          memcpy( ctx->duplicate_shred_chunk, chunk_laddr + sizeof(fd_gossip_duplicate_shred_t), FD_EQVOC_PROOF_CHUNK_SZ );
          break;
        }
        default: {
          FD_LOG_ERR(( "unexpected crds discriminant %lu", sig ));
          break;
        }
      }
      break;
    }

    case IN_KIND_REPLAY: {
      in_ctx_t const * in_ctx = &ctx->in_links[ in_idx ];
      ulong parent_slot = fd_ulong_extract_lsb( sig, 32 );
      uchar const * chunk_laddr = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
      if( FD_UNLIKELY( parent_slot == UINT_MAX /* no parent, so snapshot slot */ ) ) {
        memcpy   ( ctx->slot_hash.uc,     chunk_laddr,                     sizeof(fd_hash_t) );
      } else {
        memcpy( ctx->bank_hash.uc,   chunk_laddr,                     sizeof(fd_hash_t) );
        memcpy( ctx->block_hash.uc,  chunk_laddr+1*sizeof(fd_hash_t), sizeof(fd_hash_t) );
        memcpy( ctx->slot_hash.uc,   chunk_laddr+2*sizeof(fd_hash_t), sizeof(fd_hash_t) );
        memcpy( ctx->parent_hash.uc, chunk_laddr+3*sizeof(fd_hash_t), sizeof(fd_hash_t) );
        /* FIXME: worth making a repair->replay packed msg to directly cast? */
      }
      break;
    }

    case IN_KIND_STAKE: {
      in_ctx_t const * in_ctx = &ctx->in_links[ in_idx ];
      uchar const * chunk_laddr = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
      fd_stake_weight_msg_t const * stake_weight_msg = (fd_stake_weight_msg_t const *)fd_type_pun_const( chunk_laddr );
      memcpy( &ctx->stake_weight_meta, stake_weight_msg, sizeof(ctx->stake_weight_meta) );
      FD_LOG_NOTICE(( "TOWER TILE HAS RECIEVED A STAKE MSG after_frag %lu, epoch: %lu, staked_cnt: %lu, start_slot: %lu, ", sz, ctx->stake_weight_meta.epoch, ctx->stake_weight_meta.staked_cnt, ctx->stake_weight_meta.start_slot ));
      fd_memcpy( ctx->epoch_voters_buf, chunk_laddr + sizeof(fd_stake_weight_msg_t), sz - sizeof(fd_stake_weight_msg_t) );
      break;
    }

    case IN_KIND_SIGN:
      break;

    default:
      FD_LOG_ERR(( "Unknown in_kind %u", in_kind ));
  }
}

static void
after_frag( ctx_t *             ctx,
            ulong               in_idx,
            ulong               seq     FD_PARAM_UNUSED,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub   FD_PARAM_UNUSED,
            fd_stem_context_t * stem ) {
  uint in_kind = ctx->in_kind[in_idx];
  if( FD_UNLIKELY( in_kind == IN_KIND_STAKE ) ) {
    update_epoch( ctx, sz - sizeof(fd_stake_weight_msg_t) );
  }
  if( FD_UNLIKELY( in_kind != IN_KIND_REPLAY ) ) return;

  ulong slot        = fd_ulong_extract( sig, 32, 63 );
  ulong parent_slot = fd_ulong_extract_lsb( sig, 32 );

  if( FD_UNLIKELY( (uint)parent_slot == UINT_MAX ) ) { /* snapshot slot */
    FD_TEST( ctx->funk );
    FD_TEST( fd_funk_txn_map( ctx->funk ) );
    fd_ghost_init( ctx->ghost, slot, &ctx->slot_hash );
    return;
  }

  fd_funk_txn_xid_t   txn_xid  = { .ul = { slot, slot } };
  fd_funk_txn_map_t * txn_map  = fd_funk_txn_map( ctx->funk );
  fd_funk_txn_start_read( ctx->funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( &txn_xid, txn_map );
  if( FD_UNLIKELY( !funk_txn ) ) FD_LOG_ERR(( "Could not find valid funk transaction" ));
  fd_funk_txn_end_read( ctx->funk );

  /* Initialize the tower */

  if( FD_UNLIKELY( fd_tower_votes_empty( ctx->tower ) ) ) fd_tower_from_vote_acc( ctx->tower, ctx->funk, funk_txn, &ctx->funk_key );

  fd_ghost_ele_t const * ghost_ele  = fd_ghost_insert( ctx->ghost, &ctx->parent_hash, slot, &ctx->slot_hash, ctx->epoch->total_stake );
  FD_TEST( ghost_ele );
  update_ghost( ctx, funk_txn );

  ulong vote_slot = fd_tower_vote_slot( ctx->tower, ctx->epoch, ctx->funk, funk_txn, ctx->ghost, ctx->scratch );
  if( FD_UNLIKELY( vote_slot == FD_SLOT_NULL ) ) return; /* nothing to vote on */

  ulong root = fd_tower_vote( ctx->tower, vote_slot );
  if( FD_LIKELY( root != FD_SLOT_NULL ) ) {
    fd_hash_t const * root_bid = fd_ghost_hash( ctx->ghost, root );
    if( FD_UNLIKELY( !root_bid ) ) {
      FD_LOG_WARNING(( "Lowest vote slot %lu is not in ghost, skipping publish", root ));
    } else {
      fd_ghost_publish( ctx->ghost, root_bid );
      fd_stem_publish ( stem, ctx->replay_out_idx, root, 0UL, 0UL, 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
    }
    ctx->root = root;
  }

  /* Send our updated tower to the cluster. */

  fd_txn_p_t * vote_txn = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->send_out_mem, ctx->send_out_chunk );
  fd_tower_to_vote_txn( ctx->tower, ctx->root, ctx->lockouts, &ctx->bank_hash, &ctx->block_hash, ctx->identity_key, ctx->identity_key, ctx->vote_acc, vote_txn );
  FD_TEST( !fd_tower_votes_empty( ctx->tower ) );
  FD_TEST( vote_txn->payload_sz > 0UL );
  fd_stem_publish( stem, ctx->send_out_idx, vote_slot, ctx->send_out_chunk, sizeof(fd_txn_p_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );

  fd_ghost_print( ctx->ghost, ctx->epoch->total_stake, fd_ghost_root( ctx->ghost ) );
  fd_tower_print( ctx->tower, ctx->root );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx        = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t)        );
  void * epoch_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(),             fd_epoch_footprint( FD_VOTER_MAX ) );
  void * ghost_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),             fd_ghost_footprint( FD_BLOCK_MAX ) );
  void * tower_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),             fd_tower_footprint()               );
  void * scratch_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),             fd_tower_footprint()               );
  void * voter_mem   = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                        VOTER_FOOTPRINT * VOTER_MAX        );
  ulong scratch_top  = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align()                                                  );
  FD_TEST( scratch_top == (ulong)scratch + scratch_footprint( tile ) );

  ctx->epoch   = fd_epoch_join( fd_epoch_new( epoch_mem, FD_VOTER_MAX       ) );
  ctx->ghost   = fd_ghost_join( fd_ghost_new( ghost_mem, FD_BLOCK_MAX, 42UL ) );
  ctx->tower   = fd_tower_join( fd_tower_new( tower_mem                     ) );
  ctx->scratch = fd_tower_join( fd_tower_new( scratch_mem                   ) );

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->tower.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  ctx->epoch_voters_buf = voter_mem;

  memcpy( ctx->identity_key->uc, fd_keyload_load( tile->tower.identity_key_path, 1 ), sizeof(fd_pubkey_t) );

  if( FD_UNLIKELY( !fd_base58_decode_32( tile->tower.vote_acc_path, ctx->vote_acc->uc ) ) ) {
    const uchar * vote_key = fd_keyload_load( tile->tower.vote_acc_path, 1 );
    memcpy( ctx->vote_acc->uc, vote_key, sizeof(fd_pubkey_t) );
  }

  memset( ctx->funk_key.uc, 0, sizeof(fd_funk_rec_key_t) );
  memcpy( ctx->funk_key.uc, ctx->vote_acc->uc, sizeof(fd_pubkey_t) );
  ctx->funk_key.uc[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_FUNK_KEY_TYPE_ACC;

  if( FD_UNLIKELY( tile->in_cnt > MAX_IN_LINKS ) ) FD_LOG_ERR(( "repair tile has too many input links" ));

  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if(        0==strcmp( link->name, "gossip_tower" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_GOSSIP;
    } else if( 0==strcmp( link->name, "replay_tower" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_REPLAY;
    } else if( 0==strcmp( link->name, "stake_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_STAKE;
    } else {
      FD_LOG_ERR(( "tower tile has unexpected input link %s", link->name ));
    }
    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;
  }

  ctx->replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "tower_replay", 0 );
  FD_TEST( ctx->replay_out_idx!= ULONG_MAX );

  ctx->send_out_idx = fd_topo_find_tile_out_link( topo, tile, "tower_send", 0 );
  FD_TEST( ctx->send_out_idx!=ULONG_MAX );
  fd_topo_link_t * send_out = &topo->links[ tile->out_link_id[ ctx->send_out_idx ] ];
  ctx->send_out_mem         = topo->workspaces[ topo->objs[ send_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->send_out_chunk0      = fd_dcache_compact_chunk0( ctx->send_out_mem, send_out->dcache );
  ctx->send_out_wmark       = fd_dcache_compact_wmark ( ctx->send_out_mem, send_out->dcache, send_out->mtu );
  ctx->send_out_chunk       = ctx->send_out_chunk0;
  FD_TEST( fd_dcache_compact_is_safe( ctx->send_out_mem, send_out->dcache, send_out->mtu, send_out->depth ) );

  ctx->stake_weight_received = 0;
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
