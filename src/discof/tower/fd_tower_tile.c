#include "fd_tower_tile.h"
#include "generated/fd_tower_tile_seccomp.h"

#include "../replay/fd_replay_tile.h"
#include "../../choreo/ghost/fd_ghost.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/voter/fd_voter.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/topo/fd_topo.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#include <errno.h>
#include <fcntl.h>

#define LOGGING 0

#define IN_KIND_GENESIS (0)
#define IN_KIND_SNAP    (1)
#define IN_KIND_REPLAY  (2)

struct fd_tower_tile_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_tower_tile_in fd_tower_tile_in_t;

struct fd_tower_tile {
  fd_pubkey_t identity_key[1];
  fd_pubkey_t vote_acc[1];

  int initialized;

  int  checkpt_fd;
  int  restore_fd;

  fd_epoch_t * epoch;
  fd_ghost_t * ghost;
  fd_tower_t * scratch;
  fd_tower_t * tower;
  uchar *      voters;

  long  ts;   /* tower timestamp */

  fd_snapshot_manifest_t manifest;
  fd_replay_slot_completed_t replay_slot_info;

  ulong             replay_towers_cnt;
  fd_replay_tower_t replay_towers[ FD_REPLAY_TOWER_VOTE_ACC_MAX ];

  fd_tower_t * vote_towers[ FD_REPLAY_TOWER_VOTE_ACC_MAX ];
  fd_pubkey_t  vote_keys[ FD_REPLAY_TOWER_VOTE_ACC_MAX ];

  uchar vote_state[ FD_REPLAY_TOWER_VOTE_ACC_MAX ]; /* our vote state */

  int in_kind[ 64UL ];
  fd_tower_tile_in_t in[ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
};

typedef struct fd_tower_tile fd_tower_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t)                            );
  l = FD_LAYOUT_APPEND( l, fd_epoch_align(),         fd_epoch_footprint( FD_REPLAY_TOWER_VOTE_ACC_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(),         fd_ghost_footprint( FD_BLOCK_MAX )                 );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),         fd_tower_footprint()                               );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),         fd_tower_footprint()*FD_REPLAY_TOWER_VOTE_ACC_MAX  );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
update_ghost( fd_tower_tile_t * ctx ) {
  fd_voter_t * epoch_voters = fd_epoch_voters( ctx->epoch );
  for( ulong i=0UL; i<ctx->replay_towers_cnt; i++ ) {
    fd_replay_tower_t const * replay_tower = &ctx->replay_towers[ i ];
    fd_pubkey_t const *       pubkey       = &replay_tower->key;
    fd_voter_state_t const *  voter_state  = (fd_voter_state_t const *)fd_type_pun_const( replay_tower->acc );
    fd_tower_t *              tower        = ctx->vote_towers[ i ];

    /* Look up the voter for this vote account */
    fd_voter_t * voter = fd_epoch_voters_query( epoch_voters, *pubkey, NULL );
    if( FD_UNLIKELY( !voter ) ) {
      /* This means that the cached list of epoch voters is not in sync
         with the list passed through from replay. This likely means
         that we have crossed an epoch boundary and the epoch_voter list
         has not been updated.

         TODO: update the set of account in epoch_voter's to match the
               list received from replay, so that epoch_voters is
               correct across epoch boundaries. */
      FD_LOG_CRIT(( "voter %s was not in epoch voters", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
    }

    voter->stake = replay_tower->stake; /* update the voters stake */

    if( FD_UNLIKELY( !fd_voter_state_cnt( voter_state ) ) ) continue; /* skip voters with no votes */

    ulong vote = fd_tower_votes_peek_tail( tower )->slot; /* peek last vote from the tower */
    ulong root = fd_voter_root_slot( voter_state );

    /* Only process votes for slots >= root. */
    if( FD_LIKELY( vote != FD_SLOT_NULL && vote >= fd_ghost_root( ctx->ghost )->slot ) ) {
      fd_ghost_ele_t const * ele = fd_ghost_query_const( ctx->ghost, fd_ghost_hash( ctx->ghost, vote ) );

      /* It is an invariant violation if the vote slot is not in ghost.
         These votes come from replay ie. on-chain towers stored in vote
         accounts which implies every vote slot must have been processed
         by the vote program (ie. replayed) and therefore in ghost. */

      if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "voter %s's vote slot %lu was not in ghost", FD_BASE58_ENC_32_ALLOCA( &voter->key ), vote ));
      fd_ghost_replay_vote( ctx->ghost, voter, &ele->key );
    }

    /* Check if this voter's root >= ghost root. We can't process roots
       before our own root because it was already pruned. */

    if( FD_LIKELY( root!=FD_SLOT_NULL && root>=fd_ghost_root( ctx->ghost )->slot ) ) {
      fd_ghost_ele_t const * ele = fd_ghost_query( ctx->ghost, fd_ghost_hash( ctx->ghost, root ) );

      /* Error if the node's root slot is not in ghost. This is an
         invariant violation, because we know their tower must be on the
         same fork as this current one that we're processing, and so by
         definition their root slot must be in our ghost (ie. we can't
         have rooted past it or be on a different fork). */

      if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "voter %s's root slot %lu was not in ghost", FD_BASE58_ENC_32_ALLOCA( &voter->key ), root ));

      fd_ghost_rooted_vote( ctx->ghost, voter, root );
    }
  }
}

static void
replay_slot_completed( fd_tower_tile_t *            ctx,
                       fd_replay_slot_completed_t * slot_info,
                       ulong                        tsorig,
                       fd_stem_context_t *          stem ) {
  /* If we have not received any votes, something is wrong. */
  if( FD_UNLIKELY( !ctx->replay_towers_cnt ) ) {
    /* TODO: This is not correct. It is fine and valid to receive a
       block with no votes, we don't want to return here as we still
       want to vote on the block. */
    FD_LOG_WARNING(( "No vote states received from replay. No votes will be sent"));
    return;
  }

  /* Parse the replay vote towers */
  for( ulong i=0UL; i<ctx->replay_towers_cnt; i++ ) {
    fd_tower_votes_remove_all( ctx->vote_towers[ i ] );
    fd_tower_from_vote_acc_data( ctx->replay_towers[ i ].acc, ctx->vote_towers[ i ] );
    ctx->vote_keys[ i ] = ctx->replay_towers[ i ].key;

    if( FD_UNLIKELY( 0==memcmp( &ctx->vote_keys[ i ], ctx->vote_acc, sizeof(fd_pubkey_t) ) ) ) {

      /* If this is our vote account, and our tower has not been
         initialized, initialize it with our vote state */

      if( FD_UNLIKELY( fd_tower_votes_empty( ctx->tower ) ) ) {
        fd_tower_from_vote_acc_data( ctx->replay_towers[i].acc, ctx->tower );
      }

      /* Copy in our voter state */
      memcpy( &ctx->vote_state, ctx->replay_towers[ i ].acc, ctx->replay_towers[ i ].acc_sz );
    }
  }

  /* Update ghost with the vote account states received from replay. */

  fd_ghost_ele_t const * ghost_ele  = fd_ghost_insert( ctx->ghost, &slot_info->parent_block_id, slot_info->slot, &slot_info->block_id, ctx->epoch->total_stake );
  FD_TEST( ghost_ele );
  update_ghost( ctx );

  /* Populate the out frag. */

  fd_tower_slot_done_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  /* 1. Determine next slot to vote for, if one exists. */

  msg->vote_slot = fd_tower_vote_slot( ctx->tower, ctx->epoch, ctx->vote_keys, ctx->vote_towers, ctx->replay_towers_cnt, ctx->ghost );

  /* 2. Determine new root, if there is one.  A new vote slot can result
        in a new root but not always. */

  if( FD_LIKELY( msg->vote_slot!=FD_SLOT_NULL ) ) {
    msg->root_slot                  = fd_tower_vote( ctx->tower, msg->vote_slot );
    fd_hash_t const * root_block_id = fd_ghost_hash( ctx->ghost, msg->root_slot );
    if( FD_LIKELY( root_block_id ) ) {
      msg->root_block_id = *root_block_id;
      msg->new_root      = 1;
      fd_ghost_publish( ctx->ghost, &msg->root_block_id );
    } else {
      msg->root_block_id = (fd_hash_t){ 0 };
      msg->new_root      = 0;
    }
  }

  /* 3. Populate vote_txn with the current tower (regardless of whether
        there was a new vote slot or not). */

  fd_lockout_offset_t lockouts[ FD_TOWER_VOTE_MAX ];
  fd_txn_p_t txn[1];
  fd_tower_to_vote_txn( ctx->tower, msg->root_slot, lockouts, &slot_info->bank_hash, &slot_info->block_hash, ctx->identity_key, ctx->identity_key, ctx->vote_acc, txn );
  FD_TEST( !fd_tower_votes_empty( ctx->tower ) );
  FD_TEST( txn->payload_sz && txn->payload_sz<=FD_TPU_MTU );
  fd_memcpy( msg->vote_txn, txn->payload, txn->payload_sz );
  msg->vote_txn_sz = txn->payload_sz;

  /* 4. Determine next slot to reset leader pipeline to. */

  msg->reset_slot     = fd_tower_reset_slot( ctx->tower, ctx->epoch, ctx->ghost );
  msg->reset_block_id = *fd_ghost_hash( ctx->ghost, msg->reset_slot ); /* FIXME fd_ghost_hash is a naive lookup but reset_slot only ever refers to the confirmed duplicate */

  /* Publish the frag */

  fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, sizeof(fd_tower_slot_done_t), 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_done_t), ctx->out_chunk0, ctx->out_wmark );

# if LOGGING
  fd_ghost_print( ctx->ghost, ctx->epoch->total_stake, fd_ghost_root( ctx->ghost ) );
  fd_tower_print( ctx->tower, msg->root_slot );
# endif
}

static void
init_genesis( fd_tower_tile_t *                  ctx,
              fd_genesis_solana_global_t const * genesis ) {
  fd_hash_t manifest_block_id = { .ul = { 0xf17eda2ce7b1d } }; /* FIXME manifest_block_id */
  fd_ghost_init( ctx->ghost, 0UL, &manifest_block_id );

  fd_voter_t * epoch_voters = fd_epoch_voters( ctx->epoch );

  fd_pubkey_account_pair_global_t const * accounts = fd_genesis_solana_accounts_join( genesis );
  for( ulong i=0UL; i<genesis->accounts_len; i++ ) {
    fd_solana_account_global_t const * account = &accounts[ i ].account;
    if( FD_LIKELY( memcmp( account->owner.key, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) ) continue;

    uchar const * acc_data = fd_solana_account_data_join( account );

    fd_stake_state_v2_t stake_state;
    if( FD_UNLIKELY( !fd_bincode_decode_static( stake_state_v2, &stake_state, acc_data, account->data_len, NULL ) ) ) {
      FD_LOG_ERR(( "Failed to deserialize genesis stake account %s", FD_BASE58_ENC_32_ALLOCA( accounts[ i ].key.uc ) ));
    }

    if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state )     ) ) continue;
    if( FD_UNLIKELY( !stake_state.inner.stake.stake.delegation.stake ) ) continue;

    fd_pubkey_t const * pubkey = &stake_state.inner.stake.stake.delegation.voter_pubkey;

    fd_voter_t * voter = fd_epoch_voters_insert( epoch_voters, *pubkey );

    voter->stake             = stake_state.inner.stake.stake.delegation.stake;
    ctx->epoch->total_stake += voter->stake;
  }
}

static void
snapshot_done( fd_tower_tile_t *              ctx,
               fd_snapshot_manifest_t const * manifest ) {
  fd_hash_t manifest_block_id = { .ul = { 0xf17eda2ce7b1d } }; /* FIXME manifest_block_id */
  fd_ghost_init( ctx->ghost, manifest->slot, &manifest_block_id );

  /* As per the documentation in fd_ssmsg.h, we use
     manifest->epoch_stakes[1] to initialize the epoch voters. These
     correspond to the amount staked to each vote account at the
     beginning of the current epoch:

     manifest->epoch_stakes[0] represents the stakes used to generate
     the leader schedule at the end of the current epoch. These are the
     stakes as of the end of two epochs ago.

     manifest->epoch_stakes[1] represents the stakes used to generate
     the leader schedule at the end of the next epoch. These are the
     stakes as of the end of the previous epoch, so these will be the
     stakes throughout the current epoch. */
  fd_voter_t * epoch_voters = fd_epoch_voters( ctx->epoch );
  fd_snapshot_manifest_epoch_stakes_t const * epoch_stakes = &manifest->epoch_stakes[ 1 ];
  for( ulong i=0UL; i<epoch_stakes->vote_stakes_len; i++ ) {
    if( FD_UNLIKELY( !epoch_stakes->vote_stakes[ i ].stake ) ) continue;

    fd_pubkey_t const * pubkey = (fd_pubkey_t const *)epoch_stakes->vote_stakes[ i ].vote;

#if FD_EPOCH_USE_HANDHOLDING
    FD_TEST( !fd_epoch_voters_query( epoch_voters, *pubkey, NULL ) );
    FD_TEST( fd_epoch_voters_key_cnt( epoch_voters ) < fd_epoch_voters_key_max( epoch_voters ) );
#endif

    fd_voter_t * voter = fd_epoch_voters_insert( epoch_voters, *pubkey );

#if FD_EPOCH_USE_HANDHOLDING
    FD_TEST( 0==memcmp( voter->key.uc, pubkey->uc, sizeof(fd_pubkey_t) ) );
    FD_TEST( fd_epoch_voters_query( epoch_voters, voter->key, NULL ) );
#endif

    voter->stake             = epoch_stakes->vote_stakes[ i ].stake;
    voter->replay_vote.slot  = FD_SLOT_NULL;
    voter->gossip_vote.slot  = FD_SLOT_NULL;
    voter->rooted_vote.slot  = FD_SLOT_NULL;
    ctx->epoch->total_stake += voter->stake;
  }
}

static inline int
returnable_frag( fd_tower_tile_t *   ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq;
  (void)tspub;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GENESIS ) ) {
    init_genesis( ctx, fd_type_pun( (uchar*)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk )+sizeof(fd_lthash_value_t)+sizeof(fd_hash_t) ) );
    ctx->initialized = 1;
  } else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SNAP ) ) {
    if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )==FD_SSMSG_DONE ) ) {
      snapshot_done( ctx, &ctx->manifest );
      ctx->initialized = 1;
    } else {
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
        FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_memcpy( &ctx->manifest, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_snapshot_manifest_t) );
    }
  } else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
      FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    /* If we haven't initialized from either genesis or a snapshot yet,
       we cannot process any frags from replay as it's a race condition,
       just wait until we initialize and then process. */
    if( FD_UNLIKELY( !ctx->initialized ) ) return 1;

    if( FD_LIKELY( sig==REPLAY_SIG_SLOT_COMPLETED ) ) {
      fd_memcpy( &ctx->replay_slot_info, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_replay_slot_completed_t) );
    } else if( FD_LIKELY( sig==REPLAY_SIG_VOTE_STATE ) ) {
      if( FD_UNLIKELY( fd_frag_meta_ctl_som( ctl ) ) ) ctx->replay_towers_cnt = 0;

      if( FD_UNLIKELY( ctx->replay_towers_cnt>=FD_REPLAY_TOWER_VOTE_ACC_MAX ) ) FD_LOG_ERR(( "tower received more vote states than expected" ));
      memcpy( &ctx->replay_towers[ ctx->replay_towers_cnt ], fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_replay_tower_t) );
      ctx->replay_towers_cnt++;

      if( FD_UNLIKELY( fd_frag_meta_ctl_eom( ctl ) ) ) replay_slot_completed( ctx, &ctx->replay_slot_info, tsorig, stem );
    } else if( FD_UNLIKELY( sig==REPLAY_SIG_ROOT_ADVANCED ) ) {
      /* Ignore root advanced messages, we don't need them */
    } else {
      FD_LOG_ERR(( "unexpected replay message sig %lu", sig ));
    }
  } else {
    FD_LOG_ERR(( "unexpected input kind %d", ctx->in_kind[ in_idx ] ));
  }

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t) );

  if( FD_UNLIKELY( !strcmp( tile->tower.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.identity_key_path, /* pubkey only: */ 1 ) );

  /* The vote key can be specified either directly as a base58 encoded
     pubkey, or as a file path.  We first try to decode as a pubkey.

     TODO: The "vote_acc_path" should be renamed, as it might not be
     a path. */
  uchar * vote_key = fd_base58_decode_32( tile->tower.vote_acc_path, ctx->vote_acc->uc );
  if( FD_UNLIKELY( !vote_key ) ) {
    ctx->vote_acc[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.vote_acc_path, /* pubkey only: */ 1 ) );
  }

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/tower-1_9-%s.bin.new", tile->tower.ledger_path, FD_BASE58_ENC_32_ALLOCA( ctx->identity_key->uc ) ) );
  ctx->checkpt_fd = open( path, O_WRONLY|O_CREAT|O_TRUNC, 0600 );
  if( FD_UNLIKELY( -1==ctx->checkpt_fd ) ) FD_LOG_ERR(( "open(`%s`) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/tower-1_9-%s.bin", tile->tower.ledger_path, FD_BASE58_ENC_32_ALLOCA( ctx->identity_key->uc ) ) );
  ctx->restore_fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==ctx->restore_fd && errno!=ENOENT ) ) FD_LOG_WARNING(( "open(`%s`) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t)                            );
  void * _epoch          = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(),         fd_epoch_footprint( FD_REPLAY_TOWER_VOTE_ACC_MAX ) );
  void * _ghost          = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),         fd_ghost_footprint( FD_BLOCK_MAX )                 );
  void * _tower          = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint()                               );
  void * _vote_towers    = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint()*FD_REPLAY_TOWER_VOTE_ACC_MAX  );

  ctx->epoch = fd_epoch_join( fd_epoch_new( _epoch, FD_REPLAY_TOWER_VOTE_ACC_MAX ) );
  FD_TEST( ctx->epoch );

  ctx->ghost = fd_ghost_join( fd_ghost_new( _ghost, FD_BLOCK_MAX, 42UL ) );
  FD_TEST( ctx->ghost );

  ctx->tower = fd_tower_join( fd_tower_new( _tower ) );
  FD_TEST( ctx->tower );

  for( ulong i=0UL; i<FD_REPLAY_TOWER_VOTE_ACC_MAX; i++ ) {
    ctx->vote_towers[ i ] = fd_tower_join( fd_tower_new( (uchar*)_vote_towers+(i*fd_tower_footprint() ) ) );
    FD_TEST( ctx->vote_towers[ i ] );
  }

  ctx->initialized = 0;

  ctx->replay_towers_cnt = 0UL;

  FD_TEST( tile->in_cnt<sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "genesi_out"      ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESIS;
    else if( FD_LIKELY( !strcmp( link->name, "snap_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else FD_LOG_ERR(( "tower tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].mtu    = link->mtu;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t) );

  populate_sock_filter_policy_fd_tower_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->checkpt_fd, (uint)ctx->restore_fd );
  return sock_filter_policy_fd_tower_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t) );

  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->checkpt_fd;
  out_fds[ out_cnt++ ] = ctx->restore_fd;
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE    fd_tower_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_tower_tile_t)
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_tower = {
  .name                     = "tower",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
