#include "fd_tower_tile.h"
#include "generated/fd_tower_tile_seccomp.h"

#include "../../ballet/lthash/fd_lthash.h"
#include "../../choreo/ghost/fd_ghost.h"
#include "../../choreo/notar/fd_notar.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_accts.h"
#include "../../choreo/tower/fd_tower_forks.h"
#include "../../choreo/tower/fd_tower_serde.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_txn_m.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#include <errno.h>
#include <fcntl.h>

/* The tower tile is responsible for two things:

   1. running the fork choice (fd_ghost) and TowerBFT (fd_tower) rules
      after replaying a block.
   2. listening to gossip (duplicate shred messages and votes) and
      monitoring for duplicate or duplicate confirmed blocks (fd_notar).

   Tower signals to other tiles about events that occur as a result of
   those two above events, such as what block to vote on, what block to
   reset onto as leader, what block got rooted, what blocks are
   duplicates and what blocks are confirmed.

   In general, tower uses the block_id as the identifier for blocks. The
   block_id is the merkle root of the last FEC set for a block.  This is
   guaranteed to be unique for a given block and is the canonical
   identifier over the slot number because unlike slot numbers, if a
   leader equivocates (produces multiple blocks for the same slot) the
   block_id can disambiguate the blocks.

   However, the block_id was only introduced into the Solana protocol
   recently, and TowerBFT still uses the "legacy" identifier of slot
   numbers for blocks.  So the tile (and relevant modules) will use
   block_id when possible to interface with the protocol but otherwise
   falling back to slot number when block_id is unsupported. */

#define LOGGING 1

#define IN_KIND_GENESIS (0)
#define IN_KIND_GOSSIP  (1)
#define IN_KIND_REPLAY  (2)
#define IN_KIND_SNAP    (3)
#define IN_KIND_TOWER   (4)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

typedef struct {
  int   init;
  ulong init_slot; /* initialization slot, either the snapshot or genesis slot. */

  fd_pubkey_t identity_key[1];
  fd_pubkey_t vote_account[1];

  int  checkpt_fd;
  int  restore_fd;

  fd_epoch_t * epoch;
  fd_ghost_t * ghost;
  fd_notar_t * notar;
  fd_tower_t * tower;

  ulong     tower_vote_slot;     /* most recent tower vote slot */
  fd_hash_t tower_vote_block_id; /* most recent tower vote block_id */
  ulong     tower_root_slot;     /* most recent tower root slot */
  ulong     tower_root_block_id; /* most recent tower root block_id */

  uchar vote_txn_buf[ FD_TPU_PARSED_MTU ];

  fd_sha512_t * sha[ FD_TXN_ACTUAL_SIG_MAX ];

  fd_snapshot_manifest_t     manifest;
  fd_replay_slot_completed_t replay_slot_info;
  ulong                      replay_vote_states_cnt;
  fd_replay_vote_state_t     replay_vote_states[ FD_VOTER_MAX ];
  fd_tower_t *               vote_towers       [ FD_VOTER_MAX ];
  fd_pubkey_t                vote_keys         [ FD_VOTER_MAX ];

  fd_tower_accts_t * tower_accts;
  fd_tower_forks_t * tower_forks;

  fd_tower_sync_serde_t      tower_sync_serde;

  int      in_kind[ 64UL ];
  in_ctx_t in     [ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( FD_PARAM_UNUSED fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),         sizeof(ctx_t)                            );
  l = FD_LAYOUT_APPEND( l, fd_epoch_align(),       fd_epoch_footprint( FD_VOTER_MAX )       );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(),       fd_ghost_footprint( FD_BLOCK_MAX )       );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),       fd_tower_footprint()                     );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),       fd_tower_footprint()*FD_VOTER_MAX        );
  l = FD_LAYOUT_APPEND( l, fd_tower_accts_align(), fd_tower_accts_footprint( FD_VOTER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_tower_forks_align(), fd_tower_forks_footprint( FD_BLOCK_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
update_ghost( ctx_t * ctx ) {
  fd_voter_t * epoch_voters = fd_epoch_voters( ctx->epoch );
  for( ulong i=0UL; i<ctx->replay_vote_states_cnt; i++ ) {
    fd_replay_vote_state_t const * replay_tower = &ctx->replay_vote_states[i];
    fd_pubkey_t const *            pubkey       = &replay_tower->pubkey;
    fd_voter_state_t const *       voter_state  = (fd_voter_state_t const *)fd_type_pun_const( replay_tower->acc );
    fd_tower_t * tower = ctx->vote_towers[i];

    /* Look up the voter for this vote account */

    fd_voter_t * voter = fd_epoch_voters_query( epoch_voters, *pubkey, NULL );
    if( FD_UNLIKELY( !voter ) ) {
      /* This means that the cached list of epoch voters is not in sync
         with the list passed through from replay. This likely means
         that we have crossed an epoch boundary and the epoch_voter list
         has not been updated.

         TODO: update the set of account in epoch_voter's to match the
         list received from replay, so that epoch_voters is correct
         across epoch boundaries. */
      FD_LOG_CRIT(( "voter %s was not in epoch voters", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
    }

    voter->stake = replay_tower->stake; /* update the voters stake */

    if( FD_UNLIKELY( !fd_voter_state_cnt( voter_state ) ) ) continue; /* skip voters with no votes */

    ulong vote = fd_tower_peek_tail( tower )->slot; /* peek last vote from the tower */
    ulong root = fd_voter_root_slot( voter_state );

    /* Only process votes for slots >= root. */
    if( FD_LIKELY( vote != FD_SLOT_NULL && vote >= fd_ghost_root( ctx->ghost )->slot ) ) {
      fd_ghost_blk_t const * ele = fd_ghost_query( ctx->ghost, vote. );

      /* It is an invariant violation if the vote slot is not in ghost.
         These votes come from replay ie. on-chain towers stored in vote
         accounts which implies every vote slot must have been processed
         by the vote program (ie. replayed) and therefore in ghost. */

      if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "voter %s's vote slot %lu was not in ghost", FD_BASE58_ENC_32_ALLOCA( &voter->key ), vote ));
      count_vote( ctx->ghost, voter, &ele->key );
    }
  }
}

static void
replay_slot_completed( ctx_t *                      ctx,
                       fd_replay_slot_completed_t * slot_info,
                       ulong                        tsorig,
                       fd_stem_context_t *          stem ) {
  /* If we have not received any votes, something is wrong. */
  if( FD_UNLIKELY( !ctx->replay_vote_states_cnt ) ) {
    /* TODO: This is not correct. It is fine and valid to receive a
       block with no votes, we don't want to return here as we still
       want to vote on the block. */
    FD_LOG_WARNING(( "No vote states received from replay. No votes will be sent"));
    return;
  }

  /* Parse the replay vote towers. */

  for( ulong i=0UL; i<ctx->replay_vote_states_cnt; i++ ) {
    fd_tower_remove_all( ctx->vote_towers[i] );
    fd_tower_from_vote_acc( ctx->replay_vote_states[ i ].acc, ctx->vote_towers[ i ] );
    ctx->vote_keys[ i ] = ctx->replay_vote_states[ i ].pubkey;

    if( FD_UNLIKELY( 0==memcmp( &ctx->vote_keys[ i ], ctx->vote_account, sizeof(fd_pubkey_t) ) ) ) {

      /* If this is our vote account, and our tower has not been
         initialized, initialize it with our vote state */

      if( FD_UNLIKELY( fd_tower_empty( ctx->tower ) ) ) { /* FIXME this is wrong and can only be done on "caught up" */
        uchar const * acc = ctx->replay_vote_states[ i ].acc;
        fd_tower_from_vote_acc( acc, ctx->tower );
        ctx->tower_root_slot = fd_ulong_load_8_fast( fd_voter_root_laddr( (fd_voter_state_t const *)fd_type_pun_const( acc ) ) );
      }
    }
  }

  /* Update ghost with the vote account states received from replay. */

  fd_ghost_blk_t const * ghost_ele = fd_ghost_insert( ctx->ghost, &slot_info->parent_block_id, slot_info->slot, &slot_info->block_id );
  FD_TEST( ghost_ele );
  update_ghost( ctx );

  /* Update tower forks */

  fd_tower_forks_t * fork = fd_tower_forks_insert( ctx->tower_forks, slot_info->slot );
  fork->parent_slot       = slot_info->parent_slot;

  /* Populate the out frag. */

  fd_tower_slot_done_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  /* 1. Determine next slot to vote for, if one exists. */

  msg->vote_slot = fd_tower_vote_slot( ctx->tower, ctx->tower_forks, ctx->ghost,  );
  msg->new_root  = 0;

  /* 2. Determine new root, if there is one.  A new vote slot can result
        in a new root but not always. */

  if( FD_LIKELY( msg->vote_slot!=ULONG_MAX ) ) {
    msg->root_slot = fd_tower_vote( ctx->tower, msg->vote_slot );
    fd_tower_forks_t * fork = fd_tower_forks_insert( ctx->tower_forks, msg->vote_slot );
    fork->voted_block_id = ctx->tower_vote_block_id;

    if( FD_LIKELY( msg->root_slot != ULONG_MAX ) ) {
      ctx->tower_root = msg->root_slot;
      fd_hash_t const * root_block_id = fd_ghost_hash( ctx->ghost, msg->root_slot );
      FD_TEST( root_block_id || msg->root_slot < ctx->init_slot ); /* it is only possible to not have the block_id if the new tower root precedes init slot */
      if( FD_LIKELY( root_block_id ) ) {
        msg->new_root      = 1;
        msg->root_block_id = *root_block_id;
        fd_ghost_publish( ctx->ghost, &msg->root_block_id );
      }
    }
  }

  /* 3. Populate vote_txn with the current tower (regardless of whether
        there was a new vote slot or not). */

  fd_lockout_offset_t lockouts[ FD_TOWER_VOTE_MAX ];
  fd_txn_p_t txn[1];
  fd_tower_to_vote_txn( ctx->tower, msg->root_slot, lockouts, &slot_info->bank_hash, &slot_info->block_hash, ctx->identity_key, ctx->identity_key, ctx->vote_account, txn );
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
  fd_tower_print( ctx->tower, ctx->tower_root );
# endif
}

static void
init_genesis( ctx_t *                  ctx,
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
snapshot_done( ctx_t *                        ctx,
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
returnable_frag( ctx_t *             ctx,
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

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_GENESIS: {
    init_genesis( ctx, fd_type_pun( (uchar*)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk )+sizeof(fd_lthash_value_t)+sizeof(fd_hash_t) ) );
    ctx->init      = 1;
    ctx->init_slot = 0UL;
    return 0;
  }
  case IN_KIND_SNAP: {
    if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )==FD_SSMSG_DONE ) ) {
      snapshot_done( ctx, &ctx->manifest );
      ctx->init      = 1;
      ctx->init_slot = ctx->manifest.slot;
    } else {
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
        FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_memcpy( &ctx->manifest, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_snapshot_manifest_t) );
    }
    return 0;
  }
  case IN_KIND_GOSSIP: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
      FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    if( FD_UNLIKELY( sig==FD_GOSSIP_UPDATE_TAG_VOTE ) ) {
      fd_gossip_vote_t const * vote = &((fd_gossip_update_message_t const *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ))->vote;

      /* Parse the gossip vote txn and check it's a vote txn. */

      uchar const * payload    = vote->txn;
      ulong         payload_sz = vote->txn_sz;
      ulong         sz         = fd_txn_parse_core( vote->txn, vote->txn_sz, ctx->vote_txn_buf, NULL, NULL );
      if( FD_UNLIKELY( sz==0 ) ) return 0;
      fd_txn_t * txn = (fd_txn_t *)ctx->vote_txn_buf;
      if( FD_UNLIKELY( !fd_txn_is_simple_vote_transaction( txn, vote->txn ) ) ) return 0;  /* TODO Agave doesn't have the same validation of <=2 signatures */

      /* Filter any non-T. */

      fd_txn_instr_t * instr      = &txn->instr[0];
      uchar const *    instr_data = vote->txn + instr->data_off;
      uint             kind       = fd_uint_load_4_fast( instr_data );
      if( FD_UNLIKELY( kind!=FD_TOWER_SYNC_SERDE_KIND && kind!=FD_TOWER_SYNC_SWITCH_SERDE_KIND ) ) return 0;

      /* Sigverify the vote txn. */

      uchar         signature_cnt = txn->signature_cnt;
      ushort        signature_off = txn->signature_off;
      ushort        acct_addr_off = txn->acct_addr_off;
      ushort        message_off   = txn->message_off;
      uchar const * signatures    = payload + signature_off;
      uchar const * pubkeys       = payload + acct_addr_off;
      uchar const * msg           = payload + message_off;
      ulong         msg_sz        = (ulong)payload_sz - message_off;
      int           err           = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signatures, pubkeys, ctx->sha, signature_cnt );
      if( FD_UNLIKELY( err != FD_ED25519_SUCCESS ) ) return 0;

      /* Deserialize the TowerSync. */

      err = fd_tower_sync_deserialize( &ctx->tower_sync_serde, instr_data+sizeof(uint), instr->data_sz-sizeof(uint) ); /* FIXME validate */
      if( FD_UNLIKELY( err==-1 ) ) return 0;
      uchar tower_mem[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));
      fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem ) );
      ulong        slot  = ctx->tower_sync_serde.root;
      for( ulong i = 0; i < ctx->tower_sync_serde.lockouts_cnt; i++ ) {
        slot += ctx->tower_sync_serde.lockouts[i].offset;
        fd_tower_votes_push_tail( tower, (fd_tower_vote_t){ .slot = slot, .conf = ctx->tower_sync_serde.lockouts[i].confirmation_count } );
      }
      fd_tower_print( tower, ctx->tower_sync_serde.root );

      /* Update notar. */

      fd_pubkey_t const * vote_acc  = (fd_pubkey_t const *)fd_type_pun_const( &pubkeys[0] ); /* the first pubkey */
      fd_notar_vote( ctx->notar, vote_acc, tower, &ctx->tower_sync_serde.hash, &ctx->tower_sync_serde.block_id );
      while( FD_LIKELY( !fd_notar_out_empty( ctx->notar->out ) ) ) {
        fd_notar_out_t              out = fd_notar_out_pop_head( ctx->notar->out );
        fd_tower_slot_confirmed_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
        msg->block_id = out.block_id;
        memcpy( msg, &out, sizeof(fd_tower_slot_confirmed_t) ); /* binary compatible */
        fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, sizeof(fd_tower_slot_confirmed_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
        ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_tower_slot_confirmed_t), ctx->out_chunk0, ctx->out_wmark );
      }
    }
    return 0;
  }
  case IN_KIND_REPLAY: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
      FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    /* If we haven't initialized from either genesis or a snapshot yet,
       we cannot process any frags from replay as it's a race condition,
       just wait until we initialize and then process. */
    if( FD_UNLIKELY( !ctx->init ) ) return 1;

    if( FD_LIKELY( sig==REPLAY_SIG_SLOT_COMPLETED ) ) {
      fd_memcpy( &ctx->replay_slot_info, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_replay_slot_completed_t) );
    } else if( FD_LIKELY( sig==REPLAY_SIG_VOTE_STATE ) ) {
      if( FD_UNLIKELY( fd_frag_meta_ctl_som( ctl ) ) ) ctx->replay_vote_states_cnt = 0;

      if( FD_UNLIKELY( ctx->replay_vote_states_cnt>=FD_VOTER_MAX ) ) FD_LOG_ERR(( "tower received more vote states than expected" ));
      memcpy( &ctx->replay_vote_states[ ctx->replay_vote_states_cnt ], fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_replay_vote_state_t) );
      ctx->replay_vote_states_cnt++;

      if( FD_UNLIKELY( fd_frag_meta_ctl_eom( ctl ) ) ) replay_slot_completed( ctx, &ctx->replay_slot_info /* FIXME this seems racy */, tsorig, stem );
    }
    return 0;
  }
  default: FD_LOG_ERR(( "unexpected input kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  if( FD_UNLIKELY( !strcmp( tile->tower.identity_key, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));
  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.identity_key, /* pubkey only: */ 1 ) );

  /* The vote key can be specified either directly as a base58 encoded
     pubkey, or as a file path.  We first try to decode as a pubkey. */

  uchar * vote_key = fd_base58_decode_32( tile->tower.vote_account, ctx->vote_account->uc );
  if( FD_UNLIKELY( !vote_key ) ) ctx->vote_account[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->tower.vote_account, /* pubkey only: */ 1 ) );

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
  ctx_t * ctx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),         sizeof(ctx_t)                            );
  void  * epoch = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(),       fd_epoch_footprint( FD_VOTER_MAX )       );
  void  * ghost = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),       fd_ghost_footprint( FD_BLOCK_MAX )       );
  void  * notar = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_align(),       fd_notar_footprint( FD_BLOCK_MAX )       );
  void  * tower = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),       fd_tower_footprint()                     );
  void  * accts = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_accts_align(), fd_tower_accts_footprint( FD_VOTER_MAX ) );
  void  * forks = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_forks_align(), fd_tower_forks_footprint( FD_BLOCK_MAX ) );
  void  * _vote_towers   = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint()*FD_VOTER_MAX  );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->epoch       = fd_epoch_join      ( fd_epoch_new      ( epoch, FD_VOTER_MAX       ) );
  ctx->ghost       = fd_ghost_join      ( fd_ghost_new      ( ghost, FD_BLOCK_MAX, 42UL ) );
  ctx->notar       = fd_notar_join      ( fd_notar_new      ( notar, FD_BLOCK_MAX       ) );
  ctx->tower       = fd_tower_join      ( fd_tower_new      ( tower                     ) );
  ctx->tower_accts = fd_tower_accts_join( fd_tower_accts_new( accts, FD_VOTER_MAX       ) );
  ctx->tower_forks = fd_tower_forks_join( fd_tower_forks_new( forks, FD_BLOCK_MAX       ) );
  FD_TEST( ctx->epoch );
  FD_TEST( ctx->ghost );
  FD_TEST( ctx->notar );
  FD_TEST( ctx->tower );

  for( ulong i = 0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sha512_t), sizeof(fd_sha512_t) ) ) );
    FD_TEST( sha );
    ctx->sha[i] = sha;
  }

  for( ulong i=0UL; i<FD_VOTER_MAX; i++ ) {
    ctx->vote_towers[ i ] = fd_tower_join( fd_tower_new( (uchar*)_vote_towers+(i*fd_tower_footprint() ) ) );
    FD_TEST( ctx->vote_towers[ i ] );
  }

  ctx->init = 0;

  ctx->replay_vote_states_cnt = 0UL;

  FD_TEST( tile->in_cnt<sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "genesi_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESIS;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "snap_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAP;
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
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

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
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->checkpt_fd!=-1 ) ) out_fds[ out_cnt++ ] = ctx->checkpt_fd;
  if( FD_LIKELY( ctx->restore_fd!=-1 ) ) out_fds[ out_cnt++ ] = ctx->restore_fd;
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE    ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(ctx_t)
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
