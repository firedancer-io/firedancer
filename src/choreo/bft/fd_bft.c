#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_borrowed_account.h"
#include "../../flamenco/runtime/program/fd_program_util.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

#include "../fd_choreo_base.h"
#include "../ghost/fd_ghost.h"
#include "../tower/fd_tower.h"
#include "fd_bft.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

void *
fd_bft_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_bft_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_bft_footprint();
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad mem" ) );
    return NULL;
  }

  return shmem;
}

fd_bft_t *
fd_bft_join( void * shbft ) {

  if( FD_UNLIKELY( !shbft ) ) {
    FD_LOG_WARNING( ( "NULL bft" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbft, fd_bft_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned bft" ) );
    return NULL;
  }

  return (fd_bft_t *)shbft;
}

void *
fd_bft_leave( fd_bft_t const * bft ) {

  if( FD_UNLIKELY( !bft ) ) {
    FD_LOG_WARNING( ( "NULL bft" ) );
    return NULL;
  }

  return (void *)bft;
}

void *
fd_bft_delete( void * bft ) {

  if( FD_UNLIKELY( !bft ) ) {
    FD_LOG_WARNING( ( "NULL bft" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)bft, fd_bft_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned bft" ) );
    return NULL;
  }

  return bft;
}

static ulong
query_pubkey_stake( fd_pubkey_t const * pubkey, fd_vote_accounts_t * vote_accounts ) {
  fd_vote_accounts_pair_t_mapnode_t key         = { 0 };
  key.elem.key                                  = *pubkey;
  fd_vote_accounts_pair_t_mapnode_t * vote_node = fd_vote_accounts_pair_t_map_find(
      vote_accounts->vote_accounts_pool, vote_accounts->vote_accounts_root, &key );
  return vote_node ? vote_node->elem.stake : 0;
}

static void
count_replay_votes( fd_bft_t * bft, fd_fork_t * fork ) {
  FD_PARAM_UNUSED long now = fd_log_wallclock();

  fd_latest_vote_t * latest_votes = fork->slot_ctx.latest_votes;

  fd_root_vote_t * root_votes = bft->root_votes;

  ulong smr = bft->smr;

  for( fd_latest_vote_deque_iter_t iter = fd_latest_vote_deque_iter_init( latest_votes );
       !fd_latest_vote_deque_iter_done( latest_votes, iter );
       iter = fd_latest_vote_deque_iter_next( latest_votes, iter ) ) {

    fd_latest_vote_t *  latest_vote = fd_latest_vote_deque_iter_ele( latest_votes, iter );
    fd_pubkey_t const * node_pubkey = &latest_vote->node_pubkey;

    ulong vote_slot = latest_vote->slot_hash.slot;

    /* Ignore votes for slots < smr. */

    if( FD_UNLIKELY( vote_slot <= bft->smr ) ) continue;

    /* Look up _our_ bank hash for this vote. Note, because these are replay votes that come from
       the vote program, the bank hashes must match. */

    fd_blockstore_start_read( bft->blockstore );
    fd_hash_t const * bank_hash = fd_blockstore_bank_hash_query( bft->blockstore, vote_slot );
    fd_blockstore_end_read( bft->blockstore );

#if FD_BFT_USE_HANDHOLDING
    /* This indicates a programming error, because if these are replay votes that were successfully
       executed by the vote program that should imply the vote program attempts to look up the bank
       hash the vote is voting on). This invariant is broken if the bank hash is missing. */
    // if( FD_UNLIKELY( !bank_hash ) ) FD_LOG_ERR( ( "missing bank hash %lu", vote_slot ) );
    if( FD_UNLIKELY( !bank_hash ) ) {
      FD_LOG_WARNING( ( "unexpected missing bank hash for slot %lu", vote_slot ) );
      continue;
    };
#endif

    /* Look up the stake for this pubkey. */

    ulong stake = query_pubkey_stake( node_pubkey,
                                      &fork->slot_ctx.epoch_ctx->epoch_bank.stakes.vote_accounts );

    /* Look up the ghost node. */

    fd_slot_hash_t    slot_hash  = { .slot = vote_slot, .hash = *bank_hash };
    fd_ghost_node_t * ghost_node = fd_ghost_node_query( bft->ghost, &slot_hash );

#if FD_BFT_USE_HANDHOLDING
    /* This indicates a programming error, because the slot hash must have been inserted if we are
     * processesing replay votes. */
    if( FD_UNLIKELY( !ghost_node ) ) {
      FD_LOG_ERR( ( "missing ghost key %lu %32J", slot_hash.slot, slot_hash.hash.hash ) );
    };
#endif

    /* Upsert the vote into ghost. */

    fd_ghost_replay_vote_upsert( bft->ghost, &slot_hash, node_pubkey, stake );

    /* Check this slot's stake pct in ghost, and mark stake threshold accordingly if reached. */

    double pct = (double)ghost_node->stake / (double)bft->epoch_stake;

    if( FD_UNLIKELY( !ghost_node->eqv_safe && pct > FD_BFT_EQV_SAFE ) ) {
      ghost_node->eqv_safe = 1;
#if FD_BFT_USE_HANDHOLDING
      // FD_LOG_NOTICE(
      //     ( "[bft] eqv safe (%lf): (%lu, %32J)", pct, slot_hash.slot, slot_hash.hash.hash ) );
#endif
    }

    if( FD_UNLIKELY( !ghost_node->opt_conf && pct > FD_BFT_OPT_CONF ) ) {
      ghost_node->opt_conf = 1;
#if FD_BFT_USE_HANDHOLDING
      // FD_LOG_NOTICE(
      //     ( "[bft] opt conf (%lf): (%lu, %32J)", pct, slot_hash.slot, slot_hash.hash.hash ) );
#endif
    }

    /* Only process vote slots higher than our SMR. */

    if( FD_LIKELY( latest_vote->root > bft->smr ) ) {

      /* Find the previous root vote by node pubkey. */

      fd_root_vote_t * prev_root_vote =
          fd_root_vote_map_query( root_votes, latest_vote->node_pubkey, NULL );

      if( FD_UNLIKELY( !prev_root_vote ) ) {

        /* This node pubkey has not yet voted. */

        prev_root_vote = fd_root_vote_map_insert( root_votes, latest_vote->node_pubkey );
      } else {

        fd_root_stake_t * root_stake =
            fd_root_stake_map_query( bft->root_stakes, prev_root_vote->root, NULL );
        root_stake->stake -= stake;
      }

      /* Update our bookkeeping of this node pubkey's root. */

      prev_root_vote->root = latest_vote->root;

      /* Add this node pubkey's stake to all slots in the ancestry back to the SMR. */

      fd_root_stake_t * root_stake =
          fd_root_stake_map_query( bft->root_stakes, latest_vote->root, NULL );
      if( FD_UNLIKELY( !root_stake ) ) {
        root_stake = fd_root_stake_map_insert( bft->root_stakes, latest_vote->root );
      }
      root_stake->stake += stake;
    }
  }

  if( FD_LIKELY( smr > bft->smr ) ) { bft->smr = smr; }
}

FD_FN_UNUSED static void
count_gossip_votes( fd_bft_t *                    bft,
                    fd_latest_vote_t *            gossip_votes,
                    FD_PARAM_UNUSED fd_stakes_t * epoch_stakes ) {
  for( fd_latest_vote_deque_iter_t iter = fd_latest_vote_deque_iter_init( gossip_votes );
       !fd_latest_vote_deque_iter_done( gossip_votes, iter );
       iter = fd_latest_vote_deque_iter_next( gossip_votes, iter ) ) {

    fd_latest_vote_t * vote      = fd_latest_vote_deque_iter_ele( gossip_votes, iter );
    ulong              vote_slot = vote->slot_hash.slot;

    fd_hash_t const * bank_hash = fd_blockstore_bank_hash_query( bft->blockstore, vote_slot );
    if( FD_UNLIKELY( !bank_hash ) ) {
      /* TODO we need to implement repair logic here */
      FD_LOG_WARNING( ( "couldn't find bank hash for slot %lu", vote_slot ) );
      continue;
    }

    fd_slot_hash_t    slot_hash  = { .slot = vote_slot, .hash = *bank_hash };
    fd_ghost_node_t * ghost_node = fd_ghost_node_query( bft->ghost, &slot_hash );

#if FD_BFT_USE_HANDHOLDING
    /* This indicates a programming error, because the checks above should ensure slot hash is in
       ghost given we are using our own (slot, bank hash) that we just looked up in blockstore. */
    if( FD_UNLIKELY( !ghost_node ) ) {
      FD_LOG_ERR( ( "missing ghost key %lu %32J", slot_hash.slot, slot_hash.hash.hash ) );
    };
#endif

    if( FD_UNLIKELY( 0 != memcmp( bank_hash, &vote->slot_hash, sizeof( fd_hash_t ) ) ) ) {
      ghost_node->eqv = 1;

#if FD_BFT_USE_HANDHOLDING
      FD_LOG_WARNING( ( "eqv on slot: %lu. ours: %32J vs. theirs: %32J",
                        vote_slot,
                        bank_hash,
                        &vote->slot_hash.hash ) );
#endif

      continue;
    }

    // ulong stake = query_pubkey_stake( &vote->node_pubkey, epoch_stakes );
    // fd_ghost_gossip_vote_upsert( bft->ghost, &slot_hash, &vote->node_pubkey, stake );
  }
}

/* Update fork with the votes in the block. */
void
fd_bft_fork_update( fd_bft_t * bft, fd_fork_t * fork ) {
  FD_PARAM_UNUSED long now = fd_log_wallclock();

  fd_slot_bank_t * bank = &fork->slot_ctx.slot_bank;

  /* Update the current fork head's bft key. */

  fd_slot_hash_t curr_key = {
      .slot = fork->slot,
      .hash = bank->banks_hash,
  };

  /* Get the parent key. Every block must have a parent (except genesis or snapshot block). */

  fd_blockstore_start_read( bft->blockstore );
  ulong parent_slot = fd_blockstore_parent_slot_query( bft->blockstore, fork->slot );
  fd_blockstore_end_read( bft->blockstore );

  /* Insert this fork into bft. */

  if( FD_UNLIKELY( parent_slot == FD_SLOT_NULL ) ) {
    fd_ghost_leaf_insert( bft->ghost, &curr_key, NULL );
  } else {
    fd_blockstore_start_read( bft->blockstore );
    fd_hash_t const * parent_bank_hash =
        fd_blockstore_bank_hash_query( bft->blockstore, parent_slot );
    fd_blockstore_end_read( bft->blockstore );

    if( FD_UNLIKELY( !parent_bank_hash ) ) {
      __asm__( "int $3" );
      FD_LOG_ERR( ( "invariant violation: executed child before having parent bank hash." ) );
    }

    fd_slot_hash_t parent_key = {
        .slot = parent_slot,
        .hash = *parent_bank_hash,
    };

    fd_ghost_leaf_insert( bft->ghost, &curr_key, &parent_key );
  }

  count_replay_votes( bft, fork );
}

fd_fork_t *
fd_bft_fork_choice( fd_bft_t * bft ) {
  // long now = fd_log_wallclock();
  fd_ghost_node_t * head = bft->ghost->root;
  while( head->child ) {
    fd_ghost_node_t * curr = head;
    while( curr ) {
      head = FD_GHOST_NODE_MAX( curr, head );
      curr = curr->sibling;
    }
    head = head->child;
  }

  /* search for the fork head in the frontier. */

  fd_fork_t * fork = fd_fork_frontier_ele_query(
      bft->forks->frontier, &head->slot_hash.slot, NULL, bft->forks->pool );
#if FD_BFT_USE_HANDHOLDING
  /* the ghost head must exist in the frontier. */
  if( FD_UNLIKELY( !fork ) ) {
    FD_LOG_ERR( ( "missing fork head (%lu, %32J)", head->slot_hash.slot, &head->slot_hash.hash ) );
  }
#endif

  return fork;
}

void
fd_bft_epoch_stake_update( fd_bft_t * bft, fd_exec_epoch_ctx_t * epoch_ctx ) {
  ulong                               epoch_stake = 0;
  fd_epoch_bank_t *                   epoch_bank  = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  fd_vote_accounts_pair_t_mapnode_t * pool = epoch_bank->stakes.vote_accounts.vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * root = epoch_bank->stakes.vote_accounts.vote_accounts_root;
  for( fd_vote_accounts_pair_t_mapnode_t * node = fd_vote_accounts_pair_t_map_minimum( pool, root );
       node;
       node = fd_vote_accounts_pair_t_map_successor( pool, node ) ) {
    epoch_stake += node->elem.stake;
  }
  bft->epoch_stake = epoch_stake;
}
