#include "fd_tower.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#define THRESHOLD_DEPTH         (8)
#define THRESHOLD_PCT           (2.0 / 3.0)
#define SHALLOW_THRESHOLD_DEPTH (4)
#define SHALLOW_THRESHOLD_PCT   (0.38)
#define SWITCH_PCT              (0.38)

void *
fd_tower_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tower_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  return fd_tower_votes_new( shmem );
}

fd_tower_t *
fd_tower_join( void * shtower ) {

  if( FD_UNLIKELY( !shtower ) ) {
    FD_LOG_WARNING(( "NULL tower" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtower, fd_tower_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tower" ));
    return NULL;
  }

  return fd_tower_votes_join( shtower );
}

void *
fd_tower_leave( fd_tower_t * tower ) {

  if( FD_UNLIKELY( !tower ) ) {
    FD_LOG_WARNING(( "NULL tower" ));
    return NULL;
  }

  return fd_tower_votes_leave( tower );
}

void *
fd_tower_delete( void * tower ) {

  if( FD_UNLIKELY( !tower ) ) {
    FD_LOG_WARNING(( "NULL tower" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)tower, fd_tower_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tower" ));
    return NULL;
  }

  return fd_tower_votes_delete( tower );
}

static inline ulong
expiration( fd_tower_vote_t const * vote ) {
  ulong lockout = 1UL << vote->conf;
  return vote->slot + lockout;
}

static inline ulong
simulate_vote( fd_tower_t const * tower, ulong slot ) {
  ulong cnt = fd_tower_votes_cnt( tower );
  while( cnt ) {

    /* Return early if we can't pop the top tower vote, even if votes
       below it are expired. */

    if( FD_LIKELY( expiration( fd_tower_votes_peek_index_const( tower, cnt - 1 ) ) >= slot ) ) {
      break;
    }
    cnt--;
  }
  return cnt;
}

int
fd_tower_lockout_check( fd_tower_t const * tower,
                        fd_ghost_t const * ghost,
                        ulong              slot,
                        fd_hash_t const  * block_id ) {
  #if FD_TOWER_USE_HANDHOLDING
  FD_TEST( !fd_tower_votes_empty( tower ) ); /* caller error */
  #endif

  /* Simulate a vote to pop off all the votes that have been expired at
     the top of the tower. */

  ulong cnt = simulate_vote( tower, slot );

  /* By definition, all votes in the tower must be for the same fork, so
     check if the previous vote (ie. the last vote in the tower) is on
     the same fork as the fork we want to vote for. We do this using
     ghost by checking if the previous vote slot is an ancestor of the
     `slot`. If the previous vote slot is too old (ie. older than
     ghost->root), then we don't have ancestry information anymore and
     we just assume it is on the same fork.

     FIXME discuss if it is safe to assume that? */

  fd_tower_vote_t const * vote = fd_tower_votes_peek_index_const( tower, cnt - 1 );
  fd_ghost_ele_t const *  root = fd_ghost_root_const( ghost );

  int lockout_check = (slot > vote->slot) &&
                      (vote->slot < root->slot || fd_ghost_is_ancestor( ghost, fd_ghost_hash( ghost, vote->slot ), block_id ));
  FD_LOG_NOTICE(( "[fd_tower_lockout_check] ok? %d. top: (slot: %lu, conf: %lu). switch: %lu.", lockout_check, vote->slot, vote->conf, slot ));
  return lockout_check;
}

int
fd_tower_switch_check( fd_tower_t const * tower,
                       fd_epoch_t const * epoch,
                       fd_ghost_t const * ghost,
                       ulong              slot,
                       fd_hash_t const *  block_id ) {
  #if FD_TOWER_USE_HANDHOLDING
  FD_TEST( !fd_tower_votes_empty( tower ) ); /* caller error */
  #endif

  fd_tower_vote_t const * vote = fd_tower_votes_peek_tail_const( tower );
  fd_ghost_ele_t const *  root = fd_ghost_root_const( ghost );

  if( FD_UNLIKELY( vote->slot < root->slot ) ) {

    /* It is possible our last vote slot precedes our ghost root. This
       can happen, for example, when we restart from a snapshot and set
       the ghost root to the snapshot slot (we won't have an ancestry
       before the snapshot slot.)

       If this is the case, we assume it's ok to switch. */

    return 1;
  }

  /* fd_tower_switch_check is only called if latest_vote->slot and
     fork->slot are on different forks (determined by is_descendant), so
     they must not fall on the same ancestry path back to the gca.

     INVALID:

       0
        \
         1    <- a
          \
           2  <- b

     VALID:

       0
      / \
     1   2
     ^   ^
     a   b

  */

  #if FD_TOWER_USE_HANDHOLDING
  FD_TEST( !fd_ghost_is_ancestor( ghost, fd_ghost_hash( ghost, vote->slot ), block_id ) );
  #endif
  fd_hash_t     const * vote_block_id = fd_ghost_hash( ghost, vote->slot );
  fd_ghost_hash_map_t const * maph    = fd_ghost_hash_map_const( ghost );
  fd_ghost_ele_t      const * pool    = fd_ghost_pool_const( ghost );
  fd_ghost_ele_t      const * gca     = fd_ghost_gca( ghost, vote_block_id, block_id );
  ulong                       gca_idx = fd_ghost_hash_map_idx_query_const( maph, &gca->key, ULONG_MAX, pool );

  /* gca_child is our latest_vote slot's ancestor that is also a direct
     child of GCA.  So we do not count it towards the stake of the
     different forks. */

  fd_ghost_ele_t const * gca_child = fd_ghost_query_const( ghost, vote_block_id );
  while( FD_LIKELY( gca_child->parent != gca_idx ) ) {
    gca_child = fd_ghost_pool_ele_const( pool, gca_child->parent );
  }

  ulong switch_stake = 0;
  fd_ghost_ele_t const * child = fd_ghost_child_const( ghost, gca );
  while( FD_LIKELY( child ) ) {
    if( FD_LIKELY( child != gca_child ) ) {
      switch_stake += child->weight;
    }
    child = fd_ghost_pool_ele_const( pool, child->sibling );
  }

  double switch_pct = (double)switch_stake / (double)epoch->total_stake;
  FD_LOG_DEBUG(( "[%s] ok? %d. top: %lu. switch: %lu. switch stake: %.0lf%%.", __func__, switch_pct > SWITCH_PCT, fd_tower_votes_peek_tail_const( tower )->slot, slot, switch_pct * 100.0 ));
  return switch_pct > SWITCH_PCT;
}

int
fd_tower_threshold_check( fd_tower_t const *    tower,
                          fd_epoch_t const *    epoch,
                          fd_funk_t *           funk,
                          fd_funk_txn_t const * txn,
                          ulong                 slot,
                          fd_tower_t *          scratch ) {

  /* First, simulate a vote, popping off everything that would be
     expired by voting for the current slot. */

  ulong cnt = simulate_vote( tower, slot );

  /* Return early if our tower is not at least THRESHOLD_DEPTH deep
     after simulating. */

  if( FD_UNLIKELY( cnt < THRESHOLD_DEPTH ) ) return 1;

  /* Get the vote slot from THRESHOLD_DEPTH back. Note THRESHOLD_DEPTH
     is the 8th index back _including_ the simulated vote at index 0,
     which is not accounted for by `cnt`, so subtracting THRESHOLD_DEPTH
     will conveniently index the threshold vote. */

  ulong threshold_slot = fd_tower_votes_peek_index_const( tower, cnt - THRESHOLD_DEPTH )->slot;

  /* Track the amount of stake that has vote slot >= threshold_slot. */

  ulong threshold_stake = 0;

  /* Iterate all the vote accounts. */

  fd_voter_t const * epoch_voters = fd_epoch_voters_const( epoch );
  for (ulong i = 0; i < fd_epoch_voters_slot_cnt( epoch_voters ); i++ ) {
    if( FD_LIKELY( fd_epoch_voters_key_inval( epoch_voters[i].key ) ) ) continue /* most slots are empty */;

    fd_voter_t const * voter = &epoch_voters[i];

    /* Convert the landed_votes into tower's vote_slots interface. */

    fd_tower_votes_remove_all( scratch );
    int err = fd_tower_from_vote_acc( scratch, funk, txn, &voter->rec );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "[%s] failed to read vote account %s", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key) ));
      continue;
    }

    /* If this voter has not voted, continue. */

    if( FD_UNLIKELY( fd_tower_votes_empty( scratch ) ) ) continue;

    ulong cnt = simulate_vote( scratch, slot );

    /* Continue if their tower is empty after simulating. */

    if( FD_UNLIKELY( !cnt ) ) continue;

    /* Get their latest vote. */

    fd_tower_vote_t const * vote = fd_tower_votes_peek_index( scratch, cnt - 1 );

    /* Count their stake towards the threshold check if their latest
        vote slot >= our threshold slot.

        Because we are iterating vote accounts on the same fork that we
        we want to vote for, we know these slots must all occur along
        the same fork ancestry.

        Therefore, if their latest vote slot >= our threshold slot, we
        know that vote must be for the threshold slot itself or one of
        threshold slot's descendants. */

    if( FD_LIKELY( vote->slot >= threshold_slot ) ) {
      threshold_stake += voter->stake;
    }
  }

  double threshold_pct = (double)threshold_stake / (double)epoch->total_stake;
  FD_LOG_NOTICE(( "[%s] ok? %d. top: %lu. threshold: %lu. stake: %.0lf%%.", __func__, threshold_pct > THRESHOLD_PCT, fd_tower_votes_peek_tail_const( tower )->slot, threshold_slot, threshold_pct * 100.0 ));
  return threshold_pct > THRESHOLD_PCT;
}

ulong
fd_tower_reset_slot( fd_tower_t const * tower,
                     fd_ghost_t const * ghost ) {

  fd_tower_vote_t const *    vote = fd_tower_votes_peek_tail_const( tower );
  fd_ghost_ele_t const *     root = fd_ghost_root_const( ghost );
  fd_ghost_ele_t const *     head = fd_ghost_head( ghost, root );
  fd_hash_t const * vote_block_id = fd_ghost_hash( ghost, vote->slot );

  /* Reset to the ghost head if any of the following is true:
       1. haven't voted
       2. last vote < ghost root
       3. ghost root is not an ancestory of last vote */

  if( FD_UNLIKELY( !vote || vote->slot < root->slot ||
                   !fd_ghost_is_ancestor( ghost, &root->key, vote_block_id ) ) ) {
    return head->slot;
  }

  /* Find the ghost node keyed by our last vote slot. It is invariant
     that this node must always be found after doing the above check.
     Otherwise ghost and tower contain implementation bugs and/or are
     corrupt. */

  fd_ghost_ele_t const * vote_node = fd_ghost_query_const( ghost, vote_block_id );
  #if FD_TOWER_USE_HANDHOLDING
  if( FD_UNLIKELY( !vote_node ) ) {
    fd_ghost_print( ghost, 0, root );
    FD_LOG_ERR(( "[%s] invariant violation: unable to find last tower vote slot %lu in ghost.", __func__, vote->slot ));
  }
  #endif

  /* Starting from the node keyed by the last vote slot, greedy traverse
     for the head. */

  return fd_ghost_head( ghost, vote_node )->slot;
}

ulong
fd_tower_vote_slot( fd_tower_t *          tower,
                    fd_epoch_t const *    epoch,
                    fd_funk_t *           funk,
                    fd_funk_txn_t const * txn,
                    fd_ghost_t const *    ghost,
                    fd_tower_t *          scratch ) {

  fd_tower_vote_t const * vote = fd_tower_votes_peek_tail_const( tower );
  fd_ghost_ele_t const *  root = fd_ghost_root_const( ghost );
  fd_ghost_ele_t const *  head = fd_ghost_head( ghost, root );

  /* Vote for the ghost head if any of the following is true:

     1. haven't voted
     2. last vote < ghost root
     3. ghost root is not an ancestory of last vote

     FIXME need to ensure lockout safety for case 2 and 3 */

  if( FD_UNLIKELY( !vote || vote->slot < root->slot ) ) {
    return head->slot;
  }
  fd_hash_t const * vote_block_id = fd_ghost_hash( ghost, vote->slot );
  if( FD_UNLIKELY( !fd_ghost_is_ancestor( ghost, &root->key, vote_block_id ) ) ) {
    return head->slot;
  }

  /* Optimize for when there is just one fork or that we already
     previously voted for the best fork. */

  if( FD_LIKELY( fd_ghost_is_ancestor( ghost, vote_block_id, &head->key ) ) ) {

    /* The ghost head is on the same fork as our last vote slot, so we
       can vote fork it as long as we pass the threshold check. */

    if( FD_LIKELY( head->slot > vote->slot && fd_tower_threshold_check( tower, epoch, funk, txn, head->slot, scratch ) ) ) {
      FD_LOG_DEBUG(( "[%s] success (threshold). best: %lu. vote: (slot: %lu conf: %lu)", __func__, head->slot, vote->slot, vote->conf ));
      return head->slot;
    }
    FD_LOG_DEBUG(( "[%s] failure (threshold). best: %lu. vote: (slot: %lu conf: %lu)", __func__, head->slot, vote->slot, vote->conf ));
    return FD_SLOT_NULL; /* can't vote. need to wait for threshold check. */
  }

  /* The ghost head is on a different fork from our last vote slot, so
      try to switch if we pass lockout and switch threshold. */

  if( FD_UNLIKELY( fd_tower_lockout_check( tower, ghost, head->slot, &head->key ) &&
                   fd_tower_switch_check( tower, epoch, ghost, head->slot, &head->key ) ) ) {
    FD_LOG_DEBUG(( "[%s] success (lockout switch). best: %lu. vote: (slot: %lu conf: %lu)", __func__, head->slot, vote->slot, vote->conf ));
    return head->slot;
  }
  FD_LOG_DEBUG(( "[%s] failure (lockout switch). best: %lu. vote: (slot: %lu conf: %lu)", __func__, head->slot, vote->slot, vote->conf ));
  return FD_SLOT_NULL;
}

ulong
fd_tower_vote( fd_tower_t * tower, ulong slot ) {
  FD_LOG_DEBUG(( "[%s] voting for slot %lu", __func__, slot ));

  #if FD_TOWER_USE_HANDHOLDING
  fd_tower_vote_t const * vote = fd_tower_votes_peek_tail_const( tower );
  if( FD_UNLIKELY( vote && slot < vote->slot ) ) FD_LOG_ERR(( "[%s] slot %lu < vote->slot %lu", __func__, slot, vote->slot )); /* caller error*/
  #endif

  /* Use simulate_vote to determine how many expired votes to pop. */

  ulong cnt = simulate_vote( tower, slot );

  /* Pop everything that got expired. */

  while( fd_tower_votes_cnt( tower ) > cnt ) {
    fd_tower_votes_pop_tail( tower );
  }

  /* If the tower is still full after expiring, then pop and return the
     bottom vote slot as the new root because this vote has incremented
     it to max lockout.  Otherwise this is a no-op and there is no new
     root (FD_SLOT_NULL). */

  ulong root = FD_SLOT_NULL;
  if( FD_LIKELY( fd_tower_votes_full( tower ) ) ) { /* optimize for full tower */
    root = fd_tower_votes_pop_head( tower ).slot;
  }

  /* Increment confirmations (double lockouts) for consecutive
     confirmations in prior votes. */

  ulong prev_conf = 0;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower );
       !fd_tower_votes_iter_done_rev( tower, iter );
       iter = fd_tower_votes_iter_prev( tower, iter ) ) {
    fd_tower_vote_t * vote = fd_tower_votes_iter_ele( tower, iter );
    if( FD_UNLIKELY( vote->conf != ++prev_conf ) ) {
      break;
    }
    vote->conf++;
  }

  /* Add the new vote to the tower. */

  fd_tower_votes_push_tail( tower, (fd_tower_vote_t){ .slot = slot, .conf = 1 } );

  /* Return the new root (FD_SLOT_NULL if there is none). */

  return root;
}

ulong
fd_tower_simulate_vote( fd_tower_t const * tower, ulong slot ) {
  #if FD_TOWER_USE_HANDHOLDING
  FD_TEST( !fd_tower_votes_empty( tower ) ); /* caller error */
  #endif

  return simulate_vote( tower, slot );
}

int
fd_tower_from_vote_acc( fd_tower_t *              tower,
                        fd_funk_t *               funk,
                        fd_funk_txn_t const *     txn,
                        fd_funk_rec_key_t const * vote_acc ) {
# if FD_TOWER_USE_HANDHOLDING
  FD_TEST( fd_tower_votes_empty( tower ) );
# endif

  for(;;) {

    /* Speculatively query the record and parse the voter state. If the
       record is missing or the voter state fails to parse, then return
       early (tower will be empty). */

    fd_funk_rec_query_t   query;
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, txn, vote_acc, NULL, &query );
    if( FD_UNLIKELY( !rec ) ) return -1; /* record not found */
    fd_voter_state_t const * state = fd_voter_state( funk, rec );
    if( FD_UNLIKELY( !state ) ) return -1; /* unable to parse voter state */

    /* Speculatively query the cnt.  */

    ulong cnt = fd_voter_state_cnt( state ); /* TODO remove once Funk reads are safe */
    if( FD_UNLIKELY( fd_funk_rec_query_test( &query ) != FD_FUNK_SUCCESS ) ) continue;
    if( FD_UNLIKELY( cnt > 31UL ) ) FD_LOG_ERR(( "[%s] funk vote account corruption. cnt %lu > 31", __func__, cnt ));

    /* Speculatively read the votes out of the state and push them onto
       the tower. If there is a conflicting operation during this read,
       rollback the tower. */

    fd_tower_vote_t vote = { 0 };
    ulong sz = sizeof(fd_voter_vote_old_t);
    for( ulong i = 0; i < cnt; i++ ) {
      if( FD_UNLIKELY( state->discriminant == fd_vote_state_versioned_enum_v0_23_5 ) ) {
        memcpy( (uchar *)&vote, (uchar *)(state->v0_23_5.votes + i), sz );
      } else if ( FD_UNLIKELY( state->discriminant == fd_vote_state_versioned_enum_v1_14_11 ) ) {
        memcpy( (uchar *)&vote, (uchar *)(state->v1_14_11.votes + i), sz );
      } else if ( FD_UNLIKELY( state->discriminant == fd_vote_state_versioned_enum_current ) ) {
        memcpy( (uchar *)&vote, (uchar *)(state->votes + i) + sizeof(uchar) /* latency */, sz );
      } else {
        FD_LOG_ERR(( "[%s] unknown state->discriminant %u", __func__, state->discriminant ));
      }
      fd_tower_votes_push_tail( tower, vote );
    }

    if( FD_LIKELY( fd_funk_rec_query_test( &query ) == FD_FUNK_SUCCESS ) ) return 0;
    else fd_tower_votes_remove_all( tower ); /* reset the tower and try again  */
  }
}

void
fd_tower_to_vote_txn( fd_tower_t const *    tower,
                      ulong                 root,
                      fd_lockout_offset_t * lockouts_scratch,
                      fd_hash_t const *     bank_hash,
                      fd_hash_t const *     recent_blockhash,
                      fd_pubkey_t const *   validator_identity,
                      fd_pubkey_t const *   vote_authority,
                      fd_pubkey_t const *   vote_acc,
                      fd_txn_p_t *          vote_txn ) {

  fd_compact_vote_state_update_t tower_sync;
  tower_sync.root          = root;
  tower_sync.lockouts_len  = (ushort)fd_tower_votes_cnt( tower );
  tower_sync.lockouts      = lockouts_scratch;
  tower_sync.timestamp     = fd_log_wallclock() / (long)1e9; /* seconds */
  tower_sync.has_timestamp = 1;

  ulong prev = tower_sync.root;
  ulong i    = 0UL;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower );
      !fd_tower_votes_iter_done( tower, iter );
      iter = fd_tower_votes_iter_next( tower, iter ) ) {
    fd_tower_vote_t const * vote              = fd_tower_votes_iter_ele_const( tower, iter );
    tower_sync.lockouts[i].offset             = vote->slot - prev;
    tower_sync.lockouts[i].confirmation_count = (uchar)vote->conf;
    prev                                      = vote->slot;
    i++;
  }
  memcpy( tower_sync.hash.uc, bank_hash, sizeof(fd_hash_t) );

  uchar * txn_out = vote_txn->payload;
  uchar * txn_meta_out = vote_txn->_;

  int same_addr = !memcmp( validator_identity, vote_authority, sizeof(fd_pubkey_t) );
  if( FD_LIKELY( same_addr ) ) {

    /* 0: validator identity
       1: vote account address
       2: vote program */

    fd_txn_accounts_t accts;
    accts.signature_cnt         = 1;
    accts.readonly_signed_cnt   = 0;
    accts.readonly_unsigned_cnt = 1;
    accts.acct_cnt              = 3;
    accts.signers_w             = validator_identity;
    accts.signers_r             = NULL;
    accts.non_signers_w         = vote_acc;
    accts.non_signers_r         = &fd_solana_vote_program_id;
    FD_TEST( fd_txn_base_generate( txn_meta_out, txn_out, accts.signature_cnt, &accts, recent_blockhash->uc ) );
  } else {

    /* 0: validator identity
       1: vote authority
       2: vote account address
       3: vote program */

    fd_txn_accounts_t accts;
    accts.signature_cnt         = 2;
    accts.readonly_signed_cnt   = 1;
    accts.readonly_unsigned_cnt = 1;
    accts.acct_cnt              = 4;
    accts.signers_w             = validator_identity;
    accts.signers_r             = vote_authority;
    accts.non_signers_w         = vote_acc;
    accts.non_signers_r         = &fd_solana_vote_program_id;
    FD_TEST( fd_txn_base_generate( txn_meta_out, txn_out, accts.signature_cnt, &accts, recent_blockhash->uc ) );
  }

  /* Add the vote instruction to the transaction. */

  fd_vote_instruction_t vote_ix;
  uchar                 vote_ix_buf[FD_TXN_MTU];
  vote_ix.discriminant                    = fd_vote_instruction_enum_compact_update_vote_state;
  vote_ix.inner.compact_update_vote_state = tower_sync;
  fd_bincode_encode_ctx_t encode = { .data = vote_ix_buf, .dataend = ( vote_ix_buf + FD_TXN_MTU ) };
  fd_vote_instruction_encode( &vote_ix, &encode );
  uchar program_id;
  uchar ix_accs[2];
  if( FD_LIKELY( same_addr ) ) {
    ix_accs[0] = 1; /* vote account address */
    ix_accs[1] = 0; /* vote authority */
    program_id = 2; /* vote program */
  } else {
    ix_accs[0] = 2; /* vote account address */
    ix_accs[1] = 1; /* vote authority */
    program_id = 3; /* vote program */
  }
  ushort vote_ix_sz = (ushort)fd_vote_instruction_size( &vote_ix );
  vote_txn->payload_sz = fd_txn_add_instr( txn_meta_out, txn_out, program_id, ix_accs, 2, vote_ix_buf, vote_ix_sz );
}

int
fd_tower_verify( fd_tower_t const * tower ) {
  fd_tower_vote_t const * prev = NULL;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower );
       !fd_tower_votes_iter_done( tower, iter );
       iter = fd_tower_votes_iter_next( tower, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_votes_iter_ele_const( tower, iter );
    if( FD_LIKELY( prev && !( vote->slot < prev->slot && vote->conf < prev->conf ) ) ) {
      FD_LOG_WARNING(( "[%s] invariant violation: vote %lu %lu. prev %lu %lu", __func__, vote->slot, vote->conf, prev->slot, prev->conf ));
      return -1;
    }
    prev = vote;
  }
  return 0;
}

#include <stdio.h>

void
fd_tower_print( fd_tower_t const * tower, ulong root ) {
  FD_LOG_NOTICE( ( "\n\n[Tower]" ) );
  ulong max_slot = 0;

  /* Determine spacing. */

  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower );
       !fd_tower_votes_iter_done_rev( tower, iter );
       iter = fd_tower_votes_iter_prev( tower, iter ) ) {

    max_slot = fd_ulong_max( max_slot, fd_tower_votes_iter_ele_const( tower, iter )->slot );
  }

  /* Calculate the number of digits in the maximum slot value. */

  int           digit_cnt = 0;
  unsigned long rem       = max_slot;
  do {
    rem /= 10;
    ++digit_cnt;
  } while( rem > 0 );

  /* Print the table header */

  printf( "slot%*s | %s\n", digit_cnt - (int)strlen("slot"), "", "confirmation count" );

  /* Print the divider line */

  for( int i = 0; i < digit_cnt; i++ ) {
    printf( "-" );
  }
  printf( " | " );
  for( ulong i = 0; i < strlen( "confirmation count" ); i++ ) {
    printf( "-" );
  }
  printf( "\n" );

  /* Print each record in the table */

  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower );
       !fd_tower_votes_iter_done_rev( tower, iter );
       iter = fd_tower_votes_iter_prev( tower, iter ) ) {

    fd_tower_vote_t const * vote = fd_tower_votes_iter_ele_const( tower, iter );
    printf( "%*lu | %lu\n", digit_cnt, vote->slot, vote->conf );
    max_slot = fd_ulong_max( max_slot, fd_tower_votes_iter_ele_const( tower, iter )->slot );
  }
  printf( "%*lu | root\n", digit_cnt, root );
  printf( "\n" );
}
