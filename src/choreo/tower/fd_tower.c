#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "fd_tower.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

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
fd_tower_threshold_check( fd_tower_t const *   tower,
                          fd_epoch_t *         epoch,
                          fd_pubkey_t *        vote_keys,
                          fd_tower_t * const * vote_towers,
                          ulong                vote_cnt,
                          ulong                slot ) {

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

  for (ulong i = 0; i < vote_cnt; i++ ) {
    fd_tower_t const * vote_tower = vote_towers[i];

    /* If this voter has not voted, continue. */

    if( FD_UNLIKELY( fd_tower_votes_empty( vote_tower ) ) ) continue;

    ulong cnt = simulate_vote( vote_tower, slot );

    /* Continue if their tower is empty after simulating. */

    if( FD_UNLIKELY( !cnt ) ) continue;

    /* Get their latest vote. */

    fd_tower_vote_t const * vote = fd_tower_votes_peek_index_const( vote_tower, cnt - 1 );

    /* Count their stake towards the threshold check if their latest
        vote slot >= our threshold slot.

        Because we are iterating vote accounts on the same fork that we
        we want to vote for, we know these slots must all occur along
        the same fork ancestry.

        Therefore, if their latest vote slot >= our threshold slot, we
        know that vote must be for the threshold slot itself or one of
        threshold slot's descendants. */

    if( FD_LIKELY( vote->slot >= threshold_slot ) ) {
      fd_voter_t * epoch_voters = fd_epoch_voters( epoch );
      fd_voter_t * voter        = fd_epoch_voters_query( epoch_voters, vote_keys[i], NULL );
      if( FD_UNLIKELY( !voter ) ) {
        /* This means that the cached list of epoch voters is not in sync with the list passed
           through from replay. This likely means that we have crossed an epoch boundary and the
           epoch_voter list has not been updated.

           TODO: update the set of account in epoch_voter's to match the list received from replay,
                 so that epoch_voters is correct across epoch boundaries. */
        FD_LOG_CRIT(( "[%s] voter %s was not in epoch voters", __func__,
          FD_BASE58_ENC_32_ALLOCA(&vote_keys[i]) ));
        continue;
      }
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
fd_tower_vote_slot( fd_tower_t const *   tower,
                    fd_epoch_t *         epoch,
                    fd_pubkey_t *        vote_keys,
                    fd_tower_t * const * vote_towers,
                    ulong                vote_cnt,
                    fd_ghost_t const *   ghost ) {

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

    if( FD_LIKELY( head->slot > vote->slot && fd_tower_threshold_check( tower, epoch, vote_keys, vote_towers, vote_cnt, head->slot ) ) ) {
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

  while( FD_LIKELY( fd_tower_votes_cnt( tower ) > cnt ) ) {
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
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower       );
                                   !fd_tower_votes_iter_done_rev( tower, iter );
                             iter = fd_tower_votes_iter_prev    ( tower, iter ) ) {
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

void
fd_tower_checkpt( fd_tower_t const * tower,
                  ulong              root,
                  uchar *            vote_state,
                  ulong              vote_state_sz,
                  uchar *            tower_sync,
                  ulong              tower_sync_sz,
                  uchar const        pvtkey[static 32],
                  uchar const        pubkey[static 32],
                  uchar *            ser,
                  ulong *            ser_sz ) {

  ulong off = 0; uchar * rem = NULL;

  /* kind            */ FD_STORE( uint, ser+off, fd_saved_tower_versions_enum_current ); off += sizeof(uint);
  /* signature       */ uchar * sig = ser+off;                                           off += FD_ED25519_SIG_SZ;
  /* msg             */ uchar * msg = ser+off;                                           off += sizeof(ulong);
  /* node_pubkey     */ memcpy( ser+off, pubkey, sizeof(fd_pubkey_t) );                  off += sizeof(fd_pubkey_t);
  /* threshold_depth */ FD_STORE( ulong, ser+off, THRESHOLD_DEPTH );                     off += sizeof(ulong);
  /* threshold_size  */ FD_STORE( double, ser+off, THRESHOLD_PCT );                      off += sizeof(double);

  /* vote_state      */

  memcpy( ser+off, vote_state, sizeof(fd_voter_meta_t) );                                off += sizeof(fd_voter_meta_t);
  FD_STORE( ulong, ser+off, fd_tower_votes_cnt( tower ) );
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower       );
                                   !fd_tower_votes_iter_done( tower, iter );
                             iter = fd_tower_votes_iter_next( tower, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_votes_iter_ele_const( tower, iter );
    FD_STORE( ulong, ser+off, vote->slot       );                                        off += sizeof(ulong);
    FD_STORE( uint,  ser+off, (uint)vote->conf );                                        off += sizeof(uint);
  }
  *ser = 1;                                                                              off += sizeof(uchar);
  FD_STORE( ulong, ser+off, root );                                                      off += sizeof(ulong);
  fd_voter_state_t * state = (fd_voter_state_t *)fd_type_pun( vote_state );
  rem = fd_voter_root_laddr( state ) + sizeof(uchar) + sizeof(ulong);
  memcpy( ser+off, rem, vote_state_sz - off );                                           off += vote_state_sz - off;

  /* vote_txn        */

  FD_STORE( uint, ser+off, fd_vote_transaction_enum_tower_sync );                        off += sizeof(uint);
  memcpy( ser+off, tower_sync, tower_sync_sz );                                          off += tower_sync_sz;

  /* block timestamp */

  ulong last_vote_slot = fd_tower_votes_peek_tail_const( tower )->slot;
  FD_STORE( ulong, ser+off, last_vote_slot  );                                           off += sizeof(ulong);
  FD_STORE( long, ser+off, fd_log_wallclock() / (long)1e9 );                             off += sizeof(long);

  /* sign the data (everything beginning from msg )*/

  ulong msg_sz = off - sizeof(uint) - FD_ED25519_SIG_SZ;
  FD_STORE( ulong, msg, msg_sz ); /* store the final msg sz */
  fd_sha512_t sha[1];
  fd_ed25519_sign( sig, msg, msg_sz, pubkey, pvtkey, sha );

  *ser_sz = off;
}

int
fd_tower_restore( fd_tower_t * tower,
                  ulong      * root,
                  uchar const  pubkey[ static 32 ],
                  uchar      * ser,
                  ulong        ser_sz,
                  uchar      * de,
                  ulong        de_sz ) {
  if( FD_UNLIKELY( !fd_tower_votes_empty( tower ) ) ) { FD_LOG_WARNING(( "[%s] tower must be empty", __func__ )); return -1; };

  fd_bincode_decode_ctx_t ctx; ulong sz; int err;
  ctx.data = ser; ctx.dataend = ser + ser_sz;
  err = fd_saved_tower_versions_decode_footprint( &ctx, &sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) { FD_LOG_WARNING(( "decode failed. %d",    err       )); return -1; };
  if( FD_UNLIKELY( sz > de_sz              ) ) { FD_LOG_WARNING(( "sz: %lu > de_sz: %lu", sz, de_sz )); return -1; };
  fd_saved_tower_versions_decode( de, &ctx );
  fd_saved_tower_versions_t * saved_tower_versions = (fd_saved_tower_versions_t *)fd_type_pun( de );

  if( FD_UNLIKELY( saved_tower_versions->discriminant!= fd_saved_tower_versions_enum_current ) ) {

  /* It's unclear whether the relevant Agave version is 1.7.14 or
     1.17.14. Agave references both versions in the same struct. Most
     likely a typo. */

    FD_LOG_WARNING(( "Firedancer only supports restoring modern towers (>1.17.14) from the tower binary file." ));
    return -1;
  }

  fd_saved_tower_t * current = &saved_tower_versions->inner.current;

  fd_sha512_t sha[1];
  err = fd_ed25519_verify( current->data, current->data_len, current->signature.uc, pubkey, sha );
  if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS ) ) { FD_LOG_WARNING(( "%s", fd_ed25519_strerror( err ) )); return -1; }

  ctx.data = current->data; ctx.dataend = current->data + current->data_len;
  err = fd_tower_1_14_11_decode_footprint( &ctx, &sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) { FD_LOG_WARNING(( "bincode_decode failed. %d", err )); return -1; }
  fd_tower_1_14_11_decode( ser, &ctx ); /* safe to reuse ser, because data was copied into de */
  fd_tower_1_14_11_t * tower_1_14_11 = (fd_tower_1_14_11_t *)fd_type_pun( ser );

  fd_vote_state_1_14_11_t * vote_state = &tower_1_14_11->vote_state;
  fd_vote_lockout_t * votes = vote_state->votes;
  for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( votes       );
                                          !deq_fd_vote_lockout_t_iter_done( votes, iter );
                                    iter = deq_fd_vote_lockout_t_iter_next( votes, iter ) ) {
    fd_vote_lockout_t const * vote_lockout = deq_fd_vote_lockout_t_iter_ele_const( votes, iter );
    fd_tower_votes_push_tail( tower, (fd_tower_vote_t){ .slot = vote_lockout->slot, .conf = vote_lockout->confirmation_count } );
  }
  fd_ulong_store_if( vote_state->has_root_slot, root, vote_state->root_slot );

  return 0;
}

fd_tower_sync_t *
fd_tower_to_tower_sync( fd_tower_t const * tower, ulong root, fd_hash_t * bank_hash, fd_hash_t * block_id, fd_tower_sync_t * tower_sync ) {
  tower_sync->lockouts      = tower_sync->lockouts;
  tower_sync->lockouts_cnt  = (ushort)fd_tower_votes_cnt( tower );
  tower_sync->root          = root;
  tower_sync->has_root      = 1;
  tower_sync->hash          = *bank_hash;
  tower_sync->timestamp     = fd_log_wallclock() / (long)1e9; /* seconds */
  tower_sync->has_timestamp = 1;
  tower_sync->block_id      = *block_id;

  ulong i = 0;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower       );
                                   !fd_tower_votes_iter_done( tower, iter );
                             iter = fd_tower_votes_iter_next( tower, iter ) ) {
    fd_tower_vote_t const * vote               = fd_tower_votes_iter_ele_const( tower, iter );
    tower_sync->lockouts[i].slot               = vote->slot;
    tower_sync->lockouts[i].confirmation_count = (uint)vote->conf;
    i++;
  }
  return tower_sync;
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
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower       );
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
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower       );
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

  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower       );
                                   !fd_tower_votes_iter_done_rev( tower, iter );
                             iter = fd_tower_votes_iter_prev    ( tower, iter ) ) {

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

  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower       );
                                   !fd_tower_votes_iter_done_rev( tower, iter );
                             iter = fd_tower_votes_iter_prev    ( tower, iter ) ) {

    fd_tower_vote_t const * vote = fd_tower_votes_iter_ele_const( tower, iter );
    printf( "%*lu | %lu\n", digit_cnt, vote->slot, vote->conf );
    max_slot = fd_ulong_max( max_slot, fd_tower_votes_iter_ele_const( tower, iter )->slot );
  }
  printf( "%*lu | root\n", digit_cnt, root );
  printf( "\n" );
}

void
fd_tower_from_vote_acc_data( uchar const * data,
                             fd_tower_t *  tower_out ) {
# if FD_TOWER_USE_HANDHOLDING
  FD_TEST( fd_tower_votes_empty( tower_out ) );
# endif

  fd_voter_state_t const * state = (fd_voter_state_t const *)fd_type_pun_const( data );

  /* Push all the votes onto the tower. */
  for( ulong i = 0; i < fd_voter_state_cnt( state ); i++ ) {
    fd_tower_vote_t vote = { 0 };
    if( FD_UNLIKELY( state->kind == fd_vote_state_versioned_enum_v0_23_5 ) ) {
      vote.slot = state->v0_23_5.votes[i].slot;
      vote.conf = state->v0_23_5.votes[i].conf;
    } else if( FD_UNLIKELY( state->kind == fd_vote_state_versioned_enum_v1_14_11 ) ) {
      vote.slot = state->v1_14_11.votes[i].slot;
      vote.conf = state->v1_14_11.votes[i].conf;
    } else if ( FD_UNLIKELY( state->kind == fd_vote_state_versioned_enum_current ) ) {
      vote.slot = state->votes[i].slot;
      vote.conf = state->votes[i].conf;
    } else {
      FD_LOG_CRIT(( "[%s] unknown vote state version. discriminant %u", __func__, state->kind ));
    }
    fd_tower_votes_push_tail( tower_out, vote );
  }
}
