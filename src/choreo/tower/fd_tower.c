#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "fd_tower.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#define THRESHOLD_DEPTH         (8)
#define THRESHOLD_RATIO         (2.0 / 3.0)
#define SHALLOW_THRESHOLD_DEPTH (4)
#define SHALLOW_THRESHOLD_RATIO (0.38)
#define SWITCH_PCT              (0.38)
#define SERDE_KIND              (1)
#define SERDE_LAST_VOTE_KIND    (3)

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
# if FD_TOWER_PARANOID
  FD_TEST( !fd_tower_votes_empty( tower ) ); /* caller error */
# endif

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

  int lockout_check = (slot > vote->slot) && (vote->slot < root->slot || fd_ghost_is_ancestor( ghost, fd_ghost_hash( ghost, vote->slot ), block_id ));
# if LOGGING
  FD_LOG_NOTICE(( "[%s] %d. top: (slot: %lu, conf: %lu). switch: %lu.", __func__, lockout_check, vote->slot, vote->conf, slot ));
# endif
  return lockout_check;
}

int
fd_tower_switch_check( fd_tower_t const * tower,
                       fd_epoch_t const * epoch,
                       fd_ghost_t const * ghost,
                       ulong              slot,
                       fd_hash_t const *  block_id ) {
  #if FD_TOWER_PARANOID
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

# if FD_TOWER_PARANOID
  FD_TEST( !fd_ghost_is_ancestor( ghost, fd_ghost_hash( ghost, vote->slot ), block_id ) );
# endif
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
# if LOGGING
  FD_LOG_NOTICE(( "[%s] ok? %d. top: %lu. threshold: %lu. stake: %.0lf%%.", __func__, threshold_pct > THRESHOLD_RATIO, fd_tower_votes_peek_tail_const( tower )->slot, threshold_slot, threshold_pct * 100.0 ));
# endif
  return threshold_pct > THRESHOLD_RATIO;
}

ulong
fd_tower_reset_slot( fd_tower_t const * tower,
                     fd_epoch_t const * epoch,
                     fd_ghost_t const * ghost ) {

  fd_tower_vote_t const * last = fd_tower_votes_peek_tail_const( tower );
  fd_ghost_ele_t const *  vote = last ? fd_ghost_query_const( ghost, fd_ghost_hash( ghost, last->slot ) ) : NULL;
  fd_ghost_ele_t const *  root = fd_ghost_root_const( ghost );
  fd_ghost_ele_t const *  head = fd_ghost_head( ghost, root );

# if FD_TOWER_PARANOID
  if( FD_UNLIKELY( !vote ) ) FD_LOG_CRIT(( "[%s] missing vote %lu", __func__, last->slot  ));
  if( FD_UNLIKELY( !root ) ) FD_LOG_CRIT(( "[%s] missing root",     __func__              ));
  if( FD_UNLIKELY( !head ) ) FD_LOG_CRIT(( "[%s] missing head",     __func__              ));
# endif

  /* Case 0: reset to the ghost head (ie. heaviest leaf slot of any
     fork) if any of the following is true:

     a. haven't voted
     b. last vote slot < ghost root slot
     c. ghost root is not an ancestor of last vote

     TODO can c. happen in non-exceptional conditions? error out? */

  if( FD_UNLIKELY( !vote || vote->slot < root->slot || !fd_ghost_is_ancestor( ghost, &root->key, &vote->key ) ) )
    return head->slot;

  /* Case 1: last vote on same fork as heaviest leaf (ie. last vote slot
     is an ancestor of heaviest leaf ). This is the common case. */

  else if( FD_LIKELY( fd_ghost_is_ancestor( ghost, &vote->key, &head->key ) ) )
    return head->slot;

  /* Case 2: last vote is on different fork from heaviest leaf (ie. last
     vote slot is _not_ an ancestor of heaviest leaf), but we have a
     valid switch proof for the heaviest leaf. */

  else if( FD_LIKELY( fd_tower_switch_check( tower, epoch, ghost, head->slot, &head->key ) ) )
    return head->slot;

  /* Case 3: same as case 2 except we don't have a valid switch proof,
     but we detect last vote is now on an "invalid" fork (ie. any
     ancestor of our last vote slot equivocates AND has not reached 52%
     of stake). If we do find such an ancestor, we reset to the heaviest
     leaf anyways, despite it being on a different fork and not having a
     valid switch proof. */

  else if( FD_LIKELY( fd_ghost_invalid( ghost, vote ) ) )
    return head->slot;

  /* Case 4: same as case 3 except last vote's fork is not invalid. In
     this case we reset to the heaviest leaf starting from the subtree
     rooted at our last vote slot, instead of the overall heaviest leaf.
     This is done to ensure votes propagate (see top-level documentation
     in fd_tower.h for details) */

  else
    return fd_ghost_head( ghost, vote )->slot;
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

  #if FD_TOWER_PARANOID
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
    if( FD_UNLIKELY( vote->conf != ++prev_conf ) ) break;
    vote->conf++;
  }

  /* Add the new vote to the tower. */

  fd_tower_votes_push_tail( tower, (fd_tower_vote_t){ .slot = slot, .conf = 1 } );

  /* Return the new root (FD_SLOT_NULL if there is none). */

  return root;
}

ulong
fd_tower_simulate_vote( fd_tower_t const * tower, ulong slot ) {
# if FD_TOWER_PARANOID
  FD_TEST( !fd_tower_votes_empty( tower ) ); /* caller error */
# endif

  return simulate_vote( tower, slot );
}

static const uchar option_some = 1; /* this is a hack to lift the lifetime of a uchar outside fd_tower_sync_serde */

fd_tower_sync_serde_t *
fd_tower_to_tower_sync( fd_tower_t const * tower, ulong root, fd_hash_t * bank_hash, fd_hash_t * block_id, long ts, fd_tower_sync_serde_t * ser ) {
  ser->root         = &root;
  ser->lockouts_cnt = (ushort)fd_tower_votes_cnt( tower );
  ushort i          = 0;
  ulong  prev       = root;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower );
                                   !fd_tower_votes_iter_done( tower, iter );
                             iter = fd_tower_votes_iter_next( tower, iter ) ) {
    fd_tower_vote_t const * vote        = fd_tower_votes_iter_ele_const( tower, iter );
    ser->lockouts[i].offset             = vote->slot - prev;
    ser->lockouts[i].confirmation_count = (uchar const *)fd_type_pun_const( &vote->conf );
    i++;
  }
  ser->hash              = bank_hash;
  ser->timestamp_option  = &option_some;
  ser->timestamp         = &ts;
  ser->block_id          = block_id;
  return ser;
}

int
fd_tower_checkpt( fd_tower_t const *      tower,
                  ulong                   root,
                  fd_tower_sync_serde_t * last_vote,
                  uchar const             pubkey[static 32],
                  fd_tower_sign_fn *      sign_fn,
                  int                     fd,
                  uchar *                 buf,
                  ulong                   buf_max ) {

  /* TODO check no invalid ptrs */

  fd_tower_serde_t ser = { 0 };

  uint   kind            = SERDE_KIND;
  ulong  threshold_depth = THRESHOLD_DEPTH;
  double threshold_size  = THRESHOLD_RATIO;

  ser.kind            = &kind;
  ser.threshold_depth = &threshold_depth;
  ser.threshold_size  = &threshold_size;

  fd_voter_v2_serde_t * voter_v2_ser = &ser.vote_state;

  /* Agave defaults all fields except the actual tower votes and root
     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus/tower_vote_state.rs#L118-L128 */

  fd_pubkey_t pubkey_null            = { 0 };
  voter_v2_ser->node_pubkey           = &pubkey_null;
  voter_v2_ser->authorized_withdrawer = &pubkey_null;
  uchar commission                   = 0;
  voter_v2_ser->commission            = &commission;

  ulong votes_cnt        = fd_tower_votes_cnt( tower );
  voter_v2_ser->votes_cnt = &votes_cnt;

  ulong i = 0;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower       );
                                   !fd_tower_votes_iter_done( tower, iter );
                             iter = fd_tower_votes_iter_next( tower, iter ) ) {
    fd_tower_vote_t const * vote              = fd_tower_votes_iter_ele_const( tower, iter );
    voter_v2_ser->votes[i].slot               = &vote->slot;
    voter_v2_ser->votes[i].confirmation_count = (uint const *)fd_type_pun_const( &vote->conf );
    i++;
  }

  uchar root_slot_option        = root == ULONG_MAX;
  voter_v2_ser->root_slot_option = &root_slot_option;
  voter_v2_ser->root_slot        = root_slot_option ? NULL : &root;

  ulong authorized_voters_cnt        = 0;
  voter_v2_ser->authorized_voters_cnt = &authorized_voters_cnt;

  ulong start_epoch = 0;
  ulong end_epoch   = 0;
  for( ulong i = 0; i < 32; i++ ) {
    voter_v2_ser->prior_voters.buf[i].pubkey      = &pubkey_null;
    voter_v2_ser->prior_voters.buf[i].start_epoch = &start_epoch;
    voter_v2_ser->prior_voters.buf[i].end_epoch   = &end_epoch;
  }
  ulong idx                           = 31;
  voter_v2_ser->prior_voters.idx      = &idx;
  uchar is_empty                      = 0;
  voter_v2_ser->prior_voters.is_empty = &is_empty;

  ulong epoch_credits_cnt         = 0;
  voter_v2_ser->epoch_credits_cnt = &epoch_credits_cnt;

  ulong slot                             = 0;
  long  timestamp                        = 0;
  voter_v2_ser->last_timestamp.slot      = &slot;
  voter_v2_ser->last_timestamp.timestamp = &timestamp;

  /* Copy the last vote (reused from the actual ) into the Tower */

  uint last_vote_kind = SERDE_LAST_VOTE_KIND;
  ser.last_vote_kind  = &last_vote_kind;
  ser.last_vote       = *last_vote;

  ulong last_timestamp_slot      = fd_tower_votes_peek_tail_const( tower )->slot;
  long  last_timestamp_timestamp = fd_log_wallclock() / (long)1e9;
  ser.last_timestamp.slot        = &last_timestamp_slot;
  ser.last_timestamp.timestamp   = &last_timestamp_timestamp;

  int err;

  ulong buf_sz; err = fd_tower_serialize( &ser, buf, buf_max, &buf_sz );
  if( FD_UNLIKELY( err ) ) { FD_LOG_WARNING(( "fd_tower_serialize failed" )); return -1; }

  ulong   off    = sizeof(uint) /* kind */ + FD_ED25519_SIG_SZ /* signature */ + sizeof(ulong) /* data_sz */;
  uchar * sig    = buf + sizeof(uint);
  uchar * msg    = buf + off;
  ulong   msg_sz = buf_sz - off;

  sign_fn( pubkey, sig, msg, msg_sz );

  ser.signature = (fd_ed25519_sig_t const *)fd_type_pun_const( &buf );
  ser.data_sz   = &msg_sz;

  ulong wsz; err = fd_io_write( fd, buf, buf_sz, buf_sz, &wsz );
  if( FD_UNLIKELY( err ) ) { FD_LOG_WARNING(( "fd_io_write failed: %s", strerror( err ) )); return -1; }

  fsync( fd );

  return 0;
}

int
fd_tower_restore( fd_tower_t * tower,
                  ulong *      root,
                  long *       ts,
                  uchar const  pubkey[static 32],
                  int          fd,
                  uchar *      buf,
                  ulong        buf_max,
                  ulong *      buf_sz ) {
  int err = fd_io_sz( fd, buf_sz );
  if( FD_UNLIKELY( err             ) ) { FD_LOG_WARNING(( "%s: %s", __func__, fd_io_strerror( err )                  )); return -1; }
  if( FD_UNLIKELY( buf_max<*buf_sz ) ) { FD_LOG_WARNING(( "%s: buf_max %lu < buf_sz %lu", __func__, buf_max, *buf_sz )); return -1; }

  ulong rsz; err = fd_io_read( fd, buf, *buf_sz, *buf_sz, &rsz );
  if( FD_UNLIKELY( err<0        ) ) { FD_LOG_WARNING(( "%s: unexpected EOF", __func__                             )); return -1; }
  if( FD_UNLIKELY( *buf_sz!=rsz ) ) { FD_LOG_WARNING(( "%s: read %lu bytes, expected %lu", __func__, rsz, *buf_sz )); return -1; }
  if( FD_UNLIKELY( err>0        ) ) { FD_LOG_WARNING(( "%s: %s", __func__, fd_io_strerror( err )                  )); return -1; }

  fd_tower_serde_t de = { 0 };
  fd_tower_deserialize( buf, *buf_sz, &de );

  uchar *       msg    = (uchar *)de.node_pubkey; /* signed data region begins at this field */
  ulong         msg_sz = *de.data_sz;
  uchar const * sig    = *de.signature;
  fd_sha512_t sha[1];
  err = fd_ed25519_verify( msg, msg_sz, sig, pubkey, sha );
  if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS                      ) ) { FD_LOG_WARNING(( "serialized tower failed sigverify: %s", fd_ed25519_strerror( err )             )); return -1; }
  if( FD_UNLIKELY( 0!=memcmp( de.node_pubkey->uc, pubkey, 32 ) ) ) { FD_LOG_WARNING(( "node_pubkey does not match pubkey"                                             )); return -1; }
  if( FD_UNLIKELY( *de.kind!=SERDE_KIND                        ) ) { FD_LOG_WARNING(( "serialized tower generated by too old agave version (required >= 2.3.7)"       )); return -1; }
  if( FD_UNLIKELY( *de.threshold_depth!=THRESHOLD_DEPTH        ) ) { FD_LOG_WARNING(( "threshold_depth does not match THRESHOLD_DEPTH"                                )); return -1; }
  if( FD_UNLIKELY( *de.threshold_size !=THRESHOLD_RATIO        ) ) { FD_LOG_WARNING(( "threshold_size does not match THRESHOLD_RATIO"                                 )); return -1; }
  if( FD_UNLIKELY( *de.vote_state.votes_cnt > 31               ) ) { FD_LOG_WARNING(( "invalid votes_cnt %lu > 31", *de.vote_state.votes_cnt                         )); return -1; }
  if( FD_UNLIKELY( *de.vote_state.authorized_voters_cnt > 31   ) ) { FD_LOG_WARNING(( "invalid authorized_voters_cnt %lu > 31", *de.vote_state.authorized_voters_cnt )); return -1; }
  if( FD_UNLIKELY(  de.last_vote.lockouts_cnt > 31             ) ) { FD_LOG_WARNING(( "invalid lockouts_cnt %u > 31", de.last_vote.lockouts_cnt                      )); return -1; }

  for( ulong i = 0; i < *de.vote_state.votes_cnt; i++ ) {
    fd_tower_votes_push_tail( tower, (fd_tower_vote_t){ .slot = *de.vote_state.votes[i].slot, .conf = *de.vote_state.votes[i].confirmation_count } );
  }
  *root = *de.vote_state.root_slot_option ? *de.vote_state.root_slot : ULONG_MAX;
  *ts   = *de.last_timestamp.timestamp;

  return 0;
}

static ulong
ser_short_vec_cnt( uchar * dst, ushort src ) {
  if     ( FD_LIKELY( src < 0x80UL   ) ) { *dst   = (uchar)  src;                                                                                          return 1; }
  else if( FD_LIKELY( src < 0x4000UL ) ) { *dst++ = (uchar)((src&0x7FUL)|0x80UL); *dst++ = (uchar)(  src>>7);                                              return 2; }
  else                                   { *dst++ = (uchar)((src&0x7FUL)|0x80UL); *dst++ = (uchar)(((src>>7)&0x7FUL)|0x80UL); *dst++ = (uchar)(src>>14UL); return 3; }
}

static ulong
ser_varint( uchar * dst, ulong src ) {
  ulong off = 0;
  while( FD_LIKELY( 1 ) ) {
    if( FD_LIKELY( src < 0x80UL ) ) {
      *(dst) = (uchar)src;
      off   += 1;
      return off;
    }
    *(dst+off) = (uchar)((src&0x7FUL)|0x80UL);
    off       += 1;
    src      >>= 7;
  }
}

int
fd_tower_serialize( fd_tower_serde_t * ser,
                    uchar *            buf,
                    ulong              buf_max,
                    ulong *            buf_sz ) {

  if( FD_UNLIKELY( *ser->threshold_depth!=THRESHOLD_DEPTH      ) ) { FD_LOG_WARNING(( "threshold_depth does not match THRESHOLD_DEPTH"                                 )); return -1; }
  if( FD_UNLIKELY( *ser->threshold_size !=THRESHOLD_RATIO      ) ) { FD_LOG_WARNING(( "threshold_size does not match THRESHOLD_RATIO"                                  )); return -1; }
  if( FD_UNLIKELY( *ser->vote_state.votes_cnt > 31             ) ) { FD_LOG_WARNING(( "invalid votes_cnt %lu > 31", *ser->vote_state.votes_cnt                         )); return -1; }
  if( FD_UNLIKELY( *ser->vote_state.authorized_voters_cnt > 31 ) ) { FD_LOG_WARNING(( "invalid authorized_voters_cnt %lu > 31", *ser->vote_state.authorized_voters_cnt )); return -1; }
  if( FD_UNLIKELY(  ser->last_vote.lockouts_cnt > 31           ) ) { FD_LOG_WARNING(( "invalid lockouts_cnt %u > 31", ser->last_vote.lockouts_cnt                      )); return -1; }

  #define SER( T, name ) do {                                                                 \
      if( FD_UNLIKELY( off+sizeof(T)>buf_max ) ) {                                            \
        FD_LOG_WARNING(( "ser %s: overflow (off %lu > buf_max: %lu)", #name, off, buf_max )); \
        return -1;                                                                            \
      }                                                                                       \
      if( FD_LIKELY( ser->name ) ) {                                                          \
        FD_STORE( T, buf+off, *ser->name );                                                   \
        ser->name = (T const *)fd_type_pun_const( buf+off );                                  \
      }                                                                                       \
      off += sizeof(T);                                                                       \
  } while(0)

  #define OFF( T, name ) do {                                                                 \
      if( FD_UNLIKELY( off+sizeof(T)>buf_max ) ) {                                            \
        FD_LOG_WARNING(( "ser %s: overflow (off %lu > buf_max: %lu)", #name, off, buf_max )); \
        return -1;                                                                            \
      }                                                                                       \
      ser->name = (T const *)fd_type_pun_const( buf+off );                                    \
      off += sizeof(T);                                                                       \
  } while(0)

  ulong off = 0;

  /* SavedTower::Current */

  SER( uint,             kind                                       );
  OFF( fd_ed25519_sig_t, signature                                  );
  OFF( ulong,            data_sz                                    );
  SER( fd_pubkey_t,      node_pubkey                                );
  SER( ulong,            threshold_depth                            );
  SER( double,           threshold_size                             );

  /* VoteState1_14_11 */

  SER( fd_pubkey_t,      vote_state.node_pubkey                     );
  SER( fd_pubkey_t,      vote_state.authorized_withdrawer           );
  SER( uchar,            vote_state.commission                      );
  SER( ulong,            vote_state.votes_cnt                       );
  for( ulong i=0; i < fd_ulong_min( *ser->vote_state.votes_cnt, 31 ); i++ ) {
    SER( ulong,          vote_state.votes[i].slot                   );
    SER( uint,           vote_state.votes[i].confirmation_count     );
  }
  SER( uchar,            vote_state.root_slot_option                );
  if( FD_LIKELY( *ser->vote_state.root_slot_option ) ) {
    SER( ulong,          vote_state.root_slot                       );
  }
  SER( ulong,            vote_state.authorized_voters_cnt           );
  for( ulong i = 0; i < fd_ulong_min( *ser->vote_state.authorized_voters_cnt, 32 ); i++ ) {
    SER( ulong,          vote_state.authorized_voters[i].epoch      );
    SER( fd_pubkey_t,    vote_state.authorized_voters[i].pubkey     );
  }
  for( ulong i = 0; i < 32; i++ ) {
    SER( fd_pubkey_t,    vote_state.prior_voters.buf[i].pubkey      );
    SER( ulong,          vote_state.prior_voters.buf[i].start_epoch );
    SER( ulong,          vote_state.prior_voters.buf[i].end_epoch   );
  }
  SER( ulong,            vote_state.prior_voters.idx                );
  SER( uchar,            vote_state.prior_voters.is_empty           );
  SER( ulong,            vote_state.epoch_credits_cnt               );
  for( ulong i = 0; i < fd_ulong_min( *ser->vote_state.epoch_credits_cnt, 32 ); i++ ) {
    SER( ulong,          vote_state.epoch_credits[i].epoch          );
    SER( ulong,          vote_state.epoch_credits[i].credits        );
    SER( ulong,          vote_state.epoch_credits[i].prev_credits   );
  }
  SER( ulong,            vote_state.last_timestamp.slot             );
  SER( long,             vote_state.last_timestamp.timestamp        );

  /* VoteTransaction::TowerSync */

  SER( uint,             last_vote_kind                             );
  SER( ulong,            last_vote.root                             );
  off += ser_short_vec_cnt( buf+off, ser->last_vote.lockouts_cnt );
  for( ulong i = 0; i < fd_ulong_min( ser->last_vote.lockouts_cnt, 31 ); i++ ) {
    off += ser_varint( buf+off, ser->last_vote.lockouts[i].offset );
    SER( uchar,          last_vote.lockouts[i].confirmation_count   );
  }
  SER( fd_hash_t,        last_vote.hash                             );
  SER( uchar,            last_vote.timestamp_option                 );
  if( FD_LIKELY( *ser->last_vote.timestamp_option ) ) {
    SER( long,           last_vote.timestamp                        );
  }
  SER( fd_hash_t,        last_vote.block_id                         );

  /* BlockTimestamp */

  SER( ulong,            last_timestamp.slot                        );
  SER( long,             last_timestamp.timestamp                   );

  #undef SER
  #undef OFF

  *buf_sz = off;

  return 0;
}

static ulong
de_short_vec_cnt( ushort * dst, uchar * src ) {
  if     ( FD_LIKELY( !(0x80U & src[0]) ) ) { *dst = (ushort)src[0];                                                                           return 1; }
  else if( FD_LIKELY( !(0x80U & src[1]) ) ) { *dst = (ushort)((ulong)(src[0]&0x7FUL) + (((ulong)src[1])<<7));                                  return 2; }
  else                                      { *dst = (ushort)((ulong)(src[0]&0x7FUL) + (((ulong)(src[1]&0x7FUL))<<7) + (((ulong)src[2])<<14)); return 3; }
}

static ulong
de_varint( ulong * dst, uchar * src ) {
  *dst = 0;
  ulong off = 0;
  ulong bit = 0;
  while( FD_LIKELY( bit < 64 ) ) {
    uchar byte = *(uchar const *)(src+off);
    off       += 1;
    *dst      |= (byte & 0x7FUL) << bit;
    if( FD_LIKELY( (byte & 0x80U) == 0U ) ) {
      if( FD_UNLIKELY( (*dst>>bit) != byte                ) ) FD_LOG_CRIT(( "de_varint" ));
      if( FD_UNLIKELY( byte==0U && (bit!=0U || *dst!=0UL) ) ) FD_LOG_CRIT(( "de_varint" ));
      return off;
    }
    bit += 7;
  }
  FD_LOG_CRIT(( "de_varint" ));
}

int
fd_tower_deserialize( uchar *            buf,
                      ulong              buf_sz,
                      fd_tower_serde_t * de ) {

  #define DE( T, name ) do {                                                               \
      if( FD_UNLIKELY( off+sizeof(T)>buf_sz ) ) {                                          \
        FD_LOG_WARNING(( "de %s: overflow (off %lu > buf_sz: %lu)", #name, off, buf_sz )); \
        return -1;                                                                         \
      }                                                                                    \
      de->name = (T const *)fd_type_pun_const( buf+off );                                  \
      off += sizeof(T);                                                                    \
  } while(0)

  ulong off = 0;

  /* SavedTower::Current */

  DE( uint,             kind                                       );
  DE( fd_ed25519_sig_t, signature                                  );
  DE( ulong,            data_sz                                    );
  DE( fd_pubkey_t,      node_pubkey                                );
  DE( ulong,            threshold_depth                            );
  DE( double,           threshold_size                             );

  /* VoteState1_14_11 */

  DE( fd_pubkey_t,      vote_state.node_pubkey                     );
  DE( fd_pubkey_t,      vote_state.authorized_withdrawer           );
  DE( uchar,            vote_state.commission                      );
  DE( ulong,            vote_state.votes_cnt                       );
  for( ulong i=0; i < fd_ulong_min( *de->vote_state.votes_cnt, 31 ); i++ ) {
    DE( ulong,          vote_state.votes[i].slot                   );
    DE( uint,           vote_state.votes[i].confirmation_count     );
  }
  DE( uchar,            vote_state.root_slot_option                );
  if( FD_LIKELY( *de->vote_state.root_slot_option ) ) {
    DE( ulong,          vote_state.root_slot                       );
  }
  DE( ulong,            vote_state.authorized_voters_cnt           );
  for( ulong i = 0; i < fd_ulong_min( *de->vote_state.authorized_voters_cnt, 32 ); i++ ) {
    DE( ulong,          vote_state.authorized_voters[i].epoch      );
    DE( fd_pubkey_t,    vote_state.authorized_voters[i].pubkey     );
  }
  for( ulong i = 0; i < 32; i++ ) {
    DE( fd_pubkey_t,    vote_state.prior_voters.buf[i].pubkey      );
    DE( ulong,          vote_state.prior_voters.buf[i].start_epoch );
    DE( ulong,          vote_state.prior_voters.buf[i].end_epoch   );
  }
  DE( ulong,            vote_state.prior_voters.idx                );
  DE( uchar,            vote_state.prior_voters.is_empty           );
  DE( ulong,            vote_state.epoch_credits_cnt               );
  for( ulong i = 0; i < fd_ulong_min( *de->vote_state.epoch_credits_cnt, 32 ); i++ ) {
    DE( ulong,          vote_state.epoch_credits[i].epoch          );
    DE( ulong,          vote_state.epoch_credits[i].credits        );
    DE( ulong,          vote_state.epoch_credits[i].prev_credits   );
  }
  DE( ulong,            vote_state.last_timestamp.slot             );
  DE( long,             vote_state.last_timestamp.timestamp        );

  /* VoteTransaction::TowerSync */

  DE( uint,             last_vote_kind                             );
  DE( ulong,            last_vote.root                             );
  off += de_short_vec_cnt( &de->last_vote.lockouts_cnt, buf+off );
  for( ulong i = 0; i < fd_ulong_min( de->last_vote.lockouts_cnt, 31 ); i++ ) {
    off += de_varint( &de->last_vote.lockouts[i].offset, buf+off );
    DE( uchar,          last_vote.lockouts[i].confirmation_count   );
  }
  DE( fd_hash_t,        last_vote.hash                             );
  DE( uchar,            last_vote.timestamp_option                 );
  if( FD_LIKELY( *de->last_vote.timestamp_option ) ) {
    DE( long,           last_vote.timestamp                        );
  }
  DE( fd_hash_t,        last_vote.block_id                         );

  /* BlockTimestamp */

  DE( ulong,            last_timestamp.slot                        );
  DE( long,             last_timestamp.timestamp                   );

  #undef DE

  return 0;
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
  tower_sync.root          = fd_ulong_if( root == ULONG_MAX, 0UL, root );
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
# if FD_TOWER_PARANOID
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
