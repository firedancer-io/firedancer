#include "fd_vote_program.h"
#include "../fd_runtime.h"
#include "../fd_borrowed_account.h"
#include "../fd_executor.h"
#include "../fd_pubkey_utils.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../sysvar/fd_sysvar.h"
#include "../fd_system_ids.h"
#include "vote/fd_authorized_voters.h"
#include "vote/fd_vote_utils.h"
#include "vote/fd_vote_codec_tmpl.h"
#include "vote/fd_vote_codec.h"
#include "vote/fd_vote_state_versioned.h"
#include "vote/fd_vote_state_v4.h"
#include "../../../ballet/bls/fd_bls12_381.h"

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

// https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/state/mod.rs#L37
#define INITIAL_LOCKOUT 2UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L51
#define VOTE_CREDITS_MAXIMUM_PER_SLOT_OLD 8

// https://github.com/anza-xyz/solana-sdk/blob/clock%40v4.0.0/clock/src/lib.rs#L171
#define SLOT_DEFAULT 0UL

// https://github.com/anza-xyz/solana-sdk/blob/clock%40v4.0.0/clock/src/lib.rs#L171
#define SLOT_MAX ULONG_MAX

#define ACCOUNTS_MAX 4 /* Vote instructions take in at most 4 accounts */

#define DEFAULT_COMPUTE_UNITS 2100UL
#define COMPUTE_UNITS_POP    34500UL

/**********************************************************************/
/* VoteStateHandler                                                   */
/**********************************************************************/

/* Check the vote state, deserialize it as V4 and convert older versions
   to V4 in-place.

   If the vote account is a V5 account, it is deserialized as a V5
   account. Non-V5 accounts are not automatically upgraded, because V5
   accounts require the location to be set.

   https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L34-L53 */
static int
get_vote_state_handler_checked( fd_borrowed_account_t const * vote_account,
                                int                           target_version,
                                uchar                         check_initialized,
                                fd_vote_state_versioned_t *   vote_state_versioned ) {
  (void)target_version;
  (void)check_initialized; /* V4 vote states are always initialized */

  int rc = fd_vsv_deserialize( vote_account->acc, vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  if( FD_UNLIKELY( fd_vsv_is_uninitialized( vote_state_versioned ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  }

  if( vote_state_versioned->kind!=fd_vote_state_versioned_enum_v5 ) {
    rc = fd_vsv_try_convert_to_v4( vote_state_versioned, (fd_pubkey_t*)vote_account->acc->pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/handler.rs#L432-L445 */
static int
check_vote_account_length( fd_borrowed_account_t const * vote_account,
                           int                           target_version ) {
  (void)target_version;
  ulong length = fd_borrowed_account_get_data_len( vote_account );
  if( FD_UNLIKELY( length!=FD_VOTE_STATE_V4_SZ ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/handler.rs#L381-L395 */
static int
init_vote_account_state( fd_exec_instr_ctx_t *         ctx,
                         fd_borrowed_account_t *       vote_account,
                         fd_vote_state_versioned_t *   versioned,
                         int                           target_version,
                         fd_vote_init_t *              vote_init,
                         fd_sol_sysvar_clock_t const * clock ) {
  (void)target_version;
  fd_vote_state_v4_create_new_with_defaults( (fd_pubkey_t*)vote_account->acc->pubkey, vote_init, clock, versioned );
  return fd_vote_state_v4_set_vote_account_state( ctx, vote_account, versioned );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/handler.rs#L397-L417 */
static int
init_vote_account_state_v2( fd_exec_instr_ctx_t *         ctx,
                            fd_borrowed_account_t *       vote_account,
                            fd_vote_state_versioned_t *   versioned,
                            int                           target_version,
                            fd_vote_init_v2_t *           vote_init_v2,
                            fd_sol_sysvar_clock_t const * clock ) {
  (void)target_version;
  fd_vote_state_v4_create_new( vote_init_v2, clock, versioned );
  return fd_vote_state_v4_set_vote_account_state( ctx, vote_account, versioned );
}

/**********************************************************************/
/* mod vote_state                                                    */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L58-L298 */
static int
check_and_filter_proposed_vote_state( fd_exec_instr_ctx_t *       ctx,
                                      fd_vote_state_versioned_t * versioned,
                                      fd_vote_lockout_t *         proposed_lockouts,
                                      uchar *                     proposed_has_root,
                                      ulong *                     proposed_root,
                                      fd_hash_t const *           proposed_hash,
                                      fd_slot_hashes_t const *    slot_hashes ) {
  fd_landed_vote_t const * votes         = fd_vsv_get_votes( versioned );
  ulong const *            root_slot     = fd_vsv_get_root_slot( versioned );
  uchar                    has_root_slot = !!(root_slot!=NULL);

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L65
  if( FD_UNLIKELY( deq_fd_vote_lockout_t_empty( proposed_lockouts ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  fd_landed_vote_t const * last_vote = NULL;
  if( !deq_fd_landed_vote_t_empty( votes ) ) {
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L69
    last_vote = deq_fd_landed_vote_t_peek_tail_const( votes );
  }
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L75
  if( FD_LIKELY( last_vote ) ) {
    if( FD_UNLIKELY( deq_fd_vote_lockout_t_peek_tail_const( proposed_lockouts )->slot <=
                     last_vote->lockout.slot ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_VOTE_TOO_OLD;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  /* must be nonempty, checked above */
  ulong last_vote_state_update_slot = deq_fd_vote_lockout_t_peek_tail_const( proposed_lockouts )->slot;

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L81
  if( FD_UNLIKELY( !slot_hashes->cnt ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L84
  ulong earliest_slot_hash_in_history = slot_hashes->elems[ slot_hashes->cnt-1UL ].slot;

  /* Check if the proposed vote is too old to be in the SlotHash history */
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L87
  if( FD_UNLIKELY( last_vote_state_update_slot < earliest_slot_hash_in_history ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check if the proposed root is too old */
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L94
  if( *proposed_has_root ) {
    ulong const proposed_root_ = *proposed_root;
    /* If the new proposed root `R` is less than the earliest slot hash in the history
       such that we cannot verify whether the slot was actually was on this fork, set
       the root to the latest vote in the current vote that's less than R. */
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L99
    if( proposed_root_ < earliest_slot_hash_in_history ) {
      *proposed_has_root = has_root_slot;
      if( has_root_slot ) {
        *proposed_root   = *root_slot;
      }
      for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init_rev( votes );
                                             !deq_fd_landed_vote_t_iter_done_rev( votes, iter );
                                       iter = deq_fd_landed_vote_t_iter_prev( votes, iter ) ) {
        /* Ensure we're iterating from biggest to smallest vote in the
           current vote state */
        fd_landed_vote_t const * vote = deq_fd_landed_vote_t_iter_ele_const( votes, iter );
        // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L105
        if( vote->lockout.slot <= proposed_root_ ) {
          *proposed_has_root = 1;
          *proposed_root     = vote->lockout.slot;
          break;
        }
      }
    }
  }

  /* Index into the new proposed vote state's slots, starting with the root if it exists then
     we use this mutable root to fold checking the root slot into the below loop for performance */
  int   has_root_to_check       = *proposed_has_root;
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L116
  ulong root_to_check           = *proposed_root;
  ulong proposed_lockouts_index = 0UL;
  ulong lockouts_len = deq_fd_vote_lockout_t_cnt( proposed_lockouts );

  /* Index into the slot_hashes, starting at the oldest known slot hash */
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L121
  ulong slot_hashes_index = slot_hashes->cnt;

  /* proposed_lockouts_indexes_to_filter's size is bounded by the length
     of the proposed lockouts provided in the instruction data. */
  ulong proposed_lockouts_indexes_to_filter[ FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN ];
  ulong filter_index = 0UL;

  /* Note:

    1) `vote_state_update.lockouts` is sorted from oldest/smallest vote to newest/largest
    vote, due to the way votes are applied to the vote state (newest votes
    pushed to the back).

    2) Conversely, `slot_hashes` is sorted from newest/largest vote to
    the oldest/smallest vote.

    Unlike for vote updates, vote state updates here can't only check votes older than the last vote
    because have to ensure that every slot is actually part of the history, not just the most
    recent ones */

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L136
  while( proposed_lockouts_index < lockouts_len && slot_hashes_index > 0 ) {
    ulong proposed_vote_slot =
      fd_ulong_if( has_root_to_check,
        // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L138
        root_to_check,
        // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L140
        deq_fd_vote_lockout_t_peek_index_const( proposed_lockouts,
          proposed_lockouts_index )
        ->slot );
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L142
    if( !has_root_to_check && proposed_lockouts_index > 0UL &&
      proposed_vote_slot <=
      deq_fd_vote_lockout_t_peek_index_const(
        proposed_lockouts,
          fd_ulong_checked_sub_expect(
            proposed_lockouts_index,
              1,
              "`proposed_lockouts_index` is positive when checking `SlotsNotOrdered`" ) )
      ->slot ) {
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L150
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_NOT_ORDERED;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L152
    ulong ancestor_slot =
      slot_hashes->elems[
          fd_ulong_checked_sub_expect(
            slot_hashes_index,
              1UL,
              "`slot_hashes_index` is positive when computing `ancestor_slot`" ) ]
      .slot;
    /* Find if this slot in the proposed vote state exists in the SlotHashes history
       to confirm if it was a valid ancestor on this fork */
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L160
    if( proposed_vote_slot < ancestor_slot ) {
      if( slot_hashes_index == slot_hashes->cnt ) {
        /* The vote slot does not exist in the SlotHashes history because it's too old,
           i.e. older than the oldest slot in the history. */
        if( proposed_vote_slot >= earliest_slot_hash_in_history ) {
          ctx->txn_out->err.custom_err = 0;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }
        // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L167
        if( !fd_vote_contains_slot( votes, proposed_vote_slot ) && !has_root_to_check ) {
          /* If the vote slot is both:
             1) Too old
             2) Doesn't already exist in vote state
             Then filter it out */
          proposed_lockouts_indexes_to_filter[filter_index++] = proposed_lockouts_index;        }
        // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L175
        if( has_root_to_check ) {
          ulong new_proposed_root = root_to_check;
          /* 1. Because `root_to_check.is_some()`, then we know that
             we haven't checked the root yet in this loop, so
             `proposed_vote_slot` == `new_proposed_root` == `vote_state_update.root` */
          FD_TEST( new_proposed_root == proposed_vote_slot );
          /* 2. We know from the assert earlier in the function that
             `proposed_vote_slot < earliest_slot_hash_in_history`,
             so from 1. we know that `new_proposed_root < earliest_slot_hash_in_history` */
          if( new_proposed_root >= earliest_slot_hash_in_history ) {
            ctx->txn_out->err.custom_err = 0;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          }

          // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L186
          has_root_to_check = 0;
          root_to_check     = ULONG_MAX;
        } else {
          // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L188
          proposed_lockouts_index = fd_ulong_checked_add_expect(
            proposed_lockouts_index,
              1,
              "`proposed_lockouts_index` is bounded by `MAX_LOCKOUT_HISTORY` when "
              "`proposed_vote_slot` is too old to be in SlotHashes history" );
        }
        continue;
      } else {
        /* If the vote slot is new enough to be in the slot history,
           but is not part of the slot history, then it must belong to another fork,
           which means this vote state update is invalid. */
        // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L198
        if( has_root_to_check ) {
          ctx->txn_out->err.custom_err = FD_VOTE_ERR_ROOT_ON_DIFFERENT_FORK;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        } else {
          ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }
      }
    } else if( proposed_vote_slot > ancestor_slot ) {
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L205

      /* Decrement `slot_hashes_index` to find newer slots in the SlotHashes history */
      slot_hashes_index = fd_ulong_checked_sub_expect(
        slot_hashes_index,
          1,
          "`slot_hashes_index` is positive when finding newer slots in SlotHashes history" );
      continue;
    } else {
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L213

      /* Once the slot in `vote_state_update.lockouts` is found, bump to the next slot
         in `vote_state_update.lockouts` and continue. If we were checking the root,
         start checking the vote state instead. */
      if( has_root_to_check ) {
        has_root_to_check = 0;
        root_to_check     = ULONG_MAX;
      } else {
        proposed_lockouts_index = fd_ulong_checked_add_expect(
          proposed_lockouts_index,
            1,
            "`proposed_lockouts_index` is bounded by `MAX_LOCKOUT_HISTORY` "
            "when match is found in SlotHashes history" );
        slot_hashes_index = fd_ulong_checked_sub_expect(
          slot_hashes_index,
            1,
            "`slot_hashes_index` is positive when match is found in SlotHashes history" );
      }
    }
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L232
  if( proposed_lockouts_index != deq_fd_vote_lockout_t_cnt( proposed_lockouts ) ) {
    /* The last vote slot in the update did not exist in SlotHashes */
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L261
  if( memcmp( &slot_hashes->elems[ slot_hashes_index ].hash,
      proposed_hash,
      sizeof( fd_hash_t ) ) != 0 ) {
    /* This means the newest vote in the slot has a match that
       doesn't match the expected hash for that slot on this fork */
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L277
  /* Filter out the irrelevant votes */
  proposed_lockouts_index = 0UL;
  ulong filter_votes_index = deq_fd_vote_lockout_t_cnt( proposed_lockouts );

  /* We need to iterate backwards here because proposed_lockouts_indexes_to_filter[ i ] is a
     strictly increasing value. Forward iterating can lead to the proposed lockout indices to get
     shifted leading to popping the wrong proposed lockouts or out of bounds accessing. We need
     to be sure of handling underflow in this case. */

  for( ulong i=filter_index; i>0UL && filter_votes_index>0UL; i-- ) {
    proposed_lockouts_index = i - 1UL;
    if( FD_UNLIKELY( proposed_lockouts_indexes_to_filter[ proposed_lockouts_index ]>=filter_votes_index ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
    }

    deq_fd_vote_lockout_t_pop_idx_tail( proposed_lockouts, proposed_lockouts_indexes_to_filter[ proposed_lockouts_index ] );
    filter_votes_index--;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L300
static int
check_slots_are_valid( fd_exec_instr_ctx_t *       ctx,
                       fd_vote_state_versioned_t * versioned,
                       ulong const *               vote_slots,
                       fd_hash_t const *           vote_hash,
                       fd_slot_hashes_t const *    slot_hashes ) {
  ulong i              = 0;
  ulong j              = slot_hashes->cnt;
  ulong vote_slots_len = deq_ulong_cnt( vote_slots );

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L322
  while( i < vote_slots_len && j > 0 ) {
    ulong const * last_voted_slot_ = fd_vsv_get_last_voted_slot( versioned );
    if( FD_UNLIKELY( last_voted_slot_ &&
                     *deq_ulong_peek_index_const( vote_slots, i ) <= *last_voted_slot_ ) ) {
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L329
      i = fd_ulong_checked_add_expect(
          i, 1, "`i` is bounded by `MAX_LOCKOUT_HISTORY` when finding larger slots" );
      continue;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L336
    if( FD_UNLIKELY(
            *deq_ulong_peek_index_const( vote_slots, i ) !=
            slot_hashes->elems[
              fd_ulong_checked_sub_expect( j, 1, "`j` is positive" ) ]
                .slot ) ) {
      j = fd_ulong_checked_sub_expect( j, 1, "`j` is positive when finding newer slots" );
      continue;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L346
    i = fd_ulong_checked_add_expect(
        i, 1, "`i` is bounded by `MAX_LOCKOUT_HISTORY` when hash is found" );
    j = fd_ulong_checked_sub_expect( j, 1, "`j` is positive when hash is found" );
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L354
  if( FD_UNLIKELY( j == slot_hashes->cnt ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if( FD_UNLIKELY( i != vote_slots_len ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L378
  if( FD_UNLIKELY( 0 != memcmp( &slot_hashes->elems[ j ].hash,
                                vote_hash,
                                32UL ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L431
static int
process_new_vote_state( fd_exec_instr_ctx_t *       ctx,
                        fd_vote_state_versioned_t * versioned,
                        fd_landed_vote_t *          new_state,
                        int                         has_new_root,
                        ulong                       new_root,
                        int                         has_timestamp,
                        long                        timestamp,
                        ulong                       epoch,
                        ulong                       current_slot ) {
  int rc;
  fd_landed_vote_t * votes         = fd_vsv_get_votes_mutable( versioned );
  ulong const *      root_slot     = fd_vsv_get_root_slot( versioned );
  uchar              has_root_slot = !!(root_slot!=NULL);

  FD_TEST( !deq_fd_landed_vote_t_empty( new_state ) );
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L440
  if( FD_UNLIKELY( deq_fd_landed_vote_t_cnt( new_state ) > MAX_LOCKOUT_HISTORY ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_TOO_MANY_VOTES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  };

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L444
  if( FD_UNLIKELY( has_new_root && has_root_slot ) ) {
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L445
    if( FD_UNLIKELY( new_root<*root_slot ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_ROOT_ROLL_BACK;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else if( FD_UNLIKELY( !has_new_root && has_root_slot ) ) {
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L449
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_ROOT_ROLL_BACK;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  } else {
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L451
    /* no-op */
  }

  fd_landed_vote_t * previous_vote = NULL;
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
       !deq_fd_landed_vote_t_iter_done( new_state, iter );
       iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    if( FD_LIKELY( vote->lockout.confirmation_count == 0 ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_ZERO_CONFIRMATIONS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else if( FD_UNLIKELY( vote->lockout.confirmation_count > MAX_LOCKOUT_HISTORY ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_CONFIRMATION_TOO_LARGE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else if( FD_LIKELY( has_new_root ) ) {
      if( FD_UNLIKELY( vote->lockout.slot <= new_root && new_root != SLOT_DEFAULT ) ) {
        ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOT_SMALLER_THAN_ROOT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }

    if( FD_LIKELY( previous_vote ) ) {
      if( FD_UNLIKELY( previous_vote->lockout.slot >= vote->lockout.slot ) ) {
        ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      } else if( FD_UNLIKELY( previous_vote->lockout.confirmation_count <=
                              vote->lockout.confirmation_count ) ) {
        ctx->txn_out->err.custom_err = FD_VOTE_ERR_CONFIRMATIONS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      } else if( FD_UNLIKELY( vote->lockout.slot >
                              fd_vote_lockout_last_locked_out_slot( &previous_vote->lockout ) ) ) {
        ctx->txn_out->err.custom_err = FD_VOTE_ERR_NEW_VOTE_STATE_LOCKOUT_MISMATCH;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }
    previous_vote = vote;
  }

  ulong current_vote_state_index = 0;
  ulong new_vote_state_index     = 0;

  /* Accumulate credits earned by newly rooted slots.  The behavior changes with
     timely_vote_credits: prior to this feature, there was a bug that counted a new root slot as 1
     credit even if it had never been voted on. timely_vote_credits fixes this bug by only awarding
     credits for slots actually voted on and finalized. */

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L635

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L495
  ulong earned_credits      = 0;

  if( FD_LIKELY( has_new_root ) ) {
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( votes );
                                           !deq_fd_landed_vote_t_iter_done( votes, iter );
                                     iter = deq_fd_landed_vote_t_iter_next( votes, iter ) ) {
      fd_landed_vote_t const * current_vote = deq_fd_landed_vote_t_iter_ele_const( votes, iter );
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L501
      if( FD_UNLIKELY( current_vote->lockout.slot <= new_root ) ) {
        // this is safe because we're inside if has_new_root
        earned_credits = fd_ulong_checked_add_expect(
            fd_vote_credits_for_vote_at_index(
                votes,
                current_vote_state_index
            ),
            earned_credits,
            "`earned_credits` does not overflow" );
        current_vote_state_index = fd_ulong_checked_add_expect(
            current_vote_state_index,
            1,
            "`current_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
            "when processing new root" );
        continue;
      }
      break;
    }
  }

  // For any slots newly added to the new vote state, the vote latency of that slot is not provided by the
  // vote instruction contents, but instead is computed from the actual latency of the vote
  // instruction. This prevents other validators from manipulating their own vote latencies within their vote states
  // and forcing the rest of the cluster to accept these possibly fraudulent latency values.  If the
  // timly_vote_credits feature is not enabled then vote latency is set to 0 for new votes.
  //
  // For any slot that is in both the new state and the current state, the vote latency of the new state is taken
  // from the current state.
  //
  // Thus vote latencies are set here for any newly vote-on slots when a vote instruction is received.
  // They are copied into the new vote state after every vote for already voted-on slots.
  // And when voted-on slots are rooted, the vote latencies stored in the vote state of all the rooted slots is used
  // to compute credits earned.
  // All validators compute the same vote latencies because all process the same vote instruction at the
  // same slot, and the only time vote latencies are ever computed is at the time that their slot is first voted on;
  // after that, the latencies are retained unaltered until the slot is rooted.

  // All the votes in our current vote state that are missing from the new vote state
  // must have been expired by later votes. Check that the lockouts match this assumption.

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L535
  while( current_vote_state_index < deq_fd_landed_vote_t_cnt( votes ) &&
         new_vote_state_index < deq_fd_landed_vote_t_cnt( new_state ) ) {
    fd_landed_vote_t const * current_vote = deq_fd_landed_vote_t_peek_index_const( votes, current_vote_state_index );

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L539
    fd_landed_vote_t * new_vote =
        deq_fd_landed_vote_t_peek_index( new_state, new_vote_state_index );

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L545
    if( FD_LIKELY( current_vote->lockout.slot < new_vote->lockout.slot ) ) {
      /* The agave implementation of calculating the last locked out
         slot does not calculate a min between the current vote's
         confirmation count and max lockout history. The reason we do
         this is to make sure that the fuzzers continue working:
         the max lockout history can not be > MAX_LOCKOUT_HISTORY. */
      ulong confirmation_count   = fd_ulong_min( current_vote->lockout.confirmation_count, MAX_LOCKOUT_HISTORY );
      ulong last_locked_out_slot = fd_ulong_sat_add( current_vote->lockout.slot,
                                                     (ulong)pow( INITIAL_LOCKOUT, (double)confirmation_count ) );
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L546
      if( last_locked_out_slot >= new_vote->lockout.slot ) {
        // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L547
        ctx->txn_out->err.custom_err = FD_VOTE_ERR_LOCKOUT_CONFLICT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L549
      current_vote_state_index =
          fd_ulong_checked_add_expect( current_vote_state_index,
                                       1,
                                       "`current_vote_state_index` is bounded by "
                                       "`MAX_LOCKOUT_HISTORY` when slot is less than proposed" );
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L554
    } else if( FD_UNLIKELY( current_vote->lockout.slot == new_vote->lockout.slot ) ) {
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L557
      if( new_vote->lockout.confirmation_count < current_vote->lockout.confirmation_count ) {
        ctx->txn_out->err.custom_err = FD_VOTE_ERR_CONFIRMATION_ROLL_BACK;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L562
      new_vote->latency = deq_fd_landed_vote_t_peek_index_const( votes, current_vote_state_index )->latency;

      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L564
      current_vote_state_index =
          fd_ulong_checked_add_expect( current_vote_state_index,
                                       1,
                                       "`current_vote_state_index` is bounded by "
                                       "`MAX_LOCKOUT_HISTORY` when slot is equal to proposed" );
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L568
      new_vote_state_index =
          fd_ulong_checked_add_expect( new_vote_state_index,
                                       1,
                                       "`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
                                       "when slot is equal to proposed" );
    } else {
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L574
      new_vote_state_index =
          fd_ulong_checked_add_expect( new_vote_state_index,
                                       1,
                                       "`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
                                       "when slot is greater than proposed" );
    }
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L587
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
        !deq_fd_landed_vote_t_iter_done( new_state, iter );
        iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * new_vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L588
    if( FD_UNLIKELY( new_vote->latency == 0 ) ) {
      // this is unlikely because as validators upgrade, it should converge to the new vote state
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L589
      new_vote->latency = fd_vote_compute_vote_latency( new_vote->lockout.slot, current_slot );
    }
  }

  // doesn't matter what the value of slot if `is_some = 0` i.e. `Option::None`
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L593
  int both_none = !has_root_slot && !has_new_root;
  if( ( !both_none && ( has_root_slot!=has_new_root ||
                        *root_slot!=new_root ) ) ) {
    fd_vsv_increment_credits( versioned, epoch, earned_credits );
  }
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L599
  if( FD_LIKELY( has_timestamp ) ) {
    /* new_state asserted nonempty at function beginning */
    if( FD_UNLIKELY( deq_fd_landed_vote_t_empty( new_state ) ) ) {
      FD_LOG_CRIT(( "invariant violation: landed votes is empty" ));
    }
    ulong last_slot = deq_fd_landed_vote_t_peek_tail( new_state )->lockout.slot;
    rc              = fd_vsv_process_timestamp( ctx, versioned, last_slot, timestamp );
    if( FD_UNLIKELY( rc ) ) { return rc; }
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L603
  fd_vsv_set_root_slot( versioned, has_new_root ? &new_root : NULL );

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L604
  deq_fd_landed_vote_t_remove_all( votes );
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
       !deq_fd_landed_vote_t_iter_done( new_state, iter );
       iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    deq_fd_landed_vote_t_push_tail_wrap( votes, *landed_vote );
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

__attribute__((weak)) int
fd_bls12_381_proof_of_possession_verify( uchar const msg[],
                                         ulong       msg_sz,
                                         uchar const proof[ static FD_BLS_PROOF_OF_POSSESSION_COMPRESSED_SZ ],
                                         uchar const public_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] ) {
  (void)msg; (void)msg_sz; (void)proof; (void)public_key;
  FD_LOG_ERR(( "This build does not include BLST, which is required to run a validator.\n"
               "Rebuild with a MACHINE config that enables config/extra/with-blst.mk" ));
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1015-L1058 */
#define FD_VOTE_BLS_MSG_SZ ( 9 + 32 + 48 )
static int
fd_vote_verify_bls_proof_of_possession( fd_exec_instr_ctx_t * ctx,
                                        uchar const           vote_account_pubkey[ static 32 ],
                                        uchar const           bls_pubkey[ static FD_BLS_PUBKEY_COMPRESSED_SZ ],
                                        uchar const           bls_proof[ static FD_BLS_PROOF_OF_POSSESSION_COMPRESSED_SZ ] ) {
  /* Consume CUs for proof of possession */
  FD_EXEC_CU_UPDATE( ctx, COMPUTE_UNITS_POP );

  /* Build message */
  uchar msg[ FD_VOTE_BLS_MSG_SZ ];
  memcpy( msg, "ALPENGLOW", 9 );
  memcpy( msg+9, vote_account_pubkey, 32 );
  memcpy( msg+9+32, bls_pubkey, 48 );

  /* Verify */
  if( FD_UNLIKELY( fd_bls12_381_proof_of_possession_verify(
    msg,
    FD_VOTE_BLS_MSG_SZ,
    bls_proof,
    bls_pubkey
  )!=FD_BLS_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }
  return 0;
}
#undef FD_VOTE_BLS_MSG_SZ

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L692-L773 */
static int
authorize( fd_exec_instr_ctx_t *         ctx,
           fd_borrowed_account_t *       vote_account,
           int                           target_version,
           fd_pubkey_t const *           authorized,
           fd_vote_authorize_t const *   vote_authorize,
           fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
           ulong                         signers_cnt,
           fd_sol_sysvar_clock_t const * clock,
           int                           is_vote_authorize_with_bls_enabled ) {
  fd_vote_state_versioned_t * vote_state_versioned = &ctx->runtime->vote_program.authorize.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L705 */
  int rc = get_vote_state_handler_checked( vote_account, target_version, 0, vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L707-L770 */
  switch( vote_authorize->discriminant ) {

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L708-L732 */
    case fd_vote_authorize_enum_voter: {

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L709-L711 */
      if( FD_UNLIKELY( is_vote_authorize_with_bls_enabled && fd_vsv_has_bls_pubkey( vote_state_versioned ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L712-L713 */
      int authorized_withdrawer_signer = !fd_vote_verify_authorized_signer(
          fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
          signers,
          signers_cnt
      );

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L718-L721 */
      ulong target_epoch;
      rc = fd_ulong_checked_add( clock->leader_schedule_epoch, 1UL, &target_epoch );
      if( FD_UNLIKELY( rc!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L715 */
      rc = fd_vsv_set_new_authorized_voter(
          ctx,
          vote_state_versioned,
          authorized,
          clock->epoch,
          target_epoch,
          NULL, /* no BLS pubkey */
          authorized_withdrawer_signer,
          signers,
          signers_cnt
      );
      if( FD_UNLIKELY( rc ) ) return rc;
      break;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L733-L737 */
    case fd_vote_authorize_enum_withdrawer: {
      rc = fd_vote_verify_authorized_signer(
          fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
          signers,
          signers_cnt
      );
      if( FD_UNLIKELY( rc ) ) return rc;
      fd_vsv_set_authorized_withdrawer( vote_state_versioned, authorized );
      break;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L738 */
    case fd_vote_authorize_enum_voter_with_bls: {
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L739-L741 */
      if( FD_UNLIKELY( !is_vote_authorize_with_bls_enabled ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L742-L743 */
      int authorized_withdrawer_signer = !fd_vote_verify_authorized_signer(
          fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
          signers,
          signers_cnt
      );

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L745-L750 */
      rc = fd_vote_verify_bls_proof_of_possession(
        ctx,
        vote_account->acc->pubkey,
        vote_authorize->voter_with_bls.bls_pubkey,
        vote_authorize->voter_with_bls.bls_proof_of_possession
      );
      if( FD_UNLIKELY( rc ) ) {
        return rc;
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L755-L758 */
      ulong target_epoch;
      rc = fd_ulong_checked_add( clock->leader_schedule_epoch, 1UL, &target_epoch );
      if( FD_UNLIKELY( rc!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L752 */
      rc = fd_vsv_set_new_authorized_voter(
          ctx,
          vote_state_versioned,
          authorized,
          clock->epoch,
          target_epoch,
          vote_authorize->voter_with_bls.bls_pubkey,
          authorized_withdrawer_signer,
          signers,
          signers_cnt
      );
      if( FD_UNLIKELY( rc ) ) return rc;

      break;
    }

    default:
      FD_LOG_CRIT(( "unsupported vote_authorize discriminant: %u", vote_authorize->discriminant ));
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L772 */
  return fd_vsv_set_vote_account_state( ctx, vote_account, vote_state_versioned );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L776-L800 */
static int
update_validator_identity( fd_exec_instr_ctx_t *   ctx,
                           int                     target_version,
                           fd_borrowed_account_t * vote_account,
                           fd_pubkey_t const *     node_pubkey,
                           fd_pubkey_t const *     signers[static FD_INSTR_SIGNERS_MAX],
                           ulong                   signers_cnt,
                           int                     custom_commission_collector_enabled ) {
  fd_vote_state_versioned_t * vote_state_versioned = &ctx->runtime->vote_program.update_validator_identity.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L783 */
  int rc = get_vote_state_handler_checked( vote_account, target_version, 0, vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L786 */
  rc = fd_vote_verify_authorized_signer(
      fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
      signers,
      signers_cnt
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L789 */
  rc = fd_vote_verify_authorized_signer( node_pubkey, signers, signers_cnt );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L791 */
  fd_vsv_set_node_pubkey( vote_state_versioned, node_pubkey );

  /* Before SIMD-0232, block_revenue_collector is always synced with node_pubkey.
     After SIMD-0232, the collector can be set independently.
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L793-L797 */
  if( !custom_commission_collector_enabled ) {
    fd_vsv_set_block_revenue_collector( vote_state_versioned, node_pubkey );
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L799 */
  return fd_vsv_set_vote_account_state( ctx, vote_account, vote_state_versioned );
}

// https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L990
static int
is_commission_update_allowed( ulong slot, fd_epoch_schedule_t const * epoch_schedule ) {
  if( FD_LIKELY( epoch_schedule->slots_per_epoch > 0UL ) ) {
    ulong relative_slot = fd_ulong_sat_sub( slot, epoch_schedule->first_normal_slot );
    relative_slot %= epoch_schedule->slots_per_epoch;
    return fd_ulong_sat_mul( relative_slot, 2 ) <= epoch_schedule->slots_per_epoch;
  } else {
    return 1;
  }
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L803-L818 */
static int
update_commission( fd_exec_instr_ctx_t *         ctx,
                   int                           target_version,
                   fd_borrowed_account_t *       vote_account,
                   uchar                         commission,
                   fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
                   ulong                         signers_cnt,
                   fd_epoch_schedule_t const *   epoch_schedule,
                   fd_sol_sysvar_clock_t const * clock,
                   int                           disable_commission_update_rule ) {
  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L809 */
  int rc         = 0;
  int get_vsv_rc = get_vote_state_handler_checked(
      vote_account,
      target_version,
      false,
      &ctx->runtime->vote_program.update_commission.vote_state
  );

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-alpha.0/programs/vote/src/vote_state/mod.rs#L851-L855 */
  fd_vote_state_versioned_t * vote_state_versioned           = NULL;
  int                         enforce_commission_update_rule = !disable_commission_update_rule;
  if( FD_LIKELY( get_vsv_rc==FD_EXECUTOR_INSTR_SUCCESS ) ) {
    vote_state_versioned           = &ctx->runtime->vote_program.update_commission.vote_state;
    enforce_commission_update_rule = (!disable_commission_update_rule) && (commission>fd_vsv_get_commission( vote_state_versioned ));
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L806-L808 */
  if( FD_UNLIKELY( enforce_commission_update_rule && !is_commission_update_allowed( clock->slot, epoch_schedule ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_COMMISSION_UPDATE_TOO_LATE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L810 */
  if( FD_UNLIKELY( get_vsv_rc ) ) return get_vsv_rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L813 */
  rc = fd_vote_verify_authorized_signer(
      fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
      signers,
      signers_cnt
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L815 */
  fd_vsv_set_commission( vote_state_versioned, commission, clock->epoch );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L817 */
  return fd_vsv_set_vote_account_state( ctx, vote_account, vote_state_versioned );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L820-L852 */
static int
update_commission_bps( fd_exec_instr_ctx_t *                    ctx,
                       fd_borrowed_account_t *                  vote_account,
                       int                                      target_version,
                       fd_update_commission_bps_args_t const *  args,
                       fd_pubkey_t const *                      signers[static FD_INSTR_SIGNERS_MAX],
                       ulong                                    signers_cnt,
                       int                                      block_revenue_sharing ) {
  fd_vote_state_versioned_t * vote_state_versioned = &ctx->runtime->vote_program.update_commission_bps.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L831-L833 */
  if( FD_UNLIKELY( args->kind.discriminant==fd_commission_kind_enum_block_revenue && !block_revenue_sharing ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L835 */
  int rc = get_vote_state_handler_checked( vote_account, target_version, false, vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L840 */
  rc = fd_vote_verify_authorized_signer(
    fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
    signers,
    signers_cnt
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  ulong current_epoch = 0UL;
  if( vote_state_versioned->kind==fd_vote_state_versioned_enum_v5 ) {
    fd_sol_sysvar_clock_t         clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    current_epoch = clock->epoch;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L842-L849 */
  switch( args->kind.discriminant ) {
    case fd_commission_kind_enum_inflation_rewards: {
      fd_vsv_set_inflation_rewards_commission_bps( vote_state_versioned, args->commission_bps, current_epoch );
      break;
    }
    case fd_commission_kind_enum_block_revenue: {
      fd_vsv_set_block_revenue_commission_bps( vote_state_versioned, args->commission_bps, current_epoch );
      break;
    }
    default: {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
  }

  return fd_vsv_set_vote_account_state( ctx, vote_account, vote_state_versioned );
}

/* Updates the vote account's commission collector (SIMD-0232).
   collector_account==NULL means the collector is the vote account
   itself, which is exempt from the collector constraints.
   https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L897-L931 */
static int
update_commission_collector( fd_exec_instr_ctx_t *         ctx,
                             fd_borrowed_account_t *       vote_account,
                             int                           target_version,
                             fd_borrowed_account_t const * collector_account,
                             fd_commission_kind_t const *  kind,
                             fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
                             ulong                         signers_cnt,
                             fd_rent_t const *             rent ) {
  fd_vote_state_versioned_t * vote_state_versioned = &ctx->runtime->vote_program.update_commission_collector.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L909 */
  int rc = get_vote_state_handler_checked( vote_account, target_version, 0, vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L911-L912 */
  rc = fd_vote_verify_authorized_signer(
      fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
      signers,
      signers_cnt
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* An external collector must be system program owned, rent-exempt,
     and not reserved (checked via the writable flag).
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L854-L895 */
  fd_pubkey_t const * new_collector_key;
  if( !collector_account ) {
    new_collector_key = (fd_pubkey_t const *)vote_account->acc->pubkey;
  } else {
    if( FD_UNLIKELY( !fd_pubkey_eq( fd_borrowed_account_get_owner( collector_account ), &fd_solana_system_program_id ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }

    if( FD_UNLIKELY( fd_borrowed_account_get_lamports( collector_account ) <
                     fd_rent_exempt_minimum_balance( rent, fd_borrowed_account_get_data_len( collector_account ) ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    if( FD_UNLIKELY( !fd_borrowed_account_is_writable( collector_account ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    new_collector_key = (fd_pubkey_t const *)collector_account->acc->pubkey;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L921-L928 */
  switch( kind->discriminant ) {
    case fd_commission_kind_enum_inflation_rewards: {
      fd_vsv_set_inflation_rewards_collector( vote_state_versioned, new_collector_key );
      break;
    }
    case fd_commission_kind_enum_block_revenue: {
      fd_vsv_set_block_revenue_collector( vote_state_versioned, new_collector_key );
      break;
    }
    default: {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L930 */
  return fd_vsv_set_vote_account_state( ctx, vote_account, vote_state_versioned );
}

/* SIMD-0674 UpdateLocation: sets the location of a V5 vote account,
   converting a V4 account to V5. */

/*  */
static int
update_location( fd_exec_instr_ctx_t *           ctx,
                 fd_borrowed_account_t *         vote_account,
                 int                             target_version,
                 fd_validator_location_t const * location,
                 fd_pubkey_t const *             signers[static FD_INSTR_SIGNERS_MAX],
                 ulong                           signers_cnt,
                 fd_sol_sysvar_clock_t const *   clock ) {
  fd_vote_state_versioned_t * versioned = &ctx->runtime->vote_program.update_location.vote_state;

  int rc = get_vote_state_handler_checked( vote_account, target_version, 0, versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* The current epoch's authorized voter must sign */
  fd_pubkey_t * authorized_voter = NULL;
  rc = fd_authorized_voters_get_and_update_authorized_voter( versioned, clock->epoch, &authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  rc = fd_vote_verify_authorized_signer( authorized_voter, signers, signers_cnt );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* The validator location must be within the allowed bounds */
  if( FD_UNLIKELY( !fd_validator_location_is_valid( location ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  /* Convert the vote state account to a V5 vote account if it isn't already */
  if( versioned->kind!=fd_vote_state_versioned_enum_v5 ) {
    if( FD_UNLIKELY( fd_borrowed_account_get_data_len( vote_account )!=FD_VOTE_STATE_V4_SZ ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    rc = fd_vsv_try_convert_to_v5( versioned, clock->epoch );
    if( FD_UNLIKELY( rc ) ) return rc;
    rc = fd_borrowed_account_set_data_length( vote_account, FD_VOTE_STATE_V5_SZ );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  /* Now, we can set the location */
  versioned->v5.location = *location;

  return fd_vsv_set_vote_account_state( ctx, vote_account, versioned );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1061-L1127 */
static int
withdraw( fd_exec_instr_ctx_t *         ctx,
          fd_borrowed_account_t *       vote_account,
          int                           target_version,
          ulong                         lamports,
          ushort                        to_account_index,
          fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
          ulong                         signers_cnt,
          fd_rent_t const *             rent_sysvar,
          fd_sol_sysvar_clock_t const * clock,
          int *                         deinitialized ) {
  fd_vote_state_versioned_t * versioned = &ctx->runtime->vote_program.withdraw.vote_state;
  *deinitialized = 0;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1073 */
  int rc = get_vote_state_handler_checked( vote_account, target_version, 0, versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1075 */
  rc = fd_vote_verify_authorized_signer(
      fd_vsv_get_authorized_withdrawer( versioned ),
      signers,
      signers_cnt
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* Always zero until SIMD-0123 is activated.
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1083 */
  ulong pending_delegator_rewards = fd_vsv_get_pending_delegator_rewards( versioned );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1077-L1080 */
  ulong vote_account_lamports = fd_borrowed_account_get_lamports( vote_account );
  if( FD_UNLIKELY( lamports>vote_account_lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }
  ulong remaining_balance = vote_account_lamports-lamports;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1085-L1120 */
  if( FD_UNLIKELY( remaining_balance==0UL ) ) {
    /* SIMD-0123: vote account cannot be closed if pending_delegator_rewards > 0.
       https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1086-L1090 */
    if( FD_UNLIKELY( pending_delegator_rewards > 0 ) ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1092-L1102 */
    fd_vote_epoch_credits_t const * last_epoch_credits = fd_vsv_get_last_epoch_credits( versioned );
    ulong                           last_epoch_with_credits;
    int                             reject_active_vote_account_close = 0;
    if( FD_LIKELY( last_epoch_credits ) ) {
      ulong current_epoch              = clock->epoch;
      last_epoch_with_credits          = last_epoch_credits->epoch;
      reject_active_vote_account_close = fd_ulong_sat_sub( current_epoch, last_epoch_with_credits )<2UL;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1104-L1109 */
    if( FD_UNLIKELY( reject_active_vote_account_close ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_ACTIVE_VOTE_ACCOUNT_CLOSE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else {
      rc = fd_vsv_deinitialize_vote_account_state(
          ctx,
          vote_account,
          target_version
      );
      if( FD_UNLIKELY( rc ) ) return rc;
      *deinitialized = 1;
    }
  } else {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1113-L1119 */
    ulong min_rent_exempt_balance = fd_rent_exempt_minimum_balance( rent_sysvar, fd_borrowed_account_get_data_len( vote_account ) );

    /* SIMD-0123: withdrawable balance when pending_delegator_rewards > 0
       is lamports - pending_delegator_rewards - rent_exempt_minimum.
       https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1111-L1116 */
    ulong min_balance;
    if( FD_UNLIKELY( fd_ulong_checked_add( min_rent_exempt_balance, pending_delegator_rewards, &min_balance ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
    }

    if( FD_UNLIKELY( remaining_balance<min_balance ) ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1122 */
  rc = fd_borrowed_account_checked_sub_lamports( vote_account, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1123 */
  fd_borrowed_account_drop( vote_account );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1124 */
  fd_guarded_borrowed_account_t to = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, to_account_index, &to );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1125 */
  rc = fd_borrowed_account_checked_add_lamports( &to, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L609-L622 */
static int
process_vote_unfiltered( fd_exec_instr_ctx_t *       ctx,
                         fd_vote_state_versioned_t * versioned,
                         ulong *                     vote_slots,
                         fd_legacy_vote_t const *    vote,
                         fd_slot_hashes_t const *    slot_hashes,
                         ulong                       epoch,
                         ulong                       current_slot ) {
  int rc;
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L617
  rc = check_slots_are_valid( ctx, versioned, vote_slots, &vote->hash, slot_hashes );
  if( FD_UNLIKELY( rc ) ) return rc;
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote_slots );
       !deq_ulong_iter_done( vote_slots, iter );
       iter = deq_ulong_iter_next( vote_slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote_slots, iter );
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L620
    fd_vsv_process_next_vote_slot( versioned, *ele, epoch, current_slot );
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L624
static int
process_vote( fd_exec_instr_ctx_t *       ctx,
              fd_vote_state_versioned_t * versioned,
              fd_legacy_vote_t const *    vote,
              fd_slot_hashes_t const *    slot_hashes,
              ulong                       epoch,
              ulong                       current_slot ) {
  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L631
  if( FD_UNLIKELY( deq_ulong_empty( vote->slots ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L634
  ulong earliest_slot_in_history = 0;
  if( FD_UNLIKELY( !!slot_hashes->cnt ) ) {
    earliest_slot_in_history = slot_hashes->elems[ slot_hashes->cnt-1UL ].slot;
  }

  /* We know that the size of the vote_slots is bounded by the number of
     slots that can fit inside of an instruction.  Because the
     instructions are deserialized with
     limited_deserialize(data, PACKET_DATA_SIZE), we can use
     FD_TXN_MTU_V0 as a bound on the size of the instruction. If this
     instruction is filled only with a vote slot deque, we get
     (1232/8) == 154 slots.
     The footprint of a deque is as follows:
     fd_ulong_align_up( fd_ulong_align_up( 32UL, alignof(DEQUE_T) ) + sizeof(DEQUE_T)*max, alignof(DEQUE_(private_t)) );
     So, the footprint in our case is:
     fd_ulong_align_up( fd_ulong_align_up( 32UL, alignof(ulong) ) + sizeof(ulong)*154, alignof(DEQUE_(private_t)) );
     Which is equal to
     fd_ulong_align_up( 32UL + 154 * 8UL, 8UL ) = 1264UL; */
  #define VOTE_SLOTS_MAX             (FD_TXN_MTU_V0/sizeof(ulong))
  #define VOTE_SLOTS_DEQUE_FOOTPRINT (1264UL )
  #define VOTE_SLOTS_DEQUE_ALIGN     (8UL)
  FD_TEST( deq_ulong_footprint( VOTE_SLOTS_MAX ) == VOTE_SLOTS_DEQUE_FOOTPRINT );
  FD_TEST( deq_ulong_align()                     == 8UL );
  FD_TEST( deq_ulong_cnt( vote->slots )          <= VOTE_SLOTS_MAX );
  uchar * vote_slots_mem[ VOTE_SLOTS_DEQUE_FOOTPRINT ] __attribute__((aligned(VOTE_SLOTS_DEQUE_ALIGN)));

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L635
  ulong * vote_slots = deq_ulong_join( deq_ulong_new( vote_slots_mem, deq_ulong_cnt( vote->slots ) ) );
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
       !deq_ulong_iter_done( vote->slots, iter );
       iter = deq_ulong_iter_next( vote->slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
    if( FD_UNLIKELY( *ele >= earliest_slot_in_history ) ) {
      vote_slots = deq_ulong_push_tail_wrap( vote_slots, *ele );
    }
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L641
  if( FD_UNLIKELY( deq_ulong_cnt( vote_slots ) == 0 ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_VOTES_TOO_OLD_ALL_FILTERED;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L644
  return process_vote_unfiltered(
      ctx,
      versioned,
      vote_slots,
      vote,
      slot_hashes,
      epoch,
      current_slot
  );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1198-L1219 */
static int
initialize_account( fd_exec_instr_ctx_t *         ctx,
                    fd_borrowed_account_t *       vote_account,
                    int                           target_version,
                    fd_vote_init_t *              vote_init,
                    fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
                    ulong                         signers_cnt,
                    fd_sol_sysvar_clock_t const * clock ) {
  int rc;
  fd_vote_state_versioned_t * versioned = &ctx->runtime->vote_program.init_account.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1208 */
  rc = check_vote_account_length( vote_account, target_version );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1209 */
  rc = fd_vsv_get_state( vote_account->acc, versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1211-L1213 */
  if( FD_UNLIKELY( !fd_vsv_is_uninitialized( versioned ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1216 */
  rc = fd_vote_verify_authorized_signer( &vote_init->node_pubkey, signers, signers_cnt );
  if( FD_UNLIKELY( rc ) ) {
    return rc;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1218 */
  return init_vote_account_state( ctx, vote_account, versioned, target_version, vote_init, clock );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1129-L1196
   Note: this is very similar to initialize_account() but also does verify_bls_proof_of_possession() */
static int
initialize_account_v2( fd_exec_instr_ctx_t *         ctx,
                       fd_borrowed_account_t *       vote_account,
                       int                           target_version,
                       fd_vote_init_v2_t *           vote_init_v2,
                       fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
                       ulong                         signers_cnt,
                       fd_sol_sysvar_clock_t const * clock ) {
  int rc;
  fd_vote_state_versioned_t * versioned = &ctx->runtime->vote_program.init_account.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1156 */
  rc = check_vote_account_length( vote_account, target_version );
  if( FD_UNLIKELY( rc ) ) return rc;

  rc = fd_vsv_get_state( vote_account->acc, versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  if( FD_UNLIKELY( !fd_vsv_is_uninitialized( versioned ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  rc = fd_vote_verify_authorized_signer( &vote_init_v2->node_pubkey, signers, signers_cnt );
  if( FD_UNLIKELY( rc ) ) {
    return rc;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1181-L1186 */
  rc = fd_vote_verify_bls_proof_of_possession(
    ctx,
    vote_account->acc->pubkey,
    vote_init_v2->authorized_voter_bls_pubkey,
    vote_init_v2->authorized_voter_bls_proof_of_possession
  );
  if( FD_UNLIKELY( rc ) ) {
    return rc;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1188-L1195 */
  return init_vote_account_state_v2( ctx, vote_account, versioned, target_version, vote_init_v2, clock );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1221-L1243 */
static int
process_vote_with_account( fd_exec_instr_ctx_t *         ctx,
                           fd_borrowed_account_t *       vote_account,
                           int                           target_version,
                           fd_slot_hashes_t const *      slot_hashes,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_legacy_vote_t *            vote,
                           fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
                           ulong                         signers_cnt ) {
  fd_vote_state_versioned_t * versioned = &ctx->runtime->vote_program.process_vote.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1229 */
  int rc = get_vote_state_handler_checked( vote_account, target_version, 1, versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* V5 has no tower votes */
  if( FD_UNLIKELY( !fd_vsv_has_tower_votes( versioned ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1231 */
  fd_pubkey_t * authorized_voter = NULL;
  rc = fd_authorized_voters_get_and_update_authorized_voter( versioned, clock->epoch, &authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1232 */
  rc = fd_vote_verify_authorized_signer( authorized_voter, signers, signers_cnt );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1234 */
  rc = process_vote( ctx, versioned, vote, slot_hashes, clock->epoch, clock->slot );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1235-L1241 */
  if( FD_LIKELY( vote->has_timestamp ) ) {
    /* Calling max() on an empty iterator returns None */
    if( FD_UNLIKELY( deq_ulong_cnt( vote->slots )==0 ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1238 */
    ulong max = 0UL;
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
                                !deq_ulong_iter_done( vote->slots, iter );
                          iter = deq_ulong_iter_next( vote->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
      max         = fd_ulong_max( max, *ele );
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1240 */
    rc = fd_vsv_process_timestamp( ctx, versioned, max, vote->timestamp );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1242 */
  return fd_vsv_set_vote_account_state( ctx, vote_account, versioned );
}

// https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1268
static int
do_process_vote_state_update( fd_exec_instr_ctx_t *       ctx,
                              fd_vote_state_versioned_t * versioned,
                              fd_slot_hashes_t const *    slot_hashes,
                              ulong                       epoch,
                              ulong                       slot,
                              fd_vote_state_update_t *    vote_state_update ) {
  int rc;

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1275
  rc = check_and_filter_proposed_vote_state(
      ctx,
      versioned,
      vote_state_update->lockouts,
      &vote_state_update->has_root,
      &vote_state_update->root,
      &vote_state_update->hash,
      slot_hashes
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1288
  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_join( deq_fd_landed_vote_t_new( ctx->runtime->vote_program.process_vote.vs_update_landed_votes_mem, deq_fd_vote_lockout_t_cnt( vote_state_update->lockouts ) ) );
  for( deq_fd_vote_lockout_t_iter_t iter =
           deq_fd_vote_lockout_t_iter_init( vote_state_update->lockouts );
       !deq_fd_vote_lockout_t_iter_done( vote_state_update->lockouts, iter );
       iter = deq_fd_vote_lockout_t_iter_next( vote_state_update->lockouts, iter ) ) {
    fd_vote_lockout_t * lockout =
        deq_fd_vote_lockout_t_iter_ele( vote_state_update->lockouts, iter );
    deq_fd_landed_vote_t_push_tail_wrap( landed_votes,
                                    ( fd_landed_vote_t ){ .latency = 0, .lockout = *lockout } );
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1282
  return process_new_vote_state(
      ctx,
      versioned,
      landed_votes,
      vote_state_update->has_root,
      vote_state_update->root,
      vote_state_update->has_timestamp,
      vote_state_update->timestamp,
      epoch,
      slot
  );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1245-L1266 */
static int
process_vote_state_update( fd_exec_instr_ctx_t *         ctx,
                           fd_borrowed_account_t *       vote_account,
                           int                           target_version,
                           fd_slot_hashes_t const *      slot_hashes,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_vote_state_update_t *      vote_state_update,
                           fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
                           ulong                         signers_cnt ) {
  fd_vote_state_versioned_t * versioned = &ctx->runtime->vote_program.process_vote.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1253 */
  int rc = get_vote_state_handler_checked( vote_account, target_version, 1, versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* V5 has no tower votes */
  if( FD_UNLIKELY( !fd_vsv_has_tower_votes( versioned ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1255 */
  fd_pubkey_t * authorized_voter = NULL;
  rc = fd_authorized_voters_get_and_update_authorized_voter( versioned, clock->epoch, &authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1256 */
  rc = fd_vote_verify_authorized_signer( authorized_voter, signers, signers_cnt );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1258-L1264 */
  rc = do_process_vote_state_update(
      ctx,
      versioned,
      slot_hashes,
      clock->epoch,
      clock->slot,
      vote_state_update
  );
  if( FD_UNLIKELY( rc ) ) {
    return rc;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1265 */
  return fd_vsv_set_vote_account_state( ctx, vote_account, versioned );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1319-L1345 */
static int
do_process_tower_sync( fd_exec_instr_ctx_t *       ctx,
                       fd_vote_state_versioned_t * versioned,
                       fd_slot_hashes_t const *    slot_hashes,
                       ulong                       epoch,
                       ulong                       slot,
                       fd_tower_sync_t *           tower_sync ) {

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1326-L1332 */
  int rc = check_and_filter_proposed_vote_state(
      ctx,
      versioned,
      tower_sync->lockouts,
      &tower_sync->has_root,
      &tower_sync->root,
      &tower_sync->hash,
      slot_hashes
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1333-L1344 */
  return process_new_vote_state(
      ctx,
      versioned,
      fd_vote_lockout_landed_votes_from_lockouts( tower_sync->lockouts, ctx->runtime->vote_program.tower_sync.tower_sync_landed_votes_mem ),
      tower_sync->has_root,
      tower_sync->root,
      tower_sync->has_timestamp,
      tower_sync->timestamp,
      epoch,
      slot
  );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1296-L1317 */
static int
process_tower_sync( fd_exec_instr_ctx_t *         ctx,
                    fd_borrowed_account_t *       vote_account,
                    int                           target_version,
                    fd_slot_hashes_t const *      slot_hashes,
                    fd_sol_sysvar_clock_t const * clock,
                    fd_tower_sync_t *             tower_sync,
                    fd_pubkey_t const *           signers[static FD_INSTR_SIGNERS_MAX],
                    ulong                         signers_cnt ) {
  fd_vote_state_versioned_t * versioned = &ctx->runtime->vote_program.tower_sync.vote_state;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1304 */
  int rc = get_vote_state_handler_checked( vote_account, target_version, 1, versioned );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* V5 has no tower votes */
  if( FD_UNLIKELY( !fd_vsv_has_tower_votes( versioned ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1306 */
  fd_pubkey_t * authorized_voter = NULL;
  rc = fd_authorized_voters_get_and_update_authorized_voter( versioned, clock->epoch, &authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1307 */
  rc = fd_vote_verify_authorized_signer( authorized_voter, signers, signers_cnt );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1309-L1315 */
  rc = do_process_tower_sync(
      ctx,
      versioned,
      slot_hashes,
      clock->epoch,
      clock->slot,
      tower_sync
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1316 */
  return fd_vsv_set_vote_account_state( ctx, vote_account, versioned );
}

/**********************************************************************/
/* FD-only encoders / decoders (doesn't map directly to Labs impl)    */
/**********************************************************************/

int
fd_vote_decode_compact_update( fd_compact_vote_state_update_t * compact_update,
                               fd_vote_state_update_t *         vote_update,
                               fd_exec_instr_ctx_t const *      ctx ) {
  // Taken from:
  // https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/state/mod.rs#L381-L391
  if( compact_update->root != ULONG_MAX ) {
    vote_update->has_root = 1;
    vote_update->root     = compact_update->root;
  } else {
    vote_update->has_root = 0;
    vote_update->root     = ULONG_MAX;
  }

  ulong lockouts_len = compact_update->lockouts_len;
  ulong lockouts_max = fd_ulong_max( lockouts_len, MAX_LOCKOUT_HISTORY );

  vote_update->lockouts = deq_fd_vote_lockout_t_join( deq_fd_vote_lockout_t_new( ctx->runtime->vote_program.process_vote.compact_vs_lockout_mem, lockouts_max ) );
  ulong slot            = fd_ulong_if( vote_update->has_root, vote_update->root, 0 );

  for( ulong i=0; i < lockouts_len; ++i ) {
    fd_vote_lockout_t *   elem        = deq_fd_vote_lockout_t_push_tail_nocopy( vote_update->lockouts );
    fd_lockout_offset_t * lock_offset = &compact_update->lockouts[i];

    ulong next_slot;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( slot, lock_offset->offset, &next_slot ) ) ) {
      return 0;
    }

    elem->slot = slot        = next_slot;
    elem->confirmation_count = (uint)lock_offset->confirmation_count;
  }

  vote_update->hash          = compact_update->hash;
  vote_update->has_timestamp = compact_update->has_timestamp;
  vote_update->timestamp     = compact_update->timestamp;

  return 1;
}

/**********************************************************************/
/* mod vote_processor                                                 */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L77-L80 */
static inline int
should_reject_legacy_vote_instructions( fd_exec_instr_ctx_t const * ctx ) {
  return FD_FEATURE_ACTIVE_BANK( ctx->bank, deprecate_legacy_vote_ixs ) ||
         ctx->bank->f.alpenglow_migration_slot!=ULONG_MAX;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L21-L61 */
static int
process_authorize_with_seed_instruction( /* invoke_context */
                                         fd_exec_instr_ctx_t *       ctx,
                                         int                         target_version,
                                         fd_borrowed_account_t *     vote_account,
                                         fd_pubkey_t const *         new_authority,
                                         fd_vote_authorize_t const * authorization_type,
                                         fd_pubkey_t const *         current_authority_derived_key_owner,
                                         uchar const *               current_authority_derived_key_seed,
                                         ulong                       current_authority_derived_key_seed_len,
                                         int                         is_vote_authorize_with_bls_enabled ) {
  int rc = 0;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L36 */
  rc = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_clock_id );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_sol_sysvar_clock_t clock_;
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
  if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  fd_pubkey_t * expected_authority_keys[FD_INSTR_SIGNERS_MAX] = { 0 };
  ulong         expected_authority_keys_cnt             = 0UL;
  fd_pubkey_t   single_signer                           = { 0 };

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L38-L50 */
  if( fd_instr_acc_is_signer_idx( ctx->instr, 2, &rc ) ) {

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L39 */
    fd_pubkey_t const * base_pubkey = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 2UL, &base_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L42-L48 */
    expected_authority_keys[0] = &single_signer;
    rc = fd_pubkey_create_with_seed( ctx,
                                     base_pubkey->uc,
                                     (char const *)current_authority_derived_key_seed,
                                     current_authority_derived_key_seed_len,
                                     current_authority_derived_key_owner->uc,
                                     /* insert */ expected_authority_keys[0]->uc );
    if( FD_UNLIKELY( rc ) ) return rc;
    expected_authority_keys_cnt = 1UL;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L51-L60 */
  return authorize(
      ctx,
      vote_account,
      target_version,
      new_authority,
      authorization_type,
      (fd_pubkey_t const **)expected_authority_keys,
      expected_authority_keys_cnt,
      clock,
      is_vote_authorize_with_bls_enabled
  );
}

/**********************************************************************/
/* Entry point for the Vote Program                                   */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L89
int
fd_vote_program_execute( fd_exec_instr_ctx_t * ctx ) {
  /* FD-specific init */
  int rc = FD_EXECUTOR_INSTR_SUCCESS;

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L89
  FD_EXEC_CU_UPDATE( ctx, DEFAULT_COMPUTE_UNITS );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L96-L99 */
  fd_guarded_borrowed_account_t me = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &me );
  if( FD_UNLIKELY( !fd_pubkey_eq( fd_borrowed_account_get_owner( &me ), &fd_solana_vote_program_id ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L101-L102 */
  int target_version = VOTE_STATE_TARGET_VERSION_V4;

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L104
  fd_pubkey_t const * signers[FD_INSTR_SIGNERS_MAX] = { 0 };
  ulong               signers_cnt                   = 0UL;
  fd_exec_instr_ctx_get_signers( ctx, signers, &signers_cnt );

  int bls_pubkey_management_in_vote_account = FD_FEATURE_ACTIVE_BANK( ctx->bank, bls_pubkey_management_in_vote_account );
  int delay_commission_updates              = FD_FEATURE_ACTIVE_BANK( ctx->bank, delay_commission_updates );
  int commission_rate_in_basis_points       = FD_FEATURE_ACTIVE_BANK( ctx->bank, commission_rate_in_basis_points );
  int custom_commission_collector           = FD_FEATURE_ACTIVE_BANK( ctx->bank, custom_commission_collector );
  int block_revenue_sharing                 = FD_FEATURE_ACTIVE_BANK( ctx->bank, block_revenue_sharing );
  int validator_location_registration       = FD_FEATURE_ACTIVE_BANK( ctx->bank, validator_location_registration );
  int vote_account_initialize_v2            = 0;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L71-L75 */
  int is_vote_authorize_with_bls_enabled = bls_pubkey_management_in_vote_account;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L63-L69 */
  int is_init_account_v2_enabled =
      bls_pubkey_management_in_vote_account &&
      commission_rate_in_basis_points &&
      custom_commission_collector &&
      block_revenue_sharing &&
      vote_account_initialize_v2;

  fd_vote_instruction_t instruction[1];
  if( FD_UNLIKELY( !fd_vote_instruction_deserialize( instruction, ctx->instr->data, ctx->instr->data_sz ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* PLEASE PRESERVE SWITCH-CASE ORDERING TO MIRROR LABS IMPL:
   */
  switch( instruction->discriminant ) {

  /* InitializeAccount
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L66
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L116
   */
  case fd_vote_instruction_enum_initialize_account: {
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L117
    rc = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_rent_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_rent_t rent_;
    fd_rent_t const * rent = fd_sysvar_cache_rent_read( ctx->sysvar_cache, &rent_ );
    if( FD_UNLIKELY( !rent ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    if( FD_UNLIKELY( fd_borrowed_account_get_lamports( &me ) <
                     fd_rent_exempt_minimum_balance( rent, fd_borrowed_account_get_data_len( &me ) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L122
    rc = fd_sysvar_instr_acct_check( ctx, 2, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L124
    rc = initialize_account( ctx, &me, target_version, &instruction->initialize_account, signers, signers_cnt, clock );

    if( FD_LIKELY( !rc ) ) {
      ctx->txn_out->accounts.new_vote[ ctx->instr->accounts[0].index_in_transaction ] = 1;
      ctx->txn_out->accounts.rm_vote[ ctx->instr->accounts[0].index_in_transaction ] = 0;
    }

    break;
  }

  /* Authorize
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L77
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L126
   *
   * Notes:
   * - Up to two signers: the vote authority and the authorized withdrawer.
   */
  case fd_vote_instruction_enum_authorize: {
    fd_pubkey_t const * voter_pubkey   = &instruction->authorize.pubkey;
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L127
    rc = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    rc = authorize( ctx, &me, target_version, voter_pubkey, &instruction->authorize.vote_authorize, signers, signers_cnt, clock, is_vote_authorize_with_bls_enabled );

    break;
  }

  /* AuthorizeWithSeed
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L161
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L140
   */
  case fd_vote_instruction_enum_authorize_with_seed: {
    fd_vote_authorize_with_seed_args_t * args = &instruction->authorize_with_seed;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L141
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 3 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }

    rc = process_authorize_with_seed_instruction(
        ctx,
        target_version,
        &me,
        &args->new_authority,
        &args->authorization_type,
        &args->current_authority_derived_key_owner,
        args->current_authority_derived_key_seed,
        args->current_authority_derived_key_seed_len,
        is_vote_authorize_with_bls_enabled
    );

    break;
  }

  /* AuthorizeCheckedWithSeed
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L179
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L155
   */
  case fd_vote_instruction_enum_authorize_checked_with_seed: {
    fd_vote_authorize_checked_with_seed_args_t const * args = &instruction->authorize_checked_with_seed;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L156
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 4 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L157
    fd_pubkey_t const * new_authority = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 3UL, &new_authority );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L158
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 3, &rc ) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/transaction-context/src/instruction.rs#L236 */
      if( FD_UNLIKELY( !!rc ) ) break;
      // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L159
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L161
    rc = process_authorize_with_seed_instruction(
        ctx,
        target_version,
        &me,
        new_authority,
        &args->authorization_type,
        &args->current_authority_derived_key_owner,
        args->current_authority_derived_key_seed,
        args->current_authority_derived_key_seed_len,
        is_vote_authorize_with_bls_enabled );

    break;
  }

  /* UpdateValidatorIdentity
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L102
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L174
   */
  case fd_vote_instruction_enum_update_validator_identity: {
    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L175
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L176
    fd_pubkey_t const * node_pubkey = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 1UL, &node_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L179
    rc = update_validator_identity( ctx, target_version, &me, node_pubkey, signers, signers_cnt, custom_commission_collector );

    break;
  }

  // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L187
  case fd_vote_instruction_enum_update_commission: {

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L149
    fd_epoch_schedule_t epoch_schedule_;
    fd_epoch_schedule_t const * epoch_schedule = fd_sysvar_cache_epoch_schedule_read( ctx->sysvar_cache, &epoch_schedule_ );
    if( FD_UNLIKELY( !epoch_schedule ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L150

    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L188
    rc = update_commission(
        ctx,
        target_version,
        &me,
        instruction->update_commission,
        signers,
        signers_cnt,
        epoch_schedule,
        clock,
        delay_commission_updates
    );

    break;
  }

  /* Vote
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L86
   */
  case fd_vote_instruction_enum_vote:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* VoteSwitch
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L118
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L190
   */
  case fd_vote_instruction_enum_vote_switch: {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L191-L193 */
    if( should_reject_legacy_vote_instructions( ctx ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_legacy_vote_t * vote;
    if( instruction->discriminant == fd_vote_instruction_enum_vote ) {
      vote = &instruction->vote;
    } else if( instruction->discriminant == fd_vote_instruction_enum_vote_switch ) {
      vote = &instruction->vote_switch.vote;
    } else {
      FD_LOG_CRIT(( "unsupported instruction discriminant: %u", instruction->discriminant ));
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L194
    int err;
    err = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_slot_hashes_id );
    if( FD_UNLIKELY( err ) ) return err;

    if( FD_UNLIKELY( !fd_sysvar_cache_slot_hashes_is_valid( ctx->sysvar_cache ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L199
    err = fd_sysvar_instr_acct_check( ctx, 2, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( err ) ) return err;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    fd_slot_hashes_t slot_hashes_[1];
    fd_slot_hashes_t const * slot_hashes = fd_sysvar_cache_slot_hashes_view( ctx->sysvar_cache, slot_hashes_ );
    if( FD_UNLIKELY( !slot_hashes ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    rc = process_vote_with_account(
        ctx,
        &me,
        target_version,
        slot_hashes,
        clock,
        vote,
        signers,
        signers_cnt
    );

    break;
  }

  /* UpdateVoteState
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L140
   */
  case fd_vote_instruction_enum_update_vote_state:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* UpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L147
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L211
   */
  case fd_vote_instruction_enum_update_vote_state_switch: {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L212-L214 */
    if( should_reject_legacy_vote_instructions( ctx ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_vote_state_update_t * vote_state_update;
    switch( instruction->discriminant ) {
    case fd_vote_instruction_enum_update_vote_state:
      vote_state_update = &instruction->update_vote_state;
      break;
    case fd_vote_instruction_enum_update_vote_state_switch:
      vote_state_update = &instruction->update_vote_state_switch.vote_state_update;
      break;
    default:
      FD_LOG_CRIT(( "unsupported instruction discriminant: %u", instruction->discriminant ));
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L216
    if( FD_UNLIKELY( !fd_sysvar_cache_slot_hashes_is_valid( ctx->sysvar_cache ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L217
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L218
    fd_slot_hashes_t slot_hashes_[1];
    fd_slot_hashes_t const * slot_hashes = fd_sysvar_cache_slot_hashes_view( ctx->sysvar_cache, slot_hashes_ );
    if( FD_UNLIKELY( !slot_hashes ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    rc = process_vote_state_update(
        ctx,
        &me,
        target_version,
        slot_hashes,
        clock,
        vote_state_update,
        signers,
        signers_cnt
    );

    break;
  }

  /* CompactUpdateVoteState
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L187
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state:;
    __attribute__((fallthrough));

  /* CompactUpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L196
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L228
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state_switch: {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L229-L231 */
    if( should_reject_legacy_vote_instructions( ctx ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_compact_vote_state_update_t * vote_state_update = NULL;
    if( instruction->discriminant == fd_vote_instruction_enum_compact_update_vote_state ) {
      vote_state_update = &instruction->compact_update_vote_state;
    } else if( instruction->discriminant ==
               fd_vote_instruction_enum_compact_update_vote_state_switch ) {
      vote_state_update =
          &instruction->compact_update_vote_state_switch.compact_vote_state_update;
    }

    fd_vote_state_update_t vote_update = {0};
    if( FD_UNLIKELY( !fd_vote_decode_compact_update( vote_state_update, &vote_update, ctx ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L233
    if( FD_UNLIKELY( !fd_sysvar_cache_slot_hashes_is_valid( ctx->sysvar_cache ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L235
    fd_slot_hashes_t slot_hashes_[1];
    fd_slot_hashes_t const * slot_hashes = fd_sysvar_cache_slot_hashes_view( ctx->sysvar_cache, slot_hashes_ );
    if( FD_UNLIKELY( !slot_hashes ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    rc = process_vote_state_update(
        ctx,
        &me,
        target_version,
        slot_hashes,
        clock,
        &vote_update,
        signers,
        signers_cnt
    );

    break;
  }

  /* TowerSync(Switch)
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L203-L209
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L244-L260
   */

  case fd_vote_instruction_enum_tower_sync:
  case fd_vote_instruction_enum_tower_sync_switch: {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L246-L248 */
    if( FD_UNLIKELY( ctx->bank->f.alpenglow_migration_slot!=ULONG_MAX ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_tower_sync_t * tower_sync = (instruction->discriminant == fd_vote_instruction_enum_tower_sync)
        ? &instruction->tower_sync
        : &instruction->tower_sync_switch.tower_sync;

    if( FD_UNLIKELY( !fd_sysvar_cache_slot_hashes_is_valid( ctx->sysvar_cache ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    fd_slot_hashes_t slot_hashes_[1];
    fd_slot_hashes_t const * slot_hashes = fd_sysvar_cache_slot_hashes_view( ctx->sysvar_cache, slot_hashes_ );
    if( FD_UNLIKELY( !slot_hashes ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    rc = process_tower_sync(
        ctx,
        &me,
        target_version,
        slot_hashes,
        clock,
        tower_sync,
        signers,
        signers_cnt
    );

    break;
  }

  /* Withdraw
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L94
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L261
   */
  case fd_vote_instruction_enum_withdraw: {
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }
    fd_rent_t rent_;
    fd_rent_t const * rent_sysvar = fd_sysvar_cache_rent_read( ctx->sysvar_cache, &rent_ );
    if( FD_UNLIKELY( !rent_sysvar ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock_sysvar = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock_sysvar ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    int deinitialized = 0;
    rc = withdraw(
        ctx,
        &me,
        target_version,
        instruction->withdraw,
        1UL,
        signers,
        signers_cnt,
        rent_sysvar,
        clock_sysvar,
        &deinitialized
    );

    if( FD_LIKELY( !rc && deinitialized ) ) {
      ctx->txn_out->accounts.new_vote[ ctx->instr->accounts[0].index_in_transaction ] = 0;
      ctx->txn_out->accounts.rm_vote[ ctx->instr->accounts[0].index_in_transaction ] = 1;
    }


    break;
  }

  /* AuthorizeChecked
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L133
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L284
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_authorize_checked: {
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 4 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L286
    fd_pubkey_t const * voter_pubkey = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 3UL, &voter_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L287
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 3, &rc ) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/transaction-context/src/instruction.rs#L236 */
      if( FD_UNLIKELY( !!rc ) ) break;

      rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L290
    rc = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    rc = authorize(
        ctx,
        &me,
        target_version,
        voter_pubkey,
        &instruction->authorize_checked,
        signers,
        signers_cnt,
        clock,
        is_vote_authorize_with_bls_enabled
    );
    break;
  }

  /* InitializeAccountV2
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L223-L243
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L303-L327
   *
   * Notes:
   * - The code is identical to InitializeAccount, except calling the actual initialize_account_v2
   * - Feature gated.
   */
  case fd_vote_instruction_enum_initialize_account_v2: {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L304-L306 */
    if( FD_UNLIKELY( !is_init_account_v2_enabled ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    rc = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_rent_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_rent_t rent_;
    fd_rent_t const * rent = fd_sysvar_cache_rent_read( ctx->sysvar_cache, &rent_ );
    if( FD_UNLIKELY( !rent ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    if( FD_UNLIKELY( fd_borrowed_account_get_lamports( &me ) <
                     fd_rent_exempt_minimum_balance( rent, fd_borrowed_account_get_data_len( &me ) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

    rc = fd_sysvar_instr_acct_check( ctx, 2, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    rc = initialize_account_v2( ctx, &me, target_version, &instruction->initialize_account_v2, signers, signers_cnt, clock );

    if( FD_LIKELY( !rc ) ) {
      ctx->txn_out->accounts.new_vote[ ctx->instr->accounts[0].index_in_transaction ] = 1;
      ctx->txn_out->accounts.rm_vote[ ctx->instr->accounts[0].index_in_transaction ] = 0;
    }

    break;
  }

  /* UpdateCommissionBps (commission_rate_in_basis_points feature)
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L255-L264
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L328-L338
   *
   */
  case fd_vote_instruction_enum_update_commission_bps: {
    if( FD_UNLIKELY( !commission_rate_in_basis_points
                  || !delay_commission_updates ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    rc = update_commission_bps( ctx, &me, target_version, &instruction->update_commission_bps, signers, signers_cnt, block_revenue_sharing );

    break;
  }

  /* UpdateCommissionCollector (SIMD-0232)
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L245-L253
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L339-L365
   *
   * Notes:
   * - Feature gated on custom_commission_collector
   */
  case fd_vote_instruction_enum_update_commission_collector: {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L340-L346 */
    if( FD_UNLIKELY( !custom_commission_collector ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L348 */
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 3 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }

    /* If instruction account 1 is the vote account itself, no account
       is borrowed.
       https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L868-L874 */
    fd_pubkey_t const * collector_key = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 1, &collector_key );
    if( FD_UNLIKELY( rc ) ) return rc;

    fd_guarded_borrowed_account_t collector = {0};
    fd_borrowed_account_t const * collector_account = NULL;
    if( !fd_pubkey_eq( collector_key, (fd_pubkey_t const *)me.acc->pubkey ) ) {
      FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 1, &collector );
      collector_account = &collector;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L350-L353 */
    fd_rent_t rent_;
    fd_rent_t const * rent = fd_sysvar_cache_rent_read( ctx->sysvar_cache, &rent_ );
    if( FD_UNLIKELY( !rent ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    rc = update_commission_collector(
        ctx,
        &me,
        target_version,
        collector_account,
        &instruction->update_commission_collector,
        signers,
        signers_cnt,
        rent
    );

    break;
  }

  /* DepositDelegatorRewards (SIMD-0123)
   *
   * Instruction:
   * https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/instruction.rs#L266-L272
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_processor.rs#L366-L368
   *
   * Notes:
   * - Disabled, always fails with InvalidInstructionData
   */
  case fd_vote_instruction_enum_deposit_delegator_rewards: {
    rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    break;
  }

  /* UpdateLocation (SIMD-0674 validator_location_registration feature)
   *
   * Notes:
   * - Feature gated on validator_location_registration
   * - Converts the vote account to a Vote State V5 account if it
   *   wasn't already.
   */
  case fd_vote_instruction_enum_update_location: {
    if( FD_UNLIKELY( !validator_location_registration ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    rc = update_location( ctx, &me, target_version, &instruction->update_location, signers, signers_cnt, clock );
    break;
  }

  default:
    FD_LOG_CRIT(( "unsupported vote instruction: %u", instruction->discriminant ));
  }

  return rc;
}
