#include "fd_vote_program.h"
#include "../fd_runtime.h"
#include "../fd_borrowed_account.h"
#include "../fd_executor.h"
#include "../fd_pubkey_utils.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar.h"
#include "../fd_system_ids.h"
#include "vote/fd_authorized_voters.h"
#include "vote/fd_vote_common.h"
#include "vote/fd_vote_lockout.h"
#include "vote/fd_vote_state_versioned.h"
#include "vote/fd_vote_state_v3.h"
#include "vote/fd_vote_state_v4.h"

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L36
#define INITIAL_LOCKOUT 2UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L51
#define VOTE_CREDITS_MAXIMUM_PER_SLOT_OLD 8

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/clock.rs#L147
#define SLOT_DEFAULT 0UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/clock.rs#L147
#define SLOT_MAX ULONG_MAX

#define ACCOUNTS_MAX 4 /* Vote instructions take in at most 4 accounts */

#define DEFAULT_COMPUTE_UNITS 2100UL

/**********************************************************************/
/* VoteStateHandler                                                   */
/**********************************************************************/

/* This is a temporary method in Agave (until the vote state v4 feature
   is cleaned up) to check the vote state and, in some cases, check
   if the vote account is uninitialized or not. Initializes a v3 or v4
   vote account depending on the target version.
   https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L45-L77 */
static int
get_vote_state_handler_checked( fd_borrowed_account_t const * vote_account,
                                int                           target_version,
                                uchar                         check_initialized,
                                uchar *                       vote_state_mem,
                                uchar *                       authorized_voters_mem,
                                uchar *                       landed_votes_mem ) {
  int rc;
  switch( target_version ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L50-L62 */
    case VOTE_STATE_TARGET_VERSION_V3: {
      rc = fd_vote_state_v3_deserialize( vote_account, vote_state_mem, authorized_voters_mem, landed_votes_mem );
      if( FD_UNLIKELY( rc ) ) return rc;

      fd_vote_state_versioned_t * versioned = (fd_vote_state_versioned_t *)vote_state_mem;
      if( FD_UNLIKELY( check_initialized && fd_vsv_is_uninitialized( versioned ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
      }

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L63-L75 */
    case VOTE_STATE_TARGET_VERSION_V4: {
      rc = fd_vsv_deserialize( vote_account, vote_state_mem );
      if( FD_UNLIKELY( rc ) ) return rc;

      fd_vote_state_versioned_t * versioned = (fd_vote_state_versioned_t *)vote_state_mem;
      if( FD_UNLIKELY( fd_vsv_is_uninitialized( versioned ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
      }

      rc = fd_vsv_try_convert_to_v4( versioned, vote_account->pubkey, landed_votes_mem );
      if( FD_UNLIKELY( rc ) ) return rc;

      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    default:
      FD_LOG_CRIT(( "unsupported version: %d", target_version ));
  }
}

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L888-L902 */
static int
check_vote_account_length( fd_borrowed_account_t const * vote_account,
                           int                           target_version ) {
  ulong length = fd_borrowed_account_get_data_len( vote_account );
  ulong expected;
  switch( target_version ) {
    case VOTE_STATE_TARGET_VERSION_V3:
      expected = FD_VOTE_STATE_V3_SZ;
      break;
    case VOTE_STATE_TARGET_VERSION_V4:
      expected = FD_VOTE_STATE_V4_SZ;
      break;
    default:
      FD_LOG_CRIT(( "unsupported version: %d", target_version ));
  }
  if( FD_UNLIKELY( length!=expected ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* The versioned parameter must point to a buffer that is aligned to
   FD_VOTE_STATE_VERSIONED_ALIGN and is at least
   FD_VOTE_STATE_VERSIONED_FOOTPRINT bytes in size.
   https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L855-L870 */
static int
init_vote_account_state( fd_exec_instr_ctx_t *         ctx,
                         fd_borrowed_account_t *       vote_account,
                         fd_vote_state_versioned_t *   versioned,
                         int                           target_version,
                         fd_vote_init_t *              vote_init,
                         fd_sol_sysvar_clock_t const * clock ) {
  /* Reset the object */
  fd_vote_state_versioned_new( versioned );

  switch( target_version ) {
    case VOTE_STATE_TARGET_VERSION_V3:
      fd_vote_program_v3_create_new(
          vote_init,
          clock,
          ctx->runtime->vote_program.init_account.authorized_voters_mem,
          versioned
      );
      return fd_vote_state_v3_set_vote_account_state(
          ctx,
          vote_account,
          versioned,
          ctx->runtime->vote_program.init_account.vote_lockout_mem
      );
    case VOTE_STATE_TARGET_VERSION_V4:
      fd_vote_state_v4_create_new(
          vote_account->pubkey,
          vote_init,
          clock,
          ctx->runtime->vote_program.init_account.authorized_voters_mem,
          versioned
      );
      return fd_vote_state_v4_set_vote_account_state( ctx, vote_account, versioned );
    default:
      FD_LOG_CRIT(( "unsupported version: %d", target_version ));
  }
}

/**********************************************************************/
/* mod vote_state                                                    */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L82-L324 */
static int
check_and_filter_proposed_vote_state( fd_exec_instr_ctx_t *       ctx,
                                      fd_vote_state_versioned_t * versioned,
                                      fd_vote_lockout_t *         proposed_lockouts,
                                      uchar *                     proposed_has_root,
                                      ulong *                     proposed_root,
                                      fd_hash_t const *           proposed_hash,
                                      fd_slot_hash_t const *      slot_hashes /* deque */ ) {
  fd_landed_vote_t const * votes         = fd_vsv_get_votes( versioned );
  ulong const *            root_slot     = fd_vsv_get_root_slot( versioned );
  uchar                    has_root_slot = !!(root_slot!=NULL);

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L208
  if( FD_UNLIKELY( deq_fd_vote_lockout_t_empty( proposed_lockouts ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  fd_landed_vote_t const * last_vote = NULL;
  if( !deq_fd_landed_vote_t_empty( votes ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L212
    last_vote = deq_fd_landed_vote_t_peek_tail_const( votes );
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L218
  if( FD_LIKELY( last_vote ) ) {
    if( FD_UNLIKELY( deq_fd_vote_lockout_t_peek_tail_const( proposed_lockouts )->slot <=
                     last_vote->lockout.slot ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_VOTE_TOO_OLD;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  /* must be nonempty, checked above */
  ulong last_vote_state_update_slot = deq_fd_vote_lockout_t_peek_tail_const( proposed_lockouts )->slot;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L224
  if( FD_UNLIKELY( deq_fd_slot_hash_t_empty( slot_hashes ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L227
  ulong earliest_slot_hash_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes )->slot;

  /* Check if the proposed vote is too old to be in the SlotHash history */
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L230
  if( FD_UNLIKELY( last_vote_state_update_slot < earliest_slot_hash_in_history ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check if the proposed root is too old */
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L237
  if( *proposed_has_root ) {
    ulong const proposed_root_ = *proposed_root;
    /* If the new proposed root `R` is less than the earliest slot hash in the history
       such that we cannot verify whether the slot was actually was on this fork, set
       the root to the latest vote in the current vote that's less than R. */
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L242
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
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L248
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
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L259
  ulong root_to_check           = *proposed_root;
  ulong proposed_lockouts_index = 0UL;
  ulong lockouts_len = deq_fd_vote_lockout_t_cnt( proposed_lockouts );

  /* Index into the slot_hashes, starting at the oldest known slot hash */
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L264
  ulong slot_hashes_index = deq_fd_slot_hash_t_cnt( slot_hashes );

  /* proposed_lockouts_indexes_to_filter's size is bounded by the length
     of the proposed lockouts provided in the instruction data, which is
     capped at roughly 10KB / sizeof(ulong). */
  ulong proposed_lockouts_indexes_to_filter[ FD_INSTR_DATA_MAX/sizeof(ulong) ];
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

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L279
  while( proposed_lockouts_index < lockouts_len && slot_hashes_index > 0 ) {
    ulong proposed_vote_slot =
      fd_ulong_if( has_root_to_check,
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L281
        root_to_check,
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L283
        deq_fd_vote_lockout_t_peek_index_const( proposed_lockouts,
          proposed_lockouts_index )
        ->slot );
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L285
    if( !has_root_to_check && proposed_lockouts_index > 0UL &&
      proposed_vote_slot <=
      deq_fd_vote_lockout_t_peek_index_const(
        proposed_lockouts,
          fd_ulong_checked_sub_expect(
            proposed_lockouts_index,
              1,
              "`proposed_lockouts_index` is positive when checking `SlotsNotOrdered`" ) )
      ->slot ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L293
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_NOT_ORDERED;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L295
    ulong ancestor_slot =
      deq_fd_slot_hash_t_peek_index_const(
        slot_hashes,
          fd_ulong_checked_sub_expect(
            slot_hashes_index,
              1UL,
              "`slot_hashes_index` is positive when computing `ancestor_slot`" ) )
      ->slot;
    /* Find if this slot in the proposed vote state exists in the SlotHashes history
       to confirm if it was a valid ancestor on this fork */
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L303
    if( proposed_vote_slot < ancestor_slot ) {
      if( slot_hashes_index == deq_fd_slot_hash_t_cnt( slot_hashes ) ) {
        /* The vote slot does not exist in the SlotHashes history because it's too old,
           i.e. older than the oldest slot in the history. */
        if( proposed_vote_slot >= earliest_slot_hash_in_history ) {
          ctx->txn_out->err.custom_err = 0;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L310
        if( !fd_vote_contains_slot( votes, proposed_vote_slot ) && !has_root_to_check ) {
          /* If the vote slot is both:
             1) Too old
             2) Doesn't already exist in vote state
             Then filter it out */
          proposed_lockouts_indexes_to_filter[filter_index++] = proposed_lockouts_index;        }
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L318
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

          // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L329
          has_root_to_check = 0;
          root_to_check     = ULONG_MAX;
        } else {
          // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L331
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
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L340
        if( has_root_to_check ) {
          ctx->txn_out->err.custom_err = FD_VOTE_ERR_ROOT_ON_DIFFERENT_FORK;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        } else {
          ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }
      }
    } else if( proposed_vote_slot > ancestor_slot ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L347

      /* Decrement `slot_hashes_index` to find newer slots in the SlotHashes history */
      slot_hashes_index = fd_ulong_checked_sub_expect(
        slot_hashes_index,
          1,
          "`slot_hashes_index` is positive when finding newer slots in SlotHashes history" );
      continue;
    } else {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L354

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

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L372
  if( proposed_lockouts_index != deq_fd_vote_lockout_t_cnt( proposed_lockouts ) ) {
    /* The last vote slot in the update did not exist in SlotHashes */
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L401
  if( memcmp( &deq_fd_slot_hash_t_peek_index_const( slot_hashes, slot_hashes_index )->hash,
      proposed_hash,
      sizeof( fd_hash_t ) ) != 0 ) {
    /* This means the newest vote in the slot has a match that
       doesn't match the expected hash for that slot on this fork */
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L418
  /* Filter out the irrelevant votes */
  proposed_lockouts_index = 0UL;
  ulong filter_votes_index = deq_fd_vote_lockout_t_cnt( proposed_lockouts );

  /* We need to iterate backwards here because proposed_lockouts_indexes_to_filter[ i ] is a
     strictly increasing value. Forward iterating can lead to the proposed lockout indicies to get
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

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L440
static int
check_slots_are_valid( fd_exec_instr_ctx_t *       ctx,
                       fd_vote_state_versioned_t * versioned,
                       ulong const *               vote_slots,
                       fd_hash_t const *           vote_hash,
                       fd_slot_hash_t const *      slot_hashes /* deque */ ) {
  ulong i              = 0;
  ulong j              = deq_fd_slot_hash_t_cnt( slot_hashes );
  ulong vote_slots_len = deq_ulong_cnt( vote_slots );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L462
  while( i < vote_slots_len && j > 0 ) {
    ulong const * last_voted_slot_ = fd_vsv_get_last_voted_slot( versioned );
    if( FD_UNLIKELY( last_voted_slot_ &&
                     *deq_ulong_peek_index_const( vote_slots, i ) <= *last_voted_slot_ ) ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L469
      i = fd_ulong_checked_add_expect(
          i, 1, "`i` is bounded by `MAX_LOCKOUT_HISTORY` when finding larger slots" );
      continue;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L476
    if( FD_UNLIKELY(
            *deq_ulong_peek_index_const( vote_slots, i ) !=
            deq_fd_slot_hash_t_peek_index_const( slot_hashes,
              fd_ulong_checked_sub_expect( j, 1, "`j` is positive" ) )
                ->slot ) ) {
      j = fd_ulong_checked_sub_expect( j, 1, "`j` is positive when finding newer slots" );
      continue;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L486
    i = fd_ulong_checked_add_expect(
        i, 1, "`i` is bounded by `MAX_LOCKOUT_HISTORY` when hash is found" );
    j = fd_ulong_checked_sub_expect( j, 1, "`j` is positive when hash is found" );
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L494
  if( FD_UNLIKELY( j == deq_fd_slot_hash_t_cnt( slot_hashes ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if( FD_UNLIKELY( i != vote_slots_len ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L514
  if( FD_UNLIKELY( 0 != memcmp( &deq_fd_slot_hash_t_peek_index_const( slot_hashes, j )->hash,
                                vote_hash,
                                32UL ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_SLOTS_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L565
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
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L575
  if( FD_UNLIKELY( deq_fd_landed_vote_t_cnt( new_state ) > MAX_LOCKOUT_HISTORY ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_TOO_MANY_VOTES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  };

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L579
  if( FD_UNLIKELY( has_new_root && has_root_slot ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L581
    if( FD_UNLIKELY( new_root<*root_slot ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_ROOT_ROLL_BACK;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else if( FD_UNLIKELY( !has_new_root && has_root_slot ) ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L586
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_ROOT_ROLL_BACK;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  } else {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L588
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

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L641
  ulong earned_credits      = 0;

  if( FD_LIKELY( has_new_root ) ) {
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( votes );
                                           !deq_fd_landed_vote_t_iter_done( votes, iter );
                                     iter = deq_fd_landed_vote_t_iter_next( votes, iter ) ) {
      fd_landed_vote_t const * current_vote = deq_fd_landed_vote_t_iter_ele_const( votes, iter );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L647
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

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L686
  while( current_vote_state_index < deq_fd_landed_vote_t_cnt( votes ) &&
         new_vote_state_index < deq_fd_landed_vote_t_cnt( new_state ) ) {
    fd_landed_vote_t const * current_vote = deq_fd_landed_vote_t_peek_index_const( votes, current_vote_state_index );

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L690
    fd_landed_vote_t * new_vote =
        deq_fd_landed_vote_t_peek_index( new_state, new_vote_state_index );

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L696
    if( FD_LIKELY( current_vote->lockout.slot < new_vote->lockout.slot ) ) {
      /* The agave implementation of calculating the last locked out
         slot does not calculate a min between the current vote's
         confirmation count and max lockout history. The reason we do
         this is to make sure that the fuzzers continue working:
         the max lockout history can not be > MAX_LOCKOUT_HISTORY. */
      ulong confirmation_count   = fd_ulong_min( current_vote->lockout.confirmation_count, MAX_LOCKOUT_HISTORY );
      ulong last_locked_out_slot = fd_ulong_sat_add( current_vote->lockout.slot,
                                                     (ulong)pow( INITIAL_LOCKOUT, (double)confirmation_count ) );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L697
      if( last_locked_out_slot >= new_vote->lockout.slot ) {
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L698
        ctx->txn_out->err.custom_err = FD_VOTE_ERR_LOCKOUT_CONFLICT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L700
      current_vote_state_index =
          fd_ulong_checked_add_expect( current_vote_state_index,
                                       1,
                                       "`current_vote_state_index` is bounded by "
                                       "`MAX_LOCKOUT_HISTORY` when slot is less than proposed" );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L704
    } else if( FD_UNLIKELY( current_vote->lockout.slot == new_vote->lockout.slot ) ) {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L707
      if( new_vote->lockout.confirmation_count < current_vote->lockout.confirmation_count ) {
        ctx->txn_out->err.custom_err = FD_VOTE_ERR_CONFIRMATION_ROLL_BACK;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L712
      new_vote->latency = deq_fd_landed_vote_t_peek_index_const( votes, current_vote_state_index )->latency;

      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L714
      current_vote_state_index =
          fd_ulong_checked_add_expect( current_vote_state_index,
                                       1,
                                       "`current_vote_state_index` is bounded by "
                                       "`MAX_LOCKOUT_HISTORY` when slot is equal to proposed" );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L717
      new_vote_state_index =
          fd_ulong_checked_add_expect( new_vote_state_index,
                                       1,
                                       "`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
                                       "when slot is equal to proposed" );
    } else {
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L722
      new_vote_state_index =
          fd_ulong_checked_add_expect( new_vote_state_index,
                                       1,
                                       "`new_vote_state_index` is bounded by `MAX_LOCKOUT_HISTORY` "
                                       "when slot is greater than proposed" );
    }
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L737
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
        !deq_fd_landed_vote_t_iter_done( new_state, iter );
        iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * new_vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L738
    if( FD_UNLIKELY( new_vote->latency == 0 ) ) {
      // this is unlikely because as validators upgrade, it should converge to the new vote state
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L739
      new_vote->latency = fd_vote_compute_vote_latency( new_vote->lockout.slot, current_slot );
    }
  }

  // doesn't matter what the value of slot if `is_some = 0` i.e. `Option::None`
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L744
  int both_none = !has_root_slot && !has_new_root;
  if( ( !both_none && ( has_root_slot!=has_new_root ||
                        *root_slot!=new_root ) ) ) {
    fd_vsv_increment_credits( versioned, epoch, earned_credits );
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L750
  if( FD_LIKELY( has_timestamp ) ) {
    /* new_state asserted nonempty at function beginning */
    if( FD_UNLIKELY( deq_fd_landed_vote_t_empty( new_state ) ) ) {
      FD_LOG_CRIT(( "invariant violation: landed votes is empty" ));
    }
    ulong last_slot = deq_fd_landed_vote_t_peek_tail( new_state )->lockout.slot;
    rc              = fd_vsv_process_timestamp( ctx, versioned, last_slot, timestamp );
    if( FD_UNLIKELY( rc ) ) { return rc; }
    fd_vsv_process_timestamp( ctx, versioned, last_slot, timestamp );
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L754
  fd_vsv_set_root_slot( versioned, has_new_root ? &new_root : NULL );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L755
  deq_fd_landed_vote_t_remove_all( votes );
  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( new_state );
       !deq_fd_landed_vote_t_iter_done( new_state, iter );
       iter = deq_fd_landed_vote_t_iter_next( new_state, iter ) ) {
    fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_iter_ele( new_state, iter );
    deq_fd_landed_vote_t_push_tail_wrap( votes, *landed_vote );
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L716-L759 */
static int
authorize( fd_exec_instr_ctx_t *         ctx,
           fd_borrowed_account_t *       vote_account,
           int                           target_version,
           fd_pubkey_t const *           authorized,
           fd_vote_authorize_t           vote_authorize,
           fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
           fd_sol_sysvar_clock_t const * clock ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L724-L727 */
  int rc = get_vote_state_handler_checked(
      vote_account,
      target_version,
      0,
      ctx->runtime->vote_program.authorize.vote_state_mem,
      ctx->runtime->vote_program.authorize.authorized_voters_mem,
      ctx->runtime->vote_program.authorize.landed_votes_mem
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L729-L756 */
  fd_vote_state_versioned_t * vote_state_versioned = (fd_vote_state_versioned_t *)ctx->runtime->vote_program.authorize.vote_state_mem;
  switch( vote_authorize.discriminant ) {

    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L730-L750 */
    case fd_vote_authorize_enum_voter: {

      /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L731-L732 */
      int authorized_withdrawer_signer = !fd_vote_verify_authorized_signer(
          fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
          signers
      );

      /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L737-L740 */
      ulong target_epoch;
      rc = fd_ulong_checked_add( clock->leader_schedule_epoch, 1UL, &target_epoch );
      if( FD_UNLIKELY( rc!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L866
      rc = fd_vsv_set_new_authorized_voter(
          ctx,
          vote_state_versioned,
          authorized,
          clock->epoch,
          target_epoch,
          authorized_withdrawer_signer,
          signers
      );
      if( FD_UNLIKELY( rc ) ) return rc;
      break;
    }

    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L751-L756 */
    case fd_vote_authorize_enum_withdrawer: {
      rc = fd_vote_verify_authorized_signer(
          fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
          signers
      );
      if( FD_UNLIKELY( rc ) ) return rc;
      fd_vsv_set_authorized_withdrawer( vote_state_versioned, authorized );
      break;
    }
    default:
      FD_LOG_CRIT(( "unsupported vote_authorize discriminant: %u", vote_authorize.discriminant ));
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L758 */
  return fd_vsv_set_vote_account_state(
      ctx,
      vote_account,
      vote_state_versioned,
      ctx->runtime->vote_program.authorize.vote_lockout_mem
  );
}

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L761-L785 */
static int
update_validator_identity( fd_exec_instr_ctx_t *   ctx,
                           int                     target_version,
                           fd_borrowed_account_t * vote_account,
                           fd_pubkey_t const *     node_pubkey,
                           fd_pubkey_t const *     signers[static FD_TXN_SIG_MAX] ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L768-L771 */
  int rc = get_vote_state_handler_checked(
      vote_account,
      target_version,
      0,
      ctx->runtime->vote_program.update_validator_identity.vote_state_mem,
      ctx->runtime->vote_program.update_validator_identity.authorized_voters_mem,
      ctx->runtime->vote_program.update_validator_identity.landed_votes_mem
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_vote_state_versioned_t * vote_state_versioned = (fd_vote_state_versioned_t *)ctx->runtime->vote_program.update_validator_identity.vote_state_mem;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L774 */
  rc = fd_vote_verify_authorized_signer(
      fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
      signers
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L777 */
  rc = fd_vote_verify_authorized_signer( node_pubkey, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L779 */
  fd_vsv_set_node_pubkey( vote_state_versioned, node_pubkey );

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L782 */
  fd_vsv_set_block_revenue_collector( vote_state_versioned, node_pubkey );

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L784 */
  return fd_vsv_set_vote_account_state(
      ctx,
      vote_account,
      vote_state_versioned,
      ctx->runtime->vote_program.update_validator_identity.vote_lockout_mem
  );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L971
static int
is_commission_update_allowed( ulong slot, fd_epoch_schedule_t const * epoch_schedule ) {
  if( FD_LIKELY( epoch_schedule->slots_per_epoch > 0UL ) ) {
    ulong relative_slot = fd_ulong_sat_sub( slot, epoch_schedule->first_normal_slot );
    // TODO underflow and overflow edge cases in addition to div by 0
    relative_slot %= epoch_schedule->slots_per_epoch;
    return fd_ulong_sat_mul( relative_slot, 2 ) <= epoch_schedule->slots_per_epoch;
  } else {
    return 1;
  }
}

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L787-L818 */
static int
update_commission( fd_exec_instr_ctx_t *         ctx,
                   int                           target_version,
                   fd_borrowed_account_t *       vote_account,
                   uchar                         commission,
                   fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                   fd_epoch_schedule_t const *   epoch_schedule,
                   fd_sol_sysvar_clock_t const * clock ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L796-L799 */
  int rc         = 0;
  int get_vsv_rc = get_vote_state_handler_checked(
      vote_account,
      target_version,
      false,
      ctx->runtime->vote_program.update_commission.vote_state_mem,
      ctx->runtime->vote_program.update_commission.authorized_voters_mem,
      ctx->runtime->vote_program.update_commission.landed_votes_mem
  );

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L800-L804 */
  fd_vote_state_versioned_t * vote_state_versioned           = NULL;
  int                         enforce_commission_update_rule = 1;
  if( FD_LIKELY( get_vsv_rc==FD_EXECUTOR_INSTR_SUCCESS ) ) {
    vote_state_versioned           = (fd_vote_state_versioned_t *)ctx->runtime->vote_program.update_commission.vote_state_mem;
    enforce_commission_update_rule = (commission>fd_vsv_get_commission( vote_state_versioned ));
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L806-L808 */
  if( FD_UNLIKELY( enforce_commission_update_rule && !is_commission_update_allowed( clock->slot, epoch_schedule ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_COMMISSION_UPDATE_TOO_LATE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L810 */
  if( FD_UNLIKELY( get_vsv_rc ) ) return get_vsv_rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L813 */
  rc = fd_vote_verify_authorized_signer(
      fd_vsv_get_authorized_withdrawer( vote_state_versioned ),
      signers
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L815 */
  fd_vsv_set_commission( vote_state_versioned, commission );

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L817 */
  return fd_vsv_set_vote_account_state(
      ctx,
      vote_account,
      vote_state_versioned,
      ctx->runtime->vote_program.update_commission.vote_lockout_mem
  );
}

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L848C8-L903 */
static int
withdraw( fd_exec_instr_ctx_t *         ctx,
          fd_borrowed_account_t *       vote_account,
          int                           target_version,
          ulong                         lamports,
          ushort                        to_account_index,
          fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
          fd_rent_t const *             rent_sysvar,
          fd_sol_sysvar_clock_t const * clock ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L860-L863 */
  int rc = get_vote_state_handler_checked(
      vote_account,
      target_version,
      0,
      ctx->runtime->vote_program.withdraw.vote_state_mem,
      ctx->runtime->vote_program.withdraw.authorized_voters_mem,
      ctx->runtime->vote_program.withdraw.landed_votes_mem
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_vote_state_versioned_t * versioned = (fd_vote_state_versioned_t *)ctx->runtime->vote_program.withdraw.vote_state_mem;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L865 */
  rc = fd_vote_verify_authorized_signer(
      fd_vsv_get_authorized_withdrawer( versioned ),
      signers
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L867-L870 */
  ulong vote_account_lamports = fd_borrowed_account_get_lamports( vote_account );
  if( FD_UNLIKELY( lamports>vote_account_lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }
  ulong remaining_balance = vote_account_lamports-lamports;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L872-L896 */
  if( FD_UNLIKELY( remaining_balance==0UL ) ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L873-L883 */
    fd_vote_epoch_credits_t const * epoch_credits = fd_vsv_get_epoch_credits( versioned );
    ulong                           last_epoch_with_credits;
    int                             reject_active_vote_account_close = 0;
    if( FD_LIKELY( !deq_fd_vote_epoch_credits_t_empty( epoch_credits ) ) ) {
      ulong current_epoch              = clock->epoch;
      last_epoch_with_credits          = deq_fd_vote_epoch_credits_t_peek_tail_const( epoch_credits )->epoch;
      reject_active_vote_account_close = fd_ulong_sat_sub( current_epoch, last_epoch_with_credits )<2UL;
    }

    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L885-L890 */
    if( FD_UNLIKELY( reject_active_vote_account_close ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_ACTIVE_VOTE_ACCOUNT_CLOSE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else {
      rc = fd_vsv_deinitialize_vote_account_state(
          ctx,
          vote_account,
          target_version,
          ctx->runtime->vote_program.withdraw.vote_lockout_mem
      );
      if( FD_UNLIKELY( rc ) ) return rc;
    }
  } else {
    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L892-L895 */
    ulong min_rent_exempt_balance = fd_rent_exempt_minimum_balance( rent_sysvar, fd_borrowed_account_get_data_len( vote_account ) );
    if( FD_UNLIKELY( remaining_balance<min_rent_exempt_balance ) ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L898 */
  rc = fd_borrowed_account_checked_sub_lamports( vote_account, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L899 */
  fd_borrowed_account_drop( vote_account );

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L900 */
  fd_guarded_borrowed_account_t to = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, to_account_index, &to );

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L901 */
  rc = fd_borrowed_account_checked_add_lamports( &to, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L638-L651 */
static int
process_vote_unfiltered( fd_exec_instr_ctx_t *       ctx,
                         fd_vote_state_versioned_t * versioned,
                         ulong *                     vote_slots,
                         fd_vote_t const *           vote,
                         fd_slot_hash_t const *      slot_hashes, /* deque */
                         ulong                       epoch,
                         ulong                       current_slot ) {
  int rc;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L770
  rc = check_slots_are_valid( ctx, versioned, vote_slots, &vote->hash, slot_hashes );
  if( FD_UNLIKELY( rc ) ) return rc;
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote_slots );
       !deq_ulong_iter_done( vote_slots, iter );
       iter = deq_ulong_iter_next( vote_slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote_slots, iter );
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L772
    fd_vsv_process_next_vote_slot( versioned, *ele, epoch, current_slot );
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L783
static int
process_vote( fd_exec_instr_ctx_t *       ctx,
              fd_vote_state_versioned_t * versioned,
              fd_vote_t const *           vote,
              fd_slot_hash_t const *      slot_hashes, /* deque */
              ulong                       epoch,
              ulong                       current_slot ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L792
  if( FD_UNLIKELY( deq_ulong_empty( vote->slots ) ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L795
  ulong earliest_slot_in_history = 0;
  if( FD_UNLIKELY( !deq_fd_slot_hash_t_empty( slot_hashes ) ) ) {
    earliest_slot_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes )->slot;
  }

  /* We know that the size of the vote_slots is bounded by the number of
     slots that can fit inside of an instruction.  A very loose bound is
     assuming that the entire transaction is just filled with a vote
     slot deque (1232 bytes per transaction/8 bytes per slot) == 154
     slots.  The footprint of a deque is as follows:
     fd_ulong_align_up( fd_ulong_align_up( 32UL, alignof(DEQUE_T) ) + sizeof(DEQUE_T)*max, alignof(DEQUE_(private_t)) );
     So, the footprint in our case is:
     fd_ulong_align_up( fd_ulong_align_up( 32UL, alignof(ulong) ) + sizeof(ulong)*154, alignof(DEQUE_(private_t)) );
     Which is equal to
     fd_ulong_align_up( 32UL + 154 * 8UL, 8UL ) = 1264UL; */
  #define VOTE_SLOTS_MAX             (FD_TXN_MTU/sizeof(ulong))
  #define VOTE_SLOTS_DEQUE_FOOTPRINT (1264UL )
  #define VOTE_SLOTS_DEQUE_ALIGN     (8UL)
  FD_TEST( deq_ulong_footprint( VOTE_SLOTS_MAX ) == VOTE_SLOTS_DEQUE_FOOTPRINT );
  FD_TEST( deq_ulong_align()                     == 8UL );
  FD_TEST( deq_ulong_cnt( vote->slots )          <= VOTE_SLOTS_MAX );
  uchar * vote_slots_mem[ VOTE_SLOTS_DEQUE_FOOTPRINT ] __attribute__((aligned(VOTE_SLOTS_DEQUE_ALIGN)));

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L796
  ulong * vote_slots = deq_ulong_join( deq_ulong_new( vote_slots_mem, deq_ulong_cnt( vote->slots ) ) );
  for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
       !deq_ulong_iter_done( vote->slots, iter );
       iter = deq_ulong_iter_next( vote->slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
    if( FD_UNLIKELY( *ele >= earliest_slot_in_history ) ) {
      vote_slots = deq_ulong_push_tail_wrap( vote_slots, *ele );
    }
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L802
  if( FD_UNLIKELY( deq_ulong_cnt( vote_slots ) == 0 ) ) {
    ctx->txn_out->err.custom_err = FD_VOTE_ERR_VOTES_TOO_OLD_ALL_FILTERED;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L805
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

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L905-L926 */
static int
initialize_account( fd_exec_instr_ctx_t *         ctx,
                    fd_borrowed_account_t *       vote_account,
                    int                           target_version,
                    fd_vote_init_t *              vote_init,
                    fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                    fd_sol_sysvar_clock_t const * clock ) {
  int rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L915 */
  rc = check_vote_account_length( vote_account, target_version );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L916 */
  rc = fd_vsv_get_state( vote_account->meta, ctx->runtime->vote_program.init_account.vote_state_mem );
  if( FD_UNLIKELY( rc ) ) return rc;
  fd_vote_state_versioned_t * versioned = (fd_vote_state_versioned_t *)ctx->runtime->vote_program.init_account.vote_state_mem;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L918-L920 */
  if( FD_UNLIKELY( !fd_vsv_is_uninitialized( versioned ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L923 */
  rc = fd_vote_verify_authorized_signer( &vote_init->node_pubkey, signers );
  if( FD_UNLIKELY( rc ) ) {
    return rc;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L925 */
  return init_vote_account_state( ctx, vote_account, versioned, target_version, vote_init, clock );
}

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L928-L953 */
static int
process_vote_with_account( fd_exec_instr_ctx_t *         ctx,
                           fd_borrowed_account_t *       vote_account,
                           int                           target_version,
                           fd_slot_hash_t const *        slot_hashes, /* deque */
                           fd_sol_sysvar_clock_t const * clock,
                           fd_vote_t *                   vote,
                           fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX] ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L936-L939 */
  int rc = get_vote_state_handler_checked(
      vote_account,
      target_version,
      1,
      ctx->runtime->vote_program.process_vote.vote_state_mem,
      ctx->runtime->vote_program.process_vote.authorized_voters_mem,
      ctx->runtime->vote_program.process_vote.landed_votes_mem
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_vote_state_versioned_t * versioned = (fd_vote_state_versioned_t *)ctx->runtime->vote_program.process_vote.vote_state_mem;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L941 */
  fd_pubkey_t * authorized_voter = NULL;
  rc = fd_authorized_voters_get_and_update_authorized_voter( versioned, clock->epoch, &authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L942 */
  rc = fd_vote_verify_authorized_signer( authorized_voter, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L944 */
  rc = process_vote( ctx, versioned, vote, slot_hashes, clock->epoch, clock->slot );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L945-L951 */
  if( FD_LIKELY( vote->has_timestamp ) ) {
    /* Calling max() on an empty iterator returns None */
    if( FD_UNLIKELY( deq_ulong_cnt( vote->slots )==0 ) ) {
      ctx->txn_out->err.custom_err = FD_VOTE_ERR_EMPTY_SLOTS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L948 */
    ulong max = 0UL;
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
                                !deq_ulong_iter_done( vote->slots, iter );
                          iter = deq_ulong_iter_next( vote->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
      max         = fd_ulong_max( max, *ele );
    }

    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L950 */
    rc = fd_vsv_process_timestamp( ctx, versioned, max, vote->timestamp );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L952 */
  return fd_vsv_set_vote_account_state(
      ctx,
      vote_account,
      versioned,
      ctx->runtime->vote_program.process_vote.vote_lockout_mem
  );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1156
static int
do_process_vote_state_update( fd_exec_instr_ctx_t *       ctx,
                              fd_vote_state_versioned_t * versioned,
                              fd_slot_hash_t const *      slot_hashes, /* deque */
                              ulong                       epoch,
                              ulong                       slot,
                              fd_vote_state_update_t *    vote_state_update ) {
  int rc;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1164
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

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1177
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

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1171
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

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L955-L979 */
static int
process_vote_state_update( fd_exec_instr_ctx_t *         ctx,
                           fd_borrowed_account_t *       vote_account,
                           int                           target_version,
                           fd_slot_hash_t const *        slot_hashes,
                           fd_sol_sysvar_clock_t const * clock,
                           fd_vote_state_update_t *      vote_state_update,
                           fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX] ) {

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L963-L966 */
  int rc = get_vote_state_handler_checked(
      vote_account,
      target_version,
      1,
      ctx->runtime->vote_program.process_vote.vote_state_mem,
      ctx->runtime->vote_program.process_vote.authorized_voters_mem,
      ctx->runtime->vote_program.process_vote.landed_votes_mem
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_vote_state_versioned_t * versioned = (fd_vote_state_versioned_t *)ctx->runtime->vote_program.process_vote.vote_state_mem;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L968 */
  fd_pubkey_t * authorized_voter = NULL;
  rc = fd_authorized_voters_get_and_update_authorized_voter( versioned, clock->epoch, &authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L969 */
  rc = fd_vote_verify_authorized_signer( authorized_voter, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L971-L977 */
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

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L978 */
  return fd_vsv_set_vote_account_state(
      ctx,
      vote_account,
      versioned,
      ctx->runtime->vote_program.process_vote.vote_lockout_mem
  );
}

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1035-L1061 */
static int
do_process_tower_sync( fd_exec_instr_ctx_t *       ctx,
                       fd_vote_state_versioned_t * versioned,
                       fd_slot_hash_t const *      slot_hashes, /* deque */
                       ulong                       epoch,
                       ulong                       slot,
                       fd_tower_sync_t *           tower_sync ) {

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1042-L1048 */
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

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1049-L1060 */
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

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1009-L1033 */
static int
process_tower_sync( fd_exec_instr_ctx_t *         ctx,
                    fd_borrowed_account_t *       vote_account,
                    int                           target_version,
                    fd_slot_hash_t const *        slot_hashes, /* deque */
                    fd_sol_sysvar_clock_t const * clock,
                    fd_tower_sync_t *             tower_sync,
                    fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX] ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1017-L1020 */
  int rc = get_vote_state_handler_checked(
     vote_account,
     target_version,
     1,
     ctx->runtime->vote_program.tower_sync.vote_state_mem,
     ctx->runtime->vote_program.tower_sync.authorized_voters_mem,
     ctx->runtime->vote_program.tower_sync.vote_state_landed_votes_mem
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_vote_state_versioned_t * versioned = (fd_vote_state_versioned_t *)ctx->runtime->vote_program.tower_sync.vote_state_mem;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1022 */
  fd_pubkey_t * authorized_voter = NULL;
  rc = fd_authorized_voters_get_and_update_authorized_voter( versioned, clock->epoch, &authorized_voter );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1023 */
  rc = fd_vote_verify_authorized_signer( authorized_voter, signers );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1025-L1031 */
  rc = do_process_tower_sync(
      ctx,
      versioned,
      slot_hashes,
      clock->epoch,
      clock->slot,
      tower_sync
  );
  if( FD_UNLIKELY( rc ) ) return rc;

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L1032 */
  return fd_vsv_set_vote_account_state(
      ctx,
      vote_account,
      versioned,
      ctx->runtime->vote_program.tower_sync.vote_lockout_mem
  );
}

/**********************************************************************/
/* FD-only encoders / decoders (doesn't map directly to Labs impl)    */
/**********************************************************************/

int
fd_vote_decode_compact_update( fd_compact_vote_state_update_t * compact_update,
                               fd_vote_state_update_t *         vote_update,
                               fd_exec_instr_ctx_t const *      ctx ) {
  // Taken from:
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L954
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
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( vote_update->lockouts );
    fd_vote_lockout_new( elem );

    fd_lockout_offset_t * lock_offset = &compact_update->lockouts[i];

    ulong next_slot;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( slot, lock_offset->offset, &next_slot ) ) )
      return 0;

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

/* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L21-L51 */
static int
process_authorize_with_seed_instruction( /* invoke_context */
                                         fd_exec_instr_ctx_t *   ctx,
                                         int                     target_version,
                                         fd_borrowed_account_t * vote_account,
                                         fd_pubkey_t const *     new_authority,
                                         fd_vote_authorize_t     authorization_type,
                                         fd_pubkey_t const *     current_authority_derived_key_owner,
                                         uchar const *           current_authority_derived_key_seed,
                                         ulong                   current_authority_derived_key_seed_len ) {
  int rc = 0;

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L31 */
  rc = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_clock_id );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_sol_sysvar_clock_t clock_;
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
  if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  fd_pubkey_t * expected_authority_keys[FD_TXN_SIG_MAX] = { 0 };
  fd_pubkey_t   single_signer                        = { 0 };

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_processor.rs#L30-L42 */
  if( fd_instr_acc_is_signer_idx( ctx->instr, 2, &rc ) ) {

    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_processor.rs#L31 */
    fd_pubkey_t const * base_pubkey = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 2UL, &base_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_processor.rs#L34-L40 */
    expected_authority_keys[0] = &single_signer;
    rc = fd_pubkey_create_with_seed( ctx,
                                     base_pubkey->uc,
                                     (char const *)current_authority_derived_key_seed,
                                     current_authority_derived_key_seed_len,
                                     current_authority_derived_key_owner->uc,
                                     /* insert */ expected_authority_keys[0]->uc );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_processor.rs#L43-L50 */
  return authorize(
      ctx,
      vote_account,
      target_version,
      new_authority,
      authorization_type,
      (fd_pubkey_t const **)expected_authority_keys,
      clock
  );
}

/**********************************************************************/
/* Entry point for the Vote Program                                   */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L57
int
fd_vote_program_execute( fd_exec_instr_ctx_t * ctx ) {
  /* FD-specific init */
  int rc = FD_EXECUTOR_INSTR_SUCCESS;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L57
  FD_EXEC_CU_UPDATE( ctx, DEFAULT_COMPUTE_UNITS );

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_processor.rs#L64-L67 */
  fd_guarded_borrowed_account_t me = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &me );
  if( FD_UNLIKELY( !fd_pubkey_eq( fd_borrowed_account_get_owner( &me ), &fd_solana_vote_program_id ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_processor.rs#L69-L74 */
  int target_version = FD_FEATURE_ACTIVE_BANK( ctx->bank, vote_state_v4 ) ? VOTE_STATE_TARGET_VERSION_V4 : VOTE_STATE_TARGET_VERSION_V3;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L69
  fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = { 0 };
  fd_exec_instr_ctx_get_signers( ctx, signers );

  uchar __attribute__((aligned(alignof(fd_vote_instruction_t)))) vote_instruction_mem[ FD_VOTE_INSTRUCTION_FOOTPRINT ];
  fd_vote_instruction_t * instruction = fd_bincode_decode_static_limited_deserialize(
      vote_instruction,
      vote_instruction_mem,
      ctx->instr->data,
      ctx->instr->data_sz,
      FD_TXN_MTU,
      NULL );
  if( FD_UNLIKELY( !instruction ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* PLEASE PRESERVE SWITCH-CASE ORDERING TO MIRROR LABS IMPL:
   */
  switch( instruction->discriminant ) {

  /* InitializeAccount
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L32
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L71
   */
  case fd_vote_instruction_enum_initialize_account: {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L72
    rc = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_rent_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_rent_t rent_;
    fd_rent_t const * rent = fd_sysvar_cache_rent_read( ctx->sysvar_cache, &rent_ );
    if( FD_UNLIKELY( !rent ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    if( FD_UNLIKELY( fd_borrowed_account_get_lamports( &me ) <
                     fd_rent_exempt_minimum_balance( rent, fd_borrowed_account_get_data_len( &me ) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L76
    rc = fd_sysvar_instr_acct_check( ctx, 2, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L78
    rc = initialize_account( ctx, &me, target_version, &instruction->inner.initialize_account, signers, clock );

    break;
  }

  /* Authorize
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L40
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L86
   *
   * Notes:
   * - Up to two signers: the vote authority and the authorized withdrawer.
   */
  case fd_vote_instruction_enum_authorize: {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L87
    rc = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L89
    fd_pubkey_t const * voter_pubkey   = &instruction->inner.authorize.pubkey;
    fd_vote_authorize_t vote_authorize = instruction->inner.authorize.vote_authorize;

    rc = authorize( ctx, &me, target_version, voter_pubkey, vote_authorize, signers, clock );

    break;
  }

  /* AuthorizeWithSeed
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L117
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L98
   */
  case fd_vote_instruction_enum_authorize_with_seed: {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L99
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 3 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L100
    fd_vote_authorize_with_seed_args_t * args = &instruction->inner.authorize_with_seed;

    rc = process_authorize_with_seed_instruction(
        ctx,
        target_version,
        &me,
        &args->new_authority,
        args->authorization_type,
        &args->current_authority_derived_key_owner,
        args->current_authority_derived_key_seed,
        args->current_authority_derived_key_seed_len
    );

    break;
  }

  /* AuthorizeCheckedWithSeed
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L131
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L111
   */
  case fd_vote_instruction_enum_authorize_checked_with_seed: {
    fd_vote_authorize_checked_with_seed_args_t const * args =
        &instruction->inner.authorize_checked_with_seed;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L112
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 4 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.1.14/programs/vote/src/vote_processor.rs#L99-L100
    fd_pubkey_t const * new_authority = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 3UL, &new_authority );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L116
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 3, &rc ) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v3.0.3/transaction-context/src/lib.rs#L789 */
      if( FD_UNLIKELY( !!rc ) ) break;
      // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L117
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L119
    rc = process_authorize_with_seed_instruction(
        ctx,
        target_version,
        &me,
        new_authority,
        args->authorization_type,
        &args->current_authority_derived_key_owner,
        args->current_authority_derived_key_seed,
        args->current_authority_derived_key_seed_len );

    break;
  }

  /* UpdateValidatorIdentity
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L65
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L130
   */
  case fd_vote_instruction_enum_update_validator_identity: {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L131
    if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.1.14/programs/vote/src/vote_processor.rs#L118-L120
    fd_pubkey_t const * node_pubkey = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 1UL, &node_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L135
    rc = update_validator_identity( ctx, target_version, &me, node_pubkey, signers );

    break;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L142
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

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L145
    rc = update_commission(
        ctx,
        target_version,
        &me,
        instruction->inner.update_commission,
        signers,
        epoch_schedule,
        clock
    );

    break;
  }

  /* Vote
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L49
   */
  case fd_vote_instruction_enum_vote:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* VoteSwitch
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L81
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L154
   */
  case fd_vote_instruction_enum_vote_switch: {
    if( FD_FEATURE_ACTIVE_BANK( ctx->bank, deprecate_legacy_vote_ixs ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_vote_t * vote;
    if( instruction->discriminant == fd_vote_instruction_enum_vote ) {
      vote = &instruction->inner.vote;
    } else if( instruction->discriminant == fd_vote_instruction_enum_vote_switch ) {
      vote = &instruction->inner.vote_switch.vote;
    } else {
      FD_LOG_CRIT(( "unsupported instruction discriminant: %u", instruction->discriminant ));
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L155
    int err;
    err = fd_sysvar_instr_acct_check( ctx, 1, &fd_sysvar_slot_hashes_id );
    if( FD_UNLIKELY( err ) ) return err;

    if( FD_UNLIKELY( !fd_sysvar_cache_slot_hashes_is_valid( ctx->sysvar_cache ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L157
    err = fd_sysvar_instr_acct_check( ctx, 2, &fd_sysvar_clock_id );
    if( FD_UNLIKELY( err ) ) return err;
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    fd_slot_hash_t const * slot_hashes = fd_sysvar_cache_slot_hashes_join_const( ctx->sysvar_cache ); /* guaranteed to succeed */
    rc = process_vote_with_account(
        ctx,
        &me,
        target_version,
        slot_hashes,
        clock,
        vote,
        signers
    );
    fd_sysvar_cache_slot_hashes_leave_const( ctx->sysvar_cache, slot_hashes );

    break;
  }

  /* UpdateVoteState
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L100
   */
  case fd_vote_instruction_enum_update_vote_state:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* UpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L107
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L169
   */
  case fd_vote_instruction_enum_update_vote_state_switch: {
    if( FD_FEATURE_ACTIVE_BANK( ctx->bank, deprecate_legacy_vote_ixs ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_vote_state_update_t * vote_state_update;
    switch( instruction->discriminant ) {
    case fd_vote_instruction_enum_update_vote_state:
      vote_state_update = &instruction->inner.update_vote_state;
      break;
    case fd_vote_instruction_enum_update_vote_state_switch:
      vote_state_update = &instruction->inner.update_vote_state_switch.vote_state_update;
      break;
    default:
      FD_LOG_CRIT(( "unsupported instruction discriminant: %u", instruction->discriminant ));
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L171
    if( FD_LIKELY( !fd_sysvar_cache_slot_hashes_is_valid( ctx->sysvar_cache ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L172
    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L173
    fd_slot_hash_t const * slot_hashes = fd_sysvar_cache_slot_hashes_join_const( ctx->sysvar_cache );
    rc = process_vote_state_update(
        ctx,
        &me,
        target_version,
        slot_hashes,
        clock,
        vote_state_update,
        signers
    );
    fd_sysvar_cache_slot_hashes_leave_const( ctx->sysvar_cache, slot_hashes );

    break;
  }

  /* CompactUpdateVoteState
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L139
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
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L146
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L183
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state_switch: {
    /* https://github.com/anza-xyz/agave/blob/dc4b9dcbbf859ff48f40d00db824bde063fdafcc/programs/vote/src/vote_processor.rs#L183-L191 */
    if( FD_FEATURE_ACTIVE_BANK( ctx->bank, deprecate_legacy_vote_ixs ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    fd_compact_vote_state_update_t * vote_state_update = NULL;
    if( instruction->discriminant == fd_vote_instruction_enum_compact_update_vote_state ) {
      vote_state_update = &instruction->inner.compact_update_vote_state;
    } else if( instruction->discriminant ==
               fd_vote_instruction_enum_compact_update_vote_state_switch ) {
      vote_state_update =
          &instruction->inner.compact_update_vote_state_switch.compact_vote_state_update;
    }

    fd_vote_state_update_t vote_update;
    fd_vote_state_update_new( &vote_update );
    if( FD_UNLIKELY( !fd_vote_decode_compact_update( vote_state_update, &vote_update, ctx ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L185
    if( FD_LIKELY( !fd_sysvar_cache_slot_hashes_is_valid( ctx->sysvar_cache ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L187
    fd_slot_hash_t const * slot_hashes = fd_sysvar_cache_slot_hashes_join_const( ctx->sysvar_cache ); /* guaranteed to succeed */
    rc = process_vote_state_update(
        ctx,
        &me,
        target_version,
        slot_hashes,
        clock,
        &vote_update,
        signers
    );
    fd_sysvar_cache_slot_hashes_leave_const( ctx->sysvar_cache, slot_hashes );

    break;
  }

  /* TowerSync(Switch)
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L151-L157
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L196-L215
   */

  case fd_vote_instruction_enum_tower_sync:
  case fd_vote_instruction_enum_tower_sync_switch: {
    fd_tower_sync_t * tower_sync = (instruction->discriminant == fd_vote_instruction_enum_tower_sync)
        ? &instruction->inner.tower_sync
        : &instruction->inner.tower_sync_switch.tower_sync;

    if( FD_LIKELY( !fd_sysvar_cache_slot_hashes_is_valid( ctx->sysvar_cache ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    fd_sol_sysvar_clock_t clock_;
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
    if( FD_UNLIKELY( !clock ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    fd_slot_hash_t const * slot_hashes = fd_sysvar_cache_slot_hashes_join_const( ctx->sysvar_cache );
    FD_TEST( slot_hashes );
    rc = process_tower_sync(
        ctx,
        &me,
        target_version,
        slot_hashes,
        clock,
        tower_sync,
        signers
    );
    fd_sysvar_cache_slot_hashes_leave_const( ctx->sysvar_cache, slot_hashes );

    break;
  }

  /* Withdraw
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L57
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L216
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

    rc = withdraw(
        ctx,
        &me,
        target_version,
        instruction->inner.withdraw,
        1UL,
        signers,
        rent_sysvar,
        clock_sysvar
    );

    break;
  }

  /* AuthorizeChecked
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/instruction.rs#L93
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L234
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

    // https://github.com/anza-xyz/agave/blob/v2.1.14/programs/vote/src/vote_processor.rs#L243-L245
    fd_pubkey_t const * voter_pubkey = NULL;
    rc = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 3UL, &voter_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L239
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 3, &rc ) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v3.0.3/transaction-context/src/lib.rs#L789 */
      if( FD_UNLIKELY( !!rc ) ) break;

      rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L242
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
        instruction->inner.authorize_checked,
        signers,
        clock
    );
    break;
  }

  default:
    FD_LOG_CRIT(( "unsupported vote instruction: %u", instruction->discriminant ));
  }

  return rc;
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

/* TODO: Old code, remove whenever stake program gets cleaned up */
void
fd_vote_convert_to_current( fd_vote_state_versioned_t * self,
                            uchar *                     authorized_voters_mem,
                            uchar *                     landed_votes_mem ) {
  fd_vsv_try_convert_to_v3( self, authorized_voters_mem, landed_votes_mem );
}

fd_vote_state_versioned_t *
fd_vote_get_state( fd_account_meta_t const * self,
                   uchar *                   mem ) {
  int err = fd_vsv_get_state( self, mem );
  return err ? NULL : (fd_vote_state_versioned_t *)mem;
}
