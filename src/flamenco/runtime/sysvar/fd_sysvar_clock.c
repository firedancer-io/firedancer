#include "fd_sysvar.h"
#include "fd_sysvar_clock.h"
#include "fd_sysvar_epoch_schedule.h"
#include "../fd_runtime_stack.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../program/fd_program_util.h"
#include "../../accdb/fd_accdb_impl_v1.h"

/* Syvar Clock Possible Values:
  slot:
  [0, ULONG_MAX]

  epoch:
  [0, slot/432000UL]

  epoch_start_timestamp:
  [0, ULONG_MAX]

  unix_timestamp:
  This value is bounded by the slot distance from the
  epoch_start_timestamp.
  The protocol allows for a maximum drift (either fast or slow) from the
  start of the epoch's timestamp.  The expected time is called the PoH
  offset.  This offset is calculated by (epoch_start_timestamp + slots
  since epoch * slot_duration). The drift is then bounded by the
  max_allowable_drift_{slow,fast}.  The stake weighted offset can be
  150% more than the PoH offset and 25% less than the PoH offset.
  So, the bounds for the unix_timestamp can be calculated by:
  upper bound = epoch_start_timestamp + (slots since epoch * slot_duration) * 2.5
  lower bound = epoch_start_timestamp + (slots since epoch * slot_duration) * 0.75

  leader_schedule_epoch:
  This is the value of the epoch used for the leader schedule.  It is
  computed based on the values of the epoch schedule (first_normal_slot,
  leader_schedule_slot_offset, slots_per_epoch).  It is always equal to
  ((slot - first_normal_slot) + leader_schedule_slot_offset) / schedule->slots_per_epoch
*/

/* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L14 */
#define MAX_ALLOWABLE_DRIFT_FAST_PERCENT ( 25U )

/* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L15 */
#define MAX_ALLOWABLE_DRIFT_SLOW_PERCENT ( 150U )

/* Do all intermediate calculations at nanosecond precision, to mirror
   Solana's behavior. */
#define NS_IN_S ((long)1e9)

/* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamps.rs#L2110-L2117 */
static inline long
unix_timestamp_from_genesis( fd_bank_t * bank ) {
  /* TODO: genesis_creation_time needs to be a long in the bank. */
  return fd_long_sat_add(
      (long)fd_bank_genesis_creation_time_get( bank ),
      (long)( fd_uint128_sat_mul( fd_bank_slot_get( bank ), fd_bank_ns_per_slot_get( bank ).ud ) / NS_IN_S ) );
}

void
fd_sysvar_clock_write( fd_bank_t *               bank,
                       fd_accdb_user_t *         accdb,
                       fd_funk_txn_xid_t const * xid,
                       fd_capture_ctx_t *        capture_ctx,
                       fd_sol_sysvar_clock_t *   clock ) {
  uchar enc[ sizeof(fd_sol_sysvar_clock_t) ];
  fd_bincode_encode_ctx_t ctx = {
    .data    = enc,
    .dataend = enc + sizeof(fd_sol_sysvar_clock_t),
  };
  if( FD_UNLIKELY( fd_sol_sysvar_clock_encode( clock, &ctx ) ) ) {
    FD_LOG_ERR(( "fd_sol_sysvar_clock_encode failed" ));
  }

  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_clock_id, enc, sizeof(fd_sol_sysvar_clock_t) );
}


fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_funk_t *               funk,
                      fd_funk_txn_xid_t const * xid,
                      fd_sol_sysvar_clock_t *   clock ) {
  fd_txn_account_t acc[1];
  int rc = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_clock_id, funk, xid );
  if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS ) ) {
    return NULL;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( fd_txn_account_get_lamports( acc )==0UL ) ) {
    return NULL;
  }

  return fd_bincode_decode_static(
      sol_sysvar_clock, clock,
      fd_txn_account_get_data( acc ),
      fd_txn_account_get_data_len( acc ),
      NULL );
}

void
fd_sysvar_clock_init( fd_bank_t *               bank,
                      fd_accdb_user_t *         accdb,
                      fd_funk_txn_xid_t const * xid,
                      fd_capture_ctx_t *        capture_ctx ) {
  long timestamp = unix_timestamp_from_genesis( bank );

  fd_sol_sysvar_clock_t clock = {
    .slot                  = fd_bank_slot_get( bank ),
    .epoch                 = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 1,
    .unix_timestamp        = timestamp,
  };
  fd_sysvar_clock_write( bank, accdb, xid, capture_ctx, &clock );
}

#define SORT_NAME  sort_stake_ts
#define SORT_KEY_T ts_est_ele_t
#define SORT_BEFORE(a,b) ( (a).timestamp < (b).timestamp )
#include "../../../util/tmpl/fd_sort.c"

/* get_timestamp_estimate calculates a timestamp estimate.  Does not
   modify the slot context.  Walks all cached vote accounts (from the
   "bank") and calculates a unix timestamp estimate. Returns the
   timestamp estimate.  spad is used for scratch allocations (allocates
   a treap of size FD_SYSVAR_CLOCK_STAKE_WEIGHTS_MAX). Crashes the
   process with FD_LOG_ERR on failure (e.g. too many vote accounts).

  https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2563-L2601 */
long
get_timestamp_estimate( fd_bank_t *             bank,
                        fd_sol_sysvar_clock_t * clock,
                        fd_runtime_stack_t *    runtime_stack ) {
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong                       slot_duration  = fd_bank_ns_per_slot_get( bank ).ul[0];
  ulong                       current_slot   = fd_bank_slot_get( bank );

  ts_est_ele_t * ts_eles = runtime_stack->clock_ts.staked_ts;
  ulong ts_ele_cnt = 0UL;

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L41 */
  uint128 total_stake = 0UL;

  /* A timestamp estimate is calculated at every slot using the most
     recent vote states of voting validators. This estimated is based on
     a stake weighted median using the stake as of the end of epoch E-2
     if we are currently in epoch E. We do not count vote accounts that
     have not voted in an epoch's worth of slots (432k). */
  fd_vote_states_t const * vote_states = fd_bank_vote_states_locking_query( bank );

  FD_TEST( fd_vote_states_cnt( vote_states )<=FD_RUNTIME_MAX_VOTE_ACCOUNTS );

  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
       !fd_vote_states_iter_done( iter );
       fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );

    /* https://github.com/anza-xyz/agave/blob/v3.0.0/runtime/src/bank.rs#L2445 */
    ulong slot_delta;
    int err = fd_ulong_checked_sub( current_slot, vote_state->last_vote_slot, &slot_delta );
    if( FD_UNLIKELY( err ) ) {
      /* Don't count vote accounts with a last vote slot that is greater
         than the current slot. */
      continue;
    }

    if( FD_UNLIKELY( !vote_state->stake_t_2 ) ) {
      /* Don't count vote accounts that didn't have stake at the end of
         epoch E-2. */
      continue;
    }

    /* Don't count vote accounts that haven't voted in the past 432k
       slots (length of an epoch).
       https://github.com/anza-xyz/agave/blob/v3.0.0/runtime/src/bank.rs#L2446-L2447 */
    if( FD_UNLIKELY( slot_delta>epoch_schedule->slots_per_epoch ) ) {
      continue;
    }

    /* Calculate the timestamp estimate by taking the last vote
       timestamp and adding the estimated time since the last vote
       (delta from last vote slot to current slot * slot duration).
       https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L44-L45 */
    ulong offset   = fd_ulong_sat_mul( slot_duration, slot_delta );
    long  estimate = vote_state->last_vote_timestamp + (long)(offset / NS_IN_S);

    /* For each timestamp, accumulate the stake from E-2.  If the entry
       for the timestamp doesn't exist yet, insert it.  Otherwise,
       update the existing entry.
       https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L46-L53 */
    ts_eles[ ts_ele_cnt ] = (ts_est_ele_t){
      .timestamp = estimate,
      .stake     = { .ud=vote_state->stake_t_2 },
    };
    ts_ele_cnt++;

    /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L54 */
    total_stake += vote_state->stake_t_2;
  }
  fd_bank_vote_states_end_locking_query( bank );

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L56-L58 */
  if( FD_UNLIKELY( total_stake==0UL ) ) {
    return 0L;
  }

  sort_stake_ts_inplace( ts_eles, ts_ele_cnt );

  /* Populate estimate with the stake-weighted median timestamp.
     https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L59-L68 */
  uint128 stake_accumulator = 0;
  long    estimate          = 0L;
  for( ulong i=0UL; i<ts_ele_cnt; i++ ) {
    stake_accumulator = fd_uint128_sat_add( stake_accumulator, ts_eles[i].stake.ud );
    if( stake_accumulator>(total_stake/2UL) ) {
      estimate = ts_eles[ i ].timestamp;
      break;
    }
  }

  int const fix_estimate_into_u64 = FD_FEATURE_ACTIVE_BANK( bank, warp_timestamp_again );

  /* Bound estimate by `max_allowable_drift` since the start of the epoch
     https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L69-L99 */
  ulong epoch_start_slot      = fd_epoch_slot0( epoch_schedule, clock->epoch );
  long  epoch_start_timestamp = clock->epoch_start_timestamp;

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L71-L72 */
  ulong poh_estimate_offset = fd_ulong_sat_mul( slot_duration, fd_ulong_sat_sub( current_slot, epoch_start_slot ) );

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L73-L77 */
  ulong estimate_offset;
  if( fix_estimate_into_u64 ) {
    estimate_offset = fd_ulong_sat_mul( NS_IN_S, fd_ulong_sat_sub( (ulong)estimate, (ulong)epoch_start_timestamp ) );
  } else {
    estimate_offset = fd_ulong_sat_mul( NS_IN_S, (ulong)fd_long_sat_sub( estimate, epoch_start_timestamp ) );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L78-L81 */
  ulong max_allowable_drift_fast = fd_ulong_sat_mul( poh_estimate_offset, MAX_ALLOWABLE_DRIFT_FAST_PERCENT ) / 100UL;
  ulong max_allowable_drift_slow = fd_ulong_sat_mul( poh_estimate_offset, MAX_ALLOWABLE_DRIFT_SLOW_PERCENT ) / 100UL;

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L82-L98 */
  if( estimate_offset>poh_estimate_offset && fd_ulong_sat_sub( estimate_offset, poh_estimate_offset )>max_allowable_drift_slow ) {
    estimate = fd_long_sat_add(
        epoch_start_timestamp,
        fd_long_sat_add( (long)poh_estimate_offset / NS_IN_S, (long)max_allowable_drift_slow / NS_IN_S ) );
  } else if( estimate_offset<poh_estimate_offset && fd_ulong_sat_sub( poh_estimate_offset, estimate_offset )>max_allowable_drift_fast ) {
    estimate = fd_long_sat_sub(
        fd_long_sat_add( epoch_start_timestamp, (long)poh_estimate_offset / NS_IN_S ),
        (long)max_allowable_drift_fast / NS_IN_S );
  }

  return estimate;
}

/* TODO: This function should be called from genesis bootup as well with
   parent_epoch = NULL
   https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2158-L2215 */
void
fd_sysvar_clock_update( fd_bank_t *               bank,
                        fd_accdb_user_t *         accdb,
                        fd_funk_txn_xid_t const * xid,
                        fd_capture_ctx_t *        capture_ctx,
                        fd_runtime_stack_t *      runtime_stack,
                        ulong const *             parent_epoch ) {
  fd_funk_t * funk = fd_accdb_user_v1_funk( accdb );
  fd_sol_sysvar_clock_t clock_[1];
  fd_sol_sysvar_clock_t * clock = fd_sysvar_clock_read( funk, xid, clock_ );
  if( FD_UNLIKELY( !clock ) ) FD_LOG_ERR(( "fd_sysvar_clock_read failed" ));

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong                       current_slot   = fd_bank_slot_get( bank );
  ulong                       current_epoch  = fd_slot_to_epoch( epoch_schedule, current_slot, NULL );

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2159 */
  long unix_timestamp = clock->unix_timestamp;

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2175 */
  long ancestor_timestamp = clock->unix_timestamp;

  /* TODO: Are we handling slot 0 correctly?
     https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2176-L2183 */
  long timestamp_estimate = get_timestamp_estimate( bank, clock, runtime_stack );

  /* If the timestamp was successfully calculated, use it. It not keep the old one. */
  if( FD_LIKELY( timestamp_estimate!=0L ) ) {
    unix_timestamp = timestamp_estimate;

    /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2180-L2182 */
    if( timestamp_estimate<ancestor_timestamp ) {
      unix_timestamp = ancestor_timestamp;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2191-L2197 */
  long epoch_start_timestamp = (parent_epoch!=NULL && *parent_epoch!=current_epoch) ?
      unix_timestamp :
      clock->epoch_start_timestamp;

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2198-L2201 */
  if( FD_UNLIKELY( current_slot==0UL ) ) {
    long timestamp_from_genesis = unix_timestamp_from_genesis( bank );
    unix_timestamp              = timestamp_from_genesis;
    epoch_start_timestamp       = timestamp_from_genesis;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2202-L2208 */
  *clock = (fd_sol_sysvar_clock_t){
    .slot                  = current_slot,
    .epoch_start_timestamp = epoch_start_timestamp,
    .epoch                 = current_epoch,
    .leader_schedule_epoch = fd_slot_to_leader_schedule_epoch( epoch_schedule, current_slot ),
    .unix_timestamp        = unix_timestamp,
  };

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2209-L2214 */
  fd_sysvar_clock_write( bank, accdb, xid, capture_ctx, clock );
}
