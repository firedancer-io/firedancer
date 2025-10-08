#include "fd_sysvar.h"
#include "fd_sysvar_clock.h"
#include "fd_sysvar_epoch_schedule.h"
#include "fd_sysvar_rent.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L14 */
#define MAX_ALLOWABLE_DRIFT_FAST ( 25 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L16 */
#define MAX_ALLOWABLE_DRIFT_SLOW ( 150 )

/* Do all intermediate calculations at nanosecond precision, to mirror Solana's behaviour. */
#define NS_IN_S ((long)1e9)

/* The target tick duration, derived from the target tick rate.
 https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/poh_config.rs#L32
  */
#define DEFAULT_TARGET_TICK_DURATION_NS ( NS_IN_S / FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK )

/* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2110-L2117 */
static inline long
unix_timestamp_from_genesis( fd_bank_t * bank ) {
  /* TODO: genesis_creation_time needs to be a long in the bank. */
  return fd_long_sat_add(
      (long)fd_bank_genesis_creation_time_get( bank ),
      (long)( fd_uint128_sat_mul( fd_bank_slot_get( bank ), fd_bank_ns_per_slot_get( bank ) ) / NS_IN_S ) );
}

void
fd_sysvar_clock_write( fd_bank_t *               bank,
                       fd_funk_t *               funk,
                       fd_funk_txn_xid_t const * xid,
                       fd_capture_ctx_t *        capture_ctx,
                       fd_sol_sysvar_clock_t *   clock ) {
  ulong sz = fd_sol_sysvar_clock_size( clock );
  uchar enc[sz];
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if( fd_sol_sysvar_clock_encode( clock, &ctx ) )
    FD_LOG_ERR(("fd_sol_sysvar_clock_encode failed"));

  fd_sysvar_account_update( bank, funk, xid, capture_ctx, &fd_sysvar_clock_id, enc, sz );
}


fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_funk_t *               funk,
                      fd_funk_txn_xid_t const * xid,
                      fd_sol_sysvar_clock_t *   clock ) {
  FD_TXN_ACCOUNT_DECL( acc );
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
      &err );
}

void
fd_sysvar_clock_init( fd_bank_t *               bank,
                      fd_funk_t *               funk,
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
  fd_sysvar_clock_write( bank, funk, xid, capture_ctx, &clock );
}

#define CIDX_T ulong
#define VAL_T  long
struct stake_ts_ele {
  CIDX_T parent_cidx;
  CIDX_T left_cidx;
  CIDX_T right_cidx;
  CIDX_T prio_cidx;
  VAL_T timestamp;
  uint128 stake;
};

typedef struct stake_ts_ele stake_ts_ele_t;

#define POOL_NAME  stake_ts_pool
#define POOL_T     stake_ts_ele_t
#define POOL_IDX_T CIDX_T
#define POOL_NEXT  parent_cidx
#include "../../../util/tmpl/fd_pool.c"

FD_FN_CONST static inline int valcmp (VAL_T a, VAL_T b) {
  int val = (a < b) ? -1 : 1;
  return (a == b) ? 0 : val;
}

#define TREAP_NAME       stake_ts_treap
#define TREAP_T          stake_ts_ele_t
#define TREAP_QUERY_T    VAL_T
#define TREAP_CMP(q,e)   valcmp(q, e->timestamp)
#define TREAP_LT(e0,e1)  (((VAL_T)((e0)->timestamp)) < ((VAL_T)((e1)->timestamp)))
#define TREAP_IDX_T      CIDX_T
#define TREAP_PARENT     parent_cidx
#define TREAP_LEFT       left_cidx
#define TREAP_RIGHT      right_cidx
#define TREAP_PRIO       prio_cidx
#define TREAP_IMPL_STYLE 0
#include "../../../util/tmpl/fd_treap.c"

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
                        uchar *                 pool_mem ) {

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong                       slot_duration  = (ulong)fd_bank_ns_per_slot_get( bank );
  ulong                       current_slot   = fd_bank_slot_get( bank );

  /* Set up a temporary treap, pool, and rng (required for treap prio).
     This is to establish a mapping between each vote timestamp and the
     amount of stake associated with each timestamp. */
  stake_ts_treap_t   _treap[1];
  stake_ts_treap_t * treap   = stake_ts_treap_join( stake_ts_treap_new( _treap, FD_RUNTIME_MAX_VOTE_ACCOUNTS ) );
  stake_ts_ele_t *   pool    = stake_ts_pool_join( stake_ts_pool_new( pool_mem, FD_RUNTIME_MAX_VOTE_ACCOUNTS ) );
  uint               txn_cnt = (uint)fd_bank_transaction_count_get( bank );

  fd_rng_t           _rng[1];
  fd_rng_t *         rng     = fd_rng_join( fd_rng_new( _rng, txn_cnt, 0UL ) );

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L41 */
  uint128 total_stake = 0UL;

  /* A timestamp estimate is calculated at every slot using the most
     recent vote states of voting validators. This estimated is based on
     a stake weighted median using the stake as of the end of epoch E-2
     if we are currently in epoch E. We do not count vote accounts that
     have not voted in an epoch's worth of slots (432k). */
  fd_vote_states_t const * vote_states           = fd_bank_vote_states_locking_query( bank );
  fd_vote_states_t const * vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_query( bank );

  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
       !fd_vote_states_iter_done( iter );
       fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state      = fd_vote_states_iter_ele( iter );
    fd_vote_state_ele_t const * vote_state_prev = fd_vote_states_query_const( vote_states_prev_prev, &vote_state->vote_account );
    if( !vote_state_prev ) {
      /* Don't count vote accounts that didn't have stake at the end of
         epoch E-2. */
      continue;
    }
    ulong vote_stake     = vote_state_prev->stake;
    ulong vote_timestamp = (ulong)vote_state->last_vote_timestamp;
    ulong vote_slot      = vote_state->last_vote_slot;

    /* https://github.com/anza-xyz/agave/blob/v3.0.0/runtime/src/bank.rs#L2445 */
    ulong slot_delta;
    int err = fd_ulong_checked_sub( current_slot, vote_slot, &slot_delta );
    if( FD_UNLIKELY( err ) ) {
      continue;
    }

    /* Don't count vote accounts that haven't voted in the past 432k
       slots (length of an epoch).
       https://github.com/anza-xyz/agave/blob/v3.0.0/runtime/src/bank.rs#L2446-L2447 */
    if( slot_delta>epoch_schedule->slots_per_epoch ) {
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L44-L45 */
    ulong offset   = fd_ulong_sat_mul(slot_duration, slot_delta);
    long  estimate = (long)vote_timestamp + (long)(offset / NS_IN_S);

    /* Get the vote account stake and upsert it to the treap.
       https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L46-L53 */
    ulong treap_idx = stake_ts_treap_idx_query( treap, estimate, pool );
    if ( FD_LIKELY( treap_idx < ULONG_MAX ) ) {
      pool[ treap_idx ].stake += vote_stake;
    } else {
      if( FD_UNLIKELY( stake_ts_pool_free( pool )==0UL ) ){
        FD_LOG_ERR(( "stake_ts_pool is empty" ));
      }
      ulong idx = stake_ts_pool_idx_acquire( pool );
      pool[ idx ].prio_cidx = fd_rng_ulong( rng );
      pool[ idx ].timestamp = estimate;
      pool[ idx ].stake     = vote_stake;
      stake_ts_treap_idx_insert( treap, idx, pool );
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L54 */
    total_stake += vote_stake;
  }
  fd_bank_vote_states_end_locking_query( bank );
  fd_bank_vote_states_prev_prev_end_locking_query( bank );

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L56-L58 */
  if( FD_UNLIKELY( total_stake==0UL ) ) {
    return 0L;
  }

  /* Populate estimate with the stake-weighted median timestamp.
     https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L59-L68 */
  uint128 stake_accumulator = 0;
  long    estimate          = 0L;
  for( stake_ts_treap_fwd_iter_t iter = stake_ts_treap_fwd_iter_init( treap, pool );
       !stake_ts_treap_fwd_iter_done( iter );
       iter = stake_ts_treap_fwd_iter_next( iter, pool ) ) {
    ulong idx         = stake_ts_treap_fwd_iter_idx( iter );
    stake_accumulator = fd_uint128_sat_add( stake_accumulator, pool[ idx ].stake );
    if( stake_accumulator>(total_stake/2UL) ) {
      estimate = pool[ idx ].timestamp;
      break;
    }
  }

  FD_LOG_DEBUG(( "stake weighted timestamp: %ld total stake %lu", estimate, (ulong)total_stake ));

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
  ulong max_allowable_drift_fast = fd_ulong_sat_mul( poh_estimate_offset, MAX_ALLOWABLE_DRIFT_FAST ) / 100UL;
  ulong max_allowable_drift_slow = fd_ulong_sat_mul( poh_estimate_offset, MAX_ALLOWABLE_DRIFT_SLOW ) / 100UL;
  FD_LOG_DEBUG(( "poh offset %lu estimate %lu fast %lu slow %lu", poh_estimate_offset, estimate_offset, max_allowable_drift_fast, max_allowable_drift_slow ));

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/stake_weighted_timestamp.rs#L82-L98 */
  if( estimate_offset>poh_estimate_offset && fd_ulong_sat_sub(estimate_offset, poh_estimate_offset)>max_allowable_drift_slow ) {
    estimate = fd_long_sat_add(
        epoch_start_timestamp,
        fd_long_sat_add( (long)poh_estimate_offset / NS_IN_S, (long)max_allowable_drift_slow / NS_IN_S ) );
  } else if( estimate_offset<poh_estimate_offset && fd_ulong_sat_sub(poh_estimate_offset, estimate_offset)>max_allowable_drift_fast ) {
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
                        fd_funk_t *               funk,
                        fd_funk_txn_xid_t const * xid,
                        fd_capture_ctx_t *        capture_ctx,
                        uchar *                   ts_pool_mem,
                        ulong const *             parent_epoch ) {
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
  long timestamp_estimate = get_timestamp_estimate( bank, clock, ts_pool_mem );

  /* If the timestamp was successfully calculated, use it. It not keep the old one. */
  if( FD_LIKELY( timestamp_estimate!=0L ) ) {
    unix_timestamp = timestamp_estimate;

    /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2180-L2182 */
    if( timestamp_estimate<ancestor_timestamp ) {
      unix_timestamp = ancestor_timestamp;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank.rs#L2191-L2197 */
  long epoch_start_timestamp = ( parent_epoch!=NULL && *parent_epoch!=current_epoch ) ?
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
  fd_sysvar_clock_write( bank, funk, xid, capture_ctx, clock );
}
