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

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2200 */
static long
timestamp_from_genesis( fd_bank_t * bank ) {
  /* TODO: maybe make types of timestamps the same throughout the runtime codebase. as Solana uses a signed representation */

  return (long)(fd_bank_genesis_creation_time_get( bank ) + ((fd_bank_slot_get( bank ) * fd_bank_ns_per_slot_get( bank )) / NS_IN_S));
}

void
fd_sysvar_clock_write( fd_exec_slot_ctx_t *    slot_ctx,
                       fd_sol_sysvar_clock_t * clock ) {
  ulong sz = fd_sol_sysvar_clock_size( clock );
  uchar enc[sz];
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if( fd_sol_sysvar_clock_encode( clock, &ctx ) )
    FD_LOG_ERR(("fd_sol_sysvar_clock_encode failed"));

  fd_sysvar_account_update( slot_ctx, &fd_sysvar_clock_id, enc, sz );
}


fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_funk_t *             funk,
                      fd_funk_txn_t *         funk_txn,
                      fd_sol_sysvar_clock_t * clock ) {
  FD_TXN_ACCOUNT_DECL( acc );
  int rc = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_clock_id, funk, funk_txn );
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
fd_sysvar_clock_init( fd_exec_slot_ctx_t * slot_ctx ) {
  long timestamp = timestamp_from_genesis( slot_ctx->bank );

  fd_sol_sysvar_clock_t clock = {
    .slot                  = fd_bank_slot_get( slot_ctx->bank ),
    .epoch                 = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 1,
    .unix_timestamp        = timestamp,
  };
  fd_sysvar_clock_write( slot_ctx, &clock );
}

/* Bounds the timestamp estimate by the max allowable drift from the expected PoH slot duration.

https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L67 */
static long
bound_timestamp_estimate( fd_bank_t * bank,
                          long        estimate,
                          long        epoch_start_timestamp ) {

  /* Determine offsets from start of epoch */
  /* TODO: handle epoch boundary case */
  uint128 poh_estimate_offset = fd_bank_ns_per_slot_get( bank ) * fd_bank_slot_get( bank );
  uint128 estimate_offset = (uint128)( ( estimate - epoch_start_timestamp ) * NS_IN_S );

  uint128 max_delta_fast = ( poh_estimate_offset * MAX_ALLOWABLE_DRIFT_FAST ) / 100;
  uint128 max_delta_slow = ( poh_estimate_offset * MAX_ALLOWABLE_DRIFT_SLOW ) / 100;

  if ( ( estimate_offset > poh_estimate_offset ) && ( ( estimate_offset - poh_estimate_offset ) > max_delta_slow ) ) {
    return epoch_start_timestamp + (long)( poh_estimate_offset / NS_IN_S ) + (long)( max_delta_slow / NS_IN_S );
  } else if ( ( estimate_offset < poh_estimate_offset ) && ( ( poh_estimate_offset - estimate_offset ) > max_delta_fast ) ) {
    return epoch_start_timestamp + (long)( poh_estimate_offset / NS_IN_S ) - (long)( max_delta_fast / NS_IN_S );
  }

  return estimate;
}

/* Estimates the current timestamp, using the stake-weighted median of the latest validator timestamp oracle votes received
   from each voting node:
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2927

   Linear interpolation, using the target duration of a slot, is used to calculate the timestamp estimate for the current slot:

    timestamp = (stake-weighted median of vote timestamps) + ((target slot duration) * (slots since median timestamp vote was received))
 */
static long
estimate_timestamp( fd_bank_t * bank ) {
  /* TODO: bound the estimate to ensure it stays within a certain range of the expected PoH clock:
  https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L13 */

  fd_clock_timestamp_votes_global_t const * clock_timestamp_votes = fd_bank_clock_timestamp_votes_locking_query( bank );
  fd_clock_timestamp_vote_t_mapnode_t *     votes                  = !!clock_timestamp_votes ? fd_clock_timestamp_votes_votes_root_join( clock_timestamp_votes ) : NULL;
  if( NULL==votes ) {
    fd_bank_clock_timestamp_votes_end_locking_query( bank );
    return timestamp_from_genesis( bank );
  }

  /* TODO: actually take the stake-weighted median. For now, just use the root node. */
  fd_clock_timestamp_vote_t * head          = &votes->elem;
  ulong                       slots         = fd_bank_slot_get( bank ) - head->slot;
  uint128                     ns_correction = fd_bank_ns_per_slot_get( bank ) * slots;
  fd_bank_clock_timestamp_votes_end_locking_query( bank );
  return head->timestamp  + (long) (ns_correction / NS_IN_S) ;
}

#define CIDX_T ulong
#define VAL_T  long
struct stake_ts_ele {
  CIDX_T parent_cidx;
  CIDX_T left_cidx;
  CIDX_T right_cidx;
  CIDX_T prio_cidx;
  VAL_T timestamp;
  unsigned long stake;
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

/* https://github.com/solana-labs/solana/blob/c091fd3da8014c0ef83b626318018f238f506435/runtime/src/bank.rs#L3600 */
void
fd_calculate_stake_weighted_timestamp( fd_exec_slot_ctx_t * slot_ctx,
                                       long *               result_timestamp,
                                       fd_spad_t *          spad ) {

  fd_sol_sysvar_clock_t clock_[1];
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_clock_read( slot_ctx->funk, slot_ctx->funk_txn, clock_ );
  if( FD_UNLIKELY( !clock ) ) FD_LOG_ERR(( "fd_sysvar_clock_read failed" ));

  fd_bank_t * bank = slot_ctx->bank;
  FD_SPAD_FRAME_BEGIN( spad ) {

  ulong slot_duration = (ulong)fd_bank_ns_per_slot_get( bank );
  // get the unique timestamps
  /* stake per timestamp */

  /* Set up a temporary treap, pool, and rng (required for treap prio) */
  /* FIXME: Hardcoded constant */
  stake_ts_treap_t   _treap[1];
  stake_ts_treap_t * treap    = stake_ts_treap_join( stake_ts_treap_new( _treap, 10240UL ) );
  uchar *            pool_mem = fd_spad_alloc( spad, stake_ts_pool_align(), stake_ts_pool_footprint( 10240UL ) );
  stake_ts_ele_t *   pool     = stake_ts_pool_join( stake_ts_pool_new( pool_mem, 10240UL ) );
  uint               txn_cnt  = (uint)fd_bank_transaction_count_get( bank );

  fd_rng_t           _rng[1];
  fd_rng_t *         rng      = fd_rng_join( fd_rng_new( _rng, txn_cnt, 0UL ) );

  ulong total_stake = 0;

  fd_clock_timestamp_votes_global_t const * clock_timestamp_votes = fd_bank_clock_timestamp_votes_locking_query( bank );
  if( FD_UNLIKELY( !clock_timestamp_votes ) ) {
    fd_bank_clock_timestamp_votes_end_locking_query( bank );
    *result_timestamp = 0;
    return;
  }

  fd_clock_timestamp_vote_t_mapnode_t *      timestamp_votes_pool = fd_clock_timestamp_votes_votes_pool_join( clock_timestamp_votes );
  fd_clock_timestamp_vote_t_mapnode_t *      timestamp_votes_root = fd_clock_timestamp_votes_votes_root_join( clock_timestamp_votes );

  fd_vote_accounts_global_t const *          epoch_stakes  = fd_bank_epoch_stakes_locking_query( bank );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_acc_pool = fd_vote_accounts_vote_accounts_pool_join( epoch_stakes );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_acc_root = fd_vote_accounts_vote_accounts_root_join( epoch_stakes );

  for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum(vote_acc_pool, vote_acc_root);
       n;
       n = fd_vote_accounts_pair_global_t_map_successor( vote_acc_pool, n ) ) {

    /* get timestamp */
    fd_pubkey_t const * vote_pubkey = &n->elem.key;

    if( timestamp_votes_pool == NULL ) {
      continue;
    } else {
      fd_clock_timestamp_vote_t_mapnode_t query_vote_acc_node;
      query_vote_acc_node.elem.pubkey = *vote_pubkey;
      fd_clock_timestamp_vote_t_mapnode_t * vote_acc_node = fd_clock_timestamp_vote_t_map_find( timestamp_votes_pool,
                                                                                                timestamp_votes_root,
                                                                                                &query_vote_acc_node );
      ulong vote_timestamp = 0;
      ulong vote_slot = 0;
      if( vote_acc_node == NULL ) {
        int err;

        uchar * data     = fd_solana_account_data_join( &n->elem.value );
        ulong   data_len = n->elem.value.data_len;

        FD_SPAD_FRAME_BEGIN( spad ) {
          fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
              vote_state_versioned, spad,
              data,
              data_len,
              &err );
          if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
            FD_LOG_WARNING(( "Vote state versioned decode failed" ));
            continue;
          }

          switch( vsv->discriminant ) {
          case fd_vote_state_versioned_enum_v0_23_5:
            vote_timestamp = (ulong)vsv->inner.v0_23_5.last_timestamp.timestamp;
            vote_slot = vsv->inner.v0_23_5.last_timestamp.slot;
            break;
          case fd_vote_state_versioned_enum_v1_14_11:
            vote_timestamp = (ulong)vsv->inner.v1_14_11.last_timestamp.timestamp;
            vote_slot = vsv->inner.v1_14_11.last_timestamp.slot;
            break;
          case fd_vote_state_versioned_enum_current:
            vote_timestamp = (ulong)vsv->inner.current.last_timestamp.timestamp;
            vote_slot = vsv->inner.current.last_timestamp.slot;
            break;
          default:
            __builtin_unreachable();
          }
        }
        FD_SPAD_FRAME_END;

      } else {
        vote_timestamp = (ulong)vote_acc_node->elem.timestamp;
        vote_slot = vote_acc_node->elem.slot;
      }

      ulong slot_delta = fd_ulong_sat_sub(fd_bank_slot_get( bank ), vote_slot);
      fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
      if( slot_delta > epoch_schedule->slots_per_epoch ) {
        continue;
      }

      ulong offset   = fd_ulong_sat_mul(slot_duration, slot_delta);
      long  estimate = (long)vote_timestamp + (long)(offset / NS_IN_S);
      /* get stake */
      total_stake += n->elem.stake;
      ulong treap_idx = stake_ts_treap_idx_query( treap, estimate, pool );
      if ( FD_LIKELY( treap_idx < ULONG_MAX ) ) {
        pool[ treap_idx ].stake += n->elem.stake;
      } else {
        if( 0 == stake_ts_pool_free( pool ) ) {
          FD_LOG_ERR(( "stake_ts_pool is empty" ));
        }
        ulong idx = stake_ts_pool_idx_acquire( pool );
        pool[ idx ].prio_cidx = fd_rng_ulong( rng );
        pool[ idx ].timestamp = estimate;
        pool[ idx ].stake     = n->elem.stake;
        stake_ts_treap_idx_insert( treap, idx, pool );
      }
    }
  }
  fd_bank_epoch_stakes_end_locking_query( bank );
  fd_bank_clock_timestamp_votes_end_locking_query( bank );

  *result_timestamp = 0;
  if( total_stake == 0 ) {
    return;
  }

  // FIXME: this should be a uint128
  ulong stake_accumulator = 0;
  for( stake_ts_treap_fwd_iter_t iter = stake_ts_treap_fwd_iter_init( treap, pool );
       !stake_ts_treap_fwd_iter_done( iter );
       iter = stake_ts_treap_fwd_iter_next( iter, pool ) ) {
    ulong idx         = stake_ts_treap_fwd_iter_idx( iter );
    stake_accumulator = fd_ulong_sat_add(stake_accumulator, pool[ idx ].stake);
    if( stake_accumulator > (total_stake / 2) ) {
      *result_timestamp = pool[ idx ].timestamp;
      break;
    }
  }

  FD_LOG_DEBUG(( "stake weighted timestamp: %ld total stake %lu", *result_timestamp, total_stake ));

  int const fix_estimate_into_u64 = FD_FEATURE_ACTIVE_BANK( bank, warp_timestamp_again );

  // Bound estimate by `max_allowable_drift` since the start of the epoch
  fd_epoch_schedule_t const * epoch_schedule   = fd_bank_epoch_schedule_query( bank );
  ulong                       epoch_start_slot = fd_epoch_slot0( epoch_schedule, clock->epoch );
  FD_LOG_DEBUG(( "Epoch start slot %lu", epoch_start_slot ));
  ulong poh_estimate_offset = fd_ulong_sat_mul( slot_duration, fd_ulong_sat_sub( fd_bank_slot_get( bank ), epoch_start_slot ) );
  ulong estimate_offset     = fd_ulong_sat_mul( NS_IN_S, (fix_estimate_into_u64) ? fd_ulong_sat_sub( (ulong)*result_timestamp, (ulong)clock->epoch_start_timestamp ) : (ulong)(*result_timestamp - clock->epoch_start_timestamp));
  ulong max_delta_fast      = fd_ulong_sat_mul( poh_estimate_offset, MAX_ALLOWABLE_DRIFT_FAST ) / 100;
  ulong max_delta_slow      = fd_ulong_sat_mul( poh_estimate_offset, MAX_ALLOWABLE_DRIFT_SLOW ) / 100;
  FD_LOG_DEBUG(( "poh offset %lu estimate %lu fast %lu slow %lu", poh_estimate_offset, estimate_offset, max_delta_fast, max_delta_slow ));
  if( estimate_offset > poh_estimate_offset && fd_ulong_sat_sub(estimate_offset, poh_estimate_offset) > max_delta_slow ) {
    *result_timestamp = clock->epoch_start_timestamp + (long)poh_estimate_offset / NS_IN_S + (long)max_delta_slow / NS_IN_S;
  } else if( estimate_offset < poh_estimate_offset && fd_ulong_sat_sub(poh_estimate_offset, estimate_offset) > max_delta_fast ) {
    *result_timestamp = clock->epoch_start_timestamp + (long)poh_estimate_offset / NS_IN_S - (long)max_delta_fast / NS_IN_S;
  }

  if (*result_timestamp < clock->unix_timestamp) {
    FD_LOG_DEBUG(( "updated timestamp to ancestor" ));
    *result_timestamp = clock->unix_timestamp;
  }
  return;

  } FD_SPAD_FRAME_END;
}

void
fd_sysvar_clock_update( fd_exec_slot_ctx_t * slot_ctx,
                        fd_spad_t *          spad ) {
  fd_sol_sysvar_clock_t clock_[1];
  fd_sol_sysvar_clock_t * clock = fd_sysvar_clock_read( slot_ctx->funk, slot_ctx->funk_txn, clock_ );
  if( FD_UNLIKELY( !clock ) ) FD_LOG_ERR(( "fd_sysvar_clock_read failed" ));

  long ancestor_timestamp = clock->unix_timestamp;

  fd_bank_t * bank = slot_ctx->bank;
  if( fd_bank_slot_get( bank ) != 0 ) {
    long new_timestamp = 0L;
    fd_calculate_stake_weighted_timestamp( slot_ctx, &new_timestamp, spad );

    /* If the timestamp was successfully calculated, use it. It not keep the old one.
       https://github.com/anza-xyz/agave/blob/v2.1.14/runtime/src/bank.rs#L1947-L1954 */
    if( FD_LIKELY( new_timestamp ) ) {
      clock->unix_timestamp = new_timestamp;
    }
  }

  if( FD_UNLIKELY( !clock->unix_timestamp ) ) {
    /* generate timestamp for genesis */
    long timestamp_estimate         = estimate_timestamp( bank );
    long bounded_timestamp_estimate = bound_timestamp_estimate( bank,
                                                                timestamp_estimate,
                                                                clock->epoch_start_timestamp );
    if( timestamp_estimate != bounded_timestamp_estimate ) {
      FD_LOG_INFO(( "corrected timestamp_estimate %ld to %ld", timestamp_estimate, bounded_timestamp_estimate ));
    }
    /*  if let Some(timestamp_estimate) =
            self.get_timestamp_estimate(max_allowable_drift, epoch_start_timestamp)
        {
            unix_timestamp = timestamp_estimate;
            if timestamp_estimate < ancestor_timestamp {
                unix_timestamp = ancestor_timestamp;
            }
        } */
    if( bounded_timestamp_estimate < ancestor_timestamp ) {
      FD_LOG_DEBUG(( "clock rewind detected: %ld -> %ld", ancestor_timestamp, bounded_timestamp_estimate ));
      bounded_timestamp_estimate = ancestor_timestamp;
    }
    clock->unix_timestamp = bounded_timestamp_estimate;
  }

  clock->slot = fd_bank_slot_get( bank );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );

  ulong epoch_old  = clock->epoch;
  ulong epoch_new  = fd_slot_to_epoch( epoch_schedule, clock->slot, NULL );
  clock->epoch = epoch_new;
  if( epoch_old != epoch_new ) {
    long timestamp_estimate = 0L;
    fd_calculate_stake_weighted_timestamp( slot_ctx,
                                           &timestamp_estimate,
                                           spad );
    clock->unix_timestamp        = fd_long_max( timestamp_estimate, ancestor_timestamp );
    clock->epoch_start_timestamp = clock->unix_timestamp;
    clock->leader_schedule_epoch = fd_slot_to_leader_schedule_epoch( epoch_schedule, fd_bank_slot_get( bank ) );
  }

  fd_sysvar_clock_write( slot_ctx, clock );
}
