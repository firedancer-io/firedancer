#include "fd_sysvar_clock.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"


#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L14 */
#define MAX_ALLOWABLE_DRIFT_FAST ( 25 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L16 */
#define MAX_ALLOWABLE_DRIFT_SLOW ( 150 )

/* Do all intermediate calculations at nanosecond precision, to mirror Solana's behaviour. */
#define NS_IN_S ( 1000000000 )

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
#define DEFAULT_TICKS_PER_SECOND ( 160 )

/* The target tick duration, derived from the target tick rate.
 https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/poh_config.rs#L32
  */
#define DEFAULT_TARGET_TICK_DURATION_NS ( NS_IN_S / DEFAULT_TICKS_PER_SECOND )

/* Calculates the target duration of a slot, in nanoseconds.
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/src/genesis_config.rs#L222

   ticks_per_slot is found in the genesis block. The default value is 64, for a target slot duration of 400ms:
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L22
*/
uint128 ns_per_slot( ulong ticks_per_slot ) {
  return DEFAULT_TARGET_TICK_DURATION_NS * ticks_per_slot;
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2200 */
long timestamp_from_genesis( fd_global_ctx_t* global ) {
  /* TODO: maybe make types of timestamps the same throughout the runtime codebase. as Solana uses a signed representation */
  return (long)(global->bank.genesis_creation_time + ( ( global->bank.slot * ns_per_slot( global->bank.ticks_per_slot ) ) / NS_IN_S ) );
}

void write_clock( fd_global_ctx_t* global, fd_sol_sysvar_clock_t* clock ) {
  ulong          sz = fd_sol_sysvar_clock_size( clock );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_sol_sysvar_clock_encode( clock, &ctx ) )
    FD_LOG_ERR(("fd_sol_sysvar_clock_encode failed"));

  fd_sysvar_set( global, global->sysvar_owner, (fd_pubkey_t *) global->sysvar_clock, enc, sz, global->bank.slot );
}

int fd_sysvar_clock_read( fd_global_ctx_t* global, fd_sol_sysvar_clock_t* result ) {
  int err = 0;
  char * raw_acc_data = (char*) fd_acc_mgr_view_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_clock, NULL, &err);
  if (NULL == raw_acc_data)
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data + m->hlen;
  ctx.dataend = (char *) ctx.data + m->dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;

  return fd_sol_sysvar_clock_decode( result, &ctx );
}

void fd_sysvar_clock_init( fd_global_ctx_t* global ) {
  long timestamp = timestamp_from_genesis( global );

  fd_sol_sysvar_clock_t clock = {
    .slot = global->bank.slot,
    .epoch = 0,
    .epoch_start_timestamp = timestamp,
    .leader_schedule_epoch = 1,
    .unix_timestamp = timestamp,
  };
  write_clock( global, &clock );
}

/* Bounds the timestamp estimate by the max allowable drift from the expected PoH slot duration.

https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L67 */
long bound_timestamp_estimate( fd_global_ctx_t* global, long estimate, long epoch_start_timestamp ) {

  /* Determine offsets from start of epoch */
  /* TODO: handle epoch boundary case */
  uint128 poh_estimate_offset = ns_per_slot( global->bank.ticks_per_slot ) * global->bank.slot;
  uint128 estimate_offset = (uint128)( ( estimate - epoch_start_timestamp ) * NS_IN_S );

  uint128 max_delta_fast = ( poh_estimate_offset * MAX_ALLOWABLE_DRIFT_FAST ) / 100;
  uint128 max_delta_slow = ( poh_estimate_offset * MAX_ALLOWABLE_DRIFT_SLOW ) / 100;

  if ( ( estimate_offset > poh_estimate_offset ) && ( ( estimate_offset - poh_estimate_offset ) > max_delta_slow ) ) {
    return epoch_start_timestamp + (long)( poh_estimate_offset / NS_IN_S ) + (long)( max_delta_slow / NS_IN_S );
  } else if ( ( estimate_offset < poh_estimate_offset ) && ( ( poh_estimate_offset - estimate_offset ) > max_delta_fast ) ) {
    return epoch_start_timestamp + (long)( poh_estimate_offset / NS_IN_S ) + (long)( max_delta_fast / NS_IN_S );
  }

  return estimate;
}

/* Estimates the current timestamp, using the stake-weighted median of the latest validator timestamp oracle votes received
   from each voting node:
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2927

   Linear interpolation, using the target duration of a slot, is used to calculate the timestamp estimate for the current slot:

    timestamp = (stake-weighted median of vote timestamps) + ((target slot duration) * (slots since median timestamp vote was received))
 */
long estimate_timestamp( fd_global_ctx_t* global, uint128 ns_per_slot ) {
  /* TODO: bound the estimate to ensure it stays within a certain range of the expected PoH clock:
  https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L13 */

  fd_clock_timestamp_vote_t_mapnode_t * votes = global->bank.timestamp_votes.votes_root;
  if ( NULL == votes )
    return timestamp_from_genesis( global );

  /* TODO: actually take the stake-weighted median. For now, just use the root node. */
  fd_clock_timestamp_vote_t * head = &votes->elem;
  ulong slots = global->bank.slot - head->slot;
  uint128 ns_correction = ns_per_slot * slots;
  return head->timestamp  + (long) (ns_correction / NS_IN_S) ;
}

int fd_sysvar_clock_update( fd_global_ctx_t* global ) {
  fd_sol_sysvar_clock_t clock;

  int err = 0;
  fd_funk_rec_t const *con_rec = NULL;
  char * raw_acc_data = (char*) fd_acc_mgr_view_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_clock, &con_rec, &err);
  if (NULL == raw_acc_data)
    return err;  // This should be a trap
  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data + m->hlen;
  ctx.dataend = (char *) ctx.data + m->dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;

  if ( fd_sol_sysvar_clock_decode( &clock, &ctx ) )
    FD_LOG_ERR(("fd_sol_sysvar_clock_decode failed"));

  long timestamp_estimate         = estimate_timestamp( global, ns_per_slot( global->bank.ticks_per_slot ) );
  long bounded_timestamp_estimate = bound_timestamp_estimate( global, timestamp_estimate, clock.epoch_start_timestamp );
  if ( timestamp_estimate != bounded_timestamp_estimate ) {
    FD_LOG_INFO(( "corrected timestamp_estimate %ld to %ld", timestamp_estimate, bounded_timestamp_estimate ));
  }
  clock.slot                      = global->bank.slot;
  clock.unix_timestamp            = bounded_timestamp_estimate;

  FD_LOG_INFO(( "Updated clock at slot %lu", global->bank.slot ));
  FD_LOG_INFO(( "clock.slot: %lu", clock.slot ));
  FD_LOG_INFO(( "clock.epoch_start_timestamp: %ld", clock.epoch_start_timestamp ));
  FD_LOG_INFO(( "clock.epoch: %lu", clock.epoch ));
  FD_LOG_INFO(( "clock.leader_schedule_epoch: %lu", clock.leader_schedule_epoch ));
  FD_LOG_INFO(( "clock.unix_timestamp: %ld", clock.unix_timestamp ));

  ulong sz = fd_sol_sysvar_clock_size(&clock);
  ulong acc_sz = sizeof(fd_account_meta_t) + sz;
  fd_funk_rec_t * acc_data_rec = NULL;

  err = 0;
  raw_acc_data = fd_acc_mgr_modify_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *)  global->sysvar_clock, 1, &acc_sz, con_rec, &acc_data_rec, &err);
  if ( FD_UNLIKELY (NULL == raw_acc_data) )
    return err;

  m = (fd_account_meta_t *)raw_acc_data;

  fd_bincode_encode_ctx_t e_ctx;
  e_ctx.data = raw_acc_data + m->hlen;
  e_ctx.dataend = (char*)e_ctx.data + sz;
  if ( fd_sol_sysvar_clock_encode( &clock, &e_ctx ) )
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  ulong lamps = (sz + 128) * ((ulong) ((double)global->bank.rent.lamports_per_uint8_year * global->bank.rent.exemption_threshold));
  if (m->info.lamports < lamps)
    m->info.lamports = lamps;

  m->dlen = sz;
  fd_memcpy(m->info.owner, global->sysvar_owner, 32);

  err = fd_acc_mgr_commit_data(global->acc_mgr, acc_data_rec, (fd_pubkey_t *) global->sysvar_slot_history, raw_acc_data, global->bank.slot, 0);

  fd_bincode_destroy_ctx_t ctx_d;
  ctx_d.freef = global->freef;
  ctx_d.freef_arg = global->allocf_arg;
  fd_sol_sysvar_clock_destroy( &clock, &ctx_d );

  return err;
}

  /* Slot of next epoch boundary */
//  ulong epoch           = fd_slot_to_epoch( &schedule, state->global->bank.slot+1, NULL );
//  ulong last_epoch_slot = fd_epoch_slot0  ( &schedule, epoch+1UL );



#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1024UL)
static uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

void fd_calculate_stake_weighted_timestamp(
  fd_global_ctx_t* global,
  fd_clock_timestamp_votes_t *unique_timestamps,
  ulong slot_duration,
  long * result_timestamp,
  uint max_allowable_drift_fast,
  uint max_allowable_drift_slow,
  ushort fix_estimate_into_u64
 ) {

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( global, &clock );
  // get the unique timestamps
  /* stake per timestamp */
  treap_t _treap[1];
  void * shmem = (void *)_treap;
  void * shtreap = treap_new( shmem, 64UL );
  treap_t * treap = treap_join( shtreap );
  ele_t * pool = pool_join( pool_new( scratch, 64UL ) );
  ulong total_stake = 0;

  for ( fd_clock_timestamp_vote_t_mapnode_t* n = fd_clock_timestamp_vote_t_map_minimum(unique_timestamps->votes_pool, unique_timestamps->votes_root); n; n = fd_clock_timestamp_vote_t_map_successor(unique_timestamps->votes_pool, n) ) {
    long estimate = n->elem.timestamp + ((long)clock.slot - (long)n->elem.slot) * (long)slot_duration;
    FD_LOG_NOTICE(("estimate = %lu", estimate));
    /* get stake */
    fd_stake_state_t stake_state;
    int result = read_stake_state(global, &n->elem.pubkey, &stake_state);
    ulong stake_weight = (result != FD_EXECUTOR_INSTR_SUCCESS) ? 0 : stake_state.inner.stake.stake.delegation.stake;
    total_stake += stake_weight;
    ulong idx = pool_idx_acquire( pool );
    pool[ idx ].timestamp = estimate;
    pool[ idx ].stake = stake_weight;
    treap_idx_insert( treap, idx, pool );
  }
  if (total_stake == 0) {
    result_timestamp = NULL;
    return;
  }
  ulong stake_accumulator = 0;
  *result_timestamp = 0;

  for (treap_fwd_iter_t iter = treap_fwd_iter_init ( treap, pool);
       !treap_fwd_iter_done( iter );
       iter = treap_fwd_iter_next( iter, pool ) ) {
    ulong idx = treap_fwd_iter_idx( iter );
    stake_accumulator += pool[ idx ].stake;
    if (stake_accumulator > total_stake / 2) {
      *result_timestamp = pool[ idx ].timestamp;
      break;
    }
  }
  // Bound estimate by `max_allowable_drift` since the start of the epoch
  fd_epoch_schedule_t schedule;
  fd_sysvar_epoch_schedule_read( global, &schedule );
  ulong epoch_start_slot = fd_epoch_slot0( &schedule, clock.epoch );
  ulong poh_estimate_offset = fd_ulong_sat_mul(slot_duration, fd_ulong_sat_sub(clock.slot, epoch_start_slot));
  ulong estimate_offset = fd_ulong_sat_mul(NS_IN_S, (fix_estimate_into_u64) ? fd_ulong_sat_sub((ulong)*result_timestamp, (ulong)clock.epoch_start_timestamp) : (ulong)(*result_timestamp - clock.epoch_start_timestamp));
  ulong max_delta_fast = fd_ulong_sat_mul(poh_estimate_offset, max_allowable_drift_fast) / 100;
  ulong max_delta_slow = fd_ulong_sat_mul(poh_estimate_offset, max_allowable_drift_slow) / 100;

  if (estimate_offset > poh_estimate_offset && fd_ulong_sat_sub(estimate_offset, poh_estimate_offset) > max_delta_slow) {
    *result_timestamp = clock.epoch_start_timestamp + (long)poh_estimate_offset / NS_IN_S + (long)max_delta_slow / NS_IN_S;
  } else if (estimate_offset < poh_estimate_offset && fd_ulong_sat_sub(poh_estimate_offset, estimate_offset) > max_delta_fast) {
    *result_timestamp = clock.epoch_start_timestamp + (long)poh_estimate_offset / NS_IN_S - (long)max_delta_fast / NS_IN_S;
  }
  return;
 }


//    fn get_timestamp_estimate(
//        &self,
//        max_allowable_drift: MaxAllowableDrift,
//        epoch_start_timestamp: Option<(Slot, UnixTimestamp)>,
//    ) -> Option<UnixTimestamp> {
//        let mut get_timestamp_estimate_time = Measure::start("get_timestamp_estimate");
//        let slots_per_epoch = self.epoch_schedule().slots_per_epoch;
//        let vote_accounts = self.vote_accounts();
//        let recent_timestamps = vote_accounts.iter().filter_map(|(pubkey, (_, account))| {
//            let vote_state = account.vote_state();
//            let vote_state = vote_state.as_ref().ok()?;
//            let slot_delta = self.slot().checked_sub(vote_state.last_timestamp.slot)?;
//            (slot_delta <= slots_per_epoch).then(|| {
//                (
//                    *pubkey,
//                    (
//                        vote_state.last_timestamp.slot,
//                        vote_state.last_timestamp.timestamp,
//                    ),
//                )
//            })
//        });
//        let slot_duration = Duration::from_nanos(self.ns_per_slot as u64);
//        let epoch = self.epoch_schedule().get_epoch(self.slot());
//        let stakes = self.epoch_vote_accounts(epoch)?;
//        let stake_weighted_timestamp = calculate_stake_weighted_timestamp(
//            recent_timestamps,
//            stakes,
//            self.slot(),
//            slot_duration,
//            epoch_start_timestamp,
//            max_allowable_drift,
//            self.feature_set
//                .is_active(&feature_set::warp_timestamp_again::id()),
//        );
//        get_timestamp_estimate_time.stop();
//        datapoint_info!(
//            "bank-timestamp",
//            (
//                "get_timestamp_estimate_us",
//                get_timestamp_estimate_time.as_us(),
//                i64
//            ),
//        );
//        stake_weighted_timestamp
//    }
