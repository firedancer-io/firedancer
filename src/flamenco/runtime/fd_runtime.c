#include "fd_runtime.h"
#include "context/fd_capture_ctx.h"
#include "fd_acc_mgr.h"
#include "fd_bank.h"
#include "fd_runtime_err.h"
#include "fd_runtime_init.h"
#include "fd_pubkey_utils.h"

#include "fd_executor.h"
#include "fd_cost_tracker.h"
#include "fd_runtime_public.h"
#include "fd_txncache.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/bmtree/fd_bmtree.h"

#include "../stakes/fd_stakes.h"
#include "../rewards/fd_rewards.h"

#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "info/fd_microblock_batch_info.h"
#include "info/fd_microblock_info.h"

#include "program/fd_stake_program.h"
#include "program/fd_builtin_programs.h"
#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include "program/fd_bpf_program_util.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_compute_budget_program.h"
#include "program/fd_address_lookup_table_program.h"

#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_last_restart_slot.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_slot_hashes.h"
#include "sysvar/fd_sysvar_slot_history.h"

#include "tests/fd_dump_pb.h"

#include "../../ballet/nanopb/pb_decode.h"
#include "../../ballet/nanopb/pb_encode.h"
#include "../types/fd_solana_block.pb.h"

#include "fd_system_ids.h"
#include "../vm/fd_vm.h"
#include "fd_blockstore.h"
#include "../../disco/pack/fd_pack.h"
#include "../fd_rwlock.h"

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

/******************************************************************************/
/* Public Runtime Helpers                                                     */
/******************************************************************************/

/*
   https://github.com/anza-xyz/agave/blob/v2.1.1/runtime/src/bank.rs#L1254-L1258
   https://github.com/anza-xyz/agave/blob/v2.1.1/runtime/src/bank.rs#L1749
 */
int
fd_runtime_compute_max_tick_height( ulong   ticks_per_slot,
                                    ulong   slot,
                                    ulong * out_max_tick_height /* out */ ) {
  ulong max_tick_height = 0UL;
  if( FD_LIKELY( ticks_per_slot > 0UL ) ) {
    ulong next_slot = fd_ulong_sat_add( slot, 1UL );
    if( FD_UNLIKELY( next_slot == slot ) ) {
      FD_LOG_WARNING(( "max tick height addition overflowed slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
      return -1;
    }
    if( FD_UNLIKELY( ULONG_MAX / ticks_per_slot < next_slot ) ) {
      FD_LOG_WARNING(( "max tick height multiplication overflowed slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
      return -1;
    }
    max_tick_height = fd_ulong_sat_mul( next_slot, ticks_per_slot );
  }
  *out_max_tick_height = max_tick_height;
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_update_slots_per_epoch( fd_bank_t * bank,
                                   ulong       slots_per_epoch ) {
  if( FD_LIKELY( slots_per_epoch == fd_bank_slots_per_epoch_get( bank ) ) ) {
    return;
  }

  fd_bank_slots_per_epoch_set( bank, slots_per_epoch );

  fd_bank_part_width_set( bank, fd_rent_partition_width( slots_per_epoch ) );
}

void
fd_runtime_update_leaders( fd_bank_t * bank,
                           ulong       slot,
                           fd_spad_t * runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );

  FD_LOG_INFO(( "schedule->slots_per_epoch = %lu", epoch_schedule->slots_per_epoch ));
  FD_LOG_INFO(( "schedule->leader_schedule_slot_offset = %lu", epoch_schedule->leader_schedule_slot_offset ));
  FD_LOG_INFO(( "schedule->warmup = %d", epoch_schedule->warmup ));
  FD_LOG_INFO(( "schedule->first_normal_epoch = %lu", epoch_schedule->first_normal_epoch ));
  FD_LOG_INFO(( "schedule->first_normal_slot = %lu", epoch_schedule->first_normal_slot ));

  fd_vote_accounts_global_t const *          epoch_vaccs   = fd_bank_epoch_stakes_locking_query( bank );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_acc_pool = fd_vote_accounts_vote_accounts_pool_join( epoch_vaccs );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_acc_root = fd_vote_accounts_vote_accounts_root_join( epoch_vaccs );

  ulong epoch    = fd_slot_to_epoch( epoch_schedule, slot, NULL );
  ulong slot0    = fd_epoch_slot0( epoch_schedule, epoch );
  ulong slot_cnt = fd_epoch_slot_cnt( epoch_schedule, epoch );

  fd_runtime_update_slots_per_epoch( bank, fd_epoch_slot_cnt( epoch_schedule, epoch ) );

  ulong vote_acc_cnt  = fd_vote_accounts_pair_global_t_map_size( vote_acc_pool, vote_acc_root );
  fd_bank_epoch_stakes_end_locking_query( bank );

  fd_stake_weight_t * epoch_weights = fd_spad_alloc_check( runtime_spad, alignof(fd_stake_weight_t), vote_acc_cnt * sizeof(fd_stake_weight_t) );

  ulong stake_weight_cnt = fd_stake_weights_by_node( epoch_vaccs, epoch_weights, runtime_spad );

  if( FD_UNLIKELY( stake_weight_cnt == ULONG_MAX ) ) {
    FD_LOG_ERR(( "fd_stake_weights_by_node() failed" ));
  }

  /* Derive leader schedule */

  FD_LOG_INFO(( "stake_weight_cnt=%lu slot_cnt=%lu", stake_weight_cnt, slot_cnt ));
  ulong epoch_leaders_footprint = fd_epoch_leaders_footprint( stake_weight_cnt, slot_cnt );
  FD_LOG_INFO(( "epoch_leaders_footprint=%lu", epoch_leaders_footprint ));
  if( FD_LIKELY( epoch_leaders_footprint ) ) {
    if( FD_UNLIKELY( stake_weight_cnt>MAX_PUB_CNT ) ) {
      FD_LOG_ERR(( "Stake weight count exceeded max" ));
    }
    if( FD_UNLIKELY( slot_cnt>MAX_SLOTS_PER_EPOCH ) ) {
      FD_LOG_ERR(( "Slot count exceeeded max" ));
    }

    void * epoch_leaders_mem = fd_bank_epoch_leaders_locking_modify( bank );
    fd_epoch_leaders_t * leaders = fd_epoch_leaders_join( fd_epoch_leaders_new( epoch_leaders_mem,
                                                                                           epoch,
                                                                                           slot0,
                                                                                           slot_cnt,
                                                                                           stake_weight_cnt,
                                                                                           epoch_weights,
                                                                                           0UL ) );
    fd_bank_epoch_leaders_end_locking_modify( bank );
    if( FD_UNLIKELY( !leaders ) ) {
      FD_LOG_ERR(( "Unable to init and join fd_epoch_leaders" ));
    }
  }

  } FD_SPAD_FRAME_END;
}

/******************************************************************************/
/* Various Private Runtime Helpers                                            */
/******************************************************************************/

/* fee to be deposited should be > 0
   Returns 0 if validation succeeds
   Returns the amount to burn(==fee) on failure */
static ulong
fd_runtime_validate_fee_collector( fd_bank_t *              bank,
                                   fd_txn_account_t const * collector,
                                   ulong                    fee ) {
  if( FD_UNLIKELY( fee<=0UL ) ) {
    FD_LOG_ERR(( "expected fee(%lu) to be >0UL", fee ));
  }

  if( FD_UNLIKELY( memcmp( collector->vt->get_owner( collector ), fd_solana_system_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( collector->pubkey->key, _out_key );
    FD_LOG_WARNING(( "cannot pay a non-system-program owned account (%s)", _out_key ));
    return fee;
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.23/runtime/src/bank/fee_distribution.rs#L111
     https://github.com/anza-xyz/agave/blob/v1.18.23/runtime/src/accounts/account_rent_state.rs#L39
     In agave's fee deposit code, rent state transition check logic is as follows:
     The transition is NOT allowed iff
     === BEGIN
     the post deposit account is rent paying AND the pre deposit account is not rent paying
     OR
     the post deposit account is rent paying AND the pre deposit account is rent paying AND !(post_data_size == pre_data_size && post_lamports <= pre_lamports)
     === END
     post_data_size == pre_data_size is always true during fee deposit.
     However, post_lamports > pre_lamports because we are paying a >0 amount.
     So, the above reduces down to
     === BEGIN
     the post deposit account is rent paying AND the pre deposit account is not rent paying
     OR
     the post deposit account is rent paying AND the pre deposit account is rent paying AND TRUE
     === END
     This is equivalent to checking that the post deposit account is rent paying.
     An account is rent paying if the post deposit balance is >0 AND it's not rent exempt.
     We already know that the post deposit balance is >0 because we are paying a >0 amount.
     So TLDR we just check if the account is rent exempt.
   */
  fd_rent_t const * rent = fd_bank_rent_query( bank );
  ulong minbal = fd_rent_exempt_minimum_balance( rent, collector->vt->get_data_len( collector ) );
  if( FD_UNLIKELY( collector->vt->get_lamports( collector ) + fee < minbal ) ) {
    FD_BASE58_ENCODE_32_BYTES( collector->pubkey->key, _out_key );
    FD_LOG_WARNING(("cannot pay a rent paying account (%s)", _out_key ));
    return fee;
  }

  return 0UL;
}

static int
fd_runtime_run_incinerator( fd_bank_t *     bank,
                            fd_funk_t *     funk,
                            fd_funk_txn_t * funk_txn ) {
  FD_TXN_ACCOUNT_DECL( rec );

  int err = fd_txn_account_init_from_funk_mutable( rec,
                                                   &fd_sysvar_incinerator_id,
                                                   funk,
                                                   funk_txn,
                                                   0,
                                                   0UL );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    // TODO: not really an error! This is fine!
    return -1;
  }

  ulong new_capitalization = fd_ulong_sat_sub( fd_bank_capitalization_get( bank ), rec->vt->get_lamports( rec ) );
  fd_bank_capitalization_set( bank, new_capitalization );

  rec->vt->set_lamports( rec, 0UL );
  fd_txn_account_mutable_fini( rec, funk, funk_txn );

  return 0;
}

static void
fd_runtime_freeze( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {

  fd_sysvar_recent_hashes_update( slot_ctx, runtime_spad );

  ulong execution_fees = fd_bank_execution_fees_get( slot_ctx->bank );
  ulong priority_fees  = fd_bank_priority_fees_get( slot_ctx->bank );

  ulong burn = execution_fees / 2;
  ulong fees = fd_ulong_sat_add( priority_fees, execution_fees - burn );

  if( FD_LIKELY( fees ) ) {
    // Look at collect_fees... I think this was where I saw the fee payout..
    FD_TXN_ACCOUNT_DECL( rec );

    do {
      /* do_create=1 because we might wanna pay fees to a leader
         account that we've purged due to 0 balance. */

      fd_epoch_leaders_t const * leaders = fd_bank_epoch_leaders_locking_query( slot_ctx->bank );
      if( FD_UNLIKELY( !leaders ) ) {
        FD_LOG_WARNING(( "fd_runtime_freeze: leaders not found" ));
        break;
      }

      fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, slot_ctx->bank->slot );
      if( FD_UNLIKELY( !leader ) ) {
        FD_LOG_WARNING(( "fd_runtime_freeze: leader not found" ));
        break;
      }

      int err = fd_txn_account_init_from_funk_mutable( rec, leader, slot_ctx->funk, slot_ctx->funk_txn, 1, 0UL );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(("fd_runtime_freeze: fd_txn_account_init_from_funk_mutable for leader (%s) failed (%d)", FD_BASE58_ENC_32_ALLOCA( leader ), err));
        burn = fd_ulong_sat_add( burn, fees );
        break;
      }

      fd_bank_epoch_leaders_end_locking_query( slot_ctx->bank );

      if ( FD_LIKELY( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, validate_fee_collector_account ) ) ) {
        ulong _burn;
        if( FD_UNLIKELY( _burn=fd_runtime_validate_fee_collector( slot_ctx->bank, rec, fees ) ) ) {
          if( FD_UNLIKELY( _burn!=fees ) ) {
            FD_LOG_ERR(( "expected _burn(%lu)==fees(%lu)", _burn, fees ));
          }
          burn = fd_ulong_sat_add( burn, fees );
          FD_LOG_WARNING(("fd_runtime_freeze: burned %lu", fees ));
          break;
        }
      }

      /* TODO: is it ok to not check the overflow error here? */
      rec->vt->checked_add_lamports( rec, fees );
      rec->vt->set_slot( rec, slot_ctx->bank->slot );

      fd_txn_account_mutable_fini( rec, slot_ctx->funk, slot_ctx->funk_txn );

    } while(0);

    ulong old = fd_bank_capitalization_get( slot_ctx->bank );
    fd_bank_capitalization_set( slot_ctx->bank, fd_ulong_sat_sub( old, burn ) );
    FD_LOG_DEBUG(( "fd_runtime_freeze: burn %lu, capitalization %lu->%lu ", burn, old, fd_bank_capitalization_get( slot_ctx->bank ) ));

    fd_bank_execution_fees_set( slot_ctx->bank, 0UL );

    fd_bank_priority_fees_set( slot_ctx->bank, 0UL );
  }

  fd_runtime_run_incinerator( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn );

}

#define FD_RENT_EXEMPT (-1L)

static long
fd_runtime_get_rent_due( fd_epoch_schedule_t const * schedule,
                         fd_rent_t const *           rent,
                         double                      slots_per_year,
                         fd_txn_account_t *          acc,
                         ulong                       epoch ) {
  /* Nothing due if account is rent-exempt
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L90 */
  ulong min_balance = fd_rent_exempt_minimum_balance( rent, acc->vt->get_data_len( acc ) );
  if( acc->vt->get_lamports( acc )>=min_balance ) {
    return FD_RENT_EXEMPT;
  }

  /* Count the number of slots that have passed since last collection. This
     inlines the agave function get_slots_in_peohc
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L93-L98 */
  ulong slots_elapsed = 0UL;
  if( FD_UNLIKELY( acc->vt->get_rent_epoch( acc )<schedule->first_normal_epoch ) ) {
    /* Count the slots before the first normal epoch separately */
    for( ulong i=acc->vt->get_rent_epoch( acc ); i<schedule->first_normal_epoch && i<=epoch; i++ ) {
      slots_elapsed += fd_epoch_slot_cnt( schedule, i+1UL );
    }
    slots_elapsed += fd_ulong_sat_sub( epoch+1UL, schedule->first_normal_epoch ) * schedule->slots_per_epoch;
  }
  // slots_elapsed should remain 0 if rent_epoch is greater than epoch
  else if( acc->vt->get_rent_epoch( acc )<=epoch ) {
    slots_elapsed = (epoch - acc->vt->get_rent_epoch( acc ) + 1UL) * schedule->slots_per_epoch;
  }
  /* Consensus-critical use of doubles :( */

  double years_elapsed;
  if( FD_LIKELY( slots_per_year!=0.0 ) ) {
    years_elapsed = (double)slots_elapsed / slots_per_year;
  } else {
    years_elapsed = 0.0;
  }

  ulong lamports_per_year = rent->lamports_per_uint8_year * (acc->vt->get_data_len( acc ) + 128UL);
  /* https://github.com/anza-xyz/agave/blob/d2124a995f89e33c54f41da76bfd5b0bd5820898/sdk/src/rent_collector.rs#L108 */
  /* https://github.com/anza-xyz/agave/blob/d2124a995f89e33c54f41da76bfd5b0bd5820898/sdk/program/src/rent.rs#L95 */
  return (long)fd_rust_cast_double_to_ulong(years_elapsed * (double)lamports_per_year);
}

/* fd_runtime_collect_rent_from_account performs rent collection duties.
   Although the Solana runtime prevents the creation of new accounts
   that are subject to rent, some older accounts are still undergo the
   rent collection process.  Updates the account's 'rent_epoch' if
   needed. Returns the amount of rent collected. */
/* https://github.com/anza-xyz/agave/blob/v2.0.10/svm/src/account_loader.rs#L71-96 */
ulong
fd_runtime_collect_rent_from_account( fd_epoch_schedule_t const * schedule,
                                      fd_rent_t const *           rent,
                                      double                      slots_per_year,
                                      fd_txn_account_t *          acc,
                                      ulong                       epoch ) {

  if( FD_UNLIKELY( acc->vt->get_rent_epoch( acc )!=FD_RENT_EXEMPT_RENT_EPOCH &&
                     fd_runtime_get_rent_due( schedule,
                                              rent,
                                              slots_per_year,
                                              acc,
                                              epoch )==FD_RENT_EXEMPT ) ) {
      acc->vt->set_rent_epoch( acc, FD_RENT_EXEMPT_RENT_EPOCH );
  }
  return 0UL;
}

#undef FD_RENT_EXEMPT

/******************************************************************************/
/* Block-Level Execution Preparation/Finalization                             */
/******************************************************************************/

/*
https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/sdk/program/src/fee_calculator.rs#L105-L165
*/
static void
fd_runtime_new_fee_rate_governor_derived( fd_bank_t * bank,
                                          ulong       latest_singatures_per_slot ) {

  fd_fee_rate_governor_t const * base_fee_rate_governor = fd_bank_fee_rate_governor_query( bank );

  ulong old_lamports_per_signature = fd_bank_lamports_per_signature_get( bank );

  fd_fee_rate_governor_t me = {
    .target_signatures_per_slot    = base_fee_rate_governor->target_signatures_per_slot,
    .target_lamports_per_signature = base_fee_rate_governor->target_lamports_per_signature,
    .max_lamports_per_signature    = base_fee_rate_governor->max_lamports_per_signature,
    .min_lamports_per_signature    = base_fee_rate_governor->min_lamports_per_signature,
    .burn_percent                  = base_fee_rate_governor->burn_percent
  };

  ulong new_lamports_per_signature = 0;
  if( me.target_signatures_per_slot > 0 ) {
    me.min_lamports_per_signature = fd_ulong_max( 1UL, (ulong)(me.target_lamports_per_signature / 2) );
    me.max_lamports_per_signature = me.target_lamports_per_signature * 10;
    ulong desired_lamports_per_signature = fd_ulong_min(
      me.max_lamports_per_signature,
      fd_ulong_max(
        me.min_lamports_per_signature,
        me.target_lamports_per_signature
        * fd_ulong_min(latest_singatures_per_slot, (ulong)UINT_MAX)
        / me.target_signatures_per_slot
      )
    );
    long gap = (long)desired_lamports_per_signature - (long)old_lamports_per_signature;
    if ( gap == 0 ) {
      new_lamports_per_signature = desired_lamports_per_signature;
    } else {
      long gap_adjust = (long)(fd_ulong_max( 1UL, (ulong)(me.target_lamports_per_signature / 20) ))
        * (gap != 0)
        * (gap > 0 ? 1 : -1);
      new_lamports_per_signature = fd_ulong_min(
        me.max_lamports_per_signature,
        fd_ulong_max(
          me.min_lamports_per_signature,
          (ulong)((long)old_lamports_per_signature + gap_adjust)
        )
      );
    }
  } else {
    new_lamports_per_signature = base_fee_rate_governor->target_lamports_per_signature;
    me.min_lamports_per_signature = me.target_lamports_per_signature;
    me.max_lamports_per_signature = me.target_lamports_per_signature;
  }

  if( FD_UNLIKELY( old_lamports_per_signature==0UL ) ) {
    fd_bank_prev_lamports_per_signature_set( bank, new_lamports_per_signature );
  } else {
    fd_bank_prev_lamports_per_signature_set( bank, old_lamports_per_signature );
  }

  fd_bank_fee_rate_governor_set( bank, me );

  fd_bank_lamports_per_signature_set( bank, new_lamports_per_signature );
}

static int
fd_runtime_block_sysvar_update_pre_execute( fd_exec_slot_ctx_t * slot_ctx,
                                            fd_spad_t *          runtime_spad ) {
  // let (fee_rate_governor, fee_components_time_us) = measure_us!(
  //     FeeRateGovernor::new_derived(&parent.fee_rate_governor, parent.signature_count())
  // );
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1312-L1314 */

  fd_runtime_new_fee_rate_governor_derived( slot_ctx->bank, fd_bank_parent_signature_cnt_get( slot_ctx->bank ) );

  // TODO: move all these out to a fd_sysvar_update() call...
  long clock_update_time      = -fd_log_wallclock();
  fd_sysvar_clock_update( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
  clock_update_time          += fd_log_wallclock();
  double clock_update_time_ms = (double)clock_update_time * 1e-6;
  FD_LOG_INFO(( "clock updated - slot: %lu, elapsed: %6.6f ms", slot_ctx->bank->slot, clock_update_time_ms ));

  // It has to go into the current txn previous info but is not in slot 0
  if( slot_ctx->bank->slot != 0 ) {
    fd_sysvar_slot_hashes_update( slot_ctx, runtime_spad );
  }
  fd_sysvar_last_restart_slot_update( slot_ctx, runtime_spad );

  return 0;
}

int
fd_runtime_microblock_verify_ticks( fd_blockstore_t *           blockstore,
                                    ulong                       slot,
                                    fd_microblock_hdr_t const * hdr,
                                    bool               slot_complete,
                                    ulong              tick_height,
                                    ulong              max_tick_height,
                                    ulong              hashes_per_tick ) {
  ulong invalid_tick_hash_count = 0UL;
  ulong has_trailing_entry      = 0UL;

  /*
    In order to mimic the order of checks in Agave,
    we cache the results of some checks but do not immediately return
    an error.
  */
  fd_block_map_query_t quer[1];
  int err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, quer, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * query = fd_block_map_query_ele( quer );
  if( FD_UNLIKELY( err || query->slot != slot ) ) {
    FD_LOG_ERR(( "fd_runtime_microblock_verify_ticks: fd_block_map_prepare on %lu failed", slot ));
  }

  query->tick_hash_count_accum = fd_ulong_sat_add( query->tick_hash_count_accum, hdr->hash_cnt );
  if( hdr->txn_cnt == 0UL ) {
    query->ticks_consumed++;
    if( FD_LIKELY( hashes_per_tick > 1UL ) ) {
      if( FD_UNLIKELY( query->tick_hash_count_accum != hashes_per_tick ) ) {
        FD_LOG_WARNING(( "tick_hash_count %lu hashes_per_tick %lu tick_count %lu", query->tick_hash_count_accum, hashes_per_tick, query->ticks_consumed ));
        invalid_tick_hash_count = 1U;
      }
    }
    query->tick_hash_count_accum = 0UL;
  } else {
    /* This wasn't a tick entry, but it's the last entry. */
    if( FD_UNLIKELY( slot_complete ) ) {
      FD_LOG_WARNING(( "last has %lu transactions expects 0", hdr->txn_cnt ));
      has_trailing_entry = 1U;
    }
  }

  ulong next_tick_height = tick_height + query->ticks_consumed;
  fd_block_map_publish( quer );

  if( FD_UNLIKELY( next_tick_height > max_tick_height ) ) {
    FD_LOG_WARNING(( "Too many ticks tick_height %lu max_tick_height %lu hashes_per_tick %lu tick_count %lu", tick_height, max_tick_height, hashes_per_tick, query->ticks_consumed ));
    return FD_BLOCK_ERR_TOO_MANY_TICKS;
  }
  if( FD_UNLIKELY( slot_complete && next_tick_height < max_tick_height ) ) {
    FD_LOG_WARNING(( "Too few ticks" ));
    return FD_BLOCK_ERR_TOO_FEW_TICKS;
  }
  if( FD_UNLIKELY( slot_complete && has_trailing_entry ) ) {
    FD_LOG_WARNING(( "Did not end with a tick" ));
    return FD_BLOCK_ERR_TRAILING_ENTRY;
  }

  /* Not returning FD_BLOCK_ERR_INVALID_LAST_TICK because we assume the
     slot is full. */

  /* Don't care about low power hashing or no hashing. */
  if( FD_LIKELY( hashes_per_tick > 1UL ) ) {
    if( FD_UNLIKELY( invalid_tick_hash_count ) ) {
      FD_LOG_WARNING(( "Tick with invalid number of hashes found" ));
      return FD_BLOCK_ERR_INVALID_TICK_HASH_COUNT;
    }
  }
  return FD_BLOCK_OK;
}

/* A streaming version of this by batch is implemented in batch_verify_ticks.
   This block_verify_ticks should only used for offline replay. */
ulong
fd_runtime_block_verify_ticks( fd_blockstore_t * blockstore,
                               ulong             slot,
                               uchar *           block_data,
                               ulong             block_data_sz,
                               ulong             tick_height,
                               ulong             max_tick_height,
                               ulong             hashes_per_tick ) {
  ulong tick_count              = 0UL;
  ulong tick_hash_count         = 0UL;
  ulong has_trailing_entry      = 0UL;
  uchar invalid_tick_hash_count = 0U;
  /*
    Iterate over microblocks/entries to
    (1) count the number of ticks
    (2) check whether the last entry is a tick
    (3) check whether ticks align with hashes per tick

    This precomputes everything we need in a single loop over the array.
    In order to mimic the order of checks in Agave,
    we cache the results of some checks but do not immediately return
    an error.
   */
  ulong slot_complete_idx = FD_SHRED_IDX_NULL;
  fd_block_set_t data_complete_idxs[FD_SHRED_BLK_MAX / sizeof(ulong)];
  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    fd_block_map_query_t quer[1] = {0};
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, quer, 0 );
    fd_block_info_t * query = fd_block_map_query_ele( quer );
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) )continue;
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) FD_LOG_ERR(( "fd_runtime_block_verify_ticks: fd_block_map_query_try failed" ));
    slot_complete_idx = query->slot_complete_idx;
    fd_memcpy( data_complete_idxs, query->data_complete_idxs, sizeof(data_complete_idxs) );
    err = fd_block_map_query_test( quer );
  }

  uint   batch_cnt = 0;
  ulong  batch_idx = 0;
  while ( batch_idx <= slot_complete_idx ) {
    batch_cnt++;
    ulong batch_sz = 0;
    uint  end_idx  = (uint)fd_block_set_const_iter_next( data_complete_idxs, batch_idx - 1 );
    FD_TEST( fd_blockstore_slice_query( blockstore, slot, (uint) batch_idx, end_idx, block_data_sz, block_data, &batch_sz ) == FD_BLOCKSTORE_SUCCESS );
    ulong micro_cnt = FD_LOAD( ulong, block_data );
    ulong off       = sizeof(ulong);
    for( ulong i = 0UL; i < micro_cnt; i++ ){
      fd_microblock_hdr_t const * hdr = fd_type_pun_const( ( block_data + off ) );
      off += sizeof(fd_microblock_hdr_t);
      tick_hash_count = fd_ulong_sat_add( tick_hash_count, hdr->hash_cnt );
      if( hdr->txn_cnt == 0UL ){
        tick_count++;
        if( FD_LIKELY( hashes_per_tick > 1UL ) ) {
          if( FD_UNLIKELY( tick_hash_count != hashes_per_tick ) ) {
            FD_LOG_WARNING(( "tick_hash_count %lu hashes_per_tick %lu tick_count %lu i %lu micro_cnt %lu", tick_hash_count, hashes_per_tick, tick_count, i, micro_cnt ));
            invalid_tick_hash_count = 1U;
          }
        }
        tick_hash_count = 0UL;
        continue;
      }
      /* This wasn't a tick entry, but it's the last entry. */
      if( FD_UNLIKELY( i == micro_cnt - 1UL ) ) {
        has_trailing_entry = batch_cnt;
      }

      /* seek past txns */
      uchar txn[FD_TXN_MAX_SZ];
      for( ulong j = 0; j < hdr->txn_cnt; j++ ) {
        ulong pay_sz = 0;
        ulong txn_sz = fd_txn_parse_core( block_data + off, fd_ulong_min( batch_sz - off, FD_TXN_MTU ), txn, NULL, &pay_sz );
        if( FD_UNLIKELY( !pay_sz ) ) FD_LOG_ERR(( "failed to parse transaction %lu in microblock %lu in slot %lu", j, i, slot ) );
        if( FD_UNLIKELY( !txn_sz || txn_sz > FD_TXN_MTU )) FD_LOG_ERR(( "failed to parse transaction %lu in microblock %lu in slot %lu. txn size: %lu", j, i, slot, txn_sz ));
        off += pay_sz;
      }
    }
    /* advance batch iterator */
    if( FD_UNLIKELY( batch_cnt == 1 ) ){ /* first batch */
      batch_idx = fd_block_set_const_iter_init( data_complete_idxs ) + 1;
    } else {
      batch_idx = fd_block_set_const_iter_next( data_complete_idxs, batch_idx - 1 ) + 1;
    }
  }

  ulong next_tick_height = tick_height + tick_count;
  if( FD_UNLIKELY( next_tick_height > max_tick_height ) ) {
    FD_LOG_WARNING(( "Too many ticks tick_height %lu max_tick_height %lu hashes_per_tick %lu tick_count %lu", tick_height, max_tick_height, hashes_per_tick, tick_count ));
    FD_LOG_WARNING(( "Too many ticks" ));
    return FD_BLOCK_ERR_TOO_MANY_TICKS;
  }
  if( FD_UNLIKELY( next_tick_height < max_tick_height ) ) {
    FD_LOG_WARNING(( "Too few ticks" ));
    return FD_BLOCK_ERR_TOO_FEW_TICKS;
  }
  if( FD_UNLIKELY( has_trailing_entry == batch_cnt ) ) {
    FD_LOG_WARNING(( "Did not end with a tick" ));
    return FD_BLOCK_ERR_TRAILING_ENTRY;
  }

  /* Not returning FD_BLOCK_ERR_INVALID_LAST_TICK because we assume the
     slot is full. */

  /* Don't care about low power hashing or no hashing. */
  if( FD_LIKELY( hashes_per_tick > 1UL ) ) {
    if( FD_UNLIKELY( invalid_tick_hash_count ) ) {
      FD_LOG_WARNING(( "Tick with invalid number of hashes found" ));
      return FD_BLOCK_ERR_INVALID_TICK_HASH_COUNT;
    }
  }

  return FD_BLOCK_OK;
}

int
fd_runtime_load_txn_address_lookup_tables( fd_txn_t const * txn,
                                           uchar const *    payload,
                                           fd_funk_t *      funk,
                                           fd_funk_txn_t *  funk_txn,
                                           ulong            slot,
                                           fd_slot_hash_t * hashes,
                                           fd_acct_addr_t * out_accts_alt ) {

  if( FD_LIKELY( txn->transaction_version!=FD_TXN_V0 ) ) return FD_RUNTIME_EXECUTE_SUCCESS;

  ulong            readonly_lut_accs_cnt = 0UL;
  ulong            writable_lut_accs_cnt = 0UL;
  fd_acct_addr_t * readonly_lut_accs     = out_accts_alt+txn->addr_table_adtl_writable_cnt;
  fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn );
  for( ulong i = 0UL; i < txn->addr_table_lookup_cnt; i++ ) {
    fd_txn_acct_addr_lut_t const * addr_lut  = &addr_luts[i];
    fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)(payload + addr_lut->addr_off);

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L90-L94 */
    FD_TXN_ACCOUNT_DECL( addr_lut_rec );
    int err = fd_txn_account_init_from_funk_readonly( addr_lut_rec,
                                                      addr_lut_acc,
                                                      funk,
                                                      funk_txn );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      return FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
    }

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L96-L114 */
    if( FD_UNLIKELY( memcmp( addr_lut_rec->vt->get_owner( addr_lut_rec ), fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER;
    }

    /* Realistically impossible case, but need to make sure we don't cause an OOB data access
       https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L205-L209 */
    if( FD_UNLIKELY( addr_lut_rec->vt->get_data_len( addr_lut_rec ) < FD_LOOKUP_TABLE_META_SIZE ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/accounts-db/src/accounts.rs#L141-L142 */
    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = addr_lut_rec->vt->get_data( addr_lut_rec ),
      .dataend = &addr_lut_rec->vt->get_data( addr_lut_rec )[FD_LOOKUP_TABLE_META_SIZE]
    };

    ulong total_sz = 0UL;
    err = fd_address_lookup_table_state_decode_footprint( &decode_ctx, &total_sz );
    if( FD_UNLIKELY( err ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L197-L214 */
    fd_address_lookup_table_state_t table[1];
    fd_address_lookup_table_state_t * addr_lookup_table_state = fd_address_lookup_table_state_decode( table, &decode_ctx );

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L200-L203 */
    if( FD_UNLIKELY( addr_lookup_table_state->discriminant != fd_address_lookup_table_state_enum_lookup_table ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
    }

    /* Again probably an impossible case, but the ALUT data needs to be 32-byte aligned
       https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L210-L214 */
    if( FD_UNLIKELY( (addr_lut_rec->vt->get_data_len( addr_lut_rec ) - FD_LOOKUP_TABLE_META_SIZE) & 0x1fUL ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L101-L112 */
    fd_acct_addr_t * lookup_addrs  = (fd_acct_addr_t *)&addr_lut_rec->vt->get_data( addr_lut_rec )[FD_LOOKUP_TABLE_META_SIZE];
    ulong         lookup_addrs_cnt = (addr_lut_rec->vt->get_data_len( addr_lut_rec ) - FD_LOOKUP_TABLE_META_SIZE) >> 5UL; // = (dlen - 56) / 32

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L175-L176 */
    ulong active_addresses_len;
    err = fd_get_active_addresses_len( &addr_lookup_table_state->inner.lookup_table,
                                       slot,
                                       hashes,
                                       lookup_addrs_cnt,
                                       &active_addresses_len );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L169-L182 */
    uchar * writable_lut_idxs = (uchar *)payload + addr_lut->writable_off;
    for( ulong j=0; j<addr_lut->writable_cnt; j++ ) {
      /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L177-L181 */
      if( writable_lut_idxs[j] >= active_addresses_len ) {
        return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
      }
      out_accts_alt[writable_lut_accs_cnt++] = lookup_addrs[writable_lut_idxs[j]];
    }

    uchar * readonly_lut_idxs = (uchar *)payload + addr_lut->readonly_off;
    for( ulong j = 0; j < addr_lut->readonly_cnt; j++ ) {
      /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L177-L181 */
      if( readonly_lut_idxs[j] >= active_addresses_len ) {
        return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
      }
      readonly_lut_accs[readonly_lut_accs_cnt++] = lookup_addrs[readonly_lut_idxs[j]];
    }
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_microblock_verify_read_write_conflicts( fd_txn_p_t *               txns,
                                                   ulong                      txn_cnt,
                                                   fd_conflict_detect_ele_t * acct_map,
                                                   fd_acct_addr_t *           acct_arr,
                                                   fd_funk_t *                funk,
                                                   fd_funk_txn_t *            funk_txn,
                                                   ulong                      slot,
                                                   fd_slot_hash_t *           slot_hashes,
                                                   fd_features_t *            features,
                                                   int *                      out_conflict_detected,
                                                   fd_acct_addr_t *           out_conflict_addr_opt ) {
  *out_conflict_detected=FD_RUNTIME_NO_CONFLICT_DETECTED;
#define NO_CONFLICT ( *out_conflict_detected==FD_RUNTIME_NO_CONFLICT_DETECTED )

#define UPDATE_CONFLICT(cond1, cond2, acct) \
if( FD_UNLIKELY( cond1 ) ) { \
  if( FD_LIKELY( out_conflict_addr_opt ) ) *out_conflict_addr_opt = acct; \
  *out_conflict_detected=FD_RUNTIME_WRITE_WRITE_CONFLICT_DETECTED; \
} else if( FD_UNLIKELY( cond2 ) ) { \
  if( FD_LIKELY( out_conflict_addr_opt ) ) *out_conflict_addr_opt = acct; \
  *out_conflict_detected=FD_RUNTIME_READ_WRITE_CONFLICT_DETECTED; \
}

  ulong curr_idx            = 0;
  ulong sentinel_is_read    = 0;
  ulong sentinel_is_written = 0;
  int runtime_err           = FD_RUNTIME_EXECUTE_SUCCESS;
  for( ulong i=0; i<txn_cnt && NO_CONFLICT; i++ ) {
    fd_txn_p_t *           txn = txns+i;
    fd_acct_addr_t * txn_accts = acct_arr+curr_idx;

    /* Put the immediate & ALT accounts at txn_accts */
    const fd_acct_addr_t * accts_imm = fd_txn_get_acct_addrs( TXN(txn), txn->payload );
    ulong              accts_imm_cnt = fd_txn_account_cnt( TXN(txn), FD_TXN_ACCT_CAT_IMM );
    fd_memcpy( txn_accts, accts_imm, accts_imm_cnt*sizeof(fd_acct_addr_t) );
    runtime_err = fd_runtime_load_txn_address_lookup_tables( TXN(txn),
                                                             txn->payload,
                                                             funk,
                                                             funk_txn,
                                                             slot,
                                                             slot_hashes,
                                                             txn_accts+accts_imm_cnt );
    if( FD_UNLIKELY( runtime_err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) break;

    ulong accounts_cnt   = fd_txn_account_cnt( TXN(txn), FD_TXN_ACCT_CAT_ALL );
    curr_idx            +=accounts_cnt;
    uint bpf_upgradeable = fd_txn_account_has_bpf_loader_upgradeable( fd_type_pun( txn_accts ), accounts_cnt );

    /* Iterate all writable accounts and detect W-W/R-W conflicts */
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( TXN(txn), FD_TXN_ACCT_CAT_WRITABLE );
         iter!=fd_txn_acct_iter_end() && NO_CONFLICT;
         iter=fd_txn_acct_iter_next( iter ) ) {
      ushort idx                     = (ushort)fd_txn_acct_iter_idx( iter );
      fd_acct_addr_t writable_acc = txn_accts[ idx ];

      /* Check whether writable_acc is demoted to a read-only account */
      if( FD_UNLIKELY( !fd_exec_txn_account_is_writable_idx_flat( slot,
                                                                  idx,
                                                                  fd_type_pun( &txn_accts[ idx ] ),
                                                                  TXN(txn),
                                                                  features,
                                                                  bpf_upgradeable ) ) ) {
        continue;
      }

      /* writable_acc is the sentinel (fd_acct_addr_null) */
      if( FD_UNLIKELY( fd_conflict_detect_map_key_inval( writable_acc ) ) ) {
        UPDATE_CONFLICT( sentinel_is_written, sentinel_is_read, writable_acc );
        sentinel_is_written = 1;
        continue;
      }

      /* writable_acc is not the sentinel (fd_acct_addr_null) */
      fd_conflict_detect_ele_t * found = fd_conflict_detect_map_query( acct_map, writable_acc, NULL );
      if( FD_UNLIKELY( found ) ) {
        UPDATE_CONFLICT( found->writable, !found->writable, writable_acc );
      } else {
        fd_conflict_detect_ele_t * entry = fd_conflict_detect_map_insert( acct_map, writable_acc );
        entry->writable                  = 1;
      }
    }

    /* Iterate all readonly accounts and detect R-W conflicts */
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( TXN(txn), FD_TXN_ACCT_CAT_READONLY );
         iter!=fd_txn_acct_iter_end() && NO_CONFLICT;
         iter=fd_txn_acct_iter_next( iter ) ) {
      fd_acct_addr_t readonly_acc = txn_accts[ fd_txn_acct_iter_idx( iter ) ];

      /* readonly_acc is the sentinel (fd_acct_addr_null) */
      if( FD_UNLIKELY( fd_conflict_detect_map_key_inval( readonly_acc ) ) ) {
        UPDATE_CONFLICT( 0, sentinel_is_written, readonly_acc );
        sentinel_is_read = 1;
        continue;
      }

      /* readonly_acc is not the sentinel (fd_acct_addr_null) */
      fd_conflict_detect_ele_t * found = fd_conflict_detect_map_query( acct_map, readonly_acc, NULL );
      if( FD_UNLIKELY( found ) ) {
        UPDATE_CONFLICT( 0, found->writable, readonly_acc );
      } else {
        fd_conflict_detect_ele_t * entry = fd_conflict_detect_map_insert( acct_map, readonly_acc );
        entry->writable                  = 0;
      }
    }
  }

  /* Clear all the entries inserted into acct_map */
  for( ulong i=0; i<curr_idx; i++ ) {
    if( FD_UNLIKELY( fd_conflict_detect_map_key_inval( acct_arr[i] ) ) ) continue;
    fd_conflict_detect_ele_t * found = fd_conflict_detect_map_query( acct_map, acct_arr[i], NULL );
    if( FD_LIKELY( found ) ) fd_conflict_detect_map_remove( acct_map, found );
  }

  if( FD_UNLIKELY( runtime_err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return runtime_err;
  } else {
    /* https://github.com/anza-xyz/agave/blob/v2.2.3/accounts-db/src/account_locks.rs#L31 */
    /* https://github.com/anza-xyz/agave/blob/v2.2.3/accounts-db/src/account_locks.rs#L34 */
    return NO_CONFLICT? FD_RUNTIME_EXECUTE_SUCCESS : FD_RUNTIME_TXN_ERR_ACCOUNT_IN_USE;
  }
}

void
fd_runtime_poh_verify( fd_poh_verifier_t * poh_info ) {

  fd_hash_t working_hash = *(poh_info->in_poh_hash);
  fd_hash_t init_hash    = working_hash;

  fd_microblock_hdr_t const * hdr = poh_info->microblock.hdr;
  ulong               microblk_sz = poh_info->microblk_max_sz;

  if( !hdr->txn_cnt ){
    fd_poh_append( &working_hash, hdr->hash_cnt );
  } else { /* not a tick, regular microblock */
    if( hdr->hash_cnt ){
      fd_poh_append( &working_hash, hdr->hash_cnt - 1 );
    }

    ulong leaf_cnt_max = FD_TXN_ACTUAL_SIG_MAX * hdr->txn_cnt;

    FD_SPAD_FRAME_BEGIN( poh_info->spad ) {
      uchar *               commit = fd_spad_alloc( poh_info->spad, FD_WBMTREE32_ALIGN, fd_wbmtree32_footprint(leaf_cnt_max) );
      fd_wbmtree32_leaf_t * leafs  = fd_spad_alloc( poh_info->spad, alignof(fd_wbmtree32_leaf_t), sizeof(fd_wbmtree32_leaf_t) * leaf_cnt_max );
      fd_wbmtree32_t *      tree   = fd_wbmtree32_init( commit, leaf_cnt_max );
      fd_wbmtree32_leaf_t * l      = &leafs[0];

      /* Loop across transactions */
      ulong leaf_cnt = 0UL;
      ulong off      = sizeof(fd_microblock_hdr_t);
      for( ulong txn_idx=0UL; txn_idx<hdr->txn_cnt; txn_idx++ ) {
        fd_txn_p_t txn_p;
        ulong pay_sz = 0UL;
        ulong txn_sz = fd_txn_parse_core( poh_info->microblock.raw + off,
                                          fd_ulong_min( FD_TXN_MTU, microblk_sz - off ),
                                          TXN(&txn_p),
                                          NULL,
                                          &pay_sz );
        if( FD_UNLIKELY( !pay_sz || !txn_sz || txn_sz > FD_TXN_MTU )  ) {
          FD_LOG_ERR(( "failed to parse transaction %lu in replay", txn_idx ));
        }

        /* Loop across signatures */
        fd_txn_t const *         txn  = (fd_txn_t const *) txn_p._;
        fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)fd_type_pun((poh_info->microblock.raw + off) + (ulong)txn->signature_off);
        for( ulong j=0UL; j<txn->signature_cnt; j++ ) {
          l->data     = (uchar *)&sigs[j];
          l->data_len = sizeof(fd_ed25519_sig_t);
          l++;
          leaf_cnt++;
        }
        off += pay_sz;
      }

      uchar * mbuf = fd_spad_alloc( poh_info->spad, 1UL, leaf_cnt * (sizeof(fd_ed25519_sig_t) + 1) );
      fd_wbmtree32_append( tree, leafs, leaf_cnt, mbuf );
      uchar * root = fd_wbmtree32_fini( tree );
      fd_poh_mixin( &working_hash, root );
    } FD_SPAD_FRAME_END;
  }

  if( FD_UNLIKELY( memcmp(hdr->hash, working_hash.hash, sizeof(fd_hash_t)) ) ) {
    FD_LOG_WARNING(( "poh mismatch (bank: %s, entry: %s, INIT: %s )", FD_BASE58_ENC_32_ALLOCA( working_hash.hash ), FD_BASE58_ENC_32_ALLOCA( hdr->hash ), FD_BASE58_ENC_32_ALLOCA( init_hash.hash ) ));
    poh_info->success = -1;
  }
}

int
fd_runtime_block_execute_prepare( fd_exec_slot_ctx_t * slot_ctx,
                                  fd_blockstore_t *    blockstore,
                                  fd_spad_t *          runtime_spad ) {


  if( blockstore && slot_ctx->bank->slot != 0UL ) {
    fd_blockstore_block_height_update( blockstore,
                                       slot_ctx->bank->slot,
                                       fd_bank_block_height_get( slot_ctx->bank ) );
  }

  fd_bank_execution_fees_set( slot_ctx->bank, 0UL );

  fd_bank_priority_fees_set( slot_ctx->bank, 0UL );

  fd_bank_signature_count_set( slot_ctx->bank, 0UL );

  fd_bank_txn_count_set( slot_ctx->bank, 0UL );

  fd_bank_nonvote_txn_count_set( slot_ctx->bank, 0UL );

  fd_bank_failed_txn_count_set( slot_ctx->bank, 0UL );

  fd_bank_nonvote_failed_txn_count_set( slot_ctx->bank, 0UL );

  fd_bank_total_compute_units_used_set( slot_ctx->bank, 0UL );

  int result = fd_runtime_block_sysvar_update_pre_execute( slot_ctx, runtime_spad );
  if( FD_UNLIKELY( result != 0 ) ) {
    FD_LOG_WARNING(("updating sysvars failed"));
    return result;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_block_execute_finalize_start( fd_exec_slot_ctx_t *             slot_ctx,
                                         fd_spad_t *                      runtime_spad,
                                         fd_accounts_hash_task_data_t * * task_data,
                                         ulong                            lt_hash_cnt ) {

  fd_sysvar_slot_history_update( slot_ctx, runtime_spad );

  /* This slot is now "frozen" and can't be changed anymore. */
  fd_runtime_freeze( slot_ctx, runtime_spad );

  int result = fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, runtime_spad );
  if( FD_UNLIKELY( result ) ) {
    FD_LOG_WARNING(( "update bpf program cache failed" ));
    return;
  }

  /* Collect list of changed accounts to be added to bank hash */
  *task_data = fd_spad_alloc( runtime_spad,
                              alignof(fd_accounts_hash_task_data_t),
                              sizeof(fd_accounts_hash_task_data_t) );
  (*task_data)->lthash_values = fd_spad_alloc_check(
      runtime_spad, alignof(fd_lthash_value_t), lt_hash_cnt * sizeof(fd_lthash_value_t) );

  for( ulong i=0UL; i<lt_hash_cnt; i++ ) {
    fd_lthash_zero( &((*task_data)->lthash_values)[i] );
  }

  fd_collect_modified_accounts( slot_ctx, *task_data, runtime_spad );
}

int
fd_runtime_block_execute_finalize_finish( fd_exec_slot_ctx_t *             slot_ctx,
                                          fd_capture_ctx_t *               capture_ctx,
                                          fd_runtime_block_info_t const *  block_info,
                                          fd_spad_t *                      runtime_spad,
                                          fd_accounts_hash_task_data_t *   task_data,
                                          ulong                            lt_hash_cnt ) {

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( slot_ctx->bank );
  int err = fd_update_hash_bank_exec_hash( slot_ctx,
                                           bank_hash,
                                           capture_ctx,
                                           task_data,
                                           1UL,
                                           task_data->lthash_values,
                                           lt_hash_cnt,
                                           block_info->signature_cnt,
                                           runtime_spad );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to hash at end of slot" ));
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;

}

void
block_finalize_tpool_wrapper( void * para_arg_1,
                              void * para_arg_2 FD_PARAM_UNUSED,
                              void * arg_1,
                              void * arg_2,
                              void * arg_3,
                              void * arg_4 FD_PARAM_UNUSED ) {
  fd_tpool_t *                   tpool      = (fd_tpool_t *)para_arg_1;
  fd_accounts_hash_task_data_t * task_data  = (fd_accounts_hash_task_data_t *)arg_1;
  ulong                          worker_cnt = (ulong)arg_2;
  fd_exec_slot_ctx_t *           slot_ctx   = (fd_exec_slot_ctx_t *)arg_3;

  ulong cnt_per_worker = (worker_cnt>1) ? (task_data->info_sz / (worker_cnt-1UL)) + 1UL : task_data->info_sz;
  for( ulong worker_idx=1UL; worker_idx<worker_cnt; worker_idx++ ) {
    ulong start_idx = (worker_idx-1UL) * cnt_per_worker;
    if( start_idx >= task_data->info_sz ) {
      worker_cnt = worker_idx;
      break;
    }
    ulong end_idx = fd_ulong_sat_sub((worker_idx) * cnt_per_worker, 1UL);
    if( end_idx >= task_data->info_sz )
      end_idx = fd_ulong_sat_sub( task_data->info_sz, 1UL );;
    fd_tpool_exec( tpool, worker_idx, fd_account_hash_task,
                   task_data, start_idx, end_idx,
                   &task_data->lthash_values[worker_idx], slot_ctx, 0UL,
                   0UL, 0UL, worker_idx, 0UL, 0UL, 0UL );
  }

  for( ulong worker_idx=1UL; worker_idx<worker_cnt; worker_idx++ ) {
    fd_tpool_wait( tpool, worker_idx );
  }
}

int
fd_runtime_block_execute_finalize_para( fd_exec_slot_ctx_t *             slot_ctx,
                                        fd_capture_ctx_t *               capture_ctx,
                                        fd_runtime_block_info_t const *  block_info,
                                        ulong                            worker_cnt,
                                        fd_spad_t *                      runtime_spad,
                                        fd_exec_para_cb_ctx_t *          exec_para_ctx ) {

  fd_accounts_hash_task_data_t * task_data = NULL;

  fd_runtime_block_execute_finalize_start( slot_ctx, runtime_spad, &task_data, worker_cnt );

  exec_para_ctx->fn_arg_1 = (void*)task_data;
  exec_para_ctx->fn_arg_2 = (void*)worker_cnt;
  exec_para_ctx->fn_arg_3 = (void*)slot_ctx;
  fd_exec_para_call_func( exec_para_ctx );

  fd_runtime_block_execute_finalize_finish( slot_ctx, capture_ctx, block_info, runtime_spad, task_data, worker_cnt );

  return 0;
}

/******************************************************************************/
/* Transaction Level Execution Management                                     */
/******************************************************************************/

/* fd_runtime_prepare_txns_start is responsible for setting up the task infos,
   the slot_ctx, and for setting up the accessed accounts. */

int
fd_runtime_prepare_txns_start( fd_exec_slot_ctx_t *         slot_ctx,
                               fd_execute_txn_task_info_t * task_info,
                               fd_txn_p_t *                 txns,
                               ulong                        txn_cnt,
                               fd_spad_t *                  runtime_spad ) {
  int res = 0;
  /* Loop across transactions */
  for( ulong txn_idx = 0UL; txn_idx < txn_cnt; txn_idx++ ) {
    fd_txn_p_t * txn = &txns[txn_idx];

    /* Allocate/setup transaction context and task infos */
    task_info[txn_idx].txn_ctx      = fd_spad_alloc( runtime_spad, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
    fd_exec_txn_ctx_t * txn_ctx     = task_info[txn_idx].txn_ctx;
    task_info[txn_idx].exec_res     = 0;
    task_info[txn_idx].txn          = txn;
    fd_txn_t const * txn_descriptor = (fd_txn_t const *) txn->_;

    fd_rawtxn_b_t raw_txn = { .raw = txn->payload, .txn_sz = (ushort)txn->payload_sz };

    task_info[txn_idx].txn_ctx->spad      = runtime_spad;
    task_info[txn_idx].txn_ctx->spad_wksp = fd_wksp_containing( runtime_spad );
    int err = fd_execute_txn_prepare_start( slot_ctx,
                                            txn_ctx,
                                            txn_descriptor,
                                            &raw_txn );
    if( FD_UNLIKELY( err ) ) {
      task_info[txn_idx].exec_res = err;
      txn->flags                  = 0U;
      res |= err;
    }
  }

  return res;
}

/* fd_runtime_pre_execute_check is responsible for conducting many of the
   transaction sanitization checks. */

void
fd_runtime_pre_execute_check( fd_execute_txn_task_info_t * task_info ) {
  if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    return;
  }

  int err;

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/sdk/src/transaction/sanitized.rs#L263-L275
     TODO: Agave's precompile verification is done at the slot level, before batching and executing transactions. This logic should probably
     be moved in the future. The Agave call heirarchy looks something like this:
            process_single_slot
                   v
            confirm_full_slot
                   v
            confirm_slot_entries --------------------------------------------------->
                   v                               v                                v
            verify_transaction    ComputeBudget::process_instruction         process_entries
                   v                                                                v
            verify_precompiles                                                process_batches
                                                                                    v
                                                                                   ...
                                                                                    v
                                                                        load_and_execute_transactions
                                                                                    v
                                                                                   ...
                                                                                    v
                                                                              load_accounts --> load_transaction_accounts
                                                                                    v
                                                                       general transaction execution

  */

  uchar dump_txn = !!( task_info->txn_ctx->capture_ctx &&
                       task_info->txn_ctx->slot >= task_info->txn_ctx->capture_ctx->dump_proto_start_slot &&
                       task_info->txn_ctx->capture_ctx->dump_txn_to_pb );
  if( FD_UNLIKELY( dump_txn ) ) {
    fd_dump_txn_to_protobuf( task_info->txn_ctx, task_info->txn_ctx->spad );
  }

  /* Verify the transaction. For now, this step only involves processing
     the compute budget instructions. */
  err = fd_executor_verify_transaction( task_info->txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }

  /* Resolve and verify ALUT-referenced account keys, if applicable */
  err = fd_executor_setup_txn_alut_account_keys( task_info->txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }

  /* Set up the transaction accounts and other txn ctx metadata */
  fd_exec_txn_ctx_t * txn_ctx = task_info->txn_ctx;
  fd_executor_setup_accounts_for_txn( txn_ctx );

  /* Post-sanitization checks. Called from `prepare_sanitized_batch()` which, for now, only is used
     to lock the accounts and perform a couple basic validations.
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118 */
  err = fd_executor_validate_account_locks( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }

  /* `load_and_execute_transactions()` -> `check_transactions()`
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L3667-L3672 */
  err = fd_executor_check_transactions( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }

  /* `load_and_execute_sanitized_transactions()` -> `validate_fees()` -> `validate_transaction_fee_payer()`
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L236-L249 */
  err = fd_executor_validate_transaction_fee_payer( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L284-L296 */
  err = fd_executor_load_transaction_accounts( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    /* Regardless of whether transaction accounts were loaded successfully, the transaction is
        included in the block and transaction fees are collected.
        https://github.com/anza-xyz/agave/blob/v2.1.6/svm/src/transaction_processor.rs#L341-L357 */
    task_info->txn->flags |= FD_TXN_P_FLAGS_FEES_ONLY;
    task_info->exec_res    = err;

    /* If the transaction fails to load, the "rollback" accounts will include one of the following:
        1. Nonce account only
        2. Fee payer only
        3. Nonce account + fee payer

        Because the cost tracker uses the loaded account data size in block cost calculations, we need to
        make sure our calculated loaded accounts data size is conformant with Agave's.
        https://github.com/anza-xyz/agave/blob/v2.1.14/runtime/src/bank.rs#L4116

        In any case, we should always add the dlen of the fee payer. */
    task_info->txn_ctx->loaded_accounts_data_size = task_info->txn_ctx->accounts[FD_FEE_PAYER_TXN_IDX].vt->get_data_len( &task_info->txn_ctx->accounts[FD_FEE_PAYER_TXN_IDX] );

    /* Special case handling for if a nonce account is present in the transaction. */
    if( task_info->txn_ctx->nonce_account_idx_in_txn!=ULONG_MAX ) {
      /* If the nonce account is not the fee payer, then we separately add the dlen of the nonce account. Otherwise, we would
          be double counting the dlen of the fee payer. */
      if( task_info->txn_ctx->nonce_account_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) {
        task_info->txn_ctx->loaded_accounts_data_size += task_info->txn_ctx->rollback_nonce_account->vt->get_data_len( task_info->txn_ctx->rollback_nonce_account );
      }
    }
  }

  /*
     The fee payer and the nonce account will be stored and hashed so
     long as the transaction landed on chain, or, in Agave terminology,
     the transaction was processed.
     https://github.com/anza-xyz/agave/blob/v2.1.1/runtime/src/account_saver.rs#L72

     A transaction lands on chain in one of two ways:
     (1) Passed fee validation and loaded accounts.
     (2) Passed fee validation and failed to load accounts and the enable_transaction_loading_failure_fees feature is enabled as per
         SIMD-0082 https://github.com/anza-xyz/feature-gate-tracker/issues/52

     So, at this point, the transaction is committable.
   */
}

/* fd_runtime_finalize_txn is a helper used by the non-tpool transaction
   executor to finalize borrowed account changes back into funk. It also
   handles txncache insertion and updates to the vote/stake cache.
   TODO: This function should probably be moved to fd_executor.c. */

void
fd_runtime_finalize_txn( fd_funk_t *                  funk,
                         fd_funk_txn_t *              funk_txn,
                         fd_execute_txn_task_info_t * task_info,
                         fd_spad_t *                  finalize_spad,
                         fd_bank_t *                  bank ) {

  /* for all accounts, if account->is_verified==true, propagate update
     to cache entry. */

  /* Store transaction info including logs */
  // fd_runtime_finalize_txns_update_blockstore_meta( slot_ctx, task_info, 1UL );

  /* Collect fees */

  FD_ATOMIC_FETCH_AND_ADD( fd_bank_execution_fees_modify( bank ), task_info->txn_ctx->execution_fee );
  FD_ATOMIC_FETCH_AND_ADD( fd_bank_priority_fees_modify( bank ), task_info->txn_ctx->priority_fee );

  fd_exec_txn_ctx_t * txn_ctx      = task_info->txn_ctx;
  int                 exec_txn_err = task_info->exec_res;

  FD_ATOMIC_FETCH_AND_ADD( fd_bank_signature_count_modify( bank ), txn_ctx->txn_descriptor->signature_cnt );

  if( FD_UNLIKELY( exec_txn_err ) ) {

    /* Save the fee_payer. Everything but the fee balance should be reset.
       TODO: an optimization here could be to use a dirty flag in the
       borrowed account. If the borrowed account data has been changed in
       any way, then the full account can be rolled back as it is done now.
       However, most of the time the account data is not changed, and only
       the lamport balance has to change. */

    /* With nonce account rollbacks, there are three cases:
       1. No nonce account in the transaction
       2. Nonce account is the fee payer
       3. Nonce account is not the fee payer

       We should always rollback the nonce account first. Note that the nonce account may be the fee payer (case 2). */
    if( txn_ctx->nonce_account_idx_in_txn!=ULONG_MAX ) {
      fd_txn_account_save( txn_ctx->rollback_nonce_account, funk, funk_txn, txn_ctx->spad_wksp );
    }

    /* Now, we must only save the fee payer if the nonce account was not the fee payer (because that was already saved above) */
    if( FD_LIKELY( txn_ctx->nonce_account_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) ) {
      fd_txn_account_save( txn_ctx->rollback_fee_payer_account, funk, funk_txn, txn_ctx->spad_wksp );
    }
  } else {

    int dirty_vote_acc  = txn_ctx->dirty_vote_acc;
    int dirty_stake_acc = txn_ctx->dirty_stake_acc;

    for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
      /* We are only interested in saving writable accounts and the fee
         payer account. */
      if( !fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, i ) && i!=FD_FEE_PAYER_TXN_IDX ) {
        continue;
      }

      fd_txn_account_t * acc_rec = &txn_ctx->accounts[i];

      if( dirty_vote_acc && 0==memcmp( acc_rec->vt->get_owner( acc_rec ), &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
        fd_vote_store_account( acc_rec, bank );
        FD_SPAD_FRAME_BEGIN( finalize_spad ) {
          int err;
          fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
              vote_state_versioned, finalize_spad,
              acc_rec->vt->get_data( acc_rec ),
              acc_rec->vt->get_data_len( acc_rec ),
              &err );
          if( FD_UNLIKELY( err ) ) {
            FD_LOG_WARNING(( "failed to decode vote state versioned" ));
            continue;
          }

          fd_vote_block_timestamp_t const * ts = NULL;
          switch( vsv->discriminant ) {
          case fd_vote_state_versioned_enum_v0_23_5:
            ts = &vsv->inner.v0_23_5.last_timestamp;
            break;
          case fd_vote_state_versioned_enum_v1_14_11:
            ts = &vsv->inner.v1_14_11.last_timestamp;
            break;
          case fd_vote_state_versioned_enum_current:
            ts = &vsv->inner.current.last_timestamp;
            break;
          default:
            __builtin_unreachable();
          }

          fd_vote_record_timestamp_vote_with_slot( acc_rec->pubkey,
                                                   ts->timestamp,
                                                   ts->slot,
                                                   bank );
        } FD_SPAD_FRAME_END;
      }

      if( dirty_stake_acc && 0==memcmp( acc_rec->vt->get_owner( acc_rec ), &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) {
        // TODO: does this correctly handle stake account close?
        fd_store_stake_delegation( acc_rec, bank );
      }

      fd_txn_account_save( &txn_ctx->accounts[i], funk, funk_txn, txn_ctx->spad_wksp );
    }
  }

  int is_vote = fd_txn_is_simple_vote_transaction( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw );
  if( !is_vote ){
    ulong * nonvote_txn_count = fd_bank_nonvote_txn_count_modify( bank );
    FD_ATOMIC_FETCH_AND_ADD(nonvote_txn_count, 1);

    if( FD_UNLIKELY( exec_txn_err ) ){
      ulong * nonvote_failed_txn_count = fd_bank_nonvote_failed_txn_count_modify( bank );
      FD_ATOMIC_FETCH_AND_ADD( nonvote_failed_txn_count, 1 );
    }
  } else {
    if( FD_UNLIKELY( exec_txn_err ) ){
      ulong * failed_txn_count = fd_bank_failed_txn_count_modify( bank );
      FD_ATOMIC_FETCH_AND_ADD( failed_txn_count, 1 );
    }
  }

  ulong * total_compute_units_used = fd_bank_total_compute_units_used_modify( bank );
  FD_ATOMIC_FETCH_AND_ADD( total_compute_units_used, txn_ctx->compute_unit_limit - txn_ctx->compute_meter );

}

/* fd_runtime_prepare_and_execute_txn is the main entrypoint into the executor
   tile. At this point, the slot and epoch context should NOT be changed.
   NOTE: The executor tile doesn't exist yet. */

static int
fd_runtime_prepare_and_execute_txn( fd_exec_slot_ctx_t const *   slot_ctx,
                                    fd_txn_p_t *                 txn,
                                    fd_execute_txn_task_info_t * task_info,
                                    fd_spad_t *                  exec_spad,
                                    fd_capture_ctx_t *           capture_ctx ) {

  int res = 0;

  fd_exec_txn_ctx_t * txn_ctx     = task_info->txn_ctx;
  task_info->exec_res             = -1;
  task_info->txn                  = txn;
  fd_txn_t const * txn_descriptor = (fd_txn_t const *) txn->_;
  task_info->txn_ctx->spad        = exec_spad;
  task_info->txn_ctx->spad_wksp   = fd_wksp_containing( exec_spad );

  fd_rawtxn_b_t raw_txn = { .raw = txn->payload, .txn_sz = (ushort)txn->payload_sz };

  res = fd_execute_txn_prepare_start( slot_ctx, txn_ctx, txn_descriptor, &raw_txn );
  if( FD_UNLIKELY( res ) ) {
    txn->flags = 0U;
    return -1;
  }

  task_info->txn_ctx->capture_ctx = capture_ctx;

  if( FD_UNLIKELY( fd_executor_txn_verify( txn_ctx )!=0 ) ) {
    FD_LOG_WARNING(( "sigverify failed: %s", FD_BASE58_ENC_64_ALLOCA( (uchar *)txn_ctx->_txn_raw->raw+txn_ctx->txn_descriptor->signature_off ) ));
    task_info->txn->flags = 0U;
    task_info->exec_res   = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
  }

  fd_runtime_pre_execute_check( task_info ); /* TODO: check if this will be called from executor tile or replay tile */
  if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    res  = task_info->exec_res;
    return -1;
  }

  /* Execute */
  task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  task_info->exec_res    = fd_execute_txn( task_info );

  if( task_info->exec_res==0 ) {
    fd_txn_reclaim_accounts( task_info->txn_ctx );
  }

  return res;

}

static void
fd_runtime_prepare_execute_finalize_txn_task( void * tpool,
                                              ulong  t0,
                                              ulong  t1,
                                              void * args,
                                              void * reduce,
                                              ulong  stride FD_PARAM_UNUSED,
                                              ulong  l0     FD_PARAM_UNUSED,
                                              ulong  l1     FD_PARAM_UNUSED,
                                              ulong  m0     FD_PARAM_UNUSED,
                                              ulong  m1     FD_PARAM_UNUSED,
                                              ulong  n0     FD_PARAM_UNUSED,
                                              ulong  n1     FD_PARAM_UNUSED ) {

  fd_exec_slot_ctx_t *         slot_ctx     = (fd_exec_slot_ctx_t *)tpool;
  fd_capture_ctx_t *           capture_ctx  = (fd_capture_ctx_t *)t0;
  fd_txn_p_t *                 txn          = (fd_txn_p_t *)t1;
  fd_execute_txn_task_info_t * task_info    = (fd_execute_txn_task_info_t *)args;
  fd_spad_t *                  exec_spad    = (fd_spad_t *)reduce;

  fd_runtime_prepare_and_execute_txn( slot_ctx,
                                      txn,
                                      task_info,
                                      exec_spad,
                                      capture_ctx );

  if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) ) {
    return;
  }

  fd_runtime_finalize_txn( slot_ctx->funk, slot_ctx->funk_txn, task_info, task_info->txn_ctx->spad, slot_ctx->bank );
}

/* fd_executor_txn_verify and fd_runtime_pre_execute_check are responisble
   for the bulk of the pre-transaction execution checks in the runtime.
   They aim to preserve the ordering present in the Agave client to match
   parity in terms of error codes. Sigverify is kept separate from the rest
   of the transaction checks for fuzzing convenience.

   For reference this is the general code path which contains all relevant
   pre-transactions checks in the v2.0.x Agave client from upstream
   to downstream is as follows:

   confirm_slot_entries() which calls verify_ticks() and
   verify_transaction(). verify_transaction() calls verify_and_hash_message()
   and verify_precompiles() which parallels fd_executor_txn_verify() and
   fd_executor_verify_transaction().

   process_entries() contains a duplicate account check which is part of
   agave account lock acquiring. This is checked inline in
   fd_runtime_pre_execute_check().

   load_and_execute_transactions() contains the function check_transactions().
   This contains check_age() and check_status_cache() which is paralleled by
   fd_check_transaction_age() and fd_executor_check_status_cache()
   respectively.

   load_and_execute_sanitized_transactions() contains validate_fees()
   which is responsible for executing the compute budget instructions,
   validating the fee payer and collecting the fee. This is mirrored in
   firedancer with fd_executor_compute_budget_program_execute_instructions()
   and fd_executor_collect_fees(). load_and_execute_sanitized_transactions()
   also checks the total data size of the accounts in load_accounts() and
   validates the program accounts in load_transaction_accounts(). This
   is paralled by fd_executor_load_transaction_accounts(). */

int
fd_runtime_process_txns_in_microblock_stream( fd_exec_slot_ctx_t * slot_ctx,
                                              fd_capture_ctx_t *   capture_ctx,
                                              fd_txn_p_t *         txns,
                                              ulong                txn_cnt,
                                              fd_tpool_t *         tpool,
                                              fd_spad_t * *        exec_spads,
                                              ulong                exec_spad_cnt,
                                              fd_spad_t *          runtime_spad,
                                              fd_cost_tracker_t *  cost_tracker_opt ) {

  int res = 0;

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    txns[i].flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
  }

  fd_execute_txn_task_info_t * task_infos = fd_spad_alloc( runtime_spad,
                                                           alignof(fd_execute_txn_task_info_t),
                                                           txn_cnt * sizeof(fd_execute_txn_task_info_t) );

  ulong curr_exec_idx = 0UL;
  while( curr_exec_idx<txn_cnt ) {
    ulong exec_idx_start = curr_exec_idx;

    // Push a new spad frame for each exec spad
    for( ulong worker_idx=1UL; worker_idx<exec_spad_cnt; worker_idx++ ) {
      fd_spad_push( exec_spads[ worker_idx ] );
    }

    for( ulong worker_idx=1UL; worker_idx<exec_spad_cnt; worker_idx++ ) {
      if( curr_exec_idx>=txn_cnt ) {
        break;
      }
      if( !fd_tpool_worker_idle( tpool, worker_idx ) ) {
        continue;
      }

      task_infos[ curr_exec_idx ].spad    = exec_spads[ worker_idx ];
      task_infos[ curr_exec_idx ].txn     = &txns[ curr_exec_idx ];
      task_infos[ curr_exec_idx ].txn_ctx = fd_spad_alloc( task_infos[ curr_exec_idx ].spad,
                                                           FD_EXEC_TXN_CTX_ALIGN,
                                                           FD_EXEC_TXN_CTX_FOOTPRINT );
      if( FD_UNLIKELY( !task_infos[ curr_exec_idx ].txn_ctx ) ) {
        FD_LOG_ERR(( "failed to allocate txn ctx" ));
      }

      fd_tpool_exec( tpool, worker_idx, fd_runtime_prepare_execute_finalize_txn_task,
                     slot_ctx, (ulong)capture_ctx, (ulong)task_infos[curr_exec_idx].txn,
                     &task_infos[ curr_exec_idx ], exec_spads[ worker_idx ], 0UL,
                     0UL, 0UL, 0UL, 0UL, 0UL, 0UL );

      curr_exec_idx++;
    }

    /* Wait for the workers to finish before we try to dispatch them a new task */
    for( ulong worker_idx=1UL; worker_idx<exec_spad_cnt; worker_idx++ ) {
      fd_tpool_wait( tpool, worker_idx );
    }

    /* Verify cost tracker limits (only for offline replay)
       https://github.com/anza-xyz/agave/blob/v2.2.0/ledger/src/blockstore_processor.rs#L284-L299 */
    if( cost_tracker_opt!=NULL ) {
      for( ulong i=exec_idx_start; i<curr_exec_idx; i++ ) {

        /* Skip any transactions that were not processed */
        fd_execute_txn_task_info_t const * task_info = &task_infos[ i ];
        if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) ) continue;

        fd_exec_txn_ctx_t const * txn_ctx          = task_info->txn_ctx;
        fd_transaction_cost_t     transaction_cost = fd_calculate_cost_for_executed_transaction( task_info->txn_ctx,
                                                                                                 runtime_spad );

        /* https://github.com/anza-xyz/agave/blob/v2.2.0/ledger/src/blockstore_processor.rs#L302-L307 */
        res = fd_cost_tracker_try_add( cost_tracker_opt, txn_ctx, &transaction_cost );
        if( FD_UNLIKELY( res ) ) {
          FD_LOG_WARNING(( "Block cost limits exceeded for slot %lu", slot_ctx->bank->slot ));
          break;
        }
      }
    }

    // Pop the spad frame
    for( ulong worker_idx=1UL; worker_idx<exec_spad_cnt; worker_idx++ ) {
      fd_spad_pop( exec_spads[ worker_idx ] );
    }

    /* If there was a error with cost tracker calculations, return the error */
    if( FD_UNLIKELY( res ) ) return res;
  }

  return 0;

}

/******************************************************************************/
/* Epoch Boundary                                                             */
/******************************************************************************/

/* Update the epoch bank stakes cache with the delegated stake values from the slot bank cache.
The slot bank cache will have been accumulating this epoch, and now we are at an epoch boundary
we can safely update the epoch stakes cache with the latest values.

In Solana, the stakes cache is updated after every transaction
  (https://github.com/solana-labs/solana/blob/c091fd3da8014c0ef83b626318018f238f506435/runtime/src/bank.rs#L7587).
As delegations have to warm up, the contents of the cache will not change inter-epoch. We can therefore update
the cache only at epoch boundaries.

https://github.com/solana-labs/solana/blob/c091fd3da8014c0ef83b626318018f238f506435/runtime/src/stakes.rs#L65 */
static void
fd_update_stake_delegations( fd_exec_slot_ctx_t * slot_ctx,
                             fd_epoch_info_t *    temp_info ) {

  fd_stakes_global_t * stakes = fd_bank_stakes_locking_modify( slot_ctx->bank );
  fd_delegation_pair_t_mapnode_t * stake_delegations_pool = fd_stakes_stake_delegations_pool_join( stakes );
  fd_delegation_pair_t_mapnode_t * stake_delegations_root = fd_stakes_stake_delegations_root_join( stakes );

  /* In one pass, iterate over all the new stake infos and insert the updated values into the epoch stakes cache
      This assumes that there is enough memory pre-allocated for the stakes cache. */
  for( ulong idx=temp_info->stake_infos_new_keys_start_idx; idx<temp_info->stake_infos_len; idx++ ) {
    // Fetch and store the delegation associated with this stake account
    fd_delegation_pair_t_mapnode_t key;
    key.elem.account = temp_info->stake_infos[idx].account;
    fd_delegation_pair_t_mapnode_t * entry = fd_delegation_pair_t_map_find( stake_delegations_pool, stake_delegations_root, &key );
    if( FD_LIKELY( entry==NULL ) ) {
      entry = fd_delegation_pair_t_map_acquire( stake_delegations_pool );
      if( FD_UNLIKELY( !entry ) ) {
        FD_TEST( 0 == fd_delegation_pair_t_map_verify( stake_delegations_pool, stake_delegations_root ) );
        FD_LOG_CRIT(( "stake_delegations_pool full %lu", fd_delegation_pair_t_map_size( stake_delegations_pool, stake_delegations_root ) ));
      }
      entry->elem.account    = temp_info->stake_infos[idx].account;
      entry->elem.delegation = temp_info->stake_infos[idx].stake.delegation;
      fd_delegation_pair_t_map_insert( stake_delegations_pool, &stake_delegations_root, entry );
    }
  }

  fd_stakes_stake_delegations_pool_update( stakes, stake_delegations_pool );
  fd_stakes_stake_delegations_root_update( stakes, stake_delegations_root );
  fd_bank_stakes_end_locking_modify( slot_ctx->bank );

  /* At the epoch boundary, release all of the stake account keys
     because at this point all of the changes have been applied to the
     stakes. */
  fd_account_keys_global_t * stake_account_keys = fd_bank_stake_account_keys_locking_modify( slot_ctx->bank );
  fd_account_keys_pair_t_mapnode_t * account_keys_pool = fd_account_keys_account_keys_pool_join( stake_account_keys );
  fd_account_keys_pair_t_mapnode_t * account_keys_root = fd_account_keys_account_keys_root_join( stake_account_keys );

  fd_account_keys_pair_t_map_release_tree( account_keys_pool, account_keys_root );
  account_keys_root = NULL;

  fd_account_keys_account_keys_pool_update( stake_account_keys, account_keys_pool );
  fd_account_keys_account_keys_root_update( stake_account_keys, account_keys_root );
  fd_bank_stake_account_keys_end_locking_modify( slot_ctx->bank );
}

/* Replace the stakes in T-2 (epoch_stakes) by the stakes at T-1 (next_epoch_stakes) */
static void
fd_update_epoch_stakes( fd_exec_slot_ctx_t * slot_ctx ) {

  /* Copy epoch_bank->next_epoch_stakes into slot_ctx->bank->slot_bank.epoch_stakes */

  ulong total_sz = sizeof(fd_vote_accounts_global_t) +
                   fd_vote_accounts_pair_global_t_map_footprint( 50000UL ) +
                   4000 * 50000UL;

  fd_vote_accounts_global_t const * next_epoch_stakes = fd_bank_next_epoch_stakes_locking_query( slot_ctx->bank );

  fd_vote_accounts_global_t * epoch_stakes = fd_bank_epoch_stakes_locking_modify( slot_ctx->bank );
  fd_memcpy( epoch_stakes, next_epoch_stakes, total_sz );
  fd_bank_epoch_stakes_end_locking_modify( slot_ctx->bank );

  fd_bank_next_epoch_stakes_end_locking_query( slot_ctx->bank );

}

/* Copy stakes->vote_accounts into next_epoch_stakes. */
static void
fd_update_next_epoch_stakes( fd_exec_slot_ctx_t * slot_ctx ) {

  /* FIXME: This is technically not correct, since the vote accounts
     could be laid out after the stake delegations from fd_stakes.
     The correct solution is to split out the stake delgations from the
     vote accounts in fd_stakes. */

  /* Copy stakes->vote_accounts into next_epoch_stakes */

  ulong total_sz = sizeof(fd_vote_accounts_global_t) +
                   fd_vote_accounts_pair_global_t_map_footprint( 50000UL ) +
                   4000 * 50000UL;

  fd_stakes_global_t const *        stakes = fd_bank_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_global_t const * vote_stakes = &stakes->vote_accounts;


  fd_vote_accounts_global_t * next_epoch_stakes = fd_bank_next_epoch_stakes_locking_modify( slot_ctx->bank );
  fd_memcpy( next_epoch_stakes, vote_stakes, total_sz );
  fd_bank_next_epoch_stakes_end_locking_modify( slot_ctx->bank );

  fd_bank_stakes_end_locking_query( slot_ctx->bank );
}

/* Mimics `bank.new_target_program_account()`. Assumes `out_rec` is a modifiable record.

   From the calling context, `out_rec` points to a native program record (e.g. Config, ALUT native programs).
   There should be enough space in `out_rec->data` to hold at least 36 bytes (the size of a BPF upgradeable
   program account) when calling this function. The native program account's owner is set to the BPF loader
   upgradeable program ID, and lamports are increased / deducted to contain the rent exempt minimum balance.

   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L79-L95 */
static int
fd_new_target_program_account( fd_exec_slot_ctx_t * slot_ctx,
                               fd_pubkey_t const *  target_program_data_address,
                               fd_txn_account_t *   out_rec ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.0/sdk/account/src/lib.rs#L471 */
  out_rec->vt->set_rent_epoch( out_rec, 0UL );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L86-L88 */
  fd_bpf_upgradeable_loader_state_t state = {
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program,
    .inner = {
      .program = {
        .programdata_address = *target_program_data_address,
      }
    }
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L89-L90 */
  fd_rent_t const * rent = fd_bank_rent_query( slot_ctx->bank );
  if( FD_UNLIKELY( rent==NULL ) ) {
    return -1;
  }

  out_rec->vt->set_lamports( out_rec, fd_rent_exempt_minimum_balance( rent, SIZE_OF_PROGRAM ) );
  fd_bincode_encode_ctx_t ctx = {
    .data    = out_rec->vt->get_data_mut( out_rec ),
    .dataend = out_rec->vt->get_data_mut( out_rec ) + SIZE_OF_PROGRAM,
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L91-L9 */
  int err = fd_bpf_upgradeable_loader_state_encode( &state, &ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  out_rec->vt->set_owner( out_rec, &fd_solana_bpf_loader_upgradeable_program_id );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L93-L94 */
  out_rec->vt->set_executable( out_rec, 1 );
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* Mimics `bank.new_target_program_data_account()`. Assumes `new_target_program_data_account` is a modifiable record.
   `config_upgrade_authority_address` may be NULL.

   This function uses an existing buffer account `buffer_acc_rec` to set the program data account data for a core
   program BPF migration. Sets the lamports and data fields of `new_target_program_data_account` based on the
   ELF data length, and sets the owner to the BPF loader upgradeable program ID.

   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L97-L153 */
static int
fd_new_target_program_data_account( fd_exec_slot_ctx_t * slot_ctx,
                                    fd_pubkey_t *        config_upgrade_authority_address,
                                    fd_txn_account_t *   buffer_acc_rec,
                                    fd_txn_account_t *   new_target_program_data_account,
                                    fd_spad_t *          runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L113-L116 */
  int err;
  fd_bpf_upgradeable_loader_state_t * state = fd_bincode_decode_spad(
      bpf_upgradeable_loader_state, runtime_spad,
      buffer_acc_rec->vt->get_data( buffer_acc_rec ),
      buffer_acc_rec->vt->get_data_len( buffer_acc_rec ),
      &err );
  if( FD_UNLIKELY( err ) ) return err;

  if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_buffer( state ) ) ) {
    return -1;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L118-L125 */
  if( config_upgrade_authority_address!=NULL ) {
    if( FD_UNLIKELY( state->inner.buffer.authority_address==NULL ||
                     memcmp( config_upgrade_authority_address, state->inner.buffer.authority_address, sizeof(fd_pubkey_t) ) ) ) {
      return -1;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L127-L132 */
  fd_rent_t const * rent = fd_bank_rent_query( slot_ctx->bank );
  if( FD_UNLIKELY( rent==NULL ) ) {
    return -1;
  }

  const uchar * elf = buffer_acc_rec->vt->get_data( buffer_acc_rec ) + BUFFER_METADATA_SIZE;
  ulong space = PROGRAMDATA_METADATA_SIZE - BUFFER_METADATA_SIZE + buffer_acc_rec->vt->get_data_len( buffer_acc_rec );
  ulong lamports = fd_rent_exempt_minimum_balance( rent, space );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L134-L137 */
  fd_bpf_upgradeable_loader_state_t programdata_metadata = {
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
    .inner = {
      .program_data = {
        .slot = slot_ctx->bank->slot,
        .upgrade_authority_address = config_upgrade_authority_address
      }
    }
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L139-L144 */
  new_target_program_data_account->vt->set_lamports( new_target_program_data_account, lamports );
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = new_target_program_data_account->vt->get_data_mut( new_target_program_data_account ),
    .dataend = new_target_program_data_account->vt->get_data_mut( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE,
  };
  err = fd_bpf_upgradeable_loader_state_encode( &programdata_metadata, &encode_ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  new_target_program_data_account->vt->set_owner( new_target_program_data_account, &fd_solana_bpf_loader_upgradeable_program_id );

  /* Copy the ELF data over
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L145 */
  fd_memcpy( new_target_program_data_account->vt->get_data_mut( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE, elf, buffer_acc_rec->vt->get_data_len( buffer_acc_rec ) - BUFFER_METADATA_SIZE );

  return FD_RUNTIME_EXECUTE_SUCCESS;

  } FD_SPAD_FRAME_END;
}

/* Mimics `migrate_builtin_to_core_bpf()`. The arguments map as follows:
    - builtin_program_id: builtin_program_id
    - config
      - source_buffer_address: source_buffer_address
      - migration_target
        - Builtin: !stateless
        - Stateless: stateless
      - upgrade_authority_address: upgrade_authority_address
  https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L235-L318 */
static void
fd_migrate_builtin_to_core_bpf( fd_exec_slot_ctx_t * slot_ctx,
                                fd_pubkey_t *        upgrade_authority_address,
                                fd_pubkey_t const *  builtin_program_id,
                                fd_pubkey_t const *  source_buffer_address,
                                uchar                stateless,
                                fd_spad_t *          runtime_spad ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L242-L243

     The below logic is used to obtain a `TargetBuiltin` account. There are three fields of `TargetBuiltin` returned:
      - target.program_address: builtin_program_id
      - target.program_account:
          - if stateless: an AccountSharedData::default() (i.e. system program id, 0 lamports, 0 data, non-executable, system program owner)
          - if NOT stateless: the existing account (for us its called `target_program_account`)
      - target.program_data_address: `target_program_data_address` for us, derived below. */

  /* These checks will fail if the core program has already been migrated to BPF, since the account will exist + the program owner
     will no longer be the native loader.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L23-L50 */
  FD_TXN_ACCOUNT_DECL( target_program_account );
  uchar program_exists = ( fd_txn_account_init_from_funk_readonly( target_program_account, builtin_program_id, slot_ctx->funk, slot_ctx->funk_txn )==FD_ACC_MGR_SUCCESS );
  if( !stateless ) {
    /* The program account should exist.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L30-L33 */
    if( FD_UNLIKELY( !program_exists ) ) {
      FD_LOG_WARNING(( "Builtin program %s does not exist, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }

    /* The program account should be owned by the native loader.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L35-L38 */
    if( FD_UNLIKELY( memcmp( target_program_account->vt->get_owner( target_program_account ), fd_solana_native_loader_id.uc, sizeof(fd_pubkey_t) ) ) ) {
      FD_LOG_WARNING(( "Builtin program %s is not owned by the native loader, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }
  } else {
    /* The program account should _not_ exist.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L42-L46 */
    if( FD_UNLIKELY( program_exists ) ) {
      FD_LOG_WARNING(( "Stateless program %s already exists, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }
  }

  /* The program data account should not exist.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L52-L62 */
  uint custom_err = UINT_MAX;
  fd_pubkey_t target_program_data_address[ 1UL ];
  uchar * seeds[ 1UL ];
  seeds[ 0UL ]    = (uchar *)builtin_program_id;
  ulong seed_sz   = sizeof(fd_pubkey_t);
  uchar bump_seed = 0;
  err = fd_pubkey_find_program_address( &fd_solana_bpf_loader_upgradeable_program_id, 1UL, seeds, &seed_sz, target_program_data_address, &bump_seed, &custom_err );
  if( FD_UNLIKELY( err ) ) {
    /* TODO: We should handle these errors more gracefully instead of just killing the client. */
    FD_LOG_ERR(( "Unable to find a viable program address bump seed" )); // Solana panics, error code is undefined
    return;
  }
  FD_TXN_ACCOUNT_DECL( program_data_account );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( program_data_account, target_program_data_address, slot_ctx->funk, slot_ctx->funk_txn )==FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "Program data account %s already exists, skipping migration...", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L244

     Obtains a `SourceBuffer` account. There are two fields returned:
      - source.buffer_address: source_buffer_address
      - source.buffer_account: the existing buffer account */

  /* The buffer account should exist.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L26-L29 */
  FD_TXN_ACCOUNT_DECL( source_buffer_account );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_mutable( source_buffer_account, source_buffer_address, slot_ctx->funk, slot_ctx->funk_txn, 0, 0UL )!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "Buffer account %s does not exist, skipping migration...", FD_BASE58_ENC_32_ALLOCA( source_buffer_address ) ));
    return;
  }

  /* The buffer account should be owned by the upgradeable loader.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L31-L34 */
  if( FD_UNLIKELY( memcmp( source_buffer_account->vt->get_owner( source_buffer_account ), fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_WARNING(( "Buffer account %s is not owned by the upgradeable loader, skipping migration...", FD_BASE58_ENC_32_ALLOCA( source_buffer_address ) ));
    return;
  }

  /* The buffer account should have the correct state. We already check the buffer account state in `fd_new_target_program_data_account`,
      so we can skip the checks here.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L37-L47 */

  /* This check is done a bit prematurely because we calculate the previous account state's lamports. We use 0 for starting lamports
     for stateless accounts because they don't yet exist.

     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L277-L280 */
  ulong lamports_to_burn = ( stateless ? 0UL : target_program_account->vt->get_lamports( target_program_account ) ) + source_buffer_account->vt->get_lamports( source_buffer_account );

  /* Start a funk write txn */
  fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
  fd_funk_txn_xid_t migration_xid = fd_funk_generate_xid();
  fd_funk_txn_start_write( slot_ctx->funk );
  slot_ctx->funk_txn = fd_funk_txn_prepare( slot_ctx->funk, slot_ctx->funk_txn, &migration_xid, 0UL );
  fd_funk_txn_end_write( slot_ctx->funk );

  /* Attempt serialization of program account. If the program is stateless, we want to create the account. Otherwise,
     we want a writable handle to modify the existing account.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L246-L249 */
  FD_TXN_ACCOUNT_DECL( new_target_program_account );
  err = fd_txn_account_init_from_funk_mutable( new_target_program_account, builtin_program_id, slot_ctx->funk, slot_ctx->funk_txn, stateless, SIZE_OF_PROGRAM );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Builtin program ID %s does not exist", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }
  new_target_program_account->vt->set_data_len( new_target_program_account, SIZE_OF_PROGRAM );
  new_target_program_account->vt->set_slot( new_target_program_account, slot_ctx->bank->slot );

  /* Create a new target program account. This modifies the existing record. */
  err = fd_new_target_program_account( slot_ctx, target_program_data_address, new_target_program_account );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write new program state to %s", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }

  fd_txn_account_mutable_fini( new_target_program_account, slot_ctx->funk, slot_ctx->funk_txn );

  /* Create a new target program data account. */
  ulong new_target_program_data_account_sz = PROGRAMDATA_METADATA_SIZE - BUFFER_METADATA_SIZE + source_buffer_account->vt->get_data_len( source_buffer_account );
  FD_TXN_ACCOUNT_DECL( new_target_program_data_account );
  err = fd_txn_account_init_from_funk_mutable( new_target_program_data_account,
                                               target_program_data_address,
                                               slot_ctx->funk,
                                               slot_ctx->funk_txn,
                                               1,
                                               new_target_program_data_account_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to create new program data account to %s", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    goto fail;
  }
  new_target_program_data_account->vt->set_data_len( new_target_program_data_account, new_target_program_data_account_sz );
  new_target_program_data_account->vt->set_slot( new_target_program_data_account, slot_ctx->bank->slot );

  err = fd_new_target_program_data_account( slot_ctx,
                                            upgrade_authority_address,
                                            source_buffer_account,
                                            new_target_program_data_account,
                                            runtime_spad );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write new program data state to %s", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    goto fail;
  }

  fd_txn_account_mutable_fini( new_target_program_data_account, slot_ctx->funk, slot_ctx->funk_txn );

  /* Deploy the new target Core BPF program.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L268-L271 */
  err = fd_directly_invoke_loader_v3_deploy( slot_ctx,
                                             new_target_program_data_account->vt->get_data( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE,
                                             new_target_program_data_account->vt->get_data_len( new_target_program_data_account ) - PROGRAMDATA_METADATA_SIZE,
                                             runtime_spad );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to deploy program %s", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L281-L284 */
  ulong lamports_to_fund = new_target_program_account->vt->get_lamports( new_target_program_account ) + new_target_program_data_account->vt->get_lamports( new_target_program_data_account );

  /* Update capitalization.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L286-L297 */
  if( lamports_to_burn>lamports_to_fund ) {
    fd_bank_capitalization_set( slot_ctx->bank, fd_bank_capitalization_get( slot_ctx->bank ) - ( lamports_to_burn - lamports_to_fund ) );
  } else {
    fd_bank_capitalization_set( slot_ctx->bank, fd_bank_capitalization_get( slot_ctx->bank ) + ( lamports_to_fund - lamports_to_burn ) );
  }

  /* Reclaim the source buffer account
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L305 */
  source_buffer_account->vt->set_lamports( source_buffer_account, 0 );
  source_buffer_account->vt->set_data_len( source_buffer_account, 0 );
  source_buffer_account->vt->clear_owner( source_buffer_account );

  fd_txn_account_mutable_fini( source_buffer_account, slot_ctx->funk, slot_ctx->funk_txn );

  /* Publish the in-preparation transaction into the parent. We should not have to create
     a BPF cache entry here because the program is technically "delayed visibility", so the program
     should not be invokable until the next slot. The cache entry will be created at the end of the
     block as a part of the finalize routine. */
  fd_funk_txn_start_write( slot_ctx->funk );
  fd_funk_txn_publish_into_parent( slot_ctx->funk, slot_ctx->funk_txn, 1 );
  fd_funk_txn_end_write( slot_ctx->funk );
  slot_ctx->funk_txn = parent_txn;
  return;

fail:
  /* Cancel the in-preparation transaction and discard any in-progress changes. */
  fd_funk_txn_start_write( slot_ctx->funk );
  fd_funk_txn_cancel( slot_ctx->funk, slot_ctx->funk_txn, 0UL );
  fd_funk_txn_end_write( slot_ctx->funk );
  slot_ctx->funk_txn = parent_txn;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6704 */
static void
fd_apply_builtin_program_feature_transitions( fd_exec_slot_ctx_t * slot_ctx,
                                              fd_spad_t *          runtime_spad ) {
  /* TODO: Set the upgrade authority properly from the core bpf migration config. Right now it's set to None.

     Migrate any necessary stateless builtins to core BPF. So far, the only "stateless" builtin
     is the Feature program. Beginning checks in the `migrate_builtin_to_core_bpf` function will
     fail if the program has already been migrated to BPF. */

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_builtin_program_t const * builtins = fd_builtins();
  for( ulong i=0UL; i<fd_num_builtins(); i++ ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6732-L6751 */
    if( builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( slot_ctx->bank->slot, fd_bank_features_get( slot_ctx->bank ), builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      FD_LOG_NOTICE(( "Migrating builtin program %s to core BPF", FD_BASE58_ENC_32_ALLOCA( builtins[i].pubkey->key ) ));
      fd_migrate_builtin_to_core_bpf( slot_ctx,
                                      builtins[i].core_bpf_migration_config->upgrade_authority_address,
                                      builtins[i].core_bpf_migration_config->builtin_program_id,
                                      builtins[i].core_bpf_migration_config->source_buffer_address,
                                      0,
                                      runtime_spad );
    }
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6753-L6774 */
    if( builtins[i].enable_feature_offset!=NO_ENABLE_FEATURE_ID && FD_FEATURE_JUST_ACTIVATED_OFFSET( slot_ctx, builtins[i].enable_feature_offset ) ) {
      FD_LOG_NOTICE(( "Enabling builtin program %s", FD_BASE58_ENC_32_ALLOCA( builtins[i].pubkey->key ) ));
      fd_write_builtin_account( slot_ctx, *builtins[i].pubkey, builtins[i].data,strlen(builtins[i].data) );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6776-L6793 */
  fd_stateless_builtin_program_t const * stateless_builtins = fd_stateless_builtins();
  for( ulong i=0UL; i<fd_num_stateless_builtins(); i++ ) {
    if( stateless_builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( slot_ctx->bank->slot, fd_bank_features_get( slot_ctx->bank ), stateless_builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      FD_LOG_NOTICE(( "Migrating stateless builtin program %s to core BPF", FD_BASE58_ENC_32_ALLOCA( stateless_builtins[i].pubkey->key ) ));
      fd_migrate_builtin_to_core_bpf( slot_ctx,
                                      stateless_builtins[i].core_bpf_migration_config->upgrade_authority_address,
                                      stateless_builtins[i].core_bpf_migration_config->builtin_program_id,
                                      stateless_builtins[i].core_bpf_migration_config->source_buffer_address,
                                      1,
                                      runtime_spad );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/c1080de464cfb578c301e975f498964b5d5313db/runtime/src/bank.rs#L6795-L6805 */
  fd_precompile_program_t const * precompiles = fd_precompiles();
  for( ulong i=0UL; i<fd_num_precompiles(); i++ ) {
    if( FD_FEATURE_JUST_ACTIVATED_OFFSET( slot_ctx, precompiles[i].feature_offset ) ) {
      fd_write_builtin_account( slot_ctx, *precompiles[i].pubkey, "", 0 );
    }
  }

  } FD_SPAD_FRAME_END;
}

static void
fd_feature_activate( fd_features_t *         features,
                     fd_exec_slot_ctx_t *    slot_ctx,
                     fd_feature_id_t const * id,
                     uchar const             acct[ static 32 ],
                     fd_spad_t *             runtime_spad ) {

  // Skip reverted features from being activated
  if( id->reverted==1 ) {
    return;
  }

  FD_TXN_ACCOUNT_DECL( acct_rec );
  int err = fd_txn_account_init_from_funk_readonly( acct_rec, (fd_pubkey_t*)acct, slot_ctx->funk, slot_ctx->funk_txn );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    return;
  }

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  int decode_err = 0;
  fd_feature_t * feature = fd_bincode_decode_spad(
      feature, runtime_spad,
      acct_rec->vt->get_data( acct_rec ),
      acct_rec->vt->get_data_len( acct_rec ),
      &decode_err );
  if( FD_UNLIKELY( decode_err ) ) {
    FD_LOG_WARNING(( "Failed to decode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
    return;
  }

  if( feature->has_activated_at ) {
    FD_LOG_INFO(( "feature already activated - acc: %s, slot: %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
    fd_features_set( features, id, feature->activated_at);
  } else {
    FD_LOG_INFO(( "Feature %s not activated at %lu, activating", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));

    FD_TXN_ACCOUNT_DECL( modify_acct_rec );
    err = fd_txn_account_init_from_funk_mutable( modify_acct_rec, (fd_pubkey_t *)acct, slot_ctx->funk, slot_ctx->funk_txn, 0, 0UL );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      return;
    }

    feature->has_activated_at = 1;
    feature->activated_at     = slot_ctx->bank->slot;
    fd_bincode_encode_ctx_t encode_ctx = {
      .data    = modify_acct_rec->vt->get_data_mut( modify_acct_rec ),
      .dataend = modify_acct_rec->vt->get_data_mut( modify_acct_rec ) + modify_acct_rec->vt->get_data_len( modify_acct_rec ),
    };
    int encode_err = fd_feature_encode( feature, &encode_ctx );
    if( FD_UNLIKELY( encode_err != FD_BINCODE_SUCCESS ) ) {
      FD_LOG_ERR(( "Failed to encode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
    }

    fd_txn_account_mutable_fini( modify_acct_rec, slot_ctx->funk, slot_ctx->funk_txn );
  }

  } FD_SPAD_FRAME_END;
}

static void
fd_features_activate( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  fd_features_t * features = fd_bank_features_modify( slot_ctx->bank );
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_activate( features, slot_ctx, id, id->id.key, runtime_spad );
  }
}

uint
fd_runtime_is_epoch_boundary( fd_exec_slot_ctx_t * slot_ctx, ulong curr_slot, ulong prev_slot ) {
  ulong slot_idx;
  fd_epoch_schedule_t const * schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );
  ulong prev_epoch = fd_slot_to_epoch( schedule, prev_slot, &slot_idx );
  ulong new_epoch  = fd_slot_to_epoch( schedule, curr_slot, &slot_idx );

  return ( prev_epoch < new_epoch || slot_idx == 0 );
}

/* Starting a new epoch.
  New epoch:        T
  Just ended epoch: T-1
  Epoch before:     T-2

  In this function:
  - stakes in T-2 (epoch_stakes) should be replaced by T-1 (next_epoch_stakes)
  - stakes at T-1 (next_epoch_stakes) should be replaced by updated stakes at T (stakes->vote_accounts)
  - leader schedule should be calculated using new T-2 stakes (epoch_stakes)

  Invariant during an epoch T:
  next_epoch_stakes holds the stakes at T-1
  epoch_stakes holds the stakes at T-2
 */
/* process for the start of a new epoch */
static void
fd_runtime_process_new_epoch( fd_exec_slot_ctx_t * slot_ctx,
                              ulong                parent_epoch,
                              fd_tpool_t *         tpool,
                              fd_spad_t * *        exec_spads,
                              ulong                exec_spad_cnt,
                              fd_spad_t *          runtime_spad ) {
  FD_LOG_NOTICE(( "fd_process_new_epoch start" ));

  long start = fd_log_wallclock();

  ulong                       slot;
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );
  ulong                       epoch          = fd_slot_to_epoch( epoch_schedule, slot_ctx->bank->slot, &slot );

  /* Activate new features
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6587-L6598 */
  fd_features_activate( slot_ctx, runtime_spad );
  fd_features_restore( slot_ctx, runtime_spad );

  /* Apply builtin program feature transitions
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6621-L6624 */
  fd_apply_builtin_program_feature_transitions( slot_ctx, runtime_spad );

  /* Get the new rate activation epoch */
  int _err[1];
  ulong   new_rate_activation_epoch_val = 0UL;
  ulong * new_rate_activation_epoch     = &new_rate_activation_epoch_val;
  int     is_some                       = fd_new_warmup_cooldown_rate_epoch( slot_ctx->bank->slot,
                                                                             slot_ctx->funk,
                                                                             slot_ctx->funk_txn,
                                                                             runtime_spad,
                                                                             fd_bank_features_query( slot_ctx->bank ),
                                                                             new_rate_activation_epoch,
                                                                             _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_rate_activation_epoch = NULL;
  }

  fd_epoch_info_t temp_info = {0};
  fd_epoch_info_new( &temp_info );

  /* If appropiate, use the stakes at T-1 to generate the leader schedule instead of T-2.
      This is due to a subtlety in how Agave's stake caches interact when loading from snapshots.
      See the comment in fd_exec_slot_ctx_recover_. */

  if( fd_bank_use_prev_epoch_stake_get( slot_ctx->bank ) == epoch ) {
    fd_update_epoch_stakes( slot_ctx );
  }

  /* Updates stake history sysvar accumulated values. */
  fd_stakes_activate_epoch( slot_ctx,
                            new_rate_activation_epoch,
                            &temp_info,
                            tpool,
                            exec_spads,
                            exec_spad_cnt,
                            runtime_spad );

  /* Update the stakes epoch value to the new epoch */
  fd_stakes_global_t * stakes = fd_bank_stakes_locking_modify( slot_ctx->bank );
  stakes->epoch = epoch;
  fd_bank_stakes_end_locking_modify( slot_ctx->bank );

  fd_update_stake_delegations( slot_ctx, &temp_info );

  /* Refresh vote accounts in stakes cache using updated stake weights, and merges slot bank vote accounts with the epoch bank vote accounts.
    https://github.com/anza-xyz/agave/blob/v2.1.6/runtime/src/stakes.rs#L363-L370 */
  fd_stake_history_t const * history = fd_sysvar_stake_history_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
  if( FD_UNLIKELY( !history ) ) {
    FD_LOG_ERR(( "StakeHistory sysvar could not be read and decoded" ));
  }

  /* In order to correctly handle the lifetimes of allocations for partitioned
     epoch rewards, we will push a spad frame when rewards partitioning starts.
     We will only pop this frame when all of the rewards for the epoch have
     been distributed. As a note, this is technically not the most optimal use
     of memory as some data structures used can be freed when this function
     exits, but this is okay since the additional allocations are on the order
     of a few megabytes and are freed after a few thousand slots. */

  fd_spad_push( runtime_spad );

  fd_refresh_vote_accounts( slot_ctx,
                            history,
                            new_rate_activation_epoch,
                            &temp_info,
                            tpool,
                            exec_spads,
                            exec_spad_cnt,
                            runtime_spad );

  /* Distribute rewards */

  fd_block_hash_queue_global_t const * bhq              = (fd_block_hash_queue_global_t *)&slot_ctx->bank->block_hash_queue[0];
  fd_hash_t const *                    parent_blockhash = fd_block_hash_queue_last_hash_join( bhq );

  fd_begin_partitioned_rewards( slot_ctx,
                                parent_blockhash,
                                parent_epoch,
                                &temp_info,
                                tpool,
                                exec_spads,
                                exec_spad_cnt,
                                runtime_spad );

  /* Replace stakes at T-2 (epoch_stakes) by stakes at T-1 (next_epoch_stakes) */
  fd_update_epoch_stakes( slot_ctx );

  /* Replace stakes at T-1 (next_epoch_stakes) by updated stakes at T (stakes->vote_accounts) */
  fd_update_next_epoch_stakes( slot_ctx );

  /* Update current leaders using epoch_stakes (new T-2 stakes) */
  fd_runtime_update_leaders( slot_ctx->bank, slot_ctx->bank->slot, runtime_spad );

  fd_calculate_epoch_accounts_hash_values( slot_ctx );

  FD_LOG_NOTICE(( "fd_process_new_epoch end" ));

  long end = fd_log_wallclock();
  FD_LOG_NOTICE(("fd_process_new_epoch took %ld ns", end - start));
}

/******************************************************************************/
/* Block Parsing                                                              */
/******************************************************************************/

/* Block iteration and parsing */

/* As a note, all of the logic in this section is used by the full firedancer
   client. The store tile uses these APIs to help parse raw (micro)blocks
   received from the network. */

/* Helpers */

static int
fd_runtime_parse_microblock_hdr( void const *          buf FD_PARAM_UNUSED,
                                 ulong                 buf_sz ) {

  if( FD_UNLIKELY( buf_sz<sizeof(fd_microblock_hdr_t) ) ) {
    return -1;
  }
  return 0;
}

void
fd_runtime_update_program_cache( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_txn_p_t const *   txn_p,
                                 fd_spad_t *          runtime_spad ) {
  fd_txn_t const * txn_descriptor = TXN( txn_p );

  /* Iterate over account keys referenced directly in the transaction first */
  fd_acct_addr_t const * acc_addrs = fd_txn_get_acct_addrs( txn_descriptor, txn_p );
  for( ushort acc_idx=0; acc_idx<txn_descriptor->acct_addr_cnt; acc_idx++ ) {
    fd_pubkey_t const * account = fd_type_pun_const( &acc_addrs[acc_idx] );
    fd_bpf_program_update_program_cache( slot_ctx, account, runtime_spad );
  }

  if( txn_descriptor->transaction_version==FD_TXN_V0 ) {

    /* Iterate over account keys referenced in ALUTs */
    fd_acct_addr_t alut_accounts[256];
    fd_slot_hashes_global_t const * slot_hashes_global = fd_sysvar_slot_hashes_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
    if( FD_UNLIKELY( !slot_hashes_global ) ) {
      return;
    }

    fd_slot_hash_t * slot_hash = deq_fd_slot_hash_t_join( (uchar *)slot_hashes_global + slot_hashes_global->hashes_offset );

    if( FD_UNLIKELY( fd_runtime_load_txn_address_lookup_tables( txn_descriptor,
                         txn_p->payload,
                         slot_ctx->funk,
                         slot_ctx->funk_txn,
                         slot_ctx->bank->slot,
                         slot_hash,
                         alut_accounts ) ) ) {
      return;
    }

    for( ushort alut_idx=0; alut_idx<txn_descriptor->addr_table_adtl_cnt; alut_idx++ ) {
      fd_pubkey_t const * account = fd_type_pun_const( &alut_accounts[alut_idx] );
      fd_bpf_program_update_program_cache( slot_ctx, account, runtime_spad );
    }
  }
}

/* if we are currently in the middle of a batch, batch_cnt will include the current batch.
   if we are at the start of a batch, batch_cnt will include the current batch. */
static fd_raw_block_txn_iter_t
find_next_txn_in_raw_block( uchar const *                  orig_data,
                            fd_block_entry_batch_t const * batches, /* The batch we are currently consuming. */
                            ulong                          batch_cnt, /* Includes batch we are currently consuming. */
                            ulong                          curr_offset,
                            ulong                          num_microblocks ) {

  /* At this point, all the transactions in the current microblock have been consumed
     by fd_raw_block_txn_iter_next */

  /* Case 1: there are microblocks remaining in the current batch */
  for( ulong i=0UL; i<num_microblocks; i++ ) {
    ulong microblock_hdr_size            = sizeof(fd_microblock_hdr_t);
    fd_microblock_info_t microblock_info = {0};
    if( FD_UNLIKELY( fd_runtime_parse_microblock_hdr( orig_data + curr_offset,
                                                      batches->end_off - curr_offset ) ) ) {
      /* TODO: improve error handling */
      FD_LOG_ERR(( "premature end of batch" ));
    }
    microblock_info.microblock.hdr = (fd_microblock_hdr_t const * )(orig_data + curr_offset);
    curr_offset += microblock_hdr_size;

    /* If we have found a microblock with transactions in the current batch, return that */
    if( FD_LIKELY( microblock_info.microblock.hdr->txn_cnt ) ) {
      return (fd_raw_block_txn_iter_t){
        .curr_batch            = batches,
        .orig_data             = orig_data,
        .remaining_batches     = batch_cnt,
        .remaining_microblocks = fd_ulong_sat_sub( fd_ulong_sat_sub(num_microblocks, i), 1UL),
        .remaining_txns        = microblock_info.microblock.hdr->txn_cnt,
        .curr_offset           = curr_offset,
        .curr_txn_sz           = ULONG_MAX
      };
    }
  }

  /* If we have consumed the current batch, but did not find any txns, we need to move on to the next one */
  curr_offset = batches->end_off;
  batch_cnt   = fd_ulong_sat_sub( batch_cnt, 1UL );
  batches++;

  /* Case 2: need to find the next batch with a microblock in that has a non-zero number of txns */
  for( ulong i=0UL; i<batch_cnt; i++ ) {
    /* Sanity-check that we have not over-shot the end of the batch */
    ulong const batch_end_off = batches[i].end_off;
    if( FD_UNLIKELY( curr_offset+sizeof(ulong)>batch_end_off ) ) {
      FD_LOG_ERR(( "premature end of batch" ));
    }

    /* Consume the ulong describing how many microblocks there are */
    num_microblocks = FD_LOAD( ulong, orig_data + curr_offset );
    curr_offset    += sizeof(ulong);

    /* Iterate over each microblock until we find one with a non-zero txn cnt */
    for( ulong j=0UL; j<num_microblocks; j++ ) {
      ulong microblock_hdr_size            = sizeof(fd_microblock_hdr_t);
      fd_microblock_info_t microblock_info = {0};
      if( FD_UNLIKELY( fd_runtime_parse_microblock_hdr( orig_data + curr_offset,
                                                        batch_end_off - curr_offset ) ) ) {
        /* TODO: improve error handling */
        FD_LOG_ERR(( "premature end of batch" ));
      }
      microblock_info.microblock.hdr = (fd_microblock_hdr_t const * )(orig_data + curr_offset);
      curr_offset += microblock_hdr_size;

      /* If we have found a microblock with a non-zero number of transactions in, return that */
      if( FD_LIKELY( microblock_info.microblock.hdr->txn_cnt ) ) {
        return (fd_raw_block_txn_iter_t){
          .curr_batch            = &batches[i],
          .orig_data             = orig_data,
          .remaining_batches     = fd_ulong_sat_sub( batch_cnt, i ),
          .remaining_microblocks = fd_ulong_sat_sub( fd_ulong_sat_sub( num_microblocks, j ), 1UL ),
          .remaining_txns        = microblock_info.microblock.hdr->txn_cnt,
          .curr_offset           = curr_offset,
          .curr_txn_sz           = ULONG_MAX
        };
      }
    }

    /* Skip to the start of the next batch */
    curr_offset = batch_end_off;
  }

  /* Case 3: we didn't manage to find any microblocks with non-zero transaction counts in */
  return (fd_raw_block_txn_iter_t) {
    .curr_batch            = batches,
    .orig_data             = orig_data,
    .remaining_batches     = 0UL,
    .remaining_microblocks = 0UL,
    .remaining_txns        = 0UL,
    .curr_offset           = curr_offset,
    .curr_txn_sz           = ULONG_MAX
  };
}

/* Public API */

fd_raw_block_txn_iter_t
fd_raw_block_txn_iter_init( uchar const *                  orig_data,
                            fd_block_entry_batch_t const * batches,
                            ulong                          batch_cnt ) {
  /* In general, every read of a lower level count should lead to a
     decrement of a higher level count.  For example, reading a count
     of microblocks should lead to a decrement of the number of
     remaining batches.  In some sense, the batch count is drained into
     the microblock count. */

  ulong num_microblocks = FD_LOAD( ulong, orig_data );
  return find_next_txn_in_raw_block( orig_data, batches, batch_cnt, sizeof(ulong), num_microblocks );
}

ulong
fd_raw_block_txn_iter_done( fd_raw_block_txn_iter_t iter ) {
  return iter.remaining_batches==0UL && iter.remaining_microblocks==0UL && iter.remaining_txns==0UL;
}

fd_raw_block_txn_iter_t
fd_raw_block_txn_iter_next( fd_raw_block_txn_iter_t iter ) {
  ulong const batch_end_off = iter.curr_batch->end_off;
  fd_txn_p_t out_txn;
  if( iter.curr_txn_sz == ULONG_MAX ) {
    ulong payload_sz = 0;
    ulong txn_sz = fd_txn_parse_core( iter.orig_data + iter.curr_offset, fd_ulong_min( batch_end_off - iter.curr_offset, FD_TXN_MTU), TXN(&out_txn), NULL, &payload_sz );
    if( FD_UNLIKELY( !txn_sz || txn_sz>FD_TXN_MTU ) ) {
      FD_LOG_ERR(("Invalid txn parse"));
    }
    iter.curr_offset += payload_sz;
  } else {
    iter.curr_offset += iter.curr_txn_sz;
    iter.curr_txn_sz  = ULONG_MAX;
  }

  if( --iter.remaining_txns ) {
    return iter;
  }

  return find_next_txn_in_raw_block( iter.orig_data,
                                     iter.curr_batch,
                                     iter.remaining_batches,
                                     iter.curr_offset,
                                     iter.remaining_microblocks );
}

void
fd_raw_block_txn_iter_ele( fd_raw_block_txn_iter_t iter, fd_txn_p_t * out_txn ) {
  ulong const batch_end_off = iter.curr_batch->end_off;
  ulong       payload_sz    = 0UL;
  ulong       txn_sz        = fd_txn_parse_core( iter.orig_data + iter.curr_offset,
                                                 fd_ulong_min( batch_end_off - iter.curr_offset, FD_TXN_MTU ),
                                                 TXN( out_txn ), NULL, &payload_sz );

  if( FD_UNLIKELY( !txn_sz || txn_sz>FD_TXN_MTU ) ) {
    FD_LOG_ERR(( "Invalid txn parse %lu", txn_sz ));
  }
  fd_memcpy( out_txn->payload, iter.orig_data + iter.curr_offset, payload_sz );
  out_txn->payload_sz = (ushort)payload_sz;
  iter.curr_txn_sz    = payload_sz;
}

/******************************************************************************/
/* Block Parsing logic (Only for offline replay)                              */
/******************************************************************************/

/* The below runtime block parsing and block destroying logic is ONLY used in
   offline replay to simulate the block parsing/freeing that would occur in
   the full, live firedancer client. This is done via two APIs:
   fd_runtime_block_prepare and fd_runtime_block_destroy. */

/* Helpers for fd_runtime_block_prepare */

static int
fd_runtime_parse_microblock_txns( void const *                buf,
                                  ulong                       buf_sz,
                                  fd_microblock_hdr_t const * microblock_hdr,
                                  fd_txn_p_t *                out_txns,
                                  ulong *                     out_signature_cnt,
                                  ulong *                     out_account_cnt,
                                  ulong *                     out_microblock_txns_sz ) {

  ulong buf_off       = 0UL;
  ulong signature_cnt = 0UL;
  ulong account_cnt   = 0UL;

  for( ulong i=0UL; i<microblock_hdr->txn_cnt; i++ ) {
    ulong payload_sz = 0UL;
    ulong txn_sz     = fd_txn_parse_core( (uchar const *)buf + buf_off,
                                          fd_ulong_min( buf_sz-buf_off, FD_TXN_MTU ),
                                          TXN( &out_txns[i] ),
                                          NULL,
                                          &payload_sz );
    if( FD_UNLIKELY( !txn_sz || txn_sz>FD_TXN_MTU || !payload_sz  ) ) {
      return -1;
    }

    fd_memcpy( out_txns[i].payload, (uchar *)buf + buf_off, payload_sz );
    out_txns[i].payload_sz = (ushort)payload_sz;

    signature_cnt += TXN( &out_txns[i] )->signature_cnt;
    account_cnt   += fd_txn_account_cnt( TXN(&out_txns[i]), FD_TXN_ACCT_CAT_ALL );
    buf_off       += payload_sz;
  }

  *out_signature_cnt      = signature_cnt;
  *out_account_cnt        = account_cnt;
  *out_microblock_txns_sz = buf_off;

  return 0;
}

static int
fd_runtime_microblock_prepare( void const *           buf,
                               ulong                  buf_sz,
                               fd_spad_t *            runtime_spad,
                               fd_microblock_info_t * out_microblock_info ) {

  fd_microblock_info_t microblock_info = {
    .signature_cnt  = 0UL,
  };
  ulong buf_off = 0UL;
  ulong hdr_sz  = sizeof(fd_microblock_hdr_t);
  if( FD_UNLIKELY( fd_runtime_parse_microblock_hdr( buf, buf_sz ) ) ) {
    return -1;
  }
  microblock_info.microblock.hdr = (fd_microblock_hdr_t const *)buf;
  buf_off += hdr_sz;

  ulong txn_cnt        = microblock_info.microblock.hdr->txn_cnt;
  microblock_info.txns = fd_spad_alloc( runtime_spad, alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );
  ulong txns_sz        = 0UL;
  if( FD_UNLIKELY( fd_runtime_parse_microblock_txns( (uchar *)buf + buf_off,
                                                     buf_sz - buf_off,
                                                     microblock_info.microblock.hdr,
                                                     microblock_info.txns,
                                                     &microblock_info.signature_cnt,
                                                     &microblock_info.account_cnt,
                                                     &txns_sz ) ) ) {
    return -1;
  }

  buf_off                          += txns_sz;
  microblock_info.raw_microblock_sz = buf_off;
  *out_microblock_info              = microblock_info;

  return 0;
}

static int
fd_runtime_microblock_batch_prepare( void const *                 buf,
                                     ulong                        buf_sz,
                                     fd_spad_t *                  runtime_spad,
                                     fd_microblock_batch_info_t * out_microblock_batch_info ) {

  fd_microblock_batch_info_t microblock_batch_info = {
    .raw_microblock_batch = buf,
    .signature_cnt        = 0UL,
    .txn_cnt              = 0UL,
    .account_cnt          = 0UL,
  };
  ulong buf_off = 0UL;

  if( FD_UNLIKELY( buf_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "microblock batch buffer too small" ));
    return -1;
  }
  ulong microblock_cnt = FD_LOAD( ulong, buf );
  buf_off             += sizeof(ulong);

  microblock_batch_info.microblock_cnt   = microblock_cnt;
  microblock_batch_info.microblock_infos = fd_spad_alloc( runtime_spad, alignof(fd_microblock_info_t), microblock_cnt * sizeof(fd_microblock_info_t) );

  ulong signature_cnt = 0UL;
  ulong txn_cnt       = 0UL;
  ulong account_cnt   = 0UL;
  for( ulong i=0UL; i<microblock_cnt; i++ ) {
    fd_microblock_info_t * microblock_info = &microblock_batch_info.microblock_infos[i];
    if( FD_UNLIKELY( fd_runtime_microblock_prepare( (uchar const *)buf + buf_off, buf_sz - buf_off, runtime_spad, microblock_info ) ) ) {
      return -1;
    }

    signature_cnt += microblock_info->signature_cnt;
    txn_cnt       += microblock_info->microblock.hdr->txn_cnt;
    account_cnt   += microblock_info->account_cnt;
    buf_off       += microblock_info->raw_microblock_sz;
  }

  microblock_batch_info.signature_cnt           = signature_cnt;
  microblock_batch_info.txn_cnt                 = txn_cnt;
  microblock_batch_info.account_cnt             = account_cnt;
  microblock_batch_info.raw_microblock_batch_sz = buf_off;

  *out_microblock_batch_info                    = microblock_batch_info;

  return 0;
}

/* This function is used for parsing/preparing blocks during offline runtime replay. */
static int
fd_runtime_block_prepare( fd_blockstore_t         * blockstore,
                          fd_block_t              * block,
                          ulong                     slot,
                          fd_spad_t               * runtime_spad,
                          fd_runtime_block_info_t * out_block_info ) {
  uchar const *                  buf         = fd_blockstore_block_data_laddr( blockstore, block );
  ulong const                    buf_sz      = block->data_sz;
  fd_block_entry_batch_t const * batch_laddr = fd_blockstore_block_batch_laddr( blockstore, block );
  ulong const                    batch_cnt   = block->batch_cnt;

  fd_runtime_block_info_t block_info = {
      .raw_block    = buf,
      .raw_block_sz = buf_sz,
  };

  ulong microblock_batch_cnt        = 0UL;
  ulong microblock_cnt              = 0UL;
  ulong signature_cnt               = 0UL;
  ulong txn_cnt                     = 0UL;
  ulong account_cnt                 = 0UL;
  block_info.microblock_batch_infos = fd_spad_alloc( runtime_spad, alignof(fd_microblock_batch_info_t), block->batch_cnt * sizeof(fd_microblock_batch_info_t) );

  ulong buf_off = 0UL;
  for( microblock_batch_cnt=0UL; microblock_batch_cnt < batch_cnt; microblock_batch_cnt++ ) {
    ulong const batch_end_off = batch_laddr[ microblock_batch_cnt ].end_off;
    fd_microblock_batch_info_t * microblock_batch_info = block_info.microblock_batch_infos + microblock_batch_cnt;
    if( FD_UNLIKELY( fd_runtime_microblock_batch_prepare( buf + buf_off, batch_end_off - buf_off, runtime_spad, microblock_batch_info ) ) ) {
      return -1;
    }

    signature_cnt  += microblock_batch_info->signature_cnt;
    txn_cnt        += microblock_batch_info->txn_cnt;
    account_cnt    += microblock_batch_info->account_cnt;
    microblock_cnt += microblock_batch_info->microblock_cnt;

    uchar allow_trailing = 1UL;
    buf_off += microblock_batch_info->raw_microblock_batch_sz;
    if( FD_UNLIKELY( buf_off > batch_end_off ) ) {
      FD_LOG_ERR(( "parser error: shouldn't have been allowed to read past batch boundary" ));
    }
    if( FD_UNLIKELY( buf_off < batch_end_off ) ) {
      if( FD_LIKELY( allow_trailing ) ) {
        FD_LOG_NOTICE(( "ignoring %lu trailing bytes in slot %lu batch %lu", batch_end_off-buf_off, slot, microblock_batch_cnt ));
      }
      if( FD_UNLIKELY( !allow_trailing ) ) {
        FD_LOG_WARNING(( "%lu trailing bytes in slot %lu batch %lu", batch_end_off-buf_off, slot, microblock_batch_cnt ));
        return -1;
      }
    }
    buf_off = batch_end_off;
  }

  block_info.microblock_batch_cnt = microblock_batch_cnt;
  block_info.microblock_cnt       = microblock_cnt;
  block_info.signature_cnt        = signature_cnt;
  block_info.txn_cnt              = txn_cnt;
  block_info.account_cnt          = account_cnt;

  *out_block_info = block_info;

  return 0;
}

/* Block collecting (Only for offline replay) */

static ulong
fd_runtime_microblock_collect_txns( fd_microblock_info_t const * microblock_info,
                                    fd_txn_p_t *                 out_txns ) {
  ulong txn_cnt = microblock_info->microblock.hdr->txn_cnt;
  fd_memcpy( out_txns, microblock_info->txns, txn_cnt * sizeof(fd_txn_p_t) );
  return txn_cnt;
}

static ulong
fd_runtime_microblock_batch_collect_txns( fd_microblock_batch_info_t const * microblock_batch_info,
                                          fd_txn_p_t *                       out_txns ) {
  for( ulong i=0UL; i<microblock_batch_info->microblock_cnt; i++ ) {
    ulong txns_collected = fd_runtime_microblock_collect_txns( &microblock_batch_info->microblock_infos[i], out_txns );
    out_txns            += txns_collected;
  }

  return microblock_batch_info->txn_cnt;
}

static ulong
fd_runtime_block_collect_txns( fd_runtime_block_info_t const * block_info,
                               fd_txn_p_t *            out_txns ) {
  for( ulong i=0UL; i<block_info->microblock_batch_cnt; i++ ) {
    ulong txns_collected = fd_runtime_microblock_batch_collect_txns( &block_info->microblock_batch_infos[i], out_txns );
    out_txns            += txns_collected;
  }

  return block_info->txn_cnt;
}

/******************************************************************************/
/* Genesis                                                                    */
/*******************************************************************************/

static void
fd_runtime_init_program( fd_exec_slot_ctx_t * slot_ctx,
                         fd_spad_t *          runtime_spad ) {
  fd_sysvar_recent_hashes_init( slot_ctx, runtime_spad );
  fd_sysvar_clock_init( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn );
  fd_sysvar_slot_history_init( slot_ctx, runtime_spad );
  fd_sysvar_slot_hashes_init( slot_ctx, runtime_spad );
  fd_sysvar_epoch_schedule_init( slot_ctx );
  fd_sysvar_rent_init( slot_ctx );
  fd_sysvar_stake_history_init( slot_ctx );
  fd_sysvar_last_restart_slot_init( slot_ctx );

  fd_builtin_programs_init( slot_ctx );
  fd_stake_program_config_init( slot_ctx );
}

static void
fd_runtime_init_bank_from_genesis( fd_exec_slot_ctx_t *        slot_ctx,
                                   fd_genesis_solana_t const * genesis_block,
                                   fd_hash_t const *           genesis_hash,
                                   fd_spad_t *                 runtime_spad ) {

  fd_bank_poh_set( slot_ctx->bank, *genesis_hash );

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( slot_ctx->bank );
  memset( bank_hash->hash, 0, FD_SHA256_HASH_SZ );

  fd_poh_config_t const * poh  = &genesis_block->poh_config;
  uint128 target_tick_duration = ((uint128)poh->target_tick_duration.seconds * 1000000000UL + (uint128)poh->target_tick_duration.nanoseconds);

  fd_bank_epoch_schedule_set( slot_ctx->bank, genesis_block->epoch_schedule );

  fd_bank_rent_set( slot_ctx->bank, genesis_block->rent );

  fd_bank_block_height_set( slot_ctx->bank, 0UL );

  fd_bank_inflation_set( slot_ctx->bank, genesis_block->inflation );

  fd_block_hash_queue_global_t *      block_hash_queue = (fd_block_hash_queue_global_t *)&slot_ctx->bank->block_hash_queue[0];
  uchar *                             last_hash_mem    = (uchar *)fd_ulong_align_up( (ulong)block_hash_queue + sizeof(fd_block_hash_queue_global_t), alignof(fd_hash_t) );
  uchar *                             ages_pool_mem    = (uchar *)fd_ulong_align_up( (ulong)last_hash_mem + sizeof(fd_hash_t), fd_hash_hash_age_pair_t_map_align() );
  fd_hash_hash_age_pair_t_mapnode_t * ages_pool        = fd_hash_hash_age_pair_t_map_join( fd_hash_hash_age_pair_t_map_new( ages_pool_mem, 400 ) );
  fd_hash_hash_age_pair_t_mapnode_t * ages_root        = NULL;

  fd_hash_hash_age_pair_t_mapnode_t * node = fd_hash_hash_age_pair_t_map_acquire( ages_pool );
  node->elem = (fd_hash_hash_age_pair_t){
    .key = *genesis_hash,
    .val = (fd_hash_age_t){ .hash_index = 0UL, .fee_calculator = (fd_fee_calculator_t){ .lamports_per_signature = 0UL }, .timestamp = (ulong)fd_log_wallclock() }
  };
  fd_hash_hash_age_pair_t_map_insert( ages_pool, &ages_root, node );
  fd_memcpy( last_hash_mem, genesis_hash, FD_HASH_FOOTPRINT );

  block_hash_queue->last_hash_index  = 0UL;
  block_hash_queue->last_hash_offset = (ulong)last_hash_mem - (ulong)block_hash_queue;
  block_hash_queue->ages_pool_offset = (ulong)fd_hash_hash_age_pair_t_map_leave( ages_pool ) - (ulong)block_hash_queue;
  block_hash_queue->ages_root_offset = (ulong)ages_root - (ulong)block_hash_queue;
  block_hash_queue->max_age          = FD_BLOCKHASH_QUEUE_MAX_ENTRIES;

  fd_bank_fee_rate_governor_set( slot_ctx->bank, genesis_block->fee_rate_governor );

  fd_bank_lamports_per_signature_set( slot_ctx->bank, 0UL );

  fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, 0UL );

  fd_bank_max_tick_height_set( slot_ctx->bank, genesis_block->ticks_per_slot * (slot_ctx->bank->slot + 1) );

  fd_bank_hashes_per_tick_set( slot_ctx->bank, !!poh->hashes_per_tick ? poh->hashes_per_tick : 0UL );

  fd_bank_ns_per_slot_set( slot_ctx->bank, target_tick_duration * genesis_block->ticks_per_slot );

  fd_bank_ticks_per_slot_set( slot_ctx->bank, genesis_block->ticks_per_slot );

  fd_bank_genesis_creation_time_set( slot_ctx->bank, genesis_block->creation_time );

  fd_bank_slots_per_year_set( slot_ctx->bank, SECONDS_PER_YEAR * (1000000000.0 / (double)target_tick_duration) / (double)genesis_block->ticks_per_slot );

  fd_bank_signature_count_set( slot_ctx->bank, 0UL );

  /* Derive epoch stakes */

  fd_stakes_global_t * stakes_global = fd_bank_stakes_locking_modify( slot_ctx->bank );

  uchar * vacc_pool_mem = (uchar *)fd_ulong_align_up( (ulong)stakes_global + sizeof(fd_stakes_global_t), fd_vote_accounts_pair_global_t_map_align() );
  fd_vote_accounts_pair_global_t_mapnode_t * vacc_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( vacc_pool_mem, 5000UL ) );
  fd_vote_accounts_pair_global_t_mapnode_t * vacc_root = NULL;


  uchar * sacc_pool_mem = (uchar *)fd_ulong_align_up( (ulong)vacc_pool + fd_vote_accounts_pair_global_t_map_footprint( 5000UL ), fd_delegation_pair_t_map_align() );
  fd_delegation_pair_t_mapnode_t * sacc_pool = fd_delegation_pair_t_map_join( fd_delegation_pair_t_map_new( sacc_pool_mem, 5000UL ) );
  fd_delegation_pair_t_mapnode_t * sacc_root = NULL;

  fd_acc_lamports_t capitalization = 0UL;

  fd_features_t * features = fd_bank_features_modify( slot_ctx->bank );
  FD_FEATURE_SET_ACTIVE(features, accounts_lt_hash, 0);
  FD_FEATURE_SET_ACTIVE(features, remove_accounts_delta_hash, 0);

  for( ulong i=0UL; i<genesis_block->accounts_len; i++ ) {
    fd_pubkey_account_pair_t const * acc = &genesis_block->accounts[i];
    capitalization = fd_ulong_sat_add( capitalization, acc->account.lamports );

    if( !memcmp(acc->account.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)) ) {
      /* Vote Program Account */
      fd_vote_accounts_pair_global_t_mapnode_t * node = fd_vote_accounts_pair_global_t_map_acquire(vacc_pool);
      FD_TEST( node );

      fd_memcpy(node->elem.key.key, acc->key.key, sizeof(fd_pubkey_t));
      node->elem.stake = acc->account.lamports;
      node->elem.value = (fd_solana_account_global_t){
        .lamports = acc->account.lamports,
        .data_len = acc->account.data_len,
        .data_offset = 0UL, /* FIXME: remove this field from the cache altogether. */
        .owner = acc->account.owner,
        .executable = acc->account.executable,
        .rent_epoch = acc->account.rent_epoch
      };
      fd_solana_account_data_update( &node->elem.value, acc->account.data );

      fd_vote_accounts_pair_global_t_map_insert( vacc_pool, &vacc_root, node );

      FD_LOG_INFO(( "Adding genesis vote account: key=%s stake=%lu",
                    FD_BASE58_ENC_32_ALLOCA( node->elem.key.key ),
                    node->elem.stake ));
    } else if( !memcmp( acc->account.owner.key, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* stake program account */
      fd_stake_state_v2_t   stake_state   = {0};
      fd_account_meta_t     meta          = { .dlen = acc->account.data_len };
      FD_TXN_ACCOUNT_DECL( stake_account );
      fd_txn_account_init_from_meta_and_data_mutable( stake_account, &meta, acc->account.data );
      FD_TEST( fd_stake_get_state( stake_account, &stake_state ) == 0 );
      if( !stake_state.inner.stake.stake.delegation.stake ) {
        continue;
      }
      fd_delegation_pair_t_mapnode_t   query_node = {0};
      fd_memcpy(&query_node.elem.account, acc->key.key, sizeof(fd_pubkey_t));
      fd_delegation_pair_t_mapnode_t * node = fd_delegation_pair_t_map_find( sacc_pool, sacc_root, &query_node );

      if( !node ) {
        node = fd_delegation_pair_t_map_acquire( sacc_pool );
        fd_memcpy( &node->elem.account, acc->key.key, sizeof(fd_pubkey_t) );
        node->elem.delegation = stake_state.inner.stake.stake.delegation;
        fd_delegation_pair_t_map_insert( sacc_pool, &sacc_root, node );
      } else {
        fd_memcpy( &node->elem.account, acc->key.key, sizeof(fd_pubkey_t) );
        node->elem.delegation = stake_state.inner.stake.stake.delegation;
      }
    } else if( !memcmp(acc->account.owner.key, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t)) ) {
      /* Feature Account */

      /* Scan list of feature IDs to resolve address => feature offset */
      fd_feature_id_t const *found = NULL;
      for( fd_feature_id_t const * id = fd_feature_iter_init();
           !fd_feature_iter_done( id );
           id = fd_feature_iter_next( id ) ) {
        if( !memcmp( acc->key.key, id->id.key, sizeof(fd_pubkey_t) ) ) {
          found = id;
          break;
        }
      }

      if( found ) {
        /* Load feature activation */
        FD_SPAD_FRAME_BEGIN( runtime_spad ) {
          int err;
          fd_feature_t * feature = fd_bincode_decode_spad(
              feature, runtime_spad,
              acc->account.data,
              acc->account.data_len,
              &err );
          FD_TEST( err==FD_BINCODE_SUCCESS );

          fd_features_t * features = fd_bank_features_modify( slot_ctx->bank );
          if( feature->has_activated_at ) {
            FD_LOG_DEBUG(( "Feature %s activated at %lu (genesis)", FD_BASE58_ENC_32_ALLOCA( acc->key.key ), feature->activated_at ));
            fd_features_set( features, found, feature->activated_at );
          } else {
            FD_LOG_DEBUG(( "Feature %s not activated (genesis)", FD_BASE58_ENC_32_ALLOCA( acc->key.key ) ));
            fd_features_set( features, found, ULONG_MAX );
          }
        } FD_SPAD_FRAME_END;
      }
    }
  }

  fd_vote_accounts_global_t * epoch_stakes = fd_bank_epoch_stakes_locking_modify( slot_ctx->bank );
  uchar * pool_mem = (uchar *)fd_ulong_align_up( (ulong)epoch_stakes + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_t_map_align() );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( pool_mem, 50000UL ) );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = NULL;

  uchar * epoch_stakes_vote_acc_region_curr = (uchar *)fd_ulong_align_up( (ulong)vote_accounts_pool + fd_vote_accounts_pair_global_t_map_footprint( 50000UL ), 8UL );

  fd_vote_accounts_global_t * next_epoch_stakes = fd_bank_next_epoch_stakes_locking_modify( slot_ctx->bank );
  uchar * next_pool_mem = (uchar *)fd_ulong_align_up( (ulong)next_epoch_stakes + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_t_map_align() );
  fd_vote_accounts_pair_global_t_mapnode_t * next_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( next_pool_mem, 50000UL ) );
  fd_vote_accounts_pair_global_t_mapnode_t * next_root = NULL;

  uchar * next_epoch_stakes_acc_region_curr = (uchar *)fd_ulong_align_up( (ulong)next_pool + fd_vote_accounts_pair_global_t_map_footprint( 50000UL ), 8UL );

  for( ulong i=0UL; i<genesis_block->accounts_len; i++ ) {
    fd_pubkey_account_pair_t const * acc = &genesis_block->accounts[i];

    if( !memcmp( acc->account.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {

      /* Insert into the epoch_stakes vote accounts map */
      fd_vote_accounts_pair_global_t_mapnode_t * e = fd_vote_accounts_pair_global_t_map_acquire( vote_accounts_pool );
      FD_TEST( e );
      e->elem.key = acc->key;
      e->elem.stake = acc->account.lamports;
      e->elem.value = (fd_solana_account_global_t){
        .lamports = acc->account.lamports,
        .data_len = acc->account.data_len,
        .data_offset = 0UL, /* FIXME: remove this field from the cache altogether. */
        .owner = acc->account.owner,
        .executable = acc->account.executable,
        .rent_epoch = acc->account.rent_epoch
      };

      memcpy( epoch_stakes_vote_acc_region_curr, acc->account.data, acc->account.data_len );
      e->elem.value.data_offset = (ulong)(epoch_stakes_vote_acc_region_curr - (uchar *)&e->elem.value);
      epoch_stakes_vote_acc_region_curr += acc->account.data_len;

      fd_vote_accounts_pair_global_t_map_insert( vote_accounts_pool, &vote_accounts_root, e );

      /* Insert into the next_epoch_stakes vote accounts map */
      /* FIXME: is this correct? */
      fd_vote_accounts_pair_global_t_mapnode_t * next_e = fd_vote_accounts_pair_global_t_map_acquire( next_pool );
      FD_TEST( next_e );
      next_e->elem.key = acc->key;
      next_e->elem.stake = acc->account.lamports;
      next_e->elem.value = (fd_solana_account_global_t){
        .lamports = acc->account.lamports,
        .data_len = acc->account.data_len,
        .data_offset = 0UL, /* FIXME: remove this field from the cache altogether. */
        .owner = acc->account.owner,
        .executable = acc->account.executable,
        .rent_epoch = acc->account.rent_epoch
      };

      memcpy( next_epoch_stakes_acc_region_curr, acc->account.data, acc->account.data_len );
      next_e->elem.value.data_offset = (ulong)(next_epoch_stakes_acc_region_curr - (uchar *)&next_e->elem.value);
      next_epoch_stakes_acc_region_curr += acc->account.data_len;

      fd_vote_accounts_pair_global_t_map_insert( next_pool, &next_root, next_e );
    }

  }

  for( fd_delegation_pair_t_mapnode_t *n = fd_delegation_pair_t_map_minimum( sacc_pool, sacc_root );
       n;
       n = fd_delegation_pair_t_map_successor( sacc_pool, n )) {
    fd_vote_accounts_pair_global_t_mapnode_t query_voter = {0};
    query_voter.elem.key = n->elem.delegation.voter_pubkey;

    fd_vote_accounts_pair_global_t_mapnode_t * voter = fd_vote_accounts_pair_global_t_map_find( vacc_pool, vacc_root, &query_voter );

    if( !!voter ) {
      voter->elem.stake = fd_ulong_sat_add( voter->elem.stake, n->elem.delegation.stake );
    }
  }

  fd_vote_accounts_vote_accounts_pool_update( epoch_stakes, vote_accounts_pool );
  fd_vote_accounts_vote_accounts_root_update( epoch_stakes, vote_accounts_root );


  fd_vote_accounts_vote_accounts_pool_update( next_epoch_stakes, next_pool );
  fd_vote_accounts_vote_accounts_root_update( next_epoch_stakes, next_root );

  fd_bank_epoch_stakes_end_locking_modify( slot_ctx->bank );

  fd_bank_next_epoch_stakes_end_locking_modify( slot_ctx->bank );



  stakes_global->epoch  = 0UL;
  stakes_global->unused = 0UL;

  fd_vote_accounts_vote_accounts_pool_update( &stakes_global->vote_accounts, vacc_pool );
  fd_vote_accounts_vote_accounts_root_update( &stakes_global->vote_accounts, vacc_root );
  fd_stakes_stake_delegations_pool_update( stakes_global, sacc_pool );
  fd_stakes_stake_delegations_root_update( stakes_global, sacc_root );
  fd_bank_stakes_end_locking_modify( slot_ctx->bank );

  fd_bank_capitalization_set( slot_ctx->bank, capitalization );

  fd_clock_timestamp_votes_global_t * clock_timestamp_votes = fd_bank_clock_timestamp_votes_locking_modify( slot_ctx->bank );
  uchar * clock_pool_mem = (uchar *)fd_ulong_align_up( (ulong)clock_timestamp_votes + sizeof(fd_clock_timestamp_votes_global_t), fd_clock_timestamp_vote_t_map_align() );
  fd_clock_timestamp_vote_t_mapnode_t * clock_pool = fd_clock_timestamp_vote_t_map_join( fd_clock_timestamp_vote_t_map_new(clock_pool_mem, 30000UL ) );
  clock_timestamp_votes->votes_pool_offset = (ulong)fd_clock_timestamp_vote_t_map_leave( clock_pool) - (ulong)clock_timestamp_votes;
  clock_timestamp_votes->votes_root_offset = 0UL;
  fd_bank_clock_timestamp_votes_end_locking_modify( slot_ctx->bank );
}

static int
fd_runtime_process_genesis_block( fd_exec_slot_ctx_t * slot_ctx,
                                  fd_capture_ctx_t *   capture_ctx,
                                  fd_spad_t *          runtime_spad ) {


  fd_hash_t * poh = fd_bank_poh_modify( slot_ctx->bank );
  ulong hashcnt_per_slot = fd_bank_hashes_per_tick_get( slot_ctx->bank ) * fd_bank_ticks_per_slot_get( slot_ctx->bank );
  while( hashcnt_per_slot-- ) {
    fd_sha256_hash( poh->hash, sizeof(fd_hash_t), poh->hash );
  }

  fd_bank_execution_fees_set( slot_ctx->bank, 0UL );

  fd_bank_priority_fees_set( slot_ctx->bank, 0UL );

  fd_bank_signature_count_set( slot_ctx->bank, 0UL );

  fd_bank_txn_count_set( slot_ctx->bank, 0UL );

  fd_bank_failed_txn_count_set( slot_ctx->bank, 0UL );

  fd_bank_nonvote_failed_txn_count_set( slot_ctx->bank, 0UL );

  fd_bank_total_compute_units_used_set( slot_ctx->bank, 0UL );

  fd_runtime_init_program( slot_ctx, runtime_spad );

  fd_sysvar_slot_history_update( slot_ctx, runtime_spad );

  fd_runtime_update_leaders( slot_ctx->bank, 0, runtime_spad );

  fd_runtime_freeze( slot_ctx, runtime_spad );

  /* sort and update bank hash */
  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( slot_ctx->bank );
  int result = fd_update_hash_bank_tpool( slot_ctx,
                                          capture_ctx,
                                          bank_hash,
                                          0UL,
                                          NULL,
                                          runtime_spad );

  if( FD_UNLIKELY( result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    FD_LOG_ERR(( "Failed to update bank hash with error=%d", result ));
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_read_genesis( fd_exec_slot_ctx_t * slot_ctx,
                         char const *         genesis_filepath,
                         uchar                is_snapshot,
                         fd_capture_ctx_t *   capture_ctx,
                         fd_spad_t *          runtime_spad ) {

  if( strlen( genesis_filepath ) == 0 ) {
    return;
  }

  struct stat sbuf;
  if( FD_UNLIKELY( stat( genesis_filepath, &sbuf) < 0 ) ) {
    FD_LOG_ERR(( "cannot open %s : %s", genesis_filepath, strerror(errno) ));
  }
  int fd = open( genesis_filepath, O_RDONLY );
  if( FD_UNLIKELY( fd < 0 ) ) {
    FD_LOG_ERR(("cannot open %s : %s", genesis_filepath, strerror(errno)));
  }

  fd_genesis_solana_t * genesis_block;
  fd_hash_t             genesis_hash;

  /* NOTE: These genesis decode spad allocs persist through the lifetime of fd_runtime,
     even though they aren't used outside of this function. This is because
     fd_runtime_init_bank_from_genesis, which depends on the genesis_block, initializes
     a bunch of structures on spad that need to persist throughout fd_runtime. Using a bump
     allocator does not let us free memory lower in the stack without freeing everything
     above it (in a meaningful way).

     FIXME: Use spad frames here once the fd_runtime structures initialized here are no
     longer spad-backed. */

  uchar * buf = fd_spad_alloc( runtime_spad, alignof(ulong), (ulong)sbuf.st_size );
  ulong sz    = 0UL;
  int res     = fd_io_read( fd, buf, (ulong)sbuf.st_size, (ulong)sbuf.st_size, &sz );
  FD_TEST( res==0 );
  FD_TEST( sz==(ulong)sbuf.st_size );
  close( fd );

    int err;
    genesis_block = fd_bincode_decode_spad(
        genesis_solana, runtime_spad, buf, sz, &err );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_ERR(( "fd_genesis_solana_decode_footprint failed (%d)", err ));
    }

  // The hash is generated from the raw data... don't mess with this..
  fd_sha256_hash( buf, sz, genesis_hash.uc );

  fd_hash_t * genesis_hash_bm = fd_bank_genesis_hash_modify( slot_ctx->bank );
  fd_memcpy( genesis_hash_bm, buf, sizeof(fd_hash_t) );

  if( !is_snapshot ) {
    /* Create a new Funk transaction for slot 0 */
    fd_funk_txn_start_write( slot_ctx->funk );
    fd_funk_txn_xid_t xid = { 0 };
    xid.ul[1] = 0UL;
    xid.ul[0] = 0UL;
    slot_ctx->funk_txn = fd_funk_txn_prepare( slot_ctx->funk, NULL, &xid, 1 );
    fd_funk_txn_end_write( slot_ctx->funk );

    fd_runtime_init_bank_from_genesis( slot_ctx,
                                        genesis_block,
                                        &genesis_hash,
                                        runtime_spad );

    FD_LOG_DEBUG(( "start genesis accounts - count: %lu", genesis_block->accounts_len ));

    for( ulong i=0; i<genesis_block->accounts_len; i++ ) {
      fd_pubkey_account_pair_t * a = &genesis_block->accounts[i];

      FD_TXN_ACCOUNT_DECL( rec );

      int err = fd_txn_account_init_from_funk_mutable( rec,
                                                      &a->key,
                                                      slot_ctx->funk,
                                                      slot_ctx->funk_txn,
                                                      1, /* do_create */
                                                      a->account.data_len );

      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "fd_txn_account_init_from_funk_mutable failed (%d)", err ));
      }

      rec->vt->set_data( rec, a->account.data, a->account.data_len );
      rec->vt->set_lamports( rec, a->account.lamports );
      rec->vt->set_rent_epoch( rec, a->account.rent_epoch );
      rec->vt->set_executable( rec, a->account.executable );
      rec->vt->set_owner( rec, &a->account.owner );

      fd_txn_account_mutable_fini( rec, slot_ctx->funk, slot_ctx->funk_txn );
    }

    FD_LOG_DEBUG(( "end genesis accounts" ));

    FD_LOG_DEBUG(( "native instruction processors - count: %lu", genesis_block->native_instruction_processors_len ));

    for( ulong i=0UL; i < genesis_block->native_instruction_processors_len; i++ ) {
      fd_string_pubkey_pair_t * a = &genesis_block->native_instruction_processors[i];
      fd_write_builtin_account( slot_ctx, a->pubkey, (const char *) a->string, a->string_len );
    }

    fd_features_restore( slot_ctx, runtime_spad );

    int err = fd_runtime_process_genesis_block( slot_ctx, capture_ctx, runtime_spad );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Genesis slot 0 execute failed with error %d", err ));
    }
  }


  fd_account_keys_global_t *         stake_account_keys      = fd_bank_stake_account_keys_locking_modify( slot_ctx->bank );
  uchar *                            pool_mem                = (uchar *)fd_ulong_align_up( (ulong)stake_account_keys + sizeof(fd_account_keys_global_t), fd_account_keys_pair_t_map_align() );
  fd_account_keys_pair_t_mapnode_t * stake_account_keys_pool = fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( pool_mem, 100000UL ) );
  fd_account_keys_pair_t_mapnode_t * stake_account_keys_root = NULL;

  fd_account_keys_account_keys_pool_update( stake_account_keys, stake_account_keys_pool );
  fd_account_keys_account_keys_root_update( stake_account_keys, stake_account_keys_root );
  fd_bank_stake_account_keys_end_locking_modify( slot_ctx->bank );

  fd_account_keys_global_t *         vote_account_keys      = fd_bank_vote_account_keys_locking_modify( slot_ctx->bank );
                                     pool_mem               = (uchar *)fd_ulong_align_up( (ulong)vote_account_keys + sizeof(fd_account_keys_global_t), fd_account_keys_pair_t_map_align() );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_pool = fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( pool_mem, 100000UL ) );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_root = NULL;

  fd_account_keys_account_keys_pool_update( vote_account_keys, vote_account_keys_pool );
  fd_account_keys_account_keys_root_update( vote_account_keys, vote_account_keys_root );

  fd_bank_vote_account_keys_end_locking_modify( slot_ctx->bank );
}

/******************************************************************************/
/* Offline Replay                                                             */
/******************************************************************************/

/* As a note, currently offline and live replay of transactions has differences
   with regards to how the execution environment is setup. These are helpers
   used to emulate this behavior */

struct fd_poh_verification_info {
  fd_microblock_info_t const * microblock_info;
  fd_hash_t const            * in_poh_hash;
  int success;
};
typedef struct fd_poh_verification_info fd_poh_verification_info_t;

static void
fd_runtime_microblock_verify_info_collect( fd_microblock_info_t const * microblock_info,
                                           fd_hash_t            const * in_poh_hash,
                                           fd_poh_verification_info_t * poh_verification_info ) {
  poh_verification_info->microblock_info = microblock_info;
  poh_verification_info->in_poh_hash     = in_poh_hash;
  poh_verification_info->success         = 0;
}

static void
fd_runtime_microblock_batch_verify_info_collect( fd_microblock_batch_info_t const * microblock_batch_info,
                                                 fd_hash_t                  const * in_poh_hash,
                                                 fd_poh_verification_info_t *       poh_verification_info ) {
  for( ulong i=0UL; i<microblock_batch_info->microblock_cnt; i++ ) {
    fd_microblock_info_t const * microblock_info = &microblock_batch_info->microblock_infos[i];
    fd_runtime_microblock_verify_info_collect( microblock_info, in_poh_hash, &poh_verification_info[i] );
    in_poh_hash = (fd_hash_t const *)&microblock_info->microblock.hdr->hash;
  }
}

static void
fd_runtime_block_verify_info_collect( fd_runtime_block_info_t const *      block_info,
                                      fd_hash_t       const *      in_poh_hash,
                                      fd_poh_verification_info_t * poh_verification_info)
{
  for( ulong i=0UL; i<block_info->microblock_batch_cnt; i++ ) {
    fd_microblock_batch_info_t const * microblock_batch_info = &block_info->microblock_batch_infos[i];

    fd_runtime_microblock_batch_verify_info_collect( microblock_batch_info, in_poh_hash, poh_verification_info );
    in_poh_hash            = (fd_hash_t const *)poh_verification_info[microblock_batch_info->microblock_cnt - 1].microblock_info->microblock.hdr->hash;
    poh_verification_info += microblock_batch_info->microblock_cnt;
  }
}

static void
fd_runtime_poh_verify_wide_task( void * tpool,
                                 ulong  t0 FD_PARAM_UNUSED,
                                 ulong  t1 FD_PARAM_UNUSED,
                                 void * args FD_PARAM_UNUSED,
                                 void * reduce FD_PARAM_UNUSED,
                                 ulong  stride FD_PARAM_UNUSED,
                                 ulong  l0 FD_PARAM_UNUSED,
                                 ulong  l1 FD_PARAM_UNUSED,
                                 ulong  m0,
                                 ulong  m1 FD_PARAM_UNUSED,
                                 ulong  n0 FD_PARAM_UNUSED,
                                 ulong  n1 FD_PARAM_UNUSED ) {
  fd_poh_verification_info_t * poh_info = (fd_poh_verification_info_t *)tpool + m0;

  fd_hash_t out_poh_hash = *poh_info->in_poh_hash;
  fd_hash_t init_poh_hash_cpy = *poh_info->in_poh_hash;

  fd_microblock_info_t const *microblock_info = poh_info->microblock_info;
  ulong hash_cnt = microblock_info->microblock.hdr->hash_cnt;
  ulong txn_cnt = microblock_info->microblock.hdr->txn_cnt;

  if( !txn_cnt ) { /* microblock is a tick */
    fd_poh_append( &out_poh_hash, hash_cnt );
  } else {
    if( hash_cnt ) {
      fd_poh_append(&out_poh_hash, hash_cnt - 1);
    }

    ulong                 leaf_cnt = microblock_info->signature_cnt;
    uchar *               commit   = fd_alloca_check( FD_WBMTREE32_ALIGN, fd_wbmtree32_footprint(leaf_cnt));
    fd_wbmtree32_leaf_t * leafs    = fd_alloca_check(alignof(fd_wbmtree32_leaf_t), sizeof(fd_wbmtree32_leaf_t) * leaf_cnt);
    uchar *               mbuf     = fd_alloca_check( 1UL, leaf_cnt * (sizeof(fd_ed25519_sig_t) + 1) );

    fd_wbmtree32_t *      tree = fd_wbmtree32_init(commit, leaf_cnt);
    fd_wbmtree32_leaf_t * l    = &leafs[0];

    /* Loop across transactions */
    for( ulong txn_idx=0UL; txn_idx<txn_cnt; txn_idx++ ) {
      fd_txn_p_t          * txn_p      = &microblock_info->txns[txn_idx];
      fd_txn_t      const * txn        = (fd_txn_t const *) txn_p->_;
      fd_rawtxn_b_t const   raw_txn[1] = {{ .raw = txn_p->payload, .txn_sz = (ushort)txn_p->payload_sz } };

      /* Loop across signatures */
      fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)((ulong)raw_txn->raw + (ulong)txn->signature_off);
      for( ulong j=0UL; j<txn->signature_cnt; j++ ) {
        l->data     = (uchar *)&sigs[j];
        l->data_len = sizeof(fd_ed25519_sig_t);
        l++;
      }
    }

    fd_wbmtree32_append( tree, leafs, leaf_cnt, mbuf );
    uchar * root = fd_wbmtree32_fini( tree );
    fd_poh_mixin( &out_poh_hash, root );
  }

  if( FD_UNLIKELY( memcmp(microblock_info->microblock.hdr->hash, out_poh_hash.hash, sizeof(fd_hash_t)) ) ) {
    FD_LOG_WARNING(( "poh mismatch (bank: %s, entry: %s. INIT: %s)",
        FD_BASE58_ENC_32_ALLOCA( out_poh_hash.hash ),
        FD_BASE58_ENC_32_ALLOCA( microblock_info->microblock.hdr->hash ),
        FD_BASE58_ENC_32_ALLOCA(&init_poh_hash_cpy) ));
    poh_info->success = -1;
  }
}

static int
fd_runtime_poh_verify_tpool( fd_poh_verification_info_t * poh_verification_info,
                             ulong                        poh_verification_info_cnt,
                             fd_tpool_t *                 tpool ) {
  fd_tpool_exec_all_rrobin( tpool,
                            0,
                            fd_tpool_worker_cnt( tpool ),
                            fd_runtime_poh_verify_wide_task,
                            poh_verification_info,
                            NULL,
                            NULL,
                            1,
                            0,
                            poh_verification_info_cnt );

  for( ulong i=0UL; i<poh_verification_info_cnt; i++ ) {
    if( poh_verification_info[i].success ) {
      return -1;
    }
  }

  return 0;
}

static int
fd_runtime_block_verify_tpool( fd_exec_slot_ctx_t *            slot_ctx,
                               fd_blockstore_t *               blockstore,
                               fd_runtime_block_info_t const * block_info,
                               fd_hash_t const *               in_poh_hash,
                               fd_hash_t *                     out_poh_hash,
                               fd_tpool_t *                    tpool,
                               fd_spad_t *                     runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  long block_verify_time = -fd_log_wallclock();

  fd_hash_t                    tmp_in_poh_hash           = *in_poh_hash;
  ulong                        poh_verification_info_cnt = block_info->microblock_cnt;
  fd_poh_verification_info_t * poh_verification_info     = fd_spad_alloc( runtime_spad,
                                                                          alignof(fd_poh_verification_info_t),
                                                                          poh_verification_info_cnt * sizeof(fd_poh_verification_info_t) );
  fd_runtime_block_verify_info_collect( block_info, &tmp_in_poh_hash, poh_verification_info );

  uchar * block_data = fd_spad_alloc( runtime_spad, 128UL, FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT );
  ulong   tick_res   = fd_runtime_block_verify_ticks( blockstore,
                                                      slot_ctx->bank->slot,
                                                      block_data,
                                                      FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT,
                                                      fd_bank_tick_height_get( slot_ctx->bank ),
                                                      fd_bank_max_tick_height_get( slot_ctx->bank ),
                                                      fd_bank_hashes_per_tick_get( slot_ctx->bank ) );

  if( FD_UNLIKELY( tick_res != FD_BLOCK_OK ) ) {
    FD_LOG_WARNING(( "failed to verify ticks res %lu slot %lu", tick_res, slot_ctx->bank->slot ));
    return -1;
  }

  /* poh_verification_info is now in order information of all the microblocks */

  int result = fd_runtime_poh_verify_tpool( poh_verification_info, poh_verification_info_cnt, tpool );
  fd_memcpy( out_poh_hash->hash, poh_verification_info[poh_verification_info_cnt - 1].microblock_info->microblock.hdr->hash, sizeof(fd_hash_t) );

  block_verify_time          += fd_log_wallclock();
  double block_verify_time_ms = (double)block_verify_time * 1e-6;

  FD_LOG_INFO(( "verified block successfully - elapsed: %6.6f ms", block_verify_time_ms ));

  return result;

  } FD_SPAD_FRAME_END;
}

/* Should only be called in offline replay */
static int
fd_runtime_publish_old_txns( fd_exec_slot_ctx_t * slot_ctx,
                             fd_capture_ctx_t *   capture_ctx,
                             fd_tpool_t *         tpool,
                             fd_spad_t *          runtime_spad ) {
  /* Publish any transaction older than 31 slots */
  fd_funk_txn_start_write( slot_ctx->funk );
  fd_funk_t *          funk       = slot_ctx->funk;
  fd_funk_txn_pool_t * txnpool    = fd_funk_txn_pool( funk );

  if( capture_ctx != NULL ) {
    fd_runtime_checkpt( capture_ctx, slot_ctx, slot_ctx->bank->slot );
  }

  int do_eah = 0;

  uint depth = 0;
  for( fd_funk_txn_t * txn = slot_ctx->funk_txn; txn; txn = fd_funk_txn_parent(txn, txnpool) ) {
    if( ++depth == (FD_RUNTIME_OFFLINE_NUM_ROOT_BLOCKS - 1 ) ) {
      FD_LOG_DEBUG(("publishing %s (slot %lu)", FD_BASE58_ENC_32_ALLOCA( &txn->xid ), txn->xid.ul[0]));

      if( FD_UNLIKELY( !fd_funk_txn_publish( funk, txn, 1 ) ) ) {
        FD_LOG_ERR(( "No transactions were published" ));
      }

      /* Also publish the bank */
      ulong slot = txn->xid.ul[0];
      fd_banks_publish( slot_ctx->banks, slot );

      if( txn->xid.ul[0] >= fd_bank_eah_start_slot_get( slot_ctx->bank ) ) {
        if( !FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, accounts_lt_hash ) ) {
          do_eah = 1;
        }
        fd_bank_eah_start_slot_set( slot_ctx->bank, ULONG_MAX );
      }

      break;
    }
  }

  fd_funk_txn_end_write( slot_ctx->funk );

  /* Do the EAH calculation after we have released the Funk lock, to avoid a deadlock */
  if( FD_UNLIKELY( do_eah ) ) {
    fd_exec_para_cb_ctx_t exec_para_ctx = {
      .func       = fd_accounts_hash_counter_and_gather_tpool_cb,
      .para_arg_1 = tpool
    };


    fd_hash_t * epoch_account_hash = fd_bank_epoch_account_hash_modify( slot_ctx->bank );
    fd_accounts_hash( slot_ctx->funk,
                      slot_ctx->bank->slot,
                      epoch_account_hash,
                      runtime_spad,
                      fd_bank_features_query( slot_ctx->bank ),
                      &exec_para_ctx,
                      NULL );
  }

  return 0;
}

int
fd_runtime_block_execute_tpool( fd_exec_slot_ctx_t *            slot_ctx,
                                fd_blockstore_t *               blockstore,
                                fd_capture_ctx_t *              capture_ctx,
                                fd_runtime_block_info_t const * block_info,
                                fd_tpool_t *                    tpool,
                                fd_spad_t * *                   exec_spads,
                                ulong                           exec_spad_cnt,
                                fd_spad_t *                     runtime_spad ) {

  if ( capture_ctx != NULL && capture_ctx->capture && slot_ctx->bank->slot>=capture_ctx->solcap_start_slot ) {
    fd_solcap_writer_set_slot( capture_ctx->capture, slot_ctx->bank->slot );
  }

  long block_execute_time = -fd_log_wallclock();

  int res = fd_runtime_block_execute_prepare( slot_ctx, blockstore, runtime_spad );
  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    return res;
  }

  ulong        txn_cnt  = block_info->txn_cnt;
  fd_txn_p_t * txn_ptrs = fd_spad_alloc( runtime_spad, alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );

  fd_runtime_block_collect_txns( block_info, txn_ptrs );

  /* Initialize the cost tracker when the feature is active */
  fd_cost_tracker_t * cost_tracker = fd_spad_alloc( runtime_spad, FD_COST_TRACKER_ALIGN, sizeof(fd_cost_tracker_t) );
  fd_cost_tracker_init( cost_tracker, runtime_spad );

  /* We want to emulate microblock-by-microblock execution */
  ulong to_exec_idx = 0UL;
  for( ulong i=0UL; i<block_info->microblock_batch_cnt; i++ ) {
    for( ulong j=0UL; j<block_info->microblock_batch_infos[i].microblock_cnt; j++ ) {
      ulong txn_cnt = block_info->microblock_batch_infos[i].microblock_infos[j].microblock.hdr->txn_cnt;
      fd_txn_p_t * mblock_txn_ptrs = &txn_ptrs[ to_exec_idx ];
      ulong        mblock_txn_cnt  = txn_cnt;
      to_exec_idx += txn_cnt;

      /* UPDATE */

      if( !mblock_txn_cnt ) continue;

      /* Reverify programs for this epoch if needed */
      for( ulong txn_idx=0UL; txn_idx<mblock_txn_cnt; txn_idx++ ) {
        fd_runtime_update_program_cache( slot_ctx, &mblock_txn_ptrs[txn_idx], runtime_spad );
      }

      res = fd_runtime_process_txns_in_microblock_stream( slot_ctx,
                                                          capture_ctx,
                                                          mblock_txn_ptrs,
                                                          mblock_txn_cnt,
                                                          tpool,
                                                          exec_spads,
                                                          exec_spad_cnt,
                                                          runtime_spad,
                                                          cost_tracker );
      if( FD_UNLIKELY( res!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        return res;
      }
    }
  }

  long block_finalize_time = -fd_log_wallclock();

  fd_exec_para_cb_ctx_t exec_para_ctx = {
    .func       = block_finalize_tpool_wrapper,
    .para_arg_1 = tpool
  };

  res = fd_runtime_block_execute_finalize_para( slot_ctx,
                                                capture_ctx,
                                                block_info,
                                                fd_tpool_worker_cnt( tpool ),
                                                runtime_spad,
                                                &exec_para_ctx );
  if( FD_UNLIKELY( res!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return res;
  }

  block_finalize_time += fd_log_wallclock();
  double block_finalize_time_ms = (double)block_finalize_time * 1e-6;
  FD_LOG_INFO(( "finalized block successfully - slot: %lu, elapsed: %6.6f ms", slot_ctx->bank->slot, block_finalize_time_ms ));

  block_execute_time += fd_log_wallclock();
  double block_execute_time_ms = (double)block_execute_time * 1e-6;

  FD_LOG_INFO(( "executed block successfully - slot: %lu, elapsed: %6.6f ms", slot_ctx->bank->slot, block_execute_time_ms ));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_block_pre_execute_process_new_epoch( fd_exec_slot_ctx_t * slot_ctx,
                                                fd_tpool_t *         tpool,
                                                fd_spad_t * *        exec_spads,
                                                ulong                exec_spad_cnt,
                                                fd_spad_t *          runtime_spad,
                                                int *                is_epoch_boundary ) {

  /* Update block height. */
  fd_bank_block_height_set( slot_ctx->bank, fd_bank_block_height_get( slot_ctx->bank ) + 1UL );

  if( slot_ctx->bank->slot != 0UL ) {
    fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );

    ulong             slot_idx;
    ulong             prev_epoch = fd_slot_to_epoch( epoch_schedule, fd_bank_prev_slot_get( slot_ctx->bank ), &slot_idx );
    ulong             new_epoch  = fd_slot_to_epoch( epoch_schedule, slot_ctx->bank->slot, &slot_idx );
    if( FD_UNLIKELY( slot_idx==1UL && new_epoch==0UL ) ) {
      /* The block after genesis has a height of 1. */
      fd_bank_block_height_set( slot_ctx->bank, 1UL );
    }

    if( FD_UNLIKELY( prev_epoch<new_epoch || !slot_idx ) ) {
      FD_LOG_DEBUG(( "Epoch boundary" ));
      /* Epoch boundary! */
      fd_runtime_process_new_epoch( slot_ctx,
                                    new_epoch - 1UL,
                                    tpool,
                                    exec_spads,
                                    exec_spad_cnt,
                                    runtime_spad );
      *is_epoch_boundary = 1;
    }
  } else {
    *is_epoch_boundary = 0;
  }

  if( FD_LIKELY( slot_ctx->bank->slot!=0UL ) ) {
    fd_distribute_partitioned_epoch_rewards( slot_ctx,
                                             tpool,
                                             exec_spads,
                                             exec_spad_cnt,
                                             runtime_spad );
  }
}

int
fd_runtime_block_eval_tpool( fd_exec_slot_ctx_t * slot_ctx,
                             ulong                slot,
                             fd_block_t *         block,
                             fd_capture_ctx_t *   capture_ctx,
                             fd_tpool_t *         tpool,
                             ulong                scheduler,
                             ulong *              txn_cnt,
                             fd_spad_t * *        exec_spads,
                             ulong                exec_spad_cnt,
                             fd_spad_t *          runtime_spad,
                             fd_blockstore_t *    blockstore ) {

  /* offline replay */
  (void)scheduler;

  int err = fd_runtime_publish_old_txns( slot_ctx, capture_ctx, tpool, runtime_spad );
  if( err != 0 ) {
    return err;
  }

  fd_funk_t * funk = slot_ctx->funk;

  long block_eval_time = -fd_log_wallclock();
  fd_runtime_block_info_t block_info;
  int ret = FD_RUNTIME_EXECUTE_SUCCESS;
  do {

    /* Start a new funk txn. */

    fd_funk_txn_xid_t xid = { .ul = { slot, slot } };
    fd_funk_txn_start_write( funk );
    slot_ctx->funk_txn = fd_funk_txn_prepare( funk, slot_ctx->funk_txn, &xid, 1 );
    fd_funk_txn_end_write( funk );

    /* Capturing block-agnostic state in preparation for the epoch boundary */
    uchar dump_block = capture_ctx && slot >= capture_ctx->dump_proto_start_slot && capture_ctx->dump_block_to_pb;
    fd_exec_test_block_context_t * block_ctx = NULL;
    if( FD_UNLIKELY( dump_block ) ) {
      /* TODO: This probably should get allocated from a separate spad for the capture ctx */
      block_ctx = fd_spad_alloc( runtime_spad, alignof(fd_exec_test_block_context_t), sizeof(fd_exec_test_block_context_t) );
      fd_memset( block_ctx, 0, sizeof(fd_exec_test_block_context_t) );
      fd_dump_block_to_protobuf( slot_ctx, capture_ctx, runtime_spad, block_ctx );
    }

    int is_epoch_boundary = 0;
    fd_runtime_block_pre_execute_process_new_epoch( slot_ctx,
                                                    tpool,
                                                    exec_spads,
                                                    exec_spad_cnt,
                                                    runtime_spad,
                                                    &is_epoch_boundary );

    /* All runtime allocations here are scoped to the end of a block. */
    FD_SPAD_FRAME_BEGIN( runtime_spad ) {

    if( FD_UNLIKELY( (ret = fd_runtime_block_prepare( blockstore,
                                                      block,
                                                      slot,
                                                      runtime_spad,
                                                      &block_info )) != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      break;
    }
    *txn_cnt = block_info.txn_cnt;

    fd_hash_t poh_out = {0};
    fd_hash_t poh_in = fd_bank_poh_get( slot_ctx->bank );
    if( FD_UNLIKELY( (ret = fd_runtime_block_verify_tpool( slot_ctx, blockstore, &block_info, &poh_in, &poh_out, tpool, runtime_spad )) != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      break;
    }

    fd_bank_poh_set( slot_ctx->bank, poh_out );

    /* Dump the remainder of the block after preparation, POH verification, etc */
    if( FD_UNLIKELY( dump_block ) ) {
      fd_dump_block_to_protobuf_tx_only( &block_info, slot_ctx, capture_ctx, runtime_spad, block_ctx );
    }

    if( FD_UNLIKELY( (ret = fd_runtime_block_execute_tpool( slot_ctx,
                                                            blockstore,
                                                            capture_ctx,
                                                            &block_info,
                                                            tpool,
                                                            exec_spads,
                                                            exec_spad_cnt,
                                                            runtime_spad )) != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      break;
    }

    } FD_SPAD_FRAME_END;

  } while( 0 );

  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != ret ) ) {
    FD_LOG_WARNING(( "execution failure, code %d", ret ));
    return ret;
  }

  block_eval_time          += fd_log_wallclock();
  double block_eval_time_ms = (double)block_eval_time * 1e-6;
  double tps                = (double) block_info.txn_cnt / ((double)block_eval_time * 1e-9);
  fd_epoch_leaders_t const * leaders = fd_bank_epoch_leaders_locking_query( slot_ctx->bank );
  fd_pubkey_t const *        leader  = fd_epoch_leaders_get( leaders, slot );
  FD_LOG_INFO(( "evaluated block successfully - slot: %lu, elapsed: %6.6f ms, signatures: %lu, txns: %lu, tps: %6.6f, leader: %s",
                slot,
                block_eval_time_ms,
                block_info.signature_cnt,
                block_info.txn_cnt,
                tps,
                FD_BASE58_ENC_32_ALLOCA( leader ) ));
  fd_bank_epoch_leaders_end_locking_query( slot_ctx->bank );

  fd_bank_transaction_count_set( slot_ctx->bank, fd_bank_transaction_count_get( slot_ctx->bank ) + block_info.txn_cnt );

  fd_bank_prev_slot_set( slot_ctx->bank, slot );

  return 0;
}

/******************************************************************************/
/* Debugging Tools                                                            */
/******************************************************************************/

void
fd_runtime_checkpt( fd_capture_ctx_t *   capture_ctx,
                    fd_exec_slot_ctx_t * slot_ctx,
                    ulong                slot ) {
  int is_checkpt_freq = capture_ctx != NULL && slot % capture_ctx->checkpt_freq == 0;
  int is_abort_slot   = slot == ULONG_MAX;
  if( !is_checkpt_freq && !is_abort_slot ) {
    return;
  }

  if( capture_ctx->checkpt_path != NULL ) {
    if( !is_abort_slot ) {
      FD_LOG_NOTICE(( "checkpointing at slot=%lu to file=%s", slot, capture_ctx->checkpt_path ));
    } else {
      FD_LOG_NOTICE(( "checkpointing after mismatch to file=%s", capture_ctx->checkpt_path ));
    }

    unlink( capture_ctx->checkpt_path );
    int err = fd_wksp_checkpt( fd_funk_wksp( slot_ctx->funk ), capture_ctx->checkpt_path, 0666, 0, NULL );
    if ( err ) {
      FD_LOG_ERR(( "backup failed: error %d", err ));
    }
  }
}
