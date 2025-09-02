#include "fd_runtime.h"
#include "context/fd_capture_ctx.h"
#include "fd_acc_mgr.h"
#include "fd_bank.h"
#include "fd_hashes.h"
#include "fd_runtime_err.h"
#include "fd_runtime_init.h"
#include "fd_pubkey_utils.h"

#include "fd_executor.h"
#include "fd_cost_tracker.h"
#include "fd_runtime_public.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_stake_history.h"

#include "../stakes/fd_stakes.h"
#include "../rewards/fd_rewards.h"

#include "context/fd_exec_txn_ctx.h"
#include "info/fd_microblock_batch_info.h"
#include "info/fd_microblock_info.h"

#include "program/fd_stake_program.h"
#include "program/fd_builtin_programs.h"
#include "program/fd_vote_program.h"
#include "program/fd_program_cache.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_address_lookup_table_program.h"

#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_last_restart_slot.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_slot_hashes.h"
#include "sysvar/fd_sysvar_slot_history.h"

#include "tests/fd_dump_pb.h"

#include "fd_system_ids.h"
#include "../vm/fd_vm.h"
#include "../../disco/pack/fd_pack.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

/******************************************************************************/
/* Public Runtime Helpers                                                     */
/******************************************************************************/

int
fd_runtime_should_use_vote_keyed_leader_schedule( fd_bank_t * bank ) {
  /* Agave uses an option type for their effective_epoch value. We
     represent None as ULONG_MAX and Some(value) as the value.
     https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L6149-L6165 */
  if( FD_FEATURE_ACTIVE_BANK( bank, enable_vote_address_leader_schedule ) ) {
    /* Return the first epoch if activated at genesis
       https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L6153-L6157 */
    ulong activation_slot = fd_bank_features_query( bank )->enable_vote_address_leader_schedule;
    if( activation_slot==0UL ) return 0;

    /* Calculate the epoch that the feature became activated in
       https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L6159-L6160 */
    fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
    ulong activation_epoch = fd_slot_to_epoch( epoch_schedule, activation_slot, NULL );

    /* The effective epoch is the epoch immediately after the activation
       epoch.
       https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L6162-L6164 */
    ulong effective_epoch = activation_epoch + 1UL;
    ulong current_epoch   = fd_bank_epoch_get( bank );

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L6167-L6170 */
    return !!( current_epoch >= effective_epoch );
  }

  /* ...The rest of the logic in this function either returns None or
     Some(false) so we will just return 0 by default. */
  return 0;
}

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
}

void
fd_runtime_update_leaders( fd_bank_t * bank,
                           ulong       slot,
                           fd_spad_t * runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );

  ulong epoch    = fd_slot_to_epoch ( epoch_schedule, slot, NULL );
  ulong slot0    = fd_epoch_slot0   ( epoch_schedule, epoch );
  ulong slot_cnt = fd_epoch_slot_cnt( epoch_schedule, epoch );

  fd_vote_states_t const * vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_query( bank );
  ulong                    vote_acc_cnt          = fd_vote_states_cnt( vote_states_prev_prev ) ;
  fd_vote_stake_weight_t * epoch_weights         = fd_spad_alloc_check( runtime_spad, alignof(fd_vote_stake_weight_t), vote_acc_cnt * sizeof(fd_vote_stake_weight_t) );
  ulong                    stake_weight_cnt      = fd_stake_weights_by_node( vote_states_prev_prev, epoch_weights );
  fd_bank_vote_states_prev_prev_end_locking_query( bank );

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

    ulong vote_keyed_lsched = (ulong)fd_runtime_should_use_vote_keyed_leader_schedule( bank );
    void * epoch_leaders_mem = fd_bank_epoch_leaders_locking_modify( bank );
    fd_epoch_leaders_t * leaders = fd_epoch_leaders_join( fd_epoch_leaders_new(
        epoch_leaders_mem,
        epoch,
        slot0,
        slot_cnt,
        stake_weight_cnt,
        epoch_weights,
        0UL,
        vote_keyed_lsched ) );
    if( FD_UNLIKELY( !leaders ) ) {
      FD_LOG_ERR(( "Unable to init and join fd_epoch_leaders" ));
    }
    fd_bank_epoch_leaders_end_locking_modify( bank );
  }
  } FD_SPAD_FRAME_END;

  fd_bank_epoch_leaders_locking_query( bank );
  fd_bank_epoch_leaders_end_locking_query( bank );
}

/******************************************************************************/
/* Various Private Runtime Helpers                                            */
/******************************************************************************/

static fd_funk_txn_t *
fd_runtime_funk_txn_get( fd_funk_t * funk,
                         ulong       slot ) {
  /* Query the funk transaction for the given slot. */
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( funk );
  if( FD_UNLIKELY( !txn_map->map ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction map" ));
  }
  fd_funk_txn_xid_t xid = { .ul = { slot, slot } };
  fd_funk_txn_start_read( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( &xid, txn_map );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction" ));
  }
  fd_funk_txn_end_read( funk );
  return funk_txn;
}

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

  if( FD_UNLIKELY( memcmp( fd_txn_account_get_owner( collector ), fd_solana_system_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
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
  ulong minbal = fd_rent_exempt_minimum_balance( rent, fd_txn_account_get_data_len( collector ) );
  if( FD_UNLIKELY( fd_txn_account_get_lamports( collector )+fee<minbal ) ) {
    FD_BASE58_ENCODE_32_BYTES( collector->pubkey->key, _out_key );
    FD_LOG_WARNING(("cannot pay a rent paying account (%s)", _out_key ));
    return fee;
  }

  return 0UL;
}

static int
fd_runtime_run_incinerator( fd_bank_t *        bank,
                            fd_funk_t *        funk,
                            fd_funk_txn_t *    funk_txn,
                            fd_capture_ctx_t * capture_ctx ) {
  FD_TXN_ACCOUNT_DECL( rec );
  fd_funk_rec_prepare_t prepare = {0};

  int err = fd_txn_account_init_from_funk_mutable(
      rec,
      &fd_sysvar_incinerator_id,
      funk,
      funk_txn,
      0,
      0UL,
      &prepare );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    // TODO: not really an error! This is fine!
    return -1;
  }

  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash( rec->pubkey, fd_txn_account_get_meta( rec ), fd_txn_account_get_data( rec ), prev_hash );

  ulong new_capitalization = fd_ulong_sat_sub( fd_bank_capitalization_get( bank ), fd_txn_account_get_lamports( rec ) );
  fd_bank_capitalization_set( bank, new_capitalization );

  fd_txn_account_set_lamports( rec, 0UL );
  fd_hashes_update_lthash( rec, prev_hash, bank, capture_ctx );
  fd_txn_account_mutable_fini( rec, funk, funk_txn, &prepare );

  return 0;
}

static void
fd_runtime_freeze( fd_exec_slot_ctx_t * slot_ctx ) {

  if( FD_LIKELY( fd_bank_slot_get( slot_ctx->bank ) != 0UL ) ) {
    fd_sysvar_recent_hashes_update( slot_ctx );
  }

  fd_sysvar_slot_history_update( slot_ctx );

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
        FD_LOG_CRIT(( "fd_runtime_freeze: leaders not found" ));
        fd_bank_epoch_leaders_end_locking_query( slot_ctx->bank );
        break;
      }

      fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, fd_bank_slot_get( slot_ctx->bank ) );
      if( FD_UNLIKELY( !leader ) ) {
        FD_LOG_CRIT(( "fd_runtime_freeze: leader not found" ));
        fd_bank_epoch_leaders_end_locking_query( slot_ctx->bank );
        break;
      }

      fd_funk_rec_prepare_t prepare = {0};
      int err = fd_txn_account_init_from_funk_mutable(
          rec,
          leader,
          slot_ctx->funk,
          slot_ctx->funk_txn,
          1,
          0UL,
          &prepare );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(("fd_runtime_freeze: fd_txn_account_init_from_funk_mutable for leader (%s) failed (%d)", FD_BASE58_ENC_32_ALLOCA( leader ), err));
        burn = fd_ulong_sat_add( burn, fees );
        fd_bank_epoch_leaders_end_locking_query( slot_ctx->bank );
        break;
      }

      fd_lthash_value_t prev_hash[1];
      fd_hashes_account_lthash( leader, fd_txn_account_get_meta( rec ), fd_txn_account_get_data( rec ), prev_hash );

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
      fd_txn_account_checked_add_lamports( rec, fees );
      fd_txn_account_set_slot( rec, fd_bank_slot_get( slot_ctx->bank ) );

      fd_hashes_update_lthash( rec, prev_hash, slot_ctx->bank, slot_ctx->capture_ctx );
      fd_txn_account_mutable_fini( rec, slot_ctx->funk, slot_ctx->funk_txn, &prepare );

    } while(0);

    ulong old = fd_bank_capitalization_get( slot_ctx->bank );
    fd_bank_capitalization_set( slot_ctx->bank, fd_ulong_sat_sub( old, burn ) );
    FD_LOG_DEBUG(( "fd_runtime_freeze: burn %lu, capitalization %lu->%lu ", burn, old, fd_bank_capitalization_get( slot_ctx->bank ) ));

    fd_bank_execution_fees_set( slot_ctx->bank, 0UL );

    fd_bank_priority_fees_set( slot_ctx->bank, 0UL );
  }

  fd_runtime_run_incinerator( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn, slot_ctx->capture_ctx );

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
  ulong min_balance = fd_rent_exempt_minimum_balance( rent, fd_txn_account_get_data_len( acc ) );
  if( fd_txn_account_get_lamports( acc )>=min_balance ) {
    return FD_RENT_EXEMPT;
  }

  /* Count the number of slots that have passed since last collection. This
     inlines the agave function get_slots_in_peohc
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L93-L98 */
  ulong slots_elapsed = 0UL;
  if( FD_UNLIKELY( fd_txn_account_get_rent_epoch( acc )<schedule->first_normal_epoch ) ) {
    /* Count the slots before the first normal epoch separately */
    for( ulong i=fd_txn_account_get_rent_epoch( acc ); i<schedule->first_normal_epoch && i<=epoch; i++ ) {
      slots_elapsed += fd_epoch_slot_cnt( schedule, i+1UL );
    }
    slots_elapsed += fd_ulong_sat_sub( epoch+1UL, schedule->first_normal_epoch ) * schedule->slots_per_epoch;
  }
  // slots_elapsed should remain 0 if rent_epoch is greater than epoch
  else if( fd_txn_account_get_rent_epoch( acc )<=epoch ) {
    slots_elapsed = (epoch - fd_txn_account_get_rent_epoch( acc ) + 1UL) * schedule->slots_per_epoch;
  }
  /* Consensus-critical use of doubles :( */

  double years_elapsed;
  if( FD_LIKELY( slots_per_year!=0.0 ) ) {
    years_elapsed = (double)slots_elapsed / slots_per_year;
  } else {
    years_elapsed = 0.0;
  }

  ulong lamports_per_year = rent->lamports_per_uint8_year * (fd_txn_account_get_data_len( acc ) + 128UL);
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

  if( FD_UNLIKELY( fd_txn_account_get_rent_epoch( acc )!=FD_RENT_EXEMPT_RENT_EPOCH &&
                     fd_runtime_get_rent_due( schedule,
                                              rent,
                                              slots_per_year,
                                              acc,
                                              epoch )==FD_RENT_EXEMPT ) ) {
      fd_txn_account_set_rent_epoch( acc, FD_RENT_EXEMPT_RENT_EPOCH );
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
                                          ulong       latest_signatures_per_slot ) {

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
        * fd_ulong_min(latest_signatures_per_slot, (ulong)UINT_MAX)
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

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_runtime_new_fee_rate_governor_derived( slot_ctx->bank, fd_bank_parent_signature_cnt_get( slot_ctx->bank ) );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );
  ulong                       parent_epoch   = fd_slot_to_epoch( epoch_schedule, fd_bank_parent_slot_get( slot_ctx->bank ), NULL );
  fd_sysvar_clock_update( slot_ctx, runtime_spad, &parent_epoch );

  // It has to go into the current txn previous info but is not in slot 0
  if( fd_bank_slot_get( slot_ctx->bank ) != 0 ) {
    fd_sysvar_slot_hashes_update( slot_ctx, runtime_spad );
  }
  fd_sysvar_last_restart_slot_update( slot_ctx, fd_bank_last_restart_slot_get( slot_ctx->bank ).slot );

  } FD_SPAD_FRAME_END;

  return 0;
}

int
fd_runtime_load_txn_address_lookup_tables(
    fd_txn_t const *       txn,
    uchar const *          payload,
    fd_funk_t *            funk,
    fd_funk_txn_t *        funk_txn,
    ulong                  slot,
    fd_slot_hash_t const * hashes, /* deque */
    fd_acct_addr_t *       out_accts_alt
) {

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
    if( FD_UNLIKELY( memcmp( fd_txn_account_get_owner( addr_lut_rec ), fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER;
    }

    /* Realistically impossible case, but need to make sure we don't cause an OOB data access
       https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L205-L209 */
    if( FD_UNLIKELY( fd_txn_account_get_data_len( addr_lut_rec ) < FD_LOOKUP_TABLE_META_SIZE ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/accounts-db/src/accounts.rs#L141-L142 */
    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = fd_txn_account_get_data( addr_lut_rec ),
      .dataend = &fd_txn_account_get_data( addr_lut_rec )[FD_LOOKUP_TABLE_META_SIZE]
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
    if( FD_UNLIKELY( (fd_txn_account_get_data_len( addr_lut_rec ) - FD_LOOKUP_TABLE_META_SIZE) & 0x1fUL ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
    }

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L101-L112 */
    fd_acct_addr_t * lookup_addrs  = (fd_acct_addr_t *)&fd_txn_account_get_data( addr_lut_rec )[FD_LOOKUP_TABLE_META_SIZE];
    ulong         lookup_addrs_cnt = (fd_txn_account_get_data_len( addr_lut_rec ) - FD_LOOKUP_TABLE_META_SIZE) >> 5UL; // = (dlen - 56) / 32

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

int
fd_runtime_block_execute_prepare( fd_exec_slot_ctx_t * slot_ctx,
                                  fd_spad_t *          runtime_spad ) {
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

  if( FD_UNLIKELY( !fd_sysvar_cache_restore( slot_ctx ) ) ) {
    FD_LOG_ERR(( "Failed to restore sysvar cache" ));
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static void
fd_runtime_update_bank_hash( fd_exec_slot_ctx_t * slot_ctx ) {
  /* Save the previous bank hash, and the parents signature count */
  fd_hash_t const * prev_bank_hash = NULL;
  if( FD_LIKELY( fd_bank_slot_get( slot_ctx->bank )!=0UL ) ) {
    prev_bank_hash = fd_bank_bank_hash_query( slot_ctx->bank );
    fd_bank_prev_bank_hash_set( slot_ctx->bank, *prev_bank_hash );
  } else {
    prev_bank_hash = fd_bank_prev_bank_hash_query( slot_ctx->bank );
  }

  fd_bank_parent_signature_cnt_set( slot_ctx->bank, fd_bank_signature_count_get( slot_ctx->bank ) );

  /* Compute the new bank hash */
  fd_lthash_value_t const * lthash = fd_bank_lthash_locking_query( slot_ctx->bank );
  fd_hash_t new_bank_hash[1] = { 0 };
  fd_hashes_hash_bank(
      lthash,
      prev_bank_hash,
      (fd_hash_t *)fd_bank_poh_query( slot_ctx->bank )->hash,
      fd_bank_signature_count_get( slot_ctx->bank ),
      new_bank_hash );

  /* Update the bank hash */
  fd_bank_bank_hash_set( slot_ctx->bank, *new_bank_hash );

  if( !slot_ctx->silent ) {
    FD_LOG_NOTICE(( "\n\n[Runtime]\n"
                    "slot:             %lu\n"
                    "bank hash:        %s\n"
                    "parent bank hash: %s\n"
                    "lthash:           %s\n"
                    "signature_count:  %lu\n"
                    "last_blockhash:   %s\n",
                    fd_bank_slot_get( slot_ctx->bank ),
                    FD_BASE58_ENC_32_ALLOCA( new_bank_hash->hash ),
                    FD_BASE58_ENC_32_ALLOCA( fd_bank_prev_bank_hash_query( slot_ctx->bank ) ),
                    FD_LTHASH_ENC_32_ALLOCA( lthash->bytes ),
                    fd_bank_signature_count_get( slot_ctx->bank ),
                    FD_BASE58_ENC_32_ALLOCA( fd_bank_poh_query( slot_ctx->bank )->hash ) ));
  }

  if( slot_ctx->capture_ctx != NULL && slot_ctx->capture_ctx->capture != NULL &&
    fd_bank_slot_get( slot_ctx->bank )>=slot_ctx->capture_ctx->solcap_start_slot ) {

    uchar lthash_hash[FD_HASH_FOOTPRINT];
    fd_blake3_hash(lthash->bytes, FD_LTHASH_LEN_BYTES, lthash_hash );

    fd_solcap_write_bank_preimage(
          slot_ctx->capture_ctx->capture,
          new_bank_hash->hash,
          fd_bank_prev_bank_hash_query( slot_ctx->bank ),
          NULL,
          lthash_hash,
          fd_bank_poh_query( slot_ctx->bank )->hash,
          fd_bank_signature_count_get( slot_ctx->bank ) );
  }

  fd_bank_lthash_end_locking_query( slot_ctx->bank );
}

/******************************************************************************/
/* Transaction Level Execution Management                                     */
/******************************************************************************/

/* fd_runtime_pre_execute_check is responsible for conducting many of the
   transaction sanitization checks. */

int
fd_runtime_pre_execute_check( fd_txn_p_t * txn, fd_exec_txn_ctx_t * txn_ctx ) {

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

  uchar dump_txn = !!( txn_ctx->capture_ctx &&
                       txn_ctx->slot >= txn_ctx->capture_ctx->dump_proto_start_slot &&
                       txn_ctx->capture_ctx->dump_txn_to_pb );
  if( FD_UNLIKELY( dump_txn ) ) {
    fd_dump_txn_to_protobuf( txn_ctx, txn_ctx->spad );
  }

  /* Verify the transaction. For now, this step only involves processing
     the compute budget instructions. */
  err = fd_executor_verify_transaction( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn->flags = 0U;
    return err;
  }

  /* Resolve and verify ALUT-referenced account keys, if applicable */
  err = fd_executor_setup_txn_alut_account_keys( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn->flags = 0U;
    return err;
  }

  /* Set up the transaction accounts and other txn ctx metadata */
  fd_executor_setup_accounts_for_txn( txn_ctx );

  /* Post-sanitization checks. Called from prepare_sanitized_batch()
     which, for now, only is used to lock the accounts and perform a
     couple basic validations.
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118 */
  err = fd_executor_validate_account_locks( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn->flags = 0U;
    return err;
  }

  /* load_and_execute_transactions() -> check_transactions()
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L3667-L3672 */
  err = fd_executor_check_transactions( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn->flags = 0U;
    return err;
  }

  /* load_and_execute_sanitized_transactions() -> validate_fees() ->
     validate_transaction_fee_payer()
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L236-L249 */
  err = fd_executor_validate_transaction_fee_payer( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn->flags = 0U;
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L284-L296 */
  err = fd_executor_load_transaction_accounts( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    /* Regardless of whether transaction accounts were loaded successfully, the transaction is
       included in the block and transaction fees are collected.
       https://github.com/anza-xyz/agave/blob/v2.1.6/svm/src/transaction_processor.rs#L341-L357 */
    txn->flags |= FD_TXN_P_FLAGS_FEES_ONLY;

    /* If the transaction fails to load, the "rollback" accounts will include one of the following:
        1. Nonce account only
        2. Fee payer only
        3. Nonce account + fee payer

        Because the cost tracker uses the loaded account data size in block cost calculations, we need to
        make sure our calculated loaded accounts data size is conformant with Agave's.
        https://github.com/anza-xyz/agave/blob/v2.1.14/runtime/src/bank.rs#L4116

        In any case, we should always add the dlen of the fee payer. */
    txn_ctx->loaded_accounts_data_size = fd_txn_account_get_data_len( &txn_ctx->accounts[FD_FEE_PAYER_TXN_IDX] );

    /* Special case handling for if a nonce account is present in the transaction. */
    if( txn_ctx->nonce_account_idx_in_txn!=ULONG_MAX ) {
      /* If the nonce account is not the fee payer, then we separately add the dlen of the nonce account. Otherwise, we would
          be double counting the dlen of the fee payer. */
      if( txn_ctx->nonce_account_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) {
        txn_ctx->loaded_accounts_data_size += fd_txn_account_get_data_len( txn_ctx->rollback_nonce_account );
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

  return err;
}

/* fd_runtime_finalize_account is a helper used to commit the data from
   a writable transaction account back into the accountsdb. */

static void
fd_runtime_finalize_account( fd_funk_t *        funk,
                             fd_funk_txn_t *    funk_txn,
                             fd_txn_account_t * acc ) {
  if( FD_UNLIKELY( !fd_txn_account_is_mutable( acc ) ) ) {
    FD_LOG_CRIT(( "fd_runtime_finalize_account: account is not mutable" ));
  }

  fd_pubkey_t const * key         = acc->pubkey;
  uchar       const * record_data = (uchar *)fd_txn_account_get_meta( acc );
  ulong               record_sz   = fd_account_meta_get_record_sz( acc->meta );

  int err = FD_FUNK_SUCCESS;

  fd_funk_rec_key_t     funk_key = fd_funk_acc_key( key );
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t *       rec = fd_funk_rec_prepare( funk, funk_txn, &funk_key, prepare, &err );
  if( FD_UNLIKELY( !rec || err!=FD_FUNK_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_runtime_finalize_account: failed to prepare record (%i-%s)", err, fd_funk_strerror( err ) ));
  }

  if( FD_UNLIKELY( !fd_funk_val_truncate(
      rec,
      fd_funk_alloc( funk ),
      fd_funk_wksp( funk ),
      0UL,
      record_sz,
      &err ) ) ) {
    FD_LOG_ERR(( "fd_funk_val_truncate(sz=%lu) for account failed (%i-%s)", record_sz, err, fd_funk_strerror( err ) ));
  }

  fd_memcpy( fd_funk_val( rec, fd_funk_wksp( funk ) ), record_data, record_sz );

  fd_funk_rec_publish( funk, prepare );
}

/* fd_runtime_buffer_solcap_account_update buffers an account
   update event message in the capture context, which will be
   sent to the replay tile via the writer_replay link.
   This buffering is done to avoid passing stem down into the runtime.

   TODO: remove this when solcap v2 is here. */
static void
fd_runtime_buffer_solcap_account_update( fd_txn_account_t *        account,
                                         fd_bank_t *               bank,
                                         fd_capture_ctx_t *        capture_ctx ) {

  /* Check if we should publish the update */
  if( FD_UNLIKELY( !capture_ctx || fd_bank_slot_get( bank )<capture_ctx->solcap_start_slot ) ) {
    return;
  }

  /* Get account data */
  fd_account_meta_t const * meta = fd_txn_account_get_meta( account );
  void const * data              = fd_txn_account_get_data( account );

  /* Calculate account hash using lthash */
  fd_lthash_value_t lthash[1];
  fd_hashes_account_lthash( account->pubkey, meta, data, lthash );

  /* Calculate message size */
  if( FD_UNLIKELY( capture_ctx->account_updates_len > FD_CAPTURE_CTX_MAX_ACCOUNT_UPDATES ) ) {
    FD_LOG_CRIT(( "cannot buffer solcap account update. this should never happen" ));
    return;
  }

  /* Write the message to the buffer */
  fd_runtime_public_account_update_msg_t * account_update_msg = (fd_runtime_public_account_update_msg_t *)(capture_ctx->account_updates_buffer_ptr);
  account_update_msg->pubkey               = *account->pubkey;
  account_update_msg->info                 = meta->info;
  account_update_msg->data_sz              = meta->dlen;
  memcpy( account_update_msg->hash.uc, lthash->bytes, sizeof(fd_hash_t) );
  capture_ctx->account_updates_buffer_ptr += sizeof(fd_runtime_public_account_update_msg_t);

  /* Write the account data to the buffer */
  memcpy( capture_ctx->account_updates_buffer_ptr, data, meta->dlen );
  capture_ctx->account_updates_buffer_ptr += meta->dlen;

  capture_ctx->account_updates_len++;
}

/* fd_runtime_save_account is a convenience wrapper that looks
   up the previous account state from funk before updating the lthash
   and saving the new version of the account to funk.

   TODO: We have to make a read request to the DB, so that we can calculate
   the previous version of the accounts hash, to mix-out from the accumulated
   lthash.  In future we should likely cache the previous version of the account
   in transaction setup, so that we don't have to issue a read request here.

   funk is the funk database handle.  funk_txn is the transaction
   context to query (NULL for root context).  account is the modified
   account.  bank and capture_ctx are passed to fd_hashes_update_lthash.

   This function:
   - Queries funk for the previous account version
   - Computes the hash of the previous version (or uses zero for new)
   - Calls fd_hashes_update_lthash with the computed previous hash
   - Saves the new version of the account to Funk
   - Notifies the replay tile that an account update has occurred, so it
     can write the account to the solcap file.

   The function handles FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT gracefully (uses
   zero hash).  On other funk errors, the function will FD_LOG_ERR.
   All non-optional pointers must be valid. */

static void
fd_runtime_save_account( fd_funk_t *        funk,
                         fd_funk_txn_t *    funk_txn,
                         fd_txn_account_t * account,
                         fd_bank_t *        bank,
                         fd_wksp_t *        acc_data_wksp,
                         fd_capture_ctx_t * capture_ctx ) {

  /* Join the transaction account */
  if( FD_UNLIKELY( !fd_txn_account_join( account, acc_data_wksp ) ) ) {
    FD_LOG_CRIT(( "fd_runtime_save_account: failed to join account" ));
  }

  /* Look up the previous version of the account from Funk */
  FD_TXN_ACCOUNT_DECL( previous_account_version );
  int err = fd_txn_account_init_from_funk_readonly( previous_account_version, account->pubkey, funk, funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS && err!=FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
    FD_LOG_CRIT(( "Failed to read old account version from Funk" ));
    return;
  }

  /* Hash the old version of the account */
  fd_lthash_value_t prev_hash[1];
  fd_lthash_zero( prev_hash );
  if( err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    fd_hashes_account_lthash(
      account->pubkey,
      fd_txn_account_get_meta( previous_account_version ),
      fd_txn_account_get_data( previous_account_version ),
      prev_hash );
  }

  /* Mix in the account hash into the bank hash */
  fd_hashes_update_lthash( account, prev_hash, bank, NULL );

  /* Publish account update to replay tile for solcap writing
     TODO: write in the writer tile with solcap v2 */
  fd_runtime_buffer_solcap_account_update( account, bank, capture_ctx );

  /* Save the new version of the account to Funk */
  fd_runtime_finalize_account( funk, funk_txn, account );
}

/* fd_runtime_finalize_txn is a helper used by the non-tpool transaction
   executor to finalize borrowed account changes back into funk. It also
   handles txncache insertion and updates to the vote/stake cache.
   TODO: This function should probably be moved to fd_executor.c. */

void
fd_runtime_finalize_txn( fd_funk_t *         funk,
                         fd_funk_txn_t *     funk_txn,
                         fd_exec_txn_ctx_t * txn_ctx,
                         fd_bank_t *         bank,
                         fd_capture_ctx_t *  capture_ctx ) {

  /* Collect fees */

  FD_ATOMIC_FETCH_AND_ADD( fd_bank_txn_count_modify( bank ), 1UL );
  FD_ATOMIC_FETCH_AND_ADD( fd_bank_execution_fees_modify( bank ), txn_ctx->execution_fee );
  FD_ATOMIC_FETCH_AND_ADD( fd_bank_priority_fees_modify( bank ), txn_ctx->priority_fee );

  FD_ATOMIC_FETCH_AND_ADD( fd_bank_signature_count_modify( bank ), txn_ctx->txn_descriptor->signature_cnt );

  if( FD_UNLIKELY( txn_ctx->exec_err ) ) {

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
      fd_runtime_save_account( funk, funk_txn, txn_ctx->rollback_nonce_account, bank, txn_ctx->spad_wksp, capture_ctx );
    }

    /* Now, we must only save the fee payer if the nonce account was not the fee payer (because that was already saved above) */
    if( FD_LIKELY( txn_ctx->nonce_account_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) ) {
      fd_runtime_save_account( funk, funk_txn, txn_ctx->rollback_fee_payer_account, bank, txn_ctx->spad_wksp, capture_ctx );
    }
  } else {

    int dirty_vote_acc  = txn_ctx->dirty_vote_acc;

    for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
      /* We are only interested in saving writable accounts and the fee
         payer account. */
      if( !fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, i ) && i!=FD_FEE_PAYER_TXN_IDX ) {
        continue;
      }

      fd_txn_account_t * acc_rec = fd_txn_account_join( &txn_ctx->accounts[i], txn_ctx->spad_wksp );
      if( FD_UNLIKELY( !acc_rec ) ) {
        FD_LOG_CRIT(( "fd_runtime_finalize_txn: failed to join account at idx %u", i ));
      }

      if( dirty_vote_acc && 0==memcmp( fd_txn_account_get_owner( acc_rec ), &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
        fd_vote_store_account( acc_rec, bank );
      }

      if( 0==memcmp( fd_txn_account_get_owner( acc_rec ), &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) {
        fd_update_stake_delegation( acc_rec, bank );
      }

      /* Reclaim any accounts that have 0-lamports, now that any related
         cache updates have been applied. */
      fd_executor_reclaim_account( txn_ctx, &txn_ctx->accounts[i] );

      fd_runtime_save_account( funk, funk_txn, &txn_ctx->accounts[i], bank, txn_ctx->spad_wksp, capture_ctx );
    }

    /* We need to queue any existing program accounts that may have
       been deployed / upgraded for reverification in the program
       cache since their programdata may have changed. ELF / sBPF
       metadata will need to be updated. */
      ulong current_slot = fd_bank_slot_get( bank );
      for( uchar i=0; i<txn_ctx->programs_to_reverify_cnt; i++ ) {
        fd_pubkey_t const * program_key = &txn_ctx->programs_to_reverify[i];
        fd_program_cache_queue_program_for_reverification( funk, funk_txn, program_key, current_slot );
      }
  }

  int is_vote = fd_txn_is_simple_vote_transaction( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw );
  if( !is_vote ){
    ulong * nonvote_txn_count = fd_bank_nonvote_txn_count_modify( bank );
    FD_ATOMIC_FETCH_AND_ADD(nonvote_txn_count, 1);

    if( FD_UNLIKELY( txn_ctx->exec_err ) ){
      ulong * nonvote_failed_txn_count = fd_bank_nonvote_failed_txn_count_modify( bank );
      FD_ATOMIC_FETCH_AND_ADD( nonvote_failed_txn_count, 1 );
    }
  } else {
    if( FD_UNLIKELY( txn_ctx->exec_err ) ){
      ulong * failed_txn_count = fd_bank_failed_txn_count_modify( bank );
      FD_ATOMIC_FETCH_AND_ADD( failed_txn_count, 1 );
    }
  }

  ulong * total_compute_units_used = fd_bank_total_compute_units_used_modify( bank );
  FD_ATOMIC_FETCH_AND_ADD( total_compute_units_used, txn_ctx->compute_budget_details.compute_unit_limit - txn_ctx->compute_budget_details.compute_meter );

}

int
fd_runtime_prepare_and_execute_txn( fd_banks_t *        banks,
                                    fd_exec_txn_ctx_t * txn_ctx,
                                    fd_txn_p_t *        txn,
                                    fd_spad_t *         exec_spad,
                                    ulong               slot,
                                    fd_capture_ctx_t *  capture_ctx,
                                    uchar               do_sigverify ) {
  FD_SPAD_FRAME_BEGIN( exec_spad ) {
  int exec_res = 0;

  fd_funk_txn_t * funk_txn = fd_runtime_funk_txn_get( txn_ctx->funk, slot );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_CRIT(( "Could not get funk transaction for slot %lu", slot ));
  }

  /* Get the bank for the given slot. */
  fd_bank_t * bank = fd_banks_get_bank( banks, slot );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "Could not get bank for slot %lu", slot ));
  }

  /* Setup and execute the transaction. */
  txn_ctx->bank                  = bank;
  txn_ctx->slot                  = fd_bank_slot_get( bank );
  txn_ctx->features              = fd_bank_features_get( bank );
  txn_ctx->status_cache          = NULL; // TODO: Make non-null once implemented
  txn_ctx->enable_exec_recording = !!( bank->flags & FD_BANK_FLAGS_EXEC_RECORDING );
  txn_ctx->funk_txn              = funk_txn;
  txn_ctx->capture_ctx           = capture_ctx;

  fd_txn_t const * txn_descriptor = TXN( txn );
  fd_rawtxn_b_t    raw_txn        = {
    .raw    = txn->payload,
    .txn_sz = (ushort)txn->payload_sz
  };

  txn->flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
  fd_exec_txn_ctx_setup( txn_ctx, txn_descriptor, &raw_txn );

  /* Set up the core account keys. These are the account keys directly
     passed in via the serialized transaction, represented as an array.
     Note that this does not include additional keys referenced in
     address lookup tables. */
  fd_executor_setup_txn_account_keys( txn_ctx );

  if( FD_LIKELY( do_sigverify ) ) {
    exec_res = fd_executor_txn_verify( txn_ctx );
    if( FD_UNLIKELY( exec_res!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      txn->flags = 0U;
      return exec_res;
    }
  }

  /* Pre-execution checks */
  exec_res = fd_runtime_pre_execute_check( txn, txn_ctx );
  if( FD_UNLIKELY( !( txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    return exec_res;
  }

  /* Execute the transaction. Note that fees-only transactions are still
     marked as "executed". */
  txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  if( FD_LIKELY( !( txn->flags & FD_TXN_P_FLAGS_FEES_ONLY ) ) ) {
    exec_res = fd_execute_txn( txn_ctx );
  }

  return exec_res;

  } FD_SPAD_FRAME_END;
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
   fd_executor_check_transaction_age_and_compute_budget_limits() and
   fd_executor_check_status_cache() respectively.

   load_and_execute_sanitized_transactions() contains validate_fees()
   which is responsible for executing the compute budget instructions,
   validating the fee payer and collecting the fee. This is mirrored in
   firedancer with fd_executor_compute_budget_program_execute_instructions()
   and fd_executor_collect_fees(). load_and_execute_sanitized_transactions()
   also checks the total data size of the accounts in load_accounts() and
   validates the program accounts in load_transaction_accounts(). This
   is paralled by fd_executor_load_transaction_accounts(). */

/******************************************************************************/
/* Epoch Boundary                                                             */
/******************************************************************************/

/* Replace the vote states for T-2 (vote_states_prev_prev) with the vote
   states for T-1 (vote_states_prev) */

static void
fd_update_vote_states_prev_prev( fd_exec_slot_ctx_t * slot_ctx ) {

  fd_vote_states_t *       vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( slot_ctx->bank );
  fd_vote_states_t const * vote_states_prev      = fd_bank_vote_states_prev_locking_query( slot_ctx->bank );
  fd_memcpy( vote_states_prev_prev, vote_states_prev, fd_bank_vote_states_footprint );
  fd_bank_vote_states_prev_prev_end_locking_modify( slot_ctx->bank );
  fd_bank_vote_states_prev_end_locking_query( slot_ctx->bank );
}

/* Replace the vote states for T-1 (vote_states_prev) with the vote
   states for T-1 (vote_states) */

static void
fd_update_vote_states_prev( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_vote_states_t *       vote_states_prev = fd_bank_vote_states_prev_locking_modify( slot_ctx->bank );
  fd_vote_states_t const * vote_states      = fd_bank_vote_states_locking_query( slot_ctx->bank );
  fd_memcpy( vote_states_prev, vote_states, fd_bank_vote_states_footprint );
  fd_bank_vote_states_prev_end_locking_modify( slot_ctx->bank );
  fd_bank_vote_states_end_locking_query( slot_ctx->bank );
}

/* Mimics bank.new_target_program_account(). Assumes out_rec is a
   modifiable record.

   From the calling context, out_rec points to a native program record
   (e.g. Config, ALUT native programs). There should be enough space in
   out_rec->data to hold at least 36 bytes (the size of a BPF
   upgradeable program account) when calling this function. The native
   program account's owner is set to the BPF loader upgradeable program
   ID, and lamports are increased / deducted to contain the rent exempt
   minimum balance.

   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L79-L95 */
static int
fd_new_target_program_account( fd_exec_slot_ctx_t * slot_ctx,
                               fd_pubkey_t const *  target_program_data_address,
                               fd_txn_account_t *   out_rec ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.0/sdk/account/src/lib.rs#L471 */
  fd_txn_account_set_rent_epoch( out_rec, 0UL );

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

  fd_txn_account_set_lamports( out_rec, fd_rent_exempt_minimum_balance( rent, SIZE_OF_PROGRAM ) );
  fd_bincode_encode_ctx_t ctx = {
    .data    = fd_txn_account_get_data_mut( out_rec ),
    .dataend = fd_txn_account_get_data_mut( out_rec ) + SIZE_OF_PROGRAM,
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L91-L9 */
  int err = fd_bpf_upgradeable_loader_state_encode( &state, &ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  fd_txn_account_set_owner( out_rec, &fd_solana_bpf_loader_upgradeable_program_id );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L93-L94 */
  fd_txn_account_set_executable( out_rec, 1 );
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* Mimics bank.new_target_program_data_account(). Assumes
   new_target_program_data_account is a modifiable record.
   config_upgrade_authority_address may be NULL.

   This function uses an existing buffer account buffer_acc_rec to set
   the program data account data for a core program BPF migration. Sets
   the lamports and data fields of new_target_program_data_account
   based on the ELF data length, and sets the owner to the BPF loader
   upgradeable program ID.

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
      fd_txn_account_get_data( buffer_acc_rec ),
      fd_txn_account_get_data_len( buffer_acc_rec ),
      &err );
  if( FD_UNLIKELY( err ) ) return err;

  if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_buffer( state ) ) ) {
    return -1;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L118-L125 */
  if( config_upgrade_authority_address!=NULL ) {
    if( FD_UNLIKELY( !state->inner.buffer.has_authority_address ||
                     !fd_pubkey_eq( config_upgrade_authority_address, &state->inner.buffer.authority_address ) ) ) {
      return -1;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L127-L132 */
  fd_rent_t const * rent = fd_bank_rent_query( slot_ctx->bank );
  if( FD_UNLIKELY( rent==NULL ) ) {
    return -1;
  }

  const uchar * elf = fd_txn_account_get_data( buffer_acc_rec ) + BUFFER_METADATA_SIZE;
  ulong space = PROGRAMDATA_METADATA_SIZE - BUFFER_METADATA_SIZE + fd_txn_account_get_data_len( buffer_acc_rec );
  ulong lamports = fd_rent_exempt_minimum_balance( rent, space );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L134-L137 */
  fd_bpf_upgradeable_loader_state_t programdata_metadata = {
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
    .inner = {
      .program_data = {
        .slot = fd_bank_slot_get( slot_ctx->bank ),
        .has_upgrade_authority_address = !!config_upgrade_authority_address,
        .upgrade_authority_address     = config_upgrade_authority_address ? *config_upgrade_authority_address : (fd_pubkey_t){{0}}
      }
    }
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L139-L144 */
  fd_txn_account_set_lamports( new_target_program_data_account, lamports );
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = fd_txn_account_get_data_mut( new_target_program_data_account ),
    .dataend = fd_txn_account_get_data_mut( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE,
  };
  err = fd_bpf_upgradeable_loader_state_encode( &programdata_metadata, &encode_ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  fd_txn_account_set_owner( new_target_program_data_account, &fd_solana_bpf_loader_upgradeable_program_id );

  /* Copy the ELF data over
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L145 */
  fd_memcpy( fd_txn_account_get_data_mut( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE, elf, fd_txn_account_get_data_len( buffer_acc_rec ) - BUFFER_METADATA_SIZE );

  return FD_RUNTIME_EXECUTE_SUCCESS;

  } FD_SPAD_FRAME_END;
}

/* Initializes a source buffer account from funk. Returns 1 if the
   buffer account does not exist or is not owned by the upgradeable
   loader. Returns 0 on success.

   https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L22-L49 */
static int
fd_source_buffer_account_new( fd_exec_slot_ctx_t * slot_ctx,
                              fd_txn_account_t *   buffer_account,
                              fd_pubkey_t const *  buffer_address,
                              fd_funk_rec_prepare_t * prepare ) {
  /* The buffer account should exist.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L27-L29 */
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_mutable( buffer_account, buffer_address, slot_ctx->funk, slot_ctx->funk_txn, 0, 0UL, prepare )!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_DEBUG(( "Buffer account %s does not exist, skipping migration...", FD_BASE58_ENC_32_ALLOCA( buffer_address ) ));
    return 1;
  }

  /* The buffer account should be owned by the upgradeable loader.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L31-L34 */
  if( FD_UNLIKELY( memcmp( fd_txn_account_get_owner( buffer_account ), fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_DEBUG(( "Buffer account %s is not owned by the upgradeable loader, skipping migration...", FD_BASE58_ENC_32_ALLOCA( buffer_address ) ));
    return 1;
  }

  /* The buffer account should have the correct state. We already check
     the buffer account state in fd_new_target_program_data_account(),
     so we can skip the checks here.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L37-L47 */

  return 0;
}

/* Similar to fd_source_buffer_account_new() but also checks the build
   hash of the buffer account for verification. verified_build_hash must
   be valid and non-NULL. Returns 1 if fd_source_buffer_account_new()
   fails, the buffer dlen is too small, or if the build hash mismatches.
   Returns 0 on success.

   https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L51-L75 */
static int
fd_source_buffer_account_new_with_hash( fd_exec_slot_ctx_t *    slot_ctx,
                                        fd_txn_account_t *      buffer_account,
                                        fd_pubkey_t const *     buffer_address,
                                        fd_hash_t const *       verified_build_hash,
                                        fd_funk_rec_prepare_t * prepare ) {
  /* https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L58 */
  int err = fd_source_buffer_account_new( slot_ctx, buffer_account, buffer_address, prepare );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L59 */
  uchar const * data = fd_txn_account_get_data( buffer_account );
  ulong         data_len = fd_txn_account_get_data_len( buffer_account );

  /* https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L61 */
  ulong offset = BUFFER_METADATA_SIZE;
  if( FD_UNLIKELY( data_len<offset ) ) {
    return 1;
  }

  /* Search for the first nonzero byte in the buffer account data starting
     from the right.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L62 */
  ulong end_offset = offset;
  for( ulong i=data_len-1UL; i>=offset; i-- ) {
    if( data[i]!=0 ) {
      end_offset = i+1UL;
      break;
    }
  }

  /* Compute and verify the hash.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L64-L71 */
  fd_hash_t hash[1];
  fd_sha256_hash( data+offset, end_offset-offset, hash );
  if( FD_UNLIKELY( memcmp( verified_build_hash, hash, sizeof(fd_hash_t) ) ) ) {
    FD_LOG_WARNING(( "Mismatching build hash for Buffer account %s (expected=%s, actual=%s). Skipping migration...", FD_BASE58_ENC_32_ALLOCA( buffer_address ), FD_BASE58_ENC_32_ALLOCA( verified_build_hash ), FD_BASE58_ENC_32_ALLOCA( hash ) ));
    return 1;
  }

  return 0;
}

/* Mimics migrate_builtin_to_core_bpf().
  https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L235-L318 */
static void
fd_migrate_builtin_to_core_bpf( fd_exec_slot_ctx_t *                   slot_ctx,
                                fd_core_bpf_migration_config_t const * config,
                                fd_spad_t *                            runtime_spad ) {
  int err;

  /* Initialize local variables from the config */
  fd_pubkey_t const * source_buffer_address     = config->source_buffer_address;
  fd_pubkey_t *       upgrade_authority_address = config->upgrade_authority_address;
  uchar               stateless                 = !!( config->migration_target==FD_CORE_BPF_MIGRATION_TARGET_STATELESS );
  fd_pubkey_t const * builtin_program_id        = config->builtin_program_id;
  fd_hash_t const *   verified_build_hash       = config->verified_build_hash;

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L242-L243

     The below logic is used to obtain a TargetBuiltin account. There
     are three fields of TargetBuiltin returned:
      - target.program_address: builtin_program_id
      - target.program_account:
          - if stateless: an AccountSharedData::default() (i.e. system
            program id, 0 lamports, 0 data, non-executable, system
            program owner)
          - if NOT stateless: the existing account (for us its called
            target_program_account)
      - target.program_data_address: target_program_data_address for
        us, derived below. */

  /* These checks will fail if the core program has already been migrated to BPF, since the account will exist + the program owner
     will no longer be the native loader.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L23-L50 */
  FD_TXN_ACCOUNT_DECL( target_program_account );
  uchar program_exists = ( fd_txn_account_init_from_funk_readonly( target_program_account, builtin_program_id, slot_ctx->funk, slot_ctx->funk_txn )==FD_ACC_MGR_SUCCESS );
  if( !stateless ) {
    /* The program account should exist.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L30-L33 */
    if( FD_UNLIKELY( !program_exists ) ) {
      FD_LOG_DEBUG(( "Builtin program %s does not exist, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }

    /* The program account should be owned by the native loader.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L35-L38 */
    if( FD_UNLIKELY( memcmp( fd_txn_account_get_owner( target_program_account ), fd_solana_native_loader_id.uc, sizeof(fd_pubkey_t) ) ) ) {
      FD_LOG_DEBUG(( "Builtin program %s is not owned by the native loader, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }
  } else {
    /* The program account should _not_ exist.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L42-L46 */
    if( FD_UNLIKELY( program_exists ) ) {
      FD_LOG_DEBUG(( "Stateless program %s already exists, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
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

  /* https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L221-L229

     Obtains a SourceBuffer account. There are two fields returned:
      - source.buffer_address: source_buffer_address
      - source.buffer_account: the existing buffer account
     Depending on if the verified build hash is provided,  */
  FD_TXN_ACCOUNT_DECL( source_buffer_account );
  fd_funk_rec_prepare_t source_buffer_prepare = {0};
  if( verified_build_hash!=NULL ) {
    if( FD_UNLIKELY( fd_source_buffer_account_new_with_hash( slot_ctx, source_buffer_account, source_buffer_address, verified_build_hash, &source_buffer_prepare ) ) ) {
      return;
    }
  } else {
    if( FD_UNLIKELY( fd_source_buffer_account_new( slot_ctx, source_buffer_account, source_buffer_address, &source_buffer_prepare ) ) ) {
      return;
    }
  }

  fd_lthash_value_t prev_source_buffer_hash[1];
  fd_hashes_account_lthash(
    source_buffer_address,
    fd_txn_account_get_meta( source_buffer_account ),
    fd_txn_account_get_data( source_buffer_account ),
    prev_source_buffer_hash );

  /* This check is done a bit prematurely because we calculate the
     previous account state's lamports. We use 0 for starting lamports
     for stateless accounts because they don't yet exist.

     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L277-L280 */
  ulong lamports_to_burn = ( stateless ? 0UL : fd_txn_account_get_lamports( target_program_account ) ) + fd_txn_account_get_lamports( source_buffer_account );

  /* Start a funk write txn */
  fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
  fd_funk_txn_xid_t migration_xid = fd_funk_generate_xid();
  fd_funk_txn_start_write( slot_ctx->funk );
  slot_ctx->funk_txn = fd_funk_txn_prepare( slot_ctx->funk, slot_ctx->funk_txn, &migration_xid, 0UL );
  fd_funk_txn_end_write( slot_ctx->funk );

  /* Attempt serialization of program account. If the program is
     stateless, we want to create the account. Otherwise, we want a
     writable handle to modify the existing account.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L246-L249 */
  FD_TXN_ACCOUNT_DECL( new_target_program_account );
  fd_funk_rec_prepare_t new_target_program_prepare = {0};
  err = fd_txn_account_init_from_funk_mutable(
      new_target_program_account,
      builtin_program_id,
      slot_ctx->funk,
      slot_ctx->funk_txn,
      stateless,
      SIZE_OF_PROGRAM,
      &new_target_program_prepare );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Builtin program ID %s does not exist", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }
  fd_lthash_value_t prev_new_target_program_account_hash[1];
  fd_hashes_account_lthash(
    builtin_program_id,
    fd_txn_account_get_meta( new_target_program_account ),
    fd_txn_account_get_data( new_target_program_account ),
    prev_new_target_program_account_hash );
  fd_txn_account_set_data_len( new_target_program_account, SIZE_OF_PROGRAM );
  fd_txn_account_set_slot( new_target_program_account, fd_bank_slot_get( slot_ctx->bank ) );

  /* Create a new target program account. This modifies the existing record. */
  err = fd_new_target_program_account( slot_ctx, target_program_data_address, new_target_program_account );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write new program state to %s", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }

  fd_hashes_update_lthash(
    new_target_program_account,
    prev_new_target_program_account_hash,
    slot_ctx->bank,
    slot_ctx->capture_ctx );
  fd_txn_account_mutable_fini( new_target_program_account, slot_ctx->funk, slot_ctx->funk_txn, &new_target_program_prepare );

  /* Create a new target program data account. */
  ulong new_target_program_data_account_sz = PROGRAMDATA_METADATA_SIZE - BUFFER_METADATA_SIZE + fd_txn_account_get_data_len( source_buffer_account );
  FD_TXN_ACCOUNT_DECL( new_target_program_data_account );
  fd_funk_rec_prepare_t new_target_program_data_prepare = {0};
  err = fd_txn_account_init_from_funk_mutable(
      new_target_program_data_account,
      target_program_data_address,
      slot_ctx->funk,
      slot_ctx->funk_txn,
      1,
      new_target_program_data_account_sz,
      &new_target_program_data_prepare );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to create new program data account to %s", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    goto fail;
  }
  fd_lthash_value_t prev_new_target_program_data_account_hash[1];
  fd_hashes_account_lthash(
    target_program_data_address,
    fd_txn_account_get_meta( new_target_program_data_account ),
    fd_txn_account_get_data( new_target_program_data_account ),
    prev_new_target_program_data_account_hash );
  fd_txn_account_set_data_len( new_target_program_data_account, new_target_program_data_account_sz );
  fd_txn_account_set_slot( new_target_program_data_account, fd_bank_slot_get( slot_ctx->bank ) );

  err = fd_new_target_program_data_account( slot_ctx,
                                            upgrade_authority_address,
                                            source_buffer_account,
                                            new_target_program_data_account,
                                            runtime_spad );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write new program data state to %s", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    goto fail;
  }

  fd_hashes_update_lthash(
    new_target_program_data_account,
    prev_new_target_program_data_account_hash,
    slot_ctx->bank,
    slot_ctx->capture_ctx );
  fd_txn_account_mutable_fini( new_target_program_data_account, slot_ctx->funk, slot_ctx->funk_txn, &new_target_program_data_prepare );

  /* Deploy the new target Core BPF program.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L268-L271 */
  err = fd_directly_invoke_loader_v3_deploy( slot_ctx,
                                             builtin_program_id,
                                             fd_txn_account_get_data( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE,
                                             fd_txn_account_get_data_len( new_target_program_data_account ) - PROGRAMDATA_METADATA_SIZE,
                                             runtime_spad );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to deploy program %s", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L281-L284 */
  ulong lamports_to_fund = fd_txn_account_get_lamports( new_target_program_account ) + fd_txn_account_get_lamports( new_target_program_data_account );

  /* Update capitalization.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L286-L297 */
  if( lamports_to_burn>lamports_to_fund ) {
    fd_bank_capitalization_set( slot_ctx->bank, fd_bank_capitalization_get( slot_ctx->bank ) - ( lamports_to_burn - lamports_to_fund ) );
  } else {
    fd_bank_capitalization_set( slot_ctx->bank, fd_bank_capitalization_get( slot_ctx->bank ) + ( lamports_to_fund - lamports_to_burn ) );
  }

  /* Reclaim the source buffer account
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L305 */
  fd_txn_account_set_lamports( source_buffer_account, 0 );
  fd_txn_account_set_data_len( source_buffer_account, 0 );
  fd_txn_account_clear_owner( source_buffer_account );

  fd_hashes_update_lthash(
    source_buffer_account,
    prev_source_buffer_hash,
    slot_ctx->bank,
    slot_ctx->capture_ctx );
  fd_txn_account_mutable_fini( source_buffer_account, slot_ctx->funk, slot_ctx->funk_txn, &source_buffer_prepare );

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
fd_apply_builtin_program_feature_transitions( fd_exec_slot_ctx_t *   slot_ctx,
                                              fd_spad_t *            runtime_spad ) {
  /* TODO: Set the upgrade authority properly from the core bpf migration config. Right now it's set to None.

     Migrate any necessary stateless builtins to core BPF. So far,
     the only "stateless" builtin is the Feature program. Beginning
     checks in the migrate_builtin_to_core_bpf function will fail if the
     program has already been migrated to BPF. */

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_builtin_program_t const * builtins = fd_builtins();
  for( ulong i=0UL; i<fd_num_builtins(); i++ ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6732-L6751 */
    if( builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( fd_bank_slot_get( slot_ctx->bank ), fd_bank_features_get( slot_ctx->bank ), builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      FD_LOG_DEBUG(( "Migrating builtin program %s to core BPF", FD_BASE58_ENC_32_ALLOCA( builtins[i].pubkey->key ) ));
      fd_migrate_builtin_to_core_bpf( slot_ctx, builtins[i].core_bpf_migration_config, runtime_spad );
    }
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6753-L6774 */
    if( builtins[i].enable_feature_offset!=NO_ENABLE_FEATURE_ID && FD_FEATURE_JUST_ACTIVATED_OFFSET( slot_ctx, builtins[i].enable_feature_offset ) ) {
      FD_LOG_DEBUG(( "Enabling builtin program %s", FD_BASE58_ENC_32_ALLOCA( builtins[i].pubkey->key ) ));
      fd_write_builtin_account( slot_ctx, *builtins[i].pubkey, builtins[i].data,strlen(builtins[i].data) );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6776-L6793 */
  fd_stateless_builtin_program_t const * stateless_builtins = fd_stateless_builtins();
  for( ulong i=0UL; i<fd_num_stateless_builtins(); i++ ) {
    if( stateless_builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( fd_bank_slot_get( slot_ctx->bank ), fd_bank_features_get( slot_ctx->bank ), stateless_builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      FD_LOG_DEBUG(( "Migrating stateless builtin program %s to core BPF", FD_BASE58_ENC_32_ALLOCA( stateless_builtins[i].pubkey->key ) ));
      fd_migrate_builtin_to_core_bpf( slot_ctx, stateless_builtins[i].core_bpf_migration_config, runtime_spad );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/c1080de464cfb578c301e975f498964b5d5313db/runtime/src/bank.rs#L6795-L6805 */
  fd_precompile_program_t const * precompiles = fd_precompiles();
  for( ulong i=0UL; i<fd_num_precompiles(); i++ ) {
    if( precompiles[i].feature_offset != NO_ENABLE_FEATURE_ID && FD_FEATURE_JUST_ACTIVATED_OFFSET( slot_ctx, precompiles[i].feature_offset ) ) {
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
      fd_txn_account_get_data( acct_rec ),
      fd_txn_account_get_data_len( acct_rec ),
      &decode_err );
  if( FD_UNLIKELY( decode_err ) ) {
    FD_LOG_WARNING(( "Failed to decode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
    return;
  }

  if( feature->has_activated_at ) {
    FD_LOG_DEBUG(( "feature already activated - acc: %s, slot: %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
    fd_features_set( features, id, feature->activated_at);
  } else {
    FD_LOG_DEBUG(( "Feature %s not activated at %lu, activating", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));

    FD_TXN_ACCOUNT_DECL( modify_acct_rec );
    fd_funk_rec_prepare_t modify_acct_prepare = {0};
    err = fd_txn_account_init_from_funk_mutable( modify_acct_rec, (fd_pubkey_t *)acct, slot_ctx->funk, slot_ctx->funk_txn, 0, 0UL, &modify_acct_prepare );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      return;
    }

    fd_lthash_value_t prev_hash[1];
    fd_hashes_account_lthash(
      fd_type_pun_const( acct ),
      fd_txn_account_get_meta( modify_acct_rec ),
      fd_txn_account_get_data( modify_acct_rec ),
      prev_hash );

    feature->has_activated_at = 1;
    feature->activated_at     = fd_bank_slot_get( slot_ctx->bank );
    fd_bincode_encode_ctx_t encode_ctx = {
      .data    = fd_txn_account_get_data_mut( modify_acct_rec ),
      .dataend = fd_txn_account_get_data_mut( modify_acct_rec ) + fd_txn_account_get_data_len( modify_acct_rec ),
    };
    int encode_err = fd_feature_encode( feature, &encode_ctx );
    if( FD_UNLIKELY( encode_err != FD_BINCODE_SUCCESS ) ) {
      FD_LOG_ERR(( "Failed to encode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
    }

    fd_hashes_update_lthash( modify_acct_rec, prev_hash, slot_ctx->bank, slot_ctx->capture_ctx );
    fd_txn_account_mutable_fini( modify_acct_rec, slot_ctx->funk, slot_ctx->funk_txn, &modify_acct_prepare );
  }

  } FD_SPAD_FRAME_END;
}

static void
fd_features_activate( fd_exec_slot_ctx_t * slot_ctx,
                      fd_spad_t *          runtime_spad ) {
  fd_features_t * features = fd_bank_features_modify( slot_ctx->bank );
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_activate( features, slot_ctx, id, id->id.key, runtime_spad );
  }
}

uint
fd_runtime_is_epoch_boundary( fd_exec_slot_ctx_t * slot_ctx,
                              ulong                curr_slot,
                              ulong                prev_slot ) {
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
  - stakes in T-2 (vote_states_prev_prev) should be replaced by T-1 (vote_states_prev)
  - stakes at T-1 (vote_states_prev) should be replaced by updated stakes at T (vote_states)
  - leader schedule should be calculated using new T-2 stakes (vote_states_prev_prev)

  Invariant during an epoch T:
  vote_states_prev holds the stakes at T-1
  vote_states_prev_prev holds the stakes at T-2
 */
/* process for the start of a new epoch */
static void
fd_runtime_process_new_epoch( fd_exec_slot_ctx_t * slot_ctx,
                              ulong                parent_epoch,
                              fd_spad_t *          runtime_spad ) {
  FD_LOG_NOTICE(( "fd_process_new_epoch start, epoch: %lu, slot: %lu", fd_bank_epoch_get( slot_ctx->bank ), fd_bank_slot_get( slot_ctx->bank ) ));

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_frontier_query( slot_ctx->banks, slot_ctx->bank );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "stake_delegations is NULL" ));
  }

  long start = fd_log_wallclock();

  ulong const slot = fd_bank_slot_get ( slot_ctx->bank );

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
  int is_some = fd_new_warmup_cooldown_rate_epoch(
      fd_bank_epoch_schedule_query( slot_ctx->bank ),
      fd_bank_features_query( slot_ctx->bank ),
      slot,
      new_rate_activation_epoch,
      _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_rate_activation_epoch = NULL;
  }

  /* Updates stake history sysvar accumulated values. */
  fd_stakes_activate_epoch( slot_ctx, stake_delegations, new_rate_activation_epoch, runtime_spad );

  /* Refresh vote accounts in stakes cache using updated stake weights, and merges slot bank vote accounts with the epoch bank vote accounts.
    https://github.com/anza-xyz/agave/blob/v2.1.6/runtime/src/stakes.rs#L363-L370 */
  fd_stake_history_t const * history = fd_sysvar_stake_history_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
  if( FD_UNLIKELY( !history ) ) {
    FD_LOG_ERR(( "StakeHistory sysvar could not be read and decoded" ));
  }

  /* Now increment the epoch */

  fd_bank_epoch_set( slot_ctx->bank, fd_bank_epoch_get( slot_ctx->bank ) + 1UL );

  fd_refresh_vote_accounts( slot_ctx,
                            stake_delegations,
                            history,
                            new_rate_activation_epoch );

  /* Distribute rewards */

  fd_hash_t parent_blockhash = {0};
  {
    fd_blockhashes_t const * bhq = fd_bank_block_hash_queue_query( slot_ctx->bank );
    fd_hash_t const * bhq_last = fd_blockhashes_peek_last( bhq );
    FD_TEST( bhq_last );
    parent_blockhash = *bhq_last;
  }

  fd_begin_partitioned_rewards( slot_ctx,
                                stake_delegations,
                                slot_ctx->capture_ctx,
                                &parent_blockhash,
                                parent_epoch,
                                runtime_spad );


  /* Update vote_states_prev_prev with vote_states_prev */

  fd_update_vote_states_prev_prev( slot_ctx );

  /* Update vote_states_prev with vote_states */

  fd_update_vote_states_prev( slot_ctx );

  /* Update current leaders using epoch_stakes (new T-2 stakes) */

  fd_runtime_update_leaders( slot_ctx->bank, fd_bank_slot_get( slot_ctx->bank ), runtime_spad );

  FD_LOG_NOTICE(( "fd_process_new_epoch end" ));

  long end = fd_log_wallclock();
  FD_LOG_NOTICE(("fd_process_new_epoch took %ld ns", end - start));

  } FD_SPAD_FRAME_END;
}

/******************************************************************************/
/* Block Parsing                                                              */
/******************************************************************************/

/* Block iteration and parsing */

/* As a note, all of the logic in this section is used by the full firedancer
   client. The store tile uses these APIs to help parse raw (micro)blocks
   received from the network. */

/* Helpers */

void
fd_runtime_update_program_cache( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_txn_p_t const *   txn_p,
                                 fd_spad_t *          runtime_spad ) {
  fd_txn_t const * txn_descriptor = TXN( txn_p );

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  /* Iterate over account keys referenced directly in the transaction first */
  fd_acct_addr_t const * acc_addrs = fd_txn_get_acct_addrs( txn_descriptor, txn_p );
  for( ushort acc_idx=0; acc_idx<txn_descriptor->acct_addr_cnt; acc_idx++ ) {
    fd_pubkey_t const * account = fd_type_pun_const( &acc_addrs[acc_idx] );
    fd_program_cache_update_program( slot_ctx, account, runtime_spad );
  }

  if( txn_descriptor->transaction_version==FD_TXN_V0 ) {

    /* Iterate over account keys referenced in ALUTs */
    fd_acct_addr_t alut_accounts[256];
    fd_slot_hashes_global_t const * slot_hashes_global = fd_sysvar_slot_hashes_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
    if( FD_UNLIKELY( !slot_hashes_global ) ) {
      return;
    }

    fd_slot_hash_t * slot_hash = deq_fd_slot_hash_t_join( (uchar *)slot_hashes_global + slot_hashes_global->hashes_offset );

    /* TODO: This is done twice, once in the replay tile and once in the
       exec tile. We should consolidate the account resolution into a
       single place, but also keep in mind from a conformance
       perspective that these ALUT resolution checks happen after some
       things like compute budget instruction parsing */
    if( FD_UNLIKELY( fd_runtime_load_txn_address_lookup_tables(
          txn_descriptor,
          txn_p->payload,
          slot_ctx->funk,
          slot_ctx->funk_txn,
          fd_bank_slot_get( slot_ctx->bank ),
          slot_hash,
          alut_accounts ) ) ) {
      return;
    }

    for( ushort alut_idx=0; alut_idx<txn_descriptor->addr_table_adtl_cnt; alut_idx++ ) {
      fd_pubkey_t const * account = fd_type_pun_const( &alut_accounts[alut_idx] );
      fd_program_cache_update_program( slot_ctx, account, runtime_spad );
    }
  }

  } FD_SPAD_FRAME_END;
}

/******************************************************************************/
/* Genesis                                                                    */
/*******************************************************************************/

static void
fd_runtime_genesis_init_program( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_spad_t *          runtime_spad ) {

  fd_sysvar_clock_init( slot_ctx );
  fd_sysvar_rent_init( slot_ctx );

  fd_sysvar_slot_history_init( slot_ctx, runtime_spad );
  fd_sysvar_epoch_schedule_init( slot_ctx );
  fd_sysvar_recent_hashes_init( slot_ctx );
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

  {
    /* FIXME Why is there a previous blockhash at genesis?  Why is the
             last_hash field an option type in Agave, if even the first
             real block has a previous blockhash? */
    ulong seed; FD_TEST( fd_rng_secure( &seed, sizeof(ulong) ) );
    fd_blockhashes_t *    bhq  = fd_blockhashes_init( fd_bank_block_hash_queue_modify( slot_ctx->bank ), seed );
    fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, genesis_hash );
    info->fee_calculator.lamports_per_signature = 0UL;
  }

  fd_bank_fee_rate_governor_set( slot_ctx->bank, genesis_block->fee_rate_governor );

  fd_bank_lamports_per_signature_set( slot_ctx->bank, 0UL );

  fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, 0UL );

  fd_bank_max_tick_height_set( slot_ctx->bank, genesis_block->ticks_per_slot * (fd_bank_slot_get( slot_ctx->bank ) + 1) );

  fd_bank_hashes_per_tick_set( slot_ctx->bank, !!poh->hashes_per_tick ? poh->hashes_per_tick : 0UL );

  fd_bank_ns_per_slot_set( slot_ctx->bank, target_tick_duration * genesis_block->ticks_per_slot );

  fd_bank_ticks_per_slot_set( slot_ctx->bank, genesis_block->ticks_per_slot );

  fd_bank_genesis_creation_time_set( slot_ctx->bank, genesis_block->creation_time );

  fd_bank_slots_per_year_set( slot_ctx->bank, SECONDS_PER_YEAR * (1000000000.0 / (double)target_tick_duration) / (double)genesis_block->ticks_per_slot );

  fd_bank_signature_count_set( slot_ctx->bank, 0UL );

  /* Derive epoch stakes */

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( slot_ctx->banks );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "Failed to join and new a stake delegations" ));
  }

  fd_vote_states_t * vote_states = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_locking_modify( slot_ctx->bank ), FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  if( FD_UNLIKELY( !vote_states ) ) {
    FD_LOG_CRIT(( "Failed to join and new a vote states" ));
  }

  ulong capitalization = 0UL;

  for( ulong i=0UL; i<genesis_block->accounts_len; i++ ) {
    fd_pubkey_account_pair_t const * acc = &genesis_block->accounts[i];
    capitalization = fd_ulong_sat_add( capitalization, acc->account.lamports );

    if( !memcmp(acc->account.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)) ) {
      /* This means that there is a vote account which should be
         inserted into the vote states. Even after the vote account is
         inserted, we still don't know the total amount of stake that is
         delegated to the vote account. This must be calculated later. */
      FD_TXN_ACCOUNT_DECL( vote_acc );
      int err = fd_txn_account_init_from_funk_readonly(
          vote_acc,
          &acc->key,
          slot_ctx->funk,
          slot_ctx->funk_txn );
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_CRIT(( "Failed to init vote account from funk" ));
      }
      uchar const * vote_account_data = fd_txn_account_get_data( vote_acc );
      ulong         vote_account_dlen = fd_txn_account_get_data_len( vote_acc );
      fd_vote_states_update_from_account( vote_states, &acc->key, vote_account_data, vote_account_dlen );

    } else if( !memcmp( acc->account.owner.key, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* If an account is a stake account, then it must be added to the
         stake delegations cache. We should only add stake accounts that
         have a valid non-zero stake. */
      FD_TXN_ACCOUNT_DECL( stake_acc );
      int err = fd_txn_account_init_from_funk_readonly(
          stake_acc,
          &acc->key,
          slot_ctx->funk,
          slot_ctx->funk_txn );
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_CRIT(( "Failed to init stake account from ffunk" ));
      }

      fd_stake_state_v2_t stake_state = {0};
      if( FD_UNLIKELY( fd_stake_get_state( stake_acc, &stake_state )!=0 ) ) {
        FD_LOG_CRIT(( "Failed to get stake state" ));
      }

      if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
        continue;
      }

      if( !stake_state.inner.stake.stake.delegation.stake ) {
        continue;
      }

      fd_stake_delegations_update(
          stake_delegations,
          (fd_pubkey_t *)acc->key.key,
          &stake_state.inner.stake.stake.delegation.voter_pubkey,
          stake_state.inner.stake.stake.delegation.stake,
          stake_state.inner.stake.stake.delegation.activation_epoch,
          stake_state.inner.stake.stake.delegation.deactivation_epoch,
          stake_state.inner.stake.stake.credits_observed,
          stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );

    } else if( !memcmp(acc->account.owner.key, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t)) ) {
      /* Feature Account */

      /* Scan list of feature IDs to resolve address=>feature offset */
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
  fd_bank_vote_states_end_locking_modify( slot_ctx->bank );

  /* fd_refresh_vote_accounts is responsible for updating the vote
     states with the total amount of active delegated stake. It does
     this by iterating over all active stake delegations and summing up
     the amount of stake that is delegated to each vote account. */

  ulong new_rate_activation_epoch = 0UL;
  fd_stake_history_t * stake_history = fd_sysvar_stake_history_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
  fd_refresh_vote_accounts(
      slot_ctx,
      stake_delegations,
      stake_history,
      &new_rate_activation_epoch );

  /* Now that the stake and vote delegations are updated correctly, we
     will propagate the vote states to the vote states for the previous
     epoch and the epoch before that.

     This is despite the fact we are booting off of genesis which means
     that there is no previous or previous-previous epoch. This is done
     to simplify edge cases around leader schedule and rewards
     calculation.

     TODO: Each of the edge cases around this needs to be documented
     much better where each case is clearly enumerated and explained. */

  fd_vote_states_t const * vote_states_curr = fd_bank_vote_states_locking_query( slot_ctx->bank );

  fd_vote_states_t * vote_states_prev_prev = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_prev_prev_locking_modify( slot_ctx->bank ), FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_vote_states_t * vote_states_prev = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_prev_locking_modify( slot_ctx->bank ), FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );

  for( ulong i=0UL; i<genesis_block->accounts_len; i++ ) {
    fd_pubkey_account_pair_t const * acc = &genesis_block->accounts[i];

    if( !memcmp( acc->account.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
      fd_vote_state_ele_t * vote_state = fd_vote_states_query( vote_states_curr, &acc->key );
      fd_vote_states_update_from_account( vote_states_prev_prev, &acc->key, acc->account.data, acc->account.data_len );
      fd_vote_states_update_from_account( vote_states_prev, &acc->key, acc->account.data, acc->account.data_len );
      fd_vote_states_update_stake( vote_states_prev, &acc->key, vote_state->stake );
      fd_vote_states_update_stake( vote_states_prev_prev, &acc->key, vote_state->stake );
    }
  }

  fd_bank_vote_states_prev_prev_end_locking_modify( slot_ctx->bank );
  fd_bank_vote_states_prev_end_locking_modify( slot_ctx->bank );
  fd_bank_vote_states_end_locking_query( slot_ctx->bank );

  fd_bank_epoch_set( slot_ctx->bank, 0UL );

  fd_bank_capitalization_set( slot_ctx->bank, capitalization );
}

static int
fd_runtime_process_genesis_block( fd_exec_slot_ctx_t * slot_ctx,
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

  fd_runtime_genesis_init_program( slot_ctx, runtime_spad );

  fd_sysvar_slot_history_update( slot_ctx );

  fd_runtime_update_leaders( slot_ctx->bank, 0, runtime_spad );

  fd_runtime_freeze( slot_ctx );

  fd_lthash_value_t const * lthash = fd_bank_lthash_locking_query( slot_ctx->bank );

  fd_hash_t const * prev_bank_hash = fd_bank_bank_hash_query( slot_ctx->bank );

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( slot_ctx->bank );
  fd_hashes_hash_bank(
    lthash,
    prev_bank_hash,
    (fd_hash_t *)fd_bank_poh_query( slot_ctx->bank )->hash,
    0UL,
    bank_hash );

  fd_bank_lthash_end_locking_query( slot_ctx->bank );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static void
fd_runtime_init_accounts_from_genesis( fd_exec_slot_ctx_t *        slot_ctx,
                                       fd_genesis_solana_t const * genesis_block ) {

  fd_funk_txn_start_write( slot_ctx->funk );
  fd_funk_txn_xid_t xid = { .ul = { 0UL, 0UL } };
  slot_ctx->funk_txn = fd_funk_txn_prepare( slot_ctx->funk, NULL, &xid, 1 );
  if( FD_UNLIKELY( !slot_ctx->funk_txn ) ) {
    FD_LOG_CRIT(( "Failed to prepare funk transaction" ));
  }
  fd_funk_txn_end_write( slot_ctx->funk );

  FD_LOG_DEBUG(( "start genesis accounts - count: %lu", genesis_block->accounts_len ));

  fd_lthash_value_t prev_hash[1];
  fd_lthash_zero( prev_hash );

  for( ulong i=0; i<genesis_block->accounts_len; i++ ) {
    fd_pubkey_account_pair_t * a = &genesis_block->accounts[i];

    fd_funk_rec_prepare_t prepare = {0};

    FD_TXN_ACCOUNT_DECL( rec );
    int err = fd_txn_account_init_from_funk_mutable( rec,
                                                    &a->key,
                                                    slot_ctx->funk,
                                                    slot_ctx->funk_txn,
                                                    1, /* do_create */
                                                    a->account.data_len,
                                                    &prepare );

    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_txn_account_init_from_funk_mutable failed (%d)", err ));
    }

    fd_txn_account_set_data( rec, a->account.data, a->account.data_len );
    fd_txn_account_set_lamports( rec, a->account.lamports );
    fd_txn_account_set_rent_epoch( rec, a->account.rent_epoch );
    fd_txn_account_set_executable( rec, a->account.executable );
    fd_txn_account_set_owner( rec, &a->account.owner );
    fd_hashes_update_lthash( rec, prev_hash, slot_ctx->bank, slot_ctx->capture_ctx );
    fd_txn_account_mutable_fini( rec, slot_ctx->funk, slot_ctx->funk_txn, &prepare );
  }


}


void
fd_runtime_read_genesis( fd_exec_slot_ctx_t * slot_ctx,
                         char const *         genesis_filepath,
                         fd_spad_t *          runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  /* TODO: fd_runtime_read_genesis should include references to Agave's
     genesis booting code.
     TODO: Add a more robust description of the genesis file format. */

  if( FD_UNLIKELY( !strlen( genesis_filepath ) ) ) {
    FD_LOG_DEBUG(( "genesis_filepath is empty" ));
    return;
  }

  /* If we have a genesis file, we will need to open the file and read
     the data into a buffer. */

  /* TODO: The file handling must be handled inside privileged_init. */

  struct stat sbuf;
  if( FD_UNLIKELY( stat( genesis_filepath, &sbuf)<0 ) ) {
    FD_LOG_ERR(( "cannot open %s : %i-%s", genesis_filepath, errno, strerror( errno ) ));
  }
  int fd = open( genesis_filepath, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(("cannot open %s : %s", genesis_filepath, strerror( errno ) ));
  }

  uchar * buf = fd_spad_alloc( runtime_spad, alignof(ulong), (ulong)sbuf.st_size );
  ulong sz    = 0UL;
  int res     = fd_io_read( fd, buf, (ulong)sbuf.st_size, (ulong)sbuf.st_size, &sz );
  if( FD_UNLIKELY( res!=0 ) ) {
    FD_LOG_ERR(( "fd_io_read failed (%d)", res ));
  }
  if( FD_UNLIKELY( sz!=(ulong)sbuf.st_size ) ) {
    FD_LOG_ERR(( "fd_io_read failed (%lu != %lu)", sz, (ulong)sbuf.st_size ));
  }
  close( fd );

  /* At this point, the genesis file is closed and the data has been
     copied out to an indepedent buffer. Decode the genesis block from
     the config data. */

  int err;
  fd_genesis_solana_t * genesis_block = fd_bincode_decode_spad(
      genesis_solana, runtime_spad, buf, sz, &err );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "failed to decode genesis manifest (%d)", err ));
  }

  /* The genesis hash is generated from the raw data that is located
     inside of the genesis file. */

  fd_hash_t * genesis_hash = fd_bank_genesis_hash_modify( slot_ctx->bank );
  fd_sha256_hash( buf, sz, genesis_hash->hash );

  /* Create a new Funk transaction for slot 0 and write each of the
     accounts and their data from the genesis config into the accounts
     database. */

  fd_runtime_init_accounts_from_genesis( slot_ctx, genesis_block );

  /* Once the accounts have been loaded from the genesis config into
     the accounts db, we can initialize the bank state. This involves
     setting some fields, and notably setting up the vote and stake
     caches which are used for leader scheduling/rewards. */

  fd_runtime_init_bank_from_genesis(
      slot_ctx,
      genesis_block,
      genesis_hash,
      runtime_spad );

  /* Write the native programs to the accounts db. */

  for( ulong i=0UL; i < genesis_block->native_instruction_processors_len; i++ ) {
    fd_string_pubkey_pair_t * a = &genesis_block->native_instruction_processors[i];
    fd_write_builtin_account( slot_ctx, a->pubkey, (const char *)a->string, a->string_len );
  }
  fd_features_restore( slot_ctx, runtime_spad );

  /* At this point, state related to the bank and the accounts db
     have been initialized and we are free to finish executing the
     block. In practice, this updates some bank fields (notably the
     poh and bank hash). */

  err = fd_runtime_process_genesis_block( slot_ctx, runtime_spad );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_CRIT(( "Genesis slot 0 execute failed with error %d", err ));
  }

  } FD_SPAD_FRAME_END;
}

/******************************************************************************/
/* Offline Replay                                                             */
/******************************************************************************/

/* As a note, currently offline and live replay of transactions has differences
   with regards to how the execution environment is setup. These are helpers
   used to emulate this behavior */

void
fd_runtime_block_pre_execute_process_new_epoch( fd_exec_slot_ctx_t * slot_ctx,
                                                fd_capture_ctx_t *   capture_ctx,
                                                fd_spad_t *          runtime_spad,
                                                int *                is_epoch_boundary ) {

  ulong const slot = fd_bank_slot_get( slot_ctx->bank );
  if( slot != 0UL ) {
    fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );

    ulong prev_epoch = fd_slot_to_epoch( epoch_schedule, fd_bank_parent_slot_get( slot_ctx->bank ), NULL );
    ulong slot_idx;
    ulong new_epoch  = fd_slot_to_epoch( epoch_schedule, slot, &slot_idx );
    if( FD_UNLIKELY( slot_idx==1UL && new_epoch==0UL ) ) {
      /* The block after genesis has a height of 1. */
      fd_bank_block_height_set( slot_ctx->bank, 1UL );
    }

    if( FD_UNLIKELY( prev_epoch<new_epoch || !slot_idx ) ) {
      FD_LOG_DEBUG(( "Epoch boundary" ));
      /* Epoch boundary! */
      fd_runtime_process_new_epoch( slot_ctx, prev_epoch, runtime_spad );
      *is_epoch_boundary = 1;
    }
  } else {
    *is_epoch_boundary = 0;
  }

  if( FD_LIKELY( fd_bank_slot_get( slot_ctx->bank )!=0UL ) ) {
    fd_distribute_partitioned_epoch_rewards( slot_ctx, capture_ctx );
  }
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

void
fd_runtime_block_execute_finalize( fd_exec_slot_ctx_t * slot_ctx ) {

  /* This slot is now "frozen" and can't be changed anymore. */
  fd_runtime_freeze( slot_ctx );

  fd_runtime_update_bank_hash( slot_ctx );
}
