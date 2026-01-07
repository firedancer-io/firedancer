#include "fd_runtime.h"
#include "../capture/fd_capture_ctx.h"
#include "../types/fd_cast.h"
#include "fd_acc_mgr.h"
#include "fd_alut_interp.h"
#include "fd_bank.h"
#include "fd_executor_err.h"
#include "fd_hashes.h"
#include "fd_runtime_err.h"
#include "fd_runtime_stack.h"
#include "fd_acc_pool.h"
#include "fd_genesis_parse.h"
#include "fd_executor.h"
#include "fd_txn_account.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_stake_history.h"

#include "../stakes/fd_stakes.h"
#include "../rewards/fd_rewards.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../progcache/fd_progcache_user.h"

#include "program/fd_stake_program.h"
#include "program/fd_builtin_programs.h"
#include "program/fd_program_util.h"

#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_last_restart_slot.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_slot_hashes.h"
#include "sysvar/fd_sysvar_slot_history.h"

#include "tests/fd_dump_pb.h"

#include "fd_system_ids.h"

#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_tip_prog_blacklist.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
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

/* Returns whether the specified epoch should use the new vote account
   keyed leader schedule (returns 1) or the old validator identity keyed
   leader schedule (returns 0). See SIMD-0180.  This is the analogous to
   Agave's Bank::should_use_vote_keyed_leader_schedule():
   https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L6148 */

static int
fd_runtime_should_use_vote_keyed_leader_schedule( fd_bank_t * bank ) {
  /* Agave uses an option type for their effective_epoch value. We
     represent None as ULONG_MAX and Some(value) as the value.
     https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L6149-L6165 */
  if( FD_FEATURE_ACTIVE_BANK( bank, enable_vote_address_leader_schedule ) ) {
    /* Return the first epoch if activated at genesis
       https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L6153-L6157 */
    ulong activation_slot = fd_bank_features_query( bank )->enable_vote_address_leader_schedule;
    if( activation_slot==0UL ) return 1; /* effective_epoch=0, current_epoch >= effective_epoch always true */

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

void
fd_runtime_update_leaders( fd_bank_t *          bank,
                           fd_runtime_stack_t * runtime_stack ) {

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );

  ulong epoch    = fd_slot_to_epoch ( epoch_schedule, fd_bank_slot_get( bank ), NULL );
  ulong slot0    = fd_epoch_slot0   ( epoch_schedule, epoch );
  ulong slot_cnt = fd_epoch_slot_cnt( epoch_schedule, epoch );

  fd_vote_states_t const * vote_states_prev_prev = fd_bank_vote_states_prev_prev_query( bank );
  fd_vote_stake_weight_t * epoch_weights         = runtime_stack->stakes.stake_weights;
  ulong                    stake_weight_cnt      = fd_stake_weights_by_node( vote_states_prev_prev, epoch_weights );

  /* Derive leader schedule */

  ulong epoch_leaders_footprint = fd_epoch_leaders_footprint( stake_weight_cnt, slot_cnt );
  if( FD_LIKELY( epoch_leaders_footprint ) ) {
    if( FD_UNLIKELY( stake_weight_cnt>MAX_PUB_CNT ) ) {
      FD_LOG_ERR(( "Stake weight count exceeded max" ));
    }
    if( FD_UNLIKELY( slot_cnt>MAX_SLOTS_PER_EPOCH ) ) {
      FD_LOG_ERR(( "Slot count exceeeded max" ));
    }

    ulong vote_keyed_lsched = (ulong)fd_runtime_should_use_vote_keyed_leader_schedule( bank );
    void * epoch_leaders_mem = fd_bank_epoch_leaders_modify( bank );
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
  }
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
fd_runtime_run_incinerator( fd_bank_t *               bank,
                            fd_accdb_user_t *         accdb,
                            fd_funk_txn_xid_t const * xid,
                            fd_capture_ctx_t *        capture_ctx ) {
  fd_txn_account_t rec[1];
  fd_funk_rec_prepare_t prepare = {0};

  int ok = !!fd_txn_account_init_from_funk_mutable(
      rec,
      &fd_sysvar_incinerator_id,
      accdb,
      xid,
      0,
      0UL,
      &prepare );
  if( FD_UNLIKELY( !ok ) ) {
    // TODO: not really an error! This is fine!
    return -1;
  }

  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash( rec->pubkey, fd_txn_account_get_meta( rec ), fd_txn_account_get_data( rec ), prev_hash );

  ulong new_capitalization = fd_ulong_sat_sub( fd_bank_capitalization_get( bank ), fd_txn_account_get_lamports( rec ) );
  fd_bank_capitalization_set( bank, new_capitalization );

  fd_txn_account_set_lamports( rec, 0UL );
  fd_hashes_update_lthash( rec->pubkey, rec->meta, prev_hash, bank, capture_ctx );
  fd_txn_account_mutable_fini( rec, accdb, &prepare );

  return 0;
}

static void
fd_runtime_freeze( fd_bank_t *         bank,
                   fd_accdb_user_t *   accdb,
                   fd_capture_ctx_t *  capture_ctx ) {

  fd_funk_txn_xid_t const xid = { .ul = { fd_bank_slot_get( bank ), bank->idx } };

  if( FD_LIKELY( fd_bank_slot_get( bank ) != 0UL ) ) {
    fd_sysvar_recent_hashes_update( bank, accdb, &xid, capture_ctx );
  }

  fd_sysvar_slot_history_update( bank, accdb, &xid, capture_ctx );

  ulong execution_fees = fd_bank_execution_fees_get( bank );
  ulong priority_fees  = fd_bank_priority_fees_get( bank );

  ulong burn = execution_fees / 2;
  ulong fees = fd_ulong_sat_add( priority_fees, execution_fees - burn );

  if( FD_LIKELY( fees ) ) {
    // Look at collect_fees... I think this was where I saw the fee payout..
    fd_txn_account_t rec[1];

    do {
      /* do_create=1 because we might wanna pay fees to a leader
         account that we've purged due to 0 balance. */

      fd_epoch_leaders_t const * leaders = fd_bank_epoch_leaders_query( bank );
      if( FD_UNLIKELY( !leaders ) ) {
        FD_LOG_CRIT(( "fd_runtime_freeze: leaders not found" ));
        break;
      }

      fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, fd_bank_slot_get( bank ) );
      if( FD_UNLIKELY( !leader ) ) {
        FD_LOG_CRIT(( "fd_runtime_freeze: leader not found" ));
        break;
      }

      fd_funk_rec_prepare_t prepare = {0};
      int ok = !!fd_txn_account_init_from_funk_mutable(
          rec,
          leader,
          accdb,
          &xid,
          1,
          0UL,
          &prepare );
      if( FD_UNLIKELY( !ok ) ) {
        FD_BASE58_ENCODE_32_BYTES( leader->uc, leader_b58 );
        FD_LOG_WARNING(( "fd_runtime_freeze: fd_txn_account_init_from_funk_mutable for leader (%s) failed", leader_b58 ));
        burn = fd_ulong_sat_add( burn, fees );
        break;
      }

      fd_lthash_value_t prev_hash[1];
      fd_hashes_account_lthash( leader, fd_txn_account_get_meta( rec ), fd_txn_account_get_data( rec ), prev_hash );

      if ( FD_LIKELY( FD_FEATURE_ACTIVE_BANK( bank, validate_fee_collector_account ) ) ) {
        ulong _burn;
        if( FD_UNLIKELY( _burn=fd_runtime_validate_fee_collector( bank, rec, fees ) ) ) {
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
      fd_txn_account_set_slot( rec, fd_bank_slot_get( bank ) );

      fd_hashes_update_lthash( rec->pubkey, rec->meta, prev_hash, bank, capture_ctx );
      fd_txn_account_mutable_fini( rec, accdb, &prepare );

    } while(0);

    ulong old = fd_bank_capitalization_get( bank );
    fd_bank_capitalization_set( bank, fd_ulong_sat_sub( old, burn ) );
    FD_LOG_DEBUG(( "fd_runtime_freeze: burn %lu, capitalization %lu->%lu ", burn, old, fd_bank_capitalization_get( bank ) ));
  }

  /* jito collects a 3% fee at the end of the block + 3% fee at
     distribution time. */
  fd_bank_tips_set( bank, (fd_bank_tips_get( bank ) * 6UL / 100UL) );

  fd_runtime_run_incinerator( bank, accdb, &xid, capture_ctx );

}

/******************************************************************************/
/* Block-Level Execution Preparation/Finalization                             */
/******************************************************************************/
void
fd_runtime_new_fee_rate_governor_derived( fd_bank_t * bank,
                                          ulong       latest_signatures_per_slot ) {

  fd_fee_rate_governor_t const * base_fee_rate_governor = fd_bank_fee_rate_governor_query( bank );

  ulong old_lamports_per_signature = fd_bank_rbh_lamports_per_sig_get( bank );

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
  fd_bank_fee_rate_governor_set( bank, me );
  fd_bank_rbh_lamports_per_sig_set( bank, new_lamports_per_signature );
}

/******************************************************************************/
/* Epoch Boundary                                                             */
/******************************************************************************/

static void
fd_runtime_refresh_previous_stake_values( fd_bank_t * bank ) {
  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( bank );
  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
       !fd_vote_states_iter_done( iter );
       fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t * vote_state = fd_vote_states_iter_ele( iter );
    vote_state->stake_t_2 = vote_state->stake_t_1;
    vote_state->stake_t_1 = vote_state->stake;
  }
  fd_bank_vote_states_end_locking_modify( bank );
}

/* Replace the vote states for T-2 (vote_states_prev_prev) with the vote
   states for T-1 (vote_states_prev) */

static void
fd_runtime_update_vote_states_prev_prev( fd_bank_t * bank ) {
  fd_vote_states_t *       vote_states_prev_prev = fd_bank_vote_states_prev_prev_modify( bank );
  fd_vote_states_t const * vote_states_prev      = fd_bank_vote_states_prev_query( bank );
  fd_memcpy( vote_states_prev_prev, vote_states_prev, FD_VOTE_STATES_FOOTPRINT );
}

/* Replace the vote states for T-1 (vote_states_prev) with the vote
   states for T-1 (vote_states) */

static void
fd_runtime_update_vote_states_prev( fd_bank_t * bank ) {
  fd_vote_states_t *       vote_states_prev = fd_bank_vote_states_prev_modify( bank );
  fd_vote_states_t const * vote_states      = fd_bank_vote_states_locking_query( bank );
  fd_memcpy( vote_states_prev, vote_states, FD_VOTE_STATES_FOOTPRINT );
  fd_bank_vote_states_end_locking_query( bank );
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6704 */
static void
fd_apply_builtin_program_feature_transitions( fd_bank_t *               bank,
                                              fd_accdb_user_t *         accdb,
                                              fd_funk_txn_xid_t const * xid,
                                              fd_runtime_stack_t *      runtime_stack,
                                              fd_capture_ctx_t *        capture_ctx ) {
  /* TODO: Set the upgrade authority properly from the core bpf migration config. Right now it's set to None.

     Migrate any necessary stateless builtins to core BPF. So far,
     the only "stateless" builtin is the Feature program. Beginning
     checks in the migrate_builtin_to_core_bpf function will fail if the
     program has already been migrated to BPF. */

  fd_builtin_program_t const * builtins = fd_builtins();
  for( ulong i=0UL; i<fd_num_builtins(); i++ ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6732-L6751 */
    if( builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( fd_bank_slot_get( bank ), fd_bank_features_query( bank ), builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( builtins[i].pubkey->key, pubkey_b58 );
      FD_LOG_DEBUG(( "Migrating builtin program %s to core BPF", pubkey_b58 ));
      fd_migrate_builtin_to_core_bpf( bank, accdb, xid, runtime_stack, builtins[i].core_bpf_migration_config, capture_ctx );
    }
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6753-L6774 */
    if( builtins[i].enable_feature_offset!=NO_ENABLE_FEATURE_ID && FD_FEATURE_JUST_ACTIVATED_OFFSET( bank, builtins[i].enable_feature_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( builtins[i].pubkey->key, pubkey_b58 );
      FD_LOG_DEBUG(( "Enabling builtin program %s", pubkey_b58 ));
      fd_write_builtin_account( bank, accdb, xid, capture_ctx, *builtins[i].pubkey, builtins[i].data,strlen(builtins[i].data) );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6776-L6793 */
  fd_stateless_builtin_program_t const * stateless_builtins = fd_stateless_builtins();
  for( ulong i=0UL; i<fd_num_stateless_builtins(); i++ ) {
    if( stateless_builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( fd_bank_slot_get( bank ), fd_bank_features_query( bank ), stateless_builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( stateless_builtins[i].pubkey->key, pubkey_b58 );
      FD_LOG_DEBUG(( "Migrating stateless builtin program %s to core BPF", pubkey_b58 ));
      fd_migrate_builtin_to_core_bpf( bank, accdb, xid, runtime_stack, stateless_builtins[i].core_bpf_migration_config, capture_ctx );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/c1080de464cfb578c301e975f498964b5d5313db/runtime/src/bank.rs#L6795-L6805 */
  fd_precompile_program_t const * precompiles = fd_precompiles();
  for( ulong i=0UL; i<fd_num_precompiles(); i++ ) {
    if( precompiles[i].feature_offset != NO_ENABLE_FEATURE_ID && FD_FEATURE_JUST_ACTIVATED_OFFSET( bank, precompiles[i].feature_offset ) ) {
      fd_write_builtin_account( bank, accdb, xid, capture_ctx, *precompiles[i].pubkey, "", 0 );
    }
  }
}

static void
fd_feature_activate( fd_bank_t *               bank,
                     fd_accdb_user_t *         accdb,
                     fd_funk_txn_xid_t const * xid,
                     fd_capture_ctx_t *        capture_ctx,
                     fd_feature_id_t const *   id,
                     fd_pubkey_t const *       addr ) {
  fd_features_t * features = fd_bank_features_modify( bank );

  if( id->reverted==1 ) return;

  fd_funk_t * funk = fd_accdb_user_v1_funk( accdb );
  fd_txn_account_t acct_rec[1];
  int err = fd_txn_account_init_from_funk_readonly( acct_rec, addr, funk, xid );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    return;
  }

  FD_BASE58_ENCODE_32_BYTES( addr->uc, addr_b58 );
  fd_feature_t feature[1];
  int decode_err = 0;
  if( FD_UNLIKELY( !fd_bincode_decode_static( feature, feature, fd_txn_account_get_data( acct_rec ), fd_txn_account_get_data_len( acct_rec ), &decode_err ) ) ) {
    FD_LOG_WARNING(( "Failed to decode feature account %s (%d)", addr_b58, decode_err ));
    return;
  }

  if( feature->has_activated_at ) {
    FD_LOG_DEBUG(( "feature already activated - acc: %s, slot: %lu", addr_b58, feature->activated_at ));
    fd_features_set( features, id, feature->activated_at);
  } else {
    FD_LOG_DEBUG(( "Feature %s not activated at %lu, activating", addr_b58, feature->activated_at ));

    fd_txn_account_t modify_acct_rec[1];
    fd_funk_rec_prepare_t modify_acct_prepare = {0};
    int ok = !!fd_txn_account_init_from_funk_mutable( modify_acct_rec, addr, accdb, xid, 0, 0UL, &modify_acct_prepare );
    if( FD_UNLIKELY( !ok ) ) return;

    fd_lthash_value_t prev_hash[1];
    fd_hashes_account_lthash(
      addr,
      fd_txn_account_get_meta( modify_acct_rec ),
      fd_txn_account_get_data( modify_acct_rec ),
      prev_hash );

    feature->has_activated_at = 1;
    feature->activated_at     = fd_bank_slot_get( bank );
    fd_bincode_encode_ctx_t encode_ctx = {
      .data    = fd_txn_account_get_data_mut( modify_acct_rec ),
      .dataend = fd_txn_account_get_data_mut( modify_acct_rec ) + fd_txn_account_get_data_len( modify_acct_rec ),
    };
    int encode_err = fd_feature_encode( feature, &encode_ctx );
    if( FD_UNLIKELY( encode_err != FD_BINCODE_SUCCESS ) ) {
      FD_LOG_ERR(( "Failed to encode feature account %s (%d)", addr_b58, decode_err ));
    }

    fd_hashes_update_lthash( modify_acct_rec->pubkey, modify_acct_rec->meta, prev_hash, bank, capture_ctx );
    fd_txn_account_mutable_fini( modify_acct_rec, accdb, &modify_acct_prepare );
  }
}

static void
fd_features_activate( fd_bank_t *               bank,
                      fd_accdb_user_t  *        accdb,
                      fd_funk_txn_xid_t const * xid,
                      fd_capture_ctx_t *        capture_ctx ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_activate( bank, accdb, xid, capture_ctx, id, &id->id );
  }
}

/* SIMD-0194: deprecate_rent_exemption_threshold
   https://github.com/anza-xyz/agave/blob/v3.1.4/runtime/src/bank.rs#L5322-L5329 */
static void
deprecate_rent_exemption_threshold( fd_bank_t *               bank,
                                    fd_accdb_user_t *         accdb,
                                    fd_funk_txn_xid_t const * xid,
                                    fd_capture_ctx_t *        capture_ctx,
                                    fd_funk_t *               funk ) {
  fd_rent_t rent[1] = {0};
  if( FD_UNLIKELY( !fd_sysvar_rent_read( funk, xid, rent ) ) ) {
    FD_LOG_CRIT(( "fd_sysvar_rent_read failed" ));
  }
  rent->lamports_per_uint8_year = fd_rust_cast_double_to_ulong(
    (double)rent->lamports_per_uint8_year * rent->exemption_threshold );
  rent->exemption_threshold     = FD_SIMD_0194_NEW_RENT_EXEMPTION_THRESHOLD;

  /* We don't refresh the sysvar cache here. The cache is refreshed in
     fd_sysvar_cache_restore, which is called at the start of every block
     in fd_runtime_block_execute_prepare, after this function. */
  fd_sysvar_rent_write( bank, accdb, xid, capture_ctx, rent );
  fd_bank_rent_set( bank, *rent );
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
fd_runtime_process_new_epoch( fd_banks_t *              banks,
                              fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx,
                              ulong                     parent_epoch,
                              fd_runtime_stack_t *      runtime_stack ) {

  FD_LOG_NOTICE(( "fd_process_new_epoch start, epoch: %lu, slot: %lu", fd_bank_epoch_get( bank ), fd_bank_slot_get( bank ) ));

  runtime_stack->stakes.prev_vote_credits_used = 0;

  fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "stake_delegations is NULL" ));
  }

  long start = fd_log_wallclock();

  ulong const slot = fd_bank_slot_get( bank );

  /* Activate new features
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6587-L6598 */

  fd_funk_t * funk = fd_accdb_user_v1_funk( accdb );
  fd_features_activate( bank, accdb, xid, capture_ctx );
  fd_features_restore( bank, funk, xid );

  /* SIMD-0194: deprecate_rent_exemption_threshold
     https://github.com/anza-xyz/agave/blob/v3.1.4/runtime/src/bank.rs#L5322-L5329 */
  if( FD_UNLIKELY( FD_FEATURE_JUST_ACTIVATED_BANK( bank, deprecate_rent_exemption_threshold ) ) ) {
    deprecate_rent_exemption_threshold( bank, accdb, xid, capture_ctx, funk );
  }

  /* Apply builtin program feature transitions
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6621-L6624 */

  fd_apply_builtin_program_feature_transitions( bank, accdb, xid, runtime_stack, capture_ctx );

  /* Get the new rate activation epoch */
  int _err[1];
  ulong   new_rate_activation_epoch_val = 0UL;
  ulong * new_rate_activation_epoch     = &new_rate_activation_epoch_val;
  int is_some = fd_new_warmup_cooldown_rate_epoch(
      fd_bank_epoch_schedule_query( bank ),
      fd_bank_features_query( bank ),
      slot,
      new_rate_activation_epoch,
      _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_rate_activation_epoch = NULL;
  }

  /* Updates stake history sysvar accumulated values and recomputes
     stake delegations for vote accounts. */

  fd_stakes_activate_epoch( bank, accdb, xid, capture_ctx, stake_delegations, new_rate_activation_epoch );

  /* Distribute rewards.  This involves calculating the rewards for
     every vote and stake account. */

  fd_hash_t const * parent_blockhash = fd_blockhashes_peek_last_hash( fd_bank_block_hash_queue_query( bank ) );
  fd_begin_partitioned_rewards( bank,
                                accdb,
                                xid,
                                runtime_stack,
                                capture_ctx,
                                stake_delegations,
                                parent_blockhash,
                                parent_epoch );

  /* The Agave client handles updating their stakes cache with a call to
     update_epoch_stakes() which keys stakes by the leader schedule
     epochs and retains up to 6 epochs of stakes.  However, to correctly
     calculate the leader schedule, we just need to maintain the vote
     states for the current epoch, the previous epoch, and the one
     before that.
     https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank.rs#L2175
  */

  /* We want to cache the stake values for T-1 and T-2 in the forward
     looking vote states.  This is done as an optimization for tower
     calculations (T-1 stake) and clock calculation (T-2 stake).
     We use the current stake to populate the T-1 stake and the T-1
     stake to populate the T-2 stake. */
  fd_runtime_refresh_previous_stake_values( bank );

  /* Update vote_states_prev_prev with vote_states_prev */

  fd_runtime_update_vote_states_prev_prev( bank );

  /* Update vote_states_prev with vote_states */

  fd_runtime_update_vote_states_prev( bank );

  /* Now that our stakes caches have been updated, we can calculate the
     leader schedule for the upcoming epoch epoch using our new
     vote_states_prev_prev (stakes for T-2). */

  fd_runtime_update_leaders( bank, runtime_stack );

  long end = fd_log_wallclock();
  FD_LOG_NOTICE(("fd_process_new_epoch took %ld ns", end - start));

}

static void
fd_runtime_block_pre_execute_process_new_epoch( fd_banks_t *              banks,
                                                fd_bank_t *               bank,
                                                fd_accdb_user_t *         accdb,
                                                fd_funk_txn_xid_t const * xid,
                                                fd_capture_ctx_t *        capture_ctx,
                                                fd_runtime_stack_t *      runtime_stack,
                                                int *                     is_epoch_boundary ) {

  ulong const slot = fd_bank_slot_get( bank );
  if( slot != 0UL ) {
    fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );

    ulong prev_epoch = fd_slot_to_epoch( epoch_schedule, fd_bank_parent_slot_get( bank ), NULL );
    ulong slot_idx;
    ulong new_epoch  = fd_slot_to_epoch( epoch_schedule, slot, &slot_idx );
    if( FD_UNLIKELY( slot_idx==1UL && new_epoch==0UL ) ) {
      /* The block after genesis has a height of 1. */
      fd_bank_block_height_set( bank, 1UL );
    }

    if( FD_UNLIKELY( prev_epoch<new_epoch || !slot_idx ) ) {
      FD_LOG_DEBUG(( "Epoch boundary starting" ));
      fd_runtime_process_new_epoch( banks, bank, accdb, xid, capture_ctx, prev_epoch, runtime_stack );
      *is_epoch_boundary = 1;
    }
  } else {
    *is_epoch_boundary = 0;
  }

  if( FD_LIKELY( fd_bank_slot_get( bank )!=0UL ) ) {
    fd_distribute_partitioned_epoch_rewards( bank, accdb, xid, capture_ctx );
  }
}


static void
fd_runtime_block_sysvar_update_pre_execute( fd_bank_t *               bank,
                                            fd_accdb_user_t *         accdb,
                                            fd_funk_txn_xid_t const * xid,
                                            fd_runtime_stack_t *      runtime_stack,
                                            fd_capture_ctx_t *        capture_ctx ) {
  // let (fee_rate_governor, fee_components_time_us) = measure_us!(
  //     FeeRateGovernor::new_derived(&parent.fee_rate_governor, parent.signature_count())
  // );
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1312-L1314 */

  fd_runtime_new_fee_rate_governor_derived( bank, fd_bank_parent_signature_cnt_get( bank ) );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong                       parent_epoch   = fd_slot_to_epoch( epoch_schedule, fd_bank_parent_slot_get( bank ), NULL );
  fd_sysvar_clock_update( bank, accdb, xid, capture_ctx, runtime_stack, &parent_epoch );

  // It has to go into the current txn previous info but is not in slot 0
  if( fd_bank_slot_get( bank ) != 0 ) {
    fd_sysvar_slot_hashes_update( bank, accdb, xid, capture_ctx );
  }
  fd_sysvar_last_restart_slot_update( bank, accdb, xid, capture_ctx, fd_bank_last_restart_slot_get( bank ).slot );
}

int
fd_runtime_load_txn_address_lookup_tables(
    fd_txn_t const *          txn,
    uchar const *             payload,
    fd_funk_t *               funk,
    fd_funk_txn_xid_t const * xid,
    ulong                     slot,
    fd_slot_hash_t const *    hashes, /* deque */
    fd_acct_addr_t *          out_accts_alt ) {

  if( FD_LIKELY( txn->transaction_version!=FD_TXN_V0 ) ) return FD_RUNTIME_EXECUTE_SUCCESS;

  fd_alut_interp_t interp[1];
  fd_alut_interp_new(
      interp,
      out_accts_alt,
      txn,
      payload,
      hashes,
      slot );

  fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn );
  for( ulong i=0UL; i<txn->addr_table_lookup_cnt; i++ ) {
    fd_txn_acct_addr_lut_t const * addr_lut = &addr_luts[i];
    fd_pubkey_t addr_lut_acc = FD_LOAD( fd_pubkey_t, payload+addr_lut->addr_off );

    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L90-L94 */
    fd_txn_account_t addr_lut_rec[1];
    int db_err = fd_txn_account_init_from_funk_readonly(
        addr_lut_rec, &addr_lut_acc, funk,  xid );
    if( FD_UNLIKELY( db_err!=FD_ACC_MGR_SUCCESS ) ) {
      return FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
    }

    int err = fd_alut_interp_next(
        interp,
        &addr_lut_acc,
        fd_txn_account_get_owner   ( addr_lut_rec ),
        fd_txn_account_get_data    ( addr_lut_rec ),
        fd_txn_account_get_data_len( addr_lut_rec ) );
    if( FD_UNLIKELY( err ) ) return err;
  }

  fd_alut_interp_delete( interp );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_block_execute_prepare( fd_banks_t *         banks,
                                  fd_bank_t *          bank,
                                  fd_accdb_user_t  *   accdb,
                                  fd_runtime_stack_t * runtime_stack,
                                  fd_capture_ctx_t *   capture_ctx,
                                  int *                is_epoch_boundary ) {

  fd_funk_txn_xid_t const xid = { .ul = { fd_bank_slot_get( bank ), bank->idx } };

  fd_runtime_block_pre_execute_process_new_epoch( banks, bank, accdb, &xid, capture_ctx, runtime_stack, is_epoch_boundary );

  fd_bank_execution_fees_set( bank, 0UL );
  fd_bank_priority_fees_set( bank, 0UL );
  fd_bank_signature_count_set( bank, 0UL );
  fd_bank_total_compute_units_used_set( bank, 0UL );

  if( FD_LIKELY( fd_bank_slot_get( bank ) ) ) {
    fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_locking_modify( bank );
    FD_TEST( cost_tracker );
    fd_cost_tracker_init( cost_tracker, fd_bank_features_query( bank ), fd_bank_slot_get( bank ) );
    fd_bank_cost_tracker_end_locking_modify( bank );
  }

  fd_runtime_block_sysvar_update_pre_execute( bank, accdb, &xid, runtime_stack, capture_ctx );

  fd_funk_t * funk = fd_accdb_user_v1_funk( accdb );
  if( FD_UNLIKELY( !fd_sysvar_cache_restore( bank, funk, &xid ) ) ) {
    FD_LOG_ERR(( "Failed to restore sysvar cache" ));
  }
}

static void
fd_runtime_update_bank_hash( fd_bank_t *        bank,
                             fd_capture_ctx_t * capture_ctx ) {
  /* Save the previous bank hash, and the parents signature count */
  fd_hash_t const * prev_bank_hash = NULL;
  if( FD_LIKELY( fd_bank_slot_get( bank )!=0UL ) ) {
    prev_bank_hash = fd_bank_bank_hash_query( bank );
    fd_bank_prev_bank_hash_set( bank, *prev_bank_hash );
  } else {
    prev_bank_hash = fd_bank_prev_bank_hash_query( bank );
  }

  fd_bank_parent_signature_cnt_set( bank, fd_bank_signature_count_get( bank ) );

  /* Compute the new bank hash */
  fd_lthash_value_t const * lthash = fd_bank_lthash_locking_query( bank );
  fd_hash_t new_bank_hash[1] = { 0 };
  fd_hashes_hash_bank(
      lthash,
      prev_bank_hash,
      (fd_hash_t *)fd_bank_poh_query( bank )->hash,
      fd_bank_signature_count_get( bank ),
      new_bank_hash );

  /* Update the bank hash */
  fd_bank_bank_hash_set( bank, *new_bank_hash );

  if( capture_ctx != NULL && capture_ctx->capture != NULL &&
    fd_bank_slot_get( bank )>=capture_ctx->solcap_start_slot ) {

    uchar lthash_hash[FD_HASH_FOOTPRINT];
    fd_blake3_hash(lthash->bytes, FD_LTHASH_LEN_BYTES, lthash_hash );
    fd_capture_link_write_bank_preimage(
      capture_ctx,
      fd_bank_slot_get( bank ),
      (fd_hash_t *)new_bank_hash->hash,
      (fd_hash_t *)fd_bank_prev_bank_hash_query( bank ),
      (fd_hash_t *)lthash_hash,
      (fd_hash_t *)fd_bank_poh_query( bank )->hash,
      fd_bank_signature_count_get( bank ) );
  }

  fd_bank_lthash_end_locking_query( bank );
}

/******************************************************************************/
/* Transaction Level Execution Management                                     */
/******************************************************************************/

/* fd_runtime_pre_execute_check is responsible for conducting many of the
   transaction sanitization checks. */

static inline int
fd_runtime_pre_execute_check( fd_runtime_t *      runtime,
                              fd_bank_t *         bank,
                              fd_txn_in_t const * txn_in,
                              fd_txn_out_t *      txn_out ) {

  /* Set up the core account keys. These are the account keys directly
     passed in via the serialized transaction, represented as an array.
     Note that this does not include additional keys referenced in
     address lookup tables. */
  fd_executor_setup_txn_account_keys( txn_in, txn_out );

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

# if FD_HAS_FLATCC
  uchar dump_txn = !!( runtime->log.capture_ctx &&
                       fd_bank_slot_get( bank ) >= runtime->log.capture_ctx->dump_proto_start_slot &&
                       runtime->log.capture_ctx->dump_txn_to_pb );
  if( FD_UNLIKELY( dump_txn ) ) {
    fd_dump_txn_to_protobuf( runtime, bank, txn_in, txn_out );
  }
# endif

  /* Verify the transaction. For now, this step only involves processing
     the compute budget instructions. */
  err = fd_executor_verify_transaction( bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  /* Resolve and verify ALUT-referenced account keys, if applicable */
  err = fd_executor_setup_txn_alut_account_keys( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  /* Set up the transaction accounts and other txn ctx metadata */
  fd_executor_setup_accounts_for_txn( runtime, bank, txn_in, txn_out );

  /* Post-sanitization checks. Called from prepare_sanitized_batch()
     which, for now, only is used to lock the accounts and perform a
     couple basic validations.
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118 */
  err = fd_executor_validate_account_locks( bank, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  /* load_and_execute_transactions() -> check_transactions()
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L3667-L3672 */
  err = fd_executor_check_transactions( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  /* load_and_execute_sanitized_transactions() -> validate_fees() ->
     validate_transaction_fee_payer()
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L236-L249 */
  err = fd_executor_validate_transaction_fee_payer( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  txn_out->details.exec_start_timestamp = fd_tickcount();

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L284-L296 */
  err = fd_executor_load_transaction_accounts( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    /* Regardless of whether transaction accounts were loaded successfully, the transaction is
       included in the block and transaction fees are collected.
       https://github.com/anza-xyz/agave/blob/v2.1.6/svm/src/transaction_processor.rs#L341-L357 */
    txn_out->err.is_fees_only = 1;

    /* If the transaction fails to load, the "rollback" accounts will include one of the following:
        1. Nonce account only
        2. Fee payer only
        3. Nonce account + fee payer

        Because the cost tracker uses the loaded account data size in block cost calculations, we need to
        make sure our calculated loaded accounts data size is conformant with Agave's.
        https://github.com/anza-xyz/agave/blob/v2.1.14/runtime/src/bank.rs#L4116

        In any case, we should always add the dlen of the fee payer. */
    txn_out->details.loaded_accounts_data_size = txn_out->accounts.metas[ FD_FEE_PAYER_TXN_IDX ]->dlen;

    /* Special case handling for if a nonce account is present in the transaction. */
    if( txn_out->accounts.nonce_idx_in_txn!=ULONG_MAX ) {
      /* If the nonce account is not the fee payer, then we separately add the dlen of the nonce account. Otherwise, we would
          be double counting the dlen of the fee payer. */
      if( txn_out->accounts.nonce_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) {
        txn_out->details.loaded_accounts_data_size += txn_out->accounts.rollback_nonce->dlen;
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
fd_runtime_finalize_account( fd_accdb_user_t *         accdb,
                             fd_funk_txn_xid_t const * xid,
                             fd_pubkey_t const *       pubkey,
                             fd_account_meta_t *       meta ) {
  /* FIXME if account doesn't change according to LtHash, don't update
           database record */

  fd_accdb_rw_t rw[1];
  int rw_ok = !!fd_accdb_open_rw(
      accdb,
      rw,
      xid,
      pubkey,
      meta->dlen,
      FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_TRUNCATE );
  if( FD_UNLIKELY( !rw_ok ) ) FD_LOG_CRIT(( "fd_accdb_open_rw failed" ));

  void const * data = fd_account_data( meta );
  fd_accdb_ref_lamports_set( rw, meta->lamports   );
  fd_accdb_ref_owner_set   ( rw, meta->owner      );
  fd_accdb_ref_exec_bit_set( rw, meta->executable );
  fd_accdb_ref_data_set    ( rw, data, meta->dlen );
  fd_accdb_ref_slot_set    ( rw, xid->ul[0]    );

  fd_accdb_close_rw( accdb, rw );
}

/* fd_runtime_save_account persists a transaction account to the account
   database and updates the bank lthash.

   This function:
   - Loads the previous account revision
   - Computes the LtHash of the previous revision
   - Computes the LtHash of the new revision
   - Removes/adds the previous/new revision's LtHash
   - Saves the new version of the account to funk
   - Sends updates to metrics and capture infra

   Returns FD_RUNTIME_SAVE_* */

static int
fd_runtime_save_account( fd_accdb_user_t *         accdb,
                         fd_funk_txn_xid_t const * xid,
                         fd_pubkey_t const *       pubkey,
                         fd_account_meta_t *       meta,
                         fd_bank_t *               bank,
                         fd_capture_ctx_t *        capture_ctx ) {
  fd_lthash_value_t lthash_post[1];
  fd_lthash_value_t lthash_prev[1];

  /* Update LtHash
     - Query old version of account and hash it
     - Hash new version of account */
  fd_accdb_ro_t ro[1];
  int old_exist = 0;
  if( fd_accdb_open_ro( accdb, ro, xid, pubkey ) ) {
    old_exist = fd_accdb_ref_lamports( ro )!=0UL;
    fd_hashes_account_lthash(
      pubkey,
      ro->meta,
      fd_accdb_ref_data_const( ro ),
      lthash_prev );
    fd_accdb_close_ro( accdb, ro );
  } else {
    old_exist = 0;
    fd_lthash_zero( lthash_prev );
  }
  int new_exist = meta->lamports!=0UL;

  fd_hashes_update_lthash1( lthash_post, lthash_prev, pubkey, meta, bank, capture_ctx );

  /* The first 32 bytes of an LtHash with a single input element are
     equal to the BLAKE3_256 hash of an account.  Therefore, comparing
     the first 32 bytes is a cryptographically secure equality check
     for an account. */
  int unchanged = 0==memcmp( lthash_post->bytes, lthash_prev->bytes, 32UL );

  if( old_exist || new_exist ) {
    fd_runtime_finalize_account( accdb, xid, pubkey, meta );
  }

  int save_type = (old_exist<<1) | (new_exist);
  if( save_type==FD_RUNTIME_SAVE_MODIFY && unchanged ) {
    save_type = FD_RUNTIME_SAVE_UNCHANGED;
  }
  return save_type;
}

/* fd_runtime_commit_txn is a helper used by the non-tpool transaction
   executor to finalize borrowed account changes back into funk. It also
   handles txncache insertion and updates to the vote/stake cache.
   TODO: This function should probably be moved to fd_executor.c. */

void
fd_runtime_commit_txn( fd_runtime_t * runtime,
                       fd_bank_t *    bank,
                       fd_txn_out_t * txn_out ) {

  txn_out->details.commit_start_timestamp = fd_tickcount();

  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->idx } };

  if( FD_UNLIKELY( txn_out->err.txn_err ) ) {

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
    if( txn_out->accounts.nonce_idx_in_txn!=ULONG_MAX ) {
      int save_type =
        fd_runtime_save_account(
            runtime->accdb,
            &xid,
            &txn_out->accounts.keys[txn_out->accounts.nonce_idx_in_txn],
            txn_out->accounts.rollback_nonce,
            bank,
            runtime->log.capture_ctx );
      runtime->metrics.txn_account_save[ save_type ]++;
    }
    /* Now, we must only save the fee payer if the nonce account was not the fee payer (because that was already saved above) */
    if( FD_LIKELY( txn_out->accounts.nonce_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) ) {
      int save_type =
        fd_runtime_save_account(
            runtime->accdb,
            &xid,
            &txn_out->accounts.keys[FD_FEE_PAYER_TXN_IDX],
            txn_out->accounts.rollback_fee_payer,
            bank,
            runtime->log.capture_ctx );
      runtime->metrics.txn_account_save[ save_type ]++;
    }
  } else {

    for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
      /* We are only interested in saving writable accounts and the fee
         payer account. */
      if( !txn_out->accounts.is_writable[i] ) {
        continue;
      }

      fd_pubkey_t const * pubkey = &txn_out->accounts.keys[i];
      fd_account_meta_t * meta   = txn_out->accounts.metas[i];

      /* Tips for bundles are collected in the bank: a user submitting a
         bundle must include a instruction that transfers lamports to
         a specific tip account.  Tips accumulated through the slot. */
      if( fd_pack_tip_is_tip_account( fd_type_pun_const( pubkey->uc ) ) ) {
        txn_out->details.tips += fd_ulong_sat_sub( meta->lamports, runtime->accounts.starting_lamports[i] );
        FD_ATOMIC_FETCH_AND_ADD( fd_bank_tips_modify( bank ), txn_out->details.tips );
      }

      if( 0==memcmp( meta->owner, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
        fd_stakes_update_vote_state( pubkey, meta, bank );
      }

      if( 0==memcmp( meta->owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) {
        fd_stakes_update_stake_delegation( pubkey, meta, bank );
      }

      /* Reclaim any accounts that have 0-lamports, now that any related
         cache updates have been applied. */
      fd_executor_reclaim_account( txn_out->accounts.metas[i], fd_bank_slot_get( bank ) );

      int save_type =
        fd_runtime_save_account( runtime->accdb, &xid, pubkey, meta, bank, runtime->log.capture_ctx );
      runtime->metrics.txn_account_save[ save_type ]++;
    }

    /* We need to queue any existing program accounts that may have
       been deployed / upgraded for reverification in the program
       cache since their programdata may have changed. ELF / sBPF
       metadata will need to be updated. */
    ulong current_slot = fd_bank_slot_get( bank );
    for( uchar i=0; i<txn_out->details.programs_to_reverify_cnt; i++ ) {
      fd_pubkey_t const * program_key = &txn_out->details.programs_to_reverify[i];
      fd_progcache_invalidate( runtime->progcache, &xid, program_key, current_slot );
    }
  }

  /* Accumulate block-level information to the bank. */

  FD_ATOMIC_FETCH_AND_ADD( fd_bank_txn_count_modify( bank ),       1UL );
  FD_ATOMIC_FETCH_AND_ADD( fd_bank_execution_fees_modify( bank ),  txn_out->details.execution_fee );
  FD_ATOMIC_FETCH_AND_ADD( fd_bank_priority_fees_modify( bank ),   txn_out->details.priority_fee );
  FD_ATOMIC_FETCH_AND_ADD( fd_bank_signature_count_modify( bank ), txn_out->details.signature_count );

  if( !txn_out->details.is_simple_vote ) {
    FD_ATOMIC_FETCH_AND_ADD( fd_bank_nonvote_txn_count_modify( bank ), 1 );
    if( FD_UNLIKELY( txn_out->err.exec_err ) ) {
      FD_ATOMIC_FETCH_AND_ADD( fd_bank_nonvote_failed_txn_count_modify( bank ), 1 );
    }
  }

  if( FD_UNLIKELY( txn_out->err.exec_err ) ) {
    FD_ATOMIC_FETCH_AND_ADD( fd_bank_failed_txn_count_modify( bank ), 1 );
  }

  FD_ATOMIC_FETCH_AND_ADD( fd_bank_total_compute_units_used_modify( bank ), txn_out->details.compute_budget.compute_unit_limit - txn_out->details.compute_budget.compute_meter );

  /* Update the cost tracker. */

  fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_locking_modify( bank );
  int res = fd_cost_tracker_try_add_cost( cost_tracker, txn_out );
  if( FD_UNLIKELY( res!=FD_COST_TRACKER_SUCCESS ) ) {
    FD_LOG_DEBUG(( "fd_runtime_commit_txn: transaction failed to fit into block %d", res ));
    txn_out->err.is_committable = fd_cost_tracker_err_to_runtime_err( res );
  }
  fd_bank_cost_tracker_end_locking_modify( bank );

  /* Finally, update the status cache. */

  if( FD_LIKELY( runtime->status_cache && txn_out->accounts.nonce_idx_in_txn==ULONG_MAX ) ) {
    /* In Agave, durable nonce transactions are inserted to the status
       cache the same as any others, but this is only to serve RPC
       requests, they do not need to be in there for correctness as the
       nonce mechanism itself prevents double spend.  We skip this logic
       entirely to simplify and improve performance of the txn cache. */

    fd_txncache_insert( runtime->status_cache, bank->txncache_fork_id, txn_out->details.blockhash.uc, txn_out->details.blake_txn_msg_hash.uc );
  }

  for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
    if( txn_out->accounts.is_writable[i] ) {
      fd_acc_pool_release( runtime->acc_pool, fd_type_pun( txn_out->accounts.metas[i] ) );
    }
  }

  fd_acc_pool_release( runtime->acc_pool, txn_out->accounts.rollback_nonce_mem );
  fd_acc_pool_release( runtime->acc_pool, txn_out->accounts.rollback_fee_payer_mem );
}

void
fd_runtime_cancel_txn( fd_runtime_t * runtime,
                       fd_txn_out_t * txn_out ) {
  if( !txn_out->accounts.is_setup ) {
    return;
  }

  for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
    if( txn_out->accounts.is_writable[i] ) {
      fd_acc_pool_release( runtime->acc_pool, fd_type_pun( txn_out->accounts.metas[i] ) );
    }
  }

  fd_acc_pool_release( runtime->acc_pool, txn_out->accounts.rollback_nonce_mem );
  fd_acc_pool_release( runtime->acc_pool, txn_out->accounts.rollback_fee_payer_mem );
}

static inline void
fd_runtime_reset_runtime( fd_runtime_t * runtime ) {
  runtime->instr.stack_sz          = 0;
  runtime->instr.trace_length      = 0UL;
  runtime->accounts.executable_cnt = 0UL;
}

static inline void
fd_runtime_new_txn_out( fd_txn_in_t const * txn_in,
                        fd_txn_out_t *      txn_out ) {
  txn_out->details.prep_start_timestamp   = fd_tickcount();
  txn_out->details.load_start_timestamp   = LONG_MAX;
  txn_out->details.exec_start_timestamp   = LONG_MAX;
  txn_out->details.commit_start_timestamp = LONG_MAX;

  fd_compute_budget_details_new( &txn_out->details.compute_budget );

  txn_out->details.loaded_accounts_data_size = 0UL;
  txn_out->details.accounts_resize_delta     = 0UL;

  txn_out->details.return_data.len = 0UL;
  memset( txn_out->details.return_data.program_id.key, 0, sizeof(fd_pubkey_t) );

  txn_out->details.tips            = 0UL;
  txn_out->details.execution_fee   = 0UL;
  txn_out->details.priority_fee    = 0UL;
  txn_out->details.signature_count = 0UL;

  txn_out->details.programs_to_reverify_cnt = 0UL;

  txn_out->details.signature_count = TXN( txn_in->txn )->signature_cnt;
  txn_out->details.is_simple_vote  = fd_txn_is_simple_vote_transaction( TXN( txn_in->txn ), txn_in->txn->payload );

  fd_hash_t * blockhash = (fd_hash_t *)((uchar *)txn_in->txn->payload + TXN( txn_in->txn )->recent_blockhash_off);
  memcpy( txn_out->details.blockhash.uc, blockhash->hash, sizeof(fd_hash_t) );

  txn_out->accounts.is_setup           = 0;
  txn_out->accounts.cnt                = 0UL;
  txn_out->accounts.rollback_nonce     = NULL;
  txn_out->accounts.rollback_fee_payer = NULL;

  txn_out->err.is_committable = 1;
  txn_out->err.is_fees_only   = 0;
  txn_out->err.txn_err        = FD_RUNTIME_EXECUTE_SUCCESS;
  txn_out->err.exec_err       = FD_EXECUTOR_INSTR_SUCCESS;
  txn_out->err.exec_err_kind  = FD_EXECUTOR_ERR_KIND_NONE;
  txn_out->err.exec_err_idx   = INT_MAX;
  txn_out->err.custom_err     = 0;
}

void
fd_runtime_prepare_and_execute_txn( fd_runtime_t *       runtime,
                                    fd_bank_t *          bank,
                                    fd_txn_in_t const *  txn_in,
                                    fd_txn_out_t *       txn_out ) {

  fd_runtime_reset_runtime( runtime );

  fd_runtime_new_txn_out( txn_in, txn_out );

  /* Transaction sanitization.  If a transaction can't be commited or is
     fees-only, we return early. */
  txn_out->err.txn_err = fd_runtime_pre_execute_check( runtime, bank, txn_in, txn_out );

  txn_out->details.exec_start_timestamp = fd_tickcount();

  /* Execute the transaction if eligible to do so. */
  if( FD_LIKELY( txn_out->err.is_committable ) ) {
    if( FD_LIKELY( !txn_out->err.is_fees_only ) ) {
      txn_out->err.txn_err = fd_execute_txn( runtime, bank, txn_in, txn_out );
    }
    fd_cost_tracker_calculate_cost( bank, txn_in, txn_out );
  }
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
/* Genesis                                                                    */
/*******************************************************************************/

static void
fd_runtime_genesis_init_program( fd_bank_t *               bank,
                                 fd_accdb_user_t *         accdb,
                                 fd_funk_txn_xid_t const * xid,
                                 fd_capture_ctx_t *        capture_ctx ) {

  fd_sysvar_clock_init( bank, accdb, xid, capture_ctx );
  fd_sysvar_rent_init( bank, accdb, xid, capture_ctx );

  fd_sysvar_slot_history_init( bank, accdb, xid, capture_ctx );
  fd_sysvar_epoch_schedule_init( bank, accdb, xid, capture_ctx );
  fd_sysvar_recent_hashes_init( bank, accdb, xid, capture_ctx );
  fd_sysvar_stake_history_init( bank, accdb, xid, capture_ctx );
  fd_sysvar_last_restart_slot_init( bank, accdb, xid, capture_ctx );

  fd_builtin_programs_init( bank, accdb, xid, capture_ctx );
  fd_stake_program_config_init( accdb, xid );
}

static void
fd_runtime_init_bank_from_genesis( fd_banks_t *              banks,
                                   fd_bank_t *               bank,
                                   fd_funk_t *               funk,
                                   fd_funk_txn_xid_t const * xid,
                                   fd_genesis_t const *      genesis_block,
                                   fd_hash_t const *         genesis_hash ) {

  fd_bank_poh_set( bank, *genesis_hash );

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( bank );
  memset( bank_hash->hash, 0, FD_SHA256_HASH_SZ );

  uint128 target_tick_duration = (uint128)genesis_block->poh.tick_duration_secs * 1000000000UL + (uint128)genesis_block->poh.tick_duration_ns;

  fd_epoch_schedule_t * epoch_schedule = fd_bank_epoch_schedule_modify( bank );
  epoch_schedule->leader_schedule_slot_offset = genesis_block->epoch_schedule.leader_schedule_slot_offset;
  epoch_schedule->warmup                      = genesis_block->epoch_schedule.warmup;
  epoch_schedule->first_normal_epoch          = genesis_block->epoch_schedule.first_normal_epoch;
  epoch_schedule->first_normal_slot           = genesis_block->epoch_schedule.first_normal_slot;
  epoch_schedule->slots_per_epoch             = genesis_block->epoch_schedule.slots_per_epoch;

  fd_rent_t * rent = fd_bank_rent_modify( bank );
  rent->lamports_per_uint8_year = genesis_block->rent.lamports_per_uint8_year;
  rent->exemption_threshold     = genesis_block->rent.exemption_threshold;
  rent->burn_percent            = genesis_block->rent.burn_percent;

  fd_inflation_t * inflation = fd_bank_inflation_modify( bank );
  inflation->initial         = genesis_block->inflation.initial;
  inflation->terminal        = genesis_block->inflation.terminal;
  inflation->taper           = genesis_block->inflation.taper;
  inflation->foundation      = genesis_block->inflation.foundation;
  inflation->foundation_term = genesis_block->inflation.foundation_term;
  inflation->unused          = 0.0;

  fd_bank_block_height_set( bank, 0UL );

  {
    /* FIXME Why is there a previous blockhash at genesis?  Why is the
             last_hash field an option type in Agave, if even the first
             real block has a previous blockhash? */
    fd_blockhashes_t *    bhq  = fd_blockhashes_init( fd_bank_block_hash_queue_modify( bank ), 0UL );
    fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, genesis_hash );
    info->fee_calculator.lamports_per_signature = 0UL;
  }

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( bank );
  fee_rate_governor->target_lamports_per_signature = genesis_block->fee_rate_governor.target_lamports_per_signature;
  fee_rate_governor->target_signatures_per_slot    = genesis_block->fee_rate_governor.target_signatures_per_slot;
  fee_rate_governor->min_lamports_per_signature    = genesis_block->fee_rate_governor.min_lamports_per_signature;
  fee_rate_governor->max_lamports_per_signature    = genesis_block->fee_rate_governor.max_lamports_per_signature;
  fee_rate_governor->burn_percent                  = genesis_block->fee_rate_governor.burn_percent;

  fd_bank_max_tick_height_set( bank, genesis_block->poh.ticks_per_slot * (fd_bank_slot_get( bank ) + 1) );

  fd_bank_hashes_per_tick_set( bank, genesis_block->poh.hashes_per_tick );

  fd_bank_ns_per_slot_set( bank, (fd_w_u128_t) { .ud=target_tick_duration * genesis_block->poh.ticks_per_slot } );

  fd_bank_ticks_per_slot_set( bank, genesis_block->poh.ticks_per_slot );

  fd_bank_genesis_creation_time_set( bank, genesis_block->creation_time );

  fd_bank_slots_per_year_set( bank, SECONDS_PER_YEAR * (1000000000.0 / (double)target_tick_duration) / (double)genesis_block->poh.ticks_per_slot );

  fd_bank_signature_count_set( bank, 0UL );

  /* Derive epoch stakes */

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "Failed to join and new a stake delegations" ));
  }

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( bank );
  if( FD_UNLIKELY( !vote_states ) ) {
    FD_LOG_CRIT(( "Failed to join and new a vote states" ));
  }

  ulong capitalization = 0UL;


  for( ulong i=0UL; i<genesis_block->accounts_len; i++ ) {
    fd_genesis_account_t * account = fd_type_pun( (uchar *)genesis_block + genesis_block->accounts_off[ i ] );

    capitalization = fd_ulong_sat_add( capitalization, account->meta.lamports );

    uchar const * acc_data = account->data;

    if( !memcmp( account->meta.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* This means that there is a vote account which should be
         inserted into the vote states. Even after the vote account is
         inserted, we still don't know the total amount of stake that is
         delegated to the vote account. This must be calculated later. */
      fd_vote_states_update_from_account( vote_states, fd_type_pun( account->pubkey ), acc_data, account->meta.dlen );
    } else if( !memcmp( account->meta.owner, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* If an account is a stake account, then it must be added to the
         stake delegations cache. We should only add stake accounts that
         have a valid non-zero stake. */
      fd_stake_state_v2_t stake_state = {0};
      if( FD_UNLIKELY( !fd_bincode_decode_static(
          stake_state_v2, &stake_state,
          acc_data, account->meta.dlen,
          NULL ) ) ) {
        FD_BASE58_ENCODE_32_BYTES( account->pubkey, stake_b58 );
        FD_LOG_ERR(( "Failed to deserialize genesis stake account %s", stake_b58 ));
      }
      if( !fd_stake_state_v2_is_stake( &stake_state )     ) continue;
      if( !stake_state.inner.stake.stake.delegation.stake ) continue;

      fd_stake_delegations_update(
          stake_delegations,
          (fd_pubkey_t *)account->pubkey,
          &stake_state.inner.stake.stake.delegation.voter_pubkey,
          stake_state.inner.stake.stake.delegation.stake,
          stake_state.inner.stake.stake.delegation.activation_epoch,
          stake_state.inner.stake.stake.delegation.deactivation_epoch,
          stake_state.inner.stake.stake.credits_observed,
          stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );

    } else if( !memcmp( account->meta.owner, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* Feature Account */

      /* Scan list of feature IDs to resolve address=>feature offset */
      fd_feature_id_t const *found = NULL;
      for( fd_feature_id_t const * id = fd_feature_iter_init();
           !fd_feature_iter_done( id );
           id = fd_feature_iter_next( id ) ) {
        if( !memcmp( account->pubkey, id->id.key, sizeof(fd_pubkey_t) ) ) {
          found = id;
          break;
        }
      }

      if( found ) {
        /* Load feature activation */
        fd_feature_t feature[1];
        FD_TEST( fd_bincode_decode_static( feature, feature, acc_data, account->meta.dlen, NULL ) );

        fd_features_t * features = fd_bank_features_modify( bank );
        if( feature->has_activated_at ) {
          FD_BASE58_ENCODE_32_BYTES( account->pubkey, pubkey_b58 );
          FD_LOG_DEBUG(( "Feature %s activated at %lu (genesis)", pubkey_b58, feature->activated_at ));
          fd_features_set( features, found, feature->activated_at );
        } else {
          FD_BASE58_ENCODE_32_BYTES( account->pubkey, pubkey_b58 );
          FD_LOG_DEBUG(( "Feature %s not activated (genesis)", pubkey_b58 ));
          fd_features_set( features, found, ULONG_MAX );
        }
      }
    }
  }
  fd_bank_vote_states_end_locking_modify( bank );

  /* fd_refresh_vote_accounts is responsible for updating the vote
     states with the total amount of active delegated stake. It does
     this by iterating over all active stake delegations and summing up
     the amount of stake that is delegated to each vote account. */

  ulong new_rate_activation_epoch = 0UL;

  fd_stake_history_t stake_history[1];
  fd_sysvar_stake_history_read( funk, xid, stake_history );

  fd_refresh_vote_accounts(
      bank,
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

  vote_states = fd_bank_vote_states_locking_modify( bank );
  for( ulong i=0UL; i<genesis_block->accounts_len; i++ ) {
    fd_genesis_account_t * account = fd_type_pun( (uchar *)genesis_block + genesis_block->accounts_off[ i ] );

    if( !memcmp( account->meta.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
      fd_vote_state_ele_t * vote_state = fd_vote_states_query( vote_states, fd_type_pun( account->pubkey ) );

      vote_state->stake_t_1 = vote_state->stake;
      vote_state->stake_t_2 = vote_state->stake;
    }
  }

  fd_vote_states_t * vote_states_prev_prev = fd_bank_vote_states_prev_prev_modify( bank );
  fd_memcpy( vote_states_prev_prev, vote_states, FD_VOTE_STATES_FOOTPRINT );

  fd_vote_states_t * vote_states_prev = fd_bank_vote_states_prev_modify( bank );
  fd_memcpy( vote_states_prev, vote_states, FD_VOTE_STATES_FOOTPRINT );

  fd_bank_vote_states_end_locking_modify( bank );

  fd_bank_epoch_set( bank, 0UL );

  fd_bank_capitalization_set( bank, capitalization );
}

static int
fd_runtime_process_genesis_block( fd_bank_t *               bank,
                                  fd_accdb_user_t *         accdb,
                                  fd_funk_txn_xid_t const * xid,
                                  fd_capture_ctx_t *        capture_ctx,
                                  fd_runtime_stack_t *      runtime_stack ) {

  fd_hash_t * poh = fd_bank_poh_modify( bank );
  ulong hashcnt_per_slot = fd_bank_hashes_per_tick_get( bank ) * fd_bank_ticks_per_slot_get( bank );
  while( hashcnt_per_slot-- ) {
    fd_sha256_hash( poh->hash, sizeof(fd_hash_t), poh->hash );
  }

  fd_bank_execution_fees_set( bank, 0UL );

  fd_bank_priority_fees_set( bank, 0UL );

  fd_bank_signature_count_set( bank, 0UL );

  fd_bank_txn_count_set( bank, 0UL );

  fd_bank_failed_txn_count_set( bank, 0UL );

  fd_bank_nonvote_failed_txn_count_set( bank, 0UL );

  fd_bank_total_compute_units_used_set( bank, 0UL );

  fd_runtime_genesis_init_program( bank, accdb, xid, capture_ctx );

  fd_sysvar_slot_history_update( bank, accdb, xid, capture_ctx );

  fd_runtime_update_leaders( bank, runtime_stack );

  fd_runtime_freeze( bank, accdb, capture_ctx );

  fd_lthash_value_t const * lthash = fd_bank_lthash_locking_query( bank );

  fd_hash_t const * prev_bank_hash = fd_bank_bank_hash_query( bank );

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( bank );
  fd_hashes_hash_bank(
    lthash,
    prev_bank_hash,
    (fd_hash_t *)fd_bank_poh_query( bank )->hash,
    0UL,
    bank_hash );

  fd_bank_lthash_end_locking_query( bank );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_read_genesis( fd_banks_t *              banks,
                         fd_bank_t *               bank,
                         fd_accdb_user_t *         accdb,
                         fd_funk_txn_xid_t const * xid,
                         fd_capture_ctx_t *        capture_ctx,
                         fd_hash_t const *         genesis_hash,
                         fd_lthash_value_t const * genesis_lthash,
                         fd_genesis_t const *      genesis_block,
                         fd_runtime_stack_t *      runtime_stack ) {

  fd_lthash_value_t * lthash = fd_bank_lthash_locking_modify( bank );
  *lthash = *genesis_lthash;
  fd_bank_lthash_end_locking_modify( bank );

  /* Once the accounts have been loaded from the genesis config into
     the accounts db, we can initialize the bank state. This involves
     setting some fields, and notably setting up the vote and stake
     caches which are used for leader scheduling/rewards. */

  fd_funk_t * funk = fd_accdb_user_v1_funk( accdb );
  fd_runtime_init_bank_from_genesis( banks, bank, funk, xid, genesis_block, genesis_hash );

  /* Write the native programs to the accounts db. */

  for( ulong i=0UL; i<genesis_block->builtin_len; i++ ) {
    fd_genesis_account_t * account = fd_type_pun( (uchar *)genesis_block + genesis_block->builtin_off[ i ] );

    fd_pubkey_t pubkey;
    fd_memcpy( pubkey.uc, account->pubkey, sizeof(fd_pubkey_t) );
    fd_write_builtin_account( bank, accdb, xid, capture_ctx, pubkey, (const char *)account->data, account->meta.dlen );
  }

  fd_features_restore( bank, funk, xid );

  /* At this point, state related to the bank and the accounts db
     have been initialized and we are free to finish executing the
     block. In practice, this updates some bank fields (notably the
     poh and bank hash). */

  int err = fd_runtime_process_genesis_block( bank, accdb, xid, capture_ctx, runtime_stack );
  if( FD_UNLIKELY( err ) ) FD_LOG_CRIT(( "genesis slot 0 execute failed with error %d", err ));
}

void
fd_runtime_block_execute_finalize( fd_bank_t *        bank,
                                   fd_accdb_user_t *  accdb,
                                   fd_capture_ctx_t * capture_ctx ) {

  /* This slot is now "frozen" and can't be changed anymore. */
  fd_runtime_freeze( bank, accdb, capture_ctx );

  fd_runtime_update_bank_hash( bank, capture_ctx );
}


/* Mirrors Agave function solana_sdk::transaction_context::find_index_of_account

   Backward scan over transaction accounts.
   Returns -1 if not found.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L233-L238 */

int
fd_runtime_find_index_of_account( fd_txn_out_t const * txn_out,
                                  fd_pubkey_t const *  pubkey ) {
  for( ulong i=txn_out->accounts.cnt; i>0UL; i-- ) {
    if( 0==memcmp( pubkey, &txn_out->accounts.keys[ i-1UL ], sizeof(fd_pubkey_t) ) ) {
      return (int)(i-1UL);
    }
  }
  return -1;
}

int
fd_runtime_get_account_at_index( fd_txn_in_t const *             txn_in,
                                 fd_txn_out_t *                  txn_out,
                                 ushort                          idx,
                                 fd_txn_account_condition_fn_t * condition ) {
  if( FD_UNLIKELY( idx>=txn_out->accounts.cnt ) ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  if( FD_LIKELY( condition != NULL ) ) {
    if( FD_UNLIKELY( !condition( txn_in, txn_out, idx ) ) ) {
      return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
    }
  }

  return FD_ACC_MGR_SUCCESS;
}

int
fd_runtime_get_account_with_key( fd_txn_in_t const *             txn_in,
                                 fd_txn_out_t *                  txn_out,
                                 fd_pubkey_t const *             pubkey,
                                 int *                           index_out,
                                 fd_txn_account_condition_fn_t * condition ) {
  int index = fd_runtime_find_index_of_account( txn_out, pubkey );
  if( FD_UNLIKELY( index==-1 ) ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  *index_out = index;

  return fd_runtime_get_account_at_index( txn_in,
                                          txn_out,
                                          (uchar)index,
                                          condition );
}

int
fd_runtime_get_executable_account( fd_runtime_t *              runtime,
                                   fd_txn_in_t const *         txn_in,
                                   fd_txn_out_t *              txn_out,
                                   fd_pubkey_t const *         pubkey,
                                   fd_account_meta_t const * * meta ) {
  /* First try to fetch the executable account from the existing
     borrowed accounts.  If the pubkey is in the account keys, then we
     want to re-use that borrowed account since it reflects changes from
     prior instructions.  Referencing the read-only executable accounts
     list is incorrect behavior when the program data account is written
     to in a prior instruction (e.g. program upgrade + invoke within the
     same txn) */

  fd_txn_account_condition_fn_t * condition = fd_runtime_account_check_exists;

  int index;
  int err = fd_runtime_get_account_with_key( txn_in,
                                             txn_out,
                                             pubkey,
                                             &index,
                                             condition );
  if( FD_UNLIKELY( err==FD_ACC_MGR_SUCCESS ) ) {
    *meta = txn_out->accounts.metas[index];
    return FD_ACC_MGR_SUCCESS;
  }

  for( ushort i=0; i<runtime->accounts.executable_cnt; i++ ) {
    if( memcmp( pubkey->uc, runtime->accounts.executable_pubkeys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      *meta = runtime->accounts.executables_meta[i];
      if( FD_UNLIKELY( !fd_account_meta_exists( *meta ) ) ) {
        return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
      }
      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

int
fd_runtime_get_key_of_account_at_index( fd_txn_out_t *        txn_out,
                                             ushort                idx,
                                             fd_pubkey_t const * * key ) {
  /* Return a NotEnoughAccountKeys error if idx is out of bounds.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L218 */
  if( FD_UNLIKELY( idx>=txn_out->accounts.cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  *key = &txn_out->accounts.keys[ idx ];
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.1/sdk/program/src/message/versions/v0/loaded.rs#L162 */
int
fd_txn_account_is_demotion( const int        idx,
                            const fd_txn_t * txn_descriptor,
                            const uint       bpf_upgradeable_in_txn ) {
  uint is_program = 0U;
  for( ulong j=0UL; j<txn_descriptor->instr_cnt; j++ ) {
    if( txn_descriptor->instr[j].program_id == idx ) {
      is_program = 1U;
      break;
    }
  }

  return (is_program && !bpf_upgradeable_in_txn);
}

uint
fd_txn_account_has_bpf_loader_upgradeable( const fd_pubkey_t * account_keys,
                                           const ulong         accounts_cnt ) {
  for( ulong j=0; j<accounts_cnt; j++ ) {
    const fd_pubkey_t * acc = &account_keys[j];
    if ( memcmp( acc->uc, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) {
      return 1U;
    }
  }
  return 0U;
}

static inline int
fd_runtime_account_is_writable_idx_flat( const ulong           slot,
                                         const ushort          idx,
                                         const fd_pubkey_t *   addr_at_idx,
                                         const fd_txn_t *      txn_descriptor,
                                         const fd_features_t * features,
                                         const uint            bpf_upgradeable_in_txn ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L43 */
  if( !fd_txn_is_writable( txn_descriptor, idx ) ) {
    return 0;
  }

  /* See comments in fd_system_ids.h.
     https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L44 */
  if( fd_pubkey_is_active_reserved_key( addr_at_idx ) ||
      fd_pubkey_is_pending_reserved_key( addr_at_idx ) ||
      ( FD_FEATURE_ACTIVE( slot, features, enable_secp256r1_precompile ) &&
                           fd_pubkey_is_secp256r1_key( addr_at_idx ) ) ) {

    return 0;
  }

  if( fd_txn_account_is_demotion( idx, txn_descriptor, bpf_upgradeable_in_txn ) ) {
    return 0;
  }

  return 1;
}


/* This function aims to mimic the writable accounts check to populate the writable accounts cache, used
   to determine if accounts are writable or not.

   https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L38-L47 */
int
fd_runtime_account_is_writable_idx( fd_txn_in_t const *  txn_in,
                                    fd_txn_out_t const * txn_out,
                                    fd_bank_t *          bank,
                                    ushort               idx ) {
  uint bpf_upgradeable = fd_txn_account_has_bpf_loader_upgradeable( txn_out->accounts.keys, txn_out->accounts.cnt );
  return fd_runtime_account_is_writable_idx_flat( fd_bank_slot_get( bank ),
                                                   idx,
                                                   &txn_out->accounts.keys[idx],
                                                   TXN( txn_in->txn ),
                                                   fd_bank_features_query( bank ),
                                                   bpf_upgradeable );
}

/* Account pre-condition filtering functions */

int
fd_runtime_account_check_exists( fd_txn_in_t const * txn_in,
                                 fd_txn_out_t *      txn_out,
                                 ushort              idx ) {
  (void) txn_in;
  return fd_account_meta_exists( txn_out->accounts.metas[idx] );
}

int
fd_runtime_account_check_fee_payer_writable( fd_txn_in_t const * txn_in,
                                             fd_txn_out_t *      txn_out,
                                             ushort              idx ) {
  (void) txn_out;
  return fd_txn_is_writable( TXN( txn_in->txn ), idx );
}


int
fd_account_meta_checked_sub_lamports( fd_account_meta_t * meta, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_sub( meta->lamports,
                                  lamports,
                                  &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  meta->lamports = balance_post;
  return FD_EXECUTOR_INSTR_SUCCESS;
}
