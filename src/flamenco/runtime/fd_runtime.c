#include "fd_runtime.h"
#include "fd_acc_mgr.h"
#include "fd_runtime_err.h"
#include "fd_runtime_init.h"
#include "fd_pubkey_utils.h"

#include "fd_executor.h"
#include "fd_account.h"
#include "fd_hashes.h"
#include "fd_txncache.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/bmtree/fd_wbmtree.h"

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

#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_fees.h"
#include "sysvar/fd_sysvar_last_restart_slot.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_slot_hashes.h"
#include "sysvar/fd_sysvar_slot_history.h"

#include "tests/fd_dump_pb.h"

#include "../nanopb/pb_decode.h"
#include "../nanopb/pb_encode.h"
#include "../types/fd_solana_block.pb.h"

#include "fd_system_ids.h"
#include "../vm/fd_vm.h"
#include "fd_blockstore.h"
#include "../../ballet/pack/fd_pack.h"
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
      return FD_RUNTIME_EXECUTE_GENERIC_ERR;
    }
    if( FD_UNLIKELY( ULONG_MAX / ticks_per_slot < next_slot ) ) {
      FD_LOG_WARNING(( "max tick height multiplication overflowed slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
      return FD_RUNTIME_EXECUTE_GENERIC_ERR;
    }
    max_tick_height = fd_ulong_sat_mul( next_slot, ticks_per_slot );
  }
  *out_max_tick_height = max_tick_height;
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void 
fd_runtime_update_leaders( fd_exec_slot_ctx_t * slot_ctx, ulong slot ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_epoch_schedule_t schedule = slot_ctx->epoch_ctx->epoch_bank.epoch_schedule;

    FD_LOG_INFO(( "schedule->slots_per_epoch = %lu", schedule.slots_per_epoch ));
    FD_LOG_INFO(( "schedule->leader_schedule_slot_offset = %lu", schedule.leader_schedule_slot_offset ));
    FD_LOG_INFO(( "schedule->warmup = %d", schedule.warmup ));
    FD_LOG_INFO(( "schedule->first_normal_epoch = %lu", schedule.first_normal_epoch ));
    FD_LOG_INFO(( "schedule->first_normal_slot = %lu", schedule.first_normal_slot ));

    fd_vote_accounts_t const * epoch_vaccs = &slot_ctx->slot_bank.epoch_stakes;

    ulong epoch    = fd_slot_to_epoch( &schedule, slot, NULL );
    ulong slot0    = fd_epoch_slot0( &schedule, epoch );
    ulong slot_cnt = fd_epoch_slot_cnt( &schedule, epoch );

    FD_LOG_INFO(( "starting rent list init" ));

    fd_acc_mgr_set_slots_per_epoch( slot_ctx, fd_epoch_slot_cnt(&schedule, epoch) );
    FD_LOG_INFO(( "rent list init done" ));

    ulong               vote_acc_cnt  = fd_vote_accounts_pair_t_map_size( epoch_vaccs->vote_accounts_pool, epoch_vaccs->vote_accounts_root );
    fd_stake_weight_t * epoch_weights = fd_scratch_alloc( alignof(fd_stake_weight_t), vote_acc_cnt * sizeof(fd_stake_weight_t) );
    if( FD_UNLIKELY( !epoch_weights ) ) {
      FD_LOG_ERR(("fd_scratch_alloc() failed"));
    }

    ulong stake_weight_cnt = fd_stake_weights_by_node(epoch_vaccs, epoch_weights);

    if( FD_UNLIKELY( stake_weight_cnt == ULONG_MAX ) ) {
      FD_LOG_ERR(("fd_stake_weights_by_node() failed"));
    }

    /* Derive leader schedule */

    FD_LOG_INFO(( "stake_weight_cnt=%lu slot_cnt=%lu", stake_weight_cnt, slot_cnt ));
    ulong epoch_leaders_footprint = fd_epoch_leaders_footprint( stake_weight_cnt, slot_cnt );
    FD_LOG_INFO(( "epoch_leaders_footprint=%lu", epoch_leaders_footprint ));
    if( FD_LIKELY( epoch_leaders_footprint ) ) {
      FD_TEST( stake_weight_cnt <= MAX_PUB_CNT );
      FD_TEST( slot_cnt <= MAX_SLOTS_CNT );
      void *               epoch_leaders_mem = fd_exec_epoch_ctx_leaders( slot_ctx->epoch_ctx );
      fd_epoch_leaders_t * leaders           = fd_epoch_leaders_join( fd_epoch_leaders_new( epoch_leaders_mem, 
                                                                                                       epoch, 
                                                                                                       slot0,
                                                                                                       slot_cnt,
                                                                                                       stake_weight_cnt,
                                                                                                       epoch_weights,
                                                                                                       0UL ) );
      FD_TEST( leaders );
    }
  } FD_SCRATCH_SCOPE_END;
}

/* Loads the sysvar cache. Expects acc_mgr, funk_txn, valloc to be non-NULL and valid. */
int 
fd_runtime_sysvar_cache_load( fd_exec_slot_ctx_t * slot_ctx ) {
  if( FD_UNLIKELY( !slot_ctx->acc_mgr ) ) { 
    return -1;
  }

  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, slot_ctx->acc_mgr, slot_ctx->funk_txn );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/******************************************************************************/
/* Various Private Runtime Helpers                                            */
/******************************************************************************/

/* NOTE: Rent functions are not being cleaned up due to the fact that they will
   be entirely torn out of the codebase very soon. */

static void
fd_runtime_collect_rent_for_slot( fd_exec_slot_ctx_t * slot_ctx, ulong off, ulong epoch ) {

  /* Every known Solana cluster currently has no rent-paying accounts. If
     this feature is active, that means that there is no condition in which
     we need to iterate through a rent partition. Put more simply, if this 
     feature is active, rent is NEVER collected. */
  if( FD_FEATURE_ACTIVE( slot_ctx, skip_rent_rewrites ) ) {
    return;
  }

  fd_funk_txn_t * txn     = slot_ctx->funk_txn;
  fd_acc_mgr_t *  acc_mgr = slot_ctx->acc_mgr;
  fd_funk_t *     funk    = slot_ctx->acc_mgr->funk;
  fd_wksp_t *     wksp    = fd_funk_wksp( funk );

  fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  for( fd_funk_rec_t const *rec_ro = fd_funk_part_head( partvec, (uint)off, rec_map );
       rec_ro != NULL;
       rec_ro = fd_funk_part_next( rec_ro, rec_map ) ) {

    if ( FD_UNLIKELY( !fd_funk_key_is_acc( rec_ro->pair.key ) ) ) {
      continue;
    }

    fd_pubkey_t const *key = fd_type_pun_const( rec_ro->pair.key[0].uc );
    FD_BORROWED_ACCOUNT_DECL( rec );
    int err = fd_acc_mgr_view( acc_mgr, txn, key, rec );

    /* Account might not exist anymore in the current world */
    if( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
      continue;
    }
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_runtime_collect_rent: fd_acc_mgr_view failed (%d)", err ));
      continue;
    }

    /* Check if latest version in this transaction */
    if( rec_ro!=rec->const_rec ) {
      continue;
    }

    /* Upgrade read-only handle to writable */
    err = fd_acc_mgr_modify(
        acc_mgr, txn, key,
        /* do_create   */ 0,
        /* min_data_sz */ 0UL,
        rec);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_runtime_collect_rent_range: fd_acc_mgr_modify failed (%d)", err ));
      continue;
    }

    /* Actually invoke rent collection */
    slot_ctx->slot_bank.collected_rent += fd_runtime_collect_rent_from_account( slot_ctx, rec->meta, key, epoch );
  }
}

/* Yes, this is a real function that exists in Solana. Yes, I am ashamed I have had to replicate it. */
// https://github.com/firedancer-io/solana/blob/d8292b427adf8367d87068a3a88f6fd3ed8916a5/runtime/src/bank.rs#L5618
static ulong
fd_runtime_slot_count_in_two_day( ulong ticks_per_slot ) {
  return 2UL * FD_SYSVAR_CLOCK_DEFAULT_TICKS_PER_SECOND * 86400UL /* seconds per day */ / ticks_per_slot;
}

// https://github.com/firedancer-io/solana/blob/d8292b427adf8367d87068a3a88f6fd3ed8916a5/runtime/src/bank.rs#L5594
static int
fd_runtime_use_multi_epoch_collection( fd_exec_slot_ctx_t const * slot_ctx, ulong slot ) {
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong off;
  ulong epoch = fd_slot_to_epoch( schedule, slot, &off );
  ulong slots_per_normal_epoch = fd_epoch_slot_cnt( schedule, schedule->first_normal_epoch );

  ulong slot_count_in_two_day = fd_runtime_slot_count_in_two_day( epoch_bank->ticks_per_slot );

  int use_multi_epoch_collection = ( epoch >= schedule->first_normal_epoch )
      && ( slots_per_normal_epoch < slot_count_in_two_day );

  return use_multi_epoch_collection;
}

static ulong
fd_runtime_num_rent_partitions( fd_exec_slot_ctx_t const * slot_ctx, ulong slot ) {
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong off;
  ulong epoch = fd_slot_to_epoch( schedule, slot, &off );
  ulong slots_per_epoch = fd_epoch_slot_cnt( schedule, epoch );

  ulong slot_count_in_two_day = fd_runtime_slot_count_in_two_day( epoch_bank->ticks_per_slot );

  int use_multi_epoch_collection = fd_runtime_use_multi_epoch_collection( slot_ctx, slot );

  if( use_multi_epoch_collection ) {
    ulong epochs_in_cycle = slot_count_in_two_day / slots_per_epoch;
    return slots_per_epoch * epochs_in_cycle;
  } else {
    return slots_per_epoch;
  }
}

// https://github.com/anza-xyz/agave/blob/2bdcc838c18d262637524274cbb2275824eb97b8/accounts-db/src/accounts_partition.rs#L30
static ulong
fd_runtime_get_rent_partition( fd_exec_slot_ctx_t const * slot_ctx, ulong slot ) {
  int use_multi_epoch_collection = fd_runtime_use_multi_epoch_collection( slot_ctx, slot );

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong off;
  ulong epoch = fd_slot_to_epoch( schedule, slot, &off );
  ulong slot_count_per_epoch = fd_epoch_slot_cnt( schedule, epoch );
  ulong slot_count_in_two_day = fd_runtime_slot_count_in_two_day( epoch_bank->ticks_per_slot );

  ulong base_epoch;
  ulong epoch_count_in_cycle;
  if( use_multi_epoch_collection ) {
    base_epoch = schedule->first_normal_epoch;
    epoch_count_in_cycle = slot_count_in_two_day / slot_count_per_epoch;
  } else {
    base_epoch = 0;
    epoch_count_in_cycle = 1;
  }

  ulong epoch_offset = epoch - base_epoch;
  ulong epoch_index_in_cycle = epoch_offset % epoch_count_in_cycle;
  return off + ( epoch_index_in_cycle * slot_count_per_epoch );
}

static ulong 
fd_runtime_calculate_rent_burn( ulong             rent_collected,
                                fd_rent_t const * rent ) {
  return (rent_collected * rent->burn_percent) / 100UL;
}

static void
fd_runtime_collect_rent( fd_exec_slot_ctx_t * slot_ctx ) {
  // Bank::collect_rent_eagerly (enter)

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  // Bank::rent_collection_partitions              (enter)
  // Bank::variable_cycle_partitions               (enter)
  // Bank::variable_cycle_partitions_between_slots (enter)

  ulong slot0 = slot_ctx->slot_bank.prev_slot;
  ulong slot1 = slot_ctx->slot_bank.slot;

  /* For genesis, we collect rent for slot 0. */
  if (slot1 == 0) {
    ulong s = slot1;
    ulong off;
    ulong epoch = fd_slot_to_epoch(schedule, s, &off);

    /* FIXME: This will not necessarily support warmup_epochs */
    ulong num_partitions = fd_runtime_num_rent_partitions( slot_ctx, s );
    /* Reconstruct rent lists if the number of slots per epoch changes */
    fd_acc_mgr_set_slots_per_epoch( slot_ctx, num_partitions );
    fd_runtime_collect_rent_for_slot( slot_ctx, fd_runtime_get_rent_partition( slot_ctx, s ), epoch );
    return;
  }

  FD_TEST(slot0 <= slot1);

  for( ulong s = slot0 + 1; s <= slot1; ++s ) {
    ulong off;
    ulong epoch = fd_slot_to_epoch(schedule, s, &off);

    /* FIXME: This will not necessarily support warmup_epochs */
    ulong num_partitions = fd_runtime_num_rent_partitions( slot_ctx, s );
    /* Reconstruct rent lists if the number of slots per epoch changes */
    fd_acc_mgr_set_slots_per_epoch( slot_ctx, num_partitions );
    fd_runtime_collect_rent_for_slot( slot_ctx, fd_runtime_get_rent_partition( slot_ctx, s ), epoch );
  }

  // FD_LOG_DEBUG(("rent collected - lamports: %lu", slot_ctx->slot_bank.collected_rent));
}


/* fee to be deposited should be > 0
   Returns 0 if validation succeeds
   Returns the amount to burn(==fee) on failure */
FD_FN_PURE static ulong 
fd_runtime_validate_fee_collector( fd_exec_slot_ctx_t    const * slot_ctx,
                                   fd_borrowed_account_t const * collector,
                                   ulong                         fee ) {
  if( FD_UNLIKELY( fee<=0UL ) ) {
    FD_LOG_ERR(( "expected fee(%lu) to be >0UL", fee ));
  }

  if( FD_UNLIKELY( memcmp( collector->const_meta->info.owner, fd_solana_system_program_id.key, sizeof(collector->const_meta->info.owner) ) ) ) {
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
  ulong minbal = fd_rent_exempt_minimum_balance( fd_sysvar_cache_rent( slot_ctx->sysvar_cache ), collector->const_meta->dlen );
  if( FD_UNLIKELY( collector->const_meta->info.lamports + fee < minbal ) ) {
    FD_BASE58_ENCODE_32_BYTES( collector->pubkey->key, _out_key );
    FD_LOG_WARNING(("cannot pay a rent paying account (%s)", _out_key ));
    return fee;
  }

  return 0UL;
}

struct fd_validator_stake_pair {
  fd_pubkey_t pubkey;
  ulong stake;
};
typedef struct fd_validator_stake_pair fd_validator_stake_pair_t;

static int
fd_validator_stake_pair_compare_before( fd_validator_stake_pair_t const * a,
                                        fd_validator_stake_pair_t const * b ) {
  if( a->stake > b->stake ) {
    return 1;
  } else if (a->stake == b->stake) {
    return memcmp(&a->pubkey, &b->pubkey, sizeof(fd_pubkey_t)) > 0;
  }
  else
  { // a->stake < b->stake
    return 0;
  }
}

#define SORT_NAME sort_validator_stake_pair
#define SORT_KEY_T fd_validator_stake_pair_t
#define SORT_BEFORE(a, b) (fd_validator_stake_pair_compare_before((fd_validator_stake_pair_t const *)&a, (fd_validator_stake_pair_t const *)&b))
#include "../../util/tmpl/fd_sort.c"
#undef SORT_NAME
#undef SORT_KEY_T
#undef SORT_BERFORE

static void 
fd_runtime_distribute_rent_to_validators( fd_exec_slot_ctx_t * slot_ctx,
                                          ulong                rent_to_be_distributed ) {

  FD_SCRATCH_SCOPE_BEGIN {
    ulong total_staked = 0;

    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    fd_vote_accounts_pair_t_mapnode_t *vote_accounts_pool = epoch_bank->stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t *vote_accounts_root = epoch_bank->stakes.vote_accounts.vote_accounts_root;

    ulong num_validator_stakes = fd_vote_accounts_pair_t_map_size( vote_accounts_pool, vote_accounts_root );
    fd_validator_stake_pair_t * validator_stakes = fd_scratch_alloc( 8UL, sizeof(fd_validator_stake_pair_t) * num_validator_stakes );
    ulong i = 0;

    for( fd_vote_accounts_pair_t_mapnode_t *n = fd_vote_accounts_pair_t_map_minimum( vote_accounts_pool, vote_accounts_root );
        n;
        n = fd_vote_accounts_pair_t_map_successor( vote_accounts_pool, n ), i++) {

      validator_stakes[i].pubkey = n->elem.value.node_pubkey;
      validator_stakes[i].stake = n->elem.stake;

      total_staked += n->elem.stake;

    }

    sort_validator_stake_pair_inplace(validator_stakes, num_validator_stakes);

    ulong validate_fee_collector_account = FD_FEATURE_ACTIVE(slot_ctx, validate_fee_collector_account);

    ulong rent_distributed_in_initial_round = 0;

    // We now do distribution, reusing the validator stakes array for the rent stares
    for( i = 0; i < num_validator_stakes; i++ ) {
      ulong staked = validator_stakes[i].stake;
      ulong rent_share = (ulong)(((uint128)staked * (uint128)rent_to_be_distributed) / (uint128)total_staked);

      validator_stakes[i].stake = rent_share;
      rent_distributed_in_initial_round += rent_share;
    }

    ulong leftover_lamports = rent_to_be_distributed - rent_distributed_in_initial_round;

    for( i = 0; i < num_validator_stakes; i++ ) {
      if (leftover_lamports == 0) {
        break;
      }

      /* Not using saturating sub because Agave doesn't.
         https://github.com/anza-xyz/agave/blob/c88e6df566c5c17d71e9574785755683a8fb033a/runtime/src/bank/fee_distribution.rs#L207
       */
      leftover_lamports--;
      validator_stakes[i].stake++;
    }

    for( i = 0; i < num_validator_stakes; i++ ) {
      ulong rent_to_be_paid = validator_stakes[i].stake;

      if( rent_to_be_paid > 0 ) {
        fd_pubkey_t pubkey = validator_stakes[i].pubkey;

        FD_BORROWED_ACCOUNT_DECL(rec);

        int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &pubkey, rec );
        if( FD_UNLIKELY(err) ) {
          FD_LOG_WARNING(( "cannot view pubkey %s. fd_acc_mgr_view failed (%d)", FD_BASE58_ENC_32_ALLOCA( &pubkey ), err ));
          leftover_lamports = fd_ulong_sat_add( leftover_lamports, rent_to_be_paid );
          continue;
        }

        if( FD_LIKELY( validate_fee_collector_account ) ) {
          ulong burn;
          if( FD_UNLIKELY( burn=fd_runtime_validate_fee_collector( slot_ctx, rec, rent_to_be_paid ) ) ) {
            if( FD_UNLIKELY( burn!=rent_to_be_paid ) ) {
              FD_LOG_ERR(( "expected burn(%lu)==rent_to_be_paid(%lu)", burn, rent_to_be_paid ));
            }
            leftover_lamports = fd_ulong_sat_add( leftover_lamports, rent_to_be_paid );
            continue;
          }
        }

        err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, &pubkey, 0, 0UL, rec );
        if( FD_UNLIKELY(err) ) {
          FD_LOG_WARNING(( "cannot modify pubkey %s. fd_acc_mgr_modify failed (%d)", FD_BASE58_ENC_32_ALLOCA( &pubkey ), err ));
          leftover_lamports = fd_ulong_sat_add( leftover_lamports, rent_to_be_paid );
          continue;
        }
        rec->meta->info.lamports += rent_to_be_paid;
      }
    } // end of iteration over validator_stakes

    ulong old = slot_ctx->slot_bank.capitalization;
    slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub(slot_ctx->slot_bank.capitalization, leftover_lamports);
    FD_LOG_DEBUG(( "fd_runtime_distribute_rent_to_validators: burn %lu, capitalization %lu->%lu ", leftover_lamports, old, slot_ctx->slot_bank.capitalization ));

  } FD_SCRATCH_SCOPE_END;
}


static void
fd_runtime_distribute_rent( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong total_rent_collected = slot_ctx->slot_bank.collected_rent;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong burned_portion = fd_runtime_calculate_rent_burn( total_rent_collected, &epoch_bank->rent );
  slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub( slot_ctx->slot_bank.capitalization, burned_portion );
  ulong rent_to_be_distributed = total_rent_collected - burned_portion;

  FD_LOG_DEBUG(( "rent distribution - slot: %lu, burned_lamports: %lu, distributed_lamports: %lu, total_rent_collected: %lu", slot_ctx->slot_bank.slot, burned_portion, rent_to_be_distributed, total_rent_collected ));
  if( rent_to_be_distributed == 0 ) {
    return;
  }

  fd_runtime_distribute_rent_to_validators( slot_ctx, rent_to_be_distributed );
}

static int
fd_runtime_run_incinerator( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_BORROWED_ACCOUNT_DECL( rec );

  int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_incinerator_id, 0, 0UL, rec );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    // TODO: not really an error! This is fine!
    return -1;
  }

  slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub( slot_ctx->slot_bank.capitalization, rec->const_meta->info.lamports );
  rec->meta->info.lamports           = 0UL;

  return 0;
}

static void
fd_runtime_freeze( fd_exec_slot_ctx_t * slot_ctx ) {

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L2820-L2821 */
  fd_runtime_collect_rent( slot_ctx );
  // self.collect_fees();

  fd_sysvar_recent_hashes_update( slot_ctx );

  if( !FD_FEATURE_ACTIVE(slot_ctx, disable_fees_sysvar) )
    fd_sysvar_fees_update(slot_ctx);

  ulong fees = 0UL;
  ulong burn = 0UL;
  if ( FD_FEATURE_ACTIVE( slot_ctx, reward_full_priority_fee ) ) {
    ulong half_fee = slot_ctx->slot_bank.collected_execution_fees / 2;
    fees = fd_ulong_sat_add( slot_ctx->slot_bank.collected_priority_fees, slot_ctx->slot_bank.collected_execution_fees - half_fee );
    burn = half_fee;
  } else {
    ulong total_fees = fd_ulong_sat_add( slot_ctx->slot_bank.collected_execution_fees, slot_ctx->slot_bank.collected_priority_fees );
    ulong half_fee = total_fees / 2;
    fees = total_fees - half_fee;
    burn = half_fee;
  }
  if( FD_LIKELY( fees ) ) {
    // Look at collect_fees... I think this was where I saw the fee payout..
    FD_BORROWED_ACCOUNT_DECL(rec);

    do {
      /* do_create=1 because we might wanna pay fees to a leader
         account that we've purged due to 0 balance. */
      fd_pubkey_t const * leader = fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( slot_ctx->epoch_ctx ), slot_ctx->slot_bank.slot );
      int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, leader, 1, 0UL, rec );
      if( FD_UNLIKELY(err) ) {
        FD_LOG_WARNING(("fd_runtime_freeze: fd_acc_mgr_modify for leader (%s) failed (%d)", FD_BASE58_ENC_32_ALLOCA( leader ), err));
        burn = fd_ulong_sat_add( burn, fees );
        break;
      }

      if ( FD_LIKELY( FD_FEATURE_ACTIVE( slot_ctx, validate_fee_collector_account ) ) ) {
        ulong _burn;
        if( FD_UNLIKELY( _burn=fd_runtime_validate_fee_collector( slot_ctx, rec, fees ) ) ) {
          if( FD_UNLIKELY( _burn!=fees ) ) {
            FD_LOG_ERR(( "expected _burn(%lu)==fees(%lu)", _burn, fees ));
          }
          burn = fd_ulong_sat_add( burn, fees );
          FD_LOG_WARNING(("fd_runtime_freeze: burned %lu", fees ));
          break;
        }
      }

      rec->meta->info.lamports += fees;
      rec->meta->slot = slot_ctx->slot_bank.slot;

      fd_blockstore_start_write( slot_ctx->blockstore );
      fd_block_t * blk = slot_ctx->block;
      blk->rewards.collected_fees = fees;
      blk->rewards.post_balance = rec->meta->info.lamports;
      memcpy( blk->rewards.leader.uc, leader->uc, sizeof(fd_hash_t) );
      fd_blockstore_end_write( slot_ctx->blockstore );
    } while(0);

    ulong old = slot_ctx->slot_bank.capitalization;
    slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub( slot_ctx->slot_bank.capitalization, burn);
    FD_LOG_DEBUG(( "fd_runtime_freeze: burn %lu, capitalization %lu->%lu ", burn, old, slot_ctx->slot_bank.capitalization));

    slot_ctx->slot_bank.collected_execution_fees = 0;
    slot_ctx->slot_bank.collected_priority_fees = 0;
  }

  fd_runtime_distribute_rent( slot_ctx );
  fd_runtime_run_incinerator( slot_ctx );

  FD_LOG_DEBUG(( "fd_runtime_freeze: capitalization %lu ", slot_ctx->slot_bank.capitalization));
  slot_ctx->slot_bank.collected_rent = 0;
}

#define FD_RENT_EXEMPT (-1L)

static long
fd_runtime_get_rent_due( fd_exec_slot_ctx_t const * slot_ctx,
                         fd_account_meta_t *        acc,
                         ulong                      epoch ) {

  fd_epoch_bank_t     * epoch_bank     = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t * schedule       = &epoch_bank->rent_epoch_schedule;
  fd_rent_t           * rent           = &epoch_bank->rent;
  double                slots_per_year = epoch_bank->slots_per_year;

  fd_solana_account_meta_t *info = &acc->info;

  /* Nothing due if account is rent-exempt
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L90 */
  ulong min_balance = fd_rent_exempt_minimum_balance( rent, acc->dlen );
  if( info->lamports>=min_balance ) {
    return FD_RENT_EXEMPT;
  }

  /* Count the number of slots that have passed since last collection. This
     inlines the agave function get_slots_in_peohc
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L93-L98 */
  ulong slots_elapsed = 0UL;
  if( FD_UNLIKELY( info->rent_epoch<schedule->first_normal_epoch ) ) {
    /* Count the slots before the first normal epoch separately */
    for( ulong i=info->rent_epoch; i<schedule->first_normal_epoch && i<=epoch; i++ ) {
      slots_elapsed += fd_epoch_slot_cnt( schedule, i+1UL );
    }
    slots_elapsed += fd_ulong_sat_sub( epoch+1UL, schedule->first_normal_epoch ) * schedule->slots_per_epoch;
  }
  // slots_elapsed should remain 0 if rent_epoch is greater than epoch
  else if( info->rent_epoch<=epoch ) {
    slots_elapsed = (epoch - info->rent_epoch + 1UL) * schedule->slots_per_epoch;
  }
  /* Consensus-critical use of doubles :( */

  double years_elapsed;
  if( FD_LIKELY( slots_per_year!=0.0 ) ) {
    years_elapsed = (double)slots_elapsed / slots_per_year;
  } else {
    years_elapsed = 0.0;
  }

  ulong lamports_per_year = rent->lamports_per_uint8_year * (acc->dlen + 128UL);
  /* https://github.com/anza-xyz/agave/blob/d2124a995f89e33c54f41da76bfd5b0bd5820898/sdk/src/rent_collector.rs#L108 */
  /* https://github.com/anza-xyz/agave/blob/d2124a995f89e33c54f41da76bfd5b0bd5820898/sdk/program/src/rent.rs#L95 */
  return (long)fd_rust_cast_double_to_ulong(years_elapsed * (double)lamports_per_year);
}

/* https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L117-149 */
/* Collect rent from an account. Returns the amount of rent collected. */
static ulong
fd_runtime_collect_from_existing_account( fd_exec_slot_ctx_t const * slot_ctx,
                                          fd_account_meta_t *        acc,
                                          fd_pubkey_t const *        pubkey,
                                          ulong                      epoch ) {
  ulong collected_rent = 0UL;
  #define NO_RENT_COLLECTION_NOW (-1)
  #define EXEMPT                 (-2)
  #define COLLECT_RENT           (-3)

  /* An account must be hashed regardless of if rent is collected from it. */
  acc->slot = slot_ctx->slot_bank.slot;

  /* Inlining calculate_rent_result
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L153-184 */
  int calculate_rent_result = COLLECT_RENT;

  /* RentResult::NoRentCollectionNow */
  if( FD_LIKELY( acc->info.rent_epoch==FD_RENT_EXEMPT_RENT_EPOCH || acc->info.rent_epoch>epoch ) ) {
    calculate_rent_result = NO_RENT_COLLECTION_NOW;
    goto rent_calculation;
  }
  /* RentResult::Exempt */
  /* Inlining should_collect_rent() */
  int should_collect_rent = !( acc->info.executable ||
                               !memcmp( pubkey, &fd_sysvar_incinerator_id, sizeof(fd_pubkey_t) ) );
  if( !should_collect_rent ) {
    calculate_rent_result = EXEMPT;
    goto rent_calculation;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L167-180 */
  long rent_due = fd_runtime_get_rent_due( slot_ctx, acc, epoch );
  if( rent_due==FD_RENT_EXEMPT ) {
    calculate_rent_result = EXEMPT;
  } else if( rent_due==0L ) {
    calculate_rent_result = NO_RENT_COLLECTION_NOW;
  } else {
    calculate_rent_result = COLLECT_RENT;
  }

  rent_calculation:
  switch( calculate_rent_result ) {
    case EXEMPT:
      acc->info.rent_epoch = FD_RENT_EXEMPT_RENT_EPOCH;
      break;
    case NO_RENT_COLLECTION_NOW:
      break;
    case COLLECT_RENT:
      if( FD_UNLIKELY( (ulong)rent_due>=acc->info.lamports ) ) {
        /* Reclaim account */
        collected_rent += (ulong)acc->info.lamports;
        acc->info.lamports                  = 0UL;
        acc->dlen                           = 0UL;
        fd_memset( acc->info.owner, 0, sizeof(acc->info.owner) );
      } else {
        collected_rent += (ulong)rent_due;
        acc->info.lamports                 -= (ulong)rent_due;
        acc->info.rent_epoch                = epoch+1UL;
      }
  }

  return collected_rent;

  #undef NO_RENT_COLLECTION_NOW
  #undef EXEMPT
  #undef COLLECT_RENT
}


/* fd_runtime_collect_rent_from_account performs rent collection duties.
   Although the Solana runtime prevents the creation of new accounts
   that are subject to rent, some older accounts are still undergo the
   rent collection process.  Updates the account's 'rent_epoch' if
   needed. Returns the amount of rent collected. */
/* https://github.com/anza-xyz/agave/blob/v2.0.10/svm/src/account_loader.rs#L71-96 */
ulong
fd_runtime_collect_rent_from_account( fd_exec_slot_ctx_t const * slot_ctx,
                                      fd_account_meta_t *        acc,
                                      fd_pubkey_t const *        key,
                                      ulong                      epoch ) {

  if( !FD_FEATURE_ACTIVE( slot_ctx, disable_rent_fees_collection ) ) {
    return fd_runtime_collect_from_existing_account( slot_ctx, acc, key, epoch );
  } else {
    if( FD_UNLIKELY( acc->info.rent_epoch!=FD_RENT_EXEMPT_RENT_EPOCH &&
                     fd_runtime_get_rent_due( slot_ctx, acc, epoch )==FD_RENT_EXEMPT ) ) {
      acc->info.rent_epoch = ULONG_MAX;
    }
  }
  return 0UL;
}

#undef FD_RENT_EXEMPT

void
fd_runtime_write_transaction_status( fd_capture_ctx_t * capture_ctx,
                                     fd_exec_slot_ctx_t * slot_ctx,
                                     fd_exec_txn_ctx_t * txn_ctx,
                                     int exec_txn_err) {
  /* Look up solana-side transaction status details */
  fd_blockstore_t * blockstore = txn_ctx->slot_ctx->blockstore;
  uchar * sig = (uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->signature_off;
  fd_blockstore_start_read( blockstore );
  fd_txn_map_t * txn_map_entry = fd_blockstore_txn_query( blockstore, sig );
  if( FD_LIKELY( txn_map_entry != NULL ) ) {
    void * meta = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), txn_map_entry->meta_gaddr );

    fd_solblock_TransactionStatusMeta txn_status = {0};
    /* Need to handle case for ledgers where transaction status is not available.
        This case will be handled in fd_solcap_diff. */
    ulong fd_cus_consumed     = txn_ctx->compute_unit_limit - txn_ctx->compute_meter;
    ulong solana_cus_consumed = ULONG_MAX;
    ulong solana_txn_err      = ULONG_MAX;
    if( FD_LIKELY( meta != NULL ) ) {
      pb_istream_t stream = pb_istream_from_buffer( meta, txn_map_entry->meta_sz );
      fd_blockstore_end_read( blockstore );
      if ( pb_decode( &stream, fd_solblock_TransactionStatusMeta_fields, &txn_status ) == false ) {
        FD_LOG_WARNING(("no txn_status decoding found sig=%s (%s)", FD_BASE58_ENC_64_ALLOCA( sig ), PB_GET_ERROR(&stream)));
      }
      if ( txn_status.has_compute_units_consumed ) {
        solana_cus_consumed = txn_status.compute_units_consumed;
      }
      if ( txn_status.has_err ) {
        solana_txn_err = txn_status.err.err->bytes[0];
      }

      fd_solcap_Transaction txn = {
        .slot            = slot_ctx->slot_bank.slot,
        .fd_txn_err      = exec_txn_err,
        .fd_custom_err   = txn_ctx->custom_err,
        .solana_txn_err  = solana_txn_err,
        .fd_cus_used     = fd_cus_consumed,
        .solana_cus_used = solana_cus_consumed,
        .instr_err_idx = txn_ctx->instr_err_idx == INT_MAX ? -1 : txn_ctx->instr_err_idx,
      };
      memcpy( txn.txn_sig, sig, sizeof(fd_signature_t) );

      fd_exec_instr_ctx_t const * failed_instr = txn_ctx->failed_instr;
      if( failed_instr ) {
        assert( failed_instr->depth < 4 );
        txn.instr_err               = failed_instr->instr_err;
        txn.failed_instr_path_count = failed_instr->depth + 1;
        for( long j = failed_instr->depth; j>=0L; j-- ) {
          txn.failed_instr_path[j] = failed_instr->index;
          failed_instr             = failed_instr->parent;
        }
      }

      fd_solcap_write_transaction2( capture_ctx->capture, &txn );
    }
  } else {
    fd_blockstore_end_read( blockstore );
  }
}

static bool
encode_return_data( pb_ostream_t *stream, const pb_field_t *field, void * const *arg ) {
  fd_exec_txn_ctx_t * txn_ctx = (fd_exec_txn_ctx_t *)(*arg);
  pb_encode_tag_for_field(stream, field);
  pb_encode_string(stream, txn_ctx->return_data.data, txn_ctx->return_data.len );
  return 1;
}

static ulong
fd_txn_copy_meta( fd_exec_txn_ctx_t * txn_ctx, uchar * dest, ulong dest_sz ) {
  fd_solblock_TransactionStatusMeta txn_status = {0};

  txn_status.has_fee = 1;
  txn_status.fee = txn_ctx->execution_fee + txn_ctx->priority_fee;

  txn_status.has_compute_units_consumed = 1;
  txn_status.compute_units_consumed = txn_ctx->compute_unit_limit - txn_ctx->compute_meter;

  ulong readonly_cnt = 0;
  ulong writable_cnt = 0;
  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn_ctx->txn_descriptor );
    for( ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++ ) {
      fd_txn_acct_addr_lut_t const * addr_lut = &addr_luts[i];
      readonly_cnt += addr_lut->readonly_cnt;
      writable_cnt += addr_lut->writable_cnt;
    }
  }

  typedef PB_BYTES_ARRAY_T(32) my_ba_t;
  typedef union { my_ba_t my; pb_bytes_array_t normal; } union_ba_t;
  union_ba_t writable_ba[writable_cnt];
  pb_bytes_array_t * writable_baptr[writable_cnt];
  txn_status.loaded_writable_addresses_count = (uint)writable_cnt;
  txn_status.loaded_writable_addresses = writable_baptr;
  ulong idx2 = txn_ctx->txn_descriptor->acct_addr_cnt;
  for (ulong idx = 0; idx < writable_cnt; idx++) {
    pb_bytes_array_t * ba = writable_baptr[ idx ] = &writable_ba[ idx ].normal;
    ba->size = 32;
    fd_memcpy(ba->bytes, &txn_ctx->accounts[idx2++], 32);
  }

  union_ba_t readonly_ba[readonly_cnt];
  pb_bytes_array_t * readonly_baptr[readonly_cnt];
  txn_status.loaded_readonly_addresses_count = (uint)readonly_cnt;
  txn_status.loaded_readonly_addresses = readonly_baptr;
  for (ulong idx = 0; idx < readonly_cnt; idx++) {
    pb_bytes_array_t * ba = readonly_baptr[ idx ] = &readonly_ba[ idx ].normal;
    ba->size = 32;
    fd_memcpy(ba->bytes, &txn_ctx->accounts[idx2++], 32);
  }
  ulong acct_cnt = txn_ctx->accounts_cnt;
  FD_TEST(acct_cnt == idx2);

  txn_status.pre_balances_count = txn_status.post_balances_count = (pb_size_t)acct_cnt;
  uint64_t pre_balances[acct_cnt];
  txn_status.pre_balances = pre_balances;
  uint64_t post_balances[acct_cnt];
  txn_status.post_balances = post_balances;

  for (ulong idx = 0; idx < acct_cnt; idx++) {
    fd_borrowed_account_t const * acct = &txn_ctx->borrowed_accounts[idx];
    ulong pre = ( acct->starting_lamports == ULONG_MAX ? 0UL : acct->starting_lamports );
    pre_balances[idx] = pre;
    post_balances[idx] = ( acct->meta ? acct->meta->info.lamports :
                           ( acct->orig_meta ? acct->orig_meta->info.lamports : pre ) );
  }

  if( txn_ctx->return_data.len ) {
    txn_status.has_return_data = 1;
    txn_status.return_data.has_program_id = 1;
    fd_memcpy( txn_status.return_data.program_id, txn_ctx->return_data.program_id.uc, 32U );
    pb_callback_t data = { .funcs.encode = encode_return_data, .arg = txn_ctx };
    txn_status.return_data.data = data;
  }

  union {
    pb_bytes_array_t arr;
    uchar space[64];
  } errarr;
  pb_byte_t * errptr = errarr.arr.bytes;
  if( txn_ctx->custom_err != UINT_MAX ) {
    *(uint*)errptr = 8 /* Instruction error */;
    errptr += sizeof(uint);
    *errptr = (uchar)txn_ctx->instr_err_idx;
    errptr += 1;
    *(int*)errptr = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    errptr += sizeof(int);
    *(uint*)errptr = txn_ctx->custom_err;
    errptr += sizeof(uint);
    errarr.arr.size = (uint)(errptr - errarr.arr.bytes);
    txn_status.has_err = 1;
    txn_status.err.err = &errarr.arr;
  } else if( txn_ctx->exec_err ) {
    switch( txn_ctx->exec_err_kind ) {
      case FD_EXECUTOR_ERR_KIND_SYSCALL:
        break;
      case FD_EXECUTOR_ERR_KIND_INSTR:
        *(uint*)errptr = 8 /* Instruction error */;
        errptr += sizeof(uint);
        *errptr = (uchar)txn_ctx->instr_err_idx;
        errptr += 1;
        *(int*)errptr = txn_ctx->exec_err;
        errptr += sizeof(int);
        errarr.arr.size = (uint)(errptr - errarr.arr.bytes);
        txn_status.has_err = 1;
        txn_status.err.err = &errarr.arr;
        break;
      case FD_EXECUTOR_ERR_KIND_EBPF:
        break;
    }
  }

  if( dest == NULL ) {
    size_t sz = 0;
    bool r = pb_get_encoded_size( &sz, fd_solblock_TransactionStatusMeta_fields, &txn_status );
    if( !r ) {
      FD_LOG_WARNING(( "pb_get_encoded_size failed" ));
      return 0;
    }
    return sz + txn_ctx->log_collector.buf_sz;
  }

  pb_ostream_t stream = pb_ostream_from_buffer( dest, dest_sz );
  bool r = pb_encode( &stream, fd_solblock_TransactionStatusMeta_fields, &txn_status );
  if( !r ) {
    FD_LOG_WARNING(( "pb_encode failed" ));
    return 0;
  }
  pb_write( &stream, txn_ctx->log_collector.buf, txn_ctx->log_collector.buf_sz );
  return stream.bytes_written;
}

/* fd_runtime_finalize_txns_update_blockstore_meta() updates transaction metadata
   after execution.

   Execution recording is controlled by slot_ctx->enable_exec_recording, and this
   function does nothing if execution recording is off.  The following comments
   only apply when execution recording is on.

   Transaction metadata includes execution result (success/error), balance changes,
   transaction logs, ...  All this info is not part of consensus but can be retrieved,
   for instace, via RPC getTransaction.  Firedancer stores txn meta in the blockstore,
   in the same binary format as Agave, protobuf TransactionStatusMeta. */
static void
fd_runtime_finalize_txns_update_blockstore_meta( fd_exec_slot_ctx_t *         slot_ctx,
                                                 fd_execute_txn_task_info_t * task_info,
                                                 ulong                        txn_cnt ) {
  /* Nothing to do if execution recording is off */
  if( !slot_ctx->enable_exec_recording ) {
    return;
  }

  fd_blockstore_t * blockstore      = slot_ctx->blockstore;
  fd_wksp_t * blockstore_wksp       = fd_blockstore_wksp( blockstore );
  fd_alloc_t * blockstore_alloc     = fd_blockstore_alloc( blockstore );
  fd_txn_map_t * txn_map = fd_blockstore_txn_map( blockstore );

  /* Get the total size of all logs */
  ulong tot_meta_sz = 2*sizeof(ulong);
  for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
    /* Prebalance compensation */
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
    txn_ctx->borrowed_accounts[0].starting_lamports += (txn_ctx->execution_fee + txn_ctx->priority_fee);
    /* Get the size without the copy */
    tot_meta_sz += fd_txn_copy_meta( txn_ctx, NULL, 0 );
  }
  uchar * cur_laddr = fd_alloc_malloc( blockstore_alloc, 1, tot_meta_sz );
  if( cur_laddr == NULL ) {
    return;
  }
  uchar * const end_laddr = cur_laddr + tot_meta_sz;

  fd_blockstore_start_write( blockstore );
  fd_block_t * blk = slot_ctx->block;
  /* Link to previous allocation */
  ((ulong*)cur_laddr)[0] = blk->txns_meta_gaddr;
  ((ulong*)cur_laddr)[1] = blk->txns_meta_sz;
  blk->txns_meta_gaddr = fd_wksp_gaddr_fast( blockstore_wksp, cur_laddr );
  blk->txns_meta_sz    = tot_meta_sz;
  cur_laddr += 2*sizeof(ulong);

  for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
    ulong meta_sz = fd_txn_copy_meta( txn_ctx, cur_laddr, (size_t)(end_laddr - cur_laddr) );
    if( meta_sz ) {
      ulong  meta_gaddr = fd_wksp_gaddr_fast( blockstore_wksp, cur_laddr );

      /* Update all the signatures */
      char const * sig_p = (char const *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->signature_off;
      fd_txn_key_t sig;
      for( uchar i=0U; i<txn_ctx->txn_descriptor->signature_cnt; i++ ) {
        fd_memcpy( &sig, sig_p, sizeof(fd_txn_key_t) );
        fd_txn_map_t * txn_map_entry = fd_txn_map_query( txn_map, &sig, NULL );
        if( FD_LIKELY( txn_map_entry ) ) {
          txn_map_entry->meta_gaddr = meta_gaddr;
          txn_map_entry->meta_sz    = meta_sz;
        }
        sig_p += FD_ED25519_SIG_SZ;
      }

      cur_laddr += meta_sz;
    }
    fd_log_collector_delete( &txn_ctx->log_collector );
  }

  FD_TEST( cur_laddr == end_laddr );

  fd_blockstore_end_write( blockstore );
}

/******************************************************************************/
/* Block-Level Execution Preparation/Finalization                             */
/******************************************************************************/

static int
fd_runtime_block_sysvar_update_pre_execute( fd_exec_slot_ctx_t * slot_ctx ) {
  // let (fee_rate_governor, fee_components_time_us) = measure_us!(
  //     FeeRateGovernor::new_derived(&parent.fee_rate_governor, parent.signature_count())
  // );
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1312-L1314 */
  fd_sysvar_fees_new_derived( slot_ctx,
                              slot_ctx->slot_bank.fee_rate_governor,
                              slot_ctx->slot_bank.parent_signature_cnt );

  // TODO: move all these out to a fd_sysvar_update() call...
  long clock_update_time      = -fd_log_wallclock();
  fd_sysvar_clock_update( slot_ctx );
  clock_update_time          += fd_log_wallclock();
  double clock_update_time_ms = (double)clock_update_time * 1e-6;
  FD_LOG_INFO(( "clock updated - slot: %lu, elapsed: %6.6f ms", slot_ctx->slot_bank.slot, clock_update_time_ms ));
  if( !FD_FEATURE_ACTIVE(slot_ctx, disable_fees_sysvar ) ) {
    fd_sysvar_fees_update(slot_ctx);
  }
  // It has to go into the current txn previous info but is not in slot 0
  if( slot_ctx->slot_bank.slot != 0 ) {
    fd_sysvar_slot_hashes_update( slot_ctx );
  }
  fd_sysvar_last_restart_slot_update( slot_ctx );

  return 0;
}

/*
   TODO Perhaps update this function to support verifying ticks before
   the block is full.  Could be useful when we move to a streaming
   execution model.
 */
ulong
fd_runtime_block_verify_ticks( fd_block_micro_t const * micro,
                               ulong                    micro_cnt,
                               uchar const *            block_data,
                               ulong                    tick_height,
                               ulong                    max_tick_height,
                               ulong                    hashes_per_tick ) {
  ulong tick_count              = 0UL;
  ulong tick_hash_count         = 0UL;
  uchar has_trailing_entry      = 0U;
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
  for( ulong i = 0UL; i < micro_cnt; i++ ) {
    fd_microblock_hdr_t const * hdr = fd_type_pun_const( ( block_data + micro[ i ].off ) );
    tick_hash_count = fd_ulong_sat_add( tick_hash_count, hdr->hash_cnt );
    if( hdr->txn_cnt == 0UL ) {
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
      FD_LOG_WARNING(( "entry %lu has %lu transactions expects 0", i, hdr->txn_cnt ));
      has_trailing_entry = 1U;
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
  if( FD_UNLIKELY( has_trailing_entry ) ) {
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
fd_runtime_block_execute_prepare( fd_exec_slot_ctx_t * slot_ctx ) {
  if( slot_ctx->slot_bank.slot != 0UL ) {
    fd_blockstore_start_write( slot_ctx->blockstore );
    fd_blockstore_block_height_update( slot_ctx->blockstore,
                                       slot_ctx->slot_bank.slot,
                                       slot_ctx->slot_bank.block_height );
    slot_ctx->block = fd_blockstore_block_query( slot_ctx->blockstore, slot_ctx->slot_bank.slot );
    fd_blockstore_end_write( slot_ctx->blockstore );
  }

  slot_ctx->slot_bank.collected_execution_fees = 0UL;
  slot_ctx->slot_bank.collected_priority_fees  = 0UL;
  slot_ctx->slot_bank.collected_rent           = 0UL;
  slot_ctx->signature_cnt                      = 0UL;
  slot_ctx->txn_count                          = 0UL;
  slot_ctx->nonvote_txn_count                  = 0UL;
  slot_ctx->failed_txn_count                   = 0UL;
  slot_ctx->nonvote_failed_txn_count           = 0UL;
  slot_ctx->total_compute_units_used           = 0UL;

  fd_funk_start_write( slot_ctx->acc_mgr->funk );
  int result = fd_runtime_block_sysvar_update_pre_execute( slot_ctx );
  fd_funk_end_write( slot_ctx->acc_mgr->funk );
  if( FD_UNLIKELY( result != 0 ) ) {
    FD_LOG_WARNING(("updating sysvars failed"));
    return result;
  }

  /* Load sysvars into cache */
  if( FD_UNLIKELY( result = fd_runtime_sysvar_cache_load( slot_ctx ) ) ) {
    /* non-zero error */
    return result;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_block_execute_finalize_tpool( fd_exec_slot_ctx_t *    slot_ctx,
                                         fd_capture_ctx_t *      capture_ctx,
                                         fd_block_info_t const * block_info,
                                         fd_tpool_t *            tpool ) {
  fd_funk_start_write( slot_ctx->acc_mgr->funk );

  fd_sysvar_slot_history_update( slot_ctx );

  /* This slot is now "frozen" and can't be changed anymore. */
  fd_runtime_freeze( slot_ctx );

  int result = fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( slot_ctx, slot_ctx->funk_txn, tpool );
  if( FD_UNLIKELY( result ) ) {
    FD_LOG_WARNING(( "update bpf program cache failed" ));
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
    return result;
  }

  result = fd_update_hash_bank_tpool( slot_ctx, capture_ctx, &slot_ctx->slot_bank.banks_hash, block_info->signature_cnt, tpool );
  if( FD_UNLIKELY( result!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    FD_LOG_WARNING(( "hashing bank failed" ));
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
    return result;
  }

  /* We don't want to save the epoch bank at the end of every slot because it
     should only be changing at the epoch boundary. */

  result = fd_runtime_save_slot_bank( slot_ctx );
  if( FD_UNLIKELY( result!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to save slot bank" ));
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
    return result;
  }

  fd_funk_end_write( slot_ctx->acc_mgr->funk );

  slot_ctx->total_compute_units_requested = 0UL;

  return FD_RUNTIME_EXECUTE_SUCCESS;
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
                               ulong                        txn_cnt ) {
  int res = 0;
  /* Loop across transactions */
  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_txn_p_t * txn = &txns[txn_idx];

    /* Allocate/setup transaction context and task infos */
    task_info[txn_idx].txn_ctx      = fd_valloc_malloc( fd_scratch_virtual(), FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
    fd_exec_txn_ctx_t * txn_ctx     = task_info[txn_idx].txn_ctx;
    task_info[txn_idx].exec_res     = 0;
    task_info[txn_idx].txn          = txn;
    fd_txn_t const * txn_descriptor = (fd_txn_t const *) txn->_;

    fd_rawtxn_b_t raw_txn = { .raw = txn->payload, .txn_sz = (ushort)txn->payload_sz };

    int err = fd_execute_txn_prepare_start( slot_ctx, txn_ctx, txn_descriptor, &raw_txn );
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

  fd_exec_txn_ctx_t *          txn_ctx   = task_info->txn_ctx;

  fd_funk_txn_t * parent_txn = txn_ctx->slot_ctx->funk_txn;
  txn_ctx->funk_txn          = parent_txn;
  fd_executor_setup_borrowed_accounts_for_txn( txn_ctx );

  int err;

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/sdk/src/transaction/sanitized.rs#L263-L275
     TODO: Agave's precompile verification is done at the slot level, before batching and executing transactions. This logic should probably
     be moved in the future. The Agave call heirarchy looks something like this:
            process_single_slot
                   v
            confirm_full_slot
                   v
            confirm_slot_entries --------->
                   v                      v
            verify_transaction      process_entries
                   v                      v
            verify_precompiles      process_batches
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
  err = fd_executor_verify_precompiles( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }

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
    task_info->exec_res = err;
    return;
  }

  /* `load_and_execute_sanitized_transactions()` -> `validate_fees()` -> `validate_transaction_fee_payer()`
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L236-L249 */
  err = fd_executor_validate_transaction_fee_payer( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res = err;
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L284-L296 */
  err = fd_executor_load_transaction_accounts( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
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
   handles txncache insertion and updates to the vote/stake cache. */

static int
fd_runtime_finalize_txn( fd_exec_slot_ctx_t *         slot_ctx,
                         fd_capture_ctx_t *           capture_ctx,
                         fd_execute_txn_task_info_t * task_info ) {

  fd_exec_txn_ctx_t * txn_ctx      = task_info->txn_ctx;
  int                 exec_txn_err = task_info->exec_res;

  /* Store transaction info including logs */
  fd_runtime_finalize_txns_update_blockstore_meta( slot_ctx, task_info, 1UL );

  /* For ledgers that contain txn status, decode and write out for solcap */
  if( capture_ctx != NULL && capture_ctx->capture && capture_ctx->capture_txns ) {
    // TODO: probably need to get rid of this lock or special case it to not use funk's lock.
    fd_funk_start_write( slot_ctx->acc_mgr->funk );
    fd_runtime_write_transaction_status( capture_ctx, slot_ctx, txn_ctx, exec_txn_err );
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
  }

  if( slot_ctx->status_cache ) {
    fd_txncache_insert_t * status_insert = fd_scratch_alloc( alignof(fd_txncache_insert_t), sizeof(fd_txncache_insert_t) );
    uchar *                results       = fd_scratch_alloc( alignof(uchar), sizeof(uchar) );

    results[0] = exec_txn_err == 0 ? 1 : 0;
    fd_txncache_insert_t * curr_insert = &status_insert[0];
    curr_insert->blockhash = ((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->recent_blockhash_off);
    curr_insert->slot = slot_ctx->slot_bank.slot;
    fd_hash_t * hash = &txn_ctx->blake_txn_msg_hash;
    curr_insert->txnhash = hash->uc;
    curr_insert->result = &results[0];
    if( !fd_txncache_insert_batch( slot_ctx->status_cache, status_insert, 1UL ) ) {
      FD_LOG_DEBUG(("Status cache is full, this should not be possible"));
    }
  }

  if( FD_UNLIKELY( exec_txn_err ) ) {

    /* Save the fee_payer. Everything but the fee balance should be reset.
       TODO: an optimization here could be to use a dirty flag in the
       borrowed account. If the borrowed account data has been changed in
       any way, then the full account can be rolled back as it is done now.
       However, most of the time the account data is not changed, and only
       the lamport balance has to change. */
    fd_borrowed_account_t * borrowed_account = fd_borrowed_account_init( &txn_ctx->borrowed_accounts[0] );

    fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, &txn_ctx->accounts[0], borrowed_account );
    memcpy( borrowed_account->pubkey->key, &txn_ctx->accounts[0], sizeof(fd_pubkey_t) );

    void * borrowed_account_data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );
    fd_borrowed_account_make_modifiable( borrowed_account, borrowed_account_data );
    borrowed_account->meta->info.lamports -= (txn_ctx->execution_fee + txn_ctx->priority_fee);

    fd_acc_mgr_save_non_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, &txn_ctx->borrowed_accounts[0] );

    for( ulong i=1UL; i<txn_ctx->accounts_cnt; i++ ) {
      if( txn_ctx->is_nonce_accounts[i] ) {
        FD_BASE58_ENCODE_32_BYTES(txn_ctx->borrowed_accounts[i].pubkey->key, pkey_str);
        FD_LOG_WARNING(("%s is a nonce account on a failed transaction", pkey_str));

        if( FD_LIKELY( txn_ctx->adv_nonce_accounts[i] ) ) {
          fd_acc_mgr_save_non_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, &txn_ctx->borrowed_accounts[ i ] );
        } else {
          fd_acc_mgr_save_non_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, &txn_ctx->rollback_nonce_account[ 0 ] );
        }
      }
    }
  } else {

    int dirty_vote_acc  = txn_ctx->dirty_vote_acc;
    int dirty_stake_acc = txn_ctx->dirty_stake_acc;

    for( ulong i=0UL; i<txn_ctx->accounts_cnt; i++ ) {
      /* We are only interested in saving writable accounts and the fee
         payer account. */
      if( !fd_txn_account_is_writable_idx( txn_ctx, (int)i ) || i!=FD_FEE_PAYER_TXN_IDX ) {
        continue;
      }

      fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

      if( dirty_vote_acc && 0==memcmp( acc_rec->const_meta->info.owner, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
        /* lock for inserting/modifying vote accounts in slot ctx. */
        fd_funk_start_write( slot_ctx->acc_mgr->funk );
        fd_vote_store_account( slot_ctx, acc_rec, txn_ctx->spad );
        FD_SPAD_FRAME_BEGIN( txn_ctx->spad ) {
          fd_vote_state_versioned_t vsv[1];
          fd_bincode_decode_ctx_t decode_vsv =
            { .data    = acc_rec->const_data,
              .dataend = acc_rec->const_data + acc_rec->const_meta->dlen,
              .valloc  = fd_spad_virtual( txn_ctx->spad ) };

          int err = fd_vote_state_versioned_decode( vsv, &decode_vsv );
          if( err ) break; /* out of scratch scope */

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

          fd_valloc_t valloc = fd_spad_virtual( txn_ctx->spad );
          fd_vote_record_timestamp_vote_with_slot( slot_ctx, acc_rec->pubkey, ts->timestamp, ts->slot, valloc );
        } FD_SPAD_FRAME_END;
        fd_funk_end_write( slot_ctx->acc_mgr->funk );
      }

      if( dirty_stake_acc && 0==memcmp( acc_rec->const_meta->info.owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) {
        // TODO: does this correctly handle stake account close?
        fd_funk_start_write( slot_ctx->acc_mgr->funk );
        fd_store_stake_delegation( slot_ctx, acc_rec );
        fd_funk_end_write( slot_ctx->acc_mgr->funk );
      }

      fd_acc_mgr_save_non_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, &txn_ctx->borrowed_accounts[i] );
    }
  }

  FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->signature_cnt, txn_ctx->txn_descriptor->signature_cnt );

  return 0;
}

/* fd_runtime_prepare_execute_finalize_txn is responsible for processing the 
   entire transaction end-to-end. */

static int
fd_runtime_prepare_execute_finalize_txn( fd_exec_slot_ctx_t *         slot_ctx,
                                         fd_spad_t *                  spad,
                                         fd_capture_ctx_t *           capture_ctx,
                                         fd_txn_p_t *                 txn,
                                         fd_execute_txn_task_info_t * task_info ) {
  FD_SPAD_FRAME_BEGIN( spad ) {
  FD_SCRATCH_SCOPE_BEGIN {

  int res = 0;

  task_info->txn_ctx              = fd_valloc_malloc( fd_scratch_virtual(), FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
  fd_exec_txn_ctx_t * txn_ctx     = task_info->txn_ctx;
  task_info->exec_res             = -1;
  task_info->txn                  = txn;
  fd_txn_t const * txn_descriptor = (fd_txn_t const *) txn->_;

  task_info->txn_ctx->spad = spad;

  fd_rawtxn_b_t raw_txn = { .raw = txn->payload, .txn_sz = (ushort)txn->payload_sz };

  res = fd_execute_txn_prepare_start( slot_ctx, txn_ctx, txn_descriptor, &raw_txn );
  if( FD_UNLIKELY( res ) ) {
    txn->flags = 0U;
    return -1;
  }

  if( FD_UNLIKELY( fd_executor_txn_verify( txn_ctx )!=0 ) ) {
    FD_LOG_WARNING(( "sigverify failed: %s", FD_BASE58_ENC_64_ALLOCA( (uchar *)txn_ctx->_txn_raw->raw+txn_ctx->txn_descriptor->signature_off ) ));
    task_info->txn->flags = 0U;
    task_info->exec_res   = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
  }

  fd_runtime_pre_execute_check( task_info );
  if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    res  = task_info->exec_res;
    return -1;
  }

  /* Execute */
  task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  task_info->exec_res = fd_execute_txn( task_info->txn_ctx );

  if( task_info->exec_res==0 ) {
    fd_txn_reclaim_accounts( task_info->txn_ctx );
  }

  FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->slot_bank.collected_execution_fees, task_info->txn_ctx->execution_fee );
  FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->slot_bank.collected_priority_fees, task_info->txn_ctx->priority_fee );
  FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->slot_bank.collected_rent, task_info->txn_ctx->collected_rent );

  fd_runtime_finalize_txn( slot_ctx, capture_ctx, task_info );

  return res;

  } FD_SCRATCH_SCOPE_END;
  } FD_SPAD_FRAME_END;
}

/* fd_runtime_process_txns is the entrypoint for processing a batch of txns. */

int
fd_runtime_process_txns( fd_exec_slot_ctx_t * slot_ctx,
                         fd_spad_t *          spad,
                         fd_capture_ctx_t *   capture_ctx,
                         fd_txn_p_t *         txns,
                         ulong                txn_cnt ) {

  FD_SCRATCH_SCOPE_BEGIN {

    fd_execute_txn_task_info_t * task_infos = fd_scratch_alloc( 8, txn_cnt * sizeof(fd_execute_txn_task_info_t));

    for( ulong i=0UL; i<txn_cnt; i++ ) {
      txns[i].flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    }

    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_runtime_prepare_execute_finalize_txn( slot_ctx, spad, capture_ctx, &txns[i], &task_infos[i] );
    }

    FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->slot_bank.transaction_count, txn_cnt );

    return 0;
  } FD_SCRATCH_SCOPE_END;

}

/* fd_runtime_execute_txn_task is a tpool wrapper around transaction execution. */

static void FD_FN_UNUSED
fd_runtime_execute_txn_task( void * tpool,
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

  fd_execute_txn_task_info_t * task_info = (fd_execute_txn_task_info_t *)tpool + m0;

  if( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) {
    task_info->exec_res = -1;
    return;
  }

  task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  task_info->exec_res    = fd_execute_txn( task_info->txn_ctx );

  if( task_info->exec_res != 0 ) {
    return;
  }
  fd_txn_reclaim_accounts( task_info->txn_ctx );
}

/* fd_txn_sigverify_task and fd_txn_pre_execute_checks_task are responisble
   for the bulk of the pre-transaction execution checks in the runtime.
   They aim to preserve the ordering present in the Agave client to match
   parity in terms of error codes. Sigverify is kept seperate from the rest
   of the transaction checks for fuzzing convenience.

   For reference this is the general code path which contains all relevant
   pre-transactions checks in the v2.0.x Agave client from upstream
   to downstream is as follows:

   confirm_slot_entries() which calls verify_ticks() and
   verify_transaction(). verify_transaction() calls verify_and_hash_message()
   and verify_precompiles() which parallels fd_executor_txn_verify() and
   fd_executor_verify_precompiles().

   process_entries() contains a duplicate account check which is part of
   agave account lock acquiring. This is checked inline in
   fd_txn_pre_execute_checks_task().

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

static void FD_FN_UNUSED
fd_txn_sigverify_task( void *tpool,
                                       ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                                       void *args FD_PARAM_UNUSED,
                                       void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                                       ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                                       ulong m0, ulong m1 FD_PARAM_UNUSED,
                                       ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_execute_txn_task_info_t * task_info = (fd_execute_txn_task_info_t *)tpool + m0;

  /* the txn failed sanitize sometime earlier */
  if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    return;
  }

  fd_exec_txn_ctx_t * txn_ctx = task_info->txn_ctx;
  if( FD_UNLIKELY( fd_executor_txn_verify( txn_ctx )!=0 ) ) {
    FD_LOG_WARNING(("sigverify failed: %s", FD_BASE58_ENC_64_ALLOCA( (uchar *)txn_ctx->_txn_raw->raw+txn_ctx->txn_descriptor->signature_off ) ));
    task_info->txn->flags = 0U;
    task_info->exec_res   = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
  }

}

static void FD_FN_UNUSED
fd_txn_prep_and_exec_task( void  *tpool,
                           ulong t0 FD_PARAM_UNUSED,      ulong t1 FD_PARAM_UNUSED,
                           void  *args FD_PARAM_UNUSED,
                           void  *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                           ulong l0 FD_PARAM_UNUSED,      ulong l1 FD_PARAM_UNUSED,
                           ulong m0,                      ulong m1 FD_PARAM_UNUSED,
                           ulong n0 FD_PARAM_UNUSED,      ulong n1 FD_PARAM_UNUSED ) {

  fd_execute_txn_task_info_t * task_info = (fd_execute_txn_task_info_t *)tpool + m0;
  fd_exec_slot_ctx_t * slot_ctx = (fd_exec_slot_ctx_t *)args;
  // fd_capture_ctx_t * capture_ctx = (fd_capture_ctx_t *)reduce;

  /* It is important to note that there is currently a 1-1 mapping between the
     tiles and tpool threads at the time of this comment. Eventually, this will
     change and the transaction context's spad will not be queried by tile
     index as every tile will correspond to one CPU core. */
  ulong tile_idx = fd_tile_idx();
  task_info->txn_ctx->spad = task_info->spads[ tile_idx ];
  if( FD_UNLIKELY( !task_info->txn_ctx->spad ) ) {
    FD_LOG_ERR(("spad is NULL"));
  }

  fd_runtime_pre_execute_check( task_info );

  /* Transaction sanitization is complete at this point. Now finish account
    setup, execute the transaction, and reclaim dead accounts. */
  if( FD_LIKELY( !task_info->exec_res ) ) {
    task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
    task_info->exec_res    = fd_execute_txn( task_info->txn_ctx );
    fd_txn_reclaim_accounts( task_info->txn_ctx );
  }

  FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->slot_bank.collected_execution_fees, task_info->txn_ctx->execution_fee );
  FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->slot_bank.collected_priority_fees, task_info->txn_ctx->priority_fee );
  FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->slot_bank.collected_rent, task_info->txn_ctx->collected_rent );

  // fd_runtime_finalize_txn( slot_ctx, capture_ctx, task_info );

}

/* This task could be combined with the rest of the transaction checks that
   exist in fd_runtime_prepare_txns_phase2_tpool, but creates a lot more
   complexity to make the transaction fuzzer work. */
static int
fd_runtime_verify_txn_signatures_tpool( fd_execute_txn_task_info_t * task_info,
                                        ulong txn_cnt,
                                        fd_tpool_t * tpool ) {
  int res = 0;
  fd_tpool_exec_all_rrobin( tpool, 0, fd_tpool_worker_cnt( tpool ), fd_txn_sigverify_task, task_info, NULL, NULL, 1, 0, txn_cnt );
  for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
    if( FD_UNLIKELY( !( task_info[txn_idx].txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
      task_info->exec_res = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
      res |= FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
      break;
    }
  }
  return res;
}

/* This setup phase sets up the borrowed accounts in each transaction and
   performs a series of checks on each of the transactions. */
int
fd_runtime_prep_and_exec_txns_tpool( fd_exec_slot_ctx_t *         slot_ctx,
                                     fd_execute_txn_task_info_t * task_info,
                                     ulong                        txn_cnt,
                                     fd_tpool_t *                 tpool ) {
  int res = 0;
  FD_SCRATCH_SCOPE_BEGIN {

    fd_tpool_exec_all_rrobin( tpool, 0, fd_tpool_worker_cnt( tpool ), fd_txn_prep_and_exec_task, task_info, slot_ctx, task_info->txn_ctx->capture_ctx, 1, 0, txn_cnt );

    for( ulong txn_idx=0UL; txn_idx<txn_cnt; txn_idx++ ) {
      if( FD_UNLIKELY( !( task_info[txn_idx].txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
        res |= task_info[txn_idx].exec_res;
        continue;
      }
    }

  } FD_SCRATCH_SCOPE_END;
  return res;
}

/* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/accounts-db/src/accounts.rs#L700 */
/* fd_runtime_finalize_txns_tpool is the tpool version of fd_runtime_finalize_txn. */

static int
fd_runtime_finalize_txns_tpool( fd_exec_slot_ctx_t *         slot_ctx,
                                fd_capture_ctx_t *           capture_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong                        txn_cnt,
                                fd_tpool_t *                 tpool ) {
  FD_SCRATCH_SCOPE_BEGIN {

    /* Store transaction metadata, including logs */
    fd_runtime_finalize_txns_update_blockstore_meta( slot_ctx, task_info, txn_cnt );

    fd_txncache_insert_t * status_insert  = NULL;
    uchar *                results        = NULL;
    ulong                  num_cache_txns = 0UL;


    if( FD_LIKELY( slot_ctx->status_cache ) ) {
      status_insert = fd_scratch_alloc( alignof(fd_txncache_insert_t), txn_cnt * sizeof(fd_txncache_insert_t) );
      results       = fd_scratch_alloc( alignof(uchar), txn_cnt * sizeof(uchar) );
    }

    fd_borrowed_account_t * * accounts_to_save         = fd_scratch_alloc( 8UL, MAX_TX_ACCOUNT_LOCKS * txn_cnt * sizeof(fd_borrowed_account_t *) );
    ulong                     acc_idx                  = 0UL;
    ulong                     nonvote_txn_count        = 0UL;
    ulong                     failed_txn_count         = 0UL;
    ulong                     nonvote_failed_txn_count = 0UL;
    ulong                     compute_units_used       = 0UL;

    for( ulong txn_idx=0UL; txn_idx<txn_cnt; txn_idx++ ) {
      /* Transaction was skipped due to preparation failure. */
      if( FD_UNLIKELY( !( task_info[txn_idx].txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) ) {
        continue;
      }
      fd_exec_txn_ctx_t * txn_ctx      = task_info[txn_idx].txn_ctx;
      int                 exec_txn_err = task_info[txn_idx].exec_res;

      /* For ledgers that contain txn status, decode and write out for solcap */
      if( FD_UNLIKELY( capture_ctx != NULL && capture_ctx->capture && capture_ctx->capture_txns ) ) {
        fd_runtime_write_transaction_status( capture_ctx, slot_ctx, txn_ctx, exec_txn_err );
      }

      slot_ctx->signature_cnt += txn_ctx->txn_descriptor->signature_cnt;

      int is_vote = fd_txn_is_simple_vote_transaction( txn_ctx->txn_descriptor,
                                                       txn_ctx->_txn_raw->raw,
                                                       fd_solana_vote_program_id.key );
      if( is_vote ) {
        if( FD_UNLIKELY( exec_txn_err ) ) {
          failed_txn_count++;
        }
      } else {
        nonvote_txn_count++;
        if( FD_UNLIKELY( exec_txn_err ) ) {
          nonvote_failed_txn_count++;
          failed_txn_count++;
        }
      }
      compute_units_used += txn_ctx->compute_unit_limit - txn_ctx->compute_meter;

      if( FD_LIKELY( slot_ctx->status_cache ) ) {
        results[num_cache_txns]            = exec_txn_err == 0 ? 1 : 0;
        fd_txncache_insert_t * curr_insert = &status_insert[num_cache_txns];
        curr_insert->blockhash             = ((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->recent_blockhash_off);
        curr_insert->slot                  = slot_ctx->slot_bank.slot;
        fd_hash_t *            hash        = &txn_ctx->blake_txn_msg_hash;
        curr_insert->txnhash               = hash->uc;
        curr_insert->result                = &results[num_cache_txns];
        num_cache_txns++;
      }

      if( FD_UNLIKELY( exec_txn_err ) ) {
        /* Save the fee_payer. Everything but the fee balance should be reset.
           TODO: an optimization here could be to use a dirty flag in the
           borrowed account. If the borrowed account data has been changed in
           any way, then the full account can be rolled back as it is done now.
           However, most of the time the account data is not changed, and only
           the lamport balance has to change. */
        fd_borrowed_account_t * borrowed_account = fd_borrowed_account_init( &txn_ctx->borrowed_accounts[ FD_FEE_PAYER_TXN_IDX ] );

        fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, &txn_ctx->accounts[ FD_FEE_PAYER_TXN_IDX ], borrowed_account );
        memcpy( borrowed_account->pubkey->key, &txn_ctx->accounts[ FD_FEE_PAYER_TXN_IDX ], sizeof(fd_pubkey_t) );

        void * borrowed_account_data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );
        fd_borrowed_account_make_modifiable( borrowed_account, borrowed_account_data );
        borrowed_account->meta->info.lamports -= (txn_ctx->execution_fee + txn_ctx->priority_fee);

        accounts_to_save[acc_idx++] = &txn_ctx->borrowed_accounts[ FD_FEE_PAYER_TXN_IDX ];
        for( ulong i=1UL; i<txn_ctx->accounts_cnt; i++ ) {
          if( txn_ctx->is_nonce_accounts[i] ) {
            FD_BASE58_ENCODE_32_BYTES(txn_ctx->borrowed_accounts[i].pubkey->key, pkey_str);
            FD_LOG_WARNING(("%s is a nonce account on a failed transaction", pkey_str));
            if( FD_LIKELY( txn_ctx->adv_nonce_accounts[i] ) ) {
              accounts_to_save[acc_idx++] = &txn_ctx->borrowed_accounts[ i ];
            } else {
              accounts_to_save[acc_idx++] = &txn_ctx->rollback_nonce_account[ 0 ];
            }
            break;
          }
        }
      } else {
        int dirty_vote_acc  = txn_ctx->dirty_vote_acc;
        int dirty_stake_acc = txn_ctx->dirty_stake_acc;

        for( ulong i=0UL; i<txn_ctx->accounts_cnt; i++ ) {
          /* We are only interested in saving writable accounts and the fee
             payer account. */
          if( !fd_txn_account_is_writable_idx( txn_ctx, (int)i ) && i!=FD_FEE_PAYER_TXN_IDX ) {
            continue;
          }

          fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

          if( dirty_vote_acc && !memcmp( acc_rec->const_meta->info.owner, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
            fd_vote_store_account( slot_ctx, acc_rec, txn_ctx->spad );
            FD_SPAD_FRAME_BEGIN( txn_ctx->spad ) {
              fd_vote_state_versioned_t vsv[1];
              fd_bincode_decode_ctx_t decode_vsv =
                { .data    = acc_rec->const_data,
                  .dataend = acc_rec->const_data + acc_rec->const_meta->dlen,
                  .valloc  = fd_spad_virtual( txn_ctx->spad ) };

              int err = fd_vote_state_versioned_decode( vsv, &decode_vsv );
              if( err ) break; /* out of scratch scope */

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

              fd_valloc_t valloc = fd_spad_virtual( txn_ctx->spad );
              fd_vote_record_timestamp_vote_with_slot( slot_ctx, acc_rec->pubkey, ts->timestamp, ts->slot, valloc );
            } FD_SPAD_FRAME_END;
          }

          if( dirty_stake_acc && !memcmp( acc_rec->const_meta->info.owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) {
            // TODO: does this correctly handle stake account close?
            fd_store_stake_delegation( slot_ctx, acc_rec );
          }

          accounts_to_save[acc_idx++] = acc_rec;
        }
      }
    }

    /* Accumulate transaction counters */

    FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->nonvote_txn_count, nonvote_txn_count );
    FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->failed_txn_count, failed_txn_count );
    FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->nonvote_failed_txn_count, nonvote_failed_txn_count );
    FD_ATOMIC_FETCH_AND_ADD( &slot_ctx->total_compute_units_used, compute_units_used );

    /* All the accounts have been accumulated and can be saved */

    // TODO: we need to use the txn ctx funk_txn, valloc, etc.
    int err = fd_acc_mgr_save_many_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, accounts_to_save, acc_idx, tpool );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to save edits to accounts" ));
      return -1;
    }

    if( FD_LIKELY( slot_ctx->status_cache ) ) {
      if( FD_UNLIKELY( !fd_txncache_insert_batch( slot_ctx->status_cache, status_insert, num_cache_txns ) ) ) {
        FD_LOG_WARNING(("Status cache is full, this should not be possible"));
      }
    }

  return 0;
  } FD_SCRATCH_SCOPE_END;
}

struct fd_pubkey_map_node {
  ulong       pubkey;
  uint        hash;
};
typedef struct fd_pubkey_map_node fd_pubkey_map_node_t;

#define MAP_NAME                fd_pubkey_map
#define MAP_T                   fd_pubkey_map_node_t
#define MAP_KEY                 pubkey
#define MAP_KEY_T               ulong
#define MAP_KEY_NULL            0
#define MAP_KEY_INVAL( k )      k==0
#define MAP_KEY_EQUAL( k0, k1 ) k0==k1
#define MAP_KEY_EQUAL_IS_SLOW   1
#define MAP_KEY_HASH( key )     ( (uint)key )
#define MAP_MEMOIZE             1
#include "../../util/tmpl/fd_map_dynamic.c"

/* return 0 on failure, 1 if exists, 2 if inserted */
static uint
fd_pubkey_map_insert_if_not_in( fd_pubkey_map_node_t * map,
                                fd_pubkey_t            pubkey ) {
  /* Check if entry already exists */
  ulong h = fd_hash( 0UL, &pubkey, sizeof( fd_pubkey_t ) );
  fd_pubkey_map_node_t * entry = fd_pubkey_map_query( map, h, NULL );
  if( entry )
    return 1;

  /* Insert new */
  entry = fd_pubkey_map_insert( map, h );
  if( FD_UNLIKELY( !entry ) ) return 0;  /* check for internal map collision */

  return 2;
}

/* fd_runtime_generate_wave is responsible for scheduling parallel transactions */

static void
fd_runtime_generate_wave( fd_execute_txn_task_info_t * task_infos,
                          ulong *                      prev_incomplete_txn_idxs,
                          ulong                        prev_incomplete_txn_idxs_cnt,
                          ulong                        prev_accounts_cnt,
                          ulong *                      incomplete_txn_idxs,
                          ulong *                      _incomplete_txn_idxs_cnt,
                          ulong *                      _incomplete_accounts_cnt,
                          fd_execute_txn_task_info_t * wave_task_infos,
                          ulong *                      _wave_task_infos_cnt ) {
  FD_SCRATCH_SCOPE_BEGIN {
    int                    lg_slot_cnt  = fd_ulong_find_msb( prev_accounts_cnt ) + 1;
    void *                 read_map_mem = fd_scratch_alloc( fd_pubkey_map_align(), fd_pubkey_map_footprint( lg_slot_cnt ) );
    fd_pubkey_map_node_t * read_map     = fd_pubkey_map_join( fd_pubkey_map_new( read_map_mem, lg_slot_cnt ) );

    void *                 write_map_mem = fd_scratch_alloc( fd_pubkey_map_align(), fd_pubkey_map_footprint( lg_slot_cnt ) );
    fd_pubkey_map_node_t * write_map     = fd_pubkey_map_join( fd_pubkey_map_new( write_map_mem, lg_slot_cnt ) );

    ulong incomplete_txn_idxs_cnt = 0UL;
    ulong wave_task_infos_cnt     = 0UL;
    ulong accounts_in_wave        = 0UL;
    for( ulong i=0UL; i<prev_incomplete_txn_idxs_cnt; i++ ) {
      ulong txn_idx           = prev_incomplete_txn_idxs[i];
      uint  is_executable_now = 1;
      fd_execute_txn_task_info_t * task_info = &task_infos[txn_idx];

      for( ulong j=0UL; j<task_info->txn_ctx->accounts_cnt; j++ ) {
        ulong h = fd_hash( 0UL, &task_info->txn_ctx->accounts[j], sizeof( fd_pubkey_t ) );
        if( fd_pubkey_map_query( write_map, h, NULL ) != NULL ) {
          is_executable_now = 0;
          break;
        }
        if( fd_txn_account_is_writable_idx( task_info->txn_ctx, (int)j ) ) {
          if( fd_pubkey_map_query( read_map, h, NULL ) != NULL ) {
            is_executable_now = 0;
            break;
          }
        }
      }

      if( !is_executable_now ) {
        incomplete_txn_idxs[incomplete_txn_idxs_cnt++] = txn_idx;
      } else {
        wave_task_infos[wave_task_infos_cnt++] = *task_info;
      }

      /* Include txn in wave */
      for( ulong j=0UL; j<task_info->txn_ctx->accounts_cnt; j++ ) {
        if( fd_txn_account_is_writable_idx( task_info->txn_ctx, (int)j ) ) {
          uint ins_res = fd_pubkey_map_insert_if_not_in( write_map, task_info->txn_ctx->accounts[j] );
          if( ins_res==2U ) {
            accounts_in_wave++;
          }
        } else {
          uint ins_res = fd_pubkey_map_insert_if_not_in( read_map, task_info->txn_ctx->accounts[j] );
          if( ins_res==2UL ) {
            accounts_in_wave++;
          }
        }
      }

    }

    *_incomplete_txn_idxs_cnt = incomplete_txn_idxs_cnt;
    *_incomplete_accounts_cnt = prev_accounts_cnt - accounts_in_wave;
    *_wave_task_infos_cnt     = wave_task_infos_cnt;
  } FD_SCRATCH_SCOPE_END;
}

/* NOTE: Don't mess with this call without updating the transaction fuzzing harness appropriately!
   fd_exec_instr_test.c:_txn_context_create_and_exec.
   
   This function is the tpool version of fd_runtime_process_txn. */
int
fd_runtime_process_txns_in_waves_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                        fd_capture_ctx_t *   capture_ctx,
                                        fd_txn_p_t *         all_txns,
                                        ulong                total_txn_cnt,
                                        fd_tpool_t *         tpool,
                                        fd_spad_t * *        spads,
                                        ulong                spad_cnt ) {
    int dump_txn = capture_ctx && slot_ctx->slot_bank.slot >= capture_ctx->dump_proto_start_slot && capture_ctx->dump_txn_to_pb;

    /* As a note, the batch size of 128 is a relatively arbitrary number. The
       notion of batching here will change as the transaction execution model
       changes with respect to transaction execution. */
    #define BATCH_SIZE (128UL)
    ulong batch_size = fd_ulong_min( fd_tile_cnt(), BATCH_SIZE );

    for( ulong i=0UL; i<total_txn_cnt; i++ ) {
      all_txns[i].flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    }

    ulong num_batches = total_txn_cnt/batch_size;
    ulong rem         = total_txn_cnt%batch_size;
    num_batches      += rem ? 1UL : 0UL;

    int res = 0;
    for( ulong i=0UL; i<num_batches; i++ ) {
      FD_SCRATCH_SCOPE_BEGIN {

      fd_txn_p_t * txns    = all_txns + (batch_size * i);
      ulong        txn_cnt = ((i+1UL==num_batches) && rem) ? rem : batch_size;

      fd_execute_txn_task_info_t * task_infos          = fd_scratch_alloc( 8UL, txn_cnt * sizeof(fd_execute_txn_task_info_t) );
      fd_execute_txn_task_info_t * wave_task_infos     = fd_scratch_alloc( 8UL, txn_cnt * sizeof(fd_execute_txn_task_info_t) );
      ulong                        wave_task_infos_cnt = 0UL;

      res = fd_runtime_prepare_txns_start( slot_ctx, task_infos, txns, txn_cnt );
      if( res != 0 ) {
        FD_LOG_DEBUG(("Fail prep 1"));
      }

      ulong * incomplete_txn_idxs     = fd_scratch_alloc( 8UL, txn_cnt * sizeof(ulong) );
      ulong   incomplete_txn_idxs_cnt = 0UL;
      ulong   incomplete_accounts_cnt = 0UL;

      /* Setup sanitized txns as incomplete and set the capture context */
      for( ulong i=0UL; i<txn_cnt; i++ ) {
        if( FD_UNLIKELY( !( task_infos[i].txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
          continue;
        }
        incomplete_txn_idxs[incomplete_txn_idxs_cnt++] = i;
        incomplete_accounts_cnt                       += task_infos[i].txn_ctx->accounts_cnt;
        task_infos[i].txn_ctx->capture_ctx             = capture_ctx;
      }

      ulong * next_incomplete_txn_idxs     = fd_scratch_alloc( 8UL, txn_cnt * sizeof(ulong) );
      ulong   next_incomplete_txn_idxs_cnt = 0UL;
      ulong   next_incomplete_accounts_cnt = 0UL;

      while( incomplete_txn_idxs_cnt > 0 ) {
        fd_runtime_generate_wave( task_infos, incomplete_txn_idxs, incomplete_txn_idxs_cnt, incomplete_accounts_cnt,
                                  next_incomplete_txn_idxs, &next_incomplete_txn_idxs_cnt, &next_incomplete_accounts_cnt,
                                  wave_task_infos, &wave_task_infos_cnt );
        ulong * temp_incomplete_txn_idxs = incomplete_txn_idxs;
        incomplete_txn_idxs              = next_incomplete_txn_idxs;
        next_incomplete_txn_idxs         = temp_incomplete_txn_idxs;
        incomplete_txn_idxs_cnt          = next_incomplete_txn_idxs_cnt;

        for( ulong i=0UL; i<spad_cnt; i++ ) {
          /* Borrowed accounts are allocated during prep and need to
             persist till the end of finalize. This initial frame will
             be holding that. */
          fd_spad_push( spads[ i ] );
        }

        /* Assign out spads to the transaction contexts */
        for( ulong i=0UL; i<wave_task_infos_cnt; i++ ) {
          wave_task_infos[i].spads = spads;
        }

        // Dump txns in waves
        if( dump_txn ) {
          for( ulong i = 0; i < wave_task_infos_cnt; ++i ) {
            /* Manual push/pop on the spad within the callee. */
            fd_dump_txn_to_protobuf( wave_task_infos[i].txn_ctx, spads[0] );
          }
        }

        res |= fd_runtime_verify_txn_signatures_tpool( wave_task_infos, wave_task_infos_cnt, tpool );
        if( FD_UNLIKELY( res ) ) {
          FD_LOG_WARNING(( "Fail signature verification" ));
        }

        res |= fd_runtime_prep_and_exec_txns_tpool( slot_ctx, wave_task_infos, wave_task_infos_cnt, tpool );
        if( res != 0 ) {
          FD_LOG_DEBUG(( "Fail prep and exec" ));
        }

        int finalize_res = fd_runtime_finalize_txns_tpool( slot_ctx, capture_ctx, wave_task_infos, wave_task_infos_cnt, tpool );
        if( finalize_res != 0 ) {
          FD_LOG_ERR(( "Fail finalize" ));
        }

        for( ulong i=0UL; i<spad_cnt; i++ ) {
          /* The first frame, which holds borrowed accounts, can be
             pretty big, and there are additional dynamic allocations
             during finalize. */
          if( FD_UNLIKELY( fd_spad_verify( spads[ i ] ) ) ) {
            FD_LOG_ERR(( "spad corrupted or overflown" ));
          }
          /* We indiscriminately pushed a frame to every spad.
             So it should be safe to indiscriminately pop here. */
          fd_spad_pop( spads[ i ] );
          if( FD_UNLIKELY( fd_spad_frame_used( spads[ i ] )!=0 ) ) {
            FD_LOG_ERR(( "stray spad frame frame_used=%lu", fd_spad_frame_used( spads[ i ] ) ));
          }
        }

      }
      } FD_SCRATCH_SCOPE_END;
    }
    slot_ctx->slot_bank.transaction_count += total_txn_cnt;

    #undef BATCH_SIZE

    return res;
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
fd_update_stake_delegations( fd_exec_slot_ctx_t * slot_ctx, fd_epoch_info_t * temp_info ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    fd_stakes_t *     stakes     = &epoch_bank->stakes;

    // TODO: is this size correct if the same stake account is in both the slot and epoch cache? Is this possible?
    ulong stake_delegations_size = fd_delegation_pair_t_map_size(
      stakes->stake_delegations_pool, stakes->stake_delegations_root );
    stake_delegations_size += fd_stake_accounts_pair_t_map_size(
      slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );

    // Create a new epoch stake delegations cache, which will hold the union of the slot and epoch caches.
    fd_delegation_pair_t_mapnode_t * new_stake_root = NULL;
    fd_delegation_pair_t_mapnode_t * new_stake_pool = fd_delegation_pair_t_map_alloc( fd_scratch_virtual(), stake_delegations_size );

    for ( ulong idx = 0; idx < temp_info->infos_len; idx++ ) {
        // Fetch the delegation associated with this stake account
      fd_delegation_pair_t_mapnode_t * entry = fd_delegation_pair_t_map_acquire( new_stake_pool );
      fd_memcpy(&entry->elem.account, &temp_info->infos[idx].account, sizeof(fd_pubkey_t));
      fd_memcpy(&entry->elem.delegation, &temp_info->infos[idx].stake.delegation, sizeof(fd_delegation_t));
      fd_delegation_pair_t_map_insert( new_stake_pool, &new_stake_root, entry );
    }

    // Update the epoch bank vote_accounts with the latest values from the slot bank
    // FIXME: resize the vote_accounts_pool if necessary
    ulong total_epoch_stake = 0UL;
    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
        slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool,
          slot_ctx->slot_bank.vote_account_keys.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, n ) ) {

      // If the vote account is not in the epoch stakes cache, insert it
      fd_vote_accounts_pair_t_mapnode_t key;
      fd_memcpy( &key.elem.key, &n->elem.key, FD_PUBKEY_FOOTPRINT );
      fd_vote_accounts_pair_t_mapnode_t * epoch_cache_node = fd_vote_accounts_pair_t_map_find( stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root, &key );
      if( epoch_cache_node == NULL ) {
        epoch_cache_node = fd_vote_accounts_pair_t_map_acquire( stakes->vote_accounts.vote_accounts_pool );

        fd_memcpy(&epoch_cache_node->elem.key, &n->elem.key, sizeof(fd_pubkey_t));
        fd_memcpy(&epoch_cache_node->elem.stake, &n->elem.stake, sizeof(ulong));
        fd_memcpy(&epoch_cache_node->elem.value, &n->elem.value, sizeof(fd_solana_account_t));

        fd_vote_accounts_pair_t_map_insert( stakes->vote_accounts.vote_accounts_pool, &stakes->vote_accounts.vote_accounts_root, epoch_cache_node );
      } else {
        epoch_cache_node->elem.stake = n->elem.stake;
      }
      total_epoch_stake += epoch_cache_node->elem.stake;
    }
    slot_ctx->epoch_ctx->total_epoch_stake = total_epoch_stake;

    fd_bincode_destroy_ctx_t destroy_slot = { .valloc = slot_ctx->valloc };
    fd_vote_accounts_destroy( &slot_ctx->slot_bank.vote_account_keys, &destroy_slot );
    fd_stake_accounts_destroy(&slot_ctx->slot_bank.stake_account_keys, &destroy_slot );

    /* Release all nodes in tree.
       FIXME sweep pool and ignore tree nodes might is probably faster
       than recursive descent */
    fd_delegation_pair_t_map_release_tree( stakes->stake_delegations_pool, stakes->stake_delegations_root );
    stakes->stake_delegations_root = NULL;

    for( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum( new_stake_pool, new_stake_root ); n; n = fd_delegation_pair_t_map_successor( new_stake_pool, n ) ) {
      fd_delegation_pair_t_mapnode_t * e = fd_delegation_pair_t_map_acquire( stakes->stake_delegations_pool );
      if( FD_UNLIKELY( !e ) ) {
        FD_LOG_CRIT(( "Stake delegation map overflowed! (capacity=%lu)", fd_delegation_pair_t_map_max( stakes->stake_delegations_pool ) ));
      }
      fd_memcpy( &e->elem.account, &n->elem.account, sizeof(fd_pubkey_t));
      fd_memcpy( &e->elem.delegation, &n->elem.delegation, sizeof(fd_delegation_t));
      fd_delegation_pair_t_map_insert( stakes->stake_delegations_pool, &stakes->stake_delegations_root, e );
    }

    slot_ctx->slot_bank.stake_account_keys.stake_accounts_root = NULL;
    slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool = fd_stake_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000 );

    slot_ctx->slot_bank.vote_account_keys.vote_accounts_root = NULL;
    slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000 );
  } FD_SCRATCH_SCOPE_END;
}

/* Replace the stakes in T-2 (slot_ctx->slot_bank.epoch_stakes) by the stakes at T-1 (epoch_bank->next_epoch_stakes) */
static void 
fd_update_epoch_stakes( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_epoch_bank_t * epoch_bank = &slot_ctx->epoch_ctx->epoch_bank;

    /* Copy epoch_bank->next_epoch_stakes into slot_ctx->slot_bank.epoch_stakes */
    fd_vote_accounts_pair_t_map_release_tree(
      slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool,
      slot_ctx->slot_bank.epoch_stakes.vote_accounts_root );
    slot_ctx->slot_bank.epoch_stakes.vote_accounts_root = NULL;

    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
      epoch_bank->next_epoch_stakes.vote_accounts_pool,
      epoch_bank->next_epoch_stakes.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( epoch_bank->next_epoch_stakes.vote_accounts_pool, n ) ) {

      const fd_pubkey_t null_pubkey = {{ 0 }};
      if ( memcmp( &n->elem.key, &null_pubkey, FD_PUBKEY_FOOTPRINT ) == 0 ) {
        continue;
      }

      fd_vote_accounts_pair_t_mapnode_t * elem = fd_vote_accounts_pair_t_map_acquire(
        slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool );
      if ( FD_UNLIKELY(
          fd_vote_accounts_pair_t_map_free( slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool ) == 0 ) ) {
        FD_LOG_ERR(( "slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool full" ));
      }

      fd_memcpy( &elem->elem, &n->elem, sizeof(fd_vote_accounts_pair_t));
      fd_vote_accounts_pair_t_map_insert(
        slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool,
        &slot_ctx->slot_bank.epoch_stakes.vote_accounts_root,
        elem );
    }
  } FD_SCRATCH_SCOPE_END;
}

/* Copy epoch_bank->stakes.vote_accounts into epoch_bank->next_epoch_stakes. */
static void fd_update_next_epoch_stakes( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_epoch_bank_t * epoch_bank = &slot_ctx->epoch_ctx->epoch_bank;

    /* Copy epoch_ctx->epoch_bank->stakes.vote_accounts into epoch_bank->next_epoch_stakes */
    fd_vote_accounts_pair_t_map_release_tree(
      epoch_bank->next_epoch_stakes.vote_accounts_pool,
      epoch_bank->next_epoch_stakes.vote_accounts_root );

    epoch_bank->next_epoch_stakes.vote_accounts_pool = fd_exec_epoch_ctx_next_epoch_stakes_join( slot_ctx->epoch_ctx );
    epoch_bank->next_epoch_stakes.vote_accounts_root = NULL;

    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
      epoch_bank->stakes.vote_accounts.vote_accounts_pool,
      epoch_bank->stakes.vote_accounts.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( epoch_bank->stakes.vote_accounts.vote_accounts_pool, n ) ) {
      fd_vote_accounts_pair_t_mapnode_t * elem = fd_vote_accounts_pair_t_map_acquire( epoch_bank->next_epoch_stakes.vote_accounts_pool );
      fd_memcpy( &elem->elem, &n->elem, sizeof(fd_vote_accounts_pair_t));
      fd_vote_accounts_pair_t_map_insert( epoch_bank->next_epoch_stakes.vote_accounts_pool, &epoch_bank->next_epoch_stakes.vote_accounts_root, elem );
    }
  } FD_SCRATCH_SCOPE_END;
}

/* Mimics `bank.new_target_program_account()`. Assumes `out_rec` is a modifiable record.

   From the calling context, `out_rec` points to a native program record (e.g. Config, ALUT native programs).
   There should be enough space in `out_rec->data` to hold at least 36 bytes (the size of a BPF upgradeable
   program account) when calling this function. The native program account's owner is set to the BPF loader
   upgradeable program ID, and lamports are increased / deducted to contain the rent exempt minimum balance.

   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L79-L95 */
static int
fd_new_target_program_account( fd_exec_slot_ctx_t *    slot_ctx,
                               const fd_pubkey_t *     target_program_data_address,
                               fd_borrowed_account_t * out_rec ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.0/sdk/account/src/lib.rs#L471 */
  out_rec->meta->info.rent_epoch = 0UL;

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
  const fd_rent_t * rent = fd_sysvar_cache_rent( slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( rent==NULL ) ) {
    return -1;
  }

  out_rec->meta->info.lamports = fd_rent_exempt_minimum_balance( rent, SIZE_OF_PROGRAM );
  fd_bincode_encode_ctx_t ctx = {
    .data = out_rec->data,
    .dataend = out_rec->data + SIZE_OF_PROGRAM,
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L91-L9 */
  int err = fd_bpf_upgradeable_loader_state_encode( &state, &ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  fd_memcpy( out_rec->meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L93-L94 */
  out_rec->meta->info.executable = 1;
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* Mimics `bank.new_target_program_data_account()`. Assumes `new_target_program_data_account` is a modifiable record.
   `config_upgrade_authority_address` may be NULL.

   This function uses an existing buffer account `buffer_acc_rec` to set the program data account data for a core
   program BPF migration. Sets the lamports and data fields of `new_target_program_data_account` based on the
   ELF data length, and sets the owner to the BPF loader upgradeable program ID.

   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L97-L153 */
static int
fd_new_target_program_data_account( fd_exec_slot_ctx_t *    slot_ctx,
                                    fd_pubkey_t *           config_upgrade_authority_address,
                                    fd_borrowed_account_t * buffer_acc_rec,
                                    fd_borrowed_account_t * new_target_program_data_account ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L113-L116 */
  fd_bpf_upgradeable_loader_state_t state;
  fd_bincode_decode_ctx_t decode_ctx = {
    .data = buffer_acc_rec->const_data,
    .dataend = buffer_acc_rec->const_data + buffer_acc_rec->const_meta->dlen,
    .valloc = fd_scratch_virtual()
  };
  int err = fd_bpf_upgradeable_loader_state_decode( &state, &decode_ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_buffer( &state ) ) ) {
    return -1;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L118-L125 */
  if( config_upgrade_authority_address!=NULL ) {
    if( FD_UNLIKELY( state.inner.buffer.authority_address==NULL ||
                     memcmp( config_upgrade_authority_address, state.inner.buffer.authority_address, sizeof(fd_pubkey_t) ) ) ) {
      return -1;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L127-L132 */
  const fd_rent_t * rent = fd_sysvar_cache_rent( slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( rent==NULL ) ) {
    return -1;
  }

  const uchar * elf = buffer_acc_rec->const_data + BUFFER_METADATA_SIZE;
  ulong space = PROGRAMDATA_METADATA_SIZE - BUFFER_METADATA_SIZE + buffer_acc_rec->const_meta->dlen;
  ulong lamports = fd_rent_exempt_minimum_balance( rent, space );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L134-L137 */
  fd_bpf_upgradeable_loader_state_t programdata_metadata = {
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
    .inner = {
      .program_data = {
        .slot = slot_ctx->slot_bank.slot,
        .upgrade_authority_address = config_upgrade_authority_address
      }
    }
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L139-L144 */
  new_target_program_data_account->meta->info.lamports = lamports;
  fd_bincode_encode_ctx_t encode_ctx = {
    .data = new_target_program_data_account->data,
    .dataend = new_target_program_data_account->data + PROGRAMDATA_METADATA_SIZE,
  };
  err = fd_bpf_upgradeable_loader_state_encode( &programdata_metadata, &encode_ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  fd_memcpy( new_target_program_data_account->meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) );

  /* Copy the ELF data over
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L145 */
  fd_memcpy( new_target_program_data_account->data + PROGRAMDATA_METADATA_SIZE, elf, buffer_acc_rec->const_meta->dlen - BUFFER_METADATA_SIZE );

  return FD_RUNTIME_EXECUTE_SUCCESS;
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
                                const fd_pubkey_t *  builtin_program_id,
                                const fd_pubkey_t *  source_buffer_address,
                                uchar                stateless ) {
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
  FD_BORROWED_ACCOUNT_DECL( target_program_account );
  uchar program_exists = ( fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, builtin_program_id, target_program_account )==FD_ACC_MGR_SUCCESS );
  if( !stateless ) {
    /* The program account should exist.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L30-L33 */
    if( FD_UNLIKELY( !program_exists ) ) {
      FD_LOG_WARNING(( "Builtin program %s does not exist, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }

    /* The program account should be owned by the native loader.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L35-L38 */
    if( FD_UNLIKELY( memcmp( target_program_account->const_meta->info.owner, fd_solana_native_loader_id.uc, sizeof(fd_pubkey_t) ) ) ) {
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
  FD_BORROWED_ACCOUNT_DECL( program_data_account );
  if( FD_UNLIKELY( fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, target_program_data_address, program_data_account )==FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "Program data account %s already exists, skipping migration...", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L244

     Obtains a `SourceBuffer` account. There are two fields returned:
      - source.buffer_address: source_buffer_address
      - source.buffer_account: the existing buffer account */

  /* The buffer account should exist.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L26-L29 */
  FD_BORROWED_ACCOUNT_DECL( source_buffer_account );
  if( FD_UNLIKELY( fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, source_buffer_address, 0, 0UL, source_buffer_account )!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "Buffer account %s does not exist, skipping migration...", FD_BASE58_ENC_32_ALLOCA( source_buffer_address ) ));
    return;
  }

  /* The buffer account should be owned by the upgradeable loader.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L31-L34 */
  if( FD_UNLIKELY( memcmp( source_buffer_account->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_WARNING(( "Buffer account %s is not owned by the upgradeable loader, skipping migration...", FD_BASE58_ENC_32_ALLOCA( source_buffer_address ) ));
    return;
  }

  /* The buffer account should have the correct state. We already check the buffer account state in `fd_new_target_program_data_account`,
      so we can skip the checks here.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L37-L47 */

  /* This check is done a bit prematurely because we calculate the previous account state's lamports. We use 0 for starting lamports
     for stateless accounts because they don't yet exist.

     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L277-L280 */
  ulong lamports_to_burn = ( stateless ? 0UL : target_program_account->const_meta->info.lamports ) + source_buffer_account->const_meta->info.lamports;

  /* Start a funk write txn */
  fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
  fd_funk_txn_xid_t migration_xid = fd_funk_generate_xid();
  slot_ctx->funk_txn = fd_funk_txn_prepare( slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, &migration_xid, 0UL );

  /* Attempt serialization of program account. If the program is stateless, we want to create the account. Otherwise,
     we want a writable handle to modify the existing account.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L246-L249 */
  FD_BORROWED_ACCOUNT_DECL( new_target_program_account );
  err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, builtin_program_id, stateless, SIZE_OF_PROGRAM, new_target_program_account );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Builtin program ID %s does not exist", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }
  new_target_program_account->meta->dlen = SIZE_OF_PROGRAM;
  new_target_program_account->meta->slot = slot_ctx->slot_bank.slot;

  /* Create a new target program account. This modifies the existing record. */
  err = fd_new_target_program_account( slot_ctx, target_program_data_address, new_target_program_account );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write new program state to %s", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }

  /* Create a new target program data account. */
  ulong new_target_program_data_account_sz = PROGRAMDATA_METADATA_SIZE - BUFFER_METADATA_SIZE + source_buffer_account->const_meta->dlen;
  FD_BORROWED_ACCOUNT_DECL( new_target_program_data_account );
  err = fd_acc_mgr_modify( slot_ctx->acc_mgr,
                           slot_ctx->funk_txn,
                           target_program_data_address,
                           1,
                           new_target_program_data_account_sz,
                           new_target_program_data_account );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to create new program data account to %s", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    goto fail;
  }
  new_target_program_data_account->meta->dlen = new_target_program_data_account_sz;
  new_target_program_data_account->meta->slot = slot_ctx->slot_bank.slot;

  err = fd_new_target_program_data_account( slot_ctx, upgrade_authority_address, source_buffer_account, new_target_program_data_account );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write new program data state to %s", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    goto fail;
  }

  /* Deploy the new target Core BPF program.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L268-L271 */
  err = fd_directly_invoke_loader_v3_deploy( slot_ctx,
                                             new_target_program_data_account->const_data + PROGRAMDATA_METADATA_SIZE,
                                             new_target_program_data_account->const_meta->dlen - PROGRAMDATA_METADATA_SIZE );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to deploy program %s", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L281-L284 */
  ulong lamports_to_fund = new_target_program_account->const_meta->info.lamports + new_target_program_data_account->const_meta->info.lamports;

  /* Update capitalization.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L286-L297 */
  if( lamports_to_burn>lamports_to_fund ) {
    slot_ctx->slot_bank.capitalization -= lamports_to_burn - lamports_to_fund;
  } else {
    slot_ctx->slot_bank.capitalization += lamports_to_fund - lamports_to_burn;
  }

  /* Reclaim the source buffer account
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L305 */
  source_buffer_account->meta->info.lamports = 0;
  source_buffer_account->meta->dlen = 0;
  fd_memset( source_buffer_account->meta->info.owner, 0, sizeof(fd_pubkey_t) );

  /* Publish the in-preparation transaction into the parent. We should not have to create
     a BPF cache entry here because the program is technically "delayed visibility", so the program
     should not be invokable until the next slot. The cache entry will be created at the end of the
     block as a part of the finalize routine. */
  fd_funk_txn_publish_into_parent( slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, 1 );
  slot_ctx->funk_txn = parent_txn;
  return;

fail:
  /* Cancel the in-preparation transaction and discard any in-progress changes. */
  fd_funk_txn_cancel( slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, 0UL );
  slot_ctx->funk_txn = parent_txn;
}

static void
fd_apply_builtin_program_feature_transitions( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    /* TODO: Set the upgrade authority properly from the core bpf migration config. Right now it's set to None.

       Migrate any necessary stateless builtins to core BPF. So far, the only "stateless" builtin
       is the Feature program. Beginning checks in the `migrate_builtin_to_core_bpf` function will
       fail if the program has already been migrated to BPF.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6776-L6793 */
    if( FD_FEATURE_ACTIVE( slot_ctx, migrate_feature_gate_program_to_core_bpf ) ) {
      fd_migrate_builtin_to_core_bpf( slot_ctx, NULL, &fd_solana_feature_program_id, &fd_solana_feature_program_buffer_address, 1 );
    }

    if( FD_FEATURE_ACTIVE( slot_ctx, migrate_config_program_to_core_bpf ) ) {
      fd_migrate_builtin_to_core_bpf( slot_ctx, NULL, &fd_solana_config_program_id, &fd_solana_config_program_buffer_address, 0 );
    }

    if( FD_FEATURE_ACTIVE( slot_ctx, migrate_address_lookup_table_program_to_core_bpf ) ) {
      fd_migrate_builtin_to_core_bpf( slot_ctx, NULL, &fd_solana_address_lookup_table_program_id, &fd_solana_address_lookup_table_program_buffer_address, 0 );
    }

    if( FD_FEATURE_ACTIVE( slot_ctx, migrate_stake_program_to_core_bpf ) ) {
      fd_migrate_builtin_to_core_bpf( slot_ctx, NULL, &fd_solana_stake_program_id, &fd_solana_stake_program_buffer_address, 0 );
    }
  } FD_SCRATCH_SCOPE_END;
}

static void
fd_feature_activate( fd_exec_slot_ctx_t * slot_ctx,
                    fd_feature_id_t const * id,
                    uchar const       acct[ static 32 ] ) {

  // Skip reverted features from being activated
  if ( id->reverted==1 ) {
    return;
  }

  FD_BORROWED_ACCOUNT_DECL(acct_rec);
  int err = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *)acct, acct_rec);
  if (FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS))
    return;

  fd_feature_t feature[1];

  FD_SCRATCH_SCOPE_BEGIN
  {

    fd_bincode_decode_ctx_t ctx = {
        .data = acct_rec->const_data,
        .dataend = acct_rec->const_data + acct_rec->const_meta->dlen,
        .valloc = fd_scratch_virtual(),
    };
    int decode_err = fd_feature_decode(feature, &ctx);
    if (FD_UNLIKELY(decode_err != FD_BINCODE_SUCCESS)) {
      FD_LOG_ERR(( "Failed to decode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
    }

    if( feature->has_activated_at ) {
      FD_LOG_INFO(( "feature already activated - acc: %s, slot: %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
      fd_features_set(&slot_ctx->epoch_ctx->features, id, feature->activated_at);
    } else {
      FD_LOG_INFO(( "Feature %s not activated at %lu, activating", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));

      FD_BORROWED_ACCOUNT_DECL(modify_acct_rec);
      err = fd_acc_mgr_modify(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *)acct, 0, 0UL, modify_acct_rec);
      if (FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS)) {
        return;
      }

      feature->has_activated_at = 1;
      feature->activated_at = slot_ctx->slot_bank.slot;
      fd_bincode_encode_ctx_t encode_ctx = {
        .data = modify_acct_rec->data,
        .dataend = modify_acct_rec->data + modify_acct_rec->meta->dlen,
      };
      int encode_err = fd_feature_encode(feature, &encode_ctx);
      if (FD_UNLIKELY(encode_err != FD_BINCODE_SUCCESS)) {
        FD_LOG_ERR(( "Failed to encode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
      }
    }
    /* No need to call destroy, since we are using fd_scratch allocator. */
  } FD_SCRATCH_SCOPE_END;
}

static void
fd_features_activate( fd_exec_slot_ctx_t * slot_ctx ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_activate( slot_ctx, id, id->id.key );
  }
}

uint
fd_runtime_is_epoch_boundary( fd_epoch_bank_t * epoch_bank, ulong curr_slot, ulong prev_slot ) {
  ulong slot_idx;
  ulong prev_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, prev_slot, &slot_idx );
  ulong new_epoch  = fd_slot_to_epoch( &epoch_bank->epoch_schedule, curr_slot, &slot_idx );

  return ( prev_epoch < new_epoch || slot_idx == 0 );
}

/* Starting a new epoch.
  New epoch:        T
  Just ended epoch: T-1
  Epoch before:     T-2

  In this function:
  - stakes in T-2 (slot_ctx->slot_bank.epoch_stakes) should be replaced by T-1 (epoch_bank->next_epoch_stakes)
  - stakes at T-1 (epoch_bank->next_epoch_stakes) should be replaced by updated stakes at T (stakes->vote_accounts)
  - leader schedule should be calculated using new T-2 stakes (slot_ctx->slot_bank.epoch_stakes)

  Invariant during an epoch T:
  epoch_bank->next_epoch_stakes    holds the stakes at T-1
  slot_ctx->slot_bank.epoch_stakes holds the stakes at T-2
 */
/* process for the start of a new epoch */
static
void fd_runtime_process_new_epoch( fd_exec_slot_ctx_t * slot_ctx,
                                   ulong                parent_epoch ) {
  FD_LOG_NOTICE(( "fd_process_new_epoch start" ));

  ulong             slot;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong             epoch      = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, &slot );

  /* Activate new features
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6587-L6598 */
  fd_features_activate( slot_ctx );
  fd_features_restore( slot_ctx );

  /* Apply builtin program feature transitions
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6621-L6624 */
  fd_apply_builtin_program_feature_transitions( slot_ctx );

  /* Change the speed of the poh clock
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6627-L6649 */
  if( FD_FEATURE_JUST_ACTIVATED( slot_ctx, update_hashes_per_tick6 ) ) {
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK6;
  } else if( FD_FEATURE_JUST_ACTIVATED(slot_ctx, update_hashes_per_tick5 ) ) {
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK5;
  } else if( FD_FEATURE_JUST_ACTIVATED( slot_ctx, update_hashes_per_tick4 ) ) {
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK4;
  } else if( FD_FEATURE_JUST_ACTIVATED(slot_ctx, update_hashes_per_tick3 ) ) {
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK3;
  } else if( FD_FEATURE_JUST_ACTIVATED(slot_ctx, update_hashes_per_tick2 ) ) {
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK2;
  }

  /* Get the new rate activation epoch */
  int _err[1];
  ulong * new_rate_activation_epoch = fd_scratch_alloc( alignof(ulong), sizeof(ulong) );
  int     is_some                   = fd_new_warmup_cooldown_rate_epoch( slot_ctx, new_rate_activation_epoch, _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_rate_activation_epoch = NULL;
  }

  FD_SCRATCH_SCOPE_BEGIN {

    fd_epoch_info_t temp_info = {0};
    fd_epoch_info_new( &temp_info );

    /* Updates stake history sysvar accumulated values. */
    fd_stakes_activate_epoch( slot_ctx, new_rate_activation_epoch, &temp_info );

    /* Update the stakes epoch value to the new epoch */
    epoch_bank->stakes.epoch = epoch;

    /* If appropiate, use the stakes at T-1 to generate the leader schedule instead of T-2.
       This is due to a subtlety in how Agave's stake caches interact when loading from snapshots.
       See the comment in fd_exec_slot_ctx_recover_. */
    if( slot_ctx->slot_bank.has_use_preceeding_epoch_stakes && slot_ctx->slot_bank.use_preceeding_epoch_stakes == epoch ) {
      fd_update_epoch_stakes( slot_ctx );
    }

    /* Distribute rewards */
    fd_hash_t const * parent_blockhash = slot_ctx->slot_bank.block_hash_queue.last_hash;
    if( ( FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) ||
          FD_FEATURE_ACTIVE( slot_ctx, partitioned_epoch_rewards_superfeature ) ) ) {
      FD_LOG_NOTICE(( "fd_begin_partitioned_rewards" ));
      fd_begin_partitioned_rewards( slot_ctx, parent_blockhash, parent_epoch, &temp_info );
    } else {
      fd_update_rewards( slot_ctx, parent_blockhash, parent_epoch, &temp_info );
    }

    /* Updates stakes at time T */
    fd_stake_history_t const * history = fd_sysvar_cache_stake_history( slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !history ) ) {
      FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));
    }

    FD_LOG_NOTICE(( "refresh_vote_accounts" ));

    refresh_vote_accounts( slot_ctx, history, new_rate_activation_epoch, &temp_info );
    fd_update_stake_delegations( slot_ctx, &temp_info );

    /* Replace stakes at T-2 (slot_ctx->slot_bank.epoch_stakes) by stakes at T-1 (epoch_bank->next_epoch_stakes) */
    fd_update_epoch_stakes( slot_ctx );

    /* Replace stakes at T-1 (epoch_bank->next_epoch_stakes) by updated stakes at T (stakes->vote_accounts) */
    fd_update_next_epoch_stakes( slot_ctx );

    /* Update current leaders using slot_ctx->slot_bank.epoch_stakes (new T-2 stakes) */
    fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );

    fd_calculate_epoch_accounts_hash_values( slot_ctx );
  } FD_SCRATCH_SCOPE_END;

  FD_LOG_NOTICE(( "fd_process_new_epoch end" ));
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
fd_runtime_parse_microblock_hdr( void const *          buf,
                                 ulong                 buf_sz,
                                 fd_microblock_hdr_t * opt_microblock_hdr,
                                 ulong *               opt_microblock_hdr_size ) {

  if( FD_UNLIKELY( buf_sz<sizeof(fd_microblock_hdr_t) ) ) {
    return -1;
  }

  if( !!opt_microblock_hdr ) {
    *opt_microblock_hdr = *(fd_microblock_hdr_t *)buf;
  }

  if( !!opt_microblock_hdr_size ) {
    *opt_microblock_hdr_size = sizeof(fd_microblock_hdr_t);
  }

  return 0;
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
    ulong microblock_hdr_size            = 0UL;
    fd_microblock_info_t microblock_info = {0};
    if( FD_UNLIKELY( fd_runtime_parse_microblock_hdr( orig_data + curr_offset, 
                                                      batches->end_off - curr_offset, 
                                                      &microblock_info.microblock_hdr, 
                                                      &microblock_hdr_size ) ) ) {
      /* TODO: improve error handling */
      FD_LOG_ERR(( "premature end of batch" ));
    }
    curr_offset += microblock_hdr_size;

    /* If we have found a microblock with transactions in the current batch, return that */
    if( FD_LIKELY( microblock_info.microblock_hdr.txn_cnt ) ) {
      return (fd_raw_block_txn_iter_t){
        .curr_batch            = batches,
        .orig_data             = orig_data,
        .remaining_batches     = batch_cnt,
        .remaining_microblocks = fd_ulong_sat_sub( fd_ulong_sat_sub(num_microblocks, i), 1UL),
        .remaining_txns        = microblock_info.microblock_hdr.txn_cnt,
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
      ulong microblock_hdr_size            = 0UL;
      fd_microblock_info_t microblock_info = {0};
      if( FD_UNLIKELY( fd_runtime_parse_microblock_hdr( orig_data + curr_offset, 
                                                        batch_end_off - curr_offset, 
                                                        &microblock_info.microblock_hdr, 
                                                        &microblock_hdr_size ) ) ) {
        /* TODO: improve error handling */
        FD_LOG_ERR(( "premature end of batch" ));
      }
      curr_offset += microblock_hdr_size;

      /* If we have found a microblock with a non-zero number of transactions in, return that */
      if( FD_LIKELY( microblock_info.microblock_hdr.txn_cnt ) ) {
        return (fd_raw_block_txn_iter_t){
          .curr_batch            = &batches[i],
          .orig_data             = orig_data,
          .remaining_batches     = fd_ulong_sat_sub( batch_cnt, i ),
          .remaining_microblocks = fd_ulong_sat_sub( fd_ulong_sat_sub( num_microblocks, j ), 1UL ),
          .remaining_txns        = microblock_info.microblock_hdr.txn_cnt,
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
    if( FD_UNLIKELY( !txn_sz || txn_sz>FD_TXN_MTU ) ) {
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
                               fd_valloc_t            valloc,
                               fd_microblock_info_t * out_microblock_info ) {

  fd_microblock_info_t microblock_info = {
    .raw_microblock = buf,
    .signature_cnt  = 0UL,
  };
  ulong buf_off = 0UL;
  ulong hdr_sz  = 0UL;
  if( FD_UNLIKELY( fd_runtime_parse_microblock_hdr( buf, buf_sz, &microblock_info.microblock_hdr, &hdr_sz ) ) ) {
    return -1;
  }
  buf_off += hdr_sz;

  ulong txn_cnt        = microblock_info.microblock_hdr.txn_cnt;
  microblock_info.txns = fd_valloc_malloc( valloc, alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );
  ulong txns_sz        = 0UL;
  if( FD_UNLIKELY( fd_runtime_parse_microblock_txns( (uchar *)buf + buf_off,
                                                     buf_sz - buf_off,
                                                     &microblock_info.microblock_hdr,
                                                     microblock_info.txns,
                                                     &microblock_info.signature_cnt,
                                                     &microblock_info.account_cnt,
                                                     &txns_sz ) ) ) {
    fd_valloc_free( valloc, microblock_info.txns );
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
                                     fd_valloc_t                  valloc,
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
  microblock_batch_info.microblock_infos = fd_valloc_malloc( valloc, alignof(fd_microblock_info_t), microblock_cnt * sizeof(fd_microblock_info_t) );

  ulong signature_cnt = 0UL;
  ulong txn_cnt       = 0UL;
  ulong account_cnt   = 0UL;
  for( ulong i=0UL; i<microblock_cnt; i++ ) {
    fd_microblock_info_t * microblock_info = &microblock_batch_info.microblock_infos[i];
    if( FD_UNLIKELY( fd_runtime_microblock_prepare( (uchar const *)buf + buf_off, buf_sz - buf_off, valloc, microblock_info ) ) ) {
      fd_valloc_free( valloc, microblock_batch_info.microblock_infos );
      return -1;
    }

    signature_cnt += microblock_info->signature_cnt;
    txn_cnt       += microblock_info->microblock_hdr.txn_cnt;
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
fd_runtime_block_prepare( fd_blockstore_t * blockstore,
                          fd_block_t *      block,
                          ulong             slot,
                          fd_valloc_t       valloc,
                          fd_block_info_t * out_block_info ) {
  uchar const *                  buf         = fd_blockstore_block_data_laddr( blockstore, block );
  ulong const                    buf_sz      = block->data_sz;
  fd_block_entry_batch_t const * batch_laddr = fd_blockstore_block_batch_laddr( blockstore, block );
  ulong const                    batch_cnt   = block->batch_cnt;

  fd_block_info_t block_info = {
      .raw_block    = buf,
      .raw_block_sz = buf_sz,
  };

  ulong microblock_batch_cnt = 0UL;
  ulong microblock_cnt       = 0UL;
  ulong signature_cnt        = 0UL;
  ulong txn_cnt              = 0UL;
  ulong account_cnt          = 0UL;
  block_info.microblock_batch_infos = fd_valloc_malloc( valloc, alignof(fd_microblock_batch_info_t), block->batch_cnt * sizeof(fd_microblock_batch_info_t) );

  ulong buf_off = 0UL;
  for( microblock_batch_cnt=0UL; microblock_batch_cnt < batch_cnt; microblock_batch_cnt++ ) {
    ulong const batch_end_off = batch_laddr[ microblock_batch_cnt ].end_off;
    fd_microblock_batch_info_t * microblock_batch_info = block_info.microblock_batch_infos + microblock_batch_cnt;
    if( FD_UNLIKELY( fd_runtime_microblock_batch_prepare( buf + buf_off, batch_end_off - buf_off, valloc, microblock_batch_info ) ) ) {
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
  ulong txn_cnt = microblock_info->microblock_hdr.txn_cnt;
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
fd_runtime_block_collect_txns( fd_block_info_t const * block_info,
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
fd_runtime_init_program( fd_exec_slot_ctx_t * slot_ctx )
{
  fd_sysvar_recent_hashes_init( slot_ctx );
  fd_sysvar_clock_init( slot_ctx );
  fd_sysvar_slot_history_init( slot_ctx );
  fd_sysvar_epoch_schedule_init( slot_ctx );
  if( !FD_FEATURE_ACTIVE( slot_ctx, disable_fees_sysvar ) ) {
    fd_sysvar_fees_init( slot_ctx );
  }
  fd_sysvar_rent_init( slot_ctx );
  fd_sysvar_stake_history_init( slot_ctx );
  fd_sysvar_last_restart_slot_init( slot_ctx );

  fd_builtin_programs_init( slot_ctx );
  fd_stake_program_config_init( slot_ctx );
}

static void
fd_runtime_init_bank_from_genesis( fd_exec_slot_ctx_t *  slot_ctx,
                                   fd_genesis_solana_t * genesis_block,
                                   fd_hash_t const *     genesis_hash ) {
  slot_ctx->slot_bank.slot = 0UL;

  memcpy( &slot_ctx->slot_bank.poh, genesis_hash->hash, FD_SHA256_HASH_SZ );
  memset( slot_ctx->slot_bank.banks_hash.hash, 0, FD_SHA256_HASH_SZ );

  slot_ctx->slot_bank.fee_rate_governor      = genesis_block->fee_rate_governor;
  slot_ctx->slot_bank.lamports_per_signature = 0UL;
  slot_ctx->prev_lamports_per_signature      = 0UL;

  fd_poh_config_t *     poh        = &genesis_block->poh_config;
  fd_exec_epoch_ctx_t * epoch_ctx  = slot_ctx->epoch_ctx;
  fd_epoch_bank_t *     epoch_bank = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  if( poh->has_hashes_per_tick ) {
    epoch_bank->hashes_per_tick = poh->hashes_per_tick;
  } else {
    epoch_bank->hashes_per_tick = 0UL;
  }
  epoch_bank->ticks_per_slot        = genesis_block->ticks_per_slot;
  epoch_bank->genesis_creation_time = genesis_block->creation_time;
  uint128 target_tick_duration      = ((uint128)poh->target_tick_duration.seconds * 1000000000UL + (uint128)poh->target_tick_duration.nanoseconds);
  epoch_bank->ns_per_slot           = target_tick_duration * epoch_bank->ticks_per_slot;

  epoch_bank->slots_per_year          = SECONDS_PER_YEAR * (1000000000.0 / (double)target_tick_duration) / (double)epoch_bank->ticks_per_slot;
  epoch_bank->genesis_creation_time   = genesis_block->creation_time;
  slot_ctx->slot_bank.max_tick_height = epoch_bank->ticks_per_slot * (slot_ctx->slot_bank.slot + 1);
  epoch_bank->epoch_schedule          = genesis_block->epoch_schedule;
  epoch_bank->inflation               = genesis_block->inflation;
  epoch_bank->rent                    = genesis_block->rent;
  slot_ctx->slot_bank.block_height    = 0UL;

  fd_block_block_hash_entry_t * hashes = slot_ctx->slot_bank.recent_block_hashes.hashes =
                                         deq_fd_block_block_hash_entry_t_alloc( slot_ctx->valloc, FD_SYSVAR_RECENT_HASHES_CAP );
  fd_block_block_hash_entry_t * elem   = deq_fd_block_block_hash_entry_t_push_head_nocopy( hashes );
  fd_block_block_hash_entry_new( elem );
  fd_memcpy( elem->blockhash.hash, genesis_hash, FD_SHA256_HASH_SZ );
  elem->fee_calculator.lamports_per_signature = 0UL;

  slot_ctx->slot_bank.block_hash_queue.ages_root = NULL;
  slot_ctx->slot_bank.block_hash_queue.ages_pool = fd_hash_hash_age_pair_t_map_alloc( slot_ctx->valloc, 400 );
  fd_hash_hash_age_pair_t_mapnode_t * node       = fd_hash_hash_age_pair_t_map_acquire( slot_ctx->slot_bank.block_hash_queue.ages_pool );
  node->elem = (fd_hash_hash_age_pair_t){
    .key = *genesis_hash,
    .val = (fd_hash_age_t){ .hash_index = 0UL, .fee_calculator = (fd_fee_calculator_t){.lamports_per_signature = 0UL}, .timestamp = (ulong)fd_log_wallclock() }
  };
  fd_hash_hash_age_pair_t_map_insert( slot_ctx->slot_bank.block_hash_queue.ages_pool, &slot_ctx->slot_bank.block_hash_queue.ages_root, node );
  slot_ctx->slot_bank.block_hash_queue.last_hash_index = 0UL;
  slot_ctx->slot_bank.block_hash_queue.last_hash       = fd_valloc_malloc( slot_ctx->valloc, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );
  fd_memcpy( slot_ctx->slot_bank.block_hash_queue.last_hash, genesis_hash, FD_SHA256_HASH_SZ );
  slot_ctx->slot_bank.block_hash_queue.max_age         = FD_BLOCKHASH_QUEUE_MAX_ENTRIES;

  slot_ctx->signature_cnt = 0UL;

  /* Derive epoch stakes */

  fd_vote_accounts_pair_t_mapnode_t * vacc_pool = fd_exec_epoch_ctx_stake_votes_join( epoch_ctx );
  fd_vote_accounts_pair_t_mapnode_t * vacc_root = NULL;
  FD_TEST( vacc_pool );

  fd_delegation_pair_t_mapnode_t * sacc_pool = fd_exec_epoch_ctx_stake_delegations_join( epoch_ctx );
  fd_delegation_pair_t_mapnode_t * sacc_root = NULL;

  fd_acc_lamports_t capitalization = 0UL;

  for( ulong i=0UL; i<genesis_block->accounts_len; i++ ) {
    fd_pubkey_account_pair_t const * acc = &genesis_block->accounts[i];
    capitalization = fd_ulong_sat_add( capitalization, acc->account.lamports );

    if( !memcmp(acc->account.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)) ) {
      /* Vote Program Account */
      fd_vote_accounts_pair_t_mapnode_t *node = fd_vote_accounts_pair_t_map_acquire(vacc_pool);
      FD_TEST( node );

      fd_vote_block_timestamp_t last_timestamp = {0};
      fd_pubkey_t               node_pubkey    = {0};
      FD_SCRATCH_SCOPE_BEGIN {
        /* Deserialize content */
        fd_vote_state_versioned_t vs[1];
        fd_bincode_decode_ctx_t decode =
            { .data    = acc->account.data,
              .dataend = acc->account.data + acc->account.data_len,
              .valloc  = fd_scratch_virtual() };
        int decode_err = fd_vote_state_versioned_decode( vs, &decode );
        if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) {
          FD_LOG_WARNING(( "fd_vote_state_versioned_decode failed (%d)", decode_err ));
          return;
        }

        switch( vs->discriminant )
        {
        case fd_vote_state_versioned_enum_current:
          last_timestamp = vs->inner.current.last_timestamp;
          node_pubkey    = vs->inner.current.node_pubkey;
          break;
        case fd_vote_state_versioned_enum_v0_23_5:
          last_timestamp = vs->inner.v0_23_5.last_timestamp;
          node_pubkey    = vs->inner.v0_23_5.node_pubkey;
          break;
        case fd_vote_state_versioned_enum_v1_14_11:
          last_timestamp = vs->inner.v1_14_11.last_timestamp;
          node_pubkey    = vs->inner.v1_14_11.node_pubkey;
          break;
        default:
          __builtin_unreachable();
        }

      } FD_SCRATCH_SCOPE_END;

      fd_memcpy(node->elem.key.key, acc->key.key, sizeof(fd_pubkey_t));
      node->elem.stake = acc->account.lamports;
      node->elem.value = (fd_solana_vote_account_t){
        .lamports = acc->account.lamports,
        .node_pubkey = node_pubkey,
        .last_timestamp_ts = last_timestamp.timestamp,
        .last_timestamp_slot = last_timestamp.slot,
        .owner = acc->account.owner,
        .executable = acc->account.executable,
        .rent_epoch = acc->account.rent_epoch 
      };

      fd_vote_accounts_pair_t_map_insert( vacc_pool, &vacc_root, node );

      FD_LOG_INFO(( "Adding genesis vote account: key=%s stake=%lu",
                    FD_BASE58_ENC_32_ALLOCA( node->elem.key.key ),
                    node->elem.stake ));
    } else if( !memcmp( acc->account.owner.key, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* stake program account */
      fd_stake_state_v2_t   stake_state   = {0};
      fd_account_meta_t     meta          = { .dlen = acc->account.data_len };
      fd_borrowed_account_t stake_account = {
        .const_data = acc->account.data,
        .const_meta = &meta,
        .data = acc->account.data,
        .meta = &meta 
      };
      FD_TEST( fd_stake_get_state(&stake_account, &slot_ctx->valloc, &stake_state) == 0 );
      if( !stake_state.inner.stake.stake.delegation.stake ) { 
        continue;
      }
      fd_delegation_pair_t_mapnode_t   query_node = {0};
      fd_memcpy(&query_node.elem.account, acc->key.key, sizeof(fd_pubkey_t));
      fd_delegation_pair_t_mapnode_t * node = fd_delegation_pair_t_map_find( sacc_pool, sacc_root, &query_node );

      if( !node ) {
        node = fd_delegation_pair_t_map_acquire( sacc_pool );
        fd_memcpy( &node->elem.account, acc->key.key, sizeof(fd_pubkey_t) );
        fd_memcpy( &node->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t) );
        fd_delegation_pair_t_map_insert( sacc_pool, &sacc_root, node );
      } else {
        fd_memcpy( &node->elem.account, acc->key.key, sizeof(fd_pubkey_t) );
        fd_memcpy( &node->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t) );
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
        FD_SCRATCH_SCOPE_BEGIN {
          fd_bincode_decode_ctx_t decode = { 
            .data = acc->account.data,
            .dataend = acc->account.data + acc->account.data_len,
            .valloc = fd_scratch_virtual()
          };
          fd_feature_t feature = {0};
          int err = fd_feature_decode( &feature, &decode );
          FD_TEST( err==FD_BINCODE_SUCCESS );
          if( feature.has_activated_at ) {
            FD_LOG_DEBUG(( "Feature %s activated at %lu (genesis)", FD_BASE58_ENC_32_ALLOCA( acc->key.key ), feature.activated_at ));
            fd_features_set( &slot_ctx->epoch_ctx->features, found, feature.activated_at );
          } else {
            FD_LOG_DEBUG(( "Feature %s not activated (genesis)", FD_BASE58_ENC_32_ALLOCA( acc->key.key ) ));
            fd_features_set( &slot_ctx->epoch_ctx->features, found, ULONG_MAX );
          }
        } FD_SCRATCH_SCOPE_END;
      }
    }
  }

  slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000 );  /* FIXME remove magic constant */
  slot_ctx->slot_bank.epoch_stakes.vote_accounts_root = NULL;

  fd_vote_accounts_pair_t_mapnode_t * next_pool = fd_exec_epoch_ctx_next_epoch_stakes_join( slot_ctx->epoch_ctx );
  fd_vote_accounts_pair_t_mapnode_t * next_root = NULL;

  for( fd_vote_accounts_pair_t_mapnode_t *n = fd_vote_accounts_pair_t_map_minimum( vacc_pool, vacc_root );
       n;
       n = fd_vote_accounts_pair_t_map_successor( vacc_pool, n )) {
    fd_vote_accounts_pair_t_mapnode_t * e = fd_vote_accounts_pair_t_map_acquire( slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool );
    fd_memcpy( &e->elem, &n->elem, sizeof(fd_vote_accounts_pair_t) );
    fd_vote_accounts_pair_t_map_insert( slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool, &slot_ctx->slot_bank.epoch_stakes.vote_accounts_root, e );

    fd_vote_accounts_pair_t_mapnode_t * next_e = fd_vote_accounts_pair_t_map_acquire( next_pool );
    fd_memcpy( &next_e->elem, &n->elem, sizeof(fd_vote_accounts_pair_t) );
    fd_vote_accounts_pair_t_map_insert( next_pool, &next_root, next_e );
  }

  for( fd_delegation_pair_t_mapnode_t *n = fd_delegation_pair_t_map_minimum( sacc_pool, sacc_root );
       n;
       n = fd_delegation_pair_t_map_successor( sacc_pool, n )) {
    fd_vote_accounts_pair_t_mapnode_t query_voter  = {0};
    fd_pubkey_t *                     voter_pubkey = &n->elem.delegation.voter_pubkey;
    fd_memcpy( &query_voter.elem.key, voter_pubkey, sizeof(fd_pubkey_t) );

    fd_vote_accounts_pair_t_mapnode_t * voter = fd_vote_accounts_pair_t_map_find( vacc_pool, vacc_root, &query_voter );

    if( !!voter ) {
      voter->elem.stake = fd_ulong_sat_add( voter->elem.stake, n->elem.delegation.stake );
    }
  }

  epoch_bank->next_epoch_stakes = (fd_vote_accounts_t){
    .vote_accounts_pool = next_pool,
    .vote_accounts_root = next_root,
  };

  /* Initializes the stakes cache in the Bank structure. */
  epoch_bank->stakes = (fd_stakes_t){
      .stake_delegations_pool = sacc_pool,
      .stake_delegations_root = sacc_root,
      .epoch                  = 0UL,
      .unused                 = 0UL,
      .vote_accounts = (fd_vote_accounts_t){
        .vote_accounts_pool = vacc_pool,
        .vote_accounts_root = vacc_root
      },
      .stake_history = {0}
  };

  slot_ctx->slot_bank.capitalization             = capitalization;
  slot_ctx->slot_bank.timestamp_votes.votes_pool = fd_clock_timestamp_vote_t_map_alloc( slot_ctx->valloc, 10000 ); /* FIXME: remove magic constant */
  slot_ctx->slot_bank.timestamp_votes.votes_root = NULL;

}

static int
fd_runtime_process_genesis_block( fd_exec_slot_ctx_t * slot_ctx, fd_capture_ctx_t * capture_ctx, fd_tpool_t * tpool ) {
  ulong hashcnt_per_slot = slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick * slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;
  while( hashcnt_per_slot-- ) {
    fd_sha256_hash( slot_ctx->slot_bank.poh.uc, sizeof(fd_hash_t), slot_ctx->slot_bank.poh.uc );
  }

  slot_ctx->slot_bank.collected_execution_fees = 0UL;
  slot_ctx->slot_bank.collected_priority_fees  = 0UL;
  slot_ctx->slot_bank.collected_rent           = 0UL;
  slot_ctx->signature_cnt                      = 0UL;
  slot_ctx->txn_count                          = 0UL;
  slot_ctx->nonvote_txn_count                  = 0UL;
  slot_ctx->failed_txn_count                   = 0UL;
  slot_ctx->nonvote_failed_txn_count           = 0UL;
  slot_ctx->total_compute_units_used           = 0UL;

  fd_sysvar_slot_history_update( slot_ctx );

  fd_runtime_freeze( slot_ctx );

  /* sort and update bank hash */
  int result = fd_update_hash_bank_tpool( slot_ctx, capture_ctx, &slot_ctx->slot_bank.banks_hash, slot_ctx->signature_cnt, tpool );
  if( FD_UNLIKELY( result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    FD_LOG_ERR(( "Failed to update bank hash with error=%d", result ));
  }

  FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS==fd_runtime_save_epoch_bank( slot_ctx ) );

  FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS==fd_runtime_save_slot_bank( slot_ctx ) );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_read_genesis( fd_exec_slot_ctx_t * slot_ctx,
                         char const         * genesis_filepath,
                         uchar                is_snapshot,
                         fd_capture_ctx_t   * capture_ctx,
                         fd_tpool_t         * tpool ) {
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

  fd_genesis_solana_t genesis_block = {0};
  fd_genesis_solana_new( &genesis_block );
  fd_hash_t           genesis_hash;

  fd_epoch_bank_t *   epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );

  FD_SCRATCH_SCOPE_BEGIN {
    uchar * buf = fd_scratch_alloc( alignof(ulong), (ulong)sbuf.st_size );
    ssize_t n   = read( fd, buf, (ulong)sbuf.st_size );
    close( fd );

    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = buf,
      .dataend = buf + n,
      .valloc  = slot_ctx->valloc,
    };
    if( FD_UNLIKELY( fd_genesis_solana_decode( &genesis_block, &decode_ctx ) ) ) {
      FD_LOG_ERR(("fd_genesis_solana_decode failed"));
    }

    // The hash is generated from the raw data... don't mess with this..
    fd_sha256_hash( buf, (ulong)n, genesis_hash.uc );

  } FD_SCRATCH_SCOPE_END;

  fd_memcpy( epoch_bank->genesis_hash.uc, genesis_hash.uc, sizeof(fd_hash_t) );
  epoch_bank->cluster_type = genesis_block.cluster_type;

  fd_funk_start_write( slot_ctx->acc_mgr->funk );

  if( !is_snapshot ) {
    fd_runtime_init_bank_from_genesis( slot_ctx, &genesis_block, &genesis_hash );

    fd_runtime_init_program( slot_ctx );

    FD_LOG_DEBUG(( "start genesis accounts - count: %lu", genesis_block.accounts_len ));

    for( ulong i=0; i<genesis_block.accounts_len; i++ ) {
      fd_pubkey_account_pair_t * a = &genesis_block.accounts[i];

      FD_BORROWED_ACCOUNT_DECL( rec );

      int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, 
                                   slot_ctx->funk_txn, 
                                   &a->key,
                                   /* do_create */ 1, 
                                   a->account.data_len, 
                                   rec );

      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "fd_acc_mgr_modify failed (%d)", err ));
      }

      rec->meta->dlen            = a->account.data_len;
      rec->meta->info.lamports   = a->account.lamports;
      rec->meta->info.rent_epoch = a->account.rent_epoch;
      rec->meta->info.executable = a->account.executable;
      memcpy( rec->meta->info.owner, a->account.owner.key, sizeof(fd_hash_t));
      if( a->account.data_len ) {
        memcpy( rec->data, a->account.data, a->account.data_len );
      }
    }

    FD_LOG_DEBUG(( "end genesis accounts" ));

    FD_LOG_DEBUG(( "native instruction processors - count: %lu", genesis_block.native_instruction_processors_len ));

    for( ulong i=0UL; i < genesis_block.native_instruction_processors_len; i++ ) {
      fd_string_pubkey_pair_t * a = &genesis_block.native_instruction_processors[i];
      fd_write_builtin_bogus_account( slot_ctx, a->pubkey.uc, (const char *) a->string, a->string_len );
    }

    fd_features_restore( slot_ctx );

    slot_ctx->slot_bank.slot = 0UL;

    int err = fd_runtime_process_genesis_block( slot_ctx, capture_ctx, tpool );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Genesis slot 0 execute failed with error %d", err ));
    }
  }

  slot_ctx->slot_bank.stake_account_keys.stake_accounts_root = NULL;
  slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool = fd_stake_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000UL );

  slot_ctx->slot_bank.vote_account_keys.vote_accounts_root   = NULL;
  slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool   = fd_vote_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000UL );

  fd_funk_end_write( slot_ctx->acc_mgr->funk );

  fd_bincode_destroy_ctx_t ctx2 = { .valloc = slot_ctx->valloc };
  fd_genesis_solana_destroy( &genesis_block, &ctx2 );
}

/******************************************************************************/
/* Offline Replay                                                             */
/******************************************************************************/

/* As a note, currently offline and live replay of transactions has differences
   with regards to how the execution environment is setup. These are helpers
   used to emulate this behavior */

struct fd_poh_verification_info {
  fd_microblock_info_t const *microblock_info;
  fd_hash_t const *in_poh_hash;
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
    in_poh_hash = (fd_hash_t const *)&microblock_info->microblock_hdr.hash;
  }
}

static void 
fd_runtime_block_verify_info_collect( fd_block_info_t const *      block_info,
                                      fd_hash_t       const *      in_poh_hash,
                                      fd_poh_verification_info_t * poh_verification_info)
{
  for( ulong i=0UL; i<block_info->microblock_batch_cnt; i++ ) {
    fd_microblock_batch_info_t const * microblock_batch_info = &block_info->microblock_batch_infos[i];

    fd_runtime_microblock_batch_verify_info_collect( microblock_batch_info, in_poh_hash, poh_verification_info );
    in_poh_hash            = (fd_hash_t const *)poh_verification_info[microblock_batch_info->microblock_cnt - 1].microblock_info->microblock_hdr.hash;
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

  fd_microblock_info_t const *microblock_info = poh_info->microblock_info;
  ulong hash_cnt = microblock_info->microblock_hdr.hash_cnt;
  ulong txn_cnt = microblock_info->microblock_hdr.txn_cnt;

  if( !txn_cnt ) {
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
      fd_txn_p_t *          txn_p      = &microblock_info->txns[txn_idx];
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

  if( FD_UNLIKELY( memcmp(microblock_info->microblock_hdr.hash, out_poh_hash.hash, sizeof(fd_hash_t)) ) ) {
    FD_LOG_WARNING(( "poh mismatch (bank: %s, entry: %s)", FD_BASE58_ENC_32_ALLOCA( out_poh_hash.hash ), FD_BASE58_ENC_32_ALLOCA( microblock_info->microblock_hdr.hash ) ));
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
fd_runtime_block_verify_tpool( fd_block_info_t const * block_info,
                               fd_hash_t       const * in_poh_hash,
                               fd_hash_t *             out_poh_hash,
                               fd_valloc_t             valloc,
                               fd_tpool_t *            tpool ) {
  long block_verify_time = -fd_log_wallclock();

  fd_hash_t                    tmp_in_poh_hash           = *in_poh_hash;
  ulong                        poh_verification_info_cnt = block_info->microblock_cnt;
  fd_poh_verification_info_t * poh_verification_info     = fd_valloc_malloc( valloc,
                                                                             alignof(fd_poh_verification_info_t),
                                                                             poh_verification_info_cnt * sizeof(fd_poh_verification_info_t));
  fd_runtime_block_verify_info_collect( block_info, &tmp_in_poh_hash, poh_verification_info );
  int result = fd_runtime_poh_verify_tpool( poh_verification_info, poh_verification_info_cnt, tpool );
  fd_memcpy( out_poh_hash->hash, poh_verification_info[poh_verification_info_cnt - 1].microblock_info->microblock_hdr.hash, sizeof(fd_hash_t) );
  fd_valloc_free( valloc, poh_verification_info );

  block_verify_time          += fd_log_wallclock();
  double block_verify_time_ms = (double)block_verify_time * 1e-6;

  FD_LOG_INFO(( "verified block successfully - elapsed: %6.6f ms", block_verify_time_ms ));

  return result;
}

static int
fd_runtime_publish_old_txns( fd_exec_slot_ctx_t * slot_ctx,
                             fd_capture_ctx_t *   capture_ctx,
                             fd_tpool_t *         tpool ) {        
  /* Publish any transaction older than 31 slots */
  fd_funk_t *       funk       = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t *   txnmap     = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );

  uint depth = 0;
  for( fd_funk_txn_t * txn = slot_ctx->funk_txn; txn; txn = fd_funk_txn_parent(txn, txnmap) ) {
    if( ++depth == (FD_RUNTIME_NUM_ROOT_BLOCKS - 1 ) ) {
      FD_LOG_DEBUG(("publishing %s (slot %lu)", FD_BASE58_ENC_32_ALLOCA( &txn->xid ), txn->xid.ul[0]));

      if( slot_ctx->status_cache && !fd_txncache_get_is_constipated( slot_ctx->status_cache ) ) {
        fd_txncache_register_root_slot( slot_ctx->status_cache, txn->xid.ul[0] );
      } else if( slot_ctx->status_cache ) {
        fd_txncache_register_constipated_slot( slot_ctx->status_cache, txn->xid.ul[0] );
      }

      fd_funk_start_write( funk );
      if( slot_ctx->epoch_ctx->constipate_root ) {
        fd_funk_txn_t * parent = fd_funk_txn_parent( txn, txnmap );
        if( parent != NULL ) {
          slot_ctx->root_slot = txn->xid.ul[0];

          if( FD_UNLIKELY( fd_funk_txn_publish_into_parent( funk, txn, 1) != FD_FUNK_SUCCESS ) ) {
            FD_LOG_ERR(( "Unable to publish into the parent transaction" ));
          }
        }
      } else {
        slot_ctx->root_slot = txn->xid.ul[0];
        /* TODO: The epoch boundary check is not correct due to skipped slots. */
        if( (!(slot_ctx->root_slot % slot_ctx->snapshot_freq) || (
             !(slot_ctx->root_slot % slot_ctx->incremental_freq) && slot_ctx->last_snapshot_slot)) &&
             !fd_runtime_is_epoch_boundary( epoch_bank, slot_ctx->root_slot, slot_ctx->root_slot - 1UL )) {

          slot_ctx->last_snapshot_slot         = slot_ctx->root_slot;
          slot_ctx->epoch_ctx->constipate_root = 1;
          fd_txncache_set_is_constipated( slot_ctx->status_cache, 1 );
        }

        if( FD_UNLIKELY( !fd_funk_txn_publish( funk, txn, 1 ) ) ) {
          FD_LOG_ERR(( "No transactions were published" ));
        }
      }

      if( txn->xid.ul[0] >= epoch_bank->eah_start_slot ) {
        fd_accounts_hash( slot_ctx->acc_mgr->funk, &slot_ctx->slot_bank, slot_ctx->valloc, tpool, &slot_ctx->slot_bank.epoch_account_hash );
        epoch_bank->eah_start_slot = ULONG_MAX;
      }

      if( capture_ctx != NULL ) {
        fd_runtime_checkpt( capture_ctx, slot_ctx, txn->xid.ul[0] );
      }

      fd_funk_end_write( funk );

      break;
    }
  }

  return 0;
}

static int
fd_runtime_block_execute_tpool( fd_exec_slot_ctx_t *    slot_ctx,
                                fd_capture_ctx_t *      capture_ctx,
                                fd_block_info_t const * block_info,
                                fd_tpool_t *            tpool,
                                fd_spad_t * *           spads,
                                ulong                   spad_cnt ) {
  FD_SCRATCH_SCOPE_BEGIN {
    if ( capture_ctx != NULL && capture_ctx->capture ) {
      fd_solcap_writer_set_slot( capture_ctx->capture, slot_ctx->slot_bank.slot );
    }

    long block_execute_time = -fd_log_wallclock();

    int res = fd_runtime_block_execute_prepare( slot_ctx );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      return res;
    }

    ulong txn_cnt = block_info->txn_cnt;
    fd_txn_p_t * txn_ptrs = fd_scratch_alloc( alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );

    fd_runtime_block_collect_txns( block_info, txn_ptrs );

    res = fd_runtime_process_txns_in_waves_tpool( slot_ctx, capture_ctx, txn_ptrs, txn_cnt, tpool, spads, spad_cnt );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      return res;
    }

    long block_finalize_time = -fd_log_wallclock();
    res = fd_runtime_block_execute_finalize_tpool( slot_ctx, capture_ctx, block_info, tpool );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      return res;
    }

    slot_ctx->slot_bank.transaction_count += txn_cnt;

    block_finalize_time += fd_log_wallclock();
    double block_finalize_time_ms = (double)block_finalize_time * 1e-6;
    FD_LOG_INFO(( "finalized block successfully - slot: %lu, elapsed: %6.6f ms", slot_ctx->slot_bank.slot, block_finalize_time_ms ));

    block_execute_time += fd_log_wallclock();
    double block_execute_time_ms = (double)block_execute_time * 1e-6;

    FD_LOG_INFO(( "executed block successfully - slot: %lu, elapsed: %6.6f ms", slot_ctx->slot_bank.slot, block_execute_time_ms ));

    return FD_RUNTIME_EXECUTE_SUCCESS;
  } FD_SCRATCH_SCOPE_END;
}

int
fd_runtime_block_pre_execute_process_new_epoch( fd_exec_slot_ctx_t * slot_ctx ) {
  /* Update block height. */
  slot_ctx->slot_bank.block_height += 1UL;

  if( slot_ctx->slot_bank.slot != 0UL ) {
    ulong             slot_idx;
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    ulong             prev_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.prev_slot, &slot_idx );
    ulong             new_epoch  = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, &slot_idx );
    if( FD_UNLIKELY( slot_idx==1UL && new_epoch==0UL ) ) {
      /* The block after genesis has a height of 1. */
      slot_ctx->slot_bank.block_height = 1UL;
    }

    if( FD_UNLIKELY( prev_epoch<new_epoch || !slot_idx ) ) {
      FD_LOG_DEBUG(("Epoch boundary"));
      /* Epoch boundary! */
      fd_funk_start_write( slot_ctx->acc_mgr->funk );
      fd_runtime_process_new_epoch( slot_ctx, new_epoch - 1UL );
      fd_funk_end_write( slot_ctx->acc_mgr->funk );
    }
  }

  if( slot_ctx->slot_bank.slot != 0UL && (
      FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) ||
      FD_FEATURE_ACTIVE( slot_ctx, partitioned_epoch_rewards_superfeature ) ) ) {
    fd_funk_start_write( slot_ctx->acc_mgr->funk );
    fd_distribute_partitioned_epoch_rewards( slot_ctx );
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_block_eval_tpool( fd_exec_slot_ctx_t * slot_ctx,
                             fd_capture_ctx_t *   capture_ctx,
                             fd_tpool_t *         tpool,
                             ulong                scheduler,
                             ulong *              txn_cnt,
                             fd_spad_t * *        spads,
                             ulong                spad_cnt ) {
  (void)scheduler;

  FD_SCRATCH_SCOPE_BEGIN {

  int err = fd_runtime_publish_old_txns( slot_ctx, capture_ctx, tpool );
  if( err != 0 ) {
    return err;
  }

  fd_funk_t * funk = slot_ctx->acc_mgr->funk;

  ulong slot = slot_ctx->slot_bank.slot;

  long block_eval_time = -fd_log_wallclock();
  fd_block_info_t block_info;
  int ret = FD_RUNTIME_EXECUTE_SUCCESS;
  do {
    if( FD_UNLIKELY( (ret = fd_runtime_block_prepare( slot_ctx->blockstore, slot_ctx->block, slot, fd_scratch_virtual(), &block_info )) != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      break;
    }
    *txn_cnt = block_info.txn_cnt;

    /* Use the blockhash as the funk xid */
    fd_funk_txn_xid_t xid;

    fd_blockstore_start_read( slot_ctx->blockstore );
    fd_hash_t const * hash = fd_blockstore_block_hash_query( slot_ctx->blockstore, slot );
    if( FD_UNLIKELY( !hash ) ) {
      ret = FD_RUNTIME_EXECUTE_GENERIC_ERR;
      FD_LOG_WARNING(( "missing blockhash for %lu", slot ));
      break;
    } else {
      fd_memcpy( xid.uc, hash->uc, sizeof(fd_funk_txn_xid_t) );
      xid.ul[0] = slot_ctx->slot_bank.slot;
      /* push a new transaction on the stack */
      fd_funk_start_write( funk );
      slot_ctx->funk_txn = fd_funk_txn_prepare( funk, slot_ctx->funk_txn, &xid, 1 );
      fd_funk_end_write( funk );
    }
    fd_blockstore_end_read( slot_ctx->blockstore );

    if( FD_UNLIKELY( (ret = fd_runtime_block_pre_execute_process_new_epoch( slot_ctx )) != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      break;
    }

    fd_blockstore_start_read( slot_ctx->blockstore );
    fd_block_t * block = fd_blockstore_block_query( slot_ctx->blockstore, slot );
    fd_blockstore_end_read( slot_ctx->blockstore );
    ulong tick_res = fd_runtime_block_verify_ticks(
      fd_blockstore_block_micro_laddr( slot_ctx->blockstore, block ),
      block->micros_cnt,
      fd_blockstore_block_data_laddr( slot_ctx->blockstore, block ),
      slot_ctx->slot_bank.tick_height,
      slot_ctx->slot_bank.max_tick_height,
      slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick
    );
    if( FD_UNLIKELY( tick_res != FD_BLOCK_OK ) ) {
      FD_LOG_WARNING(( "failed to verify ticks res %lu slot %lu", tick_res, slot ));
      ret = FD_RUNTIME_EXECUTE_GENERIC_ERR;
      break;
    }

    if( FD_UNLIKELY( (ret = fd_runtime_block_verify_tpool( &block_info, &slot_ctx->slot_bank.poh, &slot_ctx->slot_bank.poh, fd_scratch_virtual(), tpool )) != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      break;
    }
    if( FD_UNLIKELY( (ret = fd_runtime_block_execute_tpool( slot_ctx, capture_ctx, &block_info, tpool, spads, spad_cnt )) != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      break;
    }
  } while( 0 );

  // FIXME: better way of using starting slot
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != ret ) ) {
    FD_LOG_WARNING(( "execution failure, code %d", ret ));
    /* Skip over slot next time */
    slot_ctx->slot_bank.slot = slot+1UL;
    return ret;
  }

  block_eval_time          += fd_log_wallclock();
  double block_eval_time_ms = (double)block_eval_time * 1e-6;
  double tps                = (double) block_info.txn_cnt / ((double)block_eval_time * 1e-9);
  FD_LOG_INFO(( "evaluated block successfully - slot: %lu, elapsed: %6.6f ms, signatures: %lu, txns: %lu, tps: %6.6f, bank_hash: %s, leader: %s",
                slot_ctx->slot_bank.slot,
                block_eval_time_ms,
                block_info.signature_cnt,
                block_info.txn_cnt,
                tps,
                FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.banks_hash.hash ),
                FD_BASE58_ENC_32_ALLOCA( fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( slot_ctx->epoch_ctx ), slot_ctx->slot_bank.slot ) ) ));

  slot_ctx->slot_bank.transaction_count += block_info.txn_cnt;

  fd_funk_start_write( slot_ctx->acc_mgr->funk );
  fd_runtime_save_slot_bank( slot_ctx );
  fd_funk_end_write( slot_ctx->acc_mgr->funk );

  slot_ctx->slot_bank.prev_slot = slot;
  // FIXME: this shouldn't be doing this, it doesn't work with forking. punting changing it though
  slot_ctx->slot_bank.slot = slot+1UL;

  } FD_SCRATCH_SCOPE_END;

  return 0;
}

/******************************************************************************/
/* Debugging Tools                                                            */
/******************************************************************************/

static void
fd_runtime_copy_program_data_acc_to_pruned_funk( fd_funk_t *          pruned_funk,
                                                 fd_funk_txn_t *      prune_txn,
                                                 fd_exec_slot_ctx_t * slot_ctx,
                                                 fd_pubkey_t const *  program_pubkey ) {
  /* If account corresponds to bpf_upgradeable, copy over the programdata as well.
     This is necessary for executing any bpf upgradeable program. */

  fd_account_meta_t const * program_acc = fd_acc_mgr_view_raw( slot_ctx->acc_mgr, NULL,
                                                               program_pubkey, NULL, NULL, NULL );

  if( memcmp( program_acc->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = (uchar *)program_acc + program_acc->hlen,
    .dataend = (char *) ctx.data + program_acc->dlen,
    .valloc  = slot_ctx->valloc,
  };

  fd_bpf_upgradeable_loader_state_t loader_state;
  if ( fd_bpf_upgradeable_loader_state_decode( &loader_state, &ctx ) ) {
    FD_LOG_ERR(( "fd_bpf_upgradeable_loader_state_decode failed" ));
  }

  if( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) ) {
    FD_LOG_ERR(( "fd_bpf_upgradeable_loader_state_is_program failed" ));
  }

  fd_pubkey_t * programdata_pubkey = (fd_pubkey_t *)&loader_state.inner.program.programdata_address;
  fd_funk_rec_key_t programdata_reckey = fd_acc_funk_key( programdata_pubkey );

  /* Copy over programdata record */
  fd_funk_rec_t * new_rec_pd = fd_funk_rec_write_prepare( pruned_funk, prune_txn, &programdata_reckey,
                                                          0, 1, NULL, NULL );
  FD_TEST(( !!new_rec_pd ));
}

static void FD_FN_UNUSED
fd_runtime_copy_accounts_to_pruned_funk( fd_funk_t *          pruned_funk,
                                         fd_funk_txn_t *      prune_txn,
                                         fd_exec_slot_ctx_t * slot_ctx,
                                         fd_exec_txn_ctx_t *  txn_ctx ) {
  /* This function is only responsible for copying over the account ids that are
     modified. The account data is copied over after execution is complete. */

  /* Copy over ALUTs */
  fd_txn_acct_addr_lut_t * addr_luts = fd_txn_get_address_tables( (fd_txn_t *) txn_ctx->txn_descriptor );
  for( ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++ ) {
    fd_txn_acct_addr_lut_t * addr_lut = &addr_luts[i];
    fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + addr_lut->addr_off);
    if ( addr_lut_acc ) {
      fd_funk_rec_key_t acc_lut_rec_key = fd_acc_funk_key( addr_lut_acc );
      fd_funk_rec_write_prepare( pruned_funk, prune_txn, &acc_lut_rec_key, 0, 1, NULL, NULL );
    }
  }

  /* Get program id from top level instructions and copy over programdata */
  fd_instr_info_t instrs[txn_ctx->txn_descriptor->instr_cnt];
  for ( ushort i = 0; i < txn_ctx->txn_descriptor->instr_cnt; i++ ) {
    fd_txn_instr_t const * txn_instr = &txn_ctx->txn_descriptor->instr[i];
    fd_convert_txn_instr_to_instr( txn_ctx, txn_instr, txn_ctx->borrowed_accounts, &instrs[i] );
    fd_pubkey_t program_pubkey = instrs[i].program_id_pubkey;
    fd_funk_rec_key_t program_rec_key = fd_acc_funk_key( &program_pubkey );
    fd_funk_rec_t *new_rec = fd_funk_rec_write_prepare(pruned_funk, prune_txn, &program_rec_key, 0, 1, NULL, NULL);
    if ( !new_rec ) {
      FD_LOG_NOTICE(("fd_funk_rec_write_prepare failed %s", FD_BASE58_ENC_32_ALLOCA( &program_pubkey ) ));
      continue;
    }

    /* If account corresponds to bpf_upgradeable, copy over the programdata as well */
    fd_runtime_copy_program_data_acc_to_pruned_funk( pruned_funk, prune_txn, slot_ctx, &program_pubkey );
  }

  /* Write out all accounts touched during the transaction, copy over all program data accounts for
     any BPF upgradeable accounts in case they are a CPI's program account. */
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    fd_pubkey_t * acc_pubkey = (fd_pubkey_t *)&txn_ctx->accounts[i].key;
    fd_funk_rec_key_t rec_key = fd_acc_funk_key( acc_pubkey );
    fd_funk_rec_t * rec = fd_funk_rec_write_prepare( pruned_funk, prune_txn, &rec_key, 0, 1, NULL, NULL );
    FD_TEST(( !!rec ));
    fd_runtime_copy_program_data_acc_to_pruned_funk( pruned_funk, prune_txn, slot_ctx, acc_pubkey );
  }
}

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
      fd_funk_end_write( slot_ctx->acc_mgr->funk );
    } else {
      FD_LOG_NOTICE(( "checkpointing after mismatch to file=%s", capture_ctx->checkpt_path ));
    }

    unlink( capture_ctx->checkpt_path );
    int err = fd_wksp_checkpt( fd_funk_wksp( slot_ctx->acc_mgr->funk ), capture_ctx->checkpt_path, 0666, 0, NULL );
    if ( err ) {
      FD_LOG_ERR(( "backup failed: error %d", err ));
    }

    if( !is_abort_slot ) {
      fd_funk_start_write( slot_ctx->acc_mgr->funk );
    }
  }

}

void
fd_runtime_collect_rent_accounts_prune( ulong slot, fd_exec_slot_ctx_t * slot_ctx, fd_capture_ctx_t * capture_ctx ) {
  /* TODO: Test if this works across epoch boundaries */

  /* As a note, the number of partitions are determined before execution begins.
     The rent accounts for each slot are added to the pruned funk. The data in
     the accounts is populated after execution is completed. */
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank_const( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong off;

  fd_slot_to_epoch( schedule, slot, &off );

  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  for (fd_funk_rec_t const *rec_ro = fd_funk_part_head(partvec, (uint)off, rec_map);
      rec_ro != NULL;
      rec_ro = fd_funk_part_next(rec_ro, rec_map)) {

    fd_pubkey_t const * key = fd_type_pun_const(rec_ro->pair.key[0].uc);
    fd_funk_rec_key_t rec_key = fd_acc_funk_key( key );

    fd_funk_txn_xid_t prune_xid;
    fd_memset( &prune_xid, 0x42, sizeof(fd_funk_txn_xid_t));

    fd_funk_txn_t * txn_map = fd_funk_txn_map( capture_ctx->pruned_funk, fd_funk_wksp( capture_ctx->pruned_funk ) );
    fd_funk_txn_t * prune_txn = fd_funk_txn_query( &prune_xid, txn_map );

    fd_funk_rec_t * rec = fd_funk_rec_write_prepare( capture_ctx->pruned_funk, prune_txn, &rec_key, 0, 1, NULL, NULL );
    FD_TEST(( !!rec ));

    int res = fd_funk_part_set( capture_ctx->pruned_funk, rec, (uint)off );
    FD_TEST(( res == 0 ));
  }
}

// TODO: add tracking account_state hashes so that we can verify our
// banks hash... this has interesting threading implications since we
// could execute the cryptography in another thread for tracking this
// but we don't actually have anything to compare it to until we hit
// another snapshot...  Probably we should just store the results into
// the slot_ctx state (a slot/hash map)?
//
// What slots exactly do cache'd account_updates go into?  how are
// they hashed (which slot?)?
