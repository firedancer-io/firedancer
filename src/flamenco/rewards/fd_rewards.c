#include "fd_rewards.h"
#include "fd_stake_rewards.h"
#include "fd_reward_epoch_delegated_stakes.h"
#include "fd_epoch_inflation_account.h"

#include "../runtime/sysvar/fd_sysvar_epoch_rewards.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"
#include "../runtime/fd_hashes.h"
#include "../../ballet/lthash/fd_lthash_adder.h"
#include "../stakes/fd_stakes.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/fd_system_ids.h"
#include "../capture/fd_capture_ctx.h"
#include "../runtime/fd_runtime_stack_tmpl.h"
#include "../runtime/fd_accdb_svm.h"
#include "fd_rewards_base.h"
#include "../events/fd_event_runtime.h"

#include <math.h>

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/feature-set/src/lib.rs#L1537-L1541 */
#define FD_DOUBLE_DISINFLATION_TAPER (0.30)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/inflation.rs#L85 */
static double
total( fd_inflation_t const * inflation, double year ) {
  double tapered = inflation->initial * pow( (1.0 - inflation->taper), year );
  return (tapered > inflation->terminal) ? tapered : inflation->terminal;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/inflation.rs#L102 */
static double
foundation( fd_inflation_t const * inflation, double year ) {
  return (year < inflation->foundation_term) ? inflation->foundation * total(inflation, year) : 0.0;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/inflation.rs#L97 */
static double
validator( fd_inflation_t const * inflation, double year) {
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/sdk/src/inflation.rs#L96-L99 */
  FD_LOG_DEBUG(("Validator Rate: %.16f %.16f %.16f %.16f %.16f", year, total( inflation, year ), foundation( inflation, year ), inflation->taper, inflation->initial));
  /* We need 2 independent rounded ops like in Agave. Volatile blocks FMA contraction.
     https://github.com/anza-xyz/solana-sdk/blob/inflation%40v3.1.1/inflation/src/lib.rs#L105-L116 */
  volatile double foundation_portion = foundation( inflation, year );
  return total( inflation, year ) - foundation_portion;
}

/* Calculates the starting slot for inflation from the activation slot. The activation slot is the earliest
    activation slot of the following features:
    - devnet_and_testnet
    - full_inflation_enable, if full_inflation_vote has been activated

    https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2095 */
static FD_FN_PURE ulong
get_inflation_start_slot( fd_bank_t const * bank ) {
  ulong devnet_and_testnet = FD_FEATURE_ACTIVE_BANK( bank, devnet_and_testnet )
      ? bank->f.features.devnet_and_testnet
      : ULONG_MAX;

  ulong enable = bank->f.features.full_inflation_enable;

  ulong min_slot = fd_ulong_min( enable, devnet_and_testnet );
  if( min_slot == ULONG_MAX ) {
    if( FD_FEATURE_ACTIVE_BANK( bank, pico_inflation ) ) {
      min_slot = bank->f.features.pico_inflation;
    } else {
      min_slot = 0;
    }
  }
  return min_slot;
}

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/bank.rs#L2921-L2928 */
static ulong
inflation_start_slot_aligned_to_rewards( fd_bank_t const *           bank,
                                         fd_epoch_schedule_t const * epoch_schedule ) {
  ulong inflation_activation_slot = get_inflation_start_slot( bank );
  return fd_epoch_slot0( epoch_schedule,
                         fd_ulong_sat_sub( fd_slot_to_epoch( epoch_schedule, inflation_activation_slot, NULL ), 1UL ) );
}

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/bank.rs#L2915-L2918 */
static ulong
get_inflation_num_slots( fd_bank_t const *           bank,
                         fd_epoch_schedule_t const * epoch_schedule,
                         ulong                       slot ) {
  ulong inflation_start_slot = inflation_start_slot_aligned_to_rewards( bank, epoch_schedule );
  return fd_epoch_slot0( epoch_schedule, fd_slot_to_epoch( epoch_schedule, slot, NULL ) ) - inflation_start_slot;
}

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/bank.rs#L2931-L2935 */
static double
slot_in_year_for_inflation( fd_bank_t const * bank ) {
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong num_slots            = get_inflation_num_slots( bank, epoch_schedule, bank->f.slot );
  ulong inflation_start_slot = inflation_start_slot_aligned_to_rewards( bank, epoch_schedule );
  return fd_slot_params_slot_range_duration_years( bank,
                                                   inflation_start_slot, inflation_start_slot + num_slots );
}

void
fd_apply_double_disinflation_rate( fd_bank_t * bank ) {
  double           year        = slot_in_year_for_inflation( bank );
  fd_inflation_t * inflation   = &bank->f.inflation;
  double           anchor_rate = total( inflation, year );

  inflation->taper   = FD_DOUBLE_DISINFLATION_TAPER;

  /* Matches Agave's calculation, as this is floating-point calculation
     https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/bank.rs#L6125 */
  inflation->initial = anchor_rate / pow( 1.0-FD_DOUBLE_DISINFLATION_TAPER, year );
}

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/inflation_rewards/mod.rs#L412-L440 */
static void
fd_vote_commission_split_preserve_lamports( ushort                  commission,
                                            ulong                   on,
                                            fd_commission_split_t * result ) {
  ushort commission_split = fd_ushort_min( commission, 10000U );
  switch( commission_split ) {
  case 0U:
    *result = (fd_commission_split_t){ .voter_portion=0UL, .staker_portion=on, .is_split=0U };
    break;
  case 10000U:
    *result = (fd_commission_split_t){ .voter_portion=on, .staker_portion=0UL, .is_split=0U };
    break;
  default:
    result->staker_portion = (ulong)( (uint128)on *
                                      (uint128)(10000U-commission_split) /
                                      (uint128)10000U );
    result->voter_portion  = on-result->staker_portion;
    result->is_split       = 1U;
    break;
  }
}

/* Validates an external SIMD-0232 inflation commission collector
   after all rewards routed to it have been added.  Returns 0 to
   deposit, 1 to burn.  The vote account itself is always valid and
   must not be passed here.
   https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime/src/bank/fee_distribution.rs#L231-L270 */
static int
fd_rewards_validate_commission_collector( fd_bank_t const *   bank,
                                          fd_pubkey_t const * collector,
                                          fd_acc_t const *    account,
                                          ulong               rewards ) {
  /* Must be a system program owned account. */
  if( FD_UNLIKELY( memcmp( account->owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) ) ) ) return 1;

  /* Must not be a reserved account. */
  if( FD_UNLIKELY( fd_pubkey_is_active_reserved_key( collector ) ||
                   fd_pubkey_is_pending_reserved_key( collector ) ) ) return 1;

  ulong post_balance;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( account->lamports, rewards, &post_balance ) ) ) return 1;

  /* The incinerator is exempt from the rent check so the deposit
     always works.  Incinerator funds are burned at the end of the
     rewards distribution block. */
  if( FD_UNLIKELY( fd_pubkey_eq( collector, &fd_sysvar_incinerator_id ) ) ) return 0;

  /* Must be rent-exempt after the deposit.  With
     relax_post_exec_min_balance_check (SIMD-0392) a pre-existing
     account may stay rent-paying. */
  int is_rent_exempt = post_balance>=fd_rent_exempt_minimum_balance( &bank->f.rent, account->data_len );
  return !is_rent_exempt &&
         ( !FD_FEATURE_ACTIVE_BANK( bank, relax_post_exec_min_balance_check ) || !account->lamports );
}

/* Resolves the SIMD-0232 inflation commission collector from the vote
   account state at the start of the distribution epoch (the t-1 vote
   stakes set); defaults to the vote account.
   https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L667-L672 */
static void
fd_rewards_inflation_collector( fd_bank_t *         bank,
                                fd_pubkey_t const * vote_pubkey,
                                fd_pubkey_t *       collector_out ) {
  fd_vote_stakes_ele_t ele[1];
  if( fd_vote_stakes_query_t_1( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id, vote_pubkey, ele ) ) {
    *collector_out = ele->inflation_collector;
  } else {
    *collector_out = *vote_pubkey;
  }
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L33
   https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/inflation_rewards/mod.rs#L204-L371 */
static int
redeem_rewards( fd_stake_delegation_t const *   stake,
                ulong                           vote_state_idx,
                ulong                           rewarded_epoch,
                ulong                           total_rewards,
                fd_runtime_stack_t *            runtime_stack,
                fd_calculated_stake_points_t *  stake_points_result,
                fd_calculated_stake_rewards_t * result ) {

  /* The firedancer implementation of redeem_rewards inlines a lot of
     the helper functions that the Agave implementation uses.
     In Agave: redeem_rewards calls redeem_stake_rewards which calls
     calculate_stake_rewards. */

  // Drive credits_observed forward unconditionally when rewards are disabled
  // or when this is the stake's activation epoch
  if( total_rewards==0UL || stake->activation_epoch==rewarded_epoch ) {
    stake_points_result->force_credits_update_with_skipped_reward = 1;
  }

  if( stake_points_result->force_credits_update_with_skipped_reward ) {
    result->staker_rewards       = 0;
    result->voter_rewards        = 0;
    result->new_credits_observed = stake_points_result->new_credits_observed;
    return 0;
  }
  if( stake_points_result->points.ud==0 ) {
    if( stake_points_result->new_credits_observed!=stake->credits_observed ) {
      /* Don't update credits_observed if the delegation is inactive.

         TODO: remove this after remove_inactive_stakes is active
         everywhere.

         https://github.com/anza-xyz/agave/blob/v4.3.0-beta.3/runtime/src/inflation_rewards/mod.rs#L255-L258 */
      if( FD_LIKELY( stake_points_result->inactive ) ) {
        return 1;
      }
      result->staker_rewards       = 0UL;
      result->voter_rewards        = 0UL;
      result->new_credits_observed = stake_points_result->new_credits_observed;
      return 0;
    }
    return 1;
  }

  if( FD_UNLIKELY( stake_points_result->points.ud>(uint128)ULONG_MAX ) ) {
    FD_LOG_ERR(( "Rewards should fit within u64" ));
  }

  fd_commission_split_t split_result;
  fd_vote_commission_split_preserve_lamports( runtime_stack->stakes.vote_ele[ vote_state_idx ].commission,
                                              (ulong)stake_points_result->points.ud,
                                              &split_result );

  result->staker_rewards       = split_result.staker_portion;
  result->voter_rewards        = split_result.voter_portion;
  result->new_credits_observed = stake_points_result->new_credits_observed;
  return 0;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L2082 */
static double
epoch_duration_in_years( fd_bank_t const * bank,
                         ulong             prev_epoch ) {
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong                       slots_in_epoch = fd_epoch_slot_cnt( epoch_schedule, prev_epoch );
  double                      slots_per_year = fd_slot_params_at_slot( bank,
                                                                       fd_epoch_slot0( epoch_schedule, prev_epoch ) ).slots_per_year;
  return (double)slots_in_epoch / slots_per_year;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2128 */
static void
calculate_previous_epoch_inflation_rewards( fd_bank_t const *                   bank,
                                            ulong                               prev_epoch_capitalization,
                                            ulong                               prev_epoch,
                                            fd_prev_epoch_inflation_rewards_t * rewards ) {
  double slot_in_year = slot_in_year_for_inflation( bank );

  rewards->validator_rate               = validator( &bank->f.inflation, slot_in_year );
  rewards->foundation_rate              = foundation( &bank->f.inflation, slot_in_year );
  rewards->prev_epoch_duration_in_years = epoch_duration_in_years( bank, prev_epoch );
  rewards->validator_rewards            = (ulong)(rewards->validator_rate * (double)prev_epoch_capitalization * rewards->prev_epoch_duration_in_years);
  FD_LOG_DEBUG(( "Rewards %lu, Rate %.16f, Duration %.18f Capitalization %lu Slot in year %.16f", rewards->validator_rewards, rewards->validator_rate, rewards->prev_epoch_duration_in_years, prev_epoch_capitalization, slot_in_year ));
}

/* Calculate the number of blocks required to distribute rewards to all stake accounts.

    https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L214
 */
static uint
get_reward_distribution_num_blocks( fd_epoch_schedule_t const * epoch_schedule,
                                    ulong                       slot,
                                    ulong                       total_stake_accounts,
                                    ulong                       stake_account_stores_per_block ) {
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1250-L1267 */
  if( epoch_schedule->warmup &&
      fd_slot_to_epoch( epoch_schedule, slot, NULL ) < epoch_schedule->first_normal_epoch ) {
    return 1UL;
  }

  FD_TEST( stake_account_stores_per_block );
  ulong num_chunks = total_stake_accounts / stake_account_stores_per_block + (total_stake_accounts % stake_account_stores_per_block != 0);
  num_chunks       = fd_ulong_max( num_chunks, 1UL );
  num_chunks       = fd_ulong_min( num_chunks,
                                   fd_ulong_max( epoch_schedule->slots_per_epoch / (ulong)MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH, 1UL ) );
  return (uint)num_chunks;
}

uint
fd_rewards_get_reward_distribution_num_blocks( fd_epoch_schedule_t const * epoch_schedule,
                                               ulong                       slot,
                                               ulong                       total_stake_accounts,
                                               ulong                       stake_account_stores_per_block ) {
  return get_reward_distribution_num_blocks( epoch_schedule, slot, total_stake_accounts, stake_account_stores_per_block );
}

static void
read_stake_history( fd_accdb_t *         accdb,
                    fd_accdb_fork_id_t   fork_id,
                    uchar                data[ static FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ],
                    fd_stake_history_t * stake_history ) {
  fd_acc_t ro = fd_accdb_read_one( accdb, fork_id, fd_sysvar_stake_history_id.uc );
  if( FD_UNLIKELY( !ro.lamports ) ) FD_LOG_ERR(( "Unable to read stake history sysvar" ));
  ulong copy_sz = fd_ulong_min( ro.data_len, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  fd_memcpy( data, ro.data, copy_sz );
  fd_accdb_unread_one( accdb, &ro );
  if( FD_UNLIKELY( !fd_sysvar_stake_history_view( stake_history, data, copy_sz ) ) ) {
    FD_LOG_ERR(( "Unable to decode stake history sysvar" ));
  }
}

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/inflation_rewards/points.rs#L236-L312 */
static void
calculate_alpenglow_points( fd_epoch_credits_t const *    epoch_credits,
                            fd_stake_history_t const *    stake_history,
                            fd_stake_delegation_t const * stake,
                            ulong *                       new_rate_activation_epoch,
                            int                           use_fixed_point_stake_math,
                            ulong                         rewarded_epoch,
                            ulong                         validator_reward_epoch_stake,
                            fd_calculated_stake_points_t * result ) {
  ulong credits_in_stake = stake->credits_observed;
  ulong cnt              = epoch_credits->cnt;
  ulong base             = epoch_credits->base_credits;
  ulong credits_in_vote  = cnt ? base+epoch_credits->credits_delta[ cnt-1UL ] : 0UL;

  result->points.ud                                = 0;
  result->new_credits_observed                     = credits_in_stake;
  result->force_credits_update_with_skipped_reward = 0;
  result->inactive                                 = 0;

  if( FD_UNLIKELY( credits_in_vote<credits_in_stake ) ) {
    result->new_credits_observed                     = credits_in_vote;
    result->force_credits_update_with_skipped_reward = 1;
    return;
  }
  if( FD_UNLIKELY( credits_in_vote==credits_in_stake || !cnt ) ) return;

  ulong idx = cnt-1UL;
  if( FD_UNLIKELY( (ulong)epoch_credits->epoch[ idx ]!=rewarded_epoch ) ) return;

  ulong initial_epoch_credits = base+epoch_credits->prev_credits_delta[ idx ];
  ulong earned_credits;
  if( credits_in_stake<initial_epoch_credits ) {
    earned_credits = credits_in_vote-initial_epoch_credits;
  } else {
    earned_credits = credits_in_vote-credits_in_stake;
  }
  result->new_credits_observed = credits_in_vote;

  fd_stake_history_entry_t status = fd_stake_delegation_activation_status(
      stake,
      rewarded_epoch,
      stake_history,
      new_rate_activation_epoch,
      use_fixed_point_stake_math );
  result->inactive = (uchar)( !status.effective && !status.activating );

  if( FD_UNLIKELY( !earned_credits ) ) return;
  if( FD_UNLIKELY( !status.effective ) ) return;

  if( FD_UNLIKELY( !validator_reward_epoch_stake ) ) {
    result->force_credits_update_with_skipped_reward = 1;
    return;
  }

  result->points.ud = (uint128)earned_credits *
                      (uint128)status.effective /
                      (uint128)validator_reward_epoch_stake;
}

static inline void
calculate_stake_points_for_reward( fd_runtime_stack_t *           runtime_stack,
                                   fd_epoch_credits_t const *     epoch_credits,
                                   fd_stake_history_t const *     stake_history,
                                   fd_stake_delegation_t const *  stake,
                                   ulong *                        new_rate_activation_epoch,
                                   int                            use_fixed_point_stake_math,
                                   ulong                          rewarded_epoch,
                                   fd_calculated_stake_points_t * result ) {
  ulong                    validator_reward_epoch_stake = 0UL;
  fd_stake_accum_t const * accumulated                  = fd_stake_accum_map_ele_query_const(
      runtime_stack->stakes.stake_accum_map,
      &stake->vote_account,
      NULL,
      runtime_stack->stakes.stake_accum );
  if( accumulated ) validator_reward_epoch_stake = accumulated->reward_stake;
  calculate_alpenglow_points( epoch_credits,
                              stake_history,
                              stake,
                              new_rate_activation_epoch,
                              use_fixed_point_stake_math,
                              rewarded_epoch,
                              validator_reward_epoch_stake,
                              result );
}

/* Calculates the reward points of the first max_stake_accounts stake
   delegations into runtime_stack's stake points cache.
   https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L445 */
static void
calculate_reward_points_partitioned( fd_bank_t *                    bank,
                                     fd_stake_delegations_t const * stake_delegations,
                                     fd_stake_history_t const *     stake_history,
                                     ulong                          rewarded_epoch,
                                     fd_runtime_stack_t *           runtime_stack ) {
  fd_vote_rewards_t *     vote_ele     = runtime_stack->stakes.vote_ele;
  fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;

  fd_epoch_credits_view_t epoch_credits_view[1];
  FD_TEST( fd_epoch_credits_view_init( epoch_credits_view, fd_bank_epoch_credits( bank ), bank->epoch_credits_fork_id ) );
  fd_epoch_credits_t * epoch_credits_arr = epoch_credits_view->credits;

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation     = fd_stake_delegations_iter_ele( iter );
    ulong                         stake_delegation_idx = fd_stake_delegations_iter_idx( iter );
    if( FD_UNLIKELY( stake_delegation_idx>=runtime_stack->max_stake_accounts ) ) continue;
    fd_calculated_stake_points_t * stake_points_result = &runtime_stack->stakes.stake_points_result[ stake_delegation_idx ];

    if( FD_UNLIKELY( FD_FEATURE_ACTIVE_BANK( bank, remove_inactive_stakes ) &&
                     fd_stake_delegation_is_inactive( stake_delegation, rewarded_epoch, stake_history, &bank->f.warmup_cooldown_rate_epoch,
                                                      FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ) ) ) ) {
      stake_points_result->vote_idx = UINT_MAX;
      continue;
    }

    /* Note that we don't check minimum delegation here, as there are
       no plans to activate stake_minimum_delegation_for_rewards.
       If this changes we need to skip stake accounts that are
       below the minimum delegation here. However we don't do this yet,
       to ensure that we audit the feature properly if this happens. */

    uint idx = (uint)fd_vote_rewards_map_idx_query( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
    stake_points_result->vote_idx = idx;
    if( FD_UNLIKELY( idx==UINT_MAX ) ) continue;

    calculate_stake_points_for_reward( runtime_stack,
                                       &epoch_credits_arr[ idx ],
                                       stake_history,
                                       stake_delegation,
                                       &bank->f.warmup_cooldown_rate_epoch,
                                       FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
                                       rewarded_epoch,
                                       stake_points_result );
  }

  fd_epoch_credits_view_fini( epoch_credits_view );
}

/* https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/inflation_rewards/mod.rs#L161-L173 */
static int
delegation_may_need_adjustment( fd_bank_t *                   bank,
                                fd_stake_delegation_t const * stake_delegation,
                                fd_stake_history_t const *    stake_history,
                                ulong                         rewarded_epoch,
                                ulong                         new_delegation_with_rewards,
                                ulong                         lamports_with_rewards,
                                ulong                         minimum_lamports ) {
  ulong new_delegation = fd_ulong_min(
    new_delegation_with_rewards,
    fd_ulong_sat_sub( lamports_with_rewards, minimum_lamports )
  );

  if( FD_LIKELY( new_delegation==stake_delegation->stake ) ) return 0;

  /* Delegations that are neither effective nor activating are left
     alone.  This is checked last because it can walk many stake history
     entries. */
  fd_stake_history_entry_t status = fd_stake_delegation_activation_status(
    stake_delegation,
    rewarded_epoch,
    stake_history,
    &bank->f.warmup_cooldown_rate_epoch,
    FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ) );

  return !( status.effective==0UL && status.activating==0UL );
}

/* Calculates block reward for a stake account based on SIMD-0123.
   https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L173 */
static ulong
calculate_block_reward( fd_bank_t *                   bank,
                        fd_runtime_stack_t *          runtime_stack,
                        fd_stake_history_t const *    stake_history,
                        fd_stake_delegation_t const * stake_delegation,
                        ulong                         rewarded_epoch ) {
  fd_pubkey_t const * vote_pubkey = &stake_delegation->vote_account;
  fd_vote_stakes_ele_t ele[1];
  if( !fd_vote_stakes_query_t_1( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id, vote_pubkey, ele ) ) {
    return 0UL;
  }
  ulong pending_delegator_rewards = ele->pending_delegator_rewards;
  fd_stake_accum_t const * accumulated = fd_stake_accum_map_ele_query_const(
      runtime_stack->stakes.stake_accum_map, vote_pubkey, NULL, runtime_stack->stakes.stake_accum );
  ulong total_active_stake = accumulated ? accumulated->reward_stake : 0UL;
  if( total_active_stake==0UL ) return 0UL;

  ulong stake = fd_stake_delegation_activation_status( stake_delegation,
                                                       rewarded_epoch,
                                                       stake_history,
                                                       &bank->f.warmup_cooldown_rate_epoch,
                                                       FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ) ).effective;
  /* During recalculation, if stake account has already received rewards,
     it's possible to have `stake > total_active_stake`. If
     `pending_delegator_rewards` is a huge number, we could potentially
     overflow a `u64`. We can also have individual rewards look greater
     than the pending rewards. This is harmless in practice, but we
     clamp it just to be safe */
  uint128 reward = (uint128)pending_delegator_rewards * (uint128)stake / (uint128)total_active_stake;
  return fd_ulong_min( reward>(uint128)ULONG_MAX ? ULONG_MAX : (ulong)reward, pending_delegator_rewards );
}

/* Calculates epoch rewards for stake/vote accounts.
   Returns vote rewards, stake rewards, and the sum of all stake rewards
   in lamports.

   In the future, the calculation will be cached in the snapshot, but
   for now we just re-calculate it (as Agave does).
   calculate_stake_vote_rewards is responsible for calculating
   stake account rewards based off of a combination of the
   stake delegation state as well as the vote account. If this
   calculation is done at the end of an epoch, we can just use the
   vote states at the end of the current epoch. However, because we
   are presumably booting up a node in the middle of rewards
   distribution, we need to make sure that we are using the vote
   states from the end of the previous epoch.

   https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L323 */
static void
calculate_stake_vote_rewards( fd_bank_t *                    bank,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_capture_ctx_t *             capture_ctx FD_PARAM_UNUSED,
                              fd_stake_history_t const *     stake_history,
                              ulong                          rewarded_epoch,
                              ulong                          total_rewards,
                              fd_runtime_stack_t *           runtime_stack,
                              int                            is_recalculation ) {

  runtime_stack->stakes.stake_rewards_cnt = 0UL;

  int block_revenue_sharing = FD_FEATURE_ACTIVE_BANK( bank, block_revenue_sharing );

  fd_calculated_stake_rewards_t calculated_stake_rewards_[1];
  fd_epoch_credits_view_t       epoch_credits_view[1];
  FD_TEST( fd_epoch_credits_view_init( epoch_credits_view, fd_bank_epoch_credits( bank ), bank->epoch_credits_fork_id ) );
  fd_epoch_credits_t * epoch_credits_arr = epoch_credits_view->credits;

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation     = fd_stake_delegations_iter_ele( iter );
    ulong                         stake_delegation_idx = fd_stake_delegations_iter_idx( iter );

    /* Note that we don't check minimum delegation here, as there are
       no plans to activate stake_minimum_delegation_for_rewards.
       If this changes we need to skip stake accounts that are
       below the minimum delegation here. However we don't do this yet,
       to ensure that we audit the feature properly if this happens. */

    fd_calculated_stake_rewards_t * calculated_stake_rewards = NULL;
    if( stake_delegation_idx>=runtime_stack->max_stake_accounts ) {
      calculated_stake_rewards = calculated_stake_rewards_;
    } else {
      calculated_stake_rewards = &runtime_stack->stakes.stake_rewards_result[ stake_delegation_idx ];
    }
    calculated_stake_rewards->success = 0;


    if( FD_UNLIKELY( FD_FEATURE_ACTIVE_BANK( bank, remove_inactive_stakes ) &&
                     fd_stake_delegation_is_inactive( stake_delegation, rewarded_epoch, stake_history, &bank->f.warmup_cooldown_rate_epoch,
                                                      FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ) ) ) ) {
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L856-L867 */
    ulong block_reward = block_revenue_sharing ? calculate_block_reward( bank, runtime_stack, stake_history, stake_delegation, rewarded_epoch ) : 0UL;

    int cached = !is_recalculation && stake_delegation_idx<runtime_stack->max_stake_accounts;
    uint idx;
    if( FD_LIKELY( cached ) ) {
      idx = runtime_stack->stakes.stake_points_result[ stake_delegation_idx ].vote_idx;
    } else {
      fd_vote_rewards_t *     vote_ele     = runtime_stack->stakes.vote_ele;
      fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;
      idx = (uint)fd_vote_rewards_map_idx_query( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
    }

    /* Stake account may need to be adjusted to meet rent-exempt minimum
       balance requirements based on new rent and delegation parameters.
       https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L568-L608 */
    if( FD_UNLIKELY( idx==UINT_MAX ) ) {
      /* If the stake account's resulting lamports would cause it to be
         below the rent exempt minimum balance, it needs to be queued
         for update (and thus affects the epoch reward partitions). */
      int may_need_adjustment = delegation_may_need_adjustment(
          bank,
          stake_delegation,
          stake_history,
          rewarded_epoch,
          stake_delegation->stake,
          stake_delegation->lamports,
          fd_rent_exempt_minimum_balance( &bank->f.rent, stake_delegation->acc_dlen ) );
      if( !may_need_adjustment && !block_reward ) continue;

      /* Place an empty entry for this stake delegation idx so that
         the partitioning logic factors it in. */
      *calculated_stake_rewards = (fd_calculated_stake_rewards_t){
        .success              = 1,
        .staker_rewards       = 0,
        .voter_rewards        = 0,
        .new_credits_observed = stake_delegation->credits_observed,
        .block_reward         = block_reward
      };
      runtime_stack->stakes.stake_rewards_cnt++;
      continue;
    }

    fd_calculated_stake_points_t   stake_points_result_[1];
    fd_calculated_stake_points_t * stake_points_result;
    if( FD_LIKELY( cached ) ) {
      stake_points_result = &runtime_stack->stakes.stake_points_result[ stake_delegation_idx ];
    } else {
      /* We have not cached the stake points yet if we are recalculating
         stake rewards so we need to recalculate them. */
      calculate_stake_points_for_reward( runtime_stack,
                                         &epoch_credits_arr[ idx ],
                                         stake_history,
                                         stake_delegation,
                                         &bank->f.warmup_cooldown_rate_epoch,
                                         FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
                                         rewarded_epoch,
                                         stake_points_result_ );
      stake_points_result = stake_points_result_;
    }

    /* redeem_rewards is actually just responsible for calculating the
       vote and stake rewards for each stake account.  It does not do
       rewards redemption: it is a misnomer. */
    int err = redeem_rewards(
        stake_delegation,
        idx,
        rewarded_epoch,
        total_rewards,
        runtime_stack,
        stake_points_result,
        calculated_stake_rewards );

    if( FD_UNLIKELY( err!=0 ) ) {
      /* Even if there is an error computing rewards for the stake
         account, there may be a required balance update for the stake
         account if rent increased.
         https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/inflation_rewards/mod.rs#L132-L152 */
      int may_need_adjustment = delegation_may_need_adjustment(
          bank,
          stake_delegation,
          stake_history,
          rewarded_epoch,
          stake_delegation->stake,
          stake_delegation->lamports,
          fd_rent_exempt_minimum_balance( &bank->f.rent, stake_delegation->acc_dlen ) );
      if( !may_need_adjustment && !block_reward ) continue;

      *calculated_stake_rewards = (fd_calculated_stake_rewards_t){
        .success              = 1,
        .staker_rewards       = 0,
        .voter_rewards        = 0,
        .new_credits_observed = stake_delegation->credits_observed,
        .block_reward         = block_reward
      };
    } else {
      calculated_stake_rewards->success      = 1;
      calculated_stake_rewards->block_reward = block_reward;
    }

    if( capture_ctx && capture_ctx->capture_solcap ) {
      fd_capture_link_write_stake_reward_event( capture_ctx,
                                                bank->f.slot,
                                                stake_delegation->stake_account,
                                                stake_delegation->vote_account,
                                                runtime_stack->stakes.vote_ele[ idx ].commission,
                                                (long)calculated_stake_rewards->voter_rewards,
                                                (long)calculated_stake_rewards->staker_rewards,
                                                (long)calculated_stake_rewards->new_credits_observed );
    }

    runtime_stack->stakes.vote_ele[ idx ].vote_rewards += calculated_stake_rewards->voter_rewards;
    runtime_stack->stakes.stake_rewards_cnt++;
  }
  fd_epoch_credits_view_fini( epoch_credits_view );
}

/* setup_stake_partitions hashes every stake reward of the epoch into
   its partition.  Only the rewards landing inside the fork's current
   window are retained; see fd_stake_rewards.h.  The fork must already
   have been initialized and its window positioned by the caller. */

static void
setup_stake_partitions( fd_bank_t *                    bank,
                        fd_stake_history_t const *     stake_history,
                        fd_stake_delegations_t const * stake_delegations,
                        fd_runtime_stack_t *           runtime_stack,
                        ushort                         fork_idx,
                        ulong                          rewarded_epoch,
                        ulong                          total_rewards ) {

  int block_revenue_sharing = FD_FEATURE_ACTIVE_BANK( bank, block_revenue_sharing );

  fd_stake_rewards_t * stake_rewards     = fd_bank_stake_rewards_modify( bank );
  fd_epoch_credits_view_t epoch_credits_view[1];
  FD_TEST( fd_epoch_credits_view_init( epoch_credits_view, fd_bank_epoch_credits( bank ), bank->epoch_credits_fork_id ) );
  fd_epoch_credits_t * epoch_credits_arr = epoch_credits_view->credits;

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation     = fd_stake_delegations_iter_ele( iter );
    ulong                         stake_delegation_idx = fd_stake_delegations_iter_idx( iter );

    if( FD_UNLIKELY( FD_FEATURE_ACTIVE_BANK( bank, remove_inactive_stakes ) &&
                     fd_stake_delegation_is_inactive( stake_delegation, rewarded_epoch, stake_history, &bank->f.warmup_cooldown_rate_epoch,
                                                      FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ) ) ) ) {
      continue;
    }

    fd_calculated_stake_rewards_t calculated_stake_rewards_[1];
    fd_calculated_stake_rewards_t * calculated_stake_rewards = NULL;

    if( FD_UNLIKELY( stake_delegation_idx>=runtime_stack->max_stake_accounts ) ) {

      calculated_stake_rewards = calculated_stake_rewards_;

      /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L856-L867 */
      ulong block_reward = block_revenue_sharing ? calculate_block_reward( bank, runtime_stack, stake_history, stake_delegation, rewarded_epoch ) : 0UL;

      fd_vote_rewards_t * vote_ele = runtime_stack->stakes.vote_ele;
      fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;
      uint idx = (uint)fd_vote_rewards_map_idx_query( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
      if( FD_UNLIKELY( idx==UINT_MAX ) ) {
        /* If the stake account's resulting lamports would cause it to be
           below the rent exempt minimum balance, it needs to be queued
           for update (and thus affects the epoch reward partitions). */
        int may_need_adjustment = delegation_may_need_adjustment(
            bank,
            stake_delegation,
            stake_history,
            rewarded_epoch,
            stake_delegation->stake,
            stake_delegation->lamports,
            fd_rent_exempt_minimum_balance( &bank->f.rent, stake_delegation->acc_dlen ) );
        if( !may_need_adjustment && !block_reward ) continue;

        fd_stake_rewards_insert( stake_rewards, fork_idx, &stake_delegation->stake_account, 0UL, stake_delegation->credits_observed, block_reward );
        continue;
      }

      fd_calculated_stake_points_t stake_points_result[1];
      calculate_stake_points_for_reward( runtime_stack,
                                         &epoch_credits_arr[ idx ],
                                         stake_history,
                                         stake_delegation,
                                         &bank->f.warmup_cooldown_rate_epoch,
                                         FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
                                         rewarded_epoch,
                                         stake_points_result );

      /* redeem_rewards is actually just responsible for calculating the
         vote and stake rewards for each stake account.  It does not do
         rewards redemption: it is a misnomer. */
      int err = redeem_rewards(
          stake_delegation,
          idx,
          rewarded_epoch,
          total_rewards,
          runtime_stack,
          stake_points_result,
          calculated_stake_rewards );

      if( FD_UNLIKELY( err!=0 ) ) {
        /* Even if there is an error computing rewards for the stake
           account, there may be a required balance update for the stake
           account if rent increased.
           https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/inflation_rewards/mod.rs#L132-L152 */
        int may_need_adjustment = delegation_may_need_adjustment(
            bank,
            stake_delegation,
            stake_history,
            rewarded_epoch,
            stake_delegation->stake,
            stake_delegation->lamports,
            fd_rent_exempt_minimum_balance( &bank->f.rent, stake_delegation->acc_dlen ) );
        if( !may_need_adjustment && !block_reward ) continue;

        fd_stake_rewards_insert( stake_rewards, fork_idx, &stake_delegation->stake_account, 0UL, stake_delegation->credits_observed, block_reward );
        continue;
      } else {
        calculated_stake_rewards->success      = 1;
        calculated_stake_rewards->block_reward = block_reward;
      }
    } else {
      calculated_stake_rewards = &runtime_stack->stakes.stake_rewards_result[ stake_delegation_idx ];
    }

    if( FD_UNLIKELY( !calculated_stake_rewards->success ) ) continue;

    fd_stake_rewards_insert(
      stake_rewards,
      fork_idx,
      &stake_delegation->stake_account,
      calculated_stake_rewards->staker_rewards,
      calculated_stake_rewards->new_credits_observed,
      calculated_stake_rewards->block_reward
    );
  }

  fd_stake_rewards_fini( stake_rewards, fork_idx );
  fd_epoch_credits_view_fini( epoch_credits_view );
}

/* Calculate epoch reward and return vote and stake rewards.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L273 */
static void
calculate_validator_rewards( fd_bank_t *                    bank,
                             fd_accdb_t *                   accdb,
                             fd_runtime_stack_t *           runtime_stack,
                             fd_stake_delegations_t const * stake_delegations,
                             fd_capture_ctx_t *             capture_ctx,
                             ulong                          rewarded_epoch,
                             ulong                          total_rewards ) {
  uchar              stake_history_data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_stake_history_t stake_history[1];
  read_stake_history( accdb, bank->accdb_fork_id, stake_history_data, stake_history );

  /* Calculate the epoch reward points from stake/vote accounts */
  calculate_reward_points_partitioned(
      bank,
      stake_delegations,
      stake_history,
      rewarded_epoch,
      runtime_stack );

  if( FD_UNLIKELY( capture_ctx && capture_ctx->capture_solcap ) ) {
    ulong epoch = bank->f.epoch;
    ulong slot  = bank->f.slot;
    fd_capture_link_write_stake_rewards_begin( capture_ctx,
                                               slot,
                                               epoch,
                                               epoch-1UL, /* FIXME: this is not strictly correct */
                                               total_rewards,
                                               0UL );
  }

  /* Calculate the stake and vote rewards for each account. We want to
     use the vote states from the end of the current_epoch. */
  calculate_stake_vote_rewards(
      bank,
      stake_delegations,
      capture_ctx,
      stake_history,
      rewarded_epoch,
      total_rewards,
      runtime_stack,
      0 );

  fd_hash_t const * parent_blockhash      = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  ulong             starting_block_height = bank->f.block_height + REWARD_CALCULATION_NUM_BLOCKS;
  uint              num_partitions        = get_reward_distribution_num_blocks( &bank->f.epoch_schedule,
                                                                                bank->f.slot,
                                                                                runtime_stack->stakes.stake_rewards_cnt,
                                                                                bank->f.slot_params.stake_account_stores_per_block );

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  ushort               fork_idx      = fd_stake_rewards_init( stake_rewards,
                                                              parent_blockhash,
                                                              starting_block_height,
                                                              num_partitions,
                                                              0U,
                                                              runtime_stack->stakes.stake_rewards_cnt );
  if( FD_UNLIKELY( bank->stake_rewards_fork_id!=USHORT_MAX ) ) {
    fd_stake_rewards_release( stake_rewards, bank->stake_rewards_fork_id );
  }
  bank->stake_rewards_fork_id = fork_idx;

  setup_stake_partitions( bank,
                          stake_history,
                          stake_delegations,
                          runtime_stack,
                          fork_idx,
                          rewarded_epoch,
                          total_rewards );
}

/* Calculate rewards from previous epoch to prepare for partitioned distribution.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L277
   https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L470-L495 */
static void
calculate_rewards_for_partitioning( fd_bank_t *                            bank,
                                    fd_accdb_t *                           accdb,
                                    fd_runtime_stack_t *                   runtime_stack,
                                    fd_stake_delegations_t const *         stake_delegations,
                                    fd_capture_ctx_t *                     capture_ctx,
                                    ulong                                  prev_epoch,
                                    fd_partitioned_rewards_calculation_t * result ) {
  fd_prev_epoch_inflation_rewards_t rewards;

  calculate_previous_epoch_inflation_rewards( bank,
                                              bank->f.capitalization,
                                              prev_epoch,
                                              &rewards );
  ulong total_rewards = fd_epoch_inflation_rewards_for_epoch( bank, accdb, prev_epoch );

  calculate_validator_rewards( bank,
                               accdb,
                               runtime_stack,
                               stake_delegations,
                               capture_ctx,
                               prev_epoch,
                               total_rewards );

  /* The agave client does not partition the stake rewards until the
     first distribution block.  We calculate the partitions during the
     boundary. */
  result->validator_rewards            = total_rewards;
  result->validator_rate               = rewards.validator_rate;
  result->foundation_rate              = rewards.foundation_rate;
  result->prev_epoch_duration_in_years = rewards.prev_epoch_duration_in_years;
  result->capitalization               = bank->f.capitalization;
}

/* Sweeps the given vote account's pending delegator rewards.
   maybe_stake is the validator's reward epoch delegated stake, NULL if
   unknown.  Only accounts holding pending rewards are rewritten.
   https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L233 */
static void
sweep_vote_account( fd_bank_t *         bank,
                    fd_accdb_t *        accdb,
                    fd_capture_ctx_t *  capture_ctx,
                    fd_pubkey_t const * vote_address,
                    ulong const *       maybe_stake,
                    ulong *             total_block_reward_lamports ) {
  ulong pending_delegator_rewards = 0UL;
  {
    fd_acc_t ro = fd_accdb_read_one( accdb, bank->accdb_fork_id, vote_address->uc );
    int skip = !ro.lamports ||
               memcmp( ro.owner, fd_solana_vote_program_id.uc, sizeof(fd_pubkey_t) ) ||
               fd_vote_account_pending_delegator_rewards( ro.data, ro.data_len, &pending_delegator_rewards ) ||
               !pending_delegator_rewards;
    fd_accdb_unread_one( accdb, &ro );
    if( FD_LIKELY( skip ) ) return;
  }

  fd_accdb_svm_update_t update[1];
  fd_acc_t              acc = fd_accdb_svm_open_rw( bank, accdb, update, vote_address, 0 );
  ulong                 pending_reset;
  /* The read above already parsed this data as a v4 state. */
  FD_TEST( !fd_vote_account_reset_pending_delegator_rewards( acc.data, acc.data_len, &pending_reset ) );
  /* If validator has no stake, delegator rewards go back to the validator, no
     distribution needed.
     If the validator's stake is not known, it likely did not pay VAT, so that
     validator's block rewards get burned. */
  if( !( maybe_stake && *maybe_stake==0UL ) ) {
    /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L249-L259 */
    FD_TEST( acc.lamports>=pending_delegator_rewards );
    acc.lamports                 -= pending_delegator_rewards;
    *total_block_reward_lamports += pending_delegator_rewards;
  }
  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &acc, update );
}

/* reward_epoch_delegated_stakes lookup: the t-1 set decides whether
   the validator is known.  The stake is the accumulator's reward epoch
   stake.  Returns stake_out or NULL if the validator is unknown.
   https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/alpenglow_epoch_type.rs#L72 */
static ulong const *
reward_epoch_delegated_stake( fd_bank_t *          bank,
                              fd_runtime_stack_t * runtime_stack,
                              fd_pubkey_t const *  vote_address,
                              ulong *              stake_out ) {
  fd_stake_accum_t const * accumulated = fd_stake_accum_map_ele_query_const(
      runtime_stack->stakes.stake_accum_map, vote_address, NULL, runtime_stack->stakes.stake_accum );
  *stake_out = accumulated ? accumulated->reward_stake : 0UL;
  return fd_vote_stakes_query_t_1( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id, vote_address, NULL ) ? stake_out : NULL;
}

/* Sweeps pending delegator rewards out of the vote accounts.
   Returns the swept lamports.

   Important. We must iterate the t-3 set, because both the fee settlement
   and the vote program limit pending_delegator_rewards to leaders, i.e. t-2 set
   (t-2 set has already rotated to t-3 when we call sweep_pending_delegator_rewards).

   https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L1258-L1290 */
static ulong
sweep_pending_delegator_rewards( fd_bank_t *          bank,
                                 fd_accdb_t *         accdb,
                                 fd_capture_ctx_t *   capture_ctx,
                                 fd_runtime_stack_t * runtime_stack ) {
  ulong total_block_reward_lamports = 0UL;

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ushort             fork_id     = bank->vote_stakes_fork_id;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_3, iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_3, iter );
       fd_vote_stakes_iter_next( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_3, iter ) ) {
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_3, iter, ele );
    /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L1276-L1278 */
    ulong         stake;
    ulong const * maybe_stake = reward_epoch_delegated_stake( bank, runtime_stack, &ele->pubkey, &stake );
    /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L1279-L1285 */
    sweep_vote_account( bank, accdb, capture_ctx, &ele->pubkey, maybe_stake, &total_block_reward_lamports );
  }

  return total_block_reward_lamports;
}

/* Calculate rewards from previous epoch and distribute vote rewards
   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L148
   https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L234-L296 */
static ulong
calculate_rewards_and_distribute_vote_rewards( fd_bank_t *                    bank,
                                               fd_accdb_t *                   accdb,
                                               fd_runtime_stack_t *           runtime_stack,
                                               fd_stake_delegations_t const * stake_delegations,
                                               fd_capture_ctx_t *             capture_ctx,
                                               ulong                          prev_epoch ) {

  fd_vote_rewards_t *     vote_ele_pool = runtime_stack->stakes.vote_ele;
  fd_vote_rewards_map_t * vote_ele_map  = runtime_stack->stakes.vote_map;

  /* First we must compute the stake and vote rewards for the just
     completed epoch.  We store the stake account rewards and vote
     states rewards in the bank */

  fd_partitioned_rewards_calculation_t rewards_calc_result[1] = {0};
  calculate_rewards_for_partitioning( bank,
                                      accdb,
                                      runtime_stack,
                                      stake_delegations,
                                      capture_ctx,
                                      prev_epoch,
                                      rewards_calc_result );

  /* Sweep while stake_accum still holds the reward epoch delegated stakes.
     https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L1258-L1290 */
  runtime_stack->stakes.block_rewards = 0UL;
  if( FD_FEATURE_ACTIVE_BANK( bank, block_revenue_sharing ) ) {
    runtime_stack->stakes.block_rewards = sweep_pending_delegator_rewards( bank, accdb, capture_ctx, runtime_stack );
  }


  /* Distribute the commission rewards.  distributed_rewards includes
     burned and incinerated amounts: the epoch rewards sysvar counts
     them as distributed.
     https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L186-L217 */
  ulong distributed_rewards   = 0UL;
  ulong credited_vote_rewards = 0UL;
  if( FD_FEATURE_ACTIVE_BANK( bank, custom_commission_collector ) ) {
    /* Aggregate rewards per collector before validation: several small
       rewards may collectively make a new collector rent-exempt.
       stake_accum is free for reuse as scratch here. */
    fd_stake_accum_t *     collector_pool = runtime_stack->stakes.stake_accum;
    fd_stake_accum_map_t * collector_map  = runtime_stack->stakes.stake_accum_map;
    fd_stake_accum_map_reset( collector_map );
    ulong collector_cnt = 0UL;

    for( fd_vote_rewards_map_iter_t iter = fd_vote_rewards_map_iter_init( vote_ele_map, vote_ele_pool );
         !fd_vote_rewards_map_iter_done( iter, vote_ele_map, vote_ele_pool );
         iter = fd_vote_rewards_map_iter_next( iter, vote_ele_map, vote_ele_pool ) ) {
      uint                idx = (uint)fd_vote_rewards_map_iter_idx( iter, vote_ele_map, vote_ele_pool );
      fd_vote_rewards_t * ele = &vote_ele_pool[idx];

      ulong rewards = ele->vote_rewards;
      if( FD_UNLIKELY( !rewards ) ) continue;
      distributed_rewards = fd_ulong_sat_add( distributed_rewards, rewards );

      fd_pubkey_t collector;
      fd_rewards_inflation_collector( bank, &ele->pubkey, &collector );

      fd_stake_accum_t * collector_reward = fd_stake_accum_map_ele_query( collector_map, &collector, NULL, collector_pool );
      if( FD_UNLIKELY( !collector_reward ) ) {
        FD_TEST( collector_cnt<runtime_stack->max_vote_accounts );
        collector_reward         = &collector_pool[ collector_cnt++ ];
        collector_reward->pubkey = collector;
        collector_reward->stake  = rewards;
        fd_stake_accum_map_ele_insert( collector_map, collector_reward, collector_pool );
      } else {
        collector_reward->stake = fd_ulong_sat_add( collector_reward->stake, rewards );
      }
    }

    for( fd_stake_accum_map_iter_t iter = fd_stake_accum_map_iter_init( collector_map, collector_pool );
         !fd_stake_accum_map_iter_done( iter, collector_map, collector_pool );
         iter = fd_stake_accum_map_iter_next( iter, collector_map, collector_pool ) ) {
      fd_stake_accum_t * collector_reward = fd_stake_accum_map_iter_ele( iter, collector_map, collector_pool );

      /* A collector that is itself a self-collecting vote account is
         paid only its own reward; rewards routed to it by other vote
         accounts are burned (it is not system-owned).
         https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L70-L124 */
      fd_vote_rewards_t * self_ele = fd_vote_rewards_map_ele_query( vote_ele_map, &collector_reward->pubkey, NULL, vote_ele_pool );
      int is_vote_account = 0;
      if( self_ele && self_ele->vote_rewards ) {
        fd_pubkey_t self_collector;
        fd_rewards_inflation_collector( bank, &self_ele->pubkey, &self_collector );
        is_vote_account = fd_pubkey_eq( &self_collector, &self_ele->pubkey );
      }
      ulong rewards = is_vote_account ? self_ele->vote_rewards : collector_reward->stake;

      fd_acc_t account = fd_accdb_read_one( accdb, bank->accdb_fork_id, collector_reward->pubkey.uc );
      int      burn;
      if( is_vote_account ) {
        /* The vote account itself only needs the overflow check. */
        ulong post_balance;
        burn = __builtin_uaddl_overflow( account.lamports, rewards, &post_balance );
      } else {
        burn = fd_rewards_validate_commission_collector( bank, &collector_reward->pubkey, &account, rewards );
      }
      fd_accdb_unread_one( accdb, &account );

      if( FD_UNLIKELY( burn ) ) continue;

      /* Credit rewards to the collector (creating a new system account
         if it does not exist).  This is always a vote reward. */
      fd_accdb_svm_credit( bank, accdb, capture_ctx, &collector_reward->pubkey, rewards, 1 );
      if( FD_LIKELY( !fd_pubkey_eq( &collector_reward->pubkey, &fd_sysvar_incinerator_id ) ) ) {
        credited_vote_rewards = fd_ulong_sat_add( credited_vote_rewards, rewards );
      }
    }
  } else {
    for( fd_vote_rewards_map_iter_t iter = fd_vote_rewards_map_iter_init( vote_ele_map, vote_ele_pool );
         !fd_vote_rewards_map_iter_done( iter, vote_ele_map, vote_ele_pool );
         iter = fd_vote_rewards_map_iter_next( iter, vote_ele_map, vote_ele_pool ) ) {

      uint idx = (uint)fd_vote_rewards_map_iter_idx( iter, vote_ele_map, vote_ele_pool );
      fd_vote_rewards_t * ele = &vote_ele_pool[idx];

      ulong rewards = ele->vote_rewards;
      if( rewards==0UL ) {
        continue;
      }

      /* Credit rewards to vote account (creating a new system account if
         it does not exist) */
      fd_accdb_svm_credit( bank, accdb, capture_ctx, &ele->pubkey, rewards, 1 );
      distributed_rewards   = fd_ulong_sat_add( distributed_rewards, rewards );
      credited_vote_rewards = fd_ulong_sat_add( credited_vote_rewards, rewards );
    }
  }

  /* Verify that we didn't pay any more than we expected to */
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  ulong total_stake_rewards = fd_stake_rewards_total_rewards( stake_rewards, bank->stake_rewards_fork_id );

  ulong total_rewards = fd_ulong_sat_add( distributed_rewards, total_stake_rewards );
  if( FD_UNLIKELY( rewards_calc_result->validator_rewards<total_rewards ) ) {
    FD_LOG_CRIT(( "Unexpected rewards calculation result" ));
  }

  runtime_stack->stakes.distributed_rewards = distributed_rewards;
  runtime_stack->stakes.total_rewards       = rewards_calc_result->validator_rewards;
  return fd_ulong_sat_add( credited_vote_rewards, total_stake_rewards );
}

/* Note: modifies delegation in-place, adjusting it for rent-exempt
   minimum balance requirements.
   https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L55-L76 */
static void
adjust_delegation_for_rent( fd_delegation_t * delegation,
                            ulong             rewarded_epoch,
                            ulong             new_delegation_with_rewards,
                            ulong             lamports_with_rewards,
                            ulong             minimum_lamports ) {
  ulong new_delegation = fd_ulong_min( new_delegation_with_rewards,
                                       fd_ulong_sat_sub( lamports_with_rewards, minimum_lamports ) );

  if( new_delegation!=delegation->stake ) {
    delegation->stake = new_delegation;
    if( FD_UNLIKELY( new_delegation==0UL ) ) {
      delegation->deactivation_epoch = rewarded_epoch;
    }
  }
}

/* Distributes a single partitioned reward to a single stake account.  acc was
   acquired by the caller as part of a batch and is released with it, so the
   early returns below leave commit at 0, which fd_accdb_release skips. */

static int
distribute_epoch_reward_to_stake_acc( fd_bank_t *         bank,
                                      fd_capture_ctx_t *  capture_ctx,
                                      ulong               reward_lamports,
                                      ulong               block_reward,
                                      ulong               new_credits_observed,
                                      ulong               partition_idx,
                                      fd_acc_t *          acc,
                                      fd_lthash_adder_t * adder_pre,
                                      fd_lthash_value_t * sum_pre,
                                      fd_lthash_adder_t * adder_post,
                                      fd_lthash_value_t * sum_post ) {
  if( FD_UNLIKELY( !acc->lamports ) ) {
    return 1; /* account does not exist */
  }

  fd_stake_state_t const * stake_state_orig = fd_stakes_get_state( acc );
  if( FD_UNLIKELY( !stake_state_orig || stake_state_orig->stake_type!=FD_STAKE_STATE_STAKE ) ) {
    return 1; /* not a valid stake account */
  }

  fd_pubkey_t const * stake_pubkey   = fd_type_pun_const(acc->pubkey);
  fd_stake_state_t    stake_state[1] = { *stake_state_orig };

  fd_lthash_adder_push_solana_account( adder_pre, sum_pre, stake_pubkey->uc, acc->data, acc->data_len, acc->lamports, (uchar)!!acc->executable, acc->owner );

  /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L263-L268 */
  ulong lamports_pre = acc->lamports;
  FD_TEST( !__builtin_add_overflow( acc->lamports, reward_lamports, &acc->lamports ) );
  FD_TEST( !__builtin_add_overflow( acc->lamports, block_reward,    &acc->lamports ) );

  ulong old_credits_observed                = stake_state->stake.stake.credits_observed;
  stake_state->stake.stake.credits_observed = new_credits_observed;
  stake_state->stake.stake.delegation.stake = fd_ulong_sat_add( stake_state->stake.stake.delegation.stake, reward_lamports );

  /* https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L259-L283 */
  fd_stake_t * new_stake = &stake_state->stake.stake;
  if( FD_FEATURE_ACTIVE_BANK( bank, relax_post_exec_min_balance_check ) ) {
    ulong minimum_balance = fd_rent_exempt_minimum_balance( &bank->f.rent, acc->data_len );
    adjust_delegation_for_rent(
      &new_stake->delegation,
      fd_ulong_sat_sub( bank->f.epoch, 1UL ),
      new_stake->delegation.stake,
      acc->lamports,
      minimum_balance );
  }

  fd_stake_delegations_t * stake_delegations_upd = fd_bank_stake_delegations_modify( bank );
  fd_stake_delegations_fork_update( stake_delegations_upd,
                                    bank->stake_delegations_fork_id, 0UL,
                                    stake_pubkey,
                                    &stake_state->stake.stake.delegation.voter_pubkey,
                                    stake_state->stake.stake.delegation.stake,
                                    stake_state->stake.stake.delegation.activation_epoch,
                                    stake_state->stake.stake.delegation.deactivation_epoch,
                                    stake_state->stake.stake.credits_observed,
                                    acc->lamports,
                                    (uint)acc->data_len );
  if( FD_UNLIKELY( fd_bank_report_runtime_diffs( bank ) ) ) {
    fd_event_runtime_stake_delegation_payout_emit( bank,
                                                   stake_pubkey->uc,
                                                   stake_state->stake.stake.delegation.voter_pubkey.uc,
                                                   stake_state->stake.stake.delegation.stake,
                                                   stake_state->stake.stake.delegation.activation_epoch,
                                                   stake_state->stake.stake.delegation.deactivation_epoch,
                                                   stake_state->stake.stake.credits_observed );
  }

  if( FD_UNLIKELY( capture_ctx && capture_ctx->capture_solcap ) ) {
    fd_capture_link_write_stake_account_payout( capture_ctx,
                                                bank->f.slot,
                                                *stake_pubkey,
                                                bank->f.slot,
                                                acc->lamports,
                                                (long)( reward_lamports+block_reward ),
                                                new_credits_observed,
                                                (long)( new_credits_observed - old_credits_observed ),
                                                stake_state->stake.stake.delegation.stake,
                                                (long)( reward_lamports+block_reward ) );
  }

  FD_STORE( fd_stake_state_t, acc->data, *stake_state );
  fd_lthash_adder_push_solana_account( adder_post, sum_post, stake_pubkey->uc, acc->data, acc->data_len, acc->lamports, (uchar)!!acc->executable, acc->owner );
  fd_hashes_capture_account( stake_pubkey->uc, acc->owner, acc->lamports, acc->executable, acc->data, acc->data_len, bank, capture_ctx );
  if( FD_UNLIKELY( fd_bank_report_runtime_diffs( bank ) ) ) {
    fd_event_runtime_reward_emit( bank, FD_EVENT_RUNTIME_REWARD_KIND_STAKE, acc->pubkey, acc->owner,
                                  lamports_pre, acc->lamports, partition_idx, new_credits_observed,
                                  stake_state->stake.stake.delegation.stake );
  }
  acc->commit = 1;

  return 0;
}

/* Accdb batch size for updating stake accounts */
#define STAKE_REWARD_ACC_BATCH_SZ (32UL)

/* Process reward credits for a partition of rewards.  Store the rewards
   to AccountsDB, update reward history record and total capitalization
   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L88 */
static void
distribute_epoch_rewards_in_partition( fd_stake_rewards_t *      stake_rewards,
                                       ulong                     partition_idx,
                                       fd_bank_t *               bank,
                                       fd_accdb_t *              accdb,
                                       fd_capture_ctx_t *        capture_ctx ) {

  ulong lamports_distributed     = 0UL;
  ulong lamports_burned          = 0UL;
  ulong block_reward_distributed = 0UL;
  ulong block_reward_burned      = 0UL;

  fd_lthash_adder_t adder_pre[1], adder_post[1];
  fd_lthash_adder_new( adder_pre  );
  fd_lthash_adder_new( adder_post );
  fd_lthash_value_t sum_pre[1], sum_post[1];
  fd_lthash_zero( sum_pre  );
  fd_lthash_zero( sum_post );

  /* Acquire and process stake accounts in batches of 32 */

  fd_pubkey_t   pubkeys         [ STAKE_REWARD_ACC_BATCH_SZ ];
  uchar const * pubkey_ptrs     [ STAKE_REWARD_ACC_BATCH_SZ ];
  int           writable        [ STAKE_REWARD_ACC_BATCH_SZ ];
  fd_acc_t      accs            [ STAKE_REWARD_ACC_BATCH_SZ ];
  ulong         reward_lamports [ STAKE_REWARD_ACC_BATCH_SZ ];
  ulong         credits_observed[ STAKE_REWARD_ACC_BATCH_SZ ];
  ulong         block_rewards   [ STAKE_REWARD_ACC_BATCH_SZ ];

  for( ulong i=0UL; i<STAKE_REWARD_ACC_BATCH_SZ; i++ ) {
    pubkey_ptrs[ i ] = pubkeys[ i ].uc;
    writable   [ i ] = 1;
  }

  fd_stake_rewards_iter_init( stake_rewards, bank->stake_rewards_fork_id, (ushort)partition_idx );
  while( !fd_stake_rewards_iter_done( stake_rewards ) ) {

    /* Gather the next batch of rewards out of the partition. */
    ulong batch_cnt = 0UL;
    for( ; batch_cnt<STAKE_REWARD_ACC_BATCH_SZ && !fd_stake_rewards_iter_done( stake_rewards );
         batch_cnt++, fd_stake_rewards_iter_next( stake_rewards, bank->stake_rewards_fork_id ) ) {
      fd_stake_rewards_iter_ele( stake_rewards,
                                 bank->stake_rewards_fork_id,
                                 &pubkeys         [ batch_cnt ],
                                 &reward_lamports [ batch_cnt ],
                                 &credits_observed[ batch_cnt ],
                                 &block_rewards   [ batch_cnt ] );
    }

    fd_accdb_acquire( accdb, bank->accdb_fork_id, batch_cnt, pubkey_ptrs, writable, accs );

    /* Calculate and flush stake account updates */
    for( ulong i=0UL; i<batch_cnt; i++ ) {
      if( FD_LIKELY( !distribute_epoch_reward_to_stake_acc( bank,
                                                            capture_ctx,
                                                            reward_lamports[ i ],
                                                            block_rewards[ i ],
                                                            credits_observed[ i ],
                                                            partition_idx,
                                                            &accs[ i ],
                                                            adder_pre, sum_pre,
                                                            adder_post, sum_post ) ) ) {
        lamports_distributed     += reward_lamports[ i ];
        block_reward_distributed += block_rewards[ i ];
      } else {
        lamports_burned     += reward_lamports[ i ];
        block_reward_burned += block_rewards[ i ];
      }
    }

    fd_accdb_release( accdb, batch_cnt, accs );
  }

  fd_lthash_adder_flush( adder_pre,  sum_pre  );
  fd_lthash_adder_flush( adder_post, sum_post );

  fd_lthash_value_t * bank_lthash = fd_bank_lthash_locking_modify( bank );
  fd_lthash_sub( bank_lthash, sum_pre  );
  fd_lthash_add( bank_lthash, sum_post );
  fd_bank_lthash_end_locking_modify( bank );

  /* Update the epoch rewards sysvar with the amount distributed and burnt */
  fd_sysvar_epoch_rewards_distribute( bank, accdb, capture_ctx,
                                      lamports_distributed + lamports_burned,
                                      block_reward_distributed + block_reward_burned );

  FD_LOG_DEBUG(( "lamports burned: %lu, lamports distributed: %lu, block rewards burned: %lu, block rewards distributed: %lu",
                 lamports_burned, lamports_distributed, block_reward_burned, block_reward_distributed ));

  bank->f.capitalization = bank->f.capitalization + lamports_distributed + block_reward_distributed;
}

static int
recalculate_partitioned_rewards( fd_bank_t *          bank,
                                 fd_accdb_t *         accdb,
                                 fd_runtime_stack_t * runtime_stack,
                                 fd_capture_ctx_t *   capture_ctx,
                                 int                  snapshot_boot,
                                 uint                 win_lo );

/* Process reward distribution for the block if it is inside reward interval.

   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L45-L136 */
void
fd_distribute_partitioned_epoch_rewards( fd_bank_t *          bank,
                                         fd_accdb_t *         accdb,
                                         fd_runtime_stack_t * runtime_stack,
                                         fd_capture_ctx_t *   capture_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L46-L48 */
  if( FD_LIKELY( bank->stake_rewards_fork_id==USHORT_MAX ) ) return;

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );

  ulong block_height                       = bank->f.block_height;
  ulong distribution_starting_block_height = fd_stake_rewards_starting_block_height( stake_rewards, bank->stake_rewards_fork_id );
  ulong distribution_end_exclusive         = fd_stake_rewards_exclusive_ending_block_height( stake_rewards, bank->stake_rewards_fork_id );

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L55-L58 */
  if( FD_UNLIKELY( block_height<distribution_starting_block_height ) ) {
    return;
  }

  /* The logic in Agave for EpochRewardPhase::Calculation has no direct
     equivalent in Firedancer, because reward calculation is done
     eagerly at the epoch boundary, whereas for Agave it's done at the
     first distribution block.
     https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L60-L90 */

  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong                       epoch          = bank->f.epoch;

  if( FD_UNLIKELY( fd_epoch_slot_cnt( epoch_schedule, epoch ) <= fd_stake_rewards_num_partitions( stake_rewards, bank->stake_rewards_fork_id ) ) ) {
    FD_LOG_CRIT(( "Should not be distributing rewards" ));
  }

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L110-L114 */
  if( FD_LIKELY( block_height>=distribution_starting_block_height && block_height<distribution_end_exclusive ) ) {
    ulong partition_idx = block_height-distribution_starting_block_height;

    /* The rewards of this partition are only in memory if the window
       covers it.  If they are not, re-derive the window that does. */
    ushort fork_id = bank->stake_rewards_fork_id;
    if( FD_UNLIKELY( partition_idx<(ulong)fd_stake_rewards_window_lo( stake_rewards, fork_id ) ||
                     partition_idx>(ulong)fd_stake_rewards_window_hi( stake_rewards, fork_id ) ) ) {
      FD_LOG_INFO(( "reward partition is not in the window, recalculating" ));
      if( FD_UNLIKELY( !recalculate_partitioned_rewards( bank, accdb, runtime_stack, capture_ctx, 0, (uint)partition_idx ) ) ) {
        FD_LOG_CRIT(( "failed to recalculate partitioned rewards "
                      "(slot=%lu block_height=%lu partition=%lu fork=%u)",
                      bank->f.slot,
                      block_height,
                      partition_idx,
                      (uint)fork_id ));
      }
      stake_rewards = fd_bank_stake_rewards_modify( bank );
    }

    distribute_epoch_rewards_in_partition( stake_rewards, partition_idx, bank, accdb, capture_ctx );
  }

  /* If we have finished distributing rewards, set the status to inactive
     https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L116-L135 */
  if( fd_ulong_sat_add( block_height, 1UL )>=distribution_end_exclusive ) {
    fd_sysvar_epoch_rewards_set_inactive( bank, accdb, capture_ctx );
    fd_stake_rewards_release( stake_rewards, bank->stake_rewards_fork_id );
    bank->stake_rewards_fork_id = USHORT_MAX;
  }
}

/* Partitioned epoch rewards entry-point.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L102
   https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/bank.rs#L1748-L1899
*/
void
fd_begin_partitioned_rewards( fd_bank_t *                    bank,
                              fd_accdb_t *                   accdb,
                              fd_runtime_stack_t *           runtime_stack,
                              fd_capture_ctx_t *             capture_ctx,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_hash_t const *              parent_blockhash,
                              ulong                          parent_epoch,
                              ulong                          parent_capitalization ) {

  fd_reward_epoch_stakes_set( bank,
                              accdb,
                              capture_ctx,
                              parent_epoch,
                              runtime_stack );

  ulong capitalization_rewards = calculate_rewards_and_distribute_vote_rewards(
      bank,
      accdb,
      runtime_stack,
      stake_delegations,
      capture_ctx,
      parent_epoch );

  /* Once the rewards for vote accounts have been distributed and stake
     account rewards have been calculated, we can now set our epoch
     reward status to be active and we can initialize the epoch rewards
     sysvar.  This sysvar is then deleted once all of the partitioned
     stake rewards have been distributed.

     The Agave client calculates the partitions for each stake reward
     when the first distribution block is reached.  The Firedancer
     client differs here since we hash the partitions during the epoch
     boundary. */

  ulong distribution_starting_block_height = bank->f.block_height + REWARD_CALCULATION_NUM_BLOCKS;
  uint  num_partitions                     = fd_stake_rewards_num_partitions( fd_bank_stake_rewards_query( bank ), bank->stake_rewards_fork_id );

  fd_sysvar_epoch_rewards_init(
      bank,
      accdb,
      capture_ctx,
      runtime_stack->stakes.distributed_rewards,
      distribution_starting_block_height,
      num_partitions,
      runtime_stack->stakes.total_rewards,
      0UL, /* Alpenglow rewards are not points based */
      parent_blockhash,
      runtime_stack->stakes.block_rewards );

  ulong capitalization;
  FD_TEST( !__builtin_uaddl_overflow( parent_capitalization, capitalization_rewards, &capitalization ) );
  fd_prev_epoch_inflation_rewards_t rewards[1];
  calculate_previous_epoch_inflation_rewards( bank, capitalization, bank->f.epoch, rewards );
  fd_epoch_inflation_account_update( bank, accdb, capture_ctx, rewards->validator_rewards );
}

/*
    Re-calculates partitioned stake rewards.
    This updates the slot context's epoch reward status with the recalculated partitioned rewards.

    Everything the calculation needs survives in the epoch rewards
    sysvar and in the bank, so the partitions can be rebuilt at any
    point during the distribution interval.  The rebuilt partitions
    always go into a freshly acquired fork, with its window starting at
    win_lo, so that banks reading the fork this bank was using keep the
    entries they computed for themselves.  snapshot_boot selects where
    the vote commissions come from: a bank restored from a snapshot has
    to resolve them, every other caller reuses the ones the epoch
    boundary resolved.

    https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L521
    https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L1038-L1095 */
static int
recalculate_partitioned_rewards( fd_bank_t *          bank,
                                 fd_accdb_t *         accdb,
                                 fd_runtime_stack_t * runtime_stack,
                                 fd_capture_ctx_t *   capture_ctx,
                                 int                  snapshot_boot,
                                 uint                 win_lo ) {

  fd_sysvar_epoch_rewards_t epoch_rewards_sysvar[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_rewards_read(
          accdb, bank->accdb_fork_id, epoch_rewards_sysvar ) ) ) {
    FD_LOG_DEBUG(( "Failed to read or decode epoch rewards sysvar - may not have been created yet" ));
    return 0;
  }

  FD_LOG_DEBUG(( "recalculating partitioned rewards" ));

  if( FD_UNLIKELY( !epoch_rewards_sysvar->active ) ) {
    FD_LOG_DEBUG(( "epoch rewards is inactive" ));
    return 0;
  }

  ulong partition_cnt = epoch_rewards_sysvar->num_partitions;
  ulong starting_block_height =
      epoch_rewards_sysvar->distribution_starting_block_height;
  if( FD_UNLIKELY( !partition_cnt ||
                   partition_cnt>MAX_PARTITIONS_PER_EPOCH ||
                   starting_block_height>ULONG_MAX-partition_cnt ||
                   (ulong)win_lo>=partition_cnt ) ) {
    FD_LOG_WARNING(( "invalid epoch rewards partition window" ));
    return 0;
  }

  fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;
  fd_vote_rewards_map_reset( vote_ele_map );

  fd_epoch_credits_view_t epoch_credits_view[1];
  FD_TEST( fd_epoch_credits_view_init( epoch_credits_view, fd_bank_epoch_credits( bank ), bank->epoch_credits_fork_id ) );
  ulong                epoch_credits_len = epoch_credits_view->len;
  fd_epoch_credits_t * epoch_credits_arr = epoch_credits_view->credits;

  if( FD_LIKELY( !snapshot_boot ) ) {

    /* The rewards of this epoch were computed once already, at the epoch
       boundary or at snapshot load, and only the window is moving.  The
       commissions resolved back then are stored with the epoch credits
       and must be reused: they come from a vote account snapshot two
       epochs behind the rewarded epoch, which the top votes sets no
       longer retain. */

    for( ulong i=0UL; i<epoch_credits_len; i++ ) {
      fd_epoch_credits_t const * epoch_credits = &epoch_credits_arr[i];

      fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[i];
      vote_ele->pubkey       = *(fd_pubkey_t const *)epoch_credits->pubkey;
      vote_ele->vote_rewards = 0UL;
      vote_ele->commission   = epoch_credits->commission;
      fd_vote_rewards_map_idx_insert( vote_ele_map, i, runtime_stack->stakes.vote_ele );
    }

  } else {

    /* If the snapshot was loaded while partitioned epoch rewards is
       active, then the vote rewards map must be populated with the state
       of the vote accounts as of the end of the previous epoch boundary.
       The epoch credits for these accounts are stored in the bank, and
       the vote stakes retain the t-3 commission.  With this, it's
       possible to recalculate the rewards for the previous epoch
       boundary.  We need the commission from the end of the t-3 epoch
       if we are calculating rewards for the transition from epoch t-1
       to t since there needs to be a 2 epoch commission gap for the
       delay_commission_updates feature. */

    fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
    ushort             fork_id     = bank->vote_stakes_fork_id;

    for( ulong i=0UL; i<epoch_credits_len; i++ ) {
      fd_epoch_credits_t * epoch_credits = &epoch_credits_arr[i];
      fd_pubkey_t const *  pubkey        = (fd_pubkey_t const *)epoch_credits->pubkey;

      /* Get the t-1 stake account information.  This is guaranteed to be
         valid since the epoch credits are populated from the t-1 stakes
         in the snapshot manifest. */
      fd_vote_stakes_ele_t ele_t_1[1];
      FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, fork_id, pubkey, ele_t_1 ) );

      /* Get the t-3 information before the t-2 fallback.  Either may be
         absent if the vote account was created in a later epoch. */
      fd_vote_stakes_ele_t ele_t_3[1];
      int exists_t_3 = fd_vote_stakes_query_t_3( vote_stakes, fork_id, pubkey, ele_t_3 );

      /* Now get the t-2 information (if it exists).  This is not
         guaranteed to be valid since it's possible for a vote account to
         have been created in the last epoch. */
      fd_vote_stakes_ele_t ele_t_2[1];
      int exists_t_2 = fd_vote_stakes_query_t_2( vote_stakes, fork_id, pubkey, ele_t_2 );

      fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[i];
      vote_ele->pubkey       = *(fd_pubkey_t *)epoch_credits->pubkey;
      vote_ele->vote_rewards = 0UL;
      if( FD_FEATURE_ACTIVE_BANK( bank, delay_commission_updates ) ) {
        vote_ele->commission = exists_t_3 ? ele_t_3->commission : (exists_t_2 ? ele_t_2->commission : ele_t_1->commission);
      } else {
        vote_ele->commission = ele_t_1->commission;
      }
      fd_vote_rewards_map_idx_insert( vote_ele_map, i, runtime_stack->stakes.vote_ele );
    }

    /* Publish the resolved commissions so that any later repositioning
       of this fork's window reuses them. */
    for( ulong i=0UL; i<epoch_credits_len; i++ ) {
      epoch_credits_arr[i].commission = runtime_stack->stakes.vote_ele[i].commission;
    }
  }
  fd_epoch_credits_view_fini( epoch_credits_view );

  /* If partitioned rewards are active, the rewarded epoch is always the immediately
      preceding epoch.

      https://github.com/anza-xyz/agave/blob/2316fea4c0852e59c071f72d72db020017ffd7d0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L566 */
  FD_LOG_DEBUG(( "epoch rewards is active" ));

  ulong const epoch          = bank->f.epoch;
  ulong const rewarded_epoch = fd_ulong_sat_sub( epoch, 1UL );

  fd_reward_epoch_stakes_restore( bank, accdb, rewarded_epoch, runtime_stack );

  uchar              stake_history_data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_stake_history_t stake_history[1];
  read_stake_history( accdb, bank->accdb_fork_id, stake_history_data, stake_history );

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( bank );
  fd_stake_delegations_view_begin( stake_delegations,
                                   bank->f.epoch,
                                   stake_history,
                                   &bank->f.warmup_cooldown_rate_epoch,
                                   FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
                                   bank->stake_delegations_fork_id );

  calculate_stake_vote_rewards(
      bank,
      stake_delegations,
      capture_ctx,
      stake_history,
      rewarded_epoch,
      epoch_rewards_sysvar->total_rewards,
      runtime_stack,
      1 );

  /* The recomputed rewards go into a fork of their own rather than over
     the window the bank is holding: banks that branched off this one
     share that window and are entitled to the entries they already have,
     which were computed from their own delegations. */

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  ushort               fork_idx      = fd_stake_rewards_init( stake_rewards,
                                                              &epoch_rewards_sysvar->parent_blockhash,
                                                              starting_block_height,
                                                              (uint)partition_cnt,
                                                              win_lo,
                                                              runtime_stack->stakes.stake_rewards_cnt );
  if( FD_LIKELY( bank->stake_rewards_fork_id!=USHORT_MAX ) ) {
    fd_stake_rewards_release( stake_rewards, bank->stake_rewards_fork_id );
  }
  bank->stake_rewards_fork_id = fork_idx;

  setup_stake_partitions(
      bank,
      stake_history,
      stake_delegations,
      runtime_stack,
      fork_idx,
      rewarded_epoch,
      epoch_rewards_sysvar->total_rewards );

  fd_stake_delegations_view_end( stake_delegations,
                                 stake_history,
                                 &bank->f.warmup_cooldown_rate_epoch,
                                 FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ) );
  return 1;
}

void
fd_rewards_recalculate_partitioned_rewards( fd_bank_t *          bank,
                                            fd_accdb_t *         accdb,
                                            fd_runtime_stack_t * runtime_stack,
                                            fd_capture_ctx_t *   capture_ctx ) {
  recalculate_partitioned_rewards( bank, accdb, runtime_stack, capture_ctx, 1, 0U );
}
