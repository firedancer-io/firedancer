#include "fd_rewards.h"
#include "fd_stake_rewards.h"

#include "../runtime/sysvar/fd_sysvar_epoch_rewards.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"
#include "../runtime/fd_hashes.h"
#include "../stakes/fd_stakes.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/fd_system_ids.h"
#include "../capture/fd_capture_ctx.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_accdb_svm.h"
#include "fd_rewards_base.h"

#include <math.h>

/* A note on the calculation of points for inflation rewards at the
   epoch boundary.

   As of today there are more than 1.5 million stake delegations on
   mainnet (1,583,562 at the 987->988 boundary).  Each and every one of
   them could in theory earn some lamports of inflation rewards, so at
   the boundary each and every delegation is looked at to compute its
   share.  A delegation's share is directly proportional to its
   "points", and the points are essentially the area under a curve where
   the y axis is the delegation's effective stake and the x axis is the
   monotonically increasing vote credits.

     points = SUM over eligible epochs e of ( effective(e) * credits_owed(e) )

   There are two dimensions to this summation formula.  (1) A vote
   account monotonically ticks up its vote credit as it votes, and
   records its per-epoch credit history as (epoch,final,initial) tuples,
   where the [initial,final] ranges are contiguous and non-overlapping.
   That is to say, initial[n]=final[n-1].  A stake delegation stores a
   watermark, credits_observed, of how far it has already been paid
   along the corresponding vote account's credit history.  What the
   stake delegation is owed for an epoch is the part of that epoch's
   [initial,final] that sits above the credits_observed.  The credit
   history is capped at 64 epochs, so the sum is never more than 64
   terms long.  The epochs that overlap [credits_observed,final[last]]
   are the ones that contribute to the sum.  This is the x axis.  (2)
   Delegated stake ramps up to the full delegated amount over one or
   more epochs when it's activating, and ramps down gradually to 0 when
   it's deactivating.  So the effective stake at an epoch, aka
   effective(e), is not always simply the delegated amount.  Computing
   effective(e) involves running a simulation of the ramp, encoded in
   the activating_and_deactivating() function.  This is the y axis.

     stake |        ______________P________________
           |       /                               \
           | L   U/  warmup               cooldown  \D     R
         0 |_____/                                   \____________
           +-----+---------------------------------+--------------->  vote credits
            activation         activated          deactivation    cooled down
            (ramps up)   (effective=delegated)    (ramps down)    (effective=0)

   So under a reference implementation, the worst case is 64 effective()
   computations per delegation.  The delegations that tend to hit this
   case are dust delegations, either activated or deactivated, whose
   tiny or zero points share keeps rounding their rewards down to zero.
   As a result, reward doesn't pay out to a dust delegation, so it never
   advances its credits_observed, and over time it gets pegged at the
   worst case 64-term sum.  Roughly 14% of delegations are multi-term
   evaluations like this, and they account for ~89% (11.3M of 12.6M) of
   all the effective() invocations the points pass does.  A minority of
   delegations demanding the overwhelming majority of work, and they
   barely get any rewards, if at all.

   The good news is that the shape of the warmup/cooldown curve isn't
   arbitrary.  Observe that within a given boundary, a delegation's
   (activation_epoch,deactivation_epoch,stake) are fixed, and on this
   frozen tuple the effective stake curve is a single hump aka at most
   one peak.  The plot above shows the fullest warmup/cooldown curve
   within a boundary.  It rises during warmup (U) from 0 (L,
   epoch<=activation), sits on a flat plateau (P) at exactly the height
   of delegated stake, optionally ramps back down (D) after
   deactivation, and rests on a flat zero floor (R).  It never goes down
   and then back up within a given boundary.  In practice, the summation
   usually runs over just a subsection of this full curve.  Depending on
   which of the five zones {L,U,P,D,R} the first and the last
   contributing terms (the "o"s below) sit on the warmup/cooldown curve,
   there can be up to 15 unique possible subsection spans.  As of the
   987->988 boundary, the following three cases cover almost the entire
   points pass of a reference implementation.  The other spans are
   either rare or already cheap to evaluate.  We exploit the shape of
   each case to short circuit step-by-step summation.

   Case 1: Every contributing term sits on the zero floor.  The
   delegation deactivated at or before the epoch its watermark froze.
   This is the common fate of deactivated and abandoned dust stake whose
   reward payout stopped at deactivation.  This accounts for 79.8% of
   the effective() invocations and 88.4% of the effective() iterations
   in the points pass.  This is the R->R span.

           stake |
                 |
               0 | o--o--o--o--o
                 '--------------->  vote credits
                   ^ every contributing term sits past full deactivation

   Case 2: The contributing terms straddle the hump.  A few terms ride
   the hump, and the rest sit on the zero floor.  This accounts for just
   0.05% of the effective() invocations and 0.04% of the effective()
   iterations in the points pass.  This is a tiny population (230
   delegations) but catching the 0-tail of this case is a free side
   effect of trying to short circuit Case 1.  This is the {L,U,P,D}->R
   spans.

           stake | o--o--.
                 |        \
               0 |         o--o--o
                 '----------------->  vote credits
                           ^ first full deactivation term

   Case 3: Every contributing term sits on the plateau.  The delegation
   is fully activated and, almost always, never deactivated.  This is
   the fate of activated dust whose reward keeps rounding down to zero
   while its vote account keeps voting.  This accounts for 19.8% of the
   effective() invocations and 11.6% of the effective() iterations in
   the points pass.  This is the P->P span.  As a side note, P->P also
   includes a small sliver, ~14.8K delegations here, that deactivated no
   earlier than the epoch of its last contributing term.  The stake is
   still fully effective at the deactivation epoch itself.  The fast
   path below doesn't cover these.

           stake | o--o--o--o--o
                 |
               0 |________________
                 '--------------->  vote credits

   We try to short circuit multi-term Cases 1 and 3, as well as the
   multi-term tail floor of Case 2.  The short circuit conditions do not
   have to be fully precise, they just need to be conservative but not
   overly conservative and ideally cheap so as to net a performance win
   for most of the case population.

   Further observe that the vast majority (84%, 1.33M of 1.58M) of stake
   delegations have an up-to-date (>=initial[last]) credits watermark
   and they are almost all either single-term Case 1 or single-term Case
   3.  We fast path 1.27M of these with delegation state tags.  The
   small delta is almost entirely fresh delegations in the just-ended
   epoch.

   Note that VAT doesn't make the problem of dust points go away.  If we
   were to apply VAT on the 987->988 boundary, 96.3% of effective() and
   98.5% of iterations in effective() would still survive.
   Unfortunately, there's just a lot of abandoned dust stake pointing at
   validators that are still live and voting.

   ===

   For the data minded, the full census of the possible spans at the
   reference points pass of the 987->988 boundary:

     span   delegations    invocations            iterations
     R->R       182,920     10,067,849 (79.8%)    14,585,005 (88.4%)  Case 1
     P->R           225          5,745 (0.05%)         6,902 (0.04%)  Case 2
     L->R             5            164                     0          Case 2
     P->P     1,327,803      2,500,408 (19.8%)     1,905,636 (11.6%)  Case 3
     L->L        49,087         49,087 (0.4%)              0
     L->P             3             42                    11
     other            0              0                     0
     none        23,519              0                     0
     total    1,583,562     12,623,295            16,497,554

   The L->L span is fresh delegations from the just-ended epoch.  Their
   contributing term sits at or before the activation epoch, so every
   effective() invocation early exits from the all-activating branch
   without entering the simulation loop, hence zero iterations.  "other"
   is the nine spans that include either the U or D ramp zones.  They
   are all empty, because under today's mainnet warmup/cooldown budget
   both ramps complete in a single epoch step, so no term ever observes
   a partially warmed or partially cooled stake.  "none" is delegations
   with no contributing terms, i.e. their watermark already caught up to
   the vote credits.

   And broken down by how much each fast/slow path covers:

     span  fast/slow path                delegations  invocations   iterations
     P->P  single-term state tag           1,268,371 /  1,268,371 /  1,094,607
           single-term effective()            12,745 /     12,745 /     12,265
           multi-term is_warmed_plateau()     44,683 /  1,179,761 /    777,412
           slow path                           2,004 /     39,531 /     21,352
     R->R  early exit at 0-tail              181,263 / 10,066,192 / 14,581,965
           single-term state tag                  22 /         22 /         22
           single-term effective()             1,635 /      1,635 /      3,018
     L->L  single-term effective()            49,006 /     49,006 /          0
           single-term state tag                  81 /         81 /          0
     P->R  early exit at 0-tail                  225 /      5,745 /      6,902
     L->R  early exit at 0-tail                    5 /        164 /          0
     L->P  slow path                               3 /         42 /         11

   The single-term effective() branch gets taken on state tag misses,
   including fresh L->L delegations whose tag is still WARMING/UNKNOWN,
   P->P stakes that deactivated during the rewarded epoch (tag COOLING,
   though every term is still fully effective) or whose delinquent
   vote's last credit entry predates the rewarded epoch, and a few stale
   R->R.  The 81 L->L state tag hits are accounts that delegated and
   deactivated in the same epoch because activation==deactivation
   classifies as COOLED with effective 0.  The P->P slow path is taken
   by multi-term stakes that deactivated no earlier than their last
   contributing term, so they get rejected by is_warmed_plateau() and
   the 0-tail exit doesn't happen either. */

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
  return total( inflation, year ) - foundation( inflation, year );
}

/* Calculates the starting slot for inflation from the activation slot. The activation slot is the earliest
    activation slot of the following features:
    - devnet_and_testnet
    - full_inflation_enable, if full_inflation_vote has been activated

    https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2095 */
static FD_FN_CONST ulong
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

/* Returns 1 if effective stake is clearly a warmed plateau.

   This function seeks to conservatively prove that the given stake has
   effective=delegated throughout its entire multi-term points
   calculation.  Concretely, this boils down to the following.

   - The stake is not slated for deactivation.  This removes the
     downramp.
   - The first contributing epoch is > the activation epoch.
   - The stake easily activated at activation epoch+1.  This removes the
     upramp.

   These conditions constrain the warmup/cooldown curve to a flat
   plateau at effective=delegated.  What makes this conservative is that
   there could be false negatives only: this function says that a stake
   is not a multi-term plateau when in fact it is.  We do a single-step
   warmup simulation in this function, and the stake is rejected if it
   failed to easily warm up in a single epoch one past the activation
   epoch.  So a stake that took >=2 epochs to warm up may well be fully
   warmed up by the time of its first contributing epoch.  We make this
   tradeoff because this function is meant to be a fast detector and in
   practice most stake activate quickly under today's mainnet warmup
   budget.  Another case of false negative rejections is for multi-term
   stakes that deactivated no earlier than the last contributing epoch.
   We could easily eliminate this class of false negatives by passing in
   the last contributing epoch and comparing against deactivation epoch.
   We make this tradeoff because this class is empirically small and
   this function becomes that much easier to reason about by virtue of
   cleanly eliminating the deactivation simulation. */
static inline int
is_warmed_plateau( fd_stake_delegation_t const * stake,
                   ulong                         first_contributing_epoch,
                   fd_stake_history_t const *    stake_history,
                   ulong *                       new_rate_activation_epoch,
                   int                           use_fixed_point_stake_math ) {
  /* Slated for deactivation. */
  if( stake->deactivation_epoch!=USHORT_MAX ) return 0;

  /* is_bootstrap(): https://github.com/solana-program/stake/blob/interface%40v4.3.1/interface/src/state.rs#L892
     Stake activated as per protocol. */
  if( stake->activation_epoch==USHORT_MAX ) {
    return 1;
  }

  ulong ae = stake->activation_epoch;
  if( ae>=first_contributing_epoch ) return 0;

  /* Dropped out of history: https://github.com/solana-program/stake/blob/interface%40v4.3.1/interface/src/state.rs#L969
     Stake activated as per protocol. */
  fd_stake_history_entry_t const * e = fd_sysvar_stake_history_query( stake_history, ae );
  if( FD_UNLIKELY( !e ) ) {
    return 1;
  }

  /* Note that e may not actually be epoch ae's entry on a
     non-contiguous window.  That is fine here because the reference
     simulation's first step reads the exact same entry via the exact
     same query and the exact same allowance function below, and
     acceptance means the simulation completes warmup on that first
     step, before reading any other entry.  Similarly, the NULL return
     from the query above may also be spurious, and that's fine because
     Agave also just assumes fully effective. */

  /* Agave claims this is a "should have been fully effective" branch.
     Practically this branch probably won't be taken and so we will
     conservatively reject the fast path in this branch. */
  if( FD_UNLIKELY( e->activating==0UL ) ) return 0;

  /* Run a single-step simulation and see if stake easily activated. */
  ulong newly_effective;
  if( use_fixed_point_stake_math ) {
    newly_effective = fd_ulong_max( fd_stake_calculate_activation_allowance( ae+1UL, stake->stake, e, new_rate_activation_epoch ), 1UL );
  } else {
#if FD_HAS_DOUBLE
    newly_effective = fd_ulong_max( fd_stake_calculate_change_allowance_float( ae+1UL, stake->stake, e->activating, e->effective, new_rate_activation_epoch ), 1UL );
#else
    return 0;
#endif
  }
  if( newly_effective>=stake->stake ) {
    return 1;
  }
  return 0;
}

/* Inverted activation and deactivation epochs shouldn't really be
   possible on delegations created by the stake program.  To be safe, we
   will fall back to the slow path if any of these are detected. */
static inline int
stake_epochs_are_normal( fd_stake_delegation_t const * stake ) {
  return stake->activation_epoch==USHORT_MAX   ||
         stake->deactivation_epoch==USHORT_MAX ||
         stake->activation_epoch<=stake->deactivation_epoch;
}

/* For a given stake and epoch credit history, calculate how many
   points, aka (credits * stake) were earned and the new value for
   credits_observed if the points were to materialize to non-zero
   inflation rewards.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L109 */
static void
calculate_stake_points_and_credits( fd_epoch_credits_t *           epoch_credits,
                                    fd_stake_history_t const *     stake_history,
                                    fd_stake_delegation_t const *  stake,
                                    ulong *                        new_rate_activation_epoch,
                                    int                            use_fixed_point_stake_math,
                                    fd_calculated_stake_points_t * result ) {

  ulong credits_in_stake = stake->credits_observed;
  ulong credits_cnt      = epoch_credits->cnt;
  ulong base             = epoch_credits->base_credits;
  ulong credits_in_vote  = credits_cnt > 0UL ? base + epoch_credits->credits_delta[ credits_cnt - 1UL ] : 0UL;


  /* If the Vote account has less credits observed than the Stake account,
      something is wrong and we need to force an update.

      https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L142 */
  if( FD_UNLIKELY( credits_in_vote < credits_in_stake ) ) {
    result->points.ud = 0;
    result->new_credits_observed = credits_in_vote;
    result->force_credits_update_with_skipped_reward = 1;
    return;
  }

  /* If the Vote account has the same amount of credits observed as the Stake account,
      then the Vote account hasn't earnt any credits and so there is nothing to update.

      https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L148 */
  if( FD_UNLIKELY( credits_in_vote == credits_in_stake ) ) {
    result->points.ud = 0;
    result->new_credits_observed = credits_in_vote;
    result->force_credits_update_with_skipped_reward = 0;
    return;
  }

  int coalesce_eligible = stake_epochs_are_normal( stake ) && epoch_credits->fast_path_ok;

  /* Calculate the points for each epoch credit */
  uint128 points               = 0;
  ulong   new_credits_observed = credits_in_stake;
  for( ulong i=0UL; i<epoch_credits->cnt; i++ ) {

    ulong final_epoch_credits   = base + epoch_credits->credits_delta[ i ];
    ulong initial_epoch_credits = base + epoch_credits->prev_credits_delta[ i ];

    /* All production inputs should satisfy
       initial_epoch_credits <= final_epoch_credits

       If final_epoch_credits <= credits_in_stake, then:
        initial_epoch_credits <= final_epoch_credits <= credits_in_stake

       * earned_credits = 0 since both conditions are false.
       * new_credits_observed stays the same since it is already set
         to credits_in_stake and final_epoch_credits <= credits_in_stake

       Since earned_credits = 0 and new_credits_observed stays the same,
       points computation can be skipped. */
    if( FD_LIKELY( epoch_credits->fast_path_ok && final_epoch_credits<=credits_in_stake ) ) continue;

    uint128 earned_credits = 0;
    if( FD_LIKELY( credits_in_stake < initial_epoch_credits ) ) {
      earned_credits = (uint128)(final_epoch_credits - initial_epoch_credits);
    } else if( FD_UNLIKELY( credits_in_stake < final_epoch_credits ) ) {
      earned_credits = (uint128)(final_epoch_credits - new_credits_observed);
    }

    new_credits_observed = fd_ulong_max( new_credits_observed, final_epoch_credits );

    ulong stake_amount = fd_stakes_activating_and_deactivating( stake, epoch_credits->epoch[ i ], stake_history, new_rate_activation_epoch, use_fixed_point_stake_math ).effective;
    if( coalesce_eligible && stake_amount==0UL && epoch_credits->epoch[ i ]>stake->deactivation_epoch ) {
      /* Multi-term Cases 1 and 2.  Note that
         deactivation_epoch!=USHORT_MAX is implied since epoch[ i ] is
         also a ushort. */
      new_credits_observed = credits_in_vote;
      break;
    }

    points += (uint128)stake_amount * earned_credits;
  }

  result->points.ud = points;
  result->new_credits_observed = new_credits_observed;
  result->force_credits_update_with_skipped_reward = 0;
}

/* Returns commission split as
   (voter_portion, staker_portion, was_split) tuple.  If commission
   calculation is 10000 (100%) one way or other, indicate with false for
   was_split.

   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/inflation_rewards/mod.rs#L237-L272 */
void
fd_vote_commission_split( ushort                  commission,
                          ulong                   on,
                          fd_commission_split_t * result ) {
  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/inflation_rewards/mod.rs#L244-L245 */
  #define MAX_BPS (10000)

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/inflation_rewards/mod.rs#L246-L271 */
  ushort commission_split = fd_ushort_min( commission, MAX_BPS );
  switch( commission_split ) {
    case 0: {
      /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/inflation_rewards/mod.rs#L246 */
      result->voter_portion  = 0UL;
      result->staker_portion = on;
      result->is_split       = 0;
      break;
    }
    case MAX_BPS: {
      /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/inflation_rewards/mod.rs#L247 */
      result->voter_portion  = on;
      result->staker_portion = 0UL;
      result->is_split       = 0;
      break;
    }
    default: {
      /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/inflation_rewards/mod.rs#L256-L259 */
      result->voter_portion  = (ulong)((uint128)on * (uint128)commission_split / (uint128)MAX_BPS);
      result->staker_portion = (ulong)((uint128)on * (uint128)(MAX_BPS-commission_split) / (uint128)MAX_BPS);
      result->is_split       = 1;
      break;
    }
  }

  #undef MAX_BPS
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L33 */
static int
redeem_rewards( fd_stake_delegation_t const *   stake,
                ulong                           vote_state_idx,
                ulong                           rewarded_epoch,
                ulong                           total_rewards,
                uint128                         total_points,
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
  if( stake_points_result->points.ud==0 || total_points==0 ) {
    return 1;
  }

  uint128 rewards_u128;
  if( FD_UNLIKELY( __builtin_mul_overflow( stake_points_result->points.ud, (uint128)(total_rewards), &rewards_u128 ) ) ) {
    FD_LOG_ERR(( "Rewards intermediate calculation should fit within u128" ));
  }

  FD_TEST( total_points );
  rewards_u128 /=  (uint128) total_points;

  if( FD_UNLIKELY( rewards_u128>(uint128)ULONG_MAX ) ) {
    FD_LOG_ERR(( "Rewards should fit within u64" ));
  }

  ulong rewards = (ulong)rewards_u128;
  if( rewards == 0 ) {
    return 1;
  }

  fd_commission_split_t split_result;
  fd_vote_commission_split( runtime_stack->stakes.vote_ele[ vote_state_idx ].commission, rewards, &split_result );
  if( split_result.is_split && (split_result.voter_portion == 0 || split_result.staker_portion == 0) ) {
    return 1;
  }

  result->staker_rewards       = split_result.staker_portion;
  result->voter_rewards        = split_result.voter_portion;
  result->new_credits_observed = stake_points_result->new_credits_observed;
  return 0;
}

/* Returns the length of the given epoch in slots

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/epoch_schedule.rs#L103 */
static ulong
get_slots_in_epoch( ulong                       epoch,
                    fd_epoch_schedule_t const * epoch_schedule ) {
  return epoch < epoch_schedule->first_normal_epoch ?
         1UL << fd_ulong_sat_add( epoch, FD_EPOCH_LEN_MIN_TRAILING_ZERO ) :
         epoch_schedule->slots_per_epoch;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L2082 */
static double
epoch_duration_in_years( fd_bank_t const * bank,
                         ulong             prev_epoch ) {
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong                       slots_in_epoch = get_slots_in_epoch( prev_epoch, epoch_schedule );
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

/* calculate_stake_points_and_credits() with some fast paths. */
static inline void
calculate_stake_points_fast( fd_epoch_credits_t *           epoch_credits,
                             fd_stake_history_t const *     stake_history,
                             fd_stake_delegation_t const *  stake,
                             ulong *                        new_rate_activation_epoch,
                             int                            use_fixed_point_stake_math,
                             ulong                          rewarded_epoch,
                             fd_calculated_stake_points_t * result ) {
  if( FD_UNLIKELY( !stake_epochs_are_normal( stake ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( stake->stake_account.uc, stake_account_str );
    FD_BASE58_ENCODE_32_BYTES( stake->vote_account.uc,  vote_account_str  );
    FD_LOG_INFO(( "stake delegation (stake_account=%s vote_account=%s delegated=%lu balance=%lu credits_observed=%lu) activation epoch %u > deactivation epoch %u",
                  stake_account_str, vote_account_str, stake->stake, stake->lamports, stake->credits_observed, stake->activation_epoch, stake->deactivation_epoch ));
    calculate_stake_points_and_credits( epoch_credits, stake_history, stake, new_rate_activation_epoch, use_fixed_point_stake_math, result );
    return;
  }

  ulong cnt = epoch_credits->cnt;
  if( FD_LIKELY( epoch_credits->fast_path_ok && cnt ) ) {
    ulong base             = epoch_credits->base_credits;
    ulong credits_in_stake = stake->credits_observed;
    ulong credits_in_vote  = base+epoch_credits->credits_delta[ cnt-1UL ];
    if( FD_LIKELY( credits_in_vote>credits_in_stake ) ) {
      ulong initial_last = base+epoch_credits->prev_credits_delta[ cnt-1UL ];
      int fast = 0;

      if( FD_LIKELY( credits_in_stake>=initial_last ) ) {
        /* Single-term. */
        ulong target_epoch = epoch_credits->epoch[ cnt-1UL ];
        ulong effective_stake;
        if( FD_LIKELY( target_epoch==rewarded_epoch && (stake->state==FD_STAKE_DELEGATION_STATE_WARMED||stake->state==FD_STAKE_DELEGATION_STATE_COOLED) ) ) { /* See the block comment for state tags for why we need target_epoch==rewarded_epoch. */
          /* Single-term Case 3 or Case 1. */
          effective_stake = stake->state==FD_STAKE_DELEGATION_STATE_WARMED ? stake->stake : 0UL;
        } else {
          /* We could let this branch fall through to the slow path,
             whose loop will skip a whole bunch of epoch credits only to
             get to the final and only contributing term.  Computing it
             right here reduces about 800 instructions retired per such
             delegation. */
          effective_stake = fd_stakes_activating_and_deactivating( stake, target_epoch, stake_history, new_rate_activation_epoch, use_fixed_point_stake_math ).effective;
        }
        result->points.ud            = (uint128)effective_stake * (uint128)( credits_in_vote - credits_in_stake );
        result->new_credits_observed = credits_in_vote;
        fast = 1;
      } else {
        /* Multi-term. */
        ulong first_contributing_idx = 0UL;
        while( base+epoch_credits->credits_delta[ first_contributing_idx ]<=credits_in_stake ) first_contributing_idx++;
        FD_TEST( first_contributing_idx<cnt ); /* Guaranteed found because of the earlier credits_in_vote>credits_in_stake gate. */
        /* Multi-term Case 3.  effective=delegated at the earliest
           contributing term, and no deactivation at all, so the plateau
           simplifies the points calculation to a single closed form
           multiplication. */
        if( FD_LIKELY( is_warmed_plateau( stake, epoch_credits->epoch[ first_contributing_idx ], stake_history, new_rate_activation_epoch, use_fixed_point_stake_math ) ) ) {
          ulong start_credits          = fd_ulong_max( credits_in_stake, base+epoch_credits->prev_credits_delta[ 0UL ] );
          result->points.ud            = (uint128)stake->stake*(uint128)(credits_in_vote-start_credits);
          result->new_credits_observed = credits_in_vote;
          fast = 1;
        }
      }

      if( FD_LIKELY( fast ) ) {
        result->force_credits_update_with_skipped_reward = 0;
        return;
      }
    }
  }
  /* Potentially term-by-term slow path fallback for anything we can't
     conservatively prove to take the fast paths so far.  In this
     callee, early exit at the first fully deactivated term is the
     0-tail short circuit fast path for multi-term Cases 1 and 2. */
  calculate_stake_points_and_credits( epoch_credits, stake_history, stake, new_rate_activation_epoch, use_fixed_point_stake_math, result );
}

/* Calculates epoch reward points from stake/vote accounts.
   https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L445 */
static uint128
calculate_reward_points_partitioned( fd_bank_t *                    bank,
                                     fd_stake_delegations_t const * stake_delegations,
                                     fd_stake_history_t const *     stake_history,
                                     ulong                          rewarded_epoch,
                                     fd_runtime_stack_t *           runtime_stack ) {
  /* Calculate the points for each stake delegation */
  uint128 total_points = 0;

  fd_vote_rewards_t *     vote_ele     = runtime_stack->stakes.vote_ele;
  fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;

  fd_epoch_credits_t * epoch_credits_base = fd_bank_epoch_credits( bank );

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

    uint idx = (uint)fd_vote_rewards_map_idx_query( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );

    if( FD_LIKELY( stake_delegation_idx<runtime_stack->expected_stake_accounts ) ) {
      runtime_stack->stakes.stake_points_result[ stake_delegation_idx ].vote_idx = idx;
    }

    if( FD_UNLIKELY( idx==UINT_MAX ) ) continue;

    fd_calculated_stake_points_t   stake_points_result_[1];
    fd_calculated_stake_points_t * stake_points_result;
    if( FD_UNLIKELY( stake_delegation_idx>=runtime_stack->expected_stake_accounts ) ) {
      stake_points_result = stake_points_result_;
    } else {
      stake_points_result = &runtime_stack->stakes.stake_points_result[ stake_delegation_idx ];
    }

    fd_epoch_credits_t * epoch_credits = &epoch_credits_base[ idx ];

    calculate_stake_points_fast( epoch_credits,
                                 stake_history,
                                 stake_delegation,
                                 &bank->f.warmup_cooldown_rate_epoch,
                                 FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
                                 rewarded_epoch,
                                 stake_points_result );

    total_points += stake_points_result->points.ud;
  }

  return total_points;
}

/* https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/inflation_rewards/mod.rs#L161-L173 */
static int
delegation_may_need_adjustment( ulong current_delegation,
                                ulong new_delegation_with_rewards,
                                ulong lamports_with_rewards,
                                ulong minimum_lamports ) {
  ulong new_delegation = fd_ulong_min(
    new_delegation_with_rewards,
    fd_ulong_sat_sub( lamports_with_rewards, minimum_lamports )
  );

  return !!( new_delegation!=current_delegation );
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
                              uint128                        total_points,
                              fd_runtime_stack_t *           runtime_stack,
                              int                            is_recalculation ) {

  runtime_stack->stakes.stake_rewards_cnt = 0UL;

  fd_calculated_stake_rewards_t calculated_stake_rewards_[1];

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
    if( stake_delegation_idx>=runtime_stack->expected_stake_accounts ) {
      calculated_stake_rewards = calculated_stake_rewards_;
    } else {
      calculated_stake_rewards = &runtime_stack->stakes.stake_rewards_result[ stake_delegation_idx ];
    }
    calculated_stake_rewards->success = 0;

    int cached = !is_recalculation && stake_delegation_idx<runtime_stack->expected_stake_accounts;
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
      if( !FD_FEATURE_ACTIVE_BANK( bank, relax_post_exec_min_balance_check ) ) continue;

      /* If the stake account's resulting lamports would cause it to be
         below the rent exempt minimum balance, it needs to be queued
         for update (and thus affects the epoch reward partitions). */
      if( !delegation_may_need_adjustment(
            stake_delegation->stake,
            stake_delegation->stake,
            stake_delegation->lamports,
            fd_rent_exempt_minimum_balance( &bank->f.rent, stake_delegation->acc_dlen ) ) ) {
        continue;
      }

      /* Place an empty entry for this stake delegation idx so that
         the partitioning logic factors it in. */
      *calculated_stake_rewards = (fd_calculated_stake_rewards_t){
        .success              = 1,
        .staker_rewards       = 0,
        .voter_rewards        = 0,
        .new_credits_observed = stake_delegation->credits_observed
      };
      runtime_stack->stakes.stake_rewards_cnt++;
      continue;
    }

    fd_calculated_stake_points_t   stake_points_result_[1];
    fd_calculated_stake_points_t * stake_points_result;
    if( FD_LIKELY( cached ) ) {
      stake_points_result = &runtime_stack->stakes.stake_points_result[ stake_delegation_idx ];
    } else {
      fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[ idx ];

      /* We have not cached the stake points yet if we are recalculating
         stake rewards so we need to recalculate them.  ULONG_MAX
         disables the tag fast path. */
      calculate_stake_points_fast( epoch_credits,
                                   stake_history,
                                   stake_delegation,
                                   &bank->f.warmup_cooldown_rate_epoch,
                                   FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
                                   ULONG_MAX,
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
        total_points,
        runtime_stack,
        stake_points_result,
        calculated_stake_rewards );

    if( FD_UNLIKELY( err!=0 ) ) {
      /* Even if there is an error computing rewards for the stake
         account, there may be a required balance update for the stake
         account if rent increased.
         https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/inflation_rewards/mod.rs#L132-L152 */
      if( !FD_FEATURE_ACTIVE_BANK( bank, relax_post_exec_min_balance_check ) ) continue;

      /* staker rewards is 0 in the error case, so we can just use
         the current stake and lamports in the function args. */
      if( !delegation_may_need_adjustment(
            stake_delegation->stake,
            stake_delegation->stake,
            stake_delegation->lamports,
            fd_rent_exempt_minimum_balance( &bank->f.rent, stake_delegation->acc_dlen ) ) ) {
        continue;
      }

      *calculated_stake_rewards = (fd_calculated_stake_rewards_t){
        .success              = 1,
        .staker_rewards       = 0,
        .voter_rewards        = 0,
        .new_credits_observed = stake_delegation->credits_observed
      };
    } else {
      calculated_stake_rewards->success = 1;
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
}

static void
setup_stake_partitions( fd_bank_t *                    bank,
                        fd_stake_history_t const *     stake_history,
                        fd_stake_delegations_t const * stake_delegations,
                        fd_runtime_stack_t *           runtime_stack,
                        fd_hash_t const *              parent_blockhash,
                        ulong                          starting_block_height,
                        uint                           num_partitions,
                        ulong                          rewarded_epoch,
                        ulong                          total_rewards,
                        uint128                        total_points ) {

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  uchar fork_idx = fd_stake_rewards_init( stake_rewards, bank->f.epoch, parent_blockhash, starting_block_height, (uint)num_partitions );
  bank->stake_rewards_fork_id = fork_idx;

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation     = fd_stake_delegations_iter_ele( iter );
    ulong                         stake_delegation_idx = fd_stake_delegations_iter_idx( iter );

    fd_calculated_stake_rewards_t calculated_stake_rewards_[1];
    fd_calculated_stake_rewards_t * calculated_stake_rewards = NULL;

    if( FD_UNLIKELY( stake_delegation_idx>=runtime_stack->expected_stake_accounts ) ) {

      calculated_stake_rewards = calculated_stake_rewards_;

      fd_vote_rewards_t * vote_ele = runtime_stack->stakes.vote_ele;
      fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;
      uint idx = (uint)fd_vote_rewards_map_idx_query( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
      if( FD_UNLIKELY( idx==UINT_MAX ) ) {
        if( !FD_FEATURE_ACTIVE_BANK( bank, relax_post_exec_min_balance_check ) ) continue;

        /* If the stake account's resulting lamports would cause it to be
           below the rent exempt minimum balance, it needs to be queued
           for update (and thus affects the epoch reward partitions). */
        if( !delegation_may_need_adjustment(
              stake_delegation->stake,
              stake_delegation->stake,
              stake_delegation->lamports,
              fd_rent_exempt_minimum_balance( &bank->f.rent, stake_delegation->acc_dlen ) ) ) {
          continue;
        }

        fd_stake_rewards_insert( stake_rewards, fork_idx, &stake_delegation->stake_account, 0UL, stake_delegation->credits_observed );
        continue;
      }

      fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[ idx ];

      fd_calculated_stake_points_t stake_points_result[1];
      calculate_stake_points_fast( epoch_credits,
                                   stake_history,
                                   stake_delegation,
                                   &bank->f.warmup_cooldown_rate_epoch,
                                   FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
                                   ULONG_MAX,
                                   stake_points_result );

      /* redeem_rewards is actually just responsible for calculating the
         vote and stake rewards for each stake account.  It does not do
         rewards redemption: it is a misnomer. */
      int err = redeem_rewards(
          stake_delegation,
          idx,
          rewarded_epoch,
          total_rewards,
          total_points,
          runtime_stack,
          stake_points_result,
          calculated_stake_rewards );

      if( FD_UNLIKELY( err!=0 ) ) {
        /* Even if there is an error computing rewards for the stake
           account, there may be a required balance update for the stake
           account if rent increased.
           https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/inflation_rewards/mod.rs#L132-L152 */
        if( !FD_FEATURE_ACTIVE_BANK( bank, relax_post_exec_min_balance_check ) ) continue;

        /* staker rewards is 0 in the error case, so we can just use
           the current stake and lamports in the function args. */
        if( !delegation_may_need_adjustment(
              stake_delegation->stake,
              stake_delegation->stake,
              stake_delegation->lamports,
              fd_rent_exempt_minimum_balance( &bank->f.rent, stake_delegation->acc_dlen ) ) ) {
          continue;
        }

        fd_stake_rewards_insert( stake_rewards, fork_idx, &stake_delegation->stake_account, 0UL, stake_delegation->credits_observed );
        continue;
      } else {
        calculated_stake_rewards->success = 1;
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
      calculated_stake_rewards->new_credits_observed
    );
  }
}

/* Calculate epoch reward and return vote and stake rewards.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L273 */
static uint128
calculate_validator_rewards( fd_bank_t *                    bank,
                             fd_accdb_t *                   accdb,
                             fd_runtime_stack_t *           runtime_stack,
                             fd_stake_delegations_t const * stake_delegations,
                             fd_capture_ctx_t *             capture_ctx,
                             ulong                          rewarded_epoch,
                             ulong *                        rewards_out ) {
  fd_acc_t ro = fd_accdb_read_one( accdb, bank->accdb_fork_id, fd_sysvar_stake_history_id.uc );
  if( FD_UNLIKELY( !ro.lamports ) ) FD_LOG_ERR(( "Unable to read stake history sysvar" ));
  fd_stake_history_t stake_history[1];
  if( FD_UNLIKELY( !fd_sysvar_stake_history_view( stake_history, ro.data, ro.data_len ) ) ) {
    FD_LOG_ERR(( "Unable to decode stake history sysvar" ));
  }

  /* Calculate the epoch reward points from stake/vote accounts */
  uint128 total_points = calculate_reward_points_partitioned(
      bank,
      stake_delegations,
      stake_history,
      rewarded_epoch,
      runtime_stack );

  /* If there are no points, then we set the rewards to 0. */
  *rewards_out = total_points>0UL ? *rewards_out: 0UL;

  if( FD_UNLIKELY( capture_ctx && capture_ctx->capture_solcap ) ) {
    ulong epoch = bank->f.epoch;
    ulong slot  = bank->f.slot;
    fd_capture_link_write_stake_rewards_begin( capture_ctx,
                                               slot,
                                               epoch,
                                               epoch-1UL, /* FIXME: this is not strictly correct */
                                               *rewards_out,
                                               (ulong)total_points );
  }

  /* Calculate the stake and vote rewards for each account. We want to
     use the vote states from the end of the current_epoch. */
  calculate_stake_vote_rewards(
      bank,
      stake_delegations,
      capture_ctx,
      stake_history,
      rewarded_epoch,
      *rewards_out,
      total_points,
      runtime_stack,
      0 );

  fd_hash_t const * parent_blockhash      = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  ulong             starting_block_height = bank->f.block_height + REWARD_CALCULATION_NUM_BLOCKS;
  uint              num_partitions        = get_reward_distribution_num_blocks( &bank->f.epoch_schedule,
                                                                                bank->f.slot,
                                                                                runtime_stack->stakes.stake_rewards_cnt,
                                                                                bank->f.slot_params.stake_account_stores_per_block );

  setup_stake_partitions(
      bank,
      stake_history,
      stake_delegations,
      runtime_stack,
      parent_blockhash,
      starting_block_height,
      num_partitions,
      rewarded_epoch,
      *rewards_out,
      total_points );

  fd_accdb_unread_one( accdb, &ro );
  return total_points;
}

/* Calculate rewards from previous epoch to prepare for partitioned distribution.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L277 */
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

  ulong total_rewards = rewards.validator_rewards;

  uint128 points = calculate_validator_rewards( bank,
                                                accdb,
                                                runtime_stack,
                                                stake_delegations,
                                                capture_ctx,
                                                prev_epoch,
                                                &total_rewards );

  /* The agave client does not partition the stake rewards until the
     first distribution block.  We calculate the partitions during the
     boundary. */
  result->validator_points             = points;
  result->validator_rewards            = total_rewards;
  result->validator_rate               = rewards.validator_rate;
  result->foundation_rate              = rewards.foundation_rate;
  result->prev_epoch_duration_in_years = rewards.prev_epoch_duration_in_years;
  result->capitalization               = bank->f.capitalization;
}

/* Calculate rewards from previous epoch and distribute vote rewards
   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L148 */
static void
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


  /* Iterate over all the vote reward nodes and distribute the rewards
     to the vote accounts.  After each reward has been paid out,
     calcualte the lthash for each vote account. */
  ulong distributed_rewards = 0UL;
  for( fd_vote_rewards_map_iter_t iter = fd_vote_rewards_map_iter_init( vote_ele_map, vote_ele_pool );
       !fd_vote_rewards_map_iter_done( iter, vote_ele_map, vote_ele_pool );
       iter = fd_vote_rewards_map_iter_next( iter, vote_ele_map, vote_ele_pool ) ) {

    uint idx = (uint)fd_vote_rewards_map_iter_idx( iter, vote_ele_map, vote_ele_pool );
    fd_vote_rewards_t * ele = &vote_ele_pool[idx];

    ulong rewards = runtime_stack->stakes.vote_ele[ idx ].vote_rewards;
    if( rewards==0UL ) {
      continue;
    }

    /* Credit rewards to vote account (creating a new system account if
       it does not exist) */
    fd_pubkey_t const * vote_pubkey = &ele->pubkey;
    fd_accdb_svm_credit( bank, accdb, capture_ctx, vote_pubkey, rewards );
    distributed_rewards = fd_ulong_sat_add( distributed_rewards, rewards );
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
  runtime_stack->stakes.total_points.ud     = rewards_calc_result->validator_points;
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

/* Distributes a single partitioned reward to a single stake account */
static int
distribute_epoch_reward_to_stake_acc( fd_bank_t *        bank,
                                      fd_accdb_t *       accdb,
                                      fd_capture_ctx_t * capture_ctx,
                                      fd_pubkey_t *      stake_pubkey,
                                      ulong              reward_lamports,
                                      ulong              new_credits_observed ) {
  fd_acc_t acc = fd_accdb_write_one( accdb, bank->accdb_fork_id, stake_pubkey->uc );
  if( FD_UNLIKELY( !acc.lamports ) ) {
    fd_accdb_unwrite_one( accdb, &acc );
    return 1; /* account does not exist */
  }

  fd_stake_state_t const * stake_state_orig = fd_stakes_get_state( &acc );
  if( FD_UNLIKELY( !stake_state_orig || stake_state_orig->stake_type!=FD_STAKE_STATE_STAKE ) ) {
    fd_accdb_unwrite_one( accdb, &acc );
    return 1; /* not a valid stake account */
  }

  fd_stake_state_t stake_state[1] = { *stake_state_orig };

  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash_simple( stake_pubkey->uc, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, prev_hash );

  FD_TEST( !__builtin_add_overflow( acc.lamports, reward_lamports, &acc.lamports ) );

  ulong old_credits_observed                = stake_state->stake.stake.credits_observed;
  stake_state->stake.stake.credits_observed = new_credits_observed;
  stake_state->stake.stake.delegation.stake = fd_ulong_sat_add( stake_state->stake.stake.delegation.stake, reward_lamports );

  /* https://github.com/anza-xyz/agave/blob/v4.2.0-beta.0/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L259-L283 */
  fd_stake_t * new_stake = &stake_state->stake.stake;
  if( FD_FEATURE_ACTIVE_BANK( bank, relax_post_exec_min_balance_check ) ) {
    ulong minimum_balance = fd_rent_exempt_minimum_balance( &bank->f.rent, acc.data_len );
    adjust_delegation_for_rent(
      &new_stake->delegation,
      fd_ulong_sat_sub( bank->f.epoch, 1UL ),
      new_stake->delegation.stake,
      acc.lamports,
      minimum_balance );
  }

  fd_stake_delegations_t * stake_delegations_upd = fd_bank_stake_delegations_modify( bank );
  fd_stake_delegations_fork_update( stake_delegations_upd,
                                    bank->stake_delegations_fork_id,
                                    stake_pubkey,
                                    &stake_state->stake.stake.delegation.voter_pubkey,
                                    stake_state->stake.stake.delegation.stake,
                                    stake_state->stake.stake.delegation.activation_epoch,
                                    stake_state->stake.stake.delegation.deactivation_epoch,
                                    stake_state->stake.stake.credits_observed,
                                    acc.lamports,
                                    (uint)acc.data_len,
                                    fd_stake_warmup_cooldown_rate( bank->f.epoch, &bank->f.warmup_cooldown_rate_epoch ) );

  if( FD_UNLIKELY( capture_ctx && capture_ctx->capture_solcap ) ) {
    fd_capture_link_write_stake_account_payout( capture_ctx,
                                                bank->f.slot,
                                                *stake_pubkey,
                                                bank->f.slot,
                                                acc.lamports,
                                                (long)reward_lamports,
                                                new_credits_observed,
                                                (long)( new_credits_observed - old_credits_observed ),
                                                stake_state->stake.stake.delegation.stake,
                                                (long)reward_lamports );
  }

  FD_STORE( fd_stake_state_t, acc.data, *stake_state );
  fd_lthash_value_t post[1];
  fd_hashes_update_simple( post, prev_hash, stake_pubkey->uc, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, bank, capture_ctx );
  acc.commit = 1;
  fd_accdb_unwrite_one( accdb, &acc );

  return 0;
}

/* Process reward credits for a partition of rewards.  Store the rewards
   to AccountsDB, update reward history record and total capitalization
   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L88 */
static void
distribute_epoch_rewards_in_partition( fd_stake_rewards_t *      stake_rewards,
                                       ulong                     partition_idx,
                                       fd_bank_t *               bank,
                                       fd_accdb_t *              accdb,
                                       fd_capture_ctx_t *        capture_ctx ) {

  ulong lamports_distributed = 0UL;
  ulong lamports_burned      = 0UL;

  for( fd_stake_rewards_iter_init( stake_rewards, bank->stake_rewards_fork_id, (ushort)partition_idx );
       !fd_stake_rewards_iter_done( stake_rewards );
       fd_stake_rewards_iter_next( stake_rewards, bank->stake_rewards_fork_id ) ) {
    fd_pubkey_t pubkey;
    ulong       lamports;
    ulong       credits_observed;
    fd_stake_rewards_iter_ele( stake_rewards, bank->stake_rewards_fork_id, &pubkey, &lamports, &credits_observed );

    if( FD_LIKELY( !distribute_epoch_reward_to_stake_acc( bank,
                                                          accdb,
                                                          capture_ctx,
                                                          &pubkey,
                                                          lamports,
                                                          credits_observed ) )  ) {
      lamports_distributed += lamports;
    } else {
      lamports_burned += lamports;
    }
  }

  /* Update the epoch rewards sysvar with the amount distributed and burnt */
  fd_sysvar_epoch_rewards_distribute( bank, accdb, capture_ctx, lamports_distributed + lamports_burned );

  FD_LOG_DEBUG(( "lamports burned: %lu, lamports distributed: %lu", lamports_burned, lamports_distributed ));

  bank->f.capitalization = bank->f.capitalization + lamports_distributed;
}

/* Process reward distribution for the block if it is inside reward interval.

   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L45-L136 */
void
fd_distribute_partitioned_epoch_rewards( fd_bank_t *        bank,
                                         fd_accdb_t *       accdb,
                                         fd_capture_ctx_t * capture_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L46-L48 */
  if( FD_LIKELY( bank->stake_rewards_fork_id==UCHAR_MAX ) ) return;

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

  if( FD_UNLIKELY( get_slots_in_epoch( epoch, epoch_schedule ) <= fd_stake_rewards_num_partitions( stake_rewards, bank->stake_rewards_fork_id ) ) ) {
    FD_LOG_CRIT(( "Should not be distributing rewards" ));
  }

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L110-L114 */
  if( FD_LIKELY( block_height>=distribution_starting_block_height && block_height<distribution_end_exclusive ) ) {
    ulong partition_idx = block_height-distribution_starting_block_height;
    distribute_epoch_rewards_in_partition( stake_rewards, partition_idx, bank, accdb, capture_ctx );
  }

  /* If we have finished distributing rewards, set the status to inactive
     https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L116-L135 */
  if( fd_ulong_sat_add( block_height, 1UL )>=distribution_end_exclusive ) {
    fd_sysvar_epoch_rewards_set_inactive( bank, accdb, capture_ctx );
    bank->stake_rewards_fork_id = UCHAR_MAX;
  }
}

/* Partitioned epoch rewards entry-point.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L102
*/
void
fd_begin_partitioned_rewards( fd_bank_t *                    bank,
                              fd_accdb_t *                   accdb,
                              fd_runtime_stack_t *           runtime_stack,
                              fd_capture_ctx_t *             capture_ctx,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_hash_t const *              parent_blockhash,
                              ulong                          parent_epoch ) {

  calculate_rewards_and_distribute_vote_rewards(
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
      runtime_stack->stakes.total_points.ud,
      parent_blockhash );
}

/*
    Re-calculates partitioned stake rewards.
    This updates the slot context's epoch reward status with the recalculated partitioned rewards.

    https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L521 */
void
fd_rewards_recalculate_partitioned_rewards( fd_banks_t *              banks,
                                            fd_bank_t *               bank,
                                            fd_accdb_t *              accdb,
                                            fd_runtime_stack_t *      runtime_stack,
                                            fd_capture_ctx_t *        capture_ctx ) {

  /* If the snapshot was loaded while partitioned epoch rewards is
     active, then the vote rewards map must be populated with the state
     of the vote accounts as of the end of the previous epoch boundary.
     The epoch credits for these accounts are stored in the bank along
     with the t-3 commission.  With this, it's possible to recalculate
     the rewards for the previous epoch boundary.  We need the
     commission from the end of the t-3 epoch if we are calculating
     rewards for the transition from epoch t-1 to t since there needs to
     be a 2 epoch commission gap for the delay_commission_updates
     feature. */

  fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;
  fd_vote_rewards_map_reset( vote_ele_map );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ushort             vs_fork_idx = bank->vote_stakes_fork_id;

  int vat_active = FD_FEATURE_ACTIVE_BANK( bank, validator_admission_ticket );
  int vat_in_t_2 = 0;
  if( FD_UNLIKELY( vat_active ) ) {
    ulong vat_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, bank->f.features.validator_admission_ticket, NULL );
    vat_in_t_2 = bank->f.epoch>=vat_epoch+1UL;
  }

  fd_top_votes_t const * top_votes_t_1 = fd_bank_top_votes_t_1_query( bank );
  fd_top_votes_t const * top_votes_t_2 = fd_bank_top_votes_t_2_query( bank );

  ulong epoch_credits_len = *fd_bank_epoch_credits_len( bank );
  for( ulong i=0UL; i<epoch_credits_len; i++ ) {
    fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[i];
    fd_pubkey_t const *  pubkey        = (fd_pubkey_t const *)epoch_credits->pubkey;

    /* Get the t-1 stake account information.  This is guaranteed to be
       valid since the epoch credits are populated from the t-1 stakes
       in the snapshot manfiest. */
    ushort commission_t_1 = 0;
    if( vat_active ) FD_TEST( fd_top_votes_query( top_votes_t_1, pubkey, NULL, NULL, NULL, NULL, &commission_t_1, NULL ) );
    else             FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, vs_fork_idx, pubkey, NULL, NULL, &commission_t_1 ) );

    /* Now get the t-2 information (if it exists).  This is not
       guaranteed to be valid since it's possible for a vote account to
       have been created in the last epoch. */
    int    exists_t_2     = 0;
    ushort commission_t_2 = 0;
    if( vat_in_t_2 ) exists_t_2 = fd_top_votes_query( top_votes_t_2, pubkey, NULL, NULL, NULL, NULL, &commission_t_2, NULL );
    else             exists_t_2 = fd_vote_stakes_query_t_2( vote_stakes, vs_fork_idx, pubkey, NULL, NULL, &commission_t_2 );

    fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[i];
    vote_ele->pubkey       = *(fd_pubkey_t *)epoch_credits->pubkey;
    vote_ele->vote_rewards = 0UL;
    if( FD_FEATURE_ACTIVE_BANK( bank, delay_commission_updates ) ) {
      vote_ele->commission = exists_t_2 ? commission_t_2 : commission_t_1;
    } else {
      vote_ele->commission = commission_t_1;
    }
    fd_vote_rewards_map_idx_insert( vote_ele_map, i, runtime_stack->stakes.vote_ele );
  }

  /* Copy in historical commission information if it exists. */
  if( FD_FEATURE_ACTIVE_BANK( bank, delay_commission_updates ) ) {
    ulong                     commission_t_3_len = *fd_bank_snapshot_commission_t_3_len( bank );
    fd_stashed_commission_t * commission_t_3     = fd_bank_snapshot_commission_t_3( bank );
    for( ulong i=0UL; i<commission_t_3_len; i++ ) {
      fd_stashed_commission_t const * ele = &commission_t_3[i];
      fd_vote_rewards_t * vote_ele = fd_vote_rewards_map_ele_query( vote_ele_map, (fd_pubkey_t *)ele->pubkey, NULL, runtime_stack->stakes.vote_ele );
      if( FD_LIKELY( vote_ele ) ) vote_ele->commission = ele->commission;
    }
  }

  fd_sysvar_epoch_rewards_t epoch_rewards_sysvar[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_rewards_read( accdb, bank->accdb_fork_id, epoch_rewards_sysvar ) ) ) {
    FD_LOG_DEBUG(( "Failed to read or decode epoch rewards sysvar - may not have been created yet" ));
    return;
  }

  FD_LOG_DEBUG(( "recalculating partitioned rewards" ));

  if( FD_UNLIKELY( !epoch_rewards_sysvar->active ) ) {
    FD_LOG_DEBUG(( "epoch rewards is inactive" ));
    return;
  }

  /* If partitioned rewards are active, the rewarded epoch is always the immediately
      preceeding epoch.

      https://github.com/anza-xyz/agave/blob/2316fea4c0852e59c071f72d72db020017ffd7d0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L566 */
  FD_LOG_DEBUG(( "epoch rewards is active" ));

  ulong const epoch          = bank->f.epoch;
  ulong const rewarded_epoch = fd_ulong_sat_sub( epoch, 1UL );

  fd_acc_t ro = fd_accdb_read_one( accdb, bank->accdb_fork_id, fd_sysvar_stake_history_id.uc );
  if( FD_UNLIKELY( !ro.lamports ) ) FD_LOG_ERR(( "Unable to read stake history sysvar" ));
  fd_stake_history_t stake_history[1];
  if( FD_UNLIKELY( !fd_sysvar_stake_history_view( stake_history, ro.data, ro.data_len ) ) ) {
    FD_LOG_ERR(( "Unable to decode stake history sysvar" ));
  }

  fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );

  calculate_stake_vote_rewards(
      bank,
      stake_delegations,
      capture_ctx,
      stake_history,
      rewarded_epoch,
      epoch_rewards_sysvar->total_rewards,
      epoch_rewards_sysvar->total_points.ud,
      runtime_stack,
      1 );

  setup_stake_partitions(
      bank,
      stake_history,
      stake_delegations,
      runtime_stack,
      &epoch_rewards_sysvar->parent_blockhash,
      epoch_rewards_sysvar->distribution_starting_block_height,
      (uint)epoch_rewards_sysvar->num_partitions,
      rewarded_epoch,
      epoch_rewards_sysvar->total_rewards,
      epoch_rewards_sysvar->total_points.ud );

  fd_accdb_unread_one( accdb, &ro );
  fd_bank_stake_delegations_end_frontier_query( banks, bank );
}
