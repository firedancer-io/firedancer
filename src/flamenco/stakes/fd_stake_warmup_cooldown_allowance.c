#include "fd_stake_warmup_cooldown_allowance.h"

#include "../../util/bits/fd_sat.h"

#if !FD_HAS_INT128
#error "fd_stake_warmup_cooldown_allowance requires FD_HAS_INT128"
#endif

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L8

   Note: this intentionally differs from the legacy float helper
   fd_stake_warmup_cooldown_rate at exactly one point.  The legacy
   helper (and legacy Agave) treats a missing activation epoch as
   ULONG_MAX, so epoch==ULONG_MAX selects the tower rate.  The Rust
   reference uses Option::is_some_and, so a missing activation epoch
   never activates the tower rate, even at epoch ULONG_MAX. */
ulong
fd_stake_warmup_cooldown_rate_bps( ulong epoch, ulong const * new_rate_activation_epoch ) {
  return ( new_rate_activation_epoch && epoch >= *new_rate_activation_epoch )
           ? FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS
           : FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS;
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L55 */
static inline ulong
calculate_stake_change_allowance( ulong epoch,
                                  ulong account_portion,
                                  ulong cluster_portion,
                                  ulong cluster_effective,
                                  ulong const * new_rate_activation_epoch ) {
  /* Early return if there's no stake to change (also prevents divide
     by zero) */
  if( FD_UNLIKELY( !account_portion || !cluster_portion || !cluster_effective ) ) return 0UL;

  ulong rate_bps = fd_stake_warmup_cooldown_rate_bps( epoch, new_rate_activation_epoch );

  /* change = (account_portion * cluster_effective * rate_bps) /
              (cluster_portion * BASIS_POINTS_PER_UNIT)
     Saturating u128 multiply chain in Rust:
     https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L82 */
  __uint128_t numerator =
      fd_uint128_sat_mul( fd_uint128_sat_mul( (__uint128_t)account_portion, (__uint128_t)cluster_effective ),
                          (__uint128_t)rate_bps );

  __uint128_t denominator =
      fd_uint128_sat_mul( (__uint128_t)cluster_portion, (__uint128_t)FD_STAKE_BASIS_POINTS_PER_UNIT );

  /* Denominator cannot be zero due to the early-return guards above
     (cluster_portion>=1 implies denominator>=BASIS_POINTS_PER_UNIT,
     and saturating multiplication of non-zero operands cannot yield
     zero). */
  __uint128_t delta = numerator / denominator;
  if( delta > (__uint128_t)account_portion ) delta = (__uint128_t)account_portion;

  return (ulong)delta;
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L20 */
ulong
fd_stake_calculate_activation_allowance( ulong                            current_epoch,
                                         ulong                            account_activating_stake,
                                         fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                         ulong const *                    new_rate_activation_epoch ) {
  return calculate_stake_change_allowance( current_epoch,
                                           account_activating_stake,
                                           prev_epoch_cluster_state->activating,
                                           prev_epoch_cluster_state->effective,
                                           new_rate_activation_epoch );
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L39 */
ulong
fd_stake_calculate_deactivation_allowance( ulong                            current_epoch,
                                           ulong                            account_deactivating_stake,
                                           fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                           ulong const *                    new_rate_activation_epoch ) {
  return calculate_stake_change_allowance( current_epoch,
                                           account_deactivating_stake,
                                           prev_epoch_cluster_state->deactivating,
                                           prev_epoch_cluster_state->effective,
                                           new_rate_activation_epoch );
}
