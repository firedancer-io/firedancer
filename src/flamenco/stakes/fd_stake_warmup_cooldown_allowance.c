#include "fd_stake_warmup_cooldown_allowance.h"

#include "../../util/bits/fd_sat.h"

#if !FD_HAS_INT128
#error "fd_stake_warmup_cooldown_allowance requires FD_HAS_INT128"
#endif

/* https://github.com/solana-program/stake/pull/152
   https://github.com/solana-program/stake/blob/9719141dc60e0f03f5865a5091136d3d3dcbebfa/interface/src/warmup_cooldown_allowance.rs#L8 */
ulong
fd_stake_warmup_cooldown_rate_bps( ulong epoch, ulong const * new_rate_activation_epoch ) {
  return ( epoch < ( new_rate_activation_epoch ? *new_rate_activation_epoch : ULONG_MAX ) )
           ? FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS
           : FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS;
}

/* https://github.com/solana-program/stake/pull/152
   https://github.com/solana-program/stake/blob/9719141dc60e0f03f5865a5091136d3d3dcbebfa/interface/src/warmup_cooldown_allowance.rs#L55 */
static inline ulong
rate_limited_stake_change( ulong epoch,
                           ulong account_portion,
                           ulong cluster_portion,
                           ulong cluster_effective,
                           ulong const * new_rate_activation_epoch ) {
  if( FD_UNLIKELY( !account_portion || !cluster_portion || !cluster_effective ) ) return 0UL;

  ulong rate_bps = fd_stake_warmup_cooldown_rate_bps( epoch, new_rate_activation_epoch );

  /* change = (account_portion * cluster_effective * rate_bps) /
              (cluster_portion * BASIS_POINTS_PER_UNIT)
     Saturating u128 multiply chain in Rust:
     https://github.com/solana-program/stake/blob/9719141dc60e0f03f5865a5091136d3d3dcbebfa/interface/src/warmup_cooldown_allowance.rs#L69 */
  __uint128_t numerator =
      fd_uint128_sat_mul( fd_uint128_sat_mul( (__uint128_t)account_portion, (__uint128_t)cluster_effective ),
                          (__uint128_t)rate_bps );

  __uint128_t denominator =
      fd_uint128_sat_mul( (__uint128_t)cluster_portion, (__uint128_t)FD_STAKE_BASIS_POINTS_PER_UNIT );

  if( FD_UNLIKELY( !denominator ) ) return 0UL;

  __uint128_t delta = numerator / denominator;
  if( delta > (__uint128_t)account_portion ) delta = (__uint128_t)account_portion;

  return (ulong)delta;
}

/* https://github.com/solana-program/stake/pull/152
   https://github.com/solana-program/stake/blob/9719141dc60e0f03f5865a5091136d3d3dcbebfa/interface/src/warmup_cooldown_allowance.rs#L20 */
ulong
fd_stake_calculate_activation_allowance( ulong                          current_epoch,
                                         ulong                          account_activating_stake,
                                         fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                         ulong const *                  new_rate_activation_epoch ) {
  return rate_limited_stake_change( current_epoch,
                                    account_activating_stake,
                                    prev_epoch_cluster_state->activating,
                                    prev_epoch_cluster_state->effective,
                                    new_rate_activation_epoch );
}

/* https://github.com/solana-program/stake/pull/152
   https://github.com/solana-program/stake/blob/9719141dc60e0f03f5865a5091136d3d3dcbebfa/interface/src/warmup_cooldown_allowance.rs#L39 */
ulong
fd_stake_calculate_deactivation_allowance( ulong                          current_epoch,
                                           ulong                          account_deactivating_stake,
                                           fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                           ulong const *                  new_rate_activation_epoch ) {
  return rate_limited_stake_change( current_epoch,
                                    account_deactivating_stake,
                                    prev_epoch_cluster_state->deactivating,
                                    prev_epoch_cluster_state->effective,
                                    new_rate_activation_epoch );
}
