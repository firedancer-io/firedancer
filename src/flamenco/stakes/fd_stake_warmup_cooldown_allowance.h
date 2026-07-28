#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_warmup_cooldown_allowance_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_warmup_cooldown_allowance_h

#include "../runtime/sysvar/fd_sysvar_base.h"

/* Fixed-point stake warmup/cooldown allowance math from SIMD-0391.
   https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0391-replace-stake-program-floating-point.md
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs

   All amounts are in lamports.  Rates are in basis points. */

#define FD_STAKE_BASIS_POINTS_PER_UNIT             (10000UL)
#define FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS (2500UL) /* 25% */
#define FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS    (900UL)  /* 9%  */

FD_PROTOTYPES_BEGIN

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L8

   Returns the rate in basis points.  NULL represents Option::None:
   the original rate applies for every epoch, including ULONG_MAX. */

ulong
fd_stake_warmup_cooldown_rate_bps( ulong epoch, ulong const * new_rate_activation_epoch );

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L20
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L55

   Returns the raw activation allowance.  Transition walkers must apply
   SIMD-0391's 1-lamport minimum progress clamp; reward payouts must
   not.  Rust transition call site:
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/state.rs#L939 */

ulong
fd_stake_calculate_activation_allowance( ulong                            current_epoch,
                                         ulong                            account_activating_stake,
                                         fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                         ulong const *                    new_rate_activation_epoch );

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L39
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L55

   Returns the raw deactivation allowance.  Same minimum-progress
   boundary as activation.  Rust transition call site:
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/state.rs#L851 */

ulong
fd_stake_calculate_deactivation_allowance( ulong                            current_epoch,
                                           ulong                            account_deactivating_stake,
                                           fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                           ulong const *                    new_rate_activation_epoch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_warmup_cooldown_allowance_h */
