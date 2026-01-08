#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_warmup_cooldown_allowance_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_warmup_cooldown_allowance_h

#include "../types/fd_types.h"

/* Port of stake warmup/cooldown allowance calculations
   https://github.com/solana-program/stake/pull/152
   https://github.com/solana-program/stake/blob/9719141dc60e0f03f5865a5091136d3d3dcbebfa/interface/src/warmup_cooldown_allowance.rs */

#define FD_STAKE_BASIS_POINTS_PER_UNIT             (10000UL)
#define FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS (2500UL) /* 25% */
#define FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS    (900UL)  /* 9%  */

FD_PROTOTYPES_BEGIN

ulong
fd_stake_warmup_cooldown_rate_bps( ulong epoch, ulong const * new_rate_activation_epoch );

ulong
fd_stake_calculate_activation_allowance( ulong                          current_epoch,
                                         ulong                          account_activating_stake,
                                         fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                         ulong const *                  new_rate_activation_epoch );

ulong
fd_stake_calculate_deactivation_allowance( ulong                          current_epoch,
                                           ulong                          account_deactivating_stake,
                                           fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                           ulong const *                  new_rate_activation_epoch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_warmup_cooldown_allowance_h */
