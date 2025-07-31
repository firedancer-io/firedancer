#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_base_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_base_h

#include "../../fd_flamenco_base.h"
#include "../../../funk/fd_funk_base.h"

#define FD_SYSVAR_ALIGN_MAX (16UL)

#define FD_SYSVAR_CLOCK_BINCODE_SZ         (    40UL)
#define FD_SYSVAR_CLOCK_ALIGN              (     8UL)
#define FD_SYSVAR_CLOCK_FOOTPRINT          (    40UL)

#define FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ (    81UL)
/*      FD_SYSVAR_EPOCH_REWARDS_ALIGN provided by fd_types.h (16UL) */
#define FD_SYSVAR_EPOCH_REWARDS_FOOTPRINT  (    96UL)

#define FD_SYSVAR_EPOCH_SCHEDULE_BINCODE_SZ (   33UL)
#define FD_SYSVAR_EPOCH_SCHEDULE_ALIGN      (    8UL)
#define FD_SYSVAR_EPOCH_SCHEDULE_FOOTPRINT  (   40UL)

#define FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ  (8UL)
#define FD_SYSVAR_LAST_RESTART_SLOT_ALIGN       (8UL)
#define FD_SYSVAR_LAST_RESTART_SLOT_FOOTPRINT   (8UL)

#define FD_SYSVAR_RECENT_HASHES_BINCODE_SZ (  6008UL) /* Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/recent_blockhashes.rs#L157 */
#define FD_SYSVAR_RECENT_HASHES_ALIGN      (     8UL)
#define FD_SYSVAR_RECENT_HASHES_FOOTPRINT  (  6088UL)

#define FD_SYSVAR_RENT_BINCODE_SZ          (    17UL)
#define FD_SYSVAR_RENT_ALIGN               (     8UL)
#define FD_SYSVAR_RENT_FOOTPRINT           (    24UL)

#define FD_SYSVAR_SLOT_HASHES_BINCODE_SZ   ( 20488UL) /* Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/slot_hashes.rs#L69 */
#define FD_SYSVAR_SLOT_HASHES_ALIGN        (     8UL)
#define FD_SYSVAR_SLOT_HASHES_FOOTPRINT    ( 20528UL)

#define FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ  (131097UL) /* Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/slot_history.rs#L65 */
#define FD_SYSVAR_SLOT_HISTORY_ALIGN       (     8UL)
#define FD_SYSVAR_SLOT_HISTORY_FOOTPRINT   (131120UL)

#define FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ( 16392UL) /* Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/stake_history.rs#L66 */
#define FD_SYSVAR_STAKE_HISTORY_ALIGN      (     8UL)
#define FD_SYSVAR_STAKE_HISTORY_FOOTPRINT  ( 16408UL)

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_base_h */
