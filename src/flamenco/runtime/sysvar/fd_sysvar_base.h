#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_base_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_base_h

#include "../../fd_flamenco_base.h"
#include "../../accdb/fd_accdb_base.h"
#include "../../types/fd_types_custom.h"

#define FD_SYSVAR_ALIGN_MAX (16UL)

#define FD_SYSVAR_CLOCK_BINCODE_SZ         (    40UL)

#define FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ (    81UL)

#define FD_SYSVAR_EPOCH_SCHEDULE_BINCODE_SZ (   33UL)

#define FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ  (8UL)

#define FD_SYSVAR_RECENT_HASHES_BINCODE_SZ (  6008UL) /* Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/recent_blockhashes.rs#L157 */
#define FD_SYSVAR_RECENT_HASHES_ALIGN      (     8UL)
#define FD_SYSVAR_RECENT_HASHES_FOOTPRINT  (  6088UL)

#define FD_SYSVAR_RENT_BINCODE_SZ          (    17UL)

#define FD_SYSVAR_SLOT_HASHES_BINCODE_SZ   ( 20488UL) /* Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/slot_hashes.rs#L69 */
#define FD_SYSVAR_SLOT_HASHES_ALIGN        (     8UL)
#define FD_SYSVAR_SLOT_HASHES_FOOTPRINT    ( 20528UL)

#define FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ  (131097UL) /* Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/slot_history.rs#L65 */
#define FD_SYSVAR_SLOT_HISTORY_ALIGN       (     8UL)
#define FD_SYSVAR_SLOT_HISTORY_FOOTPRINT   (131120UL)

#define FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ( 16392UL) /* Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/stake_history.rs#L66 */
#define FD_SYSVAR_STAKE_HISTORY_ALIGN      (     8UL)
#define FD_SYSVAR_STAKE_HISTORY_FOOTPRINT  ( 16408UL)

struct fd_sysvar_clock {
  ulong slot;
  long  epoch_start_timestamp;
  ulong epoch;
  ulong leader_schedule_epoch;
  long  unix_timestamp;
};
typedef struct fd_sysvar_clock fd_sol_sysvar_clock_t;

struct fd_sysvar_epoch_rewards {
  ulong       distribution_starting_block_height;
  ulong       num_partitions;
  fd_hash_t   parent_blockhash;
  fd_w_u128_t total_points;
  ulong       total_rewards;
  ulong       distributed_rewards;
  uchar       active; /* 0 or 1 */
  uchar       padding_[15];
};
typedef struct fd_sysvar_epoch_rewards fd_sysvar_epoch_rewards_t;

struct fd_rent {
  ulong  lamports_per_uint8_year;
  double exemption_threshold;
  uchar  burn_percent;
  uchar  padding_[7];
};
typedef struct fd_rent fd_rent_t;

struct __attribute__((packed)) fd_epoch_schedule {
  ulong slots_per_epoch;
  ulong leader_schedule_slot_offset;
  uchar warmup; /* 0 or 1 */
  ulong first_normal_epoch;
  ulong first_normal_slot;
};
typedef struct fd_epoch_schedule fd_epoch_schedule_t;

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_base_h */
