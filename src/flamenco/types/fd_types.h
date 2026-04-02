// This is an auto-generated file. To add entries, edit fd_types.json
#ifndef HEADER_FD_RUNTIME_TYPES
#define HEADER_FD_RUNTIME_TYPES

#include "fd_bincode.h"
#include "../../ballet/utf8/fd_utf8.h"
#include "fd_types_custom.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L9 */
/* Encoded Size: Fixed (8 bytes) */
struct fd_fee_calculator {
  ulong lamports_per_signature;
};
typedef struct fd_fee_calculator fd_fee_calculator_t;
#define FD_FEE_CALCULATOR_ALIGN alignof(fd_fee_calculator_t)

/* Encoded Size: Fixed (16 bytes) */
struct fd_slot_pair {
  ulong slot;
  ulong val;
};
typedef struct fd_slot_pair fd_slot_pair_t;
#define FD_SLOT_PAIR_ALIGN alignof(fd_slot_pair_t)

/* Encoded Size: Dynamic */
struct fd_hard_forks {
  ulong hard_forks_len;
  fd_slot_pair_t * hard_forks;
};
typedef struct fd_hard_forks fd_hard_forks_t;
#define FD_HARD_FORKS_ALIGN alignof(fd_hard_forks_t)

struct fd_hard_forks_global {
  ulong hard_forks_len;
  ulong hard_forks_offset;
};
typedef struct fd_hard_forks_global fd_hard_forks_global_t;
#define FD_HARD_FORKS_GLOBAL_ALIGN alignof(fd_hard_forks_global_t)

FD_FN_UNUSED static fd_slot_pair_t * fd_hard_forks_hard_forks_join( fd_hard_forks_global_t const * struct_mem ) { // vector
  return struct_mem->hard_forks_offset ? (fd_slot_pair_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->hard_forks_offset ) : NULL;
}
FD_FN_UNUSED static void fd_hard_forks_hard_forks_update( fd_hard_forks_global_t * struct_mem, fd_slot_pair_t * vec ) {
  struct_mem->hard_forks_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* Encoded Size: Fixed (48 bytes) */
struct fd_inflation {
  double initial;
  double terminal;
  double taper;
  double foundation;
  double foundation_term;
  double unused;
};
typedef struct fd_inflation fd_inflation_t;
#define FD_INFLATION_ALIGN alignof(fd_inflation_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/rent.rs#L11 */
/* Encoded Size: Fixed (17 bytes) */
struct fd_rent {
  ulong lamports_per_uint8_year;
  double exemption_threshold;
  uchar burn_percent;
};
typedef struct fd_rent fd_rent_t;
#define FD_RENT_ALIGN alignof(fd_rent_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/epoch_schedule.rs#L26 */
/* Encoded Size: Fixed (33 bytes) */
struct fd_epoch_schedule {
  ulong slots_per_epoch;
  ulong leader_schedule_slot_offset;
  uchar warmup;
  ulong first_normal_epoch;
  ulong first_normal_slot;
};
typedef struct fd_epoch_schedule fd_epoch_schedule_t;
#define FD_EPOCH_SCHEDULE_ALIGN alignof(fd_epoch_schedule_t)

/* https://github.com/solana-program/stake/blob/330d89c6246ab3fd35d02803386fa700be0455d6/interface/src/stake_history.rs#L17 */
/* Encoded Size: Fixed (24 bytes) */
struct fd_stake_history_entry {
  ulong effective;
  ulong activating;
  ulong deactivating;
};
typedef struct fd_stake_history_entry fd_stake_history_entry_t;
#define FD_STAKE_HISTORY_ENTRY_ALIGN alignof(fd_stake_history_entry_t)

/* https://github.com/solana-program/stake/blob/330d89c6246ab3fd35d02803386fa700be0455d6/interface/src/stake_history.rs#L66 */
/* Encoded Size: Fixed (32 bytes) */
struct fd_epoch_stake_history_entry_pair {
  ulong epoch;
  fd_stake_history_entry_t entry;
};
typedef struct fd_epoch_stake_history_entry_pair fd_epoch_stake_history_entry_pair_t;
#define FD_EPOCH_STAKE_HISTORY_ENTRY_PAIR_ALIGN alignof(fd_epoch_stake_history_entry_pair_t)

/* https://github.com/solana-program/stake/blob/330d89c6246ab3fd35d02803386fa700be0455d6/interface/src/stake_history.rs#L66 */
/* Encoded Size: Fixed (16392 bytes) */
struct fd_stake_history {
  ulong fd_stake_history_len;
  ulong fd_stake_history_size;
  ulong fd_stake_history_offset;
  fd_epoch_stake_history_entry_pair_t fd_stake_history[512];
};
typedef struct fd_stake_history fd_stake_history_t;
#define FD_STAKE_HISTORY_ALIGN alignof(fd_stake_history_t)

/* Encoded Size: Fixed (12 bytes) */
struct fd_rust_duration {
  ulong seconds;
  uint nanoseconds;
};
typedef struct fd_rust_duration fd_rust_duration_t;
#define FD_RUST_DURATION_ALIGN alignof(fd_rust_duration_t)

/* Encoded Size: Dynamic */
struct fd_poh_config {
  fd_rust_duration_t target_tick_duration;
  ulong target_tick_count;
  uchar has_target_tick_count;
  ulong hashes_per_tick;
  uchar has_hashes_per_tick;
};
typedef struct fd_poh_config fd_poh_config_t;
#define FD_POH_CONFIG_ALIGN alignof(fd_poh_config_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L11 */
/* Encoded Size: Dynamic */
struct fd_slot_history {
  uchar has_bits;
  ulong bits_bitvec_len;
  ulong* bits_bitvec;
  ulong bits_len;
  ulong next_slot;
};
typedef struct fd_slot_history fd_slot_history_t;
#define FD_SLOT_HISTORY_ALIGN alignof(fd_slot_history_t)

struct fd_slot_history_global {
  uchar has_bits;
  ulong bits_bitvec_len;
  ulong bits_bitvec_offset;
  ulong bits_len;
  ulong next_slot;
};
typedef struct fd_slot_history_global fd_slot_history_global_t;
#define FD_SLOT_HISTORY_GLOBAL_ALIGN alignof(fd_slot_history_global_t)

/* Encoded Size: Fixed (40 bytes) */
struct fd_slot_hash {
  ulong slot;
  fd_hash_t hash;
};
typedef struct fd_slot_hash fd_slot_hash_t;
#define FD_SLOT_HASH_ALIGN alignof(fd_slot_hash_t)

#define DEQUE_NAME deq_fd_slot_hash_t
#define DEQUE_T fd_slot_hash_t
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline fd_slot_hash_t *
deq_fd_slot_hash_t_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_slot_hash_t_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_fd_slot_hash_t_footprint( max );
  return deq_fd_slot_hash_t_join( deq_fd_slot_hash_t_new( deque_mem, max ) );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_hashes.rs#L31 */
/* Encoded Size: Dynamic */
struct fd_slot_hashes {
  fd_slot_hash_t * hashes; /* fd_deque_dynamic (min cnt 512) */
};
typedef struct fd_slot_hashes fd_slot_hashes_t;
#define FD_SLOT_HASHES_ALIGN alignof(fd_slot_hashes_t)

struct fd_slot_hashes_global {
  ulong hashes_offset; /* fd_deque_dynamic (min cnt 512) */
};
typedef struct fd_slot_hashes_global fd_slot_hashes_global_t;
#define FD_SLOT_HASHES_GLOBAL_ALIGN alignof(fd_slot_hashes_global_t)

static FD_FN_UNUSED fd_slot_hash_t * fd_slot_hashes_hashes_join( fd_slot_hashes_global_t * type ) { // deque
  return type->hashes_offset ? (fd_slot_hash_t *)deq_fd_slot_hash_t_join( fd_type_pun( (uchar *)type + type->hashes_offset ) ) : NULL;
}
/* Encoded Size: Fixed (40 bytes) */
struct fd_block_block_hash_entry {
  fd_hash_t blockhash;
  fd_fee_calculator_t fee_calculator;
};
typedef struct fd_block_block_hash_entry fd_block_block_hash_entry_t;
#define FD_BLOCK_BLOCK_HASH_ENTRY_ALIGN alignof(fd_block_block_hash_entry_t)

#define DEQUE_NAME deq_fd_block_block_hash_entry_t
#define DEQUE_T fd_block_block_hash_entry_t
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline fd_block_block_hash_entry_t *
deq_fd_block_block_hash_entry_t_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_block_block_hash_entry_t_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_fd_block_block_hash_entry_t_footprint( max );
  return deq_fd_block_block_hash_entry_t_join( deq_fd_block_block_hash_entry_t_new( deque_mem, max ) );
}

/* Encoded Size: Dynamic */
struct fd_recent_block_hashes {
  fd_block_block_hash_entry_t * hashes; /* fd_deque_dynamic (min cnt 151) */
};
typedef struct fd_recent_block_hashes fd_recent_block_hashes_t;
#define FD_RECENT_BLOCK_HASHES_ALIGN alignof(fd_recent_block_hashes_t)

struct fd_recent_block_hashes_global {
  ulong hashes_offset; /* fd_deque_dynamic (min cnt 151) */
};
typedef struct fd_recent_block_hashes_global fd_recent_block_hashes_global_t;
#define FD_RECENT_BLOCK_HASHES_GLOBAL_ALIGN alignof(fd_recent_block_hashes_global_t)

static FD_FN_UNUSED fd_block_block_hash_entry_t * fd_recent_block_hashes_hashes_join( fd_recent_block_hashes_global_t * type ) { // deque
  return type->hashes_offset ? (fd_block_block_hash_entry_t *)deq_fd_block_block_hash_entry_t_join( fd_type_pun( (uchar *)type + type->hashes_offset ) ) : NULL;
}
/* Encoded Size: Dynamic */
struct fd_slot_meta {
  ulong slot;
  ulong consumed;
  ulong received;
  long first_shred_timestamp;
  ulong last_index;
  ulong parent_slot;
  ulong next_slot_len;
  ulong* next_slot;
  uchar is_connected;
};
typedef struct fd_slot_meta fd_slot_meta_t;
#define FD_SLOT_META_ALIGN alignof(fd_slot_meta_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/fees.rs#L21 */
/* Encoded Size: Fixed (8 bytes) */
struct fd_sysvar_fees {
  fd_fee_calculator_t fee_calculator;
};
typedef struct fd_sysvar_fees fd_sysvar_fees_t;
#define FD_SYSVAR_FEES_ALIGN alignof(fd_sysvar_fees_t)

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/epoch_rewards.rs#L14 */
/* Encoded Size: Fixed (81 bytes) */
struct fd_sysvar_epoch_rewards {
  ulong distribution_starting_block_height;
  ulong num_partitions;
  fd_hash_t parent_blockhash;
  fd_w_u128_t total_points;
  ulong total_rewards;
  ulong distributed_rewards;
  uchar active;
};
typedef struct fd_sysvar_epoch_rewards fd_sysvar_epoch_rewards_t;
#define FD_SYSVAR_EPOCH_REWARDS_ALIGN alignof(fd_sysvar_epoch_rewards_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/system_instruction.rs#L158 */
/* Encoded Size: Fixed (48 bytes) */
struct fd_system_program_instruction_create_account {
  ulong lamports;
  ulong space;
  fd_pubkey_t owner;
};
typedef struct fd_system_program_instruction_create_account fd_system_program_instruction_create_account_t;
#define FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_ALIGN alignof(fd_system_program_instruction_create_account_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/system_instruction.rs#L193 */
/* Encoded Size: Dynamic */
struct fd_system_program_instruction_create_account_with_seed {
  fd_pubkey_t base;
  ulong seed_len;
  uchar* seed;
  ulong lamports;
  ulong space;
  fd_pubkey_t owner;
};
typedef struct fd_system_program_instruction_create_account_with_seed fd_system_program_instruction_create_account_with_seed_t;
#define FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_WITH_SEED_ALIGN alignof(fd_system_program_instruction_create_account_with_seed_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/system_instruction.rs#L269 */
/* Encoded Size: Dynamic */
struct fd_system_program_instruction_allocate_with_seed {
  fd_pubkey_t base;
  ulong seed_len;
  uchar* seed;
  ulong space;
  fd_pubkey_t owner;
};
typedef struct fd_system_program_instruction_allocate_with_seed fd_system_program_instruction_allocate_with_seed_t;
#define FD_SYSTEM_PROGRAM_INSTRUCTION_ALLOCATE_WITH_SEED_ALIGN alignof(fd_system_program_instruction_allocate_with_seed_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/system_instruction.rs#L288 */
/* Encoded Size: Dynamic */
struct fd_system_program_instruction_assign_with_seed {
  fd_pubkey_t base;
  ulong seed_len;
  uchar* seed;
  fd_pubkey_t owner;
};
typedef struct fd_system_program_instruction_assign_with_seed fd_system_program_instruction_assign_with_seed_t;
#define FD_SYSTEM_PROGRAM_INSTRUCTION_ASSIGN_WITH_SEED_ALIGN alignof(fd_system_program_instruction_assign_with_seed_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/system_instruction.rs#L288 */
/* Encoded Size: Dynamic */
struct fd_system_program_instruction_transfer_with_seed {
  ulong lamports;
  ulong from_seed_len;
  uchar* from_seed;
  fd_pubkey_t from_owner;
};
typedef struct fd_system_program_instruction_transfer_with_seed fd_system_program_instruction_transfer_with_seed_t;
#define FD_SYSTEM_PROGRAM_INSTRUCTION_TRANSFER_WITH_SEED_ALIGN alignof(fd_system_program_instruction_transfer_with_seed_t)

union fd_system_program_instruction_inner {
  fd_system_program_instruction_create_account_t create_account;
  fd_pubkey_t assign;
  ulong transfer;
  fd_system_program_instruction_create_account_with_seed_t create_account_with_seed;
  ulong withdraw_nonce_account;
  fd_pubkey_t initialize_nonce_account;
  fd_pubkey_t authorize_nonce_account;
  ulong allocate;
  fd_system_program_instruction_allocate_with_seed_t allocate_with_seed;
  fd_system_program_instruction_assign_with_seed_t assign_with_seed;
  fd_system_program_instruction_transfer_with_seed_t transfer_with_seed;
  fd_system_program_instruction_create_account_t create_account_allow_prefund;
};
typedef union fd_system_program_instruction_inner fd_system_program_instruction_inner_t;

/* https://github.com/anza-xyz/solana-sdk/blob/system-interface%40v3.0.0/system-interface/src/instruction.rs#L92-L299 */
struct fd_system_program_instruction {
  uint discriminant;
  fd_system_program_instruction_inner_t inner;
};
typedef struct fd_system_program_instruction fd_system_program_instruction_t;
#define FD_SYSTEM_PROGRAM_INSTRUCTION_ALIGN alignof(fd_system_program_instruction_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/nonce/state/current.rs#L17 */
/* Encoded Size: Fixed (72 bytes) */
struct fd_nonce_data {
  fd_pubkey_t authority;
  fd_hash_t durable_nonce;
  fd_fee_calculator_t fee_calculator;
};
typedef struct fd_nonce_data fd_nonce_data_t;
#define FD_NONCE_DATA_ALIGN alignof(fd_nonce_data_t)

union fd_nonce_state_inner {
  fd_nonce_data_t initialized;
};
typedef union fd_nonce_state_inner fd_nonce_state_inner_t;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/nonce/state/current.rs#L65 */
struct fd_nonce_state {
  uint discriminant;
  fd_nonce_state_inner_t inner;
};
typedef struct fd_nonce_state fd_nonce_state_t;
#define FD_NONCE_STATE_ALIGN alignof(fd_nonce_state_t)

union fd_nonce_state_versions_inner {
  fd_nonce_state_t legacy;
  fd_nonce_state_t current;
};
typedef union fd_nonce_state_versions_inner fd_nonce_state_versions_inner_t;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/nonce/state/mod.rs#L9 */
struct fd_nonce_state_versions {
  uint discriminant;
  fd_nonce_state_versions_inner_t inner;
};
typedef struct fd_nonce_state_versions fd_nonce_state_versions_t;
#define FD_NONCE_STATE_VERSIONS_ALIGN alignof(fd_nonce_state_versions_t)

/* https://github.com/solana-labs/solana/blob/6c520396cd76807f6227a7973f7373b37894251c/sdk/src/compute_budget.rs#L28 */
/* Encoded Size: Fixed (8 bytes) */
struct fd_compute_budget_program_instruction_request_units_deprecated {
  uint units;
  uint additional_fee;
};
typedef struct fd_compute_budget_program_instruction_request_units_deprecated fd_compute_budget_program_instruction_request_units_deprecated_t;
#define FD_COMPUTE_BUDGET_PROGRAM_INSTRUCTION_REQUEST_UNITS_DEPRECATED_ALIGN alignof(fd_compute_budget_program_instruction_request_units_deprecated_t)

union fd_compute_budget_program_instruction_inner {
  fd_compute_budget_program_instruction_request_units_deprecated_t request_units_deprecated;
  uint request_heap_frame;
  uint set_compute_unit_limit;
  ulong set_compute_unit_price;
  uint set_loaded_accounts_data_size_limit;
};
typedef union fd_compute_budget_program_instruction_inner fd_compute_budget_program_instruction_inner_t;

/* https://github.com/solana-labs/solana/blob/6c520396cd76807f6227a7973f7373b37894251c/sdk/src/compute_budget.rs#L25 */
struct fd_compute_budget_program_instruction {
  uint discriminant;
  fd_compute_budget_program_instruction_inner_t inner;
};
typedef struct fd_compute_budget_program_instruction fd_compute_budget_program_instruction_t;
#define FD_COMPUTE_BUDGET_PROGRAM_INSTRUCTION_ALIGN alignof(fd_compute_budget_program_instruction_t)

/* Encoded Size: Dynamic */
struct fd_bpf_loader_program_instruction_write {
  uint offset;
  ulong bytes_len;
  uchar* bytes;
};
typedef struct fd_bpf_loader_program_instruction_write fd_bpf_loader_program_instruction_write_t;
#define FD_BPF_LOADER_PROGRAM_INSTRUCTION_WRITE_ALIGN alignof(fd_bpf_loader_program_instruction_write_t)

union fd_bpf_loader_program_instruction_inner {
  fd_bpf_loader_program_instruction_write_t write;
};
typedef union fd_bpf_loader_program_instruction_inner fd_bpf_loader_program_instruction_inner_t;

struct fd_bpf_loader_program_instruction {
  uint discriminant;
  fd_bpf_loader_program_instruction_inner_t inner;
};
typedef struct fd_bpf_loader_program_instruction fd_bpf_loader_program_instruction_t;
#define FD_BPF_LOADER_PROGRAM_INSTRUCTION_ALIGN alignof(fd_bpf_loader_program_instruction_t)

/* https://github.com/anza-xyz/solana-sdk/blob/loader-v4-interface%40v2.2.1/loader-v4-interface/src/instruction.rs#L21-L27 */
/* Encoded Size: Dynamic */
struct fd_loader_v4_program_instruction_write {
  uint offset;
  ulong bytes_len;
  uchar* bytes;
};
typedef struct fd_loader_v4_program_instruction_write fd_loader_v4_program_instruction_write_t;
#define FD_LOADER_V4_PROGRAM_INSTRUCTION_WRITE_ALIGN alignof(fd_loader_v4_program_instruction_write_t)

/* https://github.com/anza-xyz/solana-sdk/blob/loader-v4-interface%40v2.2.1/loader-v4-interface/src/instruction.rs#L35-L42 */
/* Encoded Size: Fixed (12 bytes) */
struct fd_loader_v4_program_instruction_copy {
  uint destination_offset;
  uint source_offset;
  uint length;
};
typedef struct fd_loader_v4_program_instruction_copy fd_loader_v4_program_instruction_copy_t;
#define FD_LOADER_V4_PROGRAM_INSTRUCTION_COPY_ALIGN alignof(fd_loader_v4_program_instruction_copy_t)

/* https://github.com/anza-xyz/solana-sdk/blob/loader-v4-interface%40v2.2.1/loader-v4-interface/src/instruction.rs#L57-L60 */
/* Encoded Size: Fixed (4 bytes) */
struct fd_loader_v4_program_instruction_set_program_length {
  uint new_size;
};
typedef struct fd_loader_v4_program_instruction_set_program_length fd_loader_v4_program_instruction_set_program_length_t;
#define FD_LOADER_V4_PROGRAM_INSTRUCTION_SET_PROGRAM_LENGTH_ALIGN alignof(fd_loader_v4_program_instruction_set_program_length_t)

union fd_loader_v4_program_instruction_inner {
  fd_loader_v4_program_instruction_write_t write;
  fd_loader_v4_program_instruction_copy_t copy;
  fd_loader_v4_program_instruction_set_program_length_t set_program_length;
};
typedef union fd_loader_v4_program_instruction_inner fd_loader_v4_program_instruction_inner_t;

/* https://github.com/anza-xyz/agave/blob/007194391ca8313b2854d523769d0bedf040ef92/sdk/program/src/loader_v4_instruction.rs#L5 */
struct fd_loader_v4_program_instruction {
  uint discriminant;
  fd_loader_v4_program_instruction_inner_t inner;
};
typedef struct fd_loader_v4_program_instruction fd_loader_v4_program_instruction_t;
#define FD_LOADER_V4_PROGRAM_INSTRUCTION_ALIGN alignof(fd_loader_v4_program_instruction_t)

/* Encoded Size: Dynamic */
struct fd_bpf_upgradeable_loader_program_instruction_write {
  uint offset;
  ulong bytes_len;
  uchar* bytes;
};
typedef struct fd_bpf_upgradeable_loader_program_instruction_write fd_bpf_upgradeable_loader_program_instruction_write_t;
#define FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_WRITE_ALIGN alignof(fd_bpf_upgradeable_loader_program_instruction_write_t)

/* Encoded Size: Fixed (8 bytes) */
struct fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len {
  ulong max_data_len;
};
typedef struct fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t;
#define FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN_ALIGN alignof(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t)

/* Encoded Size: Fixed (4 bytes) */
struct fd_bpf_upgradeable_loader_program_instruction_extend_program {
  uint additional_bytes;
};
typedef struct fd_bpf_upgradeable_loader_program_instruction_extend_program fd_bpf_upgradeable_loader_program_instruction_extend_program_t;
#define FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_EXTEND_PROGRAM_ALIGN alignof(fd_bpf_upgradeable_loader_program_instruction_extend_program_t)

/* Encoded Size: Fixed (4 bytes) */
struct fd_bpf_upgradeable_loader_program_instruction_extend_program_checked {
  uint additional_bytes;
};
typedef struct fd_bpf_upgradeable_loader_program_instruction_extend_program_checked fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t;
#define FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_EXTEND_PROGRAM_CHECKED_ALIGN alignof(fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t)

union fd_bpf_upgradeable_loader_program_instruction_inner {
  fd_bpf_upgradeable_loader_program_instruction_write_t write;
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t deploy_with_max_data_len;
  fd_bpf_upgradeable_loader_program_instruction_extend_program_t extend_program;
  fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t extend_program_checked;
};
typedef union fd_bpf_upgradeable_loader_program_instruction_inner fd_bpf_upgradeable_loader_program_instruction_inner_t;

struct fd_bpf_upgradeable_loader_program_instruction {
  uint discriminant;
  fd_bpf_upgradeable_loader_program_instruction_inner_t inner;
};
typedef struct fd_bpf_upgradeable_loader_program_instruction fd_bpf_upgradeable_loader_program_instruction_t;
#define FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_ALIGN alignof(fd_bpf_upgradeable_loader_program_instruction_t)

/* Encoded Size: Dynamic */
struct fd_bpf_upgradeable_loader_state_buffer {
  fd_pubkey_t authority_address;
  uchar has_authority_address;
};
typedef struct fd_bpf_upgradeable_loader_state_buffer fd_bpf_upgradeable_loader_state_buffer_t;
#define FD_BPF_UPGRADEABLE_LOADER_STATE_BUFFER_ALIGN alignof(fd_bpf_upgradeable_loader_state_buffer_t)

/* Encoded Size: Fixed (32 bytes) */
struct fd_bpf_upgradeable_loader_state_program {
  fd_pubkey_t programdata_address;
};
typedef struct fd_bpf_upgradeable_loader_state_program fd_bpf_upgradeable_loader_state_program_t;
#define FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_ALIGN alignof(fd_bpf_upgradeable_loader_state_program_t)

/* Encoded Size: Dynamic */
struct fd_bpf_upgradeable_loader_state_program_data {
  ulong slot;
  fd_pubkey_t upgrade_authority_address;
  uchar has_upgrade_authority_address;
};
typedef struct fd_bpf_upgradeable_loader_state_program_data fd_bpf_upgradeable_loader_state_program_data_t;
#define FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_DATA_ALIGN alignof(fd_bpf_upgradeable_loader_state_program_data_t)

union fd_bpf_upgradeable_loader_state_inner {
  fd_bpf_upgradeable_loader_state_buffer_t buffer;
  fd_bpf_upgradeable_loader_state_program_t program;
  fd_bpf_upgradeable_loader_state_program_data_t program_data;
};
typedef union fd_bpf_upgradeable_loader_state_inner fd_bpf_upgradeable_loader_state_inner_t;

struct fd_bpf_upgradeable_loader_state {
  uint discriminant;
  fd_bpf_upgradeable_loader_state_inner_t inner;
};
typedef struct fd_bpf_upgradeable_loader_state fd_bpf_upgradeable_loader_state_t;
#define FD_BPF_UPGRADEABLE_LOADER_STATE_ALIGN alignof(fd_bpf_upgradeable_loader_state_t)

/* https://github.com/anza-xyz/agave/blob/v2.1.4/sdk/program/src/loader_v4.rs#L33-L43 */
/* Encoded Size: Fixed (48 bytes) */
struct fd_loader_v4_state {
  ulong slot;
  fd_pubkey_t authority_address_or_next_version;
  ulong status;
};
typedef struct fd_loader_v4_state fd_loader_v4_state_t;
#define FD_LOADER_V4_STATE_ALIGN alignof(fd_loader_v4_state_t)

/* Encoded Size: Dynamic */
struct fd_lookup_table_meta {
  ulong deactivation_slot;
  ulong last_extended_slot;
  uchar last_extended_slot_start_index;
  fd_pubkey_t authority;
  uchar has_authority;
  ushort _padding;
};
typedef struct fd_lookup_table_meta fd_lookup_table_meta_t;
#define FD_LOOKUP_TABLE_META_ALIGN alignof(fd_lookup_table_meta_t)

/* Encoded Size: Dynamic */
struct fd_address_lookup_table {
  fd_lookup_table_meta_t meta;
};
typedef struct fd_address_lookup_table fd_address_lookup_table_t;
#define FD_ADDRESS_LOOKUP_TABLE_ALIGN alignof(fd_address_lookup_table_t)

union fd_address_lookup_table_state_inner {
  fd_address_lookup_table_t lookup_table;
};
typedef union fd_address_lookup_table_state_inner fd_address_lookup_table_state_inner_t;

struct fd_address_lookup_table_state {
  uint discriminant;
  fd_address_lookup_table_state_inner_t inner;
};
typedef struct fd_address_lookup_table_state fd_address_lookup_table_state_t;
#define FD_ADDRESS_LOOKUP_TABLE_STATE_ALIGN alignof(fd_address_lookup_table_state_t)


FD_PROTOTYPES_BEGIN

static inline void fd_fee_calculator_new( fd_fee_calculator_t * self ) { fd_memset( self, 0, sizeof(fd_fee_calculator_t) ); }
int fd_fee_calculator_encode( fd_fee_calculator_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_fee_calculator_size( fd_fee_calculator_t const * self ) { (void)self; return 8UL; }
static inline ulong fd_fee_calculator_align( void ) { return FD_FEE_CALCULATOR_ALIGN; }
static inline int fd_fee_calculator_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_fee_calculator_t);
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_fee_calculator_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_slot_pair_new( fd_slot_pair_t * self ) { fd_memset( self, 0, sizeof(fd_slot_pair_t) ); }
int fd_slot_pair_encode( fd_slot_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_slot_pair_size( fd_slot_pair_t const * self ) { (void)self; return 16UL; }
static inline ulong fd_slot_pair_align( void ) { return FD_SLOT_PAIR_ALIGN; }
static inline int fd_slot_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_pair_t);
  if( (ulong)ctx->data + 16UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_slot_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_hard_forks_new( fd_hard_forks_t * self );
int fd_hard_forks_encode( fd_hard_forks_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_hard_forks_size( fd_hard_forks_t const * self );
static inline ulong fd_hard_forks_align( void ) { return FD_HARD_FORKS_ALIGN; }
int fd_hard_forks_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_hard_forks_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_hard_forks_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_hard_forks_encode_global( fd_hard_forks_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_hard_forks_size_global( fd_hard_forks_global_t const * self );

static inline void fd_inflation_new( fd_inflation_t * self ) { fd_memset( self, 0, sizeof(fd_inflation_t) ); }
int fd_inflation_encode( fd_inflation_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_inflation_size( fd_inflation_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_inflation_align( void ) { return FD_INFLATION_ALIGN; }
static inline int fd_inflation_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_inflation_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_inflation_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_rent_new( fd_rent_t * self ) { fd_memset( self, 0, sizeof(fd_rent_t) ); }
int fd_rent_encode( fd_rent_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_rent_size( fd_rent_t const * self ) { (void)self; return 17UL; }
static inline ulong fd_rent_align( void ) { return FD_RENT_ALIGN; }
static inline int fd_rent_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_rent_t);
  if( (ulong)ctx->data + 17UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_rent_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_epoch_schedule_new( fd_epoch_schedule_t * self );
int fd_epoch_schedule_encode( fd_epoch_schedule_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_epoch_schedule_size( fd_epoch_schedule_t const * self ) { (void)self; return 33UL; }
static inline ulong fd_epoch_schedule_align( void ) { return FD_EPOCH_SCHEDULE_ALIGN; }
int fd_epoch_schedule_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_epoch_schedule_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_history_entry_new( fd_stake_history_entry_t * self ) { fd_memset( self, 0, sizeof(fd_stake_history_entry_t) ); }
int fd_stake_history_entry_encode( fd_stake_history_entry_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_stake_history_entry_size( fd_stake_history_entry_t const * self ) { (void)self; return 24UL; }
static inline ulong fd_stake_history_entry_align( void ) { return FD_STAKE_HISTORY_ENTRY_ALIGN; }
static inline int fd_stake_history_entry_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_history_entry_t);
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_history_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_epoch_stake_history_entry_pair_new( fd_epoch_stake_history_entry_pair_t * self ) { fd_memset( self, 0, sizeof(fd_epoch_stake_history_entry_pair_t) ); }
int fd_epoch_stake_history_entry_pair_encode( fd_epoch_stake_history_entry_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_epoch_stake_history_entry_pair_size( fd_epoch_stake_history_entry_pair_t const * self ) { (void)self; return 32UL; }
static inline ulong fd_epoch_stake_history_entry_pair_align( void ) { return FD_EPOCH_STAKE_HISTORY_ENTRY_PAIR_ALIGN; }
static inline int fd_epoch_stake_history_entry_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_epoch_stake_history_entry_pair_t);
  if( (ulong)ctx->data + 32UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_epoch_stake_history_entry_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_stake_history_new( fd_stake_history_t * self );
int fd_stake_history_encode( fd_stake_history_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_stake_history_size( fd_stake_history_t const * self ) { (void)self; return 16392UL; }
static inline ulong fd_stake_history_align( void ) { return FD_STAKE_HISTORY_ALIGN; }
int fd_stake_history_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_history_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_rust_duration_new( fd_rust_duration_t * self ) { fd_memset( self, 0, sizeof(fd_rust_duration_t) ); }
int fd_rust_duration_encode( fd_rust_duration_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_rust_duration_size( fd_rust_duration_t const * self ) { (void)self; return 12UL; }
static inline ulong fd_rust_duration_align( void ) { return FD_RUST_DURATION_ALIGN; }
static inline int fd_rust_duration_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_rust_duration_t);
  if( (ulong)ctx->data + 12UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_rust_duration_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_poh_config_new( fd_poh_config_t * self );
int fd_poh_config_encode( fd_poh_config_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_poh_config_size( fd_poh_config_t const * self );
static inline ulong fd_poh_config_align( void ) { return FD_POH_CONFIG_ALIGN; }
int fd_poh_config_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_poh_config_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_slot_history_new( fd_slot_history_t * self );
int fd_slot_history_encode( fd_slot_history_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_history_size( fd_slot_history_t const * self );
static inline ulong fd_slot_history_align( void ) { return FD_SLOT_HISTORY_ALIGN; }
int fd_slot_history_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_history_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_slot_history_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_slot_history_encode_global( fd_slot_history_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_history_size_global( fd_slot_history_global_t const * self );

static inline void fd_slot_hash_new( fd_slot_hash_t * self ) { fd_memset( self, 0, sizeof(fd_slot_hash_t) ); }
int fd_slot_hash_encode( fd_slot_hash_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_slot_hash_size( fd_slot_hash_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_slot_hash_align( void ) { return FD_SLOT_HASH_ALIGN; }
static inline int fd_slot_hash_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_hash_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_slot_hash_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_slot_hashes_new( fd_slot_hashes_t * self );
int fd_slot_hashes_encode( fd_slot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_hashes_size( fd_slot_hashes_t const * self );
static inline ulong fd_slot_hashes_align( void ) { return FD_SLOT_HASHES_ALIGN; }
int fd_slot_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_slot_hashes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_slot_hashes_encode_global( fd_slot_hashes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_hashes_size_global( fd_slot_hashes_global_t const * self );

static inline void fd_block_block_hash_entry_new( fd_block_block_hash_entry_t * self ) { fd_memset( self, 0, sizeof(fd_block_block_hash_entry_t) ); }
int fd_block_block_hash_entry_encode( fd_block_block_hash_entry_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_block_block_hash_entry_size( fd_block_block_hash_entry_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_block_block_hash_entry_align( void ) { return FD_BLOCK_BLOCK_HASH_ENTRY_ALIGN; }
static inline int fd_block_block_hash_entry_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_block_block_hash_entry_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_block_block_hash_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_recent_block_hashes_new( fd_recent_block_hashes_t * self );
int fd_recent_block_hashes_encode( fd_recent_block_hashes_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_recent_block_hashes_size( fd_recent_block_hashes_t const * self );
static inline ulong fd_recent_block_hashes_align( void ) { return FD_RECENT_BLOCK_HASHES_ALIGN; }
int fd_recent_block_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_recent_block_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_recent_block_hashes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_recent_block_hashes_encode_global( fd_recent_block_hashes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_recent_block_hashes_size_global( fd_recent_block_hashes_global_t const * self );

void fd_slot_meta_new( fd_slot_meta_t * self );
int fd_slot_meta_encode( fd_slot_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_meta_size( fd_slot_meta_t const * self );
static inline ulong fd_slot_meta_align( void ) { return FD_SLOT_META_ALIGN; }
int fd_slot_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_sysvar_fees_new( fd_sysvar_fees_t * self ) { fd_memset( self, 0, sizeof(fd_sysvar_fees_t) ); }
int fd_sysvar_fees_encode( fd_sysvar_fees_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_sysvar_fees_size( fd_sysvar_fees_t const * self ) { (void)self; return 8UL; }
static inline ulong fd_sysvar_fees_align( void ) { return FD_SYSVAR_FEES_ALIGN; }
static inline int fd_sysvar_fees_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_sysvar_fees_t);
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_sysvar_fees_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_sysvar_epoch_rewards_new( fd_sysvar_epoch_rewards_t * self );
int fd_sysvar_epoch_rewards_encode( fd_sysvar_epoch_rewards_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_sysvar_epoch_rewards_size( fd_sysvar_epoch_rewards_t const * self ) { (void)self; return 81UL; }
static inline ulong fd_sysvar_epoch_rewards_align( void ) { return FD_SYSVAR_EPOCH_REWARDS_ALIGN; }
int fd_sysvar_epoch_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_sysvar_epoch_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_system_program_instruction_create_account_new( fd_system_program_instruction_create_account_t * self ) { fd_memset( self, 0, sizeof(fd_system_program_instruction_create_account_t) ); }
int fd_system_program_instruction_create_account_encode( fd_system_program_instruction_create_account_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_system_program_instruction_create_account_size( fd_system_program_instruction_create_account_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_system_program_instruction_create_account_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_ALIGN; }
static inline int fd_system_program_instruction_create_account_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_system_program_instruction_create_account_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_system_program_instruction_create_account_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_create_account_with_seed_new( fd_system_program_instruction_create_account_with_seed_t * self );
int fd_system_program_instruction_create_account_with_seed_encode( fd_system_program_instruction_create_account_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_system_program_instruction_create_account_with_seed_size( fd_system_program_instruction_create_account_with_seed_t const * self );
static inline ulong fd_system_program_instruction_create_account_with_seed_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_WITH_SEED_ALIGN; }
int fd_system_program_instruction_create_account_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_create_account_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_allocate_with_seed_new( fd_system_program_instruction_allocate_with_seed_t * self );
int fd_system_program_instruction_allocate_with_seed_encode( fd_system_program_instruction_allocate_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_system_program_instruction_allocate_with_seed_size( fd_system_program_instruction_allocate_with_seed_t const * self );
static inline ulong fd_system_program_instruction_allocate_with_seed_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_ALLOCATE_WITH_SEED_ALIGN; }
int fd_system_program_instruction_allocate_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_allocate_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_assign_with_seed_new( fd_system_program_instruction_assign_with_seed_t * self );
int fd_system_program_instruction_assign_with_seed_encode( fd_system_program_instruction_assign_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_system_program_instruction_assign_with_seed_size( fd_system_program_instruction_assign_with_seed_t const * self );
static inline ulong fd_system_program_instruction_assign_with_seed_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_ASSIGN_WITH_SEED_ALIGN; }
int fd_system_program_instruction_assign_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_assign_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_transfer_with_seed_new( fd_system_program_instruction_transfer_with_seed_t * self );
int fd_system_program_instruction_transfer_with_seed_encode( fd_system_program_instruction_transfer_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_system_program_instruction_transfer_with_seed_size( fd_system_program_instruction_transfer_with_seed_t const * self );
static inline ulong fd_system_program_instruction_transfer_with_seed_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_TRANSFER_WITH_SEED_ALIGN; }
int fd_system_program_instruction_transfer_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_transfer_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_new_disc( fd_system_program_instruction_t * self, uint discriminant );
void fd_system_program_instruction_new( fd_system_program_instruction_t * self );
int fd_system_program_instruction_encode( fd_system_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_system_program_instruction_size( fd_system_program_instruction_t const * self );
static inline ulong fd_system_program_instruction_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_ALIGN; }
int fd_system_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_system_program_instruction_is_create_account( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_assign( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_transfer( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_create_account_with_seed( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_advance_nonce_account( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_withdraw_nonce_account( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_initialize_nonce_account( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_authorize_nonce_account( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_allocate( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_allocate_with_seed( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_assign_with_seed( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_transfer_with_seed( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_upgrade_nonce_account( fd_system_program_instruction_t const * self );
FD_FN_PURE uchar fd_system_program_instruction_is_create_account_allow_prefund( fd_system_program_instruction_t const * self );
enum {
fd_system_program_instruction_enum_create_account = 0,
fd_system_program_instruction_enum_assign = 1,
fd_system_program_instruction_enum_transfer = 2,
fd_system_program_instruction_enum_create_account_with_seed = 3,
fd_system_program_instruction_enum_advance_nonce_account = 4,
fd_system_program_instruction_enum_withdraw_nonce_account = 5,
fd_system_program_instruction_enum_initialize_nonce_account = 6,
fd_system_program_instruction_enum_authorize_nonce_account = 7,
fd_system_program_instruction_enum_allocate = 8,
fd_system_program_instruction_enum_allocate_with_seed = 9,
fd_system_program_instruction_enum_assign_with_seed = 10,
fd_system_program_instruction_enum_transfer_with_seed = 11,
fd_system_program_instruction_enum_upgrade_nonce_account = 12,
fd_system_program_instruction_enum_create_account_allow_prefund = 13,
};
static inline void fd_nonce_data_new( fd_nonce_data_t * self ) { fd_memset( self, 0, sizeof(fd_nonce_data_t) ); }
int fd_nonce_data_encode( fd_nonce_data_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_nonce_data_size( fd_nonce_data_t const * self ) { (void)self; return 72UL; }
static inline ulong fd_nonce_data_align( void ) { return FD_NONCE_DATA_ALIGN; }
static inline int fd_nonce_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_nonce_data_t);
  if( (ulong)ctx->data + 72UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_nonce_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_nonce_state_new_disc( fd_nonce_state_t * self, uint discriminant );
void fd_nonce_state_new( fd_nonce_state_t * self );
int fd_nonce_state_encode( fd_nonce_state_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_nonce_state_size( fd_nonce_state_t const * self );
static inline ulong fd_nonce_state_align( void ) { return FD_NONCE_STATE_ALIGN; }
int fd_nonce_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_nonce_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_nonce_state_is_uninitialized( fd_nonce_state_t const * self );
FD_FN_PURE uchar fd_nonce_state_is_initialized( fd_nonce_state_t const * self );
enum {
fd_nonce_state_enum_uninitialized = 0,
fd_nonce_state_enum_initialized = 1,
};
void fd_nonce_state_versions_new_disc( fd_nonce_state_versions_t * self, uint discriminant );
void fd_nonce_state_versions_new( fd_nonce_state_versions_t * self );
int fd_nonce_state_versions_encode( fd_nonce_state_versions_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_nonce_state_versions_size( fd_nonce_state_versions_t const * self );
static inline ulong fd_nonce_state_versions_align( void ) { return FD_NONCE_STATE_VERSIONS_ALIGN; }
int fd_nonce_state_versions_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_nonce_state_versions_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_nonce_state_versions_is_legacy( fd_nonce_state_versions_t const * self );
FD_FN_PURE uchar fd_nonce_state_versions_is_current( fd_nonce_state_versions_t const * self );
enum {
fd_nonce_state_versions_enum_legacy = 0,
fd_nonce_state_versions_enum_current = 1,
};
static inline void fd_compute_budget_program_instruction_request_units_deprecated_new( fd_compute_budget_program_instruction_request_units_deprecated_t * self ) { fd_memset( self, 0, sizeof(fd_compute_budget_program_instruction_request_units_deprecated_t) ); }
int fd_compute_budget_program_instruction_request_units_deprecated_encode( fd_compute_budget_program_instruction_request_units_deprecated_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_compute_budget_program_instruction_request_units_deprecated_size( fd_compute_budget_program_instruction_request_units_deprecated_t const * self ) { (void)self; return 8UL; }
static inline ulong fd_compute_budget_program_instruction_request_units_deprecated_align( void ) { return FD_COMPUTE_BUDGET_PROGRAM_INSTRUCTION_REQUEST_UNITS_DEPRECATED_ALIGN; }
static inline int fd_compute_budget_program_instruction_request_units_deprecated_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_compute_budget_program_instruction_request_units_deprecated_t);
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_compute_budget_program_instruction_request_units_deprecated_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_compute_budget_program_instruction_new_disc( fd_compute_budget_program_instruction_t * self, uint discriminant );
void fd_compute_budget_program_instruction_new( fd_compute_budget_program_instruction_t * self );
int fd_compute_budget_program_instruction_encode( fd_compute_budget_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_compute_budget_program_instruction_size( fd_compute_budget_program_instruction_t const * self );
static inline ulong fd_compute_budget_program_instruction_align( void ) { return FD_COMPUTE_BUDGET_PROGRAM_INSTRUCTION_ALIGN; }
int fd_compute_budget_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_compute_budget_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_compute_budget_program_instruction_is_request_units_deprecated( fd_compute_budget_program_instruction_t const * self );
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_request_heap_frame( fd_compute_budget_program_instruction_t const * self );
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_set_compute_unit_limit( fd_compute_budget_program_instruction_t const * self );
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_set_compute_unit_price( fd_compute_budget_program_instruction_t const * self );
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_set_loaded_accounts_data_size_limit( fd_compute_budget_program_instruction_t const * self );
enum {
fd_compute_budget_program_instruction_enum_request_units_deprecated = 0,
fd_compute_budget_program_instruction_enum_request_heap_frame = 1,
fd_compute_budget_program_instruction_enum_set_compute_unit_limit = 2,
fd_compute_budget_program_instruction_enum_set_compute_unit_price = 3,
fd_compute_budget_program_instruction_enum_set_loaded_accounts_data_size_limit = 4,
};
void fd_bpf_loader_program_instruction_write_new( fd_bpf_loader_program_instruction_write_t * self );
int fd_bpf_loader_program_instruction_write_encode( fd_bpf_loader_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_bpf_loader_program_instruction_write_size( fd_bpf_loader_program_instruction_write_t const * self );
static inline ulong fd_bpf_loader_program_instruction_write_align( void ) { return FD_BPF_LOADER_PROGRAM_INSTRUCTION_WRITE_ALIGN; }
int fd_bpf_loader_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_loader_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_bpf_loader_program_instruction_new_disc( fd_bpf_loader_program_instruction_t * self, uint discriminant );
void fd_bpf_loader_program_instruction_new( fd_bpf_loader_program_instruction_t * self );
int fd_bpf_loader_program_instruction_encode( fd_bpf_loader_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_bpf_loader_program_instruction_size( fd_bpf_loader_program_instruction_t const * self );
static inline ulong fd_bpf_loader_program_instruction_align( void ) { return FD_BPF_LOADER_PROGRAM_INSTRUCTION_ALIGN; }
int fd_bpf_loader_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_loader_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_bpf_loader_program_instruction_is_write( fd_bpf_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_loader_program_instruction_is_finalize( fd_bpf_loader_program_instruction_t const * self );
enum {
fd_bpf_loader_program_instruction_enum_write = 0,
fd_bpf_loader_program_instruction_enum_finalize = 1,
};
void fd_loader_v4_program_instruction_write_new( fd_loader_v4_program_instruction_write_t * self );
int fd_loader_v4_program_instruction_write_encode( fd_loader_v4_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_loader_v4_program_instruction_write_size( fd_loader_v4_program_instruction_write_t const * self );
static inline ulong fd_loader_v4_program_instruction_write_align( void ) { return FD_LOADER_V4_PROGRAM_INSTRUCTION_WRITE_ALIGN; }
int fd_loader_v4_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_loader_v4_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_loader_v4_program_instruction_copy_new( fd_loader_v4_program_instruction_copy_t * self ) { fd_memset( self, 0, sizeof(fd_loader_v4_program_instruction_copy_t) ); }
int fd_loader_v4_program_instruction_copy_encode( fd_loader_v4_program_instruction_copy_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_loader_v4_program_instruction_copy_size( fd_loader_v4_program_instruction_copy_t const * self ) { (void)self; return 12UL; }
static inline ulong fd_loader_v4_program_instruction_copy_align( void ) { return FD_LOADER_V4_PROGRAM_INSTRUCTION_COPY_ALIGN; }
static inline int fd_loader_v4_program_instruction_copy_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_loader_v4_program_instruction_copy_t);
  if( (ulong)ctx->data + 12UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_loader_v4_program_instruction_copy_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_loader_v4_program_instruction_set_program_length_new( fd_loader_v4_program_instruction_set_program_length_t * self ) { fd_memset( self, 0, sizeof(fd_loader_v4_program_instruction_set_program_length_t) ); }
int fd_loader_v4_program_instruction_set_program_length_encode( fd_loader_v4_program_instruction_set_program_length_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_loader_v4_program_instruction_set_program_length_size( fd_loader_v4_program_instruction_set_program_length_t const * self ) { (void)self; return 4UL; }
static inline ulong fd_loader_v4_program_instruction_set_program_length_align( void ) { return FD_LOADER_V4_PROGRAM_INSTRUCTION_SET_PROGRAM_LENGTH_ALIGN; }
static inline int fd_loader_v4_program_instruction_set_program_length_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_loader_v4_program_instruction_set_program_length_t);
  if( (ulong)ctx->data + 4UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_loader_v4_program_instruction_set_program_length_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_loader_v4_program_instruction_new_disc( fd_loader_v4_program_instruction_t * self, uint discriminant );
void fd_loader_v4_program_instruction_new( fd_loader_v4_program_instruction_t * self );
int fd_loader_v4_program_instruction_encode( fd_loader_v4_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_loader_v4_program_instruction_size( fd_loader_v4_program_instruction_t const * self );
static inline ulong fd_loader_v4_program_instruction_align( void ) { return FD_LOADER_V4_PROGRAM_INSTRUCTION_ALIGN; }
int fd_loader_v4_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_loader_v4_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_loader_v4_program_instruction_is_write( fd_loader_v4_program_instruction_t const * self );
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_copy( fd_loader_v4_program_instruction_t const * self );
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_set_program_length( fd_loader_v4_program_instruction_t const * self );
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_deploy( fd_loader_v4_program_instruction_t const * self );
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_retract( fd_loader_v4_program_instruction_t const * self );
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_transfer_authority( fd_loader_v4_program_instruction_t const * self );
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_finalize( fd_loader_v4_program_instruction_t const * self );
enum {
fd_loader_v4_program_instruction_enum_write = 0,
fd_loader_v4_program_instruction_enum_copy = 1,
fd_loader_v4_program_instruction_enum_set_program_length = 2,
fd_loader_v4_program_instruction_enum_deploy = 3,
fd_loader_v4_program_instruction_enum_retract = 4,
fd_loader_v4_program_instruction_enum_transfer_authority = 5,
fd_loader_v4_program_instruction_enum_finalize = 6,
};
void fd_bpf_upgradeable_loader_program_instruction_write_new( fd_bpf_upgradeable_loader_program_instruction_write_t * self );
int fd_bpf_upgradeable_loader_program_instruction_write_encode( fd_bpf_upgradeable_loader_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_bpf_upgradeable_loader_program_instruction_write_size( fd_bpf_upgradeable_loader_program_instruction_write_t const * self );
static inline ulong fd_bpf_upgradeable_loader_program_instruction_write_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_WRITE_ALIGN; }
int fd_bpf_upgradeable_loader_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_upgradeable_loader_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new( fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t * self ) { fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t) ); }
int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_encode( fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_size( fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self ) { (void)self; return 8UL; }
static inline ulong fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN_ALIGN; }
static inline int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t);
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_bpf_upgradeable_loader_program_instruction_extend_program_new( fd_bpf_upgradeable_loader_program_instruction_extend_program_t * self ) { fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_extend_program_t) ); }
int fd_bpf_upgradeable_loader_program_instruction_extend_program_encode( fd_bpf_upgradeable_loader_program_instruction_extend_program_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_bpf_upgradeable_loader_program_instruction_extend_program_size( fd_bpf_upgradeable_loader_program_instruction_extend_program_t const * self ) { (void)self; return 4UL; }
static inline ulong fd_bpf_upgradeable_loader_program_instruction_extend_program_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_EXTEND_PROGRAM_ALIGN; }
static inline int fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_program_instruction_extend_program_t);
  if( (ulong)ctx->data + 4UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_bpf_upgradeable_loader_program_instruction_extend_program_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_new( fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t * self ) { fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t) ); }
int fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_encode( fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_size( fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t const * self ) { (void)self; return 4UL; }
static inline ulong fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_EXTEND_PROGRAM_CHECKED_ALIGN; }
static inline int fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t);
  if( (ulong)ctx->data + 4UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_bpf_upgradeable_loader_program_instruction_new_disc( fd_bpf_upgradeable_loader_program_instruction_t * self, uint discriminant );
void fd_bpf_upgradeable_loader_program_instruction_new( fd_bpf_upgradeable_loader_program_instruction_t * self );
int fd_bpf_upgradeable_loader_program_instruction_encode( fd_bpf_upgradeable_loader_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_bpf_upgradeable_loader_program_instruction_size( fd_bpf_upgradeable_loader_program_instruction_t const * self );
static inline ulong fd_bpf_upgradeable_loader_program_instruction_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_ALIGN; }
int fd_bpf_upgradeable_loader_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_upgradeable_loader_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_initialize_buffer( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_write( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_deploy_with_max_data_len( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_upgrade( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_set_authority( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_close( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_extend_program( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_set_authority_checked( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_migrate( fd_bpf_upgradeable_loader_program_instruction_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_extend_program_checked( fd_bpf_upgradeable_loader_program_instruction_t const * self );
enum {
fd_bpf_upgradeable_loader_program_instruction_enum_initialize_buffer = 0,
fd_bpf_upgradeable_loader_program_instruction_enum_write = 1,
fd_bpf_upgradeable_loader_program_instruction_enum_deploy_with_max_data_len = 2,
fd_bpf_upgradeable_loader_program_instruction_enum_upgrade = 3,
fd_bpf_upgradeable_loader_program_instruction_enum_set_authority = 4,
fd_bpf_upgradeable_loader_program_instruction_enum_close = 5,
fd_bpf_upgradeable_loader_program_instruction_enum_extend_program = 6,
fd_bpf_upgradeable_loader_program_instruction_enum_set_authority_checked = 7,
fd_bpf_upgradeable_loader_program_instruction_enum_migrate = 8,
fd_bpf_upgradeable_loader_program_instruction_enum_extend_program_checked = 9,
};
void fd_bpf_upgradeable_loader_state_buffer_new( fd_bpf_upgradeable_loader_state_buffer_t * self );
int fd_bpf_upgradeable_loader_state_buffer_encode( fd_bpf_upgradeable_loader_state_buffer_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_bpf_upgradeable_loader_state_buffer_size( fd_bpf_upgradeable_loader_state_buffer_t const * self );
static inline ulong fd_bpf_upgradeable_loader_state_buffer_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_STATE_BUFFER_ALIGN; }
int fd_bpf_upgradeable_loader_state_buffer_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_upgradeable_loader_state_buffer_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_bpf_upgradeable_loader_state_program_new( fd_bpf_upgradeable_loader_state_program_t * self ) { fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_state_program_t) ); }
int fd_bpf_upgradeable_loader_state_program_encode( fd_bpf_upgradeable_loader_state_program_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_bpf_upgradeable_loader_state_program_size( fd_bpf_upgradeable_loader_state_program_t const * self ) { (void)self; return 32UL; }
static inline ulong fd_bpf_upgradeable_loader_state_program_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_ALIGN; }
static inline int fd_bpf_upgradeable_loader_state_program_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_state_program_t);
  if( (ulong)ctx->data + 32UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_bpf_upgradeable_loader_state_program_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_bpf_upgradeable_loader_state_program_data_new( fd_bpf_upgradeable_loader_state_program_data_t * self );
int fd_bpf_upgradeable_loader_state_program_data_encode( fd_bpf_upgradeable_loader_state_program_data_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_bpf_upgradeable_loader_state_program_data_size( fd_bpf_upgradeable_loader_state_program_data_t const * self );
static inline ulong fd_bpf_upgradeable_loader_state_program_data_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_DATA_ALIGN; }
int fd_bpf_upgradeable_loader_state_program_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_upgradeable_loader_state_program_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_bpf_upgradeable_loader_state_new_disc( fd_bpf_upgradeable_loader_state_t * self, uint discriminant );
void fd_bpf_upgradeable_loader_state_new( fd_bpf_upgradeable_loader_state_t * self );
int fd_bpf_upgradeable_loader_state_encode( fd_bpf_upgradeable_loader_state_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_bpf_upgradeable_loader_state_size( fd_bpf_upgradeable_loader_state_t const * self );
static inline ulong fd_bpf_upgradeable_loader_state_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_STATE_ALIGN; }
int fd_bpf_upgradeable_loader_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_upgradeable_loader_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_bpf_upgradeable_loader_state_is_uninitialized( fd_bpf_upgradeable_loader_state_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_state_is_buffer( fd_bpf_upgradeable_loader_state_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_state_is_program( fd_bpf_upgradeable_loader_state_t const * self );
FD_FN_PURE uchar fd_bpf_upgradeable_loader_state_is_program_data( fd_bpf_upgradeable_loader_state_t const * self );
enum {
fd_bpf_upgradeable_loader_state_enum_uninitialized = 0,
fd_bpf_upgradeable_loader_state_enum_buffer = 1,
fd_bpf_upgradeable_loader_state_enum_program = 2,
fd_bpf_upgradeable_loader_state_enum_program_data = 3,
};
static inline void fd_loader_v4_state_new( fd_loader_v4_state_t * self ) { fd_memset( self, 0, sizeof(fd_loader_v4_state_t) ); }
int fd_loader_v4_state_encode( fd_loader_v4_state_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_loader_v4_state_size( fd_loader_v4_state_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_loader_v4_state_align( void ) { return FD_LOADER_V4_STATE_ALIGN; }
static inline int fd_loader_v4_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_loader_v4_state_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_loader_v4_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_lookup_table_meta_new( fd_lookup_table_meta_t * self );
int fd_lookup_table_meta_encode( fd_lookup_table_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_lookup_table_meta_size( fd_lookup_table_meta_t const * self );
static inline ulong fd_lookup_table_meta_align( void ) { return FD_LOOKUP_TABLE_META_ALIGN; }
int fd_lookup_table_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_lookup_table_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_address_lookup_table_new( fd_address_lookup_table_t * self );
int fd_address_lookup_table_encode( fd_address_lookup_table_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_address_lookup_table_size( fd_address_lookup_table_t const * self );
static inline ulong fd_address_lookup_table_align( void ) { return FD_ADDRESS_LOOKUP_TABLE_ALIGN; }
int fd_address_lookup_table_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_address_lookup_table_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_address_lookup_table_state_new_disc( fd_address_lookup_table_state_t * self, uint discriminant );
void fd_address_lookup_table_state_new( fd_address_lookup_table_state_t * self );
int fd_address_lookup_table_state_encode( fd_address_lookup_table_state_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_address_lookup_table_state_size( fd_address_lookup_table_state_t const * self );
static inline ulong fd_address_lookup_table_state_align( void ) { return FD_ADDRESS_LOOKUP_TABLE_STATE_ALIGN; }
int fd_address_lookup_table_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_address_lookup_table_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_address_lookup_table_state_is_uninitialized( fd_address_lookup_table_state_t const * self );
FD_FN_PURE uchar fd_address_lookup_table_state_is_lookup_table( fd_address_lookup_table_state_t const * self );
enum {
fd_address_lookup_table_state_enum_uninitialized = 0,
fd_address_lookup_table_state_enum_lookup_table = 1,
};
FD_PROTOTYPES_END

#endif // HEADER_FD_RUNTIME_TYPES
