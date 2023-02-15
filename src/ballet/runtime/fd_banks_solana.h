// TODO:
//    look for: FD_PROTOTYPES_BEGIN

#ifndef HEADER_fd_src_ballet_runime_fd_banks_solana_h
#define HEADER_fd_src_ballet_runtime_fd_banks_solana_h

#include "../../util/encoders/fd_bincode.h"

typedef char* (*alloc_fun)(ulong len, ulong align, void* arg);

// sdk/program/src/fee_calculator.rs:11
struct fd_fee_calculator {
  ulong lamports_per_signature;
};
typedef struct fd_fee_calculator fd_fee_calculator_t;
#define FD_FEE_CALCULATOR_FOOTPRINT sizeof(fd_fee_calculator_t)
#define FD_FEE_CALCULATOR_ALIGN (8UL)

// runtime/src/blockhash_queue.rs:12
struct fd_hash_age {
  fd_fee_calculator_t fee_calculator;
  ulong               hash_index;
  ulong               timestamp;
};
typedef struct fd_hash_age fd_hash_age_t;
#define FD_HASH_AGE_FOOTPRINT sizeof(fd_hash_age_t)
#define FD_HASH_AGE_ALIGN (8UL)

// sdk/program/src/hash.rs:47
struct fd_hash {
  unsigned char hash[32];
};
typedef struct fd_hash fd_hash_t;
#define FD_HASH_FOOTPRINT sizeof(fd_hash_t)
#define FD_HASH_ALIGN (8UL)

struct fd_hash_hash_age_pair {
  fd_hash_t     key;
  fd_hash_age_t val;
};
typedef struct fd_hash_hash_age_pair fd_hash_hash_age_pair_t;
#define FD_HASH_HASH_AGE_PAIR_FOOTPRINT sizeof(fd_hash_hash_age_pair_t)
#define FD_HASH_HASH_AGE_PAIR_ALIGN (8UL)

// runtime/src/blockhash_queue.rs:21
struct fd_block_hash_queue {
  ulong                    last_hash_index;
  fd_hash_t*               last_hash;

  ulong                    ages_len;
  fd_hash_hash_age_pair_t* ages;

  ulong                    max_age;
};
typedef struct fd_block_hash_queue fd_block_hash_queue_t;
#define FD_BLOCK_HASH_QUEUE_FOOTPRINT sizeof(fd_block_hash_queue_t)
#define FD_BLOCK_HASH_QUEUE_ALIGN (8UL)

// sdk/program/src/pubkey.rs:87
struct fd_pubkey {
  unsigned char key[32];
};
typedef struct fd_pubkey fd_pubkey_t;
#define FD_PUBKEY_FOOTPRINT sizeof(fd_pubkey_t)
#define FD_PUBKEY_ALIGN (8UL)

// sdk/program/src/epoch_schedule.rs:34
struct fd_epoch_schedule {
  ulong         slots_per_epoch;
  ulong         leader_schedule_slot_offset;
  unsigned char warmup;
  ulong         first_normal_epoch;
  ulong         first_normal_slot;
};
typedef struct fd_epoch_schedule fd_epoch_schedule_t;
#define FD_EPOCH_SCHEDULE_FOOTPRINT sizeof(fd_epoch_schedule_t)
#define FD_EPOCH_SCHEDULE_ALIGN (8UL)

// sdk/program/src/fee_calculator.rs:52
struct fd_fee_rate_governor {
  ulong         target_lamports_per_signature;
  ulong         target_signatures_per_slot;
  ulong         min_lamports_per_signature;
  ulong         max_lamports_per_signature;
  unsigned char burn_percent;
};
typedef struct fd_fee_rate_governor fd_fee_rate_governor_t;
#define FD_FEE_RATE_GOVERNOR_FOOTPRINT sizeof(fd_fee_rate_governor_t)
#define FD_FEE_RATE_GOVERNOR_ALIGN (8UL)

struct fd_slot_pair {
  ulong slot;
  ulong val;
};
typedef struct fd_slot_pair fd_slot_pair_t;
#define FD_SLOT_PAIR_FOOTPRINT sizeof(fd_slot_pair_t)
#define FD_SLOT_PAIR_ALIGN (8UL)

// sdk/src/hard_forks.rs:12
struct fd_hard_forks {
  ulong           len;
  fd_slot_pair_t* hard_forks;
};
typedef struct fd_hard_forks fd_hard_forks_t;
#define FD_HARD_FORKS_FOOTPRINT sizeof(fd_hard_forks_t)
#define FD_HARD_FORKS_ALIGN (8UL)

// sdk/src/fd_inflation.rs:5
struct fd_inflation {
  double initial;
  double terminal;
  double taper;
  double foundation;
  double foundation_term;
  double __unused;
};
typedef struct fd_inflation fd_inflation_t;
#define FD_INFLATION_FOOTPRINT sizeof(fd_inflation_t)
#define FD_INFLATION_ALIGN (8UL)

// sdk/program/src/rent.rs:12
struct fd_rent {
  ulong         lamports_per_uint8_year;
  double        exemption_threshold;
  unsigned char burn_percent;
};
typedef struct fd_rent fd_rent_t;
#define RENT_FOOTPRINT sizeof(fd_rent_t)
#define RENT_ALIGN (8UL)

// runtime/src/rent_collector.rs:13
struct fd_rent_collector {
  ulong               epoch;
  fd_epoch_schedule_t epoch_schedule;
  double              slots_per_year;
  fd_rent_t           rent;
};
typedef struct fd_rent_collector fd_rent_collector_t;
#define FD_RENT_COLLECTOR_FOOTPRINT sizeof(fd_rent_collector_t)
#define FD_RENT_COLLECTOR_ALIGN (8UL)

// sdk/program/src/stake_history.rs:15
struct fd_stake_history_entry {
  ulong effective;
  ulong activating;
  ulong deactivating;
};
typedef struct fd_stake_history_entry fd_stake_history_entry_t;
#define FD_STAKE_HISTORY_ENTRY_FOOTPRINT sizeof(fd_stake_history_entry_t)
#define FD_STAKE_HISTORY_ENTRY_ALIGN (8UL)

struct fd_stake_history_epochentry_pair {
  ulong                    epoch;
  fd_stake_history_entry_t entry;
};
typedef struct fd_stake_history_epochentry_pair fd_stake_history_epochentry_pair_t;
#define FD_STAKE_HISTORY_EPOCHENTRY_PAIR_FOOTPRINT sizeof(fd_stake_history_epochentry_pair_t)
#define FD_STAKE_HISTORY_EPOCHENTRY_PAIR_ALIGN (8UL)

// sdk/program/src/stake_history.rs
struct fd_stake_history {
  ulong                               len;
  fd_stake_history_epochentry_pair_t* entries;
};
typedef struct fd_stake_history fd_stake_history_t;
#define FD_STAKE_HISTORY_FOOTPRINT sizeof(fd_stake_history_t)
#define FD_STAKE_HISTORY_ALIGN (8UL)

// sdk/src/account.rs:27
struct fd_account {
  ulong          lamports;

  ulong          data_len;
  unsigned char* data;

  fd_pubkey_t    owner;
  unsigned char  executable;
  ulong          rent_epoch;
};
typedef struct fd_account fd_account_t;
#define ACCOUNT_FOOTPRINT sizeof(fd_account_t)
#define ACCOUNT_ALIGN (8UL)

struct fd_vote_accounts_pair {
  fd_pubkey_t  key;
  ulong        stake;
  fd_account_t value;
};
typedef struct fd_vote_accounts_pair fd_vote_accounts_pair_t;
#define FD_VOTE_ACCOUNTS_PAIR_FOOTPRINT sizeof(fd_vote_accounts_pair_t)
#define FD_VOTE_ACCOUNTS_PAIR_ALIGN (8UL)

// runtime/src/vote_account.rs:42
struct fd_vote_accounts { // tested and confirmed
  ulong                    vote_accounts_len;
  fd_vote_accounts_pair_t *vote_accounts;
};
typedef struct fd_vote_accounts fd_vote_accounts_t;
#define FD_VOTE_ACCOUNTS_FOOTPRINT sizeof(fd_vote_accounts_t)
#define FD_VOTE_ACCOUNTS_ALIGN (8UL)

// sdk/program/src/stake/state.rs:301
struct fd_delegation {
  fd_pubkey_t voter_pubkey;
  ulong       stake;
  ulong       activation_epoch;
  ulong       deactivation_epoch;
  double      warmup_cooldown_rate;
};
typedef struct fd_delegation fd_delegation_t;
#define DELEGATION_FOOTPRINT sizeof(fd_delegation_t)
#define DELEGATION_ALIGN (8UL)

struct fd_delegation_pair {
  fd_pubkey_t     key;
  fd_delegation_t value;
};
typedef struct fd_delegation_pair fd_delegation_pair_t;
#define FD_DELEGATION_PAIR_FOOTPRINT sizeof(fd_delegation_pair_t)
#define FD_DELEGATION_PAIR_ALIGN (8UL)

// runtime/src/stakes.rs:169
// runtime/src/bank.rs:747
struct fd_stakes_deligation {
  fd_vote_accounts_t     vote_accounts;
  ulong                  stake_delegations_len;
  fd_delegation_pair_t*  stake_delegations;
  ulong                  unused;
  ulong                  epoch;
  fd_stake_history_t     stake_history;
};
typedef struct fd_stakes_deligation fd_stakes_deligation_t;
#define FD_STAKES_DELIGATION_FOOTPRINT sizeof(fd_stakes_deligation_t)
#define FD_STAKES_DELIGATION_ALIGN (8UL)

// runtime/src/bank.rs:238
struct fd_bank_incremental_snapshot_persistence {
  ulong       full_slot;
  fd_hash_t   full_hash;
  ulong       full_capitalization;
  fd_hash_t   incremental_hash;
  ulong       incremental_capitalization;
};
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FOOTPRINT sizeof(fd_bank_incremental_snapshot_persistence_t)
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN (8UL)

struct node_vote_accounts {
  ulong        vote_accounts_len;
  fd_pubkey_t *vote_accounts;
  ulong        total_stake;
};
typedef struct node_vote_accounts node_vote_accounts_t;
#define NODE_VOTE_ACCOUNTS_FOOTPRINT sizeof(node_vote_accounts_t)
#define NODE_VOTE_ACCOUNTS_ALIGN (8UL)

struct fd_pubkey_node_vote_accounts_pair {
  fd_pubkey_t          key;
  node_vote_accounts_t value;
};
typedef struct fd_pubkey_node_vote_accounts_pair fd_pubkey_node_vote_accounts_pair_t;
#define FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_FOOTPRINT sizeof(fd_pubkey_node_vote_accounts_pair_t)
#define FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_ALIGN (8UL)

struct fd_pubkey_pubkey_pair {
  fd_pubkey_t key;
  fd_pubkey_t value;
};
typedef struct fd_pubkey_pubkey_pair fd_pubkey_pubkey_pair_t;
#define FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT sizeof(fd_pubkey_pubkey_pair_t)
#define FD_PUBKEY_PUBKEY_PAIR_ALIGN (8UL)

// runtime/src/epoch_stakes.rs:18
struct fd_epoch_stakes {
  fd_stakes_deligation_t                stakes;
  ulong                                 total_stake;
  ulong                                 node_id_to_vote_accounts_len;
  fd_pubkey_node_vote_accounts_pair_t * node_id_to_vote_accounts;
  ulong                                 epoch_authorized_voters_len;
  fd_pubkey_pubkey_pair_t *             epoch_authorized_voters;
};
typedef struct fd_epoch_stakes fd_epoch_stakes_t;
#define FD_EPOCH_STAKES_FOOTPRINT sizeof(fd_epoch_stakes_t)
#define FD_EPOCH_STAKES_ALIGN (8UL)

struct fd_epoch_epoch_stakes_pair {
  ulong key;
  fd_epoch_stakes_t value;
};
typedef struct fd_epoch_epoch_stakes_pair fd_epoch_epoch_stakes_pair_t;
#define FD_EPOCH_EPOCH_STAKES_PAIR_FOOTPRINT sizeof(fd_epoch_epoch_stakes_pair_t)
#define FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN (8UL)

struct fd_pubkey_u64_pair {
  fd_pubkey_t _0;
  ulong       _1;
};
typedef struct fd_pubkey_u64_pair fd_pubkey_u64_pair_t;
#define FD_PUBKEY_U64_PAIR_FOOTPRINT sizeof(fd_pubkey_u64_pair_t)
#define FD_PUBKEY_U64_PAIR_ALIGN (8UL)

// runtime/src/serde_snapshot/newer.rs:20
struct fd_unused_accounts {
  ulong                 unused1_len;
  fd_pubkey_t*          unused1;

  ulong                 unused2_len;
  fd_pubkey_t*          unused2;

  ulong                 unused3_len;
  fd_pubkey_u64_pair_t* unused3;
};
typedef struct fd_unused_accounts fd_unused_accounts_t;
#define FD_UNUSED_ACCOUNTS_FOOTPRINT sizeof(fd_unused_accounts_t)
#define FD_UNUSED_ACCOUNTS_ALIGN (8UL)

// runtime/src/serde_snapshot/newer.rs:30
struct fd_deserializable_versioned_bank {
  fd_block_hash_queue_t          blockhash_queue;
  ulong                          ancestors_len;
  fd_slot_pair_t *               ancestors;
  fd_hash_t                      hash;
  fd_hash_t                      parent_hash;
  ulong                          parent_slot;
  fd_hard_forks_t                hard_forks;
  ulong                          transaction_count;
  ulong                          tick_height;
  ulong                          signature_count;
  ulong                          capitalization;
  ulong                          max_tick_height;
  ulong *                        hashes_per_tick;
  ulong                          ticks_per_slot;
  uint128                        ns_per_slot;
  long                           genesis_creation_time;
  double                         slots_per_year;
  ulong                          accounts_data_len;
  ulong                          slot;
  ulong                          epoch;
  ulong                          block_height;
  fd_pubkey_t                    collector_id;
  ulong                          collector_fees;
  fd_fee_calculator_t            fee_calculator;
  fd_fee_rate_governor_t         fee_rate_governor;
  ulong                          collected_rent;
  fd_rent_collector_t            rent_collector;
  fd_epoch_schedule_t            epoch_schedule;
  fd_inflation_t                 fd_inflation;
  fd_stakes_deligation_t         stakes;
  fd_unused_accounts_t           unused_accounts;
  ulong                          epoch_stakes_len;
  fd_epoch_epoch_stakes_pair_t * epoch_stakes;
  char                           is_delta;
};
typedef struct fd_deserializable_versioned_bank fd_deserializable_versioned_bank_t;
#define FD_DESERIALIZABLE_VERSIONED_BANK_FOOTPRINT sizeof(fd_deserializable_versioned_bank_t)
#define FD_DESERIALIZABLE_VERSIONED_BANK_ALIGN (8UL)

struct fd_serializable_account_storage_entry {
  ulong id;
  ulong accounts_current_len;
};
typedef struct fd_serializable_account_storage_entry fd_serializable_account_storage_entry_t;
#define FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_FOOTPRINT sizeof(fd_serializable_account_storage_entry_t)
#define FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_ALIGN (8UL)

struct fd_bank_hash_stats {
  ulong num_updated_accounts;
  ulong num_removed_accounts;
  ulong num_lamports_stored;
  ulong total_data_len;
  ulong num_executable_accounts;
};
typedef struct fd_bank_hash_stats fd_bank_hash_stats_t;
#define FD_BANK_HASH_STATS_FOOTPRINT sizeof(fd_bank_hash_stats_t)
#define FD_BANK_HASH_STATS_ALIGN (8UL)

struct fd_bank_hash_info {
  fd_hash_t            hash;
  fd_hash_t            snapshot_hash;
  fd_bank_hash_stats_t stats;
};
typedef struct fd_bank_hash_info fd_bank_hash_info_t;
#define FD_BANK_HASH_INFO_FOOTPRINT sizeof(fd_bank_hash_info_t)
#define FD_BANK_HASH_INFO_ALIGN (8UL)

struct fd_slot_account_pair {
  ulong                                     slot;
  ulong                                     accounts_len;
  fd_serializable_account_storage_entry_t * accounts;
};
typedef struct fd_slot_account_pair fd_slot_account_pair_t;
#define FD_SLOT_ACCOUNT_PAIR_FOOTPRINT sizeof(fd_slot_account_pair_t)
#define FD_SLOT_ACCOUNT_PAIR_ALIGN (8UL)

struct fd_slot_map_pair {
  ulong     slot;
  fd_hash_t hash;
};
typedef struct fd_slot_map_pair fd_slot_map_pair_t;
#define FD_SLOT_MAP_PAIR_FOOTPRINT sizeof(fd_slot_map_pair_t)
#define FD_SLOT_MAP_PAIR_ALIGN (8UL)

struct fd_accounts_db_fields {
  ulong                    storages_len;
  fd_slot_account_pair_t * storages;
  ulong                    version;
  ulong                    slot;
  fd_bank_hash_info_t      bank_hash_info;
  ulong                    historical_roots_len;
  ulong *                  historical_roots;
  ulong                    historical_roots_with_hash_len;
  fd_slot_map_pair_t *     historical_roots_with_hash;
};
typedef struct fd_accounts_db_fields fd_accounts_db_fields_t;
#define FD_ACCOUNTS_DB_FIELDS_FOOTPRINT sizeof(fd_accounts_db_fields_t)
#define FD_ACCOUNTS_DB_FIELDS_ALIGN (8UL)

FD_PROTOTYPES_BEGIN

void fd_fee_calculator_decode(fd_fee_calculator_t* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_hash_age_decode(fd_hash_age_t* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_hash_decode(fd_hash_t* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_hash_hash_age_pair_decode(fd_hash_hash_age_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_block_hash_queue_decode(fd_block_hash_queue_t* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_pubkey_decode(fd_pubkey_t* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_epoch_schedule_decode(fd_epoch_schedule_t* self,  void const** data,  void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_fee_rate_governor_decode(fd_fee_rate_governor_t* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_slot_pair_decode(fd_slot_pair_t* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_hard_forks_decode(fd_hard_forks_t* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_inflation_decode(fd_inflation_t* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_rent_decode(FD_FN_UNUSED fd_rent_t* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_rent_collector_decode(fd_rent_collector_t* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_stake_history_entry_decode(FD_FN_UNUSED fd_stake_history_entry_t* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_stake_history_epochentry_pair_decode(fd_stake_history_epochentry_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_stake_history_decode(fd_stake_history_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_account_decode(fd_account_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_vote_accounts_pair_decode(fd_vote_accounts_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_vote_accounts_decode(fd_vote_accounts_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_delegation_decode(fd_delegation_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_delegation_pair_decode(fd_delegation_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_stakes_deligation_decode(fd_stakes_deligation_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void node_vote_accounts_decode(node_vote_accounts_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_pubkey_node_vote_accounts_pair_decode(fd_pubkey_node_vote_accounts_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_pubkey_pubkey_pair_decode(fd_pubkey_pubkey_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_epoch_stakes_decode(fd_epoch_stakes_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_epoch_epoch_stakes_pair_decode(fd_epoch_epoch_stakes_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_pubkey_u64_pair_decode(fd_pubkey_u64_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_unused_accounts_decode(fd_unused_accounts_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_deserializable_versioned_bank_decode(fd_deserializable_versioned_bank_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_serializable_account_storage_entry_decode(fd_serializable_account_storage_entry_t* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_bank_hash_stats_decode(fd_bank_hash_stats_t* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg);
void fd_bank_hash_info_decode(fd_bank_hash_info_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_slot_account_pair_decode(fd_slot_account_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_slot_map_pair_decode(fd_slot_map_pair_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);
void fd_accounts_db_fields_decode(fd_accounts_db_fields_t* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_banks_solana_h */
