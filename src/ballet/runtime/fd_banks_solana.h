// TODO:
//    look for: FD_PROTOTYPES_BEGIN

#ifndef HEADER_fd_src_ballet_runtime_fd_banks_solana_h
#define HEADER_fd_src_ballet_runtime_fd_banks_solana_h

#include "../../util/encoders/fd_bincode.h"

typedef char* (*fd_alloc_fun_t)(ulong len, ulong align, void* arg);
typedef void  (*fd_free_fun_t) (void *ptr, void* arg);

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

// sdk/prografd_hash_destroym/src/pubkey.rs:87
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
struct fd_solana_account {
  ulong          lamports;

  ulong          data_len;
  unsigned char* data;

  fd_pubkey_t    owner;
  unsigned char  executable;
  ulong          rent_epoch;
};
typedef struct fd_solana_account fd_solana_account_t;
#define ACCOUNT_FOOTPRINT sizeof(fd_solana_account_t)
#define ACCOUNT_ALIGN (8UL)

// As persisted to disk in the solana snapshots
// DO NOT change this structure
struct __attribute__((packed)) fd_solana_account_stored_meta {
    unsigned long write_version_obsolete;
    unsigned long data_len;
    char pubkey[32];
};
typedef struct fd_solana_account_stored_meta fd_solana_account_stored_meta_t;

// DO NOT change this structure
struct __attribute__((packed)) fd_solana_account_meta {
    unsigned long lamports;
    unsigned long rent_epoch;
    char owner[32];
    char executable;
    char padding[7];
};
typedef struct fd_solana_account_meta fd_solana_account_meta_t;

// DO NOT change this structure
struct __attribute__((packed)) fd_solana_account_fd_hash {
    char value[32];
};
typedef struct fd_solana_account_fd_hash fd_solana_account_fd_hash_t;

// DO NOT change this structure
struct __attribute__((packed)) fd_solana_account_hdr {
  fd_solana_account_stored_meta_t meta;
  fd_solana_account_meta_t        info;
  fd_solana_account_fd_hash_t     hash;
};
typedef struct fd_solana_account_hdr fd_solana_account_hdr_t;

// You can change this structure (add additional things to it.. 
struct __attribute__((packed)) fd_account_meta {
  ushort                          magic;
  // Length of header
  ushort                          hlen;
  // Length of data excluding header
  ulong                           dlen;

  unsigned char                   hash[32];
  ulong                           slot;

  // These structures directly come from solana.. is that good?
  fd_solana_account_meta_t        info; 
};
typedef struct fd_account_meta fd_account_meta_t;
#define FD_ACCOUNT_META_MAGIC 9823

struct fd_vote_accounts_pair {
  fd_pubkey_t  key;
  ulong        stake;
  fd_solana_account_t value;
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
struct fd_stakes_delegation {
  fd_vote_accounts_t     vote_accounts;
  ulong                  stake_delegations_len;
  fd_delegation_pair_t*  stake_delegations;
  ulong                  unused;
  ulong                  epoch;
  fd_stake_history_t     stake_history;
};
typedef struct fd_stakes_delegation fd_stakes_delegation_t;
#define FD_STAKES_DELIGATION_FOOTPRINT sizeof(fd_stakes_delegation_t)
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

struct fd_node_vote_accounts {
  ulong        vote_accounts_len;
  fd_pubkey_t *vote_accounts;
  ulong        total_stake;
};
typedef struct fd_node_vote_accounts fd_node_vote_accounts_t;
#define FD_NODE_VOTE_ACCOUNTS_FOOTPRINT sizeof(fd_node_vote_accounts_t)
#define FD_NODE_VOTE_ACCOUNTS_ALIGN (8UL)

struct fd_pubkey_node_vote_accounts_pair {
  fd_pubkey_t          key;
  fd_node_vote_accounts_t value;
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
  fd_stakes_delegation_t                stakes;
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
  fd_inflation_t                 inflation;
  fd_stakes_delegation_t         stakes;
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

struct fd_solana_accounts_db_fields {
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
typedef struct fd_solana_accounts_db_fields fd_solana_accounts_db_fields_t;
#define FD_ACCOUNTS_DB_FIELDS_FOOTPRINT sizeof(fd_solana_accounts_db_fields_t)
#define FD_ACCOUNTS_DB_FIELDS_ALIGN (8UL)

// 12 bytes...  both fields are in bigint format
// std::time::Duration::new(12, 10) == 0c000000000000000a000000
struct fd_rust_duration {
  ulong seconds;
  uint nanoseconds;
};
typedef struct fd_rust_duration fd_rust_duration_t;

struct fd_poh_config {
  /// The target tick rate of the cluster.
  fd_rust_duration_t target_tick_duration;
 
  /// The target total tick count to be produced; used for testing only
  ulong * target_tick_count;

  /// How many hashes to roll before emitting the next tick entry.
  /// None enables "Low power mode", which implies:
  /// * sleep for `target_tick_duration` instead of hashing
  /// * the number of hashes per tick will be variable
  ulong * hashes_per_tick;
};
typedef struct fd_poh_config fd_poh_config_t;

struct fd_string_pubkey_pair {
  char *string;
  fd_pubkey_t pubkey;
};
typedef struct fd_string_pubkey_pair fd_string_pubkey_pair_t;
#define FD_STRING_PUBKEY_PAIR_FOOTPRINT sizeof(fd_string_pubkey_pair_t)
#define FD_STRING_PUBKEY_PAIR_ALIGN (8UL)

struct fd_pubkey_account_pair {
  fd_pubkey_t  key;
  fd_solana_account_t account;
};
typedef struct fd_pubkey_account_pair fd_pubkey_account_pair_t;
#define FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT sizeof(fd_pubkey_account_pair_t)
#define FD_PUBKEY_ACCOUNT_PAIR_ALIGN (8UL)

struct fd_genesis_solana {
  /// when the network (bootstrap validator) was started relative to the UNIX Epoch
  ulong creation_time;
  /// initial accounts  (this is really a hash map in the solana version)
  ulong accounts_len;
  fd_pubkey_account_pair_t *accounts;
  /// built-in programs
  ulong native_instruction_processors_len;
  fd_string_pubkey_pair_t *native_instruction_processors;
  /// accounts for network rewards, these do not count towards capitalization
  //    hashmap
  ulong rewards_pools_len;
  fd_pubkey_account_pair_t *rewards_pools;
  //pub rewards_pools: BTreeMap<Pubkey, Account>,
  ulong ticks_per_slot;
  ulong unused;
  /// network speed configuration
  fd_poh_config_t poh_config;
  /// this field exists only to ensure that the binary layout of GenesisConfig remains compatible
  /// with the Solana v0.23 release line
  ulong  __backwards_compat_with_v0_23;
  /// transaction fee config
  fd_fee_rate_governor_t fee_rate_governor;
  /// rent config
  fd_rent_t rent;
  /// inflation config
  fd_inflation_t inflation;
  /// how slots map to epochs
  fd_epoch_schedule_t epoch_schedule;
  /// network runlevel
  uint cluster_type; // 0 - testnet, 1 - mainnetBeta,  2-devnet, 3 - dev
};
typedef struct fd_genesis_solana fd_genesis_solana_t;
#define FD_GENESIS_SOLANA_FOOTPRINT sizeof(fd_genesis_solana_t)
#define FD_GENESIS_SOLANA_ALIGN (8UL)

FD_PROTOTYPES_BEGIN

void fd_solana_account_decode(fd_solana_account_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_solana_account_destroy(fd_solana_account_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_solana_accounts_db_fields_decode(fd_solana_accounts_db_fields_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_solana_accounts_db_fields_destroy(fd_solana_accounts_db_fields_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_bank_hash_info_decode(fd_bank_hash_info_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_bank_hash_info_destroy(fd_bank_hash_info_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_bank_hash_stats_decode(fd_bank_hash_stats_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_bank_hash_stats_destroy(fd_bank_hash_stats_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_block_hash_queue_decode(fd_block_hash_queue_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_block_hash_queue_destroy(fd_block_hash_queue_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_delegation_decode(fd_delegation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_delegation_destroy(fd_delegation_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_delegation_pair_decode(fd_delegation_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_delegation_pair_destroy(fd_delegation_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_deserializable_versioned_bank_decode(fd_deserializable_versioned_bank_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_deserializable_versioned_bank_destroy(fd_deserializable_versioned_bank_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_epoch_epoch_stakes_pair_decode(fd_epoch_epoch_stakes_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_epoch_epoch_stakes_pair_destroy(fd_epoch_epoch_stakes_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_epoch_schedule_decode(fd_epoch_schedule_t* self,  void const** data,  void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_epoch_schedule_destroy(fd_epoch_schedule_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_epoch_stakes_decode(fd_epoch_stakes_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_epoch_stakes_destroy(fd_epoch_stakes_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_fee_calculator_decode(fd_fee_calculator_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_fee_calculator_destroy(fd_fee_calculator_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_fee_rate_governor_decode(fd_fee_rate_governor_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_fee_rate_governor_destroy(fd_fee_rate_governor_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_genesis_solana_decode(fd_genesis_solana_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_genesis_solana_destroy(fd_genesis_solana_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_hard_forks_decode(fd_hard_forks_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_hard_forks_destroy(fd_hard_forks_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_hash_age_decode(fd_hash_age_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_hash_age_destroy(fd_hash_age_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_hash_decode(fd_hash_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_hash_destroy(fd_hash_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_hash_hash_age_pair_decode(fd_hash_hash_age_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_hash_hash_age_pair_destroy(fd_hash_hash_age_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_inflation_decode(fd_inflation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_inflation_destroy(fd_inflation_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_node_vote_accounts_decode(fd_node_vote_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_node_vote_accounts_destroy(fd_node_vote_accounts_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_poh_config_decode(fd_poh_config_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_poh_config_destroy(fd_poh_config_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_pubkey_account_pair_decode(fd_pubkey_account_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_account_pair_destroy(fd_pubkey_account_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_pubkey_decode(fd_pubkey_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_destroy(fd_pubkey_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_pubkey_node_vote_accounts_pair_decode(fd_pubkey_node_vote_accounts_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_node_vote_accounts_pair_destroy(fd_pubkey_node_vote_accounts_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_pubkey_pubkey_pair_decode(fd_pubkey_pubkey_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_pubkey_pair_destroy(fd_pubkey_pubkey_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_pubkey_u64_pair_decode(fd_pubkey_u64_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_u64_pair_destroy(fd_pubkey_u64_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_rent_collector_decode(fd_rent_collector_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_rent_collector_destroy(fd_rent_collector_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_rent_decode(fd_rent_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_rent_destroy(fd_rent_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_rust_duration_decode(fd_rust_duration_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_rust_duration_destroy(fd_rust_duration_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);

void fd_serializable_account_storage_entry_decode(fd_serializable_account_storage_entry_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_serializable_account_storage_entry_destroy(fd_serializable_account_storage_entry_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_slot_account_pair_decode(fd_slot_account_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_account_pair_destroy(fd_slot_account_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_slot_map_pair_decode(fd_slot_map_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_map_pair_destroy(fd_slot_map_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_slot_pair_decode(fd_slot_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_pair_destroy(fd_slot_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_stake_history_decode(fd_stake_history_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_stake_history_destroy(fd_stake_history_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_stake_history_entry_decode(fd_stake_history_entry_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_stake_history_entry_destroy(fd_stake_history_entry_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_stake_history_epochentry_pair_decode(fd_stake_history_epochentry_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_stake_history_epochentry_pair_destroy(fd_stake_history_epochentry_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_stakes_delegation_decode(fd_stakes_delegation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_stakes_delegation_destroy(fd_stakes_delegation_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_string_pubkey_pair_decode(fd_string_pubkey_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_string_pubkey_pair_destroy(fd_string_pubkey_pair_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_unused_accounts_decode(fd_unused_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_unused_accounts_destroy(fd_unused_accounts_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_vote_accounts_decode(fd_vote_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_accounts_destroy(fd_vote_accounts_t* self, fd_free_fun_t freef, void* freef_arg);

void fd_vote_accounts_pair_decode(fd_vote_accounts_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_accounts_pair_destroy(fd_vote_accounts_pair_t* self, fd_free_fun_t freef, void* freef_arg);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_banks_solana_h */
