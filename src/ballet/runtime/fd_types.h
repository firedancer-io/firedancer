#ifndef HEADER_FD_BANKS_SOLANA
#define HEADER_FD_BANKS_SOLANA

#include "../../util/encoders/fd_bincode.h"
typedef char* (*fd_alloc_fun_t)(ulong len, ulong align, void* arg);
typedef void  (*fd_free_fun_t) (void *ptr, void* arg);
#define FD_ACCOUNT_META_MAGIC 9823

struct fd_fee_calculator {
  ulong lamports_per_signature;
};
typedef struct fd_fee_calculator fd_fee_calculator_t;
#define FD_FEE_CALCULATOR_FOOTPRINT sizeof(fd_fee_calculator_t)
#define FD_FEE_CALCULATOR_ALIGN (8UL)

struct fd_hash_age {
  fd_fee_calculator_t fee_calculator;
  ulong               hash_index;
  ulong               timestamp;
};
typedef struct fd_hash_age fd_hash_age_t;
#define FD_HASH_AGE_FOOTPRINT sizeof(fd_hash_age_t)
#define FD_HASH_AGE_ALIGN (8UL)

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

struct fd_pubkey {
  unsigned char key[32];
};
typedef struct fd_pubkey fd_pubkey_t;
#define FD_PUBKEY_FOOTPRINT sizeof(fd_pubkey_t)
#define FD_PUBKEY_ALIGN (8UL)

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

struct fd_hard_forks {
  ulong           hard_forks_len;
  fd_slot_pair_t* hard_forks;
};
typedef struct fd_hard_forks fd_hard_forks_t;
#define FD_HARD_FORKS_FOOTPRINT sizeof(fd_hard_forks_t)
#define FD_HARD_FORKS_ALIGN (8UL)

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

struct fd_rent {
  ulong         lamports_per_uint8_year;
  double        exemption_threshold;
  unsigned char burn_percent;
};
typedef struct fd_rent fd_rent_t;
#define FD_RENT_FOOTPRINT sizeof(fd_rent_t)
#define FD_RENT_ALIGN (8UL)

struct fd_rent_collector {
  ulong               epoch;
  fd_epoch_schedule_t epoch_schedule;
  double              slots_per_year;
  fd_rent_t           rent;
};
typedef struct fd_rent_collector fd_rent_collector_t;
#define FD_RENT_COLLECTOR_FOOTPRINT sizeof(fd_rent_collector_t)
#define FD_RENT_COLLECTOR_ALIGN (8UL)

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

struct fd_stake_history {
  ulong                               entries_len;
  fd_stake_history_epochentry_pair_t* entries;
};
typedef struct fd_stake_history fd_stake_history_t;
#define FD_STAKE_HISTORY_FOOTPRINT sizeof(fd_stake_history_t)
#define FD_STAKE_HISTORY_ALIGN (8UL)

struct fd_solana_account {
  ulong          lamports;
  ulong          data_len;
  unsigned char* data;
  fd_pubkey_t    owner;
  unsigned char  executable;
  ulong          rent_epoch;
};
typedef struct fd_solana_account fd_solana_account_t;
#define FD_SOLANA_ACCOUNT_FOOTPRINT sizeof(fd_solana_account_t)
#define FD_SOLANA_ACCOUNT_ALIGN (8UL)

struct __attribute__((packed)) fd_solana_account_stored_meta {
  ulong write_version_obsolete;
  ulong data_len;
  char  pubkey[32];
};
typedef struct fd_solana_account_stored_meta fd_solana_account_stored_meta_t;
#define FD_SOLANA_ACCOUNT_STORED_META_FOOTPRINT sizeof(fd_solana_account_stored_meta_t)
#define FD_SOLANA_ACCOUNT_STORED_META_ALIGN (8UL)

struct __attribute__((packed)) fd_solana_account_meta {
  ulong lamports;
  ulong rent_epoch;
  char  owner[32];
  char  executable;
  char  padding[7];
};
typedef struct fd_solana_account_meta fd_solana_account_meta_t;
#define FD_SOLANA_ACCOUNT_META_FOOTPRINT sizeof(fd_solana_account_meta_t)
#define FD_SOLANA_ACCOUNT_META_ALIGN (8UL)

struct __attribute__((packed)) fd_solana_account_fd_hash {
  char value[32];
};
typedef struct fd_solana_account_fd_hash fd_solana_account_fd_hash_t;
#define FD_SOLANA_ACCOUNT_FD_HASH_FOOTPRINT sizeof(fd_solana_account_fd_hash_t)
#define FD_SOLANA_ACCOUNT_FD_HASH_ALIGN (8UL)

struct __attribute__((packed)) fd_solana_account_hdr {
  fd_solana_account_stored_meta_t meta;
  fd_solana_account_meta_t        info;
  fd_solana_account_fd_hash_t     hash;
};
typedef struct fd_solana_account_hdr fd_solana_account_hdr_t;
#define FD_SOLANA_ACCOUNT_HDR_FOOTPRINT sizeof(fd_solana_account_hdr_t)
#define FD_SOLANA_ACCOUNT_HDR_ALIGN (8UL)

struct __attribute__((packed)) fd_account_meta {
  ushort                   magic;
  ushort                   hlen;
  ulong                    dlen;
  unsigned char            hash[32];
  ulong                    slot;
  fd_solana_account_meta_t info;
};
typedef struct fd_account_meta fd_account_meta_t;
#define FD_ACCOUNT_META_FOOTPRINT sizeof(fd_account_meta_t)
#define FD_ACCOUNT_META_ALIGN (8UL)

struct fd_vote_accounts_pair {
  fd_pubkey_t         key;
  ulong               stake;
  fd_solana_account_t value;
};
typedef struct fd_vote_accounts_pair fd_vote_accounts_pair_t;
#define FD_VOTE_ACCOUNTS_PAIR_FOOTPRINT sizeof(fd_vote_accounts_pair_t)
#define FD_VOTE_ACCOUNTS_PAIR_ALIGN (8UL)

struct fd_vote_accounts {
  ulong                    vote_accounts_len;
  fd_vote_accounts_pair_t* vote_accounts;
};
typedef struct fd_vote_accounts fd_vote_accounts_t;
#define FD_VOTE_ACCOUNTS_FOOTPRINT sizeof(fd_vote_accounts_t)
#define FD_VOTE_ACCOUNTS_ALIGN (8UL)

struct fd_delegation {
  fd_pubkey_t voter_pubkey;
  ulong       stake;
  ulong       activation_epoch;
  ulong       deactivation_epoch;
  double      warmup_cooldown_rate;
};
typedef struct fd_delegation fd_delegation_t;
#define FD_DELEGATION_FOOTPRINT sizeof(fd_delegation_t)
#define FD_DELEGATION_ALIGN (8UL)

struct fd_delegation_pair {
  fd_pubkey_t     key;
  fd_delegation_t value;
};
typedef struct fd_delegation_pair fd_delegation_pair_t;
#define FD_DELEGATION_PAIR_FOOTPRINT sizeof(fd_delegation_pair_t)
#define FD_DELEGATION_PAIR_ALIGN (8UL)

struct fd_stakes_delegation {
  fd_vote_accounts_t    vote_accounts;
  ulong                 stake_delegations_len;
  fd_delegation_pair_t* stake_delegations;
  ulong                 unused;
  ulong                 epoch;
  fd_stake_history_t    stake_history;
};
typedef struct fd_stakes_delegation fd_stakes_delegation_t;
#define FD_STAKES_DELEGATION_FOOTPRINT sizeof(fd_stakes_delegation_t)
#define FD_STAKES_DELEGATION_ALIGN (8UL)

struct fd_bank_incremental_snapshot_persistence {
  ulong     full_slot;
  fd_hash_t full_hash;
  ulong     full_capitalization;
  fd_hash_t incremental_hash;
  ulong     incremental_capitalization;
};
typedef struct fd_bank_incremental_snapshot_persistence fd_bank_incremental_snapshot_persistence_t;
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FOOTPRINT sizeof(fd_bank_incremental_snapshot_persistence_t)
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN (8UL)

struct fd_node_vote_accounts {
  ulong        vote_accounts_len;
  fd_pubkey_t* vote_accounts;
  ulong        total_stake;
};
typedef struct fd_node_vote_accounts fd_node_vote_accounts_t;
#define FD_NODE_VOTE_ACCOUNTS_FOOTPRINT sizeof(fd_node_vote_accounts_t)
#define FD_NODE_VOTE_ACCOUNTS_ALIGN (8UL)

struct fd_pubkey_node_vote_accounts_pair {
  fd_pubkey_t             key;
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

struct fd_epoch_stakes {
  fd_stakes_delegation_t               stakes;
  ulong                                total_stake;
  ulong                                node_id_to_vote_accounts_len;
  fd_pubkey_node_vote_accounts_pair_t* node_id_to_vote_accounts;
  ulong                                epoch_authorized_voters_len;
  fd_pubkey_pubkey_pair_t*             epoch_authorized_voters;
};
typedef struct fd_epoch_stakes fd_epoch_stakes_t;
#define FD_EPOCH_STAKES_FOOTPRINT sizeof(fd_epoch_stakes_t)
#define FD_EPOCH_STAKES_ALIGN (8UL)

struct fd_epoch_epoch_stakes_pair {
  ulong             key;
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

struct fd_deserializable_versioned_bank {
  fd_block_hash_queue_t         blockhash_queue;
  ulong                         ancestors_len;
  fd_slot_pair_t*               ancestors;
  fd_hash_t                     hash;
  fd_hash_t                     parent_hash;
  ulong                         parent_slot;
  fd_hard_forks_t               hard_forks;
  ulong                         transaction_count;
  ulong                         tick_height;
  ulong                         signature_count;
  ulong                         capitalization;
  ulong                         max_tick_height;
  ulong*                        hashes_per_tick;
  ulong                         ticks_per_slot;
  uint128                       ns_per_slot;
  ulong                         genesis_creation_time;
  double                        slots_per_year;
  ulong                         accounts_data_len;
  ulong                         slot;
  ulong                         epoch;
  ulong                         block_height;
  fd_pubkey_t                   collector_id;
  ulong                         collector_fees;
  fd_fee_calculator_t           fee_calculator;
  fd_fee_rate_governor_t        fee_rate_governor;
  ulong                         collected_rent;
  fd_rent_collector_t           rent_collector;
  fd_epoch_schedule_t           epoch_schedule;
  fd_inflation_t                inflation;
  fd_stakes_delegation_t        stakes;
  fd_unused_accounts_t          unused_accounts;
  ulong                         epoch_stakes_len;
  fd_epoch_epoch_stakes_pair_t* epoch_stakes;
  char                          is_delta;
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
  ulong                                    slot;
  ulong                                    accounts_len;
  fd_serializable_account_storage_entry_t* accounts;
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
  ulong                   storages_len;
  fd_slot_account_pair_t* storages;
  ulong                   version;
  ulong                   slot;
  fd_bank_hash_info_t     bank_hash_info;
  ulong                   historical_roots_len;
  ulong*                  historical_roots;
  ulong                   historical_roots_with_hash_len;
  fd_slot_map_pair_t*     historical_roots_with_hash;
};
typedef struct fd_solana_accounts_db_fields fd_solana_accounts_db_fields_t;
#define FD_SOLANA_ACCOUNTS_DB_FIELDS_FOOTPRINT sizeof(fd_solana_accounts_db_fields_t)
#define FD_SOLANA_ACCOUNTS_DB_FIELDS_ALIGN (8UL)

struct fd_rust_duration {
  ulong seconds;
  uint  nanoseconds;
};
typedef struct fd_rust_duration fd_rust_duration_t;
#define FD_RUST_DURATION_FOOTPRINT sizeof(fd_rust_duration_t)
#define FD_RUST_DURATION_ALIGN (8UL)

struct fd_poh_config {
  fd_rust_duration_t target_tick_duration;
  ulong*             target_tick_count;
  ulong*             hashes_per_tick;
};
typedef struct fd_poh_config fd_poh_config_t;
#define FD_POH_CONFIG_FOOTPRINT sizeof(fd_poh_config_t)
#define FD_POH_CONFIG_ALIGN (8UL)

struct fd_string_pubkey_pair {
  char*       string;
  fd_pubkey_t pubkey;
};
typedef struct fd_string_pubkey_pair fd_string_pubkey_pair_t;
#define FD_STRING_PUBKEY_PAIR_FOOTPRINT sizeof(fd_string_pubkey_pair_t)
#define FD_STRING_PUBKEY_PAIR_ALIGN (8UL)

struct fd_pubkey_account_pair {
  fd_pubkey_t         key;
  fd_solana_account_t account;
};
typedef struct fd_pubkey_account_pair fd_pubkey_account_pair_t;
#define FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT sizeof(fd_pubkey_account_pair_t)
#define FD_PUBKEY_ACCOUNT_PAIR_ALIGN (8UL)

struct fd_genesis_solana {
  ulong                     creation_time;
  ulong                     accounts_len;
  fd_pubkey_account_pair_t* accounts;
  ulong                     native_instruction_processors_len;
  fd_string_pubkey_pair_t*  native_instruction_processors;
  ulong                     rewards_pools_len;
  fd_pubkey_account_pair_t* rewards_pools;
  ulong                     ticks_per_slot;
  ulong                     unused;
  fd_poh_config_t           poh_config;
  ulong                     __backwards_compat_with_v0_23;
  fd_fee_rate_governor_t    fee_rate_governor;
  fd_rent_t                 rent;
  fd_inflation_t            inflation;
  fd_epoch_schedule_t       epoch_schedule;
  uint                      cluster_type;
};
typedef struct fd_genesis_solana fd_genesis_solana_t;
#define FD_GENESIS_SOLANA_FOOTPRINT sizeof(fd_genesis_solana_t)
#define FD_GENESIS_SOLANA_ALIGN (8UL)


FD_PROTOTYPES_BEGIN

void fd_fee_calculator_decode(fd_fee_calculator_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_fee_calculator_encode(fd_fee_calculator_t* self, void const** data);
void fd_fee_calculator_destroy(fd_fee_calculator_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_fee_calculator_size(fd_fee_calculator_t* self);

void fd_hash_age_decode(fd_hash_age_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_hash_age_encode(fd_hash_age_t* self, void const** data);
void fd_hash_age_destroy(fd_hash_age_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_hash_age_size(fd_hash_age_t* self);

void fd_hash_decode(fd_hash_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_hash_encode(fd_hash_t* self, void const** data);
void fd_hash_destroy(fd_hash_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_hash_size(fd_hash_t* self);

void fd_hash_hash_age_pair_decode(fd_hash_hash_age_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_hash_hash_age_pair_encode(fd_hash_hash_age_pair_t* self, void const** data);
void fd_hash_hash_age_pair_destroy(fd_hash_hash_age_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_hash_hash_age_pair_size(fd_hash_hash_age_pair_t* self);

void fd_block_hash_queue_decode(fd_block_hash_queue_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_block_hash_queue_encode(fd_block_hash_queue_t* self, void const** data);
void fd_block_hash_queue_destroy(fd_block_hash_queue_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_block_hash_queue_size(fd_block_hash_queue_t* self);

void fd_pubkey_decode(fd_pubkey_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_encode(fd_pubkey_t* self, void const** data);
void fd_pubkey_destroy(fd_pubkey_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_pubkey_size(fd_pubkey_t* self);

void fd_epoch_schedule_decode(fd_epoch_schedule_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_epoch_schedule_encode(fd_epoch_schedule_t* self, void const** data);
void fd_epoch_schedule_destroy(fd_epoch_schedule_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_epoch_schedule_size(fd_epoch_schedule_t* self);

void fd_fee_rate_governor_decode(fd_fee_rate_governor_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_fee_rate_governor_encode(fd_fee_rate_governor_t* self, void const** data);
void fd_fee_rate_governor_destroy(fd_fee_rate_governor_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_fee_rate_governor_size(fd_fee_rate_governor_t* self);

void fd_slot_pair_decode(fd_slot_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_pair_encode(fd_slot_pair_t* self, void const** data);
void fd_slot_pair_destroy(fd_slot_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_pair_size(fd_slot_pair_t* self);

void fd_hard_forks_decode(fd_hard_forks_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_hard_forks_encode(fd_hard_forks_t* self, void const** data);
void fd_hard_forks_destroy(fd_hard_forks_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_hard_forks_size(fd_hard_forks_t* self);

void fd_inflation_decode(fd_inflation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_inflation_encode(fd_inflation_t* self, void const** data);
void fd_inflation_destroy(fd_inflation_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_inflation_size(fd_inflation_t* self);

void fd_rent_decode(fd_rent_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_rent_encode(fd_rent_t* self, void const** data);
void fd_rent_destroy(fd_rent_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_rent_size(fd_rent_t* self);

void fd_rent_collector_decode(fd_rent_collector_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_rent_collector_encode(fd_rent_collector_t* self, void const** data);
void fd_rent_collector_destroy(fd_rent_collector_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_rent_collector_size(fd_rent_collector_t* self);

void fd_stake_history_entry_decode(fd_stake_history_entry_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_stake_history_entry_encode(fd_stake_history_entry_t* self, void const** data);
void fd_stake_history_entry_destroy(fd_stake_history_entry_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_stake_history_entry_size(fd_stake_history_entry_t* self);

void fd_stake_history_epochentry_pair_decode(fd_stake_history_epochentry_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_stake_history_epochentry_pair_encode(fd_stake_history_epochentry_pair_t* self, void const** data);
void fd_stake_history_epochentry_pair_destroy(fd_stake_history_epochentry_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_stake_history_epochentry_pair_size(fd_stake_history_epochentry_pair_t* self);

void fd_stake_history_decode(fd_stake_history_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_stake_history_encode(fd_stake_history_t* self, void const** data);
void fd_stake_history_destroy(fd_stake_history_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_stake_history_size(fd_stake_history_t* self);

void fd_solana_account_decode(fd_solana_account_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_solana_account_encode(fd_solana_account_t* self, void const** data);
void fd_solana_account_destroy(fd_solana_account_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_solana_account_size(fd_solana_account_t* self);

void fd_vote_accounts_pair_decode(fd_vote_accounts_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_accounts_pair_encode(fd_vote_accounts_pair_t* self, void const** data);
void fd_vote_accounts_pair_destroy(fd_vote_accounts_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_accounts_pair_size(fd_vote_accounts_pair_t* self);

void fd_vote_accounts_decode(fd_vote_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_accounts_encode(fd_vote_accounts_t* self, void const** data);
void fd_vote_accounts_destroy(fd_vote_accounts_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_accounts_size(fd_vote_accounts_t* self);

void fd_delegation_decode(fd_delegation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_delegation_encode(fd_delegation_t* self, void const** data);
void fd_delegation_destroy(fd_delegation_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_delegation_size(fd_delegation_t* self);

void fd_delegation_pair_decode(fd_delegation_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_delegation_pair_encode(fd_delegation_pair_t* self, void const** data);
void fd_delegation_pair_destroy(fd_delegation_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_delegation_pair_size(fd_delegation_pair_t* self);

void fd_stakes_delegation_decode(fd_stakes_delegation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_stakes_delegation_encode(fd_stakes_delegation_t* self, void const** data);
void fd_stakes_delegation_destroy(fd_stakes_delegation_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_stakes_delegation_size(fd_stakes_delegation_t* self);

void fd_bank_incremental_snapshot_persistence_decode(fd_bank_incremental_snapshot_persistence_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_bank_incremental_snapshot_persistence_encode(fd_bank_incremental_snapshot_persistence_t* self, void const** data);
void fd_bank_incremental_snapshot_persistence_destroy(fd_bank_incremental_snapshot_persistence_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_bank_incremental_snapshot_persistence_size(fd_bank_incremental_snapshot_persistence_t* self);

void fd_node_vote_accounts_decode(fd_node_vote_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_node_vote_accounts_encode(fd_node_vote_accounts_t* self, void const** data);
void fd_node_vote_accounts_destroy(fd_node_vote_accounts_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_node_vote_accounts_size(fd_node_vote_accounts_t* self);

void fd_pubkey_node_vote_accounts_pair_decode(fd_pubkey_node_vote_accounts_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_node_vote_accounts_pair_encode(fd_pubkey_node_vote_accounts_pair_t* self, void const** data);
void fd_pubkey_node_vote_accounts_pair_destroy(fd_pubkey_node_vote_accounts_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_pubkey_node_vote_accounts_pair_size(fd_pubkey_node_vote_accounts_pair_t* self);

void fd_pubkey_pubkey_pair_decode(fd_pubkey_pubkey_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_pubkey_pair_encode(fd_pubkey_pubkey_pair_t* self, void const** data);
void fd_pubkey_pubkey_pair_destroy(fd_pubkey_pubkey_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_pubkey_pubkey_pair_size(fd_pubkey_pubkey_pair_t* self);

void fd_epoch_stakes_decode(fd_epoch_stakes_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_epoch_stakes_encode(fd_epoch_stakes_t* self, void const** data);
void fd_epoch_stakes_destroy(fd_epoch_stakes_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_epoch_stakes_size(fd_epoch_stakes_t* self);

void fd_epoch_epoch_stakes_pair_decode(fd_epoch_epoch_stakes_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_epoch_epoch_stakes_pair_encode(fd_epoch_epoch_stakes_pair_t* self, void const** data);
void fd_epoch_epoch_stakes_pair_destroy(fd_epoch_epoch_stakes_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_epoch_epoch_stakes_pair_size(fd_epoch_epoch_stakes_pair_t* self);

void fd_pubkey_u64_pair_decode(fd_pubkey_u64_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_u64_pair_encode(fd_pubkey_u64_pair_t* self, void const** data);
void fd_pubkey_u64_pair_destroy(fd_pubkey_u64_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_pubkey_u64_pair_size(fd_pubkey_u64_pair_t* self);

void fd_unused_accounts_decode(fd_unused_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_unused_accounts_encode(fd_unused_accounts_t* self, void const** data);
void fd_unused_accounts_destroy(fd_unused_accounts_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_unused_accounts_size(fd_unused_accounts_t* self);

void fd_deserializable_versioned_bank_decode(fd_deserializable_versioned_bank_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_deserializable_versioned_bank_encode(fd_deserializable_versioned_bank_t* self, void const** data);
void fd_deserializable_versioned_bank_destroy(fd_deserializable_versioned_bank_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_deserializable_versioned_bank_size(fd_deserializable_versioned_bank_t* self);

void fd_serializable_account_storage_entry_decode(fd_serializable_account_storage_entry_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_serializable_account_storage_entry_encode(fd_serializable_account_storage_entry_t* self, void const** data);
void fd_serializable_account_storage_entry_destroy(fd_serializable_account_storage_entry_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_serializable_account_storage_entry_size(fd_serializable_account_storage_entry_t* self);

void fd_bank_hash_stats_decode(fd_bank_hash_stats_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_bank_hash_stats_encode(fd_bank_hash_stats_t* self, void const** data);
void fd_bank_hash_stats_destroy(fd_bank_hash_stats_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_bank_hash_stats_size(fd_bank_hash_stats_t* self);

void fd_bank_hash_info_decode(fd_bank_hash_info_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_bank_hash_info_encode(fd_bank_hash_info_t* self, void const** data);
void fd_bank_hash_info_destroy(fd_bank_hash_info_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_bank_hash_info_size(fd_bank_hash_info_t* self);

void fd_slot_account_pair_decode(fd_slot_account_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_account_pair_encode(fd_slot_account_pair_t* self, void const** data);
void fd_slot_account_pair_destroy(fd_slot_account_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_account_pair_size(fd_slot_account_pair_t* self);

void fd_slot_map_pair_decode(fd_slot_map_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_map_pair_encode(fd_slot_map_pair_t* self, void const** data);
void fd_slot_map_pair_destroy(fd_slot_map_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_map_pair_size(fd_slot_map_pair_t* self);

void fd_solana_accounts_db_fields_decode(fd_solana_accounts_db_fields_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_solana_accounts_db_fields_encode(fd_solana_accounts_db_fields_t* self, void const** data);
void fd_solana_accounts_db_fields_destroy(fd_solana_accounts_db_fields_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_solana_accounts_db_fields_size(fd_solana_accounts_db_fields_t* self);

void fd_rust_duration_decode(fd_rust_duration_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_rust_duration_encode(fd_rust_duration_t* self, void const** data);
void fd_rust_duration_destroy(fd_rust_duration_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_rust_duration_size(fd_rust_duration_t* self);

void fd_poh_config_decode(fd_poh_config_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_poh_config_encode(fd_poh_config_t* self, void const** data);
void fd_poh_config_destroy(fd_poh_config_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_poh_config_size(fd_poh_config_t* self);

void fd_string_pubkey_pair_decode(fd_string_pubkey_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_string_pubkey_pair_encode(fd_string_pubkey_pair_t* self, void const** data);
void fd_string_pubkey_pair_destroy(fd_string_pubkey_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_string_pubkey_pair_size(fd_string_pubkey_pair_t* self);

void fd_pubkey_account_pair_decode(fd_pubkey_account_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_pubkey_account_pair_encode(fd_pubkey_account_pair_t* self, void const** data);
void fd_pubkey_account_pair_destroy(fd_pubkey_account_pair_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_pubkey_account_pair_size(fd_pubkey_account_pair_t* self);

void fd_genesis_solana_decode(fd_genesis_solana_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_genesis_solana_encode(fd_genesis_solana_t* self, void const** data);
void fd_genesis_solana_destroy(fd_genesis_solana_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_genesis_solana_size(fd_genesis_solana_t* self);

FD_PROTOTYPES_END

#endif // HEADER_FD_BANKS_SOLANA
