#ifndef HEADER_FD_BANKS_SOLANA
#define HEADER_FD_BANKS_SOLANA

#include "../../util/encoders/fd_bincode.h"
typedef char* (*fd_alloc_fun_t)(void *arg, ulong align, ulong len);
typedef void  (*fd_free_fun_t) (void *arg, void *ptr);
#define FD_ACCOUNT_META_MAGIC 9823

struct fd_fee_calculator {
  unsigned long lamports_per_signature;
};
typedef struct fd_fee_calculator fd_fee_calculator_t;
#define FD_FEE_CALCULATOR_FOOTPRINT sizeof(fd_fee_calculator_t)
#define FD_FEE_CALCULATOR_ALIGN (8UL)

struct fd_hash_age {
  fd_fee_calculator_t fee_calculator;
  unsigned long       hash_index;
  unsigned long       timestamp;
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
  unsigned long            last_hash_index;
  fd_hash_t*               last_hash;
  ulong                    ages_len;
  fd_hash_hash_age_pair_t* ages;
  unsigned long            max_age;
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
  unsigned long slots_per_epoch;
  unsigned long leader_schedule_slot_offset;
  unsigned char warmup;
  unsigned long first_normal_epoch;
  unsigned long first_normal_slot;
};
typedef struct fd_epoch_schedule fd_epoch_schedule_t;
#define FD_EPOCH_SCHEDULE_FOOTPRINT sizeof(fd_epoch_schedule_t)
#define FD_EPOCH_SCHEDULE_ALIGN (8UL)

struct fd_fee_rate_governor {
  unsigned long target_lamports_per_signature;
  unsigned long target_signatures_per_slot;
  unsigned long min_lamports_per_signature;
  unsigned long max_lamports_per_signature;
  unsigned char burn_percent;
};
typedef struct fd_fee_rate_governor fd_fee_rate_governor_t;
#define FD_FEE_RATE_GOVERNOR_FOOTPRINT sizeof(fd_fee_rate_governor_t)
#define FD_FEE_RATE_GOVERNOR_ALIGN (8UL)

struct fd_slot_pair {
  unsigned long slot;
  unsigned long val;
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
  unsigned long lamports_per_uint8_year;
  double        exemption_threshold;
  unsigned char burn_percent;
};
typedef struct fd_rent fd_rent_t;
#define FD_RENT_FOOTPRINT sizeof(fd_rent_t)
#define FD_RENT_ALIGN (8UL)

struct fd_rent_collector {
  unsigned long       epoch;
  fd_epoch_schedule_t epoch_schedule;
  double              slots_per_year;
  fd_rent_t           rent;
};
typedef struct fd_rent_collector fd_rent_collector_t;
#define FD_RENT_COLLECTOR_FOOTPRINT sizeof(fd_rent_collector_t)
#define FD_RENT_COLLECTOR_ALIGN (8UL)

struct fd_stake_history_entry {
  unsigned long effective;
  unsigned long activating;
  unsigned long deactivating;
};
typedef struct fd_stake_history_entry fd_stake_history_entry_t;
#define FD_STAKE_HISTORY_ENTRY_FOOTPRINT sizeof(fd_stake_history_entry_t)
#define FD_STAKE_HISTORY_ENTRY_ALIGN (8UL)

struct fd_stake_history_epochentry_pair {
  unsigned long            epoch;
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
  unsigned long  lamports;
  ulong          data_len;
  unsigned char* data;
  fd_pubkey_t    owner;
  unsigned char  executable;
  unsigned long  rent_epoch;
};
typedef struct fd_solana_account fd_solana_account_t;
#define FD_SOLANA_ACCOUNT_FOOTPRINT sizeof(fd_solana_account_t)
#define FD_SOLANA_ACCOUNT_ALIGN (8UL)

struct __attribute__((packed)) fd_solana_account_stored_meta {
  unsigned long write_version_obsolete;
  unsigned long data_len;
  char          pubkey[32];
};
typedef struct fd_solana_account_stored_meta fd_solana_account_stored_meta_t;
#define FD_SOLANA_ACCOUNT_STORED_META_FOOTPRINT sizeof(fd_solana_account_stored_meta_t)
#define FD_SOLANA_ACCOUNT_STORED_META_ALIGN (8UL)

struct __attribute__((packed)) fd_solana_account_meta {
  unsigned long lamports;
  unsigned long rent_epoch;
  char          owner[32];
  char          executable;
  char          padding[7];
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
  unsigned long            dlen;
  unsigned char            hash[32];
  unsigned long            slot;
  fd_solana_account_meta_t info;
};
typedef struct fd_account_meta fd_account_meta_t;
#define FD_ACCOUNT_META_FOOTPRINT sizeof(fd_account_meta_t)
#define FD_ACCOUNT_META_ALIGN (8UL)

struct fd_vote_accounts_pair {
  fd_pubkey_t         key;
  unsigned long       stake;
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
  fd_pubkey_t   voter_pubkey;
  unsigned long stake;
  unsigned long activation_epoch;
  unsigned long deactivation_epoch;
  double        warmup_cooldown_rate;
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
  unsigned long         unused;
  unsigned long         epoch;
  fd_stake_history_t    stake_history;
};
typedef struct fd_stakes_delegation fd_stakes_delegation_t;
#define FD_STAKES_DELEGATION_FOOTPRINT sizeof(fd_stakes_delegation_t)
#define FD_STAKES_DELEGATION_ALIGN (8UL)

struct fd_bank_incremental_snapshot_persistence {
  unsigned long full_slot;
  fd_hash_t     full_hash;
  unsigned long full_capitalization;
  fd_hash_t     incremental_hash;
  unsigned long incremental_capitalization;
};
typedef struct fd_bank_incremental_snapshot_persistence fd_bank_incremental_snapshot_persistence_t;
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FOOTPRINT sizeof(fd_bank_incremental_snapshot_persistence_t)
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN (8UL)

struct fd_node_vote_accounts {
  ulong         vote_accounts_len;
  fd_pubkey_t*  vote_accounts;
  unsigned long total_stake;
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
  unsigned long                        total_stake;
  ulong                                node_id_to_vote_accounts_len;
  fd_pubkey_node_vote_accounts_pair_t* node_id_to_vote_accounts;
  ulong                                epoch_authorized_voters_len;
  fd_pubkey_pubkey_pair_t*             epoch_authorized_voters;
};
typedef struct fd_epoch_stakes fd_epoch_stakes_t;
#define FD_EPOCH_STAKES_FOOTPRINT sizeof(fd_epoch_stakes_t)
#define FD_EPOCH_STAKES_ALIGN (8UL)

struct fd_epoch_epoch_stakes_pair {
  unsigned long     key;
  fd_epoch_stakes_t value;
};
typedef struct fd_epoch_epoch_stakes_pair fd_epoch_epoch_stakes_pair_t;
#define FD_EPOCH_EPOCH_STAKES_PAIR_FOOTPRINT sizeof(fd_epoch_epoch_stakes_pair_t)
#define FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN (8UL)

struct fd_pubkey_u64_pair {
  fd_pubkey_t   _0;
  unsigned long _1;
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
  unsigned long                 parent_slot;
  fd_hard_forks_t               hard_forks;
  unsigned long                 transaction_count;
  unsigned long                 tick_height;
  unsigned long                 signature_count;
  unsigned long                 capitalization;
  unsigned long                 max_tick_height;
  unsigned long*                hashes_per_tick;
  unsigned long                 ticks_per_slot;
  uint128                       ns_per_slot;
  unsigned long                 genesis_creation_time;
  double                        slots_per_year;
  unsigned long                 accounts_data_len;
  unsigned long                 slot;
  unsigned long                 epoch;
  unsigned long                 block_height;
  fd_pubkey_t                   collector_id;
  unsigned long                 collector_fees;
  fd_fee_calculator_t           fee_calculator;
  fd_fee_rate_governor_t        fee_rate_governor;
  unsigned long                 collected_rent;
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
  unsigned long id;
  unsigned long accounts_current_len;
};
typedef struct fd_serializable_account_storage_entry fd_serializable_account_storage_entry_t;
#define FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_FOOTPRINT sizeof(fd_serializable_account_storage_entry_t)
#define FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_ALIGN (8UL)

struct fd_bank_hash_stats {
  unsigned long num_updated_accounts;
  unsigned long num_removed_accounts;
  unsigned long num_lamports_stored;
  unsigned long total_data_len;
  unsigned long num_executable_accounts;
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
  unsigned long                            slot;
  ulong                                    accounts_len;
  fd_serializable_account_storage_entry_t* accounts;
};
typedef struct fd_slot_account_pair fd_slot_account_pair_t;
#define FD_SLOT_ACCOUNT_PAIR_FOOTPRINT sizeof(fd_slot_account_pair_t)
#define FD_SLOT_ACCOUNT_PAIR_ALIGN (8UL)

struct fd_slot_map_pair {
  unsigned long slot;
  fd_hash_t     hash;
};
typedef struct fd_slot_map_pair fd_slot_map_pair_t;
#define FD_SLOT_MAP_PAIR_FOOTPRINT sizeof(fd_slot_map_pair_t)
#define FD_SLOT_MAP_PAIR_ALIGN (8UL)

struct fd_solana_accounts_db_fields {
  ulong                   storages_len;
  fd_slot_account_pair_t* storages;
  unsigned long           version;
  unsigned long           slot;
  fd_bank_hash_info_t     bank_hash_info;
  ulong                   historical_roots_len;
  unsigned long*          historical_roots;
  ulong                   historical_roots_with_hash_len;
  fd_slot_map_pair_t*     historical_roots_with_hash;
};
typedef struct fd_solana_accounts_db_fields fd_solana_accounts_db_fields_t;
#define FD_SOLANA_ACCOUNTS_DB_FIELDS_FOOTPRINT sizeof(fd_solana_accounts_db_fields_t)
#define FD_SOLANA_ACCOUNTS_DB_FIELDS_ALIGN (8UL)

struct fd_rust_duration {
  unsigned long seconds;
  uint          nanoseconds;
};
typedef struct fd_rust_duration fd_rust_duration_t;
#define FD_RUST_DURATION_FOOTPRINT sizeof(fd_rust_duration_t)
#define FD_RUST_DURATION_ALIGN (8UL)

struct fd_poh_config {
  fd_rust_duration_t target_tick_duration;
  unsigned long*     target_tick_count;
  unsigned long*     hashes_per_tick;
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
  unsigned long             creation_time;
  ulong                     accounts_len;
  fd_pubkey_account_pair_t* accounts;
  ulong                     native_instruction_processors_len;
  fd_string_pubkey_pair_t*  native_instruction_processors;
  ulong                     rewards_pools_len;
  fd_pubkey_account_pair_t* rewards_pools;
  unsigned long             ticks_per_slot;
  unsigned long             unused;
  fd_poh_config_t           poh_config;
  unsigned long             __backwards_compat_with_v0_23;
  fd_fee_rate_governor_t    fee_rate_governor;
  fd_rent_t                 rent;
  fd_inflation_t            inflation;
  fd_epoch_schedule_t       epoch_schedule;
  uint                      cluster_type;
};
typedef struct fd_genesis_solana fd_genesis_solana_t;
#define FD_GENESIS_SOLANA_FOOTPRINT sizeof(fd_genesis_solana_t)
#define FD_GENESIS_SOLANA_ALIGN (8UL)

struct fd_secp256k1_signature_offsets {
  ushort        signature_offset;
  unsigned char signature_instruction_index;
  ushort        eth_address_offset;
  unsigned char eth_address_instruction_index;
  ushort        message_data_offset;
  ushort        message_data_size;
  unsigned char message_instruction_index;
};
typedef struct fd_secp256k1_signature_offsets fd_secp256k1_signature_offsets_t;
#define FD_SECP256K1_SIGNATURE_OFFSETS_FOOTPRINT sizeof(fd_secp256k1_signature_offsets_t)
#define FD_SECP256K1_SIGNATURE_OFFSETS_ALIGN (8UL)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L114 */
struct fd_sol_sysvar_clock {
  unsigned long slot;
  long          epoch_start_timestamp;
  unsigned long epoch;
  unsigned long leader_schedule_epoch;
  long          unix_timestamp;
};
typedef struct fd_sol_sysvar_clock fd_sol_sysvar_clock_t;
#define FD_SOL_SYSVAR_CLOCK_FOOTPRINT sizeof(fd_sol_sysvar_clock_t)
#define FD_SOL_SYSVAR_CLOCK_ALIGN (8UL)

struct fd_vote_lockout {
  unsigned long slot;
  uint          confirmation_count;
};
typedef struct fd_vote_lockout fd_vote_lockout_t;
#define FD_VOTE_LOCKOUT_FOOTPRINT sizeof(fd_vote_lockout_t)
#define FD_VOTE_LOCKOUT_ALIGN (8UL)

struct fd_compact_vote_lockout {
  unsigned long slot;
  unsigned char confirmation_count;
};
typedef struct fd_compact_vote_lockout fd_compact_vote_lockout_t;
#define FD_COMPACT_VOTE_LOCKOUT_FOOTPRINT sizeof(fd_compact_vote_lockout_t)
#define FD_COMPACT_VOTE_LOCKOUT_ALIGN (8UL)

struct fd_vote_authorized_voter {
  unsigned long epoch;
  fd_pubkey_t   pubkey;
};
typedef struct fd_vote_authorized_voter fd_vote_authorized_voter_t;
#define FD_VOTE_AUTHORIZED_VOTER_FOOTPRINT sizeof(fd_vote_authorized_voter_t)
#define FD_VOTE_AUTHORIZED_VOTER_ALIGN (8UL)

struct fd_vote_prior_voter {
  fd_pubkey_t   pubkey;
  unsigned long epoch_start;
  unsigned long epoch_end;
};
typedef struct fd_vote_prior_voter fd_vote_prior_voter_t;
#define FD_VOTE_PRIOR_VOTER_FOOTPRINT sizeof(fd_vote_prior_voter_t)
#define FD_VOTE_PRIOR_VOTER_ALIGN (8UL)

struct fd_vote_epoch_credits {
  unsigned long epoch;
  unsigned long credits;
  unsigned long prev_credits;
};
typedef struct fd_vote_epoch_credits fd_vote_epoch_credits_t;
#define FD_VOTE_EPOCH_CREDITS_FOOTPRINT sizeof(fd_vote_epoch_credits_t)
#define FD_VOTE_EPOCH_CREDITS_ALIGN (8UL)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/authorized_voters.rs#L9 */
struct fd_vote_historical_authorized_voter {
  unsigned long epoch;
  fd_pubkey_t   pubkey;
};
typedef struct fd_vote_historical_authorized_voter fd_vote_historical_authorized_voter_t;
#define FD_VOTE_HISTORICAL_AUTHORIZED_VOTER_FOOTPRINT sizeof(fd_vote_historical_authorized_voter_t)
#define FD_VOTE_HISTORICAL_AUTHORIZED_VOTER_ALIGN (8UL)

struct fd_vote_block_timestamp {
  unsigned long slot;
  unsigned long timestamp;
};
typedef struct fd_vote_block_timestamp fd_vote_block_timestamp_t;
#define FD_VOTE_BLOCK_TIMESTAMP_FOOTPRINT sizeof(fd_vote_block_timestamp_t)
#define FD_VOTE_BLOCK_TIMESTAMP_ALIGN (8UL)

#define VECT_NAME fd_vec_fd_vote_lockout_t
#define VECT_ELEMENT fd_vote_lockout_t
#include "../../funk/fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

#define VECT_NAME fd_vec_fd_vote_epoch_credits_t
#define VECT_ELEMENT fd_vote_epoch_credits_t
#include "../../funk/fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L310 */
struct fd_vote_state {
  fd_pubkey_t                            voting_node;
  fd_pubkey_t                            authorized_withdrawer;
  unsigned char                          commission;
  fd_vec_fd_vote_lockout_t_t             votes;
  unsigned long*                         saved_root_slot;
  ulong                                  authorized_voters_len;
  fd_vote_historical_authorized_voter_t* authorized_voters;
  ulong                                  prior_voters_len;
  fd_vote_prior_voter_t*                 prior_voters;
  fd_vec_fd_vote_epoch_credits_t_t       epoch_credits;
  fd_vote_block_timestamp_t              latest_timestamp;
};
typedef struct fd_vote_state fd_vote_state_t;
#define FD_VOTE_STATE_FOOTPRINT sizeof(fd_vote_state_t)
#define FD_VOTE_STATE_ALIGN (8UL)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L185 */
struct fd_vote_state_update {
  ulong              lockouts_len;
  fd_vote_lockout_t* lockouts;
  unsigned long*     proposed_root;
  fd_hash_t          hash;
  unsigned long*     timestamp;
};
typedef struct fd_vote_state_update fd_vote_state_update_t;
#define FD_VOTE_STATE_UPDATE_FOOTPRINT sizeof(fd_vote_state_update_t)
#define FD_VOTE_STATE_UPDATE_ALIGN (8UL)

struct fd_compact_vote_state_update {
  unsigned long              proposed_root;
  ushort                     lockouts_len;
  fd_compact_vote_lockout_t* lockouts;
  fd_hash_t                  hash;
  unsigned long*             timestamp;
};
typedef struct fd_compact_vote_state_update fd_compact_vote_state_update_t;
#define FD_COMPACT_VOTE_STATE_UPDATE_FOOTPRINT sizeof(fd_compact_vote_state_update_t)
#define FD_COMPACT_VOTE_STATE_UPDATE_ALIGN (8UL)

struct fd_slot_history_inner {
  ulong          blocks_len;
  unsigned long* blocks;
};
typedef struct fd_slot_history_inner fd_slot_history_inner_t;
#define FD_SLOT_HISTORY_INNER_FOOTPRINT sizeof(fd_slot_history_inner_t)
#define FD_SLOT_HISTORY_INNER_ALIGN (8UL)

/* https://github.com/tov/bv-rs/blob/107be3e9c45324e55844befa4c4239d4d3d092c6/src/bit_vec/inner.rs#L8 */
struct fd_slot_history_bitvec {
  fd_slot_history_inner_t* bits;
  unsigned long            len;
};
typedef struct fd_slot_history_bitvec fd_slot_history_bitvec_t;
#define FD_SLOT_HISTORY_BITVEC_FOOTPRINT sizeof(fd_slot_history_bitvec_t)
#define FD_SLOT_HISTORY_BITVEC_ALIGN (8UL)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L11 */
struct fd_slot_history {
  fd_slot_history_bitvec_t bits;
  unsigned long            next_slot;
};
typedef struct fd_slot_history fd_slot_history_t;
#define FD_SLOT_HISTORY_FOOTPRINT sizeof(fd_slot_history_t)
#define FD_SLOT_HISTORY_ALIGN (8UL)

struct fd_slot_hash {
  unsigned long slot;
  fd_hash_t     hash;
};
typedef struct fd_slot_hash fd_slot_hash_t;
#define FD_SLOT_HASH_FOOTPRINT sizeof(fd_slot_hash_t)
#define FD_SLOT_HASH_ALIGN (8UL)

struct fd_slot_hashes {
  ulong           hashes_len;
  fd_slot_hash_t* hashes;
};
typedef struct fd_slot_hashes fd_slot_hashes_t;
#define FD_SLOT_HASHES_FOOTPRINT sizeof(fd_slot_hashes_t)
#define FD_SLOT_HASHES_ALIGN (8UL)

struct fd_block_block_hash_entry {
  fd_hash_t           blockhash;
  fd_fee_calculator_t fee_calculator;
};
typedef struct fd_block_block_hash_entry fd_block_block_hash_entry_t;
#define FD_BLOCK_BLOCK_HASH_ENTRY_FOOTPRINT sizeof(fd_block_block_hash_entry_t)
#define FD_BLOCK_BLOCK_HASH_ENTRY_ALIGN (8UL)

struct fd_recent_block_hashes {
  ulong                        hashes_len;
  fd_block_block_hash_entry_t* hashes;
};
typedef struct fd_recent_block_hashes fd_recent_block_hashes_t;
#define FD_RECENT_BLOCK_HASHES_FOOTPRINT sizeof(fd_recent_block_hashes_t)
#define FD_RECENT_BLOCK_HASHES_ALIGN (8UL)

struct fd_slot_meta {
  unsigned long  slot;
  unsigned long  consumed;
  unsigned long  received;
  unsigned long  first_shred_timestamp;
  unsigned long  last_index;
  unsigned long  parent_slot;
  ulong          next_slot_len;
  unsigned long* next_slot;
  unsigned char  is_connected;
  ulong          entry_end_indexes_len;
  uint*          entry_end_indexes;
};
typedef struct fd_slot_meta fd_slot_meta_t;
#define FD_SLOT_META_FOOTPRINT sizeof(fd_slot_meta_t)
#define FD_SLOT_META_ALIGN (8UL)


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

void fd_secp256k1_signature_offsets_decode(fd_secp256k1_signature_offsets_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_secp256k1_signature_offsets_encode(fd_secp256k1_signature_offsets_t* self, void const** data);
void fd_secp256k1_signature_offsets_destroy(fd_secp256k1_signature_offsets_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_secp256k1_signature_offsets_size(fd_secp256k1_signature_offsets_t* self);

void fd_sol_sysvar_clock_decode(fd_sol_sysvar_clock_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_sol_sysvar_clock_encode(fd_sol_sysvar_clock_t* self, void const** data);
void fd_sol_sysvar_clock_destroy(fd_sol_sysvar_clock_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_sol_sysvar_clock_size(fd_sol_sysvar_clock_t* self);

void fd_vote_lockout_decode(fd_vote_lockout_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_lockout_encode(fd_vote_lockout_t* self, void const** data);
void fd_vote_lockout_destroy(fd_vote_lockout_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_lockout_size(fd_vote_lockout_t* self);

void fd_compact_vote_lockout_decode(fd_compact_vote_lockout_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_compact_vote_lockout_encode(fd_compact_vote_lockout_t* self, void const** data);
void fd_compact_vote_lockout_destroy(fd_compact_vote_lockout_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_compact_vote_lockout_size(fd_compact_vote_lockout_t* self);

void fd_vote_authorized_voter_decode(fd_vote_authorized_voter_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_authorized_voter_encode(fd_vote_authorized_voter_t* self, void const** data);
void fd_vote_authorized_voter_destroy(fd_vote_authorized_voter_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_authorized_voter_size(fd_vote_authorized_voter_t* self);

void fd_vote_prior_voter_decode(fd_vote_prior_voter_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_prior_voter_encode(fd_vote_prior_voter_t* self, void const** data);
void fd_vote_prior_voter_destroy(fd_vote_prior_voter_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_prior_voter_size(fd_vote_prior_voter_t* self);

void fd_vote_epoch_credits_decode(fd_vote_epoch_credits_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_epoch_credits_encode(fd_vote_epoch_credits_t* self, void const** data);
void fd_vote_epoch_credits_destroy(fd_vote_epoch_credits_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_epoch_credits_size(fd_vote_epoch_credits_t* self);

void fd_vote_historical_authorized_voter_decode(fd_vote_historical_authorized_voter_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_historical_authorized_voter_encode(fd_vote_historical_authorized_voter_t* self, void const** data);
void fd_vote_historical_authorized_voter_destroy(fd_vote_historical_authorized_voter_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_historical_authorized_voter_size(fd_vote_historical_authorized_voter_t* self);

void fd_vote_block_timestamp_decode(fd_vote_block_timestamp_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_block_timestamp_encode(fd_vote_block_timestamp_t* self, void const** data);
void fd_vote_block_timestamp_destroy(fd_vote_block_timestamp_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_block_timestamp_size(fd_vote_block_timestamp_t* self);

void fd_vote_state_decode(fd_vote_state_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_state_encode(fd_vote_state_t* self, void const** data);
void fd_vote_state_destroy(fd_vote_state_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_state_size(fd_vote_state_t* self);

void fd_vote_state_update_decode(fd_vote_state_update_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_vote_state_update_encode(fd_vote_state_update_t* self, void const** data);
void fd_vote_state_update_destroy(fd_vote_state_update_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_vote_state_update_size(fd_vote_state_update_t* self);

void fd_compact_vote_state_update_decode(fd_compact_vote_state_update_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_compact_vote_state_update_encode(fd_compact_vote_state_update_t* self, void const** data);
void fd_compact_vote_state_update_destroy(fd_compact_vote_state_update_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_compact_vote_state_update_size(fd_compact_vote_state_update_t* self);

void fd_slot_history_inner_decode(fd_slot_history_inner_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_history_inner_encode(fd_slot_history_inner_t* self, void const** data);
void fd_slot_history_inner_destroy(fd_slot_history_inner_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_history_inner_size(fd_slot_history_inner_t* self);

void fd_slot_history_bitvec_decode(fd_slot_history_bitvec_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_history_bitvec_encode(fd_slot_history_bitvec_t* self, void const** data);
void fd_slot_history_bitvec_destroy(fd_slot_history_bitvec_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_history_bitvec_size(fd_slot_history_bitvec_t* self);

void fd_slot_history_decode(fd_slot_history_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_history_encode(fd_slot_history_t* self, void const** data);
void fd_slot_history_destroy(fd_slot_history_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_history_size(fd_slot_history_t* self);

void fd_slot_hash_decode(fd_slot_hash_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_hash_encode(fd_slot_hash_t* self, void const** data);
void fd_slot_hash_destroy(fd_slot_hash_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_hash_size(fd_slot_hash_t* self);

void fd_slot_hashes_decode(fd_slot_hashes_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_hashes_encode(fd_slot_hashes_t* self, void const** data);
void fd_slot_hashes_destroy(fd_slot_hashes_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_hashes_size(fd_slot_hashes_t* self);

void fd_block_block_hash_entry_decode(fd_block_block_hash_entry_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_block_block_hash_entry_encode(fd_block_block_hash_entry_t* self, void const** data);
void fd_block_block_hash_entry_destroy(fd_block_block_hash_entry_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_block_block_hash_entry_size(fd_block_block_hash_entry_t* self);

void fd_recent_block_hashes_decode(fd_recent_block_hashes_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_recent_block_hashes_encode(fd_recent_block_hashes_t* self, void const** data);
void fd_recent_block_hashes_destroy(fd_recent_block_hashes_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_recent_block_hashes_size(fd_recent_block_hashes_t* self);

void fd_slot_meta_decode(fd_slot_meta_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void fd_slot_meta_encode(fd_slot_meta_t* self, void const** data);
void fd_slot_meta_destroy(fd_slot_meta_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_slot_meta_size(fd_slot_meta_t* self);

FD_PROTOTYPES_END

#endif // HEADER_FD_BANKS_SOLANA
