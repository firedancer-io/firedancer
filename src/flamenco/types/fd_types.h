// This is an auto-generated file. To add entries, edit fd_types.json
#ifndef HEADER_FD_RUNTIME_TYPES
#define HEADER_FD_RUNTIME_TYPES

#include "fd_bincode.h"
#include "../../ballet/utf8/fd_utf8.h"
#include "fd_types_custom.h"
#define FD_ACCOUNT_META_MAGIC 9823

/* sdk/program/src/feature.rs#L22 */
/* Encoded Size: Dynamic */
struct fd_feature {
  ulong activated_at;
  uchar has_activated_at;
};
typedef struct fd_feature fd_feature_t;
#define FD_FEATURE_ALIGN alignof(fd_feature_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L9 */
/* Encoded Size: Fixed (8 bytes) */
struct fd_fee_calculator {
  ulong lamports_per_signature;
};
typedef struct fd_fee_calculator fd_fee_calculator_t;
#define FD_FEE_CALCULATOR_ALIGN alignof(fd_fee_calculator_t)

/* Encoded Size: Fixed (24 bytes) */
struct fd_hash_age {
  fd_fee_calculator_t fee_calculator;
  ulong hash_index;
  ulong timestamp;
};
typedef struct fd_hash_age fd_hash_age_t;
#define FD_HASH_AGE_ALIGN alignof(fd_hash_age_t)

/* Encoded Size: Fixed (56 bytes) */
struct fd_hash_hash_age_pair {
  fd_hash_t key;
  fd_hash_age_t val;
};
typedef struct fd_hash_hash_age_pair fd_hash_hash_age_pair_t;
#define FD_HASH_HASH_AGE_PAIR_ALIGN alignof(fd_hash_hash_age_pair_t)

/* Encoded Size: Dynamic */
struct fd_block_hash_vec {
  ulong last_hash_index;
  fd_hash_t * last_hash;
  ulong ages_len;
  fd_hash_hash_age_pair_t * ages;
  ulong max_age;
};
typedef struct fd_block_hash_vec fd_block_hash_vec_t;
#define FD_BLOCK_HASH_VEC_ALIGN alignof(fd_block_hash_vec_t)

struct fd_block_hash_vec_global {
  ulong last_hash_index;
  ulong last_hash_offset;
  ulong ages_len;
  ulong ages_offset;
  ulong max_age;
};
typedef struct fd_block_hash_vec_global fd_block_hash_vec_global_t;
#define FD_BLOCK_HASH_VEC_GLOBAL_ALIGN alignof(fd_block_hash_vec_global_t)

FD_FN_UNUSED static fd_hash_t * fd_block_hash_vec_last_hash_join( fd_block_hash_vec_global_t const * struct_mem ) {
  return struct_mem->last_hash_offset ? (fd_hash_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->last_hash_offset ) : NULL;
}
FD_FN_UNUSED static fd_hash_hash_age_pair_t * fd_block_hash_vec_ages_join( fd_block_hash_vec_global_t const * struct_mem ) { // vector
  return struct_mem->ages_offset ? (fd_hash_hash_age_pair_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->ages_offset ) : NULL;
}
FD_FN_UNUSED static void fd_block_hash_vec_ages_update( fd_block_hash_vec_global_t * struct_mem, fd_hash_hash_age_pair_t * vec ) {
  struct_mem->ages_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* Encoded Size: Fixed (33 bytes) */
struct fd_fee_rate_governor {
  ulong target_lamports_per_signature;
  ulong target_signatures_per_slot;
  ulong min_lamports_per_signature;
  ulong max_lamports_per_signature;
  uchar burn_percent;
};
typedef struct fd_fee_rate_governor fd_fee_rate_governor_t;
#define FD_FEE_RATE_GOVERNOR_ALIGN alignof(fd_fee_rate_governor_t)

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

/* Encoded Size: Fixed (66 bytes) */
struct fd_rent_collector {
  ulong epoch;
  fd_epoch_schedule_t epoch_schedule;
  double slots_per_year;
  fd_rent_t rent;
};
typedef struct fd_rent_collector fd_rent_collector_t;
#define FD_RENT_COLLECTOR_ALIGN alignof(fd_rent_collector_t)

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

/* https://github.com/anza-xyz/agave/blob/6ac4fe32e28d8ceb4085072b61fa0c6cb09baac1/sdk/src/account.rs#L37 */
/* Encoded Size: Dynamic */
struct fd_solana_account {
  ulong lamports;
  ulong data_len;
  uchar* data;
  fd_pubkey_t owner;
  uchar executable;
  ulong rent_epoch;
};
typedef struct fd_solana_account fd_solana_account_t;
#define FD_SOLANA_ACCOUNT_ALIGN alignof(fd_solana_account_t)

struct fd_solana_account_global {
  ulong lamports;
  ulong data_len;
  ulong data_offset;
  fd_pubkey_t owner;
  uchar executable;
  ulong rent_epoch;
};
typedef struct fd_solana_account_global fd_solana_account_global_t;
#define FD_SOLANA_ACCOUNT_GLOBAL_ALIGN alignof(fd_solana_account_global_t)

FD_FN_UNUSED static uchar * fd_solana_account_data_join( fd_solana_account_global_t const * struct_mem ) { // vector
  return struct_mem->data_offset ? (uchar *)fd_type_pun( (uchar *)struct_mem + struct_mem->data_offset ) : NULL;
}
FD_FN_UNUSED static void fd_solana_account_data_update( fd_solana_account_global_t * struct_mem, uchar * vec ) {
  struct_mem->data_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* Encoded Size: Fixed (48 bytes) */
struct __attribute__((packed)) fd_solana_account_stored_meta {
  ulong write_version_obsolete;
  ulong data_len;
  uchar pubkey[32];
};
typedef struct fd_solana_account_stored_meta fd_solana_account_stored_meta_t;
#define FD_SOLANA_ACCOUNT_STORED_META_ALIGN (8UL)

/* Encoded Size: Fixed (52 bytes) */
struct __attribute__((packed)) fd_solana_account_meta {
  ulong lamports;
  ulong rent_epoch;
  uchar owner[32];
  uchar executable;
  uchar padding[3];
};
typedef struct fd_solana_account_meta fd_solana_account_meta_t;
#define FD_SOLANA_ACCOUNT_META_ALIGN (8UL)

/* Encoded Size: Fixed (136 bytes) */
struct __attribute__((packed)) fd_solana_account_hdr {
  fd_solana_account_stored_meta_t meta;
  fd_solana_account_meta_t info;
  uchar padding[4];
  fd_hash_t hash;
};
typedef struct fd_solana_account_hdr fd_solana_account_hdr_t;
#define FD_SOLANA_ACCOUNT_HDR_ALIGN (8UL)

/* Encoded Size: Fixed (104 bytes) */
struct __attribute__((packed)) fd_account_meta {
  ushort magic;
  ushort hlen;
  ulong dlen;
  uchar hash[32];
  ulong slot;
  fd_solana_account_meta_t info;
};
typedef struct fd_account_meta fd_account_meta_t;
#define FD_ACCOUNT_META_ALIGN (8UL)

/* https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/vote/src/vote_account.rs#L323 */
/* Encoded Size: Dynamic */
struct fd_vote_accounts_pair {
  fd_pubkey_t key;
  ulong stake;
  fd_solana_account_t value;
};
typedef struct fd_vote_accounts_pair fd_vote_accounts_pair_t;
#define FD_VOTE_ACCOUNTS_PAIR_ALIGN alignof(fd_vote_accounts_pair_t)

struct fd_vote_accounts_pair_global {
  fd_pubkey_t key;
  ulong stake;
  fd_solana_account_global_t value;
};
typedef struct fd_vote_accounts_pair_global fd_vote_accounts_pair_global_t;
#define FD_VOTE_ACCOUNTS_PAIR_GLOBAL_ALIGN alignof(fd_vote_accounts_pair_global_t)

typedef struct fd_vote_accounts_pair_t_mapnode fd_vote_accounts_pair_t_mapnode_t;
#define REDBLK_T fd_vote_accounts_pair_t_mapnode_t
#define REDBLK_NAME fd_vote_accounts_pair_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_vote_accounts_pair_t_mapnode {
    fd_vote_accounts_pair_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_vote_accounts_pair_t_mapnode_t *
fd_vote_accounts_pair_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_vote_accounts_pair_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_vote_accounts_pair_t_map_footprint( len );
  return fd_vote_accounts_pair_t_map_join( fd_vote_accounts_pair_t_map_new( map_mem, len ) );
}
typedef struct fd_vote_accounts_pair_global_t_mapnode fd_vote_accounts_pair_global_t_mapnode_t;
#define REDBLK_T fd_vote_accounts_pair_global_t_mapnode_t
#define REDBLK_NAME fd_vote_accounts_pair_global_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_vote_accounts_pair_global_t_mapnode {
    fd_vote_accounts_pair_global_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_vote_accounts_pair_global_t_mapnode_t *
fd_vote_accounts_pair_global_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_vote_accounts_pair_global_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_vote_accounts_pair_global_t_map_footprint( len );
  return fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( map_mem, len ) );
}
/* https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/vote/src/vote_account.rs#L46 */
/* Encoded Size: Dynamic */
struct fd_vote_accounts {
  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root;
};
typedef struct fd_vote_accounts fd_vote_accounts_t;
#define FD_VOTE_ACCOUNTS_ALIGN alignof(fd_vote_accounts_t)

struct fd_vote_accounts_global {
  ulong vote_accounts_pool_offset;
  ulong vote_accounts_root_offset;
};
typedef struct fd_vote_accounts_global fd_vote_accounts_global_t;
#define FD_VOTE_ACCOUNTS_GLOBAL_ALIGN alignof(fd_vote_accounts_global_t)

static FD_FN_UNUSED fd_vote_accounts_pair_global_t_mapnode_t * fd_vote_accounts_vote_accounts_pool_join( fd_vote_accounts_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->vote_accounts_pool_offset ? (fd_vote_accounts_pair_global_t_mapnode_t *)fd_vote_accounts_pair_global_t_map_join( fd_type_pun( (uchar *)type + type->vote_accounts_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_vote_accounts_pair_global_t_mapnode_t * fd_vote_accounts_vote_accounts_root_join( fd_vote_accounts_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->vote_accounts_root_offset ? (fd_vote_accounts_pair_global_t_mapnode_t *)fd_type_pun( (uchar *)type + type->vote_accounts_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_vote_accounts_vote_accounts_pool_update( fd_vote_accounts_global_t * type, fd_vote_accounts_pair_global_t_mapnode_t * pool ) {
  type->vote_accounts_pool_offset = !!pool ? (ulong)fd_vote_accounts_pair_global_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_vote_accounts_vote_accounts_root_update( fd_vote_accounts_global_t * type, fd_vote_accounts_pair_global_t_mapnode_t * root ) {
  type->vote_accounts_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
/* Encoded Size: Fixed (33 bytes) */
struct fd_account_keys_pair {
  fd_pubkey_t key;
  uchar exists;
};
typedef struct fd_account_keys_pair fd_account_keys_pair_t;
#define FD_ACCOUNT_KEYS_PAIR_ALIGN alignof(fd_account_keys_pair_t)

typedef struct fd_account_keys_pair_t_mapnode fd_account_keys_pair_t_mapnode_t;
#define REDBLK_T fd_account_keys_pair_t_mapnode_t
#define REDBLK_NAME fd_account_keys_pair_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_account_keys_pair_t_mapnode {
    fd_account_keys_pair_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_account_keys_pair_t_mapnode_t *
fd_account_keys_pair_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_account_keys_pair_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_account_keys_pair_t_map_footprint( len );
  return fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( map_mem, len ) );
}
/* Encoded Size: Dynamic */
struct fd_account_keys {
  fd_account_keys_pair_t_mapnode_t * account_keys_pool;
  fd_account_keys_pair_t_mapnode_t * account_keys_root;
};
typedef struct fd_account_keys fd_account_keys_t;
#define FD_ACCOUNT_KEYS_ALIGN alignof(fd_account_keys_t)

struct fd_account_keys_global {
  ulong account_keys_pool_offset;
  ulong account_keys_root_offset;
};
typedef struct fd_account_keys_global fd_account_keys_global_t;
#define FD_ACCOUNT_KEYS_GLOBAL_ALIGN alignof(fd_account_keys_global_t)

static FD_FN_UNUSED fd_account_keys_pair_t_mapnode_t * fd_account_keys_account_keys_pool_join( fd_account_keys_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->account_keys_pool_offset ? (fd_account_keys_pair_t_mapnode_t *)fd_account_keys_pair_t_map_join( fd_type_pun( (uchar *)type + type->account_keys_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_account_keys_pair_t_mapnode_t * fd_account_keys_account_keys_root_join( fd_account_keys_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->account_keys_root_offset ? (fd_account_keys_pair_t_mapnode_t *)fd_type_pun( (uchar *)type + type->account_keys_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_account_keys_account_keys_pool_update( fd_account_keys_global_t * type, fd_account_keys_pair_t_mapnode_t * pool ) {
  type->account_keys_pool_offset = !!pool ? (ulong)fd_account_keys_pair_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_account_keys_account_keys_root_update( fd_account_keys_global_t * type, fd_account_keys_pair_t_mapnode_t * root ) {
  type->account_keys_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/state.rs#L303 */
/* Encoded Size: Fixed (64 bytes) */
struct fd_delegation {
  fd_pubkey_t voter_pubkey;
  ulong stake;
  ulong activation_epoch;
  ulong deactivation_epoch;
  double warmup_cooldown_rate;
};
typedef struct fd_delegation fd_delegation_t;
#define FD_DELEGATION_ALIGN alignof(fd_delegation_t)

/* Encoded Size: Fixed (96 bytes) */
struct fd_delegation_pair {
  fd_pubkey_t account;
  fd_delegation_t delegation;
};
typedef struct fd_delegation_pair fd_delegation_pair_t;
#define FD_DELEGATION_PAIR_ALIGN alignof(fd_delegation_pair_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/state.rs#L539 */
/* Encoded Size: Fixed (72 bytes) */
struct fd_stake {
  fd_delegation_t delegation;
  ulong credits_observed;
};
typedef struct fd_stake fd_stake_t;
#define FD_STAKE_ALIGN alignof(fd_stake_t)

/* Encoded Size: Fixed (104 bytes) */
struct fd_stake_pair {
  fd_pubkey_t account;
  fd_stake_t stake;
};
typedef struct fd_stake_pair fd_stake_pair_t;
#define FD_STAKE_PAIR_ALIGN alignof(fd_stake_pair_t)

typedef struct fd_delegation_pair_t_mapnode fd_delegation_pair_t_mapnode_t;
#define REDBLK_T fd_delegation_pair_t_mapnode_t
#define REDBLK_NAME fd_delegation_pair_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_delegation_pair_t_mapnode {
    fd_delegation_pair_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_delegation_pair_t_mapnode_t *
fd_delegation_pair_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_delegation_pair_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_delegation_pair_t_map_footprint( len );
  return fd_delegation_pair_t_map_join( fd_delegation_pair_t_map_new( map_mem, len ) );
}
/* https://github.com/anza-xyz/agave/blob/3e1c3a2f85b5b1d34031f2710d609347cfb77dfd/runtime/src/stakes.rs#L159 */
/* Encoded Size: Dynamic */
struct __attribute__((aligned(128UL))) fd_stakes {
  fd_vote_accounts_t vote_accounts;
  fd_delegation_pair_t_mapnode_t * stake_delegations_pool;
  fd_delegation_pair_t_mapnode_t * stake_delegations_root;
  ulong unused;
  ulong epoch;
  fd_stake_history_t stake_history;
};
typedef struct fd_stakes fd_stakes_t;
#define FD_STAKES_ALIGN (128UL)

struct __attribute__((aligned(128UL))) fd_stakes_global {
  fd_vote_accounts_global_t vote_accounts;
  ulong stake_delegations_pool_offset;
  ulong stake_delegations_root_offset;
  ulong unused;
  ulong epoch;
  fd_stake_history_t stake_history;
};
typedef struct fd_stakes_global fd_stakes_global_t;
#define FD_STAKES_GLOBAL_ALIGN (128UL)

static FD_FN_UNUSED fd_delegation_pair_t_mapnode_t * fd_stakes_stake_delegations_pool_join( fd_stakes_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->stake_delegations_pool_offset ? (fd_delegation_pair_t_mapnode_t *)fd_delegation_pair_t_map_join( fd_type_pun( (uchar *)type + type->stake_delegations_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_delegation_pair_t_mapnode_t * fd_stakes_stake_delegations_root_join( fd_stakes_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->stake_delegations_root_offset ? (fd_delegation_pair_t_mapnode_t *)fd_type_pun( (uchar *)type + type->stake_delegations_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_stakes_stake_delegations_pool_update( fd_stakes_global_t * type, fd_delegation_pair_t_mapnode_t * pool ) {
  type->stake_delegations_pool_offset = !!pool ? (ulong)fd_delegation_pair_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_stakes_stake_delegations_root_update( fd_stakes_global_t * type, fd_delegation_pair_t_mapnode_t * root ) {
  type->stake_delegations_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
typedef struct fd_stake_pair_t_mapnode fd_stake_pair_t_mapnode_t;
#define REDBLK_T fd_stake_pair_t_mapnode_t
#define REDBLK_NAME fd_stake_pair_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_stake_pair_t_mapnode {
    fd_stake_pair_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_stake_pair_t_mapnode_t *
fd_stake_pair_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_stake_pair_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_stake_pair_t_map_footprint( len );
  return fd_stake_pair_t_map_join( fd_stake_pair_t_map_new( map_mem, len ) );
}
/* https://github.com/anza-xyz/agave/blob/436f7333a8465739df65c2534654102896e09eb5/runtime/src/stakes.rs#L160 */
/* Encoded Size: Dynamic */
struct fd_stakes_stake {
  fd_vote_accounts_t vote_accounts;
  fd_stake_pair_t_mapnode_t * stake_delegations_pool;
  fd_stake_pair_t_mapnode_t * stake_delegations_root;
  ulong unused;
  ulong epoch;
  fd_stake_history_t stake_history;
};
typedef struct fd_stakes_stake fd_stakes_stake_t;
#define FD_STAKES_STAKE_ALIGN alignof(fd_stakes_stake_t)

struct fd_stakes_stake_global {
  fd_vote_accounts_global_t vote_accounts;
  ulong stake_delegations_pool_offset;
  ulong stake_delegations_root_offset;
  ulong unused;
  ulong epoch;
  fd_stake_history_t stake_history;
};
typedef struct fd_stakes_stake_global fd_stakes_stake_global_t;
#define FD_STAKES_STAKE_GLOBAL_ALIGN alignof(fd_stakes_stake_global_t)

static FD_FN_UNUSED fd_stake_pair_t_mapnode_t * fd_stakes_stake_stake_delegations_pool_join( fd_stakes_stake_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->stake_delegations_pool_offset ? (fd_stake_pair_t_mapnode_t *)fd_stake_pair_t_map_join( fd_type_pun( (uchar *)type + type->stake_delegations_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_stake_pair_t_mapnode_t * fd_stakes_stake_stake_delegations_root_join( fd_stakes_stake_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->stake_delegations_root_offset ? (fd_stake_pair_t_mapnode_t *)fd_type_pun( (uchar *)type + type->stake_delegations_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_stakes_stake_stake_delegations_pool_update( fd_stakes_stake_global_t * type, fd_stake_pair_t_mapnode_t * pool ) {
  type->stake_delegations_pool_offset = !!pool ? (ulong)fd_stake_pair_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_stakes_stake_stake_delegations_root_update( fd_stakes_stake_global_t * type, fd_stake_pair_t_mapnode_t * root ) {
  type->stake_delegations_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
/* Encoded Size: Fixed (88 bytes) */
struct fd_bank_incremental_snapshot_persistence {
  ulong full_slot;
  fd_hash_t full_hash;
  ulong full_capitalization;
  fd_hash_t incremental_hash;
  ulong incremental_capitalization;
};
typedef struct fd_bank_incremental_snapshot_persistence fd_bank_incremental_snapshot_persistence_t;
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN alignof(fd_bank_incremental_snapshot_persistence_t)

/* https://github.com/anza-xyz/agave/blob/de6ce29e1a7ecbdc6dc39527fce80beea404d314/runtime/src/epoch_stakes.rs#L16 */
/* Encoded Size: Dynamic */
struct fd_node_vote_accounts {
  ulong vote_accounts_len;
  fd_pubkey_t * vote_accounts;
  ulong total_stake;
};
typedef struct fd_node_vote_accounts fd_node_vote_accounts_t;
#define FD_NODE_VOTE_ACCOUNTS_ALIGN alignof(fd_node_vote_accounts_t)

struct fd_node_vote_accounts_global {
  ulong vote_accounts_len;
  ulong vote_accounts_offset;
  ulong total_stake;
};
typedef struct fd_node_vote_accounts_global fd_node_vote_accounts_global_t;
#define FD_NODE_VOTE_ACCOUNTS_GLOBAL_ALIGN alignof(fd_node_vote_accounts_global_t)

FD_FN_UNUSED static fd_pubkey_t * fd_node_vote_accounts_vote_accounts_join( fd_node_vote_accounts_global_t const * struct_mem ) { // vector
  return struct_mem->vote_accounts_offset ? (fd_pubkey_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->vote_accounts_offset ) : NULL;
}
FD_FN_UNUSED static void fd_node_vote_accounts_vote_accounts_update( fd_node_vote_accounts_global_t * struct_mem, fd_pubkey_t * vec ) {
  struct_mem->vote_accounts_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* https://github.com/anza-xyz/agave/blob/de6ce29e1a7ecbdc6dc39527fce80beea404d314/runtime/src/epoch_stakes.rs#L10 */
/* Encoded Size: Dynamic */
struct fd_pubkey_node_vote_accounts_pair {
  fd_pubkey_t key;
  fd_node_vote_accounts_t value;
};
typedef struct fd_pubkey_node_vote_accounts_pair fd_pubkey_node_vote_accounts_pair_t;
#define FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_ALIGN alignof(fd_pubkey_node_vote_accounts_pair_t)

struct fd_pubkey_node_vote_accounts_pair_global {
  fd_pubkey_t key;
  fd_node_vote_accounts_global_t value;
};
typedef struct fd_pubkey_node_vote_accounts_pair_global fd_pubkey_node_vote_accounts_pair_global_t;
#define FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_GLOBAL_ALIGN alignof(fd_pubkey_node_vote_accounts_pair_global_t)

/* Encoded Size: Fixed (64 bytes) */
struct fd_pubkey_pubkey_pair {
  fd_pubkey_t key;
  fd_pubkey_t value;
};
typedef struct fd_pubkey_pubkey_pair fd_pubkey_pubkey_pair_t;
#define FD_PUBKEY_PUBKEY_PAIR_ALIGN alignof(fd_pubkey_pubkey_pair_t)

typedef struct fd_pubkey_node_vote_accounts_pair_t_mapnode fd_pubkey_node_vote_accounts_pair_t_mapnode_t;
#define REDBLK_T fd_pubkey_node_vote_accounts_pair_t_mapnode_t
#define REDBLK_NAME fd_pubkey_node_vote_accounts_pair_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_pubkey_node_vote_accounts_pair_t_mapnode {
    fd_pubkey_node_vote_accounts_pair_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_pubkey_node_vote_accounts_pair_t_mapnode_t *
fd_pubkey_node_vote_accounts_pair_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_pubkey_node_vote_accounts_pair_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_pubkey_node_vote_accounts_pair_t_map_footprint( len );
  return fd_pubkey_node_vote_accounts_pair_t_map_join( fd_pubkey_node_vote_accounts_pair_t_map_new( map_mem, len ) );
}
typedef struct fd_pubkey_node_vote_accounts_pair_global_t_mapnode fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t;
#define REDBLK_T fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t
#define REDBLK_NAME fd_pubkey_node_vote_accounts_pair_global_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_pubkey_node_vote_accounts_pair_global_t_mapnode {
    fd_pubkey_node_vote_accounts_pair_global_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t *
fd_pubkey_node_vote_accounts_pair_global_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_pubkey_node_vote_accounts_pair_global_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_pubkey_node_vote_accounts_pair_global_t_map_footprint( len );
  return fd_pubkey_node_vote_accounts_pair_global_t_map_join( fd_pubkey_node_vote_accounts_pair_global_t_map_new( map_mem, len ) );
}
typedef struct fd_pubkey_pubkey_pair_t_mapnode fd_pubkey_pubkey_pair_t_mapnode_t;
#define REDBLK_T fd_pubkey_pubkey_pair_t_mapnode_t
#define REDBLK_NAME fd_pubkey_pubkey_pair_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_pubkey_pubkey_pair_t_mapnode {
    fd_pubkey_pubkey_pair_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_pubkey_pubkey_pair_t_mapnode_t *
fd_pubkey_pubkey_pair_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_pubkey_pubkey_pair_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_pubkey_pubkey_pair_t_map_footprint( len );
  return fd_pubkey_pubkey_pair_t_map_join( fd_pubkey_pubkey_pair_t_map_new( map_mem, len ) );
}
/* https://github.com/anza-xyz/agave/blob/de6ce29e1a7ecbdc6dc39527fce80beea404d314/runtime/src/epoch_stakes.rs#L23 */
/* Encoded Size: Dynamic */
struct fd_epoch_stakes {
  fd_stakes_t stakes;
  ulong total_stake;
  fd_pubkey_node_vote_accounts_pair_t_mapnode_t * node_id_to_vote_accounts_pool;
  fd_pubkey_node_vote_accounts_pair_t_mapnode_t * node_id_to_vote_accounts_root;
  fd_pubkey_pubkey_pair_t_mapnode_t * epoch_authorized_voters_pool;
  fd_pubkey_pubkey_pair_t_mapnode_t * epoch_authorized_voters_root;
};
typedef struct fd_epoch_stakes fd_epoch_stakes_t;
#define FD_EPOCH_STAKES_ALIGN alignof(fd_epoch_stakes_t)

struct fd_epoch_stakes_global {
  fd_stakes_global_t stakes;
  ulong total_stake;
  ulong node_id_to_vote_accounts_pool_offset;
  ulong node_id_to_vote_accounts_root_offset;
  ulong epoch_authorized_voters_pool_offset;
  ulong epoch_authorized_voters_root_offset;
};
typedef struct fd_epoch_stakes_global fd_epoch_stakes_global_t;
#define FD_EPOCH_STAKES_GLOBAL_ALIGN alignof(fd_epoch_stakes_global_t)

static FD_FN_UNUSED fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t * fd_epoch_stakes_node_id_to_vote_accounts_pool_join( fd_epoch_stakes_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->node_id_to_vote_accounts_pool_offset ? (fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t *)fd_pubkey_node_vote_accounts_pair_global_t_map_join( fd_type_pun( (uchar *)type + type->node_id_to_vote_accounts_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t * fd_epoch_stakes_node_id_to_vote_accounts_root_join( fd_epoch_stakes_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->node_id_to_vote_accounts_root_offset ? (fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t *)fd_type_pun( (uchar *)type + type->node_id_to_vote_accounts_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_epoch_stakes_node_id_to_vote_accounts_pool_update( fd_epoch_stakes_global_t * type, fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t * pool ) {
  type->node_id_to_vote_accounts_pool_offset = !!pool ? (ulong)fd_pubkey_node_vote_accounts_pair_global_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_epoch_stakes_node_id_to_vote_accounts_root_update( fd_epoch_stakes_global_t * type, fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t * root ) {
  type->node_id_to_vote_accounts_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
static FD_FN_UNUSED fd_pubkey_pubkey_pair_t_mapnode_t * fd_epoch_stakes_epoch_authorized_voters_pool_join( fd_epoch_stakes_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->epoch_authorized_voters_pool_offset ? (fd_pubkey_pubkey_pair_t_mapnode_t *)fd_pubkey_pubkey_pair_t_map_join( fd_type_pun( (uchar *)type + type->epoch_authorized_voters_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_pubkey_pubkey_pair_t_mapnode_t * fd_epoch_stakes_epoch_authorized_voters_root_join( fd_epoch_stakes_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->epoch_authorized_voters_root_offset ? (fd_pubkey_pubkey_pair_t_mapnode_t *)fd_type_pun( (uchar *)type + type->epoch_authorized_voters_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_epoch_stakes_epoch_authorized_voters_pool_update( fd_epoch_stakes_global_t * type, fd_pubkey_pubkey_pair_t_mapnode_t * pool ) {
  type->epoch_authorized_voters_pool_offset = !!pool ? (ulong)fd_pubkey_pubkey_pair_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_epoch_stakes_epoch_authorized_voters_root_update( fd_epoch_stakes_global_t * type, fd_pubkey_pubkey_pair_t_mapnode_t * root ) {
  type->epoch_authorized_voters_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
/* Encoded Size: Dynamic */
struct fd_epoch_epoch_stakes_pair {
  ulong key;
  fd_epoch_stakes_t value;
};
typedef struct fd_epoch_epoch_stakes_pair fd_epoch_epoch_stakes_pair_t;
#define FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN alignof(fd_epoch_epoch_stakes_pair_t)

struct fd_epoch_epoch_stakes_pair_global {
  ulong key;
  fd_epoch_stakes_global_t value;
};
typedef struct fd_epoch_epoch_stakes_pair_global fd_epoch_epoch_stakes_pair_global_t;
#define FD_EPOCH_EPOCH_STAKES_PAIR_GLOBAL_ALIGN alignof(fd_epoch_epoch_stakes_pair_global_t)

/* Encoded Size: Fixed (40 bytes) */
struct fd_pubkey_u64_pair {
  fd_pubkey_t _0;
  ulong _1;
};
typedef struct fd_pubkey_u64_pair fd_pubkey_u64_pair_t;
#define FD_PUBKEY_U64_PAIR_ALIGN alignof(fd_pubkey_u64_pair_t)

/* Encoded Size: Dynamic */
struct fd_unused_accounts {
  ulong unused1_len;
  fd_pubkey_t * unused1;
  ulong unused2_len;
  fd_pubkey_t * unused2;
  ulong unused3_len;
  fd_pubkey_u64_pair_t * unused3;
};
typedef struct fd_unused_accounts fd_unused_accounts_t;
#define FD_UNUSED_ACCOUNTS_ALIGN alignof(fd_unused_accounts_t)

struct fd_unused_accounts_global {
  ulong unused1_len;
  ulong unused1_offset;
  ulong unused2_len;
  ulong unused2_offset;
  ulong unused3_len;
  ulong unused3_offset;
};
typedef struct fd_unused_accounts_global fd_unused_accounts_global_t;
#define FD_UNUSED_ACCOUNTS_GLOBAL_ALIGN alignof(fd_unused_accounts_global_t)

FD_FN_UNUSED static fd_pubkey_t * fd_unused_accounts_unused1_join( fd_unused_accounts_global_t const * struct_mem ) { // vector
  return struct_mem->unused1_offset ? (fd_pubkey_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->unused1_offset ) : NULL;
}
FD_FN_UNUSED static void fd_unused_accounts_unused1_update( fd_unused_accounts_global_t * struct_mem, fd_pubkey_t * vec ) {
  struct_mem->unused1_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
FD_FN_UNUSED static fd_pubkey_t * fd_unused_accounts_unused2_join( fd_unused_accounts_global_t const * struct_mem ) { // vector
  return struct_mem->unused2_offset ? (fd_pubkey_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->unused2_offset ) : NULL;
}
FD_FN_UNUSED static void fd_unused_accounts_unused2_update( fd_unused_accounts_global_t * struct_mem, fd_pubkey_t * vec ) {
  struct_mem->unused2_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
FD_FN_UNUSED static fd_pubkey_u64_pair_t * fd_unused_accounts_unused3_join( fd_unused_accounts_global_t const * struct_mem ) { // vector
  return struct_mem->unused3_offset ? (fd_pubkey_u64_pair_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->unused3_offset ) : NULL;
}
FD_FN_UNUSED static void fd_unused_accounts_unused3_update( fd_unused_accounts_global_t * struct_mem, fd_pubkey_u64_pair_t * vec ) {
  struct_mem->unused3_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/bank.rs#L967 */
/* Encoded Size: Dynamic */
struct fd_versioned_bank {
  fd_block_hash_vec_t blockhash_queue;
  ulong ancestors_len;
  fd_slot_pair_t * ancestors;
  fd_hash_t hash;
  fd_hash_t parent_hash;
  ulong parent_slot;
  fd_hard_forks_t hard_forks;
  ulong transaction_count;
  ulong tick_height;
  ulong signature_count;
  ulong capitalization;
  ulong max_tick_height;
  ulong* hashes_per_tick;
  ulong ticks_per_slot;
  uint128 ns_per_slot;
  ulong genesis_creation_time;
  double slots_per_year;
  ulong accounts_data_len;
  ulong slot;
  ulong epoch;
  ulong block_height;
  fd_pubkey_t collector_id;
  ulong collector_fees;
  fd_fee_calculator_t fee_calculator;
  fd_fee_rate_governor_t fee_rate_governor;
  ulong collected_rent;
  fd_rent_collector_t rent_collector;
  fd_epoch_schedule_t epoch_schedule;
  fd_inflation_t inflation;
  fd_stakes_t stakes;
  fd_unused_accounts_t unused_accounts;
  ulong epoch_stakes_len;
  fd_epoch_epoch_stakes_pair_t * epoch_stakes;
  uchar is_delta;
};
typedef struct fd_versioned_bank fd_versioned_bank_t;
#define FD_VERSIONED_BANK_ALIGN alignof(fd_versioned_bank_t)

struct fd_versioned_bank_global {
  fd_block_hash_vec_global_t blockhash_queue;
  ulong ancestors_len;
  ulong ancestors_offset;
  fd_hash_t hash;
  fd_hash_t parent_hash;
  ulong parent_slot;
  fd_hard_forks_global_t hard_forks;
  ulong transaction_count;
  ulong tick_height;
  ulong signature_count;
  ulong capitalization;
  ulong max_tick_height;
  ulong hashes_per_tick_offset;
  ulong ticks_per_slot;
  uint128 ns_per_slot;
  ulong genesis_creation_time;
  double slots_per_year;
  ulong accounts_data_len;
  ulong slot;
  ulong epoch;
  ulong block_height;
  fd_pubkey_t collector_id;
  ulong collector_fees;
  fd_fee_calculator_t fee_calculator;
  fd_fee_rate_governor_t fee_rate_governor;
  ulong collected_rent;
  fd_rent_collector_t rent_collector;
  fd_epoch_schedule_t epoch_schedule;
  fd_inflation_t inflation;
  fd_stakes_global_t stakes;
  fd_unused_accounts_global_t unused_accounts;
  ulong epoch_stakes_len;
  ulong epoch_stakes_offset;
  uchar is_delta;
};
typedef struct fd_versioned_bank_global fd_versioned_bank_global_t;
#define FD_VERSIONED_BANK_GLOBAL_ALIGN alignof(fd_versioned_bank_global_t)

FD_FN_UNUSED static fd_slot_pair_t * fd_versioned_bank_ancestors_join( fd_versioned_bank_global_t const * struct_mem ) { // vector
  return struct_mem->ancestors_offset ? (fd_slot_pair_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->ancestors_offset ) : NULL;
}
FD_FN_UNUSED static void fd_versioned_bank_ancestors_update( fd_versioned_bank_global_t * struct_mem, fd_slot_pair_t * vec ) {
  struct_mem->ancestors_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
FD_FN_UNUSED static ulong * fd_versioned_bank_hashes_per_tick_join( fd_versioned_bank_global_t const * struct_mem ) {
  return struct_mem->hashes_per_tick_offset ? (ulong *)fd_type_pun( (uchar *)struct_mem + struct_mem->hashes_per_tick_offset ) : NULL;
}
FD_FN_UNUSED static fd_epoch_epoch_stakes_pair_global_t * fd_versioned_bank_epoch_stakes_join( fd_versioned_bank_global_t const * struct_mem ) { // vector
  return struct_mem->epoch_stakes_offset ? (fd_epoch_epoch_stakes_pair_global_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->epoch_stakes_offset ) : NULL;
}
FD_FN_UNUSED static void fd_versioned_bank_epoch_stakes_update( fd_versioned_bank_global_t * struct_mem, fd_epoch_epoch_stakes_pair_global_t * vec ) {
  struct_mem->epoch_stakes_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* Encoded Size: Fixed (40 bytes) */
struct fd_bank_hash_stats {
  ulong num_updated_accounts;
  ulong num_removed_accounts;
  ulong num_lamports_stored;
  ulong total_data_len;
  ulong num_executable_accounts;
};
typedef struct fd_bank_hash_stats fd_bank_hash_stats_t;
#define FD_BANK_HASH_STATS_ALIGN alignof(fd_bank_hash_stats_t)

/* Encoded Size: Fixed (104 bytes) */
struct fd_bank_hash_info {
  fd_hash_t accounts_delta_hash;
  fd_hash_t accounts_hash;
  fd_bank_hash_stats_t stats;
};
typedef struct fd_bank_hash_info fd_bank_hash_info_t;
#define FD_BANK_HASH_INFO_ALIGN alignof(fd_bank_hash_info_t)

/* Encoded Size: Fixed (40 bytes) */
struct fd_slot_map_pair {
  ulong slot;
  fd_hash_t hash;
};
typedef struct fd_slot_map_pair fd_slot_map_pair_t;
#define FD_SLOT_MAP_PAIR_ALIGN alignof(fd_slot_map_pair_t)

/* Encoded Size: Fixed (16 bytes) */
struct fd_snapshot_acc_vec {
  ulong id;
  ulong file_sz;
};
typedef struct fd_snapshot_acc_vec fd_snapshot_acc_vec_t;
#define FD_SNAPSHOT_ACC_VEC_ALIGN alignof(fd_snapshot_acc_vec_t)

/* Encoded Size: Dynamic */
struct fd_snapshot_slot_acc_vecs {
  ulong slot;
  ulong account_vecs_len;
  fd_snapshot_acc_vec_t * account_vecs;
};
typedef struct fd_snapshot_slot_acc_vecs fd_snapshot_slot_acc_vecs_t;
#define FD_SNAPSHOT_SLOT_ACC_VECS_ALIGN alignof(fd_snapshot_slot_acc_vecs_t)

struct fd_snapshot_slot_acc_vecs_global {
  ulong slot;
  ulong account_vecs_len;
  ulong account_vecs_offset;
};
typedef struct fd_snapshot_slot_acc_vecs_global fd_snapshot_slot_acc_vecs_global_t;
#define FD_SNAPSHOT_SLOT_ACC_VECS_GLOBAL_ALIGN alignof(fd_snapshot_slot_acc_vecs_global_t)

FD_FN_UNUSED static fd_snapshot_acc_vec_t * fd_snapshot_slot_acc_vecs_account_vecs_join( fd_snapshot_slot_acc_vecs_global_t const * struct_mem ) { // vector
  return struct_mem->account_vecs_offset ? (fd_snapshot_acc_vec_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->account_vecs_offset ) : NULL;
}
FD_FN_UNUSED static void fd_snapshot_slot_acc_vecs_account_vecs_update( fd_snapshot_slot_acc_vecs_global_t * struct_mem, fd_snapshot_acc_vec_t * vec ) {
  struct_mem->account_vecs_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/reward_type.rs#L7 */
struct fd_reward_type {
  uint discriminant;
};
typedef struct fd_reward_type fd_reward_type_t;
#define FD_REWARD_TYPE_ALIGN alignof(fd_reward_type_t)

/* Accounts DB related fields in a snapshot */
/* Encoded Size: Dynamic */
struct fd_solana_accounts_db_fields {
  ulong storages_len;
  fd_snapshot_slot_acc_vecs_t * storages;
  ulong version;
  ulong slot;
  fd_bank_hash_info_t bank_hash_info;
  ulong historical_roots_len;
  ulong* historical_roots;
  ulong historical_roots_with_hash_len;
  fd_slot_map_pair_t * historical_roots_with_hash;
};
typedef struct fd_solana_accounts_db_fields fd_solana_accounts_db_fields_t;
#define FD_SOLANA_ACCOUNTS_DB_FIELDS_ALIGN alignof(fd_solana_accounts_db_fields_t)

struct fd_solana_accounts_db_fields_global {
  ulong storages_len;
  ulong storages_offset;
  ulong version;
  ulong slot;
  fd_bank_hash_info_t bank_hash_info;
  ulong historical_roots_len;
  ulong historical_roots_offset;
  ulong historical_roots_with_hash_len;
  ulong historical_roots_with_hash_offset;
};
typedef struct fd_solana_accounts_db_fields_global fd_solana_accounts_db_fields_global_t;
#define FD_SOLANA_ACCOUNTS_DB_FIELDS_GLOBAL_ALIGN alignof(fd_solana_accounts_db_fields_global_t)

FD_FN_UNUSED static fd_snapshot_slot_acc_vecs_global_t * fd_solana_accounts_db_fields_storages_join( fd_solana_accounts_db_fields_global_t const * struct_mem ) { // vector
  return struct_mem->storages_offset ? (fd_snapshot_slot_acc_vecs_global_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->storages_offset ) : NULL;
}
FD_FN_UNUSED static void fd_solana_accounts_db_fields_storages_update( fd_solana_accounts_db_fields_global_t * struct_mem, fd_snapshot_slot_acc_vecs_global_t * vec ) {
  struct_mem->storages_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
FD_FN_UNUSED static ulong * fd_solana_accounts_db_fields_historical_roots_join( fd_solana_accounts_db_fields_global_t const * struct_mem ) { // vector
  return struct_mem->historical_roots_offset ? (ulong *)fd_type_pun( (uchar *)struct_mem + struct_mem->historical_roots_offset ) : NULL;
}
FD_FN_UNUSED static void fd_solana_accounts_db_fields_historical_roots_update( fd_solana_accounts_db_fields_global_t * struct_mem, ulong * vec ) {
  struct_mem->historical_roots_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
FD_FN_UNUSED static fd_slot_map_pair_t * fd_solana_accounts_db_fields_historical_roots_with_hash_join( fd_solana_accounts_db_fields_global_t const * struct_mem ) { // vector
  return struct_mem->historical_roots_with_hash_offset ? (fd_slot_map_pair_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->historical_roots_with_hash_offset ) : NULL;
}
FD_FN_UNUSED static void fd_solana_accounts_db_fields_historical_roots_with_hash_update( fd_solana_accounts_db_fields_global_t * struct_mem, fd_slot_map_pair_t * vec ) {
  struct_mem->historical_roots_with_hash_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* https://github.com/anza-xyz/agave/blob/436f7333a8465739df65c2534654102896e09eb5/runtime/src/epoch_stakes.rs#L25 */
/* Encoded Size: Dynamic */
struct fd_versioned_epoch_stakes_current {
  fd_stakes_stake_t stakes;
  ulong total_stake;
  fd_pubkey_node_vote_accounts_pair_t_mapnode_t * node_id_to_vote_accounts_pool;
  fd_pubkey_node_vote_accounts_pair_t_mapnode_t * node_id_to_vote_accounts_root;
  fd_pubkey_pubkey_pair_t_mapnode_t * epoch_authorized_voters_pool;
  fd_pubkey_pubkey_pair_t_mapnode_t * epoch_authorized_voters_root;
};
typedef struct fd_versioned_epoch_stakes_current fd_versioned_epoch_stakes_current_t;
#define FD_VERSIONED_EPOCH_STAKES_CURRENT_ALIGN alignof(fd_versioned_epoch_stakes_current_t)

struct fd_versioned_epoch_stakes_current_global {
  fd_stakes_stake_global_t stakes;
  ulong total_stake;
  ulong node_id_to_vote_accounts_pool_offset;
  ulong node_id_to_vote_accounts_root_offset;
  ulong epoch_authorized_voters_pool_offset;
  ulong epoch_authorized_voters_root_offset;
};
typedef struct fd_versioned_epoch_stakes_current_global fd_versioned_epoch_stakes_current_global_t;
#define FD_VERSIONED_EPOCH_STAKES_CURRENT_GLOBAL_ALIGN alignof(fd_versioned_epoch_stakes_current_global_t)

static FD_FN_UNUSED fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t * fd_versioned_epoch_stakes_current_node_id_to_vote_accounts_pool_join( fd_versioned_epoch_stakes_current_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->node_id_to_vote_accounts_pool_offset ? (fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t *)fd_pubkey_node_vote_accounts_pair_global_t_map_join( fd_type_pun( (uchar *)type + type->node_id_to_vote_accounts_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t * fd_versioned_epoch_stakes_current_node_id_to_vote_accounts_root_join( fd_versioned_epoch_stakes_current_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->node_id_to_vote_accounts_root_offset ? (fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t *)fd_type_pun( (uchar *)type + type->node_id_to_vote_accounts_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_versioned_epoch_stakes_current_node_id_to_vote_accounts_pool_update( fd_versioned_epoch_stakes_current_global_t * type, fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t * pool ) {
  type->node_id_to_vote_accounts_pool_offset = !!pool ? (ulong)fd_pubkey_node_vote_accounts_pair_global_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_versioned_epoch_stakes_current_node_id_to_vote_accounts_root_update( fd_versioned_epoch_stakes_current_global_t * type, fd_pubkey_node_vote_accounts_pair_global_t_mapnode_t * root ) {
  type->node_id_to_vote_accounts_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
static FD_FN_UNUSED fd_pubkey_pubkey_pair_t_mapnode_t * fd_versioned_epoch_stakes_current_epoch_authorized_voters_pool_join( fd_versioned_epoch_stakes_current_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->epoch_authorized_voters_pool_offset ? (fd_pubkey_pubkey_pair_t_mapnode_t *)fd_pubkey_pubkey_pair_t_map_join( fd_type_pun( (uchar *)type + type->epoch_authorized_voters_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_pubkey_pubkey_pair_t_mapnode_t * fd_versioned_epoch_stakes_current_epoch_authorized_voters_root_join( fd_versioned_epoch_stakes_current_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->epoch_authorized_voters_root_offset ? (fd_pubkey_pubkey_pair_t_mapnode_t *)fd_type_pun( (uchar *)type + type->epoch_authorized_voters_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_versioned_epoch_stakes_current_epoch_authorized_voters_pool_update( fd_versioned_epoch_stakes_current_global_t * type, fd_pubkey_pubkey_pair_t_mapnode_t * pool ) {
  type->epoch_authorized_voters_pool_offset = !!pool ? (ulong)fd_pubkey_pubkey_pair_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_versioned_epoch_stakes_current_epoch_authorized_voters_root_update( fd_versioned_epoch_stakes_current_global_t * type, fd_pubkey_pubkey_pair_t_mapnode_t * root ) {
  type->epoch_authorized_voters_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
union fd_versioned_epoch_stakes_inner {
  fd_versioned_epoch_stakes_current_t Current;
};
typedef union fd_versioned_epoch_stakes_inner fd_versioned_epoch_stakes_inner_t;

union fd_versioned_epoch_stakes_inner_global {
  fd_versioned_epoch_stakes_current_global_t Current;
};
typedef union fd_versioned_epoch_stakes_inner_global fd_versioned_epoch_stakes_inner_global_t;

/* https://github.com/anza-xyz/agave/blob/436f7333a8465739df65c2534654102896e09eb5/runtime/src/epoch_stakes.rs#L24 */
struct fd_versioned_epoch_stakes {
  uint discriminant;
  fd_versioned_epoch_stakes_inner_t inner;
};
typedef struct fd_versioned_epoch_stakes fd_versioned_epoch_stakes_t;
#define FD_VERSIONED_EPOCH_STAKES_ALIGN alignof(fd_versioned_epoch_stakes_t)
struct fd_versioned_epoch_stakes_global {
  uint discriminant;
  fd_versioned_epoch_stakes_inner_global_t inner;
};
typedef struct fd_versioned_epoch_stakes_global fd_versioned_epoch_stakes_global_t;
#define FD_VERSIONED_EPOCH_STAKES_GLOBAL_ALIGN alignof(fd_versioned_epoch_stakes_global_t)

/* Encoded Size: Dynamic */
struct fd_versioned_epoch_stakes_pair {
  ulong epoch;
  fd_versioned_epoch_stakes_t val;
};
typedef struct fd_versioned_epoch_stakes_pair fd_versioned_epoch_stakes_pair_t;
#define FD_VERSIONED_EPOCH_STAKES_PAIR_ALIGN alignof(fd_versioned_epoch_stakes_pair_t)

struct fd_versioned_epoch_stakes_pair_global {
  ulong epoch;
  fd_versioned_epoch_stakes_global_t val;
};
typedef struct fd_versioned_epoch_stakes_pair_global fd_versioned_epoch_stakes_pair_global_t;
#define FD_VERSIONED_EPOCH_STAKES_PAIR_GLOBAL_ALIGN alignof(fd_versioned_epoch_stakes_pair_global_t)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/reward_info.rs#L5 */
/* Encoded Size: Fixed (28 bytes) */
struct fd_reward_info {
  fd_reward_type_t reward_type;
  ulong lamports;
  ulong post_balance;
  ulong commission;
};
typedef struct fd_reward_info fd_reward_info_t;
#define FD_REWARD_INFO_ALIGN alignof(fd_reward_info_t)

/* You can cast this to a (fd_lthash_value_t *) and use it directly since the alignment is preserved */
/* Encoded Size: Fixed (2048 bytes) */
struct __attribute__((aligned(128UL))) fd_slot_lthash {
  uchar lthash[2048];
};
typedef struct fd_slot_lthash fd_slot_lthash_t;
#define FD_SLOT_LTHASH_ALIGN (128UL)

/* Encoded Size: Dynamic */
struct fd_solana_manifest {
  fd_versioned_bank_t bank;
  fd_solana_accounts_db_fields_t accounts_db;
  ulong lamports_per_signature;
  fd_bank_incremental_snapshot_persistence_t * bank_incremental_snapshot_persistence;
  fd_hash_t * epoch_account_hash;
  ulong versioned_epoch_stakes_len;
  fd_versioned_epoch_stakes_pair_t * versioned_epoch_stakes;
  fd_slot_lthash_t * lthash;
};
typedef struct fd_solana_manifest fd_solana_manifest_t;
#define FD_SOLANA_MANIFEST_ALIGN alignof(fd_solana_manifest_t)

struct fd_solana_manifest_global {
  fd_versioned_bank_global_t bank;
  fd_solana_accounts_db_fields_global_t accounts_db;
  ulong lamports_per_signature;
  ulong bank_incremental_snapshot_persistence_offset;
  ulong epoch_account_hash_offset;
  ulong versioned_epoch_stakes_len;
  ulong versioned_epoch_stakes_offset;
  ulong lthash_offset;
};
typedef struct fd_solana_manifest_global fd_solana_manifest_global_t;
#define FD_SOLANA_MANIFEST_GLOBAL_ALIGN alignof(fd_solana_manifest_global_t)

FD_FN_UNUSED static fd_bank_incremental_snapshot_persistence_t * fd_solana_manifest_bank_incremental_snapshot_persistence_join( fd_solana_manifest_global_t const * struct_mem ) {
  return struct_mem->bank_incremental_snapshot_persistence_offset ? (fd_bank_incremental_snapshot_persistence_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->bank_incremental_snapshot_persistence_offset ) : NULL;
}
FD_FN_UNUSED static fd_hash_t * fd_solana_manifest_epoch_account_hash_join( fd_solana_manifest_global_t const * struct_mem ) {
  return struct_mem->epoch_account_hash_offset ? (fd_hash_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->epoch_account_hash_offset ) : NULL;
}
FD_FN_UNUSED static fd_versioned_epoch_stakes_pair_global_t * fd_solana_manifest_versioned_epoch_stakes_join( fd_solana_manifest_global_t const * struct_mem ) { // vector
  return struct_mem->versioned_epoch_stakes_offset ? (fd_versioned_epoch_stakes_pair_global_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->versioned_epoch_stakes_offset ) : NULL;
}
FD_FN_UNUSED static void fd_solana_manifest_versioned_epoch_stakes_update( fd_solana_manifest_global_t * struct_mem, fd_versioned_epoch_stakes_pair_global_t * vec ) {
  struct_mem->versioned_epoch_stakes_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
FD_FN_UNUSED static fd_slot_lthash_t * fd_solana_manifest_lthash_join( fd_solana_manifest_global_t const * struct_mem ) {
  return struct_mem->lthash_offset ? (fd_slot_lthash_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->lthash_offset ) : NULL;
}
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
  ulong* target_tick_count;
  ulong hashes_per_tick;
  uchar has_hashes_per_tick;
};
typedef struct fd_poh_config fd_poh_config_t;
#define FD_POH_CONFIG_ALIGN alignof(fd_poh_config_t)

/* Encoded Size: Dynamic */
struct fd_string_pubkey_pair {
  ulong string_len;
  uchar* string;
  fd_pubkey_t pubkey;
};
typedef struct fd_string_pubkey_pair fd_string_pubkey_pair_t;
#define FD_STRING_PUBKEY_PAIR_ALIGN alignof(fd_string_pubkey_pair_t)

/* Encoded Size: Dynamic */
struct fd_pubkey_account_pair {
  fd_pubkey_t key;
  fd_solana_account_t account;
};
typedef struct fd_pubkey_account_pair fd_pubkey_account_pair_t;
#define FD_PUBKEY_ACCOUNT_PAIR_ALIGN alignof(fd_pubkey_account_pair_t)

/* Encoded Size: Dynamic */
struct fd_genesis_solana {
  ulong creation_time;
  ulong accounts_len;
  fd_pubkey_account_pair_t * accounts;
  ulong native_instruction_processors_len;
  fd_string_pubkey_pair_t * native_instruction_processors;
  ulong rewards_pools_len;
  fd_pubkey_account_pair_t * rewards_pools;
  ulong ticks_per_slot;
  ulong unused;
  fd_poh_config_t poh_config;
  ulong __backwards_compat_with_v0_23;
  fd_fee_rate_governor_t fee_rate_governor;
  fd_rent_t rent;
  fd_inflation_t inflation;
  fd_epoch_schedule_t epoch_schedule;
  uint cluster_type;
};
typedef struct fd_genesis_solana fd_genesis_solana_t;
#define FD_GENESIS_SOLANA_ALIGN alignof(fd_genesis_solana_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L114 */
/* Encoded Size: Fixed (40 bytes) */
struct fd_sol_sysvar_clock {
  ulong slot;
  long epoch_start_timestamp;
  ulong epoch;
  ulong leader_schedule_epoch;
  long unix_timestamp;
};
typedef struct fd_sol_sysvar_clock fd_sol_sysvar_clock_t;
#define FD_SOL_SYSVAR_CLOCK_ALIGN alignof(fd_sol_sysvar_clock_t)

/* https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/sdk/program/src/last_restart_slot.rs#L7 */
/* Encoded Size: Fixed (8 bytes) */
struct fd_sol_sysvar_last_restart_slot {
  ulong slot;
};
typedef struct fd_sol_sysvar_last_restart_slot fd_sol_sysvar_last_restart_slot_t;
#define FD_SOL_SYSVAR_LAST_RESTART_SLOT_ALIGN alignof(fd_sol_sysvar_last_restart_slot_t)

/* Encoded Size: Fixed (12 bytes) */
struct fd_vote_lockout {
  ulong slot;
  uint confirmation_count;
};
typedef struct fd_vote_lockout fd_vote_lockout_t;
#define FD_VOTE_LOCKOUT_ALIGN alignof(fd_vote_lockout_t)

/* Encoded Size: Dynamic */
struct fd_lockout_offset {
  ulong offset;
  uchar confirmation_count;
};
typedef struct fd_lockout_offset fd_lockout_offset_t;
#define FD_LOCKOUT_OFFSET_ALIGN alignof(fd_lockout_offset_t)

/* https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L9 */
/* Encoded Size: Fixed (40 bytes) */
struct fd_vote_authorized_voter {
  ulong epoch;
  fd_pubkey_t pubkey;
  ulong parent;
  ulong left;
  ulong right;
  ulong prio;
};
typedef struct fd_vote_authorized_voter fd_vote_authorized_voter_t;
#define FD_VOTE_AUTHORIZED_VOTER_ALIGN alignof(fd_vote_authorized_voter_t)

/* Encoded Size: Fixed (48 bytes) */
struct fd_vote_prior_voter {
  fd_pubkey_t pubkey;
  ulong epoch_start;
  ulong epoch_end;
};
typedef struct fd_vote_prior_voter fd_vote_prior_voter_t;
#define FD_VOTE_PRIOR_VOTER_ALIGN alignof(fd_vote_prior_voter_t)

/* Encoded Size: Fixed (56 bytes) */
struct fd_vote_prior_voter_0_23_5 {
  fd_pubkey_t pubkey;
  ulong epoch_start;
  ulong epoch_end;
  ulong slot;
};
typedef struct fd_vote_prior_voter_0_23_5 fd_vote_prior_voter_0_23_5_t;
#define FD_VOTE_PRIOR_VOTER_0_23_5_ALIGN alignof(fd_vote_prior_voter_0_23_5_t)

/* Encoded Size: Fixed (24 bytes) */
struct fd_vote_epoch_credits {
  ulong epoch;
  ulong credits;
  ulong prev_credits;
};
typedef struct fd_vote_epoch_credits fd_vote_epoch_credits_t;
#define FD_VOTE_EPOCH_CREDITS_ALIGN alignof(fd_vote_epoch_credits_t)

/* Encoded Size: Fixed (16 bytes) */
struct fd_vote_block_timestamp {
  ulong slot;
  long timestamp;
};
typedef struct fd_vote_block_timestamp fd_vote_block_timestamp_t;
#define FD_VOTE_BLOCK_TIMESTAMP_ALIGN alignof(fd_vote_block_timestamp_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L268 */
/* Encoded Size: Fixed (1545 bytes) */
struct fd_vote_prior_voters {
  fd_vote_prior_voter_t buf[32];
  ulong idx;
  uchar is_empty;
};
typedef struct fd_vote_prior_voters fd_vote_prior_voters_t;
#define FD_VOTE_PRIOR_VOTERS_ALIGN alignof(fd_vote_prior_voters_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L268 */
/* Encoded Size: Fixed (1800 bytes) */
struct fd_vote_prior_voters_0_23_5 {
  fd_vote_prior_voter_0_23_5_t buf[32];
  ulong idx;
};
typedef struct fd_vote_prior_voters_0_23_5 fd_vote_prior_voters_0_23_5_t;
#define FD_VOTE_PRIOR_VOTERS_0_23_5_ALIGN alignof(fd_vote_prior_voters_0_23_5_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L268 */
/* Encoded Size: Fixed (13 bytes) */
struct fd_landed_vote {
  uchar latency;
  fd_vote_lockout_t lockout;
};
typedef struct fd_landed_vote fd_landed_vote_t;
#define FD_LANDED_VOTE_ALIGN alignof(fd_landed_vote_t)

#define DEQUE_NAME deq_fd_vote_lockout_t
#define DEQUE_T fd_vote_lockout_t
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline fd_vote_lockout_t *
deq_fd_vote_lockout_t_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_vote_lockout_t_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_fd_vote_lockout_t_footprint( max );
  return deq_fd_vote_lockout_t_join( deq_fd_vote_lockout_t_new( deque_mem, max ) );
}

#define DEQUE_NAME deq_fd_vote_epoch_credits_t
#define DEQUE_T fd_vote_epoch_credits_t
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline fd_vote_epoch_credits_t *
deq_fd_vote_epoch_credits_t_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_vote_epoch_credits_t_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_fd_vote_epoch_credits_t_footprint( max );
  return deq_fd_vote_epoch_credits_t_join( deq_fd_vote_epoch_credits_t_new( deque_mem, max ) );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/vote_state_0_23_5.rs#L6 */
/* Encoded Size: Dynamic */
struct fd_vote_state_0_23_5 {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_voter;
  ulong authorized_voter_epoch;
  fd_vote_prior_voters_0_23_5_t prior_voters;
  fd_pubkey_t authorized_withdrawer;
  uchar commission;
  fd_vote_lockout_t * votes; /* fd_deque_dynamic (min cnt 32) */
  ulong root_slot;
  uchar has_root_slot;
  fd_vote_epoch_credits_t * epoch_credits; /* fd_deque_dynamic (min cnt 64) */
  fd_vote_block_timestamp_t last_timestamp;
};
typedef struct fd_vote_state_0_23_5 fd_vote_state_0_23_5_t;
#define FD_VOTE_STATE_0_23_5_ALIGN alignof(fd_vote_state_0_23_5_t)

#define FD_VOTE_AUTHORIZED_VOTERS_MIN 64
#define POOL_NAME fd_vote_authorized_voters_pool
#define POOL_T fd_vote_authorized_voter_t
#define POOL_NEXT parent
#include "../../util/tmpl/fd_pool.c"
static inline fd_vote_authorized_voter_t *
fd_vote_authorized_voters_pool_join_new( void * * alloc_mem, ulong num ) {
  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_vote_authorized_voters_pool_align() );
  void * pool_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_vote_authorized_voters_pool_footprint( num );
  return fd_vote_authorized_voters_pool_join( fd_vote_authorized_voters_pool_new( pool_mem, num ) );
}
#define TREAP_NAME fd_vote_authorized_voters_treap
#define TREAP_T fd_vote_authorized_voter_t
#define TREAP_QUERY_T ulong
#define TREAP_CMP(q,e) ( (q == (e)->epoch) ? 0 : ( (q < (e)->epoch) ? -1 : 1 ) )
#define TREAP_LT(e0,e1) ((e0)->epoch<(e1)->epoch)
#include "../../util/tmpl/fd_treap.c"
static inline fd_vote_authorized_voters_treap_t *
fd_vote_authorized_voters_treap_join_new( void * * alloc_mem, ulong num ) {
  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_vote_authorized_voters_treap_align() );
  void * treap_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_vote_authorized_voters_treap_footprint( num );
  return fd_vote_authorized_voters_treap_join( fd_vote_authorized_voters_treap_new( treap_mem, num ) );
}
/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L310 */
/* Encoded Size: Dynamic */
struct fd_vote_authorized_voters {
  fd_vote_authorized_voter_t * pool;
  fd_vote_authorized_voters_treap_t * treap;
};
typedef struct fd_vote_authorized_voters fd_vote_authorized_voters_t;
#define FD_VOTE_AUTHORIZED_VOTERS_ALIGN alignof(fd_vote_authorized_voters_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L310 */
/* Encoded Size: Dynamic */
struct fd_vote_state_1_14_11 {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_withdrawer;
  uchar commission;
  fd_vote_lockout_t * votes; /* fd_deque_dynamic (min cnt 32) */
  ulong root_slot;
  uchar has_root_slot;
  fd_vote_authorized_voters_t authorized_voters;
  fd_vote_prior_voters_t prior_voters;
  fd_vote_epoch_credits_t * epoch_credits; /* fd_deque_dynamic (min cnt 64) */
  fd_vote_block_timestamp_t last_timestamp;
};
typedef struct fd_vote_state_1_14_11 fd_vote_state_1_14_11_t;
#define FD_VOTE_STATE_1_14_11_ALIGN alignof(fd_vote_state_1_14_11_t)

#define DEQUE_NAME deq_fd_landed_vote_t
#define DEQUE_T fd_landed_vote_t
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline fd_landed_vote_t *
deq_fd_landed_vote_t_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_landed_vote_t_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_fd_landed_vote_t_footprint( max );
  return deq_fd_landed_vote_t_join( deq_fd_landed_vote_t_new( deque_mem, max ) );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L310 */
/* Encoded Size: Dynamic */
struct fd_vote_state {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_withdrawer;
  uchar commission;
  fd_landed_vote_t * votes; /* fd_deque_dynamic (min cnt 32) */
  ulong root_slot;
  uchar has_root_slot;
  fd_vote_authorized_voters_t authorized_voters;
  fd_vote_prior_voters_t prior_voters;
  fd_vote_epoch_credits_t * epoch_credits; /* fd_deque_dynamic (min cnt 64) */
  fd_vote_block_timestamp_t last_timestamp;
};
typedef struct fd_vote_state fd_vote_state_t;
#define FD_VOTE_STATE_ALIGN alignof(fd_vote_state_t)

union fd_vote_state_versioned_inner {
  fd_vote_state_0_23_5_t v0_23_5;
  fd_vote_state_1_14_11_t v1_14_11;
  fd_vote_state_t current;
};
typedef union fd_vote_state_versioned_inner fd_vote_state_versioned_inner_t;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/vote_state_versions.rs#L4 */
struct fd_vote_state_versioned {
  uint discriminant;
  fd_vote_state_versioned_inner_t inner;
};
typedef struct fd_vote_state_versioned fd_vote_state_versioned_t;
#define FD_VOTE_STATE_VERSIONED_ALIGN alignof(fd_vote_state_versioned_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L185 */
/* Encoded Size: Dynamic */
struct fd_vote_state_update {
  fd_vote_lockout_t * lockouts; /* fd_deque_dynamic (min cnt 32) */
  ulong root;
  uchar has_root;
  fd_hash_t hash;
  long timestamp;
  uchar has_timestamp;
};
typedef struct fd_vote_state_update fd_vote_state_update_t;
#define FD_VOTE_STATE_UPDATE_ALIGN alignof(fd_vote_state_update_t)

/* Encoded Size: Dynamic */
struct fd_compact_vote_state_update {
  ulong root;
  ushort lockouts_len;
  fd_lockout_offset_t * lockouts;
  fd_hash_t hash;
  long timestamp;
  uchar has_timestamp;
};
typedef struct fd_compact_vote_state_update fd_compact_vote_state_update_t;
#define FD_COMPACT_VOTE_STATE_UPDATE_ALIGN alignof(fd_compact_vote_state_update_t)

/* https://github.com/solana-labs/solana/blob/252438e28fbfb2c695fe1215171b83456e4b761c/programs/vote/src/vote_instruction.rs#L143 */
/* Encoded Size: Dynamic */
struct fd_compact_vote_state_update_switch {
  fd_compact_vote_state_update_t compact_vote_state_update;
  fd_hash_t hash;
};
typedef struct fd_compact_vote_state_update_switch fd_compact_vote_state_update_switch_t;
#define FD_COMPACT_VOTE_STATE_UPDATE_SWITCH_ALIGN alignof(fd_compact_vote_state_update_switch_t)

#define DEQUE_NAME deq_fd_lockout_offset_t
#define DEQUE_T fd_lockout_offset_t
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline fd_lockout_offset_t *
deq_fd_lockout_offset_t_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_lockout_offset_t_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_fd_lockout_offset_t_footprint( max );
  return deq_fd_lockout_offset_t_join( deq_fd_lockout_offset_t_new( deque_mem, max ) );
}

/* https://github.com/anza-xyz/agave/blob/20ee70cd1829cd414d09040460defecf9792a370/sdk/program/src/vote/state/mod.rs#L990 */
/* Encoded Size: Dynamic */
struct fd_compact_tower_sync {
  ulong root;
  fd_lockout_offset_t * lockout_offsets; /* fd_deque_dynamic (min cnt 32) */
  fd_hash_t hash;
  long timestamp;
  uchar has_timestamp;
  fd_hash_t block_id;
};
typedef struct fd_compact_tower_sync fd_compact_tower_sync_t;
#define FD_COMPACT_TOWER_SYNC_ALIGN alignof(fd_compact_tower_sync_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L185 */
/* Encoded Size: Dynamic */
struct fd_tower_sync {
  fd_vote_lockout_t * lockouts; /* fd_deque_dynamic */
  ulong lockouts_cnt;
  ulong root;
  uchar has_root;
  fd_hash_t hash;
  long timestamp;
  uchar has_timestamp;
  fd_hash_t block_id;
};
typedef struct fd_tower_sync fd_tower_sync_t;
#define FD_TOWER_SYNC_ALIGN alignof(fd_tower_sync_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L104 */
/* Encoded Size: Dynamic */
struct fd_tower_sync_switch {
  fd_tower_sync_t tower_sync;
  fd_hash_t hash;
};
typedef struct fd_tower_sync_switch fd_tower_sync_switch_t;
#define FD_TOWER_SYNC_SWITCH_ALIGN alignof(fd_tower_sync_switch_t)

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
  ulong entry_end_indexes_len;
  uint* entry_end_indexes;
};
typedef struct fd_slot_meta fd_slot_meta_t;
#define FD_SLOT_META_ALIGN alignof(fd_slot_meta_t)

/* A validator timestamp oracle vote received from a voting node */
/* Encoded Size: Fixed (48 bytes) */
struct fd_clock_timestamp_vote {
  fd_pubkey_t pubkey;
  long timestamp;
  ulong slot;
};
typedef struct fd_clock_timestamp_vote fd_clock_timestamp_vote_t;
#define FD_CLOCK_TIMESTAMP_VOTE_ALIGN alignof(fd_clock_timestamp_vote_t)

typedef struct fd_clock_timestamp_vote_t_mapnode fd_clock_timestamp_vote_t_mapnode_t;
#define REDBLK_T fd_clock_timestamp_vote_t_mapnode_t
#define REDBLK_NAME fd_clock_timestamp_vote_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_clock_timestamp_vote_t_mapnode {
    fd_clock_timestamp_vote_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_clock_timestamp_vote_t_mapnode_t *
fd_clock_timestamp_vote_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_clock_timestamp_vote_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_clock_timestamp_vote_t_map_footprint( len );
  return fd_clock_timestamp_vote_t_map_join( fd_clock_timestamp_vote_t_map_new( map_mem, len ) );
}
/* Validator timestamp oracle votes received from voting nodes. TODO: make this a map */
/* Encoded Size: Dynamic */
struct fd_clock_timestamp_votes {
  fd_clock_timestamp_vote_t_mapnode_t * votes_pool;
  fd_clock_timestamp_vote_t_mapnode_t * votes_root;
};
typedef struct fd_clock_timestamp_votes fd_clock_timestamp_votes_t;
#define FD_CLOCK_TIMESTAMP_VOTES_ALIGN alignof(fd_clock_timestamp_votes_t)

struct fd_clock_timestamp_votes_global {
  ulong votes_pool_offset;
  ulong votes_root_offset;
};
typedef struct fd_clock_timestamp_votes_global fd_clock_timestamp_votes_global_t;
#define FD_CLOCK_TIMESTAMP_VOTES_GLOBAL_ALIGN alignof(fd_clock_timestamp_votes_global_t)

static FD_FN_UNUSED fd_clock_timestamp_vote_t_mapnode_t * fd_clock_timestamp_votes_votes_pool_join( fd_clock_timestamp_votes_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->votes_pool_offset ? (fd_clock_timestamp_vote_t_mapnode_t *)fd_clock_timestamp_vote_t_map_join( fd_type_pun( (uchar *)type + type->votes_pool_offset ) ) : NULL;
}
static FD_FN_UNUSED fd_clock_timestamp_vote_t_mapnode_t * fd_clock_timestamp_votes_votes_root_join( fd_clock_timestamp_votes_global_t const * type ) {
  if( FD_UNLIKELY( !type ) ) return NULL;
  return !!type->votes_root_offset ? (fd_clock_timestamp_vote_t_mapnode_t *)fd_type_pun( (uchar *)type + type->votes_root_offset ) : NULL;
}
static FD_FN_UNUSED void fd_clock_timestamp_votes_votes_pool_update( fd_clock_timestamp_votes_global_t * type, fd_clock_timestamp_vote_t_mapnode_t * pool ) {
  type->votes_pool_offset = !!pool ? (ulong)fd_clock_timestamp_vote_t_map_leave( pool ) - (ulong)type : 0UL;
}
static FD_FN_UNUSED void fd_clock_timestamp_votes_votes_root_update( fd_clock_timestamp_votes_global_t * type, fd_clock_timestamp_vote_t_mapnode_t * root ) {
  type->votes_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;
}
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
  uint128 total_points;
  ulong total_rewards;
  ulong distributed_rewards;
  uchar active;
};
typedef struct fd_sysvar_epoch_rewards fd_sysvar_epoch_rewards_t;
#define FD_SYSVAR_EPOCH_REWARDS_ALIGN alignof(fd_sysvar_epoch_rewards_t)

/* Encoded Size: Fixed (33 bytes) */
struct fd_config_keys_pair {
  fd_pubkey_t key;
  uchar signer;
};
typedef struct fd_config_keys_pair fd_config_keys_pair_t;
#define FD_CONFIG_KEYS_PAIR_ALIGN alignof(fd_config_keys_pair_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/config.rs#L14 */
/* Encoded Size: Dynamic */
struct fd_stake_config {
  ushort config_keys_len;
  fd_config_keys_pair_t * config_keys;
  double warmup_cooldown_rate;
  uchar slash_penalty;
};
typedef struct fd_stake_config fd_stake_config_t;
#define FD_STAKE_CONFIG_ALIGN alignof(fd_stake_config_t)

/* Encoded Size: Dynamic */
struct fd_feature_entry {
  fd_pubkey_t pubkey;
  ulong description_len;
  uchar* description;
  ulong since_slot;
};
typedef struct fd_feature_entry fd_feature_entry_t;
#define FD_FEATURE_ENTRY_ALIGN alignof(fd_feature_entry_t)

struct fd_cluster_type {
  uint discriminant;
};
typedef struct fd_cluster_type fd_cluster_type_t;
#define FD_CLUSTER_TYPE_ALIGN alignof(fd_cluster_type_t)

/* Encoded Size: Fixed (12 bytes) */
struct fd_cluster_version {
  uint major;
  uint minor;
  uint patch;
};
typedef struct fd_cluster_version fd_cluster_version_t;
#define FD_CLUSTER_VERSION_ALIGN alignof(fd_cluster_version_t)

/* Encoded Size: Fixed (49 bytes) */
struct fd_stake_reward {
  ulong prev;
  ulong next;
  ulong parent;
  fd_pubkey_t stake_pubkey;
  ulong credits_observed;
  ulong lamports;
  uchar valid;
};
typedef struct fd_stake_reward fd_stake_reward_t;
#define FD_STAKE_REWARD_ALIGN alignof(fd_stake_reward_t)

/* Encoded Size: Fixed (42 bytes) */
struct fd_vote_reward {
  fd_pubkey_t pubkey;
  ulong vote_rewards;
  uchar commission;
  uchar needs_store;
};
typedef struct fd_vote_reward fd_vote_reward_t;
#define FD_VOTE_REWARD_ALIGN alignof(fd_vote_reward_t)

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L21 */
/* Encoded Size: Fixed (24 bytes) */
struct fd_point_value {
  ulong rewards;
  uint128 points;
};
typedef struct fd_point_value fd_point_value_t;
#define FD_POINT_VALUE_ALIGN alignof(fd_point_value_t)

#define POOL_NAME fd_partitioned_stake_rewards_pool
#define POOL_T fd_stake_reward_t
#define POOL_NEXT parent
#include "../../util/tmpl/fd_pool.c"
static inline fd_stake_reward_t *
fd_partitioned_stake_rewards_pool_join_new( void * * alloc_mem, ulong num ) {
  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_partitioned_stake_rewards_pool_align() );
  void * pool_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_partitioned_stake_rewards_pool_footprint( num );
  return fd_partitioned_stake_rewards_pool_join( fd_partitioned_stake_rewards_pool_new( pool_mem, num ) );
}
#define DLIST_NAME fd_partitioned_stake_rewards_dlist
#define DLIST_ELE_T fd_stake_reward_t
#include "../../util/tmpl/fd_dlist.c"
static inline fd_partitioned_stake_rewards_dlist_t *
fd_partitioned_stake_rewards_dlist_join_new( void * * alloc_mem, ulong num ) {
  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_partitioned_stake_rewards_dlist_align() );
  void * dlist_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_partitioned_stake_rewards_dlist_footprint();
  return fd_partitioned_stake_rewards_dlist_join( fd_partitioned_stake_rewards_dlist_new( dlist_mem ) );
}
/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L56 */
/* Encoded Size: Dynamic */
struct fd_partitioned_stake_rewards {
  ulong partitions_len;
  ulong partitions_lengths[4096];
  fd_partitioned_stake_rewards_dlist_t * partitions;
  fd_stake_reward_t * pool;
};
typedef struct fd_partitioned_stake_rewards fd_partitioned_stake_rewards_t;
#define FD_PARTITIONED_STAKE_REWARDS_ALIGN alignof(fd_partitioned_stake_rewards_t)

struct fd_partitioned_stake_rewards_global {
  ulong partitions_len;
  ulong partitions_lengths[4096];
  ulong partitions_offset;
  ulong pool_offset;
};
typedef struct fd_partitioned_stake_rewards_global fd_partitioned_stake_rewards_global_t;
#define FD_PARTITIONED_STAKE_REWARDS_GLOBAL_ALIGN alignof(fd_partitioned_stake_rewards_global_t)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L131 */
/* Encoded Size: Dynamic */
struct fd_stake_reward_calculation_partitioned {
  fd_partitioned_stake_rewards_t partitioned_stake_rewards;
  ulong total_stake_rewards_lamports;
};
typedef struct fd_stake_reward_calculation_partitioned fd_stake_reward_calculation_partitioned_t;
#define FD_STAKE_REWARD_CALCULATION_PARTITIONED_ALIGN alignof(fd_stake_reward_calculation_partitioned_t)

#define POOL_NAME fd_stake_reward_calculation_pool
#define POOL_T fd_stake_reward_t
#define POOL_NEXT parent
#include "../../util/tmpl/fd_pool.c"
static inline fd_stake_reward_t *
fd_stake_reward_calculation_pool_join_new( void * * alloc_mem, ulong num ) {
  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_stake_reward_calculation_pool_align() );
  void * pool_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_stake_reward_calculation_pool_footprint( num );
  return fd_stake_reward_calculation_pool_join( fd_stake_reward_calculation_pool_new( pool_mem, num ) );
}
#define DLIST_NAME fd_stake_reward_calculation_dlist
#define DLIST_ELE_T fd_stake_reward_t
#include "../../util/tmpl/fd_dlist.c"
static inline fd_stake_reward_calculation_dlist_t *
fd_stake_reward_calculation_dlist_join_new( void * * alloc_mem, ulong num ) {
  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_stake_reward_calculation_dlist_align() );
  void * dlist_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_stake_reward_calculation_dlist_footprint();
  return fd_stake_reward_calculation_dlist_join( fd_stake_reward_calculation_dlist_new( dlist_mem ) );
}
/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L94 */
/* Encoded Size: Dynamic */
struct fd_stake_reward_calculation {
  ulong stake_rewards_len;
  fd_stake_reward_calculation_dlist_t * stake_rewards;
  fd_stake_reward_t * pool;
  ulong total_stake_rewards_lamports;
};
typedef struct fd_stake_reward_calculation fd_stake_reward_calculation_t;
#define FD_STAKE_REWARD_CALCULATION_ALIGN alignof(fd_stake_reward_calculation_t)

typedef struct fd_vote_reward_t_mapnode fd_vote_reward_t_mapnode_t;
#define REDBLK_T fd_vote_reward_t_mapnode_t
#define REDBLK_NAME fd_vote_reward_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_vote_reward_t_mapnode {
    fd_vote_reward_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_vote_reward_t_mapnode_t *
fd_vote_reward_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_vote_reward_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_vote_reward_t_map_footprint( len );
  return fd_vote_reward_t_map_join( fd_vote_reward_t_map_new( map_mem, len ) );
}
/* Encoded Size: Dynamic */
struct fd_calculate_stake_vote_rewards_result {
  fd_stake_reward_calculation_t stake_reward_calculation;
  fd_vote_reward_t_mapnode_t * vote_reward_map_pool;
  fd_vote_reward_t_mapnode_t * vote_reward_map_root;
};
typedef struct fd_calculate_stake_vote_rewards_result fd_calculate_stake_vote_rewards_result_t;
#define FD_CALCULATE_STAKE_VOTE_REWARDS_RESULT_ALIGN alignof(fd_calculate_stake_vote_rewards_result_t)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L102 */
/* Encoded Size: Dynamic */
struct fd_calculate_validator_rewards_result {
  fd_calculate_stake_vote_rewards_result_t calculate_stake_vote_rewards_result;
  fd_point_value_t point_value;
};
typedef struct fd_calculate_validator_rewards_result fd_calculate_validator_rewards_result_t;
#define FD_CALCULATE_VALIDATOR_REWARDS_RESULT_ALIGN alignof(fd_calculate_validator_rewards_result_t)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L118 */
/* Encoded Size: Dynamic */
struct fd_partitioned_rewards_calculation {
  fd_vote_reward_t_mapnode_t * vote_reward_map_pool;
  fd_vote_reward_t_mapnode_t * vote_reward_map_root;
  fd_stake_reward_calculation_partitioned_t stake_rewards_by_partition;
  ulong old_vote_balance_and_staked;
  ulong validator_rewards;
  double validator_rate;
  double foundation_rate;
  double prev_epoch_duration_in_years;
  ulong capitalization;
  fd_point_value_t point_value;
};
typedef struct fd_partitioned_rewards_calculation fd_partitioned_rewards_calculation_t;
#define FD_PARTITIONED_REWARDS_CALCULATION_ALIGN alignof(fd_partitioned_rewards_calculation_t)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L60 */
/* Encoded Size: Dynamic */
struct fd_start_block_height_and_rewards {
  ulong distribution_starting_block_height;
  fd_partitioned_stake_rewards_t partitioned_stake_rewards;
};
typedef struct fd_start_block_height_and_rewards fd_start_block_height_and_rewards_t;
#define FD_START_BLOCK_HEIGHT_AND_REWARDS_ALIGN alignof(fd_start_block_height_and_rewards_t)

struct fd_start_block_height_and_rewards_global {
  ulong distribution_starting_block_height;
  fd_partitioned_stake_rewards_global_t partitioned_stake_rewards;
};
typedef struct fd_start_block_height_and_rewards_global fd_start_block_height_and_rewards_global_t;
#define FD_START_BLOCK_HEIGHT_AND_REWARDS_GLOBAL_ALIGN alignof(fd_start_block_height_and_rewards_global_t)

/* Encoded Size: Dynamic */
struct fd_fd_epoch_reward_status_inner {
  fd_start_block_height_and_rewards_t Active;
};
typedef struct fd_fd_epoch_reward_status_inner fd_fd_epoch_reward_status_inner_t;
#define FD_FD_EPOCH_REWARD_STATUS_INNER_ALIGN alignof(fd_fd_epoch_reward_status_inner_t)

union fd_epoch_reward_status_inner {
  fd_start_block_height_and_rewards_t Active;
};
typedef union fd_epoch_reward_status_inner fd_epoch_reward_status_inner_t;

union fd_epoch_reward_status_inner_global {
  fd_start_block_height_and_rewards_global_t Active;
};
typedef union fd_epoch_reward_status_inner_global fd_epoch_reward_status_inner_global_t;

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L70 */
struct fd_epoch_reward_status {
  uint discriminant;
  fd_epoch_reward_status_inner_t inner;
};
typedef struct fd_epoch_reward_status fd_epoch_reward_status_t;
#define FD_EPOCH_REWARD_STATUS_ALIGN alignof(fd_epoch_reward_status_t)
struct fd_epoch_reward_status_global {
  uint discriminant;
  fd_epoch_reward_status_inner_global_t inner;
};
typedef struct fd_epoch_reward_status_global fd_epoch_reward_status_global_t;
#define FD_EPOCH_REWARD_STATUS_GLOBAL_ALIGN alignof(fd_epoch_reward_status_global_t)

/* Encoded Size: Fixed (32 bytes) */
struct fd_prev_epoch_inflation_rewards {
  ulong validator_rewards;
  double prev_epoch_duration_in_years;
  double validator_rate;
  double foundation_rate;
};
typedef struct fd_prev_epoch_inflation_rewards fd_prev_epoch_inflation_rewards_t;
#define FD_PREV_EPOCH_INFLATION_REWARDS_ALIGN alignof(fd_prev_epoch_inflation_rewards_t)

#define DEQUE_NAME deq_ulong
#define DEQUE_T ulong
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline ulong *
deq_ulong_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_ulong_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_ulong_footprint( max );
  return deq_ulong_join( deq_ulong_new( deque_mem, max ) );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L133 */
/* Encoded Size: Dynamic */
struct fd_vote {
  ulong * slots; /* fd_deque_dynamic */
  fd_hash_t hash;
  long* timestamp;
};
typedef struct fd_vote fd_vote_t;
#define FD_VOTE_ALIGN alignof(fd_vote_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L230 */
/* Encoded Size: Fixed (97 bytes) */
struct fd_vote_init {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_voter;
  fd_pubkey_t authorized_withdrawer;
  uchar commission;
};
typedef struct fd_vote_init fd_vote_init_t;
#define FD_VOTE_INIT_ALIGN alignof(fd_vote_init_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L238 */
struct fd_vote_authorize {
  uint discriminant;
};
typedef struct fd_vote_authorize fd_vote_authorize_t;
#define FD_VOTE_AUTHORIZE_ALIGN alignof(fd_vote_authorize_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L37 */
/* Encoded Size: Fixed (36 bytes) */
struct fd_vote_authorize_pubkey {
  fd_pubkey_t pubkey;
  fd_vote_authorize_t vote_authorize;
};
typedef struct fd_vote_authorize_pubkey fd_vote_authorize_pubkey_t;
#define FD_VOTE_AUTHORIZE_PUBKEY_ALIGN alignof(fd_vote_authorize_pubkey_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L78 */
/* Encoded Size: Dynamic */
struct fd_vote_switch {
  fd_vote_t vote;
  fd_hash_t hash;
};
typedef struct fd_vote_switch fd_vote_switch_t;
#define FD_VOTE_SWITCH_ALIGN alignof(fd_vote_switch_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L104 */
/* Encoded Size: Dynamic */
struct fd_update_vote_state_switch {
  fd_vote_state_update_t vote_state_update;
  fd_hash_t hash;
};
typedef struct fd_update_vote_state_switch fd_update_vote_state_switch_t;
#define FD_UPDATE_VOTE_STATE_SWITCH_ALIGN alignof(fd_update_vote_state_switch_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L244 */
/* Encoded Size: Dynamic */
struct fd_vote_authorize_with_seed_args {
  fd_vote_authorize_t authorization_type;
  fd_pubkey_t current_authority_derived_key_owner;
  ulong current_authority_derived_key_seed_len;
  uchar* current_authority_derived_key_seed;
  fd_pubkey_t new_authority;
};
typedef struct fd_vote_authorize_with_seed_args fd_vote_authorize_with_seed_args_t;
#define FD_VOTE_AUTHORIZE_WITH_SEED_ARGS_ALIGN alignof(fd_vote_authorize_with_seed_args_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L252 */
/* Encoded Size: Dynamic */
struct fd_vote_authorize_checked_with_seed_args {
  fd_vote_authorize_t authorization_type;
  fd_pubkey_t current_authority_derived_key_owner;
  ulong current_authority_derived_key_seed_len;
  uchar* current_authority_derived_key_seed;
};
typedef struct fd_vote_authorize_checked_with_seed_args fd_vote_authorize_checked_with_seed_args_t;
#define FD_VOTE_AUTHORIZE_CHECKED_WITH_SEED_ARGS_ALIGN alignof(fd_vote_authorize_checked_with_seed_args_t)

union fd_vote_instruction_inner {
  fd_vote_init_t initialize_account;
  fd_vote_authorize_pubkey_t authorize;
  fd_vote_t vote;
  ulong withdraw;
  uchar update_commission;
  fd_vote_switch_t vote_switch;
  fd_vote_authorize_t authorize_checked;
  fd_vote_state_update_t update_vote_state;
  fd_update_vote_state_switch_t update_vote_state_switch;
  fd_vote_authorize_with_seed_args_t authorize_with_seed;
  fd_vote_authorize_checked_with_seed_args_t authorize_checked_with_seed;
  fd_compact_vote_state_update_t compact_update_vote_state;
  fd_compact_vote_state_update_switch_t compact_update_vote_state_switch;
  fd_tower_sync_t tower_sync;
  fd_tower_sync_switch_t tower_sync_switch;
};
typedef union fd_vote_instruction_inner fd_vote_instruction_inner_t;

/* https://github.com/firedancer-io/solana/blob/53a4e5d6c58b2ffe89b09304e4437f8ca198dadd/programs/vote/src/vote_instruction.rs#L21 */
struct fd_vote_instruction {
  uint discriminant;
  fd_vote_instruction_inner_t inner;
};
typedef struct fd_vote_instruction fd_vote_instruction_t;
#define FD_VOTE_INSTRUCTION_ALIGN alignof(fd_vote_instruction_t)

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
};
typedef union fd_system_program_instruction_inner fd_system_program_instruction_inner_t;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/system_instruction.rs#L152 */
struct fd_system_program_instruction {
  uint discriminant;
  fd_system_program_instruction_inner_t inner;
};
typedef struct fd_system_program_instruction fd_system_program_instruction_t;
#define FD_SYSTEM_PROGRAM_INSTRUCTION_ALIGN alignof(fd_system_program_instruction_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/system_instruction.rs#L16 */
struct fd_system_error {
  uint discriminant;
};
typedef struct fd_system_error fd_system_error_t;
#define FD_SYSTEM_ERROR_ALIGN alignof(fd_system_error_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/state.rs#L169 */
/* Encoded Size: Fixed (64 bytes) */
struct fd_stake_authorized {
  fd_pubkey_t staker;
  fd_pubkey_t withdrawer;
};
typedef struct fd_stake_authorized fd_stake_authorized_t;
#define FD_STAKE_AUTHORIZED_ALIGN alignof(fd_stake_authorized_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/state.rs#L135 */
/* Encoded Size: Fixed (48 bytes) */
struct fd_stake_lockup {
  long unix_timestamp;
  ulong epoch;
  fd_pubkey_t custodian;
};
typedef struct fd_stake_lockup fd_stake_lockup_t;
#define FD_STAKE_LOCKUP_ALIGN alignof(fd_stake_lockup_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/instruction.rs#L68 */
/* Encoded Size: Fixed (112 bytes) */
struct fd_stake_instruction_initialize {
  fd_stake_authorized_t authorized;
  fd_stake_lockup_t lockup;
};
typedef struct fd_stake_instruction_initialize fd_stake_instruction_initialize_t;
#define FD_STAKE_INSTRUCTION_INITIALIZE_ALIGN alignof(fd_stake_instruction_initialize_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/instruction.rs#L78 */
/* Encoded Size: Dynamic */
struct fd_stake_lockup_custodian_args {
  fd_stake_lockup_t lockup;
  fd_sol_sysvar_clock_t clock;
  fd_pubkey_t * custodian;
};
typedef struct fd_stake_lockup_custodian_args fd_stake_lockup_custodian_args_t;
#define FD_STAKE_LOCKUP_CUSTODIAN_ARGS_ALIGN alignof(fd_stake_lockup_custodian_args_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/state.rs#L117 */
struct fd_stake_authorize {
  uint discriminant;
};
typedef struct fd_stake_authorize fd_stake_authorize_t;
#define FD_STAKE_AUTHORIZE_ALIGN alignof(fd_stake_authorize_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/instruction.rs#L78 */
/* Encoded Size: Fixed (36 bytes) */
struct fd_stake_instruction_authorize {
  fd_pubkey_t pubkey;
  fd_stake_authorize_t stake_authorize;
};
typedef struct fd_stake_instruction_authorize fd_stake_instruction_authorize_t;
#define FD_STAKE_INSTRUCTION_AUTHORIZE_ALIGN alignof(fd_stake_instruction_authorize_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/instruction.rs#L241 */
/* Encoded Size: Dynamic */
struct fd_authorize_with_seed_args {
  fd_pubkey_t new_authorized_pubkey;
  fd_stake_authorize_t stake_authorize;
  ulong authority_seed_len;
  uchar* authority_seed;
  fd_pubkey_t authority_owner;
};
typedef struct fd_authorize_with_seed_args fd_authorize_with_seed_args_t;
#define FD_AUTHORIZE_WITH_SEED_ARGS_ALIGN alignof(fd_authorize_with_seed_args_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/instruction.rs#L249 */
/* Encoded Size: Dynamic */
struct fd_authorize_checked_with_seed_args {
  fd_stake_authorize_t stake_authorize;
  ulong authority_seed_len;
  uchar* authority_seed;
  fd_pubkey_t authority_owner;
};
typedef struct fd_authorize_checked_with_seed_args fd_authorize_checked_with_seed_args_t;
#define FD_AUTHORIZE_CHECKED_WITH_SEED_ARGS_ALIGN alignof(fd_authorize_checked_with_seed_args_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/instruction.rs#L235 */
/* Encoded Size: Dynamic */
struct fd_lockup_checked_args {
  long* unix_timestamp;
  ulong* epoch;
};
typedef struct fd_lockup_checked_args fd_lockup_checked_args_t;
#define FD_LOCKUP_CHECKED_ARGS_ALIGN alignof(fd_lockup_checked_args_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/instruction.rs#L228 */
/* Encoded Size: Dynamic */
struct fd_lockup_args {
  long* unix_timestamp;
  ulong* epoch;
  fd_pubkey_t * custodian;
};
typedef struct fd_lockup_args fd_lockup_args_t;
#define FD_LOCKUP_ARGS_ALIGN alignof(fd_lockup_args_t)

union fd_stake_instruction_inner {
  fd_stake_instruction_initialize_t initialize;
  fd_stake_instruction_authorize_t authorize;
  ulong split;
  ulong withdraw;
  fd_lockup_args_t set_lockup;
  fd_authorize_with_seed_args_t authorize_with_seed;
  fd_stake_authorize_t authorize_checked;
  fd_authorize_checked_with_seed_args_t authorize_checked_with_seed;
  fd_lockup_checked_args_t set_lockup_checked;
  ulong move_stake;
  ulong move_lamports;
};
typedef union fd_stake_instruction_inner fd_stake_instruction_inner_t;

/* https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/sdk/program/src/stake/instruction.rs#L96 */
struct fd_stake_instruction {
  uint discriminant;
  fd_stake_instruction_inner_t inner;
};
typedef struct fd_stake_instruction fd_stake_instruction_t;
#define FD_STAKE_INSTRUCTION_ALIGN alignof(fd_stake_instruction_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/state.rs#L248 */
/* Encoded Size: Fixed (120 bytes) */
struct fd_stake_meta {
  ulong rent_exempt_reserve;
  fd_stake_authorized_t authorized;
  fd_stake_lockup_t lockup;
};
typedef struct fd_stake_meta fd_stake_meta_t;
#define FD_STAKE_META_ALIGN alignof(fd_stake_meta_t)

/* https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/stake_flags.rs#L21 */
/* Encoded Size: Fixed (1 bytes) */
struct fd_stake_flags {
  uchar bits;
};
typedef struct fd_stake_flags fd_stake_flags_t;
#define FD_STAKE_FLAGS_ALIGN alignof(fd_stake_flags_t)

/* https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L135 */
/* Encoded Size: Fixed (120 bytes) */
struct fd_stake_state_v2_initialized {
  fd_stake_meta_t meta;
};
typedef struct fd_stake_state_v2_initialized fd_stake_state_v2_initialized_t;
#define FD_STAKE_STATE_V2_INITIALIZED_ALIGN alignof(fd_stake_state_v2_initialized_t)

/* https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L136 */
/* Encoded Size: Fixed (193 bytes) */
struct fd_stake_state_v2_stake {
  fd_stake_meta_t meta;
  fd_stake_t stake;
  fd_stake_flags_t stake_flags;
};
typedef struct fd_stake_state_v2_stake fd_stake_state_v2_stake_t;
#define FD_STAKE_STATE_V2_STAKE_ALIGN alignof(fd_stake_state_v2_stake_t)

union fd_stake_state_v2_inner {
  fd_stake_state_v2_initialized_t initialized;
  fd_stake_state_v2_stake_t stake;
};
typedef union fd_stake_state_v2_inner fd_stake_state_v2_inner_t;

/* https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L132 */
struct fd_stake_state_v2 {
  uint discriminant;
  fd_stake_state_v2_inner_t inner;
};
typedef struct fd_stake_state_v2 fd_stake_state_v2_t;
#define FD_STAKE_STATE_V2_ALIGN alignof(fd_stake_state_v2_t)

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

/* https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/lib.rs#L32 */
/* Encoded Size: Dynamic */
struct fd_config_keys {
  ushort keys_len;
  fd_config_keys_pair_t * keys;
};
typedef struct fd_config_keys fd_config_keys_t;
#define FD_CONFIG_KEYS_ALIGN alignof(fd_config_keys_t)

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

/* https://github.com/firedancer-io/solana/blob/f4b7c54f9e021b40cfc7cbd32dc12b19dedbe791/ledger/src/blockstore_meta.rs#L178 */
/* Encoded Size: Fixed (33 bytes) */
struct fd_frozen_hash_status {
  fd_hash_t frozen_hash;
  uchar is_duplicate_confirmed;
};
typedef struct fd_frozen_hash_status fd_frozen_hash_status_t;
#define FD_FROZEN_HASH_STATUS_ALIGN alignof(fd_frozen_hash_status_t)

union fd_frozen_hash_versioned_inner {
  fd_frozen_hash_status_t current;
};
typedef union fd_frozen_hash_versioned_inner fd_frozen_hash_versioned_inner_t;

/* https://github.com/firedancer-io/solana/blob/f4b7c54f9e021b40cfc7cbd32dc12b19dedbe791/ledger/src/blockstore_meta.rs#L157 */
struct fd_frozen_hash_versioned {
  uint discriminant;
  fd_frozen_hash_versioned_inner_t inner;
};
typedef struct fd_frozen_hash_versioned fd_frozen_hash_versioned_t;
#define FD_FROZEN_HASH_VERSIONED_ALIGN alignof(fd_frozen_hash_versioned_t)

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

/* https://github.com/solana-labs/solana/blob/52616cf7aa424a80f770e5ec3f2cd49d1cfeb845/gossip/src/ping_pong.rs#L22 */
/* Encoded Size: Fixed (128 bytes) */
struct fd_gossip_ping {
  fd_pubkey_t from;
  fd_hash_t token;
  fd_signature_t signature;
};
typedef struct fd_gossip_ping fd_gossip_ping_t;
#define FD_GOSSIP_PING_ALIGN alignof(fd_gossip_ping_t)

union fd_gossip_ip_addr_inner {
  fd_gossip_ip4_addr_t ip4;
  fd_gossip_ip6_addr_t ip6;
};
typedef union fd_gossip_ip_addr_inner fd_gossip_ip_addr_inner_t;

/* https://doc.rust-lang.org/beta/src/core/net/socket_addr.rs.html#33 */
struct fd_gossip_ip_addr {
  uint discriminant;
  fd_gossip_ip_addr_inner_t inner;
};
typedef struct fd_gossip_ip_addr fd_gossip_ip_addr_t;
#define FD_GOSSIP_IP_ADDR_ALIGN alignof(fd_gossip_ip_addr_t)

/* Encoded Size: Dynamic */
struct fd_gossip_prune_data {
  fd_pubkey_t pubkey;
  ulong prunes_len;
  fd_pubkey_t * prunes;
  fd_signature_t signature;
  fd_pubkey_t destination;
  ulong wallclock;
};
typedef struct fd_gossip_prune_data fd_gossip_prune_data_t;
#define FD_GOSSIP_PRUNE_DATA_ALIGN alignof(fd_gossip_prune_data_t)

/* Encoded Size: Dynamic */
struct fd_gossip_prune_sign_data {
  fd_pubkey_t pubkey;
  ulong prunes_len;
  fd_pubkey_t * prunes;
  fd_pubkey_t destination;
  ulong wallclock;
};
typedef struct fd_gossip_prune_sign_data fd_gossip_prune_sign_data_t;
#define FD_GOSSIP_PRUNE_SIGN_DATA_ALIGN alignof(fd_gossip_prune_sign_data_t)

/* Encoded Size: Dynamic */
struct fd_gossip_prune_sign_data_with_prefix {
  ulong prefix_len;
  uchar* prefix;
  fd_gossip_prune_sign_data_t data;
};
typedef struct fd_gossip_prune_sign_data_with_prefix fd_gossip_prune_sign_data_with_prefix_t;
#define FD_GOSSIP_PRUNE_SIGN_DATA_WITH_PREFIX_ALIGN alignof(fd_gossip_prune_sign_data_with_prefix_t)

/* Encoded Size: Dynamic */
struct fd_gossip_socket_addr_old {
  fd_gossip_ip_addr_t addr;
  ushort port;
};
typedef struct fd_gossip_socket_addr_old fd_gossip_socket_addr_old_t;
#define FD_GOSSIP_SOCKET_ADDR_OLD_ALIGN alignof(fd_gossip_socket_addr_old_t)

/* Encoded Size: Dynamic */
struct fd_gossip_socket_addr_ip4 {
  fd_gossip_ip4_addr_t addr;
  ushort port;
};
typedef struct fd_gossip_socket_addr_ip4 fd_gossip_socket_addr_ip4_t;
#define FD_GOSSIP_SOCKET_ADDR_IP4_ALIGN alignof(fd_gossip_socket_addr_ip4_t)

/* https://doc.rust-lang.org/beta/src/core/net/socket_addr.rs.html#147 */
/* Encoded Size: Fixed (18 bytes) */
struct fd_gossip_socket_addr_ip6 {
  fd_gossip_ip6_addr_t addr;
  ushort port;
};
typedef struct fd_gossip_socket_addr_ip6 fd_gossip_socket_addr_ip6_t;
#define FD_GOSSIP_SOCKET_ADDR_IP6_ALIGN alignof(fd_gossip_socket_addr_ip6_t)

union fd_gossip_socket_addr_inner {
  fd_gossip_socket_addr_ip4_t ip4;
  fd_gossip_socket_addr_ip6_t ip6;
};
typedef union fd_gossip_socket_addr_inner fd_gossip_socket_addr_inner_t;

/* https://doc.rust-lang.org/beta/src/core/net/socket_addr.rs.html#33 */
struct fd_gossip_socket_addr {
  uint discriminant;
  fd_gossip_socket_addr_inner_t inner;
};
typedef struct fd_gossip_socket_addr fd_gossip_socket_addr_t;
#define FD_GOSSIP_SOCKET_ADDR_ALIGN alignof(fd_gossip_socket_addr_t)

/* https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/legacy_contact_info.rs#L14 */
/* Encoded Size: Dynamic */
struct fd_gossip_contact_info_v1 {
  fd_pubkey_t id;
  fd_gossip_socket_addr_t gossip;
  fd_gossip_socket_addr_t tvu;
  fd_gossip_socket_addr_t tvu_fwd;
  fd_gossip_socket_addr_t repair;
  fd_gossip_socket_addr_t tpu;
  fd_gossip_socket_addr_t tpu_fwd;
  fd_gossip_socket_addr_t tpu_vote;
  fd_gossip_socket_addr_t rpc;
  fd_gossip_socket_addr_t rpc_pubsub;
  fd_gossip_socket_addr_t serve_repair;
  ulong wallclock;
  ushort shred_version;
};
typedef struct fd_gossip_contact_info_v1 fd_gossip_contact_info_v1_t;
#define FD_GOSSIP_CONTACT_INFO_V1_ALIGN alignof(fd_gossip_contact_info_v1_t)

/* Encoded Size: Dynamic */
struct fd_gossip_vote {
  uchar index;
  fd_pubkey_t from;
  fd_flamenco_txn_t txn;
  ulong wallclock;
};
typedef struct fd_gossip_vote fd_gossip_vote_t;
#define FD_GOSSIP_VOTE_ALIGN alignof(fd_gossip_vote_t)

struct fd_gossip_deprecated_compression_type {
  uint discriminant;
};
typedef struct fd_gossip_deprecated_compression_type fd_gossip_deprecated_compression_type_t;
#define FD_GOSSIP_DEPRECATED_COMPRESSION_TYPE_ALIGN alignof(fd_gossip_deprecated_compression_type_t)

/* Encoded Size: Dynamic */
struct fd_gossip_deprecated_epoch_incomplete_slots {
  ulong first;
  fd_gossip_deprecated_compression_type_t compression;
  ulong compressed_list_len;
  uchar* compressed_list;
};
typedef struct fd_gossip_deprecated_epoch_incomplete_slots fd_gossip_deprecated_epoch_incomplete_slots_t;
#define FD_GOSSIP_DEPRECATED_EPOCH_INCOMPLETE_SLOTS_ALIGN alignof(fd_gossip_deprecated_epoch_incomplete_slots_t)

/* Encoded Size: Dynamic */
struct fd_gossip_lowest_slot {
  uchar u8;
  fd_pubkey_t from;
  ulong root;
  ulong lowest;
  ulong slots_len;
  ulong* slots;
  ulong stash_len;
  fd_gossip_deprecated_epoch_incomplete_slots_t * stash;
  ulong wallclock;
};
typedef struct fd_gossip_lowest_slot fd_gossip_lowest_slot_t;
#define FD_GOSSIP_LOWEST_SLOT_ALIGN alignof(fd_gossip_lowest_slot_t)

/* Encoded Size: Dynamic */
struct fd_gossip_slot_hashes {
  fd_pubkey_t from;
  ulong hashes_len;
  fd_slot_hash_t * hashes;
  ulong wallclock;
};
typedef struct fd_gossip_slot_hashes fd_gossip_slot_hashes_t;
#define FD_GOSSIP_SLOT_HASHES_ALIGN alignof(fd_gossip_slot_hashes_t)

/* Encoded Size: Dynamic */
struct fd_gossip_slots {
  ulong first_slot;
  ulong num;
  uchar has_slots;
  ulong slots_bitvec_len;
  uchar* slots_bitvec;
  ulong slots_len;
};
typedef struct fd_gossip_slots fd_gossip_slots_t;
#define FD_GOSSIP_SLOTS_ALIGN alignof(fd_gossip_slots_t)

/* Encoded Size: Dynamic */
struct fd_gossip_flate2_slots {
  ulong first_slot;
  ulong num;
  ulong compressed_len;
  uchar* compressed;
};
typedef struct fd_gossip_flate2_slots fd_gossip_flate2_slots_t;
#define FD_GOSSIP_FLATE2_SLOTS_ALIGN alignof(fd_gossip_flate2_slots_t)

union fd_gossip_slots_enum_inner {
  fd_gossip_flate2_slots_t flate2;
  fd_gossip_slots_t uncompressed;
};
typedef union fd_gossip_slots_enum_inner fd_gossip_slots_enum_inner_t;

struct fd_gossip_slots_enum {
  uint discriminant;
  fd_gossip_slots_enum_inner_t inner;
};
typedef struct fd_gossip_slots_enum fd_gossip_slots_enum_t;
#define FD_GOSSIP_SLOTS_ENUM_ALIGN alignof(fd_gossip_slots_enum_t)

/* Encoded Size: Dynamic */
struct fd_gossip_epoch_slots {
  uchar u8;
  fd_pubkey_t from;
  ulong slots_len;
  fd_gossip_slots_enum_t * slots;
  ulong wallclock;
};
typedef struct fd_gossip_epoch_slots fd_gossip_epoch_slots_t;
#define FD_GOSSIP_EPOCH_SLOTS_ALIGN alignof(fd_gossip_epoch_slots_t)

/* Encoded Size: Dynamic */
struct fd_gossip_version_v1 {
  fd_pubkey_t from;
  ulong wallclock;
  ushort major;
  ushort minor;
  ushort patch;
  uint commit;
  uchar has_commit;
};
typedef struct fd_gossip_version_v1 fd_gossip_version_v1_t;
#define FD_GOSSIP_VERSION_V1_ALIGN alignof(fd_gossip_version_v1_t)

/* Encoded Size: Dynamic */
struct fd_gossip_version_v2 {
  fd_pubkey_t from;
  ulong wallclock;
  ushort major;
  ushort minor;
  ushort patch;
  uint commit;
  uchar has_commit;
  uint feature_set;
};
typedef struct fd_gossip_version_v2 fd_gossip_version_v2_t;
#define FD_GOSSIP_VERSION_V2_ALIGN alignof(fd_gossip_version_v2_t)

/* Encoded Size: Dynamic */
struct fd_gossip_version_v3 {
  ushort major;
  ushort minor;
  ushort patch;
  uint commit;
  uint feature_set;
  ushort client;
};
typedef struct fd_gossip_version_v3 fd_gossip_version_v3_t;
#define FD_GOSSIP_VERSION_V3_ALIGN alignof(fd_gossip_version_v3_t)

/* Encoded Size: Fixed (56 bytes) */
struct fd_gossip_node_instance {
  fd_pubkey_t from;
  ulong wallclock;
  ulong timestamp;
  ulong token;
};
typedef struct fd_gossip_node_instance fd_gossip_node_instance_t;
#define FD_GOSSIP_NODE_INSTANCE_ALIGN alignof(fd_gossip_node_instance_t)

/* https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/duplicate_shred.rs#L25 */
/* Encoded Size: Dynamic */
struct fd_gossip_duplicate_shred {
  ushort duplicate_shred_index;
  fd_pubkey_t from;
  ulong wallclock;
  ulong slot;
  uint _unused;
  uchar _unused_shred_type;
  uchar num_chunks;
  uchar chunk_index;
  ulong chunk_len;
  uchar* chunk;
};
typedef struct fd_gossip_duplicate_shred fd_gossip_duplicate_shred_t;
#define FD_GOSSIP_DUPLICATE_SHRED_ALIGN alignof(fd_gossip_duplicate_shred_t)

/* Encoded Size: Dynamic */
struct fd_gossip_incremental_snapshot_hashes {
  fd_pubkey_t from;
  fd_slot_hash_t base_hash;
  ulong hashes_len;
  fd_slot_hash_t * hashes;
  ulong wallclock;
};
typedef struct fd_gossip_incremental_snapshot_hashes fd_gossip_incremental_snapshot_hashes_t;
#define FD_GOSSIP_INCREMENTAL_SNAPSHOT_HASHES_ALIGN alignof(fd_gossip_incremental_snapshot_hashes_t)

/* Encoded Size: Dynamic */
struct fd_gossip_socket_entry {
  uchar key;
  uchar index;
  ushort offset;
};
typedef struct fd_gossip_socket_entry fd_gossip_socket_entry_t;
#define FD_GOSSIP_SOCKET_ENTRY_ALIGN alignof(fd_gossip_socket_entry_t)

/* https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/contact_info.rs#L85 */
/* Encoded Size: Dynamic */
struct fd_gossip_contact_info_v2 {
  fd_pubkey_t from;
  ulong wallclock;
  ulong outset;
  ushort shred_version;
  fd_gossip_version_v3_t version;
  ushort addrs_len;
  fd_gossip_ip_addr_t * addrs;
  ushort sockets_len;
  fd_gossip_socket_entry_t * sockets;
  ushort extensions_len;
  uint* extensions;
};
typedef struct fd_gossip_contact_info_v2 fd_gossip_contact_info_v2_t;
#define FD_GOSSIP_CONTACT_INFO_V2_ALIGN alignof(fd_gossip_contact_info_v2_t)

/* Encoded Size: Dynamic */
struct fd_restart_run_length_encoding_inner {
  ushort bits;
};
typedef struct fd_restart_run_length_encoding_inner fd_restart_run_length_encoding_inner_t;
#define FD_RESTART_RUN_LENGTH_ENCODING_INNER_ALIGN alignof(fd_restart_run_length_encoding_inner_t)

/* Encoded Size: Dynamic */
struct fd_restart_run_length_encoding {
  ulong offsets_len;
  fd_restart_run_length_encoding_inner_t * offsets;
};
typedef struct fd_restart_run_length_encoding fd_restart_run_length_encoding_t;
#define FD_RESTART_RUN_LENGTH_ENCODING_ALIGN alignof(fd_restart_run_length_encoding_t)

/* Encoded Size: Dynamic */
struct fd_restart_raw_offsets {
  uchar has_offsets;
  ulong offsets_bitvec_len;
  uchar* offsets_bitvec;
  ulong offsets_len;
};
typedef struct fd_restart_raw_offsets fd_restart_raw_offsets_t;
#define FD_RESTART_RAW_OFFSETS_ALIGN alignof(fd_restart_raw_offsets_t)

union fd_restart_slots_offsets_inner {
  fd_restart_run_length_encoding_t run_length_encoding;
  fd_restart_raw_offsets_t raw_offsets;
};
typedef union fd_restart_slots_offsets_inner fd_restart_slots_offsets_inner_t;

struct fd_restart_slots_offsets {
  uint discriminant;
  fd_restart_slots_offsets_inner_t inner;
};
typedef struct fd_restart_slots_offsets fd_restart_slots_offsets_t;
#define FD_RESTART_SLOTS_OFFSETS_ALIGN alignof(fd_restart_slots_offsets_t)

/* Encoded Size: Dynamic */
struct fd_gossip_restart_last_voted_fork_slots {
  fd_pubkey_t from;
  ulong wallclock;
  fd_restart_slots_offsets_t offsets;
  ulong last_voted_slot;
  fd_hash_t last_voted_hash;
  ushort shred_version;
};
typedef struct fd_gossip_restart_last_voted_fork_slots fd_gossip_restart_last_voted_fork_slots_t;
#define FD_GOSSIP_RESTART_LAST_VOTED_FORK_SLOTS_ALIGN alignof(fd_gossip_restart_last_voted_fork_slots_t)

/* Encoded Size: Fixed (90 bytes) */
struct fd_gossip_restart_heaviest_fork {
  fd_pubkey_t from;
  ulong wallclock;
  ulong last_slot;
  fd_hash_t last_slot_hash;
  ulong observed_stake;
  ushort shred_version;
};
typedef struct fd_gossip_restart_heaviest_fork fd_gossip_restart_heaviest_fork_t;
#define FD_GOSSIP_RESTART_HEAVIEST_FORK_ALIGN alignof(fd_gossip_restart_heaviest_fork_t)

union fd_crds_data_inner {
  fd_gossip_contact_info_v1_t contact_info_v1;
  fd_gossip_vote_t vote;
  fd_gossip_lowest_slot_t lowest_slot;
  fd_gossip_slot_hashes_t snapshot_hashes;
  fd_gossip_slot_hashes_t accounts_hashes;
  fd_gossip_epoch_slots_t epoch_slots;
  fd_gossip_version_v1_t version_v1;
  fd_gossip_version_v2_t version_v2;
  fd_gossip_node_instance_t node_instance;
  fd_gossip_duplicate_shred_t duplicate_shred;
  fd_gossip_incremental_snapshot_hashes_t incremental_snapshot_hashes;
  fd_gossip_contact_info_v2_t contact_info_v2;
  fd_gossip_restart_last_voted_fork_slots_t restart_last_voted_fork_slots;
  fd_gossip_restart_heaviest_fork_t restart_heaviest_fork;
};
typedef union fd_crds_data_inner fd_crds_data_inner_t;

struct fd_crds_data {
  uint discriminant;
  fd_crds_data_inner_t inner;
};
typedef struct fd_crds_data fd_crds_data_t;
#define FD_CRDS_DATA_ALIGN alignof(fd_crds_data_t)

/* https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/bloom/src/bloom.rs#L26 */
/* Encoded Size: Dynamic */
struct fd_crds_bloom {
  ulong keys_len;
  ulong* keys;
  uchar has_bits;
  ulong bits_bitvec_len;
  ulong* bits_bitvec;
  ulong bits_len;
  ulong num_bits_set;
};
typedef struct fd_crds_bloom fd_crds_bloom_t;
#define FD_CRDS_BLOOM_ALIGN alignof(fd_crds_bloom_t)

/* https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/crds_gossip_pull.rs#L60 */
/* Encoded Size: Dynamic */
struct fd_crds_filter {
  fd_crds_bloom_t filter;
  ulong mask;
  uint mask_bits;
};
typedef struct fd_crds_filter fd_crds_filter_t;
#define FD_CRDS_FILTER_ALIGN alignof(fd_crds_filter_t)

/* Encoded Size: Dynamic */
struct fd_crds_value {
  fd_signature_t signature;
  fd_crds_data_t data;
};
typedef struct fd_crds_value fd_crds_value_t;
#define FD_CRDS_VALUE_ALIGN alignof(fd_crds_value_t)

/* Encoded Size: Dynamic */
struct fd_gossip_pull_req {
  fd_crds_filter_t filter;
  fd_crds_value_t value;
};
typedef struct fd_gossip_pull_req fd_gossip_pull_req_t;
#define FD_GOSSIP_PULL_REQ_ALIGN alignof(fd_gossip_pull_req_t)

/* Encoded Size: Dynamic */
struct fd_gossip_pull_resp {
  fd_pubkey_t pubkey;
  ulong crds_len;
  fd_crds_value_t * crds;
};
typedef struct fd_gossip_pull_resp fd_gossip_pull_resp_t;
#define FD_GOSSIP_PULL_RESP_ALIGN alignof(fd_gossip_pull_resp_t)

/* Encoded Size: Dynamic */
struct fd_gossip_push_msg {
  fd_pubkey_t pubkey;
  ulong crds_len;
  fd_crds_value_t * crds;
};
typedef struct fd_gossip_push_msg fd_gossip_push_msg_t;
#define FD_GOSSIP_PUSH_MSG_ALIGN alignof(fd_gossip_push_msg_t)

/* Encoded Size: Dynamic */
struct fd_gossip_prune_msg {
  fd_pubkey_t pubkey;
  fd_gossip_prune_data_t data;
};
typedef struct fd_gossip_prune_msg fd_gossip_prune_msg_t;
#define FD_GOSSIP_PRUNE_MSG_ALIGN alignof(fd_gossip_prune_msg_t)

union fd_gossip_msg_inner {
  fd_gossip_pull_req_t pull_req;
  fd_gossip_pull_resp_t pull_resp;
  fd_gossip_push_msg_t push_msg;
  fd_gossip_prune_msg_t prune_msg;
  fd_gossip_ping_t ping;
  fd_gossip_ping_t pong;
};
typedef union fd_gossip_msg_inner fd_gossip_msg_inner_t;

/* UDP payloads of the Solana gossip protocol */
struct fd_gossip_msg {
  uint discriminant;
  fd_gossip_msg_inner_t inner;
};
typedef struct fd_gossip_msg fd_gossip_msg_t;
#define FD_GOSSIP_MSG_ALIGN alignof(fd_gossip_msg_t)

/* Encoded Size: Fixed (9 bytes) */
struct fd_addrlut_create {
  ulong recent_slot;
  uchar bump_seed;
};
typedef struct fd_addrlut_create fd_addrlut_create_t;
#define FD_ADDRLUT_CREATE_ALIGN alignof(fd_addrlut_create_t)

/* Encoded Size: Dynamic */
struct fd_addrlut_extend {
  ulong new_addrs_len;
  fd_pubkey_t * new_addrs;
};
typedef struct fd_addrlut_extend fd_addrlut_extend_t;
#define FD_ADDRLUT_EXTEND_ALIGN alignof(fd_addrlut_extend_t)

union fd_addrlut_instruction_inner {
  fd_addrlut_create_t create_lut;
  fd_addrlut_extend_t extend_lut;
};
typedef union fd_addrlut_instruction_inner fd_addrlut_instruction_inner_t;

/* https://github.com/solana-labs/solana/blob/fb80288f885a62bcd923f4c9579fd0edeafaff9b/sdk/program/src/address_lookup_table/instruction.rs#L13 */
struct fd_addrlut_instruction {
  uint discriminant;
  fd_addrlut_instruction_inner_t inner;
};
typedef struct fd_addrlut_instruction fd_addrlut_instruction_t;
#define FD_ADDRLUT_INSTRUCTION_ALIGN alignof(fd_addrlut_instruction_t)

/* https://github.com/anza-xyz/agave/blob/v2.2.7/core/src/repair/serve_repair.rs#L204-L210 */
/* Encoded Size: Fixed (140 bytes) */
struct fd_repair_request_header {
  fd_signature_t signature;
  fd_pubkey_t sender;
  fd_pubkey_t recipient;
  ulong timestamp;
  uint nonce;
};
typedef struct fd_repair_request_header fd_repair_request_header_t;
#define FD_REPAIR_REQUEST_HEADER_ALIGN alignof(fd_repair_request_header_t)

/* Encoded Size: Fixed (156 bytes) */
struct fd_repair_window_index {
  fd_repair_request_header_t header;
  ulong slot;
  ulong shred_index;
};
typedef struct fd_repair_window_index fd_repair_window_index_t;
#define FD_REPAIR_WINDOW_INDEX_ALIGN alignof(fd_repair_window_index_t)

/* Encoded Size: Fixed (156 bytes) */
struct fd_repair_highest_window_index {
  fd_repair_request_header_t header;
  ulong slot;
  ulong shred_index;
};
typedef struct fd_repair_highest_window_index fd_repair_highest_window_index_t;
#define FD_REPAIR_HIGHEST_WINDOW_INDEX_ALIGN alignof(fd_repair_highest_window_index_t)

/* Encoded Size: Fixed (148 bytes) */
struct fd_repair_orphan {
  fd_repair_request_header_t header;
  ulong slot;
};
typedef struct fd_repair_orphan fd_repair_orphan_t;
#define FD_REPAIR_ORPHAN_ALIGN alignof(fd_repair_orphan_t)

/* Encoded Size: Fixed (148 bytes) */
struct fd_repair_ancestor_hashes {
  fd_repair_request_header_t header;
  ulong slot;
};
typedef struct fd_repair_ancestor_hashes fd_repair_ancestor_hashes_t;
#define FD_REPAIR_ANCESTOR_HASHES_ALIGN alignof(fd_repair_ancestor_hashes_t)

union fd_repair_protocol_inner {
  fd_gossip_ping_t pong;
  fd_repair_window_index_t window_index;
  fd_repair_highest_window_index_t highest_window_index;
  fd_repair_orphan_t orphan;
  fd_repair_ancestor_hashes_t ancestor_hashes;
};
typedef union fd_repair_protocol_inner fd_repair_protocol_inner_t;

struct fd_repair_protocol {
  uint discriminant;
  fd_repair_protocol_inner_t inner;
};
typedef struct fd_repair_protocol fd_repair_protocol_t;
#define FD_REPAIR_PROTOCOL_ALIGN alignof(fd_repair_protocol_t)

union fd_instr_error_enum_inner {
  uint custom;
  char* borsh_io_error;
};
typedef union fd_instr_error_enum_inner fd_instr_error_enum_inner_t;

struct fd_instr_error_enum {
  uint discriminant;
  fd_instr_error_enum_inner_t inner;
};
typedef struct fd_instr_error_enum fd_instr_error_enum_t;
#define FD_INSTR_ERROR_ENUM_ALIGN alignof(fd_instr_error_enum_t)

/* Encoded Size: Dynamic */
struct fd_txn_instr_error {
  uchar instr_idx;
  fd_instr_error_enum_t error;
};
typedef struct fd_txn_instr_error fd_txn_instr_error_t;
#define FD_TXN_INSTR_ERROR_ALIGN alignof(fd_txn_instr_error_t)

union fd_txn_error_enum_inner {
  fd_txn_instr_error_t instruction_error;
  uchar duplicate_instruction;
  uchar insufficient_funds_for_rent;
  uchar program_execution_temporarily_restricted;
};
typedef union fd_txn_error_enum_inner fd_txn_error_enum_inner_t;

struct fd_txn_error_enum {
  uint discriminant;
  fd_txn_error_enum_inner_t inner;
};
typedef struct fd_txn_error_enum fd_txn_error_enum_t;
#define FD_TXN_ERROR_ENUM_ALIGN alignof(fd_txn_error_enum_t)

union fd_txn_result_inner {
  fd_txn_error_enum_t error;
};
typedef union fd_txn_result_inner fd_txn_result_inner_t;

struct fd_txn_result {
  uint discriminant;
  fd_txn_result_inner_t inner;
};
typedef struct fd_txn_result fd_txn_result_t;
#define FD_TXN_RESULT_ALIGN alignof(fd_txn_result_t)

/* Encoded Size: Dynamic */
struct fd_cache_status {
  uchar key_slice[20];
  fd_txn_result_t result;
};
typedef struct fd_cache_status fd_cache_status_t;
#define FD_CACHE_STATUS_ALIGN alignof(fd_cache_status_t)

/* Encoded Size: Dynamic */
struct fd_status_value {
  ulong txn_idx;
  ulong statuses_len;
  fd_cache_status_t * statuses;
};
typedef struct fd_status_value fd_status_value_t;
#define FD_STATUS_VALUE_ALIGN alignof(fd_status_value_t)

/* Encoded Size: Dynamic */
struct fd_status_pair {
  fd_hash_t hash;
  fd_status_value_t value;
};
typedef struct fd_status_pair fd_status_pair_t;
#define FD_STATUS_PAIR_ALIGN alignof(fd_status_pair_t)

/* Encoded Size: Dynamic */
struct fd_slot_delta {
  ulong slot;
  uchar is_root;
  ulong slot_delta_vec_len;
  fd_status_pair_t * slot_delta_vec;
};
typedef struct fd_slot_delta fd_slot_delta_t;
#define FD_SLOT_DELTA_ALIGN alignof(fd_slot_delta_t)

/* Encoded Size: Dynamic */
struct fd_bank_slot_deltas {
  ulong slot_deltas_len;
  fd_slot_delta_t * slot_deltas;
};
typedef struct fd_bank_slot_deltas fd_bank_slot_deltas_t;
#define FD_BANK_SLOT_DELTAS_ALIGN alignof(fd_bank_slot_deltas_t)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L85 */
/* Encoded Size: Fixed (60 bytes) */
struct fd_pubkey_rewardinfo_pair {
  fd_pubkey_t pubkey;
  fd_reward_info_t reward_info;
};
typedef struct fd_pubkey_rewardinfo_pair fd_pubkey_rewardinfo_pair_t;
#define FD_PUBKEY_REWARDINFO_PAIR_ALIGN alignof(fd_pubkey_rewardinfo_pair_t)

/* Encoded Size: Dynamic */
struct fd_optional_account {
  fd_solana_account_t * account;
};
typedef struct fd_optional_account fd_optional_account_t;
#define FD_OPTIONAL_ACCOUNT_ALIGN alignof(fd_optional_account_t)

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L27 */
/* Encoded Size: Fixed (25 bytes) */
struct fd_calculated_stake_points {
  uint128 points;
  ulong new_credits_observed;
  uchar force_credits_update_with_skipped_reward;
};
typedef struct fd_calculated_stake_points fd_calculated_stake_points_t;
#define FD_CALCULATED_STAKE_POINTS_ALIGN alignof(fd_calculated_stake_points_t)

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L24 */
/* Encoded Size: Fixed (24 bytes) */
struct fd_calculated_stake_rewards {
  ulong staker_rewards;
  ulong voter_rewards;
  ulong new_credits_observed;
};
typedef struct fd_calculated_stake_rewards fd_calculated_stake_rewards_t;
#define FD_CALCULATED_STAKE_REWARDS_ALIGN alignof(fd_calculated_stake_rewards_t)

/* https://github.com/anza-xyz/agave/blob/v2.0.3/ledger/src/blockstore_meta.rs#L150-L156 */
/* Encoded Size: Dynamic */
struct fd_duplicate_slot_proof {
  ulong shred1_len;
  uchar* shred1;
  ulong shred2_len;
  uchar* shred2;
};
typedef struct fd_duplicate_slot_proof fd_duplicate_slot_proof_t;
#define FD_DUPLICATE_SLOT_PROOF_ALIGN alignof(fd_duplicate_slot_proof_t)

/* Encoded Size: Fixed (104 bytes) */
struct fd_epoch_info_pair {
  fd_pubkey_t account;
  fd_stake_t stake;
};
typedef struct fd_epoch_info_pair fd_epoch_info_pair_t;
#define FD_EPOCH_INFO_PAIR_ALIGN alignof(fd_epoch_info_pair_t)

/* Encoded Size: Dynamic */
struct fd_vote_info_pair {
  fd_pubkey_t account;
  fd_vote_state_versioned_t state;
};
typedef struct fd_vote_info_pair fd_vote_info_pair_t;
#define FD_VOTE_INFO_PAIR_ALIGN alignof(fd_vote_info_pair_t)

typedef struct fd_vote_info_pair_t_mapnode fd_vote_info_pair_t_mapnode_t;
#define REDBLK_T fd_vote_info_pair_t_mapnode_t
#define REDBLK_NAME fd_vote_info_pair_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_vote_info_pair_t_mapnode {
    fd_vote_info_pair_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_vote_info_pair_t_mapnode_t *
fd_vote_info_pair_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_vote_info_pair_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_vote_info_pair_t_map_footprint( len );
  return fd_vote_info_pair_t_map_join( fd_vote_info_pair_t_map_new( map_mem, len ) );
}
/* Encoded Size: Dynamic */
struct fd_epoch_info {
  fd_vote_info_pair_t_mapnode_t * vote_states_pool;
  fd_vote_info_pair_t_mapnode_t * vote_states_root;
  ulong stake_infos_new_keys_start_idx;
};
typedef struct fd_epoch_info fd_epoch_info_t;
#define FD_EPOCH_INFO_ALIGN alignof(fd_epoch_info_t)

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/transaction_cost.rs#L153-L161 */
/* Encoded Size: Fixed (48 bytes) */
struct fd_usage_cost_details {
  ulong signature_cost;
  ulong write_lock_cost;
  ulong data_bytes_cost;
  ulong programs_execution_cost;
  ulong loaded_accounts_data_size_cost;
  ulong allocated_accounts_data_size;
};
typedef struct fd_usage_cost_details fd_usage_cost_details_t;
#define FD_USAGE_COST_DETAILS_ALIGN alignof(fd_usage_cost_details_t)

union fd_transaction_cost_inner {
  fd_usage_cost_details_t transaction;
};
typedef union fd_transaction_cost_inner fd_transaction_cost_inner_t;

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/transaction_cost.rs#L20-L23 */
struct fd_transaction_cost {
  uint discriminant;
  fd_transaction_cost_inner_t inner;
};
typedef struct fd_transaction_cost fd_transaction_cost_t;
#define FD_TRANSACTION_COST_ALIGN alignof(fd_transaction_cost_t)

/* Encoded Size: Fixed (40 bytes) */
struct fd_account_costs_pair {
  fd_pubkey_t key;
  ulong cost;
};
typedef struct fd_account_costs_pair fd_account_costs_pair_t;
#define FD_ACCOUNT_COSTS_PAIR_ALIGN alignof(fd_account_costs_pair_t)

typedef struct fd_account_costs_pair_t_mapnode fd_account_costs_pair_t_mapnode_t;
#define REDBLK_T fd_account_costs_pair_t_mapnode_t
#define REDBLK_NAME fd_account_costs_pair_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
struct fd_account_costs_pair_t_mapnode {
    fd_account_costs_pair_t elem;
    ulong redblack_parent;
    ulong redblack_left;
    ulong redblack_right;
    int redblack_color;
};
static inline fd_account_costs_pair_t_mapnode_t *
fd_account_costs_pair_t_map_join_new( void * * alloc_mem, ulong len ) {
  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_account_costs_pair_t_map_align() );
  void * map_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + fd_account_costs_pair_t_map_footprint( len );
  return fd_account_costs_pair_t_map_join( fd_account_costs_pair_t_map_new( map_mem, len ) );
}
/* Encoded Size: Dynamic */
struct fd_account_costs {
  fd_account_costs_pair_t_mapnode_t * account_costs_pool;
  fd_account_costs_pair_t_mapnode_t * account_costs_root;
};
typedef struct fd_account_costs fd_account_costs_t;
#define FD_ACCOUNT_COSTS_ALIGN alignof(fd_account_costs_t)

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L62-L79 */
/* Encoded Size: Dynamic */
struct fd_cost_tracker {
  ulong account_cost_limit;
  ulong block_cost_limit;
  ulong vote_cost_limit;
  fd_account_costs_t cost_by_writable_accounts;
  ulong block_cost;
  ulong vote_cost;
  ulong transaction_count;
  ulong allocated_accounts_data_size;
  ulong transaction_signature_count;
  ulong secp256k1_instruction_signature_count;
  ulong ed25519_instruction_signature_count;
  ulong secp256r1_instruction_signature_count;
};
typedef struct fd_cost_tracker fd_cost_tracker_t;
#define FD_COST_TRACKER_ALIGN alignof(fd_cost_tracker_t)

/* Encoded Size: Fixed (16 bytes) */
struct fd_rent_paying {
  ulong lamports;
  ulong data_size;
};
typedef struct fd_rent_paying fd_rent_paying_t;
#define FD_RENT_PAYING_ALIGN alignof(fd_rent_paying_t)

union fd_rent_state_inner {
  fd_rent_paying_t rent_paying;
};
typedef union fd_rent_state_inner fd_rent_state_inner_t;

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/rent_state.rs#L5-L15 */
struct fd_rent_state {
  uint discriminant;
  fd_rent_state_inner_t inner;
};
typedef struct fd_rent_state fd_rent_state_t;
#define FD_RENT_STATE_ALIGN alignof(fd_rent_state_t)


FD_PROTOTYPES_BEGIN

static inline void fd_hash_new( fd_hash_t * self ) { (void)self; }
int fd_hash_encode( fd_hash_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_hash_walk( void * w, fd_hash_t const * self, fd_types_walk_fn_t fun, const char * name, uint level, uint varint );
static inline ulong fd_hash_size( fd_hash_t const * self ) { (void)self; return sizeof(fd_hash_t); }
static inline ulong fd_hash_align( void ) { return alignof(fd_hash_t); }
int fd_hash_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_hash_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_signature_new( fd_signature_t * self ) { (void)self; }
int fd_signature_encode( fd_signature_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_signature_walk( void * w, fd_signature_t const * self, fd_types_walk_fn_t fun, const char * name, uint level, uint varint );
static inline ulong fd_signature_size( fd_signature_t const * self ) { (void)self; return sizeof(fd_signature_t); }
static inline ulong fd_signature_align( void ) { return alignof(fd_signature_t); }
int fd_signature_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_signature_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_gossip_ip4_addr_new( fd_gossip_ip4_addr_t * self ) { (void)self; }
int fd_gossip_ip4_addr_encode( fd_gossip_ip4_addr_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_ip4_addr_walk( void * w, fd_gossip_ip4_addr_t const * self, fd_types_walk_fn_t fun, const char * name, uint level, uint varint );
static inline ulong fd_gossip_ip4_addr_size( fd_gossip_ip4_addr_t const * self ) { (void)self; return sizeof(fd_gossip_ip4_addr_t); }
static inline ulong fd_gossip_ip4_addr_align( void ) { return alignof(fd_gossip_ip4_addr_t); }
int fd_gossip_ip4_addr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_ip4_addr_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_gossip_ip6_addr_new( fd_gossip_ip6_addr_t * self ) { (void)self; }
int fd_gossip_ip6_addr_encode( fd_gossip_ip6_addr_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_ip6_addr_walk( void * w, fd_gossip_ip6_addr_t const * self, fd_types_walk_fn_t fun, const char * name, uint level, uint varint );
static inline ulong fd_gossip_ip6_addr_size( fd_gossip_ip6_addr_t const * self ) { (void)self; return sizeof(fd_gossip_ip6_addr_t); }
static inline ulong fd_gossip_ip6_addr_align( void ) { return alignof(fd_gossip_ip6_addr_t); }
int fd_gossip_ip6_addr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_ip6_addr_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_feature_new( fd_feature_t * self );
int fd_feature_encode( fd_feature_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_feature_walk( void * w, fd_feature_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_feature_size( fd_feature_t const * self );
static inline ulong fd_feature_align( void ) { return FD_FEATURE_ALIGN; }
int fd_feature_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_feature_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_fee_calculator_new( fd_fee_calculator_t * self ) { fd_memset( self, 0, sizeof(fd_fee_calculator_t) ); }
int fd_fee_calculator_encode( fd_fee_calculator_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_fee_calculator_walk( void * w, fd_fee_calculator_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_fee_calculator_size( fd_fee_calculator_t const * self ) { (void)self; return 8UL; }
static inline ulong fd_fee_calculator_align( void ) { return FD_FEE_CALCULATOR_ALIGN; }
static inline int fd_fee_calculator_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_fee_calculator_t);
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_fee_calculator_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_hash_age_new( fd_hash_age_t * self ) { fd_memset( self, 0, sizeof(fd_hash_age_t) ); }
int fd_hash_age_encode( fd_hash_age_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_hash_age_walk( void * w, fd_hash_age_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_hash_age_size( fd_hash_age_t const * self ) { (void)self; return 24UL; }
static inline ulong fd_hash_age_align( void ) { return FD_HASH_AGE_ALIGN; }
static inline int fd_hash_age_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_hash_age_t);
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_hash_age_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_hash_hash_age_pair_new( fd_hash_hash_age_pair_t * self ) { fd_memset( self, 0, sizeof(fd_hash_hash_age_pair_t) ); }
int fd_hash_hash_age_pair_encode( fd_hash_hash_age_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_hash_hash_age_pair_walk( void * w, fd_hash_hash_age_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_hash_hash_age_pair_size( fd_hash_hash_age_pair_t const * self ) { (void)self; return 56UL; }
static inline ulong fd_hash_hash_age_pair_align( void ) { return FD_HASH_HASH_AGE_PAIR_ALIGN; }
static inline int fd_hash_hash_age_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_hash_hash_age_pair_t);
  if( (ulong)ctx->data + 56UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_hash_hash_age_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_block_hash_vec_new( fd_block_hash_vec_t * self );
int fd_block_hash_vec_encode( fd_block_hash_vec_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_block_hash_vec_walk( void * w, fd_block_hash_vec_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_block_hash_vec_size( fd_block_hash_vec_t const * self );
static inline ulong fd_block_hash_vec_align( void ) { return FD_BLOCK_HASH_VEC_ALIGN; }
int fd_block_hash_vec_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_block_hash_vec_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_block_hash_vec_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_block_hash_vec_encode_global( fd_block_hash_vec_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_block_hash_vec_size_global( fd_block_hash_vec_global_t const * self );

static inline void fd_fee_rate_governor_new( fd_fee_rate_governor_t * self ) { fd_memset( self, 0, sizeof(fd_fee_rate_governor_t) ); }
int fd_fee_rate_governor_encode( fd_fee_rate_governor_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_fee_rate_governor_walk( void * w, fd_fee_rate_governor_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_fee_rate_governor_size( fd_fee_rate_governor_t const * self ) { (void)self; return 33UL; }
static inline ulong fd_fee_rate_governor_align( void ) { return FD_FEE_RATE_GOVERNOR_ALIGN; }
static inline int fd_fee_rate_governor_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_fee_rate_governor_t);
  if( (ulong)ctx->data + 33UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_fee_rate_governor_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_slot_pair_new( fd_slot_pair_t * self ) { fd_memset( self, 0, sizeof(fd_slot_pair_t) ); }
int fd_slot_pair_encode( fd_slot_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_slot_pair_walk( void * w, fd_slot_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_hard_forks_walk( void * w, fd_hard_forks_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_hard_forks_size( fd_hard_forks_t const * self );
static inline ulong fd_hard_forks_align( void ) { return FD_HARD_FORKS_ALIGN; }
int fd_hard_forks_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_hard_forks_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_hard_forks_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_hard_forks_encode_global( fd_hard_forks_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_hard_forks_size_global( fd_hard_forks_global_t const * self );

static inline void fd_inflation_new( fd_inflation_t * self ) { fd_memset( self, 0, sizeof(fd_inflation_t) ); }
int fd_inflation_encode( fd_inflation_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_inflation_walk( void * w, fd_inflation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_rent_walk( void * w, fd_rent_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_epoch_schedule_walk( void * w, fd_epoch_schedule_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_epoch_schedule_size( fd_epoch_schedule_t const * self ) { (void)self; return 33UL; }
static inline ulong fd_epoch_schedule_align( void ) { return FD_EPOCH_SCHEDULE_ALIGN; }
int fd_epoch_schedule_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_epoch_schedule_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_rent_collector_new( fd_rent_collector_t * self );
int fd_rent_collector_encode( fd_rent_collector_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_rent_collector_walk( void * w, fd_rent_collector_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_rent_collector_size( fd_rent_collector_t const * self ) { (void)self; return 66UL; }
static inline ulong fd_rent_collector_align( void ) { return FD_RENT_COLLECTOR_ALIGN; }
int fd_rent_collector_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_rent_collector_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_history_entry_new( fd_stake_history_entry_t * self ) { fd_memset( self, 0, sizeof(fd_stake_history_entry_t) ); }
int fd_stake_history_entry_encode( fd_stake_history_entry_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_history_entry_walk( void * w, fd_stake_history_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_epoch_stake_history_entry_pair_walk( void * w, fd_epoch_stake_history_entry_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_stake_history_walk( void * w, fd_stake_history_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_history_size( fd_stake_history_t const * self ) { (void)self; return 16392UL; }
static inline ulong fd_stake_history_align( void ) { return FD_STAKE_HISTORY_ALIGN; }
int fd_stake_history_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_history_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_solana_account_new( fd_solana_account_t * self );
int fd_solana_account_encode( fd_solana_account_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_solana_account_walk( void * w, fd_solana_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_solana_account_size( fd_solana_account_t const * self );
static inline ulong fd_solana_account_align( void ) { return FD_SOLANA_ACCOUNT_ALIGN; }
int fd_solana_account_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_solana_account_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_solana_account_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_solana_account_encode_global( fd_solana_account_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_solana_account_size_global( fd_solana_account_global_t const * self );

static inline void fd_solana_account_stored_meta_new( fd_solana_account_stored_meta_t * self ) { fd_memset( self, 0, sizeof(fd_solana_account_stored_meta_t) ); }
int fd_solana_account_stored_meta_encode( fd_solana_account_stored_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_solana_account_stored_meta_walk( void * w, fd_solana_account_stored_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_solana_account_stored_meta_size( fd_solana_account_stored_meta_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_solana_account_stored_meta_align( void ) { return FD_SOLANA_ACCOUNT_STORED_META_ALIGN; }
static inline int fd_solana_account_stored_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_solana_account_stored_meta_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_solana_account_stored_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_solana_account_meta_new( fd_solana_account_meta_t * self );
int fd_solana_account_meta_encode( fd_solana_account_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_solana_account_meta_walk( void * w, fd_solana_account_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_solana_account_meta_size( fd_solana_account_meta_t const * self ) { (void)self; return 52UL; }
static inline ulong fd_solana_account_meta_align( void ) { return FD_SOLANA_ACCOUNT_META_ALIGN; }
int fd_solana_account_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_solana_account_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_solana_account_hdr_new( fd_solana_account_hdr_t * self );
int fd_solana_account_hdr_encode( fd_solana_account_hdr_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_solana_account_hdr_walk( void * w, fd_solana_account_hdr_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_solana_account_hdr_size( fd_solana_account_hdr_t const * self ) { (void)self; return 136UL; }
static inline ulong fd_solana_account_hdr_align( void ) { return FD_SOLANA_ACCOUNT_HDR_ALIGN; }
int fd_solana_account_hdr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_solana_account_hdr_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_account_meta_new( fd_account_meta_t * self );
int fd_account_meta_encode( fd_account_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_account_meta_walk( void * w, fd_account_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_account_meta_size( fd_account_meta_t const * self ) { (void)self; return 104UL; }
static inline ulong fd_account_meta_align( void ) { return FD_ACCOUNT_META_ALIGN; }
int fd_account_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_account_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_accounts_pair_new( fd_vote_accounts_pair_t * self );
int fd_vote_accounts_pair_encode( fd_vote_accounts_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_accounts_pair_walk( void * w, fd_vote_accounts_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_accounts_pair_size( fd_vote_accounts_pair_t const * self );
static inline ulong fd_vote_accounts_pair_align( void ) { return FD_VOTE_ACCOUNTS_PAIR_ALIGN; }
int fd_vote_accounts_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_accounts_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_vote_accounts_pair_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_vote_accounts_pair_encode_global( fd_vote_accounts_pair_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_vote_accounts_pair_size_global( fd_vote_accounts_pair_global_t const * self );

void fd_vote_accounts_new( fd_vote_accounts_t * self );
int fd_vote_accounts_encode( fd_vote_accounts_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_accounts_walk( void * w, fd_vote_accounts_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_accounts_size( fd_vote_accounts_t const * self );
static inline ulong fd_vote_accounts_align( void ) { return FD_VOTE_ACCOUNTS_ALIGN; }
int fd_vote_accounts_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_accounts_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_vote_accounts_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_vote_accounts_encode_global( fd_vote_accounts_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_vote_accounts_size_global( fd_vote_accounts_global_t const * self );

static inline void fd_account_keys_pair_new( fd_account_keys_pair_t * self ) { fd_memset( self, 0, sizeof(fd_account_keys_pair_t) ); }
int fd_account_keys_pair_encode( fd_account_keys_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_account_keys_pair_walk( void * w, fd_account_keys_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_account_keys_pair_size( fd_account_keys_pair_t const * self ) { (void)self; return 33UL; }
static inline ulong fd_account_keys_pair_align( void ) { return FD_ACCOUNT_KEYS_PAIR_ALIGN; }
static inline int fd_account_keys_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_account_keys_pair_t);
  if( (ulong)ctx->data + 33UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_account_keys_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_account_keys_new( fd_account_keys_t * self );
int fd_account_keys_encode( fd_account_keys_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_account_keys_walk( void * w, fd_account_keys_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_account_keys_size( fd_account_keys_t const * self );
static inline ulong fd_account_keys_align( void ) { return FD_ACCOUNT_KEYS_ALIGN; }
int fd_account_keys_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_account_keys_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_account_keys_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_account_keys_encode_global( fd_account_keys_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_account_keys_size_global( fd_account_keys_global_t const * self );

static inline void fd_delegation_new( fd_delegation_t * self ) { fd_memset( self, 0, sizeof(fd_delegation_t) ); }
int fd_delegation_encode( fd_delegation_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_delegation_walk( void * w, fd_delegation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_delegation_size( fd_delegation_t const * self ) { (void)self; return 64UL; }
static inline ulong fd_delegation_align( void ) { return FD_DELEGATION_ALIGN; }
static inline int fd_delegation_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_delegation_t);
  if( (ulong)ctx->data + 64UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_delegation_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_delegation_pair_new( fd_delegation_pair_t * self ) { fd_memset( self, 0, sizeof(fd_delegation_pair_t) ); }
int fd_delegation_pair_encode( fd_delegation_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_delegation_pair_walk( void * w, fd_delegation_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_delegation_pair_size( fd_delegation_pair_t const * self ) { (void)self; return 96UL; }
static inline ulong fd_delegation_pair_align( void ) { return FD_DELEGATION_PAIR_ALIGN; }
static inline int fd_delegation_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_delegation_pair_t);
  if( (ulong)ctx->data + 96UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_delegation_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_new( fd_stake_t * self ) { fd_memset( self, 0, sizeof(fd_stake_t) ); }
int fd_stake_encode( fd_stake_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_walk( void * w, fd_stake_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_size( fd_stake_t const * self ) { (void)self; return 72UL; }
static inline ulong fd_stake_align( void ) { return FD_STAKE_ALIGN; }
static inline int fd_stake_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_t);
  if( (ulong)ctx->data + 72UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_pair_new( fd_stake_pair_t * self ) { fd_memset( self, 0, sizeof(fd_stake_pair_t) ); }
int fd_stake_pair_encode( fd_stake_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_pair_walk( void * w, fd_stake_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_pair_size( fd_stake_pair_t const * self ) { (void)self; return 104UL; }
static inline ulong fd_stake_pair_align( void ) { return FD_STAKE_PAIR_ALIGN; }
static inline int fd_stake_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_pair_t);
  if( (ulong)ctx->data + 104UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_stakes_new( fd_stakes_t * self );
int fd_stakes_encode( fd_stakes_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stakes_walk( void * w, fd_stakes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stakes_size( fd_stakes_t const * self );
static inline ulong fd_stakes_align( void ) { return FD_STAKES_ALIGN; }
int fd_stakes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stakes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_stakes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_stakes_encode_global( fd_stakes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_stakes_size_global( fd_stakes_global_t const * self );

void fd_stakes_stake_new( fd_stakes_stake_t * self );
int fd_stakes_stake_encode( fd_stakes_stake_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stakes_stake_walk( void * w, fd_stakes_stake_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stakes_stake_size( fd_stakes_stake_t const * self );
static inline ulong fd_stakes_stake_align( void ) { return FD_STAKES_STAKE_ALIGN; }
int fd_stakes_stake_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stakes_stake_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_stakes_stake_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_stakes_stake_encode_global( fd_stakes_stake_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_stakes_stake_size_global( fd_stakes_stake_global_t const * self );

static inline void fd_bank_incremental_snapshot_persistence_new( fd_bank_incremental_snapshot_persistence_t * self ) { fd_memset( self, 0, sizeof(fd_bank_incremental_snapshot_persistence_t) ); }
int fd_bank_incremental_snapshot_persistence_encode( fd_bank_incremental_snapshot_persistence_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bank_incremental_snapshot_persistence_walk( void * w, fd_bank_incremental_snapshot_persistence_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_bank_incremental_snapshot_persistence_size( fd_bank_incremental_snapshot_persistence_t const * self ) { (void)self; return 88UL; }
static inline ulong fd_bank_incremental_snapshot_persistence_align( void ) { return FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN; }
static inline int fd_bank_incremental_snapshot_persistence_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bank_incremental_snapshot_persistence_t);
  if( (ulong)ctx->data + 88UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_bank_incremental_snapshot_persistence_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_node_vote_accounts_new( fd_node_vote_accounts_t * self );
int fd_node_vote_accounts_encode( fd_node_vote_accounts_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_node_vote_accounts_walk( void * w, fd_node_vote_accounts_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_node_vote_accounts_size( fd_node_vote_accounts_t const * self );
static inline ulong fd_node_vote_accounts_align( void ) { return FD_NODE_VOTE_ACCOUNTS_ALIGN; }
int fd_node_vote_accounts_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_node_vote_accounts_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_node_vote_accounts_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_node_vote_accounts_encode_global( fd_node_vote_accounts_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_node_vote_accounts_size_global( fd_node_vote_accounts_global_t const * self );

void fd_pubkey_node_vote_accounts_pair_new( fd_pubkey_node_vote_accounts_pair_t * self );
int fd_pubkey_node_vote_accounts_pair_encode( fd_pubkey_node_vote_accounts_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_pubkey_node_vote_accounts_pair_walk( void * w, fd_pubkey_node_vote_accounts_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_pubkey_node_vote_accounts_pair_size( fd_pubkey_node_vote_accounts_pair_t const * self );
static inline ulong fd_pubkey_node_vote_accounts_pair_align( void ) { return FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_ALIGN; }
int fd_pubkey_node_vote_accounts_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_pubkey_node_vote_accounts_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_pubkey_node_vote_accounts_pair_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_pubkey_node_vote_accounts_pair_encode_global( fd_pubkey_node_vote_accounts_pair_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_pubkey_node_vote_accounts_pair_size_global( fd_pubkey_node_vote_accounts_pair_global_t const * self );

static inline void fd_pubkey_pubkey_pair_new( fd_pubkey_pubkey_pair_t * self ) { fd_memset( self, 0, sizeof(fd_pubkey_pubkey_pair_t) ); }
int fd_pubkey_pubkey_pair_encode( fd_pubkey_pubkey_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_pubkey_pubkey_pair_walk( void * w, fd_pubkey_pubkey_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_pubkey_pubkey_pair_size( fd_pubkey_pubkey_pair_t const * self ) { (void)self; return 64UL; }
static inline ulong fd_pubkey_pubkey_pair_align( void ) { return FD_PUBKEY_PUBKEY_PAIR_ALIGN; }
static inline int fd_pubkey_pubkey_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_pubkey_pubkey_pair_t);
  if( (ulong)ctx->data + 64UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_pubkey_pubkey_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_epoch_stakes_new( fd_epoch_stakes_t * self );
int fd_epoch_stakes_encode( fd_epoch_stakes_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_epoch_stakes_walk( void * w, fd_epoch_stakes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_epoch_stakes_size( fd_epoch_stakes_t const * self );
static inline ulong fd_epoch_stakes_align( void ) { return FD_EPOCH_STAKES_ALIGN; }
int fd_epoch_stakes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_epoch_stakes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_epoch_stakes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_epoch_stakes_encode_global( fd_epoch_stakes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_epoch_stakes_size_global( fd_epoch_stakes_global_t const * self );

void fd_epoch_epoch_stakes_pair_new( fd_epoch_epoch_stakes_pair_t * self );
int fd_epoch_epoch_stakes_pair_encode( fd_epoch_epoch_stakes_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_epoch_epoch_stakes_pair_walk( void * w, fd_epoch_epoch_stakes_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_epoch_epoch_stakes_pair_size( fd_epoch_epoch_stakes_pair_t const * self );
static inline ulong fd_epoch_epoch_stakes_pair_align( void ) { return FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN; }
int fd_epoch_epoch_stakes_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_epoch_epoch_stakes_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_epoch_epoch_stakes_pair_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_epoch_epoch_stakes_pair_encode_global( fd_epoch_epoch_stakes_pair_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_epoch_epoch_stakes_pair_size_global( fd_epoch_epoch_stakes_pair_global_t const * self );

static inline void fd_pubkey_u64_pair_new( fd_pubkey_u64_pair_t * self ) { fd_memset( self, 0, sizeof(fd_pubkey_u64_pair_t) ); }
int fd_pubkey_u64_pair_encode( fd_pubkey_u64_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_pubkey_u64_pair_walk( void * w, fd_pubkey_u64_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_pubkey_u64_pair_size( fd_pubkey_u64_pair_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_pubkey_u64_pair_align( void ) { return FD_PUBKEY_U64_PAIR_ALIGN; }
static inline int fd_pubkey_u64_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_pubkey_u64_pair_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_pubkey_u64_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_unused_accounts_new( fd_unused_accounts_t * self );
int fd_unused_accounts_encode( fd_unused_accounts_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_unused_accounts_walk( void * w, fd_unused_accounts_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_unused_accounts_size( fd_unused_accounts_t const * self );
static inline ulong fd_unused_accounts_align( void ) { return FD_UNUSED_ACCOUNTS_ALIGN; }
int fd_unused_accounts_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_unused_accounts_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_unused_accounts_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_unused_accounts_encode_global( fd_unused_accounts_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_unused_accounts_size_global( fd_unused_accounts_global_t const * self );

void fd_versioned_bank_new( fd_versioned_bank_t * self );
int fd_versioned_bank_encode( fd_versioned_bank_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_versioned_bank_walk( void * w, fd_versioned_bank_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_versioned_bank_size( fd_versioned_bank_t const * self );
static inline ulong fd_versioned_bank_align( void ) { return FD_VERSIONED_BANK_ALIGN; }
int fd_versioned_bank_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_versioned_bank_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_versioned_bank_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_versioned_bank_encode_global( fd_versioned_bank_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_versioned_bank_size_global( fd_versioned_bank_global_t const * self );

static inline void fd_bank_hash_stats_new( fd_bank_hash_stats_t * self ) { fd_memset( self, 0, sizeof(fd_bank_hash_stats_t) ); }
int fd_bank_hash_stats_encode( fd_bank_hash_stats_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bank_hash_stats_walk( void * w, fd_bank_hash_stats_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_bank_hash_stats_size( fd_bank_hash_stats_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_bank_hash_stats_align( void ) { return FD_BANK_HASH_STATS_ALIGN; }
static inline int fd_bank_hash_stats_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bank_hash_stats_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_bank_hash_stats_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_bank_hash_info_new( fd_bank_hash_info_t * self ) { fd_memset( self, 0, sizeof(fd_bank_hash_info_t) ); }
int fd_bank_hash_info_encode( fd_bank_hash_info_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bank_hash_info_walk( void * w, fd_bank_hash_info_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_bank_hash_info_size( fd_bank_hash_info_t const * self ) { (void)self; return 104UL; }
static inline ulong fd_bank_hash_info_align( void ) { return FD_BANK_HASH_INFO_ALIGN; }
static inline int fd_bank_hash_info_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bank_hash_info_t);
  if( (ulong)ctx->data + 104UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_bank_hash_info_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_slot_map_pair_new( fd_slot_map_pair_t * self ) { fd_memset( self, 0, sizeof(fd_slot_map_pair_t) ); }
int fd_slot_map_pair_encode( fd_slot_map_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_slot_map_pair_walk( void * w, fd_slot_map_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_slot_map_pair_size( fd_slot_map_pair_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_slot_map_pair_align( void ) { return FD_SLOT_MAP_PAIR_ALIGN; }
static inline int fd_slot_map_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_map_pair_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_slot_map_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_snapshot_acc_vec_new( fd_snapshot_acc_vec_t * self ) { fd_memset( self, 0, sizeof(fd_snapshot_acc_vec_t) ); }
int fd_snapshot_acc_vec_encode( fd_snapshot_acc_vec_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_snapshot_acc_vec_walk( void * w, fd_snapshot_acc_vec_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_snapshot_acc_vec_size( fd_snapshot_acc_vec_t const * self ) { (void)self; return 16UL; }
static inline ulong fd_snapshot_acc_vec_align( void ) { return FD_SNAPSHOT_ACC_VEC_ALIGN; }
static inline int fd_snapshot_acc_vec_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_snapshot_acc_vec_t);
  if( (ulong)ctx->data + 16UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_snapshot_acc_vec_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_snapshot_slot_acc_vecs_new( fd_snapshot_slot_acc_vecs_t * self );
int fd_snapshot_slot_acc_vecs_encode( fd_snapshot_slot_acc_vecs_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_snapshot_slot_acc_vecs_walk( void * w, fd_snapshot_slot_acc_vecs_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_snapshot_slot_acc_vecs_size( fd_snapshot_slot_acc_vecs_t const * self );
static inline ulong fd_snapshot_slot_acc_vecs_align( void ) { return FD_SNAPSHOT_SLOT_ACC_VECS_ALIGN; }
int fd_snapshot_slot_acc_vecs_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_snapshot_slot_acc_vecs_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_snapshot_slot_acc_vecs_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_snapshot_slot_acc_vecs_encode_global( fd_snapshot_slot_acc_vecs_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_snapshot_slot_acc_vecs_size_global( fd_snapshot_slot_acc_vecs_global_t const * self );

static inline void fd_reward_type_new_disc( fd_reward_type_t * self, uint discriminant ) { self->discriminant = discriminant; }
static inline void fd_reward_type_new( fd_reward_type_t * self ) { self->discriminant = (uint)ULONG_MAX; }
int fd_reward_type_encode( fd_reward_type_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_reward_type_walk( void * w, fd_reward_type_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_reward_type_size( fd_reward_type_t const * self );
static inline ulong fd_reward_type_align( void ) { return FD_REWARD_TYPE_ALIGN; }
int fd_reward_type_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_reward_type_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_reward_type_is_fee( fd_reward_type_t const * self );
FD_FN_PURE uchar fd_reward_type_is_rent( fd_reward_type_t const * self );
FD_FN_PURE uchar fd_reward_type_is_staking( fd_reward_type_t const * self );
FD_FN_PURE uchar fd_reward_type_is_voting( fd_reward_type_t const * self );
enum {
fd_reward_type_enum_fee = 0,
fd_reward_type_enum_rent = 1,
fd_reward_type_enum_staking = 2,
fd_reward_type_enum_voting = 3,
};
void fd_solana_accounts_db_fields_new( fd_solana_accounts_db_fields_t * self );
int fd_solana_accounts_db_fields_encode( fd_solana_accounts_db_fields_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_solana_accounts_db_fields_walk( void * w, fd_solana_accounts_db_fields_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_solana_accounts_db_fields_size( fd_solana_accounts_db_fields_t const * self );
static inline ulong fd_solana_accounts_db_fields_align( void ) { return FD_SOLANA_ACCOUNTS_DB_FIELDS_ALIGN; }
int fd_solana_accounts_db_fields_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_solana_accounts_db_fields_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_solana_accounts_db_fields_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_solana_accounts_db_fields_encode_global( fd_solana_accounts_db_fields_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_solana_accounts_db_fields_size_global( fd_solana_accounts_db_fields_global_t const * self );

void fd_versioned_epoch_stakes_current_new( fd_versioned_epoch_stakes_current_t * self );
int fd_versioned_epoch_stakes_current_encode( fd_versioned_epoch_stakes_current_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_versioned_epoch_stakes_current_walk( void * w, fd_versioned_epoch_stakes_current_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_versioned_epoch_stakes_current_size( fd_versioned_epoch_stakes_current_t const * self );
static inline ulong fd_versioned_epoch_stakes_current_align( void ) { return FD_VERSIONED_EPOCH_STAKES_CURRENT_ALIGN; }
int fd_versioned_epoch_stakes_current_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_versioned_epoch_stakes_current_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_versioned_epoch_stakes_current_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_versioned_epoch_stakes_current_encode_global( fd_versioned_epoch_stakes_current_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_versioned_epoch_stakes_current_size_global( fd_versioned_epoch_stakes_current_global_t const * self );

void fd_versioned_epoch_stakes_new_disc( fd_versioned_epoch_stakes_t * self, uint discriminant );
void fd_versioned_epoch_stakes_new( fd_versioned_epoch_stakes_t * self );
int fd_versioned_epoch_stakes_encode( fd_versioned_epoch_stakes_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_versioned_epoch_stakes_walk( void * w, fd_versioned_epoch_stakes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_versioned_epoch_stakes_size( fd_versioned_epoch_stakes_t const * self );
static inline ulong fd_versioned_epoch_stakes_align( void ) { return FD_VERSIONED_EPOCH_STAKES_ALIGN; }
int fd_versioned_epoch_stakes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_versioned_epoch_stakes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_versioned_epoch_stakes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_versioned_epoch_stakes_encode_global( fd_versioned_epoch_stakes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_versioned_epoch_stakes_size_global( fd_versioned_epoch_stakes_global_t const * self );

FD_FN_PURE uchar fd_versioned_epoch_stakes_is_Current( fd_versioned_epoch_stakes_t const * self );
enum {
fd_versioned_epoch_stakes_enum_Current = 0,
};
void fd_versioned_epoch_stakes_pair_new( fd_versioned_epoch_stakes_pair_t * self );
int fd_versioned_epoch_stakes_pair_encode( fd_versioned_epoch_stakes_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_versioned_epoch_stakes_pair_walk( void * w, fd_versioned_epoch_stakes_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_versioned_epoch_stakes_pair_size( fd_versioned_epoch_stakes_pair_t const * self );
static inline ulong fd_versioned_epoch_stakes_pair_align( void ) { return FD_VERSIONED_EPOCH_STAKES_PAIR_ALIGN; }
int fd_versioned_epoch_stakes_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_versioned_epoch_stakes_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_versioned_epoch_stakes_pair_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_versioned_epoch_stakes_pair_encode_global( fd_versioned_epoch_stakes_pair_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_versioned_epoch_stakes_pair_size_global( fd_versioned_epoch_stakes_pair_global_t const * self );

void fd_reward_info_new( fd_reward_info_t * self );
int fd_reward_info_encode( fd_reward_info_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_reward_info_walk( void * w, fd_reward_info_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_reward_info_size( fd_reward_info_t const * self ) { (void)self; return 28UL; }
static inline ulong fd_reward_info_align( void ) { return FD_REWARD_INFO_ALIGN; }
int fd_reward_info_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_reward_info_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_slot_lthash_new( fd_slot_lthash_t * self ) { fd_memset( self, 0, sizeof(fd_slot_lthash_t) ); }
int fd_slot_lthash_encode( fd_slot_lthash_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_slot_lthash_walk( void * w, fd_slot_lthash_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_slot_lthash_size( fd_slot_lthash_t const * self ) { (void)self; return 2048UL; }
static inline ulong fd_slot_lthash_align( void ) { return FD_SLOT_LTHASH_ALIGN; }
static inline int fd_slot_lthash_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_lthash_t);
  if( (ulong)ctx->data + 2048UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_slot_lthash_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_solana_manifest_new( fd_solana_manifest_t * self );
int fd_solana_manifest_encode( fd_solana_manifest_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_solana_manifest_walk( void * w, fd_solana_manifest_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_solana_manifest_size( fd_solana_manifest_t const * self );
static inline ulong fd_solana_manifest_align( void ) { return FD_SOLANA_MANIFEST_ALIGN; }
int fd_solana_manifest_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_solana_manifest_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_solana_manifest_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_solana_manifest_encode_global( fd_solana_manifest_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_solana_manifest_size_global( fd_solana_manifest_global_t const * self );

static inline void fd_rust_duration_new( fd_rust_duration_t * self ) { fd_memset( self, 0, sizeof(fd_rust_duration_t) ); }
int fd_rust_duration_encode( fd_rust_duration_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_rust_duration_walk( void * w, fd_rust_duration_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_poh_config_walk( void * w, fd_poh_config_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_poh_config_size( fd_poh_config_t const * self );
static inline ulong fd_poh_config_align( void ) { return FD_POH_CONFIG_ALIGN; }
int fd_poh_config_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_poh_config_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_string_pubkey_pair_new( fd_string_pubkey_pair_t * self );
int fd_string_pubkey_pair_encode( fd_string_pubkey_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_string_pubkey_pair_walk( void * w, fd_string_pubkey_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_string_pubkey_pair_size( fd_string_pubkey_pair_t const * self );
static inline ulong fd_string_pubkey_pair_align( void ) { return FD_STRING_PUBKEY_PAIR_ALIGN; }
int fd_string_pubkey_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_string_pubkey_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_pubkey_account_pair_new( fd_pubkey_account_pair_t * self );
int fd_pubkey_account_pair_encode( fd_pubkey_account_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_pubkey_account_pair_walk( void * w, fd_pubkey_account_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_pubkey_account_pair_size( fd_pubkey_account_pair_t const * self );
static inline ulong fd_pubkey_account_pair_align( void ) { return FD_PUBKEY_ACCOUNT_PAIR_ALIGN; }
int fd_pubkey_account_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_pubkey_account_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_genesis_solana_new( fd_genesis_solana_t * self );
int fd_genesis_solana_encode( fd_genesis_solana_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_genesis_solana_walk( void * w, fd_genesis_solana_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_genesis_solana_size( fd_genesis_solana_t const * self );
static inline ulong fd_genesis_solana_align( void ) { return FD_GENESIS_SOLANA_ALIGN; }
int fd_genesis_solana_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_genesis_solana_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_sol_sysvar_clock_new( fd_sol_sysvar_clock_t * self ) { fd_memset( self, 0, sizeof(fd_sol_sysvar_clock_t) ); }
int fd_sol_sysvar_clock_encode( fd_sol_sysvar_clock_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_sol_sysvar_clock_walk( void * w, fd_sol_sysvar_clock_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_sol_sysvar_clock_size( fd_sol_sysvar_clock_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_sol_sysvar_clock_align( void ) { return FD_SOL_SYSVAR_CLOCK_ALIGN; }
static inline int fd_sol_sysvar_clock_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_sol_sysvar_clock_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_sol_sysvar_clock_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_sol_sysvar_last_restart_slot_new( fd_sol_sysvar_last_restart_slot_t * self ) { fd_memset( self, 0, sizeof(fd_sol_sysvar_last_restart_slot_t) ); }
int fd_sol_sysvar_last_restart_slot_encode( fd_sol_sysvar_last_restart_slot_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_sol_sysvar_last_restart_slot_walk( void * w, fd_sol_sysvar_last_restart_slot_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_sol_sysvar_last_restart_slot_size( fd_sol_sysvar_last_restart_slot_t const * self ) { (void)self; return 8UL; }
static inline ulong fd_sol_sysvar_last_restart_slot_align( void ) { return FD_SOL_SYSVAR_LAST_RESTART_SLOT_ALIGN; }
static inline int fd_sol_sysvar_last_restart_slot_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_sol_sysvar_last_restart_slot_t);
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_sol_sysvar_last_restart_slot_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_lockout_new( fd_vote_lockout_t * self ) { fd_memset( self, 0, sizeof(fd_vote_lockout_t) ); }
int fd_vote_lockout_encode( fd_vote_lockout_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_lockout_walk( void * w, fd_vote_lockout_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_lockout_size( fd_vote_lockout_t const * self ) { (void)self; return 12UL; }
static inline ulong fd_vote_lockout_align( void ) { return FD_VOTE_LOCKOUT_ALIGN; }
static inline int fd_vote_lockout_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_lockout_t);
  if( (ulong)ctx->data + 12UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_lockout_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_lockout_offset_new( fd_lockout_offset_t * self );
int fd_lockout_offset_encode( fd_lockout_offset_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_lockout_offset_walk( void * w, fd_lockout_offset_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_lockout_offset_size( fd_lockout_offset_t const * self );
static inline ulong fd_lockout_offset_align( void ) { return FD_LOCKOUT_OFFSET_ALIGN; }
int fd_lockout_offset_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_lockout_offset_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_authorized_voter_new( fd_vote_authorized_voter_t * self ) { fd_memset( self, 0, sizeof(fd_vote_authorized_voter_t) ); }
int fd_vote_authorized_voter_encode( fd_vote_authorized_voter_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_authorized_voter_walk( void * w, fd_vote_authorized_voter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_authorized_voter_size( fd_vote_authorized_voter_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_vote_authorized_voter_align( void ) { return FD_VOTE_AUTHORIZED_VOTER_ALIGN; }
static inline int fd_vote_authorized_voter_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_authorized_voter_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_authorized_voter_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_prior_voter_new( fd_vote_prior_voter_t * self ) { fd_memset( self, 0, sizeof(fd_vote_prior_voter_t) ); }
int fd_vote_prior_voter_encode( fd_vote_prior_voter_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_prior_voter_walk( void * w, fd_vote_prior_voter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_prior_voter_size( fd_vote_prior_voter_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_vote_prior_voter_align( void ) { return FD_VOTE_PRIOR_VOTER_ALIGN; }
static inline int fd_vote_prior_voter_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_prior_voter_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_prior_voter_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_prior_voter_0_23_5_new( fd_vote_prior_voter_0_23_5_t * self ) { fd_memset( self, 0, sizeof(fd_vote_prior_voter_0_23_5_t) ); }
int fd_vote_prior_voter_0_23_5_encode( fd_vote_prior_voter_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_prior_voter_0_23_5_walk( void * w, fd_vote_prior_voter_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_prior_voter_0_23_5_size( fd_vote_prior_voter_0_23_5_t const * self ) { (void)self; return 56UL; }
static inline ulong fd_vote_prior_voter_0_23_5_align( void ) { return FD_VOTE_PRIOR_VOTER_0_23_5_ALIGN; }
static inline int fd_vote_prior_voter_0_23_5_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_prior_voter_0_23_5_t);
  if( (ulong)ctx->data + 56UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_prior_voter_0_23_5_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_epoch_credits_new( fd_vote_epoch_credits_t * self ) { fd_memset( self, 0, sizeof(fd_vote_epoch_credits_t) ); }
int fd_vote_epoch_credits_encode( fd_vote_epoch_credits_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_epoch_credits_walk( void * w, fd_vote_epoch_credits_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_epoch_credits_size( fd_vote_epoch_credits_t const * self ) { (void)self; return 24UL; }
static inline ulong fd_vote_epoch_credits_align( void ) { return FD_VOTE_EPOCH_CREDITS_ALIGN; }
static inline int fd_vote_epoch_credits_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_epoch_credits_t);
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_epoch_credits_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_block_timestamp_new( fd_vote_block_timestamp_t * self ) { fd_memset( self, 0, sizeof(fd_vote_block_timestamp_t) ); }
int fd_vote_block_timestamp_encode( fd_vote_block_timestamp_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_block_timestamp_walk( void * w, fd_vote_block_timestamp_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_block_timestamp_size( fd_vote_block_timestamp_t const * self ) { (void)self; return 16UL; }
static inline ulong fd_vote_block_timestamp_align( void ) { return FD_VOTE_BLOCK_TIMESTAMP_ALIGN; }
static inline int fd_vote_block_timestamp_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_block_timestamp_t);
  if( (ulong)ctx->data + 16UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_block_timestamp_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_prior_voters_new( fd_vote_prior_voters_t * self );
int fd_vote_prior_voters_encode( fd_vote_prior_voters_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_prior_voters_walk( void * w, fd_vote_prior_voters_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_prior_voters_size( fd_vote_prior_voters_t const * self ) { (void)self; return 1545UL; }
static inline ulong fd_vote_prior_voters_align( void ) { return FD_VOTE_PRIOR_VOTERS_ALIGN; }
int fd_vote_prior_voters_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_prior_voters_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_prior_voters_0_23_5_new( fd_vote_prior_voters_0_23_5_t * self ) { fd_memset( self, 0, sizeof(fd_vote_prior_voters_0_23_5_t) ); }
int fd_vote_prior_voters_0_23_5_encode( fd_vote_prior_voters_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_prior_voters_0_23_5_walk( void * w, fd_vote_prior_voters_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_prior_voters_0_23_5_size( fd_vote_prior_voters_0_23_5_t const * self ) { (void)self; return 1800UL; }
static inline ulong fd_vote_prior_voters_0_23_5_align( void ) { return FD_VOTE_PRIOR_VOTERS_0_23_5_ALIGN; }
static inline int fd_vote_prior_voters_0_23_5_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_prior_voters_0_23_5_t);
  if( (ulong)ctx->data + 1800UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_prior_voters_0_23_5_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_landed_vote_new( fd_landed_vote_t * self ) { fd_memset( self, 0, sizeof(fd_landed_vote_t) ); }
int fd_landed_vote_encode( fd_landed_vote_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_landed_vote_walk( void * w, fd_landed_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_landed_vote_size( fd_landed_vote_t const * self ) { (void)self; return 13UL; }
static inline ulong fd_landed_vote_align( void ) { return FD_LANDED_VOTE_ALIGN; }
static inline int fd_landed_vote_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_landed_vote_t);
  if( (ulong)ctx->data + 13UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_landed_vote_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_state_0_23_5_new( fd_vote_state_0_23_5_t * self );
int fd_vote_state_0_23_5_encode( fd_vote_state_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_state_0_23_5_walk( void * w, fd_vote_state_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_state_0_23_5_size( fd_vote_state_0_23_5_t const * self );
static inline ulong fd_vote_state_0_23_5_align( void ) { return FD_VOTE_STATE_0_23_5_ALIGN; }
int fd_vote_state_0_23_5_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_state_0_23_5_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_authorized_voters_new( fd_vote_authorized_voters_t * self );
int fd_vote_authorized_voters_encode( fd_vote_authorized_voters_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_authorized_voters_walk( void * w, fd_vote_authorized_voters_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_authorized_voters_size( fd_vote_authorized_voters_t const * self );
static inline ulong fd_vote_authorized_voters_align( void ) { return FD_VOTE_AUTHORIZED_VOTERS_ALIGN; }
int fd_vote_authorized_voters_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_authorized_voters_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_state_1_14_11_new( fd_vote_state_1_14_11_t * self );
int fd_vote_state_1_14_11_encode( fd_vote_state_1_14_11_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_state_1_14_11_walk( void * w, fd_vote_state_1_14_11_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_state_1_14_11_size( fd_vote_state_1_14_11_t const * self );
static inline ulong fd_vote_state_1_14_11_align( void ) { return FD_VOTE_STATE_1_14_11_ALIGN; }
int fd_vote_state_1_14_11_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_state_1_14_11_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_state_new( fd_vote_state_t * self );
int fd_vote_state_encode( fd_vote_state_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_state_walk( void * w, fd_vote_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_state_size( fd_vote_state_t const * self );
static inline ulong fd_vote_state_align( void ) { return FD_VOTE_STATE_ALIGN; }
int fd_vote_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_state_versioned_new_disc( fd_vote_state_versioned_t * self, uint discriminant );
void fd_vote_state_versioned_new( fd_vote_state_versioned_t * self );
int fd_vote_state_versioned_encode( fd_vote_state_versioned_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_state_versioned_walk( void * w, fd_vote_state_versioned_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_state_versioned_size( fd_vote_state_versioned_t const * self );
static inline ulong fd_vote_state_versioned_align( void ) { return FD_VOTE_STATE_VERSIONED_ALIGN; }
int fd_vote_state_versioned_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_state_versioned_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_vote_state_versioned_is_v0_23_5( fd_vote_state_versioned_t const * self );
FD_FN_PURE uchar fd_vote_state_versioned_is_v1_14_11( fd_vote_state_versioned_t const * self );
FD_FN_PURE uchar fd_vote_state_versioned_is_current( fd_vote_state_versioned_t const * self );
enum {
fd_vote_state_versioned_enum_v0_23_5 = 0,
fd_vote_state_versioned_enum_v1_14_11 = 1,
fd_vote_state_versioned_enum_current = 2,
};
void fd_vote_state_update_new( fd_vote_state_update_t * self );
int fd_vote_state_update_encode( fd_vote_state_update_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_state_update_walk( void * w, fd_vote_state_update_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_state_update_size( fd_vote_state_update_t const * self );
static inline ulong fd_vote_state_update_align( void ) { return FD_VOTE_STATE_UPDATE_ALIGN; }
int fd_vote_state_update_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_state_update_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_compact_vote_state_update_new( fd_compact_vote_state_update_t * self );
int fd_compact_vote_state_update_encode( fd_compact_vote_state_update_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_compact_vote_state_update_walk( void * w, fd_compact_vote_state_update_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_compact_vote_state_update_size( fd_compact_vote_state_update_t const * self );
static inline ulong fd_compact_vote_state_update_align( void ) { return FD_COMPACT_VOTE_STATE_UPDATE_ALIGN; }
int fd_compact_vote_state_update_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_compact_vote_state_update_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_compact_vote_state_update_switch_new( fd_compact_vote_state_update_switch_t * self );
int fd_compact_vote_state_update_switch_encode( fd_compact_vote_state_update_switch_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_compact_vote_state_update_switch_walk( void * w, fd_compact_vote_state_update_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_compact_vote_state_update_switch_size( fd_compact_vote_state_update_switch_t const * self );
static inline ulong fd_compact_vote_state_update_switch_align( void ) { return FD_COMPACT_VOTE_STATE_UPDATE_SWITCH_ALIGN; }
int fd_compact_vote_state_update_switch_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_compact_vote_state_update_switch_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_compact_tower_sync_new( fd_compact_tower_sync_t * self );
int fd_compact_tower_sync_encode( fd_compact_tower_sync_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_compact_tower_sync_walk( void * w, fd_compact_tower_sync_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_compact_tower_sync_size( fd_compact_tower_sync_t const * self );
static inline ulong fd_compact_tower_sync_align( void ) { return FD_COMPACT_TOWER_SYNC_ALIGN; }
int fd_compact_tower_sync_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_compact_tower_sync_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_tower_sync_new( fd_tower_sync_t * self );
int fd_tower_sync_encode( fd_tower_sync_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_tower_sync_walk( void * w, fd_tower_sync_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_tower_sync_size( fd_tower_sync_t const * self );
static inline ulong fd_tower_sync_align( void ) { return FD_TOWER_SYNC_ALIGN; }
int fd_tower_sync_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_tower_sync_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_tower_sync_switch_new( fd_tower_sync_switch_t * self );
int fd_tower_sync_switch_encode( fd_tower_sync_switch_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_tower_sync_switch_walk( void * w, fd_tower_sync_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_tower_sync_switch_size( fd_tower_sync_switch_t const * self );
static inline ulong fd_tower_sync_switch_align( void ) { return FD_TOWER_SYNC_SWITCH_ALIGN; }
int fd_tower_sync_switch_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_tower_sync_switch_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_slot_history_new( fd_slot_history_t * self );
int fd_slot_history_encode( fd_slot_history_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_slot_history_walk( void * w, fd_slot_history_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_slot_history_size( fd_slot_history_t const * self );
static inline ulong fd_slot_history_align( void ) { return FD_SLOT_HISTORY_ALIGN; }
int fd_slot_history_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_history_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_slot_history_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_slot_history_encode_global( fd_slot_history_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_history_size_global( fd_slot_history_global_t const * self );

static inline void fd_slot_hash_new( fd_slot_hash_t * self ) { fd_memset( self, 0, sizeof(fd_slot_hash_t) ); }
int fd_slot_hash_encode( fd_slot_hash_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_slot_hash_walk( void * w, fd_slot_hash_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_slot_hashes_walk( void * w, fd_slot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_slot_hashes_size( fd_slot_hashes_t const * self );
static inline ulong fd_slot_hashes_align( void ) { return FD_SLOT_HASHES_ALIGN; }
int fd_slot_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_slot_hashes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_slot_hashes_encode_global( fd_slot_hashes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_hashes_size_global( fd_slot_hashes_global_t const * self );

static inline void fd_block_block_hash_entry_new( fd_block_block_hash_entry_t * self ) { fd_memset( self, 0, sizeof(fd_block_block_hash_entry_t) ); }
int fd_block_block_hash_entry_encode( fd_block_block_hash_entry_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_block_block_hash_entry_walk( void * w, fd_block_block_hash_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_recent_block_hashes_walk( void * w, fd_recent_block_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_recent_block_hashes_size( fd_recent_block_hashes_t const * self );
static inline ulong fd_recent_block_hashes_align( void ) { return FD_RECENT_BLOCK_HASHES_ALIGN; }
int fd_recent_block_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_recent_block_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_recent_block_hashes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_recent_block_hashes_encode_global( fd_recent_block_hashes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_recent_block_hashes_size_global( fd_recent_block_hashes_global_t const * self );

void fd_slot_meta_new( fd_slot_meta_t * self );
int fd_slot_meta_encode( fd_slot_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_slot_meta_walk( void * w, fd_slot_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_slot_meta_size( fd_slot_meta_t const * self );
static inline ulong fd_slot_meta_align( void ) { return FD_SLOT_META_ALIGN; }
int fd_slot_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_clock_timestamp_vote_new( fd_clock_timestamp_vote_t * self ) { fd_memset( self, 0, sizeof(fd_clock_timestamp_vote_t) ); }
int fd_clock_timestamp_vote_encode( fd_clock_timestamp_vote_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_clock_timestamp_vote_walk( void * w, fd_clock_timestamp_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_clock_timestamp_vote_size( fd_clock_timestamp_vote_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_clock_timestamp_vote_align( void ) { return FD_CLOCK_TIMESTAMP_VOTE_ALIGN; }
static inline int fd_clock_timestamp_vote_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_clock_timestamp_vote_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_clock_timestamp_vote_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_clock_timestamp_votes_new( fd_clock_timestamp_votes_t * self );
int fd_clock_timestamp_votes_encode( fd_clock_timestamp_votes_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_clock_timestamp_votes_walk( void * w, fd_clock_timestamp_votes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_clock_timestamp_votes_size( fd_clock_timestamp_votes_t const * self );
static inline ulong fd_clock_timestamp_votes_align( void ) { return FD_CLOCK_TIMESTAMP_VOTES_ALIGN; }
int fd_clock_timestamp_votes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_clock_timestamp_votes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_clock_timestamp_votes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_clock_timestamp_votes_encode_global( fd_clock_timestamp_votes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_clock_timestamp_votes_size_global( fd_clock_timestamp_votes_global_t const * self );

static inline void fd_sysvar_fees_new( fd_sysvar_fees_t * self ) { fd_memset( self, 0, sizeof(fd_sysvar_fees_t) ); }
int fd_sysvar_fees_encode( fd_sysvar_fees_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_sysvar_fees_walk( void * w, fd_sysvar_fees_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_sysvar_epoch_rewards_walk( void * w, fd_sysvar_epoch_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_sysvar_epoch_rewards_size( fd_sysvar_epoch_rewards_t const * self ) { (void)self; return 81UL; }
static inline ulong fd_sysvar_epoch_rewards_align( void ) { return FD_SYSVAR_EPOCH_REWARDS_ALIGN; }
int fd_sysvar_epoch_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_sysvar_epoch_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_config_keys_pair_new( fd_config_keys_pair_t * self );
int fd_config_keys_pair_encode( fd_config_keys_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_config_keys_pair_walk( void * w, fd_config_keys_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_config_keys_pair_size( fd_config_keys_pair_t const * self ) { (void)self; return 33UL; }
static inline ulong fd_config_keys_pair_align( void ) { return FD_CONFIG_KEYS_PAIR_ALIGN; }
int fd_config_keys_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_config_keys_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_stake_config_new( fd_stake_config_t * self );
int fd_stake_config_encode( fd_stake_config_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_config_walk( void * w, fd_stake_config_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stake_config_size( fd_stake_config_t const * self );
static inline ulong fd_stake_config_align( void ) { return FD_STAKE_CONFIG_ALIGN; }
int fd_stake_config_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_config_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_feature_entry_new( fd_feature_entry_t * self );
int fd_feature_entry_encode( fd_feature_entry_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_feature_entry_walk( void * w, fd_feature_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_feature_entry_size( fd_feature_entry_t const * self );
static inline ulong fd_feature_entry_align( void ) { return FD_FEATURE_ENTRY_ALIGN; }
int fd_feature_entry_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_feature_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_cluster_type_new_disc( fd_cluster_type_t * self, uint discriminant ) { self->discriminant = discriminant; }
static inline void fd_cluster_type_new( fd_cluster_type_t * self ) { self->discriminant = (uint)ULONG_MAX; }
int fd_cluster_type_encode( fd_cluster_type_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_cluster_type_walk( void * w, fd_cluster_type_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_cluster_type_size( fd_cluster_type_t const * self );
static inline ulong fd_cluster_type_align( void ) { return FD_CLUSTER_TYPE_ALIGN; }
int fd_cluster_type_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_cluster_type_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_cluster_type_is_Testnet( fd_cluster_type_t const * self );
FD_FN_PURE uchar fd_cluster_type_is_MainnetBeta( fd_cluster_type_t const * self );
FD_FN_PURE uchar fd_cluster_type_is_Devnet( fd_cluster_type_t const * self );
FD_FN_PURE uchar fd_cluster_type_is_Development( fd_cluster_type_t const * self );
enum {
fd_cluster_type_enum_Testnet = 0,
fd_cluster_type_enum_MainnetBeta = 1,
fd_cluster_type_enum_Devnet = 2,
fd_cluster_type_enum_Development = 3,
};
static inline void fd_cluster_version_new( fd_cluster_version_t * self ) { fd_memset( self, 0, sizeof(fd_cluster_version_t) ); }
int fd_cluster_version_encode( fd_cluster_version_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_cluster_version_walk( void * w, fd_cluster_version_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_cluster_version_size( fd_cluster_version_t const * self ) { (void)self; return 12UL; }
static inline ulong fd_cluster_version_align( void ) { return FD_CLUSTER_VERSION_ALIGN; }
static inline int fd_cluster_version_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_cluster_version_t);
  if( (ulong)ctx->data + 12UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_cluster_version_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_reward_new( fd_stake_reward_t * self ) { fd_memset( self, 0, sizeof(fd_stake_reward_t) ); }
int fd_stake_reward_encode( fd_stake_reward_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_reward_walk( void * w, fd_stake_reward_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_reward_size( fd_stake_reward_t const * self ) { (void)self; return 49UL; }
static inline ulong fd_stake_reward_align( void ) { return FD_STAKE_REWARD_ALIGN; }
static inline int fd_stake_reward_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_reward_t);
  if( (ulong)ctx->data + 49UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_reward_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_reward_new( fd_vote_reward_t * self ) { fd_memset( self, 0, sizeof(fd_vote_reward_t) ); }
int fd_vote_reward_encode( fd_vote_reward_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_reward_walk( void * w, fd_vote_reward_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_reward_size( fd_vote_reward_t const * self ) { (void)self; return 42UL; }
static inline ulong fd_vote_reward_align( void ) { return FD_VOTE_REWARD_ALIGN; }
static inline int fd_vote_reward_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_reward_t);
  if( (ulong)ctx->data + 42UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_reward_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_point_value_new( fd_point_value_t * self ) { fd_memset( self, 0, sizeof(fd_point_value_t) ); }
int fd_point_value_encode( fd_point_value_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_point_value_walk( void * w, fd_point_value_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_point_value_size( fd_point_value_t const * self ) { (void)self; return 24UL; }
static inline ulong fd_point_value_align( void ) { return FD_POINT_VALUE_ALIGN; }
static inline int fd_point_value_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_point_value_t);
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_point_value_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_partitioned_stake_rewards_new( fd_partitioned_stake_rewards_t * self );
int fd_partitioned_stake_rewards_encode( fd_partitioned_stake_rewards_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_partitioned_stake_rewards_walk( void * w, fd_partitioned_stake_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_partitioned_stake_rewards_size( fd_partitioned_stake_rewards_t const * self );
static inline ulong fd_partitioned_stake_rewards_align( void ) { return FD_PARTITIONED_STAKE_REWARDS_ALIGN; }
int fd_partitioned_stake_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_partitioned_stake_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_partitioned_stake_rewards_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_partitioned_stake_rewards_encode_global( fd_partitioned_stake_rewards_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_partitioned_stake_rewards_size_global( fd_partitioned_stake_rewards_global_t const * self );

void fd_stake_reward_calculation_partitioned_new( fd_stake_reward_calculation_partitioned_t * self );
int fd_stake_reward_calculation_partitioned_encode( fd_stake_reward_calculation_partitioned_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_reward_calculation_partitioned_walk( void * w, fd_stake_reward_calculation_partitioned_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stake_reward_calculation_partitioned_size( fd_stake_reward_calculation_partitioned_t const * self );
static inline ulong fd_stake_reward_calculation_partitioned_align( void ) { return FD_STAKE_REWARD_CALCULATION_PARTITIONED_ALIGN; }
int fd_stake_reward_calculation_partitioned_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_reward_calculation_partitioned_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_stake_reward_calculation_new( fd_stake_reward_calculation_t * self );
int fd_stake_reward_calculation_encode( fd_stake_reward_calculation_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_reward_calculation_walk( void * w, fd_stake_reward_calculation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stake_reward_calculation_size( fd_stake_reward_calculation_t const * self );
static inline ulong fd_stake_reward_calculation_align( void ) { return FD_STAKE_REWARD_CALCULATION_ALIGN; }
int fd_stake_reward_calculation_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_reward_calculation_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_calculate_stake_vote_rewards_result_new( fd_calculate_stake_vote_rewards_result_t * self );
int fd_calculate_stake_vote_rewards_result_encode( fd_calculate_stake_vote_rewards_result_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_calculate_stake_vote_rewards_result_walk( void * w, fd_calculate_stake_vote_rewards_result_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_calculate_stake_vote_rewards_result_size( fd_calculate_stake_vote_rewards_result_t const * self );
static inline ulong fd_calculate_stake_vote_rewards_result_align( void ) { return FD_CALCULATE_STAKE_VOTE_REWARDS_RESULT_ALIGN; }
int fd_calculate_stake_vote_rewards_result_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_calculate_stake_vote_rewards_result_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_calculate_validator_rewards_result_new( fd_calculate_validator_rewards_result_t * self );
int fd_calculate_validator_rewards_result_encode( fd_calculate_validator_rewards_result_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_calculate_validator_rewards_result_walk( void * w, fd_calculate_validator_rewards_result_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_calculate_validator_rewards_result_size( fd_calculate_validator_rewards_result_t const * self );
static inline ulong fd_calculate_validator_rewards_result_align( void ) { return FD_CALCULATE_VALIDATOR_REWARDS_RESULT_ALIGN; }
int fd_calculate_validator_rewards_result_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_calculate_validator_rewards_result_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_partitioned_rewards_calculation_new( fd_partitioned_rewards_calculation_t * self );
int fd_partitioned_rewards_calculation_encode( fd_partitioned_rewards_calculation_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_partitioned_rewards_calculation_walk( void * w, fd_partitioned_rewards_calculation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_partitioned_rewards_calculation_size( fd_partitioned_rewards_calculation_t const * self );
static inline ulong fd_partitioned_rewards_calculation_align( void ) { return FD_PARTITIONED_REWARDS_CALCULATION_ALIGN; }
int fd_partitioned_rewards_calculation_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_partitioned_rewards_calculation_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_start_block_height_and_rewards_new( fd_start_block_height_and_rewards_t * self );
int fd_start_block_height_and_rewards_encode( fd_start_block_height_and_rewards_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_start_block_height_and_rewards_walk( void * w, fd_start_block_height_and_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_start_block_height_and_rewards_size( fd_start_block_height_and_rewards_t const * self );
static inline ulong fd_start_block_height_and_rewards_align( void ) { return FD_START_BLOCK_HEIGHT_AND_REWARDS_ALIGN; }
int fd_start_block_height_and_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_start_block_height_and_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_start_block_height_and_rewards_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_start_block_height_and_rewards_encode_global( fd_start_block_height_and_rewards_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_start_block_height_and_rewards_size_global( fd_start_block_height_and_rewards_global_t const * self );

void fd_fd_epoch_reward_status_inner_new( fd_fd_epoch_reward_status_inner_t * self );
int fd_fd_epoch_reward_status_inner_encode( fd_fd_epoch_reward_status_inner_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_fd_epoch_reward_status_inner_walk( void * w, fd_fd_epoch_reward_status_inner_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_fd_epoch_reward_status_inner_size( fd_fd_epoch_reward_status_inner_t const * self );
static inline ulong fd_fd_epoch_reward_status_inner_align( void ) { return FD_FD_EPOCH_REWARD_STATUS_INNER_ALIGN; }
int fd_fd_epoch_reward_status_inner_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_fd_epoch_reward_status_inner_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_epoch_reward_status_new_disc( fd_epoch_reward_status_t * self, uint discriminant );
void fd_epoch_reward_status_new( fd_epoch_reward_status_t * self );
int fd_epoch_reward_status_encode( fd_epoch_reward_status_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_epoch_reward_status_walk( void * w, fd_epoch_reward_status_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_epoch_reward_status_size( fd_epoch_reward_status_t const * self );
static inline ulong fd_epoch_reward_status_align( void ) { return FD_EPOCH_REWARD_STATUS_ALIGN; }
int fd_epoch_reward_status_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_epoch_reward_status_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_epoch_reward_status_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_epoch_reward_status_encode_global( fd_epoch_reward_status_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_epoch_reward_status_size_global( fd_epoch_reward_status_global_t const * self );

FD_FN_PURE uchar fd_epoch_reward_status_is_Active( fd_epoch_reward_status_t const * self );
FD_FN_PURE uchar fd_epoch_reward_status_is_Inactive( fd_epoch_reward_status_t const * self );
enum {
fd_epoch_reward_status_enum_Active = 0,
fd_epoch_reward_status_enum_Inactive = 1,
};
static inline void fd_prev_epoch_inflation_rewards_new( fd_prev_epoch_inflation_rewards_t * self ) { fd_memset( self, 0, sizeof(fd_prev_epoch_inflation_rewards_t) ); }
int fd_prev_epoch_inflation_rewards_encode( fd_prev_epoch_inflation_rewards_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_prev_epoch_inflation_rewards_walk( void * w, fd_prev_epoch_inflation_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_prev_epoch_inflation_rewards_size( fd_prev_epoch_inflation_rewards_t const * self ) { (void)self; return 32UL; }
static inline ulong fd_prev_epoch_inflation_rewards_align( void ) { return FD_PREV_EPOCH_INFLATION_REWARDS_ALIGN; }
static inline int fd_prev_epoch_inflation_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_prev_epoch_inflation_rewards_t);
  if( (ulong)ctx->data + 32UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_prev_epoch_inflation_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_new( fd_vote_t * self );
int fd_vote_encode( fd_vote_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_walk( void * w, fd_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_size( fd_vote_t const * self );
static inline ulong fd_vote_align( void ) { return FD_VOTE_ALIGN; }
int fd_vote_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_init_new( fd_vote_init_t * self ) { fd_memset( self, 0, sizeof(fd_vote_init_t) ); }
int fd_vote_init_encode( fd_vote_init_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_init_walk( void * w, fd_vote_init_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_init_size( fd_vote_init_t const * self ) { (void)self; return 97UL; }
static inline ulong fd_vote_init_align( void ) { return FD_VOTE_INIT_ALIGN; }
static inline int fd_vote_init_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_init_t);
  if( (ulong)ctx->data + 97UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_vote_init_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_vote_authorize_new_disc( fd_vote_authorize_t * self, uint discriminant ) { self->discriminant = discriminant; }
static inline void fd_vote_authorize_new( fd_vote_authorize_t * self ) { self->discriminant = (uint)ULONG_MAX; }
int fd_vote_authorize_encode( fd_vote_authorize_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_authorize_walk( void * w, fd_vote_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_authorize_size( fd_vote_authorize_t const * self );
static inline ulong fd_vote_authorize_align( void ) { return FD_VOTE_AUTHORIZE_ALIGN; }
int fd_vote_authorize_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_authorize_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_vote_authorize_is_voter( fd_vote_authorize_t const * self );
FD_FN_PURE uchar fd_vote_authorize_is_withdrawer( fd_vote_authorize_t const * self );
enum {
fd_vote_authorize_enum_voter = 0,
fd_vote_authorize_enum_withdrawer = 1,
};
void fd_vote_authorize_pubkey_new( fd_vote_authorize_pubkey_t * self );
int fd_vote_authorize_pubkey_encode( fd_vote_authorize_pubkey_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_authorize_pubkey_walk( void * w, fd_vote_authorize_pubkey_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_vote_authorize_pubkey_size( fd_vote_authorize_pubkey_t const * self ) { (void)self; return 36UL; }
static inline ulong fd_vote_authorize_pubkey_align( void ) { return FD_VOTE_AUTHORIZE_PUBKEY_ALIGN; }
int fd_vote_authorize_pubkey_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_authorize_pubkey_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_switch_new( fd_vote_switch_t * self );
int fd_vote_switch_encode( fd_vote_switch_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_switch_walk( void * w, fd_vote_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_switch_size( fd_vote_switch_t const * self );
static inline ulong fd_vote_switch_align( void ) { return FD_VOTE_SWITCH_ALIGN; }
int fd_vote_switch_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_switch_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_update_vote_state_switch_new( fd_update_vote_state_switch_t * self );
int fd_update_vote_state_switch_encode( fd_update_vote_state_switch_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_update_vote_state_switch_walk( void * w, fd_update_vote_state_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_update_vote_state_switch_size( fd_update_vote_state_switch_t const * self );
static inline ulong fd_update_vote_state_switch_align( void ) { return FD_UPDATE_VOTE_STATE_SWITCH_ALIGN; }
int fd_update_vote_state_switch_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_update_vote_state_switch_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_authorize_with_seed_args_new( fd_vote_authorize_with_seed_args_t * self );
int fd_vote_authorize_with_seed_args_encode( fd_vote_authorize_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_authorize_with_seed_args_walk( void * w, fd_vote_authorize_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_authorize_with_seed_args_size( fd_vote_authorize_with_seed_args_t const * self );
static inline ulong fd_vote_authorize_with_seed_args_align( void ) { return FD_VOTE_AUTHORIZE_WITH_SEED_ARGS_ALIGN; }
int fd_vote_authorize_with_seed_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_authorize_with_seed_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_authorize_checked_with_seed_args_new( fd_vote_authorize_checked_with_seed_args_t * self );
int fd_vote_authorize_checked_with_seed_args_encode( fd_vote_authorize_checked_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_authorize_checked_with_seed_args_walk( void * w, fd_vote_authorize_checked_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_authorize_checked_with_seed_args_size( fd_vote_authorize_checked_with_seed_args_t const * self );
static inline ulong fd_vote_authorize_checked_with_seed_args_align( void ) { return FD_VOTE_AUTHORIZE_CHECKED_WITH_SEED_ARGS_ALIGN; }
int fd_vote_authorize_checked_with_seed_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_authorize_checked_with_seed_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_instruction_new_disc( fd_vote_instruction_t * self, uint discriminant );
void fd_vote_instruction_new( fd_vote_instruction_t * self );
int fd_vote_instruction_encode( fd_vote_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_instruction_walk( void * w, fd_vote_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_instruction_size( fd_vote_instruction_t const * self );
static inline ulong fd_vote_instruction_align( void ) { return FD_VOTE_INSTRUCTION_ALIGN; }
int fd_vote_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_vote_instruction_is_initialize_account( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_authorize( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_vote( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_withdraw( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_update_validator_identity( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_update_commission( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_vote_switch( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_authorize_checked( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_update_vote_state( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_update_vote_state_switch( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_authorize_with_seed( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_authorize_checked_with_seed( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_compact_update_vote_state( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_compact_update_vote_state_switch( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_tower_sync( fd_vote_instruction_t const * self );
FD_FN_PURE uchar fd_vote_instruction_is_tower_sync_switch( fd_vote_instruction_t const * self );
enum {
fd_vote_instruction_enum_initialize_account = 0,
fd_vote_instruction_enum_authorize = 1,
fd_vote_instruction_enum_vote = 2,
fd_vote_instruction_enum_withdraw = 3,
fd_vote_instruction_enum_update_validator_identity = 4,
fd_vote_instruction_enum_update_commission = 5,
fd_vote_instruction_enum_vote_switch = 6,
fd_vote_instruction_enum_authorize_checked = 7,
fd_vote_instruction_enum_update_vote_state = 8,
fd_vote_instruction_enum_update_vote_state_switch = 9,
fd_vote_instruction_enum_authorize_with_seed = 10,
fd_vote_instruction_enum_authorize_checked_with_seed = 11,
fd_vote_instruction_enum_compact_update_vote_state = 12,
fd_vote_instruction_enum_compact_update_vote_state_switch = 13,
fd_vote_instruction_enum_tower_sync = 14,
fd_vote_instruction_enum_tower_sync_switch = 15,
};
static inline void fd_system_program_instruction_create_account_new( fd_system_program_instruction_create_account_t * self ) { fd_memset( self, 0, sizeof(fd_system_program_instruction_create_account_t) ); }
int fd_system_program_instruction_create_account_encode( fd_system_program_instruction_create_account_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_system_program_instruction_create_account_walk( void * w, fd_system_program_instruction_create_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_system_program_instruction_create_account_with_seed_walk( void * w, fd_system_program_instruction_create_account_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_system_program_instruction_create_account_with_seed_size( fd_system_program_instruction_create_account_with_seed_t const * self );
static inline ulong fd_system_program_instruction_create_account_with_seed_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_WITH_SEED_ALIGN; }
int fd_system_program_instruction_create_account_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_create_account_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_allocate_with_seed_new( fd_system_program_instruction_allocate_with_seed_t * self );
int fd_system_program_instruction_allocate_with_seed_encode( fd_system_program_instruction_allocate_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_system_program_instruction_allocate_with_seed_walk( void * w, fd_system_program_instruction_allocate_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_system_program_instruction_allocate_with_seed_size( fd_system_program_instruction_allocate_with_seed_t const * self );
static inline ulong fd_system_program_instruction_allocate_with_seed_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_ALLOCATE_WITH_SEED_ALIGN; }
int fd_system_program_instruction_allocate_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_allocate_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_assign_with_seed_new( fd_system_program_instruction_assign_with_seed_t * self );
int fd_system_program_instruction_assign_with_seed_encode( fd_system_program_instruction_assign_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_system_program_instruction_assign_with_seed_walk( void * w, fd_system_program_instruction_assign_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_system_program_instruction_assign_with_seed_size( fd_system_program_instruction_assign_with_seed_t const * self );
static inline ulong fd_system_program_instruction_assign_with_seed_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_ASSIGN_WITH_SEED_ALIGN; }
int fd_system_program_instruction_assign_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_assign_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_transfer_with_seed_new( fd_system_program_instruction_transfer_with_seed_t * self );
int fd_system_program_instruction_transfer_with_seed_encode( fd_system_program_instruction_transfer_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_system_program_instruction_transfer_with_seed_walk( void * w, fd_system_program_instruction_transfer_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_system_program_instruction_transfer_with_seed_size( fd_system_program_instruction_transfer_with_seed_t const * self );
static inline ulong fd_system_program_instruction_transfer_with_seed_align( void ) { return FD_SYSTEM_PROGRAM_INSTRUCTION_TRANSFER_WITH_SEED_ALIGN; }
int fd_system_program_instruction_transfer_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_program_instruction_transfer_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_system_program_instruction_new_disc( fd_system_program_instruction_t * self, uint discriminant );
void fd_system_program_instruction_new( fd_system_program_instruction_t * self );
int fd_system_program_instruction_encode( fd_system_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_system_program_instruction_walk( void * w, fd_system_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
};
static inline void fd_system_error_new_disc( fd_system_error_t * self, uint discriminant ) { self->discriminant = discriminant; }
static inline void fd_system_error_new( fd_system_error_t * self ) { self->discriminant = (uint)ULONG_MAX; }
int fd_system_error_encode( fd_system_error_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_system_error_walk( void * w, fd_system_error_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_system_error_size( fd_system_error_t const * self );
static inline ulong fd_system_error_align( void ) { return FD_SYSTEM_ERROR_ALIGN; }
int fd_system_error_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_system_error_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_system_error_is_account_already_in_use( fd_system_error_t const * self );
FD_FN_PURE uchar fd_system_error_is_result_with_negative_lamports( fd_system_error_t const * self );
FD_FN_PURE uchar fd_system_error_is_invalid_program_id( fd_system_error_t const * self );
FD_FN_PURE uchar fd_system_error_is_invalid_account_data_length( fd_system_error_t const * self );
FD_FN_PURE uchar fd_system_error_is_max_seed_length_exceeded( fd_system_error_t const * self );
FD_FN_PURE uchar fd_system_error_is_address_with_seed_mismatch( fd_system_error_t const * self );
FD_FN_PURE uchar fd_system_error_is_nonce_no_recent_blockhashes( fd_system_error_t const * self );
FD_FN_PURE uchar fd_system_error_is_nonce_blockhash_not_expired( fd_system_error_t const * self );
FD_FN_PURE uchar fd_system_error_is_nonce_unexpected_blockhash_value( fd_system_error_t const * self );
enum {
fd_system_error_enum_account_already_in_use = 0,
fd_system_error_enum_result_with_negative_lamports = 1,
fd_system_error_enum_invalid_program_id = 2,
fd_system_error_enum_invalid_account_data_length = 3,
fd_system_error_enum_max_seed_length_exceeded = 4,
fd_system_error_enum_address_with_seed_mismatch = 5,
fd_system_error_enum_nonce_no_recent_blockhashes = 6,
fd_system_error_enum_nonce_blockhash_not_expired = 7,
fd_system_error_enum_nonce_unexpected_blockhash_value = 8,
};
static inline void fd_stake_authorized_new( fd_stake_authorized_t * self ) { fd_memset( self, 0, sizeof(fd_stake_authorized_t) ); }
int fd_stake_authorized_encode( fd_stake_authorized_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_authorized_walk( void * w, fd_stake_authorized_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_authorized_size( fd_stake_authorized_t const * self ) { (void)self; return 64UL; }
static inline ulong fd_stake_authorized_align( void ) { return FD_STAKE_AUTHORIZED_ALIGN; }
static inline int fd_stake_authorized_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_authorized_t);
  if( (ulong)ctx->data + 64UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_authorized_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_lockup_new( fd_stake_lockup_t * self ) { fd_memset( self, 0, sizeof(fd_stake_lockup_t) ); }
int fd_stake_lockup_encode( fd_stake_lockup_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_lockup_walk( void * w, fd_stake_lockup_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_lockup_size( fd_stake_lockup_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_stake_lockup_align( void ) { return FD_STAKE_LOCKUP_ALIGN; }
static inline int fd_stake_lockup_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_lockup_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_lockup_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_instruction_initialize_new( fd_stake_instruction_initialize_t * self ) { fd_memset( self, 0, sizeof(fd_stake_instruction_initialize_t) ); }
int fd_stake_instruction_initialize_encode( fd_stake_instruction_initialize_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_instruction_initialize_walk( void * w, fd_stake_instruction_initialize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_instruction_initialize_size( fd_stake_instruction_initialize_t const * self ) { (void)self; return 112UL; }
static inline ulong fd_stake_instruction_initialize_align( void ) { return FD_STAKE_INSTRUCTION_INITIALIZE_ALIGN; }
static inline int fd_stake_instruction_initialize_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_instruction_initialize_t);
  if( (ulong)ctx->data + 112UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_instruction_initialize_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_stake_lockup_custodian_args_new( fd_stake_lockup_custodian_args_t * self );
int fd_stake_lockup_custodian_args_encode( fd_stake_lockup_custodian_args_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_lockup_custodian_args_walk( void * w, fd_stake_lockup_custodian_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stake_lockup_custodian_args_size( fd_stake_lockup_custodian_args_t const * self );
static inline ulong fd_stake_lockup_custodian_args_align( void ) { return FD_STAKE_LOCKUP_CUSTODIAN_ARGS_ALIGN; }
int fd_stake_lockup_custodian_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_lockup_custodian_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_authorize_new_disc( fd_stake_authorize_t * self, uint discriminant ) { self->discriminant = discriminant; }
static inline void fd_stake_authorize_new( fd_stake_authorize_t * self ) { self->discriminant = (uint)ULONG_MAX; }
int fd_stake_authorize_encode( fd_stake_authorize_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_authorize_walk( void * w, fd_stake_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stake_authorize_size( fd_stake_authorize_t const * self );
static inline ulong fd_stake_authorize_align( void ) { return FD_STAKE_AUTHORIZE_ALIGN; }
int fd_stake_authorize_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_authorize_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_stake_authorize_is_staker( fd_stake_authorize_t const * self );
FD_FN_PURE uchar fd_stake_authorize_is_withdrawer( fd_stake_authorize_t const * self );
enum {
fd_stake_authorize_enum_staker = 0,
fd_stake_authorize_enum_withdrawer = 1,
};
void fd_stake_instruction_authorize_new( fd_stake_instruction_authorize_t * self );
int fd_stake_instruction_authorize_encode( fd_stake_instruction_authorize_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_instruction_authorize_walk( void * w, fd_stake_instruction_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_instruction_authorize_size( fd_stake_instruction_authorize_t const * self ) { (void)self; return 36UL; }
static inline ulong fd_stake_instruction_authorize_align( void ) { return FD_STAKE_INSTRUCTION_AUTHORIZE_ALIGN; }
int fd_stake_instruction_authorize_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_instruction_authorize_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_authorize_with_seed_args_new( fd_authorize_with_seed_args_t * self );
int fd_authorize_with_seed_args_encode( fd_authorize_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_authorize_with_seed_args_walk( void * w, fd_authorize_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_authorize_with_seed_args_size( fd_authorize_with_seed_args_t const * self );
static inline ulong fd_authorize_with_seed_args_align( void ) { return FD_AUTHORIZE_WITH_SEED_ARGS_ALIGN; }
int fd_authorize_with_seed_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_authorize_with_seed_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_authorize_checked_with_seed_args_new( fd_authorize_checked_with_seed_args_t * self );
int fd_authorize_checked_with_seed_args_encode( fd_authorize_checked_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_authorize_checked_with_seed_args_walk( void * w, fd_authorize_checked_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_authorize_checked_with_seed_args_size( fd_authorize_checked_with_seed_args_t const * self );
static inline ulong fd_authorize_checked_with_seed_args_align( void ) { return FD_AUTHORIZE_CHECKED_WITH_SEED_ARGS_ALIGN; }
int fd_authorize_checked_with_seed_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_authorize_checked_with_seed_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_lockup_checked_args_new( fd_lockup_checked_args_t * self );
int fd_lockup_checked_args_encode( fd_lockup_checked_args_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_lockup_checked_args_walk( void * w, fd_lockup_checked_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_lockup_checked_args_size( fd_lockup_checked_args_t const * self );
static inline ulong fd_lockup_checked_args_align( void ) { return FD_LOCKUP_CHECKED_ARGS_ALIGN; }
int fd_lockup_checked_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_lockup_checked_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_lockup_args_new( fd_lockup_args_t * self );
int fd_lockup_args_encode( fd_lockup_args_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_lockup_args_walk( void * w, fd_lockup_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_lockup_args_size( fd_lockup_args_t const * self );
static inline ulong fd_lockup_args_align( void ) { return FD_LOCKUP_ARGS_ALIGN; }
int fd_lockup_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_lockup_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_stake_instruction_new_disc( fd_stake_instruction_t * self, uint discriminant );
void fd_stake_instruction_new( fd_stake_instruction_t * self );
int fd_stake_instruction_encode( fd_stake_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_instruction_walk( void * w, fd_stake_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stake_instruction_size( fd_stake_instruction_t const * self );
static inline ulong fd_stake_instruction_align( void ) { return FD_STAKE_INSTRUCTION_ALIGN; }
int fd_stake_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_stake_instruction_is_initialize( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_authorize( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_delegate_stake( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_split( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_withdraw( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_deactivate( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_set_lockup( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_merge( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_authorize_with_seed( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_initialize_checked( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_authorize_checked( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_authorize_checked_with_seed( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_set_lockup_checked( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_get_minimum_delegation( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_deactivate_delinquent( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_redelegate( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_move_stake( fd_stake_instruction_t const * self );
FD_FN_PURE uchar fd_stake_instruction_is_move_lamports( fd_stake_instruction_t const * self );
enum {
fd_stake_instruction_enum_initialize = 0,
fd_stake_instruction_enum_authorize = 1,
fd_stake_instruction_enum_delegate_stake = 2,
fd_stake_instruction_enum_split = 3,
fd_stake_instruction_enum_withdraw = 4,
fd_stake_instruction_enum_deactivate = 5,
fd_stake_instruction_enum_set_lockup = 6,
fd_stake_instruction_enum_merge = 7,
fd_stake_instruction_enum_authorize_with_seed = 8,
fd_stake_instruction_enum_initialize_checked = 9,
fd_stake_instruction_enum_authorize_checked = 10,
fd_stake_instruction_enum_authorize_checked_with_seed = 11,
fd_stake_instruction_enum_set_lockup_checked = 12,
fd_stake_instruction_enum_get_minimum_delegation = 13,
fd_stake_instruction_enum_deactivate_delinquent = 14,
fd_stake_instruction_enum_redelegate = 15,
fd_stake_instruction_enum_move_stake = 16,
fd_stake_instruction_enum_move_lamports = 17,
};
static inline void fd_stake_meta_new( fd_stake_meta_t * self ) { fd_memset( self, 0, sizeof(fd_stake_meta_t) ); }
int fd_stake_meta_encode( fd_stake_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_meta_walk( void * w, fd_stake_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_meta_size( fd_stake_meta_t const * self ) { (void)self; return 120UL; }
static inline ulong fd_stake_meta_align( void ) { return FD_STAKE_META_ALIGN; }
static inline int fd_stake_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_meta_t);
  if( (ulong)ctx->data + 120UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_flags_new( fd_stake_flags_t * self ) { fd_memset( self, 0, sizeof(fd_stake_flags_t) ); }
int fd_stake_flags_encode( fd_stake_flags_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_flags_walk( void * w, fd_stake_flags_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_flags_size( fd_stake_flags_t const * self ) { (void)self; return 1UL; }
static inline ulong fd_stake_flags_align( void ) { return FD_STAKE_FLAGS_ALIGN; }
static inline int fd_stake_flags_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_flags_t);
  if( (ulong)ctx->data + 1UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_flags_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_state_v2_initialized_new( fd_stake_state_v2_initialized_t * self ) { fd_memset( self, 0, sizeof(fd_stake_state_v2_initialized_t) ); }
int fd_stake_state_v2_initialized_encode( fd_stake_state_v2_initialized_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_state_v2_initialized_walk( void * w, fd_stake_state_v2_initialized_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_state_v2_initialized_size( fd_stake_state_v2_initialized_t const * self ) { (void)self; return 120UL; }
static inline ulong fd_stake_state_v2_initialized_align( void ) { return FD_STAKE_STATE_V2_INITIALIZED_ALIGN; }
static inline int fd_stake_state_v2_initialized_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_state_v2_initialized_t);
  if( (ulong)ctx->data + 120UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_state_v2_initialized_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_stake_state_v2_stake_new( fd_stake_state_v2_stake_t * self ) { fd_memset( self, 0, sizeof(fd_stake_state_v2_stake_t) ); }
int fd_stake_state_v2_stake_encode( fd_stake_state_v2_stake_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_state_v2_stake_walk( void * w, fd_stake_state_v2_stake_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_stake_state_v2_stake_size( fd_stake_state_v2_stake_t const * self ) { (void)self; return 193UL; }
static inline ulong fd_stake_state_v2_stake_align( void ) { return FD_STAKE_STATE_V2_STAKE_ALIGN; }
static inline int fd_stake_state_v2_stake_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_state_v2_stake_t);
  if( (ulong)ctx->data + 193UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_state_v2_stake_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_stake_state_v2_new_disc( fd_stake_state_v2_t * self, uint discriminant );
void fd_stake_state_v2_new( fd_stake_state_v2_t * self );
int fd_stake_state_v2_encode( fd_stake_state_v2_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_stake_state_v2_walk( void * w, fd_stake_state_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_stake_state_v2_size( fd_stake_state_v2_t const * self );
static inline ulong fd_stake_state_v2_align( void ) { return FD_STAKE_STATE_V2_ALIGN; }
int fd_stake_state_v2_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_state_v2_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_stake_state_v2_is_uninitialized( fd_stake_state_v2_t const * self );
FD_FN_PURE uchar fd_stake_state_v2_is_initialized( fd_stake_state_v2_t const * self );
FD_FN_PURE uchar fd_stake_state_v2_is_stake( fd_stake_state_v2_t const * self );
FD_FN_PURE uchar fd_stake_state_v2_is_rewards_pool( fd_stake_state_v2_t const * self );
enum {
fd_stake_state_v2_enum_uninitialized = 0,
fd_stake_state_v2_enum_initialized = 1,
fd_stake_state_v2_enum_stake = 2,
fd_stake_state_v2_enum_rewards_pool = 3,
};
static inline void fd_nonce_data_new( fd_nonce_data_t * self ) { fd_memset( self, 0, sizeof(fd_nonce_data_t) ); }
int fd_nonce_data_encode( fd_nonce_data_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_nonce_data_walk( void * w, fd_nonce_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_nonce_state_walk( void * w, fd_nonce_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_nonce_state_versions_walk( void * w, fd_nonce_state_versions_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_compute_budget_program_instruction_request_units_deprecated_walk( void * w, fd_compute_budget_program_instruction_request_units_deprecated_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_compute_budget_program_instruction_walk( void * w, fd_compute_budget_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_config_keys_new( fd_config_keys_t * self );
int fd_config_keys_encode( fd_config_keys_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_config_keys_walk( void * w, fd_config_keys_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_config_keys_size( fd_config_keys_t const * self );
static inline ulong fd_config_keys_align( void ) { return FD_CONFIG_KEYS_ALIGN; }
int fd_config_keys_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_config_keys_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_bpf_loader_program_instruction_write_new( fd_bpf_loader_program_instruction_write_t * self );
int fd_bpf_loader_program_instruction_write_encode( fd_bpf_loader_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bpf_loader_program_instruction_write_walk( void * w, fd_bpf_loader_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_bpf_loader_program_instruction_write_size( fd_bpf_loader_program_instruction_write_t const * self );
static inline ulong fd_bpf_loader_program_instruction_write_align( void ) { return FD_BPF_LOADER_PROGRAM_INSTRUCTION_WRITE_ALIGN; }
int fd_bpf_loader_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_loader_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_bpf_loader_program_instruction_new_disc( fd_bpf_loader_program_instruction_t * self, uint discriminant );
void fd_bpf_loader_program_instruction_new( fd_bpf_loader_program_instruction_t * self );
int fd_bpf_loader_program_instruction_encode( fd_bpf_loader_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bpf_loader_program_instruction_walk( void * w, fd_bpf_loader_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_loader_v4_program_instruction_write_walk( void * w, fd_loader_v4_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_loader_v4_program_instruction_write_size( fd_loader_v4_program_instruction_write_t const * self );
static inline ulong fd_loader_v4_program_instruction_write_align( void ) { return FD_LOADER_V4_PROGRAM_INSTRUCTION_WRITE_ALIGN; }
int fd_loader_v4_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_loader_v4_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_loader_v4_program_instruction_copy_new( fd_loader_v4_program_instruction_copy_t * self ) { fd_memset( self, 0, sizeof(fd_loader_v4_program_instruction_copy_t) ); }
int fd_loader_v4_program_instruction_copy_encode( fd_loader_v4_program_instruction_copy_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_loader_v4_program_instruction_copy_walk( void * w, fd_loader_v4_program_instruction_copy_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_loader_v4_program_instruction_set_program_length_walk( void * w, fd_loader_v4_program_instruction_set_program_length_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_loader_v4_program_instruction_walk( void * w, fd_loader_v4_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_bpf_upgradeable_loader_program_instruction_write_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_bpf_upgradeable_loader_program_instruction_write_size( fd_bpf_upgradeable_loader_program_instruction_write_t const * self );
static inline ulong fd_bpf_upgradeable_loader_program_instruction_write_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_WRITE_ALIGN; }
int fd_bpf_upgradeable_loader_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_upgradeable_loader_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new( fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t * self ) { fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t) ); }
int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_encode( fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_bpf_upgradeable_loader_program_instruction_extend_program_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_extend_program_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_bpf_upgradeable_loader_program_instruction_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_bpf_upgradeable_loader_state_buffer_walk( void * w, fd_bpf_upgradeable_loader_state_buffer_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_bpf_upgradeable_loader_state_buffer_size( fd_bpf_upgradeable_loader_state_buffer_t const * self );
static inline ulong fd_bpf_upgradeable_loader_state_buffer_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_STATE_BUFFER_ALIGN; }
int fd_bpf_upgradeable_loader_state_buffer_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_upgradeable_loader_state_buffer_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_bpf_upgradeable_loader_state_program_new( fd_bpf_upgradeable_loader_state_program_t * self ) { fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_state_program_t) ); }
int fd_bpf_upgradeable_loader_state_program_encode( fd_bpf_upgradeable_loader_state_program_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bpf_upgradeable_loader_state_program_walk( void * w, fd_bpf_upgradeable_loader_state_program_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_bpf_upgradeable_loader_state_program_data_walk( void * w, fd_bpf_upgradeable_loader_state_program_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_bpf_upgradeable_loader_state_program_data_size( fd_bpf_upgradeable_loader_state_program_data_t const * self );
static inline ulong fd_bpf_upgradeable_loader_state_program_data_align( void ) { return FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_DATA_ALIGN; }
int fd_bpf_upgradeable_loader_state_program_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bpf_upgradeable_loader_state_program_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_bpf_upgradeable_loader_state_new_disc( fd_bpf_upgradeable_loader_state_t * self, uint discriminant );
void fd_bpf_upgradeable_loader_state_new( fd_bpf_upgradeable_loader_state_t * self );
int fd_bpf_upgradeable_loader_state_encode( fd_bpf_upgradeable_loader_state_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bpf_upgradeable_loader_state_walk( void * w, fd_bpf_upgradeable_loader_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
void fd_loader_v4_state_walk( void * w, fd_loader_v4_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_loader_v4_state_size( fd_loader_v4_state_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_loader_v4_state_align( void ) { return FD_LOADER_V4_STATE_ALIGN; }
static inline int fd_loader_v4_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_loader_v4_state_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_loader_v4_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_frozen_hash_status_new( fd_frozen_hash_status_t * self );
int fd_frozen_hash_status_encode( fd_frozen_hash_status_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_frozen_hash_status_walk( void * w, fd_frozen_hash_status_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_frozen_hash_status_size( fd_frozen_hash_status_t const * self ) { (void)self; return 33UL; }
static inline ulong fd_frozen_hash_status_align( void ) { return FD_FROZEN_HASH_STATUS_ALIGN; }
int fd_frozen_hash_status_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_frozen_hash_status_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_frozen_hash_versioned_new_disc( fd_frozen_hash_versioned_t * self, uint discriminant );
void fd_frozen_hash_versioned_new( fd_frozen_hash_versioned_t * self );
int fd_frozen_hash_versioned_encode( fd_frozen_hash_versioned_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_frozen_hash_versioned_walk( void * w, fd_frozen_hash_versioned_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_frozen_hash_versioned_size( fd_frozen_hash_versioned_t const * self );
static inline ulong fd_frozen_hash_versioned_align( void ) { return FD_FROZEN_HASH_VERSIONED_ALIGN; }
int fd_frozen_hash_versioned_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_frozen_hash_versioned_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_frozen_hash_versioned_is_current( fd_frozen_hash_versioned_t const * self );
enum {
fd_frozen_hash_versioned_enum_current = 0,
};
void fd_lookup_table_meta_new( fd_lookup_table_meta_t * self );
int fd_lookup_table_meta_encode( fd_lookup_table_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_lookup_table_meta_walk( void * w, fd_lookup_table_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_lookup_table_meta_size( fd_lookup_table_meta_t const * self );
static inline ulong fd_lookup_table_meta_align( void ) { return FD_LOOKUP_TABLE_META_ALIGN; }
int fd_lookup_table_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_lookup_table_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_address_lookup_table_new( fd_address_lookup_table_t * self );
int fd_address_lookup_table_encode( fd_address_lookup_table_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_address_lookup_table_walk( void * w, fd_address_lookup_table_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_address_lookup_table_size( fd_address_lookup_table_t const * self );
static inline ulong fd_address_lookup_table_align( void ) { return FD_ADDRESS_LOOKUP_TABLE_ALIGN; }
int fd_address_lookup_table_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_address_lookup_table_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_address_lookup_table_state_new_disc( fd_address_lookup_table_state_t * self, uint discriminant );
void fd_address_lookup_table_state_new( fd_address_lookup_table_state_t * self );
int fd_address_lookup_table_state_encode( fd_address_lookup_table_state_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_address_lookup_table_state_walk( void * w, fd_address_lookup_table_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
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
static inline void fd_gossip_ping_new( fd_gossip_ping_t * self ) { fd_memset( self, 0, sizeof(fd_gossip_ping_t) ); }
int fd_gossip_ping_encode( fd_gossip_ping_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_ping_walk( void * w, fd_gossip_ping_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_gossip_ping_size( fd_gossip_ping_t const * self ) { (void)self; return 128UL; }
static inline ulong fd_gossip_ping_align( void ) { return FD_GOSSIP_PING_ALIGN; }
static inline int fd_gossip_ping_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_ping_t);
  if( (ulong)ctx->data + 128UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_gossip_ping_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_ip_addr_new_disc( fd_gossip_ip_addr_t * self, uint discriminant );
void fd_gossip_ip_addr_new( fd_gossip_ip_addr_t * self );
int fd_gossip_ip_addr_encode( fd_gossip_ip_addr_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_ip_addr_walk( void * w, fd_gossip_ip_addr_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_ip_addr_size( fd_gossip_ip_addr_t const * self );
static inline ulong fd_gossip_ip_addr_align( void ) { return FD_GOSSIP_IP_ADDR_ALIGN; }
int fd_gossip_ip_addr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_ip_addr_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_gossip_ip_addr_is_ip4( fd_gossip_ip_addr_t const * self );
FD_FN_PURE uchar fd_gossip_ip_addr_is_ip6( fd_gossip_ip_addr_t const * self );
enum {
fd_gossip_ip_addr_enum_ip4 = 0,
fd_gossip_ip_addr_enum_ip6 = 1,
};
void fd_gossip_prune_data_new( fd_gossip_prune_data_t * self );
int fd_gossip_prune_data_encode( fd_gossip_prune_data_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_prune_data_walk( void * w, fd_gossip_prune_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_prune_data_size( fd_gossip_prune_data_t const * self );
static inline ulong fd_gossip_prune_data_align( void ) { return FD_GOSSIP_PRUNE_DATA_ALIGN; }
int fd_gossip_prune_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_prune_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_prune_sign_data_new( fd_gossip_prune_sign_data_t * self );
int fd_gossip_prune_sign_data_encode( fd_gossip_prune_sign_data_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_prune_sign_data_walk( void * w, fd_gossip_prune_sign_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_prune_sign_data_size( fd_gossip_prune_sign_data_t const * self );
static inline ulong fd_gossip_prune_sign_data_align( void ) { return FD_GOSSIP_PRUNE_SIGN_DATA_ALIGN; }
int fd_gossip_prune_sign_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_prune_sign_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_prune_sign_data_with_prefix_new( fd_gossip_prune_sign_data_with_prefix_t * self );
int fd_gossip_prune_sign_data_with_prefix_encode( fd_gossip_prune_sign_data_with_prefix_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_prune_sign_data_with_prefix_walk( void * w, fd_gossip_prune_sign_data_with_prefix_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_prune_sign_data_with_prefix_size( fd_gossip_prune_sign_data_with_prefix_t const * self );
static inline ulong fd_gossip_prune_sign_data_with_prefix_align( void ) { return FD_GOSSIP_PRUNE_SIGN_DATA_WITH_PREFIX_ALIGN; }
int fd_gossip_prune_sign_data_with_prefix_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_prune_sign_data_with_prefix_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_socket_addr_old_new( fd_gossip_socket_addr_old_t * self );
int fd_gossip_socket_addr_old_encode( fd_gossip_socket_addr_old_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_socket_addr_old_walk( void * w, fd_gossip_socket_addr_old_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_socket_addr_old_size( fd_gossip_socket_addr_old_t const * self );
static inline ulong fd_gossip_socket_addr_old_align( void ) { return FD_GOSSIP_SOCKET_ADDR_OLD_ALIGN; }
int fd_gossip_socket_addr_old_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_socket_addr_old_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_socket_addr_ip4_new( fd_gossip_socket_addr_ip4_t * self );
int fd_gossip_socket_addr_ip4_encode( fd_gossip_socket_addr_ip4_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_socket_addr_ip4_walk( void * w, fd_gossip_socket_addr_ip4_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_socket_addr_ip4_size( fd_gossip_socket_addr_ip4_t const * self );
static inline ulong fd_gossip_socket_addr_ip4_align( void ) { return FD_GOSSIP_SOCKET_ADDR_IP4_ALIGN; }
int fd_gossip_socket_addr_ip4_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_socket_addr_ip4_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_socket_addr_ip6_new( fd_gossip_socket_addr_ip6_t * self );
int fd_gossip_socket_addr_ip6_encode( fd_gossip_socket_addr_ip6_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_socket_addr_ip6_walk( void * w, fd_gossip_socket_addr_ip6_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_gossip_socket_addr_ip6_size( fd_gossip_socket_addr_ip6_t const * self ) { (void)self; return 18UL; }
static inline ulong fd_gossip_socket_addr_ip6_align( void ) { return FD_GOSSIP_SOCKET_ADDR_IP6_ALIGN; }
int fd_gossip_socket_addr_ip6_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_socket_addr_ip6_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_socket_addr_new_disc( fd_gossip_socket_addr_t * self, uint discriminant );
void fd_gossip_socket_addr_new( fd_gossip_socket_addr_t * self );
int fd_gossip_socket_addr_encode( fd_gossip_socket_addr_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_socket_addr_walk( void * w, fd_gossip_socket_addr_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_socket_addr_size( fd_gossip_socket_addr_t const * self );
static inline ulong fd_gossip_socket_addr_align( void ) { return FD_GOSSIP_SOCKET_ADDR_ALIGN; }
int fd_gossip_socket_addr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_socket_addr_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_gossip_socket_addr_is_ip4( fd_gossip_socket_addr_t const * self );
FD_FN_PURE uchar fd_gossip_socket_addr_is_ip6( fd_gossip_socket_addr_t const * self );
enum {
fd_gossip_socket_addr_enum_ip4 = 0,
fd_gossip_socket_addr_enum_ip6 = 1,
};
void fd_gossip_contact_info_v1_new( fd_gossip_contact_info_v1_t * self );
int fd_gossip_contact_info_v1_encode( fd_gossip_contact_info_v1_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_contact_info_v1_walk( void * w, fd_gossip_contact_info_v1_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_contact_info_v1_size( fd_gossip_contact_info_v1_t const * self );
static inline ulong fd_gossip_contact_info_v1_align( void ) { return FD_GOSSIP_CONTACT_INFO_V1_ALIGN; }
int fd_gossip_contact_info_v1_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_contact_info_v1_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_vote_new( fd_gossip_vote_t * self );
int fd_gossip_vote_encode( fd_gossip_vote_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_vote_walk( void * w, fd_gossip_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_vote_size( fd_gossip_vote_t const * self );
static inline ulong fd_gossip_vote_align( void ) { return FD_GOSSIP_VOTE_ALIGN; }
int fd_gossip_vote_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_vote_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_gossip_deprecated_compression_type_new_disc( fd_gossip_deprecated_compression_type_t * self, uint discriminant ) { self->discriminant = discriminant; }
static inline void fd_gossip_deprecated_compression_type_new( fd_gossip_deprecated_compression_type_t * self ) { self->discriminant = (uint)ULONG_MAX; }
int fd_gossip_deprecated_compression_type_encode( fd_gossip_deprecated_compression_type_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_deprecated_compression_type_walk( void * w, fd_gossip_deprecated_compression_type_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_deprecated_compression_type_size( fd_gossip_deprecated_compression_type_t const * self );
static inline ulong fd_gossip_deprecated_compression_type_align( void ) { return FD_GOSSIP_DEPRECATED_COMPRESSION_TYPE_ALIGN; }
int fd_gossip_deprecated_compression_type_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_deprecated_compression_type_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_gossip_deprecated_compression_type_is_Uncompressed( fd_gossip_deprecated_compression_type_t const * self );
FD_FN_PURE uchar fd_gossip_deprecated_compression_type_is_GZip( fd_gossip_deprecated_compression_type_t const * self );
FD_FN_PURE uchar fd_gossip_deprecated_compression_type_is_BZip2( fd_gossip_deprecated_compression_type_t const * self );
enum {
fd_gossip_deprecated_compression_type_enum_Uncompressed = 0,
fd_gossip_deprecated_compression_type_enum_GZip = 1,
fd_gossip_deprecated_compression_type_enum_BZip2 = 2,
};
void fd_gossip_deprecated_epoch_incomplete_slots_new( fd_gossip_deprecated_epoch_incomplete_slots_t * self );
int fd_gossip_deprecated_epoch_incomplete_slots_encode( fd_gossip_deprecated_epoch_incomplete_slots_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_deprecated_epoch_incomplete_slots_walk( void * w, fd_gossip_deprecated_epoch_incomplete_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_deprecated_epoch_incomplete_slots_size( fd_gossip_deprecated_epoch_incomplete_slots_t const * self );
static inline ulong fd_gossip_deprecated_epoch_incomplete_slots_align( void ) { return FD_GOSSIP_DEPRECATED_EPOCH_INCOMPLETE_SLOTS_ALIGN; }
int fd_gossip_deprecated_epoch_incomplete_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_deprecated_epoch_incomplete_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_lowest_slot_new( fd_gossip_lowest_slot_t * self );
int fd_gossip_lowest_slot_encode( fd_gossip_lowest_slot_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_lowest_slot_walk( void * w, fd_gossip_lowest_slot_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_lowest_slot_size( fd_gossip_lowest_slot_t const * self );
static inline ulong fd_gossip_lowest_slot_align( void ) { return FD_GOSSIP_LOWEST_SLOT_ALIGN; }
int fd_gossip_lowest_slot_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_lowest_slot_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_slot_hashes_new( fd_gossip_slot_hashes_t * self );
int fd_gossip_slot_hashes_encode( fd_gossip_slot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_slot_hashes_walk( void * w, fd_gossip_slot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_slot_hashes_size( fd_gossip_slot_hashes_t const * self );
static inline ulong fd_gossip_slot_hashes_align( void ) { return FD_GOSSIP_SLOT_HASHES_ALIGN; }
int fd_gossip_slot_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_slot_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_slots_new( fd_gossip_slots_t * self );
int fd_gossip_slots_encode( fd_gossip_slots_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_slots_walk( void * w, fd_gossip_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_slots_size( fd_gossip_slots_t const * self );
static inline ulong fd_gossip_slots_align( void ) { return FD_GOSSIP_SLOTS_ALIGN; }
int fd_gossip_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_flate2_slots_new( fd_gossip_flate2_slots_t * self );
int fd_gossip_flate2_slots_encode( fd_gossip_flate2_slots_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_flate2_slots_walk( void * w, fd_gossip_flate2_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_flate2_slots_size( fd_gossip_flate2_slots_t const * self );
static inline ulong fd_gossip_flate2_slots_align( void ) { return FD_GOSSIP_FLATE2_SLOTS_ALIGN; }
int fd_gossip_flate2_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_flate2_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_slots_enum_new_disc( fd_gossip_slots_enum_t * self, uint discriminant );
void fd_gossip_slots_enum_new( fd_gossip_slots_enum_t * self );
int fd_gossip_slots_enum_encode( fd_gossip_slots_enum_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_slots_enum_walk( void * w, fd_gossip_slots_enum_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_slots_enum_size( fd_gossip_slots_enum_t const * self );
static inline ulong fd_gossip_slots_enum_align( void ) { return FD_GOSSIP_SLOTS_ENUM_ALIGN; }
int fd_gossip_slots_enum_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_slots_enum_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_gossip_slots_enum_is_flate2( fd_gossip_slots_enum_t const * self );
FD_FN_PURE uchar fd_gossip_slots_enum_is_uncompressed( fd_gossip_slots_enum_t const * self );
enum {
fd_gossip_slots_enum_enum_flate2 = 0,
fd_gossip_slots_enum_enum_uncompressed = 1,
};
void fd_gossip_epoch_slots_new( fd_gossip_epoch_slots_t * self );
int fd_gossip_epoch_slots_encode( fd_gossip_epoch_slots_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_epoch_slots_walk( void * w, fd_gossip_epoch_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_epoch_slots_size( fd_gossip_epoch_slots_t const * self );
static inline ulong fd_gossip_epoch_slots_align( void ) { return FD_GOSSIP_EPOCH_SLOTS_ALIGN; }
int fd_gossip_epoch_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_epoch_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_version_v1_new( fd_gossip_version_v1_t * self );
int fd_gossip_version_v1_encode( fd_gossip_version_v1_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_version_v1_walk( void * w, fd_gossip_version_v1_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_version_v1_size( fd_gossip_version_v1_t const * self );
static inline ulong fd_gossip_version_v1_align( void ) { return FD_GOSSIP_VERSION_V1_ALIGN; }
int fd_gossip_version_v1_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_version_v1_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_version_v2_new( fd_gossip_version_v2_t * self );
int fd_gossip_version_v2_encode( fd_gossip_version_v2_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_version_v2_walk( void * w, fd_gossip_version_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_version_v2_size( fd_gossip_version_v2_t const * self );
static inline ulong fd_gossip_version_v2_align( void ) { return FD_GOSSIP_VERSION_V2_ALIGN; }
int fd_gossip_version_v2_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_version_v2_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_version_v3_new( fd_gossip_version_v3_t * self );
int fd_gossip_version_v3_encode( fd_gossip_version_v3_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_version_v3_walk( void * w, fd_gossip_version_v3_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_version_v3_size( fd_gossip_version_v3_t const * self );
static inline ulong fd_gossip_version_v3_align( void ) { return FD_GOSSIP_VERSION_V3_ALIGN; }
int fd_gossip_version_v3_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_version_v3_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_gossip_node_instance_new( fd_gossip_node_instance_t * self ) { fd_memset( self, 0, sizeof(fd_gossip_node_instance_t) ); }
int fd_gossip_node_instance_encode( fd_gossip_node_instance_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_node_instance_walk( void * w, fd_gossip_node_instance_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_gossip_node_instance_size( fd_gossip_node_instance_t const * self ) { (void)self; return 56UL; }
static inline ulong fd_gossip_node_instance_align( void ) { return FD_GOSSIP_NODE_INSTANCE_ALIGN; }
static inline int fd_gossip_node_instance_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_node_instance_t);
  if( (ulong)ctx->data + 56UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_gossip_node_instance_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_duplicate_shred_new( fd_gossip_duplicate_shred_t * self );
int fd_gossip_duplicate_shred_encode( fd_gossip_duplicate_shred_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_duplicate_shred_walk( void * w, fd_gossip_duplicate_shred_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_duplicate_shred_size( fd_gossip_duplicate_shred_t const * self );
static inline ulong fd_gossip_duplicate_shred_align( void ) { return FD_GOSSIP_DUPLICATE_SHRED_ALIGN; }
int fd_gossip_duplicate_shred_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_duplicate_shred_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_incremental_snapshot_hashes_new( fd_gossip_incremental_snapshot_hashes_t * self );
int fd_gossip_incremental_snapshot_hashes_encode( fd_gossip_incremental_snapshot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_incremental_snapshot_hashes_walk( void * w, fd_gossip_incremental_snapshot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_incremental_snapshot_hashes_size( fd_gossip_incremental_snapshot_hashes_t const * self );
static inline ulong fd_gossip_incremental_snapshot_hashes_align( void ) { return FD_GOSSIP_INCREMENTAL_SNAPSHOT_HASHES_ALIGN; }
int fd_gossip_incremental_snapshot_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_incremental_snapshot_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_socket_entry_new( fd_gossip_socket_entry_t * self );
int fd_gossip_socket_entry_encode( fd_gossip_socket_entry_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_socket_entry_walk( void * w, fd_gossip_socket_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_socket_entry_size( fd_gossip_socket_entry_t const * self );
static inline ulong fd_gossip_socket_entry_align( void ) { return FD_GOSSIP_SOCKET_ENTRY_ALIGN; }
int fd_gossip_socket_entry_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_socket_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_contact_info_v2_new( fd_gossip_contact_info_v2_t * self );
int fd_gossip_contact_info_v2_encode( fd_gossip_contact_info_v2_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_contact_info_v2_walk( void * w, fd_gossip_contact_info_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_contact_info_v2_size( fd_gossip_contact_info_v2_t const * self );
static inline ulong fd_gossip_contact_info_v2_align( void ) { return FD_GOSSIP_CONTACT_INFO_V2_ALIGN; }
int fd_gossip_contact_info_v2_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_contact_info_v2_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_restart_run_length_encoding_inner_new( fd_restart_run_length_encoding_inner_t * self );
int fd_restart_run_length_encoding_inner_encode( fd_restart_run_length_encoding_inner_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_restart_run_length_encoding_inner_walk( void * w, fd_restart_run_length_encoding_inner_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_restart_run_length_encoding_inner_size( fd_restart_run_length_encoding_inner_t const * self );
static inline ulong fd_restart_run_length_encoding_inner_align( void ) { return FD_RESTART_RUN_LENGTH_ENCODING_INNER_ALIGN; }
int fd_restart_run_length_encoding_inner_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_restart_run_length_encoding_inner_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_restart_run_length_encoding_new( fd_restart_run_length_encoding_t * self );
int fd_restart_run_length_encoding_encode( fd_restart_run_length_encoding_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_restart_run_length_encoding_walk( void * w, fd_restart_run_length_encoding_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_restart_run_length_encoding_size( fd_restart_run_length_encoding_t const * self );
static inline ulong fd_restart_run_length_encoding_align( void ) { return FD_RESTART_RUN_LENGTH_ENCODING_ALIGN; }
int fd_restart_run_length_encoding_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_restart_run_length_encoding_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_restart_raw_offsets_new( fd_restart_raw_offsets_t * self );
int fd_restart_raw_offsets_encode( fd_restart_raw_offsets_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_restart_raw_offsets_walk( void * w, fd_restart_raw_offsets_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_restart_raw_offsets_size( fd_restart_raw_offsets_t const * self );
static inline ulong fd_restart_raw_offsets_align( void ) { return FD_RESTART_RAW_OFFSETS_ALIGN; }
int fd_restart_raw_offsets_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_restart_raw_offsets_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_restart_slots_offsets_new_disc( fd_restart_slots_offsets_t * self, uint discriminant );
void fd_restart_slots_offsets_new( fd_restart_slots_offsets_t * self );
int fd_restart_slots_offsets_encode( fd_restart_slots_offsets_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_restart_slots_offsets_walk( void * w, fd_restart_slots_offsets_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_restart_slots_offsets_size( fd_restart_slots_offsets_t const * self );
static inline ulong fd_restart_slots_offsets_align( void ) { return FD_RESTART_SLOTS_OFFSETS_ALIGN; }
int fd_restart_slots_offsets_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_restart_slots_offsets_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_restart_slots_offsets_is_run_length_encoding( fd_restart_slots_offsets_t const * self );
FD_FN_PURE uchar fd_restart_slots_offsets_is_raw_offsets( fd_restart_slots_offsets_t const * self );
enum {
fd_restart_slots_offsets_enum_run_length_encoding = 0,
fd_restart_slots_offsets_enum_raw_offsets = 1,
};
void fd_gossip_restart_last_voted_fork_slots_new( fd_gossip_restart_last_voted_fork_slots_t * self );
int fd_gossip_restart_last_voted_fork_slots_encode( fd_gossip_restart_last_voted_fork_slots_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_restart_last_voted_fork_slots_walk( void * w, fd_gossip_restart_last_voted_fork_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_restart_last_voted_fork_slots_size( fd_gossip_restart_last_voted_fork_slots_t const * self );
static inline ulong fd_gossip_restart_last_voted_fork_slots_align( void ) { return FD_GOSSIP_RESTART_LAST_VOTED_FORK_SLOTS_ALIGN; }
int fd_gossip_restart_last_voted_fork_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_restart_last_voted_fork_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_gossip_restart_heaviest_fork_new( fd_gossip_restart_heaviest_fork_t * self ) { fd_memset( self, 0, sizeof(fd_gossip_restart_heaviest_fork_t) ); }
int fd_gossip_restart_heaviest_fork_encode( fd_gossip_restart_heaviest_fork_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_restart_heaviest_fork_walk( void * w, fd_gossip_restart_heaviest_fork_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_gossip_restart_heaviest_fork_size( fd_gossip_restart_heaviest_fork_t const * self ) { (void)self; return 90UL; }
static inline ulong fd_gossip_restart_heaviest_fork_align( void ) { return FD_GOSSIP_RESTART_HEAVIEST_FORK_ALIGN; }
static inline int fd_gossip_restart_heaviest_fork_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_restart_heaviest_fork_t);
  if( (ulong)ctx->data + 90UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_gossip_restart_heaviest_fork_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_crds_data_new_disc( fd_crds_data_t * self, uint discriminant );
void fd_crds_data_new( fd_crds_data_t * self );
int fd_crds_data_encode( fd_crds_data_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_crds_data_walk( void * w, fd_crds_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_crds_data_size( fd_crds_data_t const * self );
static inline ulong fd_crds_data_align( void ) { return FD_CRDS_DATA_ALIGN; }
int fd_crds_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_crds_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_crds_data_is_contact_info_v1( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_vote( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_lowest_slot( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_snapshot_hashes( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_accounts_hashes( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_epoch_slots( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_version_v1( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_version_v2( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_node_instance( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_duplicate_shred( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_incremental_snapshot_hashes( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_contact_info_v2( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_restart_last_voted_fork_slots( fd_crds_data_t const * self );
FD_FN_PURE uchar fd_crds_data_is_restart_heaviest_fork( fd_crds_data_t const * self );
enum {
fd_crds_data_enum_contact_info_v1 = 0,
fd_crds_data_enum_vote = 1,
fd_crds_data_enum_lowest_slot = 2,
fd_crds_data_enum_snapshot_hashes = 3,
fd_crds_data_enum_accounts_hashes = 4,
fd_crds_data_enum_epoch_slots = 5,
fd_crds_data_enum_version_v1 = 6,
fd_crds_data_enum_version_v2 = 7,
fd_crds_data_enum_node_instance = 8,
fd_crds_data_enum_duplicate_shred = 9,
fd_crds_data_enum_incremental_snapshot_hashes = 10,
fd_crds_data_enum_contact_info_v2 = 11,
fd_crds_data_enum_restart_last_voted_fork_slots = 12,
fd_crds_data_enum_restart_heaviest_fork = 13,
};
void fd_crds_bloom_new( fd_crds_bloom_t * self );
int fd_crds_bloom_encode( fd_crds_bloom_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_crds_bloom_walk( void * w, fd_crds_bloom_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_crds_bloom_size( fd_crds_bloom_t const * self );
static inline ulong fd_crds_bloom_align( void ) { return FD_CRDS_BLOOM_ALIGN; }
int fd_crds_bloom_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_crds_bloom_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_crds_filter_new( fd_crds_filter_t * self );
int fd_crds_filter_encode( fd_crds_filter_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_crds_filter_walk( void * w, fd_crds_filter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_crds_filter_size( fd_crds_filter_t const * self );
static inline ulong fd_crds_filter_align( void ) { return FD_CRDS_FILTER_ALIGN; }
int fd_crds_filter_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_crds_filter_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_crds_value_new( fd_crds_value_t * self );
int fd_crds_value_encode( fd_crds_value_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_crds_value_walk( void * w, fd_crds_value_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_crds_value_size( fd_crds_value_t const * self );
static inline ulong fd_crds_value_align( void ) { return FD_CRDS_VALUE_ALIGN; }
int fd_crds_value_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_crds_value_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_pull_req_new( fd_gossip_pull_req_t * self );
int fd_gossip_pull_req_encode( fd_gossip_pull_req_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_pull_req_walk( void * w, fd_gossip_pull_req_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_pull_req_size( fd_gossip_pull_req_t const * self );
static inline ulong fd_gossip_pull_req_align( void ) { return FD_GOSSIP_PULL_REQ_ALIGN; }
int fd_gossip_pull_req_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_pull_req_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_pull_resp_new( fd_gossip_pull_resp_t * self );
int fd_gossip_pull_resp_encode( fd_gossip_pull_resp_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_pull_resp_walk( void * w, fd_gossip_pull_resp_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_pull_resp_size( fd_gossip_pull_resp_t const * self );
static inline ulong fd_gossip_pull_resp_align( void ) { return FD_GOSSIP_PULL_RESP_ALIGN; }
int fd_gossip_pull_resp_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_pull_resp_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_push_msg_new( fd_gossip_push_msg_t * self );
int fd_gossip_push_msg_encode( fd_gossip_push_msg_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_push_msg_walk( void * w, fd_gossip_push_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_push_msg_size( fd_gossip_push_msg_t const * self );
static inline ulong fd_gossip_push_msg_align( void ) { return FD_GOSSIP_PUSH_MSG_ALIGN; }
int fd_gossip_push_msg_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_push_msg_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_prune_msg_new( fd_gossip_prune_msg_t * self );
int fd_gossip_prune_msg_encode( fd_gossip_prune_msg_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_prune_msg_walk( void * w, fd_gossip_prune_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_prune_msg_size( fd_gossip_prune_msg_t const * self );
static inline ulong fd_gossip_prune_msg_align( void ) { return FD_GOSSIP_PRUNE_MSG_ALIGN; }
int fd_gossip_prune_msg_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_prune_msg_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_gossip_msg_new_disc( fd_gossip_msg_t * self, uint discriminant );
void fd_gossip_msg_new( fd_gossip_msg_t * self );
int fd_gossip_msg_encode( fd_gossip_msg_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_gossip_msg_walk( void * w, fd_gossip_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_gossip_msg_size( fd_gossip_msg_t const * self );
static inline ulong fd_gossip_msg_align( void ) { return FD_GOSSIP_MSG_ALIGN; }
int fd_gossip_msg_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_gossip_msg_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_gossip_msg_is_pull_req( fd_gossip_msg_t const * self );
FD_FN_PURE uchar fd_gossip_msg_is_pull_resp( fd_gossip_msg_t const * self );
FD_FN_PURE uchar fd_gossip_msg_is_push_msg( fd_gossip_msg_t const * self );
FD_FN_PURE uchar fd_gossip_msg_is_prune_msg( fd_gossip_msg_t const * self );
FD_FN_PURE uchar fd_gossip_msg_is_ping( fd_gossip_msg_t const * self );
FD_FN_PURE uchar fd_gossip_msg_is_pong( fd_gossip_msg_t const * self );
enum {
fd_gossip_msg_enum_pull_req = 0,
fd_gossip_msg_enum_pull_resp = 1,
fd_gossip_msg_enum_push_msg = 2,
fd_gossip_msg_enum_prune_msg = 3,
fd_gossip_msg_enum_ping = 4,
fd_gossip_msg_enum_pong = 5,
};
static inline void fd_addrlut_create_new( fd_addrlut_create_t * self ) { fd_memset( self, 0, sizeof(fd_addrlut_create_t) ); }
int fd_addrlut_create_encode( fd_addrlut_create_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_addrlut_create_walk( void * w, fd_addrlut_create_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_addrlut_create_size( fd_addrlut_create_t const * self ) { (void)self; return 9UL; }
static inline ulong fd_addrlut_create_align( void ) { return FD_ADDRLUT_CREATE_ALIGN; }
static inline int fd_addrlut_create_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_addrlut_create_t);
  if( (ulong)ctx->data + 9UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_addrlut_create_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_addrlut_extend_new( fd_addrlut_extend_t * self );
int fd_addrlut_extend_encode( fd_addrlut_extend_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_addrlut_extend_walk( void * w, fd_addrlut_extend_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_addrlut_extend_size( fd_addrlut_extend_t const * self );
static inline ulong fd_addrlut_extend_align( void ) { return FD_ADDRLUT_EXTEND_ALIGN; }
int fd_addrlut_extend_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_addrlut_extend_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_addrlut_instruction_new_disc( fd_addrlut_instruction_t * self, uint discriminant );
void fd_addrlut_instruction_new( fd_addrlut_instruction_t * self );
int fd_addrlut_instruction_encode( fd_addrlut_instruction_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_addrlut_instruction_walk( void * w, fd_addrlut_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_addrlut_instruction_size( fd_addrlut_instruction_t const * self );
static inline ulong fd_addrlut_instruction_align( void ) { return FD_ADDRLUT_INSTRUCTION_ALIGN; }
int fd_addrlut_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_addrlut_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_addrlut_instruction_is_create_lut( fd_addrlut_instruction_t const * self );
FD_FN_PURE uchar fd_addrlut_instruction_is_freeze_lut( fd_addrlut_instruction_t const * self );
FD_FN_PURE uchar fd_addrlut_instruction_is_extend_lut( fd_addrlut_instruction_t const * self );
FD_FN_PURE uchar fd_addrlut_instruction_is_deactivate_lut( fd_addrlut_instruction_t const * self );
FD_FN_PURE uchar fd_addrlut_instruction_is_close_lut( fd_addrlut_instruction_t const * self );
enum {
fd_addrlut_instruction_enum_create_lut = 0,
fd_addrlut_instruction_enum_freeze_lut = 1,
fd_addrlut_instruction_enum_extend_lut = 2,
fd_addrlut_instruction_enum_deactivate_lut = 3,
fd_addrlut_instruction_enum_close_lut = 4,
};
static inline void fd_repair_request_header_new( fd_repair_request_header_t * self ) { fd_memset( self, 0, sizeof(fd_repair_request_header_t) ); }
int fd_repair_request_header_encode( fd_repair_request_header_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_repair_request_header_walk( void * w, fd_repair_request_header_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_repair_request_header_size( fd_repair_request_header_t const * self ) { (void)self; return 140UL; }
static inline ulong fd_repair_request_header_align( void ) { return FD_REPAIR_REQUEST_HEADER_ALIGN; }
static inline int fd_repair_request_header_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_repair_request_header_t);
  if( (ulong)ctx->data + 140UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_repair_request_header_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_repair_window_index_new( fd_repair_window_index_t * self ) { fd_memset( self, 0, sizeof(fd_repair_window_index_t) ); }
int fd_repair_window_index_encode( fd_repair_window_index_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_repair_window_index_walk( void * w, fd_repair_window_index_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_repair_window_index_size( fd_repair_window_index_t const * self ) { (void)self; return 156UL; }
static inline ulong fd_repair_window_index_align( void ) { return FD_REPAIR_WINDOW_INDEX_ALIGN; }
static inline int fd_repair_window_index_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_repair_window_index_t);
  if( (ulong)ctx->data + 156UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_repair_window_index_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_repair_highest_window_index_new( fd_repair_highest_window_index_t * self ) { fd_memset( self, 0, sizeof(fd_repair_highest_window_index_t) ); }
int fd_repair_highest_window_index_encode( fd_repair_highest_window_index_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_repair_highest_window_index_walk( void * w, fd_repair_highest_window_index_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_repair_highest_window_index_size( fd_repair_highest_window_index_t const * self ) { (void)self; return 156UL; }
static inline ulong fd_repair_highest_window_index_align( void ) { return FD_REPAIR_HIGHEST_WINDOW_INDEX_ALIGN; }
static inline int fd_repair_highest_window_index_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_repair_highest_window_index_t);
  if( (ulong)ctx->data + 156UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_repair_highest_window_index_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_repair_orphan_new( fd_repair_orphan_t * self ) { fd_memset( self, 0, sizeof(fd_repair_orphan_t) ); }
int fd_repair_orphan_encode( fd_repair_orphan_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_repair_orphan_walk( void * w, fd_repair_orphan_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_repair_orphan_size( fd_repair_orphan_t const * self ) { (void)self; return 148UL; }
static inline ulong fd_repair_orphan_align( void ) { return FD_REPAIR_ORPHAN_ALIGN; }
static inline int fd_repair_orphan_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_repair_orphan_t);
  if( (ulong)ctx->data + 148UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_repair_orphan_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_repair_ancestor_hashes_new( fd_repair_ancestor_hashes_t * self ) { fd_memset( self, 0, sizeof(fd_repair_ancestor_hashes_t) ); }
int fd_repair_ancestor_hashes_encode( fd_repair_ancestor_hashes_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_repair_ancestor_hashes_walk( void * w, fd_repair_ancestor_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_repair_ancestor_hashes_size( fd_repair_ancestor_hashes_t const * self ) { (void)self; return 148UL; }
static inline ulong fd_repair_ancestor_hashes_align( void ) { return FD_REPAIR_ANCESTOR_HASHES_ALIGN; }
static inline int fd_repair_ancestor_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_repair_ancestor_hashes_t);
  if( (ulong)ctx->data + 148UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_repair_ancestor_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_repair_protocol_new_disc( fd_repair_protocol_t * self, uint discriminant );
void fd_repair_protocol_new( fd_repair_protocol_t * self );
int fd_repair_protocol_encode( fd_repair_protocol_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_repair_protocol_walk( void * w, fd_repair_protocol_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_repair_protocol_size( fd_repair_protocol_t const * self );
static inline ulong fd_repair_protocol_align( void ) { return FD_REPAIR_PROTOCOL_ALIGN; }
int fd_repair_protocol_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_repair_protocol_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_repair_protocol_is_LegacyWindowIndex( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_LegacyHighestWindowIndex( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_LegacyOrphan( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_LegacyWindowIndexWithNonce( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_LegacyHighestWindowIndexWithNonce( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_LegacyOrphanWithNonce( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_LegacyAncestorHashes( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_pong( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_window_index( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_highest_window_index( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_orphan( fd_repair_protocol_t const * self );
FD_FN_PURE uchar fd_repair_protocol_is_ancestor_hashes( fd_repair_protocol_t const * self );
enum {
fd_repair_protocol_enum_LegacyWindowIndex = 0,
fd_repair_protocol_enum_LegacyHighestWindowIndex = 1,
fd_repair_protocol_enum_LegacyOrphan = 2,
fd_repair_protocol_enum_LegacyWindowIndexWithNonce = 3,
fd_repair_protocol_enum_LegacyHighestWindowIndexWithNonce = 4,
fd_repair_protocol_enum_LegacyOrphanWithNonce = 5,
fd_repair_protocol_enum_LegacyAncestorHashes = 6,
fd_repair_protocol_enum_pong = 7,
fd_repair_protocol_enum_window_index = 8,
fd_repair_protocol_enum_highest_window_index = 9,
fd_repair_protocol_enum_orphan = 10,
fd_repair_protocol_enum_ancestor_hashes = 11,
};
void fd_instr_error_enum_new_disc( fd_instr_error_enum_t * self, uint discriminant );
void fd_instr_error_enum_new( fd_instr_error_enum_t * self );
int fd_instr_error_enum_encode( fd_instr_error_enum_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_instr_error_enum_walk( void * w, fd_instr_error_enum_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_instr_error_enum_size( fd_instr_error_enum_t const * self );
static inline ulong fd_instr_error_enum_align( void ) { return FD_INSTR_ERROR_ENUM_ALIGN; }
int fd_instr_error_enum_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_instr_error_enum_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_instr_error_enum_is_generic_error( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_argument( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_instruction_data( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_account_data( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_account_data_too_small( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_insufficient_funds( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_incorrect_program_id( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_missing_required_signature( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_account_already_initialized( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_uninitialized_account( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_unbalanced_instruction( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_modified_program_id( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_external_account_lamport_spend( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_external_account_data_modified( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_readonly_lamport_change( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_readonly_data_modified( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_duplicate_account_index( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_executable_modified( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_rent_epoch_modified( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_not_enough_account_keys( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_account_data_size_changed( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_account_not_executable( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_account_borrow_failed( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_account_borrow_outstanding( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_duplicate_account_out_of_sync( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_custom( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_error( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_executable_data_modified( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_executable_lamport_change( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_executable_account_not_rent_exempt( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_unsupported_program_id( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_call_depth( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_missing_account( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_reentrancy_not_allowed( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_max_seed_length_exceeded( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_seeds( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_realloc( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_computational_budget_exceeded( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_privilege_escalation( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_program_environment_setup_failure( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_program_failed_to_complete( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_program_failed_to_compile( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_immutable( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_incorrect_authority( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_borsh_io_error( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_account_not_rent_exempt( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_account_owner( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_arithmetic_overflow( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_unsupported_sysvar( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_illegal_owner( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_max_accounts_data_allocations_exceeded( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_max_accounts_exceeded( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_max_instruction_trace_length_exceeded( fd_instr_error_enum_t const * self );
FD_FN_PURE uchar fd_instr_error_enum_is_builtin_programs_must_consume_compute_units( fd_instr_error_enum_t const * self );
enum {
fd_instr_error_enum_enum_generic_error = 0,
fd_instr_error_enum_enum_invalid_argument = 1,
fd_instr_error_enum_enum_invalid_instruction_data = 2,
fd_instr_error_enum_enum_invalid_account_data = 3,
fd_instr_error_enum_enum_account_data_too_small = 4,
fd_instr_error_enum_enum_insufficient_funds = 5,
fd_instr_error_enum_enum_incorrect_program_id = 6,
fd_instr_error_enum_enum_missing_required_signature = 7,
fd_instr_error_enum_enum_account_already_initialized = 8,
fd_instr_error_enum_enum_uninitialized_account = 9,
fd_instr_error_enum_enum_unbalanced_instruction = 10,
fd_instr_error_enum_enum_modified_program_id = 11,
fd_instr_error_enum_enum_external_account_lamport_spend = 12,
fd_instr_error_enum_enum_external_account_data_modified = 13,
fd_instr_error_enum_enum_readonly_lamport_change = 14,
fd_instr_error_enum_enum_readonly_data_modified = 15,
fd_instr_error_enum_enum_duplicate_account_index = 16,
fd_instr_error_enum_enum_executable_modified = 17,
fd_instr_error_enum_enum_rent_epoch_modified = 18,
fd_instr_error_enum_enum_not_enough_account_keys = 19,
fd_instr_error_enum_enum_account_data_size_changed = 20,
fd_instr_error_enum_enum_account_not_executable = 21,
fd_instr_error_enum_enum_account_borrow_failed = 22,
fd_instr_error_enum_enum_account_borrow_outstanding = 23,
fd_instr_error_enum_enum_duplicate_account_out_of_sync = 24,
fd_instr_error_enum_enum_custom = 25,
fd_instr_error_enum_enum_invalid_error = 26,
fd_instr_error_enum_enum_executable_data_modified = 27,
fd_instr_error_enum_enum_executable_lamport_change = 28,
fd_instr_error_enum_enum_executable_account_not_rent_exempt = 29,
fd_instr_error_enum_enum_unsupported_program_id = 30,
fd_instr_error_enum_enum_call_depth = 31,
fd_instr_error_enum_enum_missing_account = 32,
fd_instr_error_enum_enum_reentrancy_not_allowed = 33,
fd_instr_error_enum_enum_max_seed_length_exceeded = 34,
fd_instr_error_enum_enum_invalid_seeds = 35,
fd_instr_error_enum_enum_invalid_realloc = 36,
fd_instr_error_enum_enum_computational_budget_exceeded = 37,
fd_instr_error_enum_enum_privilege_escalation = 38,
fd_instr_error_enum_enum_program_environment_setup_failure = 39,
fd_instr_error_enum_enum_program_failed_to_complete = 40,
fd_instr_error_enum_enum_program_failed_to_compile = 41,
fd_instr_error_enum_enum_immutable = 42,
fd_instr_error_enum_enum_incorrect_authority = 43,
fd_instr_error_enum_enum_borsh_io_error = 44,
fd_instr_error_enum_enum_account_not_rent_exempt = 45,
fd_instr_error_enum_enum_invalid_account_owner = 46,
fd_instr_error_enum_enum_arithmetic_overflow = 47,
fd_instr_error_enum_enum_unsupported_sysvar = 48,
fd_instr_error_enum_enum_illegal_owner = 49,
fd_instr_error_enum_enum_max_accounts_data_allocations_exceeded = 50,
fd_instr_error_enum_enum_max_accounts_exceeded = 51,
fd_instr_error_enum_enum_max_instruction_trace_length_exceeded = 52,
fd_instr_error_enum_enum_builtin_programs_must_consume_compute_units = 53,
};
void fd_txn_instr_error_new( fd_txn_instr_error_t * self );
int fd_txn_instr_error_encode( fd_txn_instr_error_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_txn_instr_error_walk( void * w, fd_txn_instr_error_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_txn_instr_error_size( fd_txn_instr_error_t const * self );
static inline ulong fd_txn_instr_error_align( void ) { return FD_TXN_INSTR_ERROR_ALIGN; }
int fd_txn_instr_error_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_txn_instr_error_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_txn_error_enum_new_disc( fd_txn_error_enum_t * self, uint discriminant );
void fd_txn_error_enum_new( fd_txn_error_enum_t * self );
int fd_txn_error_enum_encode( fd_txn_error_enum_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_txn_error_enum_walk( void * w, fd_txn_error_enum_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_txn_error_enum_size( fd_txn_error_enum_t const * self );
static inline ulong fd_txn_error_enum_align( void ) { return FD_TXN_ERROR_ENUM_ALIGN; }
int fd_txn_error_enum_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_txn_error_enum_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_txn_error_enum_is_account_in_use( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_account_loaded_twice( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_account_not_found( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_program_account_not_found( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_insufficient_funds_for_fee( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_account_for_fee( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_already_processed( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_blockhash_not_found( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_instruction_error( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_call_chain_too_deep( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_missing_signature_for_fee( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_account_index( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_signature_failure( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_program_for_execution( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_sanitize_failure( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_cluster_maintenance( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_account_borrow_outstanding( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_max_block_cost_limit( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_unsupported_version( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_writable_account( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_max_account_cost_limit( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_account_data_block_limit( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_too_many_account_locks( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_address_lookup_table_not_found( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_address_lookup_table_owner( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_address_lookup_table_data( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_address_lookup_table_index( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_rent_paying_account( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_max_vote_cost_limit( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_account_data_total_limit( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_duplicate_instruction( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_insufficient_funds_for_rent( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_max_loaded_accounts_data_size_exceeded( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_loaded_accounts_data_size_limit( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_resanitization_needed( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_program_execution_temporarily_restricted( fd_txn_error_enum_t const * self );
FD_FN_PURE uchar fd_txn_error_enum_is_unbalanced_transaction( fd_txn_error_enum_t const * self );
enum {
fd_txn_error_enum_enum_account_in_use = 0,
fd_txn_error_enum_enum_account_loaded_twice = 1,
fd_txn_error_enum_enum_account_not_found = 2,
fd_txn_error_enum_enum_program_account_not_found = 3,
fd_txn_error_enum_enum_insufficient_funds_for_fee = 4,
fd_txn_error_enum_enum_invalid_account_for_fee = 5,
fd_txn_error_enum_enum_already_processed = 6,
fd_txn_error_enum_enum_blockhash_not_found = 7,
fd_txn_error_enum_enum_instruction_error = 8,
fd_txn_error_enum_enum_call_chain_too_deep = 9,
fd_txn_error_enum_enum_missing_signature_for_fee = 10,
fd_txn_error_enum_enum_invalid_account_index = 11,
fd_txn_error_enum_enum_signature_failure = 12,
fd_txn_error_enum_enum_invalid_program_for_execution = 13,
fd_txn_error_enum_enum_sanitize_failure = 14,
fd_txn_error_enum_enum_cluster_maintenance = 15,
fd_txn_error_enum_enum_account_borrow_outstanding = 16,
fd_txn_error_enum_enum_would_exceed_max_block_cost_limit = 17,
fd_txn_error_enum_enum_unsupported_version = 18,
fd_txn_error_enum_enum_invalid_writable_account = 19,
fd_txn_error_enum_enum_would_exceed_max_account_cost_limit = 20,
fd_txn_error_enum_enum_would_exceed_account_data_block_limit = 21,
fd_txn_error_enum_enum_too_many_account_locks = 22,
fd_txn_error_enum_enum_address_lookup_table_not_found = 23,
fd_txn_error_enum_enum_invalid_address_lookup_table_owner = 24,
fd_txn_error_enum_enum_invalid_address_lookup_table_data = 25,
fd_txn_error_enum_enum_invalid_address_lookup_table_index = 26,
fd_txn_error_enum_enum_invalid_rent_paying_account = 27,
fd_txn_error_enum_enum_would_exceed_max_vote_cost_limit = 28,
fd_txn_error_enum_enum_would_exceed_account_data_total_limit = 29,
fd_txn_error_enum_enum_duplicate_instruction = 30,
fd_txn_error_enum_enum_insufficient_funds_for_rent = 31,
fd_txn_error_enum_enum_max_loaded_accounts_data_size_exceeded = 32,
fd_txn_error_enum_enum_invalid_loaded_accounts_data_size_limit = 33,
fd_txn_error_enum_enum_resanitization_needed = 34,
fd_txn_error_enum_enum_program_execution_temporarily_restricted = 35,
fd_txn_error_enum_enum_unbalanced_transaction = 36,
};
void fd_txn_result_new_disc( fd_txn_result_t * self, uint discriminant );
void fd_txn_result_new( fd_txn_result_t * self );
int fd_txn_result_encode( fd_txn_result_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_txn_result_walk( void * w, fd_txn_result_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_txn_result_size( fd_txn_result_t const * self );
static inline ulong fd_txn_result_align( void ) { return FD_TXN_RESULT_ALIGN; }
int fd_txn_result_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_txn_result_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_txn_result_is_ok( fd_txn_result_t const * self );
FD_FN_PURE uchar fd_txn_result_is_error( fd_txn_result_t const * self );
enum {
fd_txn_result_enum_ok = 0,
fd_txn_result_enum_error = 1,
};
void fd_cache_status_new( fd_cache_status_t * self );
int fd_cache_status_encode( fd_cache_status_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_cache_status_walk( void * w, fd_cache_status_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_cache_status_size( fd_cache_status_t const * self );
static inline ulong fd_cache_status_align( void ) { return FD_CACHE_STATUS_ALIGN; }
int fd_cache_status_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_cache_status_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_status_value_new( fd_status_value_t * self );
int fd_status_value_encode( fd_status_value_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_status_value_walk( void * w, fd_status_value_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_status_value_size( fd_status_value_t const * self );
static inline ulong fd_status_value_align( void ) { return FD_STATUS_VALUE_ALIGN; }
int fd_status_value_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_status_value_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_status_pair_new( fd_status_pair_t * self );
int fd_status_pair_encode( fd_status_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_status_pair_walk( void * w, fd_status_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_status_pair_size( fd_status_pair_t const * self );
static inline ulong fd_status_pair_align( void ) { return FD_STATUS_PAIR_ALIGN; }
int fd_status_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_status_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_slot_delta_new( fd_slot_delta_t * self );
int fd_slot_delta_encode( fd_slot_delta_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_slot_delta_walk( void * w, fd_slot_delta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_slot_delta_size( fd_slot_delta_t const * self );
static inline ulong fd_slot_delta_align( void ) { return FD_SLOT_DELTA_ALIGN; }
int fd_slot_delta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_delta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_bank_slot_deltas_new( fd_bank_slot_deltas_t * self );
int fd_bank_slot_deltas_encode( fd_bank_slot_deltas_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_bank_slot_deltas_walk( void * w, fd_bank_slot_deltas_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_bank_slot_deltas_size( fd_bank_slot_deltas_t const * self );
static inline ulong fd_bank_slot_deltas_align( void ) { return FD_BANK_SLOT_DELTAS_ALIGN; }
int fd_bank_slot_deltas_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_bank_slot_deltas_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_pubkey_rewardinfo_pair_new( fd_pubkey_rewardinfo_pair_t * self );
int fd_pubkey_rewardinfo_pair_encode( fd_pubkey_rewardinfo_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_pubkey_rewardinfo_pair_walk( void * w, fd_pubkey_rewardinfo_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_pubkey_rewardinfo_pair_size( fd_pubkey_rewardinfo_pair_t const * self ) { (void)self; return 60UL; }
static inline ulong fd_pubkey_rewardinfo_pair_align( void ) { return FD_PUBKEY_REWARDINFO_PAIR_ALIGN; }
int fd_pubkey_rewardinfo_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_pubkey_rewardinfo_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_optional_account_new( fd_optional_account_t * self );
int fd_optional_account_encode( fd_optional_account_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_optional_account_walk( void * w, fd_optional_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_optional_account_size( fd_optional_account_t const * self );
static inline ulong fd_optional_account_align( void ) { return FD_OPTIONAL_ACCOUNT_ALIGN; }
int fd_optional_account_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_optional_account_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_calculated_stake_points_new( fd_calculated_stake_points_t * self ) { fd_memset( self, 0, sizeof(fd_calculated_stake_points_t) ); }
int fd_calculated_stake_points_encode( fd_calculated_stake_points_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_calculated_stake_points_walk( void * w, fd_calculated_stake_points_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_calculated_stake_points_size( fd_calculated_stake_points_t const * self ) { (void)self; return 25UL; }
static inline ulong fd_calculated_stake_points_align( void ) { return FD_CALCULATED_STAKE_POINTS_ALIGN; }
static inline int fd_calculated_stake_points_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_calculated_stake_points_t);
  if( (ulong)ctx->data + 25UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_calculated_stake_points_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_calculated_stake_rewards_new( fd_calculated_stake_rewards_t * self ) { fd_memset( self, 0, sizeof(fd_calculated_stake_rewards_t) ); }
int fd_calculated_stake_rewards_encode( fd_calculated_stake_rewards_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_calculated_stake_rewards_walk( void * w, fd_calculated_stake_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_calculated_stake_rewards_size( fd_calculated_stake_rewards_t const * self ) { (void)self; return 24UL; }
static inline ulong fd_calculated_stake_rewards_align( void ) { return FD_CALCULATED_STAKE_REWARDS_ALIGN; }
static inline int fd_calculated_stake_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_calculated_stake_rewards_t);
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_calculated_stake_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_duplicate_slot_proof_new( fd_duplicate_slot_proof_t * self );
int fd_duplicate_slot_proof_encode( fd_duplicate_slot_proof_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_duplicate_slot_proof_walk( void * w, fd_duplicate_slot_proof_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_duplicate_slot_proof_size( fd_duplicate_slot_proof_t const * self );
static inline ulong fd_duplicate_slot_proof_align( void ) { return FD_DUPLICATE_SLOT_PROOF_ALIGN; }
int fd_duplicate_slot_proof_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_duplicate_slot_proof_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_epoch_info_pair_new( fd_epoch_info_pair_t * self ) { fd_memset( self, 0, sizeof(fd_epoch_info_pair_t) ); }
int fd_epoch_info_pair_encode( fd_epoch_info_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_epoch_info_pair_walk( void * w, fd_epoch_info_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_epoch_info_pair_size( fd_epoch_info_pair_t const * self ) { (void)self; return 104UL; }
static inline ulong fd_epoch_info_pair_align( void ) { return FD_EPOCH_INFO_PAIR_ALIGN; }
static inline int fd_epoch_info_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_epoch_info_pair_t);
  if( (ulong)ctx->data + 104UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_epoch_info_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_vote_info_pair_new( fd_vote_info_pair_t * self );
int fd_vote_info_pair_encode( fd_vote_info_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_vote_info_pair_walk( void * w, fd_vote_info_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_vote_info_pair_size( fd_vote_info_pair_t const * self );
static inline ulong fd_vote_info_pair_align( void ) { return FD_VOTE_INFO_PAIR_ALIGN; }
int fd_vote_info_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_vote_info_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_epoch_info_new( fd_epoch_info_t * self );
int fd_epoch_info_encode( fd_epoch_info_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_epoch_info_walk( void * w, fd_epoch_info_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_epoch_info_size( fd_epoch_info_t const * self );
static inline ulong fd_epoch_info_align( void ) { return FD_EPOCH_INFO_ALIGN; }
int fd_epoch_info_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_epoch_info_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_usage_cost_details_new( fd_usage_cost_details_t * self ) { fd_memset( self, 0, sizeof(fd_usage_cost_details_t) ); }
int fd_usage_cost_details_encode( fd_usage_cost_details_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_usage_cost_details_walk( void * w, fd_usage_cost_details_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_usage_cost_details_size( fd_usage_cost_details_t const * self ) { (void)self; return 48UL; }
static inline ulong fd_usage_cost_details_align( void ) { return FD_USAGE_COST_DETAILS_ALIGN; }
static inline int fd_usage_cost_details_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_usage_cost_details_t);
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_usage_cost_details_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_transaction_cost_new_disc( fd_transaction_cost_t * self, uint discriminant );
void fd_transaction_cost_new( fd_transaction_cost_t * self );
int fd_transaction_cost_encode( fd_transaction_cost_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_transaction_cost_walk( void * w, fd_transaction_cost_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_transaction_cost_size( fd_transaction_cost_t const * self );
static inline ulong fd_transaction_cost_align( void ) { return FD_TRANSACTION_COST_ALIGN; }
int fd_transaction_cost_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_transaction_cost_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_transaction_cost_is_simple_vote( fd_transaction_cost_t const * self );
FD_FN_PURE uchar fd_transaction_cost_is_transaction( fd_transaction_cost_t const * self );
enum {
fd_transaction_cost_enum_simple_vote = 0,
fd_transaction_cost_enum_transaction = 1,
};
static inline void fd_account_costs_pair_new( fd_account_costs_pair_t * self ) { fd_memset( self, 0, sizeof(fd_account_costs_pair_t) ); }
int fd_account_costs_pair_encode( fd_account_costs_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_account_costs_pair_walk( void * w, fd_account_costs_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_account_costs_pair_size( fd_account_costs_pair_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_account_costs_pair_align( void ) { return FD_ACCOUNT_COSTS_PAIR_ALIGN; }
static inline int fd_account_costs_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_account_costs_pair_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_account_costs_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_account_costs_new( fd_account_costs_t * self );
int fd_account_costs_encode( fd_account_costs_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_account_costs_walk( void * w, fd_account_costs_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_account_costs_size( fd_account_costs_t const * self );
static inline ulong fd_account_costs_align( void ) { return FD_ACCOUNT_COSTS_ALIGN; }
int fd_account_costs_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_account_costs_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_cost_tracker_new( fd_cost_tracker_t * self );
int fd_cost_tracker_encode( fd_cost_tracker_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_cost_tracker_walk( void * w, fd_cost_tracker_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_cost_tracker_size( fd_cost_tracker_t const * self );
static inline ulong fd_cost_tracker_align( void ) { return FD_COST_TRACKER_ALIGN; }
int fd_cost_tracker_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_cost_tracker_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_rent_paying_new( fd_rent_paying_t * self ) { fd_memset( self, 0, sizeof(fd_rent_paying_t) ); }
int fd_rent_paying_encode( fd_rent_paying_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_rent_paying_walk( void * w, fd_rent_paying_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
static inline ulong fd_rent_paying_size( fd_rent_paying_t const * self ) { (void)self; return 16UL; }
static inline ulong fd_rent_paying_align( void ) { return FD_RENT_PAYING_ALIGN; }
static inline int fd_rent_paying_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_rent_paying_t);
  if( (ulong)ctx->data + 16UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_rent_paying_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_rent_state_new_disc( fd_rent_state_t * self, uint discriminant );
void fd_rent_state_new( fd_rent_state_t * self );
int fd_rent_state_encode( fd_rent_state_t const * self, fd_bincode_encode_ctx_t * ctx );
void fd_rent_state_walk( void * w, fd_rent_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );
ulong fd_rent_state_size( fd_rent_state_t const * self );
static inline ulong fd_rent_state_align( void ) { return FD_RENT_STATE_ALIGN; }
int fd_rent_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_rent_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_FN_PURE uchar fd_rent_state_is_uninitialized( fd_rent_state_t const * self );
FD_FN_PURE uchar fd_rent_state_is_rent_paying( fd_rent_state_t const * self );
FD_FN_PURE uchar fd_rent_state_is_rent_exempt( fd_rent_state_t const * self );
enum {
fd_rent_state_enum_uninitialized = 0,
fd_rent_state_enum_rent_paying = 1,
fd_rent_state_enum_rent_exempt = 2,
};
FD_PROTOTYPES_END

#endif // HEADER_FD_RUNTIME_TYPES
