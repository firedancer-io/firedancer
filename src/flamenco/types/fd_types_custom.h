#ifndef HEADER_fd_src_flamenco_runtime_fd_types_custom
#define HEADER_fd_src_flamenco_runtime_fd_types_custom

#include "fd_types_meta.h"
#include "fd_bincode.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../util/net/fd_ip4.h"

#define FD_HASH_FOOTPRINT (32UL)
#define FD_HASH_ALIGN (8UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
#define FD_PUBKEY_ALIGN FD_HASH_ALIGN

/* TODO this should not have packed alignment, but it's misused everywhere */

union __attribute__((packed)) fd_hash {
  uchar hash[ FD_HASH_FOOTPRINT ];
  uchar key [ FD_HASH_FOOTPRINT ]; // Making fd_hash and fd_pubkey interchangeable

  // Generic type specific accessors
  ulong ul  [ FD_HASH_FOOTPRINT / sizeof(ulong) ];
  uint  ui  [ FD_HASH_FOOTPRINT / sizeof(uint)  ];
  uchar uc  [ FD_HASH_FOOTPRINT ];
};

typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

static const fd_pubkey_t pubkey_null = { 0 };
static const fd_hash_t   hash_null   = { 0 };

union fd_signature {
  uchar uc[ 64 ];
  ulong ul[  8 ];
};

typedef union fd_signature fd_signature_t;

FD_PROTOTYPES_BEGIN

#define fd_hash_check_zero(_x) (!((_x)->ul[0] | (_x)->ul[1] | (_x)->ul[2] | (_x)->ul[3]))
#define fd_hash_set_zero(_x)   {((_x)->ul[0] = 0); ((_x)->ul[1] = 0); ((_x)->ul[2] = 0); ((_x)->ul[3] = 0);}

#define fd_pubkey_new              fd_hash_new
#define fd_pubkey_decode           fd_hash_decode
#define fd_pubkey_decode_preflight fd_hash_decode_preflight
#define fd_pubkey_decode_unsafe    fd_hash_decode_unsafe
#define fd_pubkey_encode           fd_hash_encode
#define fd_pubkey_decode_archival  fd_hash_decode
#define fd_pubkey_encode_archival  fd_hash_encode
#define fd_pubkey_destroy          fd_hash_destroy
#define fd_pubkey_size             fd_hash_size
#define fd_pubkey_check_zero       fd_hash_check_zero
#define fd_pubkey_set_zero         fd_hash_set_zero
#define fd_pubkey_walk             fd_hash_walk

#define fd_hash_decode_archival             fd_hash_decode
#define fd_hash_decode_archival_preflight   fd_hash_decode_preflight
#define fd_hash_decode_archival_unsafe      fd_hash_decode_unsafe
#define fd_hash_encode_archival             fd_hash_encode
#define fd_pubkey_decode_archival_preflight fd_hash_decode_preflight
#define fd_pubkey_decode_archival_unsafe    fd_hash_decode_unsafe

struct __attribute__((aligned(8UL))) fd_option_slot {
  uchar is_some;
  ulong slot;
};
typedef struct fd_option_slot fd_option_slot_t;

/* Index structure needed for transaction status (metadata) blocks */
struct fd_txnstatusidx {
    fd_ed25519_sig_t sig;
    ulong offset;
    ulong status_sz;
};
typedef struct fd_txnstatusidx fd_txnstatusidx_t;

/* IPv4 ***************************************************************/

typedef uint fd_gossip_ip4_addr_t;
typedef uint fd_gossip_ip4_addr_t;

/* IPv6 ***************************************************************/

union fd_gossip_ip6_addr {
  uchar  uc[ 16 ];
  ushort us[  8 ];
  uint   ul[  4 ];
};

typedef union fd_gossip_ip6_addr fd_gossip_ip6_addr_t;

/* Solana account struct for vote accounts. */
/* Encoded Size: Fixed (113 bytes) */
struct __attribute__((aligned(8UL))) fd_solana_vote_account {
  ulong lamports;
  fd_pubkey_t node_pubkey;
  long last_timestamp_ts;
  ulong last_timestamp_slot;
  fd_pubkey_t owner;
  uchar executable;
  ulong rent_epoch;
};
typedef struct fd_solana_vote_account fd_solana_vote_account_t;
#define FD_SOLANA_VOTE_ACCOUNT_FOOTPRINT sizeof(fd_solana_vote_account_t)
#define FD_SOLANA_VOTE_ACCOUNT_ALIGN (8UL)

void
fd_solana_vote_account_new( fd_solana_vote_account_t * self );

int
fd_solana_vote_account_decode( fd_solana_vote_account_t * self, fd_bincode_decode_ctx_t * ctx );

#define fd_solana_vote_account_decode_archival fd_solana_vote_account_decode

int
fd_solana_vote_account_decode_preflight( fd_bincode_decode_ctx_t * ctx );

#define fd_solana_vote_account_decode_archival_preflight fd_solana_vote_account_decode_preflight

void
fd_solana_vote_account_decode_unsafe( fd_solana_vote_account_t * self, fd_bincode_decode_ctx_t * ctx );

#define fd_solana_vote_account_decode_archival_unsafe fd_solana_vote_account_decode_unsafe

int
fd_solana_vote_account_encode( fd_solana_vote_account_t const * self, fd_bincode_encode_ctx_t * ctx );

#define fd_solana_vote_account_encode_archival fd_solana_vote_account_encode

void
fd_solana_vote_account_destroy( fd_solana_vote_account_t * self, fd_bincode_destroy_ctx_t * ctx );

void
fd_solana_vote_account_walk( void * w, fd_solana_vote_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level );

ulong
fd_solana_vote_account_size( fd_solana_vote_account_t const * self );

ulong
fd_solana_vote_account_footprint( void );

ulong
fd_solana_vote_account_align( void );

/* Transaction wrapper ************************************************/

/* fd_flamenco_txn_t is yet another fd_txn_t wrapper.
   This should die as soon as we have a better stubs generator. */

struct fd_flamenco_txn {
  union {
    uchar                  txn_buf[ FD_TXN_MAX_SZ ];
    __extension__ fd_txn_t txn[0];
  };
  uchar raw[ FD_TXN_MTU ];
  ulong raw_sz;
};

typedef struct fd_flamenco_txn fd_flamenco_txn_t;

static inline void
fd_flamenco_txn_new( fd_flamenco_txn_t * self FD_FN_UNUSED ) {}

int
fd_flamenco_txn_decode( fd_flamenco_txn_t *       self,
                        fd_bincode_decode_ctx_t * ctx );

int
fd_flamenco_txn_decode_preflight( fd_bincode_decode_ctx_t * ctx );

void
fd_flamenco_txn_decode_unsafe( fd_flamenco_txn_t *       self,
                               fd_bincode_decode_ctx_t * ctx );

static inline void
fd_flamenco_txn_destroy( fd_flamenco_txn_t const *  self FD_FN_UNUSED,
                         fd_bincode_destroy_ctx_t * ctx  FD_FN_UNUSED ) {}

FD_FN_CONST static inline ulong
fd_flamenco_txn_size( fd_flamenco_txn_t const * self FD_FN_UNUSED ) {
  return self->raw_sz;
}

static inline int
fd_flamenco_txn_encode( fd_flamenco_txn_t const * self,
                        fd_bincode_encode_ctx_t * ctx ) {
  return fd_bincode_bytes_encode( self->raw, self->raw_sz, ctx );
}

static inline void
fd_flamenco_txn_walk( void *                    w,
                      fd_flamenco_txn_t const * self,
                      fd_types_walk_fn_t        fun,
                      char const *              name,
                      uint                      level ) {

  static uchar const zero[ 64 ]={0};
  fd_txn_t const *   txn  = self->txn;
  uchar const *      sig0 = zero;

  if( FD_LIKELY( txn->signature_cnt > 0 ) )
    sig0 = fd_txn_get_signatures( txn, self->raw )[0];

  /* For now, just print the transaction's signature */
  fun( w, sig0, name, FD_FLAMENCO_TYPE_SIG512, "txn", level );
}

/* Represents the lamport balance associated with an account. */
typedef ulong fd_acc_lamports_t;

#if FD_HAS_INT128
/********************* Rewards types **************************************************/
/* TODO: move these into fd_types, but first we need to add dlist support to fd_types */
struct __attribute__((aligned(8UL))) fd_stake_reward {
  /* dlist */
  ulong prev;
  ulong next;
  /* pool */
  ulong parent;
  /* data */
  fd_pubkey_t stake_pubkey;
  ulong credits_observed;
  ulong lamports;
};
typedef struct fd_stake_reward fd_stake_reward_t;
#define FD_STAKE_REWARD_FOOTPRINT sizeof(fd_stake_reward_t)
#define FD_STAKE_REWARD_ALIGN (8UL)

/* Encoded Size: Fixed (42 bytes) */
struct __attribute__((aligned(8UL))) fd_vote_reward {
  fd_pubkey_t pubkey;
  ulong vote_rewards;
  uchar commission;
  uchar needs_store;
};
typedef struct fd_vote_reward fd_vote_reward_t;
#define FD_VOTE_REWARD_FOOTPRINT sizeof(fd_vote_reward_t)
#define FD_VOTE_REWARD_ALIGN (8UL)

#define DLIST_NAME fd_stake_reward_dlist
#define DLIST_ELE_T fd_stake_reward_t
#include "../../util/tmpl/fd_dlist.c"
#undef DLIST_NAME
#undef DLIST_ELE_T

#define POOL_NAME fd_stake_reward_pool
#define POOL_T fd_stake_reward_t
#define POOL_NEXT parent
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T
#undef POOL_NEXT

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

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L21 */
/* Encoded Size: Fixed (24 bytes) */
struct __attribute__((aligned(8UL))) fd_point_value {
  ulong rewards;
  uint128 points;
};
typedef struct fd_point_value fd_point_value_t;
#define FD_POINT_VALUE_FOOTPRINT sizeof(fd_point_value_t)
#define FD_POINT_VALUE_ALIGN (8UL)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L56 */
/* Encoded Size: Dynamic */
struct __attribute__((aligned(8UL))) fd_partitioned_stake_rewards {
  ulong partitions_len;
  fd_stake_reward_dlist_t * partitions;
  fd_stake_reward_t * pool;
};
typedef struct fd_partitioned_stake_rewards fd_partitioned_stake_rewards_t;
#define FD_PARTITIONED_STAKE_REWARDS_FOOTPRINT sizeof(fd_partitioned_stake_rewards_t)
#define FD_PARTITIONED_STAKE_REWARDS_ALIGN (8UL)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L131 */
/* Encoded Size: Dynamic */
struct __attribute__((aligned(8UL))) fd_stake_reward_calculation_partitioned {
  fd_partitioned_stake_rewards_t partitioned_stake_rewards;
  ulong total_stake_rewards_lamports;
};
typedef struct fd_stake_reward_calculation_partitioned fd_stake_reward_calculation_partitioned_t;
#define FD_STAKE_REWARD_CALCULATION_PARTITIONED_FOOTPRINT sizeof(fd_stake_reward_calculation_partitioned_t)
#define FD_STAKE_REWARD_CALCULATION_PARTITIONED_ALIGN (8UL)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L94 */
/* Encoded Size: Dynamic */
struct __attribute__((aligned(8UL))) fd_stake_reward_calculation {
  fd_stake_reward_dlist_t stake_rewards;
  ulong stake_rewards_len;
  fd_stake_reward_t * pool;
  ulong total_stake_rewards_lamports;
};
typedef struct fd_stake_reward_calculation fd_stake_reward_calculation_t;
#define FD_STAKE_REWARD_CALCULATION_FOOTPRINT sizeof(fd_stake_reward_calculation_t)
#define FD_STAKE_REWARD_CALCULATION_ALIGN (8UL)

/* Encoded Size: Dynamic */
struct __attribute__((aligned(8UL))) fd_calculate_stake_vote_rewards_result {
  fd_stake_reward_calculation_t stake_reward_calculation;
  fd_vote_reward_t_mapnode_t * vote_reward_map_pool;
  fd_vote_reward_t_mapnode_t * vote_reward_map_root;
};
typedef struct fd_calculate_stake_vote_rewards_result fd_calculate_stake_vote_rewards_result_t;
#define FD_CALCULATE_STAKE_VOTE_REWARDS_RESULT_FOOTPRINT sizeof(fd_calculate_stake_vote_rewards_result_t)
#define FD_CALCULATE_STAKE_VOTE_REWARDS_RESULT_ALIGN (8UL)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L102 */
/* Encoded Size: Dynamic */
struct __attribute__((aligned(8UL))) fd_calculate_validator_rewards_result {
  fd_calculate_stake_vote_rewards_result_t calculate_stake_vote_rewards_result;
  fd_point_value_t point_value;
};
typedef struct fd_calculate_validator_rewards_result fd_calculate_validator_rewards_result_t;
#define FD_CALCULATE_VALIDATOR_REWARDS_RESULT_FOOTPRINT sizeof(fd_calculate_validator_rewards_result_t)
#define FD_CALCULATE_VALIDATOR_REWARDS_RESULT_ALIGN (8UL)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L138 */
/* Encoded Size: Dynamic */
struct __attribute__((aligned(8UL))) fd_calculate_rewards_and_distribute_vote_rewards_result {
  ulong total_rewards;
  ulong distributed_rewards;
  fd_point_value_t point_value;
  fd_stake_reward_calculation_partitioned_t stake_rewards_by_partition;
};
typedef struct fd_calculate_rewards_and_distribute_vote_rewards_result fd_calculate_rewards_and_distribute_vote_rewards_result_t;
#define FD_CALCULATE_REWARDS_AND_DISTRIBUTE_VOTE_REWARDS_RESULT_FOOTPRINT sizeof(fd_calculate_rewards_and_distribute_vote_rewards_result_t)
#define FD_CALCULATE_REWARDS_AND_DISTRIBUTE_VOTE_REWARDS_RESULT_ALIGN (8UL)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L118 */
/* Encoded Size: Dynamic */
struct __attribute__((aligned(8UL))) fd_partitioned_rewards_calculation {
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
#define FD_PARTITIONED_REWARDS_CALCULATION_FOOTPRINT sizeof(fd_partitioned_rewards_calculation_t)
#define FD_PARTITIONED_REWARDS_CALCULATION_ALIGN (8UL)

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L60 */
/* Encoded Size: Dynamic */
struct __attribute__((aligned(8UL))) fd_start_block_height_and_rewards {
  ulong distribution_starting_block_height;
  fd_partitioned_stake_rewards_t partitioned_stake_rewards;
};
typedef struct fd_start_block_height_and_rewards fd_start_block_height_and_rewards_t;
#define FD_START_BLOCK_HEIGHT_AND_REWARDS_FOOTPRINT sizeof(fd_start_block_height_and_rewards_t)
#define FD_START_BLOCK_HEIGHT_AND_REWARDS_ALIGN (8UL)

union fd_epoch_reward_status_inner {
  fd_start_block_height_and_rewards_t Active;
};
typedef union fd_epoch_reward_status_inner fd_epoch_reward_status_inner_t;

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L70 */
struct fd_epoch_reward_status {
  uint discriminant;
  fd_epoch_reward_status_inner_t inner;
};
typedef struct fd_epoch_reward_status fd_epoch_reward_status_t;
#define FD_EPOCH_REWARD_STATUS_FOOTPRINT sizeof(fd_epoch_reward_status_t)
#define FD_EPOCH_REWARD_STATUS_ALIGN (8UL)

enum {
fd_epoch_reward_status_enum_Active = 0,
fd_epoch_reward_status_enum_Inactive = 1,
};

/*******************************************************************************************/
#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_types_custom */
