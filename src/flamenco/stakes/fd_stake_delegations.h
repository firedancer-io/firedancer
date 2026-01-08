#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h

#include "../rewards/fd_rewards_base.h"
#include "../runtime/fd_cost_tracker.h"
#include "../../disco/pack/fd_pack.h" /* TODO: Layering violation */
#include "../../disco/pack/fd_pack_cost.h"
#include "../../util/tmpl/fd_map.h"

#define FD_STAKE_DELEGATIONS_MAGIC (0xF17EDA2CE757A3E0) /* FIREDANCER STAKE V0 */

/* fd_stakes_delegations_t is a cache of stake accounts mapping the
   pubkey of the stake account to various information including
   stake, activation/deactivation epoch, corresponding vote_account,
   credits observed, and warmup cooldown rate. This is used to quickly
   iterate through all of the stake delegations in the system during
   epoch boundary reward calculations.

   The implementation of fd_stakes_delegations_t is a hash map which
   is backed by a memory pool. Callers are allowed to insert, replace,
   and remove entries from the map.

   fd_stakes_delegations_t can also exist in two modes: with and without
   tombstones. The mode is determined by the leave_tombstones flag
   passed to fd_stake_delegations_new. If tombstones are enabled, then
   calling fd_stake_delegations_remove will not remove the entry from
   the map, but rather set the is_tombstone flag to true. This is
   useful for delta updates where we want to keep the entry in the map
   for future reference. In practice, this struct is used in both modes
   by the bank. The stake delegations corresponding to each slot are
   stored in a delta struct which is used to update the main cache.

   There are some important invariants wrt fd_stake_delegations_t:
   1. After execution has started, there will be no invalid stake
      accounts in the stake delegations struct.
   2. The stake delegations struct can have valid delegations for vote
      accounts which no longer exist.
   3. There are no stake accounts which are valid delegations which
      exist in the accounts database but not in fd_stake_delegations_t.

   In practice, fd_stakes_delegations_t are updated in 3 cases:
   1. During bootup when the snapshot manifest is loaded in. The cache
      is also refreshed during the bootup process to ensure that the
      states are valid and up-to-date.

      The reason we can't populate the stake accounts from the cache
      is because the cache in the manifest is partially incomplete:
      all of the expected keys are there, but the values are not.
      Notably, the credits_observed field is not available until all of
      the accounts are loaded into the database.

      https://github.com/anza-xyz/agave/blob/v2.3.6/runtime/src/bank.rs#L1780-L1806

   2. After transaction execution. If an update is made to a stake
      account, the updated state is reflected in the cache (or the entry
      is evicted).
   3. During rewards distribution. Stake accounts are partitioned over
      several hundred slots where their rewards are distributed. In this
      case, the cache is updated to reflect each stake account post
      reward distribution.
   The stake accounts are read-only during the epoch boundary. */

/* The max number of stake accounts that can be modified in a current
   slot from transactions can be bounded based on CU consumption. The
   best strategy to maximize the max number of stake accounts modified
   in a single transaction.  A stake program instruction can either
   modify one or two stake accounts.  Stake program instructions that
   modify two stake accounts (merge/split) are assumed to be at least 2x
   as expensive as a stake program instruction that modifies one stake
   account.  So we will assume that the most efficient strategy is to
   modify one stake account per instruction and have as many instruction
   as posssible in this transaction.  We can have 63 stake program
   instructions in this transaction because one account will be the fee
   payer/signature and the other 63 are free to be writable accounts.

   Given the above:
   100000000 - CUs per slot
   64 - Max number of writable accounts per transaction.
   63 - Max number of writable stake accounts per transaction.
   720 - Cost of a signature
   300 - Cost of a writable account lock.
   6000 - Cost of a stake program instruction.

   We can have (100000000 / (720 + 300 * 64 + 6000 * 63)) = 251
   optimal stake program transactions per slot.  With 63 stake accounts
   per transaction, we can have 251 * 63 = 15813 stake accounts modified
   in a slot. */

#define MAX_OPTIMAL_STAKE_ACCOUNTS_POSSIBLE_IN_TXN (FD_MAX_BLOCK_UNITS_SIMD_0286/(FD_WRITE_LOCK_UNITS * FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION + FD_RUNTIME_MIN_STAKE_INSN_CUS * (FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION - 1UL) + FD_PACK_COST_PER_SIGNATURE))
FD_STATIC_ASSERT(MAX_OPTIMAL_STAKE_ACCOUNTS_POSSIBLE_IN_TXN==251, "Incorrect MAX_STAKE_ACCOUNTS_POSSIBLE_IN_TXN");
#define MAX_STAKE_ACCOUNTS_POSSIBLE_IN_SLOT_FROM_TXNS (MAX_OPTIMAL_STAKE_ACCOUNTS_POSSIBLE_IN_TXN * (FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION - 1UL))
FD_STATIC_ASSERT(MAX_STAKE_ACCOUNTS_POSSIBLE_IN_SLOT_FROM_TXNS==15813, "Incorrect MAX_STAKE_ACCOUNTS_PER_SLOT");

/* The static footprint of fd_stake_delegations_t when it is a delta
   is determined by the max total number of stake accounts that can get
   changed in a single slot. Stake accounts can get modified in two ways:
   1. Through transactions. This bound is calculated using CU
      consumption as described above.
   2. Through epoch rewards. This is a protocol-level bound is defined
      in fd_rewards_base.h and is the max number of stake accounts that
      can reside in a single reward partition. */

#define FD_STAKE_DELEGATIONS_MAX_PER_SLOT (MAX_STAKE_ACCOUNTS_POSSIBLE_IN_SLOT_FROM_TXNS + STAKE_ACCOUNT_STORES_PER_BLOCK)

/* The static footprint of the vote states assumes that there are
   FD_RUNTIME_MAX_STAKE_ACCOUNTS. It also assumes worst case alignment
   for each struct. fd_stake_delegations_t is laid out as first the
   fd_stake_delegations_t struct, followed by a pool of
   fd_stake_delegation_t structs, followed by a map of
   fd_stake_delegation_map_ele_t structs. The pool has
   FD_RUNTIME_MAX_STAKE_ACCOUNTS elements, and the map has a chain count
   determined by a call to fd_stake_delegations_chain_cnt_est.
   NOTE: the footprint is validated to be at least as large as the
   actual runtime-determined footprint (see test_stake_delegations.c) */

#define FD_STAKE_DELEGATIONS_CHAIN_CNT_EST (2097152UL)
#define FD_STAKE_DELEGATIONS_FOOTPRINT                                                         \
  /* First, layout the struct with alignment */                                                \
  sizeof(fd_stake_delegations_t) + alignof(fd_stake_delegations_t) +                           \
  /* Now layout the pool's data footprint */                                                   \
  FD_STAKE_DELEGATIONS_ALIGN + sizeof(fd_stake_delegation_t) * FD_RUNTIME_MAX_STAKE_ACCOUNTS + \
  /* Now layout the pool's meta footprint */                                                   \
  FD_STAKE_DELEGATIONS_ALIGN + 128UL /* POOL_ALIGN */ +                                        \
  /* Now layout the map.  We must make assumptions about the chain */                          \
  /* count to be equivalent to chain_cnt_est. */                                               \
  FD_STAKE_DELEGATIONS_ALIGN + 128UL /* MAP_ALIGN */ + (FD_STAKE_DELEGATIONS_CHAIN_CNT_EST * sizeof(ulong))

/* We need a footprint for the max amount of stake delegations that
   can be added in a single slot. We know that there can be up to
   8192 writable accounts in a slot (bound determined from the cost
   tracker). Using the same calculation as above, we get 120 bytes per
   stake delegation with up to ~19K delegations we have a total
   footprint of ~2.5MB. */

#define FD_STAKE_DELEGATIONS_DELTA_CHAIN_CNT_EST (16384UL)
#define FD_STAKE_DELEGATIONS_DELTA_FOOTPRINT                                                       \
  /* First, layout the struct with alignment */                                                    \
  sizeof(fd_stake_delegations_t) + alignof(fd_stake_delegations_t) +                               \
  /* Now layout the pool's data footprint */                                                       \
  FD_STAKE_DELEGATIONS_ALIGN + sizeof(fd_stake_delegation_t) * FD_STAKE_DELEGATIONS_MAX_PER_SLOT + \
  /* Now layout the pool's meta footprint */                                                       \
  FD_STAKE_DELEGATIONS_ALIGN + 128UL /* POOL_ALIGN */ +                                            \
  /* Now layout the map.  We must make assumptions about the chain */                              \
  /* count to be equivalent to chain_cnt_est. */                                                   \
  FD_STAKE_DELEGATIONS_ALIGN + 128UL /* MAP_ALIGN */ + (FD_STAKE_DELEGATIONS_DELTA_CHAIN_CNT_EST * sizeof(ulong))

#define FD_STAKE_DELEGATIONS_ALIGN (128UL)

struct fd_stake_delegation {
  fd_pubkey_t stake_account;
  fd_pubkey_t vote_account;
  ulong       next_; /* Only for internal pool/map usage */
  ulong       stake;
  ulong       activation_epoch;
  ulong       deactivation_epoch;
  ulong       credits_observed;
  double      warmup_cooldown_rate;
  int         is_tombstone;
};
typedef struct fd_stake_delegation fd_stake_delegation_t;

struct fd_stake_delegations {
  ulong magic;
  ulong map_offset_;
  ulong pool_offset_;
  ulong max_stake_accounts_;
  int   leave_tombstones_;
};
typedef struct fd_stake_delegations fd_stake_delegations_t;

/* Forward declare map iterator API generated by fd_map_chain.c */
typedef struct fd_stake_delegation_map_private fd_stake_delegation_map_t;
typedef struct fd_map_chain_iter fd_stake_delegation_map_iter_t;
struct fd_stake_delegations_iter {
  fd_stake_delegation_map_t *    map;
  fd_stake_delegation_t *        pool;
  fd_stake_delegation_map_iter_t iter;
};
typedef struct fd_stake_delegations_iter fd_stake_delegations_iter_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_delegations_align returns the alignment of the stake
   delegations struct. */

ulong
fd_stake_delegations_align( void );

/* fd_stake_delegations_footprint returns the footprint of the stake
   delegations struct for a given amount of max stake accounts. */

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts );

/* fd_stake_delegations_new creates a new stake delegations struct
   with a given amount of max stake accounts. It formats a memory region
   which is sized based off of the number of stake accounts. The struct
   can optionally be configured to leave tombstones in the map. This is
   useful if fd_stake_delegations is being used as a delta. */

void *
fd_stake_delegations_new( void * mem,
                          ulong  seed,
                          ulong  max_stake_accounts,
                          int    leave_tombstones );

/* fd_stake_delegations_join joins a stake delegations struct from a
   memory region. There can be multiple valid joins for a given memory
   region but the caller is responsible for accessing memory in a
   thread-safe manner. */

fd_stake_delegations_t *
fd_stake_delegations_join( void * mem );

/* fd_stake_delegations_leave returns the stake delegations struct
   from a memory region. */

void *
fd_stake_delegations_leave( fd_stake_delegations_t * self );

/* fd_stake_delegations_delete unformats a memory region that was
   formatted by fd_stake_delegations_new. */

void *
fd_stake_delegations_delete( void * mem );

/* fd_stake_delegations_init resets the state of a valid join of a
   stake delegations struct. */

void
fd_stake_delegations_init( fd_stake_delegations_t * stake_delegations );

/* fd_stake_delegations_update will either insert a new stake delegation
   if the pubkey doesn't exist yet, or it will update the stake
   delegation for the pubkey if already in the map, overriding any
   previous data. fd_stake_delegations_t must be a valid local join.

   NOTE: This function CAN be called while iterating over the map, but
   ONLY for keys which already exist in the map. */

void
fd_stake_delegations_update( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account,
                             fd_pubkey_t const *      vote_account,
                             ulong                    stake,
                             ulong                    activation_epoch,
                             ulong                    deactivation_epoch,
                             ulong                    credits_observed,
                             double                   warmup_cooldown_rate );

/* fd_stake_delegations_remove removes a stake delegation corresponding
   to a stake account's pubkey if one exists. Nothing happens if the
   key doesn't exist in the stake delegations. fd_stake_delegations_t
   must be a valid local join.

   NOTE: If the leave_tombstones flag is set, then the entry is not
   removed from the map, but rather set to a tombstone. If the
   delegation does not exist in the map, then a tombstone is actually
   inserted into the struct. */

void
fd_stake_delegations_remove( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account );


/* fd_stake_delegations_query returns the stake delegation for a
   stake account's pubkey if one exists. If one does not exist, returns
   NULL. fd_stake_delegations_t must be a valid local join. */

fd_stake_delegation_t const *
fd_stake_delegations_query( fd_stake_delegations_t const * stake_delegations,
                            fd_pubkey_t const *            stake_account );

/* fd_stake_delegations_refresh is used to refresh the stake
   delegations stored in fd_stake_delegations_t which is owned by
   the bank. For a given database handle, read in the state of all
   stake accounts, decode their state, and update each stake delegation.
   This is meant to be called before any slots are executed, but after
   the snapshot has finished loading.

   Before this function is called, there are some important assumptions
   made about the state of the stake delegations that are enforced by
   the Agave client:
   1. fd_stake_delegations_t is not missing any valid entries
   2. fd_stake_delegations_t may have some invalid entries that should
      be removed

   fd_stake_delegations_refresh will remove all of the invalid entries
   that are detected. An entry is considered invalid if the stake
   account does not exist (e.g. zero balance or no record) or if it
   has invalid state (e.g. not a stake account or invalid bincode data).
   No new entries are added to the struct at this point. */

void
fd_stake_delegations_refresh( fd_stake_delegations_t *  stake_delegations,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid );

/* fd_stake_delegations_cnt returns the number of stake delegations
   in the stake delegations struct. fd_stake_delegations_t must be a
   valid local join.

   NOTE: The cnt will return the number of stake delegations that are
   in the underlying map. This number includes tombstones if the
   leave_tombstones flag is set. */

ulong
fd_stake_delegations_cnt( fd_stake_delegations_t const * stake_delegations );

static inline ulong
fd_stake_delegations_max( fd_stake_delegations_t const * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  return stake_delegations->max_stake_accounts_;
}

/* Iterator API for stake delegations. The iterator is initialized with
   a call to fd_stake_delegations_iter_init. The caller is responsible
   for managing the memory for the iterator. It is safe to call
   fd_stake_delegations_iter_next if the result of
   fd_stake_delegations_iter_done() ==0. It is safe to call
   fd_stake_delegations_iter_ele() to get the current stake delegation.
   As a note, it is safe to modify the stake delegation acquired from
   fd_stake_delegations_iter_ele() as long as the next_ field is not
   modified (which the caller should never do). It is unsafe to insert
   or remove fd_stake_delegation_t from the stake delegations struct
   while iterating.

   Under the hood, the iterator is just a wrapper over the iterator in
   fd_map_chain.c.

   Example use:

   fd_stake_delegations_iter_t iter_[1];
   for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations ); !fd_stake_delegations_iter_done( iter ); fd_stake_delegations_iter_next( iter ) ) {
     fd_stake_delegation_t * stake_delegation = fd_stake_delegations_iter_ele( iter );
     // Do something with the stake delegation ...
   }
*/

fd_stake_delegation_t *
fd_stake_delegations_iter_ele( fd_stake_delegations_iter_t * iter );

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations );

void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter );

int
fd_stake_delegations_iter_done( fd_stake_delegations_iter_t * iter );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h */
