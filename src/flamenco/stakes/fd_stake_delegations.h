#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h

#include "../rewards/fd_rewards_base.h"
#include "../runtime/fd_cost_tracker.h"
#include "../../disco/pack/fd_pack.h" /* TODO: Layering violation */
#include "../../disco/pack/fd_pack_cost.h"
#include "../../util/tmpl/fd_map.h"

#define FD_STAKE_DELEGATIONS_MAGIC (0xF17EDA2CE757A3E0) /* FIREDANCER STAKE V0 */

/* fd_stake_delegations_t is a cache of stake accounts mapping the
   pubkey of the stake account to various information including
   stake, activation/deactivation epoch, corresponding vote_account,
   credits observed, and warmup cooldown rate. This is used to quickly
   iterate through all of the stake delegations in the system during
   epoch boundary reward calculations.

   The implementation of fd_stake_delegations_t is split into two:
   1. The entire set of stake delegations are stored in the root as a
      map/pool pair.  This root state is setup at boot (on snapshot
      load) and is not directly modified after that point.
   2. As banks/forks execute, they will maintain a delta-based
      representation of the stake delegations.  Each fork will hold its
      own set of deltas.  These are then applied to the root set when
      the fork is finalized.  This is implemented as each bank having
      its own dlist of deltas which are allocated from a pool which is
      shared across all stake delegation forks.  The caller is expected
      to create a new fork index for each bank and add deltas to it.

   There are some important invariants wrt fd_stake_delegations_t:
   1. After execution has started, there will be no invalid stake
      accounts in the stake delegations struct.
   2. The stake delegations struct can have valid delegations for vote
      accounts which no longer exist.
   3. There are no stake accounts which are valid delegations which
      exist in the accounts database but not in fd_stake_delegations_t.

   In practice, fd_stake_delegations_t are updated in 3 cases:
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
   The stake accounts are read-only during the epoch boundary.

   The concurrency model is limited: most operations are not allowed to
   be concurrent with each other with the exception of operations that
   operate on the stake delegations's delta pool:
    fd_stake_delegations_fork_update()
    fd_stake_delegations_fork_remove()
    fd_stake_delegations_evict_fork()
   These operations are internally synchronized with a read-write lock
   because multiple executor tiles may be trying to call
   stake_delegations_fork_update() at the same time, and the replay tile
   can simulatenously be calling fd_stake_delegations_evict_fork()
   */

#define FD_STAKE_DELEGATIONS_ALIGN (128UL)

#define FD_STAKE_DELEGATIONS_FORK_MAX (4096UL)

/* The warmup cooldown rate can only be one of two values: 0.25 or 0.09.
   The reason that the double is mapped to an enum is to save space in
   the stake delegations struct. */
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 (0)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 (1)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025      (0.25)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009      (0.09)

struct fd_stake_delegation {
  fd_pubkey_t stake_account;
  fd_pubkey_t vote_account;
  ulong       stake;
  ulong       credits_observed;
  uint        next_; /* Internal pool/map/dlist usage */

  union {
    uint      prev_; /* Internal dlist usage for delta  */
    uint      delta_idx; /* Tracking for stake delegation iteration */
  };
  ushort      activation_epoch;
  ushort      deactivation_epoch;
  union {
    uchar     is_tombstone; /* Internal dlist/delta usage */
    uchar     dne_in_root;  /* Tracking for stake delegation iteration */
  };
  uchar       warmup_cooldown_rate; /* enum representing 0.25 or 0.09 */
};
typedef struct fd_stake_delegation fd_stake_delegation_t;

struct fd_stake_delegations {
  ulong magic;
  ulong expected_stake_accounts_;
  ulong max_stake_accounts_;

  /* Root map + pool */
  ulong map_offset_;
  ulong pool_offset_;

  /* Delta pool + fork  */
  ulong       delta_pool_offset_;
  ulong       fork_pool_offset_;
  ulong       dlist_offsets_[ FD_STAKE_DELEGATIONS_FORK_MAX ];
  fd_rwlock_t delta_lock;

  /* Stake totals for the current root. */
  ulong effective_stake;
  ulong activating_stake;
  ulong deactivating_stake;
};
typedef struct fd_stake_delegations fd_stake_delegations_t;

/* Forward declare map iterator API generated by fd_map_chain.c */
typedef struct root_map_private root_map_t;
typedef struct fd_map_chain_iter fd_stake_delegation_map_iter_t;
struct fd_stake_delegations_iter {
  root_map_t *                   root_map;
  fd_stake_delegation_t *        root_pool;
  fd_stake_delegation_t *        delta_pool;
  fd_stake_delegation_map_iter_t iter;
};
typedef struct fd_stake_delegations_iter fd_stake_delegations_iter_t;

FD_PROTOTYPES_BEGIN

static inline double
fd_stake_delegations_warmup_cooldown_rate_to_double( uchar warmup_cooldown_rate ) {
  return warmup_cooldown_rate==FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 ? FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025 : FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009;
}

static inline uchar
fd_stake_delegations_warmup_cooldown_rate_enum( double warmup_cooldown_rate ) {
  /* TODO: Replace with fd_double_eq */
  if( FD_LIKELY( warmup_cooldown_rate==FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025 ) ) {
    return FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025;
  } else if( FD_LIKELY( warmup_cooldown_rate==FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009 ) ) {
    return FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009;
  }
  FD_LOG_CRIT(( "Invalid warmup cooldown rate %f", warmup_cooldown_rate ));
}

/* fd_stake_delegations_align returns the alignment of the stake
   delegations struct. */

ulong
fd_stake_delegations_align( void );

/* fd_stake_delegations_footprint returns the footprint of the stake
   delegations struct for a given amount of max stake accounts,
   expected stake accounts, and max live slots. */

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts,
                                ulong expected_stake_accounts,
                                ulong max_live_slots );

/* fd_stake_delegations_new creates a new stake delegations struct
   with a given amount of max and expected stake accounts and max live
   slots.  It formats a memory region which is sized based off the pool
   capacity, expected map occupancy, and per-fork delta structures. */

void *
fd_stake_delegations_new( void * mem,
                          ulong  seed,
                          ulong  max_stake_accounts,
                          ulong  expected_stake_accounts,
                          ulong  max_live_slots );

/* fd_stake_delegations_join joins a stake delegations struct from a
   memory region. There can be multiple valid joins for a given memory
   region but the caller is responsible for accessing memory in a
   thread-safe manner. */

fd_stake_delegations_t *
fd_stake_delegations_join( void * mem );

/* fd_stake_delegations_init resets the state of a valid join of a
   stake delegations struct.  Specifically, it only resets the root
   state, leaving the deltas intact. */

void
fd_stake_delegations_init( fd_stake_delegations_t * stake_delegations );

/* fd_stake_delegation_root_query looks up the stake delegation for the
   given stake account in the root map. */

fd_stake_delegation_t const *
fd_stake_delegation_root_query( fd_stake_delegations_t const * stake_delegations,
                                fd_pubkey_t const *            stake_account );

/* fd_stake_delegations_root_update will either insert a new stake
   delegation if the pubkey doesn't exist yet, or it will update the
   stake delegation for the pubkey if already in the map, overriding any
   previous data. fd_stake_delegations_t must be a valid local join. */

void
fd_stake_delegations_root_update( fd_stake_delegations_t * stake_delegations,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  double                   warmup_cooldown_rate );

/* fd_stake_delegations_refresh is used to refresh the stake
   delegations stored in fd_stake_delegations_t which is owned by
   the bank. For a given database handle, read in the state of all
   stake accounts, decode their state, and update each stake delegation.
   This is meant to be called before any slots are executed, but after
   the snapshot has finished loading.

   Before this function is called, there are some important assumptions
   made about the state of the stake delegations:
   1. fd_stake_delegations_t is not missing any valid entries
   2. fd_stake_delegations_t may have some invalid entries that should
      be removed

   fd_stake_delegations_refresh will remove all of the invalid entries
   that are detected. An entry is considered invalid if the stake
   account does not exist (e.g. zero balance or no record) or if it
   has invalid state (e.g. not a stake account or invalid bincode data).
   No new entries are added to the struct at this point. */

void
fd_stake_delegations_refresh( fd_stake_delegations_t *   stake_delegations,
                              ulong                      epoch,
                              fd_stake_history_t const * stake_history,
                              ulong *                    warmup_cooldown_rate_epoch,
                              fd_accdb_user_t *          accdb,
                              fd_funk_txn_xid_t const *  xid );

/* fd_stake_delegations_cnt returns the number of stake delegations
   in the base of stake delegations struct. */

ulong
fd_stake_delegations_cnt( fd_stake_delegations_t const * stake_delegations );

/* fd_stake_delegations_new_fork allocates a new fork index for the
   stake delegations.  The fork index is returned to the caller. */

ushort
fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations );

/* fd_stake_delegations_fork_update will insert a new stake delegation
   delta for the fork.  If an entry already exists in the fork, a new
   one will be inserted without removing the old one.

   TODO: Add a per fork map so multiple entries aren't needed for the
   same stake account. */

void
fd_stake_delegations_fork_update( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  double                   warmup_cooldown_rate );

/* fd_stake_delegations_fork_remove inserts a tombstone stake delegation
   entry for the given fork.  The function will not actually remove or
   free any resources corresponding to the stake account.  The reason a
   tombstone is stored is because each fork corresponds to a set of
   stake delegation deltas for a given slot.  This function may insert a
   'duplicate' entry for the same stake account but it will be resolved
   by the time the delta is applied to a base stake delegations
   object. */

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account );

/* fd_stake_delegations_evict_fork removes/frees all stake delegation
   entries for a given fork.  After this function is called it is no
   longer safe to have any references to the fork index (until it is
   reused via a call to fd_stake_delegations_new_fork).  The caller is
   responsible for making sure references to this fork index are not
   being held. */

void
fd_stake_delegations_evict_fork( fd_stake_delegations_t * stake_delegations,
                                 ushort                   fork_idx );

/* fd_stake_delegations_apply_fork_delta merges all stake delegation
   entries for fork_idx into the root map: non-tombstone entries are
   applied via fd_stake_delegations_root_update; tombstone entries remove
   the corresponding stake account from the root map.  Caller must
   ensure no concurrent iteration on stake_delegations for this fork. */

   void
   fd_stake_delegations_apply_fork_delta( ulong                      epoch,
                                          fd_stake_history_t const * stake_history,
                                          ulong *                    warmup_cooldown_rate_epoch,
                                          fd_stake_delegations_t *   stake_delegations,
                                          ushort                     fork_idx );

/* fd_stake_delegations_{mark,unmark}_delta are used to temporarily
   tag delta elements from a given fork in the base/root stake
   delegation map/pool.  This allows the caller to then iterator over
   the stake delegations for a given bank using just the deltas and the
   root without creating a copy.  Each delta that is marked, must be
   unmarked after the caller is done iterating over the stake
   delegations.

   Under the hood, it reuses internal pointers for elements in the root
   map to point to the corresponding delta element.  If the element is
   removed by a delta another field will be reused to ignore it during
   iteration.  If an element is inserted by a delta, it will be
   temporarily added to the root, but will be removed with a call to
   unmark_delta.  These functions are also used to temporarily update
   (and then unwind) the stake totals for the current root. */

void
fd_stake_delegations_mark_delta( fd_stake_delegations_t *   stake_delegations,
                                 ulong                      epoch,
                                 fd_stake_history_t const * stake_history,
                                 ulong *                    warmup_cooldown_rate_epoch,
                                 ushort                     fork_idx );

void
fd_stake_delegations_unmark_delta( fd_stake_delegations_t *   stake_delegations,
                                   ulong                      epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    warmup_cooldown_rate_epoch,
                                   ushort                     fork_idx );

/* Iterator API for stake delegations.  The iterator is initialized with
   a call to fd_stake_delegations_iter_init.  The caller is responsible
   for managing the memory for the iterator.  It is safe to call
   fd_stake_delegations_iter_next if the result of
   fd_stake_delegations_iter_done()==0.  It is safe to call
   fd_stake_delegations_iter_ele() to get the current stake delegation
   or fd_stake_delegations_iter_idx() to get the index of the current
   stake delegation.  It is not safe to modify the stake delegation
   while iterating through it.

   Under the hood, the iterator is just a wrapper over the iterator in
   fd_map_chain.c.

   Example use:

   fd_stake_delegations_iter_t iter_[1];
   for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
        !fd_stake_delegations_iter_done( iter );
        fd_stake_delegations_iter_next( iter ) ) {
     fd_stake_delegation_t * stake_delegation = fd_stake_delegations_iter_ele( iter );
   }
*/

fd_stake_delegation_t const *
fd_stake_delegations_iter_ele( fd_stake_delegations_iter_t * iter );

ulong
fd_stake_delegations_iter_idx( fd_stake_delegations_iter_t * iter );

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations );

void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter );

int
fd_stake_delegations_iter_done( fd_stake_delegations_iter_t * iter );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h */
