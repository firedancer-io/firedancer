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

#define FD_STAKE_DELEGATIONS_ALIGN (128UL)

/* The warmup cooldown rate can only be one of two values: 0.25 or 0.09.
   The reason that the double is mapped to an enum is to save space in
   the stake delegations struct. */
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 (0)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 (1)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025      (0.25)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009      (0.09)

/* TODO: The memory footprint of stake delegations can be further
   reduced by maintaining a global index of stake account pubkeys:
   stake_index: pool<pubkey, refcnt>.

   There will also be a global index of vote account pubkeys which is
   also refcnted:
   vote_index: pool<pubkey, refcnt>.

   Assuming 200M stake and vote accounts, this would require:
   200M * (32 bytes for pubkey + 4 bytes for map/pool ptr + 4 bytes for refcnt) = 8GB per index.
   So with our pubkey and stake index, we would need 16GB.

   Now each fd_stake_delegation_t can just reference the pool index of
   the stake and vote account.  With this, now each
   fd_stake_delegation_t can be stored in 40 bytes instead of 128 bytes.

   We need memory to store the frontier set, root set, and the deltas.
   Assume in total we have 200M accounts * 3 sets = 600M elements total.

   So with 40 bytes per element we would need 24GB of memory to store
   all of the elements.  This brings our total footprint to 40GB to
   handle ~200M stake accounts.  If the vote account index is shared
   with the one from fd_vote_stakes_t, the footprint can be further
   reduced by 8GB to 32GB. */

struct fd_stake_delegation {
  fd_pubkey_t stake_account;
  fd_pubkey_t vote_account;
  ulong       stake;
  ulong       credits_observed;
  uint        next_; /* Only for internal pool/map usage */
  ushort      activation_epoch;
  ushort      deactivation_epoch;
  uchar       is_tombstone;
  uchar       warmup_cooldown_rate; /* enum representing 0.25 or 0.09 */
  uint        idx;

  uint        prev;
  uint        next;
};
typedef struct fd_stake_delegation fd_stake_delegation_t;

struct fd_stake_delegations {
  ulong magic;
  ulong map_offset_;
  ulong pool_offset_;
  ulong max_stake_accounts_;
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

static inline double
fd_stake_delegations_warmup_cooldown_rate_to_double( uchar warmup_cooldown_rate ) {
  return warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 ? FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025 : FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009;
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
                          ulong  max_stake_accounts );

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

/* fd_stake_delegations_delta is a shared pool over all live slots for
   fd_stake_delegation_t objects.  It is used to store stake delegations
   for all live slots. */

struct fd_stake_delegations_delta {
  ulong magic;
  ulong pool_offset_;
  ulong map_offset_;
  ulong fork_pool_offset_;

  ulong dlist_offsets_[4096]; /* TODO:FIXME: magic number */

  ulong max_stake_accounts_;
};
typedef struct fd_stake_delegations_delta fd_stake_delegations_delta_t;

/* fd_stake_delegations_align returns the alignment of the stake
   delegations delta struct. */

ulong
fd_stake_delegations_delta_align( void );

/* fd_stake_delegations_footprint returns the footprint of the stake
   delegations delta struct for a given amount of max stake accounts,
   expected stake accounts, and max live slots. */

ulong
fd_stake_delegations_delta_footprint( ulong max_stake_accounts,
                                      ulong expected_stake_accounts,
                                      ulong max_live_slots );

/* fd_stake_delegations_new creates a new stake delegations delta struct
   with a given amount of max stake accounts.  It formats a memory
   region which is sized based off of the number of stake accounts and
   max live slots the structure will support. */

void *
fd_stake_delegations_delta_new( void * mem,
                                ulong  max_stake_accounts,
                                ulong  expected_stake_accounts,
                                ulong  max_live_slots,
                                ulong  seed );

/* fd_stake_delegations_join joins a stake delegations delta struct from
   a memory region.  There can be multiple valid joins for a given
   memory region but the caller is responsible for accessing memory in a
   thread-safe manner. */

fd_stake_delegations_delta_t *
fd_stake_delegations_delta_join( void * mem );

/* fd_stake_delegations_new_fork allocates a new fork index for the
   stake delegations delta.  The fork index is returned to the caller. */

ushort
fd_stake_delegations_delta_new_fork( fd_stake_delegations_delta_t * stake_delegations );

/* fd_stake_delegations_delta_update will either insert a new stake
   delegation for the fork.  If an entry already exists in the fork, a
   new one will be inserted without removing the old one.

   TODO: Add a per fork map so multiple entries aren't needed for the
   same stake account. */

void
fd_stake_delegations_delta_update( fd_stake_delegations_delta_t * stake_delegations,
                                   ushort                         fork_idx,
                                   fd_pubkey_t const *            stake_account,
                                   fd_pubkey_t const *            vote_account,
                                   ulong                          stake,
                                   ulong                          activation_epoch,
                                   ulong                          deactivation_epoch,
                                   ulong                          credits_observed,
                                   double                         warmup_cooldown_rate );

/* fd_stake_delegations_delta_remove inserts a tombstone stake
   delegation entry for the given fork.  The function will not actually
   remove or free any resources corresponding to the stake account.  The
   reason a tombstone is stored is because each fork corresponds to a
   set of stake delegation deltas for a given slot. */

void
fd_stake_delegations_delta_remove( fd_stake_delegations_delta_t * stake_delegations,
                                   ushort                         fork_idx,
                                   fd_pubkey_t const *            stake_account );

/* fd_stake_delegations_delta_evict_fork removes/frees all stake
   delegation entries for a given fork.  After this function is called
   it is no longer safe to have any references to the fork index (until
   it is reused via a call to fd_stake_delegations_delta_new_fork).  The
   caller is responsible for making sure references to this fork index
   are not being held. */

void
fd_stake_delegations_delta_evict_fork( fd_stake_delegations_delta_t * stake_delegations,
                                       ushort                         fork_idx );

/* fd_stake_delegations_delta_iter_{init,done,next,ele} are used to
   iterate over the stake delegation deltas for a given fork.  It is not
   safe to interleave any other iteration or modification of the stake
   delegations delta while iterating.

   Under the hood, the iterator is just a wrapper over the iterator
   described in fd_dlist.c. */

ulong
fd_stake_delegations_delta_iter_init( fd_stake_delegations_delta_t * stake_delegations,
                                      ushort                         fork_idx );

int
fd_stake_delegations_delta_iter_done( fd_stake_delegations_delta_t * stake_delegations,
                                      ushort                         fork_idx,
                                      ulong                          iter );

ulong
fd_stake_delegations_delta_iter_next( fd_stake_delegations_delta_t * stake_delegations,
                                      ushort                         fork_idx,
                                      ulong                          iter );

fd_stake_delegation_t *
fd_stake_delegations_delta_iter_ele( fd_stake_delegations_delta_t * stake_delegations,
                                     ushort                        fork_idx,
                                     ulong                         iter );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h */
