#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h

#include "../runtime/sysvar/fd_sysvar_base.h"
#include "../accdb/fd_accdb.h"
#include "../fd_rwlock.h"

#define FD_STAKE_DELEGATIONS_MAGIC (0xF17EDA2CE757A3E1) /* FIREDANCER STAKE V1 */

/* fd_stake_delegations_t is a cache of stake accounts mapping the
   pubkey of the stake account to various information including
   stake, activation/deactivation epoch, corresponding vote_account,
   credits observed, and warmup cooldown rate. This is used to quickly
   iterate through all of the stake delegations in the system during
   epoch boundary reward calculations.

   The implementation of fd_stake_delegations_t is split into two:
   1. The entire set of stake delegations are stored in the in-memory
      root map/pool and, when needed, the disk root store.  This root
      state is setup at boot (on snapshot load) and is not directly
      modified after that point.
   2. As banks/forks execute, they will maintain a delta-based
      representation of the stake delegations.  Each fork will hold its
      own set of deltas.  These are then applied to the root set when
      the fork is finalized.  This is implemented as each bank having
      its own map of deltas which are allocated from a pool shared
      across all stake delegation forks.  The caller is expected to
      create a new fork index for each bank and add deltas to it.

   Root and delta entries that exceed their respective in-memory pools
   spill to disk as full fd_stake_delegation_t records.  Root records
   are keyed by stake pubkey.  Delta records are keyed by fork index
   and stake pubkey, so sibling forks retain independent versions.

   There are some important invariants wrt fd_stake_delegations_t:
   1. After execution has started, there will be no invalid stake
      accounts in the stake delegations struct.
   2. The stake delegations struct can have valid delegations for vote
      accounts which no longer exist.
   3. There are no stake accounts which are valid delegations which
      exist in the accounts database but not in fd_stake_delegations_t.

   In practice, fd_stake_delegations_t are updated in 3 cases:
   1. During snapshot boot, snapin populates the root cache directly
      from the account stream.  The cache is refreshed after all
      accounts are loaded to resolve duplicate account versions, remove
      stale entries, and calculate activation state.

      https://github.com/anza-xyz/agave/blob/v2.3.6/runtime/src/bank.rs#L1780-L1806

   2. After transaction execution. If an update is made to a stake
      account, the updated state is reflected in the cache (or the entry
      is evicted).
   3. During rewards distribution. Stake accounts are partitioned over
      several hundred slots where their rewards are distributed. In this
      case, the cache is updated to reflect each stake account post
      reward distribution.
   The stake accounts are read-only during the epoch boundary.

   The concurrency model is: every mutating operation takes the struct's
   write lock for its whole duration, so mutators are safe to call
   concurrently from any tile.  fd_stake_delegations_{mark,unmark}_delta
   and the iterator are the exception: the caller holds the write lock
   across the whole mark/iterate/unmark bracket.

   max_disk_records bounds the number of delta records that can spill
   to disk.  The disk root capacity is max_stake_accounts plus twice
   max_disk_records. */

#define FD_STAKE_DELEGATIONS_ALIGN              (128UL)
#define FD_STAKE_DELEGATIONS_FORK_MAX           (4096UL)
#define FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT (8192UL)

/* 123458/123459 are store, 123460/123461 are accdb, and 123462+ are
   reserved by XDP. */

#define FD_STAKE_DELEGATIONS_FD (123457)

/* delta_idx uses the high bit to distinguish a dense disk-delta index
   from an in-memory delta-pool index. */

#define FD_STAKE_DELEGATIONS_DELTA_DISK_TAG (1U<<31)
#define FD_STAKE_DELEGATIONS_DELTA_IDX_MASK (FD_STAKE_DELEGATIONS_DELTA_DISK_TAG-1U)

/* The warmup cooldown rate can only be one of two values: 0.25 or 0.09.
   The reason that the double is mapped to an enum is to save space in
   the stake delegations struct. */
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 (0)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 (1)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025      (0.25)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009      (0.09)

/* fd_stake_warmup_cooldown_rate gives the warmup/cooldown rate enum
   for a given epoch.  In Agave, the per-delegation warmup_cooldown_rate
   field was deprecated (since v1.16.7) and unused in calculations.
   The rate is always determined by the epoch. */

static inline uchar
fd_stake_warmup_cooldown_rate( ulong current_epoch, ulong * new_rate_activation_epoch ) {
  ulong activation_epoch = new_rate_activation_epoch ? *new_rate_activation_epoch : ULONG_MAX;
  return current_epoch<activation_epoch
    ? (uchar)FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025
    : (uchar)FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009;
}

/* Most stake delegations are stable.  So intuitively, there should be a
   way to return their effective stake in O(1).  Essentially, at a given
   target_epoch, if we know that the delegation is in a stable state for
   the purposes of effective stake evaluation, then we can simply return
   the fully activated stake for WARMED, or 0 for COOLED, without
   running any warmup/cooldown simulation.  The vast majority of
   delegations are in fact stable and can take the fast path for
   effective stake evaluation.

   We trust a tag's prescription of stable state (WARMED/COOLED) if

   - The delegation record (stake,activation_epoch,deactivation_epoch)
     hasn't changed since the delegation was most recently evaluated and
     tagged at tag_epoch
   - tag_epoch<=target_epoch

   Condition #1 is maintained by how delegations are tagged.  Only root
   records can take on non-UNKNOWN tags.  Delta records are
   unconditionally UNKNOWN.  All delegation-updating operations funnel
   the delegation through a delta, so the delegation effectively gets
   invalidated for stable state query purposes.

   Condition #2 ultimately has to be maintained by the user of the tag
   who provides target_epoch.  A key invariant here is that stable state
   tags are awarded when the delta list gets folded into the root state,
   aka when a block roots.  Currently, the only use cases of the tag are
   at the boundary.

   - For the refresh_vote_accounts() use case, the target_epoch is the
     upcoming epoch, which is naturally the largest epoch in the
     cluster.  Since tag_epoch was sometime in the past when a block
     rooted, tag_epoch<=target_epoch holds trivially.
   - For the points calculation use case, recall that rewarded_epoch is
     the just-ended epoch.  Since we are at the boundary of
     rewarded_epoch=>rewarded_epoch+1, we know that
     tag_epoch<=rewarded_epoch, because no slot has rooted for
     rewarded_epoch+1 yet.  So if we constrain the target_epoch to be
     exactly rewarded_epoch, we get tag_epoch<=target_epoch.  It doesn't
     hurt that most delegations are up to date on rewards payout, and
     the only epoch for which they have eligible points is precisely the
     rewarded_epoch.
   - We disable the tag fast path for recalculation during boot, because
     tags are computed fresh at the snapshot root, and so
     rewarded_epoch<tag_epoch.

   WARMED and COOLED are stable states and are the only tags that the
   fast paths act on.  The unstable state tags (WARMING/COOLING) are
   defined for clarity and do not enable any fast path.  As a side note,
   WARMING tags get a chance to be promoted to WARMED if the delegation
   gets any inflation rewards or is otherwise written.  At rewards
   distribution time, the delegation will re-enter a delta tier and
   shortly afterwards get a chance to be re-classified when the
   distribution block roots.  Fresh dust delegations that don't get any
   rewards will be sticky WARMING until the next boot or a write. */
#define FD_STAKE_DELEGATION_STATE_UNKNOWN ((uchar)0)
#define FD_STAKE_DELEGATION_STATE_WARMING ((uchar)1) /* activating */
#define FD_STAKE_DELEGATION_STATE_WARMED  ((uchar)2) /* effective=delegated */
#define FD_STAKE_DELEGATION_STATE_COOLING ((uchar)3) /* deactivating */
#define FD_STAKE_DELEGATION_STATE_COOLED  ((uchar)4) /* effective=0 */

struct fd_stake_delegation {
  fd_pubkey_t stake_account;
  fd_pubkey_t vote_account;
  ulong       stake;
  ulong       lamports;
  ulong       credits_observed;
  uint        acc_dlen;
  uint        next_;     /* Internal pool/map usage */
  uint        delta_idx; /* in-memory/disk delta reference for iteration */
  ushort      activation_epoch;
  ushort      deactivation_epoch;
  union {
    /* No storage conflict because one is for delta records and the
       other for root records. */
    uchar     is_tombstone; /* Internal delta usage */
    uchar     dne_in_root;  /* Tracking for stake delegation iteration */
  };
  uchar       warmup_cooldown_rate; /* enum representing 0.25 or 0.09 */
  uchar       in_use; /* For the in-memory root pool only.  Not meaningful in the
                         delta pool.  Set to 1 if this element holds a live delegation
                         present in the root map, 0 if the element has been reclaimed. */
  uchar       state;  /* Can only be non-UNKNOWN in a root record. */
};
typedef struct fd_stake_delegation fd_stake_delegation_t;

FD_STATIC_ASSERT( sizeof(fd_stake_delegation_t)==112UL, fd_stake_delegation );

struct fd_stake_delegations {
  ulong magic;
  ulong seed_;
  ulong max_stake_accounts_;

  /* Root map + pool */
  ulong map_offset_;
  ulong pool_offset_;
  ulong pool_idx_wmk_; /* One past the highest root pool index ever acquired.  Every index in
                          [0, wmk) has been acquired at least once, so its in_use byte is
                          well defined. */

  /* Delta pool + fork and fork map  */
  ulong delta_pool_offset_;
  ulong fork_pool_offset_;
  ulong fork_map_offset_;

  /* Guards every mutating operation on the struct. */
  fd_rwlock_t lock;

  /* Management for stake delegations that spill to disk. */
  ulong max_disk_records_;        /* disk delta capacity; disk root capacity is derived */
  ulong disk_root_cnt_;           /* number of disk-backed root records */
  ulong disk_delta_cnt_;
  ulong disk_bucket_cnt_;         /* pow2 buckets in each disk hash index */
  ulong disk_root_tombstone_cnt_;
  ulong disk_delta_tombstone_cnt_;
  uint  disk_root_gen_;           /* buckets with an older generation are empty */
  uint  disk_delta_gen_;

  /* Stake totals for the current root. */
  ulong effective_stake;
  ulong activating_stake;
  ulong deactivating_stake;

  /* Epoch used to query the active frontier. */
  ulong frontier_query_epoch;

  /* Only relevant around upgrade_bpf_stake_program_to_v5_1 activation.
     See comment at consumer of this flag for why it's needed.  Remove
     after the feature activates on all clusters. */
  uchar fp_warmed_awarded;
};
typedef struct fd_stake_delegations fd_stake_delegations_t;

struct fd_stake_delegations_iter {
  fd_stake_delegation_t *        root_pool;
  fd_stake_delegation_t *        delta_pool;
  fd_stake_delegation_t *        ele;
  fd_stake_delegations_t const * stake_delegations;
  ulong                          idx;      /* externally visible index */
  ulong                          wmk;      /* in-memory root watermark */
  ulong                          disk_idx; /* dense disk-root cursor */
  fd_stake_delegation_t          disk_ele;
};
typedef struct fd_stake_delegations_iter fd_stake_delegations_iter_t;

#include "fd_stake_delegations_private.h"

FD_PROTOTYPES_BEGIN

static inline double
fd_stake_delegations_warmup_cooldown_rate_to_double( uchar warmup_cooldown_rate ) {
  return warmup_cooldown_rate==FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 ? FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025 : FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009;
}

/* Classify stake given the activation status evaluated at the provided
   epoch.  The provided epoch is expected to be >= activation epoch. */
static inline uchar
fd_stake_delegation_classify( fd_stake_delegation_t const * delegation,
                              fd_stake_history_entry_t      activation_status,
                              ulong                         epoch ) {
  /* Activation epoch in Agave's stake program is either clock.epoch, or
     inherited from an existing activation epoch, so activation epoch <=
     current epoch always holds for delegations created by the stake
     program.  Synthetic inputs do not conform to this, so we mark them
     UNKNOWN to force the slow path. */
  if( FD_UNLIKELY( delegation->activation_epoch!=(ushort)USHORT_MAX && epoch<delegation->activation_epoch ) ) {
    return FD_STAKE_DELEGATION_STATE_UNKNOWN;
  }

  if( activation_status.activating>0UL   ) return FD_STAKE_DELEGATION_STATE_WARMING;
  if( activation_status.deactivating>0UL ) return FD_STAKE_DELEGATION_STATE_COOLING;
  if( activation_status.effective==delegation->stake && delegation->deactivation_epoch==(ushort)USHORT_MAX ) return FD_STAKE_DELEGATION_STATE_WARMED;

  /* When evaluated at >= activation_epoch, (0,0,0) implies a fully
     cooled delegation.  One might think that we could simply

     if( activation_status.effective==0UL ) return FD_STAKE_DELEGATION_STATE_COOLED;

     and life would be great.  In an unfortunate turn, Agave has a
     special branch that will assume stake has been fully activated if
     the activation epoch is not found in the stake history sysvar,
     regardless of whether the delegation fully warmed up or not when
     the simulation ran faithfully from the activation epoch.

     https://github.com/solana-program/stake/blob/interface%40v4.3.1/interface/src/state.rs#L969

     This means that a COOLED tag doesn't necessarily survive against
     future stake history sysvars.  As the stake history sysvar window
     advances and evicts older epochs, a delegation's activation epoch
     will eventually be evicted.  At that point an effective stake
     simulation would cooldown from the full delegated amount, which
     might be more than the effective stake simulated at tag time, if
     the delegation only partially warmed up at deactivation epoch.
     This can in theory lead to a nonzero effective stake at the target
     epoch, once the activation epoch is evicted, contradicting the
     COOLED tag.  Note that this is exceedingly hard to pull off as it
     requires that (1) the delegation only partially warmed up at
     deactivation, and (2) the delegation failed to fully cooldown from
     the full delegated amount over the potentially hundreds of epochs
     between deactivation epoch and target epoch.  AKA either warmup or
     cooldown congestion in the cluster over an extended period of time.
     The upshot is that we will only award the COOLED tag when the
     delegation is always COOLED independent of the history sysvar.
     This safe verdict loses by a few millis at the boundary, mostly in
     the refresh_vote_accounts() phase, compared to the naive but unsafe
     classify.

     https://github.com/solana-program/stake/blob/interface%40v4.3.1/interface/src/state.rs#L877
     https://github.com/solana-program/stake/blob/interface%40v4.3.1/interface/src/state.rs#L896

     Note that the same misfortune doesn't apply to the WARMED tag.  The
     sysvar query miss's "assume fully effective" bias means that a
     WARMED delegation stays warmed forever until it's instructed to
     deactivate. */
  if( epoch>(delegation->deactivation_epoch+FD_SYSVAR_STAKE_HISTORY_CAP) || delegation->activation_epoch==delegation->deactivation_epoch || delegation->stake==0UL ) return FD_STAKE_DELEGATION_STATE_COOLED;
  return FD_STAKE_DELEGATION_STATE_UNKNOWN;
}


/* fd_stake_delegations_align returns the alignment of the stake
   delegations struct. */

ulong
fd_stake_delegations_align( void );

/* fd_stake_delegations_footprint returns the footprint of the stake
   delegations struct for the given in-memory pool capacity and max live
   slots. */

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts,
                                ulong max_live_slots );

/* fd_stake_delegations_new creates a new stake delegations struct with
   the given in-memory pool capacity, disk spill capacity, and max live
   slots.  It formats a memory region sized from the pool capacity and
   per-fork delta structures. */

void *
fd_stake_delegations_new( void * mem,
                          ulong  seed,
                          ulong  max_stake_accounts,
                          ulong  max_disk_records,
                          ulong  max_live_slots );

/* fd_stake_delegations_join joins a stake delegations struct from a
   memory region. There can be multiple valid joins for a given memory
   region but the caller is responsible for accessing memory in a
   thread-safe manner. */

fd_stake_delegations_t *
fd_stake_delegations_join( void * mem );

/* fd_stake_delegations_reset resets delegations to the post-new state. */

void
fd_stake_delegations_reset( fd_stake_delegations_t * stake_delegations );

/* fd_stake_delegations_root_update will either insert a new stake
   delegation if the pubkey doesn't exist yet, or it will update the
   stake delegation for the pubkey if already in the in-memory or disk
   root, overriding any previous data. fd_stake_delegations_t must be a
   valid local join. */

void
fd_stake_delegations_root_update( fd_stake_delegations_t * stake_delegations,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate );

/* fd_stake_delegations_prune_inactive_root removes root delegations
   that are inactive in both epoch and epoch-1.  This function removes
   all inactive delegations from the in-memory and disk roots.  It is a
   parallel to Agave removing inactive stake accounts directly at the
   epoch boundary.  Returns the number of delegations removed.  When
   emit_bank is non-NULL, a runtime_stake_delegation remove event is
   emitted for each removal (NULL to skip). */

ulong
fd_stake_delegations_prune_inactive_root( fd_stake_delegations_t *   stake_delegations,
                                          ulong                      epoch,
                                          fd_stake_history_t const * stake_history,
                                          ulong *                    warmup_cooldown_rate_epoch,
                                          int                        use_fixed_point_stake_math,
                                          fd_bank_t const *          emit_bank );

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
                              int                        use_fixed_point_stake_math,
                              int                        remove_inactive_stakes,
                              fd_accdb_t *               accdb,
                              fd_accdb_fork_id_t         fork_id );

/* fd_stake_delegations_new_fork allocates a new fork index for the
   stake delegations.  The fork index is returned to the caller. */

ushort
fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations );

/* fd_stake_delegations_fork_update upserts a stake delegation delta for
   the fork.  If an entry already exists for the stake account in this
   fork, it is overwritten in place. */

void
fd_stake_delegations_fork_update( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate );

/* fd_stake_delegations_fork_remove inserts a tombstone stake delegation
   entry for the given fork.  The function will not actually remove or
   free any resources corresponding to the stake account.  The reason a
   tombstone is stored is because each fork corresponds to a set of
   stake delegation deltas for a given slot.  If an entry already exists
   for the stake account in this fork, it is overwritten in place. */

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

/* upserts and removes accumulate across applications.  root_cnt is
   overwritten with the current in-memory and disk root count. */

struct fd_stake_delegations_delta_stats {
  ulong upserts;
  ulong removes;
  ulong root_cnt;
};
typedef struct fd_stake_delegations_delta_stats fd_stake_delegations_delta_stats_t;

/* fd_stake_delegations_apply_fork_deltas applies an ordered fork
   ancestry atomically.  If stake_delegations_delta_stats is non-NULL,
   the number of upserts and removes applied is accumulated into it
   (caller zeroes). */

void
fd_stake_delegations_apply_fork_deltas( ulong                                epoch,
                                        fd_stake_history_t const *           stake_history,
                                        ulong *                              warmup_cooldown_rate_epoch,
                                        int                                  use_fixed_point_stake_math,
                                        fd_stake_delegations_t *             stake_delegations,
                                        ushort const *                       fork_ids,
                                        ulong                                fork_id_cnt,
                                        fd_stake_delegations_delta_stats_t * stake_delegations_delta_stats );

/* fd_stake_delegations_frontier_query_{begin,end} temporarily overlay
   delta elements from the provided forks onto the base/root stake
   delegation stores.  This allows the caller to iterate over the
   delegations for a bank using the root and its deltas without creating
   a copy.

   Under the hood, each in-memory or disk root record points to the
   corresponding in-memory or disk delta.  If an element is inserted by a
   delta, a temporary root record is added and then removed by
   frontier_query_end.  These functions also temporarily update and
   unwind the stake totals for the current root.

   begin takes the stake delegations write lock, records epoch, and
   overlays each fork delta in the provided order.  The caller must pair
   it with end, which uses the recorded epoch to unwind the same fork
   IDs in the same order and releases the lock. */

void
fd_stake_delegations_frontier_query_begin( fd_stake_delegations_t *   stake_delegations,
                                           ulong                      epoch,
                                           fd_stake_history_t const * stake_history,
                                           ulong *                    warmup_cooldown_rate_epoch,
                                           int                        use_fixed_point_stake_math,
                                           ushort const *             fork_ids,
                                           ulong                      fork_id_cnt );

void
fd_stake_delegations_frontier_query_end( fd_stake_delegations_t *   stake_delegations,
                                         fd_stake_history_t const * stake_history,
                                         ulong *                    warmup_cooldown_rate_epoch,
                                         int                        use_fixed_point_stake_math,
                                         ushort const *             fork_ids,
                                         ulong                      fork_id_cnt );

/* Iterator API for stake delegations.  The iterator is initialized with
   a call to fd_stake_delegations_iter_init.  The caller is responsible
   for managing the memory for the iterator.  It is safe to call
   fd_stake_delegations_iter_next if the result of
   fd_stake_delegations_iter_done()==0.  It is safe to call
   fd_stake_delegations_iter_ele() to get the current stake delegation
   or fd_stake_delegations_iter_idx() to get the index of the current
   stake delegation.  It is not safe to modify the stake delegation
   while iterating through it.

   Under the hood, the iterator walks in-memory roots followed by dense
   disk roots, redirecting through tagged in-memory/disk delta references
   for entries a marked fork has changed.  Disk records are returned
   through iterator-owned storage, so that pointer remains valid only
   until the next call to fd_stake_delegations_iter_next.

   Example use:

   fd_stake_delegations_iter_t iter_[1];
   for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
        !fd_stake_delegations_iter_done( iter );
        fd_stake_delegations_iter_next( iter ) ) {
     fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );
   }
*/

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations );

static inline fd_stake_delegation_t const *
fd_stake_delegations_iter_ele( fd_stake_delegations_iter_t const * iter ) {
  return iter->ele;
}

static inline ulong
fd_stake_delegations_iter_idx( fd_stake_delegations_iter_t * iter ) {
  return iter->idx;
}

static inline void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter ) {
  if( FD_LIKELY( iter->idx<iter->stake_delegations->max_stake_accounts_ ) ) {
    iter->idx++;
    fd_stake_delegations_iter_advance_private( iter );
  } else {
    iter->disk_idx++;
    fd_stake_delegations_iter_advance_disk_root_private( iter );
  }
}

static inline int
fd_stake_delegations_iter_done( fd_stake_delegations_iter_t * iter ) {
  return !iter->ele;
}

/* Invalidates every WARMED tag in the in-memory and disk roots.  Only
   useful at boundaries where upgrade_bpf_stake_program_to_v5_1 is
   active but a WARMED tag may have been awarded under the old floating
   point math, aka fp_warmed_awarded is set.  Forces fully warmed
   delegations to reevaluate their effective stake, in case there's a
   difference between the old floating point math and the new integer
   math.  Also clears fp_warmed_awarded, since no WARMED tag survives
   the wipe.

   Unlike the other mutators, this one does not take the write lock
   itself: its only callers run inside the boundary's
   mark/iterate/unmark bracket, which already holds it. */

void
fd_stake_delegations_invalidate_warmed( fd_stake_delegations_t * stake_delegations );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h */
