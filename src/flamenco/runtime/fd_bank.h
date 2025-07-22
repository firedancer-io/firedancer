#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_h

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../features/fd_features.h"
#include "../rewards/fd_epoch_rewards.h"
#include "../fd_rwlock.h"
#include "fd_runtime_const.h"
#include "fd_blockhashes.h"

FD_PROTOTYPES_BEGIN

#define FD_BANKS_MAGIC 0X99999AA9999UL

/* TODO: Some optimizations, cleanups, future work:
   1. Simple data types (ulong, int, etc) should be stored as their
      underlying type instead of a byte array.
   2. For some of the more complex types in the bank, we should provide
      a way to layout the data ahead of time instead of manually.
      calculating the offsets/layout of the offset-based struct.
      This should be done as types are split out from fd_types.h
   3. Perhaps make the query/modify scoping more explicit. Right now,
      the caller is free to use the API wrong if there are no locks.
      Maybe just expose a different API if there are no locks?
   4. Rename fd_banks_t to fd_bank_mgr_t.
   6. Rename locks to suffix with _query_locking and _query_locking_end
  */

/* A fd_bank_t struct is the represenation of the bank state on Solana
   for a given slot. More specifically, the bank state corresponds to
   all information needed during execution that is not stored on-chain,
   but is instead cached in a validator's memory. Each of these bank
   fields are repesented by a member of the fd_bank_t struct.

   Management of fd_bank_t structs must be fork-aware: the state of each
   fd_bank_t must be based on the fd_bank_t of it's parent slot. This
   state is managed by the fd_banks_t struct.

   In order to support fork-awareness, there are a few key features
   that fd_banks_t and fd_bank_t MUST support:
   1. Query for any non-rooted slot's bank: create a fast lookup
      from slot to bank
   2. Be able to create a new bank for a given slot from the bank of
      that slot's parent and maintain some tree-like structure to
      track the parent-child relationships: copy the contents from a
      parent bank into a child bank.
   3. Prune the set of active banks to keep the root updated as the
      network progresses: free resources of fd_bank_t structs that
      are are not direct descendants of the root bank (remove parents
      and any competing lineages).
   4. Each bank will have field(s) that are concurrently read/write
      from multiple threads: add read-write locks to the fields that are
      concurrently written to.
   5. In practice, a bank state for a given slot can be very large and
      not all of the fields are written to every slot. Therefore, it can
      be very expensive to copy the entire bank state for a given slot
      each time a bank is created. In order to avoid large memcpys, we
      can use a CoW mechanism for certain fields.

  Each field of a fd_bank_t has a pre-specified set of fields including
    - name: the name of the field
    - footprint: the size of the field in bytes
    - align: the alignment of the field
    - CoW: whether the field is CoW
    - has_lock: whether the field has a rw-lock
    - type: type of the field

  fd_banks_t is represented by a left-child, right-sibling n-ary tree
  (as inspired by fd_ghost) to keep track of the parent-child fork tree.
  The underlying data structure is a map of fd_bank_t structs that is
  keyed by slot. This map is backed by a simple memory pool.

  Each field in fd_bank_t that is not CoW is laid out contiguously in
  the fd_bank_t struct as simple uchar buffers. This allows for a simple
  memcpy to clone the bank state from a parent to a child.

  Each field that is CoW has its own memory pool. The memory
  corresponding to the field is not located in the fd_bank_t struct and
  is instead represented by a pool index and a dirty flag. If the field
  is modified, then the dirty flag is set, and an element of the pool
  is acquired and the data is copied over from the parent pool idx.

  fd_bank_t also holds all of the rw-locks for the fields that have
  rw-locks.

  So, when a bank is cloned from a parent, the non CoW fields are copied
  over and the CoW fields just copy over a pool index. The CoW behavior
  is completely abstracted away from the caller as callers have to
  query/modify fields using specific APIs.

  NOTE: An important invariant is that if a field is CoW, then it must
  have a rw-lock.

  The usage pattern is as follows:

   To create an initial bank:
   fd_bank_t * bank_init = fd_bank_init_bank( banks, slot );

   To clone bank from parent banks:
   fd_bank_t * bank_clone = fd_banks_clone_from_parent( banks, slot, parent_slot );

   To publish a bank (aka update the root bank):
   fd_bank_t * bank_publish = fd_banks_publish( banks, slot );

   To query some arbitrary bank:
   fd_bank_t * bank_query = fd_banks_get_bank( banks, slot );

  To access fields in the bank if a field does not have a lock:

  fd_struct_t const * field = fd_bank_field_query( bank );
  OR
  fd_struct field = fd_bank_field_get( bank );

  To modify fields in the bank if a field does not have a lock:

  fd_struct_t * field = fd_bank_field_modify( bank );
  OR
  fd_bank_field_set( bank, value );

  IMPORTANT SAFETY NOTE: fd_banks_t assumes that there is only one bank
  being executed against at a time. However, it is safe to call
  fd_banks_publish while threads are executing against a bank.

  */

/* Define additional fields to the bank struct here. If trying to add
   a CoW field to the bank, define a pool for it as done below. */

#define FD_BANKS_ITER(X)                                                                                                                                                                                                             \
  /* type,                             name,                        footprint,                                 align,                                      CoW, has lock */                                                          \
  X(fd_clock_timestamp_votes_global_t, clock_timestamp_votes,       5000000UL,                                 128UL,                                      1,   1    )  /* TODO: This needs to get sized out */                      \
  X(fd_account_keys_global_t,          stake_account_keys,          100000000UL,                               128UL,                                      1,   1    )  /* Supports roughly 3M stake accounts */                     \
  X(fd_account_keys_global_t,          vote_account_keys,           3200000UL,                                 128UL,                                      1,   1    )  /* Supports roughly 100k vote accounts */                    \
  X(fd_blockhashes_t,                  block_hash_queue,            sizeof(fd_blockhashes_t),                  alignof(fd_blockhashes_t),                  0,   0    )  /* Block hash queue */                                       \
  X(fd_fee_rate_governor_t,            fee_rate_governor,           sizeof(fd_fee_rate_governor_t),            alignof(fd_fee_rate_governor_t),            0,   0    )  /* Fee rate governor */                                      \
  X(ulong,                             capitalization,              sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Capitalization */                                         \
  X(ulong,                             lamports_per_signature,      sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Lamports per signature */                                 \
  X(ulong,                             prev_lamports_per_signature, sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Previous lamports per signature */                        \
  X(ulong,                             transaction_count,           sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Transaction count */                                      \
  X(ulong,                             parent_signature_cnt,        sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Parent signature count */                                 \
  X(ulong,                             tick_height,                 sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Tick height */                                            \
  X(ulong,                             max_tick_height,             sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Max tick height */                                        \
  X(ulong,                             hashes_per_tick,             sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Hashes per tick */                                        \
  X(uint128,                           ns_per_slot,                 sizeof(uint128),                           alignof(uint128),                           0,   0    )  /* NS per slot */                                            \
  X(ulong,                             ticks_per_slot,              sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Ticks per slot */                                         \
  X(ulong,                             genesis_creation_time,       sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Genesis creation time */                                  \
  X(double,                            slots_per_year,              sizeof(double),                            alignof(double),                            0,   0    )  /* Slots per year */                                         \
  X(fd_inflation_t,                    inflation,                   sizeof(fd_inflation_t),                    alignof(fd_inflation_t),                    0,   0    )  /* Inflation */                                              \
  X(ulong,                             total_epoch_stake,           sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Total epoch stake */                                      \
                                                                                                                                                                        /* This is only used for the get_epoch_stake syscall. */     \
                                                                                                                                                                        /* If we are executing in epoch E, this is the total */      \
                                                                                                                                                                        /* stake at the end of epoch E-1. */                         \
  X(ulong,                             eah_start_slot,              sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* EAH start slot */                                         \
  X(ulong,                             eah_stop_slot,               sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* EAH stop slot */                                          \
  X(ulong,                             eah_interval,                sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* EAH interval */                                           \
  X(ulong,                             block_height,                sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Block height */                                           \
  X(fd_hash_t,                         epoch_account_hash,          sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* Epoch account hash */                                     \
  X(ulong,                             execution_fees,              sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Execution fees */                                         \
  X(ulong,                             priority_fees,               sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Priority fees */                                          \
  X(ulong,                             signature_count,             sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Signature count */                                        \
  X(ulong,                             use_prev_epoch_stake,        sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Use prev epoch stake */                                   \
  X(fd_hash_t,                         poh,                         sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* PoH */                                                    \
  X(fd_sol_sysvar_last_restart_slot_t, last_restart_slot,           sizeof(fd_sol_sysvar_last_restart_slot_t), alignof(fd_sol_sysvar_last_restart_slot_t), 0,   0    )  /* Last restart slot */                                      \
  X(fd_cluster_version_t,              cluster_version,             sizeof(fd_cluster_version_t),              alignof(fd_cluster_version_t),              0,   0    )  /* Cluster version */                                        \
  X(ulong,                             parent_slot,                 sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Previous slot */                                          \
  X(fd_hash_t,                         bank_hash,                   sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* Bank hash */                                              \
  X(fd_hash_t,                         prev_bank_hash,              sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* Previous bank hash */                                     \
  X(fd_hash_t,                         genesis_hash,                sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* Genesis hash */                                           \
  X(fd_epoch_schedule_t,               epoch_schedule,              sizeof(fd_epoch_schedule_t),               alignof(fd_epoch_schedule_t),               0,   0    )  /* Epoch schedule */                                         \
  X(fd_rent_t,                         rent,                        sizeof(fd_rent_t),                         alignof(fd_rent_t),                         0,   0    )  /* Rent */                                                   \
  X(fd_slot_lthash_t,                  lthash,                      sizeof(fd_slot_lthash_t),                  alignof(fd_slot_lthash_t),                  0,   0    )  /* LTHash */                                                 \
  X(fd_vote_accounts_global_t,         next_epoch_stakes,           200000000UL,                               128UL,                                      1,   1    )  /* Next epoch stakes, ~4K per account * 50k vote accounts */ \
                                                                                                                                                                        /* These are the stakes that determine the leader */         \
                                                                                                                                                                        /* schedule for the upcoming epoch.  If we are executing */  \
                                                                                                                                                                        /* in epoch E, these are the stakes at the end of epoch */   \
                                                                                                                                                                        /* E-1 and they determined the leader schedule for epoch */  \
                                                                                                                                                                        /* E+1. */                                                   \
  X(fd_vote_accounts_global_t,         epoch_stakes,                200000000UL,                               128UL,                                      1,   1    )  /* Epoch stakes ~4K per account * 50k vote accounts */       \
  X(fd_epoch_rewards_t,                epoch_rewards,               FD_EPOCH_REWARDS_FOOTPRINT,                FD_EPOCH_REWARDS_ALIGN,                     1,   1    )  /* Epoch rewards */                                          \
  X(fd_epoch_leaders_t,                epoch_leaders,               FD_RUNTIME_MAX_EPOCH_LEADERS,              FD_EPOCH_LEADERS_ALIGN,                     1,   1    )  /* Epoch leaders. If our system supports 100k vote accs, */  \
                                                                                                                                                                        /* then there can be 100k unique leaders in the worst */     \
                                                                                                                                                                        /* case. We also can assume 432k slots per epoch. */         \
  X(fd_stakes_global_t,                stakes,                      400000000UL,                               128UL,                                      1,   1    )  /* Stakes */                                                 \
  X(fd_features_t,                     features,                    sizeof(fd_features_t),                     alignof(fd_features_t),                     0,   0    )  /* Features */                                               \
  X(ulong,                             txn_count,                   sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Transaction count */                                      \
  X(ulong,                             nonvote_txn_count,           sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Nonvote transaction count */                              \
  X(ulong,                             failed_txn_count,            sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Failed transaction count */                               \
  X(ulong,                             nonvote_failed_txn_count,    sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Nonvote failed transaction count */                       \
  X(ulong,                             total_compute_units_used,    sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Total compute units used */                               \
  X(ulong,                             part_width,                  sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Part width */                                             \
  X(ulong,                             slots_per_epoch,             sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Slots per epoch */                                        \
  X(ulong,                             shred_cnt,                   sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Shred count */                                            \
  X(int,                               enable_exec_recording,       sizeof(int),                               alignof(int),                               0,   0    )  /* Enable exec recording */

/* Invariant Every CoW field must have a rw-lock */
#define X(type, name, footprint, align, cow, has_lock) \
  FD_STATIC_ASSERT( (cow == 1 && has_lock == 1) || (cow == 0), CoW fields must have a rw-lock );
  FD_BANKS_ITER(X)
#undef X

/* If a member of the bank is CoW then it needs a corresponding pool
   which is defined here. If a type if not a CoW then it does not need
   to be in a pool and is laid out contigiously in the bank struct. */

/* Declare a pool object wrapper for all CoW fields. */
#define HAS_COW_1(name, footprint, align)                    \
  static const ulong fd_bank_##name##_align     = align;     \
  static const ulong fd_bank_##name##_footprint = footprint; \
                                                             \
  struct fd_bank_##name {                                    \
    ulong next;                                              \
    uchar data[footprint]__attribute__((aligned(align)));    \
  };                                                         \
  typedef struct fd_bank_##name fd_bank_##name##_t;

/* Do nothing if CoW is not enabled. */
#define HAS_COW_0(name, footprint, align)

#define X(type, name, footprint, align, cow, has_lock) \
  HAS_COW_##cow(name, footprint, align)
  FD_BANKS_ITER(X)

#undef X
#undef HAS_COW_0
#undef HAS_COW_1

#define POOL_NAME fd_bank_clock_timestamp_votes_pool
#define POOL_T    fd_bank_clock_timestamp_votes_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define POOL_NAME fd_bank_stake_account_keys_pool
#define POOL_T    fd_bank_stake_account_keys_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define POOL_NAME fd_bank_vote_account_keys_pool
#define POOL_T    fd_bank_vote_account_keys_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define POOL_NAME fd_bank_next_epoch_stakes_pool
#define POOL_T    fd_bank_next_epoch_stakes_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define POOL_NAME fd_bank_epoch_stakes_pool
#define POOL_T    fd_bank_epoch_stakes_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define POOL_NAME fd_bank_epoch_leaders_pool
#define POOL_T    fd_bank_epoch_leaders_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define POOL_NAME fd_bank_stakes_pool
#define POOL_T    fd_bank_stakes_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define POOL_NAME fd_bank_epoch_rewards_pool
#define POOL_T    fd_bank_epoch_rewards_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

/* As mentioned above, the overall layout of the bank struct:
   - Fields used for internal pool/bank management
   - Non-Cow fields
   - CoW fields
   - Locks for CoW fields

   The CoW fields are laid out contiguously in the bank struct.
   The locks for the CoW fields are laid out contiguously after the
   CoW fields.
*/

struct fd_bank {
  #define FD_BANK_HEADER_SIZE (40UL)

  /* Fields used for internal pool and bank management */
  ulong             slot_;       /* slot this node is tracking, also the map key */
  ulong             next;        /* reserved for internal use by fd_pool_para, fd_map_chain_para and fd_banks_publish */
  ulong             parent_idx;  /* index of the parent in the node pool */
  ulong             child_idx;   /* index of the left-child in the node pool */
  ulong             sibling_idx; /* index of the right-sibling in the node pool */

  /* First, layout all non-CoW fields contiguously. This is done to
     allow for cloning the bank state with a simple memcpy. Each
     non-CoW field is just represented as a byte array. */

  #define HAS_COW_1(type, name, footprint, align)

  #define HAS_COW_0(type, name, footprint, align) \
    uchar name[footprint] __attribute__((aligned(align)));

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  /* Now, layout all information needed for CoW fields. These are only
     copied when explicitly requested by the caller. The field's data
     is located at teh pool idx in the pool. If the dirty flag has been
     set, then the element has been copied over for this bank. */

  #define HAS_COW_1(type, name, footprint, align) \
    int                  name##_dirty;            \
    ulong                name##_pool_idx;         \
    ulong                name##_pool_offset;

  #define HAS_COW_0(type, name, footprint, align)

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  /* Now emit locks for all fields that need a rwlock. */

  #define HAS_LOCK_1(type, name, footprint, align) \
    fd_rwlock_t name##_lock;

  #define HAS_LOCK_0(type, name, footprint, align) /* Do nothing for these. */

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_LOCK_##has_lock(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

};
typedef struct fd_bank fd_bank_t;

#define HAS_COW_1(type, name, footprint, align)                                  \
static inline void                                                               \
fd_bank_set_##name##_pool( fd_bank_t * bank, fd_bank_##name##_t * bank_pool ) {  \
  void * bank_pool_mem = fd_bank_##name##_pool_leave( bank_pool );               \
  if( FD_UNLIKELY( !bank_pool_mem ) ) {                                          \
    FD_LOG_CRIT(( "Failed to leave bank pool" ));                                \
  }                                                                              \
  bank->name##_pool_offset = (ulong)bank_pool_mem - (ulong)bank;                 \
}                                                                                \
static inline fd_bank_##name##_t *                                               \
fd_bank_get_##name##_pool( fd_bank_t * bank ) {                                  \
  return fd_bank_##name##_pool_join( (uchar *)bank + bank->name##_pool_offset ); \
}
#define HAS_COW_0(type, name, footprint, align) /* Do nothing for these. */

#define X(type, name, footprint, align, cow, has_lock) \
  HAS_COW_##cow(type, name, footprint, align)
FD_BANKS_ITER(X)
#undef X
#undef HAS_COW_0
#undef HAS_COW_1

/* fd_bank_t is the alignment for the bank state. */

ulong
fd_bank_align( void );

/* fd_bank_t is the footprint for the bank state. This does NOT
   include the footprint for the CoW state. */

ulong
fd_bank_footprint( void );

/**********************************************************************/
/* fd_banks_t is the main struct used to manage the bank state. It can
   be used to query/modify/clone/publish the bank state.

   fd_banks_t contains some metadata a map/pool pair to manage the banks.
   It also contains pointers to the CoW pools.

   The data is laid out contigiously in memory starting from fd_banks_t;
   this can be seen in fd_banks_footprint(). */

#define POOL_NAME fd_banks_pool
#define POOL_T    fd_bank_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define MAP_NAME  fd_banks_map
#define MAP_ELE_T fd_bank_t
#define MAP_KEY   slot_
#include "../../util/tmpl/fd_map_chain.c"
#undef MAP_NAME
#undef MAP_ELE_T
#undef MAP_KEY

struct fd_banks {
  ulong             magic;       /* ==FD_BANKS_MAGIC */
  ulong             max_banks;   /* Maximum number of banks */
  ulong             root;        /* root slot */
  ulong             root_idx;    /* root idx */

  fd_rwlock_t       rwlock;      /* rwlock for fd_banks_t */

  ulong             pool_offset; /* offset of pool from banks */
  ulong             map_offset;  /* offset of map from banks */

  /* Layout all CoW pools. */

  #define HAS_COW_1(type, name, footprint, align) \
    ulong           name##_pool_offset; /* offset of pool from banks */

  #define HAS_COW_0(type, name, footprint, align) /* Do nothing for these. */

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
};
typedef struct fd_banks fd_banks_t;

/* Bank accesssors. Different accessors are emitted for different types
   depending on if the field has a lock or not. */

#define HAS_LOCK_1(type, name) \
  type const * fd_bank_##name##_locking_query( fd_bank_t * bank ); \
  void fd_bank_##name##_end_locking_query( fd_bank_t * bank );     \
  type * fd_bank_##name##_locking_modify( fd_bank_t * bank );      \
  void fd_bank_##name##_end_locking_modify( fd_bank_t * bank );

#define HAS_LOCK_0(type, name)                                   \
  type const * fd_bank_##name##_query( fd_bank_t const * bank ); \
  type * fd_bank_##name##_modify( fd_bank_t * bank );

#define X(type, name, footprint, align, cow, has_lock)             \
  void fd_bank_##name##_set( fd_bank_t * bank, type value );       \
  type fd_bank_##name##_get( fd_bank_t const * bank );             \
  HAS_LOCK_##has_lock(type, name)
FD_BANKS_ITER(X)
#undef X

#undef HAS_LOCK_0
#undef HAS_LOCK_1

static inline ulong
fd_bank_slot_get( fd_bank_t const * bank ) {
  return bank->slot_;
}

ulong
fd_bank_epoch_get( fd_bank_t const * bank );

/* Simple getters and setters for members of fd_banks_t.*/

static inline fd_bank_t *
fd_banks_get_bank_pool( fd_banks_t const * banks ) {
  return fd_banks_pool_join( ((uchar *)banks + banks->pool_offset) );
}

static inline fd_banks_map_t *
fd_banks_get_bank_map( fd_banks_t const * banks ) {
  return fd_banks_map_join( ((uchar *)banks + banks->map_offset) );
}

static inline void
fd_banks_set_bank_pool( fd_banks_t * banks, fd_bank_t * bank_pool ) {
  void * bank_pool_mem = fd_banks_pool_leave( bank_pool );
  if( FD_UNLIKELY( !bank_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave bank pool" ));
  }
  banks->pool_offset = (ulong)bank_pool_mem - (ulong)banks;
}

static inline void
fd_banks_set_bank_map( fd_banks_t * banks, fd_banks_map_t * bank_map ) {
  void * bank_map_mem = fd_banks_map_leave( bank_map );
  if( FD_UNLIKELY( !bank_map_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave bank map" ));
  }
  banks->map_offset = (ulong)bank_map_mem - (ulong)banks;
}

#define HAS_COW_1(type, name, footprint, align)                                    \
static inline fd_bank_##name##_t *                                                 \
fd_banks_get_##name##_pool( fd_banks_t * banks ) {                                 \
  return fd_bank_##name##_pool_join( (uchar *)banks + banks->name##_pool_offset ); \
}                                                                                  \
static inline void                                                                 \
fd_banks_set_##name##_pool( fd_banks_t * banks, fd_bank_##name##_t * bank_pool ) { \
  void * bank_pool_mem = fd_bank_##name##_pool_leave( bank_pool );                 \
  if( FD_UNLIKELY( !bank_pool_mem ) ) {                                            \
    FD_LOG_CRIT(( "Failed to leave bank pool" ));                                  \
  }                                                                                \
  banks->name##_pool_offset = (ulong)bank_pool_mem - (ulong)banks;                 \
}

#define HAS_COW_0(type, name, footprint, align) /* Do nothing for these. */

#define X(type, name, footprint, align, cow, has_lock) \
  HAS_COW_##cow(type, name, footprint, align)
FD_BANKS_ITER(X)
#undef X
#undef HAS_COW_0
#undef HAS_COW_1

/* fd_banks_lock() and fd_banks_unlock() are locks to be acquired and
   freed around accessing or modifying a specific bank. This is only
   required if there is concurrent access to a bank while operations on
   its underlying map are being performed.

   Under the hood, this is a wrapper around fd_banks_t's rwlock.
   This is done so a caller can safely read/write a specific bank.
   Otherwise, we run the risk of accessing/modifying a bank that may be
   freed. This is acquiring and freeing a read lock around fd_banks_t. */

static inline void
fd_banks_lock( fd_banks_t * banks ) {
  fd_rwlock_read( &banks->rwlock );
}

static inline void
fd_banks_unlock( fd_banks_t * banks ) {
  fd_rwlock_unread( &banks->rwlock );
}

/* fd_banks_root returns the current root slot for the bank. */

FD_FN_PURE static inline fd_bank_t const *
fd_banks_root( fd_banks_t const * banks ) {
  return fd_banks_pool_ele_const( fd_banks_get_bank_pool( banks ), banks->root_idx );
}

/* fd_banks_align() returns the alignment of fd_banks_t */

ulong
fd_banks_align( void );

/* fd_banks_footprint() returns the footprint of fd_banks_t */

ulong
fd_banks_footprint( ulong max_banks );

/* fd_banks_new() creates a new fd_banks_t struct. */

void *
fd_banks_new( void * mem, ulong max_banks );

/* fd_banks_join() joins a new fd_banks_t struct. */

fd_banks_t *
fd_banks_join( void * mem );

/* fd_banks_leave() leaves a bank. */

void *
fd_banks_leave( fd_banks_t * banks );

/* fd_banks_delete() deletes a bank. */

void *
fd_banks_delete( void * shmem );

/* fd_banks_init_bank() initializes a new bank in the bank manager.
   This should only be used during bootup. This returns an initial
   fd_bank_t with the corresponding slot. */

fd_bank_t *
fd_banks_init_bank( fd_banks_t * banks, ulong slot );

/* fd_bank_get_bank() returns a bank for a given slot. If said bank
   does not exist, NULL is returned. */

fd_bank_t *
fd_banks_get_bank( fd_banks_t * banks, ulong slot );

/* fd_banks_clone_from_parent() clones a bank from a parent bank.
   If the bank corresponding to the parent slot does not exist,
   NULL is returned. If a bank is not able to be created, NULL is
   returned. The data from the parent bank will copied over into
   the new bank.

   A more detailed note: not all of the data is copied over and this
   is a shallow clone. All of the CoW fields are not copied over and
   will only be done so if the caller explicitly calls
   fd_bank_{*}_modify(). This naming was chosen to emulate the
   semantics of the Agave client. */

fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t * banks,
                            ulong        slot,
                            ulong        parent_slot );

/* fd_banks_publish() publishes a bank to the bank manager. This
   should only be used when a bank is no longer needed. This will
   prune off the bank from the bank manager. It returns the new root
   bank.

   All banks that are ancestors or siblings of the slot will be
   cancelled and their resources will be released back to the pool. */

fd_bank_t const *
fd_banks_publish( fd_banks_t * banks, ulong slot );

/* fd_bank_clear_bank() clears the contents of a bank. This should ONLY
   be used with banks that have no children.

   This function will memset all non-CoW fields to 0.

   For all non-CoW fields, we will reset the indices to its parent. */

void
fd_banks_clear_bank( fd_banks_t * banks, fd_bank_t * bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_h */
