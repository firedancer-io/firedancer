#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_h

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../features/fd_features.h"
#include "../rewards/fd_epoch_rewards.h"
#include "../stakes/fd_stake_delegations.h"
#include "../stakes/fd_vote_states.h"
#include "../fd_rwlock.h"
#include "fd_runtime_const.h"
#include "fd_blockhashes.h"
#include "sysvar/fd_sysvar_cache.h"
#include "../../ballet/lthash/fd_lthash.h"

FD_PROTOTYPES_BEGIN

#define FD_BANKS_MAGIC (0XF17EDA2C7EBA2450) /* FIREDANCER BANKS V0 */

/* TODO: Some optimizations, cleanups, future work:
   1. Simple data types (ulong, int, etc) should be stored as their
      underlying type instead of a byte array.
   2. Perhaps make the query/modify scoping more explicit. Right now,
      the caller is free to use the API wrong if there are no locks.
      Maybe just expose a different API if there are no locks?
   3. Rename locks to suffix with _query_locking and _query_locking_end
   4. Replace memset with custom constructors for new banks.
   5. Don't templatize out more complex types.
  */

/* A fd_bank_t struct is the representation of the bank state on Solana
   for a given block. More specifically, the bank state corresponds to
   all information needed during execution that is not stored on-chain,
   but is instead cached in a validator's memory. Each of these bank
   fields are repesented by a member of the fd_bank_t struct.

   Management of fd_bank_t structs must be fork-aware: the state of each
   fd_bank_t must be based on the fd_bank_t of it's parent block. This
   state is managed by the fd_banks_t struct.

   In order to support fork-awareness, there are several key features
   that fd_banks_t and fd_bank_t MUST support:
   1. Query for any non-rooted block's bank: create a fast lookup
      from block id to bank
   2. Be able to create a new bank for a given block from the bank of
      that block's parent and maintain some tree-like structure to
      track the parent-child relationships: copy the contents from a
      parent bank into a child bank.
   3. Prune the set of active banks to keep the root updated as the
      network progresses: free resources of fd_bank_t structs that
      are are not direct descendants of the root bank (remove parents
      and any competing lineages).
   4. Each bank will have field(s) that are concurrently read/write
      from multiple threads: add read-write locks to the fields that are
      concurrently written to.
   5. In practice, a bank state for a given block can be very large and
      not all of the fields are written to every block. Therefore, it can
      be very expensive to copy the entire bank state for a given block
      each time a bank is created. In order to avoid large memcpys, we
      can use a CoW mechanism for certain fields.
   6. In a similar vein, some fields are very large and are not written
      to very often, and are only read at the epoch boundary. The most
      notable example is the stake delegations cache. In order to handle
      this, we can use a delta-based approach where each bank only has
      a delta of the stake delegations. The root bank will own the full
      set of stake delegations. This means that the deltas are only
      applied to the root bank as each bank gets rooted. If the caller
      needs to access the full set of stake delegations for a given
      bank, they can assemble the full set of stake delegations by
      applying all of the deltas from the current bank and all of its
      ancestors up to the root bank.

  Each field of a fd_bank_t has a pre-specified set of fields including
    - name: the name of the field
    - footprint: the size of the field in bytes
    - align: the alignment of the field
    - CoW: whether the field is CoW
    - has_lock: whether the field has a rw-lock
    - type: type of the field

  fd_banks_t is represented by a left-child, right-sibling n-ary tree
  (inspired by fd_ghost) to keep track of the parent-child fork tree.
  The underlying data structure is a map of fd_bank_t structs that is
  keyed by block id. This map is backed by a simple memory pool.

  NOTE: The reason fd_banks_t is keyed by block id and not by slot is
  to handle block equivocation: if there are two different blocks for
  the same slot, we need to be able to differentiate and handle both
  blocks against different banks.

  Each field in fd_bank_t that is not CoW is laid out contiguously in
  the fd_bank_t struct as simple uchar buffers. This allows for a simple
  memcpy to clone the bank state from a parent to a child.

  Each field that is CoW has its own memory pool. The memory
  corresponding to the field is not located in the fd_bank_t struct and
  is instead represented by a pool index and a dirty flag. If the field
  is modified, then the dirty flag is set, and an element of the pool
  is acquired and the data is copied over from the parent pool idx.

  Currently, there is a delta-based field, fd_stake_delegations_t.
  Each bank stores a delta-based representation in the form of an
  aligned uchar buffer. The full state is stored in fd_banks_t also as
  a uchar buffer which corresponds to the full state of stake
  delegations for the current root. fd_banks_t also reserves another
  buffer which can store the full state of the stake delegations.

  fd_bank_t also holds all of the rw-locks for the fields that have
  rw-locks.

  So, when a bank is cloned from a parent, the non CoW fields are copied
  over and the CoW fields just copy over a pool index. The CoW behavior
  is completely abstracted away from the caller as callers have to
  query/modify fields using specific APIs.

  The memory for the banks is based off of two bounds:
  1. the max number of unrooted blocks at any given time. Most fields
     can be bounded by this value.
  2. the max number of forks that execute through any 1 block.  We bound
     fields that are only written to at the epoch boundary by
     the max fork width that can execute through the boundary instead of
     by the max number of banks.  See fd_banks_footprint() for more
     details.

  NOTE: An important invariant is that if a field is CoW, then it must
  have a rw-lock.

  NOTE: Another important invariant is that if a field is limiting its
  fork width, then it must be CoW.

  The usage pattern is as follows:

   To create an initial bank:
   fd_bank_t * bank_init = fd_bank_init_bank( banks, block_id );

   To clone bank from parent banks:
   fd_bank_t * bank_clone = fd_banks_clone_from_parent( banks, block_id, parent_block_id );

   To publish a bank (aka update the root bank):
   fd_bank_t * bank_publish = fd_banks_publish( banks, block_id );

   To query some arbitrary bank:
   fd_bank_t * bank_query = fd_banks_get_bank( banks, block_id );

  To access fields in the bank if a field does not have a lock:

  fd_struct_t const * field = fd_bank_field_query( bank );
  OR
  fd_struct field = fd_bank_field_get( bank );

  To modify fields in the bank if a field does not have a lock:

  fd_struct_t * field = fd_bank_field_modify( bank );
  OR
  fd_bank_field_set( bank, value );

  To access fields in the bank if the field has a lock:

  fd_struct_t const * field = fd_bank_field_locking_query( bank );
  ... use field ...
  fd_bank_field_locking_end_query( bank );

  To modify fields in the bank if the field has a lock:

  fd_struct_t * field = fd_bank_field_locking_modify( bank );
  ... use field ...
  fd_bank_field_locking_end_locking_modify( bank );

  IMPORTANT SAFETY NOTE: fd_banks_t assumes that there is only one bank
  being executed against at a time. However, it is safe to call
  fd_banks_publish while threads are executing against a bank.

  */

/* Define additional fields to the bank struct here. If trying to add
   a CoW field to the bank, define a pool for it as done below. */

#define FD_BANKS_ITER(X)                                                                                                                                                                                                                               \
  /* type,                             name,                        footprint,                                 align,                                      CoW, limit fork width, has lock */                                                          \
  X(fd_blockhashes_t,                  block_hash_queue,            sizeof(fd_blockhashes_t),                  alignof(fd_blockhashes_t),                  0,   0,                0    )  /* Block hash queue */                                       \
  X(fd_fee_rate_governor_t,            fee_rate_governor,           sizeof(fd_fee_rate_governor_t),            alignof(fd_fee_rate_governor_t),            0,   0,                0    )  /* Fee rate governor */                                      \
  X(int,                               done_executing,              sizeof(int),                               alignof(int),                               0,   0,                0    )  /* If a bank has executed all of its txns */                 \
  X(ulong,                             capitalization,              sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Capitalization */                                         \
  X(ulong,                             lamports_per_signature,      sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Lamports per signature */                                 \
  X(ulong,                             prev_lamports_per_signature, sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Previous lamports per signature */                        \
  X(ulong,                             transaction_count,           sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Transaction count */                                      \
  X(ulong,                             parent_signature_cnt,        sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Parent signature count */                                 \
  X(ulong,                             tick_height,                 sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Tick height */                                            \
  X(ulong,                             max_tick_height,             sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Max tick height */                                        \
  X(ulong,                             hashes_per_tick,             sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Hashes per tick */                                        \
  X(uint128,                           ns_per_slot,                 sizeof(uint128),                           alignof(uint128),                           0,   0,                0    )  /* NS per slot */                                            \
  X(ulong,                             ticks_per_slot,              sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Ticks per slot */                                         \
  X(ulong,                             genesis_creation_time,       sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Genesis creation time */                                  \
  X(double,                            slots_per_year,              sizeof(double),                            alignof(double),                            0,   0,                0    )  /* Slots per year */                                         \
  X(fd_inflation_t,                    inflation,                   sizeof(fd_inflation_t),                    alignof(fd_inflation_t),                    0,   0,                0    )  /* Inflation */                                              \
  X(ulong,                             total_epoch_stake,           sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Total epoch stake */                                      \
                                                                                                                                                                                          /* This is only used for the get_epoch_stake syscall. */     \
                                                                                                                                                                                          /* If we are executing in epoch E, this is the total */      \
                                                                                                                                                                                          /* stake at the end of epoch E-1. */                         \
  X(ulong,                             block_height,                sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Block height */                                           \
  X(ulong,                             execution_fees,              sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Execution fees */                                         \
  X(ulong,                             priority_fees,               sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Priority fees */                                          \
  X(ulong,                             signature_count,             sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Signature count */                                        \
  X(fd_hash_t,                         poh,                         sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* PoH */                                                    \
  X(fd_sol_sysvar_last_restart_slot_t, last_restart_slot,           sizeof(fd_sol_sysvar_last_restart_slot_t), alignof(fd_sol_sysvar_last_restart_slot_t), 0,   0,                0    )  /* Last restart slot */                                      \
  X(fd_cluster_version_t,              cluster_version,             sizeof(fd_cluster_version_t),              alignof(fd_cluster_version_t),              0,   0,                0    )  /* Cluster version */                                        \
  X(ulong,                             slot,                        sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Slot */                                                   \
  X(ulong,                             parent_slot,                 sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Previous slot */                                          \
  X(fd_hash_t,                         bank_hash,                   sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* Bank hash */                                              \
  X(fd_hash_t,                         prev_bank_hash,              sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* Previous bank hash */                                     \
  X(fd_hash_t,                         parent_block_id,             sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* Parent block id */                                        \
  X(fd_hash_t,                         genesis_hash,                sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* Genesis hash */                                           \
  X(fd_epoch_schedule_t,               epoch_schedule,              sizeof(fd_epoch_schedule_t),               alignof(fd_epoch_schedule_t),               0,   0,                0    )  /* Epoch schedule */                                         \
  X(fd_rent_t,                         rent,                        sizeof(fd_rent_t),                         alignof(fd_rent_t),                         0,   0,                0    )  /* Rent */                                                   \
  X(fd_lthash_value_t,                 lthash,                      sizeof(fd_lthash_value_t),                 alignof(fd_lthash_value_t),                 0,   0,                1    )  /* LTHash */                                                 \
  X(fd_sysvar_cache_t,                 sysvar_cache,                sizeof(fd_sysvar_cache_t),                 alignof(fd_sysvar_cache_t),                 0,   0,                0    )  /* Sysvar cache */                                           \
  X(fd_epoch_rewards_t,                epoch_rewards,               FD_EPOCH_REWARDS_FOOTPRINT,                FD_EPOCH_REWARDS_ALIGN,                     1,   1,                1    )  /* Epoch rewards */                                          \
  X(fd_epoch_leaders_t,                epoch_leaders,               FD_RUNTIME_MAX_EPOCH_LEADERS,              FD_EPOCH_LEADERS_ALIGN,                     1,   1,                1    )  /* Epoch leaders. If our system supports 100k vote accs, */  \
                                                                                                                                                                                          /* then there can be 100k unique leaders in the worst */     \
                                                                                                                                                                                          /* case. We also can assume 432k slots per epoch. */         \
  X(fd_features_t,                     features,                    sizeof(fd_features_t),                     alignof(fd_features_t),                     0,   0,                0    )  /* Features */                                               \
  X(ulong,                             txn_count,                   sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Transaction count */                                      \
  X(ulong,                             nonvote_txn_count,           sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Nonvote transaction count */                              \
  X(ulong,                             failed_txn_count,            sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Failed transaction count */                               \
  X(ulong,                             nonvote_failed_txn_count,    sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Nonvote failed transaction count */                       \
  X(ulong,                             total_compute_units_used,    sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Total compute units used */                               \
  X(ulong,                             slots_per_epoch,             sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Slots per epoch */                                        \
  X(ulong,                             shred_cnt,                   sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Shred count */                                            \
  X(ulong,                             epoch,                       sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Epoch */                                                  \
  X(fd_vote_states_t,                  vote_states,                 FD_VOTE_STATES_FOOTPRINT,                  FD_VOTE_STATES_ALIGN,                       1,   0,                1    )  /* Vote states for all vote accounts as of epoch E if */     \
                                                                                                                                                                                          /* epoch E is the one that is currently being executed */    \
  X(fd_vote_states_t,                  vote_states_prev,            FD_VOTE_STATES_FOOTPRINT,                  FD_VOTE_STATES_ALIGN,                       1,   1,                1    )  /* Vote states for all vote accounts as of of the end of */  \
                                                                                                                                                                                          /* epoch E-1 if epoch E is currently being executed */       \
  X(fd_vote_states_t,                  vote_states_prev_prev,       FD_VOTE_STATES_FOOTPRINT,                  FD_VOTE_STATES_ALIGN,                       1,   1,                1    )  /* Vote states for all vote accounts as of the end of */     \
                                                                                                                                                                                          /* epoch E-2 if epoch E is currently being executed */

/* Invariant Every CoW field must have a rw-lock */
#define X(type, name, footprint, align, cow, limit_fork_width, has_lock)                                              \
  FD_STATIC_ASSERT( (cow == 1 && has_lock == 1        ) || (cow == 0            ),  CoW fields must have a rw-lock ); \
  FD_STATIC_ASSERT( (cow == 1 && limit_fork_width == 1) || (limit_fork_width == 0), CoW must be 1 if limit_fork_width is 1 );
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

#define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
  HAS_COW_##cow(name, footprint, align)
  FD_BANKS_ITER(X)

#undef X
#undef HAS_COW_0
#undef HAS_COW_1

#define POOL_NAME fd_bank_epoch_leaders_pool
#define POOL_T    fd_bank_epoch_leaders_t
#include "../../util/tmpl/fd_pool.c"

#define POOL_NAME fd_bank_epoch_rewards_pool
#define POOL_T    fd_bank_epoch_rewards_t
#include "../../util/tmpl/fd_pool.c"

#define POOL_NAME fd_bank_vote_states_pool
#define POOL_T    fd_bank_vote_states_t
#include "../../util/tmpl/fd_pool.c"

#define POOL_NAME fd_bank_vote_states_prev_pool
#define POOL_T    fd_bank_vote_states_prev_t
#include "../../util/tmpl/fd_pool.c"

#define POOL_NAME fd_bank_vote_states_prev_prev_pool
#define POOL_T    fd_bank_vote_states_prev_prev_t
#include "../../util/tmpl/fd_pool.c"

#define FD_BANK_FLAGS_INIT              (0x00000000UL) /* Initialized and replayable. */
#define FD_BANK_FLAGS_FROZEN            (0x00000001UL) /* Frozen, either because we finished replaying it, or because it was a
                                                          snapshot loaded bank. */
#define FD_BANK_FLAGS_DEAD              (0x00000002UL) /* Dead, meaning we stopped replaying it before we could finish it,
                                                          because for example it exceeded the block CU limit, or we decided it
                                                          was on a minority fork. */
#define FD_BANK_FLAGS_ROOTED            (0x00000004UL) /* Rooted because tower said so. */
#define FD_BANK_FLAGS_EXEC_RECORDING    (0x00000100UL) /* Enable execution recording. */

/* As mentioned above, the overall layout of the bank struct:
   - Fields used for internal pool/bank management
   - Non-Cow fields
   - CoW fields
   - Locks for CoW fields

   The CoW fields are laid out contiguously in the bank struct.
   The locks for the CoW fields are laid out contiguously after the
   CoW fields.

   (r) Field is owned by the replay tile, and should be updated only by
       the replay tile.
*/

struct fd_bank {
  #define FD_BANK_HEADER_SIZE (80UL)

  /* Fields used for internal pool and bank management */
  fd_hash_t         block_id_;   /* block id this node is tracking, also the map key */
  ulong             next;        /* reserved for internal use by fd_pool_para, fd_map_chain_para and fd_banks_publish */
  ulong             parent_idx;  /* index of the parent in the node pool */
  ulong             child_idx;   /* index of the left-child in the node pool */
  ulong             sibling_idx; /* index of the right-sibling in the node pool */
  ulong             flags;       /* (r) keeps track of the state of the bank, as well as some configurations */
  ulong             refcnt;      /* (r) reference count on the bank, see replay for more details */

  /* First, layout all non-CoW fields contiguously. This is done to
     allow for cloning the bank state with a simple memcpy. Each
     non-CoW field is just represented as a byte array. */

  #define HAS_COW_1(type, name, footprint, align)

  #define HAS_COW_0(type, name, footprint, align) \
    uchar name[footprint] __attribute__((aligned(align)));

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
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

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  /* Now emit locks for all fields that need a rwlock. */

  #define HAS_LOCK_1(type, name, footprint, align) \
    fd_rwlock_t name##_lock;

  #define HAS_LOCK_0(type, name, footprint, align) /* Do nothing for these. */

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_LOCK_##has_lock(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_LOCK_0
  #undef HAS_LOCK_1

  /* Stake delegations delta. */

  uchar       stake_delegations_delta[FD_STAKE_DELEGATIONS_DELTA_FOOTPRINT] __attribute__((aligned(FD_STAKE_DELEGATIONS_ALIGN)));
  int         stake_delegations_delta_dirty;
  fd_rwlock_t stake_delegations_delta_lock;
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

#define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
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

   fd_banks_t contains some metadata a map/pool pair to manage the
   banks. It also contains pointers to the CoW pools.

   The data is laid out contiguously in memory starting from fd_banks_t;
   this can be seen in fd_banks_footprint(). */

#define POOL_NAME fd_banks_pool
#define POOL_T    fd_bank_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_banks_map
#define MAP_ELE_T              fd_bank_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY                block_id_
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_funk_rec_key_hash1( (uchar *)key, 0, seed ))
#include "../../util/tmpl/fd_map_chain.c"

struct fd_banks {
  ulong       magic;           /* ==FD_BANKS_MAGIC */
  ulong       max_total_banks; /* Maximum number of banks */
  ulong       max_fork_width;  /* Maximum fork width executing through
                                  any given slot. */
  ulong       root_idx;        /* root idx */

  /* This lock is only used to serialize banks fork tree reads with
     respect to fork tree writes.  In other words, tree traversals
     cannot happen at the same time as a tree pruning operation or a
     tree insertion operation.  So the public APIs on banks take either
     a read lock or a write lock depending on what they do on the fork
     tree.  For example, publishing takes a write lock, and bank lookups
     take a read lock.  Notably, individual banks can still be
     concurrently accessed or modified, and this lock does not offer
     synchronization on individual fields within a bank. */
  fd_rwlock_t rwlock;

  ulong       pool_offset;     /* offset of pool from banks */
  ulong       map_offset;      /* offset of map from banks */

  /* stake_delegations_root will be the full state of stake delegations
     for the current root. It can get updated in two ways:
     1. On boot the snapshot will be directly read into the rooted
        stake delegations because we assume that any and all snapshots
        are a rooted slot.
     2. Calls to fd_banks_publish() will apply all of the stake
        delegation deltas from each of the banks that are about to be
        published.  */

  uchar stake_delegations_root[FD_STAKE_DELEGATIONS_FOOTPRINT] __attribute__((aligned(FD_STAKE_DELEGATIONS_ALIGN)));

  /* stake_delegations_frontier is reserved memory that can represent
     the full state of stake delegations for the current frontier. This
     is done by taking the stake_delegations_root and applying all of
     the deltas from the current bank and all of its ancestors up to the
     root bank. */

  uchar stake_delegations_frontier[FD_STAKE_DELEGATIONS_FOOTPRINT] __attribute__((aligned(FD_STAKE_DELEGATIONS_ALIGN)));

  /* Layout all CoW pools. */

  #define HAS_COW_1(type, name, footprint, align) \
    ulong           name##_pool_offset; /* offset of pool from banks */

  #define HAS_COW_0(type, name, footprint, align) /* Do nothing for these. */

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
};
typedef struct fd_banks fd_banks_t;

/* Bank accesssors. Different accessors are emitted for different types
   depending on if the field has a lock or not. */

#define HAS_LOCK_1(type, name)                                     \
  type const * fd_bank_##name##_locking_query( fd_bank_t * bank ); \
  void fd_bank_##name##_end_locking_query( fd_bank_t * bank );     \
  type * fd_bank_##name##_locking_modify( fd_bank_t * bank );      \
  void fd_bank_##name##_end_locking_modify( fd_bank_t * bank );

#define HAS_LOCK_0(type, name)                                   \
  type const * fd_bank_##name##_query( fd_bank_t const * bank ); \
  type * fd_bank_##name##_modify( fd_bank_t * bank );

#define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
  void fd_bank_##name##_set( fd_bank_t * bank, type value );             \
  type fd_bank_##name##_get( fd_bank_t const * bank );                   \
  HAS_LOCK_##has_lock(type, name)
FD_BANKS_ITER(X)
#undef X

#undef HAS_LOCK_0
#undef HAS_LOCK_1

/* fd_bank_block_id_query() returns a const pointer to the block id of
   a given bank. */

static inline fd_hash_t const *
fd_bank_block_id_query( fd_bank_t const * bank ) {
  return &bank->block_id_;
}

/* Each bank has a fd_stake_delegations_t object which is delta-based.
   The usage pattern is the same as other bank fields:
   1. fd_bank_stake_dleegations_delta_locking_modify( bank ) will return
      a mutable pointer to the stake delegations delta object. If the
      caller has not yet initialized the delta object, then it will
      be initialized. Because it is a delta it is not copied over from
      a parent bank.
   2. fd_bank_stake_delegations_delta_locking_query( bank ) will return
      a const pointer to the stake delegations delta object. If the
      delta object has not been initialized, then NULL is returned.
   3. fd_bank_stake_delegations_delta_locking_end_modify( bank ) will
      release the write lock on the object.
   4. fd_bank_stake_delegations_delta_locking_end_query( bank ) will
      release a read lock on the object.
*/

static inline fd_stake_delegations_t *
fd_bank_stake_delegations_delta_locking_modify( fd_bank_t * bank ) {
  fd_rwlock_write( &bank->stake_delegations_delta_lock );
  if( !bank->stake_delegations_delta_dirty ) {
    bank->stake_delegations_delta_dirty = 1;
    fd_stake_delegations_new( bank->stake_delegations_delta, FD_RUNTIME_MAX_STAKE_ACCS_IN_SLOT, 1 );
  }
  return fd_stake_delegations_join( bank->stake_delegations_delta );
}

static inline void
fd_bank_stake_delegations_delta_end_locking_modify( fd_bank_t * bank ) {
  fd_rwlock_unwrite( &bank->stake_delegations_delta_lock );
}

static inline fd_stake_delegations_t *
fd_bank_stake_delegations_delta_locking_query( fd_bank_t * bank ) {
  fd_rwlock_read( &bank->stake_delegations_delta_lock );
  return bank->stake_delegations_delta_dirty ? fd_stake_delegations_join( bank->stake_delegations_delta ) : NULL;
}

static inline void
fd_bank_stake_delegations_delta_end_locking_query( fd_bank_t * bank ) {
  fd_rwlock_unread( &bank->stake_delegations_delta_lock );
}

/* fd_bank_stake_delegations_frontier_query() will return a pointer to
   the full stake delegations for the current frontier. The caller is
   responsible that there are no concurrent readers or writers to
   the stake delegations returned by this function.

   Under the hood, the function copies the rooted stake delegations and
   applies all of the deltas for the direct ancestry from the current
   bank up to the rooted bank to the copy. */

fd_stake_delegations_t *
fd_bank_stake_delegations_frontier_query( fd_banks_t * banks,
                                          fd_bank_t *  bank );

/* fd_banks_stake_delegations_root_query() will return a pointer to the
   full stake delegations for the current root. This function should
   only be called on boot. */

fd_stake_delegations_t *
fd_banks_stake_delegations_root_query( fd_banks_t * banks );

/* Simple getters and setters for the various maps and pools in
   fd_banks_t. Notably, the map/pool pairs for the fd_bank_t structs as
   well as all of the CoW structs in the banks. */

static inline fd_bank_t *
fd_banks_get_bank_pool( fd_banks_t const * banks ) {
  return fd_banks_pool_join( ((uchar *)banks + banks->pool_offset) );
}

static inline fd_banks_map_t *
fd_banks_get_bank_map( fd_banks_t const * banks ) {
  return fd_banks_map_join( ((uchar *)banks + banks->map_offset) );
}

static inline void
fd_banks_set_bank_pool( fd_banks_t * banks,
                        fd_bank_t *  bank_pool ) {
  void * bank_pool_mem = fd_banks_pool_leave( bank_pool );
  if( FD_UNLIKELY( !bank_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave bank pool" ));
  }
  banks->pool_offset = (ulong)bank_pool_mem - (ulong)banks;
}

static inline void
fd_banks_set_bank_map( fd_banks_t *     banks,
                       fd_banks_map_t * bank_map ) {
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

#define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
  HAS_COW_##cow(type, name, footprint, align)
FD_BANKS_ITER(X)
#undef X
#undef HAS_COW_0
#undef HAS_COW_1


/* fd_banks_root() and fd_banks_root_const() returns a non-const and
   const pointer to the root bank respectively. */

FD_FN_PURE static inline fd_bank_t const *
fd_banks_root_const( fd_banks_t const * banks ) {
  return fd_banks_pool_ele_const( fd_banks_get_bank_pool( banks ), banks->root_idx );
}

FD_FN_PURE static inline fd_bank_t *
fd_banks_root( fd_banks_t * banks ) {
  return fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), banks->root_idx );
}

/* fd_banks_align() returns the alignment of fd_banks_t */

ulong
fd_banks_align( void );

/* fd_banks_footprint() returns the footprint of fd_banks_t.  This
   includes the struct itself but also the footprint for all of the
   pools.

   The footprint of fd_banks_t is determined by the total number
   of banks that the bank manages.  This is an analog for the max number
   of unrooted blocks the bank can manage at any given time.

   We can also further bound the memory footprint of the banks by the
   max width of forks that can exist at any given time.  The reason for
   this is that there are several large CoW structs that are only
   written to during the epoch boundary (e.g. epoch_rewards,
   epoch_stakes, etc.).  These structs are read-only afterwards. This
   means if we also bound the max number of forks that can execute
   through the epoch boundary, we can bound the memory footprint of
   the banks. */

ulong
fd_banks_footprint( ulong max_total_banks,
                    ulong max_fork_width );

/* fd_banks_new() creates a new fd_banks_t struct.  This function lays
   out the memory for all of the constituent fd_bank_t structs and
   pools depending on the max_total_banks and the max_fork_width for a
   given block. */

void *
fd_banks_new( void * mem,
              ulong  max_total_banks,
              ulong  max_fork_width );

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
   fd_bank_t with the corresponding block id. */

fd_bank_t *
fd_banks_init_bank( fd_banks_t *      banks,
                    fd_hash_t const * block_id );

/* fd_banks_get_bank() returns a bank for a given block id.  If said
   bank does not exist, NULL is returned.

   The returned pointer is valid so long as the underlying bank does not
   get pruned by a publishing operation.  Higher level components are
   responsible for ensuring that publishing does not happen while a bank
   is being accessed.  This is done through the reference counter. */

fd_bank_t *
fd_banks_get_bank( fd_banks_t *      banks,
                   fd_hash_t const * block_id );

/* fd_banks_get_bank_idx returns a bank for a given index into the pool
   of banks.  This function otherwise has the same behavior as
   fd_banks_get_bank(). */

static inline fd_bank_t *
fd_banks_get_bank_idx( fd_banks_t * banks,
                       ulong        idx ) {
  return fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), idx );
}

/* fd_banks_get_pool_idx returns the index of a bank in the pool. */

static inline ulong
fd_banks_get_pool_idx( fd_banks_t * banks,
                       fd_bank_t *  bank ) {
  return fd_banks_pool_idx( fd_banks_get_bank_pool( banks ), bank );
}

/* fd_banks_clone_from_parent() clones a bank from a parent bank.
   If the bank corresponding to the parent block id does not exist,
   NULL is returned.  If a bank is not able to be created, NULL is
   returned. The data from the parent bank will copied over into
   the new bank.

   A more detailed note: not all of the data is copied over and this
   is a shallow clone.  All of the CoW fields are not copied over and
   will only be done so if the caller explicitly calls
   fd_bank_{*}_modify().  This naming was chosen to emulate the
   semantics of the Agave client. */

fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t *      banks,
                            fd_hash_t const * merkle_hash,
                            fd_hash_t const * parent_block_id );

/* fd_banks_publish() publishes a bank to the bank manager. This
   should only be used when a bank is no longer needed. This will
   prune off the bank from the bank manager. It returns the new root
   bank.

   All banks that are ancestors or siblings of the new root bank will be
   cancelled and their resources will be released back to the pool. */

fd_bank_t const *
fd_banks_publish( fd_banks_t *      banks,
                  fd_hash_t const * block_id );

/* fd_bank_clear_bank() clears the contents of a bank. This should ONLY
   be used with banks that have no children.

   This function will memset all non-CoW fields to 0.

   For all CoW fields, we will reset the indices to its parent. */

void
fd_banks_clear_bank( fd_banks_t * banks,
                     fd_bank_t *  bank );

/* Returns the highest block that can be safely published between the
   current published root of the fork tree and the target block.  See
   the note on safe publishing for more details.  In general, a node in
   the fork tree can be pruned if
   (1) the node itself can be pruned, and
   (2) all subtrees (except for the one on the rooted fork) forking off
       of the node can be pruned.
   The highest publishable block is the highest block on the rooted fork
   where the above is true, or the rooted child block of such if there
   is one.

   This function assumes that the given target block has been rooted by
   consensus.  It will mark every block on the rooted fork as rooted, up
   to the given target block.  It will also mark minority forks as dead.

   Highest publishable block is written to the out pointer.  Returns 1
   if the publishable block can be advanced beyond the current root.
   Returns 0 if no such block can be found. */

int
fd_banks_publish_prepare( fd_banks_t * banks,
                          fd_hash_t *  target_block_id,
                          fd_hash_t *  publishable_block_id );

/* Updates the current bank to have a new block id.  The block id of a
   slot is only fully known at the end of a slot.  However, it is
   continually updated as the slot progresses because the block id
   is the last merkle hash of an FEC set.  As the block executes, the
   key of the bank should be equal to the most recently executed merkle
   hash.

   This function should NOT be called once the current bank has child
   banks. */

void
fd_banks_rekey_bank( fd_banks_t *      banks,
                     fd_hash_t const * old_block_id,
                     fd_hash_t const * new_block_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_h */
