#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_h

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../features/fd_features.h"
#include "../rewards/fd_epoch_rewards.h"
#include "../stakes/fd_stake_delegations.h"
#include "../stakes/fd_vote_states.h"
#include "../fd_rwlock.h"
#include "fd_blockhashes.h"
#include "sysvar/fd_sysvar_cache.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "fd_txncache_shmem.h"

FD_PROTOTYPES_BEGIN

#define FD_BANKS_MAGIC (0XF17EDA2C7EBA2450) /* FIREDANCER BANKS V0 */

/* TODO: Some optimizations, cleanups, future work:
   1. Simple data types (ulong, int, etc) should be stored as their
      underlying type instead of a byte array.
   2. Perhaps make the query/modify scoping more explicit. Right now,
      the caller is free to use the API wrong if there are no locks.
      Maybe just expose a different API if there are no locks?
   3. Rename locks to suffix with _query_locking and _query_locking_end
   4. Don't templatize out more complex types.
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
      from bank index to bank
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
  The underlying data structure is a pool of fd_bank_t structs.  Banks
  are then accessed via an index into the bank pool (bank index).

  NOTE: The reason fd_banks_t is keyed by bank index and not by slot is
  to handle block equivocation: if there are two different blocks for
  the same slot, we need to be able to differentiate and handle both
  blocks against different banks.  As mentioned above, the bank index is
  just an index into the bank pool.  The caller is responsible for
  establishing a mapping from the bank index (which is managed by
  fd_banks_t) and runtime state (e.g. slot number).

  Most of the fields a fd_bank_t are templatized and can support CoW
  sematics or locking semantics.

  Each field in fd_bank_t that is not CoW is laid out contiguously in
  the fd_bank_t struct as simple uchar buffers. This allows for a simple
  memcpy to clone the bank state from a parent to a child.

  Each field that is CoW has its own memory pool. The memory
  corresponding to the field is not located in the fd_bank_t struct and
  is instead represented by a pool index and a dirty flag. If the field
  is modified, then the dirty flag is set, and an element of the pool
  is acquired and the data is copied over from the parent pool idx.

  Not all fields in the bank are templatized: stake_delegations and
  the cost_tracker.

  Currently, there is a delta-based field, fd_stake_delegations_t.
  Each bank stores a delta-based representation in the form of an
  aligned uchar buffer.  The full state is stored in fd_banks_t also as
  a uchar buffer which corresponds to the full state of stake
  delegations for the current root.  fd_banks_t also reserves another
  buffer which can store the full state of the stake delegations.

  The cost tracker is allocated from a pool.  The lifetime of a cost
  tracker element starts when the bank is linked to a parent with a
  call to fd_banks_clone_from_parent() which makes the bank replayable.
  The lifetime of a cost tracker element ends when the bank is marked
  dead or when the bank is frozen.

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

  There are also some important states that a bank can be in:
  - Initialized: This bank has been created and linked to a parent bank
    index with a call to fd_banks_new_bank().  However, it is not yet
    replayable.
  - Replayable: This bank has inherited state from its parent and now
    transactions can be executed against it.  For a bank to become
    replayable, it must've been initialized beforehand.
  - Dead: This bank has been marked as dead.  This means that the block
    that this bank is associated with is invalid.  A bank can be marked
    dead before, during, or after it has finished replaying.  A bank
    can still be executing transactions while it is marked dead, but it
    shouldn't be dispatched any more work.
  - Frozen: This bank has been marked as frozen and no other tasks
    should be dispatched to it.  Any bank-specific resources will be
    released (e.g. cost tracker element).  A bank can be marked frozen
    in two cases:
      1. The bank has finished executing all of its transactions
      2. The bank has been marked dead and there are no outstanding
         references to the bank.
    A bank can only be copied from a parent bank
    (fd_banks_clone_from_parent) if the parent bank has been frozen.
    The program will crash if this invariant is violated.

  NOTE: An important invariant is that if a templatized field is CoW,
  then it must have a rw-lock.

  NOTE: Another important invariant is that if a templatized field is
  limiting its fork width, then it must be CoW.

  The usage pattern is as follows:

   To create an initial bank:
   fd_bank_t * bank_init = fd_bank_init_bank( banks );

   To create a new bank:
   ulong bank_index = fd_banks_new_bank( banks, parent_bank_index );

   To clone bank from parent banks:
   fd_bank_t * bank_clone = fd_banks_clone_from_parent( banks, bank_index, parent_bank_index );

   To advance the root bank
   fd_bank_t * root_bank = fd_banks_advance_root( banks, bank_index );

   To query some arbitrary bank:
   fd_bank_t * bank_query = fd_banks_bank_query( banks, bank_index );

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
  fd_bank_field_locking_end_locking_modify( bank ); */

/* Define additional fields to the bank struct here. If trying to add
   a CoW field to the bank, define a pool for it as done below. */

#define FD_BANKS_ITER(X)                                                                                                                                                                                                                               \
  /* type,                             name,                        footprint,                                 align,                                      CoW, limit fork width, has lock */                                                          \
  X(fd_blockhashes_t,                  block_hash_queue,            sizeof(fd_blockhashes_t),                  alignof(fd_blockhashes_t),                  0,   0,                0    )  /* Block hash queue */                                       \
  X(fd_fee_rate_governor_t,            fee_rate_governor,           sizeof(fd_fee_rate_governor_t),            alignof(fd_fee_rate_governor_t),            0,   0,                0    )  /* Fee rate governor */                                      \
  X(ulong,                             rbh_lamports_per_sig,        sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Recent Block Hashes lamports per signature */             \
  X(ulong,                             slot,                        sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Slot */                                                   \
  X(ulong,                             parent_slot,                 sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Parent slot */                                            \
  X(ulong,                             capitalization,              sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Capitalization */                                         \
  X(ulong,                             transaction_count,           sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Transaction count */                                      \
  X(ulong,                             parent_signature_cnt,        sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Parent signature count */                                 \
  X(ulong,                             tick_height,                 sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Tick height */                                            \
  X(ulong,                             max_tick_height,             sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Max tick height */                                        \
  X(ulong,                             hashes_per_tick,             sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Hashes per tick */                                        \
  X(fd_w_u128_t,                       ns_per_slot,                 sizeof(fd_w_u128_t),                       alignof(fd_w_u128_t),                       0,   0,                0    )  /* NS per slot */                                            \
  X(ulong,                             ticks_per_slot,              sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Ticks per slot */                                         \
  X(ulong,                             genesis_creation_time,       sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Genesis creation time */                                  \
  X(double,                            slots_per_year,              sizeof(double),                            alignof(double),                            0,   0,                0    )  /* Slots per year */                                         \
  X(fd_inflation_t,                    inflation,                   sizeof(fd_inflation_t),                    alignof(fd_inflation_t),                    0,   0,                0    )  /* Inflation */                                              \
  X(ulong,                             cluster_type,                sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Cluster type */                                           \
  X(ulong,                             total_epoch_stake,           sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Total epoch stake */                                      \
                                                                                                                                                                                          /* This is only used for the get_epoch_stake syscall. */     \
                                                                                                                                                                                          /* If we are executing in epoch E, this is the total */      \
                                                                                                                                                                                          /* stake at the end of epoch E-1. */                         \
  X(ulong,                             block_height,                sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Block height */                                           \
  X(ulong,                             execution_fees,              sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Execution fees */                                         \
  X(ulong,                             priority_fees,               sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Priority fees */                                          \
  X(ulong,                             tips,                        sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Tips collected */                                         \
  X(ulong,                             signature_count,             sizeof(ulong),                             alignof(ulong),                             0,   0,                0    )  /* Signature count */                                        \
  X(fd_hash_t,                         poh,                         sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* PoH */                                                    \
  X(fd_sol_sysvar_last_restart_slot_t, last_restart_slot,           sizeof(fd_sol_sysvar_last_restart_slot_t), alignof(fd_sol_sysvar_last_restart_slot_t), 0,   0,                0    )  /* Last restart slot */                                      \
  X(fd_hash_t,                         bank_hash,                   sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* Bank hash */                                              \
  X(fd_hash_t,                         prev_bank_hash,              sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* Previous bank hash */                                     \
  X(fd_hash_t,                         genesis_hash,                sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0,                0    )  /* Genesis hash */                                           \
  X(fd_epoch_schedule_t,               epoch_schedule,              sizeof(fd_epoch_schedule_t),               alignof(fd_epoch_schedule_t),               0,   0,                0    )  /* Epoch schedule */                                         \
  X(fd_rent_t,                         rent,                        sizeof(fd_rent_t),                         alignof(fd_rent_t),                         0,   0,                0    )  /* Rent */                                                   \
  X(fd_lthash_value_t,                 lthash,                      sizeof(fd_lthash_value_t),                 alignof(fd_lthash_value_t),                 0,   0,                1    )  /* LTHash */                                                 \
  X(fd_sysvar_cache_t,                 sysvar_cache,                sizeof(fd_sysvar_cache_t),                 alignof(fd_sysvar_cache_t),                 0,   0,                0    )  /* Sysvar cache */                                           \
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
  X(int,                               has_identity_vote,           sizeof(int),                               alignof(int),                               0,   0,                0    )  /* Has identity vote */                                      \
  X(fd_epoch_rewards_t,                epoch_rewards,               FD_EPOCH_REWARDS_FOOTPRINT,                FD_EPOCH_REWARDS_ALIGN,                     1,   1,                1    )  /* Epoch rewards */                                          \
  X(fd_epoch_leaders_t,                epoch_leaders,               FD_EPOCH_LEADERS_MAX_FOOTPRINT,            FD_EPOCH_LEADERS_ALIGN,                     1,   1,                1    )  /* Epoch leaders. If our system supports 100k vote accs, */  \
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

static const ulong fd_bank_epoch_rewards_align     = FD_EPOCH_REWARDS_ALIGN;
static const ulong fd_bank_epoch_rewards_footprint = FD_EPOCH_REWARDS_FOOTPRINT;
struct fd_bank_epoch_rewards {
  ulong next;
  uchar data[FD_EPOCH_REWARDS_FOOTPRINT] __attribute__((aligned(FD_EPOCH_REWARDS_ALIGN)));
};
typedef struct fd_bank_epoch_rewards fd_bank_epoch_rewards_t;

static const ulong fd_bank_epoch_leaders_align     = FD_EPOCH_LEADERS_ALIGN;
static const ulong fd_bank_epoch_leaders_footprint = FD_EPOCH_LEADERS_MAX_FOOTPRINT;
struct fd_bank_epoch_leaders {
  ulong next;
  uchar data[FD_EPOCH_LEADERS_MAX_FOOTPRINT] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));
};
typedef struct fd_bank_epoch_leaders fd_bank_epoch_leaders_t;

static const ulong fd_bank_vote_states_align     = FD_VOTE_STATES_ALIGN;
static const ulong fd_bank_vote_states_footprint = FD_VOTE_STATES_FOOTPRINT;
struct fd_bank_vote_states {
  ulong next;
  uchar data[FD_VOTE_STATES_FOOTPRINT] __attribute__((aligned(FD_VOTE_STATES_ALIGN)));
};
typedef struct fd_bank_vote_states fd_bank_vote_states_t;

static const ulong fd_bank_vote_states_prev_align     = FD_VOTE_STATES_ALIGN;
static const ulong fd_bank_vote_states_prev_footprint = FD_VOTE_STATES_FOOTPRINT;
struct fd_bank_vote_states_prev {
  ulong next;
  uchar data[FD_VOTE_STATES_FOOTPRINT] __attribute__((aligned(FD_VOTE_STATES_ALIGN)));
};
typedef struct fd_bank_vote_states_prev fd_bank_vote_states_prev_t;

static const ulong fd_bank_vote_states_prev_prev_align     = FD_VOTE_STATES_ALIGN;
static const ulong fd_bank_vote_states_prev_prev_footprint = FD_VOTE_STATES_FOOTPRINT;
struct fd_bank_vote_states_prev_prev {
  ulong next;
  uchar data[FD_VOTE_STATES_FOOTPRINT] __attribute__((aligned(FD_VOTE_STATES_ALIGN)));
};
typedef struct fd_bank_vote_states_prev_prev fd_bank_vote_states_prev_prev_t;

struct fd_bank_cost_tracker {
  ulong next;
  uchar data[FD_COST_TRACKER_FOOTPRINT] __attribute__((aligned(FD_COST_TRACKER_ALIGN)));
};
typedef struct fd_bank_cost_tracker fd_bank_cost_tracker_t;

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

#define POOL_NAME fd_bank_cost_tracker_pool
#define POOL_T    fd_bank_cost_tracker_t
#include "../../util/tmpl/fd_pool.c"

#define FD_BANK_FLAGS_INIT              (0x00000001UL) /* Initialized.  Not yet replayable. */
#define FD_BANK_FLAGS_REPLAYABLE        (0x00000002UL) /* Replayable. */
#define FD_BANK_FLAGS_FROZEN            (0x00000004UL) /* Frozen.  We finished replaying or because it was a snapshot/genesis loaded bank. */
#define FD_BANK_FLAGS_DEAD              (0x00000008UL) /* Dead.  We stopped replaying it before we could finish it (e.g. invalid block or pruned minority fork). */
#define FD_BANK_FLAGS_ROOTED            (0x00000010UL) /* Rooted.  Part of the consnensus root fork.  */

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

  /* Fields used for internal pool and bank management */
  ulong idx;         /* current fork idx of the bank (synchronized with the pool index) */
  ulong next;        /* reserved for internal use by pool and fd_banks_advance_root */
  ulong parent_idx;  /* index of the parent in the node pool */
  ulong child_idx;   /* index of the left-child in the node pool */
  ulong sibling_idx; /* index of the right-sibling in the node pool */
  ulong flags;       /* (r) keeps track of the state of the bank, as well as some configurations */
  ulong bank_seq;    /* app-wide bank sequence number */

  /* Define non-templatized types here. */

  /* Cost tracker. */

  ulong       cost_tracker_pool_idx;
  ulong       cost_tracker_pool_offset;
  fd_rwlock_t cost_tracker_lock;

  /* Stake delegations delta. */

  uchar       stake_delegations_delta[FD_STAKE_DELEGATIONS_DELTA_FOOTPRINT] __attribute__((aligned(FD_STAKE_DELEGATIONS_ALIGN)));
  int         stake_delegations_delta_dirty;
  fd_rwlock_t stake_delegations_delta_lock;

  ulong refcnt; /* (r) reference count on the bank, see replay for more details */

  fd_txncache_fork_id_t txncache_fork_id; /* fork id used by the txn cache */

  /* Timestamps written and read only by replay */

  long first_fec_set_received_nanos;
  long preparation_begin_nanos;
  long first_transaction_scheduled_nanos;
  long last_transaction_finished_nanos;

  /* First, layout all non-CoW fields contiguously. This is done to
     allow for cloning the bank state with a simple memcpy. Each
     non-CoW field is just represented as a byte array. */

  struct {

  #define HAS_COW_1(type, name, footprint, align)

  #define HAS_COW_0(type, name, footprint, align) \
    uchar name[footprint] __attribute__((aligned(align)));

  #define X(type, name, footprint, align, cow, limit_fork_width, has_lock) \
    HAS_COW_##cow(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1

  } non_cow;

  /* Now, layout all information needed for CoW fields. These are only
     copied when explicitly requested by the caller. The field's data
     is located at teh pool idx in the pool. If the dirty flag has been
     set, then the element has been copied over for this bank. */

  int epoch_rewards_dirty;
  ulong epoch_rewards_pool_idx;
  ulong epoch_rewards_pool_offset;
  ulong epoch_rewards_pool_lock_offset;

  int epoch_leaders_dirty;
  ulong epoch_leaders_pool_idx;
  ulong epoch_leaders_pool_offset;
  ulong epoch_leaders_pool_lock_offset;

  int vote_states_dirty;
  ulong vote_states_pool_idx;
  ulong vote_states_pool_offset;
  ulong vote_states_pool_lock_offset;

  int vote_states_prev_dirty;
  ulong vote_states_prev_pool_idx;
  ulong vote_states_prev_pool_offset;
  ulong vote_states_prev_pool_lock_offset;

  int vote_states_prev_prev_dirty;
  ulong vote_states_prev_prev_pool_idx;
  ulong vote_states_prev_prev_pool_offset;
  ulong vote_states_prev_prev_pool_lock_offset;

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

};
typedef struct fd_bank fd_bank_t;

static inline void
fd_bank_set_epoch_rewards_pool( fd_bank_t * bank, fd_bank_epoch_rewards_t * epoch_rewards_pool ) {
  void * epoch_rewards_pool_mem = fd_bank_epoch_rewards_pool_leave( epoch_rewards_pool );
  if( FD_UNLIKELY( !epoch_rewards_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave epoch rewards pool" ));
  }
  bank->epoch_rewards_pool_offset = (ulong)epoch_rewards_pool_mem - (ulong)bank;
}

static inline fd_bank_epoch_rewards_t *
fd_bank_get_epoch_rewards_pool( fd_bank_t * bank ) {
  return fd_bank_epoch_rewards_pool_join( (uchar *)bank + bank->epoch_rewards_pool_offset );
}

static inline void
fd_bank_set_epoch_rewards_pool_lock( fd_bank_t * bank, fd_rwlock_t * rwlock ) {
  bank->epoch_rewards_pool_lock_offset = (ulong)rwlock - (ulong)bank;
}

static inline fd_rwlock_t *
fd_bank_get_epoch_rewards_pool_lock( fd_bank_t * bank ) {
  return (fd_rwlock_t *)( (uchar *)bank + bank->epoch_rewards_pool_lock_offset );
}

static inline void
fd_bank_set_epoch_leaders_pool( fd_bank_t * bank, fd_bank_epoch_leaders_t * epoch_leaders_pool ) {
  void * epoch_leaders_pool_mem = fd_bank_epoch_leaders_pool_leave( epoch_leaders_pool );
  if( FD_UNLIKELY( !epoch_leaders_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave epoch leaders pool" ));
  }
  bank->epoch_leaders_pool_offset = (ulong)epoch_leaders_pool_mem - (ulong)bank;
}

static inline fd_bank_epoch_leaders_t *
fd_bank_get_epoch_leaders_pool( fd_bank_t * bank ) {
  return fd_bank_epoch_leaders_pool_join( (uchar *)bank + bank->epoch_leaders_pool_offset );
}

static inline void
fd_bank_set_epoch_leaders_pool_lock( fd_bank_t * bank, fd_rwlock_t * rwlock ) {
  bank->epoch_leaders_pool_lock_offset = (ulong)rwlock - (ulong)bank;
}

static inline fd_rwlock_t *
fd_bank_get_epoch_leaders_pool_lock( fd_bank_t * bank ) {
  return (fd_rwlock_t *)( (uchar *)bank + bank->epoch_leaders_pool_lock_offset );
}

static inline void
fd_bank_set_vote_states_pool( fd_bank_t * bank, fd_bank_vote_states_t * vote_states_pool ) {
  void * vote_states_pool_mem = fd_bank_vote_states_pool_leave( vote_states_pool );
  if( FD_UNLIKELY( !vote_states_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave vote states pool" ));
  }
  bank->vote_states_pool_offset = (ulong)vote_states_pool_mem - (ulong)bank;
}

static inline fd_bank_vote_states_t *
fd_bank_get_vote_states_pool( fd_bank_t * bank ) {
  return fd_bank_vote_states_pool_join( (uchar *)bank + bank->vote_states_pool_offset );
}

static inline void
fd_bank_set_vote_states_pool_lock( fd_bank_t * bank, fd_rwlock_t * rwlock ) {
  bank->vote_states_pool_lock_offset = (ulong)rwlock - (ulong)bank;
}

static inline fd_rwlock_t *
fd_bank_get_vote_states_pool_lock( fd_bank_t * bank ) {
  return (fd_rwlock_t *)( (uchar *)bank + bank->vote_states_pool_lock_offset );
}

static inline void
fd_bank_set_vote_states_prev_pool( fd_bank_t * bank, fd_bank_vote_states_prev_t * vote_states_prev_pool ) {
  void * vote_states_prev_pool_mem = fd_bank_vote_states_prev_pool_leave( vote_states_prev_pool );
  if( FD_UNLIKELY( !vote_states_prev_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave vote states prev pool" ));
  }
  bank->vote_states_prev_pool_offset = (ulong)vote_states_prev_pool_mem - (ulong)bank;
}

static inline fd_bank_vote_states_prev_t *
fd_bank_get_vote_states_prev_pool( fd_bank_t * bank ) {
  return fd_bank_vote_states_prev_pool_join( (uchar *)bank + bank->vote_states_prev_pool_offset );
}

static inline void
fd_bank_set_vote_states_prev_pool_lock( fd_bank_t * bank, fd_rwlock_t * rwlock ) {
  bank->vote_states_prev_pool_lock_offset = (ulong)rwlock - (ulong)bank;
}

static inline fd_rwlock_t *
fd_bank_get_vote_states_prev_pool_lock( fd_bank_t * bank ) {
  return (fd_rwlock_t *)( (uchar *)bank + bank->vote_states_prev_pool_lock_offset );
}

static inline void
fd_bank_set_vote_states_prev_prev_pool( fd_bank_t * bank, fd_bank_vote_states_prev_prev_t * vote_states_prev_prev_pool ) {
  void * vote_states_prev_prev_pool_mem = fd_bank_vote_states_prev_prev_pool_leave( vote_states_prev_prev_pool );
  if( FD_UNLIKELY( !vote_states_prev_prev_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave vote states prev prev pool" ));
  }
  bank->vote_states_prev_prev_pool_offset = (ulong)vote_states_prev_prev_pool_mem - (ulong)bank;
}

static inline fd_bank_vote_states_prev_prev_t *
fd_bank_get_vote_states_prev_prev_pool( fd_bank_t * bank ) {
  return fd_bank_vote_states_prev_prev_pool_join( (uchar *)bank + bank->vote_states_prev_prev_pool_offset );
}

static inline void
fd_bank_set_vote_states_prev_prev_pool_lock( fd_bank_t * bank, fd_rwlock_t * rwlock ) {
  bank->vote_states_prev_prev_pool_lock_offset = (ulong)rwlock - (ulong)bank;
}

static inline fd_rwlock_t *
fd_bank_get_vote_states_prev_prev_pool_lock( fd_bank_t * bank ) {
  return (fd_rwlock_t *)( (uchar *)bank + bank->vote_states_prev_prev_pool_lock_offset );
}

/* Do the same setup for the cost tracker pool. */

static inline void
fd_bank_set_cost_tracker_pool( fd_bank_t * bank, fd_bank_cost_tracker_t * cost_tracker_pool ) {
  void * cost_tracker_pool_mem = fd_bank_cost_tracker_pool_leave( cost_tracker_pool );
  if( FD_UNLIKELY( !cost_tracker_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave cost tracker pool" ));
  }
  bank->cost_tracker_pool_offset = (ulong)cost_tracker_pool_mem - (ulong)bank;
}

static inline fd_bank_cost_tracker_t *
fd_bank_get_cost_tracker_pool( fd_bank_t * bank ) {
  return fd_bank_cost_tracker_pool_join( (uchar *)bank + bank->cost_tracker_pool_offset );
}

/* fd_bank_t is the alignment for the bank state. */

ulong
fd_bank_align( void );

/* fd_bank_t is the footprint for the bank state. This does NOT
   include the footprint for the CoW state. */

ulong
fd_bank_footprint( void );

/**********************************************************************/
/* fd_banks_t is the main struct used to manage the bank state.  It can
   be used to query/modify/clone/publish the bank state.

   fd_banks_t contains some metadata to a pool to manage the banks.
   It also contains pointers to the CoW pools.

   The data is laid out contiguously in memory starting from fd_banks_t;
   this can be seen in fd_banks_footprint(). */

#define POOL_NAME fd_banks_pool
#define POOL_T    fd_bank_t
#include "../../util/tmpl/fd_pool.c"

struct fd_banks {
  ulong       magic;           /* ==FD_BANKS_MAGIC */
  ulong       max_total_banks; /* Maximum number of banks */
  ulong       max_fork_width;  /* Maximum fork width executing through
                                  any given slot. */
  ulong       root_idx;        /* root idx */
  ulong       bank_seq;        /* app-wide bank sequence number */

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

  ulong       cost_tracker_pool_offset; /* offset of cost tracker pool from banks */

  ulong       vote_states_pool_offset_;

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

  ulong epoch_rewards_pool_offset;
  fd_rwlock_t epoch_rewards_pool_lock;

  ulong epoch_leaders_pool_offset;
  fd_rwlock_t epoch_leaders_pool_lock;

  ulong vote_states_pool_offset;
  fd_rwlock_t vote_states_pool_lock;

  ulong vote_states_prev_pool_offset;
  fd_rwlock_t vote_states_prev_pool_lock;

  ulong vote_states_prev_prev_pool_offset;
  fd_rwlock_t vote_states_prev_prev_pool_lock;
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

/* Define accessor and mutator functions for the non-templatized
   fields. */

static inline fd_cost_tracker_t *
fd_bank_cost_tracker_locking_modify( fd_bank_t * bank ) {
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_bank_get_cost_tracker_pool( bank );
  FD_TEST( bank->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) );
  uchar * cost_tracker_mem = fd_bank_cost_tracker_pool_ele( cost_tracker_pool, bank->cost_tracker_pool_idx )->data;
  FD_TEST( cost_tracker_mem );
  fd_rwlock_write( &bank->cost_tracker_lock );
  return fd_type_pun( cost_tracker_mem );
}

static inline void
fd_bank_cost_tracker_end_locking_modify( fd_bank_t * bank ) {
  fd_rwlock_unwrite( &bank->cost_tracker_lock );
}

static inline fd_cost_tracker_t const *
fd_bank_cost_tracker_locking_query( fd_bank_t * bank ) {
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_bank_get_cost_tracker_pool( bank );
  FD_TEST( bank->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) );
  uchar * cost_tracker_mem = fd_bank_cost_tracker_pool_ele( cost_tracker_pool, bank->cost_tracker_pool_idx )->data;
  FD_TEST( cost_tracker_mem );
  fd_rwlock_read( &bank->cost_tracker_lock );
  return fd_type_pun_const( cost_tracker_mem );
}

static inline void
fd_bank_cost_tracker_end_locking_query( fd_bank_t * bank ) {
  fd_rwlock_unread( &bank->cost_tracker_lock );
}

#undef HAS_LOCK_0
#undef HAS_LOCK_1

/* Each bank has a fd_stake_delegations_t object which is delta-based.
   The usage pattern is the same as other bank fields:
   1. fd_bank_stake_delegations_delta_locking_modify( bank ) will return
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
    fd_stake_delegations_init( fd_type_pun( bank->stake_delegations_delta ) );
  }
  return fd_type_pun( bank->stake_delegations_delta );
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

/* Simple getters and setters for the pools/maps in fd_banks_t.  Notably,
   the pool for the fd_bank_t structs as well as a map and pool pair of
   the CoW structs in the banks. */

static inline fd_bank_t *
fd_banks_get_bank_pool( fd_banks_t const * banks ) {
  return fd_banks_pool_join( ((uchar *)banks + banks->pool_offset) );
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

static inline fd_bank_epoch_rewards_t *
fd_banks_get_epoch_rewards_pool( fd_banks_t * banks ) {
  return fd_bank_epoch_rewards_pool_join( (uchar *)banks + banks->epoch_rewards_pool_offset );
}

static inline void
fd_banks_set_epoch_rewards_pool( fd_banks_t * banks, fd_bank_epoch_rewards_t * epoch_rewards_pool ) {
  void * epoch_rewards_pool_mem = fd_bank_epoch_rewards_pool_leave( epoch_rewards_pool );
  if( FD_UNLIKELY( !epoch_rewards_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave epoch rewards pool" ));
  }
  banks->epoch_rewards_pool_offset = (ulong)epoch_rewards_pool_mem - (ulong)banks;
}

static inline fd_bank_epoch_leaders_t *
fd_banks_get_epoch_leaders_pool( fd_banks_t * banks ) {
  return fd_bank_epoch_leaders_pool_join( (uchar *)banks + banks->epoch_leaders_pool_offset );
}

static inline void
fd_banks_set_epoch_leaders_pool( fd_banks_t * banks, fd_bank_epoch_leaders_t * epoch_leaders_pool ) {
  void * epoch_leaders_pool_mem = fd_bank_epoch_leaders_pool_leave( epoch_leaders_pool );
  if( FD_UNLIKELY( !epoch_leaders_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave epoch leaders pool" ));
  }
  banks->epoch_leaders_pool_offset = (ulong)epoch_leaders_pool_mem - (ulong)banks;
}

static inline fd_bank_vote_states_t *
fd_banks_get_vote_states_pool( fd_banks_t * banks ) {
  return fd_bank_vote_states_pool_join( (uchar *)banks + banks->vote_states_pool_offset );
}

static inline void
fd_banks_set_vote_states_pool( fd_banks_t * banks, fd_bank_vote_states_t * vote_states_pool ) {
  void * vote_states_pool_mem = fd_bank_vote_states_pool_leave( vote_states_pool );
  if( FD_UNLIKELY( !vote_states_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave vote states pool" ));
  }
  banks->vote_states_pool_offset = (ulong)vote_states_pool_mem - (ulong)banks;
}

static inline fd_bank_vote_states_prev_t *
fd_banks_get_vote_states_prev_pool( fd_banks_t * banks ) {
  return fd_bank_vote_states_prev_pool_join( (uchar *)banks + banks->vote_states_prev_pool_offset );
}

static inline void
fd_banks_set_vote_states_prev_pool( fd_banks_t * banks, fd_bank_vote_states_prev_t * vote_states_prev_pool ) {
  void * vote_states_prev_pool_mem = fd_bank_vote_states_prev_pool_leave( vote_states_prev_pool );
  if( FD_UNLIKELY( !vote_states_prev_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave vote states prev pool" ));
  }
  banks->vote_states_prev_pool_offset = (ulong)vote_states_prev_pool_mem - (ulong)banks;
}

static inline fd_bank_vote_states_prev_prev_t *
fd_banks_get_vote_states_prev_prev_pool( fd_banks_t * banks ) {
  return fd_bank_vote_states_prev_prev_pool_join( (uchar *)banks + banks->vote_states_prev_prev_pool_offset );
}

static inline void
fd_banks_set_vote_states_prev_prev_pool( fd_banks_t * banks, fd_bank_vote_states_prev_prev_t * vote_states_prev_prev_pool ) {
  void * vote_states_prev_prev_pool_mem = fd_bank_vote_states_prev_prev_pool_leave( vote_states_prev_prev_pool );
  if( FD_UNLIKELY( !vote_states_prev_prev_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave vote states prev prev pool" ));
  }
  banks->vote_states_prev_prev_pool_offset = (ulong)vote_states_prev_prev_pool_mem - (ulong)banks;
}

static inline fd_bank_cost_tracker_t *
fd_banks_get_cost_tracker_pool( fd_banks_t * banks ) {
  return fd_bank_cost_tracker_pool_join( (uchar *)banks + banks->cost_tracker_pool_offset );
}

static inline void
fd_banks_set_cost_tracker_pool( fd_banks_t *             banks,
                                fd_bank_cost_tracker_t * cost_tracker_pool ) {
  void * cost_tracker_pool_mem = fd_bank_cost_tracker_pool_leave( cost_tracker_pool );
  if( FD_UNLIKELY( !cost_tracker_pool_mem ) ) {
    FD_LOG_CRIT(( "Failed to leave cost tracker pool" ));
  }
  banks->cost_tracker_pool_offset = (ulong)cost_tracker_pool_mem - (ulong)banks;
}

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
              ulong  max_fork_width,
              int    larger_max_cost_per_block,
              ulong  seed );

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
   fd_bank_t with the corresponding bank index set to 0. */

fd_bank_t *
fd_banks_init_bank( fd_banks_t * banks );

/* fd_banks_get_bank_idx returns a bank for a given bank index. */

static inline fd_bank_t *
fd_banks_bank_mem_query( fd_banks_t * banks,
                         ulong        bank_idx ) {
  return fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank_idx );
}

static inline fd_bank_t *
fd_banks_bank_query( fd_banks_t * banks,
                     ulong        bank_idx ) {
  fd_bank_t * bank = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank_idx );
  return (bank->flags&FD_BANK_FLAGS_INIT) ? bank : NULL;
}

static inline fd_bank_t *
fd_banks_get_parent( fd_banks_t * banks,
                     fd_bank_t *  bank ) {
  return fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank->parent_idx );
}

/* fd_banks_clone_from_parent() clones a bank from a parent bank.
   This function links the child bank to its parent bank and copies
   over the data from the parent bank to the child.  This function
   assumes that the child and parent banks both have been allocated.
   The parent bank must be frozen and the child bank must be initialized
   but not yet used.

   A more detailed note: not all of the data is copied over and this
   is a shallow clone.  All of the CoW fields are not copied over and
   will only be done so if the caller explicitly calls
   fd_bank_{*}_modify().  This naming was chosen to emulate the
   semantics of the Agave client. */

fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t * banks,
                            ulong        bank_idx,
                            ulong        parent_bank_idx );

/* fd_banks_advance_root() advances the root bank to the bank manager.
   This should only be used when a bank is no longer needed and has no
   active refcnts.  This will prune off the bank from the bank manager.
   It returns the new root bank.  An invariant of this function is that
   the new root bank should be a child of the current root bank.

   All banks that are ancestors or siblings of the new root bank will be
   cancelled and their resources will be released back to the pool. */

fd_bank_t const *
fd_banks_advance_root( fd_banks_t * banks,
                       ulong        bank_idx );

/* fd_bank_clear_bank() clears the contents of a bank. This should ONLY
   be used with banks that have no children and should only be used in
   testing and fuzzing.

   This function will memset all non-CoW fields to 0.

   For all CoW fields, we will reset the indices to its parent. */

void
fd_banks_clear_bank( fd_banks_t * banks,
                     fd_bank_t *  bank );

/* fd_banks_advance_root_prepare returns the highest block that can be
   safely advanced between the current root of the fork tree and the
   target block.  See the note on safe publishing for more details.  In
   general, a node in the fork tree can be pruned if:
   (1) the node itself can be pruned, and
   (2) all subtrees (except for the one on the rooted fork) forking off
       of the node can be pruned.
   The highest publishable block is the highest block on the rooted fork
   where the above is true, or the rooted child block of such if there
   is one.

   This function assumes that the given target block has been rooted by
   consensus.  It will mark every block on the rooted fork as rooted, up
   to the given target block.  It will also mark minority forks as dead.

   Highest advanceable block is written to the out pointer.  Returns 1
   if the advanceable block can be advanced beyond the current root.
   Returns 0 if no such block can be found.  We will ONLY advance our
   advanceable_bank_idx to a child of the current root.  In order to
   advance to the target bank, fd_banks_advance_root_prepare() must be
   called repeatedly. */

int
fd_banks_advance_root_prepare( fd_banks_t * banks,
                               ulong        target_bank_idx,
                               ulong *      advanceable_bank_idx_out );

/* fd_banks_mark_bank_dead marks the current bank (and all of its
   descendants) as dead.  The caller is still responsible for handling
   the behavior of the dead bank correctly. */

void
fd_banks_mark_bank_dead( fd_banks_t * banks,
                         fd_bank_t *  bank );

/* fd_banks_mark_bank_frozen marks the current bank as frozen.  This
   should be done when the bank is no longer being updated: it should be
   done at the end of a slot.  This also releases the memory for the
   cost tracker which only has to be persisted from the start of a slot
   to the end. */

void
fd_banks_mark_bank_frozen( fd_banks_t * banks,
                           fd_bank_t *  bank );

/* fd_banks_new_bank reserves a bank index for a new bank.  New bank
   indicies should always be available.  After this function is called,
   the bank will be linked to its parent bank, but not yet replayable.
   After a call to fd_banks_clone_from_parent, the bank will be
   replayable.  This assumes that there is a parent bank which exists
   and the there are available bank indices in the bank pool. */

fd_bank_t *
fd_banks_new_bank( fd_banks_t * banks,
                   ulong        parent_bank_idx,
                   long         now );


/* fd_banks_is_full returns 1 if the banks are full, 0 otherwise. */

static inline int
fd_banks_is_full( fd_banks_t * banks ) {
  return fd_banks_pool_free( fd_banks_get_bank_pool( banks ) )==0UL;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_h */
