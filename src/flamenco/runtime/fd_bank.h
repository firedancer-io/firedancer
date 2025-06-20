#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_h

#include "../fd_flamenco_base.h"

#include "../../ballet/lthash/fd_lthash.h"
#include "../../funk/fd_funk.h"

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../features/fd_features.h"
#include "../fd_rwlock.h"

FD_PROTOTYPES_BEGIN

#define FD_BANKS_MAGIC 0X99999AA9999UL

/* fd_bank_t and fd_banks_t are used to manage the bank state in a
   fork-aware manner. fd_banks_t can be queried to get the bank state
   for a given slot. This state can be cloned and modified from the
   state of some parent bank, but it can also be responsible for
   publishing the state to prune off rooted slots.

   The usage pattern is as follows:

   To create an initial bank:
   fd_bank_t * bank_init = fd_bank_init_bank( banks, slot );

   To clone bank from parent banks:
   fd_bank_t * bank_clone = fd_banks_clone_from_parent( banks, slot, parent_slot );

   To publish a bank (aka update the root bank):
   fd_bank_t * bank_publish = fd_banks_publish( banks, slot );

   To query some arbitrary bank:
   fd_bank_t * bank_query = fd_banks_get_bank( banks, slot );

   To query a field in the bank:
   fd_struct_t * field = fd_bank_field_query( bank );
   ... do the read ...
   fd_bank_field_end_query( bank );

   To modify a field in the bank:
   fd_struct_t * field = fd_bank_field_modify( bank );
   ... do the read/write ...
   fd_bank_field_end_modify( bank );

   fd_banks_t also supports CoW semantics for more complex data
   structures which are not written to frequently. However, this is
   abstracted away from the caller who should only access/modify the
   fields using getters and setters: fd_bank_{*}_{query,modfiy}().

   As a note, the end_query() and end_modify() calls are not required
   if a field doesn't use RW-locks. */


/* Define additional fields to the bank struct here. */

#define FD_BANKS_ITER(X)                                                                                                                                                                    \
  /* type,                             name,                        footprint,                                 align,                                      CoW, has lock */                                       \
  X(fd_clock_timestamp_votes_global_t, clock_timestamp_votes,       5000000UL,                                 128UL,                                      1,   1    )  /* TODO: This needs to get sized out */   \
  X(fd_account_keys_global_t,          stake_account_keys,          100000000UL,                               128UL,                                      1,   1    )  /* Supports roughly 3M stake accounts */  \
  X(fd_account_keys_global_t,          vote_account_keys,           3200000UL,                                 128UL,                                      1,   1    )  /* Supports roughly 100k vote accounts */ \
  X(fd_rent_fresh_accounts_global_t,   rent_fresh_accounts,         50000UL,                                   128UL,                                      1,   1    )  /* Rent fresh accounts */                 \
  X(fd_block_hash_queue_global_t,      block_hash_queue,            50000UL,                                   128UL,                                      0,   0    )  /* Block hash queue */                    \
  X(fd_fee_rate_governor_t,            fee_rate_governor,           sizeof(fd_fee_rate_governor_t),            alignof(fd_fee_rate_governor_t),            0,   0    )  /* Fee rate governor */                   \
  X(ulong,                             capitalization,              sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Capitalization */                      \
  X(ulong,                             lamports_per_signature,      sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Lamports per signature */              \
  X(ulong,                             prev_lamports_per_signature, sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Previous lamports per signature */     \
  X(ulong,                             transaction_count,           sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Transaction count */                   \
  X(ulong,                             parent_signature_cnt,        sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Parent signature count */              \
  X(ulong,                             tick_height,                 sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Tick height */                         \
  X(ulong,                             max_tick_height,             sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Max tick height */ \
  X(ulong,                             hashes_per_tick,             sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Hashes per tick */ \
  X(uint128,                           ns_per_slot,                 sizeof(uint128),                           alignof(uint128),                           0,   0    )  /* NS per slot */ \
  X(ulong,                             ticks_per_slot,              sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Ticks per slot */ \
  X(ulong,                             genesis_creation_time,       sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Genesis creation time */ \
  X(double,                            slots_per_year,              sizeof(double),                            alignof(double),                            0,   0    )  /* Slots per year */ \
  X(fd_inflation_t,                    inflation,                   sizeof(fd_inflation_t),                    alignof(fd_inflation_t),                    0,   0    )  /* Inflation */ \
  X(ulong,                             total_epoch_stake,           sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Total epoch stake */ \
  X(ulong,                             eah_start_slot,              sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* EAH start slot */ \
  X(ulong,                             eah_stop_slot,               sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* EAH stop slot */ \
  X(ulong,                             eah_interval,                sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* EAH interval */ \
  X(ulong,                             block_height,                sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Block height */ \
  X(fd_hash_t,                         epoch_account_hash,          sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* Epoch account hash */ \
  X(ulong,                             execution_fees,              sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Execution fees */ \
  X(ulong,                             priority_fees,               sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Priority fees */ \
  X(ulong,                             signature_count,             sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Signature count */ \
  X(ulong,                             use_prev_epoch_stake,        sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Use prev epoch stake */ \
  X(fd_hash_t,                         poh,                         sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* PoH */ \
  X(fd_sol_sysvar_last_restart_slot_t, last_restart_slot,           sizeof(fd_sol_sysvar_last_restart_slot_t), alignof(fd_sol_sysvar_last_restart_slot_t), 0,   0    )  /* Last restart slot */ \
  X(fd_cluster_version_t,              cluster_version,             sizeof(fd_cluster_version_t),              alignof(fd_cluster_version_t),              0,   0    )  /* Cluster version */ \
  X(ulong,                             prev_slot,                   sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Previous slot */ \
  X(fd_hash_t,                         bank_hash,                   sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* Bank hash */ \
  X(fd_hash_t,                         prev_bank_hash,              sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* Previous bank hash */ \
  X(fd_hash_t,                         genesis_hash,                sizeof(fd_hash_t),                         alignof(fd_hash_t),                         0,   0    )  /* Genesis hash */ \
  X(fd_epoch_schedule_t,               epoch_schedule,              sizeof(fd_epoch_schedule_t),               alignof(fd_epoch_schedule_t),               0,   0    )  /* Epoch schedule */ \
  X(fd_rent_t,                         rent,                        sizeof(fd_rent_t),                         alignof(fd_rent_t),                         0,   0    )  /* Rent */ \
  X(fd_slot_lthash_t,                  lthash,                      sizeof(fd_slot_lthash_t),                  alignof(fd_slot_lthash_t),                  0,   0    )  /* LTHash */ \
  X(fd_vote_accounts_global_t,         next_epoch_stakes,           200000000UL,                               128UL,                                      1,   1    )  /* Next epoch stakes, ~4K per account * 50k vote accounts */ \
  X(fd_vote_accounts_global_t,         epoch_stakes,                200000000UL,                               128UL,                                      1,   1    )  /* Epoch stakes ~4K per account * 50k vote accounts */ \
  X(fd_epoch_reward_status_global_t,   epoch_reward_status,         160000000UL,                               128UL,                                      1,   1    )  /* Epoch reward status */ \
  X(fd_epoch_leaders_t,                epoch_leaders,               1000000UL,                                 128UL,                                      1,   1    )  /* Epoch leaders */ \
  X(fd_stakes_global_t,                stakes,                      400000000UL,                               128UL,                                      1,   1    )  /* Stakes */ \
  X(fd_features_t,                     features,                    sizeof(fd_features_t),                     alignof(fd_features_t),                     0,   0    )  /* Features */ \
  X(ulong,                             txn_count,                   sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Transaction count */ \
  X(ulong,                             nonvote_txn_count,           sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Nonvote transaction count */ \
  X(ulong,                             failed_txn_count,            sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Failed transaction count */ \
  X(ulong,                             nonvote_failed_txn_count,    sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Nonvote failed transaction count */ \
  X(ulong,                             total_compute_units_used,    sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Total compute units used */ \
  X(ulong,                             part_width,                  sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Part width */ \
  X(ulong,                             slots_per_epoch,             sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Slots per epoch */ \
  X(ulong,                             shred_cnt,                   sizeof(ulong),                             alignof(ulong),                             0,   0    )  /* Shred count */

/* If a member of the bank is CoW then it needs a corresponding pool
   which is defined here. If a type if not a CoW then it does not need
   to be in a pool and is laid out contigiously in the bank struct.
   TODO: Is there a way to templatize the pool definitions? */

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

#define POOL_NAME fd_bank_rent_fresh_accounts_pool
#define POOL_T    fd_bank_rent_fresh_accounts_t
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

#define POOL_NAME fd_bank_epoch_reward_status_pool
#define POOL_T    fd_bank_epoch_reward_status_t
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

struct fd_bank {
  /* Fields used for internal pool and bank management */
  ulong             slot;        /* slot this node is tracking, also the map key */
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
    fd_bank_##name##_t * name##_pool;

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

/* TODO: Document this. */
#define FD_BANK_HEADER_SIZE (40UL)

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
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"
#undef MAP_NAME
#undef MAP_ELE_T
#undef MAP_KEY

struct fd_banks {
  ulong             magic;     /* ==FD_BANKS_MAGIC */
  ulong             max_banks; /* Maximum number of banks */
  ulong             root;      /* root slot */
  ulong             root_idx;  /* root idx */

  fd_bank_t *       pool; /* local join of pool */
  fd_banks_map_t *  map;  /* local join of map */

  /* Layout all CoW pools. */

  #define HAS_COW_1(type, name, footprint, align) \
    fd_bank_##name##_t * name##_pool; /* local join of pool */

  #define HAS_COW_0(type, name, footprint, align) /* Do nothing for these. */

  #define X(type, name, footprint, align, cow, has_lock) \
    HAS_COW_##cow(type, name, footprint, align)
  FD_BANKS_ITER(X)
  #undef X
  #undef HAS_COW_0
  #undef HAS_COW_1
};
typedef struct fd_banks fd_banks_t;

/* Bank accesssors */

#define X(type, name, footprint, align, cow, has_lock)       \
  type const * fd_bank_##name##_query( fd_bank_t * bank );   \
  void fd_bank_##name##_end_query( fd_bank_t * bank );       \
  type * fd_bank_##name##_modify( fd_bank_t * bank );        \
  void fd_bank_##name##_end_modify( fd_bank_t * bank );      \
  void fd_bank_##name##_set( fd_bank_t * bank, type value ); \
  type fd_bank_##name##_get( fd_bank_t * bank );
FD_BANKS_ITER(X)
#undef X

/* fd_banks_root reutrns the current root slot for the bank/ */

FD_FN_PURE static inline fd_bank_t const *
fd_banks_root( fd_banks_t const * banks ) {
  return fd_banks_pool_ele_const( banks->pool, banks->root_idx );
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

/* TODO: Add a fd_banks_leave()/fd_banks_delete(). */

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

   A more detailed note: not all of the data is copied over. All of the
   CoW fields are not copied over and will only be done so if
   the caller explicitly calls fd_bank_{*}_modify(). */

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_h */
