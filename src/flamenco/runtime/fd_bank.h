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

   fd_banks_t also supports CoW semantics for more complex data
   structures which are not written to frequently. However, this is
   abstracted away from the caller who should only access/modify the
   fields using getters and setters: fd_bank_{*}_{query,modfiy}(). */

#define FD_BANK_BLOCK_HASH_QUEUE_SIZE (50000UL)

/* Use this to avoid code duplication */
#define FD_BANKS_COW_ITER(X)                                                                                                 \
  X(fd_clock_timestamp_votes_global_t, clock_timestamp_votes, 5000000UL,   128UL)  /* TODO: This needs to get sized out */   \
  X(fd_account_keys_global_t,          stake_account_keys,    100000000UL, 128UL)  /* Supports roughly 3M stake accounts */  \
  X(fd_account_keys_global_t,          vote_account_keys,     3200000UL,   128UL)  /* Supports roughly 100k vote accounts */

struct fd_bank {
  /* Fields used for internal pool and bank management */
  ulong             slot;        /* slot this node is tracking, also the map key */
  ulong             next;        /* reserved for internal use by fd_pool_para, fd_map_chain_para and fd_banks_publish */
  ulong             parent_idx;  /* index of the parent in the node pool */
  ulong             child_idx;   /* index of the left-child in the node pool */
  ulong             sibling_idx; /* index of the right-sibling in the node pool */


  /* Simple or frequently modified fields that are always copied over. */
  uchar                  block_hash_queue[FD_BANK_BLOCK_HASH_QUEUE_SIZE]__attribute__((aligned(128UL)));
  fd_fee_rate_governor_t fee_rate_governor;
  ulong                  capitalization;
  ulong                  lamports_per_signature;
  ulong                  prev_lamports_per_signature;
  ulong                  transaction_count;
  ulong                  parent_signature_cnt;
  ulong                  tick_height;
  ulong                  max_tick_height;
  ulong                  hashes_per_tick;
  uint128                ns_per_slot;
  ulong                  ticks_per_slot;
  ulong                  genesis_creation_time;
  double                 slots_per_year;
  fd_inflation_t         inflation;
  ulong                  total_epoch_stake;
  ulong                  eah_start_slot;
  ulong                  eah_stop_slot;
  ulong                  eah_interval;
  ulong                  block_height;
  fd_hash_t              epoch_account_hash;
  ulong                  execution_fees;
  ulong                  priority_fees;
  ulong                  signature_cnt;
  ulong                  use_prev_epoch_stake;
  fd_hash_t              poh;

  /* CoW Fields. These are only copied when explicitly requested by
     the caller. A lock is used to prevent contention between multiple
     threads trying to access the same field. These fields should NEVER
     be accessed directly and are just for internal use.. */

  #define X(type, name, footprint, align) \
  fd_rwlock_t name##_lock;                \
  int         name##_dirty;               \
  ulong       name##_pool_idx;            \

  FD_BANKS_COW_ITER(X)

  #undef X
};
typedef struct fd_bank fd_bank_t;

/* fd_bank_t is the alignment for the bank state. */

ulong
fd_bank_align( void );

/* fd_bank_t is the footprint for the bank state. This does NOT
   include the footprint for the CoW state. */

ulong
fd_bank_footprint( void );

/**********************************************************************/

/* CoW Pools used for complex data structures. The pool structs are
   just wrappers around aligned buffers. These should not be accessed
   directly and are just for itnernal use. */

#define X(type, name, footprint, align)                      \
  static const ulong fd_bank_##name##_align     = align;     \
  static const ulong fd_bank_##name##_footprint = footprint; \
                                                             \
  struct fd_bank_##name {                                    \
    ulong next;                                              \
    uchar data[footprint]__attribute__((aligned(align)));    \
  };                                                         \
  typedef struct fd_bank_##name fd_bank_##name##_t;
FD_BANKS_COW_ITER(X)
#undef X

/* All of the pools used by CoW. TODO: Is there a way to templatize
   this? */

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

  #define X(type, name, footprint, align) \
    fd_bank_##name##_t * name##_pool; /* local join of pool */
  FD_BANKS_COW_ITER(X)
  #undef X
};
typedef struct fd_banks fd_banks_t;

/* Bank accesssors */

#define X(type, name, footprint, align)                                  \
  type * fd_bank_##name##_query( fd_banks_t * banks, fd_bank_t * bank ); \
  type * fd_bank_##name##_modify( fd_banks_t * banks, fd_bank_t * bank );
FD_BANKS_COW_ITER(X)
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

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_mgr_h */
