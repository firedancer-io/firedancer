#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"

struct index_ele {
  fd_pubkey_t pubkey;
  ulong       epoch_stakes[ 2UL ];
  ushort      refcnt;
  ushort      next_evict;
  uint        next;
};
typedef struct index_ele index_ele_t;

#define POOL_NAME  index_pool
#define POOL_T     index_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               index_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              index_ele_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

/* We know we can fit 42k entries in this at any given point.
   TODO:FIXME: need to document this invariant very clearly. basically
   can only have ushort_max evictable entries between roots. Which is
   probably fine because if we root on avg every slot,  */
#define MAP_NAME               evict_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              index_ele_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next_evict
#define MAP_IDX_T              ushort
#include "../../util/tmpl/fd_map_chain.c"

/**********************************************************************/

struct snapshot_ele {
  ulong slot_age : 19;
  ulong timestamp : 45;
  uint idx;
  uint next;
};
typedef struct snapshot_ele snapshot_ele_t;

#define MAP_NAME               snapshot_map
#define MAP_KEY_T              uint
#define MAP_ELE_T              snapshot_ele_t
#define MAP_KEY                idx
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct snapshot_key {
  ushort fork_idx;
  uchar  prev;
  uchar  next;
  ulong  offset;
  ulong  map_offset;
};
typedef struct snapshot_key snapshot_key_ele_t;

#define DLIST_NAME  snapshot_key_dlist
#define DLIST_ELE_T snapshot_key_ele_t
#define DLIST_IDX_T uchar
#include "../../util/tmpl/fd_dlist.c"

#define POOL_NAME  snapshot_key_pool
#define POOL_T     snapshot_key_ele_t
#define POOL_IDX_T uchar
#include "../../util/tmpl/fd_pool.c"

/*********************************************************************/

/* TODO:FIXME: this can be improved almost defintely */

/* ts_est_ele_t is a temporary struct used for sorting vote accounts by
   last vote timestamp for clock sysvar calculation. */
   struct ts_est_ele {
    ulong       timestamp;
    fd_w_u128_t stake; /* should really be fine as ulong, but we match Agave */
  };
  typedef struct ts_est_ele ts_est_ele_t;

#define SORT_NAME  sort_stake_ts
#define SORT_KEY_T ts_est_ele_t
#define SORT_BEFORE(a,b) ( (a).timestamp < (b).timestamp )
#include "../../util/tmpl/fd_sort.c"

/* ***************************/

struct delta_ele {
  ulong timestamp;
  uint  pubkey_idx;
};
typedef struct delta_ele delta_ele_t;

struct fd_vote_timestamps {
  ulong  fork_pool_offset;

  ulong  index_pool_offset;
  ulong  index_map_offset;
  ulong  evict_map_offset;

  ushort root_idx;

  ulong  snapshot_max;
  ulong  snapshot_cnt;
  ulong  snapshot_keys_dlist_offset;
  ulong  snapshot_keys_pool_offset;

  ts_est_ele_t ts_eles[ 40200 ]; /* TODO:FIXME: this has to be configurable */
};
typedef struct fd_vote_timestamps fd_vote_timestamps_t;

struct fork_ele {
  ulong  slot;
  ushort epoch;
  /* left child, right sibling tree pointers */
  ushort parent_idx;
  ushort child_idx;
  ushort sibling_idx;
  ushort next;

  uchar  snapshot_idx;

  ushort deltas_cnt;
  /* TODO: Const for this or make it paramterizable */
  delta_ele_t deltas[ 42000UL ];
};
typedef struct fork_ele fork_ele_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_ele_t
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

static inline fork_ele_t *
fd_vote_timestamps_get_fork_pool( fd_vote_timestamps_t * vote_ts ) {
   return fd_type_pun( (uchar *)vote_ts + vote_ts->fork_pool_offset );
}

static inline index_ele_t *
fd_vote_timestamps_get_index_pool( fd_vote_timestamps_t * vote_ts ) {
  return fd_type_pun( (uchar *)vote_ts + vote_ts->index_pool_offset );
}

static inline index_map_t *
fd_vote_timestamps_get_index_map( fd_vote_timestamps_t * vote_ts ) {
  return fd_type_pun( (uchar *)vote_ts + vote_ts->index_map_offset );
}

static inline snapshot_key_dlist_t *
fd_vote_timestamps_get_snapshot_keys_dlist( fd_vote_timestamps_t * vote_ts ) {
  return fd_type_pun( (uchar *)vote_ts + vote_ts->snapshot_keys_dlist_offset );
}

static inline snapshot_key_ele_t *
fd_vote_timestamps_get_snapshot_keys_pool( fd_vote_timestamps_t * vote_ts ) {
  return fd_type_pun( (uchar *)vote_ts + vote_ts->snapshot_keys_pool_offset );
}

static inline evict_map_t *
fd_vote_timestamps_get_evict_map( fd_vote_timestamps_t * vote_ts ) {
  return fd_type_pun( (uchar *)vote_ts + vote_ts->evict_map_offset );
}

static inline snapshot_ele_t *
fd_vote_timestamps_get_snapshot( fd_vote_timestamps_t * vote_ts,
                                 uchar                  snapshot_idx ) {
  /* TODO:FIXME: this is pretty hacky. */
  snapshot_key_ele_t * snapshot_keys_pool = fd_vote_timestamps_get_snapshot_keys_pool( vote_ts );
  snapshot_key_ele_t * key                = snapshot_key_pool_ele( snapshot_keys_pool, snapshot_idx );
  return fd_type_pun( (uchar *)vote_ts + key->offset );
}

static inline snapshot_map_t *
fd_vote_timestamps_get_snapshot_map( fd_vote_timestamps_t * vote_ts,
                                         uchar                  snapshot_idx ) {
  snapshot_key_ele_t * snapshot_keys_pool = fd_vote_timestamps_get_snapshot_keys_pool( vote_ts );
  snapshot_key_ele_t * key                = snapshot_key_pool_ele( snapshot_keys_pool, snapshot_idx );
  return fd_type_pun( (uchar *)vote_ts + key->map_offset );
}
