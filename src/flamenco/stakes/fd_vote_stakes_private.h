#ifndef HEADER_fd_src_flamenco_stakes_fd_vote_stakes_private_h
#define HEADER_fd_src_flamenco_stakes_fd_vote_stakes_private_h

#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"
#include "../fd_rwlock.h"

struct index_key {
  fd_pubkey_t pubkey;
  ulong       stake_t_1;
  ulong       stake_t_2;
};
typedef struct index_key index_key_t;

struct index_ele {
  union {
    struct {
      fd_pubkey_t pubkey;
      ulong       stake_t_1;
      ulong       stake_t_2;
    };
    index_key_t index_key;
  };
  fd_pubkey_t node_account_t_1;
  fd_pubkey_t node_account_t_2;
  uint        next;
  uint        prev_multi;
  uint        next_multi;
  ushort      refcnt;
  uchar       invalid;
};
typedef struct index_ele index_ele_t;

#define POOL_NAME  index_pool
#define POOL_T     index_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               index_map
#define MAP_KEY_T              index_key_t
#define MAP_ELE_T              index_ele_t
#define MAP_KEY                index_key
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(index_key_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(index_key_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME                           index_map_multi
#define MAP_MULTI                          1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_KEY_T                          fd_pubkey_t
#define MAP_ELE_T                          index_ele_t
#define MAP_KEY                            pubkey
#define MAP_KEY_EQ(k0,k1)                  (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed)             (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_PREV                           prev_multi
#define MAP_NEXT                           next_multi
#define MAP_IDX_T                          uint
#include "../../util/tmpl/fd_map_chain.c"

/* Each pool index is just an array of uint indices into the pool. */
struct stake {
  uint idx;
  uint next;
};
typedef struct stake stake_t;

#define POOL_NAME  stakes_pool
#define POOL_T     stake_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               stakes_map
#define MAP_KEY_T              uint
#define MAP_ELE_T              stake_t
#define MAP_KEY                idx
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct fork {
  ushort prev;
  ushort next;
};
typedef struct fork fork_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_t
#define POOL_NEXT  next
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fork_dlist
#define DLIST_ELE_T fork_t
#define DLIST_IDX_T ushort
#include "../../util/tmpl/fd_dlist.c"

#define FD_VOTE_STAKES_MAGIC (0xF17EDA2CE7601E71UL) /* FIREDANCER VOTER V1 */

#define MAX_FORK_WIDTH (128UL)

struct fd_vote_stakes {
  ulong magic;
  ulong index_pool_off;
  ulong index_map_off;
  ulong index_map_multi_off;

  ulong fork_pool_off;
  ulong fork_dlist_off;

  ulong  stakes_pool_off[ MAX_FORK_WIDTH ];
  ulong  stakes_map_off[ MAX_FORK_WIDTH ];

  stakes_map_iter_t fork_iter;

  ushort max_fork_width;
  ushort root_idx;
};
typedef struct fd_vote_stakes fd_vote_stakes_t;

static inline index_ele_t *
get_index_pool( fd_vote_stakes_t * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->index_pool_off );
}

static inline index_map_t *
get_index_map( fd_vote_stakes_t * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->index_map_off );
}

static inline index_map_multi_t *
get_index_map_multi( fd_vote_stakes_t * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->index_map_multi_off );
}

static inline stake_t *
get_stakes_pool( fd_vote_stakes_t * vote_stakes,
                 ushort             fork_idx ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->stakes_pool_off[ fork_idx ] );
}

static inline stakes_map_t *
get_stakes_map( fd_vote_stakes_t * vote_stakes,
                ushort             fork_idx ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->stakes_map_off[ fork_idx ] );
}

static inline fork_t *
get_fork_pool( fd_vote_stakes_t * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->fork_pool_off );
}

static inline fork_dlist_t *
get_fork_dlist( fd_vote_stakes_t * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->fork_dlist_off );
}

#endif /* HEADER_fd_src_flamenco_stakes_fd_vote_stakes_private_h */
