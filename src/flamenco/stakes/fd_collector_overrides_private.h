#ifndef HEADER_fd_src_flamenco_stakes_fd_collector_overrides_private_h
#define HEADER_fd_src_flamenco_stakes_fd_collector_overrides_private_h

#include "fd_collector_overrides.h"
#include "../fd_rwlock.h"
#include "../../util/fd_hash32.h"

struct override_ele {
  fd_pubkey_t pubkey;
  ulong       epoch;
  fd_pubkey_t inflation; /* valid iff has_inflation */
  fd_pubkey_t block;     /* valid iff has_block */
  ulong       mask[2];   /* fork membership bits */
  uint        next;      /* pool / map chain */
  uint        prev_multi;
  uint        next_multi;
  uchar       has_inflation;
  uchar       has_block;
};
typedef struct override_ele override_ele_t;

#define POOL_NAME  override_pool
#define POOL_T     override_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           override_map
#define MAP_MULTI                          1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_KEY_T                          fd_pubkey_t
#define MAP_ELE_T                          override_ele_t
#define MAP_KEY                            pubkey
#define MAP_KEY_EQ(k0,k1)                  (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed)             (fd_hash32( key->uc, seed ))
#define MAP_PREV                           prev_multi
#define MAP_NEXT                           next_multi
#define MAP_IDX_T                          uint
#include "../../util/tmpl/fd_map_chain.c"

#define FD_COLLECTOR_OVERRIDES_MAGIC (0xF17EDA2CC011EC70UL) /* FIREDANCER COLLECTOR V0 */

struct fd_collector_overrides {
  ulong magic;
  ulong pool_off;
  ulong map_off;

  ulong         forks_used[2]; /* allocated fork id bits */
  atomic_ushort root_idx;

  fd_rwlock_t lock;
  ulong       ele_cnt;
};

#endif /* HEADER_fd_src_flamenco_stakes_fd_collector_overrides_private_h */
