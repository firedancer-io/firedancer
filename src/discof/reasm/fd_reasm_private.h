#include "fd_reasm.h"

#define POOL_NAME              pool
#define POOL_T                 fd_reasm_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               ancestry
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t))) /* FIXME keyspace partitioning */
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               frontier
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t))) /* FIXME keyspace partitioning */
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               orphaned
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t))) /* FIXME keyspace partitioning */
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               subtrees
#define MAP_ELE_T              fd_reasm_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t))) /* FIXME keyspace partitioning */
#include "../../util/tmpl/fd_map_chain.c"

#define DEQUE_NAME             bfs
#define DEQUE_T                ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

#define DEQUE_NAME             out
#define DEQUE_T                ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

typedef struct {
  ulong     slot;
  fd_hash_t block_id;
} slot_mr_t;

#define MAP_NAME         slot_mr
#define MAP_T            slot_mr_t
#define MAP_KEY          slot
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) ((k)==MAP_KEY_NULL)
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(128UL))) fd_reasm {
  ulong            root;     /* pool idx of the root FEC set */
  ulong            slot0;    /* special initialization slot. chains first FEC */
  fd_reasm_fec_t * pool;     /* pool of FEC nodes backing the above maps / tree */
  ancestry_t *     ancestry; /* map of mr->fec. non-leaves of the connected tree */
  frontier_t *     frontier; /* map of mr->fec. leaves of the connected tree */
  orphaned_t *     orphaned; /* map of mr->fec. non-roots of the orphaned subtrees */
  subtrees_t *     subtrees; /* map of mr->fec. roots of the orphaned subtrees */
  ulong *          bfs;      /* internal queue of pool idxs for BFS */
  ulong *          out;      /* delivery queue of pool idxs to output */
  slot_mr_t *      slot_mr;  /* map of slot->mr */
};
