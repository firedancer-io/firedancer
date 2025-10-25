#include "fd_ghost.h"

/* fd_ghost_vtr_t keeps track of what a voter's previously voted for. */

struct fd_ghost_vtr {
  fd_pubkey_t addr;          /* map key, vote account address */
  uint        hash;          /* reserved for fd_map_dynamic */
  ulong       prev_stake;    /* previous vote stake (vote can be from prior epoch) */
  ulong       prev_slot;     /* previous vote slot */
  fd_hash_t   prev_block_id; /* previous vote block_id  */
};
typedef struct fd_ghost_vtr fd_ghost_vtr_t;

#define POOL_NAME pool
#define POOL_T    fd_ghost_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               blk_map
#define MAP_ELE_T              fd_ghost_blk_t
#define MAP_KEY                id
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME              vtr_map
#define MAP_T                 fd_ghost_vtr_t
#define MAP_KEY               addr
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          pubkey_null
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key)     ((MAP_HASH_T)( (key).ul[1] ))
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_ghost_t is the top-level structure that holds the root of the
   tree, as well as the memory pools and map structures for tracking
   ghost eles and votes.

   These structures are bump-allocated and laid out contiguously in
   memory from the fd_ghost_t * pointer which points to the beginning of
   the memory region.

   ---------------------- <- fd_ghost_t *
   | root               |
   ----------------------
   | pool               |
   ----------------------
   | map                |
   ----------------------
   | bid                |
   ----------------------
   | vtr                |
   ---------------------- */

struct __attribute__((aligned(128UL))) fd_ghost {
  ulong            root;    /* pool idx of the root tree element */
  fd_ghost_blk_t * pool;    /* pool of tree elements (blocks) */
  blk_map_t *      blk_map; /* map of block_id->ghost_blk for fast O(1) querying */
  fd_ghost_vtr_t * vtr_map; /* map of pubkey->prior vote */
};
typedef struct fd_ghost fd_ghost_t;
