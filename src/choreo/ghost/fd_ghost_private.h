#include "fd_ghost.h"

#define POOL_NAME blk_pool
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

#define POOL_NAME vtr_pool
#define POOL_T    fd_ghost_vtr_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               vtr_map
#define MAP_ELE_T              fd_ghost_vtr_t
#define MAP_KEY                addr
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

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
   | blk_map            |
   ----------------------
   | vtr_map            |
   ---------------------- */

struct __attribute__((aligned(128UL))) fd_ghost {
  ulong root;           /* pool idx of the root tree element */
  ulong ghost_gaddr;    /* memory offset of the beginning of ghost region in the wksp */
  ulong blk_pool_gaddr; /* memory offset of the blk_pool */
  ulong blk_map_gaddr;  /* memory offset of the blk_map */
  ulong vtr_pool_gaddr; /* memory offset of the vtr_pool */
  ulong vtr_map_gaddr;  /* memory offset of the vtr_map */
};
typedef struct fd_ghost fd_ghost_t;

typedef fd_ghost_blk_t blk_pool_t;
typedef fd_ghost_vtr_t vtr_pool_t;

static inline blk_pool_t *
blk_pool( fd_ghost_t * ghost ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  return (blk_pool_t *)fd_wksp_laddr_fast( wksp, ghost->blk_pool_gaddr );
}

static inline blk_pool_t const *
blk_pool_const( fd_ghost_t const * ghost ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  return (blk_pool_t const *)fd_wksp_laddr_fast( wksp, ghost->blk_pool_gaddr );
}

static inline blk_map_t *
blk_map( fd_ghost_t * ghost ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  return (blk_map_t *)fd_wksp_laddr_fast( wksp, ghost->blk_map_gaddr );
}

static inline blk_map_t const *
blk_map_const( fd_ghost_t const * ghost ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  return (blk_map_t const *)fd_wksp_laddr_fast( wksp, ghost->blk_map_gaddr );
}

static inline vtr_pool_t *
vtr_pool( fd_ghost_t * ghost ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  return (vtr_pool_t *)fd_wksp_laddr_fast( wksp, ghost->vtr_pool_gaddr );
}

static inline vtr_pool_t const *
vtr_pool_const( fd_ghost_t const * ghost ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  return (vtr_pool_t const *)fd_wksp_laddr_fast( wksp, ghost->vtr_pool_gaddr );
}

static inline vtr_map_t *
vtr_map( fd_ghost_t * ghost ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  return (vtr_map_t *)fd_wksp_laddr_fast( wksp, ghost->vtr_map_gaddr );
}

static inline vtr_map_t const *
vtr_map_const( fd_ghost_t const * ghost ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  return (vtr_map_t const *)fd_wksp_laddr_fast( wksp, ghost->vtr_map_gaddr );
}
