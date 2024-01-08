#ifndef HEADER_fd_src_choreo_ghost_fd_ghost_h
#define HEADER_fd_src_choreo_ghost_fd_ghost_h

/* fd_ghost ("greedy heaviest-observed subtree") is an implementation of the fork choice protocol.
   It is latest message-driven (LMD) ie. only a validator's last vote counts toward the tree
   weights.

   greedy - pick the locally optimum subtree / fork right now, which may not be optimal later.
   heaviest - pick the fork with the most vote stake.
   observed - this is the validator's local view, and other validator's may have different trees.
   subtree - all descendant votes in a subtree are counted towards the ancestor.

   fd_ghost_node_t represents the n-ary tree of forks. Each node holds a pointer to the left-most
   child, and a pointer to siblings. The node also tracks the sum of stakes (stake) for that
   specific node as well as sum of stakes of the subtree rooted at that node (weight).

   fd_ghost_msg_t represents the latest message from a validator. Each message is keyed by the slot
   hash, which is the slot hash of the validator's vote, and also contains the validator's pubkey
   and stake.

   [1] GHOST paper: https://eprint.iacr.org/2013/881.pdf */

#include "../fd_choreo_base.h"

#ifndef FD_GHOST_USE_HANDHOLDING
#define FD_GHOST_USE_HANDHOLDING 1
#endif

typedef struct fd_ghost_node fd_ghost_node_t;
struct __attribute__((aligned(128UL))) fd_ghost_node {
  fd_slot_hash_t    slot_hash; /* slot hash of the fork, also the map key */
  ulong             next;      /* reserved for internal use by fd_pool and fd_map_chain */
  ulong             stake;     /* total stake amount for this slot */
  ulong             weight;    /* total stake amount for the entire subtree  */
  fd_ghost_node_t * head;      /* the head of the fork i.e. leaf of the highest-weight subtree */
  fd_ghost_node_t * parent;    /* parent slot hash */
  fd_ghost_node_t * child;     /* pointer to the left-most child */
  fd_ghost_node_t * sibling;   /* pointer to next sibling */
};
#define FD_GHOST_NODE_MAX(a,b) (fd_ptr_if(fd_int_if(a->weight == b->weight, a->slot_hash.slot < b->slot_hash.slot, a->weight > b->weight), a, b))
#define FD_GHOST_NODE_EQ(a,b)  (FD_SLOT_HASH_EQ(&a->slot_hash, &b->slot_hash))

#define POOL_NAME fd_ghost_node_pool
#define POOL_T    fd_ghost_node_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_ghost_node_map
#define MAP_ELE_T              fd_ghost_node_t
#define MAP_KEY                slot_hash
#define MAP_KEY_T              fd_slot_hash_t
#define MAP_KEY_EQ(k0,k1)      FD_SLOT_HASH_EQ(k0,k1)
#define MAP_KEY_HASH(key,seed) (key->slot + seed)
#include "../../util/tmpl/fd_map_chain.c"

struct fd_ghost_msg {
  fd_pubkey_t    pubkey;    /* validator's pubkey, also the map key */
  uint           hash;      /* reserved for internal use by fd_map */
  fd_slot_hash_t slot_hash; /* slot hash being voted for */
  ulong          stake;     /* validator's stake */
};
typedef struct fd_ghost_msg fd_ghost_msg_t;
#define MAP_NAME              fd_ghost_msg_map
#define MAP_T                 fd_ghost_msg_t
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY               pubkey
#define MAP_KEY_NULL          pubkey_null
#define MAP_KEY_INVAL(k)      (!memcmp((k).key,pubkey_null.key,sizeof(fd_pubkey_t)))
#define MAP_KEY_EQUAL(k0,k1)  (!(memcmp((k0).key,(k1).key,sizeof(fd_hash_t))))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     (key.ui[0])
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_ghost {
  fd_slot_hash_t        root;        /* root slot */
  fd_ghost_node_t *     node_pool;   /* memory pool of ghost nodes */
  fd_ghost_node_map_t * node_map;    /* map of slot_hash->fd_ghost_node_t */
  fd_ghost_msg_t *      latest_msgs; /* map of pubkey->fd_ghost_msg_t */
};
typedef struct fd_ghost fd_ghost_t;
/* clang-format on */

FD_PROTOTYPES_BEGIN

/* fd_ghost_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as ghost with up to node_max
   nodes and 1 << lg_msg_max msgs. align returns FD_GHOST_ALIGN. */

FD_FN_CONST static inline ulong
fd_ghost_align( void ) {
  return alignof( fd_ghost_t );
}

FD_FN_CONST static inline ulong
fd_ghost_footprint( ulong node_max, int lg_msg_max ) {
  return sizeof( fd_slot_hash_t ) + fd_ghost_node_pool_footprint( node_max ) +
         fd_ghost_node_map_footprint( node_max ) + fd_ghost_msg_map_footprint( lg_msg_max );
}

/* fd_ghost_new formats an unused memory region for use as a ghost. mem is a non-NULL pointer to
   this region in the local address space with the required footprint and alignment.*/

void *
fd_ghost_new( void * mem, ulong node_max, int lg_msg_max, ulong seed );

/* fd_ghost_join joins the caller to the ghost. ghost points to the first byte of the memory region
   backing the ghost in the caller's address space.

   Returns a pointer in the local address space to the GHOST structure on success.

   The ghost is not inteded to be shared across multiple processes, and attempts to join from other
   processes will result in invalid pointers. */

fd_ghost_t *
fd_ghost_join( void * ghost );

/* fd_ghost_leave leaves a current local join. Returns a pointer to the underlying shared memory
   region on success and NULL on failure (logs details). Reasons for failure include ghost is NULL.
 */

void *
fd_ghost_leave( fd_ghost_t const * ghost );

/* fd_ghost_delete unformats a memory region used as a ghost. Assumes only the local process is
   joined to the region. Returns a pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. ghost is obviously not a ghost ... logs details). The ownership of the
   memory region is transferred to the caller. */

void *
fd_ghost_delete( void * ghost );

/* fd_ghost_leaf_insert inserts a new leaf, and then updates the GHOST. Enumerated are the possible
   update cases:

   1. There is no parent, so the new leaf is the root.
   2. There is a parent with no children. The parent's head is this leaf.
   2. There is a parent with children. This leaf is compared in > stake, < slot priority,
   respectively with its siblings, and the head is updated if the leaf is has higher priority. */

void
fd_ghost_leaf_insert( fd_ghost_t *           ghost,
                      fd_slot_hash_t const * slot_hash,
                      fd_slot_hash_t const * parent_slot_hash );

/* fd_ghost_lmd_update updates the GHOST with the latest validator message. The message derives
   from the fields of a msg, and includes the slot hash being lmd for, the validator pubkey and the
   validator stake.

   The validator's stake is added to the subtree containing this slot hash. If the validator has
   previously lmd, then the validator's stake is also removed from the last msg's subtree and added
   to this msg's subtree. Note these two subtrees can be the same. */

void
fd_ghost_lmd_update( fd_ghost_t *           ghost,
                     fd_slot_hash_t const * slot_hash,
                     fd_pubkey_t const *    pubkey,
                     ulong                  stake );

/* fd_ghost_print prints a GHOST. */
void
fd_ghost_print( fd_ghost_t * ghost );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_ghost_fd_ghost_h */
