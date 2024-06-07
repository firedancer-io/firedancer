#ifndef HEADER_fd_src_choreo_ghost_fd_ghost_h
#define HEADER_fd_src_choreo_ghost_fd_ghost_h

/* fd_ghost ("greedy heaviest-observed subtree") is an implementation of the fork choice protocol.
   It is latest message-driven (LMD) ie. only a validator's most recent vote counts toward the tree
   weights.

   greedy - pick the locally optimum subtree / fork right now, which may not be optimal later.
   heaviest - pick the fork with the most vote stake.
   observed - this is the validator's local view, and other validator's may have different trees.
   subtree - all descendant votes in a subtree are counted towards the ancestor.

   fd_ghost_node_t represents the n-ary tree of forks. Each node holds a pointer to the left-most
   child, and a pointer to siblings. The node also tracks the sum of stakes (stake) for that
   specific node as well as sum of stakes of the subtree rooted at that node (weight).

   fd_ghost_vote_t represents the latest message from a validator. Each message is keyed by the slot
   hash, which is the slot hash of the validator's vote, and also contains the validator's pubkey
   and stake.

   [1] GHOST paper: https://eprint.iacr.org/2013/881.pdf */

#include "../fd_choreo_base.h"

/* FD_GHOST_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_GHOST_USE_HANDHOLDING
#define FD_GHOST_USE_HANDHOLDING 1
#endif

/* clang-format off */
typedef struct fd_ghost_node fd_ghost_node_t;
struct __attribute__((aligned(128UL))) fd_ghost_node {
  fd_slot_hash_t    slot_hash;    /* (slot, bank_hash), also the ghost key */
  ulong             next;         /* reserved for internal use by fd_pool and fd_map_chain */
  ulong             weight;       /* sum of stake for the subtree rooted at this slot hash */
  ulong             stake;        /* vote stake for this slot hash (replay votes only) */
  ulong             gossip_stake; /* vote stake from gossip (sans replay overlap) for this slot hash */
  int               eqv;          /* flag for equivocation (multiple blocks) in this slot */
  int               eqv_safe;     /* flag for equivocation safety (ie. 52% of stake has voted for this slot hash) */
  int               opt_conf;     /* flag for optimistic confirmation (ie. 2/3 of stake has voted for this slot hash ) */
  fd_ghost_node_t * parent;       /* pointer to the parent */
  fd_ghost_node_t * child;        /* pointer to the left-most child */
  fd_ghost_node_t * sibling;      /* pointer to next sibling */
};

#define FD_GHOST_EQV_SAFE ( 0.52 )
#define FD_GHOST_OPT_CONF ( 2.0 / 3.0 )

/* fork a's weight > fork b's weight, with lower slot # as tie-break */
#define FD_GHOST_NODE_MAX(a,b) (fd_ptr_if(fd_int_if(a->weight==b->weight, a->slot_hash.slot<b->slot_hash.slot, a->weight>b->weight),a,b))
#define FD_GHOST_NODE_EQ(a,b)  (FD_SLOT_HASH_EQ(&a->slot_hash,&b->slot_hash))

#define POOL_NAME fd_ghost_node_pool
#define POOL_T    fd_ghost_node_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_ghost_node_map
#define MAP_ELE_T              fd_ghost_node_t
#define MAP_KEY                slot_hash
#define MAP_KEY_T              fd_slot_hash_t
#define MAP_KEY_EQ(k0,k1)      FD_SLOT_HASH_EQ(k0,k1)
#define MAP_KEY_HASH(key,seed) (key->slot^seed)
#include "../../util/tmpl/fd_map_chain.c"

struct fd_ghost_vote {
  fd_pubkey_t    pubkey;    /* validator's pubkey, also the map key */
  ulong          next;      /* reserved for internal use by fd_pool and fd_map_chain */
  fd_slot_hash_t slot_hash; /* slot hash being voted for */
  ulong          stake;     /* validator's stake */
};
typedef struct fd_ghost_vote fd_ghost_vote_t;

#define POOL_NAME fd_ghost_vote_pool
#define POOL_T    fd_ghost_vote_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_ghost_vote_map
#define MAP_ELE_T              fd_ghost_vote_t
#define MAP_KEY                pubkey
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_EQ(k0,k1)      (!(memcmp((k0)->hash,(k1)->hash,sizeof(fd_hash_t))))
#define MAP_KEY_HASH(key,seed) (key->ui[0]^seed)
#include "../../util/tmpl/fd_map_chain.c"

#define DEQUE_NAME fd_ghost_prune_deque
#define DEQUE_T    fd_ghost_node_t *
#include "../../util/tmpl/fd_deque_dynamic.c"

struct __attribute__((aligned(128UL))) fd_ghost {
  fd_ghost_node_t *     root;
  ulong                 total_stake; /* total amount of stake */

  fd_ghost_node_t *     node_pool; /* memory pool of ghost nodes */
  fd_ghost_node_map_t * node_map;  /* map of slot_hash->fd_ghost_node_t */
  fd_ghost_vote_t *     vote_pool; /* memory pool of ghost votes */
  fd_ghost_vote_map_t * vote_map;  /* each node's latest vote. map of pubkey->fd_ghost_vote_t */

  fd_ghost_node_t **    prune_deque;     /* deque reserved for BFS */
};
typedef struct fd_ghost fd_ghost_t;
/* clang-format on */

FD_PROTOTYPES_BEGIN

/* fd_ghost_{align,footprint} return the required alignment and footprint of a memory region
   suitable for use as ghost with up to node_max nodes and vote_max votes. */

FD_FN_CONST static inline ulong
fd_ghost_align( void ) {
  return alignof( fd_ghost_t );
}

FD_FN_CONST static inline ulong
fd_ghost_footprint( ulong node_max, ulong vote_max ) {
  return FD_LAYOUT_FINI(
      FD_LAYOUT_APPEND(
          FD_LAYOUT_APPEND(
              FD_LAYOUT_APPEND(
                  FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
                                                                        alignof( fd_ghost_t ),
                                                                        sizeof( fd_ghost_t ) ),
                                                      fd_ghost_node_pool_align(),
                                                      fd_ghost_node_pool_footprint( node_max ) ),
                                    fd_ghost_node_map_align(),
                                    fd_ghost_node_map_footprint( node_max ) ),
                  fd_ghost_vote_pool_align(),
                  fd_ghost_vote_pool_footprint( vote_max ) ),
              fd_ghost_vote_map_align(),
              fd_ghost_vote_map_footprint( vote_max ) ),
          fd_ghost_prune_deque_align(),
          fd_ghost_prune_deque_footprint( node_max ) ),
      //  sizeof( ulong ),
      //  sizeof( ulong ) * node_max ),
      alignof( fd_ghost_t ) );
}

/* fd_ghost_new formats an unused memory region for use as a ghost. mem is a non-NULL pointer to
   this region in the local address space with the required footprint and alignment. */

void *
fd_ghost_new( void * mem, ulong node_max, ulong vote_max, ulong seed );

/* fd_ghost_join joins the caller to the ghost. ghost points to the first byte of the memory region
   backing the ghost in the caller's address space.

   Returns a pointer in the local address space to ghost on success. */

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

/* fd_ghost_leaf_insert inserts a new leaf node with key into the ghost, with parent_slot_hash
   optionally specified. The caller promises the key is not currently in the map and that the
   parent_slot_hash, if specified, is in the map.

   There are three cases to consider:
      1. there is no parent, implying key is the root and the fork head.
      2. key is the only child of parent, implying key is the new fork head.
      2. key has siblings. Then, key is compared in stake (>), slot (<) priority
         respectively with its siblings, and the fork head is updated if the key has the
         highest priority.
*/

void
fd_ghost_node_insert( fd_ghost_t *           ghost,
                      fd_slot_hash_t const * slot_hash,
                      fd_slot_hash_t const * parent_slot_hash_opt );

/* fd_ghost_node_query finds the node corresponding to key. */

fd_ghost_node_t *
fd_ghost_node_query( fd_ghost_t * ghost, fd_slot_hash_t const * slot_hash );

/* fd_ghost_replay_vote_upsert updates or inserts pubkey's stake in ghost.

   The stake associated with pubkey is added to the ancestry chain beginning at slot hash
   ("insert"). If pubkey has previously voted, the previous vote's stake is removed from the
   previous vote slot hash's ancestry chain ("update").

   TODO the implementation can be made more efficient by short-circuiting and doing fewer
   traversals, but as it exists this is bounded to O(h), where h is the height of ghost.

   Note it is specific to the replay vote case that stake is propagated up the ancestry
   chain.
*/

void
fd_ghost_replay_vote( fd_ghost_t *           ghost,
                      fd_slot_hash_t const * slot_hash,
                      fd_pubkey_t const *    pubkey,
                      ulong                  stake );

/* fd_ghost_gossip_vote_upsert updates or inserts pubkey's stake in ghost.

   Unlike fd_ghost_replay_vote_upsert, the stake associated with pubkey is not propagated. It is
   only counted towards the individual slot hash voted for.
*/

void
fd_ghost_gossip_vote( fd_ghost_t *           ghost,
                      fd_slot_hash_t const * slot_hash,
                      fd_pubkey_t const *    pubkey,
                      ulong                  stake );

void
fd_ghost_prune( fd_ghost_t * ghost, fd_ghost_node_t const * root );

/* fd_ghost_print calls printf to generate a pretty-printed ghost. */

void
fd_ghost_print( fd_ghost_t const * ghost, fd_ghost_node_t const * root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_ghost_fd_ghost_h */
