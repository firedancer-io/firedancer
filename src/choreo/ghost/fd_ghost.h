#ifndef HEADER_fd_src_choreo_ghost_fd_ghost_h
#define HEADER_fd_src_choreo_ghost_fd_ghost_h

/* fd_ghost implements Solana's LMD-GHOST ("latest message-driven greedy
   heaviest-observed subtree") fork choice rule.

   Protocol details:

   - LMD is an acronym for "latest message-driven". It denotes the
     specific flavor of GHOST implementation, ie. only a
     validator's latest vote counts.

   - GHOST is an acronym for "greedy heaviest-observed subtree":
     - greedy:   pick the locally optimal subtree / fork based on our
                 current view (which may not be globally optimal).
     - heaviest: pick based on the highest stake weight.
     - observed: this is the validator's local view, and other
                 validators may have differing views.
     - subtree:  pick a subtree, not an individual node.

   In-memory representation:

   - Each tree node is keyed by slot number.

   - Each tree node tracks the amount of stake (`stake`) that has voted
     for its slot, as well as the recursive sum of stake for the subtree
     rooted at that node (`weight`).

   Link to original GHOST paper: https://eprint.iacr.org/2013/881.pdf.
   This is simply a reference for those curious about the etymology, and
   not prerequisite reading for understanding this implementation. */

#include "../fd_choreo_base.h"
#include <stdbool.h>

/* FD_GHOST_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_GHOST_USE_HANDHOLDING
#define FD_GHOST_USE_HANDHOLDING 1
#endif

/* fd_ghost_node_t implements a left-child, right-sibling n-ary tree.
   Each node maintains the index of its left-most child (`child_idx`),
   its immediate-right sibling (`sibling_idx`), and its parent
   (`parent_idx`).  These indices are the pool indices from the
   `node_pool`. */

typedef struct fd_ghost_node fd_ghost_node_t;
struct __attribute__((aligned(128UL))) fd_ghost_node {
  ulong             slot;         /* slot this node is tracking, also the map key */
  ulong             next;         /* reserved for internal use by fd_pool and fd_map_chain */
  ulong             weight;       /* total stake from replay votes for this slot and descendants */
  ulong             replay_stake; /* total stake from replay votes for this slot */
  ulong             gossip_stake; /* total stake from gossip votes for this slot */
  ulong             rooted_stake; /* total stake that has rooted this slot */
  int               valid;        /* whether this node is valid for fork choice (fd_ghost_head) */
  ulong             parent_idx;   /* parent's node pool index */
  ulong             child_idx;    /* left-most child's node pool index */
  ulong             sibling_idx;  /* right sibling's node pool index */
};

#define FD_GHOST_EQV_SAFE ( 0.52 )
#define FD_GHOST_OPT_CONF ( 2.0 / 3.0 )

#define POOL_NAME fd_ghost_node_pool
#define POOL_T    fd_ghost_node_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_ghost_node_map
#define MAP_ELE_T fd_ghost_node_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

/* fd_ghost_vote_t represents a validator's vote.  This includes the
   slot being voted for, the validator's pubkey identity, and the
   validator's stake. */

struct fd_ghost_vote {
  fd_pubkey_t    pubkey; /* validator identity, also the map key */
  ulong          next;   /* reserved for internal use by fd_pool and fd_map_chain */
  ulong          slot;   /* latest vote slot */
  ulong          root;   /* latest root slot */
  ulong          stake;  /* validator's stake */
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

/* fd_ghost_t is the top-level structure that holds the root of the
   tree, as well as the memory pools and map structures for tracking
   ghost nodes and votes.

   These structures are bump-allocated and laid out contiguously in
   memory from the fd_ghost_t * pointer which points to the beginning of
   the memory region.

   ---------------------- <--- fd_ghost_t *
   | root | total_stake |
   ----------------------
   | node_pool          |
   ----------------------
   | node_map           |
   ----------------------
   | vote_pool          |
   ----------------------
   | vote_map           |
   ----------------------
*/

#define FD_GHOST_ALIGN (128UL)
#define FD_GHOST_MAGIC (0xf17eda2ce79205701UL) /* firedancer ghost version 1 */

struct __attribute__((aligned(FD_GHOST_ALIGN))) fd_ghost {

  /* Metadata */

  ulong magic;       /* ==FD_GHOST_MAGIC */
  ulong ghost_gaddr; /* wksp gaddr of this in the backing wksp, non-zero gaddr */
  ulong seed;        /* seed for various hashing function used under the hood, arbitrary */
  ulong root_idx;    /* node_pool idx of the root */
  ulong total_stake; /* total amount of stake */

  /* The ghost node_pool is a memory pool of tree nodes from which one
     is allocated for each slot.  The node map is a map_para to support
     fast, parallel O(1) querying of ghost nodes by slot. */

  ulong                 node_pool_gaddr;
  ulong                 node_map_gaddr;

   /* The ghost node_pool is a memory pool of tree nodes from which one
   is allocated for each slot.  The node map is a map_para to support
   fast, parallel O(1) querying of ghost nodes by slot. */

  ulong                 vote_pool_gaddr;
  ulong                 vote_map_gaddr;
};
typedef struct fd_ghost fd_ghost_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_ghost_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as ghost with up to
   node_max nodes and vote_max votes. */

FD_FN_CONST static inline ulong
fd_ghost_align( void ) {
  return alignof(fd_ghost_t);
}

FD_FN_CONST static inline ulong
fd_ghost_footprint( ulong node_max, ulong vote_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_ghost_t),        sizeof(fd_ghost_t) ),
      fd_ghost_node_pool_align(), fd_ghost_node_pool_footprint( node_max ) ),
      fd_ghost_node_map_align(),  fd_ghost_node_map_footprint( node_max ) ),
      fd_ghost_vote_pool_align(), fd_ghost_vote_pool_footprint( vote_max ) ),
      fd_ghost_vote_map_align(),  fd_ghost_vote_map_footprint( vote_max ) ),
    fd_ghost_align() );
}

/* fd_ghost_new formats an unused memory region for use as a ghost.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_ghost_new( void * mem, ulong node_max, ulong vote_max, ulong seed );

/* fd_ghost_join joins the caller to the ghost.  ghost points to the
   first byte of the memory region backing the ghost in the caller's
   address space.

   Returns a pointer in the local address space to ghost on success. */

fd_ghost_t *
fd_ghost_join( void * ghost );

/* fd_ghost_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include ghost is NULL. */

void *
fd_ghost_leave( fd_ghost_t const * ghost );

/* fd_ghost_delete unformats a memory region used as a ghost.
   Assumes only the nobody is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. ghost is obviously not a ghost ... logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_ghost_delete( void * ghost );

/* fd_ghost_init initializes a ghost.  Assumes ghost is a valid local
   join and no one else is joined.  root is the initial root ghost will
   use.  This is the snapshot slot if booting from a snapshot, 0 if the
   genesis slot.

   In general, this should be called by the same process that formatted
   ghost's memory, ie. the caller of fd_ghost_new. */

void
fd_ghost_init( fd_ghost_t * ghost, ulong root, ulong total_stake );

/* Accessors */

/* fd_funk_wksp returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

FD_FN_PURE static inline fd_wksp_t *
fd_ghost_wksp( fd_ghost_t const * ghost ) {
  return (fd_wksp_t *)( ( (ulong)ghost ) - ghost->ghost_gaddr );
}

FD_FN_PURE static inline fd_ghost_node_t *
fd_ghost_node_pool( fd_ghost_t const * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->node_pool_gaddr );
}

FD_FN_PURE static inline fd_ghost_node_map_t *
fd_ghost_node_map( fd_ghost_t const * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->node_map_gaddr );
}

FD_FN_PURE static inline fd_ghost_vote_t *
fd_ghost_vote_pool( fd_ghost_t const * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->vote_pool_gaddr );
}

FD_FN_PURE static inline fd_ghost_vote_map_t *
fd_ghost_vote_map( fd_ghost_t const * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->vote_map_gaddr );
}

FD_FN_PURE static inline fd_ghost_node_t const *
fd_ghost_root( fd_ghost_t const * ghost ) {
  return fd_ghost_node_pool_ele_const( fd_ghost_node_pool( ghost ), ghost->root_idx );
}

/* fd_ghost_child */

FD_FN_PURE static inline fd_ghost_node_t const *
fd_ghost_child( fd_ghost_t const * ghost, fd_ghost_node_t const * parent ) {
  return fd_ghost_node_pool_ele_const( fd_ghost_node_pool( ghost ), parent->child_idx );
}

FD_FN_PURE static inline fd_ghost_node_t const *
fd_ghost_query( fd_ghost_t const * ghost, ulong slot ) {
  fd_ghost_node_map_t * node_map = fd_ghost_node_map( ghost );
  fd_ghost_node_t * node_pool = fd_ghost_node_pool( ghost );
  return fd_ghost_node_map_ele_query_const( node_map, &slot, NULL, node_pool );
}

/* Operations */

bool
fd_ghost_verify( fd_ghost_t const * ghost );

/* fd_ghost_node_insert inserts a new node with slot as the key into the
   ghost.  Assumes slot >= ghost->smr, slot is not already in ghost,
   parent_slot is already in ghost, and the node pool has a free element
   (if handholding is enabled, explicitly checks and errors).  Returns
   the inserted ghost node. */

fd_ghost_node_t *
fd_ghost_insert( fd_ghost_t * ghost, ulong slot, ulong parent_slot );

/* fd_ghost_replay_vote votes for slot, adding pubkey's stake to the
   `stake` field for slot and to the `weight` field for both slot and
   slot's ancestors.  If pubkey has previously voted, pubkey's stake is
   also subtracted from `weight` for its previous vote slot and its
   ancestors.

   Assumes slot is present in ghost (if handholding is enabled,
   explicitly checks and errors).  Returns the ghost node keyed by slot.

   TODO the implementation can be made more efficient by
   short-circuiting and doing fewer traversals.  Currently this is
   bounded to O(h), where h is the height of ghost. */

fd_ghost_node_t const *
fd_ghost_replay_vote( fd_ghost_t * ghost, ulong slot, fd_pubkey_t const * pubkey, ulong stake );

/* fd_ghost_gossip_vote adds stake amount to the gossip_stake field of
   slot.

   Assumes slot is present in ghost (if handholding is enabled,
   explicitly checks and errors).  Returns the ghost node keyed by slot.

   Unlike fd_ghost_replay_vote, this stake is not propagated to
   the weight field for slot and slot's ancestors.  It is only counted
   towards slot itself, as gossip votes are only used for optimistic
   confirmation and not fork choice. */

fd_ghost_node_t const *
fd_ghost_gossip_vote( fd_ghost_t * ghost, ulong slot, fd_pubkey_t const * pubkey, ulong stake );

/* fd_ghost_rooted_vote adds stake amount to the rooted_stake field of
   slot.

   Assumes slot is present in ghost (if handholding is enabled,
   explicitly checks and errors).  Returns the ghost node keyed by slot.

   Note rooting a slot implies rooting its ancestor, but ghost does not
   explicitly track this. */

fd_ghost_node_t const *
fd_ghost_rooted_vote( fd_ghost_t * ghost, ulong slot, fd_pubkey_t const * pubkey, ulong stake );

/* fd_ghost_publish publishes slot as the new ghost root, setting the
   subtree beginning from slot as the new ghost tree (ie. slot and all
   its descendants).  Prunes all nodes not in slot's ancestry.  Assumes
   slot is present in ghost.  Returns the new root. */

fd_ghost_node_t const *
fd_ghost_publish( fd_ghost_t * ghost, ulong slot );

/* Traversals */

/* fd_ghost_gca returns the greatest common ancestor of slot1, slot2 in
   ghost.  Assumes slot1 or slot2 are present in ghost (warns and
   returns NULL with handholding enabled).  This is guaranteed to be
   non-NULL if slot1 and slot2 are both present. */

FD_FN_PURE fd_ghost_node_t const *
fd_ghost_gca( fd_ghost_t const * ghost, ulong slot1, ulong slot2 );

/* fd_ghost_head returns ghost's head.  Assumes caller has called
fd_ghost_init and that the ghost is non-empty, ie. has a root. */

FD_FN_PURE fd_ghost_node_t const *
fd_ghost_head( fd_ghost_t const * ghost );

/* fd_ghost_is_descendant returns 1 if `ancestor_slot` is an ancestor of
   `slot`, 0 otherwise.  Assumes slot is present in ghost (warns and
   returns 0 early if handholding is on).  Does not assume the same of
   ancestor_slot. */

FD_FN_PURE int
fd_ghost_is_ancestor( fd_ghost_t const * ghost, ulong slot, ulong ancestor_slot );

fd_ghost_node_t const *
fd_ghost_root( fd_ghost_t const * ghost );

fd_ghost_node_t const *
fd_ghost_child( fd_ghost_t const * ghost, fd_ghost_node_t const * parent );

/* Misc */

/* fd_ghost_slot_print pretty-prints a formatted ghost tree.  slot
   controls which slot to begin printing from (will appear as the root
   in the print output).  depth allows caller to specify additional
   ancestors to walk back from slot to set as the root.

   ghost->root->slot and 0 are valid defaults for the above,
   respectively.  In that case, this would print ghost beginning from
   the root.  See fd_ghost_print.

   Alternatively, caller can pass in the most recently executed slot,
   and pick an appropriate depth for visualization (20 is a reasonable
   default). */

void
fd_ghost_slot_print( fd_ghost_t * ghost, ulong slot, ulong depth );

/* fd_ghost_print pretty-prints a formatted ghost tree starting from the
   root using fd_ghost_slot_print. */

static inline void
fd_ghost_print( fd_ghost_t * ghost ) {
   fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->node_pool_gaddr );
   fd_ghost_node_t * root      = fd_ghost_node_pool_ele( node_pool, ghost->root_idx );
   fd_ghost_slot_print( ghost, root->slot, 0 );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_ghost_fd_ghost_h */
