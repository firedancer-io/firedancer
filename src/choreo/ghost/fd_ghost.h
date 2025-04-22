#ifndef HEADER_fd_src_choreo_ghost_fd_ghost_h
#define HEADER_fd_src_choreo_ghost_fd_ghost_h

/* fd_ghost implements Solana's LMD-GHOST ("latest message-driven greedy
   heaviest-observed subtree") fork choice rule.

   Protocol details:

   - LMD is an acronym for "latest message-driven".  It describes how
     votes are counted when picking the best fork.  In this scheme, only
     a validator's latest vote counts.  So if a validator votes for slot
     3 and then slot 5, the vote for 5 overwrites the vote for 3.

   - GHOST is an acronym for "greedy heaviest-observed subtree":

     greedy:   for each depth of the tree, pick the locally optimal
               child / subtree / fork.  This will result in the global
               optimal choice.

     heaviest: pick based on the highest stake weight.

     observed: this is the validator's local view, and other validators
               may have differing views because they've observed
               different votes.

     subtree:  pick based on the weight of an entire subtree, not just
               an individual node.  For example, if slot 3 has 10 stake
               and slot 5 has 5 stake, but slot 5 has two children 6
               and 7 that each have 3 stake, our weights are

               slot 3 subtree [3]        = 10
               slot 5 subtree [5, 6, 7]  = 11 (5+3+3)

               Therefore slot 5 would be the heaviest.

   In-memory representation:

   - Each tree node is keyed by slot number.

   - Each tree node tracks the amount of stake (`stake`) that has voted
     for its slot, as well as the recursive sum of stake for the subtree
     rooted at that node (`weight`).

   Link to original GHOST paper: https://eprint.iacr.org/2013/881.pdf.
   This is simply a reference for those curious about the etymology, and
   not prerequisite reading for understanding this implementation. */

#include "../fd_choreo_base.h"
#include "../epoch/fd_epoch.h"
#include "../../tango/fseq/fd_fseq.h"

/* FD_GHOST_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_GHOST_USE_HANDHOLDING
#define FD_GHOST_USE_HANDHOLDING 1
#endif

/* fd_ghost_node_t implements a left-child, right-sibling n-ary tree.
   Each node maintains the `node_pool` index of its left-most child
   (`child_idx`), its immediate-right sibling (`sibling_idx`), and its
   parent (`parent_idx`).

   This tree structure is gaddr-safe and supports accesses and
   operations from processes with separate local ghost joins. */

struct __attribute__((aligned(128UL))) fd_ghost_node {
  ulong             slot;         /* slot this node is tracking, also the map key */
  ulong             next;         /* reserved for internal use by fd_pool, fd_map_chain and fd_ghost_publish */
  ulong             weight;       /* amount of stake that has voted (via replay) for this slot or any of its descendants */
  ulong             replay_stake; /* amount of stake that has voted (via replay) for this slot */
  ulong             gossip_stake; /* amount of stake that has voted (via gossip) for this slot */
  ulong             rooted_stake; /* amount of stake that has rooted this slot */
  int               valid;        /* whether this node is valid for fork choice (fd_ghost_head) */
  ulong             parent_idx;   /* index of the parent in the node pool */
  ulong             child_idx;    /* index of the left-child in the node pool */
  ulong             sibling_idx;  /* index of the right-sibling in the node pool */
};
typedef struct fd_ghost_node fd_ghost_node_t;

#define POOL_NAME fd_ghost_node_pool
#define POOL_T    fd_ghost_node_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_ghost_node_map
#define MAP_ELE_T fd_ghost_node_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

/* fd_ghost_t is the top-level structure that holds the root of the
   tree, as well as the memory pools and map structures for tracking
   ghost nodes and votes.

   These structures are bump-allocated and laid out contiguously in
   memory from the fd_ghost_t * pointer which points to the beginning of
   the memory region.

   ---------------------- <- fd_ghost_t *
   | metadata           |
   ----------------------
   | node_pool          |
   ----------------------
   | node_map           |
   ----------------------

   A valid, initialized ghost is always non-empty.  After
   `fd_ghost_init` the ghost will always have a root node unless
   modified improperly out of ghost's API. */

#define FD_GHOST_MAGIC (0xf17eda2ce7940570UL) /* firedancer ghost version 0 */

struct __attribute__((aligned(128UL))) fd_ghost {

  /* Metadata */

  ulong magic;       /* ==FD_GHOST_MAGIC */
  ulong ghost_gaddr; /* wksp gaddr of this in the backing wksp, non-zero gaddr */
  ulong seed;        /* seed for various hashing function used under the hood, arbitrary */
  ulong root_idx;    /* node_pool idx of the root */

  /* version fseq. query pre & post read. if value is ULONG_MAX, ghost
     is uninitialized or invalid.

     odd:  if either pre or post is odd, discard read.
     even: if pre == post, read is consistent. */

  ulong ver_gaddr;

  /* The ghost node_pool is a memory pool of tree nodes from which one
     is allocated for each slot.  The node map is a fd_map_chain to
     support fast O(1) querying of ghost nodes by slot. */

  ulong node_pool_gaddr;
  ulong node_map_gaddr;
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
fd_ghost_footprint( ulong node_max ) {
  /* clang-format on */
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_ghost_t),        sizeof(fd_ghost_t) ),
      fd_fseq_align(),            fd_fseq_footprint() ),
      fd_ghost_node_pool_align(), fd_ghost_node_pool_footprint( node_max ) ),
      fd_ghost_node_map_align(),  fd_ghost_node_map_footprint( node_max ) ),
    fd_ghost_align() );
}

/* fd_ghost_new formats an unused memory region for use as a ghost.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_ghost_new( void * shmem, ulong seed, ulong node_max );

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
fd_ghost_init( fd_ghost_t * ghost, ulong root );

/* Accessors */

/* fd_ghost_wksp returns the local join to the wksp backing the ghost.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes ghost is a current local
   join. */

FD_FN_PURE static inline fd_wksp_t *
fd_ghost_wksp( fd_ghost_t const * ghost ) {
  return (fd_wksp_t *)( ( (ulong)ghost ) - ghost->ghost_gaddr );
}

FD_FN_PURE static inline ulong *
fd_ghost_ver( fd_ghost_t const * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->ver_gaddr );
}

FD_FN_PURE static inline fd_ghost_node_t *
fd_ghost_node_pool( fd_ghost_t * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->node_pool_gaddr );
}

FD_FN_PURE static inline fd_ghost_node_t const *
fd_ghost_node_pool_const( fd_ghost_t const * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->node_pool_gaddr );
}

FD_FN_PURE static inline fd_ghost_node_map_t *
fd_ghost_node_map( fd_ghost_t * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->node_map_gaddr );
}

FD_FN_PURE static inline fd_ghost_node_map_t const *
fd_ghost_node_map_const( fd_ghost_t const * ghost ) {
  return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->node_map_gaddr );
}

/* fd_ghost_root returns a pointer to the ghost root.  Assumes ghost is
   a current local join. */

FD_FN_PURE static inline fd_ghost_node_t const *
fd_ghost_root( fd_ghost_t const * ghost ) {
  return fd_ghost_node_pool_ele_const( fd_ghost_node_pool_const( ghost ), ghost->root_idx );
}

/* fd_ghost_parent returns a pointer to the `parent` of `child`.
   Assumes ghost is a current local join and child is a valid pointer
   to a node_pool element inside ghost. */

FD_FN_PURE static inline fd_ghost_node_t const *
fd_ghost_parent( fd_ghost_t const * ghost, fd_ghost_node_t const * child ) {
  return fd_ghost_node_pool_ele_const( fd_ghost_node_pool_const( ghost ), child->parent_idx );
}

/* fd_ghost_child returns a pointer to the left-most child of `parent`.
   Assumes ghost is a current local join and parent is a valid pointer
   to a node_pool element inside ghost. */

FD_FN_PURE static inline fd_ghost_node_t const *
fd_ghost_child( fd_ghost_t const * ghost, fd_ghost_node_t const * parent ) {
  return fd_ghost_node_pool_ele_const( fd_ghost_node_pool_const( ghost ), parent->child_idx );
}

/* fd_ghost_head greedily traverses the ghost beginning from `root` (not
   necessarily the root of the ghost tree) and returns the heaviest leaf
   of the traversal (see top-level documentation for traversal details).
   Assumes ghost is a current local join and has been initialized with
   fd_ghost_init and is therefore non-empty. */

fd_ghost_node_t const *
fd_ghost_head( fd_ghost_t const * ghost, fd_ghost_node_t const * root );

/* fd_ghost_query returns the node keyed by `slot` or NULL if not
   found. */

FD_FN_PURE static inline fd_ghost_node_t const *
fd_ghost_query( fd_ghost_t const * ghost, ulong slot ) {
  fd_ghost_node_map_t const * node_map = fd_ghost_node_map_const( ghost );
  fd_ghost_node_t const * node_pool = fd_ghost_node_pool_const( ghost );
  return fd_ghost_node_map_ele_query_const( node_map, &slot, NULL, node_pool );
}

/* fd_ghost_gca returns the greatest common ancestor of slot1, slot2 in
   ghost.  Assumes slot1 or slot2 are present in ghost (warns and
   returns NULL with handholding enabled).  This is guaranteed to be
   non-NULL if slot1 and slot2 are both present. */

fd_ghost_node_t const *
fd_ghost_gca( fd_ghost_t const * ghost, ulong slot1, ulong slot2 );

/* fd_ghost_is_ancestor returns 1 if `ancestor` is `slot`'s ancestor, 0
   otherwise.  Also returns 0 if either `ancestor` or `slot` are not in
   ghost. */

int
fd_ghost_is_ancestor( fd_ghost_t const * ghost, ulong ancestor, ulong slot );

/* Operations */

/* fd_ghost_insert inserts a new node keyed by `slot` into the ghost.
   Assumes slot >= ghost->smr, slot is not already in ghost, parent_slot
   is already in ghost, and the node pool has a free element (if
   handholding is enabled, explicitly checks and errors).  Returns the
   inserted ghost node. */

fd_ghost_node_t *
fd_ghost_insert( fd_ghost_t * ghost, ulong parent_slot, ulong slot );

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

void
fd_ghost_replay_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong slot );

/* fd_ghost_gossip_vote adds stake amount to the gossip_stake field of
   slot.

   Assumes slot is present in ghost (if handholding is enabled,
   explicitly checks and errors).  Returns the ghost node keyed by slot.

   Unlike fd_ghost_replay_vote, this stake is not propagated to
   the weight field for slot and slot's ancestors.  It is only counted
   towards slot itself, as gossip votes are only used for optimistic
   confirmation and not fork choice. */

void
fd_ghost_gossip_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong slot );

/* fd_ghost_rooted_vote adds stake amount to the rooted_stake field of
   slot.

   Assumes slot is present in ghost (if handholding is enabled,
   explicitly checks and errors).  Returns the ghost node keyed by slot.

   Note rooting a slot implies rooting its ancestor, but ghost does not
   explicitly track this. */

void
fd_ghost_rooted_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong root );

/* fd_ghost_publish publishes slot as the new ghost root, setting the
   subtree beginning from slot as the new ghost tree (ie. slot and all
   its descendants).  Prunes all nodes not in slot's ancestry.  Assumes
   slot is present in ghost.  Returns the new root. */

fd_ghost_node_t const *
fd_ghost_publish( fd_ghost_t * ghost, ulong slot );

/* Misc */

/* fd_ghost_verify checks the ghost is not obviously corrupt, as well as
   that ghost invariants are being preserved ie. the weight of every
   node is >= the sum of weights of its direct children.  Returns 0 if
   verify succeeds, -1 otherwise. */

int
fd_ghost_verify( fd_ghost_t const * ghost );

/* fd_ghost_print pretty-prints a formatted ghost tree.  Printing begins
   from `node` (it will appear as the root in the print output).

   The most straightforward and commonly used printing pattern is:
   `fd_ghost_print( ghost, fd_ghost_root( ghost ) )`

   This would print ghost beginning from the root.

   Alternatively, caller can print a more localized view, for example
   starting from the grandparent of the most recently executed slot:

   ```
   fd_ghost_node_t const * node = fd_ghost_query( slot );
   fd_ghost_print( ghost, fd_ghost_parent( fd_ghost_parent( node ) ) )
   ```

   Callers should add null-checks as appropriate in actual usage. */

void
fd_ghost_print( fd_ghost_t const * ghost, fd_epoch_t const * epoch, fd_ghost_node_t const * node );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_ghost_fd_ghost_h */
