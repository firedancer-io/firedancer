#ifndef HEADER_fd_src_choreo_ghost_fd_ghost_h
#define HEADER_fd_src_choreo_ghost_fd_ghost_h

/* fd_ghost implements Solana's LMD-GHOST ("latest message-driven greedy
   heaviest-observed subtree") fork choice rule.

   LMD ("latest message-driven") means only a validator's latest vote
   counts.  If a validator votes for one fork than subsequently votes
   for a different fork, their vote only counts towards the latter fork
   and not the former.

   GHOST ("greedy heaviest-observed subtree") describes the fork choice
   rule.  Forks form a tree, where each node is a block.  Here's an
   example of a fork tree in which every block is labeled with its slot:

         /-- 3
   1-- 2
         \-- 4

   In the above tree 3 and 4 are different forks.  The responsibility of
   fork choice is to decide whether the validator should vote for 3 or 4
   which ultimately determines which fork the cluster converges on.

   In Solana, votes are stake-weighted.  Here is the same tree with
   stakes associated with each block.

                     /-- 3 (30%)
   1 (80%) -- 2 (70%)
                     \-- 4 (38%)

   80% of stake voted for 1, 70% for 2, 30% for 3 and 38% for 4.  How
   does fork choice pick 3 or 4?  It traverses down the tree, beginning
   from the root (1), then picks (2), then picks (4) where it terminates
   and returns 4 as the best leaf.

   greedy:   fork choice is a greedy algorithm.  During traversal, on
             each level of the tree it picks the locally optimal value.

   heaviest: pick based on the heaviest (highest) stake.

   observed: this is the validator's local view, and other validators
             may have differing views because they've observed
             different votes or different forks.

   subtree:  sum the vote stake of an entire subtree rooted at a given
             block, not just votes for the individual block itself.  In
             the tree above, 1 and 2 both have strictly more stake than
             3 or 4.  That is because the stake for 3 and 4 both rolled
             up into 2, and the stake for 2 rolled up into 1.  There
             were also votes for 1 and 2 that weren't just roll-ups so
             the total stake for a parent can exceed (>=) the sum of its
             children.

   The above diagrams used slot numbers for simplicity but ghost in fact
   uses the `block_id`, a 32-byte hash that uniquely identifies a block,
   to key the elements of the tree.  The block_id ensures that when
   there is equivocation (two or more blocks labeled with the same slot)
   the blocks can be disambiguated.

   Ghost handles equivocation by marking forks invalid for fork choice
   if any block along that fork equivocates.  For example, consider the
   following tree:

                      /-- 4'(30%)
   1 (80%) -- 2 (70%)
                     \-- 4 (38%)

   This is the same tree from earlier except 3 has been replaced with
   4'.  There are two equivocating blocks for slot 4: how does ghost
   handle this?  Ghost marks both 4 and 4' as invalid for fork choice.
   So in this example, fork choice will pick 2 as the best leaf.

   Ghost can mark a fork valid again if it becomes "duplicate confirmed"
   ie. it has received votes from >=52% of the cluster.  Revisiting the
   above tree, modified:

                      /-- 4'(30%)
   1 (80%) -- 2 (70%)
                     \-- 4 (38%) <- gossip duplicate confirmed (>=52%)

   Now that 4 is "duplicate confirmed", ghost marks 4 as valid again.
   Fork choice picks 4 as the best leaf.  Note gossip duplicate
   confirmation is separately tracked outside of fd_ghost.  See the
   fd_ghost API for how that works. */

#include "../fd_choreo_base.h"
#include "../tower/fd_tower_accts.h"

/* FD_GHOST_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks. */

#ifndef FD_GHOST_USE_HANDHOLDING
#define FD_GHOST_USE_HANDHOLDING 1
#endif

/* fd_ghost_ele_t implements a left-child, right-sibling n-ary tree.
   Each ele maintains the `pool` index of its left-most child
   (`child_idx`), its immediate-right sibling (`sibling_idx`), and its
   parent (`parent_idx`).

   This tree structure is gaddr-safe and supports accesses and
   operations from processes with separate local ghost joins. */

struct __attribute__((aligned(128UL))) fd_ghost_blk {
  fd_hash_t key;     /* block_id (merkle root of the last FEC set in the slot) */
  ulong     slot;    /* slot this ele is tracking */
  ulong     next;    /* reserved for internal use by fd_pool, fd_map_chain and fd_ghost_publish */
  ulong     parent;  /* pool idx of the parent */
  ulong     child;   /* pool idx of the left-child */
  ulong     sibling; /* pool idx of the right-sibling */
  ulong     stake;   /* sum of stake that has voted for this slot or any of its descendants */
  int       eqvoc;   /* whether this block is equivocating. if so, it is invalid for fork choice unless duplicate confirmed */
  int       conf;    /* whether this block is "duplicate confirmed" via gossip votes (>= 52% of stake) */
  int       valid;   /* whether this block is valid for fork choice. an equivocating block is valid iff duplicate confirmed */
};
typedef struct fd_ghost_blk fd_ghost_blk_t;

#define POOL_NAME fd_ghost_pool
#define POOL_T    fd_ghost_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_ghost_map
#define MAP_ELE_T              fd_ghost_blk_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct fd_ghost_vtr {
  fd_pubkey_t pubkey;        /* map key */
  uint        hash;          /* reserved for fd_map_dynamic */
  ulong       prev_stake;    /* previous vote stake (vote can be from prior epoch) */
  ulong       prev_slot;     /* previous vote slot */
  fd_hash_t   prev_block_id; /* previous vote block_id  */
};
typedef struct fd_ghost_vtr fd_ghost_vtr_t;

#define MAP_NAME              fd_ghost_vtr
#define MAP_T                 fd_ghost_vtr_t
#define MAP_KEY               pubkey
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
  ulong            root; /* pool idx of the root tree element */
  fd_ghost_blk_t * pool; /* pool of tree elements (blocks) */
  fd_ghost_map_t * map;  /* map of block_id->ghost_blk for fast O(1) querying */
  fd_ghost_bid_t * bid;  /* map of slot->block_id */
  fd_ghost_vtr_t * vtr;  /* map of pubkey->prior vote */
};
typedef struct fd_ghost fd_ghost_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_ghost_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as ghost with up to
   ele_max eles and vote_max votes. */

FD_FN_CONST static inline ulong
fd_ghost_align( void ) {
  return alignof(fd_ghost_t);
}

FD_FN_CONST static inline ulong
fd_ghost_footprint( ulong blk_max ) {
  int lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( FD_VOTER_MAX ) ) + 1;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_ghost_t),   sizeof(fd_ghost_t)                   ),
      fd_ghost_pool_align(), fd_ghost_pool_footprint( blk_max )   ),
      fd_ghost_map_align(),  fd_ghost_map_footprint( blk_max )    ),
      fd_ghost_vtr_align(),  fd_ghost_vtr_footprint( lg_vtr_max ) ),
    fd_ghost_align() );
}

/* fd_ghost_new formats an unused memory region for use as a ghost.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_ghost_new( void * shmem, ulong ele_max, ulong seed );

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

/* Accessors */

/* fd_ghost_{root,parent,child,sibling} returns a pointer in the
   caller's address space to the {root,parent,left-child,right-sibling}.
   Assumes ghost is a current local join and blk is a valid pointer to a
   pool element inside ghost.  const versions for each are also
   provided. */

FD_FN_PURE static inline fd_ghost_blk_t       * fd_ghost_root         ( fd_ghost_t       * ghost                                 ) { return fd_ghost_pool_ele      ( ghost->pool, ghost->root      ); }
FD_FN_PURE static inline fd_ghost_blk_t const * fd_ghost_root_const   ( fd_ghost_t const * ghost                                 ) { return fd_ghost_pool_ele_const( ghost->pool, ghost->root      ); }
FD_FN_PURE static inline fd_ghost_blk_t       * fd_ghost_parent       ( fd_ghost_t       * ghost, fd_ghost_blk_t       * child   ) { return fd_ghost_pool_ele      ( ghost->pool, child->parent    ); }
FD_FN_PURE static inline fd_ghost_blk_t const * fd_ghost_parent_const ( fd_ghost_t const * ghost, fd_ghost_blk_t const * child   ) { return fd_ghost_pool_ele_const( ghost->pool, child->parent    ); }
FD_FN_PURE static inline fd_ghost_blk_t       * fd_ghost_child        ( fd_ghost_t       * ghost, fd_ghost_blk_t       * parent  ) { return fd_ghost_pool_ele      ( ghost->pool, parent->child    ); }
FD_FN_PURE static inline fd_ghost_blk_t const * fd_ghost_child_const  ( fd_ghost_t const * ghost, fd_ghost_blk_t const * parent  ) { return fd_ghost_pool_ele_const( ghost->pool, parent->child    ); }
FD_FN_PURE static inline fd_ghost_blk_t       * fd_ghost_sibling      ( fd_ghost_t       * ghost, fd_ghost_blk_t       * sibling ) { return fd_ghost_pool_ele      ( ghost->pool, sibling->sibling ); }
FD_FN_PURE static inline fd_ghost_blk_t const * fd_ghost_sibling_const( fd_ghost_t const * ghost, fd_ghost_blk_t const * sibling ) { return fd_ghost_pool_ele_const( ghost->pool, sibling->sibling ); }

/* fd_ghost_query returns the block keyed by block_id.  Returns NULL if
   not found. */

fd_ghost_blk_t const *
fd_ghost_query( fd_ghost_t const * ghost,
                fd_hash_t  const * block_id );

/* fd_ghost_best returns the best block (according to fork choice) in
   the subtree beginning at root.  This is the ideal block to vote on or
   reset to, and feeds into downstream TowerBFT rules.  This is usually
   a leaf node in the tree but may not when blocks are marked invalid
   due to unconfirmed duplicates. Assumes root is marked valid so this
   will never return NULL. */

fd_ghost_blk_t const *
fd_ghost_best( fd_ghost_t     const * ghost,
               fd_ghost_blk_t const * root );

/* fd_ghost_deepest returns the deepest ghost block (highest tree depth)
   in the subtree beginning at root.  Unlike fd_ghost_best, deepest can
   return a block marked invalid for fork choice.  In case of ties, the
   returned block will be the most recently inserted one.  This will
   never return NULL. */

fd_ghost_blk_t const *
fd_ghost_deepest( fd_ghost_t     const * ghost,
                  fd_ghost_blk_t const * root );

/* fd_ghost_invalid_ancestor returns the first ancestor on the same fork
   as descendant that is marked invalid.  Does not include descendant
   itself.  Returns NULL if there are no invalid ancestors. */

fd_ghost_blk_t const *
fd_ghost_invalid_ancestor( fd_ghost_t     const * ghost,
                           fd_ghost_blk_t const * descendant );

/* Operations */

/* fd_ghost_upsert inserts a new ghost block keyed by (slot, block_id)
   and updates ghost with the state of the vote accounts as of that
   block.  The parent_block_id is used to link this new block to its
   parent in the ghost tree.  parent_block_id may only be NULL if this
   is the very first ghost upsert, in which case this new block will be
   set to the ghost root.  Returns the new block. */

fd_ghost_blk_t *
fd_ghost_upsert( fd_ghost_t             * ghost,
                 fd_tower_accts_t const * accts,
                 ulong                    slot,
                 fd_hash_t        const * block_id,
                 fd_hash_t        const * parent_block_id );

/* fd_ghost_publish publishes block_id as the new ghost root, pruning
   any blocks not in the subtree beginning from block_id (ie. block_id
   and all its descendants).  Returns the new root. */

fd_ghost_blk_t const *
fd_ghost_publish( fd_ghost_t       * ghost,
                  fd_hash_t  const * block_id );

/* Misc */

/* fd_ghost_verify checks the ghost is not obviously corrupt, as well as
   that ghost invariants are being preserved ie. the weight of every
   ele is >= the sum of weights of its direct children.  Returns 0 if
   verify succeeds, -1 otherwise. */

int
fd_ghost_verify( fd_ghost_t const * ghost );

/* fd_ghost_print pretty-prints a formatted ghost tree.  Printing begins
   from `ele` (it will appear as the root in the print output).

   The most straightforward and commonly used printing pattern is:
   `fd_ghost_print( ghost, fd_ghost_root( ghost ) )`

   This would print ghost beginning from the root.

   Alternatively, caller can print a more localized view, for example
   starting from the grandparent of the most recently executed slot:

   ```
   fd_ghost_ele_t const * ele = fd_ghost_query( slot );
   fd_ghost_print( ghost, fd_ghost_parent( fd_ghost_parent( ele ) ) )
   ```

   Callers should add null-checks as appropriate in actual usage. */

void
fd_ghost_print( fd_ghost_t     const * ghost,
                fd_ghost_blk_t const * root,
                ulong                  total_stake );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_ghost_fd_ghost_h */
