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
               an individual ele.  For example, if slot 3 has 10 stake
               and slot 5 has 5 stake, but slot 5 has two children 6
               and 7 that each have 3 stake, our weights are

               slot 3 subtree [3]        = 10
               slot 5 subtree [5, 6, 7]  = 11 (5+3+3)

               Therefore slot 5 would be the heaviest.

   In-memory representation:

   There are two maps, both indexing the same pool of tree elements.

   - One map is keyed by slot number, and one map is keyed by hash_id
     (currently the block id, which is the merkle root of the last FEC
     set in the slot).

   - The elements in the slot map are a subset of the elements in the
     hash_id map.

   - Each tree ele tracks the amount of stake (`stake`) that has voted
     for its slot, as well as the recursive sum of stake for the subtree
     rooted at that ele (`weight`).

   The map keyed by slot is the "happy tree."  i.e. the first version of
   a block we see and replay is going to be the version visible in the
   slot map.  This is also the version of the slot that our tower is
   referring to.  The map keyed by hash_id maintains every block that
   we've seen evidence of, including the equivocating blocks.

   both equivocating blocks seen             only one block seen

              0                                      0
             / \                                    /
            1   1' (both invalid)                  1' (valid)
           /     \                                /
          2       3                              3

   The first version of block 1 we see / replay is going to be the
   version visible in the slot map.  Block 1' will be available in the
   hash-keyed tree, but not in the slot map.  Block 3 will also be
   available in the slot-keyed tree, despite being a descendant of
   something not existing in the slot map.

   Thus in ghost,

   both equivocating blocks seen             only one block seen
   slot_map: [0, 1, 2, 3]                    slot_map: [0, 1', 3]
   hash_map: [1']                            hash_map: []

   Whatever is in the slot map is the slot referenced to by tower. Tower
   is *pure* and has no notion of duplicitness.  So tower just needs to
   worry about querying ghost_slot_map for the proper hash_id.

   Slot 4 arrives, chained off of 1.  In the right case where we didn't
   see block 1, block 4 now provides evidence for 1.  We mark 1' as
   invalid for fork choice, and we repair the parent of 4 (getting 1').
   Then we replay down 1' and then replay down 4.  Now the maps in this
   case look like:

   both equivocating blocks seen             only one block seen

              0                                      0
             / \                                    / \
            1   1' (both invalid)                  1'   1 (both invalid)
           / \   \                                /      \
          2   4   3                              3        4

   both equivocating blocks seen             only one block seen
   slot_map: [0, 1, 2, 3, 4]                 slot_map: [0, 1', 3, 4]
   hash_map: [1']                            hash_map: [1']

   Let's say 1' get's duplicate confirmed.  Then the left case needs to
   switch forks in tower.  Then ghost will need to itself swap the
   corresponding ghost hash_id in the slot_map to the hash_map and vice
   versa.

   both equivocating blocks seen             only one block seen
   slot_map: [0, 1', 2, 3, 4]                slot_map: [0, 1', 3, 4]
   hash_map: [1]                             hash_map: [1']
                                             (no change)

   1' is marked as valid for fork choice.  1 remains invalid.

   Link to original GHOST paper: https://eprint.iacr.org/2013/881.pdf.
   This is simply a reference for those curious about the etymology, and
   not prerequisite reading for understanding this implementation. */

#include "../fd_choreo_base.h"
#include "../epoch/fd_epoch.h"
#include "../../tango/fseq/fd_fseq.h"

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

struct __attribute__((aligned(128UL))) fd_ghost_ele {
  fd_hash_t key;          /* hash_id (merkle root of the last FEC set in the slot) */
  ulong     slot;         /* slot this ele is tracking */
  ulong     next;         /* reserved for internal use by fd_pool, hash_map fd_map_chain and fd_ghost_publish */
  ulong     nexts;        /* reserved for internal use by slot_map fd_map_chain */
  ulong     eqvoc;        /* pool idx of a duplicate of this slot */
  ulong     parent;       /* pool idx of the parent */
  ulong     child;        /* pool idx of the left-child */
  ulong     sibling;      /* pool idx of the right-sibling */
  ulong     weight;       /* total stake from replay votes for this slot or any of its descendants */
  ulong     replay_stake; /* total stake from replay votes for this slot */
  ulong     gossip_stake; /* total stake from gossip votes for this slot */
  ulong     rooted_stake; /* replay stake that has rooted this slot */
  int       valid;        /* whether this ele is valid for fork choice */
};
typedef struct fd_ghost_ele fd_ghost_ele_t;

#define POOL_NAME fd_ghost_pool
#define POOL_T    fd_ghost_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_ghost_hash_map
#define MAP_ELE_T              fd_ghost_ele_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_ghost_slot_map
#define MAP_ELE_T fd_ghost_ele_t
#define MAP_KEY   slot
#define MAP_NEXT  nexts
#include "../../util/tmpl/fd_map_chain.c"

struct fd_dup_seen {
   ulong slot;
};
typedef struct fd_dup_seen fd_dup_seen_t;

#define MAP_NAME     fd_dup_seen_map
#define MAP_T        fd_dup_seen_t
#define MAP_KEY      slot
#define MAP_MEMOIZE  0
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_ghost_t is the top-level structure that holds the root of the
   tree, as well as the memory pools and map structures for tracking
   ghost eles and votes.

   These structures are bump-allocated and laid out contiguously in
   memory from the fd_ghost_t * pointer which points to the beginning of
   the memory region.

   ---------------------- <- fd_ghost_t *
   | metadata           |
   ----------------------
   | pool               |
   ----------------------
   | map                |
   ----------------------

   A valid, initialized ghost is always non-empty.  After
   `fd_ghost_init` the ghost will always have a root ele unless
   modified improperly out of ghost's API. */

#define FD_GHOST_MAGIC (0xf17eda2ce7940570UL) /* firedancer ghost version 0 */

struct __attribute__((aligned(128UL))) fd_ghost {

  /* Metadata */

  ulong magic;          /* ==FD_GHOST_MAGIC */
  ulong ghost_gaddr;    /* wksp gaddr of this in the backing wksp, non-zero gaddr */
  ulong seed;           /* seed for various hashing function used under the hood, arbitrary */
  ulong root;           /* pool idx of the root */
  ulong pool_gaddr;     /* wksp gaddr of the pool backing this ghost, non-zero gaddr */
  ulong hash_map_gaddr; /* wksp gaddr of the map (for fast O(1) querying by hash) backing this ghost, non-zero gaddr */
  ulong slot_map_gaddr; /* wksp gaddr of the map (for fast O(1) querying by slot) backing this ghost, non-zero gaddr */
  ulong dup_map_gaddr;  /* wksp gaddr of the map (for fast O(1) querying, non-zero gaddr */
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
fd_ghost_footprint( ulong ele_max ) {
  int lg_ele_max = fd_ulong_find_msb( fd_ulong_pow2_up( ele_max ) );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_ghost_t),       sizeof(fd_ghost_t)                        ),
      fd_ghost_pool_align(),     fd_ghost_pool_footprint    ( ele_max )    ),
      fd_ghost_hash_map_align(), fd_ghost_hash_map_footprint( ele_max )    ),
      fd_ghost_slot_map_align(), fd_ghost_slot_map_footprint( ele_max )    ),
      fd_dup_seen_map_align(),   fd_dup_seen_map_footprint  ( lg_ele_max ) ),
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

/* fd_ghost_init initializes a ghost.  Assumes ghost is a valid local
   join and no one else is joined.  root is the initial root ghost will
   use.  This is the snapshot slot if booting from a snapshot, 0 if the
   genesis slot. hash is the hash_id of the initial root.

   In general, this should be called by the same process that formatted
   ghost's memory, ie. the caller of fd_ghost_new. */

void
fd_ghost_init( fd_ghost_t * ghost, ulong root, fd_hash_t * hash );

/* Accessors */

/* fd_ghost_wksp returns the local join to the wksp backing the ghost.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes ghost is a current local
   join. */

FD_FN_PURE static inline fd_wksp_t *
fd_ghost_wksp( fd_ghost_t const * ghost ) {
  return (fd_wksp_t *)( ( (ulong)ghost ) - ghost->ghost_gaddr );
}

/* fd_ghost_{pool,map,root} returns a pointer in the caller's address
   space to the corresponding ghost field.  const versions for each are
   also provided. */

FD_FN_PURE static inline fd_ghost_ele_t            * fd_ghost_pool          ( fd_ghost_t       * ghost ) { return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->pool_gaddr     ); }
FD_FN_PURE static inline fd_ghost_ele_t const      * fd_ghost_pool_const    ( fd_ghost_t const * ghost ) { return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->pool_gaddr     ); }
FD_FN_PURE static inline fd_ghost_hash_map_t       * fd_ghost_hash_map      ( fd_ghost_t       * ghost ) { return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->hash_map_gaddr ); }
FD_FN_PURE static inline fd_ghost_hash_map_t const * fd_ghost_hash_map_const( fd_ghost_t const * ghost ) { return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->hash_map_gaddr ); }
FD_FN_PURE static inline fd_ghost_slot_map_t       * fd_ghost_slot_map      ( fd_ghost_t       * ghost ) { return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->slot_map_gaddr ); }
FD_FN_PURE static inline fd_ghost_slot_map_t const * fd_ghost_slot_map_const( fd_ghost_t const * ghost ) { return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->slot_map_gaddr ); }
FD_FN_PURE static inline fd_dup_seen_t             * fd_ghost_dup_map       ( fd_ghost_t       * ghost ) { return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->dup_map_gaddr ); }
FD_FN_PURE static inline fd_dup_seen_t       const * fd_ghost_dup_map_const ( fd_ghost_t const * ghost ) { return fd_wksp_laddr_fast( fd_ghost_wksp( ghost ), ghost->dup_map_gaddr ); }

/* fd_ghost_{parent,child,sibling} returns a pointer in the caller's
   address space to the corresponding {parent,left-child,right-sibling}
   of fec.  Assumes ghost is a current local join and fec is a valid
   pointer to a pool element inside ghost.  const versions for each are
   also provided. */

FD_FN_PURE static inline fd_ghost_ele_t       * fd_ghost_root         ( fd_ghost_t       * ghost                             ) { return fd_ghost_pool_ele      ( fd_ghost_pool      ( ghost ), ghost->root  ); }
FD_FN_PURE static inline fd_ghost_ele_t const * fd_ghost_root_const   ( fd_ghost_t const * ghost                             ) { return fd_ghost_pool_ele_const( fd_ghost_pool_const( ghost ), ghost->root  ); }
FD_FN_PURE static inline fd_ghost_ele_t       * fd_ghost_parent       ( fd_ghost_t       * ghost, fd_ghost_ele_t       * ele ) { return fd_ghost_pool_ele      ( fd_ghost_pool      ( ghost ), ele->parent  ); }
FD_FN_PURE static inline fd_ghost_ele_t const * fd_ghost_parent_const ( fd_ghost_t const * ghost, fd_ghost_ele_t const * ele ) { return fd_ghost_pool_ele_const( fd_ghost_pool_const( ghost ), ele->parent  ); }
FD_FN_PURE static inline fd_ghost_ele_t       * fd_ghost_child        ( fd_ghost_t       * ghost, fd_ghost_ele_t       * ele ) { return fd_ghost_pool_ele      ( fd_ghost_pool      ( ghost ), ele->child   ); }
FD_FN_PURE static inline fd_ghost_ele_t const * fd_ghost_child_const  ( fd_ghost_t const * ghost, fd_ghost_ele_t const * ele ) { return fd_ghost_pool_ele_const( fd_ghost_pool_const( ghost ), ele->child   ); }
FD_FN_PURE static inline fd_ghost_ele_t       * fd_ghost_sibling      ( fd_ghost_t       * ghost, fd_ghost_ele_t       * ele ) { return fd_ghost_pool_ele      ( fd_ghost_pool      ( ghost ), ele->sibling ); }
FD_FN_PURE static inline fd_ghost_ele_t const * fd_ghost_sibling_const( fd_ghost_t const * ghost, fd_ghost_ele_t const * ele ) { return fd_ghost_pool_ele_const( fd_ghost_pool_const( ghost ), ele->sibling ); }

/* fd_ghost_{query,query_const} returns the ele keyed by `hash_id`,
   NULL if not found. */

FD_FN_PURE static inline fd_ghost_ele_t *
fd_ghost_query( fd_ghost_t * ghost, fd_hash_t const * hash ) {
  if( FD_UNLIKELY( !hash ) ) { return NULL; }
  fd_ghost_hash_map_t * map  = fd_ghost_hash_map( ghost );
  fd_ghost_ele_t      * pool = fd_ghost_pool( ghost );
  return fd_ghost_hash_map_ele_query( map, hash, NULL, pool );
}

FD_FN_PURE static inline fd_ghost_ele_t const *
fd_ghost_query_const( fd_ghost_t const * ghost, fd_hash_t const * hash ) {
  if( FD_UNLIKELY( !hash ) ) { return NULL; }
  fd_ghost_hash_map_t const * map  = fd_ghost_hash_map_const ( ghost );
  fd_ghost_ele_t      const * pool = fd_ghost_pool_const( ghost );
  return fd_ghost_hash_map_ele_query_const( map, hash, NULL, pool );
}

/* fd_ghost_hash returns the hash_id of the ele keyed by `slot`.
   NULL if the slot is not found. */

FD_FN_PURE static inline fd_hash_t const *
fd_ghost_hash( fd_ghost_t const * ghost, ulong slot ) {
  fd_ghost_slot_map_t const * maps = fd_ghost_slot_map_const( ghost );
  fd_ghost_ele_t      const * pool = fd_ghost_pool_const( ghost );
  fd_ghost_ele_t      const * ele  = fd_ghost_slot_map_ele_query_const( maps, &slot, NULL, pool );
  return ele ? &ele->key : NULL;
}

/* fd_ghost_head greedily traverses down the ghost beginning from root,
   recursively picking the child with most `weight` on each level of the
   tree, terminating once it reaches a leaf (see top-level documentation
   for more traversal details).  Assumes ghost is a current local join
   and has been initialized with fd_ghost_init and is therefore
   non-empty. */

fd_ghost_ele_t const *
fd_ghost_head( fd_ghost_t const * ghost, fd_ghost_ele_t const * root );

/* fd_ghost_gca returns the greatest common ancestor of block1, block2
   in ghost.  Assumes block1 or block2 are present in ghost (warns and
   returns NULL with handholding enabled).  This is guaranteed to be
   non-NULL if block1 and block2 are both present. */

fd_ghost_ele_t const *
fd_ghost_gca( fd_ghost_t const * ghost, fd_hash_t const * bid1, fd_hash_t const * bid2 );

/* fd_ghost_is_ancestor returns 1 if `ancestor` is `slot`'s ancestor, 0
   otherwise.  Also returns 0 if either `ancestor` or `slot` are not in
   ghost. */

int
fd_ghost_is_ancestor( fd_ghost_t const * ghost, fd_hash_t const * ancestor, fd_hash_t const * slot );

/* fd_ghost_anc_eqvoc. */

int
fd_ghost_invalid( fd_ghost_t const * ghost, fd_ghost_ele_t const * ele );

/* Operations */

/* fd_ghost_insert inserts a new ele keyed by `hash_id`, for the slot
   `slot` into the ghost. Inserts an ele keyed by `slot` into the slot
   map if one doesn't already exist as well. Assumes slot >= ghost->smr,
   parent_hash_id is already in ghost, and the ele pool has a free
   element (if handholding is enabled, explicitly checks and errors).
   Returns the inserted ghost ele. */

/* FIXME: total_stake as an arg is a little unwieldy. is there a better
   way to design this API? ghost->total_stake runs the risk of forgetting
   to update*/

fd_ghost_ele_t *
fd_ghost_insert( fd_ghost_t * ghost, fd_hash_t const * parent_hash, ulong slot, fd_hash_t const * hash_id, ulong total_stake );

/* fd_ghost_replay_vote votes for hash_id, adding pubkey's stake to the
   `stake` field for slot and to the `weight` field for both slot and
   slot's ancestors.  If pubkey has previously voted, pubkey's stake is
   also subtracted from `weight` for its previous vote slot and its
   ancestors.

   Assumes slot is present in ghost (if handholding is enabled,
   explicitly checks and errors).

   TODO the implementation can be made more efficient by
   short-circuiting and doing fewer traversals.  Currently this is
   bounded to O(h), where h is the height of ghost. */

void
fd_ghost_replay_vote( fd_ghost_t * ghost, fd_voter_t * voter, fd_hash_t const * hash_id );

/* fd_ghost_gossip_vote adds stake amount to the gossip_stake field of
   slot.

   Assumes slot is present in ghost (if handholding is enabled,
   explicitly checks and errors).  Returns the ghost ele keyed by slot.

   Unlike fd_ghost_replay_vote, this stake is not propagated to
   the weight field for slot and slot's ancestors.  It is only counted
   towards slot itself, as gossip votes are only used for optimistic
   confirmation and not fork choice. */

void
fd_ghost_gossip_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong slot );

/* fd_ghost_rooted_vote adds stake amount to the rooted_stake field of
   slot.

   Assumes slot is present in ghost (if handholding is enabled,
   explicitly checks and errors).  Returns the ghost ele keyed by slot.

   Note rooting a slot implies rooting its ancestor, but ghost does not
   explicitly track this. */

void
fd_ghost_rooted_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong root );

/* fd_ghost_publish publishes slot as the new ghost root, setting the
   subtree beginning from slot as the new ghost tree (ie. slot and all
   its descendants).  Prunes all eles not in slot's ancestry.  Assumes
   slot is present in ghost.  Returns the new root. */

fd_ghost_ele_t const *
fd_ghost_publish( fd_ghost_t * ghost, fd_hash_t const * hash_id );

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
fd_ghost_print( fd_ghost_t const * ghost, ulong total_stake, fd_ghost_ele_t const * ele );

static int FD_FN_UNUSED
is_duplicate_confirmed( fd_ghost_t * ghost, fd_hash_t const * hash, ulong total_stake ) {
  fd_ghost_ele_t const * ele = fd_ghost_query( ghost, hash );
  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_WARNING(( "[%s] slot %s was not in ghost", __func__, FD_BASE58_ENC_32_ALLOCA(hash) ));
    return 0;
  }
  double pct = (double)( ele->weight + ele->gossip_stake ) / (double)total_stake; /* TODO make gossip weight a field as well */
  return pct > FD_EQVOCSAFE_PCT;
}

/* Duplicate confirmed signal */

void
process_duplicate_confirmed( fd_ghost_t * ghost, fd_hash_t const * hash, ulong slot );

void
process_duplicate( fd_ghost_t * ghost, ulong slot, ulong total_stake );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_ghost_fd_ghost_h */
