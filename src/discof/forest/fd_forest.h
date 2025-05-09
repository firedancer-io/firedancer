#ifndef HEADER_fd_src_choreo_forest_fd_forest_h
#define HEADER_fd_src_choreo_forest_fd_forest_h

/* Forest is an API for repairing blocks as they are discovered from the
   cluster via Turbine or Gossip.  Shreds (from Turbine) and votes (from
   Gossip) inform forest that a block with the given slot they are
   associated with exists.  Blk repair ensures that this block is
   received in its entirety by requesting repairs for missing shreds for
   the block.

   Like other fork-aware structures, forest maintains a tree that
   records the ancestry of slots.  It also maintains a frontier, which
   models the leaves of the tree ie. the oldest (in ancestry) blocks
   that still need to be repaired (across multiple forks).

   Forest constructs the ancestry tree backwards, and then repairs the
   tree forwards (using BFS). */

/* FD_FOREST_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#include "../../disco/fd_disco_base.h"

#ifndef FD_FOREST_USE_HANDHOLDING
#define FD_FOREST_USE_HANDHOLDING 1
#endif

#define FD_FOREST_VER_UNINIT (0UL)
#define FD_FOREST_VER_INVAL  (ULONG_MAX)

#define FD_FOREST_MAGIC (0xf17eda2ce7b1c0UL) /* firedancer forest version 0 */

#define SET_NAME fd_forest_ele_idxs
#define SET_MAX  FD_SHRED_BLK_MAX
#include "../../util/tmpl/fd_set.c"


/* fd_forest_ele_t implements a left-child, right-sibling n-ary
   tree. Each ele maintains the `pool` index of its left-most child
   (`child_idx`), its immediate-right sibling (`sibling_idx`), and its
   parent (`parent_idx`).

   This tree structure is gaddr-safe and supports accesses and
   operations from processes with separate local forest joins. */

struct __attribute__((aligned(128UL))) fd_forest_ele {
  ulong slot;     /* map key */
  ulong prev;     /* internal use by link_orphans */
  ulong next;     /* internal use by fd_pool, fd_map_chain */
  ulong parent;   /* pool idx of the parent in the tree, parent slot when orphaned */
  ulong child;    /* pool idx of the left-child */
  ulong sibling;  /* pool idx of the right-sibling */

  uint buffered_idx; /* highest contiguous buffered shred idx */
  uint complete_idx; /* shred_idx with SLOT_COMPLETE_FLAG ie. last shred idx in the slot */

  fd_forest_ele_idxs_t cmpl[fd_forest_ele_idxs_word_cnt]; /* fec complete idxs */
  fd_forest_ele_idxs_t fecs[fd_forest_ele_idxs_word_cnt]; /* fec set idxs */
  fd_forest_ele_idxs_t idxs[fd_forest_ele_idxs_word_cnt]; /* data shred idxs */
};
typedef struct fd_forest_ele fd_forest_ele_t;

#define POOL_NAME fd_forest_pool
#define POOL_T    fd_forest_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_forest_ancestry
#define MAP_ELE_T fd_forest_ele_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_forest_frontier
#define MAP_ELE_T fd_forest_ele_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_forest_orphaned
#define MAP_ELE_T fd_forest_ele_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

/* fd_forest_t is the top-level structure that holds the root of
   the tree, as well as the memory pools and map structures.

   These structures are bump-allocated and laid out contiguously in
   memory from the fd_forest_t * pointer which points to the
   beginning of the memory region.

   --------------------- <- fd_forest_t *
   | metadata          |
   |-------------------|
   | pool              |
   |-------------------|
   | ancestry          |
   |-------------------|
   | frontier          |
   |-------------------|
   | orphaned          |
   ---------------------

   A valid, initialized forest is always non-empty.  After
   `fd_forest_init` the forest will always have a root ele unless
   modified improperly out of forest's API.*/

struct __attribute__((aligned(128UL))) fd_forest {
  ulong root;           /* pool idx of the root */
  ulong iter;           /* pool idx of the iterator */
  ulong wksp_gaddr;     /* wksp gaddr of fd_forest in the backing wksp, non-zero gaddr */
  ulong ver_gaddr;      /* wksp gaddr of version fseq, incremented on write ops */
  ulong pool_gaddr;     /* wksp gaddr of fd_pool */
  ulong ancestry_gaddr; /* wksp_gaddr of fd_forest_ancestry */
  ulong frontier_gaddr; /* map of slot to ele (leaf that needs repair) */
  ulong orphaned_gaddr; /* map of parent_slot to singly-linked list of ele orphaned by that parent slot */
  ulong magic;          /* ==FD_FOREST_MAGIC */
};
typedef struct fd_forest fd_forest_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_forest_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as forest with up to
   ele_max eles and vote_max votes. */

FD_FN_CONST static inline ulong
fd_forest_align( void ) {
  return alignof(fd_forest_t);
}

FD_FN_CONST static inline ulong
fd_forest_footprint( ulong ele_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_forest_t),  sizeof(fd_forest_t)              ),
      fd_fseq_align(),           fd_fseq_footprint()                  ),
      fd_forest_pool_align(),       fd_forest_pool_footprint( ele_max )     ),
      fd_forest_ancestry_align(),   fd_forest_ancestry_footprint( ele_max ) ),
      fd_forest_frontier_align(),   fd_forest_frontier_footprint( ele_max ) ),
      fd_forest_orphaned_align(),   fd_forest_orphaned_footprint( ele_max ) ),
    fd_forest_align() );
}

/* fd_forest_new formats an unused memory region for use as a
   forest.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_forest_new( void * shmem, ulong ele_max, ulong seed );

/* fd_forest_join joins the caller to the forest.  forest
   points to the first byte of the memory region backing the forest
   in the caller's address space.  Returns a pointer in the local
   address space to forest on success. */

fd_forest_t *
fd_forest_join( void * forest );

/* fd_forest_leave leaves a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include forest is NULL. */

void *
fd_forest_leave( fd_forest_t const * forest );

/* fd_forest_delete unformats a memory region used as a
   forest. Assumes only the nobody is joined to the region.
   Returns a pointer to the underlying shared memory region or NULL if
   used obviously in error (e.g. forest is obviously not a
   forest ... logs details). The ownership of the memory region is
   transferred to the caller. */

void *
fd_forest_delete( void * forest );

/* fd_forest_init initializes a forest.  Assumes forest
   is a valid local join and no one else is joined.  root is the initial
   root forest will use.  This is the snapshot slot if booting from
   a snapshot, 0 if the genesis slot.

   In general, this should be called by the same process that formatted
   forest's memory, ie. the caller of fd_forest_new. */

fd_forest_t *
fd_forest_init( fd_forest_t * forest, ulong root );

/* fd_forest_fini finishes an forest.  Assumes forest is
   a valid local join and no one else is joined. */

void *
fd_forest_fini( fd_forest_t * forest );

/* Accessors */

/* fd_forest_wksp returns the local join to the wksp backing the
   forest.  The lifetime of the returned pointer is at least as
   long as the lifetime of the local join.  Assumes forest is a
   current local join. */

FD_FN_PURE static inline fd_wksp_t *
fd_forest_wksp( fd_forest_t const * forest ) {
  return (fd_wksp_t *)( ( (ulong)forest ) - forest->wksp_gaddr );
}

/* fd_forest_{ver, ver_const} returns the local join to the version
   number fseq.  The lifetime of the returned pointer is at least as
   long as the lifetime of the local join.  Assumes forest is a
   current local join.  If value is ULONG_MAX, ghost is uninitialized or
   invalid.  Query pre- & post-read:

   odd:  if either pre or post is odd, discard read.
   even: if pre == post, read is consistent. */

FD_FN_PURE static inline ulong *
fd_forest_ver( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->ver_gaddr );
}

FD_FN_PURE static inline ulong const *
fd_forest_ver_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->ver_gaddr );
}

/* fd_forest_{pool, pool_const} returns a pointer in the caller's address
   space to forest's element pool. */

FD_FN_PURE static inline fd_forest_ele_t *
fd_forest_pool( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->pool_gaddr );
}

FD_FN_PURE static inline fd_forest_ele_t const *
fd_forest_pool_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->pool_gaddr );
}

/* fd_forest_{ancestry, ancestry_const} returns a pointer in the caller's
   address space to forest's ancestry map. */

FD_FN_PURE static inline fd_forest_ancestry_t *
fd_forest_ancestry( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->ancestry_gaddr );
}

FD_FN_PURE static inline fd_forest_ancestry_t const *
fd_forest_ancestry_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->ancestry_gaddr );
}

/* fd_forest_{frontier, frontier_const} returns a pointer in the caller's
   address space to forest's frontier map. */

FD_FN_PURE static inline fd_forest_frontier_t *
fd_forest_frontier( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->frontier_gaddr );
}

FD_FN_PURE static inline fd_forest_frontier_t const *
fd_forest_frontier_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->frontier_gaddr );
}

/* fd_forest_{orphaned, orphaned_const} returns a pointer in the caller's
   address space to forest's orphaned map. */

FD_FN_PURE static inline fd_forest_orphaned_t *
fd_forest_orphaned( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->orphaned_gaddr );
}

FD_FN_PURE static inline fd_forest_orphaned_t const *
fd_forest_orphaned_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->orphaned_gaddr );
}

/* fd_forest_root_slot returns forest's root slot.  Assumes
   forest is a current local join. */

FD_FN_PURE static inline ulong
fd_forest_root_slot( fd_forest_t const * forest ) {
  if( FD_UNLIKELY( forest->root == fd_forest_pool_idx_null( fd_forest_pool_const( forest ) ) )) return ULONG_MAX; /* uninitialized */
  return fd_forest_pool_ele_const( fd_forest_pool_const( forest ), forest->root )->slot;
}

fd_forest_ele_t *
fd_forest_query( fd_forest_t * forest, ulong slot );

/* Operations */

/* fd_forest_shred_insert inserts a new shred into the forest.
   Assumes slot >= forest->smr, slot is not already in forest,
   parent_slot is already in forest, and the ele pool has a free
   element (if handholding is enabled, explicitly checks and errors).
   Returns the inserted forest ele. */

fd_forest_ele_t *
fd_forest_data_shred_insert( fd_forest_t * forest, ulong slot, ushort parent_off, uint shred_idx, uint fec_set_idx, int data_complete, int slot_complete );

/* fd_forest_publish publishes slot as the new forest root, setting
   the subtree beginning from slot as the new forest tree (ie. slot
   and all its descendants).  Prunes all eles not in slot's forest.
   Assumes slot is present in forest.  Returns the new root. */

fd_forest_ele_t const *
fd_forest_publish( fd_forest_t * forest, ulong slot );

/* Misc */

/* fd_forest_verify checks the forest is not obviously corrupt.
   Returns 0 if verify succeeds, -1 otherwise. */

int
fd_forest_verify( fd_forest_t const * forest );

void
fd_forest_frontier_print( fd_forest_t const * forest );

/* fd_forest_print pretty-prints a formatted forest tree.  Printing begins
   from `ele` (it will appear as the root in the print output).

   The most straightforward and commonly used printing pattern is:
   `fd_forest_print( forest, fd_forest_root( forest ) )`

   This would print forest beginning from the root.

   Alternatively, caller can print a more localized view, for example
   starting from the grandparent of the most recently executed slot:

   ```
   fd_forest_ele_t const * ele = fd_forest_query( slot );
   fd_forest_print( forest, fd_forest_parent( fd_forest_parent( ele ) ) )
   ```

   Callers should add null-checks as appropriate in actual usage. */

void
fd_forest_print( fd_forest_t const * forest );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_forest_fd_forest_h */
