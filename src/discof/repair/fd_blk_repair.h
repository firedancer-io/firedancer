#ifndef HEADER_fd_src_choreo_blk_repair_fd_blk_repair_h
#define HEADER_fd_src_choreo_blk_repair_fd_blk_repair_h

#include "../../disco/fd_disco_base.h"

/* Blk repair is an API for repairing blocks as they are discovered from
   the cluster via Turbine or Gossip.  Shreds (from Turbine) and votes
   (from Gossip) inform blk repair that a block with the given slot they
   are associated with exists.  Blk repair ensures that this block is
   received in its entirety by requesting repairs for missing shreds for
   the block.

   Like other fork-aware structures, blk repair maintains a tree that
   records the ancestry of slots.  It also maintains a frontier, which
   models the leaves of the tree ie. the oldest (in ancestry) blocks
   that still need to be repaired (across multiple forks).

   Blk repair constructs the ancestry tree backwards, and then repairs
   the tree forwards (using BFS). */

/* FD_BLK_REPAIR_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_BLK_REPAIR_USE_HANDHOLDING
#define FD_BLK_REPAIR_USE_HANDHOLDING 1
#endif

#define FD_BLK_REPAIR_VER_UNINIT (0UL)
#define FD_BLK_REPAIR_VER_INVAL  (ULONG_MAX)

#define FD_BLK_REPAIR_MAGIC (0xf17eda2ce7b1c0UL) /* firedancer blk version 0 */

#define FD_BLK_REPAIR_TEST(c) do { if( FD_UNLIKELY( !(c) ) ) fd_fseq_update( *ver, fd_fseq_query( *ver ) + 1 ); FD_LOG_ERR(( "FAIL: %s", #c )); } while(0)

#define SET_NAME fd_blk_ele_idxs
#define SET_MAX  FD_SHRED_BLK_MAX
#include "../../util/tmpl/fd_set.c"


/* fd_blk_repair_ele_t implements a left-child, right-sibling n-ary
   tree. Each ele maintains the `pool` index of its left-most child
   (`child_idx`), its immediate-right sibling (`sibling_idx`), and its
   parent (`parent_idx`).

   This tree structure is gaddr-safe and supports accesses and
   operations from processes with separate local blk_repair joins. */

struct __attribute__((aligned(128UL))) fd_blk_ele {
  ulong slot;    /* map key */
  ulong prev;    /* internal use by link_orphans */
  ulong next;    /* internal use by fd_pool, fd_map_chain */
  ulong parent;  /* pool idx of the parent in the tree, parent slot when orphaned */
  ulong child;   /* pool idx of the left-child */
  ulong sibling; /* pool idx of the right-sibling */

  uint received_idx; /* highest received shred idx */
  uint consumed_idx; /* highest contiguosly-received shred idx */
  uint complete_idx; /* shred_idx with SLOT_COMPLETE_FLAG ie. last shred idx in the slot */

  fd_blk_ele_idxs_t fecs[fd_blk_ele_idxs_word_cnt]; /* fec set idxs */
  fd_blk_ele_idxs_t idxs[fd_blk_ele_idxs_word_cnt]; /* data shred idxs */
};
typedef struct fd_blk_ele fd_blk_ele_t;

#define POOL_NAME fd_blk_pool
#define POOL_T    fd_blk_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_blk_ancestry
#define MAP_ELE_T fd_blk_ele_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_blk_frontier
#define MAP_ELE_T fd_blk_ele_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_blk_orphaned
#define MAP_ELE_T fd_blk_ele_t
#define MAP_KEY   parent
#include "../../util/tmpl/fd_map_chain.c"

/* fd_blk_repair_t is the top-level structure that holds the root of
   the tree, as well as the memory pools and map structures.

   These structures are bump-allocated and laid out contiguously in
   memory from the fd_blk_repair_t * pointer which points to the
   beginning of the memory region.

   --------------------- <- fd_blk_repair_t *
   | metadata          |
   |-------------------|
   | pool              |
   |-------------------|
   | chainer           |
   |-------------------|
   | frontier          |
   |-------------------|
   | orphaned          |
   ---------------------

   A valid, initialized blk_repair is always non-empty.  After
   `fd_blk_repair_init` the blk_repair will always have a root ele unless
   modified improperly out of blk_repair's API.*/

struct __attribute__((aligned(128UL))) fd_blk_repair {
  ulong root;           /* pool idx of the root */
  ulong wksp_gaddr;     /* wksp gaddr of fd_blk_repair in the backing wksp, non-zero gaddr */
  ulong ver_gaddr;      /* wksp gaddr of version fseq, incremented on write ops */
  ulong pool_gaddr;     /* wksp gaddr of fd_pool */
  ulong ancestry_gaddr; /* wksp_gaddr of fd_blk_ancestry */
  ulong frontier_gaddr; /* map of slot to ele (leaf that needs repair) */
  ulong orphaned_gaddr; /* map of parent_slot to singly-linked list of ele orphaned by that parent slot */
  ulong magic;          /* ==FD_BLK_REPAIR_MAGIC */
};
typedef struct fd_blk_repair fd_blk_repair_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_blk_repair_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as blk_repair with up to
   ele_max eles and vote_max votes. */

FD_FN_CONST static inline ulong
fd_blk_repair_align( void ) {
  return alignof(fd_blk_repair_t);
}

FD_FN_CONST static inline ulong
fd_blk_repair_footprint( ulong ele_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_blk_repair_t),  sizeof(fd_blk_repair_t)              ),
      fd_fseq_align(),           fd_fseq_footprint()                  ),
      fd_blk_pool_align(),       fd_blk_pool_footprint( ele_max )     ),
      fd_blk_ancestry_align(),   fd_blk_ancestry_footprint( ele_max ) ),
      fd_blk_frontier_align(),   fd_blk_frontier_footprint( ele_max ) ),
      fd_blk_orphaned_align(),   fd_blk_orphaned_footprint( ele_max ) ),
    fd_blk_repair_align() );
}

/* fd_blk_repair_new formats an unused memory region for use as a
   blk_repair.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_blk_repair_new( void * shmem, ulong seed, ulong ele_max );

/* fd_blk_repair_join joins the caller to the blk_repair.  blk_repair
   points to the first byte of the memory region backing the blk_repair
   in the caller's address space.  Returns a pointer in the local
   address space to blk_repair on success. */

fd_blk_repair_t *
fd_blk_repair_join( void * blk_repair );

/* fd_blk_repair_leave leaves a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include blk_repair is NULL. */

void *
fd_blk_repair_leave( fd_blk_repair_t const * blk_repair );

/* fd_blk_repair_delete unformats a memory region used as a
   blk_repair. Assumes only the nobody is joined to the region.
   Returns a pointer to the underlying shared memory region or NULL if
   used obviously in error (e.g. blk_repair is obviously not a
   blk_repair ... logs details). The ownership of the memory region is
   transferred to the caller. */

void *
fd_blk_repair_delete( void * blk_repair );

/* fd_blk_repair_init initializes a blk_repair.  Assumes blk_repair
   is a valid local join and no one else is joined.  root is the initial
   root blk_repair will use.  This is the snapshot slot if booting from
   a snapshot, 0 if the genesis slot.

   In general, this should be called by the same process that formatted
   blk_repair's memory, ie. the caller of fd_blk_repair_new. */

fd_blk_repair_t *
fd_blk_repair_init( fd_blk_repair_t * blk_repair, ulong root );

/* fd_blk_repair_fini finishes an blk_repair.  Assumes blk_repair is
   a valid local join and no one else is joined. */

void *
fd_blk_repair_fini( fd_blk_repair_t * blk_repair );

/* Accessors */

/* fd_blk_repair_wksp returns the local join to the wksp backing the
   blk_repair.  The lifetime of the returned pointer is at least as
   long as the lifetime of the local join.  Assumes blk_repair is a
   current local join. */

FD_FN_PURE static inline fd_wksp_t *
fd_blk_repair_wksp( fd_blk_repair_t const * blk_repair ) {
  return (fd_wksp_t *)( ( (ulong)blk_repair ) - blk_repair->wksp_gaddr );
}

/* fd_blk_repair_{ver, ver_const} returns the local join to the version
   number fseq.  The lifetime of the returned pointer is at least as
   long as the lifetime of the local join.  Assumes blk_repair is a
   current local join.  If value is ULONG_MAX, ghost is uninitialized or
   invalid.  Query pre- & post-read:

   odd:  if either pre or post is odd, discard read.
   even: if pre == post, read is consistent. */

FD_FN_PURE static inline ulong *
fd_blk_repair_ver( fd_blk_repair_t * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->ver_gaddr );
}

FD_FN_PURE static inline ulong const *
fd_blk_repair_ver_const( fd_blk_repair_t const * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->ver_gaddr );
}

/* fd_blk_{pool, pool_const} returns a pointer in the caller's address
   space to blk_repair's element pool. */

FD_FN_PURE static inline fd_blk_ele_t *
fd_blk_pool( fd_blk_repair_t * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->pool_gaddr );
}

FD_FN_PURE static inline fd_blk_ele_t const *
fd_blk_pool_const( fd_blk_repair_t const * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->pool_gaddr );
}

/* fd_blk_{ancestry, ancestry_const} returns a pointer in the caller's
   address space to blk_repair's ancestry map. */

FD_FN_PURE static inline fd_blk_ancestry_t *
fd_blk_ancestry( fd_blk_repair_t * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->ancestry_gaddr );
}

FD_FN_PURE static inline fd_blk_ancestry_t const *
fd_blk_ancestry_const( fd_blk_repair_t const * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->ancestry_gaddr );
}

/* fd_blk_{frontier, frontier_const} returns a pointer in the caller's
   address space to blk_repair's frontier map. */

FD_FN_PURE static inline fd_blk_frontier_t *
fd_blk_frontier( fd_blk_repair_t * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->frontier_gaddr );
}

FD_FN_PURE static inline fd_blk_frontier_t const *
fd_blk_frontier_const( fd_blk_repair_t const * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->frontier_gaddr );
}

/* fd_blk_{orphaned, orphaned_const} returns a pointer in the caller's
   address space to blk_repair's orphaned map. */

FD_FN_PURE static inline fd_blk_orphaned_t *
fd_blk_orphaned( fd_blk_repair_t * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->orphaned_gaddr );
}

FD_FN_PURE static inline fd_blk_orphaned_t const *
fd_blk_orphaned_const( fd_blk_repair_t const * blk_repair ) {
  return fd_wksp_laddr_fast( fd_blk_repair_wksp( blk_repair ), blk_repair->orphaned_gaddr );
}

/* fd_blk_repair_root_slot returns blk_repair's root slot.  Assumes
   blk_repair is a current local join. */

FD_FN_PURE static inline ulong
fd_blk_repair_root_slot( fd_blk_repair_t const * blk_repair ) {
  if( FD_UNLIKELY( blk_repair->root == fd_blk_pool_idx_null( fd_blk_pool_const( blk_repair ) ) )) return ULONG_MAX; /* uninitialized */
  return fd_blk_pool_ele_const( fd_blk_pool_const( blk_repair ), blk_repair->root )->slot;
}

/* Operations */

/* fd_blk_repair_shred_insert inserts a new shred into the blk_repair.
   Assumes slot >= blk_repair->smr, slot is not already in blk_repair,
   parent_slot is already in blk_repair, and the ele pool has a free
   element (if handholding is enabled, explicitly checks and errors).
   Returns the inserted blk_repair ele. */

fd_blk_ele_t *
fd_blk_repair_data_shred_insert( fd_blk_repair_t * blk_repair, ulong slot, ushort parent_off, uint shred_idx, uint fec_set_idx, uint complete_idx );

/* fd_blk_repair_publish publishes slot as the new blk_repair root, setting
   the subtree beginning from slot as the new blk_repair tree (ie. slot
   and all its descendants).  Prunes all eles not in slot's blk_repair.
   Assumes slot is present in blk_repair.  Returns the new root. */

fd_blk_ele_t const *
fd_blk_repair_publish( fd_blk_repair_t * blk_repair, ulong slot );

/* Misc */

/* fd_blk_repair_verify checks the blk_repair is not obviously corrupt.
   Returns 0 if verify succeeds, -1 otherwise. */

int
fd_blk_repair_verify( fd_blk_repair_t const * blk_repair );

void
fd_blk_repair_frontier_print( fd_blk_repair_t const * blk_repair );

/* fd_blk_repair_print pretty-prints a formatted blk_repair tree.  Printing begins
   from `ele` (it will appear as the root in the print output).

   The most straightforward and commonly used printing pattern is:
   `fd_blk_repair_print( blk_repair, fd_blk_repair_root( blk_repair ) )`

   This would print blk_repair beginning from the root.

   Alternatively, caller can print a more localized view, for example
   starting from the grandparent of the most recently executed slot:

   ```
   fd_blk_repair_ele_t const * ele = fd_blk_repair_query( slot );
   fd_blk_repair_print( blk_repair, fd_blk_repair_parent( fd_blk_repair_parent( ele ) ) )
   ```

   Callers should add null-checks as appropriate in actual usage. */

void
fd_blk_repair_print( fd_blk_repair_t const * blk_repair );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_blk_repair_fd_blk_repair_h */
