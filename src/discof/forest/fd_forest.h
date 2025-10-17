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

#define SET_NAME fd_forest_blk_idxs
#define SET_MAX  FD_SHRED_BLK_MAX
#include "../../util/tmpl/fd_set.c"

/* fd_forest_blk_t implements a left-child, right-sibling n-ary
   tree. Each ele maintains the `pool` index of its left-most child
   (`child_idx`), its immediate-right sibling (`sibling_idx`), and its
   parent (`parent_idx`).

   This tree structure is gaddr-safe and supports accesses and
   operations from processes with separate local forest joins. */

struct __attribute__((aligned(128UL))) fd_forest_blk {
  ulong slot;        /* map key */
  ulong parent_slot; /* map key of the parent. invariant: if parent is populated, parent_slot is populated. the converse is not necessarily true. */
  ulong next;        /* internal use by fd_pool, fd_map_chain */
  ulong parent;      /* pool idx of the parent in the tree */
  ulong child;       /* pool idx of the left-child */
  ulong sibling;     /* pool idx of the right-sibling */

  uint consumed_idx; /* highest contiguous fec-completed shred idx */
  uint buffered_idx; /* highest contiguous buffered shred idx */
  uint complete_idx; /* shred_idx with SLOT_COMPLETE_FLAG ie. last shred idx in the slot */

  fd_forest_blk_idxs_t fecs[fd_forest_blk_idxs_word_cnt]; /* fec set idxs - 1, or the idx of the last shred in every FEC set */
  fd_forest_blk_idxs_t idxs[fd_forest_blk_idxs_word_cnt]; /* data shred idxs */
  fd_forest_blk_idxs_t cmpl[fd_forest_blk_idxs_word_cnt]; /* last shred idx of every FEC set that has been completed by shred_tile */

  /* i.e. when fecs == cmpl, the slot is truly complete and everything
  is contained in fec store. Look at fec_clear for more details.*/

  int est_buffered_tick_recv; /* tick of shred at buffered_idx.  Note since we don't track all the
                                 ticks received, this will be a lower bound estimate on the highest tick we have seen.
                                 But this is only used for limiting eager repair, so an exact value is not necessary. */

  /* Metrics */

  fd_forest_blk_idxs_t code[fd_forest_blk_idxs_word_cnt]; /* code shred idxs */
  long first_shred_ts; /* tick of first shred rcved in slot != complete_idx */
  long first_req_ts;   /* tick of first request sent in slot != complete_idx */
  uint turbine_cnt;    /* number of shreds received from turbine */
  uint repair_cnt;     /* number of data shreds received from repair */
  uint recovered_cnt;  /* number of shreds recovered from reedsol recovery */
};
typedef struct fd_forest_blk fd_forest_blk_t;

#define POOL_NAME fd_forest_pool
#define POOL_T    fd_forest_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_forest_ancestry
#define MAP_ELE_T fd_forest_blk_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_forest_frontier
#define MAP_ELE_T fd_forest_blk_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_forest_orphaned
#define MAP_ELE_T fd_forest_blk_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME  fd_forest_subtrees
#define MAP_ELE_T fd_forest_blk_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

/* A reference to a forest element

   The following maps/pools are used to track future requests.

   Requests:
    - slots that branch from the main tree (ancestry) that are being repaired /
      have yet to be repaired.  Maintained in a dlist, where the head
      is the current slot being repaired.

   Orphreqs (orphaned requests):
    - slots that branch from the unconnected trees (subtrees/orphans) that are being repaired /
      have yet to be repaired.  Maintained in a dlist, where the head
      is the current orphan request being repaired.

      Note that orphan requests are specifically an optimization from when
      we are catching up from very far behind.  In the usual case when we
      boot and we are catching up from close behind, need orphans is
      very fast and has a non-negligible cost on total repair time.  But
      during special cases where we are catching up from very far behind,
      need orphans can take a significant time because orphan requests
      cannot be pipelined.  In this case, we can use time waiting for
      orphan requests to respond to also repair the full slots of these
      orphan trees.

    Consumed:
    - slots where the entire ancestry up to the root has been completed.
      This is what we are repairing next.  There should be <= num forks
      elements in the consumed map.
*/
struct fd_forest_ref {
  ulong idx;             /* forest pool idx of the ele this ref refers to */
  ulong next;            /* reserved by dlist */
  ulong prev;            /* reserved by dlist */
  ulong hash;            /* reserved by pool and map_chain */
};
typedef struct fd_forest_ref fd_forest_ref_t;

#define MAP_NAME     fd_forest_requests  /* TODO this map could be redundant (i.e. we only need the deque).  Also this is awkwardly coupled between forest and policy */
#define MAP_ELE_T    fd_forest_ref_t
#define MAP_KEY      idx
#define MAP_NEXT     hash
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME   fd_forest_reqslist
#define DLIST_ELE_T  fd_forest_ref_t
#define DLIST_NEXT   next
#define DLIST_PREV   prev
#include "../../util/tmpl/fd_dlist.c"

#define POOL_NAME    fd_forest_reqspool
#define POOL_T       fd_forest_ref_t
#define POOL_NEXT    hash
#include "../../util/tmpl/fd_pool.c"

/* Below for fast tracking of contiguous completes slots */
#define MAP_NAME     fd_forest_consumed
#define MAP_ELE_T    fd_forest_ref_t
#define MAP_KEY      idx
#define MAP_NEXT     hash
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME   fd_forest_conslist
#define DLIST_ELE_T  fd_forest_ref_t
#define DLIST_NEXT   next
#define DLIST_PREV   prev
#include "../../util/tmpl/fd_dlist.c"

#define POOL_NAME    fd_forest_conspool
#define POOL_T       fd_forest_ref_t
#define POOL_NEXT    hash
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME     fd_forest_orphreqs
#define MAP_ELE_T    fd_forest_ref_t
#define MAP_KEY      idx
#define MAP_NEXT     hash
#include "../../util/tmpl/fd_map_chain.c"

/* Reuse reqslist for orphan requests list, and share pool */

/* Internal use only for BFSing */
#define DEQUE_NAME fd_forest_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"


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
   | subtrees          |
   |-------------------|
   | orphaned          |
   |-------------------|
   | requests          |
   |-------------------|
   | reqslist          |
   |-------------------|
   | reqspool          |
   |-------------------|
   | orphreqs          |
   |-------------------|
   | orphlist (reqlist)|
   |-------------------|
   | consumed          |
   |-------------------|
   | conspool          |
   |-------------------|
   | deque             |
   ---------------------

   A valid, initialized forest is always non-empty.  After
   `fd_forest_init` the forest will always have a root ele unless
   modified improperly out of forest's API.*/

struct fd_forest_iter {
  ulong ele_idx;
  uint  shred_idx;
  ulong list_gaddr; /* wksp gaddr of the list this iterator corresponds to */
};
typedef struct fd_forest_iter fd_forest_iter_t;
struct __attribute__((aligned(128UL))) fd_forest {
  ulong root;           /* pool idx of the root */
  ulong wksp_gaddr;     /* wksp gaddr of fd_forest in the backing wksp, non-zero gaddr */
  ulong ver_gaddr;      /* wksp gaddr of version fseq, incremented on write ops */
  ulong pool_gaddr;     /* wksp gaddr of fd_pool */
  ulong ancestry_gaddr; /* wksp_gaddr of fd_forest_ancestry */
  ulong frontier_gaddr; /* leaves that needs repair */
  ulong subtrees_gaddr; /* head of orphaned trees */
  ulong orphaned_gaddr; /* map of parent_slot to singly-linked list of ele orphaned by that parent slot */

  /* Request trackers */

  ulong requests_gaddr; /* map of slot to pool idx of the completed repair frontier */
  ulong reqslist_gaddr; /* wksp gaddr of fd_forest_reqslist */
  ulong reqspool_gaddr; /* wksp gaddr of fd_forest_reqspool */

  ulong consumed_gaddr; /* wksp gaddr of fd_forest_consumed */
  ulong conslist_gaddr; /* wksp gaddr of fd_forest_conslist */
  ulong conspool_gaddr; /* wksp gaddr of fd_forest_conspool */

  ulong orphreqs_gaddr; /* wksp gaddr of fd_forest_orphreqs */
  ulong orphlist_gaddr; /* wksp gaddr of fd_forest_orphlist */

  fd_forest_iter_t iter; /* requests iterator corresponding to head of requests deque */
  fd_forest_iter_t orphiter; /* orphan requests iterator corresponding to head of orphan requests list */

  ulong deque_gaddr;    /* wksp gaddr of fd_forest_deque. internal use only for BFSing */
  ulong magic;          /* ==FD_FOREST_MAGIC */

  ulong subtree_cnt;    /* number of subtrees in the forest - useful for iterating over orphaned subtrees */
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
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_forest_t),       sizeof(fd_forest_t)                     ),
      fd_fseq_align(),            fd_fseq_footprint()                     ),
      fd_forest_pool_align(),     fd_forest_pool_footprint    ( ele_max ) ),
      fd_forest_ancestry_align(), fd_forest_ancestry_footprint( ele_max ) ),
      fd_forest_frontier_align(), fd_forest_frontier_footprint( ele_max ) ),
      fd_forest_subtrees_align(), fd_forest_subtrees_footprint( ele_max ) ),
      fd_forest_orphaned_align(), fd_forest_orphaned_footprint( ele_max ) ),
      fd_forest_requests_align(), fd_forest_requests_footprint( ele_max ) ),
      fd_forest_reqslist_align(), fd_forest_reqslist_footprint(         ) ),
      fd_forest_reqspool_align(), fd_forest_reqspool_footprint( ele_max ) ),
      fd_forest_consumed_align(), fd_forest_consumed_footprint( ele_max ) ),
      fd_forest_conslist_align(), fd_forest_conslist_footprint(         ) ),
      fd_forest_conspool_align(), fd_forest_conspool_footprint( ele_max ) ),
      fd_forest_orphreqs_align(), fd_forest_orphreqs_footprint( ele_max ) ),
      fd_forest_reqslist_align(), fd_forest_reqslist_footprint(         ) ),
      fd_forest_deque_align(),    fd_forest_deque_footprint   ( ele_max ) ),
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

fd_forest_t *
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

FD_FN_PURE static inline fd_forest_blk_t *
fd_forest_pool( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->pool_gaddr );
}

FD_FN_PURE static inline fd_forest_blk_t const *
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

/* fd_forest_{subtrees, subtrees_const} returns a pointer in the caller's
   address space to forest's subtrees map. */

FD_FN_PURE static inline fd_forest_subtrees_t *
fd_forest_subtrees( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->subtrees_gaddr );
}

FD_FN_PURE static inline fd_forest_subtrees_t const *
fd_forest_subtrees_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->subtrees_gaddr );
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

/* fd_forest_{consumed, consumed_const} returns a pointer in the caller's
   address space to forest's consumed map. */

FD_FN_PURE static inline fd_forest_consumed_t *
fd_forest_consumed( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->consumed_gaddr );
}

FD_FN_PURE static inline fd_forest_consumed_t const *
fd_forest_consumed_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->consumed_gaddr );
}

/* fd_forest_{conslist, conslist_const} returns a pointer in the caller's
   address space to forest's consumed list. */

FD_FN_PURE static inline fd_forest_conslist_t *
fd_forest_conslist( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->conslist_gaddr );
}

FD_FN_PURE static inline fd_forest_conslist_t const *
fd_forest_conslist_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->conslist_gaddr );
}

/* fd_forest_{conspool, conspool_const} returns a pointer in the caller's
   address space to forest's consumed pool. */

FD_FN_PURE static inline fd_forest_ref_t *
fd_forest_conspool( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->conspool_gaddr );
}

FD_FN_PURE static inline fd_forest_ref_t const *
fd_forest_conspool_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->conspool_gaddr );
}

/* fd_forest_{requests, requests_const} returns a pointer in the caller's
   address space to forest's requests map. */

FD_FN_PURE static inline fd_forest_requests_t *
fd_forest_requests( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->requests_gaddr );
}

FD_FN_PURE static inline fd_forest_requests_t const *
fd_forest_requests_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->requests_gaddr );
}

/* fd_forest_{reqslist, reqslist_const} returns a pointer in the caller's
   address space to forest's reqslist. */

FD_FN_PURE static inline fd_forest_reqslist_t *
fd_forest_reqslist( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->reqslist_gaddr );
}

FD_FN_PURE static inline fd_forest_reqslist_t const *
fd_forest_reqslist_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->reqslist_gaddr );
}

/* fd_forest_{orphreqs, orphanreqs_const} returns a pointer in the caller's
   address space to forest's orphanreqs. */

FD_FN_PURE static inline fd_forest_orphreqs_t *
fd_forest_orphreqs( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->orphreqs_gaddr );
}

FD_FN_PURE static inline fd_forest_orphreqs_t const *
fd_forest_orphreqs_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->orphreqs_gaddr );
}

/* fd_forest_{orphlist, orphanlist_const} returns a pointer in the caller's
   address space to forest's orphanlist. */

FD_FN_PURE static inline fd_forest_reqslist_t *
fd_forest_orphlist( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->orphlist_gaddr );
}

FD_FN_PURE static inline fd_forest_reqslist_t const *
fd_forest_orphlist_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->orphlist_gaddr );
}

/* fd_forest_{reqspool, reqspool_const} returns a pointer in the caller's
   address space to forest's reqspool pool. */

FD_FN_PURE static inline fd_forest_ref_t *
fd_forest_reqspool( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->reqspool_gaddr );
}

FD_FN_PURE static inline fd_forest_ref_t const *
fd_forest_reqspool_const( fd_forest_t const * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->reqspool_gaddr );
}

/* fd_forest_root_slot returns forest's root slot.  Assumes
   forest is a current local join. */

FD_FN_PURE static inline ulong
fd_forest_root_slot( fd_forest_t const * forest ) {
  if( FD_UNLIKELY( forest->root == fd_forest_pool_idx_null( fd_forest_pool_const( forest ) ) )) return ULONG_MAX; /* uninitialized */
  return fd_forest_pool_ele_const( fd_forest_pool_const( forest ), forest->root )->slot;
}

fd_forest_blk_t *
fd_forest_query( fd_forest_t * forest, ulong slot );

/* Operations */

/* fd_forest_blk_insert inserts a new block into the forest.  Assumes
   slot >= forest->smr, and the blk pool has a free element (if
   handholding is enabled, explicitly checks and errors).  This blk
   insert is idempotent, and can be called multiple times with the same
   slot. Returns the inserted forest ele. */

fd_forest_blk_t *
fd_forest_blk_insert( fd_forest_t * forest, ulong slot, ulong parent_slot );

#define SHRED_SRC_TURBINE   0
#define SHRED_SRC_REPAIR    1
#define SHRED_SRC_RECOVERED 2

/* fd_forest_shred_insert inserts a new shred into the forest.
   Assumes slot is already in forest, and should typically be called
   directly after fd_forest_block_insert. Returns the forest ele
   corresponding to the shred slot. */

fd_forest_blk_t *
fd_forest_data_shred_insert( fd_forest_t * forest, ulong slot, ulong parent_slot, uint shred_idx, uint fec_set_idx, int slot_complete, int ref_tick, int src );

fd_forest_blk_t *
fd_forest_code_shred_insert( fd_forest_t * forest, ulong slot, uint shred_idx );

/* fd_forest_fec_insert inserts a new fully completed FEC set into the
   forest. Assumes slot is already in forest, and should typically be
   called directly after fd_forest_block_insert. Returns the forest ele
   corresponding to the shred slot. */

fd_forest_blk_t *
fd_forest_fec_insert( fd_forest_t * forest, ulong slot, ulong parent_slot, uint last_shred_idx, uint fec_set_idx, int slot_complete, int ref_tick );

/* fd_forest_fec_clear clears the FEC set at the given slot and
   fec_set_idx.
   Can fec_clear break requests frontier invariants? No. Why?

   TODO: Update this comment with new requests map changes

        2) If slot n is in scope of the forest root, then the shred
           delivered to repair will trigger a data_shred_insert call
           that does nothing, as repair already has record of that
           shred.  Eventually the fec_completes or fec_clear msg will be
           delivered to repair. fec_insert will do nothing. fec_clear
           will remove the idxs for the shreds from the bitset, and
           update the buffered_idx. This doesn't matter though! because
           we already have moved past slot n on the requests frontier.
           No need to request those shreds again.

      Except 2) breaks a bit with in specific leader slot cases. See
      fd_forest_fec_clear for more details. */

void
fd_forest_fec_clear( fd_forest_t * forest, ulong slot, uint fec_set_idx, uint max_shred_idx );

/* fd_forest_publish publishes slot as the new forest root, setting
   the subtree beginning from slot as the new forest tree (ie. slot
   and all its descendants).  Prunes all eles not in slot's forest.
   Assumes slot is present in forest.  Returns the new root. */

fd_forest_blk_t const *
fd_forest_publish( fd_forest_t * forest, ulong slot );

/* fd_forest_highest_repaired_slot returns the highest child of a fully,
   contiguously repaired slot. */
ulong
fd_forest_highest_repaired_slot( fd_forest_t const * forest );

/* fd_forest_iter_* takes either the standard iterator or the orphan
   iterator and returns the next shred to request.  The iterator must
   one of the two iterators that is owned by the forest.

   The iterator will be in an iter_done state if there are no current
   shreds to request.

   The forward forest iterator will visit each shred at most once over
   the lifetime of the forest, without revisiting past shreds, so it is
   up to the caller to track which shreds will need re-requesting.  The
   exception to the rule is slots where the slot_complete shred is still
   not known - the highest window idx will be requested for that slot,
   and the slot will be added to the tail of the requests deque so that
   later we may revisit it.  As a result, the children of that slot may
   also be revisited multiple times.

   Note this case is pretty rare.

   An iterator signifies to the repair tile to request the
   highest_window_index when the ele_idx is not null and shred_idx is
   UINT_MAX.

   Otherwise, the iterator signifies to the repair tile to request a
   regular shred window_idx.

   Invariants for requests map and requests deque:

   There can only be one occurence of the slot in the requests deque at
   any time. Any slot in the requests deque must exist in the requests
   map, and vice versa. Any slot in the requests map must also exist in
   the forest.  During publish the requests map must also be pruned.

   If we are mid-request of a slot that gets pruned, forest will take
   responsibility to update the iterator to a valid slot.

   TODO: should this really be an iterator?? or just a _next function?
   also like the iterators live in forest.... so the forest can
   invalidate them.... this is just uglee */

fd_forest_iter_t *
fd_forest_iter_next( fd_forest_iter_t * iter, fd_forest_t * forest );

int
fd_forest_iter_done( fd_forest_iter_t * iter, fd_forest_t * forest );

/* Misc */

/* fd_forest_verify checks the forest is not obviously corrupt.
   Returns 0 if verify succeeds, -1 otherwise. */

int
fd_forest_verify( fd_forest_t const * forest );

/* fd_forest_print pretty-prints a formatted forest tree.  Printing begins
   from `ele` (it will appear as the root in the print output).

   The most straightforward and commonly used printing pattern is:
   `fd_forest_print( forest, fd_forest_root( forest ) )`

   This would print forest beginning from the root.

   Alternatively, caller can print a more localized view, for example
   starting from the grandparent of the most recently executed slot:

   ```
   fd_forest_blk_t const * ele = fd_forest_query( slot );
   fd_forest_print( forest, fd_forest_parent( fd_forest_parent( ele ) ) )
   ```

   Callers should add null-checks as appropriate in actual usage. */

void
fd_forest_print( fd_forest_t const * forest );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_forest_fd_forest_h */
