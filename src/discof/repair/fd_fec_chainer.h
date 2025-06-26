#ifndef HEADER_fd_src_discof_repair_fd_fec_chainer_h
#define HEADER_fd_src_discof_repair_fd_fec_chainer_h

/* FEC chainer is an API for "chaining" FEC sets as they are received
   asynchronously out-of-order over the network (via Turbine and
   Repair).  The chainer both validates and reorders those FEC sets, and
   delivers them in-order to the calling application.

   Every FEC set has a parent (the immediately preceding FEC set in the
   slot or parent slot) and children (immediately succeeding FEC set(s)
   for the same slot or child slots).  Because of forks, FEC sets can
   have multiple children, but this will only be true across slots (ie.
   the parent and child must be different slots).  The chainer treats
   forks as "concurrent" with no particular order, so the calling
   application will receive forking FEC sets in the order in which the
   chainer is able to chain them.

   There is a protocol violation called equivocation (also known as
   "duplicates") that breaks the invariant that forks must be across
   slots.  For example, equivocation can result in observing two or more
   child FEC sets for a given parent FEC set in the same slot.
   Equivocation can also result in other anomalies such as keying
   collisions (this is detailed later in the documentation).  The
   chainer makes a best-effort attempt to detect and error on
   equivocation. Examples include checking merkle roots chain correctly
   and checking FEC sets are unique.  Not all cases of equivocation can
   be detected by the chainer however, as not all the necessary
   information is yet available at this stage in the validator pipeline.
   Ultimately, if there is equivocation, it is the responsibility of the
   consensus module to handle it. */

#include "../../ballet/shred/fd_shred.h"

/* FD_FEC_CHAINER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_FEC_CHAINER_USE_HANDHOLDING
#define FD_FEC_CHAINER_USE_HANDHOLDING 1
#endif

#define FD_FEC_CHAINER_SUCCESS    ( 0)
#define FD_FEC_CHAINER_ERR_UNIQUE (-1) /* key uniqueness conflict */
#define FD_FEC_CHAINER_ERR_MERKLE (-2) /* chained merkle root conflict */

/* fd_fec_chainer is a tree-like structure backed by three maps.  At any
   given point in time, an element (FEC set) in the chainer is in one of
   three possible positions with respect to the tree: a non-leaf, leaf,
   or not connected.  This corresponds to the ancestry, frontier, or
   orphaned maps, respectively.  Therefore, a given element will always
   be present in exactly one of these maps, depending on where (and
   whether) it currently is in the tree.

   KEYING

   The chainer keys FEC sets by concatenating the slot with fec_set_idx.
   This uniquely identifies a FEC set in most cases.  It is possible to
   receive over the network two or more different FEC sets with the same
   slot and fec_set_idx due to equivocation as mentioned earlier.  In
   general, the chainer expects the caller to handle equivocation and
   assumes unique FEC sets will have unique keys (handholding is
   available to verify this).

   The map key is an encoding of the slot and fec_set_idx which uniquely
   keys every FEC set.  The 32 msb of the key are the 32 lsb of the slot
   and the 32 lsb of the key are the fec_set_idx, except when the FEC
   set is the last one for the slot, in which case the 32 lsb are set to
   UINT_MAX. By setting fec_set_idx to UINT_MAX, the chainer can easily
   query for the last FEC set in any given slot

   A useful property of the keying scheme above is a FEC set can infer
   the key of its immediate child by adding data_cnt to its fec_set_idx.
   For example, a FEC set for slot 0, fec_set_idx 0, data_cnt 32 knows
   its child key is slot 0, fec_set_idx 32. The last FEC set in the slot
   is special because the child(s) FEC set will have a different slot
   number, so we know the fec_set_idx will be zero.

   There is one exception to this keying scheme.  When the FEC set is
   the last one in the slot, an extra insertion to the parent_map is
   done. In the standard procedure, the second to last fec will create
   the (n-1, n) entry, and the following child slot will create a
   (UINT_MAX, 0) entry. Thus we insert an extra entry (n, UINT_MAX) in
   the parent_map to connect the chain. This double insertion is only
   done for the parent_map - the pool_ele will have an element with key
   slot | fec_set_idx, not UINT_MAX.

   Visually, the parent_map / elements looks like this:

      - Arrows denote a child->parent entry in the parent_map.

   parent_map                                             |  pool_ele (slot, fec_set_idx, completes)
   ──────────────────────────────────────────────────────────────────────────────────────────────────
   (slot, 0)                                              |  (slot, 0,  0)
       ▲                                                  |
       |                                                  |
   (slot, 32)                                             |  (slot, 32, 0)
       ▲                                                  |
       |                                                  |
   (slot, 64) <-- (slot, UINT_MAX)                        |  (slot, 64, 1)
                        ▲                                 |
                        |                                 |
                  (slot + 1, 0)                           |  (slot + 1, 0, 0)
                        ▲                                 |
                        |                                 |
                  (slot + 1, 32)                          |  (slot + 1, 32, 0)
                        ▲                                 |
                        |                                 |
                  (slot + 1, 64) ◄── (slot + 1, UINT_MAX) |  (slot + 1, 64, 1)
                        ▲                                 |
                        | ...                             |

   Thus we will have double entries for the last FEC set in a slot in
   the parent map, but only one entry in the ancestry/orphan/frontier
   pool. This means if we want to query for the last FEC set in a slot,
   we need to query the parent_map twice - once with the fec_set_idx set
   to UINT_MAX and once with the parent_key of the result.

   INSERTING

   When inserting a new FEC set, the chainer first checks whether the
   parent is a FEC set already in the frontier map.  This indicates that
   the new FEC set directly chains off the frontier.  If it does, the
   parent FEC set is removed, and the new FEC set is inserted into the
   frontier map.  This is the common case because we expect FEC sets to
   chain linearly the vast majority (ie. not start new forks), so the
   new FEC set is simply "advancing" the frontier.  The parent FEC set
   is also added to the ancestry map, so that every leaf can trace back
   to the root.

   If the FEC set's parent is not already in the frontier, the chainer
   checks the ancestry map next.  If the parent is in the ancestry map,
   the chainer knows that this FEC set is starting a new fork, because
   it is part of the tree (the ancestry) but not one of the leaves (the
   frontier).  In this case, the new FEC set is simply inserted into the
   frontier map, and now the frontier has an additional fork (leaf).

   Lastly, if the FEC set's parent is not in the ancestry map, the
   chainer knows that this FEC set is orphaned.  It is inserted into the
   orphaned map for later retry of tree insertion when its ancestors
   have been inserted.

   Here are some more important details on forks. Note a FEC set can
   only start a new fork when it is across a slot boundary (different
   slot than its parent).  It is invalid for two FEC sets to chain off
   the same parent FEC within the same slot - this would imply there are
   two FECs keyed by the (same slot, fec_set_idx) combination, which as
   detailed earlier, is equivocation.  Therefore, only the first FEC set
   in a slot can start a fork from the last FEC set in a parent slot. We
   know a FEC set is the first one in a slot when the fec_set_idx is 0,
   and we know it is the last one when the last shred in the FEC set has
   the SLOT_COMPLETE flag set.

   QUERYING

   The chainer can fast O(1) query any FEC set using the key.  As
   mentioned earlier, any FEC set except the last one in a slot can
   derive its direct child's key and therefore query for it.

   For the special case of the first FEC set in a slot, the chainer can
   derive the parent key by subtracting the parent_off from the slot and
   querying for (slot, UINT_MAX).

   CHAINING

   As mentioned in the top-level documentation, the purpose of the
   chainer is to chain FEC sets.  On insertion, the chainer will attempt
   to chain as many FEC sets as possible to the frontier.  The chainer
   does this by conducting a BFS from the just-inserted FEC set, looking
   for parents and orphans to traverse.  See `chain` in the .c file for
   the implementation. */

typedef struct fd_fec_chainer fd_fec_chainer_t; /* forward decl */

struct fd_fec_ele {
  ulong  key;  /* map key */
  ulong  next; /* reserved for use by fd_pool and fd_map_chain */

  ulong  slot;
  uint   fec_set_idx;
  ushort data_cnt;
  int    data_complete;
  int    slot_complete;
  ushort parent_off;
  uchar  merkle_root[FD_SHRED_MERKLE_ROOT_SZ];
  uchar  chained_merkle_root[FD_SHRED_MERKLE_ROOT_SZ];
};
typedef struct fd_fec_ele fd_fec_ele_t;

#define POOL_NAME   fd_fec_pool
#define POOL_T      fd_fec_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME    fd_fec_ancestry
#define MAP_ELE_T   fd_fec_ele_t
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME    fd_fec_frontier
#define MAP_ELE_T   fd_fec_ele_t
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME    fd_fec_orphaned
#define MAP_ELE_T   fd_fec_ele_t
#include "../../util/tmpl/fd_map_chain.c"

struct fd_fec_parent {
  ulong key;
  ulong parent_key;
};
typedef struct fd_fec_parent fd_fec_parent_t;

/* There are no FEC sets for the genesis block, so (0, 0) represents the
   NULL map key. */

#define MAP_NAME     fd_fec_parents
#define MAP_T        fd_fec_parent_t
#define MAP_MEMOIZE  0
#include "../../util/tmpl/fd_map_dynamic.c"

#define FD_FEC_CHILDREN_MAX (64) /* TODO size this more reasonably */
FD_STATIC_ASSERT( FD_FEC_CHILDREN_MAX % 64 == 0, FD_FEC_CHILDREN_MAX must be a multiple of 64 bits per word );

#define SET_NAME fd_slot_child_offs
#define SET_MAX  FD_FEC_CHILDREN_MAX
#include "../../util/tmpl/fd_set.c"

/* FIXME consider alternate pooled tree-like representation eg. fd_ghost
   maybe the ghost generic in tmpl? */

struct fd_fec_children {
  ulong                slot;
  fd_slot_child_offs_t child_offs[FD_FEC_CHILDREN_MAX / 64];
};
typedef struct fd_fec_children fd_fec_children_t;

#define MAP_NAME     fd_fec_children
#define MAP_T        fd_fec_children_t
#define MAP_KEY      slot
#define MAP_MEMOIZE  0
#include "../../util/tmpl/fd_map_dynamic.c"

#define DEQUE_NAME fd_fec_queue
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct fd_fec_out {
  ulong  slot;
  ushort parent_off;
  uint   fec_set_idx;
  ushort data_cnt;
  int    data_complete;
  int    slot_complete;
  int    err;
};
typedef struct fd_fec_out fd_fec_out_t;

#define DEQUE_NAME fd_fec_out
#define DEQUE_T    fd_fec_out_t
#include "../../util/tmpl/fd_deque_dynamic.c"

/* TODO deque probably not needed if reuse ele->next. */

struct __attribute__((aligned(128UL))) fd_fec_chainer {
  fd_fec_ancestry_t  * ancestry; /* map of key->fec. non-leaves of FEC tree */
  fd_fec_frontier_t  * frontier; /* map of key->fec. leaves */
  fd_fec_orphaned_t  * orphaned; /* map of key->fec. FECs not yet inserted to tree */
  fd_fec_ele_t       * pool;     /* pool of FEC nodes backing the above maps / tree */
  fd_fec_parent_t    * parents;  /* map of key->parent_key for fast O(1) querying */
  fd_fec_children_t  * children; /* map of slot->child_offs for fast O(1) querying */
  ulong              * queue;    /* queue of FEC keys for BFS chaining */
  fd_fec_out_t       * out;      /* queue of FEC keys to deliver to application */
  ulong              root_fec;   /* pool idx of the root FEC set */
};

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_fec_chainer_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as chainer with up to
   fec_max elements and slot_max slots. */

FD_FN_CONST static inline ulong
fd_fec_chainer_align( void ) {
  return alignof(fd_fec_chainer_t);
}

FD_FN_CONST static inline ulong
fd_fec_chainer_footprint( ulong fec_max ) {
  int lg_fec_max = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );
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
    FD_LAYOUT_INIT,
      alignof(fd_fec_chainer_t), sizeof(fd_fec_chainer_t)                ),
      fd_fec_ancestry_align(),   fd_fec_ancestry_footprint( fec_max )    ),
      fd_fec_frontier_align(),   fd_fec_frontier_footprint( fec_max )    ),
      fd_fec_orphaned_align(),   fd_fec_orphaned_footprint( fec_max )    ),
      fd_fec_pool_align(),       fd_fec_pool_footprint( fec_max )        ),
      fd_fec_parents_align(),    fd_fec_parents_footprint( lg_fec_max )  ),
      fd_fec_children_align(),   fd_fec_children_footprint( lg_fec_max ) ),
      fd_fec_queue_align(),      fd_fec_queue_footprint( fec_max )       ),
      fd_fec_out_align(),        fd_fec_out_footprint( fec_max )         ),
    fd_fec_chainer_align() );
}

/* fd_fec_chainer_new formats an unused memory region for use as a
   chainer.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_fec_chainer_new( void * shmem, ulong fec_max, ulong seed );

/* fd_fec_chainer_join joins the caller to the chainer.  chainer points
   to the first byte of the memory region backing the chainer in the
   caller's address space.

   Returns a pointer in the local address space to chainer on
   success. */

fd_fec_chainer_t *
fd_fec_chainer_join( void * chainer );

/* fd_fec_chainer_leave leaves a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include chainer is NULL. */

void *
fd_fec_chainer_leave( fd_fec_chainer_t * chainer );

/* fd_fec_chainer_delete unformats a memory region used as a chainer.
   Assumes only the nobody is joined to the region.  Returns a pointer
   to the underlying shared memory region or NULL if used obviously in
   error (e.g. chainer is obviously not a chainer ... logs details).
   The ownership of the memory region is transferred to the caller. */

void *
fd_fec_chainer_delete( void * chainer );

fd_fec_ele_t *
fd_fec_chainer_init( fd_fec_chainer_t * chainer, ulong slot, uchar merkle_root[static FD_SHRED_MERKLE_ROOT_SZ] );

FD_FN_PURE fd_fec_ele_t *
fd_fec_chainer_query( fd_fec_chainer_t * chainer, ulong slot, uint fec_set_idx );

/* fd_fec_chainer inserts a new FEC set into chainer.  Returns the newly
   inserted fd_fec_ele_t, NULL on error.  Inserting this FEC set may
   result in one or more FEC sets being ready for in-order delivery.
   Caller can consume these FEC sets via the deque in chainer->out.

   See top-level documentation for further details on insertion. */

fd_fec_ele_t *
fd_fec_chainer_insert( fd_fec_chainer_t * chainer,
                       ulong              slot,
                       uint               fec_set_idx,
                       ushort             data_cnt,
                       int                data_complete,
                       int                slot_complete,
                       ushort             parent_off,
                       uchar const        merkle_root[static FD_SHRED_MERKLE_ROOT_SZ],
                       uchar const        chained_merkle_root[static FD_SHRED_MERKLE_ROOT_SZ] );

/* fd_fec_chainer_publish prunes the fec tree when the wmk is updated. */

void
fd_fec_chainer_publish( fd_fec_chainer_t * chainer, ulong new_root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_repair_fd_fec_chainer_h */
