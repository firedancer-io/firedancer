#ifndef HEADER_fd_src_discof_repair_fd_reasm_h
#define HEADER_fd_src_discof_repair_fd_reasm_h

/* fd_reasm reassembles FEC sets into Replay order as they are received
   over the network via Turbine and Repair.  Every FEC set is guaranteed
   to be eventually delivered by reasm to the caller after it has been
   "chained" to its parent (defined below).

   Every FEC set has a parent (the immediately preceding FEC set in the
   slot or parent slot) and children (immediately succeeding FEC set(s)
   for the same slot or child slots).  Reasm always delivers a parent
   before its child.  However, because of forks, not every FEC set has a
   ancestor->descendant relationship.  Forks are treated as concurrent,
   and thus reasm only provides a partial ordering such that reasm makes
   no guarantees about the delivery order of FEC sets across forks, but
   in general this will be the order in which the reasm is able to chain
   them to their connected parents.

   Forks manifest in reasm as a FEC set with more than one child, and
   mostly occur across slots due to leader skipping (ie. parent and
   child(s) have different slots).  For example, the leader for slot 14
   forks slot 9 when another leader already built slot 10 from slot 9,
   so now the last FEC set in slot 9 has two child FEC sets ie. the
   first FEC in slot 10 and first FEC in slot 14.

   There is a protocol violation called equivocation (also known as
   "duplicates") that can also cause forks.  Unlike skips, equivocation
   is not honest behavior and only happens when validators are behaving
   maliciously or their software has a bug.  Equivocation can result in
   observing two or more child FEC sets for a given parent FEC set in
   the _same_ slot.  Moreover, there might be two FEC sets with the same
   slot and FEC set index but different payloads.  Due to equivocation,
   reasm cannot key FEC sets by the natural pair (slot, fec_set_idx) and
   instead keys by the FEC set merkle root.  Similarly, reasm connects
   FEC sets to its parent via the chained merkle root.  Not all cases of
   equivocation can be detected by the reasm however, as not all the
   necessary information is yet available at this stage in the validator
   pipeline.  Reasm will simply deliver all the equivocating FEC sets it
   does observe (with a flag indicating its detection). */

#include "../../flamenco/types/fd_types_custom.h"

/* FD_REASM_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_REASM_USE_HANDHOLDING
#define FD_REASM_USE_HANDHOLDING 1
#endif

#define FD_REASM_SUCCESS    ( 0)
#define FD_REASM_ERR_UNIQUE (-1) /* key uniqueness conflict */
#define FD_REASM_ERR_MERKLE (-2) /* chained merkle root conflict */

/* fd_reasm is a tree-like structure backed by three maps.  At any
   given point in time, an element (FEC set) in the reasm is in one of
   three possible positions with respect to the tree: a non-leaf, leaf,
   or not connected.  This corresponds to the ancestry, frontier, or
   orphaned maps, respectively.  Therefore, a given element will always
   be present in exactly one of these maps, depending on where (and
   whether) it currently is in the tree.

   KEYING

   The reasm keys FEC sets by concatenating the slot with fec_set_idx.
   This uniquely identifies a FEC set in most cases.  It is possible to
   receive over the network two or more different FEC sets with the same
   slot and fec_set_idx due to equivocation as mentioned earlier.  In
   general, the reasm expects the caller to handle equivocation and
   assumes unique FEC sets will have unique keys (handholding is
   available to verify this).

   The map key is an encoding of the slot and fec_set_idx which uniquely
   keys every FEC set.  The 32 msb of the key are the 32 lsb of the slot
   and the 32 lsb of the key are the fec_set_idx, except when the FEC
   set is the last one for the slot, in which case the 32 lsb are set to
   UINT_MAX. By setting fec_set_idx to UINT_MAX, the reasm can easily
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

   When inserting a new FEC set, the reasm first checks whether the
   parent is a FEC set already in the frontier map.  This indicates that
   the new FEC set directly chains off the frontier.  If it does, the
   parent FEC set is removed, and the new FEC set is inserted into the
   frontier map.  This is the common case because we expect FEC sets to
   chain linearly the vast majority (ie. not start new forks), so the
   new FEC set is simply "advancing" the frontier.  The parent FEC set
   is also added to the ancestry map, so that every leaf can trace back
   to the root.

   If the FEC set's parent is not already in the frontier, the reasm
   checks the ancestry map next.  If the parent is in the ancestry map,
   the reasm knows that this FEC set is starting a new fork, because
   it is part of the tree (the ancestry) but not one of the leaves (the
   frontier).  In this case, the new FEC set is simply inserted into the
   frontier map, and now the frontier has an additional fork (leaf).

   Lastly, if the FEC set's parent is not in the ancestry map, the
   reasm knows that this FEC set is orphaned.  It is inserted into the
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

   The reasm can fast O(1) query any FEC set using the key.  As
   mentioned earlier, any FEC set except the last one in a slot can
   derive its direct child's key and therefore query for it.

   For the special case of the first FEC set in a slot, the reasm can
   derive the parent key by subtracting the parent_off from the slot and
   querying for (slot, UINT_MAX).

   CHAINING

   As mentioned in the top-level documentation, the purpose of the
   reasm is to chain FEC sets.  On insertion, the reasm will attempt
   to chain as many FEC sets as possible to the frontier.  The reasm
   does this by conducting a BFS from the just-inserted FEC set, looking
   for parents and orphans to traverse.  See `chain` in the .c file for
   the implementation. */

typedef struct fd_reasm fd_reasm_t; /* forward decl */

struct __attribute__((aligned(128UL))) fd_reasm_fec {

  /* Keys */

  fd_hash_t key; /* map key, merkle root of the FEC set */
  fd_hash_t cmr; /* parent's map key, chained merkle root of the FEC set */

  /* Pointers */

  ulong next;    /* reserved for internal use by fd_pool, fd_map_chain */
  ulong parent;  /* pool idx of the parent */
  ulong child;   /* pool idx of the left-child */
  ulong sibling; /* pool idx of the right-sibling */

  /* Data */

  ulong  slot;          /* The slot of the FEC set */
  uint   fec_set_idx;   /* The index of first shred in the FEC set */
  ushort parent_off;    /* The offset for the parent slot of the FEC set */
  ushort data_cnt;      /* The number of data shreds in the FEC set */
  int    data_complete; /* Whether the FEC set completes an entry batch */
  int    slot_complete; /* Whether this FEC set completes the slot */
};
typedef struct fd_reasm_fec fd_reasm_fec_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_reasm_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as reasm with up to
   fec_max elements and slot_max slots. */

FD_FN_CONST ulong
fd_reasm_align( void );

FD_FN_CONST ulong
fd_reasm_footprint( ulong fec_max );

/* fd_reasm_new formats an unused memory region for use as a
   reasm.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_reasm_new( void * shmem, ulong fec_max, ulong seed );

/* fd_reasm_join joins the caller to the reasm.  reasm points
   to the first byte of the memory region backing the reasm in the
   caller's address space.

   Returns a pointer in the local address space to reasm on
   success. */

fd_reasm_t *
fd_reasm_join( void * reasm );

/* fd_reasm_leave leaves a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include reasm is NULL. */

void *
fd_reasm_leave( fd_reasm_t * reasm );

/* fd_reasm_delete unformats a memory region used as a reasm.
   Assumes only the nobody is joined to the region.  Returns a pointer
   to the underlying shared memory region or NULL if used obviously in
   error (e.g. reasm is obviously not a reasm ... logs details).
   The ownership of the memory region is transferred to the caller. */

void *
fd_reasm_delete( void * reasm );

/* fd_reasm_{query,query_const} returns a pointer to the current root of
   of the reasm.  Returns NULL if there is no root. */

fd_reasm_fec_t *
fd_reasm_root( fd_reasm_t * reasm );

/* FIXME block_id manifest */

ulong
fd_reasm_slot0( fd_reasm_t * reasm );

/* fd_reasm_{query,query_const} queries the FEC set keyed by merkle.
   Returns a pointer to the fd_reasm_fec_t if found, NULL otherwise. */

fd_reasm_fec_t *
fd_reasm_query( fd_reasm_t * reasm, fd_hash_t const * merkle_root );

/* fd_reasm_init initializes reasm with a dummy root of key merkle_root
   and with metadata slot.  All other fields are set to either pool null
   idx or 0.  The dummy is inserted into the frontier but will not be
   returned by fd_reasm_next. */

fd_reasm_t *
fd_reasm_init( fd_reasm_t * reasm, fd_hash_t const * merkle_root, ulong slot );

/* fd_reasm_next returns the next successfully reassembled FEC set, NULL
   if there is no FEC set to return. This pops and returns the head of
   the reasm out queue.  Any FEC sets in the out queue are part of a
   connected ancestry chain to the root therefore a parent is always
   guaranteed to be returned by consume before its child (see top-level
   documentation for details). */

fd_reasm_fec_t *
fd_reasm_next( fd_reasm_t * reasm );

/* fd_reasm_insert inserts a new FEC set into reasm.  Returns the newly
   inserted fd_reasm_fec_t, NULL on error.  Inserting this FEC set may
   make one or more FEC sets available for in-order delivery.  Caller
   can consume these FEC sets via fd_reasm_out.

   See top-level documentation for further details on insertion. */

fd_reasm_fec_t *
fd_reasm_insert( fd_reasm_t *      reasm,
                 fd_hash_t const * merkle_root,
                 fd_hash_t const * chained_merkle_root,
                 ulong             slot,
                 uint              fec_set_idx,
                 ushort            parent_off,
                 ushort            data_cnt,
                 int               data_complete,
                 int               slot_complete );

/* fd_reasm_publish publishes merkle_root as the new reasm root, pruning
   (ie. map remove and release) any FEC sets that do not descend from
   this new root. */

fd_reasm_fec_t *
fd_reasm_publish( fd_reasm_t * reasm, fd_hash_t const * merkle_root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_repair_fd_reasm_h */
