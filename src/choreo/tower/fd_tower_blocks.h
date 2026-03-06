#ifndef HEADER_fd_src_choreo_tower_fd_tower_blocks_h
#define HEADER_fd_src_choreo_tower_fd_tower_blocks_h

#include "../fd_choreo_base.h"
#include "fd_tower_voters.h"

/* fd_tower_blocks maintains tower-specific metadata about every block,
   such as what block_id we first replayed, what block_id we voted for,
   and what block_id was ultimately "duplicate confirmed".

   This is used by tower to make voting decisions, such as whether or
   not we can switch "forks".  In this context, a fork is a branch of a
   tree that extends from the root to a leaf.  For example:

        /-- 3-- 4  (A)
   1-- 2
        \-- 5      (B)

   Here, A and B are two different forks.  A is [1, 2, 3, 4] and B is
   [1, 2, 5], two branches that each extend from the root to a leaf.

   Note that even though fd_tower_blocks is block_id-aware, it does not
   use them for determining parentage.  Instead, parentage is based on
   slot numbers, so in cases of equivocation (duplicate blocks), tower
   will consider something an ancestor or descendant even if the block
   ids do not chain.

   This behavior intentionally mirrors the Agave logic implemented in
   `make_check_switch_threshold_decision`.  Essentially, tower is unable
   to distinguish duplicates because the vote account format (in which
   towers are stored) only stores slot numbers and not block_ids. */

struct fd_tower_blk {
  ulong     slot;               /* map key */
  ulong     parent_slot;        /* parent slot */
  ulong     epoch;              /* epoch of this slot */
  int       replayed;           /* whether we've replayed this slot yet */
  fd_hash_t replayed_block_id;  /* the block_id we _first_ replayed for this slot */
  int       voted;              /* whether we voted for this slot yet */
  fd_hash_t voted_block_id;     /* the block_id we voted on for this slot */
  int       confirmed;          /* whether this slot has been duplicate confirmed */
  fd_hash_t confirmed_block_id; /* the block_id that was duplicate confirmed */
  ulong     bank_idx;           /* pool idx of the bank as of this replayed block */
};
typedef struct fd_tower_blk fd_tower_blk_t;

#define MAP_NAME           fd_tower_blk
#define MAP_T              fd_tower_blk_t
#define MAP_KEY            slot
#define MAP_KEY_NULL       ULONG_MAX
#define MAP_KEY_INVAL(key) ((key)==ULONG_MAX)
#define MAP_MEMOIZE        0
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(128UL))) fd_tower_blocks {
  fd_tower_blk_t * blk_map;
};
typedef struct fd_tower_blocks fd_tower_blocks_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_tower_blocks_align( void ) {
  return alignof(fd_tower_blocks_t);
}

FD_FN_CONST static inline ulong
fd_tower_blocks_footprint( ulong slot_max ) {
  int lg_slot_max = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_tower_blocks_t), sizeof(fd_tower_blocks_t)             ),
      fd_tower_blk_align(),       fd_tower_blk_footprint( lg_slot_max ) ),
    fd_tower_blocks_align() );
}

/* fd_tower_blocks_new formats an unused memory region for use as a
   tower_blocks.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_tower_blocks_new( void * shmem,
                     ulong  slot_max,
                     ulong  seed );

/* fd_tower_blocks_join joins the caller to the tower_blocks. shblocks
   points to the first byte of the memory region backing the shblocks in
   the caller's address space.

   Returns a pointer in the local address space to blocks on success. */

fd_tower_blocks_t *
fd_tower_blocks_join( void * shblocks );

/* fd_tower_blocks_leave blocks a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include blocks is NULL. */

void *
fd_tower_blocks_leave( fd_tower_blocks_t const * blocks );

/* fd_tower_blocks_delete unformats a memory region used as a blocks.
   Assumes only the local process is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. blocks is obviously not a blocks ...  logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_tower_blocks_delete( void * blocks );

/* fd_tower_is_slot_{ancestor,descendant} return 1 or 0 depending on
   whether the specified relationship is true in blocks. */

int
fd_tower_blocks_is_slot_ancestor( fd_tower_blocks_t * blocks,
                                  ulong               descendant_slot,
                                  ulong               ancestor_slot );

int
fd_tower_blocks_is_slot_descendant( fd_tower_blocks_t * blocks,
                                    ulong               ancestor_slot,
                                    ulong               descendant_slot );

/* fd_tower_blocks_lowest_common_ancestor returns the lowest common
   ancestor of slot1 and slot 2.  There is always an LCA in a valid
   tower_forks tree (the root). */

ulong
fd_tower_blocks_lowest_common_ancestor( fd_tower_blocks_t * blocks,
                                        ulong               slot1,
                                        ulong               slot2 );

/* fd_tower_blocks_canonical_block_id returns what we think to be the
   correct block id for a given slot, based on what we've observed.

   We prioritize in-order:
   1. the duplicate-confirmed block id
   2. our voted block id
   3. our first-replayed block id

   This is the canonical order because it reflects what we think is the
   "true" block id given the information we have.

   Agave behaves similarly, except they "purge" their replay bank hash
   so they're always comparing the confirmed block id */

fd_hash_t const *
fd_tower_blocks_canonical_block_id( fd_tower_blocks_t * blocks,
                                    ulong               slot );

/* fd_tower_blocks_{query,insert,remove} provide convenient wrappers for
   {querying,inserting,removing} into the underlying map. */

fd_tower_blk_t *
fd_tower_blocks_query( fd_tower_blocks_t * blocks,
                       ulong               slot );

fd_tower_blk_t *
fd_tower_blocks_insert( fd_tower_blocks_t * blocks,
                        ulong               slot,
                        ulong               parent_slot );

void
fd_tower_blocks_remove( fd_tower_blocks_t * blocks,
                        ulong               slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_blocks_h */
