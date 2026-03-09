#ifndef HEADER_fd_src_choreo_tower_fd_tower_leaves_h
#define HEADER_fd_src_choreo_tower_fd_tower_leaves_h

#include "../fd_choreo_base.h"
#include "fd_tower_voters.h"

/* fd_tower_leaves maintains the leaves of every fork.

        /-- 3-- 4  (A)
   1-- 2
        \-- 5      (B)

   In the above example, fd_tower_leaves will contain [4, 5]. */

struct fd_tower_leaf {
  ulong slot; /* map key */
  ulong hash; /* reserved for fd_map_chain and fd_pool */
  ulong next; /* next leaf in the linked list */
  ulong prev; /* prev leaf in the linked list */
};
typedef struct fd_tower_leaf fd_tower_leaf_t;

#define MAP_NAME    fd_tower_leaves_map
#define MAP_ELE_T   fd_tower_leaf_t
#define MAP_KEY     slot
#define MAP_NEXT    hash
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_tower_leaves_pool
#define POOL_T    fd_tower_leaf_t
#define POOL_NEXT hash
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_tower_leaves_dlist
#define DLIST_ELE_T fd_tower_leaf_t
#include "../../util/tmpl/fd_dlist.c"

struct __attribute__((aligned(128UL))) fd_tower_leaves {
  fd_tower_leaf_t         * pool;
  fd_tower_leaves_map_t   * map;
  fd_tower_leaves_dlist_t * dlist;
};
typedef struct fd_tower_leaves fd_tower_leaves_t;

FD_PROTOTYPES_BEGIN

/* fd_tower_leaves_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a tower_leaves. */

FD_FN_CONST static inline ulong
fd_tower_leaves_align( void ) {
  return alignof(fd_tower_leaves_t);
}

FD_FN_CONST static inline ulong
fd_tower_leaves_footprint( ulong slot_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_tower_leaves_t),    sizeof(fd_tower_leaves_t)                  ),
      fd_tower_leaves_map_align(),   fd_tower_leaves_map_footprint( slot_max )  ),
      fd_tower_leaves_dlist_align(), fd_tower_leaves_dlist_footprint()          ),
      fd_tower_leaves_pool_align(),  fd_tower_leaves_pool_footprint( slot_max ) ),
    fd_tower_leaves_align() );
}

/* fd_tower_leaves_new formats an unused memory region for use as a
   tower_leaves.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_tower_leaves_new( void * shmem,
                     ulong  slot_max,
                     ulong  seed );

/* fd_tower_leaves_join joins the caller to the tower_leaves. shleaves
   points to the first byte of the memory region backing the shleaves in
   the caller's address space.

   Returns a pointer in the local address space to leaves on success. */

fd_tower_leaves_t *
fd_tower_leaves_join( void * shleaves );

/* fd_tower_leaves_leave leaves a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include leaves is NULL. */

void *
fd_tower_leaves_leave( fd_tower_leaves_t const * leaves );

/* fd_tower_leaves_delete unformats a memory region used as a leaves.
   Assumes only the local process is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. leaves is obviously not a leaves ...  logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_tower_leaves_delete( void * leaves );


void
fd_tower_leaves_upsert( fd_tower_leaves_t * leaves,
                        ulong               slot,
                        ulong               parent_slot );

void
fd_tower_leaves_remove( fd_tower_leaves_t * leaves,
                        ulong               slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_leaves_h */
