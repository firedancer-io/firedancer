#ifndef HEADER_fd_src_choreo_replay_fd_replay_h
#define HEADER_fd_src_choreo_replay_fd_replay_h

/* This provides APIs for orchestrating replay of blocks as they are
   received from the cluster.

   Concepts:

   - Shreds are chunks of blocks that are streamed in via Turbine and
     Repair.

   - Once enough shreds are received to complete a replayable slice of a
     block ie. an "entry batch", then that slice is replayed.

   - Replay uses the fork frontier to determine which of the slices are
     replayable. */

#include "../fd_disco_base.h"
#include "../../tango/fseq/fd_fseq.h"
#include "../../flamenco/runtime/fd_blockstore.h"


/* FD_REPLAY_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_REPLAY_USE_HANDHOLDING
#define FD_REPLAY_USE_HANDHOLDING 1
#endif

/* fd_replay_slice_t tracks a block slice that needs to be replayed. */

struct fd_replay_slice {
  ulong key;  /* high 58 bits are slot and low 6 bits are tick */
  ulong slot; /* slot number of the block */
  uchar tick; /* reference tick of the slice */
  ulong prev; /* internal use by dlist */
  ulong next; /* internal use by dlist and pool */
  ulong hash; /* internal use by map_chain */
};
typedef struct fd_replay_slice fd_replay_slice_t;

#define POOL_NAME fd_replay_slice_pool
#define POOL_T    fd_replay_slice_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_replay_slice_map
#define MAP_ELE_T fd_replay_slice_t
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  fd_replay_slice_dlist
#define DLIST_ELE_T fd_replay_slice_t
#include "../../util/tmpl/fd_dlist.c"

#define FD_REPLAY_MAGIC (0xf17eda2ce77e91a70UL) /* firedancer replay version 0 */

/* fd_replay_t is the top-level structure that maintains an LRU cache
   (pool, dlist, map) of the outstanding block slices that need replay.

   The replay order is FIFO so the first slice to go into the LRU will
   also be the first to attempt replay. */

struct __attribute__((aligned(128UL))) fd_replay {
  fd_replay_slice_t *       slice_pool;
  fd_replay_slice_map_t *   slice_map;
  fd_replay_slice_dlist_t * slice_dlist;
};
typedef struct fd_replay fd_replay_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_replay_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as replay with up to
   slice_max slices and vote_max votes. */

FD_FN_CONST static inline ulong
fd_replay_align( void ) {
  return alignof(fd_replay_t);
}

FD_FN_CONST static inline ulong
fd_replay_footprint( ulong slice_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_replay_t),          sizeof(fd_replay_t) ),
      fd_replay_slice_pool_align(),  fd_replay_slice_pool_footprint( slice_max ) ),
      fd_replay_slice_map_align(),   fd_replay_slice_map_footprint( slice_max ) ),
      fd_replay_slice_dlist_align(), fd_replay_slice_dlist_footprint() ),
    fd_replay_align() );
}

/* fd_replay_new formats an unused memory region for use as a replay.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_replay_new( void * shmem, ulong seed, ulong slice_max );

/* fd_replay_join joins the caller to the replay.  replay points to the
   first byte of the memory region backing the replay in the caller's
   address space.

   Returns a pointer in the local address space to replay on success. */

fd_replay_t *
fd_replay_join( void * replay );

/* fd_replay_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include replay is NULL. */

void *
fd_replay_leave( fd_replay_t const * replay );

/* fd_replay_delete unformats a memory region used as a replay.
   Assumes only the nobody is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. replay is obviously not a replay ... logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_replay_delete( void * replay );

/* fd_replay_init initializes a replay.  Assumes replay is a valid local
   join and no one else is joined.  root is the initial root replay will
   use.  This is the snapshot slot if booting from a snapshot, 0 if the
   genesis slot.

   In general, this should be called by the same process that formatted
   replay's memory, ie. the caller of fd_replay_new. */

void
fd_replay_init( fd_replay_t * replay, ulong root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_replay_fd_replay_h */
