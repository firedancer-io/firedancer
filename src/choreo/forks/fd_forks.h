#ifndef HEADER_fd_src_choreo_forks_fd_forks_h
#define HEADER_fd_src_choreo_forks_fd_forks_h

#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../fd_choreo_base.h"
#include "../ghost/fd_ghost.h"
#include "../voter/fd_voter.h"

/* FD_FORKS_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_FORKS_USE_HANDHOLDING
#define FD_FORKS_USE_HANDHOLDING 1
#endif

struct fd_fork {
  ulong slot; /* the fork head and frontier key */
  ulong next; /* reserved for use by fd_pool and fd_map_chain */
  ulong prev; /* reserved for use by fd_forks_publish */
  int   lock; /* IMPORTANT SAFETY TIP! lock is a boolean indicating
                 whether a fork's most recent block is still being
                 actively replayed (executed) and should generally not
                 be read or written to by downstream consumers (eg.
                 consensus, publishing) and should definitely not be
                 removed. */
};

typedef struct fd_fork fd_fork_t;

#define POOL_NAME fd_fork_pool
#define POOL_T    fd_fork_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fork_frontier
#define MAP_ELE_T fd_fork_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

/* fd_forks maintains all the outstanding fork heads known as the
   frontier.  The memory required for these fork heads is pre-allocated
   in `pool`.

   {processed, confirmed, finalized} correspond to the highest slots
   that have achieved each of these cluster commitment levels. This is
   based on what Firedancer has locally observed, so these values are
   not atomically synchronized with other nodes in the cluster (ie.
   other nodes may report higher or lower slot numbers for each of
   these) but are "eventually consistent" as long as Firedancer is
   connected to the cluster and replaying blocks. All three values are
   strictly monotonically increasing.

   processed - a slot has been replayed.
   confirmed - a slot has been "optimistically confirmed" ie. 2/3 of
               stake has voted for it.
   finalized - a slot has been "supermajority rooted" ie. 2/3 of stake
               has rooted it or any of its descendants. */

struct fd_forks {
  fd_fork_frontier_t * frontier; /* map of slot->fd_fork_t */
  fd_fork_t *          pool;     /* memory pool of fd_fork_t */
  ulong                processed;
  ulong                confirmed;
  ulong                finalized;
};
typedef struct fd_forks fd_forks_t;

/* fd_forks_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as forks with up to max
   fork heads in the frontier. */

FD_FN_CONST static inline ulong
fd_forks_align( void ) {
  return alignof( fd_forks_t );
}

FD_FN_CONST static inline ulong
fd_forks_footprint( ulong max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_forks_t),      sizeof(fd_forks_t) ),
      fd_fork_pool_align(),     fd_fork_pool_footprint( max ) ),
      fd_fork_frontier_align(), fd_fork_frontier_footprint( max ) ),
    alignof(fd_forks_t) );
}

/* fd_forks_new formats an unused memory region for use as a forks.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_forks_new( void * shmem, ulong max, ulong seed );

/* fd_forks_join joins the caller to the forks.  forks points to the
   first byte of the memory region backing the forks in the caller's
   address space.

   Returns a pointer in the local address space to forks on success. */

fd_forks_t *
fd_forks_join( void * forks );

/* fd_forks_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include forks is NULL. */

void *
fd_forks_leave( fd_forks_t const * forks );

/* fd_forks_delete unformats a memory region used as a forks.  Assumes
   only the local process is joined to the region. Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g. forks is obviously not a forks ... logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_forks_delete( void * forks );

/* fd_forks_init initializes forks.  Assumes forks is a valid local join
   and no one else is joined, and slot  Inserts the first fork.
   Returns fork on success, NULL on failure.

   In general, this should be called by the same process that formatted
   forks' memory, ie. the caller of fd_forks_new. */

fd_fork_t *
fd_forks_init( fd_forks_t * forks, ulong slot );

/* fd_forks_query queries for the fork corresponding to slot in the
   frontier.  Returns the fork if found, otherwise NULL. */

fd_fork_t *
fd_forks_query( fd_forks_t * forks, ulong slot );

/* fd_forks_query_const is the const version of the above. */

fd_fork_t const *
fd_forks_query_const( fd_forks_t const * forks, ulong slot );

/* fd_forks_advance advances a parent_slot to slot in the frontier.
   Assumes parent_slot corresponds to a fork currently in the frontier
   (ie. has already been prepared), slot is a child of parent_slot, and
   parent_slot has already been replayed.  Fails if fork is not frozen.
   Returns the updated fork on success, NULL on failure. */

fd_fork_t *
fd_forks_advance( fd_forks_t const * forks, fd_fork_t * fork, ulong slot );

/* fd_forks_prepare prepares a fork for execution.  The fork will either
   be an existing fork in the frontier if parent_slot is already a fork
   head or it will start a new fork at parent_slot and add it to the
   frontier.

   Returns fork on success, NULL on failure.  Failure reasons include
   parent_slot is not present in the blockstore, is not present in funk,
   or does not have a valid ancestry.

   It is possible for the fork to return NULL in a non-error condition.
   For example, a leader tries to rollback and start a new fork from a
   very old slot that the blockstore has already pruned. In this
   scenario, we cannot prepare a new fork at parent_slot because we have
   already rooted past it. */

fd_fork_t *
fd_forks_prepare( fd_forks_t const * forks, ulong parent_slot );

/* fd_forks_publish publishes a new root into forks.  Assumes root is a
   valid slot that exists in the cluster and has already been replayed.
   This prunes all the existing forks in the frontier except descendants
   of root.  Forks that are not frozen will also not be pruned (warns
   when handholding is enabled).  */

void
fd_forks_publish( fd_forks_t * fork, ulong root );

/* fd_forks_print prints a forks as a list of the frontiers and number
   of forks (pool eles acquired). */

void
fd_forks_print( fd_forks_t const * forks );

#endif /* HEADER_fd_src_choreo_forks_fd_forks_h */
