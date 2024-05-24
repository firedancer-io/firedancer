#ifndef HEADER_fd_src_choreo_forks_fd_forks_h
#define HEADER_fd_src_choreo_forks_fd_forks_h

#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../fd_choreo_base.h"

struct fd_fork {
  ulong              slot;     /* head of the fork, frontier key */
  ulong              next;     /* reserved for use by fd_pool and fd_map_chain */
  fd_block_t *       head;     /* the block representing the head of the fork */
  fd_exec_slot_ctx_t slot_ctx; /* the bank representing the head of the fork */
};
typedef struct fd_fork fd_fork_t;

#define POOL_NAME fd_fork_pool
#define POOL_T    fd_fork_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fork_frontier
#define MAP_ELE_T fd_fork_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

struct fd_forks {
  ulong root;
  ulong smr; /* super-majority root */

  /* internal joins */

  fd_fork_frontier_t * frontier; /* the fork heads, map of slot->fd_fork_t */
  fd_fork_t *          pool;     /* memory pool of fd_fork_t */

  /* external joins */

  fd_acc_mgr_t *        acc_mgr;
  fd_blockstore_t *     blockstore;
  fd_exec_epoch_ctx_t * epoch_ctx;
  fd_funk_t *           funk;
  fd_valloc_t           valloc;
};
typedef struct fd_forks fd_forks_t;

/* fd_forks_{align,footprint} return the required alignment and footprint of a memory region
   suitable for use as forks with up to node_max nodes and vote_max votes. */

FD_FN_CONST static inline ulong
fd_forks_align( void ) {
  return alignof( fd_forks_t );
}

FD_FN_CONST static inline ulong
fd_forks_footprint( ulong max ) {
  return FD_LAYOUT_FINI(
      FD_LAYOUT_APPEND(
          FD_LAYOUT_APPEND(
              FD_LAYOUT_APPEND( FD_LAYOUT_INIT, alignof( fd_forks_t ), sizeof( fd_forks_t ) ),
              fd_fork_pool_align(),
              fd_fork_pool_footprint( max ) ),
          fd_fork_frontier_align(),
          fd_fork_frontier_footprint( max ) ),
      alignof( fd_forks_t ) );
}

/* fd_forks_new formats an unused memory region for use as a forks. mem is a non-NULL
   pointer to this region in the local address space with the required footprint and alignment. */

void *
fd_forks_new( void * shmem, ulong max, ulong seed );

/* fd_forks_join joins the caller to the forks. forks points to the first byte of the
   memory region backing the forks in the caller's address space.

   Returns a pointer in the local address space to forks on success. */

fd_forks_t *
fd_forks_join( void * forks );

/* fd_forks_leave leaves a current local join. Returns a pointer to the underlying shared memory
   region on success and NULL on failure (logs details). Reasons for failure include forks is
   NULL. */

void *
fd_forks_leave( fd_forks_t const * forks );

/* fd_forks_delete unformats a memory region used as a forks. Assumes only the local process
   is joined to the region. Returns a pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. forks is obviously not a forks ... logs details). The ownership
   of the memory region is transferred to the caller. */

void *
fd_forks_delete( void * forks );

// /* fd_forks_insert inserts */

// fd_fork_t *
// fd_forks_insert( fd_forks_t * forks, fd_exec_slot_ctx_t * slot_ctx );

/* fd_forks_rollback starts a new fork at slot by inserting it into the frontier. Returns a handle
 * to the new fork on success, NULL on failure. Reasons for failure include slot is not in
 * blockstore or blockhash corresponding to slot is not present in funk. */

fd_fork_t *
fd_forks_rollback( fd_forks_t * forks, ulong slot );

/* fd_forks_prune removes all fork heads in the frontier not originating from root. */
void
fd_forks_prune( fd_forks_t * forks, ulong root );


#endif /* HEADER_fd_src_choreo_forks_fd_forks_h */
