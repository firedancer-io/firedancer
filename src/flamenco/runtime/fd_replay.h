#ifndef HEADER_fd_src_flamenco_runtime_fd_replay_h
#define HEADER_fd_src_flamenco_runtime_fd_replay_h

/* fd_replay tracks the vote stake a given slot has accumulated. This is used by the RPC node to
  provide commitment statuses on a block (and prune forks once a slot is finalized).

  This is not to be confused with fd_replay, which is an implementation of fork choice for active
  voting and consensus participation.

  In particular, note that "confirmed" and "finalized" have different definitions in an RPC context
  vs. a voting validator's context.

  In RPC, a slot is:
    - confirmed when >66% of stake has voted for it directly
    - finalized when >66% of stake has voted for it directly and indirectly (i.e. all ancestors)
  */

#include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "context/fd_capture_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_blockstore.h"

struct fd_replay_slot {
  ulong              slot;
  ulong              next;
  fd_exec_slot_ctx_t slot_ctx;
  ulong              stake; /* how much stake has voted on this slot */
};
typedef struct fd_replay_slot fd_replay_slot_t;

#define POOL_NAME fd_replay_pool
#define POOL_T    fd_replay_slot_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_replay_frontier
#define MAP_ELE_T fd_replay_slot_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

#define SET_NAME fd_replay_set
#define SET_MAX  FD_DEFAULT_SLOTS_PER_EPOCH
#include "../../util/tmpl/fd_set.c"

struct fd_replay {
  fd_replay_slot_t *     pool;     /* memory pool of slot_ctxs */
  fd_replay_frontier_t * frontier; /* map of slots to slot_ctxs, representing the fork heads */
  fd_replay_set_t *      pending;  /* backlog of pending slots that need replay */
  fd_replay_set_t *      missing;  /* backlog of missing slots that need repair */

  fd_blockstore_t *     blockstore;
  fd_funk_t *           funk;
  fd_acc_mgr_t *        acc_mgr;
  fd_exec_epoch_ctx_t * epoch_ctx;
  fd_repair_t *         repair;
  fd_gossip_t *         gossip;
  fd_tpool_t *          tpool;
  ulong                 max_workers;
  fd_valloc_t *         valloc;
};
typedef struct fd_replay fd_replay_t;

struct slot_capitalization {
  ulong key;
  uint  hash;
  ulong capitalization;
};
typedef struct slot_capitalization slot_capitalization_t;

#define MAP_NAME        capitalization_map
#define MAP_T           slot_capitalization_t
#define LG_SLOT_CNT     15
#define MAP_LG_SLOT_CNT LG_SLOT_CNT
#include "../../util/tmpl/fd_map.c"

#define FD_REPLAY_STATE_ALIGN ( 8UL )

#define FD_REPLAY_STATE_FOOTPRINT ( sizeof( struct fd_runtime_ctx ) )

FD_PROTOTYPES_BEGIN

/* fd_replay_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as replay with up to node_max
   nodes and 1 << lg_msg_max msgs. align returns FD_replay_ALIGN. */

FD_FN_CONST static inline ulong
fd_replay_align( void ) {
  return alignof( fd_replay_t );
}

FD_FN_CONST static inline ulong
fd_replay_footprint( ulong node_max ) {
  return sizeof( fd_replay_t ) + fd_replay_frontier_footprint( node_max ) +
         fd_replay_pool_footprint( node_max ) + fd_replay_frontier_footprint( node_max ) + fd_replay_set_footprint() + fd_replay_set_footprint();
}

/* fd_replay_new formats an unused memory region for use as a replay. mem is a non-NULL pointer to
   this region in the local address space with the required footprint and alignment.*/

void *
fd_replay_new( void * mem, ulong node_max, ulong seed );

/* fd_replay_join joins the caller to the replay. replay points to the first byte of the memory
   region backing the replay in the caller's address space.

   Returns a pointer in the local address space to the replay structure on success.

   The replay is not inteded to be shared across multiple processes, and attempts to join from other
   processes will result in invalid pointers. */

fd_replay_t *
fd_replay_join( void * replay );

/* fd_replay_leave leaves a current local join. Returns a pointer to the underlying shared memory
   region on success and NULL on failure (logs details). Reasons for failure include replay is NULL.
 */

void *
fd_replay_leave( fd_replay_t const * replay );

/* fd_replay_delete unformats a memory region used as a replay. Assumes only the local process is
   joined to the region. Returns a pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. replay is obviously not a replay ... logs details). The ownership of the
   memory region is transferred to the caller. */

void *
fd_replay_delete( void * replay );

/* fd_replay_slot_parent queries the parent of slot in the replay frontier, updating the frontier if
   it can't find it (which indicates a new fork). */
void
fd_replay_slot_parent_query( fd_replay_t * replay, ulong slot );

/* fd_replay_run attempts to execute all the current slots in pending, updating the frontier as it
   goes. It re-queues the slots it can't currently execute due to a gap in the ancestry chain, ie.
   blocks must be connected. It queues those missing parents that need to be repaired. */
void
fd_replay_pending_execute( fd_replay_t * replay );

/* fd_replay_slot_ctx_restore restores slot_ctx to its state as of slot. Assumes the blockhash
 * corresponding to slot is in funk. */
void
fd_replay_slot_ctx_restore( fd_replay_t * replay, ulong slot, fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif
