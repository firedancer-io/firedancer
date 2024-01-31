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
    - finalized when >66% of stake has rooted the slot or its descendants
  */

#include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "context/fd_capture_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_blockstore.h"
#include "fd_runtime.h"

#define FD_REPLAY_SET_MAX ( 1UL << 10 )

/* fd_replay_slot_ctx is a thin wrapper around fd_exec_slot_ctx_t for memory pools and maps */
struct fd_replay_slot_ctx {
  ulong              slot;
  ulong              next;
  fd_exec_slot_ctx_t slot_ctx;
};
typedef struct fd_replay_slot_ctx fd_replay_slot_ctx_t;

/* fd_repair_req is a map of in-flight repair requests. */ /* TODO refactor to use `dlist`? Faster
   eviction */
struct fd_repair_req {
  fd_shred_key_t key;
  uint           hash;
  long           ts;  /* request timestamp */
  ulong          cnt; /* # of request attempts */
};
typedef struct fd_repair_req fd_repair_req_t;

/* clang-format off */
#define MAP_NAME              fd_repair_req
#define MAP_T                 fd_repair_req_t
#define MAP_LG_SLOT_CNT       16
#define MAP_KEY_T             fd_shred_key_t
#define MAP_KEY_NULL          fd_shred_key_null
#define MAP_KEY_INVAL(k)      FD_SHRED_KEY_INVAL(k)
#define MAP_KEY_EQUAL(k0,k1)  FD_SHRED_KEY_EQ(k0,k1)
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     FD_SHRED_KEY_HASH(key)
#include "../../util/tmpl/fd_map.c"
/* clang-format on */

#define POOL_NAME fd_replay_pool
#define POOL_T    fd_replay_slot_ctx_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_replay_frontier
#define MAP_ELE_T fd_replay_slot_ctx_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

struct fd_replay_commitment {
  ulong slot;
  uint  hash;
  ulong confirmed_stake[32]; /* how much stake has voted on this slot */
  ulong finalized_stake;     /* how much stake has rooted this slot */
};
typedef struct fd_replay_commitment fd_replay_commitment_t;

#define MAP_NAME        fd_replay_commitment
#define MAP_T           fd_replay_commitment_t
#define MAP_KEY         slot
#define MAP_LG_SLOT_CNT 19 /* slots per epoch */
#include "../../util/tmpl/fd_map.c"

struct fd_repair_peer {
  fd_pubkey_t id;
  uint        hash;
  ulong       first_slot;
  ulong       last_slot;
  ulong       request_cnt;
  ulong       reply_cnt;
};
typedef struct fd_repair_peer fd_repair_peer_t;

#define MAP_NAME                fd_repair_peer
#define MAP_T                   fd_repair_peer_t
#define MAP_LG_SLOT_CNT         12 /* 4kb peers */
#define MAP_KEY                 id
#define MAP_KEY_T               fd_pubkey_t
#define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( &k0 ), ( &k1 ), sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL_IS_SLOW   1
#define MAP_KEY_HASH( key )     ( (uint)( fd_hash( 0UL, &key, sizeof( fd_pubkey_t ) ) ) )
#include "../../util/tmpl/fd_map.c"

#define DEQUE_NAME fd_replay_pending
#define DEQUE_T    ulong
#define DEQUE_MAX  64UL /* FIXME reasonable number of outstanding blocks */
#include "../../util/tmpl/fd_deque.c"

struct fd_replay {
  fd_replay_slot_ctx_t *   pool;       /* memory pool of slot_ctxs */
  fd_replay_frontier_t *   frontier;   /* map of slots to slot_ctxs, representing the fork heads */
  fd_replay_commitment_t * commitment; /* map of slots to stakes per commitment level */
  ulong *                  pending;    /* pending slots to try to prepare */
  ulong                    smr;        /* super-majority root */
  ulong                    snapshot_slot; /* the snapshot slot */
  ulong                    turbine_slot;  /* the first turbine slot we received on startup */

  /* turbine */
  // fd_fec_resolver_t * fec_resolver;

  /* repair */
  fd_repair_t *      repair;
  fd_repair_peer_t * repair_peers;
  fd_repair_req_t *  repair_reqs; /* map of in-flight repair requests */
  ulong              repair_req_cnt;

  fd_rng_t *            rng;
  fd_blockstore_t *     blockstore;
  fd_funk_t *           funk;
  fd_acc_mgr_t *        acc_mgr;
  fd_exec_epoch_ctx_t * epoch_ctx;
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
fd_replay_footprint( ulong slot_max ) {
  return sizeof( fd_replay_t ) + 
         fd_replay_pool_footprint( slot_max ) + fd_replay_frontier_footprint( slot_max ) +
         fd_replay_commitment_footprint() +
         fd_replay_pending_footprint() + fd_repair_peer_footprint() + fd_repair_req_footprint();
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

/* fd_replay_shred_insert inserts a shred into the blockstore. If this completes a block, and it is
   connected to a frontier fork, it also executes the block and updates the frontier accordingly. */
void
fd_replay_shred_insert( fd_replay_t * replay, fd_shred_t const * shred );

/* fd_replay_slot_parent queries the parent of slot in the replay frontier, updating the frontier if
   it can't find it (which indicates a new fork). */
void
fd_replay_slot_parent_query( fd_replay_t * replay, ulong slot );

/* fd_replay_slot_prepare prepares slot for execution. It does 3 things:
     1. the block for that slot is complete.
     2. the block is not an orphan (parent block is present).
     3. checks if the parent block is in the frontier (adding it if not).

   It is intended to be called in a loop as shreds are asynchronously received.

   Returns FD_REPLAY_READY on 3, otherwise FD_REPLAY_PENDING.
*/
fd_replay_slot_ctx_t *
fd_replay_slot_prepare( fd_replay_t *  replay,
                        ulong          slot,
                        uchar const ** block_out,
                        ulong *        block_sz_out );

/* fd_replay_slot_execute executes block at slot_ctx. Intended to be called after
   fd_replay_slot_prepare returns successfully.  */
void
fd_replay_slot_execute( fd_replay_t *          replay,
                        ulong                  slot,
                        fd_replay_slot_ctx_t * parent_slot_ctx,
                        uchar const *          block,
                        ulong                  block_sz );

/* fd_replay_slot_ctx_restore restores slot_ctx to its state as of slot. Assumes the blockhash
 * corresponding to slot is in funk. */
void
fd_replay_slot_ctx_restore( fd_replay_t * replay, ulong slot, fd_exec_slot_ctx_t * slot_ctx );

void
fd_replay_turbine_rx( fd_replay_t * replay, fd_shred_t const * shred );

void
fd_replay_repair_rx( fd_replay_t * replay, fd_shred_t const * shred );

fd_repair_peer_t *
fd_replay_repair_peer_sample( fd_replay_t * replay );

FD_PROTOTYPES_END

#endif
