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

#include "../../choreo/fd_choreo.h"
#include "../../flamenco/gossip/fd_gossip.h"
#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "fd_pending_slots.h"
#include "../shred/fd_fec_resolver.h"

#ifdef FD_HAS_LIBMICROHTTP
typedef struct fd_rpc_ctx fd_rpc_ctx_t;
#endif

#define FD_REPLAY_DATA_SHRED_CNT   ( 32UL )
#define FD_REPLAY_PARITY_SHRED_CNT ( 32UL )

#define FD_REPLAY_PENDING_MAX      ( 1U << 14U ) /* 16 kb */
#define FD_REPLAY_PENDING_MASK     ( FD_REPLAY_PENDING_MAX - 1U )

/* The standard amount of time that we wait before repeating a slot */
#define FD_REPAIR_BACKOFF_TIME ( (long)150e6 )

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

/* clang-format off */
struct __attribute__((aligned(128UL))) fd_replay {
  long now;            /* Current time */

  /* metadata */
  ulong smr;           /* super-majority root */
  ulong snapshot_slot; /* the snapshot slot */
  ulong first_turbine_slot;  /* the first turbine slot we received on startup */
  ulong curr_turbine_slot;

  /* internal joins */
  fd_replay_commitment_t *   commitment;   /* map of slots to stakes per commitment level */
  long * pending;                      /* pending slots to try to prepare */
  ulong pending_start;
  ulong pending_end;
  ulong pending_lock;
  
  /* external joins */
  fd_acc_mgr_t *        acc_mgr;
  fd_bft_t *            bft;
  fd_blockstore_t *     blockstore;
  fd_forks_t *          forks;
  fd_funk_t *           funk;
  fd_exec_epoch_ctx_t * epoch_ctx;
  fd_tpool_t *          tpool;
  ulong                 max_workers;
  fd_valloc_t           valloc;

  /* shred cap */
  FILE*                 shred_cap;
  ulong                 stable_slot_start;
  ulong                 stable_slot_end;

  /* only for live case */

  /* repair */
  fd_repair_t *      repair;

  /* turbine */
  uchar *             data_shreds;
  uchar *             parity_shreds;
  fd_fec_set_t *      fec_sets;
  fd_fec_resolver_t * fec_resolver; /* turbine */

  /* gossip */
  fd_gossip_t *         gossip;

#ifdef FD_HAS_LIBMICROHTTP
  fd_rpc_ctx_t *        rpc_ctx;
#endif
};
typedef struct fd_replay fd_replay_t;


/* clang-format on */

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

FD_PROTOTYPES_BEGIN

/* fd_replay_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as replay with up to node_max
   nodes and 1 << lg_msg_max msgs. align returns FD_replay_ALIGN. */

FD_FN_CONST static inline ulong
fd_replay_align( void ) {
  return alignof( fd_replay_t );
}

FD_FN_CONST static inline ulong
fd_replay_footprint( void ) {
  /* clang-format off */
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof( fd_replay_t ), sizeof( fd_replay_t ) ),
      fd_replay_commitment_align(), fd_replay_commitment_footprint() ),
      alignof( long ), sizeof( long )*FD_PENDING_MAX ),
    alignof( fd_replay_t ) );
  /* clang-format on */
}

/* fd_replay_new formats an unused memory region for use as a replay. mem is a non-NULL pointer to
   this region in the local address space with the required footprint and alignment.*/

void *
fd_replay_new( void * mem );

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

/* fd_replay_add_pending adds the slot to the list of slots which
   require attention (getting shreds or executing). delay is the
   number of nanosecs before we should actually act on this. */

/* fd_replay_shred_insert inserts a shred into the blockstore. If this completes a block, and it is
   connected to a frontier fork, it also executes the block and updates the frontier accordingly. */
int
fd_replay_shred_insert( fd_replay_t * replay, fd_shred_t const * shred );

/* fd_replay_slot_prepare prepares slot for execution. It does 3 things:
     1. the block for that slot is complete.
     2. the block is not an orphan (parent block is present).
     3. checks if the parent block is in the frontier (adding it if not).

//    It is intended to be called in a loop as shreds are asynchronously received.

   Returns FD_REPLAY_READY on 3, otherwise FD_REPLAY_PENDING.
*/
fd_fork_t *
fd_replay_slot_prepare( fd_replay_t * replay, ulong slot );

/* fd_replay_slot_execute executes block at slot_ctx. Intended to be called after
   fd_replay_slot_prepare returns successfully.  */
void
fd_replay_slot_execute( fd_replay_t *      replay,
                        ulong              slot,
                        fd_fork_t *        parent_slot_ctx,
                        fd_capture_ctx_t * capture_ctx );

/* fd_replay_slot_repair repairs all the missing shreds for slot. */
void
fd_replay_slot_repair( fd_replay_t * replay, ulong slot );

/* fd_replay_slot_ctx_restore restores slot_ctx to its state as of slot. Assumes the blockhash
 * corresponding to slot is in funk. */
void
fd_replay_slot_ctx_restore( fd_replay_t * replay, ulong slot, fd_exec_slot_ctx_t * slot_ctx );

void
fd_replay_turbine_rx( fd_replay_t * replay, fd_shred_t const * shred, ulong shred_sz );

void
fd_replay_repair_rx( fd_replay_t * replay, fd_shred_t const * shred );

ulong
fd_replay_pending_iter_init( fd_replay_t * replay );

ulong
fd_replay_pending_iter_next( fd_replay_t * replay, long now, ulong i );

fd_fork_t *
fd_replay_prepare_ctx( fd_replay_t * replay,
                       ulong parent_slot );

FD_PROTOTYPES_END

#endif
