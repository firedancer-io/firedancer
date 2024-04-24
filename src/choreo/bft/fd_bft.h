#ifndef HEADER_fd_src_choreo_bft_fd_bft_h
#define HEADER_fd_src_choreo_bft_fd_bft_h

#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../commitment/fd_commitment.h"
#include "../fd_choreo_base.h"
#include "../forks/fd_forks.h"
#include "../ghost/fd_ghost.h"
#include "../tower/fd_tower.h"

/* FD_BFT_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_BFT_USE_HANDHOLDING
#define FD_BFT_USE_HANDHOLDING 1
#endif

#define FD_BFT_EQV_SAFE ( 0.52 )
#define FD_BFT_OPT_CONF ( 2.0 / 3.0 )

/* fd_bft implements Solana's Proof-of-Stake consensus protocol. */

struct fd_bft {
  ulong      snapshot_slot;
  ulong      epoch_stake; /* total amount of stake in the current epoch */
  fd_tower_t tower;       /* our local vote tower */

  /* external joins */

  fd_acc_mgr_t *    acc_mgr;
  fd_blockstore_t * blockstore;
  fd_commitment_t * commitment;
  fd_forks_t *      forks;
  fd_ghost_t *      ghost;
  fd_valloc_t       valloc;
};
typedef struct fd_bft fd_bft_t;

/* fd_bft_{align,footprint} return the required alignment and footprint of a memory region
   suitable for use as bft with up to node_max nodes and vote_max votes. */

FD_FN_CONST static inline ulong
fd_bft_align( void ) {
  return alignof( fd_bft_t );
}

FD_FN_CONST static inline ulong
fd_bft_footprint( void ) {
  return FD_LAYOUT_FINI(
      FD_LAYOUT_APPEND( FD_LAYOUT_INIT, alignof( fd_bft_t ), sizeof( fd_bft_t ) ),
      alignof( fd_bft_t ) );
}

/* fd_bft_new formats an unused memory region for use as a bft. mem is a non-NULL
   pointer to this region in the local address space with the required footprint and alignment. */

void *
fd_bft_new( void * mem );

/* fd_bft_join joins the caller to the bft. bft points to the first byte of the
   memory region backing the bft in the caller's address space.

   Returns a pointer in the local address space to bft on success. */

fd_bft_t *
fd_bft_join( void * bft );

/* fd_bft_leave leaves a current local join. Returns a pointer to the underlying shared memory
   region on success and NULL on failure (logs details). Reasons for failure include bft is
   NULL. */

void *
fd_bft_leave( fd_bft_t const * bft );

/* fd_bft_delete unformats a memory region used as a bft. Assumes only the local process
   is joined to the region. Returns a pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. bft is obviously not a bft ... logs details). The ownership
   of the memory region is transferred to the caller. */

void *
fd_bft_delete( void * bft );

/* fd_bft_fork_update processes the vote accounts on the current fork to update the bft
 * and commitment structures. */
void
fd_bft_fork_update( fd_bft_t * bft, fd_fork_t * fork );

fd_slot_hash_t *
fd_bft_fork_choice( fd_bft_t * bft );

void
fd_bft_epoch_stake_update( fd_bft_t * bft, fd_exec_epoch_ctx_t * epoch_ctx );

void
fd_bft_tower_threshold_check( fd_bft_t * bft );

#endif /* HEADER_fd_src_choreo_bft_fd_bft_h */
