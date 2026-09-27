#ifndef HEADER_fd_src_discof_rotor_fd_requestor_h
#define HEADER_fd_src_discof_rotor_fd_requestor_h

/* fd_requestor turns a chainer FEC set that is due for repair into the
   one request it needs.  The rotor tile pops the most overdue set off
   a chainer worklist and calls fd_requestor_fec_request with it; what
   to ask for is read off the set and its version, so the requestor
   holds no state but a cursor into the set being filled.

   fd_requestor_block_start / fd_requestor_block_advance are the older
   per-block cursor walk, which the schedulor used to drive.  Nothing
   calls them now that the tile polls the worklists directly; they are
   kept only until their tests are retired. */

#include "../chainer/fd_chainer.h"

/* fd_requestor_block_advance results */

#define FD_REQUESTOR_ADVANCE_IDLE             (0) /* no walk in progress */
#define FD_REQUESTOR_ADVANCE_REQUEST          (1) /* *out_request filled, send it; the walk goes on */
#define FD_REQUESTOR_ADVANCE_DONE             (2) /* walk over, nothing was asked for */
#define FD_REQUESTOR_ADVANCE_REQUESTED_PARENT (3) /* walk over; *out_request holds its one metadata request, send it (fill requests may have preceded it) */

/* FD_REQUESTOR_ORPHAN_FILL_MAX bounds the fill requests one walk emits
   for a block whose parent is known but absent, or whose tip is not
   yet known. */

#define FD_REQUESTOR_ORPHAN_FILL_MAX    (32U)
#define FD_REQUESTOR_ADVANCE_REQUESTED  (4) /* walk over, fill requests went out */

/* fd_rotor_request_t is one repair request, independent of the wire:
   the tile picks a peer, builds the fd_repair_msg_t and sends it for
   signing. */

struct fd_rotor_request {
  uint      kind;     /* FD_REPAIR_KIND_*, AG_REPAIR_KIND_* */
  ulong     slot;
  uint      idx;      /* shred idx, or fec_set_idx for FEC_ROOT */
  fd_hash_t block_id; /* all-zero for positional kinds (the turbine version) */
  fd_hash_t fec_root; /* SHRED_FOR_BLOCK_ID: root of the set the shred is asked from */
};
typedef struct fd_rotor_request fd_rotor_request_t;

typedef struct fd_requestor fd_requestor_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_requestor_align( void );

FD_FN_CONST ulong
fd_requestor_footprint( void );

void *
fd_requestor_new( void * mem );

fd_requestor_t *
fd_requestor_join( void * mem );

void *
fd_requestor_leave( fd_requestor_t const * requestor );

void *
fd_requestor_delete( void * mem );

/* fd_requestor_set_block_id_only suppresses legacy request kinds
   (development only). */

void
fd_requestor_set_block_id_only( fd_requestor_t * self,
                                int              block_id_only );

/* fd_requestor_block_start begins a walk of block {slot, block_id}
   from shred 0, replacing any walk in progress. */

void
fd_requestor_block_start( fd_requestor_t *  self,
                          ulong             slot,
                          fd_hash_t const * block_id );

/* fd_requestor_block_advance cranks the walk once and returns one of
   the FD_REQUESTOR_ADVANCE_* codes.
     REQUEST           *out_request holds the next fill request and the
                       cursor has moved past it; call again.
     REQUESTED_PARENT  the walk is over and *out_request holds its one
                       metadata request: send it, then recheck the
                       block after the parent timeout.  Fill requests
                       may have been returned earlier in the walk.
     REQUESTED         the walk is over; fill requests went out.
     DONE              the walk is over; nothing was asked for (the block
                       is whole with its parent present, or gone).
     IDLE              no walk in progress.
   A terminal code is returned exactly once per walk; the requestor is
   idle afterwards.  *out_slot and *out_block_id name the walked block
   on every call but IDLE.  *out_request is untouched unless REQUEST or
   REQUESTED_PARENT is returned. */

int
fd_requestor_block_advance( fd_requestor_t *     self,
                            fd_chainer_t *       chainer,
                            fd_rotor_request_t * out_request,
                            ulong *              out_slot,
                            fd_hash_t *          out_block_id );

/* fd_requestor_fec_request builds the one request a due FEC set needs
   and returns 1, or returns 0 if the set needs nothing right now.
   slotv must be the version that owns fec (fd_chainer_fec_owner).

   What a set needs is read from its version's state and the shared
   received bitmap in chainer:

     cert-named version, set count unknown   ParentAndFecSetCount
     cert-named version, root unknown        FecSetRoot
     cert-named version, shred missing       ShredForBlockId
     turbine version,    parent unknown      Shred idx 0 (its header names the parent)
     turbine version,    shred missing       Shred
     turbine version,    tip unknown         HighestShred

   The block-level requests (ParentAndFecSetCount, HighestShred) are
   only ever emitted for set 0, which stands in for the block, so a
   block with many enrolled sets does not ask N times.  Legacy kinds
   are suppressed under block_id_only.

   from_shred_idx is the caller's sweep position: shreds below it are
   not considered, which is what keeps one round from asking the same
   shred twice.  A fill keeps a cursor within the set, so successive calls ask for
   each missing shred once rather than repeating the first.  If
   opt_more is non-NULL it is set to 1 when the set still has shreds to
   ask for after this one, which is the caller's cue to leave the
   deadline at "due now" and keep servicing it; otherwise the caller
   re-arms a repair timeout out.  Either way the caller must re-arm,
   whether or not a request went out, else the worklist spins on it. */

int
fd_requestor_fec_request( fd_requestor_t *     self,
                          fd_chainer_t *       chainer,
                          fd_chainer_slotv_t * slotv,
                          fd_chainer_fec_t *   fec,
                          uint                 from_shred_idx,
                          fd_rotor_request_t * out_request,
                          int *                opt_more );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rotor_fd_requestor_h */
