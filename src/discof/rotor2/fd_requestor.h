#ifndef HEADER_fd_src_discof_rotor2_fd_requestor_h
#define HEADER_fd_src_discof_rotor2_fd_requestor_h

/* fd_requestor walks one block ({slot, block_id}, a chainer slot
   version) and produces the repair requests it needs, one per call.
   It keeps only a cursor: the shred position the walk has reached.

   The tile starts a walk with fd_requestor_block_start when the
   schedulor pops a block and cranks it with fd_requestor_block_advance
   once per after_credit.  Every advance returns one result code:
   REQUEST while there is something to send (*request is filled), then
   exactly once a terminal code saying how the walk ended (DONE,
   REQUESTED_PARENT or REQUESTED), after which the requestor is idle and
   advance returns IDLE until the next block_start.  The tile uses the
   terminal code to decide when to check the block again.

   The ladder, evaluated on every advance:

     0. The block is gone (no version, at or below the root, or
        pruned): the walk ends, rung DONE.

     1. Metadata.  One request ends the walk with REQUESTED_PARENT:
          parent unknown        verified: ParentAndFecSetCount
                                turbine:  Shred idx 0 (its header names the parent)
          parent known, absent  Orphan (asks peers for the ancestry)
          complete_idx unknown  verified: ParentAndFecSetCount
                                turbine:  HighestShred

     2. Fill.  From the cursor (never behind the buffered prefix), the
        next missing shred; the walk ends when the cursor passes the
        tip, with REQUESTED if anything was asked or DONE otherwise:
          has_block_id, no entry at the set   one FecSetRoot for the set,
                                              cursor jumps to the next set
          has_block_id, shred missing         ShredForBlockId
          turbine,      shred missing         Shred

   Legacy requests (Shred, HighestShred, Orphan) are suppressed when
   block_id_only is set; that is a development flag for exercising
   block-id repair in isolation. */

#include "fd_chainor.h"

/* fd_requestor_block_advance results */

#define FD_REQUESTOR_ADVANCE_IDLE             (0) /* no walk in progress */
#define FD_REQUESTOR_ADVANCE_REQUEST          (1) /* *out_request filled, send it; the walk goes on */
#define FD_REQUESTOR_ADVANCE_DONE             (2) /* walk over, nothing was asked for */
#define FD_REQUESTOR_ADVANCE_REQUESTED_PARENT (3) /* walk over; *out_request holds its one metadata request, send it */
#define FD_REQUESTOR_ADVANCE_REQUESTED        (4) /* walk over, fill requests went out */

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
                       block after the parent timeout.
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
                            fd_chainor_t const * chainer,
                            fd_rotor_request_t * out_request,
                            ulong *              out_slot,
                            fd_hash_t *          out_block_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rotor2_fd_requestor_h */
