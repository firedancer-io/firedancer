#ifndef HEADER_fd_src_discof_rotor_fd_rotor_tile_h
#define HEADER_fd_src_discof_rotor_fd_rotor_tile_h

#include "../../disco/tiles.h"
#include "../../disco/shred/fd_shred_tile.h"

/* Rotor tile forwards FECs in replay order to replay tile with the following sigs:
   - REPAIR_SIG_FEC: FEC set complete

   However since rotor is a direct drop in for repair tile, we have to make
   sure the sigs do not clobber the repair tile's sigs.

   See fd_repair_tile.h
   #define REPAIR_SIG_FEC_INVALID (2UL)
   #define REPAIR_SIG_FEC_LEADER  (1UL)
   #define REPAIR_SIG_FEC         (0UL)

   FECs are delivered in replay order. Blocks that were not repaired
   through verified (i.e., received through turbine) means are delivered
   with block_id = {0} until the last FEC in the block, in which the
   block_id is set to the computed DMR of the previously delivered FECs.

   Blocks that were repaired through verified means (i.e. using ag block
   id repair from a votor event) know the block_id immediately before
   the first FEC is delivered, so the block_id on the FECs of this slot
   is set to the correct value starting from fec 0. For these blocks,
   the verified bit is 1.

   There is a race in the case no equivocation occurred, but we are
   slow to complete the block (network blip, or simply the cert
   arriving before the last FEC set) and get a votor event for the
   block_id.  Then we complete the same block through turbine and ag
   block_id repair simultaneously, as two chainer versions that share
   the same FECs (see fd_chainer.h), and every FEC is delivered twice.

   Consider this case:
   Slot A (started receiving through turbine): received FEC 0, 1, and 5
   shreds of FEC 2. FEC 0 and 1 are delivered to replay with {verified=0, block_id=null}

   *blip*

   Get a notar fallback for slot A'. No equivocation occurred, but we
   can't tell, so we also start repairing A' using ag block id repair.
   Slot A' is immediately able to complete FEC 0 and 1 (the shreds are
   local), and they are re-delivered to replay with {verified=1,
   block_id=A'}.  Remaining shreds of FEC 2 -- whether they arrive
   through turbine or ShredForBlockId repair -- fill the shared FEC,
   and FEC 2 is delivered twice: once under the turbine version, whose
   block_id finalizes to A' at that point, and once under A'.

   Replay handles the second stream.  The verified copy's FEC 0 misses
   the turbine bank (keyed {slot, 0}) and allocates its own bank keyed
   {slot, A'}, and its mid-slot FECs are ingested into it.  Whichever
   copy completes first re-keys onto {slot, A'}, unlinking the other
   copy's map entry; the other copy's slot-complete FEC then finds the
   completed bank and is skipped.  The loser is left an incomplete
   sibling bank of the same slot and is pruned when the slot roots.  So
   the cost of the race is one extra bank and the execution of the
   duplicate's prefix, not a correctness problem. */

// TODO remove after reasm removal
#define REPAIR_SIG_FEC         (0UL)
#define REPAIR_SIG_FEC_LEADER  (1UL)
#define REPAIR_SIG_FEC_INVALID (2UL)

/* alpenglow type - replayable fec */
#define ROTOR_SIG_FEC_REPLAY  (3UL)

struct fd_rotor_replay_fec {
   ulong     slot;
   uint      fec_set_idx;
   fd_hash_t mr;

   /* conditional fields */

   ulong     parent_slot;     /* only present if fec_set_idx is 0 or has
                                 parentUpdate. TBD, could also just have
                                 replay do parent reparsing */
   fd_hash_t parent_block_id;

   int       slot_complete;
   int       data_complete;
   int       is_leader;

   /* known_id.  This is not the same as slot_complete = 1. known_id
      should be set always to 1 if the block id was known from the
      start, i.e. these FECs were recovered through block_id repair of a
      votor event. known_id should be 0 for blocks that were received
      through turbine, until the last FEC is received, which should
      complete knowledge of the block_id.

      In other words, known_id is a keying instruction, not a statement about whether the block id is known:
      - known_id set: Replay keys the block by {slot, block_id} starting at FEC 0 and looks up its parent element by that key for every later FEC.
      - known_id clear: the block is a turbine version. Replay keys it by {slot, 0} until it processes the slot-complete FEC, then re-keys it to {slot, dmr}.
                        This holds for every FEC of the block, including redelivered copies, so all FECs of one block always resolve to the same element.

      Redelivery from root never changes known_id. It only affects block_id */
   int       known_id;
   fd_hash_t block_id; /* always populated if known_id is 1, or if slot_complete is 1.  Otherwise could be populated on redelivery or as soon as the block_id is computed.  */
};
typedef struct fd_rotor_replay_fec fd_rotor_replay_fec_t;

#endif /* HEADER_fd_src_discof_rotor_fd_rotor_tile_h */
