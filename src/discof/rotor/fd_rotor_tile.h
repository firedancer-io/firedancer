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

   There is a race in the case no equivocation occurred, but we
   suffered some network disconnection and are slow to complete the
   block (but we get a votor event for the block_id).  Then we would be
   simultaneously completing the same block through turbine and ag
   block_id repair, and the turbine copy's slot-complete FEC would
   re-key its replay bank from {slot, 0} to a {slot, block_id} that the
   verified copy's bank already occupies.

   To prevent that, the chainer ABANDONS the turbine version of a slot
   the moment a votor-driven version of it is created while the turbine
   block_id is still unknown (see fd_chainer.h): the abandoned version
   keeps absorbing turbine shreds (they fill the FECs the verified
   version shares) but never delivers another FEC and never finalizes a
   block_id.

   Consider this case:
   Slot A (started receiving through turbine): received FEC 0, 1, and 5
   shreds of FEC 2. FEC 0 and 1 are delivered to replay with {verified=0, block_id=null}

   *blip*

   Get a notar fallback for slot A'. No equivocation occurred, but we
   can't tell, so we also start repairing A' using ag block id repair,
   and the turbine version of the slot is abandoned.  Slot A' is
   immediately able to complete FEC 0 and 1 (the shreds are local), and
   they are re-delivered to replay with {verified=1, block_id=A'}.
   Remaining shreds of FEC 2 -- whether they arrive through turbine or
   ShredForBlockId repair -- fill the shared FEC, and FEC 2 is delivered
   once, under A', with {verified=1, block_id=A'}.

   The effect is that in time of network blips, replay ends up
   allocating up to two banks for the same slot/block: the turbine bank
   keyed {slot, 0} receives only a prefix of the block, never completes,
   never gets re-keyed (so it can never collide with the verified bank
   keyed {slot, block_id}), and is eventually evicted or pruned. */

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

      If rotor is asked to redeliver a full chain of FECs from root down
      to a slot, every re-delivered FEC should also have known_id set to 1,
      because logically we know the block_id. */
   int       verified;
   fd_hash_t block_id; /* only populated if slot_complete is 1, or if verified is 1 */
};
typedef struct fd_rotor_replay_fec fd_rotor_replay_fec_t;

#endif /* HEADER_fd_src_discof_rotor_fd_rotor_tile_h */
