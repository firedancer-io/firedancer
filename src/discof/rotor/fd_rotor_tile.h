#ifndef HEADER_fd_src_discof_rotor_fd_rotor_tile_h
#define HEADER_fd_src_discof_rotor_fd_rotor_tile_h

#include "../../disco/tiles.h"
#include "../../disco/shred/fd_shred_tile.h"

/* Rotor tile forwards FECs in replay order to replay tile with the following sigs:
   - REPAIR_SIG_FEC: FEC set complete
   - REPAIR_SIG_FEC_LEADER: Leader FEC set complete

   However since rotor is a direct drop in for repair tile, we have to make
   sure the sigs do not clobber the repair tile's sigs.

   See fd_repair_tile.h
   #define REPAIR_SIG_FEC_INVALID (2UL)
   #define REPAIR_SIG_FEC_LEADER  (1UL)
   #define REPAIR_SIG_FEC         (0UL)
*/

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
   fd_hash_t block_id;         /* only populated if slot_complete is 1 */
};
typedef struct fd_rotor_replay_fec fd_rotor_replay_fec_t;

#endif /* HEADER_fd_src_discof_rotor_fd_rotor_tile_h */
