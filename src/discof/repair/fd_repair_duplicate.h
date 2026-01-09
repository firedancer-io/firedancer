#ifndef HEADER_fd_src_disco_repair_fd_repair_duplicate_h
#define HEADER_fd_src_disco_repair_fd_repair_duplicate_h

/* fd_repair_duplicate is a module that tracks slots that we have
   received a notice to dump and repair. If it lives in the map, it
   means there is an equivocation for this slot and we currently have
   the wrong / incomplete replayable version of the slot.  This module
   works in tandem with fd_forest to repair the correct version.

   After forest dumps and begins repairing again, any shred whose slot
   lives in the map will need to pass verification with
   fd_repair_duplicate before it can be added to the forest.  i.e., to
   the best of our knowledge, it chains back to the confirmed block id.
*/

#include "../../flamenco/types/fd_types_custom.h"
#include "../../ballet/shred/fd_shred.h"

#define FD_MAX_FEC_BLK_MAX (FD_SHRED_BLK_MAX / 32UL) /* 1024 */

#define SET_NAME verified
#define SET_MAX (FD_MAX_FEC_BLK_MAX)
#include "../../util/tmpl/fd_set.c"

/* Following map tracks slots that we have received a notice to dump and
   repair. If it lives in the map, it means there is an equivocation
   for this slot and we currently have the wrong / incomplete
   replayable version of the slot. */
struct fd_repair_merkles {
  ulong     slot;
  fd_hash_t block_id;

  uint merkle_cnt;

  struct merkle_roots {
    fd_hash_t merkle_root;
    fd_hash_t chained_merkle_root;
    uchar     recvd;
  } merkle_roots[FD_MAX_FEC_BLK_MAX];
};
typedef struct fd_repair_merkles fd_repair_merkles_t;

#define MAP_NAME    fd_repair_merkles
#define MAP_KEY     slot
#define MAP_T       fd_repair_merkles_t
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_repair_duplicate {
  fd_repair_merkles_t * dup_slots;
};
typedef struct fd_repair_duplicate fd_repair_duplicate_t;

fd_repair_duplicate_t *
fd_repair_duplicate_new( void );

void
fd_repair_duplicate_confirm( fd_repair_duplicate_t * repair_duplicate, ulong slot, fd_hash_t * block_id );


#endif /* HEADER_fd_src_disco_repair_fd_repair_duplicate_h */