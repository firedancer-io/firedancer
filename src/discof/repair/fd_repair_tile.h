#ifndef HEADER_fd_src_discof_repair_fd_repair_tile_h
#define HEADER_fd_src_discof_repair_fd_repair_tile_h

#include "../../disco/tiles.h"
#include "../../disco/shred/fd_shred_tile.h"

/* Repair tile forwards all FEC completes received by the shred tile.
   It forwards the FEC completes with new sigs:
   - REPAIR_SIG_FEC: FEC set complete
   - REPAIR_SIG_FEC_LEADER: Leader FEC set complete
   - REPAIR_SIG_FEC_INVALID: FEC set detected as invalid based on duplicate confirmations

   Note that invalidity is very strict. i.e., sometimes replay may not
   want FEC set at the root / or older than the root to be inserted.
   Repair should still forward these as REPAIR_SIG_FEC, because they are
   FEC sets that are either valid, or cannot be verified as invalid.
   Similarly, repair may have received two versions of one FEC, but is
   unsure which one is canonical.  These are also forwarded as
   REPAIR_SIG_FEC. It's up to replay tile to arbitrate whether to insert
   these FEC sets.

   A FEC set forwarded as REPAIR_SIG_FEC_INVALID is with confidence
   guaranteed to be not part of the canonical chain. */

#define REPAIR_SIG_FEC         (0UL)  /* FEC set complete */
#define REPAIR_SIG_FEC_LEADER  (1UL)  /* Leader FEC set complete */
#define REPAIR_SIG_FEC_INVALID (2UL)  /* FEC set detected as invalid based on duplicate confirmations */

#endif /* HEADER_fd_src_discof_repair_fd_repair_tile_h */
