#ifndef HEADER_fd_src_choreo_tower_fd_tower_h
#define HEADER_fd_src_choreo_tower_fd_tower_h

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../fd_choreo_base.h"
#include "../ghost/fd_ghost.h"

/* FD_TOWER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_TOWER_USE_HANDHOLDING
#define FD_TOWER_USE_HANDHOLDING 1
#endif

#define FD_TOWER_THRESHOLD_CHECK_DEPTH         ( 8 )
#define FD_TOWER_THRESHOLD_CHECK_PCT           ( 2.0 / 3.0 )
#define FD_TOWER_SHALLOW_THRESHOLD_CHECK_DEPTH ( 4 )
#define FD_TOWER_SHALLOW_THRESHOLD_CHECK_PCT   ( 0.38 )

/* Maintain our local vote tower */

struct fd_tower {
  ulong     slots[32];
  ulong     slots_cnt;
  fd_hash_t root;

  fd_blockstore_t * blockstore;
  fd_ghost_t *      ghost;
};
typedef struct fd_tower fd_tower_t;

#endif /* HEADER_fd_src_choreo_tower_fd_tower_h */
