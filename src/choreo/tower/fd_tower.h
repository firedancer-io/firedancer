#ifndef HEADER_fd_src_choreo_tower_fd_tower_h
#define HEADER_fd_src_choreo_tower_fd_tower_h

#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../commitment/fd_commitment.h"
#include "../fd_choreo_base.h"
#include "../forks/fd_forks.h"
#include "../ghost/fd_ghost.h"

/* FD_TOWER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_TOWER_USE_HANDHOLDING
#define FD_TOWER_USE_HANDHOLDING 1
#endif

#define FD_TOWER_THRESHOLD_CHECK_DEPTH ( 8 )
#define FD_TOWER_THRESHOLD_CHECK_PCT   ( 2.0 / 3.0 )
#define FD_TOWER_SWITCH_FORK_DEPTH ( 4 )
#define FD_TOWER_SWITCH_FORK_PCT ( 0.38 )

/* Maintain our local vote tower */

struct fd_tower {
   ulong slots[32];
   ulong slots_cnt;
};
typedef struct fd_tower fd_tower_t;

int fd_tower_threshold_check( fd_tower_t * tower ) {
   if (FD_UNLIKELY(tower->slots_cnt < FD_TOWER_THRESHOLD_CHECK_DEPTH )) {
      return 1;
   }
   ulong slot = tower->slots[tower->slots_cnt - FD_TOWER_THRESHOLD_CHECK_DEPTH];

}
