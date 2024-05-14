#ifndef HEADER_fd_src_choreo_tower_fd_tower_h
#define HEADER_fd_src_choreo_tower_fd_tower_h

#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../fd_choreo_base.h"
#include "../forks/fd_forks.h"

/* FD_TOWER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_TOWER_USE_HANDHOLDING
#define FD_TOWER_USE_HANDHOLDING 1
#endif

#define FD_TOWER_THRESHOLD_CHECK_DEPTH         ( 8 )
#define FD_TOWER_THRESHOLD_CHECK_PCT           ( 2.0 / 3.0 )
#define FD_TOWER_SHALLOW_THRESHOLD_CHECK_DEPTH ( 4 )
#define FD_TOWER_SHALLOW_THRESHOLD_CHECK_PCT   ( 0.38 )

struct fd_tower {

  /* Maintain our local vote tower */

  ulong     slots[32];
  ulong     slots_cnt;
  fd_hash_t root;

  fd_vote_accounts_t const * vote_accounts;
  fd_valloc_t                valloc;
};
typedef struct fd_tower fd_tower_t;

FD_FN_CONST static inline ulong
fd_tower_align( void ) {
  return alignof( fd_tower_t );
}

FD_FN_CONST static inline ulong
fd_tower_footprint( void ) {
  return sizeof( fd_tower_t );
}

void
fd_tower_threshold_check( fd_vote_accounts_t * vote_accounts,
                          fd_valloc_t          valloc,
                          ulong                total_stake,
                          ulong                threshold_depth,
                          float                threshold_pct );

/* Attempt to construct a "switch proof", ie. demonstrate that at least
FD_TOWER_SWITCH_PROOF_THRESHOLD_PCT is locked out from voting for our current fork.

A validator is time-locked out from voting for other forks on a given slot n for 2^k slots, where k
is the confirmation count. Once locked out, a validator can only vote for descendants until that
lockout expires.

A switch proof is an additional constraint validators must satisfy to be able to switch forks. It is
used to safeguard optimistic confirmation

*/
fd_hash_t const *
fd_tower_switch_proof_construct( fd_tower_t * tower );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_h */
