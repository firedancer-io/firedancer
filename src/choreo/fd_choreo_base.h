#ifndef HEADER_fd_src_choreo_fd_choreo_base_h
#define HEADER_fd_src_choreo_fd_choreo_base_h

/* Choreo consensus library:

  - eqvoc: Block and vote equivocation.

  - forks: Frontier of banks.

  - ghost: Fork choice rule.

  - tower: TowerBFT algorithm.

  - voter: Voter tracking.

  */

#include "../flamenco/fd_flamenco.h"
#include "../flamenco/types/fd_types.h"

static const fd_pubkey_t pubkey_null = {{ 0 }};
static const fd_hash_t   hash_null   = {{ 0 }};

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
