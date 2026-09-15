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

static const fd_pubkey_t pubkey_null  = { { 0 } };
static const fd_hash_t   hash_null    = { { 0 } };
static const fd_hash_t   hash_invalid = { .ul = { ULONG_MAX, ULONG_MAX, ULONG_MAX, ULONG_MAX } };

/* FD_TOWER_LOCKOS_MAX is the max number of lockouts in a tower, which
   equals the max number of votes (FD_TOWER_VOTE_MAX) and the max number
   of lockouts in a CompactTowerSync vote instruction. */

#define FD_TOWER_LOCKOS_MAX 31UL
#define FD_TOWER_VOTE_MAX (FD_TOWER_LOCKOS_MAX)

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
