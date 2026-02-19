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

/* The Alpenglow VAT caps the voting set of validators to 2000.  Round
   up to the nearest power of 2 and double for a reasonable fill ratio
   of 0.5 for maps, and we have an upper bound of 4096 to use in various
   choreo structures.

   https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0357-alpenglow_validator_admission_ticket.md */

#define FD_VOTER_MAX (4096) /* the maximum # of unique voters ie. node pubkeys. */

static const fd_pubkey_t pubkey_null = {{ 0 }};
static const fd_hash_t   hash_null   = {{ 0 }};

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
