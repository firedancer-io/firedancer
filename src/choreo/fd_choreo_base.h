#ifndef HEADER_fd_src_choreo_fd_choreo_base_h
#define HEADER_fd_src_choreo_fd_choreo_base_h

/* Choreo is the consensus library.

  - bft: wires it all together.
  - eqv: equivocation (also called "duplicate block") handling.
  - forks: data structures and associated functions to manage "forks", ie. competing views in the
  canonical state of the blockchain.
  - ghost: fork choice rule, ie. which fork is the best one that I should pick.
  - tower: TowerBFT rules for reaching consensus by "finalizing" blocks, ie. you
    can no longer rollback a block or switch to a different fork.

    Includes threshold check and switch proof.

    Note this is the TowerBFT implementation on the local ("self") side. The Vote Program is the
    TowerBFT implementation for the cluster ("others") side. In other words, the local validator
    runs through these rules before submitting the vote. The other validators in the cluster then
    process the submitted vote using the Vote Program. */

#include "../flamenco/fd_flamenco_base.h"
#include "../flamenco/types/fd_types.h"

/* clang-format off */
#define FD_FORK_MAX           (1 << 10UL)
#define FD_VOTER_MAX          (1 << 14UL) /* the maximum # of unique voters ie. node pubkeys */
#define FD_SLOT_HASH_CMP(a,b) (fd_int_if(((a)->slot)<((b)->slot),-1,fd_int_if(((a)->slot)>((b)->slot),1),memcmp((a),(b),sizeof(fd_slot_hash_t))))
#define FD_SLOT_HASH_EQ(a,b)  ((((a)->slot)==((b)->slot)) & !(memcmp(((a)->hash.uc),((b)->hash.uc),sizeof(fd_hash_t))))
/* clang-format on */

static const fd_slot_hash_t FD_SLOT_HASH_NULL = { .slot = FD_SLOT_NULL, .hash = { { 0 } } };

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
