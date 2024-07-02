#ifndef HEADER_fd_src_choreo_fd_choreo_base_h
#define HEADER_fd_src_choreo_fd_choreo_base_h

/* Choreo consensus library:

  - eqvoc: Equivocation (aka. "duplicate block") handling.

  - forks: Maintains the frontier of forks (banks) that the validator
           can vote for and build blocks from.

  - ghost: Fork choice rule, ie. which fork is the best one. Necessary
           but insufficient for consensus.

  - tower: Additional consensus rules layered on top of fork choice
           determining where and when you can vote ("where" being wrt.
           to the different forks and "when" being wrt. to the current
           slot time ie. PoH). TowerBFT is the name of the algorithm for
           making these decisions.

           What's the difference between this and the Vote Program?

           The Tower module is on the sending side. It implements the
           full set of TowerBFT rules. Tower has a view of all forks,
           and the validator makes a voting decision based on all forks.

           The Vote Program is on the receiving side. It checks that
           invariants about TowerBFT are maintained on votes received
           from the cluster. These checks are comparatively superficial
           to all the rules in Tower. Furthermore, given it is a native
           program, the Vote Program only has access to the limited
           state programs are subject to. Specifically, it only has a
           view of the current fork it is executing on. It can't
           determine things like how much stake is allocated to other
           forks.

  - voter: Tooling for actually sending out vote transactions to the
           cluster.

  */

#include "../flamenco/fd_flamenco_base.h"
#include "../flamenco/types/fd_types.h"

/* clang-format off */
#define FD_BLOCK_MAX          (1 << 16UL) /* the maximum # of blocks we support holding at once. must be >=512. */
#define FD_VOTER_MAX          (1 << 12UL) /* the maximum # of unique voters ie. node pubkeys. */
#define FD_SLOT_HASH_CMP(a,b) (fd_int_if(((a)->slot)<((b)->slot),-1,fd_int_if(((a)->slot)>((b)->slot),1),memcmp((a),(b),sizeof(fd_slot_hash_t))))
#define FD_SLOT_HASH_EQ(a,b)  ((((a)->slot)==((b)->slot)) & !(memcmp(((a)->hash.uc),((b)->hash.uc),sizeof(fd_hash_t))))
/* clang-format on */

static const fd_slot_hash_t FD_SLOT_HASH_NULL = { .slot = FD_SLOT_NULL, .hash = { { 0 } } };

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
