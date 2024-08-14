#ifndef HEADER_fd_src_choreo_fd_choreo_base_h
#define HEADER_fd_src_choreo_fd_choreo_base_h

/* Choreo consensus library:

  - eqvoc: Equivocation (aka. "duplicate block") handler.

  - forks: Frontier of banks for replay and block production.

  - ghost: Fork choice rule.

  - tower: TowerBFT algorithm.

  - voter: Voter tracking.

  */

#include "../flamenco/fd_flamenco.h"
#include "../flamenco/types/fd_types.h"
#include "../tango/fd_tango.h"

/* clang-format off */
#define FD_BLOCK_MAX          (1UL << 12UL) /* the maximum # of blocks we support holding at once. must be >=512. */
#define FD_VOTER_MAX          (1UL << 12UL) /* the maximum # of unique voters ie. node pubkeys. */
#define FD_EQV_SAFE           (0.52)
#define FD_OPT_CONF           (2.0 / 3.0)
#define FD_SMR_PCT            FD_OPT_CONF
#define FD_SLOT_HASH_CMP(a,b) (fd_int_if(((a)->slot)<((b)->slot),-1,fd_int_if(((a)->slot)>((b)->slot),1),memcmp((a),(b),sizeof(fd_slot_hash_t))))
#define FD_SLOT_HASH_EQ(a,b)  ((((a)->slot)==((b)->slot)) & !(memcmp(((a)->hash.uc),((b)->hash.uc),sizeof(fd_hash_t))))
/* clang-format on */

static const fd_slot_hash_t FD_SLOT_HASH_NULL = { .slot = FD_SLOT_NULL, .hash = { { 0 } } };

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
