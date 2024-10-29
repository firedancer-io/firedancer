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
#include "../tango/fd_tango.h"

/* clang-format off */
#define FD_BLOCK_MAX                  (1UL << 14UL) /* the maximum # of blocks we support holding at once. must be >=512. */
#define FD_VOTER_MAX                  (1UL << 12UL) /* the maximum # of unique voters ie. node pubkeys. */
#define FD_EQVOCSAFE_PCT              (0.52)
#define FD_CONFIRMED_PCT              (2.0 / 3.0)
#define FD_FINALIZED_PCT               FD_CONFIRMED_PCT
#define FD_SLOT_HASH_CMP(k0,k1)       (fd_int_if(((k0)->slot)<((k1)->slot),-1,fd_int_if(((k0)->slot)>((k1)->slot),1),memcmp((k0),(k1),sizeof(fd_slot_hash_t))))
#define FD_SLOT_HASH_EQ(k0,k1)        ((((k0)->slot)==((k1)->slot)) & !(memcmp(((k0)->hash.uc),((k1)->hash.uc),sizeof(fd_hash_t))))
#define FD_SLOT_HASH_HASH(key,seed)   fd_ulong_hash( ((key)->slot) ^ ((key)->hash.ul[0]) ^ (seed) )
#define FD_SLOT_PUBKEY_CMP(a,b)       FD_SLOT_HASH_CMP(a,b)
#define FD_SLOT_PUBKEY_EQ(k0,k1)      FD_SLOT_HASH_EQ(k0,k1)
#define FD_SLOT_PUBKEY_HASH(key,seed) FD_SLOT_HASH_HASH(key,seed)
/* clang-format on */

typedef fd_slot_hash_t fd_slot_pubkey_t;

static const fd_slot_hash_t FD_SLOT_HASH_NULL = { .slot = FD_SLOT_NULL, .hash = { { 0 } } };

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
