#ifndef HEADER_fd_src_alpenglow_ag_alpenglow_base_h
#define HEADER_fd_src_alpenglow_ag_alpenglow_base_h

#include "../flamenco/fd_flamenco_base.h"
#include "types/ag_slot.h"

/* ag_alpenglow_base.h is the C stand-in for the reference impl's crate
   root: what lib.rs / consensus.rs / types.rs expose to every module.
   Anything belonging to one module lives in that module's header --
   notably the quorum predicates, which are EpochInfo methods
   (ag_epoch_info_is_*_quorum), not free functions.

   What is here, and where it comes from:

     AG_ALPENGLOW_DELTA_*                        consensus.rs
     AG_ALPENGLOW_*_QUORUM_NUMER / _DENOM        consensus.rs (the *_QUORUM_THRESHOLD Fractions)
     ag_alpenglow_fraction_is_met                types/fraction.rs (Fraction::is_met)
     ag_block_id_t                               lib.rs (pub type BlockId = (Slot, BlockHash))

   types/ag_slot.h is included here rather than by each user, mirroring
   the crate root re-exporting types::{Slot, SLOTS_PER_*}. */

/* VAT caps the number of validators */
#define AG_ALPENGLOW_VALIDATOR_MAX (2000UL)

#define AG_ALPENGLOW_DELTA_NS             (250000000L)
#define AG_ALPENGLOW_DELTA_BLOCK_NS       (400000000L)
#define AG_ALPENGLOW_DELTA_FIRST_SLICE_NS (10000000L)
#define AG_ALPENGLOW_DELTA_TIMEOUT_NS     (3L*AG_ALPENGLOW_DELTA_NS)
#define AG_ALPENGLOW_DELTA_STANDSTILL_NS  (10000000000L)

#define AG_ALPENGLOW_WEAKEST_QUORUM_NUMER (1UL)
#define AG_ALPENGLOW_WEAK_QUORUM_NUMER    (2UL)
#define AG_ALPENGLOW_QUORUM_NUMER         (3UL)
#define AG_ALPENGLOW_STRONG_QUORUM_NUMER  (4UL)
#define AG_ALPENGLOW_QUORUM_DENOM         (5UL)

struct ag_block_id {
  ulong     slot; /* slot associated with the block */
  fd_hash_t hash; /* double merkle root */
};
typedef struct ag_block_id ag_block_id_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline int
ag_alpenglow_fraction_is_met( ulong stake,
                              ulong total,
                              ulong numer,
                              ulong denom ) {
  return (uint128)stake*(uint128)denom >= (uint128)total*(uint128)numer;
}

FD_FN_PURE static inline int
ag_block_id_eq( ag_block_id_t const * a,
                ag_block_id_t const * b ) {
  return a->slot==b->slot && !memcmp( a->hash.uc, b->hash.uc, sizeof(fd_hash_t) );
}

FD_PROTOTYPES_END

#endif
