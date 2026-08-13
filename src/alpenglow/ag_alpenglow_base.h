#ifndef HEADER_fd_src_alpenglow_ag_alpenglow_base_h
#define HEADER_fd_src_alpenglow_ag_alpenglow_base_h

#include "../flamenco/fd_flamenco_base.h"
#include "types/ag_slot.h"

#define AG_VAT_MAX (2000UL) /* Validator Admission Ticket cap on number of voters */

#define AG_BLOCK_HASH_EQVOC_MAX    (7UL) /* Corollary 50 */
#define AG_NOTAR_FALLBACK_VOTE_MAX (3UL) /* Definition 12 */
#define AG_NOTAR_FALLBACK_CERT_MAX (4UL) /* Lemma 48 */

/* Block ids a window of slot_max slots can hold at once: Corollary 50
   bounds the block hashes stored per slot, so anything keyed by block id
   over a pruned window follows from slot_max and takes no cap of its
   own. */

#define AG_BLOCKID_MAX( slot_max ) ((slot_max)*AG_BLOCK_HASH_EQVOC_MAX)

#define AG_DELTA_NS             (250000000L)       /* 250 ms 0.5-RTT, partial-synchrony */
#define AG_DELTA_BLOCK_NS       (200000000L)       /* 200 ms slots */
#define AG_DELTA_FIRST_SLICE_NS (10000000L)        /* TODO */
#define AG_DELTA_TIMEOUT_NS     (3L * AG_DELTA_NS) /* skip timeout  */
#define AG_DELTA_STANDSTILL_NS  (10000000000L)     /* 10s since last finalize */

#define AG_WEAKEST_QUORUM_THRESHOLD_NUMER (1UL) /* 20%, safe-to-notar + 40% skip */
#define AG_WEAK_QUORUM_THRESHOLD_NUMER    (2UL) /* 40%, safe-to-notar / safe-to-skip */
#define AG_QUORUM_THRESHOLD_NUMER         (3UL) /* 60%, notarize, finalize and skip */
#define AG_STRONG_QUORUM_THRESHOLD_NUMER  (4UL) /* 80%, fast-finalize */
#define AG_QUORUM_THRESHOLD_DENOM         (5UL)

struct ag_block_id {
  ulong     slot; /* slot for which the block was produced */
  fd_hash_t hash; /* double merkle root */
};
typedef struct ag_block_id ag_block_id_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline int
ag_block_id_eq( ag_block_id_t const * a,
                ag_block_id_t const * b ) {
  return a->slot==b->slot && !memcmp( a->hash.uc, b->hash.uc, sizeof(fd_hash_t) );
}

FD_PROTOTYPES_END

#endif
