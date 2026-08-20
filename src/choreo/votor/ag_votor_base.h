#ifndef HEADER_fd_src_choreo_votor_ag_votor_base_h
#define HEADER_fd_src_choreo_votor_ag_votor_base_h

#include "../../flamenco/fd_flamenco_base.h"

#define AG_SLOTS_PER_WINDOW (4UL)
#define AG_SLOTS_PER_EPOCH  (18000UL)

#define AG_VAT_MAX (2000UL) /* Validator Admission Ticket caps at 2000 */

#define AG_BLOCK_HASH_EQVOC_MAX    (7UL) /* Corollary 50 */
#define AG_NOTAR_FALLBACK_VOTE_MAX (3UL) /* Definition 12 */
#define AG_NOTAR_FALLBACK_CERT_MAX (4UL) /* Lemma 48 */

#define AG_DELTA_NS             (250000000L)       /* 250 ms 0.5-RTT, partial-synchrony */
#define AG_DELTA_BLOCK_NS       (200000000L)       /* 200 ms slots */
#define AG_DELTA_FIRST_SLICE_NS (10000000L)        /* TODO */
#define AG_DELTA_TIMEOUT_NS     (3L * AG_DELTA_NS) /* skip timeout  */
#define AG_DELTA_STANDSTILL_NS  (10000000000L)     /* 10s since last finalize */

#define AG_WEAKEST_QUORUM_THRESHOLD_NUMER (1UL) /* 20%, safe-to-notar + 40% skip */
#define AG_WEAK_QUORUM_THRESHOLD_NUMER    (2UL) /* 40%, safe-to-notar / safe-to-skip */
#define AG_QUORUM_THRESHOLD_NUMER         (3UL) /* 60%, notarize, finalize and skip */
#define AG_STRONG_QUORUM_THRESHOLD_NUMER  (4UL) /* 80%, fast-finalize */
#define AG_QUORUM_THRESHOLD_DENOM         (5UL) /* 100% */

struct ag_block_id {
  ulong     slot; /* slot for which the block was produced */
  fd_hash_t hash; /* double merkle root */
};
typedef struct ag_block_id ag_block_id_t;

struct ag_block_info {
  fd_hash_t     hash;   /* double merkle root of the block */
  ag_block_id_t parent; /* the block this block extends */
};
typedef struct ag_block_info ag_block_info_t;

/* ag_standstill names votes and certs only through pointers, so their
   tags suffice.  Forward declaring them here keeps ag_votor_base a leaf:
   ag_vote.h and ag_cert.h both include it. */

typedef struct ag_vote ag_vote_t;
typedef struct ag_cert ag_cert_t;

struct ag_standstill {
  ulong       slot;
  ag_cert_t * certs;
  ulong       cert_cnt;
  ag_vote_t * votes;
  ulong       vote_cnt;
};
typedef struct ag_standstill ag_standstill_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline int
ag_block_id_eq( ag_block_id_t const * a,
                ag_block_id_t const * b ) {
  return a->slot==b->slot && !memcmp( a->hash.uc, b->hash.uc, sizeof(fd_hash_t) );
}

FD_PROTOTYPES_END

#endif
