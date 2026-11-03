#ifndef HEADER_fd_src_choreo_votor_fd_votor_base_h
#define HEADER_fd_src_choreo_votor_fd_votor_base_h

#include "../../util/fd_util.h"

#define FD_VOTOR_SLOTS_PER_WINDOW        (4UL)
#define FD_VOTOR_REWARD_SLOT_DELTA       (8UL)    /* Agave NUM_SLOTS_FOR_REWARD */
#define FD_VOTOR_VAT_MAX                 (2000UL) /* Validator Admission Ticket caps at 2000 */
#define FD_VOTOR_EQVOC_MAX               (7UL)    /* Corollary 50 */
#define FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX (3UL)    /* Definition 12 */
#define FD_VOTOR_NOTAR_FALLBACK_CERT_MAX (4UL)    /* Lemma 48 */
#define FD_VOTOR_VOTES_PER_SLOT_MAX      (5UL)    /* notar + 3 notar_fallback + skip_fallback */

#define FD_VOTOR_DELTA_TIMEOUT_NS    (400000000L)   /* skip timeout */
#define FD_VOTOR_DELTA_STANDSTILL_NS (10000000000L) /* 10s since last finalize */

#define FD_VOTOR_WEAKEST_QUORUM_THRESHOLD_NUMER (1UL) /* 20%, safe-to-notar + 40% skip */
#define FD_VOTOR_WEAK_QUORUM_THRESHOLD_NUMER    (2UL) /* 40%, safe-to-notar / safe-to-skip */
#define FD_VOTOR_QUORUM_THRESHOLD_NUMER         (3UL) /* 60%, notarize, finalize and skip */
#define FD_VOTOR_STRONG_QUORUM_THRESHOLD_NUMER  (4UL) /* 80%, fast-finalize */
#define FD_VOTOR_QUORUM_THRESHOLD_DENOM         (5UL) /* 100% */

struct fd_block_hash { /* double merkle root of the block */
  uchar uc[ 32 ];
};
typedef struct fd_block_hash fd_block_hash_t;
static const fd_block_hash_t fd_block_hash_null = { 0 };

struct fd_block_id {
  ulong           slot;
  fd_block_hash_t hash;
};
typedef struct fd_block_id fd_block_id_t;
FD_STATIC_ASSERT( sizeof(fd_block_id_t)==40UL, fd_block_id );

struct fd_block_info {
  fd_block_hash_t hash;
  fd_block_id_t   parent;
};
typedef struct fd_block_info fd_block_info_t;

typedef struct fd_vote fd_vote_t; /* forward decl */
typedef struct fd_cert fd_cert_t; /* forward decl */

struct fd_standstill {
  ulong       slot;
  fd_cert_t * certs;
  ulong       cert_cnt;
  fd_vote_t * votes;
  ulong       vote_cnt;
};
typedef struct fd_standstill fd_standstill_t;

FD_PROTOTYPES_BEGIN

/* Algorithm 2, line 1. Slot::first_slot_in_window */

FD_FN_CONST static inline ulong
fd_first_slot_in_window( ulong slot ) {
  return ( slot / FD_VOTOR_SLOTS_PER_WINDOW ) * FD_VOTOR_SLOTS_PER_WINDOW;
}

/* Algorithm 2, line 1. Slot::is_start_of_window */

FD_FN_CONST static inline int
fd_is_start_of_window( ulong slot ) {
  return ( slot % FD_VOTOR_SLOTS_PER_WINDOW )==0UL;
}

/* Definition 4. BlockId, the (Slot, BlockHash) tuple */

static inline fd_block_id_t
fd_block_id( ulong         slot,
             uchar const * hash ) {
  fd_block_id_t id = { .slot = slot };
  memcpy( &id.hash, hash, sizeof(fd_block_hash_t) );
  return id;
}

/* Definition 4. BlockId == */

FD_FN_PURE static inline int
fd_block_id_eq( fd_block_id_t const * a,
                fd_block_id_t const * b ) {
  return a->slot==b->slot && !memcmp( &a->hash, &b->hash, sizeof(fd_block_hash_t) );
}

/* Definition 4. BlockId <, ordered by (slot, hash) */

FD_FN_PURE static inline int
fd_block_id_lt( fd_block_id_t const * a,
                fd_block_id_t const * b ) {
  return a->slot<b->slot || ( a->slot==b->slot && 0>memcmp( &a->hash, &b->hash, sizeof(fd_block_hash_t) ) );
}

FD_PROTOTYPES_END

#endif
