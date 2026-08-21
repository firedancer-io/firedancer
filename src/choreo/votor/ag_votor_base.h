#ifndef HEADER_fd_src_choreo_votor_ag_votor_base_h
#define HEADER_fd_src_choreo_votor_ag_votor_base_h

#include "../../util/fd_util.h"

#define AG_SLOTS_PER_WINDOW (4UL)
#define AG_SLOTS_PER_EPOCH  (18000UL)

#define AG_VAT_MAX (2000UL) /* Validator Admission Ticket caps at 2000 */

#define AG_EQVOC_BLOCK_HASH_MAX    (7UL) /* Corollary 50 */
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

typedef uchar ag_block_hash_t[ 32 ]; /* double merkle root of a block */
typedef uchar ag_vote_key_t  [ 32 ]; /* pubkey of a validator's vote account */
typedef uchar ag_id_key_t    [ 32 ]; /* pubkey a validator is known by on the network */

/* A block hash is spelled ag_block_hash_t wherever the value is one: a
   struct field, a function parameter, or a local that owns its 32
   bytes.  C adjusts an array parameter to a pointer, so a parameter
   declared ag_block_hash_t const has type uchar const * inside the
   callee, and NULL stays a legal argument where the API documents one.

   A read-only reference to a block hash owned elsewhere keeps
   uchar const *: C cannot return an array type, and a local declared
   ag_block_hash_t would allocate 32 bytes rather than alias them.  An
   out parameter that fills 32 caller-owned bytes is still
   ag_block_hash_t.  Both spellings name the same type, so no cast or
   dereference is needed between them.

   The spelling is load-bearing across redeclarations: -Warray-parameter
   compares a definition against its prototype, so a declaration that
   drops back to uchar const * warns even though the types agree. */

struct ag_block_id {
  ulong           slot; /* slot for which the block was produced */
  ag_block_hash_t hash; /* double merkle root */
};
typedef struct ag_block_id ag_block_id_t;

/* ag_block_id_t is used as a raw-byte map key (MAP_KEY_HASH hashes
   sizeof(ag_block_id_t) bytes), so it must stay padding-free. */

FD_STATIC_ASSERT( sizeof(ag_block_id_t)==40UL, ag_block_id );

struct ag_block_info {
  ag_block_hash_t hash;   /* double merkle root of the block */
  ag_block_id_t   parent; /* the block this block extends */
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

/* Window arithmetic.  Slots are grouped into fixed-size leader windows
   of AG_SLOTS_PER_WINDOW slots.  Parent readiness is granted, and skip
   timeouts are armed, at window starts. */

FD_FN_CONST static inline ulong
ag_first_slot_in_window( ulong slot ) {
  return ( slot / AG_SLOTS_PER_WINDOW ) * AG_SLOTS_PER_WINDOW;
}

FD_FN_CONST static inline int
ag_is_start_of_window( ulong slot ) {
  return ( slot % AG_SLOTS_PER_WINDOW )==0UL;
}

/* ag_block_id constructs a block id.  ag_block_hash_t has no value
   semantics, so this stands in for a designated initializer. */

static inline ag_block_id_t
ag_block_id( ulong                 slot,
             ag_block_hash_t const hash ) {
  ag_block_id_t id = { .slot = slot };
  memcpy( id.hash, hash, sizeof(ag_block_hash_t) );
  return id;
}

FD_FN_PURE static inline int
ag_block_id_eq( ag_block_id_t const * a,
                ag_block_id_t const * b ) {
  return a->slot==b->slot && !memcmp( a->hash, b->hash, sizeof(ag_block_hash_t) );
}

FD_PROTOTYPES_END

#endif
