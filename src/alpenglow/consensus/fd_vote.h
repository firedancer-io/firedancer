#ifndef HEADER_fd_src_alpenglow_consensus_fd_vote_h
#define HEADER_fd_src_alpenglow_consensus_fd_vote_h

/* fd_vote mirrors alpenglow/src/consensus/vote.rs: the five concrete vote
   kinds and the Vote sum type over them.

     NotarVote          - cast immediately after obtaining a valid block
     NotarFallbackVote  - cast to support an alternate block after voting elsewhere
     SkipVote           - cast on invalid block / timeout
     SkipFallbackVote   - cast to contribute to skip after notarizing
     FinalVote          - cast after seeing a notarization cert for our block

   Each vote signs a VotePayload (a tagged (kind, slot[, block_hash]) tuple).
   The discriminant ordering is wire-critical and matches the Rust enum:
     Notar=0, NotarFallback=1, Skip=2, SkipFallback=3, Final=4. */

#include "../fd_alpenglow_base.h"
#include "../crypto/fd_aggsig.h"

/* Vote / VotePayload discriminants (alpenglow/src/consensus/vote.rs). */

#define FD_VOTE_TYPE_NOTAR           (0U)
#define FD_VOTE_TYPE_FINAL           (1U)
#define FD_VOTE_TYPE_SKIP            (2U)
#define FD_VOTE_TYPE_NOTAR_FALLBACK  (3U)
#define FD_VOTE_TYPE_SKIP_FALLBACK   (4U)

/* The concrete vote structs.  signer is a ValidatorIndex (Rust u64). */

struct __attribute__((packed)) fd_notar_vote {
  ulong           slot;
  fd_hash_t       block_hash;
  fd_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct fd_notar_vote fd_notar_vote_t;

struct __attribute__((packed)) fd_notar_fallback_vote {
  ulong           slot;
  fd_hash_t       block_hash;
  fd_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct fd_notar_fallback_vote fd_notar_fallback_vote_t;

struct __attribute__((packed)) fd_skip_vote {
  ulong           slot;
  fd_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct fd_skip_vote fd_skip_vote_t;

struct __attribute__((packed)) fd_skip_fallback_vote {
  ulong           slot;
  fd_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct fd_skip_fallback_vote fd_skip_fallback_vote_t;

struct __attribute__((packed)) fd_final_vote {
  ulong           slot;
  fd_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct fd_final_vote fd_final_vote_t;

/* fd_ag_vote_t is the Vote sum type (network form). */
struct __attribute__((packed)) fd_ag_vote_t {
  uint discriminant;           /* FD_VOTE_TYPE_* */
  union {
    fd_notar_vote_t          notar;
    fd_notar_fallback_vote_t notar_fallback;
    fd_skip_vote_t           skip;
    fd_skip_fallback_vote_t  skip_fallback;
    fd_final_vote_t          final_;
  } inner;
};
typedef struct fd_ag_vote_t fd_ag_vote_t;

/* Maximum size of a VotePayload's bytes-to-sign: 4 (discriminant) + 8 (slot)
   + 32 (block_hash). */

#define FD_VOTE_PAYLOAD_MAX (44UL)

/* Maximum size of a serialized Vote ConsensusMessage:
   4 (ConsensusMessage tag) + VoteMessage = vote (<=FD_VOTE_PAYLOAD_MAX)
   + 192 (BLSSignature) + 2 (rank). */

#define FD_VOTE_SERIALIZED_MAX (4UL + FD_VOTE_PAYLOAD_MAX + FD_AGGSIG_SIG_SZ + 2UL)

FD_PROTOTYPES_BEGIN

/* fd_vote_payload_bytes_to_sign encodes the bytes a vote of the given kind
   signs into out (capacity >= FD_VOTE_PAYLOAD_MAX) and returns the byte count.
   Mirrors VotePayload::bytes_to_sign (wincode serialize of the enum):
     u32 LE discriminant, u64 LE slot, and for NOTAR/NOTAR_FALLBACK the 32-byte
     block_hash.  h must be non-NULL iff kind is NOTAR or NOTAR_FALLBACK.

   NB: the wincode enum-discriminant width is taken to be 4 bytes here; this is
   not yet byte-verified against the wincode crate and is only load-bearing for
   cross-client signature interop (not for internal consensus, which signs and
   verifies with the same encoding). */

ulong
fd_vote_payload_bytes_to_sign( uchar *           out,
                               uint              kind,
                               ulong             slot,
                               fd_hash_t const * h );

/* Concrete-vote constructors: sign the appropriate VotePayload with sk and
   populate *out. */

void fd_notar_vote_new         ( fd_notar_vote_t *          out, ulong slot, fd_hash_t const * h, fd_aggsig_sk_t const * sk, ushort signer );
void fd_notar_fallback_vote_new( fd_notar_fallback_vote_t * out, ulong slot, fd_hash_t const * h, fd_aggsig_sk_t const * sk, ushort signer );
void fd_skip_vote_new          ( fd_skip_vote_t *           out, ulong slot,                      fd_aggsig_sk_t const * sk, ushort signer );
void fd_skip_fallback_vote_new ( fd_skip_fallback_vote_t *  out, ulong slot,                      fd_aggsig_sk_t const * sk, ushort signer );
void fd_final_vote_new         ( fd_final_vote_t *          out, ulong slot,                      fd_aggsig_sk_t const * sk, ushort signer );

/* Tagged Vote constructors (Vote::new_*). */

void fd_vote_new_notar         ( fd_ag_vote_t * out, ulong slot, fd_hash_t const * h, fd_aggsig_sk_t const * sk, ushort signer );
void fd_vote_new_notar_fallback( fd_ag_vote_t * out, ulong slot, fd_hash_t const * h, fd_aggsig_sk_t const * sk, ushort signer );
void fd_vote_new_skip          ( fd_ag_vote_t * out, ulong slot,                      fd_aggsig_sk_t const * sk, ushort signer );
void fd_vote_new_skip_fallback ( fd_ag_vote_t * out, ulong slot,                      fd_aggsig_sk_t const * sk, ushort signer );
void fd_vote_new_final         ( fd_ag_vote_t * out, ulong slot,                      fd_aggsig_sk_t const * sk, ushort signer );

/* fd_vote_check_sig returns 1 iff the vote's signature is valid under pk
   (Vote::check_sig). */

int fd_vote_check_sig( fd_ag_vote_t const * v, fd_aggsig_pk_t const * pk );

/* fd_vote_serialize serializes vote v into out[0,out_max) and
   returns the number of bytes written, or 0 on failure (out too small).  The
   layout mirrors votor-messages consensus_message.rs / vote.rs:

     u32 LE  ConsensusMessage tag (0 = Vote)
     <Vote>  u32 LE Vote tag + payload (u64 LE slot [, 32B block_id]) -- the
             same bytes the vote signs (fd_vote_payload_bytes_to_sign)
     192 B   BLSSignature (uncompressed affine G2, copied verbatim, already signed)
     u16 LE  rank (the signer's epoch rank; taken from v's signer field)

   out_max should be >= FD_VOTE_SERIALIZED_MAX. */

ulong
fd_vote_serialize( fd_ag_vote_t const * v,
                   uchar *           out,
                   ulong             out_max );

/* Accessors (Vote::slot / signer / block_hash). */

FD_FN_PURE static inline ulong
fd_vote_slot( fd_ag_vote_t const * v ) {
  switch( v->discriminant ) {
  case FD_VOTE_TYPE_NOTAR:          return v->inner.notar.slot;
  case FD_VOTE_TYPE_NOTAR_FALLBACK: return v->inner.notar_fallback.slot;
  case FD_VOTE_TYPE_SKIP:           return v->inner.skip.slot;
  case FD_VOTE_TYPE_SKIP_FALLBACK:  return v->inner.skip_fallback.slot;
  default:                          return v->inner.final_.slot;
  }
}

FD_FN_PURE static inline ushort
fd_vote_signer( fd_ag_vote_t const * v ) {
  switch( v->discriminant ) {
  case FD_VOTE_TYPE_NOTAR:          return v->inner.notar.signer;
  case FD_VOTE_TYPE_NOTAR_FALLBACK: return v->inner.notar_fallback.signer;
  case FD_VOTE_TYPE_SKIP:           return v->inner.skip.signer;
  case FD_VOTE_TYPE_SKIP_FALLBACK:  return v->inner.skip_fallback.signer;
  default:                          return v->inner.final_.signer;
  }
}

/* fd_vote_set_signer stamps the signer (epoch rank) into the vote.  The signer
   is not covered by the signature (which signs only kind/slot/block_hash), so
   it may be set after the vote is constructed/signed -- the votor leaves it
   unset and the tile fills it in per the vote's slot epoch before broadcast. */

static inline void
fd_vote_set_signer( fd_ag_vote_t * v, ushort signer ) {
  switch( v->discriminant ) {
  case FD_VOTE_TYPE_NOTAR:          v->inner.notar.signer          = signer; break;
  case FD_VOTE_TYPE_NOTAR_FALLBACK: v->inner.notar_fallback.signer = signer; break;
  case FD_VOTE_TYPE_SKIP:           v->inner.skip.signer           = signer; break;
  case FD_VOTE_TYPE_SKIP_FALLBACK:  v->inner.skip_fallback.signer  = signer; break;
  default:                          v->inner.final_.signer         = signer; break;
  }
}

/* fd_vote_block_hash returns a pointer to the vote's block hash, or NULL for
   skip / skip-fallback / final votes (Vote::block_hash). */

FD_FN_PURE static inline fd_hash_t const *
fd_vote_block_hash( fd_ag_vote_t const * v ) {
  switch( v->discriminant ) {
  case FD_VOTE_TYPE_NOTAR:          return &v->inner.notar.block_hash;
  case FD_VOTE_TYPE_NOTAR_FALLBACK: return &v->inner.notar_fallback.block_hash;
  default:                          return NULL;
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_fd_vote_h */
