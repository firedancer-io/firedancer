#ifndef HEADER_fd_src_alpenglow_crypto_fd_aggsig_h
#define HEADER_fd_src_alpenglow_crypto_fd_aggsig_h

/* fd_aggsig mirrors alpenglow/src/crypto/aggsig.rs: an aggregate signature
   scheme built on BLS12-381 G1 (min_sig).  Individual signatures are 96-byte
   uncompressed G1 points; public keys are compressed G2 (96 bytes); secret
   keys are 32 bytes.  An AggregateSignature is a single aggregate point plus a
   bitmask of signer validator indices.

   STATUS: STUB.  The Firedancer BLS module (src/ballet/bls/fd_bls12_381)
   currently exposes only group ops, pairing and proof-of-possession — it lacks
   keygen, sign (hash-to-curve), single verify and fast_aggregate_verify.  Until
   those land, this module implements the full WIRE FORMAT and signer-bitmask
   logic faithfully, but the cryptographic sign/verify operations are stubbed:
     - fd_aggsig_sign_bytes      produces a deterministic non-cryptographic sig
     - fd_aggsig_*_verify_bytes  perform the structural checks (bitmask length
                                 etc.) and then accept (return 1)
   This is sufficient to exercise all of the consensus logic (vote/cert
   accumulation, thresholds, finalization) which is independent of the
   underlying signature scheme.  Real BLS is the final implementation step.

   The signer bitmask is a fixed 2048-bit fd_set (matching MAX_SIGNERS=2048 in
   the reference), exposed here so cert/slot_state can embed it inline. */

#include "../fd_alpenglow_base.h"

/* signer_set is a fixed 2048-element index set used as the signer bitmask of an
   aggregate signature (one bit per validator index).  fd_set is a header-only
   library; including it here makes signer_set_t and the signer_set_* ops
   available to every translation unit that includes fd_aggsig.h. */

#define SET_NAME signer_set
#define SET_MAX  2048
#include "../../util/tmpl/fd_set.c"

#define FD_AGGSIG_SECKEY_SZ   (32UL) /* BLS secret key                       */
#define FD_AGGSIG_PUBKEY_SZ   (96UL)  /* uncompressed G1 public key (min_sig)   */
#define FD_AGGSIG_SIG_SZ      (192UL) /* uncompressed G2 signature (min_sig)  */
#define FD_AGGSIG_MAX_SIGNERS (2048UL)

struct fd_aggsig_sk { uchar v[ FD_AGGSIG_SECKEY_SZ ]; };
typedef struct fd_aggsig_sk fd_aggsig_sk_t;

struct fd_aggsig_pk { uchar v[ FD_AGGSIG_PUBKEY_SZ ]; };
typedef struct fd_aggsig_pk fd_aggsig_pk_t;

/* fd_aggsig_sig_t is a single IndividualSignature (alpenglow IndividualSignature). */

struct fd_aggsig_sig { uchar v[ FD_AGGSIG_SIG_SZ ]; };
typedef struct fd_aggsig_sig fd_aggsig_sig_t;

/* fd_aggsig_t mirrors the Rust AggregateSignature: an aggregate point plus a
   signer bitmask of nbits bits.  The bitmask is stored as a fixed
   signer_set_word_cnt array (256 bytes); nbits records the logical length (the
   epoch's validator count) for wire (de)serialization. */

struct fd_aggsig {
  uchar        sig[ FD_AGGSIG_SIG_SZ ];           /* aggregate point        */
  ulong        nbits;                             /* logical bitmask length */
  signer_set_t bitmask[ signer_set_word_cnt ];    /* 2048-bit signer set    */
};
typedef struct fd_aggsig fd_aggsig_t;

/* Serialized size of an fd_aggsig with the given nbits, matching the wincode
   encoding of AggregateSignature: 96 sig bytes + 8 (num_bits) + 8 (num_words)
   + 8*num_words. */

#define FD_AGGSIG_WORDS_FOR_BITS(nbits) (((nbits)+63UL)/64UL)
#define FD_AGGSIG_SERIALIZED_SZ(nbits)  (FD_AGGSIG_SIG_SZ + 8UL + 8UL + 8UL*FD_AGGSIG_WORDS_FOR_BITS(nbits))
/* Maximum serialized size (nbits == MAX_SIGNERS). */
#define FD_AGGSIG_SERIALIZED_MAX        (FD_AGGSIG_SERIALIZED_SZ(FD_AGGSIG_MAX_SIGNERS))

FD_PROTOTYPES_BEGIN

/* fd_aggsig_sk_to_pk derives the public key for sk into pk.
   STUB: deterministic, not a real BLS sk->pk map. */

void
fd_aggsig_sk_to_pk( fd_aggsig_pk_t *       pk,
                    fd_aggsig_sk_t const * sk );

/* fd_aggsig_sign_bytes signs msg[0,msg_sz) with sk, writing the individual
   signature into sig.  Mirrors SecretKey::sign_bytes.
   STUB: deterministic, not a real BLS signature. */

void
fd_aggsig_sign_bytes( fd_aggsig_sig_t *      sig,
                      fd_aggsig_sk_t const * sk,
                      uchar const *          msg,
                      ulong                  msg_sz );

/* fd_aggsig_individual_verify_bytes returns 1 iff sig is a valid signature of
   msg under pk.  Mirrors IndividualSignature::verify_bytes.
   STUB: always returns 1. */

int
fd_aggsig_individual_verify_bytes( fd_aggsig_sig_t const * sig,
                                   fd_aggsig_pk_t const *  pk,
                                   uchar const *           msg,
                                   ulong                   msg_sz );

/* fd_aggsig_new aggregates cnt individual signatures sigs[i] for signer
   indices indices[i] into agg, with a bitmask of nbits bits.  Mirrors
   AggregateSignature::new.  Requirements (FD_TEST'd): cnt>0, every index <
   nbits, no duplicate index, nbits <= MAX_SIGNERS. */

void
fd_aggsig_new( fd_aggsig_t *           agg,
               fd_aggsig_sig_t const * sigs,
               ulong const *           indices,
               ulong                   cnt,
               ulong                   nbits );

/* fd_aggsig_init initializes agg to an empty aggregate of nbits bits (no
   signers, zeroed point).  Used to incrementally add signers via
   fd_aggsig_add. */

void
fd_aggsig_init( fd_aggsig_t * agg,
                ulong         nbits );

/* fd_aggsig_add adds one signer's signature to agg.  Requires signer_idx <
   agg->nbits and the bit not already set (FD_TEST'd, mirroring the Rust
   duplicate-signer assert). */

void
fd_aggsig_add( fd_aggsig_t *           agg,
               ulong                   signer_idx,
               fd_aggsig_sig_t const * sig );

/* fd_aggsig_verify_bytes returns 1 iff agg verifies against msg under the
   per-index public keys pks[0,pk_cnt).  Mirrors AggregateSignature::verify_bytes
   (bitmask length must equal pk_cnt).  STUB: structural check then accept. */

int
fd_aggsig_verify_bytes( fd_aggsig_t const *    agg,
                        uchar const *          msg,
                        ulong                  msg_sz,
                        fd_aggsig_pk_t const * pks,
                        ulong                  pk_cnt );

/* fd_aggsig_verify_mixed_bytes returns 1 iff the SINGLE aggregate signature in
   agg_base->sig verifies as the distinct-message aggregate of two disjoint
   signer sets over two messages: agg_base->bitmask signed msg_base and
   agg_fb->bitmask signed msg_fb (both indexed into pks[0,pk_cnt)).  Used for
   wire NotarizeFallback / Skip certs, whose base3 bitmap encodes two signer
   sets sharing one aggregate signature.  agg_fb->sig is never read -- the one
   wire signature always lives in agg_base->sig.  Either signer set (but not
   both) may be empty, in which case this degenerates to a plain aggregate
   verify of the non-empty set's message. */

int
fd_aggsig_verify_mixed_bytes( fd_aggsig_t const *    agg_base,
                              uchar const *          msg_base,
                              ulong                  msg_base_sz,
                              fd_aggsig_t const *    agg_fb,
                              uchar const *          msg_fb,
                              ulong                  msg_fb_sz,
                              fd_aggsig_pk_t const * pks,
                              ulong                  pk_cnt );

/* fd_aggsig_is_signer returns 1 iff validator_idx is a signer of agg. */

FD_FN_PURE static inline int
fd_aggsig_is_signer( fd_aggsig_t const * agg,
                     ulong               validator_idx ) {
  if( FD_UNLIKELY( validator_idx>=agg->nbits ) ) return 0;
  return signer_set_test( agg->bitmask, validator_idx );
}

/* fd_aggsig_signer_cnt returns the number of signers in agg. */

FD_FN_PURE static inline ulong
fd_aggsig_signer_cnt( fd_aggsig_t const * agg ) {
  return signer_set_cnt( agg->bitmask );
}

/* fd_aggsig_serialize writes the wincode encoding of agg to out (capacity
   out_max) and returns the number of bytes written, or 0 on failure (out too
   small).  Mirrors the SchemaWrite impl for AggregateSignature. */

ulong
fd_aggsig_serialize( fd_aggsig_t const * agg,
                     uchar *             out,
                     ulong               out_max );

/* fd_aggsig_deserialize parses a wincode-encoded aggregate signature from
   in[0,in_sz) into agg.  Returns the number of bytes consumed, or 0 on
   failure (truncated / bitmask too long / nbits inconsistent).  Mirrors the
   SchemaRead impl for AggregateSignature. */

ulong
fd_aggsig_deserialize( fd_aggsig_t * agg,
                       uchar const * in,
                       ulong         in_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_crypto_fd_aggsig_h */
