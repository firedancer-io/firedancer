#ifndef HEADER_fd_src_alpenglow_consensus_fd_cert_h
#define HEADER_fd_src_alpenglow_consensus_fd_cert_h

/* fd_cert mirrors alpenglow/src/consensus/cert.rs: the five certificate kinds
   and the Cert sum type.  A certificate aggregates a quorum of votes into a
   single BLS aggregate signature plus a signer bitmask.

     NotarCert         >=60% notar votes for one block       (block notarized)
     NotarFallbackCert >=60% notar + notar-fallback (mixed)  (weak notarization)
     SkipCert          >=60% skip + skip-fallback (mixed)    (slot skipped)
     FastFinalCert     >=80% notar votes for one block       (fast finalized)
     FinalCert         >=60% final votes                     (slow finalized)

   The Cert discriminant order is wire-critical and matches the Rust enum:
     Notar=0, NotarFallback=1, Skip=2, FastFinal=3, Final=4.
   Note index 3 (FastFinal) differs from the Vote enum's index 3 (SkipFallback).

   The mixed certs (NotarFallback, Skip) carry TWO optional aggregate
   signatures because notar vs notar-fallback (and skip vs skip-fallback) sign
   different VotePayload variants and so cannot share one aggregate. */

#include "fd_vote.h"
#include "fd_epoch_info.h"

#define FD_CERT_TYPE_NOTAR          (0U)
#define FD_CERT_TYPE_NOTAR_FALLBACK (1U)
#define FD_CERT_TYPE_SKIP           (2U)
#define FD_CERT_TYPE_FAST_FINAL     (3U)
#define FD_CERT_TYPE_FINAL          (4U)

/* CertError (cert.rs). */

#define FD_CERT_SUCCESS              ( 0)
#define FD_CERT_ERR_SLOT_MISMATCH    (-1)
#define FD_CERT_ERR_BLOCK_HASH_MISMATCH (-2)

struct fd_notar_cert {
  ulong       slot;
  fd_hash_t   block_hash;
  fd_aggsig_t agg_sig;
  ulong       stake;
};
typedef struct fd_notar_cert fd_notar_cert_t;

struct fd_notar_fallback_cert {
  ulong       slot;
  fd_hash_t   block_hash;
  int         has_agg_sig_notar;          fd_aggsig_t agg_sig_notar;
  int         has_agg_sig_notar_fallback; fd_aggsig_t agg_sig_notar_fallback;
  ulong       stake;
};
typedef struct fd_notar_fallback_cert fd_notar_fallback_cert_t;

struct fd_skip_cert {
  ulong       slot;
  int         has_agg_sig_skip;          fd_aggsig_t agg_sig_skip;
  int         has_agg_sig_skip_fallback; fd_aggsig_t agg_sig_skip_fallback;
  ulong       stake;
};
typedef struct fd_skip_cert fd_skip_cert_t;

struct fd_fast_final_cert {
  ulong       slot;
  fd_hash_t   block_hash;
  fd_aggsig_t agg_sig;
  ulong       stake;
};
typedef struct fd_fast_final_cert fd_fast_final_cert_t;

struct fd_final_cert {
  ulong       slot;
  fd_aggsig_t agg_sig;
  ulong       stake;
};
typedef struct fd_final_cert fd_final_cert_t;

struct fd_cert {
  uint discriminant; /* FD_CERT_TYPE_* */
  union {
    fd_notar_cert_t          notar;
    fd_notar_fallback_cert_t notar_fallback;
    fd_skip_cert_t           skip;
    fd_fast_final_cert_t     fast_final;
    fd_final_cert_t          final_;
  } inner;
};
typedef struct fd_cert fd_cert_t;

FD_PROTOTYPES_BEGIN

/* Per-cert constructors.  Each aggregates the provided concrete votes into the
   cert, looking up per-signer stake in validators[0,validator_cnt) and using
   validator_cnt as the aggregate-signature bitmask length.  Return
   FD_CERT_SUCCESS, or FD_CERT_ERR_* on slot/block-hash mismatch.  The mixed
   constructors accept two vote slices (either may be empty, but not both). */

int fd_notar_cert_try_new( fd_notar_cert_t * out,
                           fd_notar_vote_t const * votes, ulong vote_cnt,
                           fd_validator_info_t const * validators, ulong validator_cnt );

int fd_notar_fallback_cert_try_new( fd_notar_fallback_cert_t * out,
                                    fd_notar_vote_t const * notar_votes, ulong notar_cnt,
                                    fd_notar_fallback_vote_t const * nf_votes, ulong nf_cnt,
                                    fd_validator_info_t const * validators, ulong validator_cnt );

int fd_skip_cert_try_new( fd_skip_cert_t * out,
                          fd_skip_vote_t const * skip_votes, ulong skip_cnt,
                          fd_skip_fallback_vote_t const * sf_votes, ulong sf_cnt,
                          fd_validator_info_t const * validators, ulong validator_cnt );

int fd_fast_final_cert_try_new( fd_fast_final_cert_t * out,
                                fd_notar_vote_t const * votes, ulong vote_cnt,
                                fd_validator_info_t const * validators, ulong validator_cnt );

int fd_final_cert_try_new( fd_final_cert_t * out,
                           fd_final_vote_t const * votes, ulong vote_cnt,
                           fd_validator_info_t const * validators, ulong validator_cnt );

/* Tagged-cert dispatchers (Cert::*). */

FD_FN_PURE ulong fd_cert_slot ( fd_cert_t const * c );
FD_FN_PURE ulong fd_cert_stake( fd_cert_t const * c );

/* fd_cert_block_hash returns the cert's block hash, or NULL for skip/final. */

FD_FN_PURE fd_hash_t const * fd_cert_block_hash( fd_cert_t const * c );

/* fd_cert_is_signer returns 1 iff validator v signed cert c (counting the union
   of both aggregate sigs for mixed certs). */

FD_FN_PURE int fd_cert_is_signer( fd_cert_t const * c, ulong v );

/* fd_cert_check_threshold returns 1 iff c meets its stake threshold against
   epoch_info (60% for notar/notar-fallback/skip/final, 80% for fast-final),
   counting each validator once.  Mirrors Cert::check_threshold. */

int fd_cert_check_threshold( fd_cert_t const * c, fd_epoch_info_t const * epoch_info );

/* fd_cert_check_sig returns 1 iff c's aggregate signatures are valid against
   the per-index voting public keys in validators[0,validator_cnt).  Mirrors
   Cert::check_sig.  (STUB aggsig: structural check then accept.) */

int fd_cert_check_sig( fd_cert_t const * c, fd_validator_info_t const * validators, ulong validator_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_fd_cert_h */
