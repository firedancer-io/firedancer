#ifndef HEADER_fd_src_alpenglow_consensus_ag_cert_h
#define HEADER_fd_src_alpenglow_consensus_ag_cert_h

#include "ag_vote.h"
#include "ag_epoch_info.h"

#define AG_CERT_TYPE_FINAL          (0U)
#define AG_CERT_TYPE_FAST_FINAL     (1U)
#define AG_CERT_TYPE_NOTAR          (2U)
#define AG_CERT_TYPE_NOTAR_FALLBACK (3U)
#define AG_CERT_TYPE_SKIP           (4U)
#define AG_CERT_TYPE_GENESIS        (5U)

/* CertError (cert.rs). */

#define AG_CERT_SUCCESS              ( 0)
#define AG_CERT_ERR_SLOT_MISMATCH    (-1)
#define AG_CERT_ERR_BLOCK_HASH_MISMATCH (-2)

#define AG_CERT_DE_SUCCESS         ( 0)
#define AG_CERT_DE_ERR_TRUNCATED   (-1)
#define AG_CERT_DE_ERR_MALFORMED   (-2)
#define AG_CERT_DE_ERR_UNSUPPORTED (-3)

struct ag_notar_cert {
  ulong       slot;
  fd_hash_t   block_hash;
  ag_aggsig_t agg_sig;
  ulong       stake;
};
typedef struct ag_notar_cert ag_notar_cert_t;

struct ag_notar_fallback_cert {
  ulong       slot;
  fd_hash_t   block_hash;
  ag_aggsig_t agg_sig_notar;
  ag_aggsig_t agg_sig_notar_fallback;
  ulong       stake;

};
typedef struct ag_notar_fallback_cert ag_notar_fallback_cert_t;

struct ag_skip_cert {
  ulong       slot;
  ag_aggsig_t agg_sig_skip;
  ag_aggsig_t agg_sig_skip_fallback;
  ulong       stake;
};
typedef struct ag_skip_cert ag_skip_cert_t;

struct ag_fast_final_cert {
  ulong       slot;
  fd_hash_t   block_hash;
  ag_aggsig_t agg_sig;
  ulong       stake;
};
typedef struct ag_fast_final_cert ag_fast_final_cert_t;

struct ag_final_cert {
  ulong       slot;
  ag_aggsig_t agg_sig;
  ulong       stake;
};
typedef struct ag_final_cert ag_final_cert_t;

struct ag_cert {
  uint kind;
  union {
    ag_notar_cert_t          notar;
    ag_notar_fallback_cert_t notar_fallback;
    ag_skip_cert_t           skip;
    ag_fast_final_cert_t     fast_final;
    ag_final_cert_t          final_;
  } inner;
};
typedef struct ag_cert ag_cert_t;

FD_PROTOTYPES_BEGIN

int ag_notar_cert_try_new( ag_notar_cert_t *           out,
                           ag_notar_vote_t const *     votes,
                           ulong                       vote_cnt,
                           ag_validator_info_t const * validators,
                           ulong                       validator_cnt );

int ag_notar_fallback_cert_try_new( ag_notar_fallback_cert_t *       out,
                                    ag_notar_vote_t const *          notar_votes,
                                    ulong                            notar_cnt,
                                    ag_notar_fallback_vote_t const * nf_votes,
                                    ulong                            nf_cnt,
                                    ag_validator_info_t const *      validators,
                                    ulong                            validator_cnt );

int ag_skip_cert_try_new( ag_skip_cert_t *                out,
                          ag_skip_vote_t const *          skip_votes,
                          ulong                           skip_cnt,
                          ag_skip_fallback_vote_t const * sf_votes,
                          ulong                           sf_cnt,
                          ag_validator_info_t const *     validators,
                          ulong                           validator_cnt );

int ag_fast_final_cert_try_new( ag_fast_final_cert_t *      out,
                                ag_notar_vote_t const *     votes,
                                ulong                       vote_cnt,
                                ag_validator_info_t const * validators,
                                ulong                       validator_cnt );

int ag_final_cert_try_new( ag_final_cert_t *           out,
                           ag_final_vote_t const *     votes,
                           ulong                       vote_cnt,
                           ag_validator_info_t const * validators,
                           ulong                       validator_cnt );

/* from-agg constructors: build a cert directly from Pool's running
   aggregate(s) (ag_slot_state stores per-kind aggregates, not individual
   votes); stake is recomputed from the signer bitmask(s) like the
   vote-array constructors.  For the dual-aggregate certs a NULL aggregate
   means no votes of that kind (initialized empty, at least one required). */

void
ag_notar_cert_from_agg( ag_notar_cert_t *           out,
                        ulong                       slot,
                        fd_hash_t const *           block_hash,
                        ag_aggsig_t const *         agg,
                        ag_validator_info_t const * validators,
                        ulong                       validator_cnt );

void
ag_fast_final_cert_from_agg( ag_fast_final_cert_t *      out,
                             ulong                       slot,
                             fd_hash_t const *           block_hash,
                             ag_aggsig_t const *         agg,
                             ag_validator_info_t const * validators,
                             ulong                       validator_cnt );

void
ag_final_cert_from_agg( ag_final_cert_t *           out,
                        ulong                       slot,
                        ag_aggsig_t const *         agg,
                        ag_validator_info_t const * validators,
                        ulong                       validator_cnt );

void
ag_notar_fallback_cert_from_aggs( ag_notar_fallback_cert_t *  out,
                                  ulong                       slot,
                                  fd_hash_t const *           block_hash,
                                  ag_aggsig_t const *         notar_agg,
                                  ag_aggsig_t const *         nf_agg,
                                  ag_validator_info_t const * validators,
                                  ulong                       validator_cnt );

void
ag_skip_cert_from_aggs( ag_skip_cert_t *            out,
                        ulong                       slot,
                        ag_aggsig_t const *         skip_agg,
                        ag_aggsig_t const *         sf_agg,
                        ag_validator_info_t const * validators,
                        ulong                       validator_cnt );

FD_FN_PURE ulong ag_cert_slot ( ag_cert_t const * self );
FD_FN_PURE ulong ag_cert_stake( ag_cert_t const * self );

FD_FN_PURE fd_hash_t const * ag_cert_block_hash( ag_cert_t const * self );

FD_FN_PURE int
ag_cert_is_signer( ag_cert_t const * self,
                   ulong             v );

int
ag_cert_check_threshold( ag_cert_t const *       self,
                         ag_epoch_info_t const * epoch_info );

int
ag_cert_check_sig( ag_cert_t const *       self,
                   ushort                  shred_version,
                   ag_epoch_info_t const * epoch_info );

int
ag_cert_de( ag_cert_t *   out,
            uchar const * in,
            ulong         in_sz );

/* ag_block_final_cert_de deserializes a finalization cert as carried in
   a block footer (agave entry/src/block_component.rs):

     slot (8) | block_id (32) | final_aggregate | has_notar (1) | [notar_aggregate]

   where an aggregate is: compressed G2 sig (96) | bitmap len (u16) | bitmap.

     notar aggregate present (slow finalization) -> out[0]=Final, out[1]=Notar
     notar aggregate absent  (fast finalization) -> out[0]=FastFinal

   Unlike the network cert encoding, the footer aggregates carry a
   COMPRESSED signature. It is caller responsibility to call
   ag_block_final_cert_decompress.  Trailing bytes after the cert are
   ignored.  Returns AG_CERT_DE_SUCCESS and sets *out_cert_cnt to 1 or
   2, or returns a negative AG_CERT_DE_ERR_*; out is valid only on
   success. */

int ag_block_final_cert_de( ag_cert_t out[ 2 ], ulong * out_cert_cnt, uchar const * in, ulong in_sz );

/* ag_block_final_cert_decompress decompresses in place the compressed G2
   aggregate signatures of certs[0,cert_cnt) as produced by
   ag_block_final_cert_de.  Returns AG_CERT_DE_SUCCESS, or
   AG_CERT_DE_ERR_MALFORMED if a signature is not a valid compressed G2
   point (certs are then partially decompressed and must be discarded). */

int ag_block_final_cert_decompress( ag_cert_t * certs, ulong cert_cnt );

static inline const char * ag_cert_type_to_string( uint type ) {
  switch( type ) {
    case AG_CERT_TYPE_FINAL:          return "Final";
    case AG_CERT_TYPE_FAST_FINAL:     return "FastFinal";
    case AG_CERT_TYPE_NOTAR:          return "Notar";
    case AG_CERT_TYPE_NOTAR_FALLBACK: return "NotarFallback";
    case AG_CERT_TYPE_SKIP:           return "Skip";
    case AG_CERT_TYPE_GENESIS:        return "Genesis";
    default: return "Unknown";
  }
}

FD_PROTOTYPES_END

#endif
