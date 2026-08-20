#ifndef HEADER_fd_src_choreo_votor_ag_cert_h
#define HEADER_fd_src_choreo_votor_ag_cert_h

#include "ag_vote.h"
#include "ag_epoch_info.h"

#define AG_CERT_TYPE_FINAL          (0)
#define AG_CERT_TYPE_FAST_FINAL     (1)
#define AG_CERT_TYPE_NOTAR          (2)
#define AG_CERT_TYPE_NOTAR_FALLBACK (3)
#define AG_CERT_TYPE_SKIP           (4)
#define AG_CERT_TYPE_GENESIS        (5)

struct ag_notar_cert {
  ulong        slot;
  fd_hash_t    block_hash;
  ag_bls_agg_t agg_sig;
  ulong        stake;
};
typedef struct ag_notar_cert ag_notar_cert_t;

struct ag_notar_fallback_cert {
  ulong        slot;
  fd_hash_t    block_hash;
  ag_bls_agg_t agg_sig_notar;
  ag_bls_agg_t agg_sig_notar_fallback;
  ulong        stake;

};
typedef struct ag_notar_fallback_cert ag_notar_fallback_cert_t;

struct ag_skip_cert {
  ulong        slot;
  ag_bls_agg_t agg_sig_skip;
  ag_bls_agg_t agg_sig_skip_fallback;
  ulong        stake;
};
typedef struct ag_skip_cert ag_skip_cert_t;

struct ag_fast_final_cert {
  ulong        slot;
  fd_hash_t    block_hash;
  ag_bls_agg_t agg_sig;
  ulong        stake;
};
typedef struct ag_fast_final_cert ag_fast_final_cert_t;

struct ag_final_cert {
  ulong        slot;
  ag_bls_agg_t agg_sig;
  ulong        stake;
};
typedef struct ag_final_cert ag_final_cert_t;

struct ag_cert {
  uint kind;
  union {
    ag_notar_cert_t          notar;
    ag_notar_fallback_cert_t notar_fallback;
    ag_skip_cert_t           skip;
    ag_fast_final_cert_t     fast_final;
    ag_final_cert_t          final;
  } inner;
};
typedef struct ag_cert ag_cert_t;

FD_PROTOTYPES_BEGIN

/* Construct certs by aggregating votes. */

ag_notar_cert_t
ag_notar_cert_construct( ag_notar_vote_t const * notar_votes,
                         ulong                   notar_vote_cnt,
                         ag_epoch_info_t const * epoch_info );

ag_notar_fallback_cert_t
ag_notar_fallback_cert_construct( ag_notar_vote_t const *          notar_votes,
                                  ulong                            notar_vote_cnt,
                                  ag_notar_fallback_vote_t const * notar_fallback_votes,
                                  ulong                            notar_fallback_vote_cnt,
                                  ag_epoch_info_t const *          epoch_info );

ag_skip_cert_t
ag_skip_cert_construct( ag_skip_vote_t const *          skip_votes,
                        ulong                           skip_vote_cnt,
                        ag_skip_fallback_vote_t const * skip_fallback_votes,
                        ulong                           skip_fallback_vote_cnt,
                        ag_epoch_info_t const *         epoch_info );

ag_fast_final_cert_t
ag_fast_final_cert_construct( ag_notar_vote_t const * notar_votes,
                              ulong                   notar_vote_cnt,
                              ag_epoch_info_t const * epoch_info );

ag_final_cert_t
ag_final_cert_construct( ag_final_vote_t const * final_votes,
                         ulong                   final_vote_cnt,
                         ag_epoch_info_t const * epoch_info );

/* Verify certs from the network. */

int
ag_notar_cert_verify( ag_notar_cert_t const * notar_cert,
                      ag_epoch_info_t const * epoch_info,
                      ushort                  shred_version );

int
ag_fast_final_cert_verify( ag_fast_final_cert_t const * fast_final_cert,
                           ag_epoch_info_t const *      epoch_info,
                           ushort                       shred_version );

int
ag_final_cert_verify( ag_final_cert_t const * final_cert,
                      ag_epoch_info_t const * epoch_info,
                      ushort                  shred_version );

int
ag_notar_fallback_cert_verify( ag_notar_fallback_cert_t const * notar_fallback_cert,
                               ag_epoch_info_t const *          epoch_info,
                               ushort                           shred_version );

int
ag_skip_cert_verify( ag_skip_cert_t const *  skip_cert,
                     ag_epoch_info_t const * epoch_info,
                     ushort                  shred_version );

/* Misc helpers. */

FD_FN_PURE static inline ulong
ag_cert_slot( ag_cert_t const * cert ) {
  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:          return cert->inner.notar.slot;
  case AG_CERT_TYPE_NOTAR_FALLBACK: return cert->inner.notar_fallback.slot;
  case AG_CERT_TYPE_SKIP:           return cert->inner.skip.slot;
  case AG_CERT_TYPE_FAST_FINAL:     return cert->inner.fast_final.slot;
  case AG_CERT_TYPE_FINAL:          return cert->inner.final.slot;
  default:                          __builtin_unreachable();
  }
}

FD_FN_PURE static inline fd_hash_t const *
ag_cert_block_hash( ag_cert_t const * cert ) {
  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:          return &cert->inner.notar.block_hash;
  case AG_CERT_TYPE_NOTAR_FALLBACK: return &cert->inner.notar_fallback.block_hash;
  case AG_CERT_TYPE_FAST_FINAL:     return &cert->inner.fast_final.block_hash;
  default:                          return NULL; /* skip and final carry no block hash */
  }
}

FD_FN_PURE static inline char const *
ag_cert_str( ag_cert_t const * cert ) {
  switch( cert->kind ) {
  case AG_CERT_TYPE_FINAL:          return "Final";
  case AG_CERT_TYPE_FAST_FINAL:     return "FastFinal";
  case AG_CERT_TYPE_NOTAR:          return "Notar";
  case AG_CERT_TYPE_NOTAR_FALLBACK: return "NotarFallback";
  case AG_CERT_TYPE_SKIP:           return "Skip";
  case AG_CERT_TYPE_GENESIS:        return "Genesis";
  default:                          __builtin_unreachable();
  }
}

FD_PROTOTYPES_END

#endif
