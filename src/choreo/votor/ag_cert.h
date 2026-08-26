#ifndef HEADER_fd_src_choreo_votor_ag_cert_h
#define HEADER_fd_src_choreo_votor_ag_cert_h

#include "ag_vote.h"
#include "ag_epoch_info.h"

#define AG_CERT_KIND_FINAL          (0)
#define AG_CERT_KIND_FAST_FINAL     (1)
#define AG_CERT_KIND_NOTAR          (2)
#define AG_CERT_KIND_NOTAR_FALLBACK (3)
#define AG_CERT_KIND_SKIP           (4)
#define AG_CERT_KIND_GENESIS        (5)

struct ag_cert_notar {
  ulong           slot;
  ag_block_hash_t block_hash;
  ag_bls_agg_t    agg_sig;
  ulong           stake;
};
typedef struct ag_cert_notar ag_cert_notar_t;

struct ag_cert_notar_fallback {
  ulong           slot;
  ag_block_hash_t block_hash;
  ag_bls_agg_t    agg_sig_notar;
  ag_bls_agg_t    agg_sig_notar_fallback;
  ulong           stake;

};
typedef struct ag_cert_notar_fallback ag_cert_notar_fallback_t;

struct ag_cert_skip {
  ulong           slot;
  ag_bls_agg_t    agg_sig_skip;
  ag_bls_agg_t    agg_sig_skip_fallback;
  ulong           stake;
};
typedef struct ag_cert_skip ag_cert_skip_t;

struct ag_cert_fast_final {
  ulong           slot;
  ag_block_hash_t block_hash;
  ag_bls_agg_t    agg_sig;
  ulong           stake;
};
typedef struct ag_cert_fast_final ag_cert_fast_final_t;

struct ag_cert_final {
  ulong           slot;
  ag_bls_agg_t    agg_sig;
  ulong           stake;
};
typedef struct ag_cert_final ag_cert_final_t;

struct ag_cert {
  uint kind;
  union {
    ag_cert_notar_t          notar;
    ag_cert_notar_fallback_t notar_fallback;
    ag_cert_skip_t           skip;
    ag_cert_fast_final_t     fast_final;
    ag_cert_final_t          final;
  };
};
typedef struct ag_cert ag_cert_t;

FD_PROTOTYPES_BEGIN

ag_cert_t
ag_cert_construct_notar( ag_vote_notar_t const * votes,
                         ulong                   vote_cnt,
                         ag_epoch_info_t const * epoch_info );

ag_cert_t
ag_cert_construct_fast_final( ag_vote_notar_t const * votes,
                              ulong                   vote_cnt,
                              ag_epoch_info_t const * epoch_info );

ag_cert_t
ag_cert_construct_final( ag_vote_final_t const * votes,
                         ulong                   vote_cnt,
                         ag_epoch_info_t const * epoch_info );

ag_cert_t
ag_cert_construct_notar_fallback( ag_vote_notar_t const *          votes,
                                  ulong                            vote_cnt,
                                  ag_vote_notar_fallback_t const * fallback_votes,
                                  ulong                            fallback_vote_cnt,
                                  ag_epoch_info_t const *          epoch_info );

ag_cert_t
ag_cert_construct_skip( ag_vote_skip_t const *          votes,
                        ulong                           vote_cnt,
                        ag_vote_skip_fallback_t const * fallback_votes,
                        ulong                           fallback_vote_cnt,
                        ag_epoch_info_t const *         epoch_info );

int
ag_cert_verify( ag_cert_t const *       self,
                ag_epoch_info_t const * epoch_info,
                ushort                  shred_version );

FD_FN_PURE static inline ulong
ag_cert_slot( ag_cert_t const * self ) {
  switch( self->kind ) {
  case AG_CERT_KIND_NOTAR:          return self->notar.slot;
  case AG_CERT_KIND_NOTAR_FALLBACK: return self->notar_fallback.slot;
  case AG_CERT_KIND_SKIP:           return self->skip.slot;
  case AG_CERT_KIND_FAST_FINAL:     return self->fast_final.slot;
  case AG_CERT_KIND_FINAL:          return self->final.slot;
  default:                          __builtin_unreachable();
  }
}

FD_FN_PURE static inline uchar const *
ag_cert_block_hash( ag_cert_t const * self ) {
  switch( self->kind ) {
  case AG_CERT_KIND_NOTAR:          return self->notar.block_hash;
  case AG_CERT_KIND_NOTAR_FALLBACK: return self->notar_fallback.block_hash;
  case AG_CERT_KIND_FAST_FINAL:     return self->fast_final.block_hash;
  default:                          return NULL; /* skip and final carry no block hash */
  }
}

FD_FN_PURE static inline char const *
ag_cert_str( ag_cert_t const * self ) {
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:          return "Final";
  case AG_CERT_KIND_FAST_FINAL:     return "FastFinal";
  case AG_CERT_KIND_NOTAR:          return "Notar";
  case AG_CERT_KIND_NOTAR_FALLBACK: return "NotarFallback";
  case AG_CERT_KIND_SKIP:           return "Skip";
  case AG_CERT_KIND_GENESIS:        return "Genesis";
  default:                          __builtin_unreachable();
  }
}

FD_PROTOTYPES_END

#endif
