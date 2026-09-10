#ifndef HEADER_fd_src_choreo_votor_ag_vote_h
#define HEADER_fd_src_choreo_votor_ag_vote_h

#include "ag_votor_base.h"
#include "../../ballet/bls/fd_bls.h"

#define AG_VOTE_KIND_NOTAR           (0U)
#define AG_VOTE_KIND_FINAL           (1U)
#define AG_VOTE_KIND_SKIP            (2U)
#define AG_VOTE_KIND_NOTAR_FALLBACK  (3U)
#define AG_VOTE_KIND_SKIP_FALLBACK   (4U)

#define AG_VOTE_CSTR_MAX (256UL)

typedef void
(* fd_bls_sign_fn)( void *         ctx,
                    fd_bls_sig_t * sig,
                    uchar const *  payload,
                    ulong          payload_sz );
struct ag_vote_notar {
  ulong           slot;
  ag_block_hash_t block_hash;
  fd_bls_sig_t    sig;
  ushort          rank;
  ushort          shred_version;
};
typedef struct ag_vote_notar ag_vote_notar_t;

struct ag_vote_final {
  ulong        slot;
  fd_bls_sig_t sig;
  ushort       rank;
  ushort       shred_version;
};
typedef struct ag_vote_final ag_vote_final_t;

struct ag_vote_skip {
  ulong        slot;
  fd_bls_sig_t sig;
  ushort       rank;
  ushort       shred_version;
};
typedef struct ag_vote_skip ag_vote_skip_t;

struct ag_vote_notar_fallback {
  ulong           slot;
  ag_block_hash_t block_hash;
  fd_bls_sig_t    sig;
  ushort          rank;
  ushort          shred_version;
};
typedef struct ag_vote_notar_fallback ag_vote_notar_fallback_t;

struct ag_vote_skip_fallback {
  ulong        slot;
  fd_bls_sig_t sig;
  ushort       rank;
  ushort       shred_version;
};
typedef struct ag_vote_skip_fallback ag_vote_skip_fallback_t;

struct ag_vote {
  uint   kind;
  ushort shred_version;
  union {
    ag_vote_notar_t          notar;
    ag_vote_final_t          final;
    ag_vote_skip_t           skip;
    ag_vote_notar_fallback_t notar_fallback;
    ag_vote_skip_fallback_t  skip_fallback;
  };
};
typedef struct ag_vote ag_vote_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline ulong
ag_vote_slot( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return self->notar.slot;
  case AG_VOTE_KIND_SKIP:           return self->skip.slot;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.slot;
  case AG_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.slot;
  default:                          return self->final.slot;
  }
}

FD_FN_PURE static inline fd_bls_sig_t const *
ag_vote_sig( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return &self->notar.sig;
  case AG_VOTE_KIND_SKIP:           return &self->skip.sig;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return &self->notar_fallback.sig;
  case AG_VOTE_KIND_SKIP_FALLBACK:  return &self->skip_fallback.sig;
  default:                          return &self->final.sig;
  }
}

FD_FN_PURE static inline ushort
ag_vote_rank( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return self->notar.rank;
  case AG_VOTE_KIND_SKIP:           return self->skip.rank;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.rank;
  case AG_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.rank;
  default:                          return self->final.rank;
  }
}

FD_FN_PURE static inline ushort
ag_vote_shred_version( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return self->notar.shred_version;
  case AG_VOTE_KIND_SKIP:           return self->skip.shred_version;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.shred_version;
  case AG_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.shred_version;
  default:                          return self->final.shred_version;
  }
}

FD_FN_PURE static inline uchar const *
ag_vote_block_hash( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return self->notar.block_hash;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.block_hash;
  default:                          return NULL;
  }
}

static inline void
ag_vote_set_rank( ag_vote_t * self,
                  ushort      rank ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          self->notar.rank          = rank; break;
  case AG_VOTE_KIND_SKIP:           self->skip.rank           = rank; break;
  case AG_VOTE_KIND_NOTAR_FALLBACK: self->notar_fallback.rank = rank; break;
  case AG_VOTE_KIND_SKIP_FALLBACK:  self->skip_fallback.rank  = rank; break;
  default:                          self->final.rank          = rank; break;
  }
}

ag_vote_t
ag_vote_construct_notar( fd_bls_sign_fn        sign_fn,
                         void *                sign_ctx,
                         ulong                 slot,
                         ag_block_hash_t const hash,
                         ushort                rank,
                         ushort                shred_version );

ag_vote_t
ag_vote_construct_final( fd_bls_sign_fn sign_fn,
                         void *         sign_ctx,
                         ulong          slot,
                         ushort         rank,
                         ushort         shred_version );

ag_vote_t
ag_vote_construct_skip( fd_bls_sign_fn sign_fn,
                        void *         sign_ctx,
                        ulong          slot,
                        ushort         rank,
                        ushort         shred_version );

ag_vote_t
ag_vote_construct_notar_fallback( fd_bls_sign_fn        sign_fn,
                                  void *                sign_ctx,
                                  ulong                 slot,
                                  ag_block_hash_t const hash,
                                  ushort                rank,
                                  ushort                shred_version );

ag_vote_t
ag_vote_construct_skip_fallback( fd_bls_sign_fn sign_fn,
                                 void *         sign_ctx,
                                 ulong          slot,
                                 ushort         rank,
                                 ushort         shred_version );

char *
ag_vote_to_cstr( ag_vote_t const * self,
                 char              cstr[ static AG_VOTE_CSTR_MAX ] );

FD_PROTOTYPES_END

#endif
