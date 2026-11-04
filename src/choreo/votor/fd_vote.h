#ifndef HEADER_fd_src_choreo_votor_fd_vote_h
#define HEADER_fd_src_choreo_votor_fd_vote_h

#include "fd_votor_base.h"
#include "../../ballet/bls/fd_bls.h"

#define FD_VOTE_KIND_NOTAR           (0U)
#define FD_VOTE_KIND_FINAL           (1U)
#define FD_VOTE_KIND_SKIP            (2U)
#define FD_VOTE_KIND_NOTAR_FALLBACK  (3U)
#define FD_VOTE_KIND_SKIP_FALLBACK   (4U)

/* public_key is the canonical compressed BLS key selector.  payload is
   the exact consensus preimage; the signer must not include public_key
   in the signed bytes. */

typedef void
(* fd_bls_sign_fn)( void *         ctx,
                    fd_bls_sig_t * sig,
                    uchar const *  public_key,
                    uchar const *  payload,
                    ulong          payload_sz );
struct fd_vote_notar {
  ulong           slot;
  fd_block_hash_t block_hash;
  fd_bls_sig_t    sig;
  ushort          rank;
  ushort          shred_version;
};
typedef struct fd_vote_notar fd_vote_notar_t;

struct fd_vote_final {
  ulong        slot;
  fd_bls_sig_t sig;
  ushort       rank;
  ushort       shred_version;
};
typedef struct fd_vote_final fd_vote_final_t;

struct fd_vote_skip {
  ulong        slot;
  fd_bls_sig_t sig;
  ushort       rank;
  ushort       shred_version;
};
typedef struct fd_vote_skip fd_vote_skip_t;

struct fd_vote_notar_fallback {
  ulong           slot;
  fd_block_hash_t block_hash;
  fd_bls_sig_t    sig;
  ushort          rank;
  ushort          shred_version;
};
typedef struct fd_vote_notar_fallback fd_vote_notar_fallback_t;

struct fd_vote_skip_fallback {
  ulong        slot;
  fd_bls_sig_t sig;
  ushort       rank;
  ushort       shred_version;
};
typedef struct fd_vote_skip_fallback fd_vote_skip_fallback_t;

struct fd_vote {
  uint   kind;
  union {
    fd_vote_notar_t          notar;
    fd_vote_final_t          final;
    fd_vote_skip_t           skip;
    fd_vote_notar_fallback_t notar_fallback;
    fd_vote_skip_fallback_t  skip_fallback;
  };
};
typedef struct fd_vote fd_vote_t;

FD_PROTOTYPES_BEGIN

/* Definition 11. Vote::slot */

FD_FN_PURE static inline ulong
fd_vote_slot( fd_vote_t const * self ) {
  switch( self->kind ) {
  case FD_VOTE_KIND_NOTAR:          return self->notar.slot;
  case FD_VOTE_KIND_FINAL:          return self->final.slot;
  case FD_VOTE_KIND_SKIP:           return self->skip.slot;
  case FD_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.slot;
  case FD_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.slot;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Definition 11. Vote::block_hash */

FD_FN_PURE static inline fd_block_hash_t const *
fd_vote_block_hash( fd_vote_t const * self ) {
  switch( self->kind ) {
  case FD_VOTE_KIND_NOTAR:          return &self->notar.block_hash;
  case FD_VOTE_KIND_FINAL:          return NULL;
  case FD_VOTE_KIND_SKIP:           return NULL;
  case FD_VOTE_KIND_NOTAR_FALLBACK: return &self->notar_fallback.block_hash;
  case FD_VOTE_KIND_SKIP_FALLBACK:  return NULL;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Definition 11. SignedVote::sig */

FD_FN_PURE static inline fd_bls_sig_t const *
fd_vote_sig( fd_vote_t const * self ) {
  switch( self->kind ) {
  case FD_VOTE_KIND_NOTAR:          return &self->notar.sig;
  case FD_VOTE_KIND_FINAL:          return &self->final.sig;
  case FD_VOTE_KIND_SKIP:           return &self->skip.sig;
  case FD_VOTE_KIND_NOTAR_FALLBACK: return &self->notar_fallback.sig;
  case FD_VOTE_KIND_SKIP_FALLBACK:  return &self->skip_fallback.sig;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Definition 11. Vote::signer; assigned by the tile from the peer, not carried on the wire */

FD_FN_PURE static inline ushort
fd_vote_rank( fd_vote_t const * self ) {
  switch( self->kind ) {
  case FD_VOTE_KIND_NOTAR:          return self->notar.rank;
  case FD_VOTE_KIND_FINAL:          return self->final.rank;
  case FD_VOTE_KIND_SKIP:           return self->skip.rank;
  case FD_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.rank;
  case FD_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.rank;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

FD_FN_PURE static inline ushort
fd_vote_shred_version( fd_vote_t const * self ) {
  switch( self->kind ) {
  case FD_VOTE_KIND_NOTAR:          return self->notar.shred_version;
  case FD_VOTE_KIND_FINAL:          return self->final.shred_version;
  case FD_VOTE_KIND_SKIP:           return self->skip.shred_version;
  case FD_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.shred_version;
  case FD_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.shred_version;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Definition 11. Vote::new_notar */

fd_vote_t
fd_vote_construct_notar( fd_bls_sign_fn          sign_fn,
                         void *                  sign_ctx,
                         uchar const *           public_key,
                         ulong                   slot,
                         fd_block_hash_t const * hash,
                         ushort                  rank,
                         ushort                  shred_version );

/* Definition 11. Vote::new_final */

fd_vote_t
fd_vote_construct_final( fd_bls_sign_fn sign_fn,
                         void *         sign_ctx,
                         uchar const *  public_key,
                         ulong          slot,
                         ushort         rank,
                         ushort         shred_version );

/* Definition 11. Vote::new_skip */

fd_vote_t
fd_vote_construct_skip( fd_bls_sign_fn sign_fn,
                        void *         sign_ctx,
                        uchar const *  public_key,
                        ulong          slot,
                        ushort         rank,
                        ushort         shred_version );

/* Definition 11. Vote::new_notar_fallback */

fd_vote_t
fd_vote_construct_notar_fallback( fd_bls_sign_fn          sign_fn,
                                  void *                  sign_ctx,
                                  uchar const *           public_key,
                                  ulong                   slot,
                                  fd_block_hash_t const * hash,
                                  ushort                  rank,
                                  ushort                  shred_version );

/* Definition 11. Vote::new_skip_fallback */

fd_vote_t
fd_vote_construct_skip_fallback( fd_bls_sign_fn sign_fn,
                                 void *         sign_ctx,
                                 uchar const *  public_key,
                                 ulong          slot,
                                 ushort         rank,
                                 ushort         shred_version );

FD_PROTOTYPES_END

#endif
