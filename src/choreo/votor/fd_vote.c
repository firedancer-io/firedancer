#include "fd_vote_serde.h"

static void
sign( fd_vote_t const * self,
      fd_bls_sign_fn    sign_fn,
      void *            sign_ctx,
      uchar const *     public_key,
      ushort            shred_version,
      fd_bls_sig_t *    sig ) {
  uchar buf[ FD_VOTE_SIGNING_SER_MAX ];
  ulong sz = fd_vote_signing_ser( self->kind, fd_vote_slot( self ), fd_vote_block_hash( self ), shred_version, buf );
  sign_fn( sign_ctx, sig, public_key, buf, sz );
}

fd_vote_t
fd_vote_construct_notar( fd_bls_sign_fn          sign_fn,
                         void *                  sign_ctx,
                         uchar const *           public_key,
                         ulong                   slot,
                         fd_block_hash_t const * hash,
                         ushort                  rank,
                         ushort                  shred_version ) {
  fd_vote_t vote;
  vote.kind                = FD_VOTE_KIND_NOTAR;
  vote.notar.slot          = slot;
  vote.notar.rank          = rank;
  vote.notar.shred_version = shred_version;
  memcpy( &vote.notar.block_hash, hash, sizeof(fd_block_hash_t) );
  sign( &vote, sign_fn, sign_ctx, public_key, shred_version, &vote.notar.sig );
  return vote;
}

fd_vote_t
fd_vote_construct_final( fd_bls_sign_fn sign_fn,
                         void *         sign_ctx,
                         uchar const *  public_key,
                         ulong          slot,
                         ushort         rank,
                         ushort         shred_version ) {
  fd_vote_t vote;
  vote.kind                = FD_VOTE_KIND_FINAL;
  vote.final.slot          = slot;
  vote.final.rank          = rank;
  vote.final.shred_version = shred_version;
  sign( &vote, sign_fn, sign_ctx, public_key, shred_version, &vote.final.sig );
  return vote;
}

fd_vote_t
fd_vote_construct_skip( fd_bls_sign_fn sign_fn,
                        void *         sign_ctx,
                        uchar const *  public_key,
                        ulong          slot,
                        ushort         rank,
                        ushort         shred_version ) {
  fd_vote_t vote;
  vote.kind               = FD_VOTE_KIND_SKIP;
  vote.skip.slot          = slot;
  vote.skip.rank          = rank;
  vote.skip.shred_version = shred_version;
  sign( &vote, sign_fn, sign_ctx, public_key, shred_version, &vote.skip.sig );
  return vote;
}

fd_vote_t
fd_vote_construct_notar_fallback( fd_bls_sign_fn          sign_fn,
                                  void *                  sign_ctx,
                                  uchar const *           public_key,
                                  ulong                   slot,
                                  fd_block_hash_t const * hash,
                                  ushort                  rank,
                                  ushort                  shred_version ) {
  fd_vote_t vote;
  vote.kind                         = FD_VOTE_KIND_NOTAR_FALLBACK;
  vote.notar_fallback.slot          = slot;
  vote.notar_fallback.rank          = rank;
  vote.notar_fallback.shred_version = shred_version;
  memcpy( &vote.notar_fallback.block_hash, hash, sizeof(fd_block_hash_t) );
  sign( &vote, sign_fn, sign_ctx, public_key, shred_version, &vote.notar_fallback.sig );
  return vote;
}

fd_vote_t
fd_vote_construct_skip_fallback( fd_bls_sign_fn sign_fn,
                                 void *         sign_ctx,
                                 uchar const *  public_key,
                                 ulong          slot,
                                 ushort         rank,
                                 ushort         shred_version ) {
  fd_vote_t vote;
  vote.kind                        = FD_VOTE_KIND_SKIP_FALLBACK;
  vote.skip_fallback.slot          = slot;
  vote.skip_fallback.rank          = rank;
  vote.skip_fallback.shred_version = shred_version;
  sign( &vote, sign_fn, sign_ctx, public_key, shred_version, &vote.skip_fallback.sig );
  return vote;
}
