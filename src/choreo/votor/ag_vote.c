#include "ag_vote_serde.h"

static void
sign( ag_vote_t const * self,
      ag_bls_sign_fn    sign_fn,
      void *            sign_ctx,
      ushort            shred_version,
      ag_bls_sig_t *    sig ) {
  uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
  ulong sz = ag_vote_signing_ser( self->kind, ag_vote_slot( self ), ag_vote_block_hash( self ), shred_version, buf );
  sign_fn( sign_ctx, sig, buf, sz );
}

ag_vote_t
ag_vote_construct_notar( ag_bls_sign_fn        sign_fn,
                         void *                sign_ctx,
                         ulong                 slot,
                         ag_block_hash_t const hash,
                         ushort                rank,
                         ushort                shred_version ) {
  ag_vote_t vote;
  vote.kind                = AG_VOTE_KIND_NOTAR;
  vote.notar.slot          = slot;
  vote.notar.rank          = rank;
  vote.notar.shred_version = shred_version;
  memcpy( vote.notar.block_hash, hash, sizeof(ag_block_hash_t) );
  sign( &vote, sign_fn, sign_ctx, shred_version, &vote.notar.sig );
  return vote;
}

ag_vote_t
ag_vote_construct_final( ag_bls_sign_fn sign_fn,
                         void *         sign_ctx,
                         ulong          slot,
                         ushort         rank,
                         ushort         shred_version ) {
  ag_vote_t vote;
  vote.kind                = AG_VOTE_KIND_FINAL;
  vote.final.slot          = slot;
  vote.final.rank          = rank;
  vote.final.shred_version = shred_version;
  sign( &vote, sign_fn, sign_ctx, shred_version, &vote.final.sig );
  return vote;
}

ag_vote_t
ag_vote_construct_skip( ag_bls_sign_fn sign_fn,
                        void *         sign_ctx,
                        ulong          slot,
                        ushort         rank,
                        ushort         shred_version ) {
  ag_vote_t vote;
  vote.kind               = AG_VOTE_KIND_SKIP;
  vote.skip.slot          = slot;
  vote.skip.rank          = rank;
  vote.skip.shred_version = shred_version;
  sign( &vote, sign_fn, sign_ctx, shred_version, &vote.skip.sig );
  return vote;
}

ag_vote_t
ag_vote_construct_notar_fallback( ag_bls_sign_fn        sign_fn,
                                  void *                sign_ctx,
                                  ulong                 slot,
                                  ag_block_hash_t const hash,
                                  ushort                rank,
                                  ushort                shred_version ) {
  ag_vote_t vote;
  vote.kind                         = AG_VOTE_KIND_NOTAR_FALLBACK;
  vote.notar_fallback.slot          = slot;
  vote.notar_fallback.rank          = rank;
  vote.notar_fallback.shred_version = shred_version;
  memcpy( vote.notar_fallback.block_hash, hash, sizeof(ag_block_hash_t) );
  sign( &vote, sign_fn, sign_ctx, shred_version, &vote.notar_fallback.sig );
  return vote;
}

ag_vote_t
ag_vote_construct_skip_fallback( ag_bls_sign_fn sign_fn,
                                 void *         sign_ctx,
                                 ulong          slot,
                                 ushort         rank,
                                 ushort         shred_version ) {
  ag_vote_t vote;
  vote.kind                        = AG_VOTE_KIND_SKIP_FALLBACK;
  vote.skip_fallback.slot          = slot;
  vote.skip_fallback.rank          = rank;
  vote.skip_fallback.shred_version = shred_version;
  sign( &vote, sign_fn, sign_ctx, shred_version, &vote.skip_fallback.sig );
  return vote;
}
