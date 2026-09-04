#include "ag_vote_serde.h"

static void
sign( ag_vote_t const *  self,
      ag_bls_sig_t       sig,
      ag_bls_sec_t const sec,
      ushort             shred_version ) {
  uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
  ulong sz = ag_vote_signing_ser( self, shred_version, buf );
  ag_bls_sec_sign( sec, sig, buf, sz );
}

static int
verify( ag_vote_t const *  self,
        ag_bls_sig_t const sig,
        ag_bls_pub_t const pub,
        ushort             shred_version ) {
  uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
  ulong sz = ag_vote_signing_ser( self, shred_version, buf );
  return ag_bls_sig_verify( sig, pub, buf, sz );
}

static int
verify_notar( ag_vote_t const *  self,
              ag_bls_pub_t const pub,
              ushort             shred_version ) {
  return verify( self, self->notar.sig, pub, shred_version );
}

static int
verify_final( ag_vote_t const *  self,
              ag_bls_pub_t const pub,
              ushort             shred_version ) {
  return verify( self, self->final.sig, pub, shred_version );
}

static int
verify_skip( ag_vote_t const *  self,
             ag_bls_pub_t const pub,
             ushort             shred_version ) {
  return verify( self, self->skip.sig, pub, shred_version );
}

static int
verify_notar_fallback( ag_vote_t const *  self,
                       ag_bls_pub_t const pub,
                       ushort             shred_version ) {
  return verify( self, self->notar_fallback.sig, pub, shred_version );
}

static int
verify_skip_fallback( ag_vote_t const *  self,
                      ag_bls_pub_t const pub,
                      ushort             shred_version ) {
  return verify( self, self->skip_fallback.sig, pub, shred_version );
}

ag_vote_t
ag_vote_construct_notar( ulong                 slot,
                         ag_block_hash_t const hash,
                         ag_bls_sec_t const    sec,
                         ushort                rank,
                         ushort                shred_version ) {
  ag_vote_t vote;
  vote.kind       = AG_VOTE_KIND_NOTAR;
  vote.notar.slot = slot;
  vote.notar.rank = rank;
  memcpy( vote.notar.block_hash, hash, sizeof(ag_block_hash_t) );
  sign( &vote, vote.notar.sig, sec, shred_version );
  return vote;
}

ag_vote_t
ag_vote_construct_final( ulong              slot,
                         ag_bls_sec_t const sec,
                         ushort             rank,
                         ushort             shred_version ) {
  ag_vote_t vote;
  vote.kind       = AG_VOTE_KIND_FINAL;
  vote.final.slot = slot;
  vote.final.rank = rank;
  sign( &vote, vote.final.sig, sec, shred_version );
  return vote;
}

ag_vote_t
ag_vote_construct_skip( ulong              slot,
                        ag_bls_sec_t const sec,
                        ushort             rank,
                        ushort             shred_version ) {
  ag_vote_t vote;
  vote.kind      = AG_VOTE_KIND_SKIP;
  vote.skip.slot = slot;
  vote.skip.rank = rank;
  sign( &vote, vote.skip.sig, sec, shred_version );
  return vote;
}

ag_vote_t
ag_vote_construct_notar_fallback( ulong                 slot,
                                  ag_block_hash_t const hash,
                                  ag_bls_sec_t const    sec,
                                  ushort                rank,
                                  ushort                shred_version ) {
  ag_vote_t vote;
  vote.kind                = AG_VOTE_KIND_NOTAR_FALLBACK;
  vote.notar_fallback.slot = slot;
  vote.notar_fallback.rank = rank;
  memcpy( vote.notar_fallback.block_hash, hash, sizeof(ag_block_hash_t) );
  sign( &vote, vote.notar_fallback.sig, sec, shred_version );
  return vote;
}

ag_vote_t
ag_vote_construct_skip_fallback( ulong              slot,
                                 ag_bls_sec_t const sec,
                                 ushort             rank,
                                 ushort             shred_version ) {
  ag_vote_t vote;
  vote.kind               = AG_VOTE_KIND_SKIP_FALLBACK;
  vote.skip_fallback.slot = slot;
  vote.skip_fallback.rank = rank;
  sign( &vote, vote.skip_fallback.sig, sec, shred_version );
  return vote;
}

int
ag_vote_verify( ag_vote_t const *  self,
                ag_bls_pub_t const pub,
                ushort             shred_version ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return verify_notar         ( self, pub, shred_version );
  case AG_VOTE_KIND_FINAL:          return verify_final         ( self, pub, shred_version );
  case AG_VOTE_KIND_SKIP:           return verify_skip          ( self, pub, shred_version );
  case AG_VOTE_KIND_NOTAR_FALLBACK: return verify_notar_fallback( self, pub, shred_version );
  case AG_VOTE_KIND_SKIP_FALLBACK:  return verify_skip_fallback ( self, pub, shred_version );
  default:                          __builtin_unreachable();
  }
}
