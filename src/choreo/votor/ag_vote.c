#include "ag_vote_serde.h"

static void
sign( ag_vote_t const *    self,
      ag_bls_sec_t const * sec,
      ushort               shred_version,
      ag_bls_sig_t *       sig ) {
  uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
  ulong sz = ag_vote_signing_ser( self->kind, ag_vote_slot( self ), ag_vote_block_hash( self ), shred_version, buf );
  ag_bls_sec_sign( sec, buf, sz, sig );
}

static int
verify( ag_vote_t const *    self,
        ag_bls_pub_t const * pub,
        ag_bls_sig_t const * sig ) {
  uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
  ulong sz = ag_vote_signing_ser( self->kind, ag_vote_slot( self ), ag_vote_block_hash( self ), ag_vote_shred_version( self ), buf );
  return ag_bls_sig_verify( sig, pub, buf, sz );
}

static int
verify_notar( ag_vote_t const *    self,
              ag_bls_pub_t const * pub ) {
  return verify( self, pub, &self->notar.sig );
}

static int
verify_final( ag_vote_t const *    self,
              ag_bls_pub_t const * pub ) {
  return verify( self, pub, &self->final.sig );
}

static int
verify_skip( ag_vote_t const *    self,
             ag_bls_pub_t const * pub ) {
  return verify( self, pub, &self->skip.sig );
}

static int
verify_notar_fallback( ag_vote_t const *    self,
                       ag_bls_pub_t const * pub ) {
  return verify( self, pub, &self->notar_fallback.sig );
}

static int
verify_skip_fallback( ag_vote_t const *    self,
                      ag_bls_pub_t const * pub ) {
  return verify( self, pub, &self->skip_fallback.sig );
}

ag_vote_t
ag_vote_construct_notar( ag_bls_sec_t const *  sec,
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
  sign( &vote, sec, shred_version, &vote.notar.sig );
  return vote;
}

ag_vote_t
ag_vote_construct_final( ag_bls_sec_t const * sec,
                         ulong                slot,
                         ushort               rank,
                         ushort               shred_version ) {
  ag_vote_t vote;
  vote.kind                = AG_VOTE_KIND_FINAL;
  vote.final.slot          = slot;
  vote.final.rank          = rank;
  vote.final.shred_version = shred_version;
  sign( &vote, sec, shred_version, &vote.final.sig );
  return vote;
}

ag_vote_t
ag_vote_construct_skip( ag_bls_sec_t const * sec,
                        ulong                slot,
                        ushort               rank,
                        ushort               shred_version ) {
  ag_vote_t vote;
  vote.kind               = AG_VOTE_KIND_SKIP;
  vote.skip.slot          = slot;
  vote.skip.rank          = rank;
  vote.skip.shred_version = shred_version;
  sign( &vote, sec, shred_version, &vote.skip.sig );
  return vote;
}

ag_vote_t
ag_vote_construct_notar_fallback( ag_bls_sec_t const *  sec,
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
  sign( &vote, sec, shred_version, &vote.notar_fallback.sig );
  return vote;
}

ag_vote_t
ag_vote_construct_skip_fallback( ag_bls_sec_t const * sec,
                                 ulong                slot,
                                 ushort               rank,
                                 ushort               shred_version ) {
  ag_vote_t vote;
  vote.kind                        = AG_VOTE_KIND_SKIP_FALLBACK;
  vote.skip_fallback.slot          = slot;
  vote.skip_fallback.rank          = rank;
  vote.skip_fallback.shred_version = shred_version;
  sign( &vote, sec, shred_version, &vote.skip_fallback.sig );
  return vote;
}

int
ag_vote_verify( ag_vote_t const *    self,
                ag_bls_pub_t const * pub ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return verify_notar         ( self, pub );
  case AG_VOTE_KIND_FINAL:          return verify_final         ( self, pub );
  case AG_VOTE_KIND_SKIP:           return verify_skip          ( self, pub );
  case AG_VOTE_KIND_NOTAR_FALLBACK: return verify_notar_fallback( self, pub );
  case AG_VOTE_KIND_SKIP_FALLBACK:  return verify_skip_fallback ( self, pub );
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}
