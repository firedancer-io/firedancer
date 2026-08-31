#include "ag_vote.h"

ulong
ag_vote_payload_bytes_to_sign( uchar *               out,
                               uint                  kind,
                               ulong                 slot,
                               ag_block_hash_t const hash,
                               ushort                shred_version ) {
  ulong off = 0UL;
  out[off] = (uchar)( kind+1U ); off += 1UL;
  FD_STORE( ulong, out+off, slot ); off += 8UL;
  if( kind==AG_VOTE_KIND_NOTAR || kind==AG_VOTE_KIND_NOTAR_FALLBACK ) {
    FD_TEST( hash );
    fd_memcpy( out+off, hash, sizeof(ag_block_hash_t) ); off += sizeof(ag_block_hash_t);
  }
  FD_STORE( ushort, out+off, shred_version ); off += 2UL;
  return off;
}

static void
sign( ag_bls_sig_t          sig,
      uint                  kind,
      ulong                 slot,
      ag_block_hash_t const hash,
      ag_bls_sec_t const    sec,
      ushort                shred_version ) {
  uchar buf[ AG_VOTE_PAYLOAD_MAX ];
  ulong sz = ag_vote_payload_bytes_to_sign( buf, kind, slot, hash, shred_version );
  ag_bls_sec_sign( sec, sig, buf, sz );
}

static int
verify( ag_bls_sig_t const    sig,
        uint                  kind,
        ulong                 slot,
        ag_block_hash_t const hash,
        ag_bls_pub_t const *  pub,
        ushort                shred_version ) {
  uchar buf[ AG_VOTE_PAYLOAD_MAX ];
  ulong sz = ag_vote_payload_bytes_to_sign( buf, kind, slot, hash, shred_version );
  return ag_bls_sig_verify( sig, pub, buf, sz );
}

ag_vote_t
ag_vote_construct_notar( ulong                 slot,
                         ag_block_hash_t const hash,
                         ag_bls_sec_t const    sec,
                         ushort                rank,
                         ushort                shred_version ) {
  ag_vote_t vote;
  vote.kind        = AG_VOTE_KIND_NOTAR;
  vote.notar.slot  = slot;
  vote.notar.rank = rank;
  memcpy( vote.notar.block_hash, hash, sizeof(ag_block_hash_t) );
  sign( vote.notar.sig, AG_VOTE_KIND_NOTAR, slot, hash, sec, shred_version );
  return vote;
}

static int
verify_notar( ag_vote_t const *    self,
              ag_bls_pub_t const * pub,
              ushort               shred_version ) {
  return verify( self->notar.sig, AG_VOTE_KIND_NOTAR, self->notar.slot, self->notar.block_hash, pub, shred_version );
}

ag_vote_t
ag_vote_construct_notar_fallback( ulong                 slot,
                                  ag_block_hash_t const hash,
                                  ag_bls_sec_t const    sec,
                                  ushort                rank,
                                  ushort                shred_version ) {
  ag_vote_t vote;
  vote.kind                  = AG_VOTE_KIND_NOTAR_FALLBACK;
  vote.notar_fallback.slot   = slot;
  vote.notar_fallback.rank = rank;
  memcpy( vote.notar_fallback.block_hash, hash, sizeof(ag_block_hash_t) );
  sign( vote.notar_fallback.sig, AG_VOTE_KIND_NOTAR_FALLBACK, slot, hash, sec, shred_version );
  return vote;
}

static int
verify_notar_fallback( ag_vote_t const *    self,
                       ag_bls_pub_t const * pub,
                       ushort               shred_version ) {
  return verify( self->notar_fallback.sig, AG_VOTE_KIND_NOTAR_FALLBACK, self->notar_fallback.slot, self->notar_fallback.block_hash, pub, shred_version );
}

ag_vote_t
ag_vote_construct_skip( ulong              slot,
                        ag_bls_sec_t const sec,
                        ushort             rank,
                        ushort             shred_version ) {
  ag_vote_t vote;
  vote.kind        = AG_VOTE_KIND_SKIP;
  vote.skip.slot   = slot;
  vote.skip.rank = rank;
  sign( vote.skip.sig, AG_VOTE_KIND_SKIP, slot, NULL, sec, shred_version );
  return vote;
}

static int
verify_skip( ag_vote_t const *    self,
             ag_bls_pub_t const * pub,
             ushort               shred_version ) {
  return verify( self->skip.sig, AG_VOTE_KIND_SKIP, self->skip.slot, NULL, pub, shred_version );
}

ag_vote_t
ag_vote_construct_skip_fallback( ulong              slot,
                                 ag_bls_sec_t const sec,
                                 ushort             rank,
                                 ushort             shred_version ) {
  ag_vote_t vote;
  vote.kind                 = AG_VOTE_KIND_SKIP_FALLBACK;
  vote.skip_fallback.slot   = slot;
  vote.skip_fallback.rank = rank;
  sign( vote.skip_fallback.sig, AG_VOTE_KIND_SKIP_FALLBACK, slot, NULL, sec, shred_version );
  return vote;
}

static int
verify_skip_fallback( ag_vote_t const *    self,
                      ag_bls_pub_t const * pub,
                      ushort               shred_version ) {
  return verify( self->skip_fallback.sig, AG_VOTE_KIND_SKIP_FALLBACK, self->skip_fallback.slot, NULL, pub, shred_version );
}

ag_vote_t
ag_vote_construct_final( ulong              slot,
                         ag_bls_sec_t const sec,
                         ushort             rank,
                         ushort             shred_version ) {
  ag_vote_t vote;
  vote.kind         = AG_VOTE_KIND_FINAL;
  vote.final.slot   = slot;
  vote.final.rank = rank;
  sign( vote.final.sig, AG_VOTE_KIND_FINAL, slot, NULL, sec, shred_version );
  return vote;
}

static int
verify_final( ag_vote_t const *    self,
              ag_bls_pub_t const * pub,
              ushort               shred_version ) {
  return verify( self->final.sig, AG_VOTE_KIND_FINAL, self->final.slot, NULL, pub, shred_version );
}

int
ag_vote_verify( ag_vote_t const *    self,
                ag_bls_pub_t const * pub,
                ushort               shred_version ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return verify_notar         ( self, pub, shred_version );
  case AG_VOTE_KIND_NOTAR_FALLBACK: return verify_notar_fallback( self, pub, shred_version );
  case AG_VOTE_KIND_SKIP:           return verify_skip          ( self, pub, shred_version );
  case AG_VOTE_KIND_SKIP_FALLBACK:  return verify_skip_fallback ( self, pub, shred_version );
  case AG_VOTE_KIND_FINAL:          return verify_final         ( self, pub, shred_version );
  default:                          __builtin_unreachable();
  }
}
