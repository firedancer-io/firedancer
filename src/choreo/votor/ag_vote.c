#include "ag_vote.h"

ulong
ag_vote_payload_bytes_to_sign( uchar *               out,
                               uint                  kind,
                               ulong                 slot,
                               ag_block_hash_t const h,
                               ushort                shred_version ) {
  ulong o = 0UL;
  out[o] = (uchar)( kind+1U ); o += 1UL;
  FD_STORE( ulong, out+o, slot ); o += 8UL;
  if( kind==AG_VOTE_KIND_NOTAR || kind==AG_VOTE_KIND_NOTAR_FALLBACK ) {
    FD_TEST( h );
    fd_memcpy( out+o, h, sizeof(ag_block_hash_t) ); o += sizeof(ag_block_hash_t);
  }
  FD_STORE( ushort, out+o, shred_version ); o += 2UL;
  return o;
}

static void
sign_payload( ag_bls_sig_t          sig,
              uint                  kind,
              ulong                 slot,
              ag_block_hash_t const h,
              ag_bls_sec_t const    sk,
              ushort                shred_version ) {
  uchar buf[ AG_VOTE_PAYLOAD_MAX ];
  ulong sz = ag_vote_payload_bytes_to_sign( buf, kind, slot, h, shred_version );
  ag_bls_sec_sign( sk, sig, buf, sz );
}

static int
verify_payload( ag_bls_sig_t const    sig,
                uint                  kind,
                ulong                 slot,
                ag_block_hash_t const h,
                ag_bls_pub_t const    pk,
                ushort                shred_version ) {
  uchar buf[ AG_VOTE_PAYLOAD_MAX ];
  ulong sz = ag_vote_payload_bytes_to_sign( buf, kind, slot, h, shred_version );
  return ag_bls_sig_verify( sig, pk, buf, sz );
}

void
ag_notar_vote_new( ag_notar_vote_t *     out,
                   ulong                 slot,
                   ag_block_hash_t const h,
                   ag_bls_sec_t const    sk,
                   ushort                signer,
                   ushort                shred_version ) {
  out->slot = slot; out->signer = signer;
  memcpy( out->block_hash, h, sizeof(ag_block_hash_t) );
  sign_payload( out->sig, AG_VOTE_KIND_NOTAR, slot, h, sk, shred_version );
}

int
ag_notar_vote_check_sig( ag_notar_vote_t const * self,
                         ag_bls_pub_t const      pk,
                         ushort                  shred_version ) {
  return verify_payload( self->sig, AG_VOTE_KIND_NOTAR, self->slot, self->block_hash, pk, shred_version );
}

void
ag_notar_fallback_vote_new( ag_notar_fallback_vote_t * out,
                            ulong                      slot,
                            ag_block_hash_t const      h,
                            ag_bls_sec_t const         sk,
                            ushort                     signer,
                            ushort                     shred_version ) {
  out->slot = slot; out->signer = signer;
  memcpy( out->block_hash, h, sizeof(ag_block_hash_t) );
  sign_payload( out->sig, AG_VOTE_KIND_NOTAR_FALLBACK, slot, h, sk, shred_version );
}

int
ag_notar_fallback_vote_check_sig( ag_notar_fallback_vote_t const * self,
                                  ag_bls_pub_t const               pk,
                                  ushort                           shred_version ) {
  return verify_payload( self->sig, AG_VOTE_KIND_NOTAR_FALLBACK, self->slot, self->block_hash, pk, shred_version );
}

void
ag_skip_vote_new( ag_skip_vote_t *   out,
                  ulong              slot,
                  ag_bls_sec_t const sk,
                  ushort             signer,
                  ushort             shred_version ) {
  out->slot = slot; out->signer = signer;
  sign_payload( out->sig, AG_VOTE_KIND_SKIP, slot, NULL, sk, shred_version );
}

int
ag_skip_vote_check_sig( ag_skip_vote_t const * self,
                        ag_bls_pub_t const     pk,
                        ushort                 shred_version ) {
  return verify_payload( self->sig, AG_VOTE_KIND_SKIP, self->slot, NULL, pk, shred_version );
}

void
ag_skip_fallback_vote_new( ag_skip_fallback_vote_t * out,
                           ulong                     slot,
                           ag_bls_sec_t const        sk,
                           ushort                    signer,
                           ushort                    shred_version ) {
  out->slot = slot; out->signer = signer;
  sign_payload( out->sig, AG_VOTE_KIND_SKIP_FALLBACK, slot, NULL, sk, shred_version );
}

int
ag_skip_fallback_vote_check_sig( ag_skip_fallback_vote_t const * self,
                                 ag_bls_pub_t const              pk,
                                 ushort                          shred_version ) {
  return verify_payload( self->sig, AG_VOTE_KIND_SKIP_FALLBACK, self->slot, NULL, pk, shred_version );
}

void
ag_final_vote_new( ag_final_vote_t *  out,
                   ulong              slot,
                   ag_bls_sec_t const sk,
                   ushort             signer,
                   ushort             shred_version ) {
  out->slot = slot; out->signer = signer;
  sign_payload( out->sig, AG_VOTE_KIND_FINAL, slot, NULL, sk, shred_version );
}

int
ag_final_vote_check_sig( ag_final_vote_t const * self,
                         ag_bls_pub_t const      pk,
                         ushort                  shred_version ) {
  return verify_payload( self->sig, AG_VOTE_KIND_FINAL, self->slot, NULL, pk, shred_version );
}

void
ag_vote_new_notar( ag_vote_t *           out,
                   ulong                 slot,
                   ag_block_hash_t const h,
                   ag_bls_sec_t const    sk,
                   ushort                signer,
                   ushort                shred_version ) {
  out->kind = AG_VOTE_KIND_NOTAR;
  ag_notar_vote_new( &out->inner.notar, slot, h, sk, signer, shred_version );
}

void
ag_vote_new_notar_fallback( ag_vote_t *           out,
                            ulong                 slot,
                            ag_block_hash_t const h,
                            ag_bls_sec_t const    sk,
                            ushort                signer,
                            ushort                shred_version ) {
  out->kind = AG_VOTE_KIND_NOTAR_FALLBACK;
  ag_notar_fallback_vote_new( &out->inner.notar_fallback, slot, h, sk, signer, shred_version );
}

void
ag_vote_new_skip( ag_vote_t *        out,
                  ulong              slot,
                  ag_bls_sec_t const sk,
                  ushort             signer,
                  ushort             shred_version ) {
  out->kind = AG_VOTE_KIND_SKIP;
  ag_skip_vote_new( &out->inner.skip, slot, sk, signer, shred_version );
}

void
ag_vote_new_skip_fallback( ag_vote_t *        out,
                           ulong              slot,
                           ag_bls_sec_t const sk,
                           ushort             signer,
                           ushort             shred_version ) {
  out->kind = AG_VOTE_KIND_SKIP_FALLBACK;
  ag_skip_fallback_vote_new( &out->inner.skip_fallback, slot, sk, signer, shred_version );
}

void
ag_vote_new_final( ag_vote_t *        out,
                   ulong              slot,
                   ag_bls_sec_t const sk,
                   ushort             signer,
                   ushort             shred_version ) {
  out->kind = AG_VOTE_KIND_FINAL;
  ag_final_vote_new( &out->inner.final, slot, sk, signer, shred_version );
}

void
ag_vote_new_signed( ag_vote_t *           out,
                    uint                  kind,
                    ulong                 slot,
                    ag_block_hash_t const h,
                    ag_bls_sign_fn        sign,
                    void *                sign_ctx,
                    ushort                signer,
                    ushort                shred_version ) {
  uchar buf[ AG_VOTE_PAYLOAD_MAX ];
  ulong sz = ag_vote_payload_bytes_to_sign( buf, kind, slot, h, shred_version );

  out->kind = kind;
  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:
    out->inner.notar.slot = slot; out->inner.notar.signer = signer;
    memcpy( out->inner.notar.block_hash, h, sizeof(ag_block_hash_t) );
    sign( sign_ctx, out->inner.notar.sig, buf, sz );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    out->inner.notar_fallback.slot = slot; out->inner.notar_fallback.signer = signer;
    memcpy( out->inner.notar_fallback.block_hash, h, sizeof(ag_block_hash_t) );
    sign( sign_ctx, out->inner.notar_fallback.sig, buf, sz );
    break;
  case AG_VOTE_KIND_SKIP:
    out->inner.skip.slot = slot; out->inner.skip.signer = signer;
    sign( sign_ctx, out->inner.skip.sig, buf, sz );
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    out->inner.skip_fallback.slot = slot; out->inner.skip_fallback.signer = signer;
    sign( sign_ctx, out->inner.skip_fallback.sig, buf, sz );
    break;
  default:
    out->kind = AG_VOTE_KIND_FINAL;
    out->inner.final.slot = slot; out->inner.final.signer = signer;
    sign( sign_ctx, out->inner.final.sig, buf, sz );
    break;
  }
}

int
ag_vote_check_sig( ag_vote_t const *  self,
                   ag_bls_pub_t const pk,
                   ushort             shred_version ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return ag_notar_vote_check_sig         ( &self->inner.notar,          pk, shred_version );
  case AG_VOTE_KIND_NOTAR_FALLBACK: return ag_notar_fallback_vote_check_sig( &self->inner.notar_fallback, pk, shred_version );
  case AG_VOTE_KIND_SKIP:           return ag_skip_vote_check_sig          ( &self->inner.skip,           pk, shred_version );
  case AG_VOTE_KIND_SKIP_FALLBACK:  return ag_skip_fallback_vote_check_sig ( &self->inner.skip_fallback,  pk, shred_version );
  default:                          return ag_final_vote_check_sig         ( &self->inner.final,          pk, shred_version );
  }
}
