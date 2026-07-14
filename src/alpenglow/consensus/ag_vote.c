#include "ag_vote.h"

ulong
ag_vote_payload_bytes_to_sign( uchar *           out,
                               uint              kind,
                               ulong             slot,
                               fd_hash_t const * h,
                               ushort            shred_version ) {
  /* VotePayloadToSign (agave votor-messages/src/wire.rs): u8 tags start
     at 1 in Vote variant order. */
  ulong o = 0UL;
  out[o] = (uchar)( kind+1U ); o += 1UL;
  FD_STORE( ulong, out+o, slot ); o += 8UL;
  if( kind==AG_VOTE_TYPE_NOTAR || kind==AG_VOTE_TYPE_NOTAR_FALLBACK ) {
    FD_TEST( h );
    fd_memcpy( out+o, h->uc, sizeof(fd_hash_t) ); o += sizeof(fd_hash_t);
  }
  FD_STORE( ushort, out+o, shred_version ); o += 2UL;
  return o;
}

static void
sign_payload( ag_aggsig_sig_t *      sig,
              uint                   kind,
              ulong                  slot,
              fd_hash_t const *      h,
              ag_aggsig_sk_t const * sk,
              ushort                 shred_version ) {
  uchar buf[ AG_VOTE_PAYLOAD_MAX ];
  ulong sz = ag_vote_payload_bytes_to_sign( buf, kind, slot, h, shred_version );
  ag_aggsig_sign_bytes( sig, sk, buf, sz );
}

void
ag_notar_vote_new( ag_notar_vote_t *      out,
                   ulong                  slot,
                   fd_hash_t const *      h,
                   ag_aggsig_sk_t const * sk,
                   ushort                 signer,
                   ushort                 shred_version ) {
  out->slot = slot; out->block_hash = *h; out->signer = signer;
  sign_payload( &out->sig, AG_VOTE_TYPE_NOTAR, slot, h, sk, shred_version );
}

void
ag_notar_fallback_vote_new( ag_notar_fallback_vote_t * out,
                            ulong                      slot,
                            fd_hash_t const *          h,
                            ag_aggsig_sk_t const *     sk,
                            ushort                     signer,
                            ushort                     shred_version ) {
  out->slot = slot; out->block_hash = *h; out->signer = signer;
  sign_payload( &out->sig, AG_VOTE_TYPE_NOTAR_FALLBACK, slot, h, sk, shred_version );
}

void
ag_skip_vote_new( ag_skip_vote_t *       out,
                  ulong                  slot,
                  ag_aggsig_sk_t const * sk,
                  ushort                 signer,
                  ushort                 shred_version ) {
  out->slot = slot; out->signer = signer;
  sign_payload( &out->sig, AG_VOTE_TYPE_SKIP, slot, NULL, sk, shred_version );
}

void
ag_skip_fallback_vote_new( ag_skip_fallback_vote_t * out,
                           ulong                     slot,
                           ag_aggsig_sk_t const *    sk,
                           ushort                    signer,
                           ushort                    shred_version ) {
  out->slot = slot; out->signer = signer;
  sign_payload( &out->sig, AG_VOTE_TYPE_SKIP_FALLBACK, slot, NULL, sk, shred_version );
}

void
ag_final_vote_new( ag_final_vote_t *      out,
                   ulong                  slot,
                   ag_aggsig_sk_t const * sk,
                   ushort                 signer,
                   ushort                 shred_version ) {
  out->slot = slot; out->signer = signer;
  sign_payload( &out->sig, AG_VOTE_TYPE_FINAL, slot, NULL, sk, shred_version );
}

void
ag_vote_new_notar( ag_vote_t *            out,
                   ulong                  slot,
                   fd_hash_t const *      h,
                   ag_aggsig_sk_t const * sk,
                   ushort                 signer,
                   ushort                 shred_version ) {
  out->kind = AG_VOTE_TYPE_NOTAR;
  ag_notar_vote_new( &out->inner.notar, slot, h, sk, signer, shred_version );
}

void
ag_vote_new_notar_fallback( ag_vote_t *            out,
                            ulong                  slot,
                            fd_hash_t const *      h,
                            ag_aggsig_sk_t const * sk,
                            ushort                 signer,
                            ushort                 shred_version ) {
  out->kind = AG_VOTE_TYPE_NOTAR_FALLBACK;
  ag_notar_fallback_vote_new( &out->inner.notar_fallback, slot, h, sk, signer, shred_version );
}

void
ag_vote_new_skip( ag_vote_t *            out,
                  ulong                  slot,
                  ag_aggsig_sk_t const * sk,
                  ushort                 signer,
                  ushort                 shred_version ) {
  out->kind = AG_VOTE_TYPE_SKIP;
  ag_skip_vote_new( &out->inner.skip, slot, sk, signer, shred_version );
}

void
ag_vote_new_skip_fallback( ag_vote_t *            out,
                           ulong                  slot,
                           ag_aggsig_sk_t const * sk,
                           ushort                 signer,
                           ushort                 shred_version ) {
  out->kind = AG_VOTE_TYPE_SKIP_FALLBACK;
  ag_skip_fallback_vote_new( &out->inner.skip_fallback, slot, sk, signer, shred_version );
}

void
ag_vote_new_final( ag_vote_t *            out,
                   ulong                  slot,
                   ag_aggsig_sk_t const * sk,
                   ushort                 signer,
                   ushort                 shred_version ) {
  out->kind = AG_VOTE_TYPE_FINAL;
  ag_final_vote_new( &out->inner.final_, slot, sk, signer, shred_version );
}

int
ag_vote_check_sig( ag_vote_t const *      self,
                   ag_aggsig_pk_t const * pk,
                   ushort                 shred_version ) {
  uchar buf[ AG_VOTE_PAYLOAD_MAX ];
  ulong sz;
  ag_aggsig_sig_t const * sig;
  switch( self->kind ) {
  case AG_VOTE_TYPE_NOTAR:
    sz  = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_NOTAR, self->inner.notar.slot, &self->inner.notar.block_hash, shred_version );
    sig = &self->inner.notar.sig; break;
  case AG_VOTE_TYPE_NOTAR_FALLBACK:
    sz  = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_NOTAR_FALLBACK, self->inner.notar_fallback.slot, &self->inner.notar_fallback.block_hash, shred_version );
    sig = &self->inner.notar_fallback.sig; break;
  case AG_VOTE_TYPE_SKIP:
    sz  = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_SKIP, self->inner.skip.slot, NULL, shred_version );
    sig = &self->inner.skip.sig; break;
  case AG_VOTE_TYPE_SKIP_FALLBACK:
    sz  = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_SKIP_FALLBACK, self->inner.skip_fallback.slot, NULL, shred_version );
    sig = &self->inner.skip_fallback.sig; break;
  default:
    sz  = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_FINAL, self->inner.final_.slot, NULL, shred_version );
    sig = &self->inner.final_.sig; break;
  }
  return ag_aggsig_individual_verify_bytes( sig, pk, buf, sz );
}

ulong
ag_vote_serialize( ag_vote_t const * self,
                   uchar *           out,
                   ulong             out_max,
                   ushort            shred_version ) {
  ulong                   slot = ag_vote_slot( self );
  fd_hash_t const *       hash = ag_vote_block_hash( self );
  ag_aggsig_sig_t const * sig;
  switch( self->kind ) {
  case AG_VOTE_TYPE_NOTAR:          sig = &self->inner.notar.sig;          break;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: sig = &self->inner.notar_fallback.sig; break;
  case AG_VOTE_TYPE_SKIP:           sig = &self->inner.skip.sig;           break;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  sig = &self->inner.skip_fallback.sig;  break;
  default:                          sig = &self->inner.final_.sig;         break;
  }

  ulong vote_sz = 1UL + 8UL + ( hash ? sizeof(fd_hash_t) : 0UL ) + 2UL;
  ulong sz      = 4UL + vote_sz + AG_AGGSIG_SIG_SZ + 2UL;
  if( FD_UNLIKELY( out_max<sz ) ) return 0UL;

  ulong off = 0UL;
  FD_STORE( uint, out+off, 0U  ); off += 4UL;
  off += ag_vote_payload_bytes_to_sign( out+off, self->kind, slot, hash, shred_version );
  fd_memcpy( out+off, sig->v, AG_AGGSIG_SIG_SZ ); off += AG_AGGSIG_SIG_SZ;
  FD_STORE( ushort, out+off, ag_vote_signer( self ) ); off += 2UL;
  FD_TEST( off==sz );
  return off;
}
