#include "fd_vote.h"

ulong
fd_vote_payload_bytes_to_sign( uchar *           out,
                               uint              kind,
                               ulong             slot,
                               fd_hash_t const * h ) {
  ulong o = 0UL;
  FD_STORE( uint,  out+o, kind ); o += 4UL; /* enum discriminant (see header caveat) */
  FD_STORE( ulong, out+o, slot ); o += 8UL;
  if( kind==FD_VOTE_TYPE_NOTAR || kind==FD_VOTE_TYPE_NOTAR_FALLBACK ) {
    FD_TEST( h );
    fd_memcpy( out+o, h->uc, sizeof(fd_hash_t) ); o += sizeof(fd_hash_t);
  }
  return o;
}

/* sign_payload signs the (kind,slot,h) payload with sk into sig. */

static void
sign_payload( fd_aggsig_sig_t *      sig,
              uint                   kind,
              ulong                  slot,
              fd_hash_t const *      h,
              fd_aggsig_sk_t const * sk ) {
  uchar buf[ FD_VOTE_PAYLOAD_MAX ];
  ulong sz = fd_vote_payload_bytes_to_sign( buf, kind, slot, h );
  fd_aggsig_sign_bytes( sig, sk, buf, sz );
}

void
fd_notar_vote_new( fd_notar_vote_t * out, ulong slot, fd_hash_t const * h, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->slot = slot; out->block_hash = *h; out->signer = signer;
  sign_payload( &out->sig, FD_VOTE_TYPE_NOTAR, slot, h, sk );
}

void
fd_notar_fallback_vote_new( fd_notar_fallback_vote_t * out, ulong slot, fd_hash_t const * h, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->slot = slot; out->block_hash = *h; out->signer = signer;
  sign_payload( &out->sig, FD_VOTE_TYPE_NOTAR_FALLBACK, slot, h, sk );
}

void
fd_skip_vote_new( fd_skip_vote_t * out, ulong slot, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->slot = slot; out->signer = signer;
  sign_payload( &out->sig, FD_VOTE_TYPE_SKIP, slot, NULL, sk );
}

void
fd_skip_fallback_vote_new( fd_skip_fallback_vote_t * out, ulong slot, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->slot = slot; out->signer = signer;
  sign_payload( &out->sig, FD_VOTE_TYPE_SKIP_FALLBACK, slot, NULL, sk );
}

void
fd_final_vote_new( fd_final_vote_t * out, ulong slot, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->slot = slot; out->signer = signer;
  sign_payload( &out->sig, FD_VOTE_TYPE_FINAL, slot, NULL, sk );
}

void fd_vote_new_notar( fd_ag_vote_t * out, ulong slot, fd_hash_t const * h, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->discriminant = FD_VOTE_TYPE_NOTAR;
  fd_notar_vote_new( &out->inner.notar, slot, h, sk, signer );
}

void fd_vote_new_notar_fallback( fd_ag_vote_t * out, ulong slot, fd_hash_t const * h, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->discriminant = FD_VOTE_TYPE_NOTAR_FALLBACK;
  fd_notar_fallback_vote_new( &out->inner.notar_fallback, slot, h, sk, signer );
}

void fd_vote_new_skip( fd_ag_vote_t * out, ulong slot, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->discriminant = FD_VOTE_TYPE_SKIP;
  fd_skip_vote_new( &out->inner.skip, slot, sk, signer );
}

void fd_vote_new_skip_fallback( fd_ag_vote_t * out, ulong slot, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->discriminant = FD_VOTE_TYPE_SKIP_FALLBACK;
  fd_skip_fallback_vote_new( &out->inner.skip_fallback, slot, sk, signer );
}

void fd_vote_new_final( fd_ag_vote_t * out, ulong slot, fd_aggsig_sk_t const * sk, ushort signer ) {
  out->discriminant = FD_VOTE_TYPE_FINAL;
  fd_final_vote_new( &out->inner.final_, slot, sk, signer );
}

int
fd_vote_check_sig( fd_ag_vote_t const * v, fd_aggsig_pk_t const * pk ) {
  uchar buf[ FD_VOTE_PAYLOAD_MAX ];
  ulong sz;
  fd_aggsig_sig_t const * sig;
  switch( v->discriminant ) {
  case FD_VOTE_TYPE_NOTAR:
    sz  = fd_vote_payload_bytes_to_sign( buf, FD_VOTE_TYPE_NOTAR, v->inner.notar.slot, &v->inner.notar.block_hash );
    sig = &v->inner.notar.sig; break;
  case FD_VOTE_TYPE_NOTAR_FALLBACK:
    sz  = fd_vote_payload_bytes_to_sign( buf, FD_VOTE_TYPE_NOTAR_FALLBACK, v->inner.notar_fallback.slot, &v->inner.notar_fallback.block_hash );
    sig = &v->inner.notar_fallback.sig; break;
  case FD_VOTE_TYPE_SKIP:
    sz  = fd_vote_payload_bytes_to_sign( buf, FD_VOTE_TYPE_SKIP, v->inner.skip.slot, NULL );
    sig = &v->inner.skip.sig; break;
  case FD_VOTE_TYPE_SKIP_FALLBACK:
    sz  = fd_vote_payload_bytes_to_sign( buf, FD_VOTE_TYPE_SKIP_FALLBACK, v->inner.skip_fallback.slot, NULL );
    sig = &v->inner.skip_fallback.sig; break;
  default:
    sz  = fd_vote_payload_bytes_to_sign( buf, FD_VOTE_TYPE_FINAL, v->inner.final_.slot, NULL );
    sig = &v->inner.final_.sig; break;
  }
  return fd_aggsig_individual_verify_bytes( sig, pk, buf, sz );
}

ulong
fd_vote_serialize( fd_ag_vote_t const * v,
                   uchar *           out,
                   ulong             out_max ) {
  ulong                   slot = fd_vote_slot( v );
  fd_hash_t const *       hash = fd_vote_block_hash( v ); /* NULL for skip/skip-fb/final */
  fd_aggsig_sig_t const * sig;
  switch( v->discriminant ) {
  case FD_VOTE_TYPE_NOTAR:          sig = &v->inner.notar.sig;          break;
  case FD_VOTE_TYPE_NOTAR_FALLBACK: sig = &v->inner.notar_fallback.sig; break;
  case FD_VOTE_TYPE_SKIP:           sig = &v->inner.skip.sig;           break;
  case FD_VOTE_TYPE_SKIP_FALLBACK:  sig = &v->inner.skip_fallback.sig;  break;
  default:                          sig = &v->inner.final_.sig;         break;
  }

  ulong vote_sz = 4UL + 8UL + ( hash ? sizeof(fd_hash_t) : 0UL ); /* Vote tag + slot [+ block_id] */
  ulong sz      = 4UL + vote_sz + FD_AGGSIG_SIG_SZ + 2UL;
  if( FD_UNLIKELY( out_max<sz ) ) return 0UL;

  ulong off = 0UL;
  FD_STORE( uint, out+off, 0U /* see fd_votor.h FD_CONSENSUS_MESSAGE_VOTE */ ); off += 4UL;
  off += fd_vote_payload_bytes_to_sign( out+off, v->discriminant, slot, hash ); /* VoteMessage.vote */
  fd_memcpy( out+off, sig->v, FD_AGGSIG_SIG_SZ ); off += FD_AGGSIG_SIG_SZ;       /* VoteMessage.signature */
  FD_STORE( ushort, out+off, fd_vote_signer( v ) ); off += 2UL;                  /* VoteMessage.rank      */
  FD_TEST( off==sz );
  return off;
}
