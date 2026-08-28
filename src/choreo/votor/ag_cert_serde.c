#include "ag_cert_serde.h"

#include "../../ballet/bls/fd_bls12_381.h"

FD_STATIC_ASSERT( sizeof(ag_cert_signature_serde_t      )==AG_BLS_SIG_SZ+8UL,                                              ag_cert_serde );
FD_STATIC_ASSERT( sizeof(ag_cert_serde_t                )==10UL+sizeof(ag_block_hash_t)+sizeof(ag_cert_signature_serde_t), ag_cert_serde );
FD_STATIC_ASSERT( sizeof(ag_cert_bitmap_serde_t         )==3UL,                                                            ag_cert_serde );
FD_STATIC_ASSERT( sizeof(ag_cert_votes_aggregate_serde_t)==AG_BLS_SIG_COMPRESSED_SZ+2UL,                                   ag_cert_serde );
FD_STATIC_ASSERT( sizeof(ag_cert_block_final_serde_t    )==8UL+sizeof(ag_block_hash_t),                                    ag_cert_serde );

#define BASE2_BITMAP (0)
#define BASE3_BITMAP (1)

/* One past the highest rank, or zero when nobody signed.  Agave trims
   the rank bitvec to exactly this width when it builds a certificate, and
   to the wider of the two partitions for base3. */

static ulong
bit_cnt( ag_bls_agg_t const * agg ) {
  return fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg->bitmask )+1UL );
}

static ulong
base2_bitmap_ser( uchar *              out,
                  ag_bls_agg_t const * agg ) {
  ag_cert_bitmap_serde_t * bm      = (ag_cert_bitmap_serde_t *)out;
  ulong                    bits    = bit_cnt( agg );
  ulong                    payload = (bits+7UL)/8UL;

  bm->version = (uchar)BASE2_BITMAP;
  bm->bit_cnt = (ushort)bits;

  uchar * p = (uchar *)( bm+1 );
  fd_memset( p, 0, payload );
  for( ulong i=0UL; i<bits; i++ ) {
    if( signer_set_test( agg->bitmask, i ) ) p[ i>>3 ] |= (uchar)( 1U << (i&7U) );
  }
  return sizeof(ag_cert_bitmap_serde_t) + payload;
}

static ulong
base3_bitmap_ser( uchar *              out,
                  ag_bls_agg_t const * base,
                  ag_bls_agg_t const * fb ) {
  ag_cert_bitmap_serde_t * bm      = (ag_cert_bitmap_serde_t *)out;
  ulong                    bits    = fd_ulong_max( bit_cnt( base ), bit_cnt( fb ) );
  ulong                    nchunks = (bits+4UL)/5UL;

  bm->version = (uchar)BASE3_BITMAP;
  bm->bit_cnt = (ushort)bits;

  uchar * p = (uchar *)( bm+1 );
  for( ulong chunk=0UL; chunk<nchunks; chunk++ ) {
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, bits );
    uint  block = 0U;
    uint  place = 1U;
    for( ulong i=start; i<end; i++ ) {
      uint digit = signer_set_test( base->bitmask, i ) ? 1U
                 : signer_set_test( fb->bitmask,   i ) ? 2U : 0U;
      block += digit*place;
      place *= 3U;
    }
    p[ chunk ] = (uchar)block;
  }
  return sizeof(ag_cert_bitmap_serde_t) + nchunks;
}

#define SKIP_BYTES( n, data, sz ) do {                              \
  if( FD_UNLIKELY( (n)>(*(sz)) ) ) return AG_CERT_DE_ERR_TRUNCATED; \
  *(data) += (n);                                                   \
  *(sz)   -= (n);                                                   \
} while( 0 )

static int
base2_bitmap_de( ag_bls_agg_t * agg,
                 uchar const *  b,
                 ulong          b_sz ) {
  if( FD_UNLIKELY( b_sz<sizeof(ag_cert_bitmap_serde_t) ) ) return AG_CERT_DE_ERR_TRUNCATED;

  ag_cert_bitmap_serde_t const * bm      = (ag_cert_bitmap_serde_t const *)b;
  ulong                          bits    = (ulong)bm->bit_cnt;
  ulong                          payload = b_sz - sizeof(ag_cert_bitmap_serde_t);
  if( FD_UNLIKELY( bm->version!=BASE2_BITMAP ) ) return AG_CERT_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( bits>AG_BLS_SIGNERS_MAX   ) ) return AG_CERT_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( payload!=(bits+7UL)/8UL   ) ) return AG_CERT_DE_ERR_MALFORMED;

  ag_bls_agg_zero( agg );

  uchar const * p = (uchar const *)( bm+1 );
  for( ulong i=0UL; i<bits; i++ ) {
    if( (p[ i>>3 ] >> (i&7U)) & 1U ) signer_set_insert( agg->bitmask, i );
  }
  return AG_CERT_DE_SUCCESS;
}

static int
base3_bitmap_de( ag_bls_agg_t * base,
                 ag_bls_agg_t * fb,
                 uchar const *  b,
                 ulong          b_sz ) {
  if( FD_UNLIKELY( b_sz<sizeof(ag_cert_bitmap_serde_t) ) ) return AG_CERT_DE_ERR_TRUNCATED;

  ag_cert_bitmap_serde_t const * bm      = (ag_cert_bitmap_serde_t const *)b;
  ulong                          bits    = (ulong)bm->bit_cnt;
  ulong                          payload = b_sz - sizeof(ag_cert_bitmap_serde_t);
  ulong                          nchunks = (bits+4UL)/5UL;
  if( FD_UNLIKELY( bm->version!=BASE3_BITMAP ) ) return AG_CERT_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( bits>AG_BLS_SIGNERS_MAX   ) ) return AG_CERT_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( payload!=nchunks          ) ) return AG_CERT_DE_ERR_MALFORMED;

  ag_bls_agg_zero( base );
  ag_bls_agg_zero( fb   );

  uchar const * p = (uchar const *)( bm+1 );
  for( ulong chunk=0UL; chunk<nchunks; chunk++ ) {
    uint  block = (uint)p[ chunk ];
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, bits );
    for( ulong i=start; i<end; i++ ) {
      uint digit = block % 3U; block /= 3U;
      if(      digit==1U ) signer_set_insert( base->bitmask, i );
      else if( digit==2U ) signer_set_insert( fb->bitmask,   i );
    }
  }
  return AG_CERT_DE_SUCCESS;
}

/* TODO: check serde accepting AG_BLS_SIGNERS_MAX (2048) vs AG_VAT_MAX
   (2000); reward processing ignores bits past the validator count
   instead of rejecting the cert. Check what Agave does with rank bits
   >= the epoch's validator set size and match it. */

static int
footer_aggregate_de( ag_bls_agg_t * agg,
                     uchar const *  buf,
                     ulong          buf_max,
                     ulong *        buf_sz ) {
  ulong remaining = buf_max;

  ag_cert_votes_aggregate_serde_t const * aggregate = (ag_cert_votes_aggregate_serde_t const *)buf;
  SKIP_BYTES( sizeof(ag_cert_votes_aggregate_serde_t), &buf, &remaining );

  ushort        bm_cnt = aggregate->bitmap_cnt;
  uchar const * bm     = buf;
  SKIP_BYTES( bm_cnt, &buf, &remaining );

  int err = base2_bitmap_de( agg, bm, bm_cnt );  if( FD_UNLIKELY( err ) ) return err;
  fd_memcpy( agg->sig, aggregate->signature, AG_BLS_SIG_COMPRESSED_SZ );
  *buf_sz = buf_max - remaining;
  return AG_CERT_DE_SUCCESS;
}

int
ag_cert_ser( ag_cert_t const * self,
             ushort            shred_version,
             uchar *           buf,
             ulong             buf_max,
             ulong *           buf_sz ) {
  ag_bls_agg_t const * base;
  ag_bls_agg_t const * fb = NULL;
  uchar const *        hash = NULL;
  ulong                slot;
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:
    slot = self->final.slot;          base = &self->final.agg_sig;
    break;
  case AG_CERT_KIND_FAST_FINAL:
    slot = self->fast_final.slot;     base = &self->fast_final.agg_sig;
    hash = self->fast_final.block_hash;
    break;
  case AG_CERT_KIND_NOTAR:
    slot = self->notar.slot;          base = &self->notar.agg_sig;
    hash = self->notar.block_hash;
    break;
  case AG_CERT_KIND_NOTAR_FALLBACK:
    slot = self->notar_fallback.slot; base = &self->notar_fallback.agg_sig_notar;
    fb   = &self->notar_fallback.agg_sig_notar_fallback;
    hash = self->notar_fallback.block_hash;
    break;
  case AG_CERT_KIND_SKIP:
    slot = self->skip.slot;           base = &self->skip.agg_sig_skip;
    fb   = &self->skip.agg_sig_skip_fallback;
    break;
  default:
    return -1;
  }

  if( fb && !ag_bls_agg_signer_cnt( fb ) ) fb = NULL;

  ulong bits    = fb ? fd_ulong_max( bit_cnt( base ), bit_cnt( fb ) ) : bit_cnt( base );
  ulong bm_sz   = sizeof(ag_cert_bitmap_serde_t) + ( fb ? (bits+4UL)/5UL : (bits+7UL)/8UL );
  ulong head_sz = sizeof(ag_cert_serde_t) - ( hash ? 0UL : sizeof(ag_block_hash_t) );
  ulong sz      = head_sz + bm_sz + sizeof(ushort);
  if( FD_UNLIKELY( buf_max<sz ) ) return -1;

  ag_cert_serde_t *           out       = (ag_cert_serde_t *)buf;
  ag_cert_signature_serde_t * signature = hash ? &out->block_cert.signature : &out->slot_cert.signature;

  out->version = (uchar)1;
  out->kind    = (uchar)( self->kind+7U );
  out->slot    = slot;
  if( hash ) memcpy( out->block_cert.block_id, hash, sizeof(ag_block_hash_t) );
  fd_memcpy( signature->signature, base->sig, AG_BLS_SIG_SZ );
  signature->bitmap_cnt = bm_sz;

  /* The bitmap starts right after the head, which is what head_sz names.
     Deriving it from buf rather than from signature+1 matters: the slot_cert
     arm is exactly one signature wide, so signature+1 lands on its end and
     the compiler reads any write there as overrunning that arm. */

  uchar * bm    = buf + head_sz;
  ulong   bm_wr = fb ? base3_bitmap_ser( bm, base, fb ) : base2_bitmap_ser( bm, base );
  FD_STORE( ushort, bm+bm_wr, shred_version );

  FD_TEST( bm_wr==bm_sz );

  if( buf_sz ) *buf_sz = sz;
  return 0;
}

int
ag_cert_de( ag_cert_t *   cert,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_max,
            ulong *       buf_sz ) {
  if( FD_UNLIKELY( buf_max<2UL ) ) return AG_CERT_DE_ERR_TRUNCATED;

  ag_cert_serde_t const * cert_ = (ag_cert_serde_t const *)buf;
  if( FD_UNLIKELY( cert_->version!=1 ) ) return AG_CERT_DE_ERR_UNSUPPORTED;

  fd_memset( cert, 0, sizeof(ag_cert_t) );
  switch( cert_->kind ) {
  case  7: cert->kind = AG_CERT_KIND_FINAL;          break;
  case  8: cert->kind = AG_CERT_KIND_FAST_FINAL;     break;
  case  9: cert->kind = AG_CERT_KIND_NOTAR;          break;
  case 10: cert->kind = AG_CERT_KIND_NOTAR_FALLBACK; break;
  case 11: cert->kind = AG_CERT_KIND_SKIP;           break;
  case 12: return AG_CERT_DE_ERR_UNSUPPORTED;
  default: return AG_CERT_DE_ERR_MALFORMED;
  }

  int   has_block_id = cert->kind==AG_CERT_KIND_FAST_FINAL || cert->kind==AG_CERT_KIND_NOTAR || cert->kind==AG_CERT_KIND_NOTAR_FALLBACK;
  ulong head_sz      = sizeof(ag_cert_serde_t) - ( has_block_id ? 0UL : sizeof(ag_block_hash_t) );
  if( FD_UNLIKELY( buf_max<head_sz ) ) return AG_CERT_DE_ERR_TRUNCATED;

  ag_cert_signature_serde_t const * signature = has_block_id ? &cert_->block_cert.signature : &cert_->slot_cert.signature;

  ulong bm_cnt = signature->bitmap_cnt;
  ulong avail  = buf_max - head_sz;
  if( FD_UNLIKELY( bm_cnt>avail || avail-bm_cnt<sizeof(ushort) ) ) return AG_CERT_DE_ERR_TRUNCATED;
  if( FD_UNLIKELY( FD_LOAD( ushort, buf+head_sz+bm_cnt )!=shred_version ) ) return AG_CERT_DE_ERR_SHRED_VERSION;

  ulong         slot = cert_->slot;
  uchar const * sig  = signature->signature;
  uchar const * bm   = buf + head_sz;

  int err;
  switch( cert->kind ) {
  case AG_CERT_KIND_FINAL:
    cert->final.slot = slot;
    if( FD_UNLIKELY( err = base2_bitmap_de(  &cert->final.agg_sig, bm, bm_cnt ) ) ) return err;
    fd_memcpy( cert->final.agg_sig.sig, sig, AG_BLS_SIG_SZ );
    break;
  case AG_CERT_KIND_FAST_FINAL:
    cert->fast_final.slot = slot;
    memcpy( cert->fast_final.block_hash, cert_->block_cert.block_id, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( err = base2_bitmap_de(  &cert->fast_final.agg_sig, bm, bm_cnt ) ) ) return err;
    fd_memcpy( cert->fast_final.agg_sig.sig, sig, AG_BLS_SIG_SZ );
    break;
  case AG_CERT_KIND_NOTAR:
    cert->notar.slot = slot;
    memcpy( cert->notar.block_hash, cert_->block_cert.block_id, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( err = base2_bitmap_de(  &cert->notar.agg_sig, bm, bm_cnt ) ) ) return err;
    fd_memcpy( cert->notar.agg_sig.sig, sig, AG_BLS_SIG_SZ );
    break;
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_bls_agg_t * b = &cert->notar_fallback.agg_sig_notar;
    ag_bls_agg_t * f = &cert->notar_fallback.agg_sig_notar_fallback;
    cert->notar_fallback.slot = slot;
    memcpy( cert->notar_fallback.block_hash, cert_->block_cert.block_id, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( bm_cnt<1UL ) ) return AG_CERT_DE_ERR_TRUNCATED;
    if( bm[0]==BASE2_BITMAP ) { if( FD_UNLIKELY( err = base2_bitmap_de( b,    bm, bm_cnt ) ) ) return err; ag_bls_agg_zero( f ); }
    else                      { if( FD_UNLIKELY( err = base3_bitmap_de( b, f, bm, bm_cnt ) ) ) return err; }
    fd_memcpy( b->sig, sig, AG_BLS_SIG_SZ );
    break;
  }
  case AG_CERT_KIND_SKIP: {
    ag_bls_agg_t * b = &cert->skip.agg_sig_skip;
    ag_bls_agg_t * f = &cert->skip.agg_sig_skip_fallback;
    cert->skip.slot = slot;
    if( FD_UNLIKELY( bm_cnt<1UL ) ) return AG_CERT_DE_ERR_TRUNCATED;
    if( bm[0]==BASE2_BITMAP ) { if( FD_UNLIKELY( err = base2_bitmap_de( b,    bm, bm_cnt ) ) ) return err; ag_bls_agg_zero( f ); }
    else                      { if( FD_UNLIKELY( err = base3_bitmap_de( b, f, bm, bm_cnt ) ) ) return err; }
    fd_memcpy( b->sig, sig, AG_BLS_SIG_SZ );
    break;
  }
  default:
    return AG_CERT_DE_ERR_MALFORMED;
  }

  if( buf_sz ) *buf_sz = head_sz + bm_cnt + sizeof(ushort);

  return AG_CERT_DE_SUCCESS;
}

static int
decompress( ag_bls_agg_t * agg ) {
  uchar csig[ AG_BLS_SIG_COMPRESSED_SZ ];
  fd_memcpy( csig, agg->sig, AG_BLS_SIG_COMPRESSED_SZ );
  return fd_bls12_381_g2_decompress_syscall( agg->sig, csig, 1 );
}

int
ag_cert_block_final_de( ag_cert_fast_final_t * fast_final,
                        ag_cert_final_t *      final,
                        ag_cert_notar_t *      notar,
                        uchar const *          buf,
                        ulong                  buf_max,
                        ulong *                buf_sz ) {
  ulong remaining = buf_max;

  if( FD_UNLIKELY( remaining<sizeof(ag_cert_block_final_serde_t) ) ) return -1;
  ag_cert_block_final_serde_t const * block_final = (ag_cert_block_final_serde_t const *)buf;
  buf       += sizeof(ag_cert_block_final_serde_t);
  remaining -= sizeof(ag_cert_block_final_serde_t);

  ag_bls_agg_t final_agg[1];
  ulong        consumed;
  if( FD_UNLIKELY( footer_aggregate_de( final_agg, buf, remaining, &consumed ) ) ) return -1;
  buf       += consumed;
  remaining -= consumed;

  if( FD_UNLIKELY( remaining<1UL ) ) return -1;
  uchar has_notar_aggregate = *buf;
  buf       += 1UL;
  remaining -= 1UL;
  if( FD_UNLIKELY( has_notar_aggregate>1 ) ) return -1;

  if( !has_notar_aggregate ) {
    fd_memset( fast_final, 0, sizeof(ag_cert_fast_final_t) );
    fast_final->slot    = block_final->slot;
    fast_final->agg_sig = *final_agg;
    memcpy( fast_final->block_hash, block_final->block_id, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( decompress( &fast_final->agg_sig ) ) ) return -1;
    if( buf_sz ) *buf_sz = buf_max - remaining;
    return 1;
  }

  ag_bls_agg_t notar_agg[1];
  if( FD_UNLIKELY( footer_aggregate_de( notar_agg, buf, remaining, &consumed ) ) ) return -1;
  remaining -= consumed;

  fd_memset( final, 0, sizeof(ag_cert_final_t) );
  fd_memset( notar, 0, sizeof(ag_cert_notar_t) );
  final->slot    = block_final->slot;
  final->agg_sig = *final_agg;
  notar->slot    = block_final->slot;
  notar->agg_sig = *notar_agg;
  memcpy( notar->block_hash, block_final->block_id, sizeof(ag_block_hash_t) );
  if( FD_UNLIKELY( decompress( &final->agg_sig ) ) ) return -1;
  if( FD_UNLIKELY( decompress( &notar->agg_sig ) ) ) return -1;
  if( buf_sz ) *buf_sz = buf_max - remaining;
  return 0;
}
