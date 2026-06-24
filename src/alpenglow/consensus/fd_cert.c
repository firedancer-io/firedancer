#include "fd_cert.h"

/* Aggregate helpers: build an fd_aggsig over a set of concrete votes via
   init + add (equivalent to AggregateSignature::new), reading sig+signer
   directly from each vote so no large temporary arrays are needed.  nbits is
   the validator count (the bitmask length). */

static void agg_notar( fd_aggsig_t * a, fd_notar_vote_t const * v, ulong n, ulong nbits ) {
  fd_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) fd_aggsig_add( a, v[i].signer, &v[i].sig );
}
static void agg_nf( fd_aggsig_t * a, fd_notar_fallback_vote_t const * v, ulong n, ulong nbits ) {
  fd_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) fd_aggsig_add( a, v[i].signer, &v[i].sig );
}
static void agg_skip( fd_aggsig_t * a, fd_skip_vote_t const * v, ulong n, ulong nbits ) {
  fd_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) fd_aggsig_add( a, v[i].signer, &v[i].sig );
}
static void agg_sf( fd_aggsig_t * a, fd_skip_fallback_vote_t const * v, ulong n, ulong nbits ) {
  fd_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) fd_aggsig_add( a, v[i].signer, &v[i].sig );
}
static void agg_final( fd_aggsig_t * a, fd_final_vote_t const * v, ulong n, ulong nbits ) {
  fd_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) fd_aggsig_add( a, v[i].signer, &v[i].sig );
}

static inline int hash_eq( fd_hash_t const * a, fd_hash_t const * b ) {
  return 0==memcmp( a->uc, b->uc, sizeof(fd_hash_t) );
}

int
fd_notar_cert_try_new( fd_notar_cert_t * out,
                       fd_notar_vote_t const * votes, ulong vote_cnt,
                       fd_validator_info_t const * validators, ulong validator_cnt ) {
  FD_TEST( vote_cnt>0UL );
  ulong       slot = votes[0].slot;
  fd_hash_t   bh   = votes[0].block_hash;
  ulong       stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    if( FD_UNLIKELY( votes[i].slot!=slot              ) ) return FD_CERT_ERR_SLOT_MISMATCH;
    if( FD_UNLIKELY( !hash_eq( &votes[i].block_hash, &bh ) ) ) return FD_CERT_ERR_BLOCK_HASH_MISMATCH;
    stake += validators[ votes[i].signer ].stake;
  }
  out->slot = slot; out->block_hash = bh; out->stake = stake;
  agg_notar( &out->agg_sig, votes, vote_cnt, validator_cnt );
  return FD_CERT_SUCCESS;
}

int
fd_fast_final_cert_try_new( fd_fast_final_cert_t * out,
                            fd_notar_vote_t const * votes, ulong vote_cnt,
                            fd_validator_info_t const * validators, ulong validator_cnt ) {
  FD_TEST( vote_cnt>0UL );
  ulong       slot = votes[0].slot;
  fd_hash_t   bh   = votes[0].block_hash;
  ulong       stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    if( FD_UNLIKELY( votes[i].slot!=slot              ) ) return FD_CERT_ERR_SLOT_MISMATCH;
    if( FD_UNLIKELY( !hash_eq( &votes[i].block_hash, &bh ) ) ) return FD_CERT_ERR_BLOCK_HASH_MISMATCH;
    stake += validators[ votes[i].signer ].stake;
  }
  out->slot = slot; out->block_hash = bh; out->stake = stake;
  agg_notar( &out->agg_sig, votes, vote_cnt, validator_cnt );
  return FD_CERT_SUCCESS;
}

int
fd_final_cert_try_new( fd_final_cert_t * out,
                       fd_final_vote_t const * votes, ulong vote_cnt,
                       fd_validator_info_t const * validators, ulong validator_cnt ) {
  FD_TEST( vote_cnt>0UL );
  ulong slot = votes[0].slot;
  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    if( FD_UNLIKELY( votes[i].slot!=slot ) ) return FD_CERT_ERR_SLOT_MISMATCH;
    stake += validators[ votes[i].signer ].stake;
  }
  out->slot = slot; out->stake = stake;
  agg_final( &out->agg_sig, votes, vote_cnt, validator_cnt );
  return FD_CERT_SUCCESS;
}

int
fd_notar_fallback_cert_try_new( fd_notar_fallback_cert_t * out,
                                fd_notar_vote_t const * notar_votes, ulong notar_cnt,
                                fd_notar_fallback_vote_t const * nf_votes, ulong nf_cnt,
                                fd_validator_info_t const * validators, ulong validator_cnt ) {
  FD_TEST( notar_cnt>0UL || nf_cnt>0UL );
  ulong     slot;
  fd_hash_t bh;
  if( notar_cnt>0UL ) { slot = notar_votes[0].slot; bh = notar_votes[0].block_hash; }
  else                { slot = nf_votes[0].slot;    bh = nf_votes[0].block_hash;    }

  ulong stake = 0UL;
  for( ulong i=0UL; i<notar_cnt; i++ ) {
    if( FD_UNLIKELY( notar_votes[i].slot!=slot              ) ) return FD_CERT_ERR_SLOT_MISMATCH;
    if( FD_UNLIKELY( !hash_eq( &notar_votes[i].block_hash, &bh ) ) ) return FD_CERT_ERR_BLOCK_HASH_MISMATCH;
    stake += validators[ notar_votes[i].signer ].stake;
  }
  for( ulong i=0UL; i<nf_cnt; i++ ) {
    if( FD_UNLIKELY( nf_votes[i].slot!=slot              ) ) return FD_CERT_ERR_SLOT_MISMATCH;
    if( FD_UNLIKELY( !hash_eq( &nf_votes[i].block_hash, &bh ) ) ) return FD_CERT_ERR_BLOCK_HASH_MISMATCH;
    stake += validators[ nf_votes[i].signer ].stake;
  }

  out->slot = slot; out->block_hash = bh; out->stake = stake;
  if( notar_cnt>0UL ) agg_notar     ( &out->agg_sig_notar, notar_votes, notar_cnt, validator_cnt );
  else                fd_aggsig_init( &out->agg_sig_notar, validator_cnt );
  if( nf_cnt   >0UL ) agg_nf        ( &out->agg_sig_notar_fallback, nf_votes, nf_cnt, validator_cnt );
  else                fd_aggsig_init( &out->agg_sig_notar_fallback, validator_cnt );
  return FD_CERT_SUCCESS;
}

int
fd_skip_cert_try_new( fd_skip_cert_t * out,
                      fd_skip_vote_t const * skip_votes, ulong skip_cnt,
                      fd_skip_fallback_vote_t const * sf_votes, ulong sf_cnt,
                      fd_validator_info_t const * validators, ulong validator_cnt ) {
  FD_TEST( skip_cnt>0UL || sf_cnt>0UL );
  ulong slot = skip_cnt>0UL ? skip_votes[0].slot : sf_votes[0].slot;

  ulong stake = 0UL;
  for( ulong i=0UL; i<skip_cnt; i++ ) {
    if( FD_UNLIKELY( skip_votes[i].slot!=slot ) ) return FD_CERT_ERR_SLOT_MISMATCH;
    stake += validators[ skip_votes[i].signer ].stake;
  }
  for( ulong i=0UL; i<sf_cnt; i++ ) {
    if( FD_UNLIKELY( sf_votes[i].slot!=slot ) ) return FD_CERT_ERR_SLOT_MISMATCH;
    stake += validators[ sf_votes[i].signer ].stake;
  }

  out->slot = slot; out->stake = stake;
  if( skip_cnt>0UL ) agg_skip      ( &out->agg_sig_skip, skip_votes, skip_cnt, validator_cnt );
  else               fd_aggsig_init( &out->agg_sig_skip, validator_cnt );
  if( sf_cnt  >0UL ) agg_sf        ( &out->agg_sig_skip_fallback, sf_votes, sf_cnt, validator_cnt );
  else               fd_aggsig_init( &out->agg_sig_skip_fallback, validator_cnt );
  return FD_CERT_SUCCESS;
}

/* ---- tagged dispatchers ---- */

ulong
fd_cert_slot( fd_cert_t const * c ) {
  switch( c->discriminant ) {
  case FD_CERT_TYPE_NOTAR:          return c->inner.notar.slot;
  case FD_CERT_TYPE_NOTAR_FALLBACK: return c->inner.notar_fallback.slot;
  case FD_CERT_TYPE_SKIP:           return c->inner.skip.slot;
  case FD_CERT_TYPE_FAST_FINAL:     return c->inner.fast_final.slot;
  default:                          return c->inner.final_.slot;
  }
}

ulong
fd_cert_stake( fd_cert_t const * c ) {
  switch( c->discriminant ) {
  case FD_CERT_TYPE_NOTAR:          return c->inner.notar.stake;
  case FD_CERT_TYPE_NOTAR_FALLBACK: return c->inner.notar_fallback.stake;
  case FD_CERT_TYPE_SKIP:           return c->inner.skip.stake;
  case FD_CERT_TYPE_FAST_FINAL:     return c->inner.fast_final.stake;
  default:                          return c->inner.final_.stake;
  }
}

fd_hash_t const *
fd_cert_block_hash( fd_cert_t const * c ) {
  switch( c->discriminant ) {
  case FD_CERT_TYPE_NOTAR:          return &c->inner.notar.block_hash;
  case FD_CERT_TYPE_NOTAR_FALLBACK: return &c->inner.notar_fallback.block_hash;
  case FD_CERT_TYPE_FAST_FINAL:     return &c->inner.fast_final.block_hash;
  default:                          return NULL; /* skip / final */
  }
}

int
fd_cert_is_signer( fd_cert_t const * c, ulong v ) {
  switch( c->discriminant ) {
  case FD_CERT_TYPE_NOTAR:      return fd_aggsig_is_signer( &c->inner.notar.agg_sig, v );
  case FD_CERT_TYPE_FAST_FINAL: return fd_aggsig_is_signer( &c->inner.fast_final.agg_sig, v );
  case FD_CERT_TYPE_FINAL:      return fd_aggsig_is_signer( &c->inner.final_.agg_sig, v );
  case FD_CERT_TYPE_NOTAR_FALLBACK: {
    fd_notar_fallback_cert_t const * n = &c->inner.notar_fallback;
    return fd_aggsig_is_signer( &n->agg_sig_notar, v ) || fd_aggsig_is_signer( &n->agg_sig_notar_fallback, v );
  }
  default: { /* SKIP */
    fd_skip_cert_t const * s = &c->inner.skip;
    return fd_aggsig_is_signer( &s->agg_sig_skip, v ) || fd_aggsig_is_signer( &s->agg_sig_skip_fallback, v );
  }
  }
}

/* signed_stake sums the stake of all epoch validators that signed c. */

static ulong
signed_stake( fd_cert_t const * c, fd_epoch_info_t const * ei ) {
  fd_validator_info_t const * v = fd_epoch_info_validators( ei );
  ulong stake = 0UL;
  for( ulong i=0UL; i<ei->validator_cnt; i++ ) if( fd_cert_is_signer( c, v[i].id ) ) stake += v[i].stake;
  return stake;
}

int
fd_cert_check_threshold( fd_cert_t const * c, fd_epoch_info_t const * ei ) {
  ulong stake = signed_stake( c, ei );
  if( c->discriminant==FD_CERT_TYPE_FAST_FINAL ) return fd_epoch_info_is_strong_quorum( ei, stake );
  return fd_epoch_info_is_quorum( ei, stake );
}

int
fd_cert_check_sig( fd_cert_t const * c, fd_epoch_info_t const * epoch_info ) {
  fd_aggsig_pk_t const * pks           = fd_epoch_info_voting_pubkeys( epoch_info );
  ulong                  validator_cnt = epoch_info->validator_cnt;
  uchar buf[ FD_VOTE_PAYLOAD_MAX ];
  ulong sz;
  switch( c->discriminant ) {
  case FD_CERT_TYPE_NOTAR:
    sz = fd_vote_payload_bytes_to_sign( buf, FD_VOTE_TYPE_NOTAR, c->inner.notar.slot, &c->inner.notar.block_hash );
    return fd_aggsig_verify_bytes( &c->inner.notar.agg_sig, buf, sz, pks, validator_cnt );
  case FD_CERT_TYPE_FAST_FINAL:
    sz = fd_vote_payload_bytes_to_sign( buf, FD_VOTE_TYPE_NOTAR, c->inner.fast_final.slot, &c->inner.fast_final.block_hash );
    return fd_aggsig_verify_bytes( &c->inner.fast_final.agg_sig, buf, sz, pks, validator_cnt );
  case FD_CERT_TYPE_FINAL:
    sz = fd_vote_payload_bytes_to_sign( buf, FD_VOTE_TYPE_FINAL, c->inner.final_.slot, NULL );
    return fd_aggsig_verify_bytes( &c->inner.final_.agg_sig, buf, sz, pks, validator_cnt );
  case FD_CERT_TYPE_NOTAR_FALLBACK: {
    /* The mixed verify handles the degenerate single-set case internally. */
    fd_notar_fallback_cert_t const * n = &c->inner.notar_fallback;
    uchar buf_fb[ FD_VOTE_PAYLOAD_MAX ]; ulong sz_fb;
    sz    = fd_vote_payload_bytes_to_sign( buf,    FD_VOTE_TYPE_NOTAR,          n->slot, &n->block_hash );
    sz_fb = fd_vote_payload_bytes_to_sign( buf_fb, FD_VOTE_TYPE_NOTAR_FALLBACK, n->slot, &n->block_hash );
    return fd_aggsig_verify_mixed_bytes( &n->agg_sig_notar,          buf,    sz,
                                         &n->agg_sig_notar_fallback, buf_fb, sz_fb,
                                         pks, validator_cnt );
  }
  default: { /* SKIP */
    fd_skip_cert_t const * s = &c->inner.skip;
    uchar buf_fb[ FD_VOTE_PAYLOAD_MAX ]; ulong sz_fb;
    sz    = fd_vote_payload_bytes_to_sign( buf,    FD_VOTE_TYPE_SKIP,          s->slot, NULL );
    sz_fb = fd_vote_payload_bytes_to_sign( buf_fb, FD_VOTE_TYPE_SKIP_FALLBACK, s->slot, NULL );
    return fd_aggsig_verify_mixed_bytes( &s->agg_sig_skip,          buf,    sz,
                                         &s->agg_sig_skip_fallback, buf_fb, sz_fb,
                                         pks, validator_cnt );
  }
  }
}

/* deserializers */

/* decode_base2_bitmap fills agg's signer bitmask + nbits from a Base2
   bitmap: [u8 version=0][u16 LE nbits][ceil(nbits/8) payload bytes,
   Lsb0 bit order].  agg->sig is left zeroed (caller fills it). */

static int
de_base2_bitmap( fd_aggsig_t * agg,
                     uchar const * b,
                     ulong         b_sz ) {
  if( FD_UNLIKELY( b_sz<3UL    ) ) return FD_CERT_DE_ERR_TRUNCATED;
  if( FD_UNLIKELY( b[0]!=0     ) ) return FD_CERT_DE_ERR_UNSUPPORTED; /* 1==Base3 (mixed) */
  ulong nbits      = (ulong)( (uint)b[1] | ((uint)b[2]<<8) );
  if( FD_UNLIKELY( nbits>FD_AGGSIG_MAX_SIGNERS ) ) return FD_CERT_DE_ERR_MALFORMED;
  ulong payload_sz = (nbits+7UL)/8UL;
  if( FD_UNLIKELY( b_sz<3UL+payload_sz ) ) return FD_CERT_DE_ERR_TRUNCATED;
  uchar const * bits = b+3UL;

  fd_aggsig_init( agg, nbits ); /* sets nbits, zeroes bitmask and sig */

  for( ulong i=0UL; i<nbits; i++ ) {
    if( (bits[ i>>3 ] >> (i&7U)) & 1U ) signer_set_insert( agg->bitmask, i );
  }
  return FD_CERT_DE_SUCCESS;
}

/* de_base3_bitmap fills TWO signer bitmasks from a Base3
   bitmap: [u8 version=1][u16 LE nbits][ceil(nbits/5) payload bytes].  Each
   payload byte packs 5 ternary digits (low digit first); per rank i the digit
   is 0 => neither set, 1 => base set, 2 => fallback set (the (1,1) combination
   is invalid and cannot be encoded).  base / fb sigs are left zeroed. */

static int
de_base3_bitmap( fd_aggsig_t * base,
                 fd_aggsig_t * fb,
                 uchar const * b,
                 ulong         b_sz ) {
  if( FD_UNLIKELY( b_sz<3UL ) ) return FD_CERT_DE_ERR_TRUNCATED;
  if( FD_UNLIKELY( b[0]!=1   ) ) return FD_CERT_DE_ERR_MALFORMED; /* not Base3 */
  ulong nbits   = (ulong)( (uint)b[1] | ((uint)b[2]<<8) );
  if( FD_UNLIKELY( nbits>FD_AGGSIG_MAX_SIGNERS ) ) return FD_CERT_DE_ERR_MALFORMED;
  ulong nchunks = (nbits+4UL)/5UL; /* ceil(nbits/5) */
  if( FD_UNLIKELY( b_sz<3UL+nchunks ) ) return FD_CERT_DE_ERR_TRUNCATED;
  uchar const * data = b+3UL;

  fd_aggsig_init( base, nbits );
  fd_aggsig_init( fb,   nbits );

  for( ulong chunk=0UL; chunk<nchunks; chunk++ ) {
    uint  block = (uint)data[ chunk ];
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, nbits );
    for( ulong i=start; i<end; i++ ) {
      uint digit = block % 3U; block /= 3U;
      if(      digit==1U ) signer_set_insert( base->bitmask, i );
      else if( digit==2U ) signer_set_insert( fb->bitmask,   i );
    }
  }
  return FD_CERT_DE_SUCCESS;
}

int
fd_cert_de( fd_cert_t *   out,
            uchar const * in,
            ulong         in_sz ) {
  ulong off = 0UL;

  /* cert_type: u32 LE tag + payload (Slot or Block). */
  if( FD_UNLIKELY( in_sz<off+4UL ) ) return FD_CERT_DE_ERR_TRUNCATED;
  uint tag = FD_LOAD( uint, in+off ); off += 4UL;

  ulong     slot = 0UL;
  fd_hash_t block_hash;
  fd_memset( &block_hash, 0, sizeof(fd_hash_t) );

  switch( tag ) {
  case FD_CERT_TYPE_FINAL:
  case FD_CERT_TYPE_SKIP:               /* Slot payload */
    if( FD_UNLIKELY( in_sz<off+8UL ) ) return FD_CERT_DE_ERR_TRUNCATED;
    slot = FD_LOAD( ulong, in+off ); off += 8UL;
    break;
  case FD_CERT_TYPE_FAST_FINAL:
  case FD_CERT_TYPE_NOTAR:
  case FD_CERT_TYPE_NOTAR_FALLBACK:
  case FD_CERT_TYPE_GENESIS:            /* Block { slot, block_id } payload */
    if( FD_UNLIKELY( in_sz<off+40UL ) ) return FD_CERT_DE_ERR_TRUNCATED;
    slot = FD_LOAD( ulong, in+off ); off += 8UL;
    fd_memcpy( block_hash.uc, in+off, sizeof(fd_hash_t) ); off += sizeof(fd_hash_t);
    break;
  default:
    return FD_CERT_DE_ERR_MALFORMED;
  }

  /* genesis is not yet supported. */
  if( tag==FD_CERT_TYPE_GENESIS ) return FD_CERT_DE_ERR_UNSUPPORTED;

  if( FD_UNLIKELY( in_sz<off+FD_AGGSIG_SIG_SZ ) ) return FD_CERT_DE_ERR_TRUNCATED;
  uchar const * sig = in+off; off += FD_AGGSIG_SIG_SZ;

  /* bitmap: wincode Vec<u8> = u64 LE length prefix + bytes */
  if( FD_UNLIKELY( in_sz<off+8UL ) ) return FD_CERT_DE_ERR_TRUNCATED;
  ulong bm_len = FD_LOAD( ulong, in+off ); off += 8UL;
  if( FD_UNLIKELY( in_sz<off+bm_len ) ) return FD_CERT_DE_ERR_TRUNCATED;
  uchar const * bm = in+off;

  fd_memset( out, 0, sizeof(fd_cert_t) );
  int err;
  switch( tag ) {
  case FD_CERT_TYPE_FINAL:
    out->discriminant      = FD_CERT_TYPE_FINAL;
    out->inner.final_.slot = slot;
    err = de_base2_bitmap(  &out->inner.final_.agg_sig, bm, bm_len );
    if( FD_UNLIKELY( err ) ) return err;
    fd_memcpy( out->inner.final_.agg_sig.sig, sig, FD_AGGSIG_SIG_SZ ); /* after init zeroed it */
    break;
  case FD_CERT_TYPE_FAST_FINAL:
    out->discriminant                = FD_CERT_TYPE_FAST_FINAL;
    out->inner.fast_final.slot       = slot;
    out->inner.fast_final.block_hash = block_hash;
    err = de_base2_bitmap(  &out->inner.fast_final.agg_sig, bm, bm_len );
    if( FD_UNLIKELY( err ) ) return err;
    fd_memcpy( out->inner.fast_final.agg_sig.sig, sig, FD_AGGSIG_SIG_SZ ); /* after init zeroed it */
    break;
  case FD_CERT_TYPE_NOTAR:
    out->discriminant           = FD_CERT_TYPE_NOTAR;
    out->inner.notar.slot       = slot;
    out->inner.notar.block_hash = block_hash;
    err = de_base2_bitmap(  &out->inner.notar.agg_sig, bm, bm_len );
    if( FD_UNLIKELY( err ) ) return err;
    fd_memcpy( out->inner.notar.agg_sig.sig, sig, FD_AGGSIG_SIG_SZ ); /* after init zeroed it */
    break;
  case FD_CERT_TYPE_NOTAR_FALLBACK: {
    /* mixed cert with no fallback voters is encoded Base2; otherwise
       Base3 (both sets).  Dispatch on the version byte.  On the Base2
       path leave the fallback set empty */
    fd_aggsig_t * b = &out->inner.notar_fallback.agg_sig_notar;
    fd_aggsig_t * f = &out->inner.notar_fallback.agg_sig_notar_fallback;
    out->discriminant                    = FD_CERT_TYPE_NOTAR_FALLBACK;
    out->inner.notar_fallback.slot       = slot;
    out->inner.notar_fallback.block_hash = block_hash;
    if( FD_UNLIKELY( bm_len<1UL ) ) return FD_CERT_DE_ERR_TRUNCATED;
    if( bm[0]==0 ) { err = de_base2_bitmap( b, bm, bm_len );    if( FD_UNLIKELY( err ) ) return err; fd_aggsig_init( f, b->nbits ); }
    else           { err = de_base3_bitmap( b, f, bm, bm_len ); if( FD_UNLIKELY( err ) ) return err; }
    fd_memcpy( b->sig, sig, FD_AGGSIG_SIG_SZ ); /* one wire sig, put in the base agg. TODO consider just a diff aggsig type for the fallback */
    break;
  }
  case FD_CERT_TYPE_SKIP: {
    fd_aggsig_t * b = &out->inner.skip.agg_sig_skip;
    fd_aggsig_t * f = &out->inner.skip.agg_sig_skip_fallback;
    out->discriminant    = FD_CERT_TYPE_SKIP;
    out->inner.skip.slot = slot;
    if( FD_UNLIKELY( bm_len<1UL ) ) return FD_CERT_DE_ERR_TRUNCATED;
    if( bm[0]==0 ) { err = de_base2_bitmap( b, bm, bm_len );    if( FD_UNLIKELY( err ) ) return err; fd_aggsig_init( f, b->nbits ); }
    else           { err = de_base3_bitmap( b, f, bm, bm_len ); if( FD_UNLIKELY( err ) ) return err; }
    fd_memcpy( b->sig, sig, FD_AGGSIG_SIG_SZ );
    break;
  }
  default:
    return FD_CERT_DE_ERR_MALFORMED;
  }

  return FD_CERT_DE_SUCCESS;
}
