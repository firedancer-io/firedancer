#include "ag_cert.h"

#if FD_HAS_BLST
#include "../../ballet/bls/fd_bls12_381.h"
#endif

static void
agg_notar( ag_aggsig_t *           a,
           ag_notar_vote_t const * v,
           ulong                   n,
           ulong                   nbits ) {
  ag_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) ag_aggsig_add( a, v[i].signer, &v[i].sig );
}
static void
agg_nf( ag_aggsig_t *                    a,
        ag_notar_fallback_vote_t const * v,
        ulong                            n,
        ulong                            nbits ) {
  ag_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) ag_aggsig_add( a, v[i].signer, &v[i].sig );
}
static void
agg_skip( ag_aggsig_t *          a,
          ag_skip_vote_t const * v,
          ulong                  n,
          ulong                  nbits ) {
  ag_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) ag_aggsig_add( a, v[i].signer, &v[i].sig );
}
static void
agg_sf( ag_aggsig_t *                   a,
        ag_skip_fallback_vote_t const * v,
        ulong                           n,
        ulong                           nbits ) {
  ag_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) ag_aggsig_add( a, v[i].signer, &v[i].sig );
}
static void
agg_final( ag_aggsig_t *           a,
           ag_final_vote_t const * v,
           ulong                   n,
           ulong                   nbits ) {
  ag_aggsig_init( a, nbits ); for( ulong i=0UL; i<n; i++ ) ag_aggsig_add( a, v[i].signer, &v[i].sig );
}

static inline int
hash_eq( fd_hash_t const * a,
         fd_hash_t const * b ) {
  return 0==memcmp( a->uc, b->uc, sizeof(fd_hash_t) );
}

int
ag_notar_cert_try_new( ag_notar_cert_t *           out,
                       ag_notar_vote_t const *     votes,
                       ulong                       vote_cnt,
                       ag_validator_info_t const * validators,
                       ulong                       validator_cnt ) {
  FD_TEST( vote_cnt>0UL );
  ulong       slot = votes[0].slot;
  fd_hash_t   bh   = votes[0].block_hash;
  ulong       stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    if( FD_UNLIKELY( votes[i].slot!=slot              ) ) return AG_CERT_ERR_SLOT_MISMATCH;
    if( FD_UNLIKELY( !hash_eq( &votes[i].block_hash, &bh ) ) ) return AG_CERT_ERR_BLOCK_HASH_MISMATCH;
    stake += validators[ votes[i].signer ].stake;
  }
  out->slot = slot; out->block_hash = bh; out->stake = stake;
  agg_notar( &out->agg_sig, votes, vote_cnt, validator_cnt );
  return AG_CERT_SUCCESS;
}

int
ag_fast_final_cert_try_new( ag_fast_final_cert_t *      out,
                            ag_notar_vote_t const *     votes,
                            ulong                       vote_cnt,
                            ag_validator_info_t const * validators,
                            ulong                       validator_cnt ) {
  FD_TEST( vote_cnt>0UL );
  ulong       slot = votes[0].slot;
  fd_hash_t   bh   = votes[0].block_hash;
  ulong       stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    if( FD_UNLIKELY( votes[i].slot!=slot              ) ) return AG_CERT_ERR_SLOT_MISMATCH;
    if( FD_UNLIKELY( !hash_eq( &votes[i].block_hash, &bh ) ) ) return AG_CERT_ERR_BLOCK_HASH_MISMATCH;
    stake += validators[ votes[i].signer ].stake;
  }
  out->slot = slot; out->block_hash = bh; out->stake = stake;
  agg_notar( &out->agg_sig, votes, vote_cnt, validator_cnt );
  return AG_CERT_SUCCESS;
}

int
ag_final_cert_try_new( ag_final_cert_t *           out,
                       ag_final_vote_t const *     votes,
                       ulong                       vote_cnt,
                       ag_validator_info_t const * validators,
                       ulong                       validator_cnt ) {
  FD_TEST( vote_cnt>0UL );
  ulong slot = votes[0].slot;
  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    if( FD_UNLIKELY( votes[i].slot!=slot ) ) return AG_CERT_ERR_SLOT_MISMATCH;
    stake += validators[ votes[i].signer ].stake;
  }
  out->slot = slot; out->stake = stake;
  agg_final( &out->agg_sig, votes, vote_cnt, validator_cnt );
  return AG_CERT_SUCCESS;
}

int
ag_notar_fallback_cert_try_new( ag_notar_fallback_cert_t *       out,
                                ag_notar_vote_t const *          notar_votes,
                                ulong                            notar_cnt,
                                ag_notar_fallback_vote_t const * nf_votes,
                                ulong                            nf_cnt,
                                ag_validator_info_t const *      validators,
                                ulong                            validator_cnt ) {
  FD_TEST( notar_cnt>0UL || nf_cnt>0UL );
  ulong     slot;
  fd_hash_t bh;
  if( notar_cnt>0UL ) { slot = notar_votes[0].slot; bh = notar_votes[0].block_hash; }
  else                { slot = nf_votes[0].slot;    bh = nf_votes[0].block_hash;    }

  ulong stake = 0UL;
  for( ulong i=0UL; i<notar_cnt; i++ ) {
    if( FD_UNLIKELY( notar_votes[i].slot!=slot              ) ) return AG_CERT_ERR_SLOT_MISMATCH;
    if( FD_UNLIKELY( !hash_eq( &notar_votes[i].block_hash, &bh ) ) ) return AG_CERT_ERR_BLOCK_HASH_MISMATCH;
    stake += validators[ notar_votes[i].signer ].stake;
  }
  for( ulong i=0UL; i<nf_cnt; i++ ) {
    if( FD_UNLIKELY( nf_votes[i].slot!=slot              ) ) return AG_CERT_ERR_SLOT_MISMATCH;
    if( FD_UNLIKELY( !hash_eq( &nf_votes[i].block_hash, &bh ) ) ) return AG_CERT_ERR_BLOCK_HASH_MISMATCH;
    stake += validators[ nf_votes[i].signer ].stake;
  }

  out->slot = slot; out->block_hash = bh; out->stake = stake;
  if( notar_cnt>0UL ) agg_notar     ( &out->agg_sig_notar, notar_votes, notar_cnt, validator_cnt );
  else                ag_aggsig_init( &out->agg_sig_notar, validator_cnt );
  if( nf_cnt   >0UL ) agg_nf        ( &out->agg_sig_notar_fallback, nf_votes, nf_cnt, validator_cnt );
  else                ag_aggsig_init( &out->agg_sig_notar_fallback, validator_cnt );
  ag_aggsig_merge_sig( &out->agg_sig_notar, &out->agg_sig_notar_fallback );
  return AG_CERT_SUCCESS;
}

int
ag_skip_cert_try_new( ag_skip_cert_t *                out,
                      ag_skip_vote_t const *          skip_votes,
                      ulong                           skip_cnt,
                      ag_skip_fallback_vote_t const * sf_votes,
                      ulong                           sf_cnt,
                      ag_validator_info_t const *     validators,
                      ulong                           validator_cnt ) {
  FD_TEST( skip_cnt>0UL || sf_cnt>0UL );
  ulong slot = skip_cnt>0UL ? skip_votes[0].slot : sf_votes[0].slot;

  ulong stake = 0UL;
  for( ulong i=0UL; i<skip_cnt; i++ ) {
    if( FD_UNLIKELY( skip_votes[i].slot!=slot ) ) return AG_CERT_ERR_SLOT_MISMATCH;
    stake += validators[ skip_votes[i].signer ].stake;
  }
  for( ulong i=0UL; i<sf_cnt; i++ ) {
    if( FD_UNLIKELY( sf_votes[i].slot!=slot ) ) return AG_CERT_ERR_SLOT_MISMATCH;
    stake += validators[ sf_votes[i].signer ].stake;
  }

  out->slot = slot; out->stake = stake;
  if( skip_cnt>0UL ) agg_skip      ( &out->agg_sig_skip, skip_votes, skip_cnt, validator_cnt );
  else               ag_aggsig_init( &out->agg_sig_skip, validator_cnt );
  if( sf_cnt  >0UL ) agg_sf        ( &out->agg_sig_skip_fallback, sf_votes, sf_cnt, validator_cnt );
  else               ag_aggsig_init( &out->agg_sig_skip_fallback, validator_cnt );
  ag_aggsig_merge_sig( &out->agg_sig_skip, &out->agg_sig_skip_fallback );
  return AG_CERT_SUCCESS;
}

static ulong
agg_stake( ag_aggsig_t const *         agg,
           ag_validator_info_t const * validators,
           ulong                       validator_cnt ) {
  ulong stake = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) if( ag_aggsig_is_signer( agg, i ) ) stake += validators[i].stake;
  return stake;
}

void
ag_notar_cert_from_agg( ag_notar_cert_t *           out,
                        ulong                       slot,
                        fd_hash_t const *           block_hash,
                        ag_aggsig_t const *         agg,
                        ag_validator_info_t const * validators,
                        ulong                       validator_cnt ) {
  out->slot       = slot;
  out->block_hash = *block_hash;
  out->agg_sig    = *agg;
  out->stake      = agg_stake( agg, validators, validator_cnt );
}

void
ag_fast_final_cert_from_agg( ag_fast_final_cert_t *      out,
                             ulong                       slot,
                             fd_hash_t const *           block_hash,
                             ag_aggsig_t const *         agg,
                             ag_validator_info_t const * validators,
                             ulong                       validator_cnt ) {
  out->slot       = slot;
  out->block_hash = *block_hash;
  out->agg_sig    = *agg;
  out->stake      = agg_stake( agg, validators, validator_cnt );
}

void
ag_final_cert_from_agg( ag_final_cert_t *           out,
                        ulong                       slot,
                        ag_aggsig_t const *         agg,
                        ag_validator_info_t const * validators,
                        ulong                       validator_cnt ) {
  out->slot    = slot;
  out->agg_sig = *agg;
  out->stake   = agg_stake( agg, validators, validator_cnt );
}

void
ag_notar_fallback_cert_from_aggs( ag_notar_fallback_cert_t *  out,
                                  ulong                       slot,
                                  fd_hash_t const *           block_hash,
                                  ag_aggsig_t const *         notar_agg,
                                  ag_aggsig_t const *         nf_agg,
                                  ag_validator_info_t const * validators,
                                  ulong                       validator_cnt ) {
  FD_TEST( notar_agg || nf_agg );
  out->slot       = slot;
  out->block_hash = *block_hash;
  if( notar_agg ) out->agg_sig_notar          = *notar_agg; else ag_aggsig_init( &out->agg_sig_notar,          validator_cnt );
  if( nf_agg    ) out->agg_sig_notar_fallback = *nf_agg;    else ag_aggsig_init( &out->agg_sig_notar_fallback, validator_cnt );
  out->stake = agg_stake( &out->agg_sig_notar,          validators, validator_cnt )
             + agg_stake( &out->agg_sig_notar_fallback, validators, validator_cnt );
  ag_aggsig_merge_sig( &out->agg_sig_notar, &out->agg_sig_notar_fallback );
}

void
ag_skip_cert_from_aggs( ag_skip_cert_t *            out,
                        ulong                       slot,
                        ag_aggsig_t const *         skip_agg,
                        ag_aggsig_t const *         sf_agg,
                        ag_validator_info_t const * validators,
                        ulong                       validator_cnt ) {
  out->slot                  = slot;
  out->agg_sig_skip          = *skip_agg;
  out->agg_sig_skip_fallback = *sf_agg;
  out->stake = agg_stake( skip_agg, validators, validator_cnt )
             + agg_stake( sf_agg,   validators, validator_cnt );
  ag_aggsig_merge_sig( &out->agg_sig_skip, &out->agg_sig_skip_fallback );
}

ulong
ag_cert_slot( ag_cert_t const * self ) {
  switch( self->kind ) {
  case AG_CERT_TYPE_NOTAR:          return self->inner.notar.slot;
  case AG_CERT_TYPE_NOTAR_FALLBACK: return self->inner.notar_fallback.slot;
  case AG_CERT_TYPE_SKIP:           return self->inner.skip.slot;
  case AG_CERT_TYPE_FAST_FINAL:     return self->inner.fast_final.slot;
  default:                          return self->inner.final.slot;
  }
}

ulong
ag_cert_stake( ag_cert_t const * self ) {
  switch( self->kind ) {
  case AG_CERT_TYPE_NOTAR:          return self->inner.notar.stake;
  case AG_CERT_TYPE_NOTAR_FALLBACK: return self->inner.notar_fallback.stake;
  case AG_CERT_TYPE_SKIP:           return self->inner.skip.stake;
  case AG_CERT_TYPE_FAST_FINAL:     return self->inner.fast_final.stake;
  default:                          return self->inner.final.stake;
  }
}

fd_hash_t const *
ag_cert_block_hash( ag_cert_t const * self ) {
  switch( self->kind ) {
  case AG_CERT_TYPE_NOTAR:          return &self->inner.notar.block_hash;
  case AG_CERT_TYPE_NOTAR_FALLBACK: return &self->inner.notar_fallback.block_hash;
  case AG_CERT_TYPE_FAST_FINAL:     return &self->inner.fast_final.block_hash;
  default:                          return NULL;
  }
}

int
ag_cert_is_signer( ag_cert_t const * self,
                   ulong             v ) {
  switch( self->kind ) {
  case AG_CERT_TYPE_NOTAR:      return ag_aggsig_is_signer( &self->inner.notar.agg_sig, v );
  case AG_CERT_TYPE_FAST_FINAL: return ag_aggsig_is_signer( &self->inner.fast_final.agg_sig, v );
  case AG_CERT_TYPE_FINAL:      return ag_aggsig_is_signer( &self->inner.final.agg_sig, v );
  case AG_CERT_TYPE_NOTAR_FALLBACK: {
    ag_notar_fallback_cert_t const * n = &self->inner.notar_fallback;
    return ag_aggsig_is_signer( &n->agg_sig_notar, v ) || ag_aggsig_is_signer( &n->agg_sig_notar_fallback, v );
  }
  default: {
    ag_skip_cert_t const * s = &self->inner.skip;
    return ag_aggsig_is_signer( &s->agg_sig_skip, v ) || ag_aggsig_is_signer( &s->agg_sig_skip_fallback, v );
  }
  }
}

static ulong
signed_stake( ag_cert_t const *       self,
              ag_epoch_info_t const * ei ) {
  ag_validator_info_t const * v = ag_epoch_info_validators( ei );
  ulong stake = 0UL;
  for( ulong i=0UL; i<ei->validator_cnt; i++ ) if( ag_cert_is_signer( self, v[i].id ) ) stake += v[i].stake;
  return stake;
}

int
ag_cert_check_threshold( ag_cert_t const *       self,
                         ag_epoch_info_t const * ei ) {
  ulong stake = signed_stake( self, ei );
  int   ok    = self->kind==AG_CERT_TYPE_FAST_FINAL ? ag_epoch_info_is_strong_quorum( ei, stake )
                                                    : ag_epoch_info_is_quorum( ei, stake );
  /* A cert that fails here is usually a validator-set mismatch (missing
     BLS keys, or the wrong epoch), not a malicious peer. */
  if( FD_UNLIKELY( !ok ) ) {
    FD_LOG_DEBUG(( "AGDBG ag_cert/check_threshold kind=%u slot=%lu signed_stake=%lu total_stake=%lu validators=%lu FAILED",
                   (uint)self->kind, ag_cert_slot( self ), stake, ei->total_stake, ei->validator_cnt ));
  }
  return ok;
}

int
ag_cert_check_sig( ag_cert_t const *       self,
                   ushort                  shred_version,
                   ag_epoch_info_t const * epoch_info ) {
  ag_aggsig_pk_t const * pks           = ag_epoch_info_voting_pubkeys( epoch_info );
  ulong                  validator_cnt = epoch_info->validator_cnt;
  uchar buf[ AG_VOTE_PAYLOAD_MAX ];
  ulong sz;
  switch( self->kind ) {
  case AG_CERT_TYPE_NOTAR:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_NOTAR, self->inner.notar.slot, &self->inner.notar.block_hash, shred_version );
    return ag_aggsig_verify_bytes( &self->inner.notar.agg_sig, buf, sz, pks, validator_cnt );
  case AG_CERT_TYPE_FAST_FINAL:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_NOTAR, self->inner.fast_final.slot, &self->inner.fast_final.block_hash, shred_version );
    return ag_aggsig_verify_bytes( &self->inner.fast_final.agg_sig, buf, sz, pks, validator_cnt );
  case AG_CERT_TYPE_FINAL:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_FINAL, self->inner.final.slot, NULL, shred_version );
    return ag_aggsig_verify_bytes( &self->inner.final.agg_sig, buf, sz, pks, validator_cnt );
  case AG_CERT_TYPE_NOTAR_FALLBACK: {

    ag_notar_fallback_cert_t const * n = &self->inner.notar_fallback;
    uchar buf_fb[ AG_VOTE_PAYLOAD_MAX ]; ulong sz_fb;
    sz    = ag_vote_payload_bytes_to_sign( buf,    AG_VOTE_TYPE_NOTAR,          n->slot, &n->block_hash, shred_version );
    sz_fb = ag_vote_payload_bytes_to_sign( buf_fb, AG_VOTE_TYPE_NOTAR_FALLBACK, n->slot, &n->block_hash, shred_version );
    return ag_aggsig_verify_mixed_bytes( &n->agg_sig_notar,          buf,    sz,
                                         &n->agg_sig_notar_fallback, buf_fb, sz_fb,
                                         pks, validator_cnt );
  }
  default: {
    ag_skip_cert_t const * s = &self->inner.skip;
    uchar buf_fb[ AG_VOTE_PAYLOAD_MAX ]; ulong sz_fb;
    sz    = ag_vote_payload_bytes_to_sign( buf,    AG_VOTE_TYPE_SKIP,          s->slot, NULL, shred_version );
    sz_fb = ag_vote_payload_bytes_to_sign( buf_fb, AG_VOTE_TYPE_SKIP_FALLBACK, s->slot, NULL, shred_version );
    return ag_aggsig_verify_mixed_bytes( &s->agg_sig_skip,          buf,    sz,
                                         &s->agg_sig_skip_fallback, buf_fb, sz_fb,
                                         pks, validator_cnt );
  }
  }
}

/* deserializers */

/* Returns AG_CERT_DE_ERR_TRUNCATED on underflow. */

#define READ_U8( dst, data, sz ) do {                               \
  if( FD_UNLIKELY( 1UL>(*(sz)) ) ) return AG_CERT_DE_ERR_TRUNCATED; \
  (dst) = FD_LOAD( uchar, *(data) );                                \
  *(data) += 1UL;                                                   \
  *(sz)   -= 1UL;                                                   \
} while( 0 )

#define READ_U16( dst, data, sz ) do {                              \
  if( FD_UNLIKELY( 2UL>(*(sz)) ) ) return AG_CERT_DE_ERR_TRUNCATED; \
  (dst) = FD_LOAD( ushort, *(data) );                               \
  *(data) += 2UL;                                                   \
  *(sz)   -= 2UL;                                                   \
} while( 0 )

#define READ_U32( dst, data, sz ) do {                              \
  if( FD_UNLIKELY( 4UL>(*(sz)) ) ) return AG_CERT_DE_ERR_TRUNCATED; \
  (dst) = FD_LOAD( uint, *(data) );                                 \
  *(data) += 4UL;                                                   \
  *(sz)   -= 4UL;                                                   \
} while( 0 )

#define READ_U64( dst, data, sz ) do {                              \
  if( FD_UNLIKELY( 8UL>(*(sz)) ) ) return AG_CERT_DE_ERR_TRUNCATED; \
  (dst) = FD_LOAD( ulong, *(data) );                                \
  *(data) += 8UL;                                                   \
  *(sz)   -= 8UL;                                                   \
} while( 0 )

#define READ_HASH( dst, data, sz ) do {                                           \
  if( FD_UNLIKELY( sizeof(fd_hash_t)>(*(sz)) ) ) return AG_CERT_DE_ERR_TRUNCATED; \
  fd_memcpy( (dst).uc, *(data), sizeof(fd_hash_t) );                              \
  *(data) += sizeof(fd_hash_t);                                                   \
  *(sz)   -= sizeof(fd_hash_t);                                                   \
} while( 0 )

#define SKIP_BYTES( n, data, sz ) do {                              \
  if( FD_UNLIKELY( (n)>(*(sz)) ) ) return AG_CERT_DE_ERR_TRUNCATED; \
  *(data) += (n);                                                   \
  *(sz)   -= (n);                                                   \
} while( 0 )

/* Bitmap version bytes */

#define BASE2_BITMAP (0)
#define BASE3_BITMAP (1)

static int
de_base2_bitmap( ag_aggsig_t * agg,
                 uchar const * b,
                 ulong         b_sz ) {
  uchar  version;
  ushort nbits;
  READ_U8 ( version, &b, &b_sz );
  READ_U16( nbits,   &b, &b_sz );
  if( FD_UNLIKELY( version!=BASE2_BITMAP              ) ) return AG_CERT_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( (ulong)nbits>AG_AGGSIG_MAX_SIGNERS ) ) return AG_CERT_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( b_sz!=((ulong)nbits+7UL)/8UL       ) ) return AG_CERT_DE_ERR_MALFORMED; /* exact payload sz */

  ag_aggsig_init( agg, (ulong)nbits ); /* sets nbits, zeroes bitmask and sig */

  for( ulong i=0UL; i<(ulong)nbits; i++ ) {
    if( (b[ i>>3 ] >> (i&7U)) & 1U ) signer_set_insert( agg->bitmask, i );
  }
  return AG_CERT_DE_SUCCESS;
}

static int
de_base3_bitmap( ag_aggsig_t * base,
                 ag_aggsig_t * fb,
                 uchar const * b,
                 ulong         b_sz ) {
  uchar  version;
  ushort nbits;
  READ_U8 ( version, &b, &b_sz );
  READ_U16( nbits,   &b, &b_sz );
  if( FD_UNLIKELY( version!=BASE3_BITMAP              ) ) return AG_CERT_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( (ulong)nbits>AG_AGGSIG_MAX_SIGNERS ) ) return AG_CERT_DE_ERR_MALFORMED;
  ulong nchunks = ((ulong)nbits+4UL)/5UL;
  if( FD_UNLIKELY( b_sz!=nchunks                      ) ) return AG_CERT_DE_ERR_MALFORMED; /* exact payload sz */

  ag_aggsig_init( base, (ulong)nbits );
  ag_aggsig_init( fb,   (ulong)nbits );

  for( ulong chunk=0UL; chunk<nchunks; chunk++ ) {
    uint  block = (uint)b[ chunk ];
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, (ulong)nbits );
    for( ulong i=start; i<end; i++ ) {
      uint digit = block % 3U; block /= 3U;
      if(      digit==1U ) signer_set_insert( base->bitmask, i );
      else if( digit==2U ) signer_set_insert( fb->bitmask,   i );
    }
  }
  return AG_CERT_DE_SUCCESS;
}

int
ag_cert_de( ag_cert_t *   out,
            uint          tag,
            uchar const * in,
            ulong         in_sz,
            ulong *       opt_consumed ) {
  ulong remaining = in_sz;

  /* genesis is not yet supported. */
  if( tag==AG_CERT_TYPE_GENESIS ) return AG_CERT_DE_ERR_UNSUPPORTED;

  ulong     slot = 0UL;
  fd_hash_t block_hash;
  fd_memset( &block_hash, 0, sizeof(fd_hash_t) );

  switch( tag ) {
  case AG_CERT_TYPE_FINAL:
  case AG_CERT_TYPE_SKIP:               /* slot-only payload */
    READ_U64( slot, &in, &remaining );
    break;
  case AG_CERT_TYPE_FAST_FINAL:
  case AG_CERT_TYPE_NOTAR:
  case AG_CERT_TYPE_NOTAR_FALLBACK:     /* slot + block_id payload */
    READ_U64( slot, &in, &remaining );
    READ_HASH( block_hash, &in, &remaining );
    break;
  default:
    return AG_CERT_DE_ERR_MALFORMED;
  }

  uchar const * sig = in;
  SKIP_BYTES( AG_AGGSIG_SIG_SZ, &in, &remaining );

  /* bitmap: u64 LE length prefix + bytes */
  ulong bm_len;
  READ_U64( bm_len, &in, &remaining );
  uchar const * bm = in;
  SKIP_BYTES( bm_len, &in, &remaining );

  fd_memset( out, 0, sizeof(ag_cert_t) );
  int err;
  switch( tag ) {
  case AG_CERT_TYPE_FINAL:
    out->kind             = AG_CERT_TYPE_FINAL;
    out->inner.final.slot = slot;
    if( FD_UNLIKELY( err = de_base2_bitmap(  &out->inner.final.agg_sig, bm, bm_len ) ) ) return err;
    fd_memcpy( out->inner.final.agg_sig.sig, sig, AG_AGGSIG_SIG_SZ ); /* after init zeroed it */
    break;
  case AG_CERT_TYPE_FAST_FINAL:
    out->kind                        = AG_CERT_TYPE_FAST_FINAL;
    out->inner.fast_final.slot       = slot;
    out->inner.fast_final.block_hash = block_hash;
    if( FD_UNLIKELY( err = de_base2_bitmap(  &out->inner.fast_final.agg_sig, bm, bm_len ) ) ) return err;
    fd_memcpy( out->inner.fast_final.agg_sig.sig, sig, AG_AGGSIG_SIG_SZ ); /* after init zeroed it */
    break;
  case AG_CERT_TYPE_NOTAR:
    out->kind                   = AG_CERT_TYPE_NOTAR;
    out->inner.notar.slot       = slot;
    out->inner.notar.block_hash = block_hash;
    if( FD_UNLIKELY( err = de_base2_bitmap(  &out->inner.notar.agg_sig, bm, bm_len ) ) ) return err;
    fd_memcpy( out->inner.notar.agg_sig.sig, sig, AG_AGGSIG_SIG_SZ ); /* after init zeroed it */
    break;
  case AG_CERT_TYPE_NOTAR_FALLBACK: {
    /* mixed cert with no fallback voters is encoded Base2; otherwise
        Base3 (both sets).  Dispatch on the version byte.  On the Base2
        path leave the fallback set empty */
    ag_aggsig_t * b = &out->inner.notar_fallback.agg_sig_notar;
    ag_aggsig_t * f = &out->inner.notar_fallback.agg_sig_notar_fallback;
    out->kind                            = AG_CERT_TYPE_NOTAR_FALLBACK;
    out->inner.notar_fallback.slot       = slot;
    out->inner.notar_fallback.block_hash = block_hash;
    if( FD_UNLIKELY( bm_len<1UL ) ) return AG_CERT_DE_ERR_TRUNCATED;
    if( bm[0]==BASE2_BITMAP ) { if( FD_UNLIKELY( err = de_base2_bitmap( b,    bm, bm_len ) ) ) return err; ag_aggsig_init( f, b->nbits ); }
    else                      { if( FD_UNLIKELY( err = de_base3_bitmap( b, f, bm, bm_len ) ) ) return err; }
    fd_memcpy( b->sig, sig, AG_AGGSIG_SIG_SZ ); /* one wire sig, put in the base agg. TODO consider just a diff aggsig type for the fallback */
    break;
  }
  case AG_CERT_TYPE_SKIP: {
    ag_aggsig_t * b = &out->inner.skip.agg_sig_skip;
    ag_aggsig_t * f = &out->inner.skip.agg_sig_skip_fallback;
    out->kind            = AG_CERT_TYPE_SKIP;
    out->inner.skip.slot = slot;
    if( FD_UNLIKELY( bm_len<1UL ) ) return AG_CERT_DE_ERR_TRUNCATED;
    if( bm[0]==BASE2_BITMAP ) { if( FD_UNLIKELY( err = de_base2_bitmap( b,    bm, bm_len ) ) ) return err; ag_aggsig_init( f, b->nbits ); }
    else                      { if( FD_UNLIKELY( err = de_base3_bitmap( b, f, bm, bm_len ) ) ) return err; }
    fd_memcpy( b->sig, sig, AG_AGGSIG_SIG_SZ );
    break;
  }
  default:
    return AG_CERT_DE_ERR_MALFORMED;
  }

  if( opt_consumed ) *opt_consumed = in_sz - remaining;

  return AG_CERT_DE_SUCCESS;
}

/* de_footer_aggregate parses one footer votes aggregate (96B compressed
   G2 signature + length-prefixed base2 bitmap) at in[0,in_sz) into agg.
   The signature bytes remain compressed. */

static int
de_footer_aggregate( ag_aggsig_t * agg,
                     uchar const * in,
                     ulong         in_sz,
                     ulong *       consumed ) {
  ulong remaining = in_sz;

  uchar const * csig = in;
  SKIP_BYTES( AG_AGGSIG_SIG_COMPRESSED_SZ, &in, &remaining );

  ushort bm_len;
  READ_U16( bm_len, &in, &remaining );

  uchar const * bm = in;
  SKIP_BYTES( bm_len, &in, &remaining );

  int err = de_base2_bitmap( agg, bm, bm_len );  if( FD_UNLIKELY( err ) ) return err;
  fd_memcpy( agg->sig, csig, AG_AGGSIG_SIG_COMPRESSED_SZ );
  *consumed = in_sz - remaining;
  return AG_CERT_DE_SUCCESS;
}

int
ag_block_final_cert_de( ag_cert_t     out[ 2 ],
                        ulong *       out_cert_cnt,
                        uchar const * in,
                        ulong         in_sz ) {
  ulong remaining = in_sz;
  ulong slot;  fd_hash_t block_hash;
  READ_U64( slot, &in, &remaining );
  READ_HASH( block_hash, &in, &remaining );

  ag_aggsig_t final_agg[1];
  ulong       consumed;
  int err = de_footer_aggregate( final_agg, in, remaining, &consumed );
  if( FD_UNLIKELY( err ) ) return err;
  SKIP_BYTES( consumed, &in, &remaining );

  uchar has_notar;
  READ_U8( has_notar, &in, &remaining );
  if( FD_UNLIKELY( has_notar>1 ) ) return AG_CERT_DE_ERR_MALFORMED;

  fd_memset( out, 0, 2UL*sizeof(ag_cert_t) );
  if( has_notar ) {
    /* Slow finalization: a final cert over the slot plus a notar cert
       over the block. */
    ag_aggsig_t notar_agg[1];
    err = de_footer_aggregate( notar_agg, in, remaining, &consumed );
    if( FD_UNLIKELY( err ) ) return err;
    out[0].kind                   = AG_CERT_TYPE_FINAL;
    out[0].inner.final.slot       = slot;
    out[0].inner.final.agg_sig    = *final_agg;
    out[1].kind                   = AG_CERT_TYPE_NOTAR;
    out[1].inner.notar.slot       = slot;
    out[1].inner.notar.block_hash = block_hash;
    out[1].inner.notar.agg_sig    = *notar_agg;
    *out_cert_cnt = 2UL;
  } else {
    /* Fast finalization: a single fast final cert. */
    out[0].kind                        = AG_CERT_TYPE_FAST_FINAL;
    out[0].inner.fast_final.slot       = slot;
    out[0].inner.fast_final.block_hash = block_hash;
    out[0].inner.fast_final.agg_sig    = *final_agg;
    *out_cert_cnt = 1UL;
  }
  return AG_CERT_DE_SUCCESS;
}

int
ag_block_final_cert_decompress( ag_cert_t * certs,
                                ulong       cert_cnt ) {
#if FD_HAS_BLST
  for( ulong i=0UL; i<cert_cnt; i++ ) {
    ag_aggsig_t * agg;
    switch( certs[ i ].kind ) {
    case AG_CERT_TYPE_FINAL:      agg = &certs[ i ].inner.final.agg_sig;      break;
    case AG_CERT_TYPE_FAST_FINAL: agg = &certs[ i ].inner.fast_final.agg_sig; break;
    case AG_CERT_TYPE_NOTAR:      agg = &certs[ i ].inner.notar.agg_sig;      break;
    default: return AG_CERT_DE_ERR_MALFORMED;
    }
    uchar csig[ AG_AGGSIG_SIG_COMPRESSED_SZ ];
    fd_memcpy( csig, agg->sig, AG_AGGSIG_SIG_COMPRESSED_SZ );
    if( FD_UNLIKELY( fd_bls12_381_g2_decompress_syscall( agg->sig, csig, 1 /* big endian */ ) ) ) return AG_CERT_DE_ERR_MALFORMED;
  }
#else
  (void)certs; (void)cert_cnt;
#endif
  return AG_CERT_DE_SUCCESS;
}

/* serializers (inverse of ag_cert_de) */

static ulong
ser_base2_bitmap( uchar *             out,
                  ag_aggsig_t const * agg ) {
  ulong nbits   = agg->nbits;
  ulong payload = (nbits+7UL)/8UL;
  ulong o       = 0UL;
  out[ o++ ] = (uchar)BASE2_BITMAP;
  FD_STORE( ushort, out+o, (ushort)nbits ); o += 2UL;
  fd_memset( out+o, 0, payload );
  for( ulong i=0UL; i<nbits; i++ ) {
    if( signer_set_test( agg->bitmask, i ) ) out[ o + (i>>3) ] |= (uchar)( 1U << (i&7U) );
  }
  return o + payload;
}

/* base-3 digits are packed least-significant-first within a chunk, matching
   de_base3_bitmap's repeated block%3 / block/=3. */

static ulong
ser_base3_bitmap( uchar *             out,
                  ag_aggsig_t const * base,
                  ag_aggsig_t const * fb ) {
  ulong nbits   = base->nbits;
  ulong nchunks = (nbits+4UL)/5UL;
  ulong o       = 0UL;
  out[ o++ ] = (uchar)BASE3_BITMAP;
  FD_STORE( ushort, out+o, (ushort)nbits ); o += 2UL;
  for( ulong chunk=0UL; chunk<nchunks; chunk++ ) {
    ulong start = chunk*5UL;
    ulong end   = fd_ulong_min( start+5UL, nbits );
    uint  block = 0U;
    uint  place = 1U;
    for( ulong i=start; i<end; i++ ) {
      uint digit = signer_set_test( base->bitmask, i ) ? 1U
                 : signer_set_test( fb->bitmask,   i ) ? 2U : 0U;
      block += digit*place;
      place *= 3U;
    }
    out[ o + chunk ] = (uchar)block;
  }
  return o + nchunks;
}

ulong
ag_cert_serialize( ag_cert_t const * self,
                   uchar *           out,
                   ulong             out_max,
                   ushort            shred_version ) {
  /* V1 wire consensus message: u8 version (1), u8 kind tag (kind+7),
     body (slot [+ block_id], 192B sig, u64 LE bitmap length, bitmap),
     u16 LE shred_version.  A mixed cert with no fallback signers is
     encoded Base2 like the single-set certs, matching what ag_cert_de
     accepts. */

  ag_aggsig_t const * base;
  ag_aggsig_t const * fb = NULL;
  fd_hash_t   const * hash = NULL;
  ulong               slot;
  switch( self->kind ) {
  case AG_CERT_TYPE_FINAL:
    slot = self->inner.final.slot;          base = &self->inner.final.agg_sig;
    break;
  case AG_CERT_TYPE_FAST_FINAL:
    slot = self->inner.fast_final.slot;     base = &self->inner.fast_final.agg_sig;
    hash = &self->inner.fast_final.block_hash;
    break;
  case AG_CERT_TYPE_NOTAR:
    slot = self->inner.notar.slot;          base = &self->inner.notar.agg_sig;
    hash = &self->inner.notar.block_hash;
    break;
  case AG_CERT_TYPE_NOTAR_FALLBACK:
    slot = self->inner.notar_fallback.slot; base = &self->inner.notar_fallback.agg_sig_notar;
    fb   = &self->inner.notar_fallback.agg_sig_notar_fallback;
    hash = &self->inner.notar_fallback.block_hash;
    break;
  case AG_CERT_TYPE_SKIP:
    slot = self->inner.skip.slot;           base = &self->inner.skip.agg_sig_skip;
    fb   = &self->inner.skip.agg_sig_skip_fallback;
    break;
  default:
    return 0UL; /* genesis has no wire form */
  }

  if( fb && !ag_aggsig_signer_cnt( fb ) ) fb = NULL;

  ulong bm_sz = fb ? ( 3UL + (base->nbits+4UL)/5UL )
                   : ( 3UL + (base->nbits+7UL)/8UL );
  ulong sz    = 2UL + 8UL + ( hash ? sizeof(fd_hash_t) : 0UL ) + AG_AGGSIG_SIG_SZ + 8UL + bm_sz + 2UL;
  if( FD_UNLIKELY( out_max<sz ) ) return 0UL;

  ulong o = 0UL;
  out[ o++ ] = (uchar)1;
  out[ o++ ] = (uchar)( self->kind+7U );
  FD_STORE( ulong, out+o, slot ); o += 8UL;
  if( hash ) { fd_memcpy( out+o, hash->uc, sizeof(fd_hash_t) ); o += sizeof(fd_hash_t); }
  fd_memcpy( out+o, base->sig, AG_AGGSIG_SIG_SZ ); o += AG_AGGSIG_SIG_SZ;
  FD_STORE( ulong, out+o, bm_sz ); o += 8UL;
  o += fb ? ser_base3_bitmap( out+o, base, fb ) : ser_base2_bitmap( out+o, base );
  FD_STORE( ushort, out+o, shred_version ); o += 2UL;

  FD_TEST( o==sz );
  return sz;
}

/* se_footer_aggregate is the inverse of de_footer_aggregate: writes a
   footer aggregate as

     compressed G2 sig (96) | bitmap len (u16 LE) | base2 bitmap

   where the base2 bitmap is solana_signer_store's encode_base2 form,
   a version byte (Base2 == 0), the bit count as a u16 LE, then the
   packed bits.  Returns the byte count, or 0 if out_max is too small or
   the signature is not a valid G2 point. */

static ulong
se_footer_aggregate( ag_aggsig_t const * agg,
                     uchar *             out,
                     ulong               out_max ) {
  ulong bm_bytes = ((ulong)agg->nbits+7UL)/8UL;
  ulong bm_len   = 1UL+2UL+bm_bytes;                    /* version + nbits + bits */
  ulong sz       = AG_AGGSIG_SIG_COMPRESSED_SZ+2UL+bm_len;
  if( FD_UNLIKELY( sz>out_max                        ) ) return 0UL;
  if( FD_UNLIKELY( agg->nbits>AG_AGGSIG_MAX_SIGNERS  ) ) return 0UL;
  if( FD_UNLIKELY( bm_len>USHORT_MAX                 ) ) return 0UL;

#if FD_HAS_BLST
  /* The in-memory aggregate holds an UNCOMPRESSED signature (that is
     what ag_block_final_cert_decompress leaves behind, and what
     verification needs); the footer carries the compressed form. */
  if( FD_UNLIKELY( fd_bls12_381_g2_compress_syscall( out, agg->sig, 1 /* big endian */ ) ) ) return 0UL;
#else
  (void)out;
  return 0UL;
#endif
  ulong o = AG_AGGSIG_SIG_COMPRESSED_SZ;

  FD_STORE( ushort, out+o, (ushort)bm_len ); o += 2UL;
  out[ o++ ] = (uchar)BASE2_BITMAP;
  FD_STORE( ushort, out+o, (ushort)agg->nbits ); o += 2UL;

  fd_memset( out+o, 0, bm_bytes );
  for( ulong i=0UL; i<agg->nbits; i++ ) {
    if( signer_set_test( agg->bitmask, i ) ) out[ o + (i>>3) ] = (uchar)( out[ o + (i>>3) ] | (uchar)(1U<<(i&7U)) );
  }
  o += bm_bytes;

  FD_TEST( o==sz );
  return sz;
}

ulong
ag_block_final_cert_se( ag_cert_t const * certs,
                        ulong             cert_cnt,
                        uchar *           out,
                        ulong             out_max ) {
  if( FD_UNLIKELY( !cert_cnt || cert_cnt>2UL ) ) return 0UL;

  /* Recover (slot, block_id, final aggregate, notar aggregate) from the
     cert shapes ag_block_final_cert_de produces. */
  ulong               slot;
  fd_hash_t const *   block_hash;
  ag_aggsig_t const * final_agg;
  ag_aggsig_t const * notar_agg = NULL;

  if( cert_cnt==2UL ) {
    /* Slow finalization: Final over the slot, Notar over the block. */
    if( FD_UNLIKELY( certs[0].kind!=AG_CERT_TYPE_FINAL ) ) return 0UL;
    if( FD_UNLIKELY( certs[1].kind!=AG_CERT_TYPE_NOTAR ) ) return 0UL;
    if( FD_UNLIKELY( certs[0].inner.final.slot!=certs[1].inner.notar.slot ) ) return 0UL;
    slot       = certs[0].inner.final.slot;
    block_hash = &certs[1].inner.notar.block_hash;
    final_agg  = &certs[0].inner.final.agg_sig;
    notar_agg  = &certs[1].inner.notar.agg_sig;
  } else {
    if( FD_UNLIKELY( certs[0].kind!=AG_CERT_TYPE_FAST_FINAL ) ) return 0UL;
    slot       = certs[0].inner.fast_final.slot;
    block_hash = &certs[0].inner.fast_final.block_hash;
    final_agg  = &certs[0].inner.fast_final.agg_sig;
  }

  ulong o = 0UL;
  if( FD_UNLIKELY( out_max<8UL+sizeof(fd_hash_t) ) ) return 0UL;
  FD_STORE( ulong, out+o, slot ); o += 8UL;
  fd_memcpy( out+o, block_hash->uc, sizeof(fd_hash_t) ); o += sizeof(fd_hash_t);

  ulong n = se_footer_aggregate( final_agg, out+o, out_max-o );
  if( FD_UNLIKELY( !n ) ) return 0UL;
  o += n;

  if( FD_UNLIKELY( out_max<o+1UL ) ) return 0UL;
  out[ o++ ] = (uchar)( notar_agg!=NULL );

  if( notar_agg ) {
    n = se_footer_aggregate( notar_agg, out+o, out_max-o );
    if( FD_UNLIKELY( !n ) ) return 0UL;
    o += n;
  }

  return o;
}
