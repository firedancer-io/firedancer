#include "ag_cert.h"

#include "ag_vote_serde.h" /* ag_vote_signing_ser */

static int
is_signer( ag_cert_t const * self,
           ulong             rank ) {
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:          return fd_bls_set_test( self->final.agg.set,               rank );
  case AG_CERT_KIND_FAST_FINAL:     return fd_bls_set_test( self->fast_final.agg.set,          rank );
  case AG_CERT_KIND_NOTAR:          return fd_bls_set_test( self->notar.agg.set,               rank );
  case AG_CERT_KIND_NOTAR_FALLBACK: return fd_bls_set_test( self->notar_fallback.agg_notar.set, rank ) || fd_bls_set_test( self->notar_fallback.agg_notar_fallback.set, rank );
  case AG_CERT_KIND_SKIP:           return fd_bls_set_test( self->skip.agg_skip.set,            rank ) || fd_bls_set_test( self->skip.agg_skip_fallback.set,            rank );
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* each validator is counted once even if in both partitions */

static int
check_threshold( ag_cert_t const *       self,
                 ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  ulong                       stake      = 0UL;
  for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) if( FD_LIKELY( is_signer( self, validators[i].id ) ) ) stake += validators[i].stake;
  return fd_int_if( self->kind==AG_CERT_KIND_FAST_FINAL,
                    ag_epoch_info_is_strong_quorum( epoch_info, stake ),
                    ag_epoch_info_is_quorum       ( epoch_info, stake ) );
}

/* TODO sum all the pubkeys on advance_epoch and subtract instead? */

static int
pub_sum( fd_bls_pub_t *          pub,
         fd_bls_set_t const *    set,
         ag_epoch_info_t const * epoch_info ) {
  memset( pub, 0, sizeof(fd_bls_pub_t) ); /* zero is the point at infinity */
  for( ulong rank=fd_bls_set_const_iter_init( set ); !fd_bls_set_const_iter_done( rank ); rank=fd_bls_set_const_iter_next( set, rank ) ) {
    if( FD_UNLIKELY( rank>=epoch_info->validator_cnt ) ) return -1;
    blst_p1_add_or_double( pub, pub, epoch_info->pubkeys+rank );
  }
  return 0;
}

static int
pair_verify( fd_bls_pub_t const * pub,
             uchar const *        msg,
             ulong                msg_sz,
             fd_bls_pub_t const * pub_fb,
             uchar const *        msg_fb,
             ulong                msg_fb_sz,
             fd_bls_sig_t const * sig ) {
  if( FD_UNLIKELY( blst_p1_is_inf( pub ) || blst_p1_is_inf( pub_fb ) || blst_p2_is_inf( sig ) ) ) return 0; /* the miller loop is wrong on an infinity operand */

  blst_p1_affine a[3];
  blst_p2_affine b[3];
  blst_p2        h[1];
  blst_p1_to_affine( a, pub );
  blst_hash_to_g2( h, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( b, h );
  blst_p1_to_affine( a+1, pub_fb );
  blst_hash_to_g2( h, msg_fb, msg_fb_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( b+1, h );
  a[2] = BLS12_381_NEG_G1;
  blst_p2_to_affine( b+2, sig );

  blst_p1_affine const * aptr[3] = { a, a+1, a+2 };
  blst_p2_affine const * bptr[3] = { b, b+1, b+2 };
  blst_fp12 r[1];
  blst_miller_loop_n( r, bptr, aptr, 3UL );
  return !!blst_fp12_finalverify( r, blst_fp12_one() );
}

static int
check_sig_one( fd_bls_agg_t const *    agg,
               uint                    kind,
               ulong                   slot,
               uchar const *           block_hash,
               ag_epoch_info_t const * epoch_info,
               ushort                  shred_version ) {
  fd_bls_pub_t pub[1];
  if( FD_UNLIKELY( pub_sum( pub, agg->set, epoch_info ) ) ) return 0;
  uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
  ulong sz = ag_vote_signing_ser( kind, slot, block_hash, shred_version, buf );
  return fd_bls_agg_verify( buf, sz, pub, &agg->sig );
}

static int
check_sig_pair( fd_bls_agg_t const *    agg,
                uint                    kind,
                fd_bls_agg_t const *    agg_fb,
                uint                    kind_fb,
                ulong                   slot,
                uchar const *           block_hash,
                ag_epoch_info_t const * epoch_info,
                ushort                  shred_version ) {
  fd_bls_pub_t pub[1], pub_fb[1];
  if( FD_UNLIKELY( pub_sum( pub, agg->set, epoch_info ) || pub_sum( pub_fb, agg_fb->set, epoch_info ) ) ) return 0;
  fd_bls_sig_t sig[1];
  blst_p2_add_or_double( sig, &agg->sig, &agg_fb->sig );
  uchar buf   [ AG_VOTE_SIGNING_SER_MAX ]; ulong sz    = ag_vote_signing_ser( kind,    slot, block_hash, shred_version, buf    );
  uchar buf_fb[ AG_VOTE_SIGNING_SER_MAX ]; ulong sz_fb = ag_vote_signing_ser( kind_fb, slot, block_hash, shred_version, buf_fb );
  if( FD_LIKELY  ( fd_bls_set_is_null( agg_fb->set ) ) ) return fd_bls_agg_verify( buf,    sz,    pub,    sig ); /* one partition is the common case */
  if( FD_UNLIKELY( fd_bls_set_is_null( agg->set    ) ) ) return fd_bls_agg_verify( buf_fb, sz_fb, pub_fb, sig );
  return pair_verify( pub, buf, sz, pub_fb, buf_fb, sz_fb, sig );
}

static int
check_sig( ag_cert_t const *       self,
           ag_epoch_info_t const * epoch_info ) {
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:      return check_sig_one( &self->final.agg,      AG_VOTE_KIND_FINAL, self->final.slot,      NULL,                        epoch_info, self->final.shred_version      );
  case AG_CERT_KIND_FAST_FINAL: return check_sig_one( &self->fast_final.agg, AG_VOTE_KIND_NOTAR, self->fast_final.slot, self->fast_final.block_hash, epoch_info, self->fast_final.shred_version );
  case AG_CERT_KIND_NOTAR:      return check_sig_one( &self->notar.agg,      AG_VOTE_KIND_NOTAR, self->notar.slot,      self->notar.block_hash,      epoch_info, self->notar.shred_version      );
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_cert_notar_fallback_t const * nf = &self->notar_fallback;
    return check_sig_pair( &nf->agg_notar, AG_VOTE_KIND_NOTAR, &nf->agg_notar_fallback, AG_VOTE_KIND_NOTAR_FALLBACK, nf->slot, nf->block_hash, epoch_info, nf->shred_version );
  }
  case AG_CERT_KIND_SKIP: {
    ag_cert_skip_t const * skip = &self->skip;
    return check_sig_pair( &skip->agg_skip, AG_VOTE_KIND_SKIP, &skip->agg_skip_fallback, AG_VOTE_KIND_SKIP_FALLBACK, skip->slot, NULL, epoch_info, skip->shred_version );
  }
  default:
    FD_LOG_CRIT(( "unreachable" ));
  }
}

int
ag_cert_verify( ag_cert_t const *       self,
                ag_epoch_info_t const * epoch_info ) {
  return check_threshold( self, epoch_info ) && check_sig( self, epoch_info );
}

char *
ag_cert_to_cstr( ag_cert_t const * self,
                 char              cstr[ static AG_CERT_CSTR_MAX ] ) {
  static char const * kind_cstr[] = { "Final", "FastFinal", "Notar", "NotarFallback", "Skip" };
  fd_bls_agg_t const * aggs[2] = { NULL, NULL };
  ulong                stake;
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:          aggs[0] = &self->final.agg;                                                                  stake = self->final.stake;          break;
  case AG_CERT_KIND_FAST_FINAL:     aggs[0] = &self->fast_final.agg;                                                             stake = self->fast_final.stake;     break;
  case AG_CERT_KIND_NOTAR:          aggs[0] = &self->notar.agg;                                                                  stake = self->notar.stake;          break;
  case AG_CERT_KIND_NOTAR_FALLBACK: aggs[0] = &self->notar_fallback.agg_notar; aggs[1] = &self->notar_fallback.agg_notar_fallback; stake = self->notar_fallback.stake; break;
  case AG_CERT_KIND_SKIP:           aggs[0] = &self->skip.agg_skip;            aggs[1] = &self->skip.agg_skip_fallback;            stake = self->skip.stake;           break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
  uchar const * block_hash = ag_cert_block_hash( self );
  char *        p          = cstr;
  p = fd_cstr_append_printf( p, "%s { slot: %lu", kind_cstr[ self->kind ], ag_cert_slot( self ) );
  if( FD_LIKELY( block_hash ) ) p = fd_cstr_append_printf( p, ", hash: %02x%02x%02x...", block_hash[0], block_hash[1], block_hash[2] );
  p = fd_cstr_append_printf( p, ", sig: %lu", fd_bls_set_cnt( aggs[0]->set ) );
  if( FD_LIKELY( aggs[1] ) ) p = fd_cstr_append_printf( p, ", sig_fallback: %lu", fd_bls_set_cnt( aggs[1]->set ) );
  p = fd_cstr_append_printf( p, ", stake: %lu }", stake );
  *p = '\0';
  return cstr;
}
