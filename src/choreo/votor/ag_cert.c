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
  if( FD_UNLIKELY( fd_bls_set_cnt( set ) &&
                   fd_bls_set_last( set )>=epoch_info->validator_cnt ) ) return -1;
  fd_bls_pub_sum( pub, epoch_info->pubkeys, set );
  return 0;
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
  if( FD_UNLIKELY( !fd_bls_sig_validate( &agg->sig ) ) ) return 0; /* deferred g2 subgroup check */
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
  fd_bls_sig_add( sig, &agg->sig, &agg_fb->sig );
  if( FD_UNLIKELY( !fd_bls_sig_validate( sig ) ) ) return 0; /* deferred g2 subgroup check */
  uchar buf   [ AG_VOTE_SIGNING_SER_MAX ]; ulong sz    = ag_vote_signing_ser( kind,    slot, block_hash, shred_version, buf    );
  uchar buf_fb[ AG_VOTE_SIGNING_SER_MAX ]; ulong sz_fb = ag_vote_signing_ser( kind_fb, slot, block_hash, shred_version, buf_fb );
  if( FD_LIKELY  ( fd_bls_set_is_null( agg_fb->set ) ) ) return fd_bls_agg_verify( buf,    sz,    pub,    sig ); /* one partition is the common case */
  if( FD_UNLIKELY( fd_bls_set_is_null( agg->set    ) ) ) return fd_bls_agg_verify( buf_fb, sz_fb, pub_fb, sig );
  return fd_bls_agg_verify_pair( buf, sz, pub, buf_fb, sz_fb, pub_fb, sig );
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
  if( FD_UNLIKELY( !check_threshold( self, epoch_info ) ) ) return AG_CERT_VERIFY_ERR_THRESHOLD;
  if( FD_UNLIKELY( !check_sig      ( self, epoch_info ) ) ) return AG_CERT_VERIFY_ERR_SIG;
  return AG_CERT_VERIFY_SUCCESS;
}
