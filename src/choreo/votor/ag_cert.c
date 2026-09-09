#include "ag_cert.h"

#include "ag_vote_serde.h" /* ag_vote_signing_ser */

static int
is_signer( ag_cert_t const * self,
           ulong             rank ) {
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:          return ag_bls_agg_is_signer( &self->final.agg, rank );
  case AG_CERT_KIND_FAST_FINAL:     return ag_bls_agg_is_signer( &self->fast_final.agg, rank );
  case AG_CERT_KIND_NOTAR:          return ag_bls_agg_is_signer( &self->notar.agg, rank );
  case AG_CERT_KIND_NOTAR_FALLBACK: return ag_bls_agg_is_signer( &self->notar_fallback.agg_notar, rank ) || ag_bls_agg_is_signer( &self->notar_fallback.agg_notar_fallback, rank );
  case AG_CERT_KIND_SKIP:           return ag_bls_agg_is_signer( &self->skip.agg_skip, rank )            || ag_bls_agg_is_signer( &self->skip.agg_skip_fallback, rank );
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

static int
check_threshold( ag_cert_t const *       self,
                 ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  ulong                       stake      = 0UL;
  for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) if( is_signer( self, validators[i].id ) ) stake += validators[i].stake;
  return fd_int_if( self->kind == AG_CERT_KIND_FAST_FINAL,
                    ag_epoch_info_is_strong_quorum( epoch_info, stake ),
                    ag_epoch_info_is_quorum( epoch_info, stake ) );
}

static int
check_sig( ag_cert_t const *       self,
           ag_epoch_info_t const * epoch_info,
           ushort                  shred_version ) {
  ag_bls_pub_t const * pks           = epoch_info->pubkeys;
  ulong                validator_cnt = epoch_info->validator_cnt;
  uchar buf[ AG_VOTE_SIGNING_SER_MAX ]; ulong sz;
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:
    sz = ag_vote_signing_ser( AG_VOTE_KIND_FINAL, self->final.slot, NULL, shred_version, buf );
    return ag_bls_agg_verify( &self->final.agg, buf, sz, pks, validator_cnt );
  case AG_CERT_KIND_FAST_FINAL:
    sz = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR, self->fast_final.slot, self->fast_final.block_hash, shred_version, buf );
    return ag_bls_agg_verify( &self->fast_final.agg, buf, sz, pks, validator_cnt );
  case AG_CERT_KIND_NOTAR:
    sz = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR, self->notar.slot, self->notar.block_hash, shred_version, buf );
    return ag_bls_agg_verify( &self->notar.agg, buf, sz, pks, validator_cnt );
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_cert_notar_fallback_t const * notar_fallback = &self->notar_fallback;
    uchar buf_fallback[ AG_VOTE_SIGNING_SER_MAX ]; ulong sz_fallback;
    sz          = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR,          notar_fallback->slot, notar_fallback->block_hash, shred_version, buf );
    sz_fallback = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR_FALLBACK, notar_fallback->slot, notar_fallback->block_hash, shred_version, buf_fallback );
    return ag_bls_agg_verify_merged( &notar_fallback->agg_notar,          buf,          sz,
                                     &notar_fallback->agg_notar_fallback, buf_fallback, sz_fallback,
                                     pks, validator_cnt );
  }
  case AG_CERT_KIND_SKIP: {
    ag_cert_skip_t const * skip = &self->skip;
    uchar buf_fallback[ AG_VOTE_SIGNING_SER_MAX ]; ulong sz_fallback;
    sz          = ag_vote_signing_ser( AG_VOTE_KIND_SKIP,          skip->slot, NULL, shred_version, buf );
    sz_fallback = ag_vote_signing_ser( AG_VOTE_KIND_SKIP_FALLBACK, skip->slot, NULL, shred_version, buf_fallback );
    return ag_bls_agg_verify_merged( &skip->agg_skip,          buf,          sz,
                                     &skip->agg_skip_fallback, buf_fallback, sz_fallback,
                                     pks, validator_cnt );
  }
  default:
    FD_LOG_CRIT(( "unreachable" ));
  }
}

int
ag_cert_verify( ag_cert_t const *       self,
                ag_epoch_info_t const * epoch_info,
                ushort                  shred_version ) {
  return check_threshold( self, epoch_info ) && check_sig( self, epoch_info, shred_version );
}
