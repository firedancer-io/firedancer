#include "ag_cert.h"

static int
is_signer( ag_cert_t const * self,
           ulong             rank ) {
  switch( self->kind ) {
  case AG_CERT_KIND_NOTAR:          return ag_bls_agg_is_signer( &self->notar.agg_sig, rank );
  case AG_CERT_KIND_FAST_FINAL:     return ag_bls_agg_is_signer( &self->fast_final.agg_sig, rank );
  case AG_CERT_KIND_FINAL:          return ag_bls_agg_is_signer( &self->final.agg_sig, rank );
  case AG_CERT_KIND_NOTAR_FALLBACK: return ag_bls_agg_is_signer( &self->notar_fallback.agg_sig_notar, rank ) || ag_bls_agg_is_signer( &self->notar_fallback.agg_sig_notar_fallback, rank );
  case AG_CERT_KIND_SKIP:           return ag_bls_agg_is_signer( &self->skip.agg_sig_skip, rank )            || ag_bls_agg_is_signer( &self->skip.agg_sig_skip_fallback, rank );
  default:                          __builtin_unreachable();
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
  uchar buf[ AG_VOTE_PAYLOAD_MAX ]; ulong sz;
  switch( self->kind ) {
  case AG_CERT_KIND_NOTAR:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_KIND_NOTAR, self->notar.slot, self->notar.block_hash, shred_version );
    return ag_bls_agg_verify( &self->notar.agg_sig, buf, sz, pks, validator_cnt );
  case AG_CERT_KIND_FAST_FINAL:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_KIND_NOTAR, self->fast_final.slot, self->fast_final.block_hash, shred_version );
    return ag_bls_agg_verify( &self->fast_final.agg_sig, buf, sz, pks, validator_cnt );
  case AG_CERT_KIND_FINAL:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_KIND_FINAL, self->final.slot, NULL, shred_version );
    return ag_bls_agg_verify( &self->final.agg_sig, buf, sz, pks, validator_cnt );
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_cert_notar_fallback_t const * notar_fallback = &self->notar_fallback;
    uchar buf_fallback[ AG_VOTE_PAYLOAD_MAX ]; ulong sz_fallback;
    sz          = ag_vote_payload_bytes_to_sign( buf,          AG_VOTE_KIND_NOTAR,          notar_fallback->slot, notar_fallback->block_hash, shred_version );
    sz_fallback = ag_vote_payload_bytes_to_sign( buf_fallback, AG_VOTE_KIND_NOTAR_FALLBACK, notar_fallback->slot, notar_fallback->block_hash, shred_version );
    return ag_bls_agg_verify_merged( &notar_fallback->agg_sig_notar,          buf,          sz,
                                     &notar_fallback->agg_sig_notar_fallback, buf_fallback, sz_fallback,
                                     pks, validator_cnt );
  }
  case AG_CERT_KIND_SKIP: {
    ag_cert_skip_t const * skip = &self->skip;
    uchar buf_fallback[ AG_VOTE_PAYLOAD_MAX ]; ulong sz_fallback;
    sz          = ag_vote_payload_bytes_to_sign( buf,          AG_VOTE_KIND_SKIP,          skip->slot, NULL, shred_version );
    sz_fallback = ag_vote_payload_bytes_to_sign( buf_fallback, AG_VOTE_KIND_SKIP_FALLBACK, skip->slot, NULL, shred_version );
    return ag_bls_agg_verify_merged( &skip->agg_sig_skip,          buf,          sz,
                                     &skip->agg_sig_skip_fallback, buf_fallback, sz_fallback,
                                     pks, validator_cnt );
  }
  default:
    __builtin_unreachable();
  }
}

int
ag_cert_verify( ag_cert_t const *       self,
                ag_epoch_info_t const * epoch_info,
                ushort                  shred_version ) {
  return check_threshold( self, epoch_info ) && check_sig( self, epoch_info, shred_version );
}

static ag_cert_notar_t
construct_notar( ag_vote_notar_t const * votes,
                 ulong                   vote_cnt,
                 ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL );
  ulong           slot  = votes[0].slot;
  ulong           stake = 0UL;
  ag_block_hash_t block_hash;
  memcpy( block_hash, votes[0].block_hash, sizeof(ag_block_hash_t) );
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    FD_TEST( !memcmp( votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake += validators[ votes[i].rank ].stake;
  }
  ag_cert_notar_t cert;
  cert.slot = slot; cert.stake = stake;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
  ag_bls_agg_zero( &cert.agg_sig );
  for( ulong i=0UL; i<vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig, votes[i].rank, votes[i].sig );
  return cert;
}

static ag_cert_fast_final_t
construct_fast_final( ag_vote_notar_t const * votes,
                      ulong                   vote_cnt,
                      ag_epoch_info_t const * epoch_info ) {
  ag_cert_notar_t      notar = construct_notar( votes, vote_cnt, epoch_info );
  ag_cert_fast_final_t cert;
  cert.slot = notar.slot; cert.stake = notar.stake; cert.agg_sig = notar.agg_sig;
  memcpy( cert.block_hash, notar.block_hash, sizeof(ag_block_hash_t) );
  return cert;
}

static ag_cert_final_t
construct_final( ag_vote_final_t const * votes,
                 ulong                   vote_cnt,
                 ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL );
  ulong slot  = votes[0].slot;
  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    stake += validators[ votes[i].rank ].stake;
  }
  ag_cert_final_t cert;
  cert.slot = slot; cert.stake = stake;
  ag_bls_agg_zero( &cert.agg_sig );
  for( ulong i=0UL; i<vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig, votes[i].rank, votes[i].sig );
  return cert;
}

static ag_cert_notar_fallback_t
construct_notar_fallback( ag_vote_notar_t const *          votes,
                          ulong                            vote_cnt,
                          ag_vote_notar_fallback_t const * fallback_votes,
                          ulong                            fallback_vote_cnt,
                          ag_epoch_info_t const *          epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL || fallback_vote_cnt>0UL );
  ulong           slot;
  ag_block_hash_t block_hash;
  if( vote_cnt>0UL ) { slot = votes[0].slot;                   memcpy( block_hash, votes[0].block_hash,                   sizeof(ag_block_hash_t) ); }
  else               { slot = fallback_votes[0].slot; memcpy( block_hash, fallback_votes[0].block_hash, sizeof(ag_block_hash_t) ); }

  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    FD_TEST( !memcmp( votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake += validators[ votes[i].rank ].stake;
  }
  ulong stake_fallback = 0UL;
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) {
    FD_TEST( fallback_votes[i].slot==slot );
    FD_TEST( !memcmp( fallback_votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake_fallback += validators[ fallback_votes[i].rank ].stake;
  }

  ag_cert_notar_fallback_t cert;
  cert.slot = slot;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
  ag_bls_agg_zero( &cert.agg_sig_notar );
  for( ulong i=0UL; i<vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig_notar, votes[i].rank, votes[i].sig );
  if( FD_UNLIKELY( ag_bls_agg_is_identity( &cert.agg_sig_notar ) ) ) {
    ag_bls_agg_zero( &cert.agg_sig_notar );
    stake = 0UL;
  }
  ag_bls_agg_zero( &cert.agg_sig_notar_fallback );
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig_notar_fallback, fallback_votes[i].rank, fallback_votes[i].sig );
  if( FD_UNLIKELY( ag_bls_agg_is_identity( &cert.agg_sig_notar_fallback ) ) ) {
    ag_bls_agg_zero( &cert.agg_sig_notar_fallback );
    stake_fallback = 0UL;
  }
  ag_bls_agg_merge( &cert.agg_sig_notar, &cert.agg_sig_notar_fallback );
  cert.stake = stake + stake_fallback;
  return cert;
}

static ag_cert_skip_t
construct_skip( ag_vote_skip_t const *          votes,
                ulong                           vote_cnt,
                ag_vote_skip_fallback_t const * fallback_votes,
                ulong                           fallback_vote_cnt,
                ag_epoch_info_t const *         epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( vote_cnt>0UL || fallback_vote_cnt>0UL );
  ulong slot = vote_cnt>0UL ? votes[0].slot : fallback_votes[0].slot;

  ulong stake = 0UL;
  for( ulong i=0UL; i<vote_cnt; i++ ) {
    FD_TEST( votes[i].slot==slot );
    stake += validators[ votes[i].rank ].stake;
  }
  ulong stake_fallback = 0UL;
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) {
    FD_TEST( fallback_votes[i].slot==slot );
    stake_fallback += validators[ fallback_votes[i].rank ].stake;
  }

  ag_cert_skip_t cert;
  cert.slot = slot;
  ag_bls_agg_zero( &cert.agg_sig_skip );
  for( ulong i=0UL; i<vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig_skip, votes[i].rank, votes[i].sig );
  if( FD_UNLIKELY( ag_bls_agg_is_identity( &cert.agg_sig_skip ) ) ) {
    ag_bls_agg_zero( &cert.agg_sig_skip );
    stake = 0UL;
  }
  ag_bls_agg_zero( &cert.agg_sig_skip_fallback );
  for( ulong i=0UL; i<fallback_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig_skip_fallback, fallback_votes[i].rank, fallback_votes[i].sig );
  if( FD_UNLIKELY( ag_bls_agg_is_identity( &cert.agg_sig_skip_fallback ) ) ) {
    ag_bls_agg_zero( &cert.agg_sig_skip_fallback );
    stake_fallback = 0UL;
  }
  cert.stake = stake + stake_fallback;
  ag_bls_agg_merge( &cert.agg_sig_skip, &cert.agg_sig_skip_fallback );
  return cert;
}

ag_cert_t
ag_cert_construct_notar( ag_vote_notar_t const * votes,
                         ulong                   vote_cnt,
                         ag_epoch_info_t const * epoch_info ) {
  return (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR, .notar = construct_notar( votes, vote_cnt, epoch_info ) };
}

ag_cert_t
ag_cert_construct_fast_final( ag_vote_notar_t const * votes,
                              ulong                   vote_cnt,
                              ag_epoch_info_t const * epoch_info ) {
  return (ag_cert_t){ .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = construct_fast_final( votes, vote_cnt, epoch_info ) };
}

ag_cert_t
ag_cert_construct_final( ag_vote_final_t const * votes,
                         ulong                   vote_cnt,
                         ag_epoch_info_t const * epoch_info ) {
  return (ag_cert_t){ .kind = AG_CERT_KIND_FINAL, .final = construct_final( votes, vote_cnt, epoch_info ) };
}

ag_cert_t
ag_cert_construct_notar_fallback( ag_vote_notar_t const *          votes,
                                  ulong                            vote_cnt,
                                  ag_vote_notar_fallback_t const * fallback_votes,
                                  ulong                            fallback_vote_cnt,
                                  ag_epoch_info_t const *          epoch_info ) {
  return (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = construct_notar_fallback( votes, vote_cnt, fallback_votes, fallback_vote_cnt, epoch_info ) };
}

ag_cert_t
ag_cert_construct_skip( ag_vote_skip_t const *          votes,
                        ulong                           vote_cnt,
                        ag_vote_skip_fallback_t const * fallback_votes,
                        ulong                           fallback_vote_cnt,
                        ag_epoch_info_t const *         epoch_info ) {
  return (ag_cert_t){ .kind = AG_CERT_KIND_SKIP, .skip = construct_skip( votes, vote_cnt, fallback_votes, fallback_vote_cnt, epoch_info ) };
}
