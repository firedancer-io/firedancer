#include "ag_cert.h"

static int
is_signer( ag_cert_t const * self,
           ulong             v ) {
  switch( self->kind ) {
  case AG_CERT_TYPE_NOTAR:          return ag_bls_agg_is_signer( &self->inner.notar.agg_sig, v );
  case AG_CERT_TYPE_FAST_FINAL:     return ag_bls_agg_is_signer( &self->inner.fast_final.agg_sig, v );
  case AG_CERT_TYPE_FINAL:          return ag_bls_agg_is_signer( &self->inner.final.agg_sig, v );
  case AG_CERT_TYPE_NOTAR_FALLBACK: return ag_bls_agg_is_signer( &self->inner.notar_fallback.agg_sig_notar, v ) || ag_bls_agg_is_signer( &self->inner.notar_fallback.agg_sig_notar_fallback, v );
  case AG_CERT_TYPE_SKIP:           return ag_bls_agg_is_signer( &self->inner.skip.agg_sig_skip, v )            || ag_bls_agg_is_signer( &self->inner.skip.agg_sig_skip_fallback, v );
  default:                          __builtin_unreachable();
  }
}

static int
check_threshold( ag_cert_t const *       self,
                 ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * v     = ag_epoch_info_validators( epoch_info );
  ulong                       stake = 0UL;
  for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) if( is_signer( self, v[i].id ) ) stake += v[i].stake;
  return fd_int_if( self->kind == AG_CERT_TYPE_FAST_FINAL,
                    ag_epoch_info_is_strong_quorum( epoch_info, stake ),
                    ag_epoch_info_is_quorum( epoch_info, stake ) );
}

static int
check_sig( ag_cert_t const *       self,
           ag_epoch_info_t const * epoch_info,
           ushort                  shred_version ) {
  ag_validator_info_t const * v             = ag_epoch_info_validators( epoch_info );
  uchar const *               pk0           = v->bls_key;
  ulong                       pk_stride     = sizeof(ag_validator_info_t);
  ulong                       validator_cnt = epoch_info->validator_cnt;
  uchar buf[ AG_VOTE_PAYLOAD_MAX ]; ulong sz;
  switch( self->kind ) {
  case AG_CERT_TYPE_NOTAR:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_NOTAR, self->inner.notar.slot, self->inner.notar.block_hash, shred_version );
    return ag_bls_agg_verify( &self->inner.notar.agg_sig, buf, sz, pk0, pk_stride, validator_cnt );
  case AG_CERT_TYPE_FAST_FINAL:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_NOTAR, self->inner.fast_final.slot, self->inner.fast_final.block_hash, shred_version );
    return ag_bls_agg_verify( &self->inner.fast_final.agg_sig, buf, sz, pk0, pk_stride, validator_cnt );
  case AG_CERT_TYPE_FINAL:
    sz = ag_vote_payload_bytes_to_sign( buf, AG_VOTE_TYPE_FINAL, self->inner.final.slot, NULL, shred_version );
    return ag_bls_agg_verify( &self->inner.final.agg_sig, buf, sz, pk0, pk_stride, validator_cnt );
  case AG_CERT_TYPE_NOTAR_FALLBACK: {
    ag_notar_fallback_cert_t const * n = &self->inner.notar_fallback;
    uchar buf_fb[ AG_VOTE_PAYLOAD_MAX ]; ulong sz_fb;
    sz    = ag_vote_payload_bytes_to_sign( buf,    AG_VOTE_TYPE_NOTAR,          n->slot, n->block_hash, shred_version );
    sz_fb = ag_vote_payload_bytes_to_sign( buf_fb, AG_VOTE_TYPE_NOTAR_FALLBACK, n->slot, n->block_hash, shred_version );
    return ag_bls_agg_verify_merged( &n->agg_sig_notar,          buf,    sz,
                                     &n->agg_sig_notar_fallback, buf_fb, sz_fb,
                                     pk0, pk_stride, validator_cnt );
  }
  case AG_CERT_TYPE_SKIP: {
    ag_skip_cert_t const * s = &self->inner.skip;
    uchar buf_fb[ AG_VOTE_PAYLOAD_MAX ]; ulong sz_fb;
    sz    = ag_vote_payload_bytes_to_sign( buf,    AG_VOTE_TYPE_SKIP,          s->slot, NULL, shred_version );
    sz_fb = ag_vote_payload_bytes_to_sign( buf_fb, AG_VOTE_TYPE_SKIP_FALLBACK, s->slot, NULL, shred_version );
    return ag_bls_agg_verify_merged( &s->agg_sig_skip,          buf,    sz,
                                    &s->agg_sig_skip_fallback, buf_fb, sz_fb,
                                    pk0, pk_stride, validator_cnt );
  }
  default: __builtin_unreachable();
  }
}

ag_notar_cert_t
ag_notar_cert_construct( ag_notar_vote_t const * notar_votes,
                         ulong                   notar_vote_cnt,
                         ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( notar_vote_cnt>0UL );
  ulong           slot  = notar_votes[0].slot;
  ulong           stake = 0UL;
  ag_block_hash_t block_hash;
  memcpy( block_hash, notar_votes[0].block_hash, sizeof(ag_block_hash_t) );
  for( ulong i=0UL; i<notar_vote_cnt; i++ ) {
    FD_TEST( notar_votes[i].slot==slot );
    FD_TEST( !memcmp( notar_votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake += validators[ notar_votes[i].signer ].stake;
  }
  ag_notar_cert_t cert;
  cert.slot = slot; cert.stake = stake;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
  ag_bls_agg_zero( &cert.agg_sig );
  for( ulong i=0UL; i<notar_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig, notar_votes[i].signer, notar_votes[i].sig );
  return cert;
}

ag_fast_final_cert_t
ag_fast_final_cert_construct( ag_notar_vote_t const * notar_votes,
                              ulong                   notar_vote_cnt,
                              ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( notar_vote_cnt>0UL );
  ulong           slot  = notar_votes[0].slot;
  ulong           stake = 0UL;
  ag_block_hash_t block_hash;
  memcpy( block_hash, notar_votes[0].block_hash, sizeof(ag_block_hash_t) );
  for( ulong i=0UL; i<notar_vote_cnt; i++ ) {
    FD_TEST( notar_votes[i].slot==slot );
    FD_TEST( !memcmp( notar_votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake += validators[ notar_votes[i].signer ].stake;
  }
  ag_fast_final_cert_t cert;
  cert.slot = slot; cert.stake = stake;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
  ag_bls_agg_zero( &cert.agg_sig );
  for( ulong i=0UL; i<notar_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig, notar_votes[i].signer, notar_votes[i].sig );
  return cert;
}

ag_final_cert_t
ag_final_cert_construct( ag_final_vote_t const * final_votes,
                         ulong                   final_vote_cnt,
                         ag_epoch_info_t const * epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( final_vote_cnt>0UL );
  ulong slot  = final_votes[0].slot;
  ulong stake = 0UL;
  for( ulong i=0UL; i<final_vote_cnt; i++ ) {
    FD_TEST( final_votes[i].slot==slot );
    stake += validators[ final_votes[i].signer ].stake;
  }
  ag_final_cert_t cert;
  cert.slot = slot; cert.stake = stake;
  ag_bls_agg_zero( &cert.agg_sig );
  for( ulong i=0UL; i<final_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig, final_votes[i].signer, final_votes[i].sig );
  return cert;
}

ag_notar_fallback_cert_t
ag_notar_fallback_cert_construct( ag_notar_vote_t const *          notar_votes,
                                  ulong                            notar_vote_cnt,
                                  ag_notar_fallback_vote_t const * notar_fallback_votes,
                                  ulong                            notar_fallback_vote_cnt,
                                  ag_epoch_info_t const *          epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( notar_vote_cnt>0UL || notar_fallback_vote_cnt>0UL );
  ulong           slot;
  ag_block_hash_t block_hash;
  if( notar_vote_cnt>0UL ) { slot = notar_votes[0].slot;          memcpy( block_hash, notar_votes[0].block_hash,          sizeof(ag_block_hash_t) ); }
  else                     { slot = notar_fallback_votes[0].slot; memcpy( block_hash, notar_fallback_votes[0].block_hash, sizeof(ag_block_hash_t) ); }

  ulong stake = 0UL;
  for( ulong i=0UL; i<notar_vote_cnt; i++ ) {
    FD_TEST( notar_votes[i].slot==slot );
    FD_TEST( !memcmp( notar_votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake += validators[ notar_votes[i].signer ].stake;
  }
  ulong stake_fb = 0UL;
  for( ulong i=0UL; i<notar_fallback_vote_cnt; i++ ) {
    FD_TEST( notar_fallback_votes[i].slot==slot );
    FD_TEST( !memcmp( notar_fallback_votes[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) );
    stake_fb += validators[ notar_fallback_votes[i].signer ].stake;
  }

  ag_notar_fallback_cert_t cert;
  cert.slot = slot;
  memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
  ag_bls_agg_zero( &cert.agg_sig_notar );
  for( ulong i=0UL; i<notar_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig_notar, notar_votes[i].signer, notar_votes[i].sig );
  if( FD_UNLIKELY( ag_bls_agg_is_identity( &cert.agg_sig_notar ) ) ) {
    ag_bls_agg_zero( &cert.agg_sig_notar );
    stake = 0UL;
  }
  ag_bls_agg_zero( &cert.agg_sig_notar_fallback );
  for( ulong i=0UL; i<notar_fallback_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig_notar_fallback, notar_fallback_votes[i].signer, notar_fallback_votes[i].sig );
  if( FD_UNLIKELY( ag_bls_agg_is_identity( &cert.agg_sig_notar_fallback ) ) ) {
    ag_bls_agg_zero( &cert.agg_sig_notar_fallback );
    stake_fb = 0UL;
  }
  ag_bls_agg_merge( &cert.agg_sig_notar, &cert.agg_sig_notar_fallback );
  cert.stake = stake + stake_fb;
  return cert;
}

ag_skip_cert_t
ag_skip_cert_construct( ag_skip_vote_t const *          skip_votes,
                        ulong                           skip_vote_cnt,
                        ag_skip_fallback_vote_t const * skip_fallback_votes,
                        ulong                           skip_fallback_vote_cnt,
                        ag_epoch_info_t const *         epoch_info ) {
  ag_validator_info_t const * validators = ag_epoch_info_validators( epoch_info );
  FD_TEST( skip_vote_cnt>0UL || skip_fallback_vote_cnt>0UL );
  ulong slot = skip_vote_cnt>0UL ? skip_votes[0].slot : skip_fallback_votes[0].slot;

  ulong stake = 0UL;
  for( ulong i=0UL; i<skip_vote_cnt; i++ ) {
    FD_TEST( skip_votes[i].slot==slot );
    stake += validators[ skip_votes[i].signer ].stake;
  }
  ulong stake_fb = 0UL;
  for( ulong i=0UL; i<skip_fallback_vote_cnt; i++ ) {
    FD_TEST( skip_fallback_votes[i].slot==slot );
    stake_fb += validators[ skip_fallback_votes[i].signer ].stake;
  }

  ag_skip_cert_t cert;
  cert.slot = slot;
  ag_bls_agg_zero( &cert.agg_sig_skip );
  for( ulong i=0UL; i<skip_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig_skip, skip_votes[i].signer, skip_votes[i].sig );
  if( FD_UNLIKELY( ag_bls_agg_is_identity( &cert.agg_sig_skip ) ) ) {
    ag_bls_agg_zero( &cert.agg_sig_skip );
    stake = 0UL;
  }
  ag_bls_agg_zero( &cert.agg_sig_skip_fallback );
  for( ulong i=0UL; i<skip_fallback_vote_cnt; i++ ) ag_bls_agg_add( &cert.agg_sig_skip_fallback, skip_fallback_votes[i].signer, skip_fallback_votes[i].sig );
  if( FD_UNLIKELY( ag_bls_agg_is_identity( &cert.agg_sig_skip_fallback ) ) ) {
    ag_bls_agg_zero( &cert.agg_sig_skip_fallback );
    stake_fb = 0UL;
  }
  cert.stake = stake + stake_fb;
  ag_bls_agg_merge( &cert.agg_sig_skip, &cert.agg_sig_skip_fallback );
  return cert;
}

int
ag_notar_cert_verify( ag_notar_cert_t const * notar_cert,
                      ag_epoch_info_t const * epoch_info,
                      ushort                  shred_version ) {
  ag_cert_t cert = { .kind = AG_CERT_TYPE_NOTAR };
  cert.inner.notar = *notar_cert;
  return check_sig( &cert, epoch_info, shred_version ) && check_threshold( &cert, epoch_info );
}

int
ag_fast_final_cert_verify( ag_fast_final_cert_t const * fast_final_cert,
                           ag_epoch_info_t const *      epoch_info,
                           ushort                       shred_version ) {
  ag_cert_t cert = { .kind = AG_CERT_TYPE_FAST_FINAL };
  cert.inner.fast_final = *fast_final_cert;
  return check_sig( &cert, epoch_info, shred_version ) && check_threshold( &cert, epoch_info );
}

int
ag_final_cert_verify( ag_final_cert_t const * final_cert,
                      ag_epoch_info_t const * epoch_info,
                      ushort                  shred_version ) {
  ag_cert_t cert = { .kind = AG_CERT_TYPE_FINAL };
  cert.inner.final = *final_cert;
  return check_sig( &cert, epoch_info, shred_version ) && check_threshold( &cert, epoch_info );
}

int
ag_notar_fallback_cert_verify( ag_notar_fallback_cert_t const * notar_fallback_cert,
                               ag_epoch_info_t const *          epoch_info,
                               ushort                           shred_version ) {
  ag_cert_t cert = { .kind = AG_CERT_TYPE_NOTAR_FALLBACK };
  cert.inner.notar_fallback = *notar_fallback_cert;
  return check_sig( &cert, epoch_info, shred_version ) && check_threshold( &cert, epoch_info );
}

int
ag_skip_cert_verify( ag_skip_cert_t const *  skip_cert,
                     ag_epoch_info_t const * epoch_info,
                     ushort                  shred_version ) {
  ag_cert_t cert = { .kind = AG_CERT_TYPE_SKIP };
  cert.inner.skip = *skip_cert;
  return check_sig( &cert, epoch_info, shred_version ) && check_threshold( &cert, epoch_info );
}
