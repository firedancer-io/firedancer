#include "ag_slot_state.h"
#include "ag_vote_serde.h"

#define AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR  (0)
#define AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK  (1)
#define AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES (2)

void
ag_slot_state_zero( ag_slot_state_t *       self,
                    ulong                   slot,
                    ag_epoch_info_t const * epoch_info,
                    ulong                   own_rank ) {
  fd_memset( self, 0, sizeof(ag_slot_state_t) );

  for( ulong i=0UL; i<AG_VAT_MAX; i++ ) {
    self->votes.notar        [i].slot = ULONG_MAX;
    self->votes.skip         [i].slot = ULONG_MAX;
    self->votes.skip_fallback[i].slot = ULONG_MAX;
    self->votes.finalize     [i].slot = ULONG_MAX;
  }
  self->certs.notar.slot         = ULONG_MAX;
  self->certs.skip.slot          = ULONG_MAX;
  self->certs.fast_finalize.slot = ULONG_MAX;
  self->certs.finalize.slot      = ULONG_MAX;

  self->slot       = slot;
  self->epoch_info = epoch_info;
  self->own_rank   = own_rank;
}

FD_FN_PURE ulong
ag_slot_state_stake( ag_slot_voted_stake_hash_t const * ele,
                     ulong                              cnt,
                     ag_block_hash_t const              block_hash ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_LIKELY( !memcmp( ele[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) return ele[i].stake;
  }
  return 0UL;
}

static int
block_hash_set_contains( ag_block_hash_set_t const * set,
                         ag_block_hash_t const       block_hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( FD_LIKELY( !memcmp( set->hash[i], block_hash, sizeof(ag_block_hash_t) ) ) ) return 1;
  }
  return 0;
}

static void
block_hash_set_insert( ag_block_hash_set_t * set,
                       ag_block_hash_t const block_hash ) {
  if( FD_UNLIKELY( block_hash_set_contains( set, block_hash ) ) ) return;
  FD_TEST( set->cnt < AG_EQVOC_BLOCK_HASH_MAX );
  memcpy( set->hash[ set->cnt++ ], block_hash, sizeof(ag_block_hash_t) );
}

static void
block_hash_set_remove( ag_block_hash_set_t * set,
                       ag_block_hash_t const block_hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( FD_LIKELY( !memcmp( set->hash[i], block_hash, sizeof(ag_block_hash_t) ) ) ) {
      set->cnt--;
      if( FD_UNLIKELY( i!=set->cnt ) ) memcpy( set->hash[i], set->hash[ set->cnt ], sizeof(ag_block_hash_t) );
      return;
    }
  }
}

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * self,
                                 ag_block_hash_t const   block_hash ) {
  ag_slot_certs_t const * c = &self->certs;
  for( ulong i=0UL; i<c->notar_fallback_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( c->notar_fallback[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) ) return 1;
  }
  return 0;
}

FD_FN_PURE int
ag_slot_state_is_notar_fallback_or_stronger( ag_slot_state_t const * self,
                                             ag_block_hash_t const   block_hash ) {
  int has_notar_cert      = self->certs.notar.slot !=ULONG_MAX && !memcmp( self->certs.notar.block_hash, block_hash, sizeof(ag_block_hash_t) );
  int has_fast_final_cert = self->certs.fast_finalize.slot!=ULONG_MAX && !memcmp( self->certs.fast_finalize.block_hash, block_hash, sizeof(ag_block_hash_t) );
  return has_notar_cert || has_fast_final_cert || ag_slot_state_is_notar_fallback( self, block_hash );
}

static int
check_safe_to_notar( ag_slot_state_t *     self,
                     ag_block_hash_t const block_hash ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ulong notar_stake = ag_slot_state_stake( self->voted_stakes.notar, self->voted_stakes.notar_cnt, block_hash );
  ulong skip_stake  = self->voted_stakes.skip;

  if( FD_UNLIKELY( !ag_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) ) ) {
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }
  if( FD_UNLIKELY( !ag_epoch_info_is_weak_quorum( epoch_info, notar_stake ) && !ag_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  ag_parent_status_t const * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( self->parents[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) { parent = &self->parents[i]; break; }
  }
  if( FD_UNLIKELY( !parent                                  ) ) return AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK;
  if( FD_UNLIKELY( parent->kind!=AG_PARENT_STATUS_CERTIFIED ) ) return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;

  ag_slot_votes_t const * v   = &self->votes;
  ulong                   own = self->own_rank;

  if( FD_LIKELY( own!=USHORT_MAX ) ) { /* must be staked */
    if( FD_UNLIKELY( v->skip[ own ].slot!=ULONG_MAX ) ) {
      block_hash_set_remove( &self->pending_safe_to_notar, block_hash );
      block_hash_set_insert( &self->sent_safe_to_notar,    block_hash );
      return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
    }
    if( FD_LIKELY( v->notar[ own ].slot!=ULONG_MAX ) ) {
      if( FD_UNLIKELY( memcmp( v->notar[ own ].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) ) {
        block_hash_set_remove( &self->pending_safe_to_notar, block_hash );
        block_hash_set_insert( &self->sent_safe_to_notar,    block_hash );
        return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
      }
      return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
    }
  }

  block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
  return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
}

static ag_slot_voted_stake_hash_t *
count_block_hash_stake( ag_slot_voted_stake_hash_t * ele,
                        ag_block_hash_t const        block_hash,
                        ulong                        stake,
                        ulong                        rank,
                        ag_bls_pub_t const *         pub,
                        ag_bls_sig_t const *         sig,
                        ulong *                      cnt,
                        ulong                        max ) {
  ag_slot_voted_stake_hash_t * self = NULL;
  for( ulong i=0UL; i<*cnt; i++ )
    if( FD_LIKELY( !memcmp( ele[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) { self = &ele[i]; break; }
  if( FD_UNLIKELY( !self ) ) {
    FD_CHECK_CRIT( *cnt<max, "invariant violation" );
    self = &ele[ (*cnt)++ ];
    memcpy( self->hash, block_hash, sizeof(ag_block_hash_t) );
    self->stake = 0UL;
    memset( &self->pub, 0, sizeof(ag_bls_pub_t) ); /* zero is the point at infinity */
    memset( &self->agg, 0, sizeof(ag_bls_sig_t) ); /* zero is the point at infinity */
    ag_bls_set_null( self->set );
  }
  self->stake += stake;
  blst_p1_add_or_double( &self->pub, &self->pub, pub );
  blst_p2_add_or_double( &self->agg, &self->agg, sig );
  ag_bls_set_insert( self->set, rank );
  return self;
}

static ag_slot_state_outputs_t
count_notar_stake( ag_slot_state_t *     self,
                   ulong                 slot,
                   ag_block_hash_t const block_hash,
                   ulong                 rank,
                   ulong                 stake,
                   ag_bls_pub_t const *  pub,
                   ag_bls_sig_t const *  sig,
                   ushort                shred_version ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ag_slot_state_outputs_t outputs; outputs.certs_cnt = 0UL; outputs.votor_events_cnt = 0UL; outputs.block_to_repair_cnt = 0UL;

  ag_slot_voted_stake_t *      voted_stake          = &self->voted_stakes;
  ag_slot_voted_stake_hash_t * voted_stake_for_hash = count_block_hash_stake( voted_stake->notar, block_hash, stake, rank, pub, sig, &voted_stake->notar_cnt, AG_VAT_MAX );

  ulong notar_stake           = voted_stake_for_hash->stake;
  voted_stake->notar_or_skip += stake;
  voted_stake->top_notar      = fd_ulong_max( notar_stake, voted_stake->top_notar );

  if( FD_UNLIKELY( !block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) {
    switch( check_safe_to_notar( self, block_hash ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, block_hash ) };
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<outputs.block_to_repair_cnt; j++ ) if( FD_UNLIKELY( !memcmp( outputs.block_to_repair[j].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==outputs.block_to_repair_cnt ) ) outputs.block_to_repair[ outputs.block_to_repair_cnt++ ] = ag_block_id( slot, block_hash );
      break;
    }
    default: break;
    }
  }
  if( FD_UNLIKELY( !self->sent_safe_to_skip
                   && ag_epoch_info_is_weak_quorum( epoch_info, self->voted_stakes.notar_or_skip - self->voted_stakes.top_notar )
                   && self->own_rank!=USHORT_MAX /* must be staked */
                   && self->votes.notar[ self->own_rank ].slot!=ULONG_MAX ) ) {
    outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_SKIP, .safe_to_skip = slot };
    self->sent_safe_to_skip = 1;
  }

  ag_slot_voted_stake_hash_t const * voted_stake_for_hash_fallback = NULL;
  for( ulong i=0UL; i<voted_stake->notar_fallback_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( voted_stake->notar_fallback[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) {
      voted_stake_for_hash_fallback = &voted_stake->notar_fallback[i];
      break;
    }
  }
  ulong nf_stake = voted_stake_for_hash_fallback ? voted_stake_for_hash_fallback->stake : 0UL;

  int notar_verified          = 0;
  int notar_fallback_verified = 0;

  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) ) ) {
    uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
    ulong msg_sz   = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR, slot, block_hash, shred_version, buf );
    notar_verified = ag_bls_agg_verify( &voted_stake_for_hash->pub, &voted_stake_for_hash->agg, buf, msg_sz );
    if( FD_LIKELY( voted_stake_for_hash_fallback ) ) {
      msg_sz                  = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR_FALLBACK, slot, block_hash, shred_version, buf );
      notar_fallback_verified = ag_bls_agg_verify( &voted_stake_for_hash_fallback->pub, &voted_stake_for_hash_fallback->agg, buf, msg_sz );
    }
  }

  if( FD_UNLIKELY( !ag_slot_state_is_notar_fallback( self, block_hash ) ) ) {
    ag_cert_notar_fallback_t cert = { 0 };
    cert.slot = slot;
    memcpy( cert.block_hash, block_hash, sizeof( ag_block_hash_t ) );

    if( FD_LIKELY( notar_verified ) ) {
      memcpy( cert.agg_notar.set, voted_stake_for_hash->set, sizeof(cert.agg_notar.set) );
      cert.agg_notar.sig = voted_stake_for_hash->agg;
      cert.stake += voted_stake_for_hash->stake;
    }
    if( FD_LIKELY( notar_fallback_verified ) ) {
      memcpy( cert.agg_notar_fallback.set, voted_stake_for_hash_fallback->set, sizeof(cert.agg_notar_fallback.set) );
      cert.agg_notar_fallback.sig = voted_stake_for_hash_fallback->agg;
      cert.stake += voted_stake_for_hash_fallback->stake;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) outputs.certs[ outputs.certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
  }

  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, notar_stake ) && self->certs.notar.slot==ULONG_MAX ) ) {
    ag_cert_notar_t cert = { 0 };
    cert.slot = slot;
    memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
    cert.stake = notar_stake;
    memcpy( cert.agg.set, voted_stake_for_hash->set, sizeof(cert.agg.set) );
    cert.agg.sig = voted_stake_for_hash->agg;
    outputs.certs[ outputs.certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR, .notar = cert };
  }

  if( FD_UNLIKELY( ag_epoch_info_is_strong_quorum( epoch_info, notar_stake ) && self->certs.fast_finalize.slot==ULONG_MAX ) ) {
    ag_cert_fast_final_t cert = { 0 };
    cert.slot = slot;
    memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
    cert.stake = notar_stake;
    memcpy( cert.agg.set, voted_stake_for_hash->set, sizeof(cert.agg.set) );
    cert.agg.sig = voted_stake_for_hash->agg;
    outputs.certs[ outputs.certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = cert };
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_notar_fallback_stake( ag_slot_state_t *     self,
                            ulong                 slot,
                            ag_block_hash_t const block_hash,
                            ulong                 rank,
                            ulong                 stake,
                            ag_bls_pub_t const *  pub,
                            ag_bls_sig_t const *  sig,
                            ushort                shred_version ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.votor_events_cnt = 0UL; outputs.block_to_repair_cnt = 0UL;

  ag_slot_voted_stake_t *      vs = &self->voted_stakes;
  ag_slot_voted_stake_hash_t * hs = count_block_hash_stake( vs->notar_fallback, block_hash, stake, rank, pub, sig, &vs->notar_fallback_cnt, AG_VAT_MAX*AG_NOTAR_FALLBACK_VOTE_MAX );

  ag_slot_voted_stake_hash_t const * notar = NULL;
  for( ulong i=0UL; i<vs->notar_cnt; i++ )
    if( FD_LIKELY( !memcmp( vs->notar[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) { notar = &vs->notar[i]; break; }
  ulong nf_stake    = hs->stake;
  ulong notar_stake = notar ? notar->stake : 0UL;
  int notar_verified          = 0;
  int notar_fallback_verified = 0;
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) && !ag_slot_state_is_notar_fallback( self, block_hash ) ) ) {
    uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
    ulong msg_sz;
    if( FD_UNLIKELY( notar ) ) { /* no notar vote for this hash is the common case here */
      msg_sz         = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR, slot, block_hash, shred_version, buf );
      notar_verified = ag_bls_agg_verify( &notar->pub, &notar->agg, buf, msg_sz );
    }
    msg_sz                  = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR_FALLBACK, slot, block_hash, shred_version, buf );
    notar_fallback_verified = ag_bls_agg_verify( &hs->pub, &hs->agg, buf, msg_sz );

    ag_cert_notar_fallback_t cert = { 0 };
    cert.slot = slot;
    memcpy( cert.block_hash, block_hash, sizeof( ag_block_hash_t ) );


    if( FD_LIKELY( notar_verified ) ) {
      memcpy( cert.agg_notar.set, notar->set, sizeof(cert.agg_notar.set) );
      cert.agg_notar.sig = notar->agg;
      cert.stake += notar->stake;
    }
    if( FD_LIKELY( notar_fallback_verified ) ) {
      memcpy( cert.agg_notar_fallback.set, hs->set, sizeof(cert.agg_notar_fallback.set) );
      cert.agg_notar_fallback.sig = hs->agg;
      cert.stake += hs->stake;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) outputs.certs[ outputs.certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_skip_stake( ag_slot_state_t *    self,
                  ulong                slot,
                  ulong                rank,
                  ulong                stake,
                  int                  fallback,
                  ag_bls_pub_t const * pub,
                  ag_bls_sig_t const * sig,
                  ushort               shred_version ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ag_slot_state_outputs_t outputs    = { 0 };

  ag_slot_voted_stake_t * vs = &self->voted_stakes;
  if( FD_UNLIKELY( fallback ) ) { vs->skip_fallback += stake; blst_p1_add_or_double( &vs->skip_fallback_pub, &vs->skip_fallback_pub, pub ); blst_p2_add_or_double( &vs->skip_fallback_agg, &vs->skip_fallback_agg, sig ); ag_bls_set_insert( vs->skip_fallback_set, rank ); }
  else                          { vs->skip          += stake; blst_p1_add_or_double( &vs->skip_pub,          &vs->skip_pub,          pub ); blst_p2_add_or_double( &vs->skip_agg,          &vs->skip_agg,          sig ); ag_bls_set_insert( vs->skip_set,          rank ); }

  ag_block_hash_set_t pending = self->pending_safe_to_notar;
  for( ulong i=0UL; i<pending.cnt; i++ ) {
    if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) ) continue;
    switch( check_safe_to_notar( self, pending.hash[i] ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, pending.hash[i] ) };
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<outputs.block_to_repair_cnt; j++ ) if( FD_UNLIKELY( !memcmp( outputs.block_to_repair[j].hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==outputs.block_to_repair_cnt ) ) outputs.block_to_repair[ outputs.block_to_repair_cnt++ ] = ag_block_id( slot, pending.hash[i] );
      break;
    }
    default:
      break;
    }
  }

  ulong total_skip_stake = self->voted_stakes.skip + self->voted_stakes.skip_fallback;

  int skip_verified          = 0;
  int skip_fallback_verified = 0;
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, total_skip_stake ) && self->certs.skip.slot==ULONG_MAX ) ) {
    uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
    ulong msg_sz           = ag_vote_signing_ser( AG_VOTE_KIND_SKIP,          slot, NULL, shred_version, buf );
    skip_verified          = ag_bls_agg_verify( &vs->skip_pub,          &vs->skip_agg,          buf, msg_sz );
    msg_sz                 = ag_vote_signing_ser( AG_VOTE_KIND_SKIP_FALLBACK, slot, NULL, shred_version, buf );
    skip_fallback_verified = ag_bls_agg_verify( &vs->skip_fallback_pub, &vs->skip_fallback_agg, buf, msg_sz );

    ag_cert_skip_t cert = { 0 };
    cert.slot = slot;


    if( FD_LIKELY( skip_verified ) ) {
      memcpy( cert.agg_skip.set, vs->skip_set, sizeof(cert.agg_skip.set) );
      cert.agg_skip.sig = vs->skip_agg;
      cert.stake += vs->skip;
    }
    if( FD_LIKELY( skip_fallback_verified ) ) {
      memcpy( cert.agg_skip_fallback.set, vs->skip_fallback_set, sizeof(cert.agg_skip_fallback.set) );
      cert.agg_skip_fallback.sig = vs->skip_fallback_agg;
      cert.stake += vs->skip_fallback;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) outputs.certs[ outputs.certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_SKIP, .skip = cert };
  }
  if( FD_UNLIKELY( !self->sent_safe_to_skip
                   && ag_epoch_info_is_weak_quorum( epoch_info, self->voted_stakes.notar_or_skip - self->voted_stakes.top_notar )
                   && self->own_rank!=USHORT_MAX /* must be staked */
                   && self->votes.notar[ self->own_rank ].slot!=ULONG_MAX ) ) {
    outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_SKIP, .safe_to_skip = slot };
    self->sent_safe_to_skip = 1;
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_finalize_stake( ag_slot_state_t *    self,
                      ulong                slot,
                      ulong                rank,
                      ulong                stake,
                      ag_bls_pub_t const * pub,
                      ag_bls_sig_t const * sig,
                      ushort               shred_version ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.votor_events_cnt = 0UL; outputs.block_to_repair_cnt = 0UL;

  ag_slot_voted_stake_t * vs = &self->voted_stakes;
  vs->finalize += stake;
  blst_p1_add_or_double( &vs->finalize_pub, &vs->finalize_pub, pub );
  blst_p2_add_or_double( &vs->finalize_agg, &vs->finalize_agg, sig );
  ag_bls_set_insert( vs->finalize_set, rank );
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, vs->finalize ) && self->certs.finalize.slot==ULONG_MAX ) ) {
    uchar buf[ AG_VOTE_SIGNING_SER_MAX ];
    ulong msg_sz = ag_vote_signing_ser( AG_VOTE_KIND_FINAL, slot, NULL, shred_version, buf );
    if( FD_LIKELY( ag_bls_agg_verify( &vs->finalize_pub, &vs->finalize_agg, buf, msg_sz ) ) ) {
      ag_cert_final_t cert;
      cert.slot = slot; cert.stake = vs->finalize;
      memset( &cert.agg, 0, sizeof(ag_bls_sig_t) );
      ag_bls_set_null( cert.agg.set );
      memcpy( cert.agg.set, vs->finalize_set, sizeof(cert.agg.set) );
      cert.agg.sig = vs->finalize_agg;
      outputs.certs[ outputs.certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_FINAL, .final = cert };
    }
  }

  return outputs;
}

void
ag_slot_state_add_cert( ag_slot_state_t * self,
                        ag_cert_t const * cert ) {
  switch( cert->kind ) {
  case AG_CERT_KIND_NOTAR: {
    self->certs.notar = cert->notar;
    break;
  }
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_cert_notar_fallback_t const * n = &cert->notar_fallback;
    if( FD_LIKELY( !ag_slot_state_is_notar_fallback( self, n->block_hash ) ) ) {
      FD_TEST( self->certs.notar_fallback_cnt < AG_NOTAR_FALLBACK_CERT_MAX );
      self->certs.notar_fallback[ self->certs.notar_fallback_cnt++ ] = *n;
    }
    break;
  }
  case AG_CERT_KIND_SKIP: {
    self->certs.skip = cert->skip;
    break;
  }
  case AG_CERT_KIND_FAST_FINAL: {
    self->certs.fast_finalize = cert->fast_final;
    break;
  }
  case AG_CERT_KIND_FINAL: {
    self->certs.finalize = cert->final;
    break;
  }
  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }
}

ag_slot_state_outputs_t
ag_slot_state_add_vote( ag_slot_state_t * self,
                        ag_vote_t const * vote,
                        ulong             stake ) {
  ag_slot_votes_t * votes = &self->votes;
  ulong             slot  = ag_vote_slot( vote );
  ulong             rank  = ag_vote_rank( vote );

  ag_bls_pub_t const * pub = &ag_epoch_info_validator( self->epoch_info, rank )->bls_key;
  ag_bls_sig_t const * sig = ag_vote_sig( vote );

  ag_slot_state_outputs_t outputs;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR:
    votes->notar[ rank ] = vote->notar;
    outputs = count_notar_stake( self, slot, vote->notar.block_hash, rank, stake, pub, sig, vote->notar.shred_version );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    FD_TEST( votes->notar_fallback_cnt[ rank ]<AG_NOTAR_FALLBACK_VOTE_MAX );
    votes->notar_fallback[ rank ][ votes->notar_fallback_cnt[ rank ]++ ] = vote->notar_fallback;
    outputs = count_notar_fallback_stake( self, slot, vote->notar_fallback.block_hash, rank, stake, pub, sig, vote->notar_fallback.shred_version );
    break;
  case AG_VOTE_KIND_SKIP:
    votes->skip[ rank ] = vote->skip;
    self->voted_stakes.notar_or_skip += stake;
    outputs = count_skip_stake( self, slot, rank, stake, 0, pub, sig, vote->skip.shred_version );
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    votes->skip_fallback[ rank ] = vote->skip_fallback;
    outputs = count_skip_stake( self, slot, rank, stake, 1, pub, sig, vote->skip_fallback.shred_version );
    break;
  case AG_VOTE_KIND_FINAL:
    votes->finalize[ rank ] = vote->final;
    outputs = count_finalize_stake( self, slot, rank, stake, pub, sig, vote->final.shred_version );
    break;
  default:
    FD_LOG_CRIT(( "unreachable" ));
  }

  if( FD_UNLIKELY( rank==self->own_rank ) ) {
    ag_block_hash_set_t pending = self->pending_safe_to_notar;
    for( ulong i=0UL; i<pending.cnt; i++ ) {
      if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) ) continue;
      switch( check_safe_to_notar( self, pending.hash[i] ) ) {
      case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR: outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, pending.hash[i] ) }; break;
      case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
        ulong j; for( j=0UL; j<outputs.block_to_repair_cnt; j++ ) if( FD_UNLIKELY( !memcmp( outputs.block_to_repair[j].hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) ) break;
        if( FD_LIKELY( j==outputs.block_to_repair_cnt ) ) outputs.block_to_repair[ outputs.block_to_repair_cnt++ ] = ag_block_id( slot, pending.hash[i] );
        break;
      }
      default: break;
      }
    }
  }

  return outputs;
}

void
ag_slot_state_notify_parent_known( ag_slot_state_t *     self,
                                   ag_block_hash_t const block_hash ) {
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( self->parents[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) return;
  }
  FD_TEST( self->parents_cnt < AG_EQVOC_BLOCK_HASH_MAX );
  ag_parent_status_t * e = &self->parents[ self->parents_cnt++ ];
  memcpy( e->hash, block_hash, sizeof(ag_block_hash_t) );
  e->kind = AG_PARENT_STATUS_KNOWN;
}

int
ag_slot_state_notify_parent_certified( ag_slot_state_t *     self,
                                       ag_block_hash_t const block_hash ) {
  ag_parent_status_t * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( self->parents[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) { parent = &self->parents[i]; break; }
  }
  FD_TEST( parent );
  parent->kind = AG_PARENT_STATUS_CERTIFIED;

  if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) return 0;

  switch( check_safe_to_notar( self, block_hash ) ) {
  case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK:  return -1;
  case AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES: return  0;
  case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:  return  1;
  default:                                     FD_LOG_CRIT(( "unreachable" ));
  }
}

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const * self,
                                       ag_vote_t const *       vote ) {
  ulong voter = ag_vote_rank( vote );
  ag_slot_votes_t const * v = &self->votes;

  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( v->skip[ voter ].slot!=ULONG_MAX ) ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    if( FD_UNLIKELY( v->notar[ voter ].slot!=ULONG_MAX
                     && memcmp( vote->notar.block_hash, v->notar[ voter ].block_hash, sizeof(ag_block_hash_t) ) ) ) {
      return AG_SLASHABLE_NOTAR_DIFFERENT_HASH;
    }
    break;
  }

  case AG_VOTE_KIND_NOTAR_FALLBACK:
    if( FD_UNLIKELY( v->finalize[ voter ].slot!=ULONG_MAX ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;

  case AG_VOTE_KIND_SKIP:
    if( FD_UNLIKELY( v->finalize[ voter ].slot!=ULONG_MAX ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    } else if( FD_UNLIKELY( v->notar[ voter ].slot!=ULONG_MAX ) ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    break;

  case AG_VOTE_KIND_SKIP_FALLBACK:
    if( FD_UNLIKELY( v->finalize[ voter ].slot!=ULONG_MAX ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    break;

  case AG_VOTE_KIND_FINAL: {
    if( FD_UNLIKELY( v->skip[ voter ].slot!=ULONG_MAX || v->skip_fallback[ voter ].slot!=ULONG_MAX ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    if( FD_UNLIKELY( v->notar_fallback_cnt[ voter ] ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;
  }

  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return AG_SLASHABLE_NONE;
}

FD_FN_PURE int
ag_slot_state_should_ignore_vote( ag_slot_state_t const * self,
                                  ag_vote_t const *       vote ) {
  ulong voter = ag_vote_rank( vote );
  ag_slot_votes_t const * v = &self->votes;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( v->notar[ voter ].slot!=ULONG_MAX ) ) return 1;

    uchar const * hash = vote->notar.block_hash;
    for( ulong j=0UL; j<v->notar_fallback_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( !memcmp( v->notar_fallback[ voter ][j].block_hash, hash, sizeof(ag_block_hash_t) ) ) ) return 1;
    }
    return 0;
  }
  case AG_VOTE_KIND_NOTAR_FALLBACK: {
    uchar const * hash = vote->notar_fallback.block_hash;
    for( ulong j=0UL; j<v->notar_fallback_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( !memcmp( v->notar_fallback[ voter ][j].block_hash, hash, sizeof(ag_block_hash_t) ) ) ) return 1;
    }

    return v->notar[ voter ].slot!=ULONG_MAX &&
           !memcmp( v->notar[ voter ].block_hash, hash, sizeof(ag_block_hash_t) );
  }
  case AG_VOTE_KIND_SKIP:
  case AG_VOTE_KIND_SKIP_FALLBACK:
    return v->skip[ voter ].slot!=ULONG_MAX || v->skip_fallback[ voter ].slot!=ULONG_MAX;
  case AG_VOTE_KIND_FINAL:
    return v->finalize[ voter ].slot!=ULONG_MAX;
  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return 0;
}
