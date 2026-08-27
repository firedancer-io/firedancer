#include "ag_slot_state.h"

#include "../../ballet/base58/fd_base58.h"

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
ag_slot_state_stake( ag_hashstake_t const * ele,
                     ulong                  cnt,
                     ag_block_hash_t const  hash ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( !memcmp( ele[i].hash, hash, sizeof(ag_block_hash_t) ) ) return ele[i].stake;
  }
  return 0UL;
}

static ulong
hashstake_add( ag_hashstake_t *      ele,
               ulong *               cnt,
               ulong                 cap,
               ag_block_hash_t const hash,
               ulong                 stake ) {
  ulong i;
  for( i=0UL; i<*cnt; i++ ) if( !memcmp( ele[i].hash, hash, sizeof(ag_block_hash_t) ) ) break;
  if( i==*cnt ) {
    FD_TEST( *cnt<cap );
    memcpy( ele[i].hash, hash, sizeof(ag_block_hash_t) );
    ele[i].stake = 0UL;
    (*cnt)++;
  }

  ulong total  = ele[i].stake + stake;
  ele[i].stake = total;
  return total;
}

static int
set_contains( ag_hash_set_t const * set,
              ag_block_hash_t const hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( !memcmp( set->hash[i], hash, sizeof(ag_block_hash_t) ) ) return 1;
  }
  return 0;
}

static void
set_insert( ag_hash_set_t *       set,
            ag_block_hash_t const hash ) {
  if( set_contains( set, hash ) ) return;
  FD_TEST( set->cnt < AG_EQVOC_BLOCK_HASH_MAX );
  memcpy( set->hash[ set->cnt++ ], hash, sizeof(ag_block_hash_t) );
}

static void
set_remove( ag_hash_set_t *       set,
            ag_block_hash_t const hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( !memcmp( set->hash[i], hash, sizeof(ag_block_hash_t) ) ) {
      set->cnt--;
      if( i!=set->cnt ) memcpy( set->hash[i], set->hash[ set->cnt ], sizeof(ag_block_hash_t) );
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

  if( !ag_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) ) {
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }
  if( !ag_epoch_info_is_weak_quorum( epoch_info, notar_stake )
      && !ag_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) {
    set_insert( &self->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  ag_parent_status_t const * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( !memcmp( self->parents[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) { parent = &self->parents[i]; break; }
  }
  if( !parent                                   ) return AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK;
  if( parent->kind!=AG_PARENT_STATUS_CERTIFIED  ) return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;

  ag_slot_votes_t const * v   = &self->votes;
  ulong                   own = self->own_rank;

  if( FD_LIKELY( own!=USHORT_MAX ) ) { /* must be staked */
    if( v->skip[ own ].slot!=ULONG_MAX ) {
      set_remove( &self->pending_safe_to_notar, block_hash );
      set_insert( &self->sent_safe_to_notar,    block_hash );
      return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
    }
    if( v->notar[ own ].slot!=ULONG_MAX ) {
      if( memcmp( v->notar[ own ].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) {
        set_remove( &self->pending_safe_to_notar, block_hash );
        set_insert( &self->sent_safe_to_notar,    block_hash );
        return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
      }
      return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
    }
  }

  set_insert( &self->pending_safe_to_notar, block_hash );
  return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
}

static ag_slot_state_outputs_t
count_notar_stake( ag_slot_state_t *     self,
                   ulong                 slot,
                   ag_block_hash_t const block_hash,
                   ulong                 stake ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.votor_events_cnt = 0UL; outputs.block_to_repair_cnt = 0UL;

  ulong notar_stake = hashstake_add( self->voted_stakes.notar, &self->voted_stakes.notar_cnt, AG_NOTAR_STAKE_MAX, block_hash, stake );
  self->voted_stakes.notar_or_skip += stake;
  self->voted_stakes.top_notar      = fd_ulong_max( notar_stake, self->voted_stakes.top_notar );

  if( !set_contains( &self->sent_safe_to_notar, block_hash ) ) {
    switch( check_safe_to_notar( self, block_hash ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, block_hash ) };
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<outputs.block_to_repair_cnt; j++ ) if( !memcmp( outputs.block_to_repair[j].hash, block_hash, sizeof(ag_block_hash_t) ) ) break;
      if( j==outputs.block_to_repair_cnt ) outputs.block_to_repair[ outputs.block_to_repair_cnt++ ] = ag_block_id( slot, block_hash );
      break;
    }
    default: break;
    }
  }
  if( !self->sent_safe_to_skip
      && ag_epoch_info_is_weak_quorum( epoch_info, self->voted_stakes.notar_or_skip - self->voted_stakes.top_notar )
      && self->own_rank!=USHORT_MAX /* must be staked */
      && self->votes.notar[ self->own_rank ].slot!=ULONG_MAX ) {
    outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_SKIP, .safe_to_skip = slot };
    self->sent_safe_to_skip = 1;
  }

  ulong nf_stake = ag_slot_state_stake( self->voted_stakes.notar_fallback, self->voted_stakes.notar_fallback_cnt, block_hash );
  if( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) && !ag_slot_state_is_notar_fallback( self, block_hash ) ) {
    ag_slot_votes_t const *    v      = &self->votes;
    ag_vote_notar_t *          notar  = self->cert_builder->notar.votes;
    ag_vote_notar_fallback_t * nf     = self->cert_builder->notar.fallback_votes;
    ulong                      n_cnt  = 0UL;
    ulong                      nf_cnt = 0UL;
    for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
      if( v->notar[i].slot!=ULONG_MAX && !memcmp( v->notar[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) notar[ n_cnt++ ] = v->notar[i];
      for( ulong j=0UL; j<v->notar_fallback_cnt[i]; j++ ) {
        if( memcmp( v->notar_fallback[i][j].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) continue;
        nf[ nf_cnt++ ] = v->notar_fallback[i][j];
        break;
      }
    }
    ag_cert_t cert = ag_cert_construct_notar_fallback( notar, n_cnt, nf, nf_cnt, epoch_info );
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.notar_fallback.stake ) ) ) outputs.certs[ outputs.certs_cnt++ ] = cert;
  }
  if( ag_epoch_info_is_quorum( epoch_info, notar_stake ) && self->certs.notar.slot==ULONG_MAX ) {
    ag_slot_votes_t const * v     = &self->votes;
    ag_vote_notar_t *       notar = self->cert_builder->notar.votes;
    ulong                   n_cnt = 0UL;
    for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
      if( v->notar[i].slot!=ULONG_MAX && !memcmp( v->notar[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) notar[ n_cnt++ ] = v->notar[i];
    }
    ag_cert_t cert = ag_cert_construct_notar( notar, n_cnt, epoch_info );
    outputs.certs[ outputs.certs_cnt++ ] = cert;
  }
  if( ag_epoch_info_is_strong_quorum( epoch_info, notar_stake ) && self->certs.fast_finalize.slot==ULONG_MAX ) {
    ag_slot_votes_t const * v     = &self->votes;
    ag_vote_notar_t *       notar = self->cert_builder->notar.votes;
    ulong                   n_cnt = 0UL;
    for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
      if( v->notar[i].slot!=ULONG_MAX && !memcmp( v->notar[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) notar[ n_cnt++ ] = v->notar[i];
    }
    ag_cert_t cert = ag_cert_construct_fast_final( notar, n_cnt, epoch_info );
    outputs.certs[ outputs.certs_cnt++ ] = cert;
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_notar_fallback_stake( ag_slot_state_t *     self,
                            ag_block_hash_t const block_hash,
                            ulong                 stake ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.votor_events_cnt = 0UL; outputs.block_to_repair_cnt = 0UL;

  ulong nf_stake    = hashstake_add( self->voted_stakes.notar_fallback, &self->voted_stakes.notar_fallback_cnt, AG_NOTAR_FALLBACK_STAKE_MAX, block_hash, stake );
  ulong notar_stake = ag_slot_state_stake( self->voted_stakes.notar, self->voted_stakes.notar_cnt, block_hash );
  if( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) && !ag_slot_state_is_notar_fallback( self, block_hash ) ) {
    ag_slot_votes_t const *    v      = &self->votes;
    ag_vote_notar_t *          notar  = self->cert_builder->notar.votes;
    ag_vote_notar_fallback_t * nf     = self->cert_builder->notar.fallback_votes;
    ulong                      n_cnt  = 0UL;
    ulong                      nf_cnt = 0UL;
    for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
      if( v->notar[i].slot!=ULONG_MAX && !memcmp( v->notar[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) notar[ n_cnt++ ] = v->notar[i];
      for( ulong j=0UL; j<v->notar_fallback_cnt[i]; j++ ) {
        if( memcmp( v->notar_fallback[i][j].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) continue;
        nf[ nf_cnt++ ] = v->notar_fallback[i][j];
        break;
      }
    }
    ag_cert_t cert = ag_cert_construct_notar_fallback( notar, n_cnt, nf, nf_cnt, epoch_info );
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.notar_fallback.stake ) ) ) outputs.certs[ outputs.certs_cnt++ ] = cert;
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_skip_stake( ag_slot_state_t * self,
                  ulong             slot,
                  ulong             stake,
                  int               fallback ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ag_slot_state_outputs_t outputs    = { 0 };

  if( fallback ) self->voted_stakes.skip_fallback += stake;
  else           self->voted_stakes.skip          += stake;

  ag_hash_set_t pending = self->pending_safe_to_notar;
  for( ulong i=0UL; i<pending.cnt; i++ ) {
    if( set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) continue;
    switch( check_safe_to_notar( self, pending.hash[i] ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, pending.hash[i] ) };
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<outputs.block_to_repair_cnt; j++ ) if( !memcmp( outputs.block_to_repair[j].hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) break;
      if( j==outputs.block_to_repair_cnt ) outputs.block_to_repair[ outputs.block_to_repair_cnt++ ] = ag_block_id( slot, pending.hash[i] );
      break;
    }
    default:
      break;
    }
  }

  ulong total_skip_stake = self->voted_stakes.skip + self->voted_stakes.skip_fallback;
  if( ag_epoch_info_is_quorum( epoch_info, total_skip_stake ) ) {
    if( self->certs.skip.slot==ULONG_MAX ) {
      ag_slot_votes_t const *   v        = &self->votes;
      ag_vote_skip_t *          skip     = self->cert_builder->skip.votes;
      ag_vote_skip_fallback_t * sf       = self->cert_builder->skip.fallback_votes;
      ulong                     skip_cnt = 0UL;
      ulong                     sf_cnt   = 0UL;
      for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
        if( v->skip         [i].slot!=ULONG_MAX ) skip[ skip_cnt++ ] = v->skip         [i];
        if( v->skip_fallback[i].slot!=ULONG_MAX ) sf  [ sf_cnt++   ] = v->skip_fallback[i];
      }
      ag_cert_t cert = ag_cert_construct_skip( skip, skip_cnt, sf, sf_cnt, epoch_info );
      if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.skip.stake ) ) ) outputs.certs[ outputs.certs_cnt++ ] = cert;
    }
  }
  if( !self->sent_safe_to_skip
      && ag_epoch_info_is_weak_quorum( epoch_info, self->voted_stakes.notar_or_skip - self->voted_stakes.top_notar )
      && self->own_rank!=USHORT_MAX /* must be staked */
      && self->votes.notar[ self->own_rank ].slot!=ULONG_MAX ) {
    outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_SKIP, .safe_to_skip = slot };
    self->sent_safe_to_skip = 1;
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_finalize_stake( ag_slot_state_t * self,
                      ulong             stake ) {
  ag_epoch_info_t const * epoch_info = self->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.votor_events_cnt = 0UL; outputs.block_to_repair_cnt = 0UL;

  self->voted_stakes.finalize += stake;
  if( ag_epoch_info_is_quorum( epoch_info, self->voted_stakes.finalize ) && self->certs.finalize.slot==ULONG_MAX ) {
    ag_slot_votes_t const * v        = &self->votes;
    ag_vote_final_t *       finalize = self->cert_builder->final.votes;
    ulong                   cnt      = 0UL;
    for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
      if( v->finalize[i].slot!=ULONG_MAX ) finalize[ cnt++ ] = v->finalize[i];
    }
    ag_cert_t cert = ag_cert_construct_final( finalize, cnt, epoch_info );
    outputs.certs[ outputs.certs_cnt++ ] = cert;
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
    if( !ag_slot_state_is_notar_fallback( self, n->block_hash ) ) {
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
                        ulong             voter_stake ) {
  ag_slot_votes_t * v     = &self->votes;
  ulong             slot  = ag_vote_slot( vote );
  ulong             voter = ag_vote_rank( vote );

  ag_slot_state_outputs_t outputs;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR:
    v->notar[ voter ] = vote->notar;
    outputs = count_notar_stake( self, slot, vote->notar.block_hash, voter_stake );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    FD_TEST( v->notar_fallback_cnt[ voter ]<AG_NOTAR_FALLBACK_VOTE_MAX );
    v->notar_fallback[ voter ][ v->notar_fallback_cnt[ voter ]++ ] = vote->notar_fallback;
    outputs = count_notar_fallback_stake( self, vote->notar_fallback.block_hash, voter_stake );
    break;
  case AG_VOTE_KIND_SKIP:
    v->skip[ voter ] = vote->skip;
    self->voted_stakes.notar_or_skip += voter_stake;
    outputs = count_skip_stake( self, slot, voter_stake, 0 );
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    v->skip_fallback[ voter ] = vote->skip_fallback;
    outputs = count_skip_stake( self, slot, voter_stake, 1 );
    break;
  case AG_VOTE_KIND_FINAL:
    v->finalize[ voter ] = vote->final;
    outputs = count_finalize_stake( self, voter_stake );
    break;
  default:
    __builtin_unreachable();
  }

  if( voter==self->own_rank ) {
    ag_hash_set_t pending = self->pending_safe_to_notar;
    for( ulong i=0UL; i<pending.cnt; i++ ) {
      if( set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) continue;
      switch( check_safe_to_notar( self, pending.hash[i] ) ) {
      case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR: outputs.votor_events[ outputs.votor_events_cnt++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, pending.hash[i] ) }; break;
      case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
        ulong j; for( j=0UL; j<outputs.block_to_repair_cnt; j++ ) if( !memcmp( outputs.block_to_repair[j].hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) break;
        if( j==outputs.block_to_repair_cnt ) outputs.block_to_repair[ outputs.block_to_repair_cnt++ ] = ag_block_id( slot, pending.hash[i] );
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
                                   ag_block_hash_t const hash ) {
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( !memcmp( self->parents[i].hash, hash, sizeof(ag_block_hash_t) ) ) return;
  }
  FD_TEST( self->parents_cnt < AG_EQVOC_BLOCK_HASH_MAX );
  ag_parent_status_t * e = &self->parents[ self->parents_cnt++ ];
  memcpy( e->hash, hash, sizeof(ag_block_hash_t) );
  e->kind = AG_PARENT_STATUS_KNOWN;
}

int
ag_slot_state_notify_parent_certified( ag_slot_state_t *     self,
                                       ag_block_hash_t const hash ) {
  ag_parent_status_t * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( !memcmp( self->parents[i].hash, hash, sizeof(ag_block_hash_t) ) ) { parent = &self->parents[i]; break; }
  }
  FD_TEST( parent );
  parent->kind = AG_PARENT_STATUS_CERTIFIED;

  if( set_contains( &self->sent_safe_to_notar, hash ) ) return 0;

  switch( check_safe_to_notar( self, hash ) ) {
  case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK:  return -1;
  case AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES: return  0;
  case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:  return  1;
  default:                                     __builtin_unreachable();
  }
}

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const * self,
                                       ag_vote_t const *       vote ) {
  ulong voter = ag_vote_rank( vote );
  ag_slot_votes_t const * v = &self->votes;

  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( v->skip[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    if( v->notar[ voter ].slot!=ULONG_MAX
        && memcmp( vote->notar.block_hash, v->notar[ voter ].block_hash, sizeof(ag_block_hash_t) ) ) {
      return AG_SLASHABLE_NOTAR_DIFFERENT_HASH;
    }
    break;
  }

  case AG_VOTE_KIND_NOTAR_FALLBACK:
    if( v->finalize[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;

  case AG_VOTE_KIND_SKIP:
    if( v->finalize[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    } else if( v->notar[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    break;

  case AG_VOTE_KIND_SKIP_FALLBACK:
    if( v->finalize[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    break;

  case AG_VOTE_KIND_FINAL: {
    if( v->skip[ voter ].slot!=ULONG_MAX || v->skip_fallback[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    if( v->notar_fallback_cnt[ voter ] ) {
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
    if( v->notar[ voter ].slot!=ULONG_MAX ) return 1;

    uchar const * hash = vote->notar.block_hash;
    for( ulong j=0UL; j<v->notar_fallback_cnt[ voter ]; j++ ) {
      if( !memcmp( v->notar_fallback[ voter ][j].block_hash, hash, sizeof(ag_block_hash_t) ) ) return 1;
    }
    return 0;
  }
  case AG_VOTE_KIND_NOTAR_FALLBACK: {
    uchar const * hash = vote->notar_fallback.block_hash;
    for( ulong j=0UL; j<v->notar_fallback_cnt[ voter ]; j++ ) {
      if( !memcmp( v->notar_fallback[ voter ][j].block_hash, hash, sizeof(ag_block_hash_t) ) ) return 1;
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
