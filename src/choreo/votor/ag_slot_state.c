#include "ag_slot_state.h"

#define AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR  (0)
#define AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK  (1)
#define AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES (2)

void
ag_slot_state_init( ag_slot_state_t *       self,
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
  self->certificates.notar.slot         = ULONG_MAX;
  self->certificates.skip.slot          = ULONG_MAX;
  self->certificates.fast_finalize.slot = ULONG_MAX;
  self->certificates.finalize.slot      = ULONG_MAX;

  self->slot       = slot;
  self->epoch_info = epoch_info;
  self->own_rank   = own_rank;
}

FD_FN_PURE ulong
ag_slot_state_stake( ag_hashstake_t const * ele,
                     ulong                  cnt,
                     fd_hash_t const *      hash ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( !memcmp( ele[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return ele[i].stake;
  }
  return 0UL;
}

static ulong
hashstake_add( ag_hashstake_t *  ele,
               ulong *           cnt,
               ulong             cap,
               fd_hash_t const * hash,
               ulong             stake ) {
  ulong i;
  for( i=0UL; i<*cnt; i++ ) if( !memcmp( ele[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) break;
  if( i==*cnt ) {
    FD_TEST( *cnt<cap );
    ele[i].hash  = *hash;
    ele[i].stake = 0UL;
    (*cnt)++;
  }

  ulong total  = ele[i].stake + stake;
  ele[i].stake = total;
  for( ; i && ele[i-1].stake<total; i-- ) {
    ag_hashstake_t tmp = ele[i-1]; ele[i-1] = ele[i]; ele[i] = tmp;
  }
  return total;
}

static ag_notar_vote_t          gather_notar[ AG_VAT_MAX ];
static ag_notar_fallback_vote_t gather_nf   [ AG_VAT_MAX ];
static ag_skip_vote_t           gather_skip [ AG_VAT_MAX ];
static ag_skip_fallback_vote_t  gather_sf   [ AG_VAT_MAX ];
static ag_final_vote_t          gather_final[ AG_VAT_MAX ];

static ulong
gather_notar_votes( ag_slot_state_t const * slot_state,
                    fd_hash_t const *       block_hash ) {
  ag_slot_votes_t const * v   = &slot_state->votes;
  ulong                   cnt = 0UL;
  for( ulong i=0UL; i<slot_state->epoch_info->validator_cnt; i++ ) {
    if( v->notar[i].slot==ULONG_MAX                                            ) continue;
    if( memcmp( v->notar[i].block_hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) continue;
    gather_notar[ cnt++ ] = v->notar[i];
  }
  return cnt;
}

static ulong
gather_nf_votes( ag_slot_state_t const * slot_state,
                 fd_hash_t const *       block_hash ) {
  ag_slot_votes_t const * v   = &slot_state->votes;
  ulong                   cnt = 0UL;
  for( ulong i=0UL; i<slot_state->epoch_info->validator_cnt; i++ ) {
    for( ulong j=0UL; j<v->notar_fallback_cnt[i]; j++ ) {
      if( memcmp( v->notar_fallback[i][j].block_hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) continue;
      gather_nf[ cnt++ ] = v->notar_fallback[i][j];
      break;
    }
  }
  return cnt;
}

static int
set_contains( ag_hash_set_t const * set,
              fd_hash_t const *     hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( !memcmp( set->hash[i].uc, hash->uc, sizeof(fd_hash_t) ) ) return 1;
  }
  return 0;
}

static void
set_insert( ag_hash_set_t *   set,
            fd_hash_t const * hash ) {
  if( set_contains( set, hash ) ) return;
  FD_TEST( set->cnt < AG_BLOCK_HASH_EQVOC_MAX );
  set->hash[ set->cnt++ ] = *hash;
}

static void
set_remove( ag_hash_set_t *   set,
            fd_hash_t const * hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( !memcmp( set->hash[i].uc, hash->uc, sizeof(fd_hash_t) ) ) {
      set->hash[i] = set->hash[ --set->cnt ];
      return;
    }
  }
}

static void
out_push_cert( ag_slot_state_outputs_t * out,
               ag_cert_t const *         cert ) {
  fd_hash_t const * hash = ag_cert_block_hash( cert );
  if( hash ) {
    FD_BASE58_ENCODE_32_BYTES( hash->uc, hash_cstr );
    FD_LOG_NOTICE(( "created %s cert slot=%lu hash=%s", ag_cert_str( cert ), ag_cert_slot( cert ), hash_cstr ));
  } else {
    FD_LOG_NOTICE(( "created %s cert slot=%lu", ag_cert_str( cert ), ag_cert_slot( cert ) ));
  }
  FD_TEST( out->certs_cnt < AG_SLOT_STATE_OUT_CERT_MAX );
  out->certs[ out->certs_cnt++ ] = *cert;
}

static void
out_push_safe_to_notar( ag_slot_state_outputs_t * out,
                        ulong                     slot,
                        fd_hash_t const *         hash ) {
  FD_TEST( out->pool_events_cnt < AG_SLOT_STATE_OUT_EVENT_MAX );
  ag_pool_event_t * ev = &out->pool_events[ out->pool_events_cnt++ ];
  ev->kind                     = AG_POOL_EVENT_SAFE_TO_NOTAR;
  ev->inner.safe_to_notar.slot = slot;
  ev->inner.safe_to_notar.hash = *hash;
}

static void
out_push_safe_to_skip( ag_slot_state_outputs_t * out,
                       ulong                     slot ) {
  FD_TEST( out->pool_events_cnt < AG_SLOT_STATE_OUT_EVENT_MAX );
  ag_pool_event_t * ev = &out->pool_events[ out->pool_events_cnt++ ];
  ev->kind               = AG_POOL_EVENT_SAFE_TO_SKIP;
  ev->inner.safe_to_skip = slot;
}

static void
out_push_repair( ag_slot_state_outputs_t * out,
                 ulong                     slot,
                 fd_hash_t const *         hash ) {
  for( ulong i=0UL; i<out->block_repairs_cnt; i++ ) {
    if( !memcmp( out->block_repairs[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return;
  }
  FD_TEST( out->block_repairs_cnt < AG_SLOT_STATE_OUT_REPAIR_MAX );
  ag_block_id_t * b = &out->block_repairs[ out->block_repairs_cnt++ ];
  b->slot = slot;
  b->hash = *hash;
}

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * slot_state,
                                 fd_hash_t const *       block_hash ) {
  ag_slot_certificates_t const * c = &slot_state->certificates;
  for( ulong i=0UL; i<c->notar_fallback_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( c->notar_fallback[i].block_hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) ) return 1;
  }
  return 0;
}

FD_FN_PURE int
ag_slot_state_is_notar_fallback_or_stronger( ag_slot_state_t const * slot_state,
                                             fd_hash_t const *       block_hash ) {
  int has_notar_cert      = slot_state->certificates.notar.slot !=ULONG_MAX && !memcmp( slot_state->certificates.notar.block_hash.uc, block_hash->uc, sizeof(fd_hash_t) );
  int has_fast_final_cert = slot_state->certificates.fast_finalize.slot!=ULONG_MAX && !memcmp( slot_state->certificates.fast_finalize.block_hash.uc, block_hash->uc, sizeof(fd_hash_t) );
  return has_notar_cert || has_fast_final_cert || ag_slot_state_is_notar_fallback( slot_state, block_hash );
}

static int
check_safe_to_notar( ag_slot_state_t * slot_state,
                     fd_hash_t const * block_hash ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ulong notar_stake = ag_slot_state_stake( slot_state->voted_stakes.notar, slot_state->voted_stakes.notar_cnt, block_hash );
  ulong skip_stake  = slot_state->voted_stakes.skip;

  if( !ag_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) ) {
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }
  if( !ag_epoch_info_is_weak_quorum( epoch_info, notar_stake )
      && !ag_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) {
    set_insert( &slot_state->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  ag_parent_status_t const * parent = NULL;
  for( ulong i=0UL; i<slot_state->parents_cnt; i++ ) {
    if( !memcmp( slot_state->parents[i].hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) { parent = &slot_state->parents[i]; break; }
  }
  if( !parent                                   ) return AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK;
  if( parent->kind!=AG_PARENT_STATUS_CERTIFIED  ) return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;

  ag_slot_votes_t const * v   = &slot_state->votes;
  ulong                   own = slot_state->own_rank;

  if( v->skip[ own ].slot!=ULONG_MAX ) {
    set_remove( &slot_state->pending_safe_to_notar, block_hash );
    set_insert( &slot_state->sent_safe_to_notar,    block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
  }
  if( v->notar[ own ].slot!=ULONG_MAX ) {
    if( memcmp( v->notar[ own ].block_hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) {
      set_remove( &slot_state->pending_safe_to_notar, block_hash );
      set_insert( &slot_state->sent_safe_to_notar,    block_hash );
      return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
    }
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  set_insert( &slot_state->pending_safe_to_notar, block_hash );
  return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
}

static void
log_own_agg_complete( ag_slot_state_t * slot_state,
                      uint              kind,
                      ulong             stake ) {
  if( slot_state->own_agg_logged & (1U<<kind) ) return;
  slot_state->own_agg_logged |= (1U<<kind);
  ulong     total = slot_state->epoch_info->total_stake;
  ag_cert_t named = { .kind = kind }; /* ag_cert_str names a cert, and here there is only a kind */
  FD_LOG_NOTICE(( "own %s aggregation complete slot=%lu at %lu%% (cert was received first)",
                  ag_cert_str( &named ), slot_state->slot, total ? stake*100UL/total : 0UL ));
}

static ag_slot_state_outputs_t
count_notar_stake( ag_slot_state_t * slot_state,
                   ulong             slot,
                   fd_hash_t const * block_hash,
                   ulong             stake ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.pool_events_cnt = 0UL; outputs.block_repairs_cnt = 0UL;

  ulong notar_stake = hashstake_add( slot_state->voted_stakes.notar, &slot_state->voted_stakes.notar_cnt,
                                     AG_NOTAR_STAKE_MAX, block_hash, stake );
  slot_state->voted_stakes.notar_or_skip += stake;

  if( !set_contains( &slot_state->sent_safe_to_notar, block_hash ) ) {
    switch( check_safe_to_notar( slot_state, block_hash ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_push_safe_to_notar( &outputs, slot, block_hash );
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK:
      out_push_repair( &outputs, slot, block_hash );
      break;
    default: break;
    }
  }
  if( !slot_state->sent_safe_to_skip
      && ag_epoch_info_is_weak_quorum( epoch_info, slot_state->voted_stakes.notar_or_skip - slot_state->voted_stakes.notar[0].stake )
      && slot_state->votes.notar[ slot_state->own_rank ].slot!=ULONG_MAX ) {
    out_push_safe_to_skip( &outputs, slot );
    slot_state->sent_safe_to_skip = 1;
  }

  ulong nf_stake = ag_slot_state_stake( slot_state->voted_stakes.notar_fallback, slot_state->voted_stakes.notar_fallback_cnt, block_hash );
  if( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) ) {
    if( !ag_slot_state_is_notar_fallback( slot_state, block_hash ) ) {
      ulong n_cnt  = gather_notar_votes( slot_state, block_hash );
      ulong nf_cnt = gather_nf_votes   ( slot_state, block_hash );
      ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR_FALLBACK;
      cert.inner.notar_fallback = ag_notar_fallback_cert_construct( gather_notar, n_cnt, gather_nf, nf_cnt, epoch_info );
      out_push_cert( &outputs, &cert );
    } else {
      log_own_agg_complete( slot_state, AG_CERT_TYPE_NOTAR_FALLBACK, nf_stake + notar_stake );
    }
  }
  if( ag_epoch_info_is_quorum( epoch_info, notar_stake ) ) {
    if( slot_state->certificates.notar.slot==ULONG_MAX ) {
      ulong n_cnt = gather_notar_votes( slot_state, block_hash );
      ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR;
      cert.inner.notar = ag_notar_cert_construct( gather_notar, n_cnt, epoch_info );
      out_push_cert( &outputs, &cert );
    } else {
      log_own_agg_complete( slot_state, AG_CERT_TYPE_NOTAR, notar_stake );
    }
  }
  if( ag_epoch_info_is_strong_quorum( epoch_info, notar_stake ) ) {
    if( slot_state->certificates.fast_finalize.slot==ULONG_MAX ) {
      ulong n_cnt = gather_notar_votes( slot_state, block_hash );
      ag_cert_t cert; cert.kind = AG_CERT_TYPE_FAST_FINAL;
      cert.inner.fast_final = ag_fast_final_cert_construct( gather_notar, n_cnt, epoch_info );
      out_push_cert( &outputs, &cert );
    } else {
      log_own_agg_complete( slot_state, AG_CERT_TYPE_FAST_FINAL, notar_stake );
    }
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_notar_fallback_stake( ag_slot_state_t * slot_state,
                            fd_hash_t const * block_hash,
                            ulong             stake ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.pool_events_cnt = 0UL; outputs.block_repairs_cnt = 0UL;

  ulong nf_stake    = hashstake_add( slot_state->voted_stakes.notar_fallback, &slot_state->voted_stakes.notar_fallback_cnt,
                                     AG_NOTAR_FALLBACK_STAKE_MAX, block_hash, stake );
  ulong notar_stake = ag_slot_state_stake( slot_state->voted_stakes.notar, slot_state->voted_stakes.notar_cnt, block_hash );
  if( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) ) {
    if( !ag_slot_state_is_notar_fallback( slot_state, block_hash ) ) {
      ulong n_cnt  = gather_notar_votes( slot_state, block_hash );
      ulong nf_cnt = gather_nf_votes   ( slot_state, block_hash );
      ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR_FALLBACK;
      cert.inner.notar_fallback = ag_notar_fallback_cert_construct( gather_notar, n_cnt, gather_nf, nf_cnt, epoch_info );
      out_push_cert( &outputs, &cert );
    } else {
      log_own_agg_complete( slot_state, AG_CERT_TYPE_NOTAR_FALLBACK, nf_stake + notar_stake );
    }
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_skip_stake( ag_slot_state_t * slot_state,
                  ulong             slot,
                  ulong             stake,
                  int               fallback ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ag_slot_state_outputs_t outputs    = { 0 };

  if( fallback ) slot_state->voted_stakes.skip_fallback += stake;
  else           slot_state->voted_stakes.skip          += stake;

  ag_hash_set_t pending = slot_state->pending_safe_to_notar;
  for( ulong i=0UL; i<pending.cnt; i++ ) {
    if( set_contains( &slot_state->sent_safe_to_notar, &pending.hash[i] ) ) continue;
    switch( check_safe_to_notar( slot_state, &pending.hash[i] ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_push_safe_to_notar( &outputs, slot, &pending.hash[i] );
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK:
      out_push_repair( &outputs, slot, &pending.hash[i] );
      break;
    default:
      break;
    }
  }

  ulong total_skip_stake = slot_state->voted_stakes.skip + slot_state->voted_stakes.skip_fallback;
  if( ag_epoch_info_is_quorum( epoch_info, total_skip_stake ) ) {
    if( slot_state->certificates.skip.slot==ULONG_MAX ) {
      ag_slot_votes_t const * v         = &slot_state->votes;
      ulong                   skip_cnt  = 0UL;
      ulong                   sf_cnt    = 0UL;
      for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
        if( v->skip         [i].slot!=ULONG_MAX ) gather_skip[ skip_cnt++ ] = v->skip[i];
        if( v->skip_fallback[i].slot!=ULONG_MAX ) gather_sf  [ sf_cnt++   ] = v->skip_fallback[i];
      }
      ag_cert_t cert; cert.kind = AG_CERT_TYPE_SKIP;
      cert.inner.skip = ag_skip_cert_construct( gather_skip, skip_cnt, gather_sf, sf_cnt, epoch_info );
      out_push_cert( &outputs, &cert );
    } else {
      log_own_agg_complete( slot_state, AG_CERT_TYPE_SKIP, total_skip_stake );
    }
  }
  if( !slot_state->sent_safe_to_skip
      && ag_epoch_info_is_weak_quorum( epoch_info, slot_state->voted_stakes.notar_or_skip - slot_state->voted_stakes.notar[0].stake )
      && slot_state->votes.notar[ slot_state->own_rank ].slot!=ULONG_MAX ) {
    out_push_safe_to_skip( &outputs, slot );
    slot_state->sent_safe_to_skip = 1;
  }

  return outputs;
}

static ag_slot_state_outputs_t
count_finalize_stake( ag_slot_state_t * slot_state,
                      ulong             stake ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.pool_events_cnt = 0UL; outputs.block_repairs_cnt = 0UL;

  slot_state->voted_stakes.finalize += stake;
  if( ag_epoch_info_is_quorum( epoch_info, slot_state->voted_stakes.finalize ) ) {
    if( slot_state->certificates.finalize.slot==ULONG_MAX ) {
      ag_slot_votes_t const * v   = &slot_state->votes;
      ulong                   cnt = 0UL;
      for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
        if( v->finalize[i].slot!=ULONG_MAX ) gather_final[ cnt++ ] = v->finalize[i];
      }
      ag_cert_t cert; cert.kind = AG_CERT_TYPE_FINAL;
      cert.inner.final = ag_final_cert_construct( gather_final, cnt, epoch_info );
      out_push_cert( &outputs, &cert );
    } else {
      log_own_agg_complete( slot_state, AG_CERT_TYPE_FINAL, slot_state->voted_stakes.finalize );
    }
  }

  return outputs;
}

void
ag_slot_state_add_cert( ag_slot_state_t * slot_state,
                        ag_cert_t const * cert ) {
  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR: {
    slot_state->certificates.notar = cert->inner.notar;
    break;
  }
  case AG_CERT_TYPE_NOTAR_FALLBACK: {
    ag_notar_fallback_cert_t const * n = &cert->inner.notar_fallback;
    if( !ag_slot_state_is_notar_fallback( slot_state, &n->block_hash ) ) {
      FD_TEST( slot_state->certificates.notar_fallback_cnt < AG_NOTAR_FALLBACK_CERT_MAX );
      slot_state->certificates.notar_fallback[ slot_state->certificates.notar_fallback_cnt++ ] = *n;
    }
    break;
  }
  case AG_CERT_TYPE_SKIP: {
    slot_state->certificates.skip = cert->inner.skip;
    break;
  }
  case AG_CERT_TYPE_FAST_FINAL: {
    slot_state->certificates.fast_finalize = cert->inner.fast_final;
    break;
  }
  case AG_CERT_TYPE_FINAL: {
    slot_state->certificates.finalize = cert->inner.final;
    break;
  }
  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }
}

ag_slot_state_outputs_t
ag_slot_state_add_vote( ag_slot_state_t * slot_state,
                        ag_vote_t const * vote,
                        ulong             voter_stake ) {
  ag_slot_votes_t * v     = &slot_state->votes;
  ulong             slot  = ag_vote_slot( vote );
  ulong             voter = ag_vote_signer( vote );

  ag_slot_state_outputs_t outputs;
  switch( vote->kind ) {
  case AG_VOTE_TYPE_NOTAR:
    v->notar[ voter ] = vote->inner.notar;
    outputs = count_notar_stake( slot_state, slot, &vote->inner.notar.block_hash, voter_stake );
    break;
  case AG_VOTE_TYPE_NOTAR_FALLBACK:
    FD_TEST( v->notar_fallback_cnt[ voter ]<AG_NOTAR_FALLBACK_VOTE_MAX );
    v->notar_fallback[ voter ][ v->notar_fallback_cnt[ voter ]++ ] = vote->inner.notar_fallback;
    outputs = count_notar_fallback_stake( slot_state, &vote->inner.notar_fallback.block_hash, voter_stake );
    break;
  case AG_VOTE_TYPE_SKIP:
    v->skip[ voter ] = vote->inner.skip;
    slot_state->voted_stakes.notar_or_skip += voter_stake;
    outputs = count_skip_stake( slot_state, slot, voter_stake, 0 );
    break;
  case AG_VOTE_TYPE_SKIP_FALLBACK:
    v->skip_fallback[ voter ] = vote->inner.skip_fallback;
    outputs = count_skip_stake( slot_state, slot, voter_stake, 1 );
    break;
  case AG_VOTE_TYPE_FINAL:
    v->finalize[ voter ] = vote->inner.final;
    outputs = count_finalize_stake( slot_state, voter_stake );
    break;
  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }

  if( voter==slot_state->own_rank ) {
    ag_hash_set_t pending = slot_state->pending_safe_to_notar;
    for( ulong i=0UL; i<pending.cnt; i++ ) {
      if( set_contains( &slot_state->sent_safe_to_notar, &pending.hash[i] ) ) continue;
      switch( check_safe_to_notar( slot_state, &pending.hash[i] ) ) {
      case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR: out_push_safe_to_notar( &outputs, slot, &pending.hash[i] ); break;
      case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: out_push_repair       ( &outputs, slot, &pending.hash[i] ); break;
      default: break;
      }
    }
  }

  return outputs;
}

void
ag_slot_state_notify_parent_known( ag_slot_state_t * slot_state,
                                   fd_hash_t const * hash ) {
  for( ulong i=0UL; i<slot_state->parents_cnt; i++ ) {
    if( !memcmp( slot_state->parents[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return;
  }
  FD_TEST( slot_state->parents_cnt < AG_BLOCK_HASH_EQVOC_MAX );
  ag_parent_status_t * e = &slot_state->parents[ slot_state->parents_cnt++ ];
  e->hash = *hash;
  e->kind = AG_PARENT_STATUS_KNOWN;
}

int
ag_slot_state_notify_parent_certified( ag_slot_state_t * slot_state,
                                       fd_hash_t const * hash ) {
  ag_parent_status_t * parent = NULL;
  for( ulong i=0UL; i<slot_state->parents_cnt; i++ ) {
    if( !memcmp( slot_state->parents[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) { parent = &slot_state->parents[i]; break; }
  }
  FD_TEST( parent );
  parent->kind = AG_PARENT_STATUS_CERTIFIED;

  if( set_contains( &slot_state->sent_safe_to_notar, hash ) ) return 0;

  switch( check_safe_to_notar( slot_state, hash ) ) {
  case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK:  return -1;
  case AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES: return  0;
  case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:  return  1;
  default: FD_LOG_ERR(( "unimplemented" ));
  }
}

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const * slot_state,
                                       ag_vote_t const *       vote ) {
  ulong voter = ag_vote_signer( vote );
  ag_slot_votes_t const * v = &slot_state->votes;

  switch( vote->kind ) {
  case AG_VOTE_TYPE_NOTAR: {
    if( v->skip[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    if( v->notar[ voter ].slot!=ULONG_MAX
        && memcmp( vote->inner.notar.block_hash.uc, v->notar[ voter ].block_hash.uc, sizeof(fd_hash_t) ) ) {
      return AG_SLASHABLE_NOTAR_DIFFERENT_HASH;
    }
    break;
  }

  case AG_VOTE_TYPE_NOTAR_FALLBACK:
    if( v->finalize[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;

  case AG_VOTE_TYPE_SKIP:
    if( v->finalize[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    } else if( v->notar[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    break;

  case AG_VOTE_TYPE_SKIP_FALLBACK:
    if( v->finalize[ voter ].slot!=ULONG_MAX ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    break;

  case AG_VOTE_TYPE_FINAL: {
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
ag_slot_state_should_ignore_vote( ag_slot_state_t const * slot_state,
                                  ag_vote_t const *       vote ) {
  ulong voter = ag_vote_signer( vote );
  ag_slot_votes_t const * v = &slot_state->votes;
  switch( vote->kind ) {
  case AG_VOTE_TYPE_NOTAR: {
    if( v->notar[ voter ].slot!=ULONG_MAX ) return 1;

    fd_hash_t const * hash = ag_vote_block_hash( vote );
    for( ulong j=0UL; j<v->notar_fallback_cnt[ voter ]; j++ ) {
      if( !memcmp( v->notar_fallback[ voter ][j].block_hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return 1;
    }
    return 0;
  }
  case AG_VOTE_TYPE_NOTAR_FALLBACK: {
    fd_hash_t const * hash = ag_vote_block_hash( vote );
    for( ulong j=0UL; j<v->notar_fallback_cnt[ voter ]; j++ ) {
      if( !memcmp( v->notar_fallback[ voter ][j].block_hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return 1;
    }

    return v->notar[ voter ].slot!=ULONG_MAX &&
           !memcmp( v->notar[ voter ].block_hash.uc, hash->uc, sizeof(fd_hash_t) );
  }
  case AG_VOTE_TYPE_SKIP:
  case AG_VOTE_TYPE_SKIP_FALLBACK:
    return v->skip[ voter ].slot!=ULONG_MAX || v->skip_fallback[ voter ].slot!=ULONG_MAX;
  case AG_VOTE_TYPE_FINAL:
    return v->finalize[ voter ].slot!=ULONG_MAX;
  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return 0;
}

FD_FN_PURE int
ag_slot_state_vote_fits( ag_slot_state_t const * slot_state,
                         ag_vote_t const *       vote ) {
  if( vote->kind!=AG_VOTE_TYPE_NOTAR_FALLBACK ) return 1;
  return slot_state->votes.notar_fallback_cnt[ ag_vote_signer( vote ) ]<AG_NOTAR_FALLBACK_VOTE_MAX;
}

FD_FN_PURE int
ag_slot_state_cert_fits( ag_slot_state_t const * slot_state,
                         ag_cert_t const *       cert ) {
  if( cert->kind!=AG_CERT_TYPE_NOTAR_FALLBACK                                  ) return 1;
  if( ag_slot_state_is_notar_fallback( slot_state, ag_cert_block_hash( cert ) )) return 1;
  return slot_state->certificates.notar_fallback_cnt<AG_NOTAR_FALLBACK_CERT_MAX;
}

FD_FN_PURE ulong
ag_slot_state_cert_voted_stake( ag_slot_state_t const * slot_state,
                                ag_cert_t const *       cert ) {
  ag_slot_voted_stake_t const * vs = &slot_state->voted_stakes;
  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:
  case AG_CERT_TYPE_FAST_FINAL:
    return ag_slot_state_stake( vs->notar, vs->notar_cnt, ag_cert_block_hash( cert ) );
  case AG_CERT_TYPE_NOTAR_FALLBACK: {
    fd_hash_t const * h = ag_cert_block_hash( cert );
    return ag_slot_state_stake( vs->notar, vs->notar_cnt, h ) + ag_slot_state_stake( vs->notar_fallback, vs->notar_fallback_cnt, h );
  }
  case AG_CERT_TYPE_SKIP:
    return vs->skip + vs->skip_fallback;
  case AG_CERT_TYPE_FINAL:
    return vs->finalize;
  default:
    return 0UL;
  }
}
