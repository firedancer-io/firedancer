#include "ag_slot_state.h"
#include "ag_vote_serde.h"

#define AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR  (0)
#define AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK  (1)
#define AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES (2)

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

static int
verify_votes( ag_slot_state_t const * self,
              uint                    kind,
              ag_block_hash_t const   block_hash,
              fd_bls_agg_t const *    agg,
              fd_bls_set_t *          bad ) {
  ag_epoch_info_t const *       epoch_info  = self->epoch_info;
  ag_slot_voted_stake_t const * voted_stake = &self->votes;

  fd_bls_sig_t const * sigs;
  fd_bls_sig_t         nf_sig[ AG_VAT_MAX ];
  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:         sigs = voted_stake->notar_sig;         break;
  case AG_VOTE_KIND_SKIP:          sigs = voted_stake->skip_sig;          break;
  case AG_VOTE_KIND_SKIP_FALLBACK: sigs = voted_stake->skip_fallback_sig; break;
  case AG_VOTE_KIND_FINAL:         sigs = voted_stake->finalize_sig;      break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    for( ulong rank = fd_bls_set_const_iter_init( agg->set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( agg->set, rank ) ) {
      for( ulong j=0UL; j<voted_stake->notar_fallback_sig_cnt[ rank ]; j++ ) if( FD_LIKELY( !memcmp( voted_stake->notar_fallback_sig_hash[ rank ][ j ], block_hash, sizeof(ag_block_hash_t) ) ) ) nf_sig[ rank ] = voted_stake->notar_fallback_sig[ rank ][ j ];
    }
    sigs = nf_sig;
    break;
  default: FD_LOG_CRIT(( "unreachable" ));
  }

  uchar msg[ AG_VOTE_SIGNING_SER_MAX ];
  ulong msg_sz = ag_vote_signing_ser( kind, self->slot, block_hash, self->shred_version, msg );
  if( FD_LIKELY( fd_bls_agg_verify( msg, msg_sz, &agg->pub, &agg->sig ) ) ) { fd_bls_set_null( bad ); return 1; }
  fd_bls_agg_verify_bisect( agg, msg, msg_sz, epoch_info->pubkeys, sigs, bad );
  return 0;
}

static int
subtract_votes( ag_slot_state_t *     self,
                uint                  kind,
                ag_block_hash_t const block_hash,
                fd_bls_agg_t const *  agg,
                fd_bls_set_t const *  bad ) {
  ag_epoch_info_t const * epoch_info  = self->epoch_info;
  ag_slot_voted_stake_t * voted_stake = &self->votes;
  int                     emptied     = fd_bls_set_cnt( bad )==fd_bls_set_cnt( agg->set );

  ag_slot_voted_stake_hash_t * voted_stake_for_hash = NULL;
  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:          voted_stake_for_hash = notar_map_query         ( voted_stake->notar,          FD_LOAD( ag_block_hash_key_t, block_hash ), NULL ); break;
  case AG_VOTE_KIND_NOTAR_FALLBACK: voted_stake_for_hash = notar_fallback_map_query( voted_stake->notar_fallback, FD_LOAD( ag_block_hash_key_t, block_hash ), NULL ); break;
  default: break;
  }

  for( ulong rank = fd_bls_set_const_iter_init( bad );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( bad, rank ) ) {
    ulong        stake   = ag_epoch_info_validator( epoch_info, rank )->stake;
    fd_bls_pub_t neg_pub = ag_epoch_info_validator( epoch_info, rank )->bls_key; blst_p1_cneg( &neg_pub, 1 );
    fd_bls_sig_t neg_sig;
    switch( kind ) {
    case AG_VOTE_KIND_NOTAR:
      neg_sig = voted_stake->notar_sig[ rank ]; blst_p2_cneg( &neg_sig, 1 );
      voted_stake_for_hash->stake -= stake;
      blst_p1_add_or_double( &voted_stake_for_hash->agg.pub, &voted_stake_for_hash->agg.pub, &neg_pub );
      blst_p2_add_or_double( &voted_stake_for_hash->agg.sig, &voted_stake_for_hash->agg.sig, &neg_sig );
      fd_bls_set_remove( voted_stake_for_hash->agg.set, rank );
      voted_stake->notar_or_skip -= stake;
      break;
    case AG_VOTE_KIND_NOTAR_FALLBACK: {
      ulong j;
      for( j=0UL; j<voted_stake->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_UNLIKELY( 0==memcmp( voted_stake->notar_fallback_sig_hash[ rank ][ j ], block_hash, sizeof(ag_block_hash_t) ) ) ) break;
      }
      FD_CHECK_CRIT( j<voted_stake->notar_fallback_sig_cnt[ rank ], "invariant violation" );
      neg_sig = voted_stake->notar_fallback_sig[ rank ][ j ]; blst_p2_cneg( &neg_sig, 1 );
      voted_stake_for_hash->stake -= stake;
      blst_p1_add_or_double( &voted_stake_for_hash->agg.pub, &voted_stake_for_hash->agg.pub, &neg_pub );
      blst_p2_add_or_double( &voted_stake_for_hash->agg.sig, &voted_stake_for_hash->agg.sig, &neg_sig );
      fd_bls_set_remove( voted_stake_for_hash->agg.set, rank );
      voted_stake->notar_fallback_sig_cnt[ rank ]--;
      voted_stake->notar_fallback_sig[ rank ][ j ] = voted_stake->notar_fallback_sig[ rank ][ voted_stake->notar_fallback_sig_cnt[ rank ] ];
      if( FD_UNLIKELY( j!=voted_stake->notar_fallback_sig_cnt[ rank ] ) ) memcpy( voted_stake->notar_fallback_sig_hash[ rank ][ j ], voted_stake->notar_fallback_sig_hash[ rank ][ voted_stake->notar_fallback_sig_cnt[ rank ] ], sizeof(ag_block_hash_t) );
      break;
    }
    case AG_VOTE_KIND_SKIP:
      neg_sig = voted_stake->skip_sig[ rank ]; blst_p2_cneg( &neg_sig, 1 );
      voted_stake->skip -= stake;
      blst_p1_add_or_double( &voted_stake->skip_agg.pub, &voted_stake->skip_agg.pub, &neg_pub );
      blst_p2_add_or_double( &voted_stake->skip_agg.sig, &voted_stake->skip_agg.sig, &neg_sig );
      fd_bls_set_remove( voted_stake->skip_agg.set, rank );
      voted_stake->notar_or_skip -= stake;
      break;
    case AG_VOTE_KIND_SKIP_FALLBACK:
      neg_sig = voted_stake->skip_fallback_sig[ rank ]; blst_p2_cneg( &neg_sig, 1 );
      voted_stake->skip_fallback -= stake;
      blst_p1_add_or_double( &voted_stake->skip_fallback_agg.pub, &voted_stake->skip_fallback_agg.pub, &neg_pub );
      blst_p2_add_or_double( &voted_stake->skip_fallback_agg.sig, &voted_stake->skip_fallback_agg.sig, &neg_sig );
      fd_bls_set_remove( voted_stake->skip_fallback_agg.set, rank );
      break;
    case AG_VOTE_KIND_FINAL:
      neg_sig = voted_stake->finalize_sig[ rank ]; blst_p2_cneg( &neg_sig, 1 );
      voted_stake->finalize -= stake;
      blst_p1_add_or_double( &voted_stake->finalize_agg.pub, &voted_stake->finalize_agg.pub, &neg_pub );
      blst_p2_add_or_double( &voted_stake->finalize_agg.sig, &voted_stake->finalize_agg.sig, &neg_sig );
      fd_bls_set_remove( voted_stake->finalize_agg.set, rank );
      break;
    default:
      FD_LOG_CRIT(( "unreachable" ));
    }
  }

  if( FD_UNLIKELY( kind==AG_VOTE_KIND_NOTAR          && emptied ) ) notar_map_remove         ( voted_stake->notar,          voted_stake_for_hash );
  if( FD_UNLIKELY( kind==AG_VOTE_KIND_NOTAR_FALLBACK && emptied ) ) notar_fallback_map_remove( voted_stake->notar_fallback, voted_stake_for_hash );
  if( FD_UNLIKELY( kind==AG_VOTE_KIND_NOTAR ) ) {
    voted_stake->top_notar = 0UL;
    for( ulong slot_idx=0UL; slot_idx<notar_map_slot_cnt(); slot_idx++ ) {
      if( FD_LIKELY( notar_map_key_inval( voted_stake->notar[ slot_idx ].hash ) ) ) continue;
      if( FD_LIKELY( voted_stake->notar[ slot_idx ].stake>voted_stake->top_notar ) ) { /* FIXME slow */
        voted_stake->top_notar = voted_stake->notar[ slot_idx ].stake;
        memcpy( voted_stake->top_notar_hash, voted_stake->notar[ slot_idx ].hash.uc, sizeof(ag_block_hash_t) );
      }
    }
  }
  return !emptied && !blst_p1_is_inf( &agg->pub );
}

static int
check_safe_to_notar( ag_slot_state_t *     self,
                     ag_block_hash_t const block_hash,
                     fd_bls_set_t *        bad ) {
  ag_epoch_info_t const *      epoch_info  = self->epoch_info;
  ag_slot_voted_stake_t *      voted_stake = &self->votes;
  ag_block_hash_key_t                    key         = FD_LOAD( ag_block_hash_key_t, block_hash );
  ag_slot_voted_stake_hash_t * notar       = notar_map_query( voted_stake->notar, key, NULL );
  ulong                        notar_stake = notar ? notar->stake : 0UL;
  ulong                        skip_stake  = voted_stake->skip;

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

  ulong own = self->own_rank;

  int safe_to_notar = 0;
  if( FD_LIKELY( own!=USHORT_MAX ) ) { /* must be staked */
    if( FD_UNLIKELY( fd_bls_set_test( voted_stake->skip_agg.set, own ) ) ) safe_to_notar = 1;
    for( ulong slot_idx=0UL; slot_idx<notar_map_slot_cnt(); slot_idx++ ) {
      if( FD_LIKELY( notar_map_key_inval( voted_stake->notar[ slot_idx ].hash ) || !fd_bls_set_test( voted_stake->notar[ slot_idx ].agg.set, own ) ) ) continue;
      if( FD_UNLIKELY( memcmp( voted_stake->notar[ slot_idx ].hash.uc, block_hash, sizeof(ag_block_hash_t) ) ) ) safe_to_notar = 1;
      else return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
    }
  }
  if( FD_UNLIKELY( !safe_to_notar ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
  int notar_verified = verify_votes( self, AG_VOTE_KIND_NOTAR, block_hash, &notar->agg, bad_notar );
  if( FD_UNLIKELY( !notar_verified ) ) subtract_votes( self, AG_VOTE_KIND_NOTAR, block_hash, &notar->agg, bad_notar );
  fd_bls_set_union( bad, bad, bad_notar );
  if( FD_LIKELY( !fd_bls_set_is_null( voted_stake->skip_agg.set ) ) ) {
    fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
    int skip_verified = verify_votes( self, AG_VOTE_KIND_SKIP, NULL, &voted_stake->skip_agg, bad_skip );
    if( FD_UNLIKELY( !skip_verified ) ) subtract_votes( self, AG_VOTE_KIND_SKIP, NULL, &voted_stake->skip_agg, bad_skip );
    fd_bls_set_union( bad, bad, bad_skip );
  }
  notar       = notar_map_query( voted_stake->notar, key, NULL );
  notar_stake = notar ? notar->stake : 0UL;
  skip_stake  = voted_stake->skip;
  if( FD_UNLIKELY( !ag_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) || ( !ag_epoch_info_is_weak_quorum( epoch_info, notar_stake ) && !ag_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  block_hash_set_remove( &self->pending_safe_to_notar, block_hash );
  block_hash_set_insert( &self->sent_safe_to_notar,    block_hash );
  return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
}

static int
check_safe_to_skip( ag_slot_state_t * self,
                    fd_bls_set_t *    bad ) {
  ag_epoch_info_t const * epoch_info  = self->epoch_info;
  ag_slot_voted_stake_t * voted_stake = &self->votes;
  if( FD_LIKELY( self->sent_safe_to_skip
                 || !ag_epoch_info_is_weak_quorum( epoch_info, voted_stake->notar_or_skip - voted_stake->top_notar )
                 || self->own_rank==USHORT_MAX /* must be staked */ ) ) return 0;
  int own_notar = 0;
  for( ulong slot_idx=0UL; slot_idx<notar_map_slot_cnt(); slot_idx++ ) own_notar |= !notar_map_key_inval( voted_stake->notar[ slot_idx ].hash ) && fd_bls_set_test( voted_stake->notar[ slot_idx ].agg.set, self->own_rank );
  if( FD_LIKELY( !own_notar ) ) return 0;

  ulong slot_idx = 0UL;
  while( slot_idx<notar_map_slot_cnt() ) {
    ag_slot_voted_stake_hash_t * notar = &voted_stake->notar[ slot_idx ];
    if( FD_LIKELY( notar_map_key_inval( notar->hash ) ) ) { slot_idx++; continue; }
    ag_block_hash_key_t    key = notar->hash;
    fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
    int notar_verified = verify_votes( self, AG_VOTE_KIND_NOTAR, key.uc, &notar->agg, bad_notar );
    if( FD_UNLIKELY( !notar_verified ) ) subtract_votes( self, AG_VOTE_KIND_NOTAR, key.uc, &notar->agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    if( FD_LIKELY( notar_map_key_equal( notar->hash, key ) ) ) slot_idx++;
  }
  if( FD_LIKELY( !fd_bls_set_is_null( voted_stake->skip_agg.set ) ) ) {
    fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
    int skip_verified = verify_votes( self, AG_VOTE_KIND_SKIP, NULL, &voted_stake->skip_agg, bad_skip );
    if( FD_UNLIKELY( !skip_verified ) ) subtract_votes( self, AG_VOTE_KIND_SKIP, NULL, &voted_stake->skip_agg, bad_skip );
    fd_bls_set_union( bad, bad, bad_skip );
  }
  own_notar = 0;
  for( slot_idx=0UL; slot_idx<notar_map_slot_cnt(); slot_idx++ ) own_notar |= !notar_map_key_inval( voted_stake->notar[ slot_idx ].hash ) && fd_bls_set_test( voted_stake->notar[ slot_idx ].agg.set, self->own_rank );
  if( FD_UNLIKELY( !ag_epoch_info_is_weak_quorum( epoch_info, voted_stake->notar_or_skip - voted_stake->top_notar ) || !own_notar ) ) return 0;
  self->sent_safe_to_skip = 1;
  return 1;
}

static int
count_notar_stake( ag_slot_state_t *       self,
                   ag_vote_notar_t const * vote,
                   ulong                   stake,
                   ag_event_cert_t *       out_cert_events,
                   ulong *                 out_cert_event_cnt,
                   ag_event_pool_t *       out_pool_events,
                   ulong *                 out_pool_event_cnt,
                   ag_event_repair_t *     out_repair_events,
                   ulong *                 out_repair_event_cnt,
                   fd_bls_set_t *          bad ) {
  ag_epoch_info_t const * epoch_info    = self->epoch_info;
  ulong                   slot          = vote->slot;
  uchar const *           block_hash    = vote->block_hash;
  ag_block_hash_key_t     key           = FD_LOAD( ag_block_hash_key_t, block_hash );
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;
  fd_bls_sig_t const *    sig           = &vote->sig;
  fd_bls_pub_t const *    pub           = &ag_epoch_info_validator( epoch_info, rank )->bls_key;

  ag_slot_voted_stake_t *      voted_stake          = &self->votes;
  ag_slot_voted_stake_hash_t * voted_stake_for_hash = notar_map_query( voted_stake->notar, key, NULL );
  if( FD_UNLIKELY( !voted_stake_for_hash ) ) {
    voted_stake_for_hash = notar_map_insert( voted_stake->notar, key );
    voted_stake_for_hash->stake = 0UL;
    memset( &voted_stake_for_hash->agg, 0, sizeof(fd_bls_agg_t) ); /* zero is the point at infinity */
  }
  voted_stake_for_hash->stake += stake;
  blst_p1_add_or_double( &voted_stake_for_hash->agg.pub, &voted_stake_for_hash->agg.pub, pub );
  blst_p2_add_or_double( &voted_stake_for_hash->agg.sig, &voted_stake_for_hash->agg.sig, sig );
  fd_bls_set_insert( voted_stake_for_hash->agg.set, rank );

  ulong notar_stake           = voted_stake_for_hash->stake;
  voted_stake->notar_or_skip += stake;
  if( FD_LIKELY( notar_stake>voted_stake->top_notar ) ) {
    voted_stake->top_notar = notar_stake;
    memcpy( voted_stake->top_notar_hash, block_hash, sizeof(ag_block_hash_t) );
  }

  if( FD_UNLIKELY( !block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) {
    switch( check_safe_to_notar( self, block_hash, bad ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_pool_events[ (*out_pool_event_cnt)++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, block_hash ) };
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].block.hash, block_hash, sizeof(ag_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ].block = ag_block_id( slot, block_hash );
      break;
    }
    default: break;
    }
  }
  if( FD_UNLIKELY( check_safe_to_skip( self, bad ) ) ) {
    out_pool_events[ (*out_pool_event_cnt)++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_SKIP, .safe_to_skip = slot };
  }
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) ) ) {
    voted_stake_for_hash = notar_map_query( voted_stake->notar, key, NULL );
    if( FD_UNLIKELY( !voted_stake_for_hash || !fd_bls_set_test( voted_stake_for_hash->agg.set, rank ) ) ) return 0;
    notar_stake = voted_stake_for_hash->stake;
  }

  ag_slot_voted_stake_hash_t * voted_stake_for_hash_fallback = notar_fallback_map_query( voted_stake->notar_fallback, key, NULL );
  ulong nf_stake = voted_stake_for_hash_fallback ? voted_stake_for_hash_fallback->stake : 0UL;

  int notar_verified          = 0;
  int notar_fallback_verified = 0;

  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) ) ) {
    fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
    notar_verified = verify_votes( self, AG_VOTE_KIND_NOTAR, block_hash, &voted_stake_for_hash->agg, bad_notar );
    if( FD_UNLIKELY( !notar_verified ) ) notar_verified = subtract_votes( self, AG_VOTE_KIND_NOTAR, block_hash, &voted_stake_for_hash->agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    if( FD_UNLIKELY( fd_bls_set_test( bad_notar, rank ) ) ) return 0;

    notar_stake = voted_stake_for_hash->stake;
    if( FD_LIKELY( voted_stake_for_hash_fallback ) ) {
      fd_bls_set_t bad_nf[ fd_bls_set_word_cnt ];
      notar_fallback_verified = verify_votes( self, AG_VOTE_KIND_NOTAR_FALLBACK, block_hash, &voted_stake_for_hash_fallback->agg, bad_nf );
      if( FD_UNLIKELY( !notar_fallback_verified ) ) notar_fallback_verified = subtract_votes( self, AG_VOTE_KIND_NOTAR_FALLBACK, block_hash, &voted_stake_for_hash_fallback->agg, bad_nf );
      fd_bls_set_union( bad, bad, bad_nf );
    }
  }

  if( FD_UNLIKELY( !ag_slot_state_is_notar_fallback( self, block_hash ) ) ) {
    ag_cert_notar_fallback_t cert = { .slot = slot, .shred_version = shred_version }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );

    if( FD_LIKELY( notar_verified ) ) {
      cert.agg_notar = voted_stake_for_hash->agg;
      cert.stake += voted_stake_for_hash->stake;
    }
    if( FD_LIKELY( notar_fallback_verified ) ) {
      cert.agg_notar_fallback = voted_stake_for_hash_fallback->agg;
      cert.stake += voted_stake_for_hash_fallback->stake;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[( *out_cert_event_cnt )++].cert = ( ag_cert_t ){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
    }
  }

  if( FD_UNLIKELY( notar_verified && ag_epoch_info_is_quorum( epoch_info, notar_stake ) && self->certs.notar.slot==ULONG_MAX ) ) {
    ag_cert_notar_t cert = { .slot = slot, .shred_version = shred_version, .stake = notar_stake, .agg = voted_stake_for_hash->agg }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
    out_cert_events[ (*out_cert_event_cnt)++ ].cert = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR, .notar = cert };
  }

  if( FD_UNLIKELY( notar_verified && ag_epoch_info_is_strong_quorum( epoch_info, notar_stake ) && self->certs.fast_finalize.slot==ULONG_MAX ) ) {
    ag_cert_fast_final_t cert = { .slot = slot, .shred_version = shred_version, .stake = notar_stake, .agg = voted_stake_for_hash->agg }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
    out_cert_events[ (*out_cert_event_cnt)++ ].cert = (ag_cert_t){ .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = cert };
  }

  return 1;
}

static int
count_notar_fallback_stake( ag_slot_state_t *                self,
                            ag_vote_notar_fallback_t const * vote,
                            ulong                            stake,
                            ag_event_cert_t *                out_cert_events,
                            ulong *                          out_cert_event_cnt,
                            fd_bls_set_t *                   bad ) {
  ag_epoch_info_t const * epoch_info    = self->epoch_info;
  ulong                   slot          = vote->slot;
  uchar const *           block_hash    = vote->block_hash;
  ag_block_hash_key_t               key           = FD_LOAD( ag_block_hash_key_t, block_hash );
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;
  fd_bls_sig_t const *    sig           = &vote->sig;
  fd_bls_pub_t const *    pub           = &ag_epoch_info_validator( epoch_info, rank )->bls_key;

  ag_slot_voted_stake_t *      voted_stake          = &self->votes;
  ag_slot_voted_stake_hash_t * voted_stake_for_hash = notar_fallback_map_query( voted_stake->notar_fallback, key, NULL );
  if( FD_UNLIKELY( !voted_stake_for_hash ) ) {
    voted_stake_for_hash = notar_fallback_map_insert( voted_stake->notar_fallback, key );
    voted_stake_for_hash->stake = 0UL;
    memset( &voted_stake_for_hash->agg, 0, sizeof(fd_bls_agg_t) ); /* zero is the point at infinity */
  }
  voted_stake_for_hash->stake += stake;
  blst_p1_add_or_double( &voted_stake_for_hash->agg.pub, &voted_stake_for_hash->agg.pub, pub );
  blst_p2_add_or_double( &voted_stake_for_hash->agg.sig, &voted_stake_for_hash->agg.sig, sig );
  fd_bls_set_insert( voted_stake_for_hash->agg.set, rank );

  ag_slot_voted_stake_hash_t * notar = notar_map_query( voted_stake->notar, key, NULL );
  ulong nf_stake    = voted_stake_for_hash->stake;
  ulong notar_stake = notar ? notar->stake : 0UL;
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) && !ag_slot_state_is_notar_fallback( self, block_hash ) ) ) {
    fd_bls_set_t bad_nf[ fd_bls_set_word_cnt ];
    int nf_verified = verify_votes( self, AG_VOTE_KIND_NOTAR_FALLBACK, block_hash, &voted_stake_for_hash->agg, bad_nf );
    if( FD_UNLIKELY( !nf_verified ) ) nf_verified = subtract_votes( self, AG_VOTE_KIND_NOTAR_FALLBACK, block_hash, &voted_stake_for_hash->agg, bad_nf );
    fd_bls_set_union( bad, bad, bad_nf );
    if( FD_UNLIKELY( fd_bls_set_test( bad_nf, rank ) ) ) return 0;
    int notar_verified = 0;
    if( FD_LIKELY( notar ) ) {
      fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
      notar_verified = verify_votes( self, AG_VOTE_KIND_NOTAR, block_hash, &notar->agg, bad_notar );
      if( FD_UNLIKELY( !notar_verified ) ) notar_verified = subtract_votes( self, AG_VOTE_KIND_NOTAR, block_hash, &notar->agg, bad_notar );
      fd_bls_set_union( bad, bad, bad_notar );
    }

    ag_cert_notar_fallback_t cert = { .slot = slot, .shred_version = shred_version }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );

    if( FD_LIKELY( notar_verified ) ) {
      cert.agg_notar = notar->agg;
      cert.stake += notar->stake;
    }
    if( FD_LIKELY( nf_verified ) ) {
      cert.agg_notar_fallback = voted_stake_for_hash->agg;
      cert.stake += voted_stake_for_hash->stake;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[ (*out_cert_event_cnt)++ ].cert = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
    }
  }

  return 1;
}

static int
count_skip_stake( ag_slot_state_t *   self,
                  ag_vote_t const *   vote,
                  ulong               stake,
                  ag_event_cert_t *   out_cert_events,
                  ulong *             out_cert_event_cnt,
                  ag_event_pool_t *   out_pool_events,
                  ulong *             out_pool_event_cnt,
                  ag_event_repair_t * out_repair_events,
                  ulong *             out_repair_event_cnt,
                  fd_bls_set_t *      bad ) {
  ag_epoch_info_t const * epoch_info    = self->epoch_info;
  int                     fallback      = vote->kind==AG_VOTE_KIND_SKIP_FALLBACK;
  ulong                   slot          = ag_vote_slot( vote );
  ulong                   rank          = ag_vote_rank( vote );
  ushort                  shred_version = ag_vote_shred_version( vote );
  fd_bls_sig_t const *    sig           = ag_vote_sig( vote );
  fd_bls_pub_t const *    pub           = &ag_epoch_info_validator( epoch_info, rank )->bls_key;

  ag_slot_voted_stake_t * voted_stake = &self->votes;
  if( FD_UNLIKELY( fallback ) ) { voted_stake->skip_fallback += stake; blst_p1_add_or_double( &voted_stake->skip_fallback_agg.pub, &voted_stake->skip_fallback_agg.pub, pub ); blst_p2_add_or_double( &voted_stake->skip_fallback_agg.sig, &voted_stake->skip_fallback_agg.sig, sig ); fd_bls_set_insert( voted_stake->skip_fallback_agg.set, rank ); }
  else                          { voted_stake->skip          += stake; blst_p1_add_or_double( &voted_stake->skip_agg.pub,          &voted_stake->skip_agg.pub,          pub ); blst_p2_add_or_double( &voted_stake->skip_agg.sig,          &voted_stake->skip_agg.sig,          sig ); fd_bls_set_insert( voted_stake->skip_agg.set,          rank ); }

  ag_block_hash_set_t pending = self->pending_safe_to_notar;
  for( ulong i=0UL; i<pending.cnt; i++ ) {
    if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) ) continue;
    switch( check_safe_to_notar( self, pending.hash[i], bad ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_pool_events[ (*out_pool_event_cnt)++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, pending.hash[i] ) };
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].block.hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ].block = ag_block_id( slot, pending.hash[i] );
      break;
    }
    default:
      break;
    }
  }

  if( FD_UNLIKELY( check_safe_to_skip( self, bad ) ) ) {
    out_pool_events[ (*out_pool_event_cnt)++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_SKIP, .safe_to_skip = slot };
  }
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) && !fd_bls_set_test( fallback ? voted_stake->skip_fallback_agg.set : voted_stake->skip_agg.set, rank ) ) ) return 0;

  ulong total_skip_stake = voted_stake->skip + voted_stake->skip_fallback;

  int skip_verified          = 0;
  int skip_fallback_verified = 0;
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, total_skip_stake ) && self->certs.skip.slot==ULONG_MAX ) ) {
    if( FD_LIKELY( !fd_bls_set_is_null( voted_stake->skip_agg.set ) ) ) {
      fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
      skip_verified = verify_votes( self, AG_VOTE_KIND_SKIP, NULL, &voted_stake->skip_agg, bad_skip );
      if( FD_UNLIKELY( !skip_verified ) ) skip_verified = subtract_votes( self, AG_VOTE_KIND_SKIP, NULL, &voted_stake->skip_agg, bad_skip );
      fd_bls_set_union( bad, bad, bad_skip );
    }
    if( FD_LIKELY( !fd_bls_set_is_null( voted_stake->skip_fallback_agg.set ) ) ) {
      fd_bls_set_t bad_sf[ fd_bls_set_word_cnt ];
      skip_fallback_verified = verify_votes( self, AG_VOTE_KIND_SKIP_FALLBACK, NULL, &voted_stake->skip_fallback_agg, bad_sf );
      if( FD_UNLIKELY( !skip_fallback_verified ) ) skip_fallback_verified = subtract_votes( self, AG_VOTE_KIND_SKIP_FALLBACK, NULL, &voted_stake->skip_fallback_agg, bad_sf );
      fd_bls_set_union( bad, bad, bad_sf );
    }
    if( FD_UNLIKELY( !fd_bls_set_test( fallback ? voted_stake->skip_fallback_agg.set : voted_stake->skip_agg.set, rank ) ) ) return 0;

    ag_cert_skip_t cert = { .slot = slot, .shred_version = shred_version };

    if( FD_LIKELY( skip_verified ) ) {
      cert.agg_skip = voted_stake->skip_agg;
      cert.stake += voted_stake->skip;
    }
    if( FD_LIKELY( skip_fallback_verified ) ) {
      cert.agg_skip_fallback = voted_stake->skip_fallback_agg;
      cert.stake += voted_stake->skip_fallback;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[ (*out_cert_event_cnt)++ ].cert = (ag_cert_t){ .kind = AG_CERT_KIND_SKIP, .skip = cert };
    }
  }

  return 1;
}

static int
count_finalize_stake( ag_slot_state_t *       self,
                      ag_vote_final_t const * vote,
                      ulong                   stake,
                      ag_event_cert_t *       out_cert_events,
                      ulong *                 out_cert_event_cnt,
                      fd_bls_set_t *          bad ) {
  ag_epoch_info_t const * epoch_info    = self->epoch_info;
  ulong                   slot          = vote->slot;
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;
  fd_bls_sig_t const *    sig           = &vote->sig;
  fd_bls_pub_t const *    pub           = &ag_epoch_info_validator( epoch_info, rank )->bls_key;

  ag_slot_voted_stake_t * voted_stake = &self->votes;
  voted_stake->finalize += stake;
  blst_p1_add_or_double( &voted_stake->finalize_agg.pub, &voted_stake->finalize_agg.pub, pub );
  blst_p2_add_or_double( &voted_stake->finalize_agg.sig, &voted_stake->finalize_agg.sig, sig );
  fd_bls_set_insert( voted_stake->finalize_agg.set, rank );
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, voted_stake->finalize ) && self->certs.finalize.slot==ULONG_MAX ) ) {
    fd_bls_set_t bad_final[ fd_bls_set_word_cnt ];
    int finalize_verified = verify_votes( self, AG_VOTE_KIND_FINAL, NULL, &voted_stake->finalize_agg, bad_final );
    if( FD_UNLIKELY( !finalize_verified ) ) finalize_verified = subtract_votes( self, AG_VOTE_KIND_FINAL, NULL, &voted_stake->finalize_agg, bad_final );
    fd_bls_set_union( bad, bad, bad_final );
    if( FD_UNLIKELY( fd_bls_set_test( bad_final, rank ) ) ) return 0;
    if( FD_UNLIKELY( !finalize_verified || !ag_epoch_info_is_quorum( epoch_info, voted_stake->finalize ) ) ) return 1;
    ag_cert_final_t cert = { .slot = slot, .shred_version = shred_version, .stake = voted_stake->finalize, .agg = voted_stake->finalize_agg };
    out_cert_events[ (*out_cert_event_cnt)++ ].cert = (ag_cert_t){ .kind = AG_CERT_KIND_FINAL, .final = cert };
  }

  return 1;
}

void
ag_slot_state_zero( ag_slot_state_t *       self,
                    ulong                   slot,
                    ag_epoch_info_t const * epoch_info,
                    ulong                   own_rank ) {
  fd_memset( self, 0, sizeof(ag_slot_state_t) );
  notar_map_new         ( self->votes.notar          );
  notar_fallback_map_new( self->votes.notar_fallback );

  self->certs.notar.slot         = ULONG_MAX;
  self->certs.skip.slot          = ULONG_MAX;
  self->certs.fast_finalize.slot = ULONG_MAX;
  self->certs.finalize.slot      = ULONG_MAX;

  self->slot       = slot;
  self->epoch_info = epoch_info;
  self->own_rank   = own_rank;
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

int
ag_slot_state_add_vote( ag_slot_state_t *   self,
                        ag_vote_t const *   vote,
                        ulong               stake,
                        ag_event_cert_t *   out_cert_events,
                        ulong *             out_cert_event_cnt,
                        ag_event_pool_t *   out_pool_events,
                        ulong *             out_pool_event_cnt,
                        ag_event_repair_t * out_repair_events,
                        ulong *             out_repair_event_cnt,
                        fd_bls_set_t *      bad ) {
  ulong slot = ag_vote_slot( vote );
  ulong rank = ag_vote_rank( vote );

  fd_bls_sig_t const * sig = ag_vote_sig( vote );

  *out_cert_event_cnt = 0UL; *out_pool_event_cnt = 0UL; *out_repair_event_cnt = 0UL; fd_bls_set_null( bad );
  self->shred_version = ag_vote_shred_version( vote );
  int err;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR:
    self->votes.notar_sig[ rank ] = *sig;
    err = count_notar_stake( self, &vote->notar, stake, out_cert_events, out_cert_event_cnt, out_pool_events, out_pool_event_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    FD_TEST( self->votes.notar_fallback_sig_cnt[ rank ]<AG_NOTAR_FALLBACK_VOTE_MAX );
    memcpy( self->votes.notar_fallback_sig_hash[ rank ][ self->votes.notar_fallback_sig_cnt[ rank ] ], vote->notar_fallback.block_hash, sizeof(ag_block_hash_t) );
    self->votes.notar_fallback_sig[ rank ][ self->votes.notar_fallback_sig_cnt[ rank ]++ ] = *sig;
    err = count_notar_fallback_stake( self, &vote->notar_fallback, stake, out_cert_events, out_cert_event_cnt, bad );
    break;
  case AG_VOTE_KIND_SKIP:
    self->votes.skip_sig[ rank ] = *sig;
    self->votes.notar_or_skip += stake;
    err = count_skip_stake( self, vote, stake, out_cert_events, out_cert_event_cnt, out_pool_events, out_pool_event_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    self->votes.skip_fallback_sig[ rank ] = *sig;
    err = count_skip_stake( self, vote, stake, out_cert_events, out_cert_event_cnt, out_pool_events, out_pool_event_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_FINAL:
    self->votes.finalize_sig[ rank ] = *sig;
    err = count_finalize_stake( self, &vote->final, stake, out_cert_events, out_cert_event_cnt, bad );
    break;
  default:
    FD_LOG_CRIT(( "unreachable" ));
  }

  if( FD_UNLIKELY( rank==self->own_rank ) ) {
    ag_block_hash_set_t pending = self->pending_safe_to_notar;
    for( ulong i=0UL; i<pending.cnt; i++ ) {
      if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) ) continue;
      switch( check_safe_to_notar( self, pending.hash[i], bad ) ) {
      case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR: out_pool_events[ (*out_pool_event_cnt)++ ] = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = ag_block_id( slot, pending.hash[i] ) }; break;
      case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
        ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].block.hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) ) break;
        if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ].block = ag_block_id( slot, pending.hash[i] );
        break;
      }
      default: break;
      }
    }
  }

  return err;
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
                                       ag_block_hash_t const block_hash,
                                       fd_bls_set_t *        bad ) {
  fd_bls_set_null( bad );
  ag_parent_status_t * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( self->parents[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) { parent = &self->parents[i]; break; }
  }
  FD_TEST( parent );
  parent->kind = AG_PARENT_STATUS_CERTIFIED;

  if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) return 0;

  switch( check_safe_to_notar( self, block_hash, bad ) ) {
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
  ag_slot_voted_stake_t const * voted_stake = &self->votes;

  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( fd_bls_set_test( voted_stake->skip_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    for( ulong slot_idx=0UL; slot_idx<notar_map_slot_cnt(); slot_idx++ ) {
      if( FD_UNLIKELY( !notar_map_key_inval( voted_stake->notar[ slot_idx ].hash )
                       && fd_bls_set_test( voted_stake->notar[ slot_idx ].agg.set, voter )
                       && memcmp( vote->notar.block_hash, voted_stake->notar[ slot_idx ].hash.uc, sizeof(ag_block_hash_t) ) ) ) {
        return AG_SLASHABLE_NOTAR_DIFFERENT_HASH;
      }
    }
    break;
  }

  case AG_VOTE_KIND_NOTAR_FALLBACK:
    if( FD_UNLIKELY( fd_bls_set_test( voted_stake->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    } else if( FD_UNLIKELY( voted_stake->notar_fallback_sig_cnt[ voter ]>=AG_NOTAR_FALLBACK_VOTE_MAX ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_OVER_THREE;
    }
    break;

  case AG_VOTE_KIND_SKIP:
    if( FD_UNLIKELY( fd_bls_set_test( voted_stake->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    for( ulong slot_idx=0UL; slot_idx<notar_map_slot_cnt(); slot_idx++ ) {
      if( FD_UNLIKELY( !notar_map_key_inval( voted_stake->notar[ slot_idx ].hash ) && fd_bls_set_test( voted_stake->notar[ slot_idx ].agg.set, voter ) ) ) return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    break;

  case AG_VOTE_KIND_SKIP_FALLBACK:
    if( FD_UNLIKELY( fd_bls_set_test( voted_stake->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    break;

  case AG_VOTE_KIND_FINAL: {
    if( FD_UNLIKELY( fd_bls_set_test( voted_stake->skip_agg.set, voter ) || fd_bls_set_test( voted_stake->skip_fallback_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    if( FD_UNLIKELY( voted_stake->notar_fallback_sig_cnt[ voter ] ) ) {
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
  ag_slot_voted_stake_t const * voted_stake = &self->votes;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( notar_map_key_inval( FD_LOAD( ag_block_hash_key_t, vote->notar.block_hash ) ) ) ) return 1;
    for( ulong slot_idx=0UL; slot_idx<notar_map_slot_cnt(); slot_idx++ ) {
      if( FD_UNLIKELY( !notar_map_key_inval( voted_stake->notar[ slot_idx ].hash ) && fd_bls_set_test( voted_stake->notar[ slot_idx ].agg.set, voter ) ) ) return 1;
    }

    uchar const * hash = vote->notar.block_hash;
    for( ulong j=0UL; j<voted_stake->notar_fallback_sig_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( !memcmp( voted_stake->notar_fallback_sig_hash[ voter ][j], hash, sizeof(ag_block_hash_t) ) ) ) return 1;
    }
    return 0;
  }
  case AG_VOTE_KIND_NOTAR_FALLBACK: {
    if( FD_UNLIKELY( notar_fallback_map_key_inval( FD_LOAD( ag_block_hash_key_t, vote->notar_fallback.block_hash ) ) ) ) return 1;
    uchar const * hash = vote->notar_fallback.block_hash;
    for( ulong j=0UL; j<voted_stake->notar_fallback_sig_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( !memcmp( voted_stake->notar_fallback_sig_hash[ voter ][j], hash, sizeof(ag_block_hash_t) ) ) ) return 1;
    }

    ag_slot_voted_stake_hash_t const * notar = notar_map_query_const( voted_stake->notar, FD_LOAD( ag_block_hash_key_t, hash ), NULL );
    return notar && fd_bls_set_test( notar->agg.set, voter );
  }
  case AG_VOTE_KIND_SKIP:
  case AG_VOTE_KIND_SKIP_FALLBACK:
    return fd_bls_set_test( voted_stake->skip_agg.set, voter ) || fd_bls_set_test( voted_stake->skip_fallback_agg.set, voter );
  case AG_VOTE_KIND_FINAL:
    return fd_bls_set_test( voted_stake->finalize_agg.set, voter );
  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return 0;
}
