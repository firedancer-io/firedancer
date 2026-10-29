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
verify_subtract_votes( ag_slot_state_t *     self,
                       ag_slot_states_t *    states,
                       uint                  kind,
                       ag_block_hash_t const block_hash,
                       fd_bls_agg_t *        agg,
                       fd_bls_set_t *        bad ) {
  ag_epoch_info_t const * epoch_info                     = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ag_slot_votes_t *       votes                          = &self->votes;
  ag_vote_stake_map_t *   notar_hash_stake_map           = states->notar_hash_stake_map;
  ag_vote_stake_map_t *   notar_fallback_hash_stake_map  = states->notar_fallback_hash_stake_map;
  ag_vote_stake_ele_t *   notar_hash_stake_pool          = states->notar_hash_stake_pool;
  ag_vote_stake_ele_t *   notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;

  fd_bls_sig_t sigs[ AG_VAT_MAX ];
  fd_bls_set_t set [ fd_bls_set_word_cnt ];
  switch( kind ) {
  case AG_VOTE_KIND_SKIP:
  case AG_VOTE_KIND_SKIP_FALLBACK:
  case AG_VOTE_KIND_FINAL:
    ag_slot_state_sigs( self, states, kind, NULL, agg->set, sigs );
    break;
  case AG_VOTE_KIND_NOTAR:
    fd_bls_set_null( set );
    for( ulong rank = fd_bls_set_const_iter_init( votes->notar_set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( votes->notar_set, rank ) ) {
      if( FD_LIKELY( !memcmp( ag_vote_stake_pool_ele( notar_hash_stake_pool, votes->notar_hash_stake_idx[ rank ] )->block_id.hash, block_hash, sizeof(ag_block_hash_t) ) ) ) fd_bls_set_insert( set, rank );
    }
    ag_slot_state_sigs( self, states, kind, block_hash, set, sigs );
    fd_bls_agg_null( agg );
    fd_bls_agg_construct( agg, epoch_info->pubkeys, sigs, set );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    fd_bls_set_null( set );
    for( ulong rank=0UL; rank<epoch_info->validator_cnt; rank++ ) {
      for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_LIKELY( !memcmp( ag_vote_stake_pool_ele( notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ rank ][ j ] )->block_id.hash, block_hash, sizeof(ag_block_hash_t) ) ) ) fd_bls_set_insert( set, rank );
      }
    }
    ag_slot_state_sigs( self, states, kind, block_hash, set, sigs );
    fd_bls_agg_null( agg );
    fd_bls_agg_construct( agg, epoch_info->pubkeys, sigs, set );
    break;
  default: FD_LOG_CRIT(( "unreachable" ));
  }

  uchar msg[ AG_VOTE_SIGNING_SER_MAX ];
  ulong msg_sz = ag_vote_signing_ser( kind, self->slot, block_hash, self->shred_version, msg );
  states->bls_verify_cnt++;
  int   err    = fd_bls_agg_verify_subtract( agg, msg, msg_sz, epoch_info->pubkeys, sigs, bad );
  if( FD_LIKELY( !err && fd_bls_set_is_null( bad ) ) ) return 1;

  ag_block_id_t key;
  ulong         id = ULONG_MAX;
  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:          key = ag_block_id( self->slot, block_hash ); id = ag_vote_stake_map_idx_query_const( notar_hash_stake_map,          &key, ULONG_MAX, notar_hash_stake_pool          ); break;
  case AG_VOTE_KIND_NOTAR_FALLBACK: key = ag_block_id( self->slot, block_hash ); id = ag_vote_stake_map_idx_query_const( notar_fallback_hash_stake_map, &key, ULONG_MAX, notar_fallback_hash_stake_pool ); break;
  default: break;
  }

  for( ulong rank = fd_bls_set_const_iter_init( bad );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( bad, rank ) ) {
    ulong stake = ag_epoch_info_validator( epoch_info, rank )->stake;
    switch( kind ) {
    case AG_VOTE_KIND_NOTAR:
      ag_vote_stake_pool_ele( notar_hash_stake_pool, id )->stake -= stake;
      votes->notar_or_skip_stake -= stake;
      fd_bls_set_remove( votes->notar_set, rank );
      fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->notar_sig_idx[ rank ] );
      break;
    case AG_VOTE_KIND_NOTAR_FALLBACK: {
      ulong j;
      for( j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_UNLIKELY( votes->notar_fallback_hash_stake_idx[ rank ][ j ]==id ) ) break;
      }
      FD_CHECK_CRIT( j<votes->notar_fallback_sig_cnt[ rank ], "invariant violation" );
      ag_vote_stake_pool_ele( notar_fallback_hash_stake_pool, id )->stake -= stake;
      fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->notar_fallback_sig_idx[ rank ][ j ] );
      votes->notar_fallback_sig_cnt[ rank ]--;
      votes->notar_fallback_sig_idx       [ rank ][ j ] = votes->notar_fallback_sig_idx       [ rank ][ votes->notar_fallback_sig_cnt[ rank ] ];
      votes->notar_fallback_hash_stake_idx[ rank ][ j ] = votes->notar_fallback_hash_stake_idx[ rank ][ votes->notar_fallback_sig_cnt[ rank ] ];
      break;
    }
    case AG_VOTE_KIND_SKIP:
      votes->skip_stake -= stake;
      votes->notar_or_skip_stake -= stake;
      fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->skip_sig_idx[ rank ] );
      break;
    case AG_VOTE_KIND_SKIP_FALLBACK:
      votes->skip_fallback_stake -= stake;
      fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->skip_fallback_sig_idx[ rank ] );
      break;
    case AG_VOTE_KIND_FINAL:
      votes->finalize_stake -= stake;
      fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->finalize_sig_idx[ rank ] );
      break;
    default:
      FD_LOG_CRIT(( "unreachable" ));
    }
  }

  if( FD_UNLIKELY( kind==AG_VOTE_KIND_NOTAR && fd_bls_set_is_null( agg->set ) ) ) {
    ulong * link = &votes->notar_hash_stake_head;
    ulong   j;
    for( j=0UL; j<votes->notar_hash_stake_cnt; j++ ) {
      if( FD_UNLIKELY( *link==id ) ) break;
      link = &ag_vote_stake_pool_ele( notar_hash_stake_pool, *link )->prev;
    }
    FD_CHECK_CRIT( j<votes->notar_hash_stake_cnt, "invariant violation" );
    *link = ag_vote_stake_pool_ele( notar_hash_stake_pool, id )->prev;
    votes->notar_hash_stake_cnt--;
    ag_vote_stake_map_idx_remove( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
    ag_vote_stake_pool_idx_release( notar_hash_stake_pool, id );
  }
  if( FD_UNLIKELY( kind==AG_VOTE_KIND_NOTAR_FALLBACK && fd_bls_set_is_null( agg->set ) ) ) {
    ulong * link = &votes->notar_fallback_hash_stake_head;
    ulong   j;
    for( j=0UL; j<votes->notar_fallback_hash_stake_cnt; j++ ) {
      if( FD_UNLIKELY( *link==id ) ) break;
      link = &ag_vote_stake_pool_ele( notar_fallback_hash_stake_pool, *link )->prev;
    }
    FD_CHECK_CRIT( j<votes->notar_fallback_hash_stake_cnt, "invariant violation" );
    *link = ag_vote_stake_pool_ele( notar_fallback_hash_stake_pool, id )->prev;
    votes->notar_fallback_hash_stake_cnt--;
    ag_vote_stake_map_idx_remove( notar_fallback_hash_stake_map, &key, ULONG_MAX, notar_fallback_hash_stake_pool );
    ag_vote_stake_pool_idx_release( notar_fallback_hash_stake_pool, id );
  }
  if( FD_UNLIKELY( kind==AG_VOTE_KIND_NOTAR ) ) {
    votes->top_notar_stake = 0UL;
    ulong i = votes->notar_hash_stake_head;
    for( ulong j=0UL; j<votes->notar_hash_stake_cnt; j++ ) {
      if( FD_LIKELY( ag_vote_stake_pool_ele( notar_hash_stake_pool, i )->stake>votes->top_notar_stake ) ) { /* FIXME slow */
        votes->top_notar_stake = ag_vote_stake_pool_ele( notar_hash_stake_pool, i )->stake;
        memcpy( votes->top_notar_hash, ag_vote_stake_pool_ele( notar_hash_stake_pool, i )->block_id.hash, sizeof(ag_block_hash_t) );
      }
      i = ag_vote_stake_pool_ele( notar_hash_stake_pool, i )->prev;
    }
  }
  return !err;
}

static int
check_safe_to_notar( ag_slot_state_t *     self,
                     ag_slot_states_t *    states,
                     ag_block_hash_t const block_hash,
                     fd_bls_set_t *        bad ) {
  ag_epoch_info_t const * epoch_info            = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ag_slot_votes_t *       votes                 = &self->votes;
  ag_vote_stake_map_t *   notar_hash_stake_map  = states->notar_hash_stake_map;
  ag_vote_stake_ele_t *   notar_hash_stake_pool = states->notar_hash_stake_pool;
  ag_block_id_t           key                   = ag_block_id( self->slot, block_hash );
  ulong                   notar                 = ag_vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
  ulong                   notar_stake           = notar!=ULONG_MAX ? ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake : 0UL;
  ulong                   skip_stake            = votes->skip_stake;

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
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, own ) ) ) safe_to_notar = 1;
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, own ) ) ) {
      if( FD_UNLIKELY( !memcmp( ag_vote_stake_pool_ele( notar_hash_stake_pool, votes->notar_hash_stake_idx[ own ] )->block_id.hash, block_hash, sizeof(ag_block_hash_t) ) ) ) return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
      safe_to_notar = 1;
    }
  }
  if( FD_UNLIKELY( !safe_to_notar ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  fd_bls_agg_t notar_agg[1];
  fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
  verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
  fd_bls_set_union( bad, bad, bad_notar );
  if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
    fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, AG_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
    fd_bls_set_union( bad, bad, bad_skip );
  }
  notar       = ag_vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
  notar_stake = notar!=ULONG_MAX ? ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake : 0UL;
  skip_stake  = votes->skip_stake;
  if( FD_UNLIKELY( !ag_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) || ( !ag_epoch_info_is_weak_quorum( epoch_info, notar_stake ) && !ag_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  block_hash_set_remove( &self->pending_safe_to_notar, block_hash );
  block_hash_set_insert( &self->sent_safe_to_notar,    block_hash );
  return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
}

static int
check_safe_to_skip( ag_slot_state_t *  self,
                    ag_slot_states_t * states,
                    fd_bls_set_t *     bad ) {
  ag_epoch_info_t const * epoch_info = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ag_slot_votes_t *       votes      = &self->votes;
  if( FD_LIKELY( self->sent_safe_to_skip
                 || !ag_epoch_info_is_weak_quorum( epoch_info, votes->notar_or_skip_stake - votes->top_notar_stake )
                 || self->own_rank==USHORT_MAX /* must be staked */ ) ) return 0;
  if( FD_LIKELY( !fd_bls_set_test( votes->notar_set, self->own_rank ) ) ) return 0;

  ag_vote_stake_ele_t * notar_hash_stake_pool = states->notar_hash_stake_pool;
  ulong                 i                     = votes->notar_hash_stake_head;
  for( ulong j=votes->notar_hash_stake_cnt; j>0UL; j-- ) {
    ag_block_id_t key  = ag_vote_stake_pool_ele( notar_hash_stake_pool, i )->block_id;
    ulong         prev = ag_vote_stake_pool_ele( notar_hash_stake_pool, i )->prev;
    fd_bls_agg_t  notar_agg[1];
    fd_bls_set_t  bad_notar[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR, key.hash, notar_agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    i = prev;
  }
  if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
    fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, AG_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
    fd_bls_set_union( bad, bad, bad_skip );
  }
  if( FD_UNLIKELY( !ag_epoch_info_is_weak_quorum( epoch_info, votes->notar_or_skip_stake - votes->top_notar_stake ) || !fd_bls_set_test( votes->notar_set, self->own_rank ) ) ) return 0;
  self->sent_safe_to_skip = 1;
  return 1;
}

static int
count_notar_stake( ag_slot_state_t *       self,
                   ag_slot_states_t *      states,
                   ag_vote_notar_t const * vote,
                   ulong                   stake,
                   ag_cert_t *             out_cert_events,
                   ulong *                 out_cert_event_cnt,
                   ag_block_id_t *         out_safe_to_notar,
                   ulong *                 out_safe_to_notar_cnt,
                   ulong *                 out_safe_to_skip,
                   ulong *                 out_safe_to_skip_cnt,
                   ag_block_id_t *         out_repair_events,
                   ulong *                 out_repair_event_cnt,
                   fd_bls_set_t *          bad ) {
  ag_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  uchar const *           block_hash    = vote->block_hash;
  ag_block_id_t           key           = ag_block_id( self->slot, block_hash );
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;

  ag_slot_votes_t *     votes                          = &self->votes;
  ag_vote_stake_map_t * notar_hash_stake_map           = states->notar_hash_stake_map;
  ag_vote_stake_map_t * notar_fallback_hash_stake_map  = states->notar_fallback_hash_stake_map;
  ag_vote_stake_ele_t * notar_hash_stake_pool          = states->notar_hash_stake_pool;
  ag_vote_stake_ele_t * notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;
  ulong                 notar                          = ag_vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
  if( FD_UNLIKELY( notar==ULONG_MAX ) ) {
    FD_TEST( ag_vote_stake_pool_free( notar_hash_stake_pool ) );
    notar = ag_vote_stake_pool_idx_acquire( notar_hash_stake_pool );
    ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->block_id = key;
    ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake    = 0UL;
    ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->prev     = votes->notar_hash_stake_cnt ? votes->notar_hash_stake_head : ag_vote_stake_pool_idx_null( notar_hash_stake_pool );
    ag_vote_stake_map_idx_insert( notar_hash_stake_map, notar, notar_hash_stake_pool );
    votes->notar_hash_stake_head = notar;
    votes->notar_hash_stake_cnt++;
  }
  votes->notar_hash_stake_idx[ rank ] = (uint)notar;
  ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake += stake;

  ulong notar_stake           = ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
  votes->notar_or_skip_stake += stake;
  if( FD_LIKELY( notar_stake>votes->top_notar_stake ) ) {
    votes->top_notar_stake = notar_stake;
    memcpy( votes->top_notar_hash, block_hash, sizeof(ag_block_hash_t) );
  }

  if( FD_UNLIKELY( !block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) {
    switch( check_safe_to_notar( self, states, block_hash, bad ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = ag_block_id( slot, block_hash );
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = ag_block_id( slot, block_hash );
      break;
    }
    default: break;
    }
  }
  if( FD_UNLIKELY( check_safe_to_skip( self, states, bad ) ) ) {
    out_safe_to_skip[ (*out_safe_to_skip_cnt)++ ] = slot;
  }
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) ) ) {
    notar = ag_vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
    if( FD_UNLIKELY( notar==ULONG_MAX || !fd_bls_set_test( votes->notar_set, rank ) ) ) return 0;
    notar_stake = ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
  }

  ag_vote_stake_ele_t const * nf_ele   = ag_vote_stake_map_ele_query_const( notar_fallback_hash_stake_map, &key, NULL, notar_fallback_hash_stake_pool );
  ulong                       nf_stake = nf_ele ? nf_ele->stake : 0UL;

  int          notar_verified          = 0;
  int          notar_fallback_verified = 0;
  int          newly_notar             = 0;
  fd_bls_agg_t notar_agg[1];
  fd_bls_agg_t nf_agg[1];

  if( FD_UNLIKELY( ( ag_epoch_info_is_quorum       ( epoch_info, nf_stake + notar_stake ) && !ag_slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ||
                   ( ag_epoch_info_is_quorum       ( epoch_info, notar_stake            ) && self->certs.notar.slot==ULONG_MAX                                ) ||
                   ( ag_epoch_info_is_strong_quorum( epoch_info, notar_stake            ) && self->certs.fast_finalize.slot==ULONG_MAX                        ) ) ) {
    fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
    notar_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    if( FD_UNLIKELY( fd_bls_set_test( bad_notar, rank ) ) ) return 0;

    notar_stake = ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
    newly_notar = notar_verified && ag_epoch_info_is_quorum( epoch_info, notar_stake ) && self->certs.notar.slot==ULONG_MAX;
    if( FD_LIKELY( nf_ele && !newly_notar && !ag_slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
      fd_bls_set_t bad_nf[ fd_bls_set_word_cnt ];
      notar_fallback_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR_FALLBACK, block_hash, nf_agg, bad_nf );
      fd_bls_set_union( bad, bad, bad_nf );
    }
  }

  if( FD_UNLIKELY( !newly_notar && !ag_slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
    ag_cert_notar_fallback_t cert = { .slot = slot, .shred_version = shred_version }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );

    if( FD_LIKELY( notar_verified ) ) {
      cert.agg_notar = *notar_agg;
      cert.stake += ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
    }
    if( FD_LIKELY( notar_fallback_verified ) ) {
      cert.agg_notar_fallback = *nf_agg;
      cert.stake += nf_ele->stake;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[( *out_cert_event_cnt )++] = ( ag_cert_t ){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
    }
  }

  if( FD_UNLIKELY( newly_notar ) ) {
    ag_cert_notar_t cert = { .slot = slot, .shred_version = shred_version, .stake = notar_stake, .agg = *notar_agg }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
    out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR, .notar = cert };
  }

  if( FD_UNLIKELY( notar_verified && ag_epoch_info_is_strong_quorum( epoch_info, notar_stake ) && self->certs.fast_finalize.slot==ULONG_MAX ) ) {
    ag_cert_fast_final_t cert = { .slot = slot, .shred_version = shred_version, .stake = notar_stake, .agg = *notar_agg }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
    out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = cert };
  }

  return 1;
}

static int
count_notar_fallback_stake( ag_slot_state_t *                self,
                            ag_slot_states_t *               states,
                            ag_vote_notar_fallback_t const * vote,
                            ulong                            stake,
                            ag_cert_t *                      out_cert_events,
                            ulong *                          out_cert_event_cnt,
                            fd_bls_set_t *                   bad ) {
  ag_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  uchar const *           block_hash    = vote->block_hash;
  ag_block_id_t           key           = ag_block_id( self->slot, block_hash );
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;

  ag_slot_votes_t *     votes                          = &self->votes;
  ag_vote_stake_map_t * notar_hash_stake_map           = states->notar_hash_stake_map;
  ag_vote_stake_map_t * notar_fallback_hash_stake_map  = states->notar_fallback_hash_stake_map;
  ag_vote_stake_ele_t * notar_hash_stake_pool          = states->notar_hash_stake_pool;
  ag_vote_stake_ele_t * notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;
  ag_vote_stake_ele_t * nf_ele                         = ag_vote_stake_map_ele_query( notar_fallback_hash_stake_map, &key, NULL, notar_fallback_hash_stake_pool );
  if( FD_UNLIKELY( !nf_ele ) ) {
    FD_TEST( ag_vote_stake_pool_free( notar_fallback_hash_stake_pool ) );
    nf_ele           = ag_vote_stake_pool_ele_acquire( notar_fallback_hash_stake_pool );
    nf_ele->block_id = key;
    nf_ele->stake    = 0UL;
    nf_ele->prev     = votes->notar_fallback_hash_stake_cnt ? votes->notar_fallback_hash_stake_head : ag_vote_stake_pool_idx_null( notar_fallback_hash_stake_pool );
    ag_vote_stake_map_ele_insert( notar_fallback_hash_stake_map, nf_ele, notar_fallback_hash_stake_pool );
    votes->notar_fallback_hash_stake_head = ag_vote_stake_pool_idx( notar_fallback_hash_stake_pool, nf_ele );
    votes->notar_fallback_hash_stake_cnt++;
  }
  votes->notar_fallback_hash_stake_idx[ rank ][ votes->notar_fallback_sig_cnt[ rank ]-1UL ] = (uint)ag_vote_stake_pool_idx( notar_fallback_hash_stake_pool, nf_ele );
  nf_ele->stake += stake;

  ulong notar       = ag_vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
  ulong nf_stake    = nf_ele->stake;
  ulong notar_stake = notar!=ULONG_MAX ? ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake : 0UL;
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) && !ag_slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
    fd_bls_agg_t nf_agg[1];
    fd_bls_agg_t notar_agg[1];
    fd_bls_set_t bad_nf[ fd_bls_set_word_cnt ];
    int nf_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR_FALLBACK, block_hash, nf_agg, bad_nf );
    fd_bls_set_union( bad, bad, bad_nf );
    if( FD_UNLIKELY( fd_bls_set_test( bad_nf, rank ) ) ) return 0;
    int notar_verified = 0;
    if( FD_LIKELY( notar!=ULONG_MAX ) ) {
      fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
      notar_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
      fd_bls_set_union( bad, bad, bad_notar );
    }

    ag_cert_notar_fallback_t cert = { .slot = slot, .shred_version = shred_version }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );

    if( FD_LIKELY( notar_verified ) ) {
      cert.agg_notar = *notar_agg;
      cert.stake += ag_vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
    }
    if( FD_LIKELY( nf_verified ) ) {
      cert.agg_notar_fallback = *nf_agg;
      cert.stake += nf_ele->stake;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
    }
  }

  return 1;
}

static int
count_skip_stake( ag_slot_state_t *  self,
                  ag_slot_states_t * states,
                  ag_vote_t const *  vote,
                  ulong              stake,
                  ag_cert_t *        out_cert_events,
                  ulong *            out_cert_event_cnt,
                  ag_block_id_t *    out_safe_to_notar,
                  ulong *            out_safe_to_notar_cnt,
                  ulong *            out_safe_to_skip,
                  ulong *            out_safe_to_skip_cnt,
                  ag_block_id_t *    out_repair_events,
                  ulong *            out_repair_event_cnt,
                  fd_bls_set_t *     bad ) {
  ag_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  int                     fallback      = vote->kind==AG_VOTE_KIND_SKIP_FALLBACK;
  ulong                   slot          = ag_vote_slot( vote );
  ulong                   rank          = ag_vote_rank( vote );
  ushort                  shred_version = ag_vote_shred_version( vote );
  fd_bls_sig_t const *    sig           = ag_vote_sig( vote );
  fd_bls_pub_t const *    pub           = ag_epoch_info_pubkey( epoch_info, rank );

  ag_slot_votes_t * votes = &self->votes;
  if( FD_UNLIKELY( fallback ) ) { votes->skip_fallback_stake += stake; blst_p1_add_or_double_affine( &votes->skip_fallback_agg.pub, &votes->skip_fallback_agg.pub, pub ); blst_p2_add_or_double_affine( &votes->skip_fallback_agg.sig, &votes->skip_fallback_agg.sig, sig ); fd_bls_set_insert( votes->skip_fallback_agg.set, rank ); }
  else                          { votes->skip_stake          += stake; blst_p1_add_or_double_affine( &votes->skip_agg.pub,          &votes->skip_agg.pub,          pub ); blst_p2_add_or_double_affine( &votes->skip_agg.sig,          &votes->skip_agg.sig,          sig ); fd_bls_set_insert( votes->skip_agg.set,          rank ); }

  ag_block_hash_set_t pending = self->pending_safe_to_notar;
  for( ulong i=0UL; i<pending.cnt; i++ ) {
    if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) ) continue;
    switch( check_safe_to_notar( self, states, pending.hash[i], bad ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = ag_block_id( slot, pending.hash[i] );
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = ag_block_id( slot, pending.hash[i] );
      break;
    }
    default:
      break;
    }
  }

  if( FD_UNLIKELY( check_safe_to_skip( self, states, bad ) ) ) {
    out_safe_to_skip[ (*out_safe_to_skip_cnt)++ ] = slot;
  }
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) && !fd_bls_set_test( fallback ? votes->skip_fallback_agg.set : votes->skip_agg.set, rank ) ) ) return 0;

  ulong total_skip_stake = votes->skip_stake + votes->skip_fallback_stake;

  int skip_verified          = 0;
  int skip_fallback_verified = 0;
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, total_skip_stake ) && self->certs.skip.slot==ULONG_MAX ) ) {
    if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
      fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
      skip_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
      fd_bls_set_union( bad, bad, bad_skip );
    }
    if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_fallback_agg.set ) ) ) {
      fd_bls_set_t bad_sf[ fd_bls_set_word_cnt ];
      skip_fallback_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_SKIP_FALLBACK, NULL, &votes->skip_fallback_agg, bad_sf );
      fd_bls_set_union( bad, bad, bad_sf );
    }
    if( FD_UNLIKELY( !fd_bls_set_test( fallback ? votes->skip_fallback_agg.set : votes->skip_agg.set, rank ) ) ) return 0;

    ag_cert_skip_t cert = { .slot = slot, .shred_version = shred_version };

    if( FD_LIKELY( skip_verified ) ) {
      cert.agg_skip = votes->skip_agg;
      cert.stake += votes->skip_stake;
    }
    if( FD_LIKELY( skip_fallback_verified ) ) {
      cert.agg_skip_fallback = votes->skip_fallback_agg;
      cert.stake += votes->skip_fallback_stake;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_SKIP, .skip = cert };
    }
  }

  return 1;
}

static int
count_finalize_stake( ag_slot_state_t *       self,
                      ag_slot_states_t *      states,
                      ag_vote_final_t const * vote,
                      ulong                   stake,
                      ag_cert_t *             out_cert_events,
                      ulong *                 out_cert_event_cnt,
                      fd_bls_set_t *          bad ) {
  ag_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;
  fd_bls_sig_t const *    sig           = &vote->sig;
  fd_bls_pub_t const *    pub           = ag_epoch_info_pubkey( epoch_info, rank );

  ag_slot_votes_t * votes = &self->votes;
  votes->finalize_stake += stake;
  blst_p1_add_or_double_affine( &votes->finalize_agg.pub, &votes->finalize_agg.pub, pub );
  blst_p2_add_or_double_affine( &votes->finalize_agg.sig, &votes->finalize_agg.sig, sig );
  fd_bls_set_insert( votes->finalize_agg.set, rank );
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, votes->finalize_stake ) && self->certs.finalize.slot==ULONG_MAX ) ) {
    fd_bls_set_t bad_final[ fd_bls_set_word_cnt ];
    int finalize_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_FINAL, NULL, &votes->finalize_agg, bad_final );
    fd_bls_set_union( bad, bad, bad_final );
    if( FD_UNLIKELY( fd_bls_set_test( bad_final, rank ) ) ) return 0;
    if( FD_UNLIKELY( !finalize_verified || !ag_epoch_info_is_quorum( epoch_info, votes->finalize_stake ) ) ) return 1;
    ag_cert_final_t cert = { .slot = slot, .shred_version = shred_version, .stake = votes->finalize_stake, .agg = votes->finalize_agg };
    out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_FINAL, .final = cert };
  }

  return 1;
}

void
ag_slot_state_null( ag_slot_state_t *  self,
                    ag_slot_states_t * states ) {
  ag_slot_votes_t * votes = &self->votes;
  for( ulong rank = fd_bls_set_const_iter_init( votes->notar_set );              !fd_bls_set_const_iter_done( rank ); rank = fd_bls_set_const_iter_next( votes->notar_set,              rank ) ) fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->notar_sig_idx        [ rank ] );
  for( ulong rank = fd_bls_set_const_iter_init( votes->skip_agg.set );          !fd_bls_set_const_iter_done( rank ); rank = fd_bls_set_const_iter_next( votes->skip_agg.set,          rank ) ) fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->skip_sig_idx         [ rank ] );
  for( ulong rank = fd_bls_set_const_iter_init( votes->skip_fallback_agg.set ); !fd_bls_set_const_iter_done( rank ); rank = fd_bls_set_const_iter_next( votes->skip_fallback_agg.set, rank ) ) fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->skip_fallback_sig_idx[ rank ] );
  for( ulong rank = fd_bls_set_const_iter_init( votes->finalize_agg.set );      !fd_bls_set_const_iter_done( rank ); rank = fd_bls_set_const_iter_next( votes->finalize_agg.set,      rank ) ) fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->finalize_sig_idx     [ rank ] );
  for( ulong rank=0UL; rank<AG_VAT_MAX; rank++ ) {
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) fd_bls_sig_pool_idx_release( states->bls_sig_pool, votes->notar_fallback_sig_idx[ rank ][ j ] );
  }
  ulong notar = votes->notar_hash_stake_head;
  for( ulong i=0UL; i<votes->notar_hash_stake_cnt; i++ ) {
    ulong prev = ag_vote_stake_pool_ele( states->notar_hash_stake_pool, notar )->prev;
    ag_vote_stake_map_idx_remove( states->notar_hash_stake_map, &ag_vote_stake_pool_ele( states->notar_hash_stake_pool, notar )->block_id, ULONG_MAX, states->notar_hash_stake_pool );
    ag_vote_stake_pool_idx_release( states->notar_hash_stake_pool, notar );
    notar = prev;
  }
  votes->notar_hash_stake_cnt = 0UL;
  fd_bls_set_null( votes->notar_set );
  ulong nf_idx = votes->notar_fallback_hash_stake_head;
  for( ulong i=0UL; i<votes->notar_fallback_hash_stake_cnt; i++ ) {
    ulong prev = ag_vote_stake_pool_ele( states->notar_fallback_hash_stake_pool, nf_idx )->prev;
    ag_vote_stake_map_idx_remove( states->notar_fallback_hash_stake_map, &ag_vote_stake_pool_ele( states->notar_fallback_hash_stake_pool, nf_idx )->block_id, ULONG_MAX, states->notar_fallback_hash_stake_pool );
    ag_vote_stake_pool_idx_release( states->notar_fallback_hash_stake_pool, nf_idx );
    nf_idx = prev;
  }
  votes->notar_fallback_hash_stake_cnt = 0UL;
  fd_memset( votes->notar_fallback_sig_cnt, 0, sizeof(votes->notar_fallback_sig_cnt) );
  votes->skip_stake = 0UL;
  fd_bls_agg_null( &votes->skip_agg );
  votes->skip_fallback_stake = 0UL;
  fd_bls_agg_null( &votes->skip_fallback_agg );
  votes->finalize_stake = 0UL;
  fd_bls_agg_null( &votes->finalize_agg );
  votes->notar_or_skip_stake = 0UL;
  votes->top_notar_stake     = 0UL;
  fd_memset( votes->top_notar_hash, 0, sizeof(ag_block_hash_t) );

  self->certs.notar.slot         = ULONG_MAX;
  self->certs.notar_fallback_cnt = 0UL;
  self->certs.skip.slot          = ULONG_MAX;
  self->certs.fast_finalize.slot = ULONG_MAX;
  self->certs.finalize.slot      = ULONG_MAX;

  self->parents_cnt               = 0UL;
  self->pending_safe_to_notar.cnt = 0UL;
  self->sent_safe_to_notar.cnt    = 0UL;
  self->sent_safe_to_skip         = 0;
}

void
ag_slot_state_set_own_rank( ag_slot_state_t * self,
                            ulong             own_rank ) {
  self->own_rank = own_rank;
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
      FD_CHECK_CRIT( self->certs.notar_fallback_cnt<AG_NOTAR_FALLBACK_CERT_MAX, "consensus safety violation" ); /* Lemma 48 */
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
ag_slot_state_add_vote( ag_slot_state_t *  self,
                        ag_slot_states_t * states,
                        ag_vote_t const *  vote,
                        ulong              stake,
                        ag_cert_t *        out_cert_events,
                        ulong *            out_cert_event_cnt,
                        ag_block_id_t *    out_safe_to_notar,
                        ulong *            out_safe_to_notar_cnt,
                        ulong *            out_safe_to_skip,
                        ulong *            out_safe_to_skip_cnt,
                        ag_block_id_t *    out_repair_events,
                        ulong *            out_repair_event_cnt,
                        fd_bls_set_t *     bad ) {
  ulong slot = ag_vote_slot( vote );
  ulong rank = ag_vote_rank( vote );

  fd_bls_sig_t const * sig = ag_vote_sig( vote );

  FD_TEST( fd_bls_sig_pool_free( states->bls_sig_pool ) );
  uint sig_idx = (uint)fd_bls_sig_pool_idx_acquire( states->bls_sig_pool );
  fd_bls_sig_pool_ele( states->bls_sig_pool, sig_idx )->sig = *sig;

  *out_cert_event_cnt = 0UL; *out_safe_to_notar_cnt = 0UL; *out_safe_to_skip_cnt = 0UL; *out_repair_event_cnt = 0UL; fd_bls_set_null( bad );
  self->shred_version = ag_vote_shred_version( vote );
  int err;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR:
    self->votes.notar_sig_idx[ rank ] = sig_idx;
    fd_bls_set_insert( self->votes.notar_set, rank );
    err = count_notar_stake( self, states, &vote->notar, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    FD_TEST( self->votes.notar_fallback_sig_cnt[ rank ]<AG_NOTAR_FALLBACK_VOTE_MAX );
    self->votes.notar_fallback_sig_idx[ rank ][ self->votes.notar_fallback_sig_cnt[ rank ] ] = sig_idx;
    self->votes.notar_fallback_sig_cnt[ rank ]++;
    err = count_notar_fallback_stake( self, states, &vote->notar_fallback, stake, out_cert_events, out_cert_event_cnt, bad );
    break;
  case AG_VOTE_KIND_SKIP:
    self->votes.skip_sig_idx[ rank ] = sig_idx;
    self->votes.notar_or_skip_stake += stake;
    err = count_skip_stake( self, states, vote, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    self->votes.skip_fallback_sig_idx[ rank ] = sig_idx;
    err = count_skip_stake( self, states, vote, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_FINAL:
    self->votes.finalize_sig_idx[ rank ] = sig_idx;
    err = count_finalize_stake( self, states, &vote->final, stake, out_cert_events, out_cert_event_cnt, bad );
    break;
  default:
    FD_LOG_CRIT(( "unreachable" ));
  }

  if( FD_UNLIKELY( rank==self->own_rank ) ) {
    ag_block_hash_set_t pending = self->pending_safe_to_notar;
    for( ulong i=0UL; i<pending.cnt; i++ ) {
      if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) ) continue;
      switch( check_safe_to_notar( self, states, pending.hash[i], bad ) ) {
      case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR: out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = ag_block_id( slot, pending.hash[i] ); break;
      case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
        ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) ) break;
        if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = ag_block_id( slot, pending.hash[i] );
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
                                       ag_slot_states_t *    states,
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

  switch( check_safe_to_notar( self, states, block_hash, bad ) ) {
  case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK:  return -1; /* unreachable: this block's parents entry was found above */
  case AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES: return  0;
  case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:  return  1;
  default:                                     FD_LOG_CRIT(( "unreachable" ));
  }
}

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const *  self,
                                       ag_slot_states_t const * states,
                                       ag_vote_t const *        vote ) {
  ulong voter = ag_vote_rank( vote );
  ag_slot_votes_t const * votes = &self->votes;

  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) {
      if( FD_UNLIKELY( memcmp( ag_vote_stake_pool_ele_const( states->notar_hash_stake_pool, votes->notar_hash_stake_idx[ voter ] )->block_id.hash, vote->notar.block_hash, sizeof(ag_block_hash_t) ) ) ) return AG_SLASHABLE_NOTAR_DIFFERENT_HASH;
    }
    break;
  }

  case AG_VOTE_KIND_NOTAR_FALLBACK:
    if( FD_UNLIKELY( fd_bls_set_test( votes->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    } else if( FD_UNLIKELY( votes->notar_fallback_sig_cnt[ voter ]>=AG_NOTAR_FALLBACK_VOTE_MAX ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_OVER_THREE;
    }
    break;

  case AG_VOTE_KIND_SKIP:
    if( FD_UNLIKELY( fd_bls_set_test( votes->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    break;

  case AG_VOTE_KIND_SKIP_FALLBACK:
    if( FD_UNLIKELY( fd_bls_set_test( votes->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    break;

  case AG_VOTE_KIND_FINAL: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, voter ) || fd_bls_set_test( votes->skip_fallback_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    if( FD_UNLIKELY( votes->notar_fallback_sig_cnt[ voter ] ) ) {
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
ag_slot_state_check_conflicting_vote( ag_slot_state_t const *  self,
                                      ag_slot_states_t const * states,
                                      ag_vote_t const *        vote ) {
  ulong                   voter = ag_vote_rank( vote );
  ag_slot_votes_t const * votes = &self->votes;
  switch( vote->kind ) {
  case AG_VOTE_KIND_SKIP:
    return fd_bls_set_test( votes->skip_fallback_agg.set, voter );
  case AG_VOTE_KIND_SKIP_FALLBACK:
    return fd_bls_set_test( votes->skip_agg.set, voter );
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    return fd_bls_set_test( votes->notar_set, voter ) && !memcmp( ag_vote_stake_pool_ele_const( states->notar_hash_stake_pool, votes->notar_hash_stake_idx[ voter ] )->block_id.hash, vote->notar_fallback.block_hash, sizeof(ag_block_hash_t) );
  case AG_VOTE_KIND_NOTAR:
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ voter ]; j++ )
      if( FD_UNLIKELY( !memcmp( ag_vote_stake_pool_ele_const( states->notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ voter ][ j ] )->block_id.hash, vote->notar.block_hash, sizeof(ag_block_hash_t) ) ) ) return 1;
    return 0;
  default:
    return 0;
  }
}

FD_FN_PURE int
ag_slot_state_should_ignore_vote( ag_slot_state_t const *  self,
                                  ag_slot_states_t const * states,
                                  ag_vote_t const *        vote ) {
  ulong                       voter                          = ag_vote_rank( vote );
  ag_slot_votes_t const *     votes                          = &self->votes;
  ag_vote_stake_ele_t const * notar_hash_stake_pool          = states->notar_hash_stake_pool;
  ag_vote_stake_ele_t const * notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) return 1;

    uchar const * hash = vote->notar.block_hash;
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( !memcmp( ag_vote_stake_pool_ele_const( notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ voter ][ j ] )->block_id.hash, hash, sizeof(ag_block_hash_t) ) ) ) return 1;
    }
    return 0;
  }
  case AG_VOTE_KIND_NOTAR_FALLBACK: {
    uchar const * hash = vote->notar_fallback.block_hash;
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( !memcmp( ag_vote_stake_pool_ele_const( notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ voter ][ j ] )->block_id.hash, hash, sizeof(ag_block_hash_t) ) ) ) return 1;
    }

    return fd_bls_set_test( votes->notar_set, voter ) && !memcmp( ag_vote_stake_pool_ele_const( notar_hash_stake_pool, votes->notar_hash_stake_idx[ voter ] )->block_id.hash, hash, sizeof(ag_block_hash_t) );
  }
  case AG_VOTE_KIND_SKIP:
  case AG_VOTE_KIND_SKIP_FALLBACK:
    return fd_bls_set_test( votes->skip_agg.set, voter ) || fd_bls_set_test( votes->skip_fallback_agg.set, voter );
  case AG_VOTE_KIND_FINAL:
    return fd_bls_set_test( votes->finalize_agg.set, voter );
  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return 0;
}

fd_bls_agg_t *
ag_slot_state_notar_reward_agg( ag_slot_state_t const *  self,
                                ag_slot_states_t const * states,
                                fd_bls_agg_t *           out ) {
  ag_epoch_info_t const * epoch_info = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ag_block_id_t           key        = ag_block_id( self->slot, self->votes.top_notar_hash );
  ulong                   top        = ag_vote_stake_map_idx_query_const( states->notar_hash_stake_map, &key, ULONG_MAX, states->notar_hash_stake_pool );
  if( FD_UNLIKELY( top==ULONG_MAX ) ) return NULL;

  fd_bls_set_t set[ fd_bls_set_word_cnt ];
  fd_bls_set_null( set );
  for( ulong rank = fd_bls_set_const_iter_init( self->votes.notar_set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( self->votes.notar_set, rank ) ) {
    if( FD_LIKELY( self->votes.notar_hash_stake_idx[ rank ]==top ) ) fd_bls_set_insert( set, rank );
  }
  fd_bls_sig_t sigs[ AG_VAT_MAX ];
  ag_slot_state_sigs( self, states, AG_VOTE_KIND_NOTAR, key.hash, set, sigs );
  fd_bls_agg_null( out );
  fd_bls_agg_construct( out, epoch_info->pubkeys, sigs, set );
  return out;
}

FD_FN_PURE fd_bls_agg_t const *
ag_slot_state_skip_reward_agg( ag_slot_state_t const * self ) {
  return fd_bls_set_is_null( self->votes.skip_agg.set ) ? NULL : &self->votes.skip_agg;
}

fd_bls_sig_t *
ag_slot_state_sigs( ag_slot_state_t const *  self,
                    ag_slot_states_t const * states,
                    uint                     kind,
                    ag_block_hash_t const    block_hash,
                    fd_bls_set_t const *     set,
                    fd_bls_sig_t *           out ) {
  ag_slot_votes_t const *     votes                          = &self->votes;
  ag_vote_stake_ele_t const * notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    ulong idx;
    switch( kind ) {
    case AG_VOTE_KIND_NOTAR:         idx = votes->notar_sig_idx        [ rank ]; break;
    case AG_VOTE_KIND_SKIP:          idx = votes->skip_sig_idx         [ rank ]; break;
    case AG_VOTE_KIND_SKIP_FALLBACK: idx = votes->skip_fallback_sig_idx[ rank ]; break;
    case AG_VOTE_KIND_FINAL:         idx = votes->finalize_sig_idx     [ rank ]; break;
    case AG_VOTE_KIND_NOTAR_FALLBACK: {
      ulong j;
      for( j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_UNLIKELY( !memcmp( ag_vote_stake_pool_ele_const( notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ rank ][ j ] )->block_id.hash, block_hash, sizeof(ag_block_hash_t) ) ) ) break;
      }
      FD_CHECK_CRIT( j<votes->notar_fallback_sig_cnt[ rank ], "invariant violation" );
      idx = votes->notar_fallback_sig_idx[ rank ][ j ];
      break;
    }
    default: FD_LOG_CRIT(( "unreachable" ));
    }
    out[ rank ] = fd_bls_sig_pool_ele_const( states->bls_sig_pool, idx )->sig;
  }
  return out;
}
