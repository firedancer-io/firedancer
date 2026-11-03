#include "fd_votor_pool.h"
#include "fd_finality_tracker.h"
#include "fd_parent_ready_tracker.h"
#include "fd_vote_serde.h"

#define PARENT_STATUS_KNOWN     (1)
#define PARENT_STATUS_CERTIFIED (2)

#define SLASHABLE_OFFENCE_NONE                        (0)
#define SLASHABLE_OFFENCE_NOTAR_DIFFERENT_HASH        (1)
#define SLASHABLE_OFFENCE_SKIP_AND_NOTARIZE           (2)
#define SLASHABLE_OFFENCE_SKIP_AND_FINALIZE           (3)
#define SLASHABLE_OFFENCE_NOTAR_FALLBACK_AND_FINALIZE (4)

#define SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR  (0)
#define SAFE_TO_NOTAR_STATUS_MISSING_BLOCK  (1)
#define SAFE_TO_NOTAR_STATUS_AWAITING_VOTES (2)

#define SLOT_STATE_OUT_CERT_MAX   (3UL)
#define SLOT_STATE_OUT_EVENT_MAX  (3UL)
#define SLOT_STATE_OUT_REPAIR_MAX (3UL)

#define NOTAR_FALLBACK_HASH_MAX (FD_VOTOR_VAT_MAX*FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX)

#define STANDSTILL_FINAL               (0UL)
#define STANDSTILL_FAST_FINAL          (1UL)
#define STANDSTILL_NOTAR               (2UL)
#define STANDSTILL_NOTAR_FALLBACK      (3UL)
#define STANDSTILL_SKIP                (STANDSTILL_NOTAR_FALLBACK+FD_VOTOR_NOTAR_FALLBACK_CERT_MAX)
#define STANDSTILL_NOTAR_VOTE          (STANDSTILL_SKIP+1UL)
#define STANDSTILL_FINAL_VOTE          (STANDSTILL_NOTAR_VOTE+1UL)
#define STANDSTILL_SKIP_VOTE           (STANDSTILL_FINAL_VOTE+1UL)
#define STANDSTILL_NOTAR_FALLBACK_VOTE (STANDSTILL_SKIP_VOTE+1UL)
#define STANDSTILL_SKIP_FALLBACK_VOTE  (STANDSTILL_NOTAR_FALLBACK_VOTE+FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX)

struct __attribute__((aligned(64UL))) vote_stake_ele {
  fd_block_id_t block_id;
  uint          next;
  uint          prev;
  ulong         stake;
};
typedef struct vote_stake_ele vote_stake_ele_t;
FD_STATIC_ASSERT( sizeof(vote_stake_ele_t)==64UL, vote_stake_ele );

#define POOL_NAME  vote_stake_pool
#define POOL_T     vote_stake_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               vote_stake_map
#define MAP_ELE_T              vote_stake_ele_t
#define MAP_KEY                block_id
#define MAP_KEY_T              fd_block_id_t
#define MAP_IDX_T              uint
#define MAP_NEXT               next
#define MAP_KEY_EQ(k0,k1)      (fd_block_id_eq((k0),(k1)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_block_id_t)))
#include "../../util/tmpl/fd_map_chain.c"

struct parent_status {
  fd_block_hash_t hash;
  int             kind;
};
typedef struct parent_status parent_status_t;

struct block_hash_set {
  fd_block_hash_t hash[ FD_VOTOR_EQVOC_MAX ];
  ulong           cnt;
};
typedef struct block_hash_set block_hash_set_t;

union bls_sig_ele {
  fd_bls_sig_t sig;
  ulong        next;
};
typedef union bls_sig_ele bls_sig_ele_t;
FD_STATIC_ASSERT( sizeof(bls_sig_ele_t)==sizeof(fd_bls_sig_t), bls_sig_ele );

#define POOL_NAME bls_sig_pool
#define POOL_T    bls_sig_ele_t
#include "../../util/tmpl/fd_pool.c"

struct slot_votes {
  fd_bls_set_t    notar_set                    [ fd_bls_set_word_cnt ];
  uint            notar_sig_idx                [ FD_VOTOR_VAT_MAX ];
  uint            notar_hash_stake_idx         [ FD_VOTOR_VAT_MAX ];
  uint            notar_hash_stake_head;
  ulong           notar_hash_stake_cnt;
  uint            notar_fallback_sig_idx       [ FD_VOTOR_VAT_MAX ][ FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX ];
  uint            notar_fallback_hash_stake_idx[ FD_VOTOR_VAT_MAX ][ FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX ];
  uint            notar_fallback_hash_stake_head;
  ulong           notar_fallback_hash_stake_cnt;
  uchar           notar_fallback_sig_cnt       [ FD_VOTOR_VAT_MAX ];
  ulong           skip_stake;
  uint            skip_sig_idx                 [ FD_VOTOR_VAT_MAX ];
  fd_bls_agg_t    skip_agg;
  ulong           skip_fallback_stake;
  uint            skip_fallback_sig_idx        [ FD_VOTOR_VAT_MAX ];
  fd_bls_agg_t    skip_fallback_agg;
  ulong           final_stake;
  uint            final_sig_idx                [ FD_VOTOR_VAT_MAX ];
  fd_bls_agg_t    final_agg;
  ulong           notar_or_skip_stake;
  ulong           top_notar_stake;
  fd_block_hash_t top_notar_hash;
};
typedef struct slot_votes slot_votes_t;

struct slot_certs {
  fd_cert_notar_t          notar;
  fd_cert_notar_fallback_t notar_fallback[ FD_VOTOR_NOTAR_FALLBACK_CERT_MAX ];
  fd_cert_skip_t           skip;
  fd_cert_fast_final_t     fast_final;
  fd_cert_final_t          final;
  uchar                    notar_fallback_cnt;
};
typedef struct slot_certs slot_certs_t;

struct slot_state {
  slot_votes_t votes;
  slot_certs_t certs;

  parent_status_t parents[ FD_VOTOR_EQVOC_MAX ];
  ulong           parents_cnt;

  block_hash_set_t pending_safe_to_notar;
  block_hash_set_t verified_safe_to_notar; /* verified votes alone meet its safe-to-notar threshold */
  block_hash_set_t sent_safe_to_notar;
  int              sent_safe_to_skip;

  ulong  slot;
  ulong  own_rank;
  ushort shred_version;
};
typedef struct slot_state slot_state_t;

struct slot_state_ele {
  ulong        slot;
  ulong        next;
  slot_state_t slot_state;
};
typedef struct slot_state_ele slot_state_ele_t;

#define POOL_NAME slot_state_pool
#define POOL_T    slot_state_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               slot_state_map
#define MAP_ELE_T              slot_state_ele_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash((*(key))^(seed)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct slot_states {
  slot_state_ele_t *      pool;
  slot_state_map_t *      map;

  bls_sig_ele_t *         bls_sig_pool;
  vote_stake_ele_t *      notar_hash_stake_pool;
  vote_stake_map_t *      notar_hash_stake_map;
  vote_stake_ele_t *      notar_fallback_hash_stake_pool;
  vote_stake_map_t *      notar_fallback_hash_stake_map;
  fd_epoch_info_t const * prev_epoch_info;
  ulong                   prev_epoch_rank;
  ulong                   prev_epoch_slot;
  fd_epoch_info_t const * curr_epoch_info;
  ulong                   curr_epoch_rank;
  ulong                   curr_epoch_slot;
  fd_epoch_info_t const * next_epoch_info;
  ulong                   next_epoch_rank;
  ulong                   next_epoch_slot;
  ulong                   bls_verify_cnt;
};
typedef struct slot_states slot_states_t;

static int
block_hash_set_contains( block_hash_set_t const * self,
                         fd_block_hash_t const *  block_hash ) {
  for( ulong i=0UL; i<self->cnt; i++ ) {
    if( FD_LIKELY( !memcmp( &self->hash[i], block_hash, sizeof(fd_block_hash_t) ) ) ) return 1;
  }
  return 0;
}

static void
block_hash_set_insert( block_hash_set_t *      self,
                       fd_block_hash_t const * block_hash ) {
  if( FD_UNLIKELY( block_hash_set_contains( self, block_hash ) ) ) return;
  FD_TEST( self->cnt < FD_VOTOR_EQVOC_MAX );
  memcpy( &self->hash[ self->cnt++ ], block_hash, sizeof(fd_block_hash_t) );
}

static void
block_hash_set_remove( block_hash_set_t *      self,
                       fd_block_hash_t const * block_hash ) {
  for( ulong i=0UL; i<self->cnt; i++ ) {
    if( FD_LIKELY( !memcmp( &self->hash[i], block_hash, sizeof(fd_block_hash_t) ) ) ) {
      self->cnt--;
      if( FD_UNLIKELY( i!=self->cnt ) ) memcpy( &self->hash[i], &self->hash[ self->cnt ], sizeof(fd_block_hash_t) );
      return;
    }
  }
}

/* Definition 13. SlotState::is_notar_fallback */

FD_FN_PURE static int
slot_state_is_notar_fallback( slot_state_t const *    self,
                              fd_block_hash_t const * block_hash ) {
  slot_certs_t const * c = &self->certs;
  for( ulong i=0UL; i<c->notar_fallback_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( &c->notar_fallback[i].block_hash, block_hash, sizeof(fd_block_hash_t) ) ) ) return 1;
  }
  return 0;
}

/* Definition 13. SlotState::is_notar_fallback_or_stronger */

FD_FN_PURE static int
slot_state_is_notar_fallback_or_stronger( slot_state_t const *    self,
                                          fd_block_hash_t const * block_hash ) {
  int has_notar_cert      = self->certs.notar.slot !=ULONG_MAX && !memcmp( &self->certs.notar.block_hash, block_hash, sizeof(fd_block_hash_t) );
  int has_fast_final_cert = self->certs.fast_final.slot!=ULONG_MAX && !memcmp( &self->certs.fast_final.block_hash, block_hash, sizeof(fd_block_hash_t) );
  return has_notar_cert || has_fast_final_cert || slot_state_is_notar_fallback( self, block_hash );
}

/* Copies the kind vote sigs of the ranks in set into out[ rank ].
   block_hash selects the sig for notar fallback; for notar the caller
   filters set by hash. */

static fd_bls_sig_t *
slot_state_sigs( slot_state_t const *    self,
                 slot_states_t const *   states,
                 uint                    kind,
                 fd_block_hash_t const * block_hash,
                 fd_bls_set_t const *    set,
                 fd_bls_sig_t *          out ) {
  slot_votes_t const *     votes                          = &self->votes;
  vote_stake_ele_t const * notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    ulong idx;
    switch( kind ) {
    case FD_VOTE_KIND_NOTAR:         idx = votes->notar_sig_idx        [ rank ]; break;
    case FD_VOTE_KIND_SKIP:          idx = votes->skip_sig_idx         [ rank ]; break;
    case FD_VOTE_KIND_SKIP_FALLBACK: idx = votes->skip_fallback_sig_idx[ rank ]; break;
    case FD_VOTE_KIND_FINAL:         idx = votes->final_sig_idx        [ rank ]; break;
    case FD_VOTE_KIND_NOTAR_FALLBACK: {
      ulong j;
      for( j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_UNLIKELY( !memcmp( &vote_stake_pool_ele_const( notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ rank ][ j ] )->block_id.hash, block_hash, sizeof(fd_block_hash_t) ) ) ) break;
      }
      FD_CHECK_CRIT( j<votes->notar_fallback_sig_cnt[ rank ], "invariant violation" );
      idx = votes->notar_fallback_sig_idx[ rank ][ j ];
      break;
    }
    default: FD_LOG_CRIT(( "unreachable" ));
    }
    out[ rank ] = bls_sig_pool_ele_const( states->bls_sig_pool, idx )->sig;
  }
  return out;
}

static int
verify_subtract_votes( slot_state_t *          self,
                       slot_states_t *         states,
                       uint                    kind,
                       fd_block_hash_t const * block_hash,
                       fd_bls_agg_t *          agg,
                       fd_bls_set_t *          bad ) {
  fd_epoch_info_t const * epoch_info                     = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  slot_votes_t *          votes                          = &self->votes;
  vote_stake_map_t *      notar_hash_stake_map           = states->notar_hash_stake_map;
  vote_stake_map_t *      notar_fallback_hash_stake_map  = states->notar_fallback_hash_stake_map;
  vote_stake_ele_t *      notar_hash_stake_pool          = states->notar_hash_stake_pool;
  vote_stake_ele_t *      notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;

  fd_bls_sig_t sigs[ FD_VOTOR_VAT_MAX ];
  fd_bls_set_t set [ fd_bls_set_word_cnt ];
  switch( kind ) {
  case FD_VOTE_KIND_SKIP:
  case FD_VOTE_KIND_SKIP_FALLBACK:
  case FD_VOTE_KIND_FINAL:
    slot_state_sigs( self, states, kind, NULL, agg->set, sigs );
    break;
  case FD_VOTE_KIND_NOTAR:
    fd_bls_set_null( set );
    for( ulong rank = fd_bls_set_const_iter_init( votes->notar_set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( votes->notar_set, rank ) ) {
      if( FD_LIKELY( !memcmp( &vote_stake_pool_ele( notar_hash_stake_pool, votes->notar_hash_stake_idx[ rank ] )->block_id.hash, block_hash, sizeof(fd_block_hash_t) ) ) ) fd_bls_set_insert( set, rank );
    }
    slot_state_sigs( self, states, kind, block_hash, set, sigs );
    fd_bls_agg_null( agg );
    fd_bls_agg_construct( agg, epoch_info->pubkeys, sigs, set );
    break;
  case FD_VOTE_KIND_NOTAR_FALLBACK:
    fd_bls_set_null( set );
    for( ulong rank=0UL; rank<epoch_info->validator_cnt; rank++ ) {
      for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_LIKELY( !memcmp( &vote_stake_pool_ele( notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ rank ][ j ] )->block_id.hash, block_hash, sizeof(fd_block_hash_t) ) ) ) fd_bls_set_insert( set, rank );
      }
    }
    slot_state_sigs( self, states, kind, block_hash, set, sigs );
    fd_bls_agg_null( agg );
    fd_bls_agg_construct( agg, epoch_info->pubkeys, sigs, set );
    break;
  default: FD_LOG_CRIT(( "unreachable" ));
  }

  uchar msg[ FD_VOTE_SIGNING_SER_MAX ];
  ulong msg_sz = fd_vote_signing_ser( kind, self->slot, block_hash, self->shred_version, msg );
  states->bls_verify_cnt++;
  int   err    = fd_bls_agg_verify_subtract( agg, msg, msg_sz, epoch_info->pubkeys, sigs, bad );
  if( FD_LIKELY( !err && fd_bls_set_is_null( bad ) ) ) return 1;

  fd_block_id_t key;
  ulong         id = ULONG_MAX;
  switch( kind ) {
  case FD_VOTE_KIND_NOTAR:          key = fd_block_id( self->slot, block_hash->uc ); id = vote_stake_map_idx_query_const( notar_hash_stake_map,          &key, ULONG_MAX, notar_hash_stake_pool          ); break;
  case FD_VOTE_KIND_NOTAR_FALLBACK: key = fd_block_id( self->slot, block_hash->uc ); id = vote_stake_map_idx_query_const( notar_fallback_hash_stake_map, &key, ULONG_MAX, notar_fallback_hash_stake_pool ); break;
  default: break;
  }

  for( ulong rank = fd_bls_set_const_iter_init( bad );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( bad, rank ) ) {
    ulong stake = fd_epoch_info_validator( epoch_info, rank )->stake;
    switch( kind ) {
    case FD_VOTE_KIND_NOTAR:
      vote_stake_pool_ele( notar_hash_stake_pool, id )->stake -= stake;
      votes->notar_or_skip_stake -= stake;
      fd_bls_set_remove( votes->notar_set, rank );
      bls_sig_pool_idx_release( states->bls_sig_pool, votes->notar_sig_idx[ rank ] );
      break;
    case FD_VOTE_KIND_NOTAR_FALLBACK: {
      ulong j;
      for( j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_UNLIKELY( votes->notar_fallback_hash_stake_idx[ rank ][ j ]==id ) ) break;
      }
      FD_CHECK_CRIT( j<votes->notar_fallback_sig_cnt[ rank ], "invariant violation" );
      vote_stake_pool_ele( notar_fallback_hash_stake_pool, id )->stake -= stake;
      bls_sig_pool_idx_release( states->bls_sig_pool, votes->notar_fallback_sig_idx[ rank ][ j ] );
      votes->notar_fallback_sig_cnt[ rank ]--;
      votes->notar_fallback_sig_idx       [ rank ][ j ] = votes->notar_fallback_sig_idx       [ rank ][ votes->notar_fallback_sig_cnt[ rank ] ];
      votes->notar_fallback_hash_stake_idx[ rank ][ j ] = votes->notar_fallback_hash_stake_idx[ rank ][ votes->notar_fallback_sig_cnt[ rank ] ];
      break;
    }
    case FD_VOTE_KIND_SKIP:
      votes->skip_stake -= stake;
      votes->notar_or_skip_stake -= stake;
      bls_sig_pool_idx_release( states->bls_sig_pool, votes->skip_sig_idx[ rank ] );
      break;
    case FD_VOTE_KIND_SKIP_FALLBACK:
      votes->skip_fallback_stake -= stake;
      bls_sig_pool_idx_release( states->bls_sig_pool, votes->skip_fallback_sig_idx[ rank ] );
      break;
    case FD_VOTE_KIND_FINAL:
      votes->final_stake -= stake;
      bls_sig_pool_idx_release( states->bls_sig_pool, votes->final_sig_idx[ rank ] );
      break;
    default:
      FD_LOG_CRIT(( "unreachable" ));
    }
  }

  if( FD_UNLIKELY( kind==FD_VOTE_KIND_NOTAR && fd_bls_set_is_null( agg->set ) ) ) {
    uint *  link = &votes->notar_hash_stake_head;
    ulong   j;
    for( j=0UL; j<votes->notar_hash_stake_cnt; j++ ) {
      if( FD_UNLIKELY( *link==id ) ) break;
      link = &vote_stake_pool_ele( notar_hash_stake_pool, *link )->prev;
    }
    FD_CHECK_CRIT( j<votes->notar_hash_stake_cnt, "invariant violation" );
    *link = vote_stake_pool_ele( notar_hash_stake_pool, id )->prev;
    votes->notar_hash_stake_cnt--;
    vote_stake_map_idx_remove( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
    vote_stake_pool_idx_release( notar_hash_stake_pool, id );
  }
  if( FD_UNLIKELY( kind==FD_VOTE_KIND_NOTAR_FALLBACK && fd_bls_set_is_null( agg->set ) ) ) {
    uint *  link = &votes->notar_fallback_hash_stake_head;
    ulong   j;
    for( j=0UL; j<votes->notar_fallback_hash_stake_cnt; j++ ) {
      if( FD_UNLIKELY( *link==id ) ) break;
      link = &vote_stake_pool_ele( notar_fallback_hash_stake_pool, *link )->prev;
    }
    FD_CHECK_CRIT( j<votes->notar_fallback_hash_stake_cnt, "invariant violation" );
    *link = vote_stake_pool_ele( notar_fallback_hash_stake_pool, id )->prev;
    votes->notar_fallback_hash_stake_cnt--;
    vote_stake_map_idx_remove( notar_fallback_hash_stake_map, &key, ULONG_MAX, notar_fallback_hash_stake_pool );
    vote_stake_pool_idx_release( notar_fallback_hash_stake_pool, id );
  }
  if( FD_UNLIKELY( kind==FD_VOTE_KIND_NOTAR ) ) {
    votes->top_notar_stake = 0UL;
    ulong i = votes->notar_hash_stake_head;
    for( ulong j=0UL; j<votes->notar_hash_stake_cnt; j++ ) {
      if( FD_LIKELY( vote_stake_pool_ele( notar_hash_stake_pool, i )->stake>votes->top_notar_stake ) ) { /* FIXME slow */
        votes->top_notar_stake = vote_stake_pool_ele( notar_hash_stake_pool, i )->stake;
        memcpy( &votes->top_notar_hash, &vote_stake_pool_ele( notar_hash_stake_pool, i )->block_id.hash, sizeof(fd_block_hash_t) );
      }
      i = vote_stake_pool_ele( notar_hash_stake_pool, i )->prev;
    }
  }
  return !err;
}

static int
check_safe_to_notar( slot_state_t *          self,
                     slot_states_t *         states,
                     fd_block_hash_t const * block_hash,
                     fd_bls_set_t *          bad ) {
  fd_epoch_info_t const * epoch_info            = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  slot_votes_t *          votes                 = &self->votes;
  vote_stake_map_t *      notar_hash_stake_map  = states->notar_hash_stake_map;
  vote_stake_ele_t *      notar_hash_stake_pool = states->notar_hash_stake_pool;
  fd_block_id_t           key                   = fd_block_id( self->slot, block_hash->uc );
  ulong                   notar                 = vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
  ulong                   notar_stake           = notar!=ULONG_MAX ? vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake : 0UL;
  ulong                   skip_stake            = votes->skip_stake;

  if( FD_UNLIKELY( !fd_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) ) ) {
    return SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }
  if( FD_UNLIKELY( !fd_epoch_info_is_weak_quorum( epoch_info, notar_stake ) && !fd_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  parent_status_t const * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( &self->parents[i].hash, block_hash, sizeof(fd_block_hash_t) ) ) ) { parent = &self->parents[i]; break; }
  }
  if( FD_UNLIKELY( !parent ) ) return SAFE_TO_NOTAR_STATUS_MISSING_BLOCK;

  ulong own = self->own_rank;

  int safe_to_notar = 0;
  if( FD_LIKELY( own!=USHORT_MAX ) ) { /* must be staked */
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, own ) ) ) safe_to_notar = 1;
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, own ) ) ) {
      if( FD_UNLIKELY( !memcmp( &vote_stake_pool_ele( notar_hash_stake_pool, votes->notar_hash_stake_idx[ own ] )->block_id.hash, block_hash, sizeof(fd_block_hash_t) ) ) ) return SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
      safe_to_notar = 1;
    }
  }
  if( FD_UNLIKELY( !safe_to_notar ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  if( FD_LIKELY( !block_hash_set_contains( &self->verified_safe_to_notar, block_hash ) ) ) {
    fd_bls_agg_t notar_agg[1];
    fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, FD_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
      fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
      verify_subtract_votes( self, states, FD_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
      fd_bls_set_union( bad, bad, bad_skip );
    }
    notar       = vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
    notar_stake = notar!=ULONG_MAX ? vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake : 0UL;
    skip_stake  = votes->skip_stake;
    if( FD_UNLIKELY( !fd_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) || ( !fd_epoch_info_is_weak_quorum( epoch_info, notar_stake ) && !fd_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) ) ) {
      block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
      return SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
    }
    block_hash_set_insert( &self->verified_safe_to_notar, block_hash );
  }
  if( FD_UNLIKELY( parent->kind!=PARENT_STATUS_CERTIFIED ) ) return SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;

  block_hash_set_remove( &self->pending_safe_to_notar, block_hash );
  block_hash_set_insert( &self->sent_safe_to_notar,    block_hash );
  return SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
}

static int
check_safe_to_skip( slot_state_t *  self,
                    slot_states_t * states,
                    fd_bls_set_t *  bad ) {
  fd_epoch_info_t const * epoch_info = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  slot_votes_t *          votes      = &self->votes;
  if( FD_LIKELY( self->sent_safe_to_skip
                 || !fd_epoch_info_is_weak_quorum( epoch_info, votes->notar_or_skip_stake - votes->top_notar_stake )
                 || self->own_rank==USHORT_MAX /* must be staked */ ) ) return 0;
  if( FD_LIKELY( !fd_bls_set_test( votes->notar_set, self->own_rank ) ) ) return 0;

  if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
    fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, FD_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
    fd_bls_set_union( bad, bad, bad_skip );
  }
  if( FD_LIKELY( fd_epoch_info_is_weak_quorum( epoch_info, votes->skip_stake ) ) ) {
    self->sent_safe_to_skip = 1;
    return 1;
  }

  vote_stake_ele_t * notar_hash_stake_pool = states->notar_hash_stake_pool;
  ulong              i                     = votes->notar_hash_stake_head;
  for( ulong j=votes->notar_hash_stake_cnt; j>0UL; j-- ) {
    fd_block_id_t key  = vote_stake_pool_ele( notar_hash_stake_pool, i )->block_id;
    ulong         prev = vote_stake_pool_ele( notar_hash_stake_pool, i )->prev;
    fd_bls_agg_t  notar_agg[1];
    fd_bls_set_t  bad_notar[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, FD_VOTE_KIND_NOTAR, &key.hash, notar_agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    i = prev;
  }
  if( FD_UNLIKELY( !fd_epoch_info_is_weak_quorum( epoch_info, votes->notar_or_skip_stake - votes->top_notar_stake ) || !fd_bls_set_test( votes->notar_set, self->own_rank ) ) ) return 0;
  self->sent_safe_to_skip = 1;
  return 1;
}

static int
count_notar_stake( slot_state_t *          self,
                   slot_states_t *         states,
                   fd_vote_notar_t const * vote,
                   ulong                   stake,
                   fd_cert_t *             out_cert_events,
                   ulong *                 out_cert_event_cnt,
                   fd_block_id_t *         out_safe_to_notar,
                   ulong *                 out_safe_to_notar_cnt,
                   ulong *                 out_safe_to_skip,
                   ulong *                 out_safe_to_skip_cnt,
                   fd_block_id_t *         out_repair_events,
                   ulong *                 out_repair_event_cnt,
                   fd_bls_set_t *          bad ) {
  fd_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  fd_block_hash_t const * block_hash    = &vote->block_hash;
  fd_block_id_t           key           = fd_block_id( self->slot, block_hash->uc );
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;

  slot_votes_t *     votes                          = &self->votes;
  vote_stake_map_t * notar_hash_stake_map           = states->notar_hash_stake_map;
  vote_stake_map_t * notar_fallback_hash_stake_map  = states->notar_fallback_hash_stake_map;
  vote_stake_ele_t * notar_hash_stake_pool          = states->notar_hash_stake_pool;
  vote_stake_ele_t * notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;
  ulong              notar                          = vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
  if( FD_UNLIKELY( notar==ULONG_MAX ) ) {
    FD_TEST( vote_stake_pool_free( notar_hash_stake_pool ) );
    notar = vote_stake_pool_idx_acquire( notar_hash_stake_pool );
    vote_stake_pool_ele( notar_hash_stake_pool, notar )->block_id = key;
    vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake    = 0UL;
    vote_stake_pool_ele( notar_hash_stake_pool, notar )->prev     = (uint)( votes->notar_hash_stake_cnt ? votes->notar_hash_stake_head : vote_stake_pool_idx_null( notar_hash_stake_pool ) );
    vote_stake_map_idx_insert( notar_hash_stake_map, notar, notar_hash_stake_pool );
    votes->notar_hash_stake_head = (uint)notar;
    votes->notar_hash_stake_cnt++;
  }
  votes->notar_hash_stake_idx[ rank ] = (uint)notar;
  vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake += stake;

  ulong notar_stake           = vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
  votes->notar_or_skip_stake += stake;
  if( FD_LIKELY( notar_stake>votes->top_notar_stake ) ) {
    votes->top_notar_stake = notar_stake;
    memcpy( &votes->top_notar_hash, block_hash, sizeof(fd_block_hash_t) );
  }

  if( FD_UNLIKELY( !block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) {
    switch( check_safe_to_notar( self, states, block_hash, bad ) ) {
    case SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = fd_block_id( slot, block_hash->uc );
      break;
    case SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( &out_repair_events[j].hash, block_hash, sizeof(fd_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = fd_block_id( slot, block_hash->uc );
      break;
    }
    default: break;
    }
  }
  if( FD_UNLIKELY( check_safe_to_skip( self, states, bad ) ) ) {
    out_safe_to_skip[ (*out_safe_to_skip_cnt)++ ] = slot;
  }
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) ) ) {
    notar = vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
    if( FD_UNLIKELY( notar==ULONG_MAX || !fd_bls_set_test( votes->notar_set, rank ) ) ) return 0;
    notar_stake = vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
  }

  vote_stake_ele_t const * nf_ele   = vote_stake_map_ele_query_const( notar_fallback_hash_stake_map, &key, NULL, notar_fallback_hash_stake_pool );
  ulong                    nf_stake = nf_ele ? nf_ele->stake : 0UL;

  int          notar_verified          = 0;
  int          notar_fallback_verified = 0;
  int          newly_notar             = 0;
  fd_bls_agg_t notar_agg[1];
  fd_bls_agg_t nf_agg[1];

  if( FD_UNLIKELY( ( fd_epoch_info_is_quorum       ( epoch_info, nf_stake + notar_stake ) && !slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ||
                   ( fd_epoch_info_is_quorum       ( epoch_info, notar_stake            ) && self->certs.notar.slot==ULONG_MAX                             ) ||
                   ( fd_epoch_info_is_strong_quorum( epoch_info, notar_stake            ) && self->certs.fast_final.slot==ULONG_MAX                        ) ) ) {
    fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
    notar_verified = verify_subtract_votes( self, states, FD_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    if( FD_UNLIKELY( fd_bls_set_test( bad_notar, rank ) ) ) return 0;

    notar_stake = vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
    newly_notar = notar_verified && fd_epoch_info_is_quorum( epoch_info, notar_stake ) && self->certs.notar.slot==ULONG_MAX;
    if( FD_LIKELY( nf_ele && !newly_notar && !slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
      fd_bls_set_t bad_nf[ fd_bls_set_word_cnt ];
      notar_fallback_verified = verify_subtract_votes( self, states, FD_VOTE_KIND_NOTAR_FALLBACK, block_hash, nf_agg, bad_nf );
      fd_bls_set_union( bad, bad, bad_nf );
    }
  }

  if( FD_UNLIKELY( !newly_notar && !slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
    fd_cert_notar_fallback_t cert = { .slot = slot, .shred_version = shred_version }; memcpy( &cert.block_hash, block_hash, sizeof(fd_block_hash_t) );

    if( FD_LIKELY( notar_verified ) ) {
      cert.agg_notar = *notar_agg;
      cert.stake += vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
    }
    if( FD_LIKELY( notar_fallback_verified ) ) {
      cert.agg_notar_fallback = *nf_agg;
      cert.stake += nf_ele->stake;
    }
    if( FD_LIKELY( fd_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[( *out_cert_event_cnt )++] = ( fd_cert_t ){ .kind = FD_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
    }
  }

  if( FD_UNLIKELY( newly_notar ) ) {
    fd_cert_notar_t cert = { .slot = slot, .shred_version = shred_version, .stake = notar_stake, .agg = *notar_agg }; memcpy( &cert.block_hash, block_hash, sizeof(fd_block_hash_t) );
    out_cert_events[ (*out_cert_event_cnt)++ ] = (fd_cert_t){ .kind = FD_CERT_KIND_NOTAR, .notar = cert };
  }

  if( FD_UNLIKELY( notar_verified && fd_epoch_info_is_strong_quorum( epoch_info, notar_stake ) && self->certs.fast_final.slot==ULONG_MAX ) ) {
    fd_cert_fast_final_t cert = { .slot = slot, .shred_version = shred_version, .stake = notar_stake, .agg = *notar_agg }; memcpy( &cert.block_hash, block_hash, sizeof(fd_block_hash_t) );
    out_cert_events[ (*out_cert_event_cnt)++ ] = (fd_cert_t){ .kind = FD_CERT_KIND_FAST_FINAL, .fast_final = cert };
  }

  return 1;
}

static int
count_notar_fallback_stake( slot_state_t *                   self,
                            slot_states_t *                  states,
                            fd_vote_notar_fallback_t const * vote,
                            ulong                            stake,
                            fd_cert_t *                      out_cert_events,
                            ulong *                          out_cert_event_cnt,
                            fd_bls_set_t *                   bad ) {
  fd_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  fd_block_hash_t const * block_hash    = &vote->block_hash;
  fd_block_id_t           key           = fd_block_id( self->slot, block_hash->uc );
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;

  slot_votes_t *     votes                          = &self->votes;
  vote_stake_map_t * notar_hash_stake_map           = states->notar_hash_stake_map;
  vote_stake_map_t * notar_fallback_hash_stake_map  = states->notar_fallback_hash_stake_map;
  vote_stake_ele_t * notar_hash_stake_pool          = states->notar_hash_stake_pool;
  vote_stake_ele_t * notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;
  vote_stake_ele_t * nf_ele                         = vote_stake_map_ele_query( notar_fallback_hash_stake_map, &key, NULL, notar_fallback_hash_stake_pool );
  if( FD_UNLIKELY( !nf_ele ) ) {
    FD_TEST( vote_stake_pool_free( notar_fallback_hash_stake_pool ) );
    nf_ele           = vote_stake_pool_ele_acquire( notar_fallback_hash_stake_pool );
    nf_ele->block_id = key;
    nf_ele->stake    = 0UL;
    nf_ele->prev     = (uint)( votes->notar_fallback_hash_stake_cnt ? votes->notar_fallback_hash_stake_head : vote_stake_pool_idx_null( notar_fallback_hash_stake_pool ) );
    vote_stake_map_ele_insert( notar_fallback_hash_stake_map, nf_ele, notar_fallback_hash_stake_pool );
    votes->notar_fallback_hash_stake_head = (uint)vote_stake_pool_idx( notar_fallback_hash_stake_pool, nf_ele );
    votes->notar_fallback_hash_stake_cnt++;
  }
  votes->notar_fallback_hash_stake_idx[ rank ][ votes->notar_fallback_sig_cnt[ rank ]-1UL ] = (uint)vote_stake_pool_idx( notar_fallback_hash_stake_pool, nf_ele );
  nf_ele->stake += stake;

  ulong notar       = vote_stake_map_idx_query_const( notar_hash_stake_map, &key, ULONG_MAX, notar_hash_stake_pool );
  ulong nf_stake    = nf_ele->stake;
  ulong notar_stake = notar!=ULONG_MAX ? vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake : 0UL;
  if( FD_UNLIKELY( fd_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) && !slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
    fd_bls_agg_t nf_agg[1];
    fd_bls_agg_t notar_agg[1];
    fd_bls_set_t bad_nf[ fd_bls_set_word_cnt ];
    int nf_verified = verify_subtract_votes( self, states, FD_VOTE_KIND_NOTAR_FALLBACK, block_hash, nf_agg, bad_nf );
    fd_bls_set_union( bad, bad, bad_nf );
    if( FD_UNLIKELY( fd_bls_set_test( bad_nf, rank ) ) ) return 0;
    int notar_verified = 0;
    if( FD_LIKELY( notar!=ULONG_MAX ) ) {
      fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
      notar_verified = verify_subtract_votes( self, states, FD_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
      fd_bls_set_union( bad, bad, bad_notar );
    }

    fd_cert_notar_fallback_t cert = { .slot = slot, .shred_version = shred_version }; memcpy( &cert.block_hash, block_hash, sizeof(fd_block_hash_t) );

    if( FD_LIKELY( notar_verified ) ) {
      cert.agg_notar = *notar_agg;
      cert.stake += vote_stake_pool_ele( notar_hash_stake_pool, notar )->stake;
    }
    if( FD_LIKELY( nf_verified ) ) {
      cert.agg_notar_fallback = *nf_agg;
      cert.stake += nf_ele->stake;
    }
    if( FD_LIKELY( fd_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[ (*out_cert_event_cnt)++ ] = (fd_cert_t){ .kind = FD_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
    }
  }

  return 1;
}

static int
count_skip_stake( slot_state_t *    self,
                  slot_states_t *   states,
                  fd_vote_t const * vote,
                  ulong             stake,
                  fd_cert_t *       out_cert_events,
                  ulong *           out_cert_event_cnt,
                  fd_block_id_t *   out_safe_to_notar,
                  ulong *           out_safe_to_notar_cnt,
                  ulong *           out_safe_to_skip,
                  ulong *           out_safe_to_skip_cnt,
                  fd_block_id_t *   out_repair_events,
                  ulong *           out_repair_event_cnt,
                  fd_bls_set_t *    bad ) {
  fd_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  int                     fallback      = vote->kind==FD_VOTE_KIND_SKIP_FALLBACK;
  ulong                   slot          = fd_vote_slot( vote );
  ulong                   rank          = fd_vote_rank( vote );
  ushort                  shred_version = fd_vote_shred_version( vote );
  fd_bls_sig_t const *    sig           = fd_vote_sig( vote );
  fd_bls_pub_t const *    pub           = fd_epoch_info_pubkey( epoch_info, rank );

  slot_votes_t * votes = &self->votes;
  if( FD_UNLIKELY( fallback ) ) { votes->skip_fallback_stake += stake; fd_bls_pub_add( &votes->skip_fallback_agg.pub, &votes->skip_fallback_agg.pub, pub ); fd_bls_sig_add( &votes->skip_fallback_agg.sig, &votes->skip_fallback_agg.sig, sig ); fd_bls_set_insert( votes->skip_fallback_agg.set, rank ); }
  else                          { votes->skip_stake          += stake; fd_bls_pub_add( &votes->skip_agg.pub,          &votes->skip_agg.pub,          pub ); fd_bls_sig_add( &votes->skip_agg.sig,          &votes->skip_agg.sig,          sig ); fd_bls_set_insert( votes->skip_agg.set,          rank ); }

  block_hash_set_t pending = self->pending_safe_to_notar;
  for( ulong i=0UL; i<pending.cnt; i++ ) {
    if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, &pending.hash[i] ) ) ) continue;
    switch( check_safe_to_notar( self, states, &pending.hash[i], bad ) ) {
    case SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = fd_block_id( slot, pending.hash[i].uc );
      break;
    case SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( &out_repair_events[j].hash, &pending.hash[i], sizeof(fd_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = fd_block_id( slot, pending.hash[i].uc );
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
  if( FD_UNLIKELY( fd_epoch_info_is_quorum( epoch_info, total_skip_stake ) && self->certs.skip.slot==ULONG_MAX ) ) {
    if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
      fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
      skip_verified = verify_subtract_votes( self, states, FD_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
      fd_bls_set_union( bad, bad, bad_skip );
    }
    if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_fallback_agg.set ) ) ) {
      fd_bls_set_t bad_sf[ fd_bls_set_word_cnt ];
      skip_fallback_verified = verify_subtract_votes( self, states, FD_VOTE_KIND_SKIP_FALLBACK, NULL, &votes->skip_fallback_agg, bad_sf );
      fd_bls_set_union( bad, bad, bad_sf );
    }
    if( FD_UNLIKELY( !fd_bls_set_test( fallback ? votes->skip_fallback_agg.set : votes->skip_agg.set, rank ) ) ) return 0;

    fd_cert_skip_t cert = { .slot = slot, .shred_version = shred_version };

    if( FD_LIKELY( skip_verified ) ) {
      cert.agg_skip = votes->skip_agg;
      cert.stake += votes->skip_stake;
    }
    if( FD_LIKELY( skip_fallback_verified ) ) {
      cert.agg_skip_fallback = votes->skip_fallback_agg;
      cert.stake += votes->skip_fallback_stake;
    }
    if( FD_LIKELY( fd_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[ (*out_cert_event_cnt)++ ] = (fd_cert_t){ .kind = FD_CERT_KIND_SKIP, .skip = cert };
    }
  }

  return 1;
}

static int
count_final_stake( slot_state_t *          self,
                   slot_states_t *         states,
                   fd_vote_final_t const * vote,
                   ulong                   stake,
                   fd_cert_t *             out_cert_events,
                   ulong *                 out_cert_event_cnt,
                   fd_bls_set_t *          bad ) {
  fd_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;
  fd_bls_sig_t const *    sig           = &vote->sig;
  fd_bls_pub_t const *    pub           = fd_epoch_info_pubkey( epoch_info, rank );

  slot_votes_t * votes = &self->votes;
  votes->final_stake += stake;
  fd_bls_pub_add( &votes->final_agg.pub, &votes->final_agg.pub, pub );
  fd_bls_sig_add( &votes->final_agg.sig, &votes->final_agg.sig, sig );
  fd_bls_set_insert( votes->final_agg.set, rank );
  if( FD_UNLIKELY( fd_epoch_info_is_quorum( epoch_info, votes->final_stake ) && self->certs.final.slot==ULONG_MAX ) ) {
    fd_bls_set_t bad_final[ fd_bls_set_word_cnt ];
    int final_verified = verify_subtract_votes( self, states, FD_VOTE_KIND_FINAL, NULL, &votes->final_agg, bad_final );
    fd_bls_set_union( bad, bad, bad_final );
    if( FD_UNLIKELY( fd_bls_set_test( bad_final, rank ) ) ) return 0;
    if( FD_UNLIKELY( !final_verified || !fd_epoch_info_is_quorum( epoch_info, votes->final_stake ) ) ) return 1;
    fd_cert_final_t cert = { .slot = slot, .shred_version = shred_version, .stake = votes->final_stake, .agg = votes->final_agg };
    out_cert_events[ (*out_cert_event_cnt)++ ] = (fd_cert_t){ .kind = FD_CERT_KIND_FINAL, .final = cert };
  }

  return 1;
}

/* Resets self to an empty slot state.  self must be zeroed memory or a
   slot state. */

static void
slot_state_null( slot_state_t *  self,
                 slot_states_t * states ) {
  slot_votes_t * votes = &self->votes;
  for( ulong rank = fd_bls_set_const_iter_init( votes->notar_set );              !fd_bls_set_const_iter_done( rank ); rank = fd_bls_set_const_iter_next( votes->notar_set,              rank ) ) bls_sig_pool_idx_release( states->bls_sig_pool, votes->notar_sig_idx        [ rank ] );
  for( ulong rank = fd_bls_set_const_iter_init( votes->skip_agg.set );          !fd_bls_set_const_iter_done( rank ); rank = fd_bls_set_const_iter_next( votes->skip_agg.set,          rank ) ) bls_sig_pool_idx_release( states->bls_sig_pool, votes->skip_sig_idx         [ rank ] );
  for( ulong rank = fd_bls_set_const_iter_init( votes->skip_fallback_agg.set ); !fd_bls_set_const_iter_done( rank ); rank = fd_bls_set_const_iter_next( votes->skip_fallback_agg.set, rank ) ) bls_sig_pool_idx_release( states->bls_sig_pool, votes->skip_fallback_sig_idx[ rank ] );
  for( ulong rank = fd_bls_set_const_iter_init( votes->final_agg.set );         !fd_bls_set_const_iter_done( rank ); rank = fd_bls_set_const_iter_next( votes->final_agg.set,         rank ) ) bls_sig_pool_idx_release( states->bls_sig_pool, votes->final_sig_idx     [ rank ] );
  for( ulong rank=0UL; rank<FD_VOTOR_VAT_MAX; rank++ ) {
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) bls_sig_pool_idx_release( states->bls_sig_pool, votes->notar_fallback_sig_idx[ rank ][ j ] );
  }
  ulong notar = votes->notar_hash_stake_head;
  for( ulong i=0UL; i<votes->notar_hash_stake_cnt; i++ ) {
    ulong prev = vote_stake_pool_ele( states->notar_hash_stake_pool, notar )->prev;
    vote_stake_map_idx_remove( states->notar_hash_stake_map, &vote_stake_pool_ele( states->notar_hash_stake_pool, notar )->block_id, ULONG_MAX, states->notar_hash_stake_pool );
    vote_stake_pool_idx_release( states->notar_hash_stake_pool, notar );
    notar = prev;
  }
  votes->notar_hash_stake_cnt = 0UL;
  fd_bls_set_null( votes->notar_set );
  ulong nf_idx = votes->notar_fallback_hash_stake_head;
  for( ulong i=0UL; i<votes->notar_fallback_hash_stake_cnt; i++ ) {
    ulong prev = vote_stake_pool_ele( states->notar_fallback_hash_stake_pool, nf_idx )->prev;
    vote_stake_map_idx_remove( states->notar_fallback_hash_stake_map, &vote_stake_pool_ele( states->notar_fallback_hash_stake_pool, nf_idx )->block_id, ULONG_MAX, states->notar_fallback_hash_stake_pool );
    vote_stake_pool_idx_release( states->notar_fallback_hash_stake_pool, nf_idx );
    nf_idx = prev;
  }
  votes->notar_fallback_hash_stake_cnt = 0UL;
  fd_memset( votes->notar_fallback_sig_cnt, 0, sizeof(votes->notar_fallback_sig_cnt) );
  votes->skip_stake = 0UL;
  fd_bls_agg_null( &votes->skip_agg );
  votes->skip_fallback_stake = 0UL;
  fd_bls_agg_null( &votes->skip_fallback_agg );
  votes->final_stake = 0UL;
  fd_bls_agg_null( &votes->final_agg );
  votes->notar_or_skip_stake = 0UL;
  votes->top_notar_stake     = 0UL;
  fd_memset( &votes->top_notar_hash, 0, sizeof(fd_block_hash_t) );

  self->certs.notar.slot         = ULONG_MAX;
  self->certs.notar_fallback_cnt = 0UL;
  self->certs.skip.slot          = ULONG_MAX;
  self->certs.fast_final.slot = ULONG_MAX;
  self->certs.final.slot      = ULONG_MAX;

  self->parents_cnt                = 0UL;
  self->pending_safe_to_notar.cnt  = 0UL;
  self->verified_safe_to_notar.cnt = 0UL;
  self->sent_safe_to_notar.cnt     = 0UL;
  self->sent_safe_to_skip          = 0;
}

/* Replaces our rank own_rank (USHORT_MAX if unstaked). */

/* Definition 13. SlotState::add_cert */

static void
slot_state_add_cert( slot_state_t *    self,
                     fd_cert_t const * cert ) {
  switch( cert->kind ) {
  case FD_CERT_KIND_NOTAR: {
    self->certs.notar = cert->notar;
    break;
  }
  case FD_CERT_KIND_NOTAR_FALLBACK: {
    fd_cert_notar_fallback_t const * n = &cert->notar_fallback;
    if( FD_LIKELY( !slot_state_is_notar_fallback( self, &n->block_hash ) ) ) {
      FD_CHECK_CRIT( self->certs.notar_fallback_cnt<FD_VOTOR_NOTAR_FALLBACK_CERT_MAX, "consensus safety violation" ); /* Lemma 48 */
      self->certs.notar_fallback[ self->certs.notar_fallback_cnt++ ] = *n;
    }
    break;
  }
  case FD_CERT_KIND_SKIP: {
    self->certs.skip = cert->skip;
    break;
  }
  case FD_CERT_KIND_FAST_FINAL: {
    self->certs.fast_final = cert->fast_final;
    break;
  }
  case FD_CERT_KIND_FINAL: {
    self->certs.final = cert->final;
    break;
  }
  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }
}

/* Definition 12. SlotState::add_vote */

static int
slot_state_add_vote( slot_state_t *    self,
                     slot_states_t *   states,
                     fd_vote_t const * vote,
                     ulong             stake,
                     fd_cert_t *       out_cert_events,
                     ulong *           out_cert_event_cnt,
                     fd_block_id_t *   out_safe_to_notar,
                     ulong *           out_safe_to_notar_cnt,
                     ulong *           out_safe_to_skip,
                     ulong *           out_safe_to_skip_cnt,
                     fd_block_id_t *   out_repair_events,
                     ulong *           out_repair_event_cnt,
                     fd_bls_set_t *    bad ) {
  ulong slot = fd_vote_slot( vote );
  ulong rank = fd_vote_rank( vote );

  fd_bls_sig_t const * sig = fd_vote_sig( vote );

  FD_TEST( bls_sig_pool_free( states->bls_sig_pool ) );
  uint sig_idx = (uint)bls_sig_pool_idx_acquire( states->bls_sig_pool );
  bls_sig_pool_ele( states->bls_sig_pool, sig_idx )->sig = *sig;

  *out_cert_event_cnt = 0UL; *out_safe_to_notar_cnt = 0UL; *out_safe_to_skip_cnt = 0UL; *out_repair_event_cnt = 0UL; fd_bls_set_null( bad );
  self->shred_version = fd_vote_shred_version( vote );
  int err;
  switch( vote->kind ) {
  case FD_VOTE_KIND_NOTAR:
    self->votes.notar_sig_idx[ rank ] = sig_idx;
    fd_bls_set_insert( self->votes.notar_set, rank );
    err = count_notar_stake( self, states, &vote->notar, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case FD_VOTE_KIND_NOTAR_FALLBACK:
    FD_TEST( self->votes.notar_fallback_sig_cnt[ rank ]<FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX );
    self->votes.notar_fallback_sig_idx[ rank ][ self->votes.notar_fallback_sig_cnt[ rank ] ] = sig_idx;
    self->votes.notar_fallback_sig_cnt[ rank ]++;
    err = count_notar_fallback_stake( self, states, &vote->notar_fallback, stake, out_cert_events, out_cert_event_cnt, bad );
    break;
  case FD_VOTE_KIND_SKIP:
    self->votes.skip_sig_idx[ rank ] = sig_idx;
    self->votes.notar_or_skip_stake += stake;
    err = count_skip_stake( self, states, vote, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case FD_VOTE_KIND_SKIP_FALLBACK:
    self->votes.skip_fallback_sig_idx[ rank ] = sig_idx;
    err = count_skip_stake( self, states, vote, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case FD_VOTE_KIND_FINAL:
    self->votes.final_sig_idx[ rank ] = sig_idx;
    err = count_final_stake( self, states, &vote->final, stake, out_cert_events, out_cert_event_cnt, bad );
    break;
  default:
    FD_LOG_CRIT(( "unreachable" ));
  }

  if( FD_UNLIKELY( rank==self->own_rank ) ) {
    block_hash_set_t pending = self->pending_safe_to_notar;
    for( ulong i=0UL; i<pending.cnt; i++ ) {
      if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, &pending.hash[i] ) ) ) continue;
      switch( check_safe_to_notar( self, states, &pending.hash[i], bad ) ) {
      case SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR: out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = fd_block_id( slot, pending.hash[i].uc ); break;
      case SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
        ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( &out_repair_events[j].hash, &pending.hash[i], sizeof(fd_block_hash_t) ) ) ) break;
        if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = fd_block_id( slot, pending.hash[i].uc );
        break;
      }
      default: break;
      }
    }
  }

  return err;
}

/* Definition 16, SafeToNotar. SlotState::notify_parent_known */

static void
slot_state_notify_parent_known( slot_state_t *          self,
                                slot_states_t *         states,
                                fd_block_hash_t const * block_hash,
                                fd_bls_set_t *          bad ) {
  fd_bls_set_null( bad );
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( &self->parents[i].hash, block_hash, sizeof(fd_block_hash_t) ) ) ) return;
  }
  FD_TEST( self->parents_cnt < FD_VOTOR_EQVOC_MAX );
  parent_status_t * e = &self->parents[ self->parents_cnt++ ];
  memcpy( &e->hash, block_hash, sizeof(fd_block_hash_t) );
  e->kind = PARENT_STATUS_KNOWN;

  check_safe_to_notar( self, states, block_hash, bad );
}

/* Definition 16, SafeToNotar. SlotState::notify_parent_certified */

static int
slot_state_notify_parent_certified( slot_state_t *          self,
                                    slot_states_t *         states,
                                    fd_block_hash_t const * block_hash,
                                    fd_bls_set_t *          bad ) {
  fd_bls_set_null( bad );
  parent_status_t * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( &self->parents[i].hash, block_hash, sizeof(fd_block_hash_t) ) ) ) { parent = &self->parents[i]; break; }
  }
  FD_TEST( parent );
  parent->kind = PARENT_STATUS_CERTIFIED;

  if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) return 0;

  switch( check_safe_to_notar( self, states, block_hash, bad ) ) {
  case SAFE_TO_NOTAR_STATUS_MISSING_BLOCK:  return -1; /* unreachable: this block's parents entry was found above */
  case SAFE_TO_NOTAR_STATUS_AWAITING_VOTES: return  0;
  case SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:  return  1;
  default:                                  FD_LOG_CRIT(( "unreachable" ));
  }
}

/* SlotState::check_slashable_offence */

FD_FN_PURE static int
slot_state_check_slashable_offence( slot_state_t const *  self,
                                    slot_states_t const * states,
                                    fd_vote_t const *     vote ) {
  ulong voter = fd_vote_rank( vote );
  slot_votes_t const * votes = &self->votes;

  switch( vote->kind ) {
  case FD_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, voter ) ) ) {
      return SLASHABLE_OFFENCE_SKIP_AND_NOTARIZE;
    }
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) {
      if( FD_UNLIKELY( memcmp( &vote_stake_pool_ele_const( states->notar_hash_stake_pool, votes->notar_hash_stake_idx[ voter ] )->block_id.hash, &vote->notar.block_hash, sizeof(fd_block_hash_t) ) ) ) return SLASHABLE_OFFENCE_NOTAR_DIFFERENT_HASH;
    }
    break;
  }

  case FD_VOTE_KIND_NOTAR_FALLBACK:
    if( FD_UNLIKELY( fd_bls_set_test( votes->final_agg.set, voter ) ) ) {
      return SLASHABLE_OFFENCE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;

  case FD_VOTE_KIND_SKIP:
    if( FD_UNLIKELY( fd_bls_set_test( votes->final_agg.set, voter ) ) ) {
      return SLASHABLE_OFFENCE_SKIP_AND_FINALIZE;
    }
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) return SLASHABLE_OFFENCE_SKIP_AND_NOTARIZE;
    break;

  case FD_VOTE_KIND_SKIP_FALLBACK:
    if( FD_UNLIKELY( fd_bls_set_test( votes->final_agg.set, voter ) ) ) {
      return SLASHABLE_OFFENCE_SKIP_AND_FINALIZE;
    }
    break;

  case FD_VOTE_KIND_FINAL: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, voter ) || fd_bls_set_test( votes->skip_fallback_agg.set, voter ) ) ) {
      return SLASHABLE_OFFENCE_SKIP_AND_FINALIZE;
    }
    if( FD_UNLIKELY( votes->notar_fallback_sig_cnt[ voter ] ) ) {
      return SLASHABLE_OFFENCE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;
  }

  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return SLASHABLE_OFFENCE_NONE;
}

/* Definition 12. SlotState::should_ignore_vote */

FD_FN_PURE static int
slot_state_should_ignore_vote( slot_state_t const *  self,
                               slot_states_t const * states,
                               fd_vote_t const *     vote ) {
  ulong                    voter                          = fd_vote_rank( vote );
  slot_votes_t const *     votes                          = &self->votes;
  vote_stake_ele_t const * notar_hash_stake_pool          = states->notar_hash_stake_pool;
  vote_stake_ele_t const * notar_fallback_hash_stake_pool = states->notar_fallback_hash_stake_pool;
  switch( vote->kind ) {
  case FD_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) return 1;

    fd_block_hash_t const * hash = &vote->notar.block_hash;
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( !memcmp( &vote_stake_pool_ele_const( notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ voter ][ j ] )->block_id.hash, hash, sizeof(fd_block_hash_t) ) ) ) return 1;
    }
    return 0;
  }
  case FD_VOTE_KIND_NOTAR_FALLBACK: {
    if( FD_UNLIKELY( votes->notar_fallback_sig_cnt[ voter ]>=FD_VOTOR_NOTAR_FALLBACK_VOTE_MAX ) ) return 1;

    fd_block_hash_t const * hash = &vote->notar_fallback.block_hash;
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( !memcmp( &vote_stake_pool_ele_const( notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ voter ][ j ] )->block_id.hash, hash, sizeof(fd_block_hash_t) ) ) ) return 1;
    }

    return fd_bls_set_test( votes->notar_set, voter ) && !memcmp( &vote_stake_pool_ele_const( notar_hash_stake_pool, votes->notar_hash_stake_idx[ voter ] )->block_id.hash, hash, sizeof(fd_block_hash_t) );
  }
  case FD_VOTE_KIND_SKIP:
  case FD_VOTE_KIND_SKIP_FALLBACK:
    return fd_bls_set_test( votes->skip_agg.set, voter ) || fd_bls_set_test( votes->skip_fallback_agg.set, voter );
  case FD_VOTE_KIND_FINAL:
    return fd_bls_set_test( votes->final_agg.set, voter );
  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return 0;
}

/* Accessors for reward certs */

static fd_bls_agg_t *
slot_state_notar_reward_agg( slot_state_t const *  self,
                             slot_states_t const * states,
                             fd_bls_agg_t *        out ) {
  fd_epoch_info_t const * epoch_info = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  fd_block_id_t           key        = fd_block_id( self->slot, self->votes.top_notar_hash.uc );
  ulong                   top        = vote_stake_map_idx_query_const( states->notar_hash_stake_map, &key, ULONG_MAX, states->notar_hash_stake_pool );
  if( FD_UNLIKELY( top==ULONG_MAX ) ) return NULL;

  fd_bls_set_t set[ fd_bls_set_word_cnt ];
  fd_bls_set_null( set );
  for( ulong rank = fd_bls_set_const_iter_init( self->votes.notar_set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( self->votes.notar_set, rank ) ) {
    if( FD_LIKELY( self->votes.notar_hash_stake_idx[ rank ]==top ) ) fd_bls_set_insert( set, rank );
  }
  fd_bls_sig_t sigs[ FD_VOTOR_VAT_MAX ];
  slot_state_sigs( self, states, FD_VOTE_KIND_NOTAR, &key.hash, set, sigs );
  fd_bls_agg_null( out );
  fd_bls_agg_construct( out, epoch_info->pubkeys, sigs, set );
  return out;
}

FD_FN_PURE static fd_bls_agg_t const *
slot_state_skip_reward_agg( slot_state_t const * self ) {
  return fd_bls_set_is_null( self->votes.skip_agg.set ) ? NULL : &self->votes.skip_agg;
}

#define QUEUE_NAME pool_events
#define QUEUE_T    fd_votor_pool_event_t
#include "../../util/tmpl/fd_queue_dynamic.c"

/* repair_events are notifications that a block has reached SafeToNotar
   (or stronger) status.  It does not necessarily trigger actual repair
   requests if we already have the block... (that is the responsibility
   of the repair tile to answer).  */

#define QUEUE_NAME repair_events
#define QUEUE_T    fd_block_id_t
#include "../../util/tmpl/fd_queue_dynamic.c"

/* Protocol bounds (< 20% byzantine stake) on what burst adds push onto
   queues drained to empty before the next add:

   - IMPLICITLY_FINALIZED / SKIPPED: once per slot of the window
   - SAFE_TO_NOTAR of waiting children: 3 hashes per child slot (stake
     arithmetic), and correct nodes notar a child only at its parent's
     slot+1 or a window start, for each of up to burst certified
     parents
   - PARENT_READY: once per window start (ready flag), plus one per add
     moving the window
   - per add: 4 of CERT_CREATED, SAFE_TO_NOTAR and SAFE_TO_SKIP
   - repair: 4 block ids per add (3 created certs, 1 missing block) */

#define POOL_EVENT_MAX(slot_max,burst) ( (slot_max)                                                                             \
                                       + 3UL*( ((slot_max)+FD_VOTOR_SLOTS_PER_WINDOW-1UL)/FD_VOTOR_SLOTS_PER_WINDOW + (burst) ) \
                                       +     ( ((slot_max)+FD_VOTOR_SLOTS_PER_WINDOW-1UL)/FD_VOTOR_SLOTS_PER_WINDOW + (burst) ) \
                                       + 4UL*(burst) )
#define REPAIR_EVENT_MAX(burst)        ( 4UL*(burst) )

struct s2n_waiting_parent_cert_ele {
  fd_block_id_t parent;
  ulong         next;
  ulong         prev;
  fd_block_id_t child;
};
typedef struct s2n_waiting_parent_cert_ele s2n_waiting_parent_cert_ele_t;

#define POOL_NAME s2n_waiting_parent_cert_pool
#define POOL_T    s2n_waiting_parent_cert_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           s2n_waiting_parent_cert_map
#define MAP_ELE_T                          s2n_waiting_parent_cert_ele_t
#define MAP_KEY                            parent.slot
#define MAP_KEY_HASH(key,seed)             (fd_ulong_hash((*(key))^(seed)))
#define MAP_NEXT                           next
#define MAP_MULTI                          1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"


struct s2n_waiting_parent_cert {
  s2n_waiting_parent_cert_ele_t * pool;
  s2n_waiting_parent_cert_map_t * map;
};
typedef struct s2n_waiting_parent_cert s2n_waiting_parent_cert_t;

struct __attribute__((aligned(128UL))) fd_votor_pool {
  ulong slot_max;

  slot_states_t *             slot_states;
  fd_parent_ready_tracker_t * parent_ready_tracker;
  fd_finality_tracker_t *     finality_tracker;
  s2n_waiting_parent_cert_t * s2n_waiting_parent_cert;

  fd_votor_pool_event_t * pool_events;
  fd_block_id_t *         repair_events;

  struct {
    fd_parent_ready_t * parent_readys;
    fd_block_id_t *     implicitly_finalized;
    ulong *             implicitly_skipped;
  } scratch;
};

ulong
fd_votor_pool_align( void ) {
  return alignof(fd_votor_pool_t);
}

ulong
fd_votor_pool_footprint( ulong slot_max,
                         ulong burst ) {
  if( FD_UNLIKELY( slot_max<FD_VOTOR_SLOTS_PER_WINDOW+FD_VOTOR_REWARD_SLOT_DELTA || slot_max>UINT_MAX/(FD_VOTOR_VAT_MAX*FD_VOTOR_VOTES_PER_SLOT_MAX) ) ) return 0UL;

  ulong slot_chain_cnt  = slot_state_map_chain_cnt_est( slot_max );
  ulong sig_max         = slot_max*FD_VOTOR_VAT_MAX*FD_VOTOR_VOTES_PER_SLOT_MAX;
  ulong notar_max       = slot_max*FD_VOTOR_VAT_MAX;
  ulong notar_chain_cnt = vote_stake_map_chain_cnt_est( notar_max );
  ulong nf_max          = slot_max*NOTAR_FALLBACK_HASH_MAX;
  ulong nf_chain_cnt    = vote_stake_map_chain_cnt_est( nf_max );
  ulong s2n_max         = slot_max*FD_VOTOR_EQVOC_MAX;
  ulong s2n_chain_cnt   = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );
  ulong ready_max       = slot_max + FD_VOTOR_SLOTS_PER_WINDOW + 1UL; /* [root-FD_VOTOR_REWARD_SLOT_DELTA-FD_VOTOR_SLOTS_PER_WINDOW, root+slot_max-FD_VOTOR_REWARD_SLOT_DELTA] */
  ulong event_max       = POOL_EVENT_MAX( slot_max, burst );
  ulong repair_max      = REPAIR_EVENT_MAX( burst );

  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_votor_pool_t),             sizeof(fd_votor_pool_t)                                 ),
      alignof(slot_states_t),               sizeof(slot_states_t)                                   ),
      slot_state_pool_align(),              slot_state_pool_footprint( slot_max )                   ),
      slot_state_map_align(),               slot_state_map_footprint ( slot_chain_cnt )             ),
      bls_sig_pool_align(),                 bls_sig_pool_footprint( sig_max )                       ),
      vote_stake_pool_align(),              vote_stake_pool_footprint( notar_max )                  ),
      vote_stake_map_align(),               vote_stake_map_footprint ( notar_chain_cnt )            ),
      vote_stake_pool_align(),              vote_stake_pool_footprint( nf_max )                     ),
      vote_stake_map_align(),               vote_stake_map_footprint ( nf_chain_cnt )               ),
      fd_parent_ready_tracker_align(),      fd_parent_ready_tracker_footprint( ready_max )          ),
      fd_finality_tracker_align(),          fd_finality_tracker_footprint( slot_max )               ),
      alignof(s2n_waiting_parent_cert_t),   sizeof(s2n_waiting_parent_cert_t)                       ),
      s2n_waiting_parent_cert_pool_align(), s2n_waiting_parent_cert_pool_footprint( s2n_max )       ),
      s2n_waiting_parent_cert_map_align(),  s2n_waiting_parent_cert_map_footprint ( s2n_chain_cnt ) ),
      pool_events_align(),                  pool_events_footprint( event_max )                      ),
      repair_events_align(),                repair_events_footprint( repair_max )                   ),
      alignof(fd_parent_ready_t),           sizeof(fd_parent_ready_t) * slot_max                    ),
      alignof(fd_block_id_t),               sizeof(fd_block_id_t)     * slot_max                    ),
      alignof(ulong),                       sizeof(ulong)             * slot_max                    ),
    fd_votor_pool_align() );
}

void *
fd_votor_pool_new( void * mem,
                   ulong  slot_max,
                   ulong  burst,
                   ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_votor_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_votor_pool_footprint( slot_max, burst );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }
  fd_memset( mem, 0, footprint );

  ulong s2n_max         = slot_max*FD_VOTOR_EQVOC_MAX;
  ulong slot_chain_cnt  = slot_state_map_chain_cnt_est( slot_max );
  ulong sig_max         = slot_max*FD_VOTOR_VAT_MAX*FD_VOTOR_VOTES_PER_SLOT_MAX;
  ulong notar_max       = slot_max*FD_VOTOR_VAT_MAX;
  ulong notar_chain_cnt = vote_stake_map_chain_cnt_est( notar_max );
  ulong nf_max          = slot_max*NOTAR_FALLBACK_HASH_MAX;
  ulong nf_chain_cnt    = vote_stake_map_chain_cnt_est( nf_max );
  ulong s2n_chain_cnt   = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );
  ulong ready_max       = slot_max + FD_VOTOR_SLOTS_PER_WINDOW + 1UL;
  ulong event_max       = POOL_EVENT_MAX( slot_max, burst );
  ulong repair_max      = REPAIR_EVENT_MAX( burst );


  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_votor_pool_t * pool                         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_pool_t),             sizeof(fd_votor_pool_t)                                 );
  void *            slot_states                  = FD_SCRATCH_ALLOC_APPEND( l, alignof(slot_states_t),               sizeof(slot_states_t)                                   );
  void *            slot_state_pool              = FD_SCRATCH_ALLOC_APPEND( l, slot_state_pool_align(),              slot_state_pool_footprint( slot_max )                   );
  void *            slot_state_map               = FD_SCRATCH_ALLOC_APPEND( l, slot_state_map_align(),               slot_state_map_footprint ( slot_chain_cnt )             );
  void *            bls_sig_pool                 = FD_SCRATCH_ALLOC_APPEND( l, bls_sig_pool_align(),                 bls_sig_pool_footprint( sig_max )                       );
  void *            notar_hash_stake_pool        = FD_SCRATCH_ALLOC_APPEND( l, vote_stake_pool_align(),              vote_stake_pool_footprint( notar_max )                  );
  void *            notar_hash_stake_map         = FD_SCRATCH_ALLOC_APPEND( l, vote_stake_map_align(),               vote_stake_map_footprint ( notar_chain_cnt )            );
  void *            nf_hash_stake_pool           = FD_SCRATCH_ALLOC_APPEND( l, vote_stake_pool_align(),              vote_stake_pool_footprint( nf_max )                     );
  void *            nf_hash_stake_map            = FD_SCRATCH_ALLOC_APPEND( l, vote_stake_map_align(),               vote_stake_map_footprint ( nf_chain_cnt )               );
  void *            parent_ready_tracker         = FD_SCRATCH_ALLOC_APPEND( l, fd_parent_ready_tracker_align(),      fd_parent_ready_tracker_footprint( ready_max )          );
  void *            finality_tracker             = FD_SCRATCH_ALLOC_APPEND( l, fd_finality_tracker_align(),          fd_finality_tracker_footprint( slot_max )               );
  void *            s2n_waiting_parent_cert      = FD_SCRATCH_ALLOC_APPEND( l, alignof(s2n_waiting_parent_cert_t),   sizeof(s2n_waiting_parent_cert_t)                       );
  void *            s2n_waiting_parent_cert_pool = FD_SCRATCH_ALLOC_APPEND( l, s2n_waiting_parent_cert_pool_align(), s2n_waiting_parent_cert_pool_footprint( s2n_max )       );
  void *            s2n_waiting_parent_cert_map  = FD_SCRATCH_ALLOC_APPEND( l, s2n_waiting_parent_cert_map_align(),  s2n_waiting_parent_cert_map_footprint ( s2n_chain_cnt ) );
  void *            pool_events                  = FD_SCRATCH_ALLOC_APPEND( l, pool_events_align(),                  pool_events_footprint( event_max )                      );
  void *            repair_events                = FD_SCRATCH_ALLOC_APPEND( l, repair_events_align(),                repair_events_footprint( repair_max )                   );
  void *            parent_ready_scratch         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_parent_ready_t),           sizeof(fd_parent_ready_t) * slot_max                    );
  void *            implicitly_finalized_scratch = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_block_id_t),               sizeof(fd_block_id_t)     * slot_max                    );
  void *            implicitly_skipped_scratch   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                       sizeof(ulong)             * slot_max                    );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_votor_pool_align() ) == (ulong)mem + footprint );

  pool->slot_states                                 = (slot_states_t *)slot_states;
  pool->slot_states->pool                           = slot_state_pool_join( slot_state_pool_new( slot_state_pool,       slot_max              ) );
  pool->slot_states->map                            = slot_state_map_join ( slot_state_map_new ( slot_state_map,        slot_chain_cnt, seed  ) );
  pool->slot_states->bls_sig_pool                   = bls_sig_pool_join   ( bls_sig_pool_new   ( bls_sig_pool,          sig_max               ) );
  pool->slot_states->notar_hash_stake_pool          = vote_stake_pool_join( vote_stake_pool_new( notar_hash_stake_pool, notar_max             ) );
  pool->slot_states->notar_hash_stake_map           = vote_stake_map_join ( vote_stake_map_new ( notar_hash_stake_map,  notar_chain_cnt, seed ) );
  pool->slot_states->notar_fallback_hash_stake_pool = vote_stake_pool_join( vote_stake_pool_new( nf_hash_stake_pool,    nf_max                ) );
  pool->slot_states->notar_fallback_hash_stake_map  = vote_stake_map_join ( vote_stake_map_new ( nf_hash_stake_map,     nf_chain_cnt, seed    ) );
  pool->slot_states->prev_epoch_info                = NULL;
  pool->slot_states->prev_epoch_rank                = USHORT_MAX;
  pool->slot_states->prev_epoch_slot                = ULONG_MAX;
  pool->slot_states->curr_epoch_info                = NULL;
  pool->slot_states->curr_epoch_rank                = USHORT_MAX;
  pool->slot_states->curr_epoch_slot                = ULONG_MAX;
  pool->slot_states->next_epoch_info                = NULL;
  pool->slot_states->next_epoch_rank                = USHORT_MAX;
  pool->slot_states->next_epoch_slot                = ULONG_MAX;
  pool->slot_states->bls_verify_cnt                 = 0UL;

  pool->parent_ready_tracker = fd_parent_ready_tracker_join( fd_parent_ready_tracker_new( parent_ready_tracker, ready_max, seed ) );

  pool->finality_tracker = fd_finality_tracker_join( fd_finality_tracker_new( finality_tracker, slot_max, seed ) );

  pool->s2n_waiting_parent_cert       = (s2n_waiting_parent_cert_t *)s2n_waiting_parent_cert;
  pool->s2n_waiting_parent_cert->pool = s2n_waiting_parent_cert_pool_join( s2n_waiting_parent_cert_pool_new( s2n_waiting_parent_cert_pool, s2n_max                            ) );
  pool->s2n_waiting_parent_cert->map  = s2n_waiting_parent_cert_map_join ( s2n_waiting_parent_cert_map_new ( s2n_waiting_parent_cert_map,  s2n_chain_cnt, seed ) );

  pool->pool_events   = pool_events_join  ( pool_events_new  ( pool_events,   event_max  ) );
  pool->repair_events = repair_events_join( repair_events_new( repair_events, repair_max ) );

  pool->slot_max = slot_max;


  pool->scratch.parent_readys        = (fd_parent_ready_t *)parent_ready_scratch;
  pool->scratch.implicitly_finalized = (fd_block_id_t *)implicitly_finalized_scratch;
  pool->scratch.implicitly_skipped   = (ulong *)implicitly_skipped_scratch;


  return mem;
}

fd_votor_pool_t *
fd_votor_pool_join( void * mem ) {
  fd_votor_pool_t * pool = (fd_votor_pool_t *)mem;
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pool, fd_votor_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return pool;
}

void *
fd_votor_pool_leave( fd_votor_pool_t const * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL pool" ));
    return NULL;
  }
  return (void *)self;
}

void *
fd_votor_pool_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_votor_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return mem;
}

FD_FN_PURE fd_votor_pool_metrics_t
fd_votor_pool_metrics( fd_votor_pool_t const * self ) {
  return (fd_votor_pool_metrics_t){
    .slot_state_pool_used = slot_state_pool_used( self->slot_states->pool ),
    .slot_state_pool_free = slot_state_pool_free( self->slot_states->pool ),
    .finalized_slot       = fd_votor_pool_finalized_slot( self ),
    .pool_events_cnt      = pool_events_cnt( self->pool_events ),
    .bls_verify_cnt       = self->slot_states->bls_verify_cnt
  };
}

static void
pool_init( fd_votor_pool_t *     self,
           fd_block_id_t const * root ) {
  fd_finality_tracker_init( self->finality_tracker, root->slot );
  self->parent_ready_tracker->root = fd_ulong_sat_sub( root->slot, FD_VOTOR_REWARD_SLOT_DELTA+FD_VOTOR_SLOTS_PER_WINDOW );
}

static void
pool_push_parent_readys( fd_votor_pool_t * self,
                         ulong             ready_cnt ) {
  for( ulong i=0UL; i<ready_cnt; i++ ) {
    pool_events_push( self->pool_events, (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_PARENT_READY, .parent_ready = self->scratch.parent_readys[i] } );
  }
}

void
fd_votor_pool_from_snapshot( fd_votor_pool_t *     self,
                             fd_block_id_t const * root ) {
  pool_init( self, root );
  pool_push_parent_readys( self, fd_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, root, self->scratch.parent_readys ) );
}

void
fd_votor_pool_from_genesis( fd_votor_pool_t *     self,
                            fd_block_id_t const * genesis ) {
  pool_init( self, genesis );
  pool_push_parent_readys( self, fd_parent_ready_tracker_mark_root( self->parent_ready_tracker, genesis, self->scratch.parent_readys ) );
}

static slot_state_t const *
slot_state_query( fd_votor_pool_t const * self,
                  ulong                   slot ) {
  slot_state_ele_t const * ele = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  return ele ? &ele->slot_state : NULL;
}

static slot_state_t *
slot_state( fd_votor_pool_t * self,
            ulong             slot ) {
  slot_state_ele_t * ele = slot_state_map_ele_query( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  if( FD_LIKELY( ele ) ) return &ele->slot_state;

  slot_states_t *         states = self->slot_states;
  fd_epoch_info_t const * info   = fd_ptr_if  ( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if  ( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   rank   = fd_ulong_if( slot>=states->next_epoch_slot, states->next_epoch_rank, fd_ulong_if( slot>=states->curr_epoch_slot, states->curr_epoch_rank, states->prev_epoch_rank ) );

  FD_TEST( info );
  FD_TEST( slot_state_pool_free( self->slot_states->pool ) );

  ele       = slot_state_pool_ele_acquire( self->slot_states->pool );
  ele->slot = slot;
  slot_state_null( &ele->slot_state, states );
  ele->slot_state.slot     = slot;
  ele->slot_state.own_rank = rank;
  slot_state_map_ele_insert( self->slot_states->map, ele, self->slot_states->pool );
  return &ele->slot_state;
}

static inline fd_finalization_event_t
finalization_event_default( fd_votor_pool_t * self ) {
  return fd_finalization_event_default( self->scratch.implicitly_finalized, self->scratch.implicitly_skipped );
}

static void
handle_finalization( fd_votor_pool_t *               self,
                     fd_finalization_event_t const * event ) {
  FD_TEST( pool_events_avail( self->pool_events )>=event->implicitly_finalized_cnt+event->implicitly_skipped_cnt );
  for( ulong i=0UL; i<event->implicitly_finalized_cnt; i++ ) pool_events_push( self->pool_events, (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_IMPLICITLY_FINALIZED, .implicitly_finalized = event->implicitly_finalized[i] } );
  for( ulong i=0UL; i<event->implicitly_skipped_cnt;   i++ ) pool_events_push( self->pool_events, (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_IMPLICITLY_SKIPPED,   .implicitly_skipped   = event->implicitly_skipped  [i] } );
  ulong first_unpruned_slot = fd_finality_tracker_first_unpruned_slot( self->finality_tracker );
  ulong retained_slot       = fd_ulong_sat_sub( first_unpruned_slot, FD_VOTOR_REWARD_SLOT_DELTA );
  for( ulong slot = fd_ulong_sat_sub( self->parent_ready_tracker->root, FD_VOTOR_REWARD_SLOT_DELTA ); slot<retained_slot; slot++ ) {
    slot_state_ele_t * ele = slot_state_map_ele_remove( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    if( FD_LIKELY( ele ) ) {
      slot_state_null( &ele->slot_state, self->slot_states );
      slot_state_pool_ele_release( self->slot_states->pool, ele );
    }
    s2n_waiting_parent_cert_ele_t * waiter;
    while( (waiter = s2n_waiting_parent_cert_map_ele_remove( self->s2n_waiting_parent_cert->map, &slot, NULL, self->s2n_waiting_parent_cert->pool )) ) s2n_waiting_parent_cert_pool_ele_release( self->s2n_waiting_parent_cert->pool, waiter );
  }
  fd_parent_ready_tracker_prune( self->parent_ready_tracker, fd_ulong_sat_sub( first_unpruned_slot, FD_VOTOR_REWARD_SLOT_DELTA+FD_VOTOR_SLOTS_PER_WINDOW ) );
}

static void
add_verified_cert( fd_votor_pool_t * self,
                   fd_cert_t const * cert,
                   fd_bls_set_t *    bad ) {
  ulong slot = fd_cert_slot( cert );

  slot_state_add_cert( slot_state( self, slot ), cert );

  switch( cert->kind ) {
  case FD_CERT_KIND_FINAL: {
    fd_finalization_event_t finalization_event = finalization_event_default( self );
    fd_finality_tracker_mark_finalized( self->finality_tracker, slot, &finalization_event );
    handle_finalization( self, &finalization_event );
    break;
  }
  case FD_CERT_KIND_FAST_FINAL:
  case FD_CERT_KIND_NOTAR:
  case FD_CERT_KIND_NOTAR_FALLBACK: {
    fd_block_hash_t const * block_hash = fd_cert_block_hash( cert );
    fd_block_id_t           block_id   = fd_block_id( slot, block_hash->uc );
    if( FD_UNLIKELY( cert->kind==FD_CERT_KIND_FAST_FINAL ) ) {
      fd_finalization_event_t finalization_event = finalization_event_default( self );
      fd_finality_tracker_mark_fast_finalized( self->finality_tracker, &block_id, &finalization_event );
      handle_finalization( self, &finalization_event );
    }
    if( FD_LIKELY( cert->kind==FD_CERT_KIND_NOTAR ) ) {
      fd_finalization_event_t finalization_event = finalization_event_default( self );
      fd_finality_tracker_mark_notarized( self->finality_tracker, &block_id, &finalization_event );
      handle_finalization( self, &finalization_event );
    }

    slot_states_t *                 states = self->slot_states;
    s2n_waiting_parent_cert_ele_t * next;
    for( s2n_waiting_parent_cert_ele_t * child = s2n_waiting_parent_cert_map_ele_query( self->s2n_waiting_parent_cert->map, &slot, NULL, self->s2n_waiting_parent_cert->pool );
                                         child;
                                         child = next ) {
      next = (s2n_waiting_parent_cert_ele_t *)s2n_waiting_parent_cert_map_ele_next_const( child, NULL, self->s2n_waiting_parent_cert->pool );
      if( FD_LIKELY( !fd_block_id_eq( &child->parent, &block_id ) ) ) continue;
      fd_block_id_t child_id = child->child; /* copy before the release below */
      s2n_waiting_parent_cert_map_ele_remove_fast( self->s2n_waiting_parent_cert->map, child, self->s2n_waiting_parent_cert->pool );
      s2n_waiting_parent_cert_pool_ele_release( self->s2n_waiting_parent_cert->pool, child );

      slot_state_t * child_state = slot_state( self, child_id.slot );
      fd_bls_set_t   bad_child[ fd_bls_set_word_cnt ];
      int output = slot_state_notify_parent_certified( child_state, states, &child_id.hash, bad_child );
      if( FD_LIKELY( fd_ptr_if( child_id.slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( child_id.slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) )==fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) ) ) ) fd_bls_set_union( bad, bad, bad_child );
      switch( output ) {
      case -1: repair_events_push( self->repair_events, child_id ); break;
      case  0: break;
      case  1: pool_events_push( self->pool_events, (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = child_id } ); break;
      }
    }

    ulong ready_cnt = fd_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, &block_id, self->scratch.parent_readys );
    for( ulong i=0UL; i<ready_cnt; i++ ) {
      pool_events_push( self->pool_events, (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_PARENT_READY, .parent_ready = self->scratch.parent_readys[i] } );
    }

    repair_events_push( self->repair_events, block_id );
    break;
  }

  case FD_CERT_KIND_SKIP: {
    ulong ready_cnt = fd_parent_ready_tracker_mark_skipped( self->parent_ready_tracker, slot, self->scratch.parent_readys );
    for( ulong i=0UL; i<ready_cnt; i++ ) {
      pool_events_push( self->pool_events, (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_PARENT_READY, .parent_ready = self->scratch.parent_readys[i] } );
    }
    break;
  }

  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }

  fd_votor_pool_event_t event = { .kind = FD_VOTOR_POOL_EVENT_CERT_CREATED, .cert_created = *cert };
  pool_events_push( self->pool_events, event );
}

void
fd_votor_pool_advance_epoch( fd_votor_pool_t *       self,
                             fd_epoch_info_t const * epoch_info,
                             ulong                   epoch_rank,
                             ulong                   epoch_slot ) {
  slot_states_t * states = self->slot_states;
  if( FD_UNLIKELY( !states->curr_epoch_info ) ) {
    states->curr_epoch_info = epoch_info;
    states->curr_epoch_rank = epoch_rank;
    states->curr_epoch_slot = epoch_slot;
  } else if( FD_UNLIKELY( !states->next_epoch_info ) ) {
    states->next_epoch_info = epoch_info;
    states->next_epoch_rank = epoch_rank;
    states->next_epoch_slot = epoch_slot;
  } else {
    states->prev_epoch_info = states->curr_epoch_info;
    states->prev_epoch_slot = states->curr_epoch_slot;
    states->prev_epoch_rank = states->curr_epoch_rank;
    states->curr_epoch_info = states->next_epoch_info;
    states->curr_epoch_slot = states->next_epoch_slot;
    states->curr_epoch_rank = states->next_epoch_rank;
    states->next_epoch_info = epoch_info;
    states->next_epoch_rank = epoch_rank;
    states->next_epoch_slot = epoch_slot;
  }
}

void
fd_votor_pool_update_own_rank( fd_votor_pool_t * self,
                               ulong             epoch_slot,
                               ulong             epoch_rank ) {
  slot_states_t * states = self->slot_states;
  if     ( epoch_slot==states->prev_epoch_slot ) states->prev_epoch_rank = epoch_rank;
  else if( epoch_slot==states->curr_epoch_slot ) states->curr_epoch_rank = epoch_rank;
  else if( epoch_slot==states->next_epoch_slot ) states->next_epoch_rank = epoch_rank;
  else FD_LOG_CRIT(( "no epoch starts at slot %lu", epoch_slot ));

  slot_state_map_t * map  = self->slot_states->map;
  slot_state_ele_t * pool = self->slot_states->pool;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
                                   !slot_state_map_iter_done( iter, map, pool );
                             iter = slot_state_map_iter_next( iter, map, pool ) ) {
    slot_state_t * slot_state = &slot_state_map_iter_ele( iter, map, pool )->slot_state;
    ulong          slot       = slot_state->slot;
    ulong          rank       = fd_ulong_if( slot>=states->next_epoch_slot, states->next_epoch_rank, fd_ulong_if( slot>=states->curr_epoch_slot, states->curr_epoch_rank, states->prev_epoch_rank ) );

    slot_state->own_rank = rank;
  }
}

int
fd_votor_pool_add_block( fd_votor_pool_t *     self,
                         fd_block_id_t const * block_id,
                         fd_block_id_t const * parent_id,
                         fd_bls_set_t *        bad ) {
  fd_bls_set_null( bad );

  ulong                   slot        = block_id->slot;
  fd_block_hash_t const * block_hash  = &block_id->hash;
  ulong                   parent_slot = parent_id->slot;
  fd_block_hash_t const * parent_hash = &parent_id->hash;

  ulong slot_far_in_future = fd_finality_tracker_first_unpruned_slot( self->finality_tracker ) + self->slot_max - FD_VOTOR_REWARD_SLOT_DELTA;
  if( FD_UNLIKELY( slot<fd_finality_tracker_first_unpruned_slot( self->finality_tracker ) ) ) return FD_VOTOR_POOL_ERR_SLOT_TOO_OLD;
  if( FD_UNLIKELY( slot>=slot_far_in_future                                            ) ) return FD_VOTOR_POOL_ERR_SLOT_TOO_NEW;
  slot_states_t * states = self->slot_states;
  if( FD_UNLIKELY( !fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) ) ) ) return fd_int_if( slot<states->curr_epoch_slot, FD_VOTOR_POOL_ERR_SLOT_TOO_OLD, FD_VOTOR_POOL_ERR_SLOT_TOO_NEW );

  fd_finalization_event_t finalization_event = finalization_event_default( self );
  fd_finality_tracker_add_parent( self->finality_tracker, block_id, parent_id, &finalization_event );
  handle_finalization( self, &finalization_event );
  if( FD_UNLIKELY( slot<fd_ulong_sat_sub( fd_finality_tracker_first_unpruned_slot( self->finality_tracker ), FD_VOTOR_REWARD_SLOT_DELTA ) ) ) return FD_VOTOR_POOL_SUCCESS; /* pruned by the parent link */

  slot_state_notify_parent_known( slot_state( self, slot ), states, block_hash, bad );
  slot_state_ele_t * parent_state_ = slot_state_map_ele_query( self->slot_states->map, &parent_slot, NULL, self->slot_states->pool );
  slot_state_t *     parent_state  = parent_state_ ? &parent_state_->slot_state : NULL;
  if( FD_LIKELY( parent_state && slot_state_is_notar_fallback_or_stronger( parent_state, parent_hash ) ) ) {
    fd_bls_set_t bad_certified[ fd_bls_set_word_cnt ];
    int output = slot_state_notify_parent_certified( slot_state( self, slot ), states, block_hash, bad_certified );
    fd_bls_set_union( bad, bad, bad_certified );
    switch( output ) {
    case -1: repair_events_push( self->repair_events, *block_id ); return FD_VOTOR_POOL_SUCCESS;
    case  0: return FD_VOTOR_POOL_SUCCESS;
    case  1: pool_events_push( self->pool_events, (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = *block_id } ); return FD_VOTOR_POOL_SUCCESS;
    }
  }

  if( FD_UNLIKELY( parent_slot<fd_ulong_sat_sub( fd_finality_tracker_first_unpruned_slot( self->finality_tracker ), FD_VOTOR_REWARD_SLOT_DELTA ) ) ) return FD_VOTOR_POOL_SUCCESS; /* the parent can no longer certify */
  for( s2n_waiting_parent_cert_ele_t const * ele = s2n_waiting_parent_cert_map_ele_query_const( self->s2n_waiting_parent_cert->map, &parent_slot, NULL, self->s2n_waiting_parent_cert->pool );
                                             ele;
                                             ele = s2n_waiting_parent_cert_map_ele_next_const( ele, NULL, self->s2n_waiting_parent_cert->pool ) ) {
    if( FD_UNLIKELY( fd_block_id_eq( &ele->child, block_id ) ) ) return FD_VOTOR_POOL_SUCCESS;
  }
  FD_TEST( s2n_waiting_parent_cert_pool_free( self->s2n_waiting_parent_cert->pool ) );
  s2n_waiting_parent_cert_ele_t * ele = s2n_waiting_parent_cert_pool_ele_acquire( self->s2n_waiting_parent_cert->pool );
  ele->parent = *parent_id;
  ele->child  = *block_id;
  s2n_waiting_parent_cert_map_ele_insert( self->s2n_waiting_parent_cert->map, ele, self->s2n_waiting_parent_cert->pool );

  return FD_VOTOR_POOL_SUCCESS;
}

int
fd_votor_pool_add_cert( fd_votor_pool_t * self,
                        fd_cert_t const * cert,
                        int               verified,
                        fd_bls_set_t *    bad ) {
  ulong slot = fd_cert_slot( cert );
  fd_bls_set_null( bad );

  ulong slot_far_in_future = fd_finality_tracker_first_unpruned_slot( self->finality_tracker ) + self->slot_max - FD_VOTOR_REWARD_SLOT_DELTA;
  if( FD_UNLIKELY( slot<fd_finality_tracker_first_unpruned_slot( self->finality_tracker ) ) ) return FD_VOTOR_POOL_ERR_SLOT_TOO_OLD;
  if( FD_UNLIKELY( slot>=slot_far_in_future                                            ) ) return FD_VOTOR_POOL_ERR_SLOT_TOO_NEW;

  slot_states_t const *   states     = self->slot_states;
  fd_epoch_info_t const * epoch_info = fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  if( FD_UNLIKELY( !epoch_info ) ) return fd_int_if( slot<states->curr_epoch_slot, FD_VOTOR_POOL_ERR_SLOT_TOO_OLD, FD_VOTOR_POOL_ERR_SLOT_TOO_NEW );

  slot_state_t * state = slot_state( self, slot );
  int duplicate = 0;
  switch( cert->kind ) {
  case FD_CERT_KIND_FINAL:          duplicate = state->certs.final.slot!=ULONG_MAX;                                break;
  case FD_CERT_KIND_FAST_FINAL:     duplicate = state->certs.fast_final.slot!=ULONG_MAX;                           break;
  case FD_CERT_KIND_NOTAR:          duplicate = state->certs.notar.slot!=ULONG_MAX;                                break;
  case FD_CERT_KIND_NOTAR_FALLBACK: duplicate = slot_state_is_notar_fallback( state, fd_cert_block_hash( cert ) ); break;
  case FD_CERT_KIND_SKIP:           duplicate = state->certs.skip.slot!=ULONG_MAX;                                 break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
  if( FD_UNLIKELY( duplicate ) ) return FD_VOTOR_POOL_ERR_DUPLICATE;

  int err = FD_CERT_VERIFY_SUCCESS;
  if( FD_LIKELY( !verified ) ) err = fd_cert_verify( cert, epoch_info );
  self->slot_states->bls_verify_cnt += (ulong)( !verified && err!=FD_CERT_VERIFY_ERR_THRESHOLD );
  if( FD_UNLIKELY( err ) ) return FD_VOTOR_POOL_ERR_CERT_VERIFY;

  switch( cert->kind ) { /* a skip cert excludes finalization certs, Lemmas 23 and 28 */
  case FD_CERT_KIND_FINAL:
  case FD_CERT_KIND_FAST_FINAL:     FD_CHECK_CRIT( state->certs.skip.slot==ULONG_MAX, "consensus safety violation" );                                                   break;
  case FD_CERT_KIND_NOTAR:
  case FD_CERT_KIND_NOTAR_FALLBACK:                                                                                                                                     break;
  case FD_CERT_KIND_SKIP:           FD_CHECK_CRIT( state->certs.final.slot==ULONG_MAX && state->certs.fast_final.slot==ULONG_MAX, "consensus safety violation" ); break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }

  add_verified_cert( self, cert, bad );
  return FD_VOTOR_POOL_SUCCESS;
}

int
fd_votor_pool_add_vote( fd_votor_pool_t * self,
                        fd_vote_t const * vote,
                        int               verified,
                        fd_bls_set_t *    bad,
                        uchar *           quorum_reached ) {
  ulong slot = fd_vote_slot( vote );
  fd_bls_set_null( bad );
  *quorum_reached = 0;

  ulong first_unpruned_slot = fd_finality_tracker_first_unpruned_slot( self->finality_tracker );
  ulong retained_slot       = fd_ulong_sat_sub( first_unpruned_slot, FD_VOTOR_REWARD_SLOT_DELTA );
  ulong slot_far_in_future  = first_unpruned_slot + self->slot_max - FD_VOTOR_REWARD_SLOT_DELTA;
  if( FD_UNLIKELY( slot<retained_slot       ) ) return FD_VOTOR_POOL_ERR_SLOT_TOO_OLD;
  if( FD_UNLIKELY( slot>=slot_far_in_future ) ) return FD_VOTOR_POOL_ERR_SLOT_TOO_NEW;
  slot_states_t *         states     = self->slot_states;
  fd_epoch_info_t const * epoch_info = fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  if( FD_UNLIKELY( !epoch_info ) ) return fd_int_if( slot<states->curr_epoch_slot, FD_VOTOR_POOL_ERR_SLOT_TOO_OLD, FD_VOTOR_POOL_ERR_SLOT_TOO_NEW );

  ulong          voter       = fd_vote_rank( vote );
  slot_state_t * slot_state_ = slot_state( self, slot );
  ulong          voter_stake = fd_epoch_info_validator( epoch_info, voter )->stake;

  if       ( FD_UNLIKELY( slot_state_check_slashable_offence( slot_state_, states, vote )!=SLASHABLE_OFFENCE_NONE ) ) {
    return FD_VOTOR_POOL_ERR_SLASHABLE;
  } else if( FD_UNLIKELY( slot_state_should_ignore_vote( slot_state_, states, vote ) ) ) {
    return FD_VOTOR_POOL_ERR_DUPLICATE;
  }
  if( FD_UNLIKELY( !verified && !fd_bls_sig_validate( fd_vote_sig( vote ) ) ) ) return FD_VOTOR_POOL_ERR_VOTE_VERIFY;

  fd_cert_t     cert_events  [ SLOT_STATE_OUT_CERT_MAX   ]; ulong cert_event_cnt;
  fd_block_id_t safe_to_notar[ SLOT_STATE_OUT_EVENT_MAX  ]; ulong safe_to_notar_cnt;
  ulong         safe_to_skip [ SLOT_STATE_OUT_EVENT_MAX  ]; ulong safe_to_skip_cnt;
  fd_block_id_t repair_events[ SLOT_STATE_OUT_REPAIR_MAX ]; ulong repair_event_cnt;
  slot_state_add_vote( slot_state_, states, vote, voter_stake, cert_events, &cert_event_cnt, safe_to_notar, &safe_to_notar_cnt, safe_to_skip, &safe_to_skip_cnt, repair_events, &repair_event_cnt, bad );

  for( ulong i=0UL; i<cert_event_cnt;    i++ ) { add_verified_cert( self, &cert_events[i], bad ); *quorum_reached = fd_uchar_set_bit( *quorum_reached, (int)cert_events[i].kind ); }
  for( ulong i=0UL; i<safe_to_notar_cnt; i++ ) { pool_events_push  ( self->pool_events,   (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = safe_to_notar[i] } ); *quorum_reached = fd_uchar_set_bit( *quorum_reached, FD_VOTOR_POOL_QUORUM_REACHED_SAFE_TO_NOTAR ); }
  for( ulong i=0UL; i<safe_to_skip_cnt;  i++ ) { pool_events_push  ( self->pool_events,   (fd_votor_pool_event_t){ .kind = FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP,  .safe_to_skip  = safe_to_skip [i] } ); *quorum_reached = fd_uchar_set_bit( *quorum_reached, FD_VOTOR_POOL_QUORUM_REACHED_SAFE_TO_SKIP  ); }
  for( ulong i=0UL; i<repair_event_cnt;  i++ ) { repair_events_push( self->repair_events, repair_events[i] ); }
  return FD_VOTOR_POOL_SUCCESS;
}

fd_block_hash_t const *
fd_votor_pool_agg_rewards( fd_votor_pool_t * self,
                           ulong             slot,
                           fd_bls_agg_t *    notar,
                           fd_bls_agg_t *    skip,
                           fd_bls_set_t *    bad ) {
  fd_bls_agg_null( notar );
  fd_bls_agg_null( skip );
  fd_bls_set_null( bad );
  slot_state_t const * state = slot_state_query( self, slot );
  if( FD_UNLIKELY( !state ) ) return NULL;

  slot_states_t *         states     = self->slot_states;
  fd_epoch_info_t const * epoch_info = fd_ptr_if( slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  fd_block_hash_t const * hash       = NULL;
  fd_bls_sig_t            sigs    [ FD_VOTOR_VAT_MAX        ];
  fd_bls_set_t            skip_bad[ fd_bls_set_word_cnt     ];
  uchar                   msg     [ FD_VOTE_SIGNING_SER_MAX ];
  ulong                   msg_sz;

  if( FD_LIKELY( slot_state_notar_reward_agg( state, states, notar ) ) ) {
    hash   = &state->votes.top_notar_hash;
    slot_state_sigs( state, states, FD_VOTE_KIND_NOTAR, hash, notar->set, sigs );
    msg_sz = fd_vote_signing_ser( FD_VOTE_KIND_NOTAR, slot, hash, state->shred_version, msg );
    states->bls_verify_cnt++;
    if( FD_UNLIKELY( fd_bls_agg_verify_subtract( notar, msg, msg_sz, epoch_info->pubkeys, sigs, bad ) ) ) { fd_bls_agg_null( notar ); hash = NULL; }
  }

  fd_bls_agg_t const * skip_agg = slot_state_skip_reward_agg( state );
  if( FD_LIKELY( skip_agg ) ) {
    *skip  = *skip_agg;
    slot_state_sigs( state, states, FD_VOTE_KIND_SKIP, NULL, skip->set, sigs );
    msg_sz = fd_vote_signing_ser( FD_VOTE_KIND_SKIP, slot, NULL, state->shred_version, msg );
    states->bls_verify_cnt++;
    if( FD_UNLIKELY( fd_bls_agg_verify_subtract( skip, msg, msg_sz, epoch_info->pubkeys, sigs, skip_bad ) ) ) fd_bls_agg_null( skip );
    fd_bls_set_union( bad, bad, skip_bad );
  }
  return hash;
}

fd_cert_final_t *
fd_votor_pool_final_cert( fd_votor_pool_t const * self,
                          ulong                   slot,
                          fd_cert_final_t *       out ) {
  slot_state_t const * state = slot_state_query( self, slot );
  if( FD_UNLIKELY( !state || state->certs.final.slot==ULONG_MAX ) ) return NULL;
  *out = state->certs.final;
  return out;
}

fd_cert_notar_t *
fd_votor_pool_notar_cert( fd_votor_pool_t const * self,
                          ulong                   slot,
                          fd_cert_notar_t *       out ) {
  slot_state_t const * state = slot_state_query( self, slot );
  if( FD_UNLIKELY( !state || state->certs.notar.slot==ULONG_MAX ) ) return NULL;
  *out = state->certs.notar;
  return out;
}

fd_votor_pool_standstill_iter_t *
fd_votor_pool_standstill_iter_init( fd_votor_pool_standstill_iter_t * iter,
                                    fd_votor_pool_t const *           self ) {
  iter->finalized = fd_votor_pool_finalized_slot( self );
  iter->slot      = iter->finalized;
  iter->idx       = 0UL;
  return fd_votor_pool_standstill_iter_next( iter, self );
}

fd_votor_pool_standstill_iter_t *
fd_votor_pool_standstill_iter_next( fd_votor_pool_standstill_iter_t * iter,
                                    fd_votor_pool_t const *           self ) {
  ulong slot_far_in_future = fd_finality_tracker_first_unpruned_slot( self->finality_tracker ) + self->slot_max - FD_VOTOR_REWARD_SLOT_DELTA;
  for( ; iter->slot<slot_far_in_future; iter->slot++, iter->idx = 0UL ) {
    slot_state_ele_t const * slot_state_ = slot_state_map_ele_query_const( self->slot_states->map, &iter->slot, NULL, self->slot_states->pool );
    if( FD_UNLIKELY( !slot_state_ ) ) continue;

    slot_certs_t const * certs         = &slot_state_->slot_state.certs;
    slot_votes_t const * votes         = &slot_state_->slot_state.votes;
    ulong                slot          = slot_state_->slot_state.slot;
    ulong                own_rank      = slot_state_->slot_state.own_rank;
    ushort               shred_version = slot_state_->slot_state.shred_version;
    ulong                idx           = iter->idx;
    int                  finalized     = slot==iter->finalized;
    int                  fast_final    = certs->fast_final.slot!=ULONG_MAX;
    int                  final         = certs->final.slot!=ULONG_MAX && ( !finalized || ( !fast_final && certs->notar.slot!=ULONG_MAX ) );
    int                  notar         = certs->notar.slot   !=ULONG_MAX && ( !finalized || final );
    ulong                nf_cert       = fd_ulong_max( idx, STANDSTILL_NOTAR_FALLBACK      ) - STANDSTILL_NOTAR_FALLBACK;
    ulong                nf_vote       = fd_ulong_max( idx, STANDSTILL_NOTAR_FALLBACK_VOTE ) - STANDSTILL_NOTAR_FALLBACK_VOTE;

    iter->is_vote = 0;
    if( FD_UNLIKELY( idx<=STANDSTILL_FINAL      && final      ) ) { iter->idx = STANDSTILL_FINAL+1UL;      iter->cert = (fd_cert_t){ .kind = FD_CERT_KIND_FINAL,      .final      = certs->final      }; return iter; }
    if( FD_UNLIKELY( idx<=STANDSTILL_FAST_FINAL && fast_final ) ) { iter->idx = STANDSTILL_FAST_FINAL+1UL; iter->cert = (fd_cert_t){ .kind = FD_CERT_KIND_FAST_FINAL, .fast_final = certs->fast_final }; return iter; }
    if( FD_LIKELY  ( idx<=STANDSTILL_NOTAR      && notar      ) ) { iter->idx = STANDSTILL_NOTAR+1UL;      iter->cert = (fd_cert_t){ .kind = FD_CERT_KIND_NOTAR,      .notar      = certs->notar         }; return iter; }
    if( FD_UNLIKELY( finalized ) ) continue;
    if( FD_UNLIKELY( nf_cert<certs->notar_fallback_cnt ) ) { iter->idx = STANDSTILL_NOTAR_FALLBACK+nf_cert+1UL; iter->cert = (fd_cert_t){ .kind = FD_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = certs->notar_fallback[ nf_cert ] }; return iter; }
    if( FD_UNLIKELY( idx<=STANDSTILL_SKIP && certs->skip.slot!=ULONG_MAX ) ) { iter->idx = STANDSTILL_SKIP+1UL; iter->cert = (fd_cert_t){ .kind = FD_CERT_KIND_SKIP, .skip = certs->skip }; return iter; }

    if( FD_UNLIKELY( own_rank==USHORT_MAX ) ) continue; /* unstaked */
    iter->is_vote = 1;
    if( FD_UNLIKELY( idx<=STANDSTILL_NOTAR_VOTE && fd_bls_set_test( votes->notar_set, own_rank ) ) ) {
      iter->idx  = STANDSTILL_NOTAR_VOTE+1UL;
      iter->vote = (fd_vote_t){ .kind = FD_VOTE_KIND_NOTAR, .notar = { .slot = slot, .sig = bls_sig_pool_ele_const( self->slot_states->bls_sig_pool, votes->notar_sig_idx[ own_rank ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } };
      memcpy( &iter->vote.notar.block_hash, &vote_stake_pool_ele_const( self->slot_states->notar_hash_stake_pool, votes->notar_hash_stake_idx[ own_rank ] )->block_id.hash, sizeof(fd_block_hash_t) );
      return iter;
    }
    if( FD_LIKELY  ( idx<=STANDSTILL_FINAL_VOTE && fd_bls_set_test( votes->final_agg.set, own_rank ) ) ) { iter->idx = STANDSTILL_FINAL_VOTE+1UL; iter->vote = (fd_vote_t){ .kind = FD_VOTE_KIND_FINAL, .final = { .slot = slot, .sig = bls_sig_pool_ele_const( self->slot_states->bls_sig_pool, votes->final_sig_idx[ own_rank ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } }; return iter; }
    if( FD_UNLIKELY( idx<=STANDSTILL_SKIP_VOTE  && fd_bls_set_test( votes->skip_agg.set,  own_rank ) ) ) { iter->idx = STANDSTILL_SKIP_VOTE+1UL;  iter->vote = (fd_vote_t){ .kind = FD_VOTE_KIND_SKIP,  .skip  = { .slot = slot, .sig = bls_sig_pool_ele_const( self->slot_states->bls_sig_pool, votes->skip_sig_idx [ own_rank ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } }; return iter; }
    if( FD_UNLIKELY( nf_vote<votes->notar_fallback_sig_cnt[ own_rank ] ) ) {
      iter->idx  = STANDSTILL_NOTAR_FALLBACK_VOTE+nf_vote+1UL;
      iter->vote = (fd_vote_t){ .kind = FD_VOTE_KIND_NOTAR_FALLBACK, .notar_fallback = { .slot = slot, .sig = bls_sig_pool_ele_const( self->slot_states->bls_sig_pool, votes->notar_fallback_sig_idx[ own_rank ][ nf_vote ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } };
      memcpy( &iter->vote.notar_fallback.block_hash, &vote_stake_pool_ele_const( self->slot_states->notar_fallback_hash_stake_pool, votes->notar_fallback_hash_stake_idx[ own_rank ][ nf_vote ] )->block_id.hash, sizeof(fd_block_hash_t) );
      return iter;
    }
    if( FD_UNLIKELY( idx<=STANDSTILL_SKIP_FALLBACK_VOTE && fd_bls_set_test( votes->skip_fallback_agg.set, own_rank ) ) ) { iter->idx = STANDSTILL_SKIP_FALLBACK_VOTE+1UL; iter->vote = (fd_vote_t){ .kind = FD_VOTE_KIND_SKIP_FALLBACK, .skip_fallback = { .slot = slot, .sig = bls_sig_pool_ele_const( self->slot_states->bls_sig_pool, votes->skip_fallback_sig_idx[ own_rank ] )->sig, .rank = (ushort)own_rank, .shred_version = shred_version } }; return iter; }
  }
  iter->slot = ULONG_MAX;
  return iter;
}

FD_FN_PURE int
fd_votor_pool_standstill_iter_done( fd_votor_pool_standstill_iter_t const * iter ) {
  return iter->slot==ULONG_MAX;
}

FD_FN_PURE ulong
fd_votor_pool_finalized_slot( fd_votor_pool_t const * self ) {
  return fd_finality_tracker_highest_finalized_slot( self->finality_tracker );
}

FD_FN_PURE ulong
fd_votor_pool_highest_parent_ready( fd_votor_pool_t const * self ) {
  return self->parent_ready_tracker->highest_ready;
}

FD_FN_PURE fd_block_hash_t const *
fd_votor_pool_finalized_block_hash( fd_votor_pool_t const * self ) {
  return fd_finality_tracker_highest_finalized_block_hash( self->finality_tracker );
}

ulong
fd_votor_pool_parents_ready( fd_votor_pool_t const * self,
                             ulong                   slot,
                             fd_block_id_t *         out,
                             ulong                   out_max ) {
  return fd_parent_ready_tracker_parents_ready( self->parent_ready_tracker, slot, out, out_max );
}

FD_FN_PURE fd_block_id_t
fd_votor_pool_wait_for_parent_ready( fd_votor_pool_t const * self,
                                     ulong                   slot ) {
  return fd_parent_ready_tracker_wait_for_parent_ready( self->parent_ready_tracker, slot );
}

int
fd_votor_pool_poll_pool_event( fd_votor_pool_t *       self,
                               fd_votor_pool_event_t * event ) {
  if( FD_LIKELY( pool_events_empty( self->pool_events ) ) ) return 0;
  *event = pool_events_pop( self->pool_events );
  if( FD_LIKELY( event->kind!=FD_VOTOR_POOL_EVENT_PARENT_READY ) ) return 1;
  fd_parent_ready_state_t * state = fd_parent_ready_state_map_ele_query( self->parent_ready_tracker->states.map, &event->parent_ready.slot, NULL, self->parent_ready_tracker->states.pool );
  if( FD_LIKELY( state ) ) state->ready = 0; /* NULL if pruned while queued */
  return 1;
}

int
fd_votor_pool_poll_repair_event( fd_votor_pool_t * self,
                                 fd_block_id_t *   block ) {
  if( FD_LIKELY( repair_events_empty( self->repair_events ) ) ) return 0;
  *block = repair_events_pop( self->repair_events );
  return 1;
}
