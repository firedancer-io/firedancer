#include "ag_slot_state.h"

/* voted_stakes.notar / notar_fallback: BTreeMap<BlockHash, Stake>.  A
   bounded (hash, stake) array with linear scan, sized for one distinct hash
   per validator. */

struct hashstake {
  fd_hash_t hash;
  ulong     stake;
};
typedef struct hashstake hashstake_t;

struct stake_map {
  ulong         cnt;
  ulong         max;
  hashstake_t * ele; /* [ validator_max ] */
};
typedef struct stake_map stake_map_t;

/* parents: BTreeMap<BlockHash, ParentStatus> */

struct parent_status {
  fd_hash_t hash;
  ulong     next;
  int       kind; /* AG_PARENT_STATUS_* */
};
typedef struct parent_status parent_status_t;

#define POOL_NAME parents_pool
#define POOL_T    parent_status_t
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               parents_map
#define MAP_ELE_T              parent_status_t
#define MAP_KEY                hash
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

/* pending_safe_to_notar / sent_safe_to_notar: BTreeSet<BlockHash>.  A
   bounded hash array with linear scan: membership requires the hash to have
   reached the weakest notar quorum, so only a handful of distinct hashes
   ever qualify per slot. */

#define AG_SLOT_STATE_SET_MAX (8UL)

struct set {
  ulong     cnt;
  fd_hash_t hash[ AG_SLOT_STATE_SET_MAX ];
};
typedef struct set set_t;

typedef parent_status_t parents_pool_t;

/* SlotVotes (slot_state.rs), stored as running BLS aggregates instead of
   individual votes (the PERF note in slot_state.rs): one incrementally
   built aggregate per vote kind whose signer bitmask is also the presence
   set.  notar / notar_fallback sign (slot, hash), so those two kinds keep
   one aggregate per block hash (bounded like the voted_stakes maps).  own
   retains this validator's individual votes for standstill re-broadcast
   (Rust reads votes[own_id]); an own vote is present iff own_id is set in
   the corresponding aggregate's bitmask. */

struct hashagg {
  fd_hash_t   hash;
  ag_aggsig_t agg;
};
typedef struct hashagg hashagg_t;

struct agg_map {
  ulong       cnt;
  ulong       max;
  hashagg_t * ele; /* [ validator_max ] */
};
typedef struct agg_map agg_map_t;

struct own_votes {
  ag_notar_vote_t          notar;
  ag_notar_fallback_vote_t notar_fallback[ AG_SLOT_STATE_SET_MAX ];
  ulong                    notar_fallback_cnt;
  ag_skip_vote_t           skip;
  ag_skip_fallback_vote_t  skip_fallback;
  ag_final_vote_t          finalize;
};
typedef struct own_votes own_votes_t;

struct slot_votes {
  agg_map_t   notar;
  agg_map_t   notar_fallback;
  ag_aggsig_t skip;
  ag_aggsig_t skip_fallback;
  ag_aggsig_t finalize;
  own_votes_t own;
};
typedef struct slot_votes slot_votes_t;

/* SlotVotedStake (slot_state.rs). */

struct slot_voted_stake {
  stake_map_t notar;          /* BTreeMap<BlockHash, Stake> */
  stake_map_t notar_fallback; /* BTreeMap<BlockHash, Stake> */
  ulong       skip;
  ulong       skip_fallback;
  ulong       finalize;
  ulong       notar_or_skip;
  ulong       top_notar;
};
typedef struct slot_voted_stake slot_voted_stake_t;

/* SlotCertificates (slot_state.rs). */

struct slot_certificates {
  int                      has_notar;         ag_notar_cert_t      notar;
  int                      has_skip;          ag_skip_cert_t       skip;
  int                      has_fast_finalize; ag_fast_final_cert_t fast_finalize;
  int                      has_finalize;      ag_final_cert_t      finalize;
  ulong                    nf_cnt;
  ag_notar_fallback_cert_t nf[ AG_SLOT_STATE_NF_CERT_MAX ];
};
typedef struct slot_certificates slot_certificates_t;

/* Mirrors SlotState in pool/slot_state.rs (same field names and order);
   the pool and map handles are fd_pool/fd_map_chain plumbing for the field
   they follow, own_id/validator_max come from ValidatorEpochInfo/sizing. */

struct __attribute__((aligned(128UL))) ag_slot_state {
  slot_votes_t votes;

  slot_voted_stake_t voted_stakes;

  slot_certificates_t certificates;

  parents_pool_t * parents_pool;
  parents_map_t *  parents;    /* BTreeMap<BlockHash, ParentStatus> */

  set_t pending_safe_to_notar; /* BTreeSet<BlockHash> */
  set_t sent_safe_to_notar;    /* BTreeSet<BlockHash> */
  int   sent_safe_to_skip;

  ulong slot;
  ulong own_id;
  ag_epoch_info_t const * epoch_info;
  ulong validator_max;
};

static inline ulong
hash_ele_max( ulong validator_max ) {
  return fd_ulong_pow2_up( fd_ulong_max( validator_max, 16UL ) );
}

ulong
ag_slot_state_align( void ) {
  return alignof(ag_slot_state_t);
}

ulong
ag_slot_state_footprint( ulong validator_max ) {
  if( FD_UNLIKELY( validator_max==0UL || validator_max>AG_ALPENGLOW_VALIDATOR_MAX ) ) return 0UL;

  ulong hmax = hash_ele_max( validator_max );

  ulong parents_chain = parents_map_chain_cnt_est( hmax );

  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(ag_slot_state_t),  sizeof(ag_slot_state_t)                       ),
      alignof(hashstake_t),      sizeof(hashstake_t)*validator_max             ),
      alignof(hashstake_t),      sizeof(hashstake_t)*validator_max             ),
      alignof(hashagg_t),        sizeof(hashagg_t)*validator_max               ),
      alignof(hashagg_t),        sizeof(hashagg_t)*validator_max               ),
      parents_pool_align(),      parents_pool_footprint  ( hmax )              ),
      parents_map_align(),       parents_map_footprint   ( parents_chain )     ),
    ag_slot_state_align() );
}

void *
ag_slot_state_new( void *                  mem,
                   ulong                   slot,
                   ulong                   own_id,
                   ulong                   validator_max,
                   ulong                   seed,
                   ag_epoch_info_t const * epoch_info ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_slot_state_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = ag_slot_state_footprint( validator_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad validator_max (%lu)", validator_max ));
    return NULL;
  }
  fd_memset( mem, 0, footprint );

  ulong hmax = hash_ele_max( validator_max );
  ulong parents_chain = parents_map_chain_cnt_est( hmax );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  ag_slot_state_t * slot_state               = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_slot_state_t), sizeof(ag_slot_state_t)              );
  void *            notar_stake_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(hashstake_t),     sizeof(hashstake_t)*validator_max    );
  void *            nf_stake_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(hashstake_t),     sizeof(hashstake_t)*validator_max    );
  void *            notar_agg_mem    = FD_SCRATCH_ALLOC_APPEND( l, alignof(hashagg_t),       sizeof(hashagg_t)*validator_max      );
  void *            nf_agg_mem       = FD_SCRATCH_ALLOC_APPEND( l, alignof(hashagg_t),       sizeof(hashagg_t)*validator_max      );
  void *            parents_p        = FD_SCRATCH_ALLOC_APPEND( l, parents_pool_align(),     parents_pool_footprint  ( hmax )     );
  void *            parents_m        = FD_SCRATCH_ALLOC_APPEND( l, parents_map_align(),      parents_map_footprint   ( parents_chain ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_slot_state_align() ) == (ulong)mem + footprint );

  slot_state->slot              = slot;
  slot_state->own_id            = own_id;
  slot_state->epoch_info        = epoch_info;
  slot_state->validator_max     = validator_max;
  slot_state->sent_safe_to_skip = 0;
  slot_state->voted_stakes.skip          = 0UL;
  slot_state->voted_stakes.skip_fallback = 0UL;
  slot_state->voted_stakes.finalize      = 0UL;
  slot_state->voted_stakes.notar_or_skip = 0UL;
  slot_state->voted_stakes.top_notar     = 0UL;
  memset( &slot_state->certificates, 0, sizeof(slot_certificates_t) );
  slot_state->pending_safe_to_notar.cnt = 0UL;
  slot_state->sent_safe_to_notar.cnt    = 0UL;

  slot_state->voted_stakes.notar.cnt          = 0UL;
  slot_state->voted_stakes.notar.max          = validator_max;
  slot_state->voted_stakes.notar.ele          = (hashstake_t *)notar_stake_mem;
  slot_state->voted_stakes.notar_fallback.cnt = 0UL;
  slot_state->voted_stakes.notar_fallback.max = validator_max;
  slot_state->voted_stakes.notar_fallback.ele = (hashstake_t *)nf_stake_mem;
  slot_state->votes.notar.cnt          = 0UL;
  slot_state->votes.notar.max          = validator_max;
  slot_state->votes.notar.ele          = (hashagg_t *)notar_agg_mem;
  slot_state->votes.notar_fallback.cnt = 0UL;
  slot_state->votes.notar_fallback.max = validator_max;
  slot_state->votes.notar_fallback.ele = (hashagg_t *)nf_agg_mem;
  ag_aggsig_init( &slot_state->votes.skip,          epoch_info->validator_cnt );
  ag_aggsig_init( &slot_state->votes.skip_fallback, epoch_info->validator_cnt );
  ag_aggsig_init( &slot_state->votes.finalize,      epoch_info->validator_cnt );
  slot_state->parents_pool = parents_pool_join( parents_pool_new( parents_p,   hmax                ) );
  slot_state->parents      = parents_map_join ( parents_map_new ( parents_m,   parents_chain, seed ) );

  return mem;
}

ag_slot_state_t *
ag_slot_state_join( void * mem ) {
  ag_slot_state_t * slot_state = (ag_slot_state_t *)mem;
  if( FD_UNLIKELY( !slot_state ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)slot_state, ag_slot_state_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return slot_state;
}

void *
ag_slot_state_leave( ag_slot_state_t const * slot_state ) {
  if( FD_UNLIKELY( !slot_state ) ) {
    FD_LOG_WARNING(( "NULL slot_state" ));
    return NULL;
  }
  return (void *)slot_state;
}

void *
ag_slot_state_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_slot_state_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return mem;
}

static ulong
hashstake_get( stake_map_t const * map,
               fd_hash_t const *   hash ) {
  for( ulong i=0UL; i<map->cnt; i++ ) {
    if( !memcmp( map->ele[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return map->ele[i].stake;
  }
  return 0UL;
}

static ulong
hashstake_add( stake_map_t *     map,
               fd_hash_t const * hash,
               ulong             stake ) {
  for( ulong i=0UL; i<map->cnt; i++ ) {
    if( !memcmp( map->ele[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) {
      map->ele[i].stake += stake;
      return map->ele[i].stake;
    }
  }
  FD_TEST( map->cnt < map->max );
  hashstake_t * e = &map->ele[ map->cnt++ ];
  e->hash  = *hash;
  e->stake = stake;
  return stake;
}

/* votes.notar / notar_fallback: running aggregate per block hash. */

static ag_aggsig_t const *
agg_map_get( agg_map_t const * map,
             fd_hash_t const * hash ) {
  for( ulong i=0UL; i<map->cnt; i++ ) {
    if( !memcmp( map->ele[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return &map->ele[i].agg;
  }
  return NULL;
}

static ag_aggsig_t *
agg_map_get_or_insert( agg_map_t *       map,
                       fd_hash_t const * hash,
                       ulong             nbits ) {
  for( ulong i=0UL; i<map->cnt; i++ ) {
    if( !memcmp( map->ele[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return &map->ele[i].agg;
  }
  FD_TEST( map->cnt < map->max );
  hashagg_t * e = &map->ele[ map->cnt++ ];
  e->hash = *hash;
  ag_aggsig_init( &e->agg, nbits );
  return &e->agg;
}

/* Which hash (if any) validator v signed in this map:
   votes.notar[v] as an Option<block_hash>. */

static hashagg_t const *
agg_map_find_signer( agg_map_t const * map,
                     ulong             v ) {
  for( ulong i=0UL; i<map->cnt; i++ ) {
    if( ag_aggsig_is_signer( &map->ele[i].agg, v ) ) return &map->ele[i];
  }
  return NULL;
}

/* self.parents.get(&hash): NULL == Entry::Vacant */

static parent_status_t *
parents_get( ag_slot_state_t * slot_state,
             fd_hash_t const * hash ) {
  return parents_map_ele_query( slot_state->parents, hash, NULL, slot_state->parents_pool );
}

/* BTreeSet<BlockHash> contains / insert / remove */

static int
set_contains( set_t const * set,
          fd_hash_t const * hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( !memcmp( set->hash[i].uc, hash->uc, sizeof(fd_hash_t) ) ) return 1;
  }
  return 0;
}

static void
set_insert( set_t *       set,
                fd_hash_t const * hash ) {
  if( set_contains( set, hash ) ) return;
  FD_TEST( set->cnt < AG_SLOT_STATE_SET_MAX );
  set->hash[ set->cnt++ ] = *hash;
}

static void
set_remove( set_t *       set,
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
  /* dedupe: the two pending sweeps re-check the same hashes (Rust pushes
     duplicates; repair requests are idempotent) */
  for( ulong i=0UL; i<out->block_repairs_cnt; i++ ) {
    if( !memcmp( out->block_repairs[i].hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return;
  }
  FD_TEST( out->block_repairs_cnt < AG_SLOT_STATE_OUT_REPAIR_MAX );
  ag_block_id_t * b = &out->block_repairs[ out->block_repairs_cnt++ ];
  b->slot = slot;
  b->hash = *hash;
}

/* is_notar_fallback (SlotState::is_notar_fallback). */

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * slot_state,
                                 fd_hash_t const *       block_hash ) {
  slot_certificates_t const * c = &slot_state->certificates;
  for( ulong i=0UL; i<c->nf_cnt; i++ ) {
    if( !memcmp( c->nf[i].block_hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) return 1;
  }
  return 0;
}

/* check_safe_to_notar (SlotState::check_safe_to_notar). */

static int
check_safe_to_notar( ag_slot_state_t * slot_state,
                     fd_hash_t const * block_hash ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ulong notar_stake = hashstake_get( &slot_state->voted_stakes.notar, block_hash );
  ulong skip_stake  = slot_state->voted_stakes.skip;

  if( !ag_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) ) {
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }
  if( !ag_epoch_info_is_weak_quorum( epoch_info, notar_stake )
      && !ag_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) {
    set_insert( &slot_state->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  parent_status_t * parent = parents_get( slot_state, block_hash );
  if( !parent ) {
    return AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK;
  }
  if( parent->kind != AG_PARENT_STATUS_CERTIFIED ) {
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  slot_votes_t * v   = &slot_state->votes;
  ulong        own = slot_state->own_id;
  int               has_skip  = ag_aggsig_is_signer( &v->skip, own );
  hashagg_t const * own_notar = agg_map_find_signer( &v->notar, own );

  if( has_skip ) {
    set_remove( &slot_state->pending_safe_to_notar, block_hash );
    set_insert( &slot_state->sent_safe_to_notar,    block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
  }
  if( own_notar ) {
    if( memcmp( own_notar->hash.uc, block_hash->uc, sizeof(fd_hash_t) ) ) {
      set_remove( &slot_state->pending_safe_to_notar, block_hash );
      set_insert( &slot_state->sent_safe_to_notar,    block_hash );
      return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
    }
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  set_insert( &slot_state->pending_safe_to_notar, block_hash );
  return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
}

/* count_notar_stake (SlotState::count_notar_stake). */

static ag_slot_state_outputs_t
count_notar_stake( ag_slot_state_t * slot_state,
                   ulong             slot,
                   fd_hash_t const * block_hash,
                   ulong             stake ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.pool_events_cnt = 0UL; outputs.block_repairs_cnt = 0UL;

  ulong notar_stake = hashstake_add( &slot_state->voted_stakes.notar, block_hash, stake );
  slot_state->voted_stakes.notar_or_skip += stake;
  slot_state->voted_stakes.top_notar = fd_ulong_max( notar_stake, slot_state->voted_stakes.top_notar );

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
      && ag_epoch_info_is_weak_quorum( epoch_info, slot_state->voted_stakes.notar_or_skip - slot_state->voted_stakes.top_notar )
      && agg_map_find_signer( &slot_state->votes.notar, slot_state->own_id ) ) {
    out_push_safe_to_skip( &outputs, slot );
    slot_state->sent_safe_to_skip = 1;
  }

  ulong nf_stake = hashstake_get( &slot_state->voted_stakes.notar_fallback, block_hash );
  if( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake )
      && !ag_slot_state_is_notar_fallback( slot_state, block_hash ) ) {
    ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR_FALLBACK;
    ag_notar_fallback_cert_from_aggs( &cert.inner.notar_fallback, slot, block_hash,
                                      agg_map_get( &slot_state->votes.notar,          block_hash ),
                                      agg_map_get( &slot_state->votes.notar_fallback, block_hash ),
                                      ag_epoch_info_validators( epoch_info ),
                                      epoch_info->validator_cnt );
    out_push_cert( &outputs, &cert );
  }
  if( ag_epoch_info_is_quorum( epoch_info, notar_stake ) && !slot_state->certificates.has_notar ) {
    ag_aggsig_t const * agg = agg_map_get( &slot_state->votes.notar, block_hash );
    FD_TEST( agg );
    ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR;
    ag_notar_cert_from_agg( &cert.inner.notar, slot, block_hash, agg,
                            ag_epoch_info_validators( epoch_info ),
                            epoch_info->validator_cnt );
    out_push_cert( &outputs, &cert );
  }
  if( ag_epoch_info_is_strong_quorum( epoch_info, notar_stake ) && !slot_state->certificates.has_fast_finalize ) {
    ag_aggsig_t const * agg = agg_map_get( &slot_state->votes.notar, block_hash );
    FD_TEST( agg );
    ag_cert_t cert; cert.kind = AG_CERT_TYPE_FAST_FINAL;
    ag_fast_final_cert_from_agg( &cert.inner.fast_final, slot, block_hash, agg,
                                 ag_epoch_info_validators( epoch_info ),
                                 epoch_info->validator_cnt );
    out_push_cert( &outputs, &cert );
  }

  return outputs;
}

/* count_notar_fallback_stake (SlotState::count_notar_fallback_stake). */

static ag_slot_state_outputs_t
count_notar_fallback_stake( ag_slot_state_t * slot_state,
                            fd_hash_t const * block_hash,
                            ulong             stake ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.pool_events_cnt = 0UL; outputs.block_repairs_cnt = 0UL;

  ulong nf_stake    = hashstake_add( &slot_state->voted_stakes.notar_fallback, block_hash, stake );
  ulong notar_stake = hashstake_get( &slot_state->voted_stakes.notar, block_hash );
  if( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake )
      && !ag_slot_state_is_notar_fallback( slot_state, block_hash ) ) {
    ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR_FALLBACK;
    ag_notar_fallback_cert_from_aggs( &cert.inner.notar_fallback, slot_state->slot, block_hash,
                                      agg_map_get( &slot_state->votes.notar,          block_hash ),
                                      agg_map_get( &slot_state->votes.notar_fallback, block_hash ),
                                      ag_epoch_info_validators( epoch_info ),
                                      epoch_info->validator_cnt );
    out_push_cert( &outputs, &cert );
  }

  return outputs;
}

/* count_skip_stake (SlotState::count_skip_stake). */

static ag_slot_state_outputs_t
count_skip_stake( ag_slot_state_t * slot_state,
                  ulong             slot,
                  ulong             stake,
                  int               fallback ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ag_slot_state_outputs_t outputs    = { 0 };

  if( fallback ) slot_state->voted_stakes.skip_fallback += stake;
  else           slot_state->voted_stakes.skip          += stake;

  set_t pending = slot_state->pending_safe_to_notar; /* TODO perf */
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
  if( ag_epoch_info_is_quorum( epoch_info, total_skip_stake ) && !slot_state->certificates.has_skip ) {
    ag_cert_t cert; cert.kind = AG_CERT_TYPE_SKIP;
    ag_skip_cert_from_aggs( &cert.inner.skip, slot,
                            &slot_state->votes.skip,
                            &slot_state->votes.skip_fallback,
                            ag_epoch_info_validators( epoch_info ),
                            epoch_info->validator_cnt );
    out_push_cert( &outputs, &cert );
  }
  if( !slot_state->sent_safe_to_skip
      && ag_epoch_info_is_weak_quorum( epoch_info, slot_state->voted_stakes.notar_or_skip - slot_state->voted_stakes.top_notar )
      && agg_map_find_signer( &slot_state->votes.notar, slot_state->own_id ) ) {
    out_push_safe_to_skip( &outputs, slot );
    slot_state->sent_safe_to_skip = 1;
  }

  return outputs;
}

/* count_finalize_stake (SlotState::count_finalize_stake). */

static ag_slot_state_outputs_t
count_finalize_stake( ag_slot_state_t * slot_state,
                      ulong             stake ) {
  ag_epoch_info_t const * epoch_info = slot_state->epoch_info;
  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.pool_events_cnt = 0UL; outputs.block_repairs_cnt = 0UL;

  slot_state->voted_stakes.finalize += stake;
  if( ag_epoch_info_is_quorum( epoch_info, slot_state->voted_stakes.finalize ) && !slot_state->certificates.has_finalize ) {
    ag_cert_t cert; cert.kind = AG_CERT_TYPE_FINAL;
    ag_final_cert_from_agg( &cert.inner.final_, slot_state->slot,
                            &slot_state->votes.finalize,
                            ag_epoch_info_validators( epoch_info ),
                            epoch_info->validator_cnt );
    out_push_cert( &outputs, &cert );
  }

  return outputs;
}

/* add_cert (SlotState::add_cert). */

void
ag_slot_state_add_cert( ag_slot_state_t * slot_state,
                        ag_cert_t const * cert ) {
  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:
    slot_state->certificates.has_notar = 1;
    slot_state->certificates.notar     = cert->inner.notar;
    break;
  case AG_CERT_TYPE_NOTAR_FALLBACK:
    if( !ag_slot_state_is_notar_fallback( slot_state, &cert->inner.notar_fallback.block_hash ) ) {
      FD_TEST( slot_state->certificates.nf_cnt < AG_SLOT_STATE_NF_CERT_MAX );
      slot_state->certificates.nf[ slot_state->certificates.nf_cnt++ ] = cert->inner.notar_fallback;
    }
    break;
  case AG_CERT_TYPE_SKIP:
    slot_state->certificates.has_skip = 1;
    slot_state->certificates.skip     = cert->inner.skip;
    break;
  case AG_CERT_TYPE_FAST_FINAL:
    slot_state->certificates.has_fast_finalize = 1;
    slot_state->certificates.fast_finalize     = cert->inner.fast_final;
    break;
  case AG_CERT_TYPE_FINAL:
    slot_state->certificates.has_finalize = 1;
    slot_state->certificates.finalize     = cert->inner.final_;
    break;
  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }
}

/* add_vote (SlotState::add_vote). */

ag_slot_state_outputs_t
ag_slot_state_add_vote( ag_slot_state_t * slot_state,
                        ag_vote_t const * vote,
                        ulong             voter_stake ) {
  ulong slot  = ag_vote_slot ( vote );
  ulong voter = ag_vote_signer( vote );
  FD_TEST( voter < slot_state->validator_max );
  slot_votes_t * v = &slot_state->votes;

  ag_slot_state_outputs_t outputs;
  outputs.certs_cnt = 0UL; outputs.pool_events_cnt = 0UL; outputs.block_repairs_cnt = 0UL;

  switch( vote->kind ) {

  case AG_VOTE_TYPE_NOTAR: {
    fd_hash_t const * h = &vote->inner.notar.block_hash;
    outputs = count_notar_stake( slot_state, slot, h, voter_stake );

    ag_aggsig_t * agg = agg_map_get_or_insert( &v->notar, h, slot_state->epoch_info->validator_cnt );
    ag_aggsig_add( agg, voter, &vote->inner.notar.sig );
    if( voter==slot_state->own_id ) v->own.notar = vote->inner.notar;
    break;
  }

  case AG_VOTE_TYPE_NOTAR_FALLBACK: {
    fd_hash_t const * h = &vote->inner.notar_fallback.block_hash;
    outputs = count_notar_fallback_stake( slot_state, h, voter_stake );

    ag_aggsig_t * agg = agg_map_get_or_insert( &v->notar_fallback, h, slot_state->epoch_info->validator_cnt );
    ag_aggsig_add( agg, voter, &vote->inner.notar_fallback.sig );
    if( voter==slot_state->own_id ) {
      FD_TEST( v->own.notar_fallback_cnt < AG_SLOT_STATE_SET_MAX );
      v->own.notar_fallback[ v->own.notar_fallback_cnt++ ] = vote->inner.notar_fallback;
    }
    break;
  }

  case AG_VOTE_TYPE_SKIP:
    ag_aggsig_add( &v->skip, voter, &vote->inner.skip.sig );
    if( voter==slot_state->own_id ) v->own.skip = vote->inner.skip;
    slot_state->voted_stakes.notar_or_skip += voter_stake;
    outputs = count_skip_stake( slot_state, slot, voter_stake, 0 );
    break;

  case AG_VOTE_TYPE_SKIP_FALLBACK:
    ag_aggsig_add( &v->skip_fallback, voter, &vote->inner.skip_fallback.sig );
    if( voter==slot_state->own_id ) v->own.skip_fallback = vote->inner.skip_fallback;
    outputs = count_skip_stake( slot_state, slot, voter_stake, 1 );
    break;

  case AG_VOTE_TYPE_FINAL:
    ag_aggsig_add( &v->finalize, voter, &vote->inner.final_.sig );
    if( voter==slot_state->own_id ) v->own.finalize = vote->inner.final_;
    outputs = count_finalize_stake( slot_state, voter_stake );
    break;

  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }

  /* own vote might have made a block safe-to-notar */
  if( voter==slot_state->own_id ) {
    set_t pending = slot_state->pending_safe_to_notar;
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
  /* self.parents.entry(hash).or_insert(ParentStatus::Known) */
  if( parents_get( slot_state, hash ) ) return;
  parent_status_t * e = parents_pool_ele_acquire( slot_state->parents_pool );
  e->hash   = *hash;
  e->kind = AG_PARENT_STATUS_KNOWN;
  parents_map_ele_insert( slot_state->parents, e, slot_state->parents_pool );
}

int
ag_slot_state_notify_parent_certified( ag_slot_state_t * slot_state,
                                       fd_hash_t const * hash ) {
  parent_status_t * parent_info = parents_get( slot_state, hash );
  FD_TEST( parent_info ); /* "parent not known" */
  parent_info->kind = AG_PARENT_STATUS_CERTIFIED;

  if( set_contains( &slot_state->sent_safe_to_notar, hash ) ) {
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }
  return check_safe_to_notar( slot_state, hash );
}

/* check_slashable_offence (SlotState::check_slashable_offence). */

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const * slot_state,
                                       ag_vote_t const *       vote ) {
  ulong voter = ag_vote_signer( vote );
  slot_votes_t const * v = &slot_state->votes;

  switch( vote->kind ) {

  case AG_VOTE_TYPE_NOTAR: {
    if( ag_aggsig_is_signer( &v->skip, voter ) ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    hashagg_t const * notar = agg_map_find_signer( &v->notar, voter );
    if( notar && memcmp( vote->inner.notar.block_hash.uc, notar->hash.uc, sizeof(fd_hash_t) ) ) {
      return AG_SLASHABLE_NOTAR_DIFFERENT_HASH;
    }
    break;
  }

  case AG_VOTE_TYPE_NOTAR_FALLBACK:
    if( ag_aggsig_is_signer( &v->finalize, voter ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;

  case AG_VOTE_TYPE_SKIP:
    if( ag_aggsig_is_signer( &v->finalize, voter ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    } else if( agg_map_find_signer( &v->notar, voter ) ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    break;

  case AG_VOTE_TYPE_SKIP_FALLBACK:
    if( ag_aggsig_is_signer( &v->finalize, voter ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    break;

  case AG_VOTE_TYPE_FINAL: {
    if( ag_aggsig_is_signer( &v->skip, voter ) || ag_aggsig_is_signer( &v->skip_fallback, voter ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    if( agg_map_find_signer( &v->notar_fallback, voter ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;
  }

  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return AG_SLASHABLE_NONE;
}

/* should_ignore_vote (SlotState::should_ignore_vote). */

FD_FN_PURE int
ag_slot_state_should_ignore_vote( ag_slot_state_t const * slot_state,
                                  ag_vote_t const *       vote ) {
  ulong voter = ag_vote_signer( vote );
  slot_votes_t const * v = &slot_state->votes;
  switch( vote->kind ) {
  case AG_VOTE_TYPE_NOTAR:
    return agg_map_find_signer( &v->notar, voter )!=NULL;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: {
    ag_aggsig_t const * agg = agg_map_get( &v->notar_fallback, &vote->inner.notar_fallback.block_hash );
    return agg && ag_aggsig_is_signer( agg, voter );
  }
  case AG_VOTE_TYPE_SKIP:
  case AG_VOTE_TYPE_SKIP_FALLBACK:
    return ag_aggsig_is_signer( &v->skip, voter ) || ag_aggsig_is_signer( &v->skip_fallback, voter );
  case AG_VOTE_TYPE_FINAL:
    return ag_aggsig_is_signer( &v->finalize, voter );
  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return 0;
}

FD_FN_PURE ulong ag_slot_state_slot( ag_slot_state_t const * slot_state ) { return slot_state->slot; }

FD_FN_PURE ulong
ag_slot_state_notar_stake( ag_slot_state_t const * slot_state,
                           fd_hash_t const *       block_hash ) {
  return hashstake_get( &slot_state->voted_stakes.notar, block_hash );
}

FD_FN_PURE ulong
ag_slot_state_notar_fallback_stake( ag_slot_state_t const * slot_state,
                                    fd_hash_t const *       block_hash ) {
  return hashstake_get( &slot_state->voted_stakes.notar_fallback, block_hash );
}


FD_FN_PURE int
ag_slot_state_has_notar_vote( ag_slot_state_t const * slot_state,
                              ulong                   v ) {
  return agg_map_find_signer( &slot_state->votes.notar, v )!=NULL;
}

FD_FN_PURE int ag_slot_state_has_notar_cert        ( ag_slot_state_t const * slot_state ) { return slot_state->certificates.has_notar;         }
FD_FN_PURE int ag_slot_state_has_skip_cert         ( ag_slot_state_t const * slot_state ) { return slot_state->certificates.has_skip;          }
FD_FN_PURE int ag_slot_state_has_fast_finalize_cert( ag_slot_state_t const * slot_state ) { return slot_state->certificates.has_fast_finalize; }
FD_FN_PURE int ag_slot_state_has_finalize_cert     ( ag_slot_state_t const * slot_state ) { return slot_state->certificates.has_finalize;      }

FD_FN_PURE ag_final_cert_t const *
ag_slot_state_finalize_cert( ag_slot_state_t const * slot_state ) {
  return slot_state->certificates.has_finalize ? &slot_state->certificates.finalize : NULL;
}

FD_FN_PURE ag_fast_final_cert_t const *
ag_slot_state_fast_finalize_cert( ag_slot_state_t const * slot_state ) {
  return slot_state->certificates.has_fast_finalize ? &slot_state->certificates.fast_finalize : NULL;
}

FD_FN_PURE ag_notar_cert_t const *
ag_slot_state_notar_cert( ag_slot_state_t const * slot_state ) {
  return slot_state->certificates.has_notar ? &slot_state->certificates.notar : NULL;
}

FD_FN_PURE ag_skip_cert_t const *
ag_slot_state_skip_cert( ag_slot_state_t const * slot_state ) {
  return slot_state->certificates.has_skip ? &slot_state->certificates.skip : NULL;
}

FD_FN_PURE ulong
ag_slot_state_notar_fallback_cert_cnt( ag_slot_state_t const * slot_state ) {
  return slot_state->certificates.nf_cnt;
}

FD_FN_PURE ag_notar_fallback_cert_t const *
ag_slot_state_notar_fallback_cert( ag_slot_state_t const * slot_state,
                                   ulong                   i ) {
  return &slot_state->certificates.nf[ i ];
}

FD_FN_PURE ag_final_vote_t const *
ag_slot_state_own_finalize_vote( ag_slot_state_t const * slot_state ) {
  slot_votes_t const * v = &slot_state->votes;
  return ag_aggsig_is_signer( &v->finalize, slot_state->own_id ) ? &v->own.finalize : NULL;
}

FD_FN_PURE ag_notar_vote_t const *
ag_slot_state_own_notar_vote( ag_slot_state_t const * slot_state ) {
  slot_votes_t const * v = &slot_state->votes;
  return agg_map_find_signer( &v->notar, slot_state->own_id ) ? &v->own.notar : NULL;
}

FD_FN_PURE ag_skip_vote_t const *
ag_slot_state_own_skip_vote( ag_slot_state_t const * slot_state ) {
  slot_votes_t const * v = &slot_state->votes;
  return ag_aggsig_is_signer( &v->skip, slot_state->own_id ) ? &v->own.skip : NULL;
}

FD_FN_PURE ag_skip_fallback_vote_t const *
ag_slot_state_own_skip_fallback_vote( ag_slot_state_t const * slot_state ) {
  slot_votes_t const * v = &slot_state->votes;
  return ag_aggsig_is_signer( &v->skip_fallback, slot_state->own_id ) ? &v->own.skip_fallback : NULL;
}

ulong
ag_slot_state_own_notar_fallback_votes( ag_slot_state_t const *    slot_state,
                                        ag_notar_fallback_vote_t * out,
                                        ulong                      out_max ) {
  own_votes_t const * own = &slot_state->votes.own;
  FD_TEST( own->notar_fallback_cnt<=out_max );
  for( ulong i=0UL; i<own->notar_fallback_cnt; i++ ) out[i] = own->notar_fallback[i];
  return own->notar_fallback_cnt;
}
