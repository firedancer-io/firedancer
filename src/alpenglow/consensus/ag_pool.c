#include "ag_pool.h"
#include "pool/ag_finality_tracker.h"
#include "pool/ag_parent_ready_tracker.h"
#include "pool/ag_slot_state.h"

struct slot_state_ele {
  ulong             slot; /* key */
  ulong             next; /* reserved for fd_pool and fd_map_chain */
  ag_slot_state_t * slot_state; /* value */
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
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

typedef slot_state_ele_t slot_state_pool_t;

struct s2n_waiting_parent_cert {
  ag_block_id_t parent;
  ulong         next;
  ag_block_id_t child;
};
typedef struct s2n_waiting_parent_cert s2n_waiting_parent_cert_t;

#define POOL_NAME s2n_waiting_parent_cert_pool
#define POOL_T    s2n_waiting_parent_cert_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               s2n_waiting_parent_cert_map
#define MAP_ELE_T              s2n_waiting_parent_cert_t
#define MAP_KEY                parent
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_EQ(k0,k1)      (ag_block_id_eq((k0),(k1)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(ag_block_id_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

typedef s2n_waiting_parent_cert_t s2n_waiting_parent_cert_pool_t;

struct __attribute__((aligned(128UL))) ag_pool {
  ulong slot_max;

  ulong           votor_event_cnt;
  ulong           repair_cnt;
  ag_pool_event_t votor_event_channel[ AG_POOL_VOTOR_EVENT_MAX ];
  ag_block_id_t   repair_channel     [ AG_POOL_REPAIR_MAX      ];
  ulong validator_max;
  ulong own_id;
  ushort shred_version;
  ulong seed;
  ulong slot_state_footprint;

  ag_epoch_info_t *                epoch_info;
  uchar *                          slot_state_arena;
  slot_state_pool_t *                 slot_state_pool;
  slot_state_map_t *                  slot_state_map;
  s2n_waiting_parent_cert_pool_t * s2n_waiting_parent_cert_pool;
  s2n_waiting_parent_cert_map_t *  s2n_waiting_parent_cert_map;
  ag_finality_tracker_t *          finality_tracker;
  ag_parent_ready_tracker_t *      parent_ready_tracker;
};

static inline void *
slot_state_region( ag_pool_t const * self,
                   ulong             i ) {
  return self->slot_state_arena + i*self->slot_state_footprint;
}

FD_FN_CONST char const *
ag_pool_strerror( int err ) {
  switch( err ) {
  case AG_POOL_SUCCESS:                    return "success";
  case AG_ADD_VOTE_ERR_SLOT_OUT_OF_BOUNDS: return "slot is either too old or too far in the future";
  case AG_ADD_VOTE_ERR_UNKNOWN_SIGNER:     return "signer is not a validator in the current epoch";
  case AG_ADD_VOTE_ERR_INVALID_SIGNATURE:  return "invalid signature on the vote";
  case AG_ADD_VOTE_ERR_DUPLICATE:          return "duplicate vote";
  case AG_ADD_VOTE_ERR_SLASHABLE:          return "vote constitutes a slashable offence";
  case AG_ADD_CERT_ERR_SLOT_OUT_OF_BOUNDS: return "slot is either too old or too far in the future";
  case AG_ADD_CERT_ERR_THRESHOLD_NOT_MET:  return "stake threshold not met";
  case AG_ADD_CERT_ERR_INVALID_SIGNATURE:  return "invalid signature on the cert";
  case AG_ADD_CERT_ERR_DUPLICATE:          return "duplicate cert";
  default:                                 return "unknown";
  }
}

ulong
ag_pool_align( void ) {
  return alignof(ag_pool_t);
}

ulong
ag_pool_footprint( ulong slot_max,
                   ulong validator_max,
                   ulong blockid_max ) {
  if( FD_UNLIKELY( slot_max==0UL || validator_max==0UL || blockid_max==0UL ) ) return 0UL;

  ulong slot_state_fp = ag_slot_state_footprint( validator_max );
  if( FD_UNLIKELY( !slot_state_fp ) ) return 0UL;

  ulong se_max       = fd_ulong_pow2_up( slot_max );
  ulong se_chain     = slot_state_map_chain_cnt_est( se_max );
  ulong s2n_max      = fd_ulong_pow2_up( blockid_max );
  ulong s2n_chain    = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );

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
    FD_LAYOUT_INIT,
      alignof(ag_pool_t),                sizeof(ag_pool_t)                                      ),
      ag_epoch_info_align(),             ag_epoch_info_footprint( validator_max )               ),
      ag_slot_state_align(),             slot_state_fp*slot_max                                         ),
      slot_state_pool_align(),                  slot_state_pool_footprint( se_max )                       ),
      slot_state_map_align(),                   slot_state_map_footprint ( se_chain )                     ),
      s2n_waiting_parent_cert_pool_align(),  s2n_waiting_parent_cert_pool_footprint( s2n_max )      ),
      s2n_waiting_parent_cert_map_align(),   s2n_waiting_parent_cert_map_footprint ( s2n_chain )    ),
      ag_finality_tracker_align(),       ag_finality_tracker_footprint( slot_max, blockid_max ) ),
      ag_parent_ready_tracker_align(),   ag_parent_ready_tracker_footprint( slot_max )          ),
    ag_pool_align() );
}

void *
ag_pool_new( void *                      mem,
             ulong                       slot_max,
             ulong                       validator_max,
             ulong                       blockid_max,
             ulong                       own_id,
             ag_validator_info_t const * validators,
             ulong                       validator_cnt,
             ushort                      shred_version,
             ulong                       seed,
             ulong                       root_slot,
             fd_hash_t const *           root_block_hash ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = ag_pool_footprint( slot_max, validator_max, blockid_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max/validator_max/blockid_max (%lu/%lu/%lu)", slot_max, validator_max, blockid_max ));
    return NULL;
  }
  if( FD_UNLIKELY( validator_cnt>validator_max ) ) {
    FD_LOG_WARNING(( "validator_cnt (%lu) > validator_max (%lu)", validator_cnt, validator_max ));
    return NULL;
  }
  fd_memset( mem, 0, footprint );

  ulong slot_state_fp     = ag_slot_state_footprint( validator_max );
  ulong se_max    = fd_ulong_pow2_up( slot_max );
  ulong se_chain  = slot_state_map_chain_cnt_est( se_max );
  ulong s2n_max   = fd_ulong_pow2_up( blockid_max );
  ulong s2n_chain = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  ag_pool_t * pool         = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_pool_t),              sizeof(ag_pool_t)                                      );
  void *      ei_mem       = FD_SCRATCH_ALLOC_APPEND( l, ag_epoch_info_align(),           ag_epoch_info_footprint( validator_max )               );
  void *      slot_state_arena     = FD_SCRATCH_ALLOC_APPEND( l, ag_slot_state_align(),           slot_state_fp*slot_max                                         );
  void *      se_pool      = FD_SCRATCH_ALLOC_APPEND( l, slot_state_pool_align(),            slot_state_pool_footprint( se_max )                       );
  void *      se_map       = FD_SCRATCH_ALLOC_APPEND( l, slot_state_map_align(),             slot_state_map_footprint ( se_chain )                     );
  void *      s2n_p        = FD_SCRATCH_ALLOC_APPEND( l, s2n_waiting_parent_cert_pool_align(), s2n_waiting_parent_cert_pool_footprint( s2n_max )   );
  void *      s2n_m        = FD_SCRATCH_ALLOC_APPEND( l, s2n_waiting_parent_cert_map_align(),  s2n_waiting_parent_cert_map_footprint ( s2n_chain ) );
  void *      fin_mem      = FD_SCRATCH_ALLOC_APPEND( l, ag_finality_tracker_align(),     ag_finality_tracker_footprint( slot_max, blockid_max ) );
  void *      pr_mem       = FD_SCRATCH_ALLOC_APPEND( l, ag_parent_ready_tracker_align(), ag_parent_ready_tracker_footprint( slot_max )          );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_pool_align() ) == (ulong)mem + footprint );

  pool->slot_max      = slot_max;
  pool->validator_max = validator_max;
  pool->own_id        = own_id;
  pool->shred_version = shred_version;
  pool->seed          = seed;
  pool->slot_state_footprint  = slot_state_fp;

  pool->epoch_info = (ag_epoch_info_t *)ag_epoch_info_new( ei_mem, validators, validator_cnt );

  pool->slot_state_arena     = (uchar *)slot_state_arena;
  pool->slot_state_pool = slot_state_pool_join( slot_state_pool_new( se_pool, se_max          ) );
  pool->slot_state_map  = slot_state_map_join ( slot_state_map_new ( se_map,  se_chain,  seed ) );
  pool->s2n_waiting_parent_cert_pool = s2n_waiting_parent_cert_pool_join( s2n_waiting_parent_cert_pool_new( s2n_p, s2n_max         ) );
  pool->s2n_waiting_parent_cert_map  = s2n_waiting_parent_cert_map_join ( s2n_waiting_parent_cert_map_new ( s2n_m, s2n_chain, seed ) );
  pool->finality_tracker     = ag_finality_tracker_join( ag_finality_tracker_new( fin_mem, slot_max, blockid_max, seed, root_slot, root_block_hash ) );

  ag_parent_ready_tracker_t * pr = ag_parent_ready_tracker_join( ag_parent_ready_tracker_new( pr_mem, slot_max, seed ) );
  if( root_slot==0UL ) ag_parent_ready_tracker_default  ( pr );
  else                 ag_parent_ready_tracker_seed_root( pr, root_slot, root_block_hash );
  pool->parent_ready_tracker = pr;

  return mem;
}

ag_pool_t *
ag_pool_join( void * mem ) {
  ag_pool_t * pool = (ag_pool_t *)mem;
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pool, ag_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return pool;
}

void *
ag_pool_leave( ag_pool_t const * pool ) {
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "NULL pool" ));
    return NULL;
  }
  return (void *)pool;
}

void *
ag_pool_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  return mem;
}

static slot_state_ele_t *
slot_state_ele_query( ag_pool_t * self,
               ulong       slot ) {
  return slot_state_map_ele_query( self->slot_state_map, &slot, NULL, self->slot_state_pool );
}

FD_FN_PURE static slot_state_ele_t const *
slot_state_ele_query_const( ag_pool_t const * self,
                     ulong             slot ) {
  return slot_state_map_ele_query_const( self->slot_state_map, &slot, NULL, self->slot_state_pool );
}

static ag_slot_state_t *
ag_pool_slot_state( ag_pool_t * self,
                    ulong       slot ) {
  slot_state_ele_t * e = slot_state_ele_query( self, slot );
  if( FD_LIKELY( e ) ) return e->slot_state;

  FD_TEST( slot_state_pool_free( self->slot_state_pool ) );

  e = slot_state_pool_ele_acquire( self->slot_state_pool );
  ulong idx = slot_state_pool_idx( self->slot_state_pool, e );
  e->slot = slot;

  void * region = slot_state_region( self, idx );
  e->slot_state = ag_slot_state_join( ag_slot_state_new( region, slot, self->own_id, self->validator_max, self->seed, self->epoch_info ) );
  slot_state_map_ele_insert( self->slot_state_map, e, self->slot_state_pool );
  return e->slot_state;
}

/* send_parent_ready_events (PoolImpl::send_parent_ready_events). */

static void
send_parent_ready_events( ag_pool_t *               self,
                          ag_parent_ready_t const * parents,
                          ulong                     parents_cnt ) {
  for( ulong i=0UL; i<parents_cnt; i++ ) {
    FD_TEST( ag_alpenglow_is_start_of_window( parents[i].slot ) );
    ag_pool_event_t event = { .kind = AG_POOL_EVENT_PARENT_READY };
    event.inner.parent_ready.slot   = parents[i].slot;
    event.inner.parent_ready.parent = parents[i].parent;
    self->votor_event_channel[ self->votor_event_cnt++ ] = event;
  }
}

/* prune (PoolImpl::prune). */

static void
prune( ag_pool_t * self ) {
  ulong first_unpruned = ag_finality_tracker_first_unpruned_slot( self->finality_tracker );

  for(;;) {
    int      found    = 0;
    ulong    drop_slot = 0UL;
    slot_state_map_t *  map  = self->slot_state_map;
    slot_state_pool_t * pool = self->slot_state_pool;
    for( slot_state_map_iter_t it = slot_state_map_iter_init( map, pool );
         !slot_state_map_iter_done( it, map, pool );
         it = slot_state_map_iter_next( it, map, pool ) ) {
      slot_state_ele_t const * e = slot_state_map_iter_ele_const( it, map, pool );
      if( e->slot < first_unpruned ) { drop_slot = e->slot; found = 1; break; }
    }
    if( !found ) break;
    slot_state_ele_t * e = slot_state_map_ele_remove( self->slot_state_map, &drop_slot, NULL, self->slot_state_pool );
    FD_TEST( e );
    slot_state_pool_ele_release( self->slot_state_pool, e );
  }

  ag_parent_ready_tracker_prune( self->parent_ready_tracker, first_unpruned );

}

/* handle_finalization (PoolImpl::handle_finalization). */

static void
handle_finalization( ag_pool_t *                     self,
                     ag_finalization_event_t const * event ) {
  ag_parent_ready_t new_parents_ready;
  if( ag_parent_ready_tracker_handle_finalization( self->parent_ready_tracker,
                                                   event->has_finalized, &event->finalized,
                                                   event->implicitly_finalized, event->if_cnt,
                                                   event->implicitly_skipped,   event->is_cnt,
                                                   &new_parents_ready ) )
    send_parent_ready_events( self, &new_parents_ready, 1UL );
  prune( self );
}

/* ag_pool_prune_to_root (C-only): shed all per-slot state below the
   certified-final consensus root; see ag_finality_tracker_prune_to. */

void
ag_pool_prune_to_root( ag_pool_t *       self,
                       ulong             root_slot,
                       fd_hash_t const * root_hash ) {
  ag_finality_tracker_prune_to( self->finality_tracker, root_slot, root_hash );
  prune( self );
}

/* add_valid_cert (PoolImpl::add_valid_cert). */

static void
add_valid_cert( ag_pool_t *       self,
                ag_cert_t const * cert ) {
  ulong slot = ag_cert_slot( cert );

  ag_slot_state_add_cert( ag_pool_slot_state( self, slot ), cert );

  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:
  case AG_CERT_TYPE_NOTAR_FALLBACK: {
    fd_hash_t const * block_hash = ag_cert_block_hash( cert );
    ag_block_id_t     block_id   = { .slot = slot, .hash = *block_hash };

    if( cert->kind==AG_CERT_TYPE_NOTAR ) {
      ag_finalization_event_t finalization_event = ag_finality_tracker_mark_notarized( self->finality_tracker, &block_id );
      handle_finalization( self, &finalization_event );
    }

    s2n_waiting_parent_cert_t * child = s2n_waiting_parent_cert_map_ele_remove( self->s2n_waiting_parent_cert_map, &block_id, NULL, self->s2n_waiting_parent_cert_pool );
    if( child ) {
      ulong         child_slot = child->child.slot;
      fd_hash_t     child_hash = child->child.hash;
      s2n_waiting_parent_cert_pool_ele_release( self->s2n_waiting_parent_cert_pool, child );

      int output = ag_slot_state_notify_parent_certified( ag_pool_slot_state( self, child_slot ), &child_hash );
      if( output==AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR ) {
        ag_pool_event_t event = { .kind = AG_POOL_EVENT_SAFE_TO_NOTAR };
        event.inner.safe_to_notar.slot = child_slot;
        event.inner.safe_to_notar.hash = child_hash;
        self->votor_event_channel[ self->votor_event_cnt++ ] = event;
      } else if( output==AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK ) {
        ag_block_id_t child_id = { .slot = child_slot, .hash = child_hash };
        self->repair_channel[ self->repair_cnt++ ] = child_id;
      }
    }

    ag_parent_ready_t new_parents_ready[ AG_PARENT_READY_OUT_MAX ];
    ulong             new_parents_ready_cnt = 0UL;
    ag_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, &block_id, new_parents_ready, &new_parents_ready_cnt );
    send_parent_ready_events( self, new_parents_ready, new_parents_ready_cnt );

    self->repair_channel[ self->repair_cnt++ ] = block_id;
    break;
  }

  case AG_CERT_TYPE_SKIP: {
    ag_parent_ready_t new_parents_ready[ AG_PARENT_READY_OUT_MAX ];
    ulong             new_parents_ready_cnt = 0UL;
    ag_parent_ready_tracker_mark_skipped( self->parent_ready_tracker, slot, new_parents_ready, &new_parents_ready_cnt );
    send_parent_ready_events( self, new_parents_ready, new_parents_ready_cnt );
    break;
  }

  case AG_CERT_TYPE_FAST_FINAL: {
    ag_fast_final_cert_t const * ff_cert = &cert->inner.fast_final;
    ag_block_id_t block_id; block_id.slot = slot; block_id.hash = ff_cert->block_hash;
    ag_finalization_event_t finalization_event = ag_finality_tracker_mark_fast_finalized( self->finality_tracker, &block_id );
    handle_finalization( self, &finalization_event );
    break;
  }

  case AG_CERT_TYPE_FINAL: {
    ag_finalization_event_t finalization_event = ag_finality_tracker_mark_finalized( self->finality_tracker, slot );
    handle_finalization( self, &finalization_event );
    break;
  }

  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }


  ag_pool_event_t event = { .kind = AG_POOL_EVENT_CERT_CREATED, .inner.cert_created = *cert };
  self->votor_event_channel[ self->votor_event_cnt++ ] = event;
}

/* add_cert (PoolImpl::add_cert). */

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert ) {
  ulong slot = ag_cert_slot( cert );

  ulong slot_far_in_future = ag_pool_finalized_slot( self ) + 2UL*AG_ALPENGLOW_SLOTS_PER_EPOCH;
  if( FD_UNLIKELY( slot < ag_pool_first_unpruned_slot( self ) || slot >= slot_far_in_future ) ) return AG_ADD_CERT_ERR_SLOT_OUT_OF_BOUNDS;

  if( FD_UNLIKELY( !ag_cert_check_threshold( cert, self->epoch_info ) ) ) return AG_ADD_CERT_ERR_THRESHOLD_NOT_MET;

  if( FD_UNLIKELY( !ag_cert_check_sig( cert, self->shred_version, self->epoch_info ) ) ) return AG_ADD_CERT_ERR_INVALID_SIGNATURE;

  ag_slot_state_t * slot_state = ag_pool_slot_state( self, slot );
  int duplicate = 0;
  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:          duplicate = ag_slot_state_has_notar_cert        ( slot_state );                                          break;
  case AG_CERT_TYPE_NOTAR_FALLBACK: duplicate = ag_slot_state_is_notar_fallback     ( slot_state, ag_cert_block_hash( cert ) );             break;
  case AG_CERT_TYPE_SKIP:           duplicate = ag_slot_state_has_skip_cert         ( slot_state );                                          break;
  case AG_CERT_TYPE_FAST_FINAL:     duplicate = ag_slot_state_has_fast_finalize_cert( slot_state );                                          break;
  case AG_CERT_TYPE_FINAL:          duplicate = ag_slot_state_has_finalize_cert     ( slot_state );                                          break;
  default:                          FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }

  if( duplicate ) return AG_ADD_CERT_ERR_DUPLICATE;

  /* first arrival of this cert: how far our own vote aggregation toward
     building it had progressed. */
  ulong own_stake   = ag_slot_state_cert_voted_stake( slot_state, cert );
  ulong total_stake = self->epoch_info->total_stake;
  if( FD_LIKELY( total_stake ) ) {
    FD_LOG_NOTICE(( "cert %s slot=%lu received; own vote aggregation at %lu%%",
                    ag_cert_type_to_string( cert->kind ), slot, own_stake*100UL/total_stake ));
  }

  add_valid_cert( self, cert );
  return AG_POOL_SUCCESS;
}

/* add_vote (PoolImpl::add_vote). */

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote ) {

  ulong slot = ag_vote_slot( vote );

  ulong slot_far_in_future = ag_pool_finalized_slot( self ) + 2UL*AG_ALPENGLOW_SLOTS_PER_EPOCH;
  if( slot < ag_pool_first_unpruned_slot( self ) || slot >= slot_far_in_future ) {
    return AG_ADD_VOTE_ERR_SLOT_OUT_OF_BOUNDS;
  }

  ag_epoch_info_t const * epoch = self->epoch_info;
  if( ag_vote_signer( vote ) >= epoch->validator_cnt ) {
    return AG_ADD_VOTE_ERR_UNKNOWN_SIGNER;
  }

  ag_aggsig_pk_t const * pk = &ag_epoch_info_validator( epoch, ag_vote_signer( vote ) )->voting_pubkey;
  if( !ag_vote_check_sig( vote, pk, self->shred_version ) ) {
    return AG_ADD_VOTE_ERR_INVALID_SIGNATURE;
  }

  ulong voter_stake = ag_epoch_info_validator( epoch, ag_vote_signer( vote ) )->stake;
  if( ag_slot_state_check_slashable_offence( ag_pool_slot_state( self, slot ), vote )!=AG_SLASHABLE_NONE ) {
    return AG_ADD_VOTE_ERR_SLASHABLE;
  } else if( ag_slot_state_should_ignore_vote( ag_pool_slot_state( self, slot ), vote ) ) {
    return AG_ADD_VOTE_ERR_DUPLICATE;
  }

  ag_slot_state_outputs_t slot_state_outputs = ag_slot_state_add_vote( ag_pool_slot_state( self, slot ), vote, voter_stake ); /* TODO perf */

  for( ulong i=0UL; i<slot_state_outputs.certs_cnt; i++ ) {
    add_valid_cert( self, &slot_state_outputs.certs[i] );
  }
  for( ulong i=0UL; i<slot_state_outputs.pool_events_cnt; i++ ) {
    self->votor_event_channel[ self->votor_event_cnt++ ] = slot_state_outputs.pool_events[i]; /* TODO perf */
  }
  for( ulong i=0UL; i<slot_state_outputs.block_repairs_cnt; i++ ) {
    self->repair_channel[ self->repair_cnt++ ] = slot_state_outputs.block_repairs[i]; /* TODO perf */
  }

  return AG_POOL_SUCCESS;
}

/* add_block (PoolImpl::add_block). */

void
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id ) {
  FD_TEST( block_id->slot > parent_id->slot );
  ulong             slot        = block_id->slot;
  fd_hash_t const * block_hash  = &block_id->hash;
  ulong             parent_slot = parent_id->slot;
  fd_hash_t const * parent_hash = &parent_id->hash;

  ag_finalization_event_t finalization_event    = ag_finality_tracker_add_parent( self->finality_tracker, block_id, parent_id );
  ag_parent_ready_t       new_parents_ready;
  if( ag_parent_ready_tracker_handle_finalization( self->parent_ready_tracker,
                                                   finalization_event.has_finalized, &finalization_event.finalized,
                                                   finalization_event.implicitly_finalized, finalization_event.if_cnt,
                                                   finalization_event.implicitly_skipped,   finalization_event.is_cnt,
                                                   &new_parents_ready ) )
    send_parent_ready_events( self, &new_parents_ready, 1UL );

  ag_slot_state_notify_parent_known( ag_pool_slot_state( self, slot ), block_hash );

  slot_state_ele_t * parent_ent = slot_state_ele_query( self, parent_slot );
  if( parent_ent && ag_slot_state_is_notar_fallback( parent_ent->slot_state, parent_hash ) ) {
    int status = ag_slot_state_notify_parent_certified( ag_pool_slot_state( self, slot ), block_hash );
    if( status==AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR ) {
      ag_pool_event_t event = { .kind = AG_POOL_EVENT_SAFE_TO_NOTAR };
      event.inner.safe_to_notar = *block_id;
      self->votor_event_channel[ self->votor_event_cnt++ ] = event;
      return;
    } else if( status==AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK ) {
      self->repair_channel[ self->repair_cnt++ ] = *block_id;
      return;
    }
    /* AWAITING_VOTES falls through to the s2n insert */
  }

  s2n_waiting_parent_cert_t * e = s2n_waiting_parent_cert_map_ele_query( self->s2n_waiting_parent_cert_map, parent_id, NULL, self->s2n_waiting_parent_cert_pool );
  if( !e ) {
    FD_TEST( s2n_waiting_parent_cert_pool_free( self->s2n_waiting_parent_cert_pool ) );
    e = s2n_waiting_parent_cert_pool_ele_acquire( self->s2n_waiting_parent_cert_pool );
    e->parent = *parent_id;
    s2n_waiting_parent_cert_map_ele_insert( self->s2n_waiting_parent_cert_map, e, self->s2n_waiting_parent_cert_pool );
  }
  e->child = *block_id;
}

static void
push_cert( ag_cert_t *  certs,
           ulong *      cnt,
           ulong        max,
           int          kind,
           void const * inner,
           ulong        inner_sz ) {
  /* The Rust reference collects the recovery bundle into unbounded Vecs.
     Here the caller supplies a fixed buffer, so a full buffer truncates
     the bundle (reported by ag_pool_recover_from_standstill) rather than
     aborting: recovery re-runs every DELTA_STANDSTILL, so truncation
     costs latency, not correctness. */
  if( FD_UNLIKELY( *cnt >= max ) ) return;
  ag_cert_t * c = &certs[ (*cnt)++ ];
  c->kind = (uint)kind;
  memcpy( &c->inner, inner, inner_sz );
}

static void
push_vote( ag_vote_t *  votes,
           ulong *      cnt,
           ulong        max,
           int          kind,
           void const * inner,
           ulong        inner_sz ) {
  if( FD_UNLIKELY( *cnt >= max ) ) return; /* truncate; see push_cert */
  ag_vote_t * v = &votes[ (*cnt)++ ];
  v->kind = (uint)kind;
  memcpy( &v->inner, inner, inner_sz );
}

/* get_certs (PoolImpl::get_certs). */

static void
get_certs( ag_pool_t * self,
           ulong       from_slot,
           ag_cert_t * certs,
           ulong *     certs_cnt,
           ulong       certs_max ) {
  slot_state_map_t *  map  = self->slot_state_map;
  slot_state_pool_t * pool = self->slot_state_pool;
  for( slot_state_map_iter_t it = slot_state_map_iter_init( map, pool );
       !slot_state_map_iter_done( it, map, pool );
       it = slot_state_map_iter_next( it, map, pool ) ) {
    slot_state_ele_t const * e = slot_state_map_iter_ele_const( it, map, pool );
    if( e->slot < from_slot ) continue;
    ag_slot_state_t const * slot_state = e->slot_state;

    ag_final_cert_t      const * fc  = ag_slot_state_finalize_cert     ( slot_state );
    ag_fast_final_cert_t const * ffc = ag_slot_state_fast_finalize_cert( slot_state );
    ag_notar_cert_t      const * nc  = ag_slot_state_notar_cert        ( slot_state );
    ag_skip_cert_t       const * skc = ag_slot_state_skip_cert         ( slot_state );
    if( fc  ) push_cert( certs, certs_cnt, certs_max, AG_CERT_TYPE_FINAL,      fc,  sizeof(*fc)  );
    if( ffc ) push_cert( certs, certs_cnt, certs_max, AG_CERT_TYPE_FAST_FINAL, ffc, sizeof(*ffc) );
    if( nc  ) push_cert( certs, certs_cnt, certs_max, AG_CERT_TYPE_NOTAR,      nc,  sizeof(*nc)  );
    ulong nf_cnt = ag_slot_state_notar_fallback_cert_cnt( slot_state );
    for( ulong i=0UL; i<nf_cnt; i++ ) {
      ag_notar_fallback_cert_t const * nfc = ag_slot_state_notar_fallback_cert( slot_state, i );
      push_cert( certs, certs_cnt, certs_max, AG_CERT_TYPE_NOTAR_FALLBACK, nfc, sizeof(*nfc) );
    }
    if( skc ) push_cert( certs, certs_cnt, certs_max, AG_CERT_TYPE_SKIP, skc, sizeof(*skc) );
  }
}

/* get_final_certs (PoolImpl::get_final_certs). */

static void
get_final_certs( ag_pool_t * self,
                 ulong       slot,
                 ag_cert_t * certs,
                 ulong *     certs_cnt,
                 ulong       certs_max ) {
  slot_state_ele_t const * e = slot_state_ele_query_const( self, slot );
  if( !e ) return;
  ag_slot_state_t const * slot_state = e->slot_state;

  ag_fast_final_cert_t const * ffc = ag_slot_state_fast_finalize_cert( slot_state );
  if( ffc ) {
    push_cert( certs, certs_cnt, certs_max, AG_CERT_TYPE_FAST_FINAL, ffc, sizeof(*ffc) );
    return;
  }
  ag_final_cert_t const * fc = ag_slot_state_finalize_cert( slot_state );
  ag_notar_cert_t const * nc = ag_slot_state_notar_cert   ( slot_state );
  if( fc && nc ) {
    push_cert( certs, certs_cnt, certs_max, AG_CERT_TYPE_FINAL, fc, sizeof(*fc) );
    push_cert( certs, certs_cnt, certs_max, AG_CERT_TYPE_NOTAR, nc, sizeof(*nc) );
  }
}

/* get_own_votes (PoolImpl::get_own_votes). */

static void
get_own_votes( ag_pool_t * self,
               ulong       from_slot,
               ag_vote_t * votes,
               ulong *     votes_cnt,
               ulong       votes_max ) {
  slot_state_map_t *  map  = self->slot_state_map;
  slot_state_pool_t * pool = self->slot_state_pool;
  for( slot_state_map_iter_t it = slot_state_map_iter_init( map, pool );
       !slot_state_map_iter_done( it, map, pool );
       it = slot_state_map_iter_next( it, map, pool ) ) {
    slot_state_ele_t const * e = slot_state_map_iter_ele_const( it, map, pool );
    if( e->slot < from_slot ) continue;
    ag_slot_state_t const * slot_state = e->slot_state;

    ag_final_vote_t         const * fv  = ag_slot_state_own_finalize_vote     ( slot_state );
    ag_notar_vote_t         const * nv  = ag_slot_state_own_notar_vote        ( slot_state );
    ag_skip_vote_t          const * sv  = ag_slot_state_own_skip_vote         ( slot_state );
    ag_skip_fallback_vote_t const * sfv = ag_slot_state_own_skip_fallback_vote( slot_state );
    if( fv ) push_vote( votes, votes_cnt, votes_max, AG_VOTE_TYPE_FINAL, fv, sizeof(*fv) );
    if( nv ) push_vote( votes, votes_cnt, votes_max, AG_VOTE_TYPE_NOTAR, nv, sizeof(*nv) );
    ag_notar_fallback_vote_t nf_buf[ AG_SLOT_STATE_NF_CERT_MAX ];
    ulong nf_cnt = ag_slot_state_own_notar_fallback_votes( slot_state, nf_buf, AG_SLOT_STATE_NF_CERT_MAX );
    for( ulong i=0UL; i<nf_cnt; i++ ) push_vote( votes, votes_cnt, votes_max, AG_VOTE_TYPE_NOTAR_FALLBACK, &nf_buf[i], sizeof(nf_buf[i]) );
    if( sv  ) push_vote( votes, votes_cnt, votes_max, AG_VOTE_TYPE_SKIP,          sv,  sizeof(*sv)  );
    if( sfv ) push_vote( votes, votes_cnt, votes_max, AG_VOTE_TYPE_SKIP_FALLBACK, sfv, sizeof(*sfv) );
  }
}

/* recover_from_standstill (PoolImpl::recover_from_standstill). */

void
ag_pool_recover_from_standstill( ag_pool_t * self,
                                 ag_cert_t * certs,
                                 ulong *     certs_cnt,
                                 ulong       certs_max,
                                 ag_vote_t * votes,
                                 ulong *     votes_cnt,
                                 ulong       votes_max ) {
  ulong slot = ag_pool_finalized_slot( self );
  *certs_cnt = 0UL;
  *votes_cnt = 0UL;

  get_final_certs( self, slot, certs, certs_cnt, certs_max );

  /* The reference asserts a final cert exists.  It cannot here: a pool
     built rooted at a snapshot slot has that slot as its finalized slot
     with no cert behind it, so bail instead of aborting -- there is
     nothing to recover with until the first real finalization lands. */
  if( FD_UNLIKELY( !*certs_cnt ) ) {
    FD_LOG_WARNING(( "standstill recovery skipped: no final cert for finalized slot %lu", slot ));
    return;
  }

  get_certs    ( self, slot + 1UL, certs, certs_cnt, certs_max );
  get_own_votes( self, slot + 1UL, votes, votes_cnt, votes_max );

  if( FD_UNLIKELY( *certs_cnt==certs_max || *votes_cnt==votes_max ) ) {
    FD_LOG_WARNING(( "standstill recovery bundle at capacity (certs %lu/%lu, votes %lu/%lu); "
                     "bundle may be truncated, recovery re-runs after DELTA_STANDSTILL",
                     *certs_cnt, certs_max, *votes_cnt, votes_max ));
  }

  FD_TEST( self->votor_event_cnt < AG_POOL_VOTOR_EVENT_MAX );
  ag_pool_event_t event = { .kind = AG_POOL_EVENT_STANDSTILL };
  event.inner.standstill = slot + 1UL;
  self->votor_event_channel[ self->votor_event_cnt++ ] = event;
}

void
ag_pool_drain_channels( ag_pool_t * self ) {
  self->votor_event_cnt = 0UL;
  self->repair_cnt      = 0UL;
}

FD_FN_CONST ag_pool_event_t const *
ag_pool_votor_event_channel( ag_pool_t const * self ) {
  return self->votor_event_channel;
}

FD_FN_PURE ulong
ag_pool_votor_event_cnt( ag_pool_t const * self ) {
  return self->votor_event_cnt;
}

FD_FN_CONST ag_block_id_t const *
ag_pool_repair_channel( ag_pool_t const * self ) {
  return self->repair_channel;
}

FD_FN_PURE ulong
ag_pool_repair_cnt( ag_pool_t const * self ) {
  return self->repair_cnt;
}

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self ) {
  return ag_finality_tracker_highest_finalized_slot( self->finality_tracker );
}

FD_FN_PURE ulong
ag_pool_first_unpruned_slot( ag_pool_t const * self ) {
  return ag_finality_tracker_first_unpruned_slot( self->finality_tracker );
}

ag_block_id_t const *
ag_pool_parents_ready( ag_pool_t * self,
                       ulong       slot,
                       ulong *     cnt ) {
  return ag_parent_ready_tracker_parents_ready( self->parent_ready_tracker, slot, cnt );
}

int
ag_pool_wait_for_parent_ready( ag_pool_t *     self,
                               ulong           slot,
                               ag_block_id_t * out_id ) {
  return ag_parent_ready_tracker_wait_for_parent_ready( self->parent_ready_tracker, slot, out_id );
}

int
ag_pool_is_parent_ready( ag_pool_t *           self,
                         ulong                 slot,
                         ag_block_id_t const * parent ) {
  ulong cnt = 0UL;
  ag_block_id_t const * ready = ag_parent_ready_tracker_parents_ready( self->parent_ready_tracker, slot, &cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    if( ag_block_id_eq( &ready[i], parent ) ) return 1;
  }
  return 0;
}

FD_FN_PURE int
ag_pool_has_notar_or_fallback_cert( ag_pool_t const * self,
                                    ulong             slot ) {
  slot_state_ele_t const * e = slot_state_ele_query_const( self, slot );
  if( !e ) return 0;
  return ag_slot_state_has_notar_cert( e->slot_state ) || ag_slot_state_notar_fallback_cert_cnt( e->slot_state )>0UL;
}

int
ag_pool_get_notarized_block( ag_pool_t const * self,
                             ulong             slot,
                             fd_hash_t *       out_hash ) {
  slot_state_ele_t const * e = slot_state_ele_query_const( self, slot );
  if( !e ) return 0;
  ag_notar_cert_t const * nc = ag_slot_state_notar_cert( e->slot_state );
  if( !nc ) return 0;
  if( out_hash ) *out_hash = nc->block_hash;
  return 1;
}

int
ag_pool_get_finalized_block( ag_pool_t const * self,
                             ulong             slot,
                             fd_hash_t *       out_hash ) {
  slot_state_ele_t const * e = slot_state_ele_query_const( self, slot );
  if( !e ) return 0;
  ag_notar_cert_t const * nc = ag_slot_state_notar_cert( e->slot_state );
  if( nc ) {
    if( out_hash ) *out_hash = nc->block_hash;
    return 1;
  }
  ag_fast_final_cert_t const * ffc = ag_slot_state_fast_finalize_cert( e->slot_state );
  if( ffc ) {
    if( out_hash ) *out_hash = ffc->block_hash;
    return 1;
  }
  return 0;
}

ulong
ag_pool_notar_voted_stake( ag_pool_t const * self,
                           ulong             slot ) {
  slot_state_ele_t const * e = slot_state_ele_query_const( self, slot );
  if( !e ) return 0UL;
  fd_hash_t hash;
  if( FD_UNLIKELY( !ag_pool_get_finalized_block( self, slot, &hash ) ) ) return 0UL; /* notar or fast-final cert hash */
  return ag_slot_state_notar_stake( e->slot_state, &hash );
}

FD_FN_PURE int
ag_pool_has_final_cert( ag_pool_t const * self,
                        ulong             slot ) {
  slot_state_ele_t const * e = slot_state_ele_query_const( self, slot );
  if( !e ) return 0;
  return ag_slot_state_has_fast_finalize_cert( e->slot_state ) || ag_slot_state_has_finalize_cert( e->slot_state );
}

FD_FN_PURE int
ag_pool_has_notar_cert( ag_pool_t const * self,
                        ulong             slot ) {
  slot_state_ele_t const * e = slot_state_ele_query_const( self, slot );
  return e && ag_slot_state_has_notar_cert( e->slot_state );
}

FD_FN_PURE int
ag_pool_has_skip_cert( ag_pool_t const * self,
                       ulong             slot ) {
  slot_state_ele_t const * e = slot_state_ele_query_const( self, slot );
  return e && ag_slot_state_has_skip_cert( e->slot_state );
}

FD_FN_PURE int
ag_pool_contains_slot( ag_pool_t const * self,
                       ulong             slot ) {
  return slot_state_ele_query_const( self, slot )!=NULL;
}
