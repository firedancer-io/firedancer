#include "ag_pool.h"
#include "pool/ag_slot_state.h"
#include "pool/ag_finality_tracker.h"
#include "pool/ag_parent_ready_tracker.h"

/* The pool's two outputs.  TODO: nothing drains either one -- the accessor
   pair that did is gone and its replacement is still to be designed -- so
   both fill and then overflow. */

#define QUEUE_NAME votor_event_channel
#define QUEUE_T    ag_pool_event_t
#include "../../util/tmpl/fd_queue_dynamic.c"

#define QUEUE_NAME repair_channel
#define QUEUE_T    ag_block_id_t
#include "../../util/tmpl/fd_queue_dynamic.c"

/* Both channels are sized against slot_max rather than a flat cap: the
   pool only ever emits for a live slot, and pruning bounds those to
   slot_max, so a caller that drains once per pass cannot overflow either
   one.  A flat cap made no such promise -- a long standstill skips every
   slot in the window, and the events that produces scale with the window.

   The per-slot ceilings below are derived from the caps the slot state
   itself enforces, so they move when those do:

     CertCreated  one per cert a slot can hold -- notar, skip, fast-final
                  and final, plus AG_NOTAR_FALLBACK_CERT_MAX
                  notar-fallback
     SafeToNotar  one per distinct block hash, and the slot tracks at most
                  AG_BLOCK_HASH_EQVOC_MAX of them
     SafeToSkip   one, deduped by sent_safe_to_skip
     ParentReady  window starts only, at most one per ready parent, which
                  ag_parent_ready_state caps at AG_PARENT_READY_STATE_CAP

   Standstill is emitted per DELTA_STANDSTILL tick rather than per slot;
   it rides in the slack the window-start terms leave on ordinary slots.

   TODO: these are ceilings, not tight bounds -- worth costing out
   properly before slot_max grows. */

#define AG_POOL_EVENTS_PER_SLOT  ( 4UL + AG_NOTAR_FALLBACK_CERT_MAX + \
                                   AG_BLOCK_HASH_EQVOC_MAX +         \
                                   1UL +                             \
                                   AG_PARENT_READY_STATE_CAP )

/* A repair is requested for a block the slot wants and does not have, so
   it is bounded the same way the hashes are, plus the one the
   notar-fallback cert path asks for unconditionally. */

#define AG_POOL_REPAIRS_PER_SLOT ( AG_BLOCK_HASH_EQVOC_MAX + 1UL )

struct slot_state_ele {
  ulong           slot;       /* key */
  ulong           next;       /* reserved for fd_pool and fd_map_chain */
  ag_slot_state_t slot_state; /* value */
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

struct s2n_waiting_parent_cert_ele {
  ag_block_id_t parent;
  ulong         next;
  ag_block_id_t child;
};
typedef struct s2n_waiting_parent_cert_ele s2n_waiting_parent_cert_ele_t;

#define POOL_NAME s2n_waiting_parent_cert_pool
#define POOL_T    s2n_waiting_parent_cert_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               s2n_waiting_parent_cert_map
#define MAP_ELE_T              s2n_waiting_parent_cert_ele_t
#define MAP_KEY                parent
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_EQ(k0,k1)      (ag_block_id_eq((k0),(k1)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(ag_block_id_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct slot_states {
  slot_state_ele_t * pool;
  slot_state_map_t * map;
};
typedef struct slot_states slot_states_t;

struct s2n_waiting_parent_cert {
  s2n_waiting_parent_cert_ele_t * pool;
  s2n_waiting_parent_cert_map_t * map;
};
typedef struct s2n_waiting_parent_cert s2n_waiting_parent_cert_t;

struct __attribute__((aligned(128UL))) ag_pool {
  slot_states_t *             slot_states;
  ag_parent_ready_tracker_t * parent_ready_tracker;
  ag_finality_tracker_t *     finality_tracker;
  s2n_waiting_parent_cert_t * s2n_waiting_parent_cert;

  ag_epoch_info_t const * curr_epoch_info;
  ulong                   curr_epoch_rank;
  ulong                   curr_epoch_slot;
  ag_epoch_info_t const * next_epoch_info;
  ulong                   next_epoch_rank;
  ulong                   next_epoch_slot;

  ag_pool_event_t * votor_event_channel; /* fd_queue_dynamic */
  ag_block_id_t *   repair_channel;      /* fd_queue_dynamic */

  /* Receive buffers for the APIs that answer with an array.  They belong
     to the pool rather than the stack of whoever calls: the counts a
     parent-ready walk can produce are bounded but not small, and the same
     buffer serves every call site because the pool is single threaded and
     nothing survives the call that filled it.  Contents are live only
     until the next call that writes the same one. */

  struct {
    ag_pool_event_t *   pool_events;
    ulong               pool_event_cnt;
    ag_parent_ready_t * parent_readys;
    ulong               parent_ready_cnt;
  } scratch;
};

FD_FN_CONST char const *
ag_pool_strerror( int err ) {
  switch( err ) {
  case AG_POOL_SUCCESS:                return "success";
  case AG_POOL_ERR_SLOT_OUT_OF_BOUNDS: return "slot is either too old or too far in the future";
  case AG_POOL_ERR_DUPLICATE:          return "duplicate vote or cert";
  case AG_POOL_ERR_SLASHABLE:          return "vote constitutes a slashable offence";
  case AG_POOL_ERR_HASH_CAPACITY:      return "slot already tracks the maximum distinct block hashes or notar-fallback certs";
  default:                             return "unknown";
  }
}

ulong
ag_pool_align( void ) {
  return alignof(ag_pool_t);
}

ulong
ag_pool_footprint( ulong slot_max ) {
  if( FD_UNLIKELY( slot_max==0UL ) ) return 0UL;

  ulong s2n_max = AG_BLOCKID_MAX( slot_max ); /* one entry per block id the window can hold */

  /* chain_cnt_est clamps and rounds to a power of two itself, so the
     element counts feed it directly. */

  ulong slot_state_chain_cnt              = slot_state_map_chain_cnt_est             ( slot_max    );
  ulong s2n_waiting_parent_cert_chain_cnt = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );

  ulong event_max  = AG_POOL_EVENTS_PER_SLOT *slot_max;
  ulong repair_max = AG_POOL_REPAIRS_PER_SLOT*slot_max;

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
    FD_LAYOUT_INIT,
      alignof(ag_pool_t),                   sizeof(ag_pool_t)                                                           ),
      alignof(slot_states_t),               sizeof(slot_states_t)                                                       ),
      slot_state_pool_align(),              slot_state_pool_footprint( slot_max )                                       ),
      slot_state_map_align(),               slot_state_map_footprint ( slot_state_chain_cnt )                           ),
      ag_parent_ready_tracker_align(),      ag_parent_ready_tracker_footprint( slot_max )                               ),
      ag_finality_tracker_align(),          ag_finality_tracker_footprint( slot_max )                      ),
      alignof(s2n_waiting_parent_cert_t),   sizeof(s2n_waiting_parent_cert_t)                                           ),
      s2n_waiting_parent_cert_pool_align(), s2n_waiting_parent_cert_pool_footprint( s2n_max )                       ),
      s2n_waiting_parent_cert_map_align(),  s2n_waiting_parent_cert_map_footprint ( s2n_waiting_parent_cert_chain_cnt ) ),
      votor_event_channel_align(),          votor_event_channel_footprint( event_max )                                  ),
      repair_channel_align(),               repair_channel_footprint     ( repair_max )                                 ),
      alignof(ag_pool_event_t),             sizeof(ag_pool_event_t)  *event_max                                         ),
      alignof(ag_parent_ready_t),           sizeof(ag_parent_ready_t)*AG_PARENT_READY_PER_SLOT*slot_max                           ),
    ag_pool_align() );
}

void *
ag_pool_new( void * mem,
             ulong  slot_max,
             ulong  seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = ag_pool_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }
  fd_memset( mem, 0, footprint );

  ulong s2n_max                           = AG_BLOCKID_MAX( slot_max );
  ulong slot_state_chain_cnt              = slot_state_map_chain_cnt_est             ( slot_max    );
  ulong s2n_waiting_parent_cert_chain_cnt = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );

  ulong event_max  = AG_POOL_EVENTS_PER_SLOT *slot_max;
  ulong repair_max = AG_POOL_REPAIRS_PER_SLOT*slot_max;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  ag_pool_t * pool                         = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_pool_t),                   sizeof(ag_pool_t)                                                           );
  void *      slot_states                  = FD_SCRATCH_ALLOC_APPEND( l, alignof(slot_states_t),               sizeof(slot_states_t)                                                       );
  void *      slot_state_pool              = FD_SCRATCH_ALLOC_APPEND( l, slot_state_pool_align(),              slot_state_pool_footprint( slot_max )                                       );
  void *      slot_state_map               = FD_SCRATCH_ALLOC_APPEND( l, slot_state_map_align(),               slot_state_map_footprint ( slot_state_chain_cnt )                           );
  void *      parent_ready_tracker         = FD_SCRATCH_ALLOC_APPEND( l, ag_parent_ready_tracker_align(),      ag_parent_ready_tracker_footprint( slot_max )                               );
  void *      finality_tracker             = FD_SCRATCH_ALLOC_APPEND( l, ag_finality_tracker_align(),          ag_finality_tracker_footprint( slot_max )                      );
  void *      s2n_waiting_parent_cert      = FD_SCRATCH_ALLOC_APPEND( l, alignof(s2n_waiting_parent_cert_t),   sizeof(s2n_waiting_parent_cert_t)                                           );
  void *      s2n_waiting_parent_cert_pool = FD_SCRATCH_ALLOC_APPEND( l, s2n_waiting_parent_cert_pool_align(), s2n_waiting_parent_cert_pool_footprint( s2n_max )                       );
  void *      s2n_waiting_parent_cert_map  = FD_SCRATCH_ALLOC_APPEND( l, s2n_waiting_parent_cert_map_align(),  s2n_waiting_parent_cert_map_footprint ( s2n_waiting_parent_cert_chain_cnt ) );
  void *      votor_event_channel          = FD_SCRATCH_ALLOC_APPEND( l, votor_event_channel_align(),          votor_event_channel_footprint( event_max )                                  );
  void *      repair_channel               = FD_SCRATCH_ALLOC_APPEND( l, repair_channel_align(),               repair_channel_footprint     ( repair_max )                                 );
  void *      pool_event_scratch           = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_pool_event_t),             sizeof(ag_pool_event_t)  *event_max                                         );
  void *      parent_ready_scratch         = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_parent_ready_t),           sizeof(ag_parent_ready_t)*AG_PARENT_READY_PER_SLOT*slot_max                           );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_pool_align() ) == (ulong)mem + footprint );

  pool->curr_epoch_info = NULL;
  pool->curr_epoch_rank = 0UL;
  pool->curr_epoch_slot = ULONG_MAX;
  pool->next_epoch_info = NULL;
  pool->next_epoch_rank = 0UL;
  pool->next_epoch_slot = ULONG_MAX;

  pool->slot_states       = (slot_states_t *)slot_states;
  pool->slot_states->pool = slot_state_pool_join( slot_state_pool_new( slot_state_pool, slot_max                   ) );
  pool->slot_states->map  = slot_state_map_join ( slot_state_map_new ( slot_state_map,  slot_state_chain_cnt, seed ) );

  pool->parent_ready_tracker = ag_parent_ready_tracker_join( ag_parent_ready_tracker_new( parent_ready_tracker, slot_max, seed ) );

  pool->finality_tracker = ag_finality_tracker_join( ag_finality_tracker_new( finality_tracker, slot_max, seed ) );

  pool->s2n_waiting_parent_cert       = (s2n_waiting_parent_cert_t *)s2n_waiting_parent_cert;
  pool->s2n_waiting_parent_cert->pool = s2n_waiting_parent_cert_pool_join( s2n_waiting_parent_cert_pool_new( s2n_waiting_parent_cert_pool, s2n_max                            ) );
  pool->s2n_waiting_parent_cert->map  = s2n_waiting_parent_cert_map_join ( s2n_waiting_parent_cert_map_new ( s2n_waiting_parent_cert_map,  s2n_waiting_parent_cert_chain_cnt, seed ) );

  pool->votor_event_channel = votor_event_channel_join( votor_event_channel_new( votor_event_channel, event_max  ) );
  pool->repair_channel      = repair_channel_join     ( repair_channel_new     ( repair_channel,      repair_max ) );

  pool->scratch.pool_events      = (ag_pool_event_t *)pool_event_scratch;
  pool->scratch.pool_event_cnt   = 0UL;
  pool->scratch.parent_readys    = (ag_parent_ready_t *)parent_ready_scratch;
  pool->scratch.parent_ready_cnt = 0UL;

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

static ag_slot_state_t *
slot_state( ag_pool_t * self,
            ulong       slot ) {
  slot_state_ele_t * ele = slot_state_map_ele_query( self->slot_states->map, &slot, NULL, self->slot_states->pool );
  if( FD_LIKELY( ele ) ) return &ele->slot_state;

  ag_epoch_info_t const * info = fd_ptr_if  ( slot>=self->next_epoch_slot, self->next_epoch_info, self->curr_epoch_info );
  ulong                   rank = fd_ulong_if( slot>=self->next_epoch_slot, self->next_epoch_rank, self->curr_epoch_rank );

  ele       = slot_state_pool_ele_acquire( self->slot_states->pool );
  ele->slot = slot;
  ag_slot_state_init( &ele->slot_state, slot, info, rank );
  slot_state_map_ele_insert( self->slot_states->map, ele, self->slot_states->pool );
  return &ele->slot_state;
}

/* prune sheds every slot state the finality tracker has decided past, and
   takes the parent-ready tracker down to the same watermark.  The tracker
   advances its own: mark_finalized recurses through ancestors, so by the
   time a slot is finalized everything below it is classified implicitly
   finalized or implicitly skipped and the walk reaches it.  Nothing
   external has to force the root forward.

   The sweep walks slot numbers rather than the slot-state map, and the
   parent-ready tracker's root is where it left off last time -- prune
   below sets that root to this same watermark on its way out.  So the two
   together bound the walk to the slots decided since the last call. */

static void
prune( ag_pool_t * self ) {
  ulong first_unpruned_slot = ag_finality_tracker_first_unpruned_slot( self->finality_tracker );
  for( ulong slot = ag_parent_ready_tracker_root( self->parent_ready_tracker ); slot<first_unpruned_slot; slot++ ) {
    slot_state_ele_t * ele = slot_state_map_ele_remove( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    if( FD_LIKELY( ele ) ) slot_state_pool_ele_release( self->slot_states->pool, ele );
  }
  ag_parent_ready_tracker_prune( self->parent_ready_tracker, first_unpruned_slot );
}

static void
handle_finalization( ag_pool_t *                     self,
                     ag_finalization_event_t const * event ) {
  ag_parent_ready_t new_parents_ready = ag_parent_ready_tracker_handle_finalization( self->parent_ready_tracker, event );
  if( new_parents_ready.slot!=ULONG_MAX ) {
    ag_pool_event_t event = { .kind = AG_POOL_EVENT_PARENT_READY, .inner.parent_ready = { .slot = new_parents_ready.slot, .parent = new_parents_ready.parent } };
    votor_event_channel_push( self->votor_event_channel, event );
  }
  prune( self );
}

static void
add_valid_cert( ag_pool_t *       self,
                ag_cert_t const * cert ) {

  ulong slot = ag_cert_slot( cert );

  ag_slot_state_add_cert( slot_state( self, slot ), cert );

  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:
  case AG_CERT_TYPE_NOTAR_FALLBACK: {
    fd_hash_t const * block_hash = ag_cert_block_hash( cert );
    ag_block_id_t     block_id   = { .slot = slot, .hash = *block_hash };
    if( FD_LIKELY( cert->kind==AG_CERT_TYPE_NOTAR ) ) {
      ag_finalization_event_t finalization_event = ag_finality_tracker_mark_notarized( self->finality_tracker, &block_id );
      handle_finalization( self, &finalization_event );
    }

    s2n_waiting_parent_cert_ele_t * child = s2n_waiting_parent_cert_map_ele_remove( self->s2n_waiting_parent_cert->map, &block_id, NULL, self->s2n_waiting_parent_cert->pool );
    if( FD_LIKELY( child ) ) {
      ulong         child_slot = child->child.slot;
      fd_hash_t     child_hash = child->child.hash;
      s2n_waiting_parent_cert_pool_ele_release( self->s2n_waiting_parent_cert->pool, child );

      int output = ag_slot_state_notify_parent_certified( slot_state( self, child_slot ), &child_hash );
      switch( output ) {
      case -1: repair_channel_push( self->repair_channel, (ag_block_id_t){ .slot = child_slot, .hash = child_hash } ); break;
      case  0: break; /* no-op, awaiting more votes for SafeToNotar */
      case  1: votor_event_channel_push( self->votor_event_channel, (ag_pool_event_t){ .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .inner.safe_to_notar = { .slot = child_slot, .hash = child_hash } } ); break;
      }
    }

    ulong                     ready_cnt;
    ag_parent_ready_t const * readys = ag_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, &block_id, &ready_cnt );
    for( ulong i=0UL; i<ready_cnt; i++ ) {
      ag_parent_ready_t const * ready = &readys[i];
      FD_TEST( ag_slot_is_start_of_window( ready->slot ) );
      ag_pool_event_t event = { .kind = AG_POOL_EVENT_PARENT_READY };
      event.inner.parent_ready.slot   = ready->slot;
      event.inner.parent_ready.parent = ready->parent;
      votor_event_channel_push( self->votor_event_channel, event );
    }

    repair_channel_push( self->repair_channel, block_id );
    break;
  }

  case AG_CERT_TYPE_SKIP: {
    ulong                     ready_cnt;
    ag_parent_ready_t const * readys = ag_parent_ready_tracker_mark_skipped( self->parent_ready_tracker, slot, &ready_cnt );
    for( ulong i=0UL; i<ready_cnt; i++ ) {
      ag_parent_ready_t const * ready = &readys[i];
      FD_TEST( ag_slot_is_start_of_window( ready->slot ) );
      ag_pool_event_t event = { .kind = AG_POOL_EVENT_PARENT_READY };
      event.inner.parent_ready.slot   = ready->slot;
      event.inner.parent_ready.parent = ready->parent;
      votor_event_channel_push( self->votor_event_channel, event );
    }
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
  votor_event_channel_push( self->votor_event_channel, event );
}

void
ag_pool_set_epoch( ag_pool_t *             self,
                   ag_epoch_info_t const * next_epoch_info,
                   ulong                   next_epoch_rank,
                   ulong                   next_epoch_slot ) {

  if( FD_UNLIKELY( !self->curr_epoch_info ) ) {
    self->curr_epoch_info = next_epoch_info;
    self->curr_epoch_rank = next_epoch_rank;
    self->curr_epoch_slot = next_epoch_slot;
  } else {
    self->curr_epoch_info = self->next_epoch_info;
    self->curr_epoch_slot = self->next_epoch_slot;
    self->curr_epoch_rank = self->next_epoch_rank;
    self->next_epoch_info = next_epoch_info;
    self->next_epoch_rank = next_epoch_rank;
    self->next_epoch_slot = next_epoch_slot;
  }
}

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert ) {

  ulong slot = ag_cert_slot( cert );

  ulong slot_far_in_future = ag_pool_finalized_slot( self ) + 2UL*AG_SLOTS_PER_EPOCH;
  if( FD_UNLIKELY( slot < ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) || slot >= slot_far_in_future ) ) return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;

  ag_slot_state_t * state = slot_state( self, slot );
  int duplicate = 0;
  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:          duplicate = state->certificates.notar.slot!=ULONG_MAX;                                                   break;
  case AG_CERT_TYPE_NOTAR_FALLBACK: duplicate = ag_slot_state_is_notar_fallback     ( state, ag_cert_block_hash( cert ) );                   break;
  case AG_CERT_TYPE_SKIP:           duplicate = state->certificates.skip.slot!=ULONG_MAX;                                                    break;
  case AG_CERT_TYPE_FAST_FINAL:     duplicate = state->certificates.fast_finalize.slot!=ULONG_MAX;                                           break;
  case AG_CERT_TYPE_FINAL:          duplicate = state->certificates.finalize.slot!=ULONG_MAX;                                                break;
  default:                          FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }

  if( duplicate ) return AG_POOL_ERR_DUPLICATE;

  if( FD_UNLIKELY( !ag_slot_state_cert_fits( state, cert ) ) ) return AG_POOL_ERR_HASH_CAPACITY;

  /* first arrival of this cert: how far our own vote aggregation toward
     building it had progressed. */
  ulong own_stake   = ag_slot_state_cert_voted_stake( state, cert );
  ulong total_stake = state->epoch_info->total_stake;
  if( FD_LIKELY( total_stake ) ) {
    FD_LOG_NOTICE(( "cert %s slot=%lu received; own vote aggregation at %lu%%",
                    ag_cert_type_to_string( cert->kind ), slot, own_stake*100UL/total_stake ));
  }

  add_valid_cert( self, cert );
  return AG_POOL_SUCCESS;
}

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote ) {

  ulong slot = ag_vote_slot( vote );

  ulong slot_far_in_future = ag_pool_finalized_slot( self ) + 2UL*AG_SLOTS_PER_EPOCH;
  if( slot < ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) || slot >= slot_far_in_future ) {
    return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;
  }

  ulong             voter       = ag_vote_signer( vote );
  ulong             voter_stake = ag_epoch_info_validator( fd_ptr_if( slot >= self->next_epoch_slot, self->next_epoch_info, self->curr_epoch_info ), voter )->stake;
  ag_slot_state_t * _slot_state = slot_state( self, slot );

  if( FD_UNLIKELY( ag_slot_state_check_slashable_offence( _slot_state, vote )!=AG_SLASHABLE_NONE ) ) {
    return AG_POOL_ERR_SLASHABLE;
  } else if( FD_UNLIKELY( ag_slot_state_should_ignore_vote( _slot_state, vote ) ) ) {
    /* TODO event AG_SLOT_STATE_IGNORE_REASON */
    return AG_POOL_ERR_DUPLICATE;
  }

  ag_slot_state_outputs_t slot_state_outputs = ag_slot_state_add_vote( _slot_state, vote, voter_stake );

  for( ulong i=0UL; i<slot_state_outputs.certs_cnt; i++ ) {
    add_valid_cert( self, &slot_state_outputs.certs[i] );
  }
  for( ulong i=0UL; i<slot_state_outputs.pool_events_cnt; i++ ) {
    votor_event_channel_push( self->votor_event_channel, slot_state_outputs.pool_events[i] ); /* TODO perf */
  }
  for( ulong i=0UL; i<slot_state_outputs.block_repairs_cnt; i++ ) {
    repair_channel_push( self->repair_channel, slot_state_outputs.block_repairs[i] ); /* TODO perf */
  }
  return AG_POOL_SUCCESS;
}

void
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id ) {

  ulong             slot        = block_id->slot;
  fd_hash_t const * block_hash  = &block_id->hash;
  ulong             parent_slot = parent_id->slot;
  fd_hash_t const * parent_hash = &parent_id->hash;

  ag_finalization_event_t finalization_event = ag_finality_tracker_add_parent( self->finality_tracker, block_id, parent_id );
  ag_parent_ready_t       new_parents_ready  = ag_parent_ready_tracker_handle_finalization( self->parent_ready_tracker, &finalization_event );
  if( new_parents_ready.slot!=ULONG_MAX ) {
    ag_pool_event_t event = { .kind = AG_POOL_EVENT_PARENT_READY, .inner.parent_ready = { .slot = new_parents_ready.slot, .parent = new_parents_ready.parent } };
    votor_event_channel_push( self->votor_event_channel, event );
  }

  ag_slot_state_notify_parent_known( slot_state( self, slot ), block_hash );
  slot_state_ele_t * _parent_state = slot_state_map_ele_query( self->slot_states->map, &parent_slot, NULL, self->slot_states->pool );
  ag_slot_state_t *  parent_state  = _parent_state ? &_parent_state->slot_state : NULL;
  if( FD_LIKELY( parent_state && ag_slot_state_is_notar_fallback_or_stronger( parent_state, parent_hash ) ) ) {
    int output = ag_slot_state_notify_parent_certified( slot_state( self, slot ), block_hash );
    switch( output ) {
    case -1: repair_channel_push( self->repair_channel, (ag_block_id_t){ .slot = slot, .hash = *block_hash } ); break;
    case  0: /* no-op, awaiting more votes for SafeToNotar */
    case  1: votor_event_channel_push( self->votor_event_channel, (ag_pool_event_t){ .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .inner.safe_to_notar = { .slot = slot, .hash = *block_hash } } ); break;
    }
  }

  s2n_waiting_parent_cert_ele_t * ele = s2n_waiting_parent_cert_map_ele_query( self->s2n_waiting_parent_cert->map, parent_id, NULL, self->s2n_waiting_parent_cert->pool );
  if( FD_UNLIKELY( !ele ) ) {
    ele         = s2n_waiting_parent_cert_pool_ele_acquire( self->s2n_waiting_parent_cert->pool );
    ele->parent = *parent_id;
    s2n_waiting_parent_cert_map_ele_insert( self->s2n_waiting_parent_cert->map, ele, self->s2n_waiting_parent_cert->pool );
  }
  ele->child = *block_id;
}

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

  { /* the finalized slot's own final certs: fast-final wins outright,
       otherwise the final + notar pair */
    slot_state_ele_t const * e = slot_state_map_ele_query_const( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    if( e ) {
      ag_slot_certificates_t const * cs = &e->slot_state.certificates;
      if( cs->fast_finalize.slot!=ULONG_MAX ) {
        if( *certs_cnt<certs_max ) {
          ag_cert_t * c = &certs[ (*certs_cnt)++ ];
          c->kind             = AG_CERT_TYPE_FAST_FINAL;
          c->inner.fast_final = cs->fast_finalize;
        }
      } else {
        if( cs->finalize.slot!=ULONG_MAX && cs->notar.slot!=ULONG_MAX ) {
          if( *certs_cnt<certs_max ) {
            ag_cert_t * c = &certs[ (*certs_cnt)++ ];
            c->kind        = AG_CERT_TYPE_FINAL;
            c->inner.final = cs->finalize;
          }
          if( *certs_cnt<certs_max ) {
            ag_cert_t * c = &certs[ (*certs_cnt)++ ];
            c->kind        = AG_CERT_TYPE_NOTAR;
            c->inner.notar = cs->notar;
          }
        }
      }
    }
  }

  /* A final cert for the finalized slot is not guaranteed: a pool built
     rooted at a snapshot slot has that slot as its finalized slot with no
     cert behind it, so bail instead of aborting -- there is nothing to
     recover with until the first real finalization lands. */
  if( FD_UNLIKELY( !*certs_cnt ) ) {
    FD_LOG_WARNING(( "standstill recovery skipped: no final cert for finalized slot %lu", slot ));
    return;
  }

  { /* every cert above the finalized slot */
    slot_state_map_t * map  = self->slot_states->map;
    slot_state_ele_t * pool = self->slot_states->pool;
    for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
         !slot_state_map_iter_done( iter, map, pool );
         iter = slot_state_map_iter_next( iter, map, pool ) ) {
      slot_state_ele_t const * e = slot_state_map_iter_ele_const( iter, map, pool );
      if( e->slot < slot + 1UL ) continue;
      ag_slot_certificates_t const * cs = &e->slot_state.certificates;

      if( cs->finalize.slot!=ULONG_MAX && *certs_cnt<certs_max ) {
        ag_cert_t * c = &certs[ (*certs_cnt)++ ];
        c->kind        = AG_CERT_TYPE_FINAL;
        c->inner.final = cs->finalize;
      }
      if( cs->fast_finalize.slot!=ULONG_MAX && *certs_cnt<certs_max ) {
        ag_cert_t * c = &certs[ (*certs_cnt)++ ];
        c->kind             = AG_CERT_TYPE_FAST_FINAL;
        c->inner.fast_final = cs->fast_finalize;
      }
      if( cs->notar.slot!=ULONG_MAX && *certs_cnt<certs_max ) {
        ag_cert_t * c = &certs[ (*certs_cnt)++ ];
        c->kind        = AG_CERT_TYPE_NOTAR;
        c->inner.notar = cs->notar;
      }
      for( ulong i=0UL; i<cs->notar_fallback_cnt; i++ ) {
        if( *certs_cnt<certs_max ) {
          ag_cert_t * c = &certs[ (*certs_cnt)++ ];
          c->kind                 = AG_CERT_TYPE_NOTAR_FALLBACK;
          c->inner.notar_fallback = cs->notar_fallback[i];
        }
      }
      if( cs->skip.slot!=ULONG_MAX && *certs_cnt<certs_max ) {
        ag_cert_t * c = &certs[ (*certs_cnt)++ ];
        c->kind       = AG_CERT_TYPE_SKIP;
        c->inner.skip = cs->skip;
      }
    }
  }

  { /* every vote we ourselves cast above the finalized slot */
    slot_state_map_t * map  = self->slot_states->map;
    slot_state_ele_t * pool = self->slot_states->pool;
    for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
         !slot_state_map_iter_done( iter, map, pool );
         iter = slot_state_map_iter_next( iter, map, pool ) ) {
      slot_state_ele_t const * e = slot_state_map_iter_ele_const( iter, map, pool );
      if( e->slot < slot + 1UL ) continue;
      /* Our own votes are just the entries at own_rank, which is how the
         reference reads them out of the same vectors. */
      ag_slot_votes_t const * sv = &e->slot_state.votes;
      ulong                   o  = e->slot_state.own_rank;

      if( sv->finalize[ o ].slot!=ULONG_MAX && *votes_cnt<votes_max ) {
        ag_vote_t * v = &votes[ (*votes_cnt)++ ];
        v->kind        = AG_VOTE_TYPE_FINAL;
        v->inner.final = sv->finalize[ o ];
      }
      if( sv->notar[ o ].slot!=ULONG_MAX && *votes_cnt<votes_max ) {
        ag_vote_t * v = &votes[ (*votes_cnt)++ ];
        v->kind        = AG_VOTE_TYPE_NOTAR;
        v->inner.notar = sv->notar[ o ];
      }
      for( ulong i=0UL; i<sv->notar_fallback_cnt[ o ] && *votes_cnt<votes_max; i++ ) {
        ag_vote_t * v = &votes[ (*votes_cnt)++ ];
        v->kind                 = AG_VOTE_TYPE_NOTAR_FALLBACK;
        v->inner.notar_fallback = sv->notar_fallback[ o ][ i ];
      }
      if( sv->skip[ o ].slot!=ULONG_MAX && *votes_cnt<votes_max ) {
        ag_vote_t * v = &votes[ (*votes_cnt)++ ];
        v->kind       = AG_VOTE_TYPE_SKIP;
        v->inner.skip = sv->skip[ o ];
      }
      if( sv->skip_fallback[ o ].slot!=ULONG_MAX && *votes_cnt<votes_max ) {
        ag_vote_t * v = &votes[ (*votes_cnt)++ ];
        v->kind                = AG_VOTE_TYPE_SKIP_FALLBACK;
        v->inner.skip_fallback = sv->skip_fallback[ o ];
      }
    }
  }

  if( FD_UNLIKELY( *certs_cnt==certs_max || *votes_cnt==votes_max ) ) {
    FD_LOG_WARNING(( "standstill recovery bundle at capacity (certs %lu/%lu, votes %lu/%lu); "
                     "bundle may be truncated, recovery re-runs after DELTA_STANDSTILL",
                     *certs_cnt, certs_max, *votes_cnt, votes_max ));
  }

  ag_pool_event_t event = { .kind = AG_POOL_EVENT_STANDSTILL };
  event.inner.standstill = slot + 1UL;
  votor_event_channel_push( self->votor_event_channel, event );
}

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self ) {
  return ag_finality_tracker_highest_finalized_slot( self->finality_tracker );
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
