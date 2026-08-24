#include "ag_pool.h"
#include "ag_slot_state.h"
#include "ag_finality_tracker.h"
#include "ag_parent_ready_tracker.h"

#define QUEUE_NAME pool_channel
#define QUEUE_T    ag_event_pool_t
#include "../../util/tmpl/fd_queue_dynamic.c"

#define QUEUE_NAME repair_channel
#define QUEUE_T    ag_event_repair_t
#include "../../util/tmpl/fd_queue_dynamic.c"

struct slot_state_ele {
  ulong           slot;
  ulong           next;
  ag_slot_state_t slot_state;
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

  ag_event_pool_t *   pool_events;
  ag_event_repair_t * repair_events;

  ulong seq;

  ulong slot_max;

  struct {
    ag_cert_t *         certs;
    ulong               cert_cnt;
    ag_vote_t *         votes;
    ulong               vote_cnt;
    ag_parent_ready_t * parent_readys;
    ulong               parent_ready_cnt;
    ag_event_pool_t *   pool_events;
    ulong               pool_event_cnt;
  } scratch;
};

ulong
ag_pool_align( void ) {
  return alignof(ag_pool_t);
}

ulong
ag_pool_footprint( ulong slot_max ) {
  if( FD_UNLIKELY( slot_max<AG_SLOTS_PER_WINDOW ) ) return 0UL;

  ulong s2n_max                           = slot_max*AG_EQVOC_BLOCK_HASH_MAX;
  ulong slot_state_chain_cnt              = slot_state_map_chain_cnt_est             ( slot_max    );
  ulong s2n_waiting_parent_cert_chain_cnt = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );

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
      pool_channel_align(),                 pool_channel_footprint( slot_max )                                          ),
      repair_channel_align(),               repair_channel_footprint( slot_max )                                        ),
      alignof(ag_cert_t),                   sizeof(ag_cert_t)        *slot_max                                         ),
      alignof(ag_vote_t),                   sizeof(ag_vote_t)        *slot_max                                         ),
      alignof(ag_parent_ready_t),           sizeof(ag_parent_ready_t)*slot_max                                         ),
      alignof(ag_event_pool_t),             sizeof(ag_event_pool_t)  *slot_max                                         ),
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

  ulong s2n_max                           = slot_max*AG_EQVOC_BLOCK_HASH_MAX;
  ulong slot_state_chain_cnt              = slot_state_map_chain_cnt_est             ( slot_max    );
  ulong s2n_waiting_parent_cert_chain_cnt = s2n_waiting_parent_cert_map_chain_cnt_est( s2n_max );


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
  void *      pool_channel                 = FD_SCRATCH_ALLOC_APPEND( l, pool_channel_align(),                 pool_channel_footprint( slot_max )                                          );
  void *      repair_channel               = FD_SCRATCH_ALLOC_APPEND( l, repair_channel_align(),               repair_channel_footprint( slot_max )                                        );
  void *      cert_scratch                 = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_cert_t),                   sizeof(ag_cert_t)        *slot_max                                         );
  void *      vote_scratch                 = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_vote_t),                   sizeof(ag_vote_t)        *slot_max                                         );
  void *      parent_ready_scratch         = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_parent_ready_t),           sizeof(ag_parent_ready_t)*slot_max                                         );
  void *      pool_event_scratch           = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_event_pool_t),             sizeof(ag_event_pool_t)  *slot_max                                         );
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

  pool->pool_events   = pool_channel_join  ( pool_channel_new  ( pool_channel,   slot_max ) );
  pool->repair_events = repair_channel_join( repair_channel_new( repair_channel, slot_max ) );

  pool->slot_max = slot_max;

  pool->seq = 0UL;

  pool->scratch.certs            = (ag_cert_t *)cert_scratch;
  pool->scratch.cert_cnt         = 0UL;
  pool->scratch.votes            = (ag_vote_t *)vote_scratch;
  pool->scratch.vote_cnt         = 0UL;
  pool->scratch.parent_readys    = (ag_parent_ready_t *)parent_ready_scratch;
  pool->scratch.parent_ready_cnt = 0UL;
  pool->scratch.pool_events      = (ag_event_pool_t *)pool_event_scratch;
  pool->scratch.pool_event_cnt   = 0UL;

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

static void
handle_finalization( ag_pool_t *                     self,
                     ag_finalization_event_t const * event ) {
  ag_parent_ready_t new_parents_ready = ag_parent_ready_tracker_handle_finalization( self->parent_ready_tracker, event, self->scratch.parent_readys, &self->scratch.parent_ready_cnt );
  if( new_parents_ready.slot!=ULONG_MAX ) {
    ag_event_pool_t event = { .seq = self->seq++, .kind = AG_EVENT_POOL_PARENT_READY, .parent_ready = { .slot = new_parents_ready.slot, .parent = new_parents_ready.parent } };
    pool_channel_push( self->pool_events, event );
  }
  ulong first_unpruned_slot = ag_finality_tracker_first_unpruned_slot( self->finality_tracker );
  for( ulong slot = self->parent_ready_tracker->root; slot<first_unpruned_slot; slot++ ) {
    slot_state_ele_t * ele = slot_state_map_ele_remove( self->slot_states->map, &slot, NULL, self->slot_states->pool );
    if( FD_LIKELY( ele ) ) slot_state_pool_ele_release( self->slot_states->pool, ele );
  }
  ag_parent_ready_tracker_prune( self->parent_ready_tracker, first_unpruned_slot );
}

static void
add_valid_cert( ag_pool_t *       self,
                ag_cert_t const * cert ) {
  ulong slot = ag_cert_slot( cert );

  ag_slot_state_add_cert( slot_state( self, slot ), cert );

  switch( cert->kind ) {
  case AG_CERT_TYPE_NOTAR:
  case AG_CERT_TYPE_NOTAR_FALLBACK: {
    uchar const * block_hash = ag_cert_block_hash( cert );
    ag_block_id_t block_id   = ag_block_id( slot, block_hash );
    if( FD_LIKELY( cert->kind==AG_CERT_TYPE_NOTAR ) ) {
      ag_finalization_event_t finalization_event = ag_finality_tracker_mark_notarized( self->finality_tracker, &block_id );
      handle_finalization( self, &finalization_event );
    }

    s2n_waiting_parent_cert_ele_t * child = s2n_waiting_parent_cert_map_ele_remove( self->s2n_waiting_parent_cert->map, &block_id, NULL, self->s2n_waiting_parent_cert->pool );
    if( FD_LIKELY( child ) ) {
      ag_block_id_t child_id = child->child; /* copy before the release below */
      s2n_waiting_parent_cert_pool_ele_release( self->s2n_waiting_parent_cert->pool, child );

      int output = ag_slot_state_notify_parent_certified( slot_state( self, child_id.slot ), child_id.hash );
      switch( output ) {
      case -1: repair_channel_push( self->repair_events, (ag_event_repair_t){ .seq = self->seq++, .block = child_id } ); break;
      case  0: break;
      case  1: pool_channel_push( self->pool_events, (ag_event_pool_t){ .seq = self->seq++, .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = child_id } ); break;
      }
    }

    ag_parent_ready_tracker_mark_notar_fallback( self->parent_ready_tracker, &block_id, self->scratch.parent_readys, &self->scratch.parent_ready_cnt );
    ag_parent_ready_t const * readys    = self->scratch.parent_readys;
    ulong                     ready_cnt = self->scratch.parent_ready_cnt;
    for( ulong i=0UL; i<ready_cnt; i++ ) {
      ag_parent_ready_t const * ready = &readys[i];
      FD_TEST( ag_is_start_of_window( ready->slot ) ); /* readiness is granted at window starts */
      ag_event_pool_t event = { .seq = self->seq++, .kind = AG_EVENT_POOL_PARENT_READY };
      event.parent_ready.slot   = ready->slot;
      event.parent_ready.parent = ready->parent;
      pool_channel_push( self->pool_events, event );
    }

    repair_channel_push( self->repair_events, (ag_event_repair_t){ .seq = self->seq++, .block = block_id } );
    break;
  }

  case AG_CERT_TYPE_SKIP: {
    ag_parent_ready_tracker_mark_skipped( self->parent_ready_tracker, slot, self->scratch.parent_readys, &self->scratch.parent_ready_cnt );
    ag_parent_ready_t const * readys    = self->scratch.parent_readys;
    ulong                     ready_cnt = self->scratch.parent_ready_cnt;
    for( ulong i=0UL; i<ready_cnt; i++ ) {
      ag_parent_ready_t const * ready = &readys[i];
      FD_TEST( ag_is_start_of_window( ready->slot ) ); /* readiness is granted at window starts */
      ag_event_pool_t event = { .seq = self->seq++, .kind = AG_EVENT_POOL_PARENT_READY };
      event.parent_ready.slot   = ready->slot;
      event.parent_ready.parent = ready->parent;
      pool_channel_push( self->pool_events, event );
    }
    break;
  }

  case AG_CERT_TYPE_FAST_FINAL: {
    ag_fast_final_cert_t const * ff_cert = &cert->inner.fast_final;
    ag_block_id_t block_id = ag_block_id( slot, ff_cert->block_hash );
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

  ag_event_pool_t event = { .seq = self->seq++, .kind = AG_EVENT_POOL_CERT_CREATED, .cert_created = *cert };
  pool_channel_push( self->pool_events, event );
}

void
ag_pool_advance_epoch( ag_pool_t *             self,
                       ag_epoch_info_t const * epoch_info,
                       ulong                   epoch_rank,
                       ulong                   epoch_slot ) {
  if( FD_UNLIKELY( !self->curr_epoch_info ) ) {
    self->curr_epoch_info = epoch_info;
    self->curr_epoch_rank = epoch_rank;
    self->curr_epoch_slot = epoch_slot;
  } else if( FD_UNLIKELY( !self->next_epoch_info ) ) {
    self->next_epoch_info = epoch_info;
    self->next_epoch_rank = epoch_rank;
    self->next_epoch_slot = epoch_slot;
  } else {
    self->curr_epoch_info = self->next_epoch_info;
    self->curr_epoch_slot = self->next_epoch_slot;
    self->curr_epoch_rank = self->next_epoch_rank;
    self->next_epoch_info = epoch_info;
    self->next_epoch_rank = epoch_rank;
    self->next_epoch_slot = epoch_slot;
  }
}

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert ) {

  ulong slot = ag_cert_slot( cert );

  ulong slot_far_in_future = ag_pool_finalized_slot( self ) + 2UL*AG_SLOTS_PER_EPOCH;
  if( FD_UNLIKELY( slot<ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) || slot>=slot_far_in_future ) ) return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;

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
  if( FD_UNLIKELY( duplicate ) ) return AG_POOL_ERR_DUPLICATE;

  add_valid_cert( self, cert );
  return AG_POOL_SUCCESS;
}

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote ) {
  ulong slot = ag_vote_slot( vote );

  ulong slot_far_in_future = ag_pool_finalized_slot( self ) + 2UL*AG_SLOTS_PER_EPOCH;
  if( slot<ag_finality_tracker_first_unpruned_slot( self->finality_tracker ) || slot>=slot_far_in_future ) {
    return AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;
  }

  ulong             voter       = ag_vote_signer( vote );
  ulong             voter_stake = ag_epoch_info_validator( fd_ptr_if( slot >= self->next_epoch_slot, self->next_epoch_info, self->curr_epoch_info ), voter )->stake;
  ag_slot_state_t * slot_state_ = slot_state( self, slot );

  if( FD_UNLIKELY( ag_slot_state_check_slashable_offence( slot_state_, vote )!=AG_SLASHABLE_NONE ) ) {
    return AG_POOL_ERR_SLASHABLE;
  } else if( FD_UNLIKELY( ag_slot_state_should_ignore_vote( slot_state_, vote ) ) ) {
    return AG_POOL_ERR_DUPLICATE;
  } else if( FD_UNLIKELY( !ag_slot_state_vote_fits( slot_state_, vote ) ) ) {
    return AG_POOL_ERR_HASH_CAPACITY;
  }

  ag_slot_state_outputs_t slot_state_outputs = ag_slot_state_add_vote( slot_state_, vote, voter_stake );

  for( ulong i=0UL; i<slot_state_outputs.certs_cnt; i++ ) {
    add_valid_cert( self, &slot_state_outputs.certs[i] );
  }
  for( ulong i=0UL; i<slot_state_outputs.pool_events_cnt; i++ ) {
    ag_event_pool_t event = slot_state_outputs.pool_events[i];
    event.seq             = self->seq++;
    pool_channel_push( self->pool_events, event );
  }
  for( ulong i=0UL; i<slot_state_outputs.block_repairs_cnt; i++ ) {
    repair_channel_push( self->repair_events, (ag_event_repair_t){ .seq = self->seq++, .block = slot_state_outputs.block_repairs[i] } );
  }
  return AG_POOL_SUCCESS;
}

void
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id ) {

  ulong         slot        = block_id->slot;
  uchar const * block_hash  = block_id->hash;
  ulong         parent_slot = parent_id->slot;
  uchar const * parent_hash = parent_id->hash;

  ag_finalization_event_t finalization_event = ag_finality_tracker_add_parent( self->finality_tracker, block_id, parent_id );
  ag_parent_ready_t       new_parents_ready  = ag_parent_ready_tracker_handle_finalization( self->parent_ready_tracker, &finalization_event, self->scratch.parent_readys, &self->scratch.parent_ready_cnt );
  if( FD_UNLIKELY( new_parents_ready.slot!=ULONG_MAX ) ) {
    ag_event_pool_t event = { .seq = self->seq++, .kind = AG_EVENT_POOL_PARENT_READY, .parent_ready = { .slot = new_parents_ready.slot, .parent = new_parents_ready.parent } };
    pool_channel_push( self->pool_events, event );
  }

  ag_slot_state_notify_parent_known( slot_state( self, slot ), block_hash );
  slot_state_ele_t * parent_state_ = slot_state_map_ele_query( self->slot_states->map, &parent_slot, NULL, self->slot_states->pool );
  ag_slot_state_t *  parent_state  = parent_state_ ? &parent_state_->slot_state : NULL;
  if( FD_LIKELY( parent_state && ag_slot_state_is_notar_fallback_or_stronger( parent_state, parent_hash ) ) ) {
    int output = ag_slot_state_notify_parent_certified( slot_state( self, slot ), block_hash );
    switch( output ) {
    case -1: repair_channel_push( self->repair_events, (ag_event_repair_t){ .seq = self->seq++, .block = *block_id } ); return;
    case  0: break;
    case  1: pool_channel_push( self->pool_events, (ag_event_pool_t){ .seq = self->seq++, .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = *block_id } ); return;
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
ag_pool_recover_from_standstill( ag_pool_t * self ) {
  ag_cert_t * certs     = self->scratch.certs;
  ulong       certs_cnt = 0UL;
  ag_vote_t * votes     = self->scratch.votes;
  ulong       votes_cnt = 0UL;

  /* 1. collect our finalized slot's cert */

  ulong                    finalized_slot  = ag_pool_finalized_slot( self );
  slot_state_ele_t const * finalized_state = slot_state_map_ele_query_const( self->slot_states->map, &finalized_slot, NULL, self->slot_states->pool );
  if( FD_LIKELY( finalized_state ) ) {
    ag_slot_certificates_t const * fast_final_or_final = &finalized_state->slot_state.certificates;
    if( FD_LIKELY( fast_final_or_final->fast_finalize.slot!=ULONG_MAX ) ) {
      certs[ certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_TYPE_FAST_FINAL, .inner.fast_final = fast_final_or_final->fast_finalize };
    } else if( fast_final_or_final->finalize.slot!=ULONG_MAX && fast_final_or_final->notar.slot!=ULONG_MAX ) {
      certs[ certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_TYPE_FINAL,      .inner.final      = fast_final_or_final->finalize      };
      certs[ certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_TYPE_NOTAR,      .inner.notar      = fast_final_or_final->notar         };
    }
  }

  /* 2. collect every cert and own vote for slots > finalized slot */

  slot_state_map_t * map  = self->slot_states->map;
  slot_state_ele_t * pool = self->slot_states->pool;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, pool );
       !slot_state_map_iter_done( iter, map, pool );
       iter = slot_state_map_iter_next( iter, map, pool ) ) {
    slot_state_ele_t const * ele = slot_state_map_iter_ele_const( iter, map, pool );
    if( ele->slot<=finalized_slot ) continue;

    ag_slot_certificates_t const * sc = &ele->slot_state.certificates;
    if( sc->finalize.slot     !=ULONG_MAX && certs_cnt<self->slot_max ) certs[ certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_TYPE_FINAL,      .inner.final      = sc->finalize      };
    if( sc->fast_finalize.slot!=ULONG_MAX && certs_cnt<self->slot_max ) certs[ certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_TYPE_FAST_FINAL, .inner.fast_final = sc->fast_finalize };
    if( sc->notar.slot        !=ULONG_MAX && certs_cnt<self->slot_max ) certs[ certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_TYPE_NOTAR,      .inner.notar      = sc->notar         };
    if( sc->skip.slot         !=ULONG_MAX && certs_cnt<self->slot_max ) certs[ certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_TYPE_SKIP,       .inner.skip       = sc->skip          };
    for( ulong i=0UL; i<sc->notar_fallback_cnt && certs_cnt<self->slot_max; i++ ) {
      certs[ certs_cnt++ ] = (ag_cert_t){ .kind = AG_CERT_TYPE_NOTAR_FALLBACK, .inner.notar_fallback = sc->notar_fallback[i] };
    }

    ag_slot_votes_t const * sv   = &ele->slot_state.votes;
    ulong                   rank = ele->slot_state.own_rank;
    if( sv->finalize     [rank].slot!=ULONG_MAX && votes_cnt<self->slot_max ) votes[ votes_cnt++ ] = (ag_vote_t){ .kind = AG_VOTE_TYPE_FINAL,         .inner.final         = sv->finalize     [rank] };
    if( sv->notar        [rank].slot!=ULONG_MAX && votes_cnt<self->slot_max ) votes[ votes_cnt++ ] = (ag_vote_t){ .kind = AG_VOTE_TYPE_NOTAR,         .inner.notar         = sv->notar        [rank] };
    if( sv->skip         [rank].slot!=ULONG_MAX && votes_cnt<self->slot_max ) votes[ votes_cnt++ ] = (ag_vote_t){ .kind = AG_VOTE_TYPE_SKIP,          .inner.skip          = sv->skip         [rank] };
    if( sv->skip_fallback[rank].slot!=ULONG_MAX && votes_cnt<self->slot_max ) votes[ votes_cnt++ ] = (ag_vote_t){ .kind = AG_VOTE_TYPE_SKIP_FALLBACK, .inner.skip_fallback = sv->skip_fallback[rank] };
    for( ulong i=0UL; i<sv->notar_fallback_cnt[rank] && votes_cnt<self->slot_max; i++ ) {
      votes[ votes_cnt++ ] = (ag_vote_t){ .kind = AG_VOTE_TYPE_NOTAR_FALLBACK, .inner.notar_fallback = sv->notar_fallback[rank][i] };
    }
  }

  /* 3. push out a standstill pool event containing the above */

  self->scratch.cert_cnt = certs_cnt;
  self->scratch.vote_cnt = votes_cnt;
  pool_channel_push( self->pool_events, (ag_event_pool_t){ .seq = self->seq++, .kind = AG_EVENT_POOL_STANDSTILL, .standstill = { .slot = finalized_slot + 1UL, .certs = certs, .cert_cnt = certs_cnt, .votes = votes, .vote_cnt = votes_cnt } } );
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

ag_block_id_t
ag_pool_wait_for_parent_ready( ag_pool_t * self,
                               ulong       slot ) {
  return ag_parent_ready_tracker_wait_for_parent_ready( self->parent_ready_tracker, slot );
}

int
ag_pool_poll_pool_event( ag_pool_t *       self,
                         ag_event_pool_t * event ) {
  if( FD_LIKELY( pool_channel_empty( self->pool_events ) ) ) return 0;
  *event = pool_channel_pop( self->pool_events );
  return 1;
}

int
ag_pool_poll_repair_event( ag_pool_t *         self,
                           ag_event_repair_t * event ) {
  if( FD_LIKELY( repair_channel_empty( self->repair_events ) ) ) return 0;
  *event = repair_channel_pop( self->repair_events );
  return 1;
}
