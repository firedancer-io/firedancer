#include "ag_parent_ready_tracker.h"

ulong
ag_parent_ready_tracker_align( void ) {
  return alignof(ag_parent_ready_tracker_t);
}

ulong
ag_parent_ready_tracker_footprint( ulong slot_max ) {
  slot_max = fd_ulong_pow2_up( slot_max );
  ulong chain_cnt = ag_parent_ready_state_map_chain_cnt_est( slot_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(ag_parent_ready_tracker_t), sizeof(ag_parent_ready_tracker_t)                            ),
      ag_parent_ready_state_pool_align(), ag_parent_ready_state_pool_footprint( slot_max )             ),
      ag_parent_ready_state_map_align(),  ag_parent_ready_state_map_footprint ( chain_cnt )            ),
    ag_parent_ready_tracker_align() );
}

void *
ag_parent_ready_tracker_new( void * shmem,
                             ulong  slot_max,
                             ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, ag_parent_ready_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = ag_parent_ready_tracker_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  slot_max = fd_ulong_pow2_up( slot_max );

  fd_memset( shmem, 0, footprint );

  ulong chain_cnt = ag_parent_ready_state_map_chain_cnt_est( slot_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  ag_parent_ready_tracker_t * tracker    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_parent_ready_tracker_t), sizeof(ag_parent_ready_tracker_t)                 );
  void *                      state_pool = FD_SCRATCH_ALLOC_APPEND( l, ag_parent_ready_state_pool_align(), ag_parent_ready_state_pool_footprint( slot_max )  );
  void *                      state_map  = FD_SCRATCH_ALLOC_APPEND( l, ag_parent_ready_state_map_align(),  ag_parent_ready_state_map_footprint ( chain_cnt )           );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_parent_ready_tracker_align() ) == (ulong)shmem + footprint );

  tracker->root        = ULONG_MAX;
  tracker->states.pool = ag_parent_ready_state_pool_join( ag_parent_ready_state_pool_new( state_pool, slot_max        ) );
  tracker->states.map  = ag_parent_ready_state_map_join ( ag_parent_ready_state_map_new ( state_map,  chain_cnt, seed ) );


  return shmem;
}

ag_parent_ready_tracker_t *
ag_parent_ready_tracker_join( void * shtracker ) {
  ag_parent_ready_tracker_t * tracker = (ag_parent_ready_tracker_t *)shtracker;

  if( FD_UNLIKELY( !tracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)tracker, ag_parent_ready_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }

  return tracker;
}

void *
ag_parent_ready_tracker_leave( ag_parent_ready_tracker_t const * tracker ) {
  if( FD_UNLIKELY( !tracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  return (void *)tracker;
}

void *
ag_parent_ready_tracker_delete( void * shtracker ) {
  if( FD_UNLIKELY( !shtracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtracker, ag_parent_ready_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }

  return shtracker;
}

static void
add_to_ready( ag_parent_ready_state_t * state,
              ag_block_id_t const *     id ) {
  if( FD_LIKELY( !state->is_ready ) ) {
    state->ready_ids[ 0 ] = *id;
    state->ready_id_cnt   = 1UL;
    state->is_ready       = 1;
  } else {
    state->ready_ids[ state->ready_id_cnt++ ] = *id;
  }
}

static ag_block_id_t
wait_for_parent_ready( ag_parent_ready_state_t * state ) {
  if( FD_UNLIKELY( state->is_ready ) ) {
    ag_block_id_t arg_min = state->ready_ids[0];
    for( ulong i=1; i<state->ready_id_cnt; i++ ) {
      ag_block_id_t const * id = &state->ready_ids[i];
      if( FD_UNLIKELY( id->slot<arg_min.slot ) || ( id->slot==arg_min.slot && 0>memcmp( id->hash, arg_min.hash, sizeof(ag_block_hash_t) ) ) ) {
        arg_min = *id;
      }
    }
    return arg_min;
  } else {
    return (ag_block_id_t){ .slot = ULONG_MAX };
  }
}

static ag_parent_ready_state_t *
slot_state( ag_parent_ready_tracker_t * self,
            ulong                       slot ) {
  ag_parent_ready_state_t * state = ag_parent_ready_state_map_ele_query( self->states.map, &slot, NULL, self->states.pool );
  if( FD_LIKELY( state ) ) return state;

  ag_parent_ready_state_t * pool = self->states.pool;
  if( FD_UNLIKELY( !ag_parent_ready_state_pool_free( pool ) ) ) {
    FD_LOG_ERR(( "parent_ready_tracker: state pool exhausted (slot_max exceeded) at slot %lu", slot ));
  }

  state                      = ag_parent_ready_state_pool_ele_acquire( pool );
  state->slot                = slot;
  state->skip                = 0;
  state->notar_fallbacks_cnt = (uchar)0;
  state->is_ready            = 0;
  state->ready_id_cnt        = 0UL;
  ag_parent_ready_state_map_ele_insert( self->states.map, state, pool );
  return state;
}

void
ag_parent_ready_tracker_mark_notar_fallback( ag_parent_ready_tracker_t * self,
                                             ag_block_id_t const *       id,
                                             ag_parent_ready_t *         newly_certified,
                                             ulong *                     newly_certified_cnt ) {
  *newly_certified_cnt = 0UL;

  ulong         slot = id->slot;
  uchar const * hash = id->hash;

  if( FD_UNLIKELY( slot < self->root ) ) return;

  ag_parent_ready_state_t * state = slot_state( self, slot );
  for( ulong i=0UL; i<state->notar_fallbacks_cnt; i++ ) {
    if( FD_UNLIKELY( 0==memcmp( state->notar_fallbacks[i], hash, sizeof(ag_block_hash_t) ) ) ) return;
  }
  memcpy( state->notar_fallbacks[ state->notar_fallbacks_cnt++ ], hash, sizeof(ag_block_hash_t) );

  for( ulong slot_=slot+1; ; slot_++ ) {
    ag_parent_ready_state_t * state_ = slot_state( self, slot_ );
    if( ag_is_start_of_window( slot_ ) ) {
      add_to_ready( state_, id );
      newly_certified[ *newly_certified_cnt ].slot   = slot_;
      newly_certified[ *newly_certified_cnt ].parent = *id;
      (*newly_certified_cnt)++;
    }
    if( !state_->skip ) break;
  }
  return;
}

void
ag_parent_ready_tracker_mark_skipped( ag_parent_ready_tracker_t * self,
                                      ulong                       marked_slot,
                                      ag_parent_ready_t *         newly_certified,
                                      ulong *                     newly_certified_cnt ) {
  *newly_certified_cnt = 0UL;

  if( FD_UNLIKELY( marked_slot < self->root ) ) return;
  ag_parent_ready_state_t * state = slot_state( self, marked_slot );
  if( FD_UNLIKELY( state->skip ) ) return;
  state->skip = 1;

  ag_block_id_t potential_parents[ AG_SLOTS_PER_WINDOW*AG_NOTAR_FALLBACK_CERT_MAX ];
  ulong         potential_cnt = 0UL;

  for( ulong slot=marked_slot; slot>=fd_ulong_max( ag_first_slot_in_window( marked_slot ), self->root ); slot-- ) {
    ag_parent_ready_state_t * state = slot_state( self, slot );

    if( FD_LIKELY( slot!=marked_slot ) ) {
      for( ulong i=0UL; i<state->notar_fallbacks_cnt; i++ ) {
        FD_TEST( potential_cnt < AG_SLOTS_PER_WINDOW*AG_NOTAR_FALLBACK_CERT_MAX );
        potential_parents[ potential_cnt ] = ag_block_id( slot, state->notar_fallbacks[i] );
        potential_cnt++;
      }
    }

    if( !state->skip ) break;

    for( ulong i=0UL; i<state->ready_id_cnt; i++ ) {
      FD_TEST( potential_cnt < AG_SLOTS_PER_WINDOW*AG_NOTAR_FALLBACK_CERT_MAX );
      potential_parents[ potential_cnt ] = state->ready_ids[i];
      potential_cnt++;
    }
  }

  for( ulong s=marked_slot+1UL; ; s++ ) {
    ag_parent_ready_state_t * fstate = slot_state( self, s );
    if( ag_is_start_of_window( s ) ) {
      for( ulong i=0UL; i<potential_cnt; i++ ) {
        add_to_ready( fstate, &potential_parents[i] );
        FD_TEST( *newly_certified_cnt < ag_parent_ready_state_pool_max( self->states.pool ) ); /* caller sized for slot_max */
        newly_certified[ *newly_certified_cnt ].slot   = s;
        newly_certified[ *newly_certified_cnt ].parent = potential_parents[i];
        (*newly_certified_cnt)++;
      }
    }
    if( !fstate->skip ) break;
  }
  return;
}

static void
keep_highest( ag_parent_ready_t *       best,
              ag_parent_ready_t const * ready,
              ulong                     ready_cnt ) {
  for( ulong i=0UL; i<ready_cnt; i++ ) {
    if( best->slot==ULONG_MAX || ready[i].slot>=best->slot ) *best = ready[i];
  }
}

ag_parent_ready_t
ag_parent_ready_tracker_handle_finalization( ag_parent_ready_tracker_t *     self,
                                             ag_finalization_event_t const * event,
                                             ag_parent_ready_t *             newly_certified,
                                             ulong *                         newly_certified_cnt ) {
  ag_parent_ready_t best;
  fd_memset( &best, 0, sizeof(ag_parent_ready_t) );
  best.slot = ULONG_MAX;

  if( event->finalized.slot!=ULONG_MAX ) {
    ag_parent_ready_tracker_mark_notar_fallback( self, &event->finalized, newly_certified, newly_certified_cnt );
    keep_highest( &best, newly_certified, *newly_certified_cnt );
  }

  for( ulong j=0UL; j<event->implicitly_finalized_cnt; j++ ) {
    ag_parent_ready_tracker_mark_notar_fallback( self, &event->implicitly_finalized[j], newly_certified, newly_certified_cnt );
    keep_highest( &best, newly_certified, *newly_certified_cnt );
  }

  for( ulong j=0UL; j<event->implicitly_skipped_cnt; j++ ) {
    ag_parent_ready_tracker_mark_skipped( self, event->implicitly_skipped[j], newly_certified, newly_certified_cnt );
    keep_highest( &best, newly_certified, *newly_certified_cnt );
  }

  return best;
}

ag_block_id_t const *
ag_parent_ready_tracker_parents_ready( ag_parent_ready_tracker_t * self,
                                       ulong                       slot,
                                       ulong *                     cnt ) {
  ag_parent_ready_state_t * state = ag_parent_ready_state_map_ele_query( self->states.map, &slot, NULL, self->states.pool );
  if( FD_UNLIKELY( !state ) ) { *cnt = 0UL; return NULL; }
  *cnt = state->ready_id_cnt;
  return state->ready_ids;
}

ag_block_id_t
ag_parent_ready_tracker_wait_for_parent_ready( ag_parent_ready_tracker_t * self,
                                               ulong                       slot ) {
  ag_parent_ready_state_t * state = ag_parent_ready_state_map_ele_query( self->states.map, &slot, NULL, self->states.pool );
  if( FD_UNLIKELY( !state ) ) return (ag_block_id_t){ .slot = ULONG_MAX };
  return wait_for_parent_ready( state );
}

void
ag_parent_ready_tracker_prune( ag_parent_ready_tracker_t * self,
                               ulong                       new_root ) {
  ag_parent_ready_state_map_t * map  = self->states.map;
  ag_parent_ready_state_t *     pool = self->states.pool;
  for( ulong slot=self->root; slot<new_root; slot++ ) {
    ag_parent_ready_state_t * ele = ag_parent_ready_state_map_ele_remove( map, &slot, NULL, pool );
    if( FD_LIKELY( ele ) ) ag_parent_ready_state_pool_ele_release( pool, ele );
  }
  self->root = new_root;
}
