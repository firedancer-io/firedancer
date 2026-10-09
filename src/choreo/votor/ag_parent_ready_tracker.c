#include "ag_parent_ready_tracker.h"

ulong
ag_parent_ready_tracker_align( void ) {
  return alignof(ag_parent_ready_tracker_t);
}

ulong
ag_parent_ready_tracker_footprint( ulong slot_max ) {
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

FD_FN_PURE static int
block_id_lt( ag_block_id_t const * a,
             ag_block_id_t const * b ) {
  return a->slot<b->slot || ( a->slot==b->slot && 0>memcmp( a->hash, b->hash, sizeof(ag_block_hash_t) ) );
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

  state                       = ag_parent_ready_state_pool_ele_acquire( pool );
  state->slot                 = slot;
  state->skip                 = 0;
  state->notar_fallbacks_cnt  = (uchar)0;
  state->b_lo                 = ULONG_MAX;
  state->parent_ready_lo.slot = ULONG_MAX;
  state->ready                = 0;
  ag_parent_ready_state_map_ele_insert( self->states.map, state, pool );
  return state;
}

static void
add_to_ready( ag_parent_ready_tracker_t * self,
              ulong                       slot,
              ag_block_id_t const *       parent,
              ag_parent_ready_t *         newly_certified,
              ulong *                     newly_certified_cnt ) {
  ag_parent_ready_state_t * state = slot_state( self, slot );
  if( FD_LIKELY( state->parent_ready_lo.slot==ULONG_MAX || block_id_lt( parent, &state->parent_ready_lo ) ) ) state->parent_ready_lo = *parent;
  if( FD_UNLIKELY( state->ready ) ) return;
  state->ready = 1;
  newly_certified[ *newly_certified_cnt ].slot   = slot;
  newly_certified[ *newly_certified_cnt ].parent = state->parent_ready_lo;
  (*newly_certified_cnt)++;
}

void
ag_parent_ready_tracker_mark_notar_fallback( ag_parent_ready_tracker_t * self,
                                             ag_block_id_t const *       block_id,
                                             ag_parent_ready_t *         newly_certified,
                                             ulong *                     newly_certified_cnt ) {
  *newly_certified_cnt = 0UL;

  ulong         slot = block_id->slot;
  uchar const * hash = block_id->hash;

  if( FD_UNLIKELY( slot < self->root ) ) return;

  ag_parent_ready_state_t * state = slot_state( self, slot );
  for( ulong i=0UL; i<state->notar_fallbacks_cnt; i++ ) {
    if( FD_UNLIKELY( 0==memcmp( state->notar_fallbacks[i], hash, sizeof(ag_block_hash_t) ) ) ) return;
  }
  FD_CHECK_CRIT( state->notar_fallbacks_cnt<AG_NOTAR_FALLBACK_CERT_MAX, "consensus safety violation" ); /* Lemma 48 */
  memcpy( state->notar_fallbacks[ state->notar_fallbacks_cnt++ ], hash, sizeof(ag_block_hash_t) );

  for( ulong s=slot+1UL; ; s++ ) {
    self->highest_parent_ready = fd_ulong_max( self->highest_parent_ready, s );
    if( FD_UNLIKELY( ag_is_start_of_window( s ) ) ) add_to_ready( self, s, block_id, newly_certified, newly_certified_cnt );
    ag_parent_ready_state_t const * next = ag_parent_ready_state_map_ele_query_const( self->states.map, &s, NULL, self->states.pool );
    if( FD_LIKELY( !next || !next->skip ) ) break;
  }
}

void
ag_parent_ready_tracker_mark_skipped( ag_parent_ready_tracker_t * self,
                                      ulong                       skipped_slot,
                                      ag_parent_ready_t *         newly_certified,
                                      ulong *                     newly_certified_cnt ) {
  *newly_certified_cnt = 0UL;

  if( FD_UNLIKELY( skipped_slot < self->root ) ) return;
  ag_parent_ready_state_t * state = slot_state( self, skipped_slot );
  if( FD_UNLIKELY( state->skip ) ) return;
  state->skip = 1;

  /* The skip extends every chain ending at skipped_slot down to b_lo,
     the highest slot below skipped_slot that is not skipped.  The
     newly ready parents are the notar fallbacks of [b_lo,skipped_slot).
     Setting b_lo makes all of them ready, and parent_ready_lo is set to
     their minimum. */

  ag_block_id_t parent = { .slot = ULONG_MAX };
  ulong         b_lo   = ULONG_MAX;
  ulong         first  = ag_first_slot_in_window( skipped_slot );
  for( ulong slot=skipped_slot; slot>fd_ulong_max( first, self->root ); ) {
    slot--;
    ag_parent_ready_state_t const * prev = ag_parent_ready_state_map_ele_query_const( self->states.map, &slot, NULL, self->states.pool );
    for( ulong i=0UL; prev && i<prev->notar_fallbacks_cnt; i++ ) {
      ag_block_id_t nf = ag_block_id( slot, prev->notar_fallbacks[i] );
      if( parent.slot==ULONG_MAX || block_id_lt( &nf, &parent ) ) parent = nf;
    }
    if( FD_LIKELY( !prev || !prev->skip ) ) { b_lo = slot; break; }
  }
  if( FD_UNLIKELY( b_lo==ULONG_MAX ) ) { /* [first,skipped_slot) all skipped, the window start knows the rest */
    ag_parent_ready_state_t const * start = ag_parent_ready_state_map_ele_query_const( self->states.map, &first, NULL, self->states.pool );
    b_lo = ( start && start->b_lo!=ULONG_MAX ) ? start->b_lo : fd_ulong_sat_sub( first, 1UL );
    if( start && start->parent_ready_lo.slot!=ULONG_MAX && start->parent_ready_lo.slot>=self->root && ( parent.slot==ULONG_MAX || block_id_lt( &start->parent_ready_lo, &parent ) ) ) parent = start->parent_ready_lo;
  }

  for( ulong s=skipped_slot+1UL; ; s++ ) {
    if( FD_LIKELY( parent.slot!=ULONG_MAX ) ) self->highest_parent_ready = fd_ulong_max( self->highest_parent_ready, s );
    if( FD_UNLIKELY( ag_is_start_of_window( s ) ) ) {
      slot_state( self, s )->b_lo = b_lo;
      if( FD_LIKELY( parent.slot!=ULONG_MAX ) ) add_to_ready( self, s, &parent, newly_certified, newly_certified_cnt );
    }
    ag_parent_ready_state_t const * next = ag_parent_ready_state_map_ele_query_const( self->states.map, &s, NULL, self->states.pool );
    if( FD_LIKELY( !next || !next->skip ) ) break;
  }
}

void
ag_parent_ready_tracker_delivered( ag_parent_ready_tracker_t * self,
                                   ulong                       slot ) {
  ag_parent_ready_state_t * state = ag_parent_ready_state_map_ele_query( self->states.map, &slot, NULL, self->states.pool );
  if( FD_LIKELY( state ) ) state->ready = 0;
}

ulong
ag_parent_ready_tracker_parents_ready( ag_parent_ready_tracker_t const * self,
                                       ulong                             slot,
                                       ag_block_id_t *                   out,
                                       ulong                             out_max ) {
  if( FD_UNLIKELY( !ag_is_start_of_window( slot ) || slot<=self->root ) ) return 0UL;

  ag_parent_ready_state_t const * state = ag_parent_ready_state_map_ele_query_const( self->states.map, &slot, NULL, self->states.pool );
  ulong                           b_lo  = ( state && state->b_lo!=ULONG_MAX ) ? state->b_lo : slot-1UL;

  ulong cnt = 0UL;
  for( ulong s=fd_ulong_max( b_lo, self->root ); s<slot; s++ ) {
    ag_parent_ready_state_t const * nf = ag_parent_ready_state_map_ele_query_const( self->states.map, &s, NULL, self->states.pool );
    for( ulong i=0UL; nf && i<nf->notar_fallbacks_cnt; i++ ) {
      if( FD_LIKELY( cnt<out_max ) ) out[ cnt ] = ag_block_id( s, nf->notar_fallbacks[i] );
      cnt++;
    }
  }
  return cnt;
}

int
ag_parent_ready_tracker_is_parent_ready( ag_parent_ready_tracker_t const * self,
                                         ulong                             slot,
                                         ag_block_id_t const *             parent ) {
  if( FD_UNLIKELY( !ag_is_start_of_window( slot ) || parent->slot>=slot || parent->slot<self->root ) ) return 0;

  ag_parent_ready_state_t const * state = ag_parent_ready_state_map_ele_query_const( self->states.map, &slot, NULL, self->states.pool );
  ulong                           b_lo  = ( state && state->b_lo!=ULONG_MAX ) ? state->b_lo : slot-1UL;
  if( FD_UNLIKELY( parent->slot<b_lo ) ) return 0;

  ag_parent_ready_state_t const * nf = ag_parent_ready_state_map_ele_query_const( self->states.map, &parent->slot, NULL, self->states.pool );
  for( ulong i=0UL; nf && i<nf->notar_fallbacks_cnt; i++ ) {
    if( FD_UNLIKELY( 0==memcmp( nf->notar_fallbacks[i], parent->hash, sizeof(ag_block_hash_t) ) ) ) return 1;
  }
  return 0;
}

ag_block_id_t
ag_parent_ready_tracker_wait_for_parent_ready( ag_parent_ready_tracker_t const * self,
                                               ulong                             slot ) {
  ag_parent_ready_state_t const * state = ag_parent_ready_state_map_ele_query_const( self->states.map, &slot, NULL, self->states.pool );
  if( FD_UNLIKELY( !state || state->parent_ready_lo.slot<self->root ) ) return (ag_block_id_t){ .slot = ULONG_MAX };
  return state->parent_ready_lo;
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

  /* A window start whose lowest ready parent was pruned takes the
     lowest of its ready parents [b_lo,slot) still retained. */

  for( ag_parent_ready_state_map_iter_t iter = ag_parent_ready_state_map_iter_init( map, pool );
                                              !ag_parent_ready_state_map_iter_done( iter, map, pool );
                                        iter = ag_parent_ready_state_map_iter_next( iter, map, pool ) ) {
    ag_parent_ready_state_t * state = ag_parent_ready_state_map_iter_ele( iter, map, pool );
    if( FD_LIKELY( state->parent_ready_lo.slot==ULONG_MAX || state->parent_ready_lo.slot>=new_root ) ) continue;
    ulong b_lo = state->b_lo!=ULONG_MAX ? state->b_lo : state->slot-1UL;
    state->parent_ready_lo.slot = ULONG_MAX;
    for( ulong s=fd_ulong_max( b_lo, new_root ); s<state->slot; s++ ) {
      ag_parent_ready_state_t const * nf = ag_parent_ready_state_map_ele_query_const( map, &s, NULL, pool );
      for( ulong i=0UL; nf && i<nf->notar_fallbacks_cnt; i++ ) {
        ag_block_id_t id = ag_block_id( s, nf->notar_fallbacks[i] );
        if( state->parent_ready_lo.slot==ULONG_MAX || block_id_lt( &id, &state->parent_ready_lo ) ) state->parent_ready_lo = id;
      }
    }
  }
}
