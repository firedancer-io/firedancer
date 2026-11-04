#include "fd_parent_ready_tracker.h"

ulong
fd_parent_ready_tracker_align( void ) {
  return alignof(fd_parent_ready_tracker_t);
}

ulong
fd_parent_ready_tracker_footprint( ulong slot_max ) {
  ulong chain_cnt = fd_parent_ready_state_map_chain_cnt_est( slot_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_parent_ready_tracker_t), sizeof(fd_parent_ready_tracker_t)                            ),
      fd_parent_ready_state_pool_align(), fd_parent_ready_state_pool_footprint( slot_max )             ),
      fd_parent_ready_state_map_align(),  fd_parent_ready_state_map_footprint ( chain_cnt )            ),
    fd_parent_ready_tracker_align() );
}

void *
fd_parent_ready_tracker_new( void * shmem,
                             ulong  slot_max,
                             ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_parent_ready_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_parent_ready_tracker_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  ulong chain_cnt = fd_parent_ready_state_map_chain_cnt_est( slot_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_parent_ready_tracker_t * tracker    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_parent_ready_tracker_t), sizeof(fd_parent_ready_tracker_t)                 );
  void *                      state_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_parent_ready_state_pool_align(), fd_parent_ready_state_pool_footprint( slot_max )  );
  void *                      state_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_parent_ready_state_map_align(),  fd_parent_ready_state_map_footprint ( chain_cnt )           );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_parent_ready_tracker_align() ) == (ulong)shmem + footprint );

  tracker->root          = ULONG_MAX;
  tracker->highest_ready = 0UL;
  tracker->states.pool = fd_parent_ready_state_pool_join( fd_parent_ready_state_pool_new( state_pool, slot_max        ) );
  tracker->states.map  = fd_parent_ready_state_map_join ( fd_parent_ready_state_map_new ( state_map,  chain_cnt, seed ) );


  return shmem;
}

fd_parent_ready_tracker_t *
fd_parent_ready_tracker_join( void * shtracker ) {
  fd_parent_ready_tracker_t * tracker = (fd_parent_ready_tracker_t *)shtracker;

  if( FD_UNLIKELY( !tracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)tracker, fd_parent_ready_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }

  return tracker;
}

void *
fd_parent_ready_tracker_leave( fd_parent_ready_tracker_t const * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  return (void *)self;
}

void *
fd_parent_ready_tracker_delete( void * shtracker ) {
  if( FD_UNLIKELY( !shtracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtracker, fd_parent_ready_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }

  return shtracker;
}

static fd_parent_ready_state_t *
slot_state( fd_parent_ready_tracker_t * self,
            ulong                       slot ) {
  fd_parent_ready_state_t * state = fd_parent_ready_state_map_ele_query( self->states.map, &slot, NULL, self->states.pool );
  if( FD_LIKELY( state ) ) return state;

  fd_parent_ready_state_t * pool = self->states.pool;
  if( FD_UNLIKELY( !fd_parent_ready_state_pool_free( pool ) ) ) {
    FD_LOG_ERR(( "parent_ready_tracker: state pool exhausted (slot_max exceeded) at slot %lu", slot ));
  }

  state                       = fd_parent_ready_state_pool_ele_acquire( pool );
  state->slot                 = slot;
  state->skip                 = 0;
  state->notar_fallbacks_cnt  = (uchar)0;
  state->b_lo                 = ULONG_MAX;
  state->parent_ready_lo.slot = ULONG_MAX;
  state->ready                = 0;
  fd_parent_ready_state_map_ele_insert( self->states.map, state, pool );
  return state;
}

static void
add_to_ready( fd_parent_ready_tracker_t * self,
              ulong                       slot,
              fd_block_id_t const *       parent,
              fd_parent_ready_t *         newly_certified,
              ulong *                     newly_certified_cnt ) {
  fd_parent_ready_state_t * state = slot_state( self, slot );
  if( FD_LIKELY( state->parent_ready_lo.slot==ULONG_MAX || fd_block_id_lt( parent, &state->parent_ready_lo ) ) ) state->parent_ready_lo = *parent;
  self->highest_ready = fd_ulong_max( self->highest_ready, slot );
  if( FD_UNLIKELY( state->ready ) ) return;
  state->ready = 1;
  newly_certified[ *newly_certified_cnt ].slot   = slot;
  newly_certified[ *newly_certified_cnt ].parent = state->parent_ready_lo;
  (*newly_certified_cnt)++;
}

ulong
fd_parent_ready_tracker_mark_notar_fallback( fd_parent_ready_tracker_t * self,
                                             fd_block_id_t const *       block_id,
                                             fd_parent_ready_t *         newly_certified ) {
  ulong newly_certified_cnt = 0UL;

  ulong                   slot = block_id->slot;
  fd_block_hash_t const * hash = &block_id->hash;

  if( FD_UNLIKELY( slot < self->root ) ) return 0UL;

  fd_parent_ready_state_t * state = slot_state( self, slot );
  for( ulong i=0UL; i<state->notar_fallbacks_cnt; i++ ) {
    if( FD_UNLIKELY( 0==memcmp( &state->notar_fallbacks[i], hash, sizeof(fd_block_hash_t) ) ) ) return 0UL;
  }
  FD_CHECK_CRIT( state->notar_fallbacks_cnt<FD_VOTOR_NOTAR_FALLBACK_CERT_MAX, "consensus safety violation" ); /* Lemma 48 */
  memcpy( &state->notar_fallbacks[ state->notar_fallbacks_cnt++ ], hash, sizeof(fd_block_hash_t) );

  for( ulong s=slot+1UL; ; s++ ) {
    if( FD_UNLIKELY( fd_is_start_of_window( s ) ) ) add_to_ready( self, s, block_id, newly_certified, &newly_certified_cnt );
    fd_parent_ready_state_t const * next = fd_parent_ready_state_map_ele_query_const( self->states.map, &s, NULL, self->states.pool );
    if( FD_LIKELY( !next || !next->skip ) ) break;
  }
  return newly_certified_cnt;
}

ulong
fd_parent_ready_tracker_mark_root( fd_parent_ready_tracker_t * self,
                                   fd_block_id_t const *       root,
                                   fd_parent_ready_t *         newly_certified ) {
  ulong newly_certified_cnt = fd_parent_ready_tracker_mark_notar_fallback( self, root, newly_certified );
  fd_parent_ready_state_t * next = slot_state( self, root->slot+1UL );
  if( FD_LIKELY( next->parent_ready_lo.slot==ULONG_MAX ) ) next->parent_ready_lo = *root;
  return newly_certified_cnt;
}

ulong
fd_parent_ready_tracker_mark_skipped( fd_parent_ready_tracker_t * self,
                                      ulong                       skipped_slot,
                                      fd_parent_ready_t *         newly_certified ) {
  ulong newly_certified_cnt = 0UL;

  if( FD_UNLIKELY( skipped_slot < self->root ) ) return 0UL;
  fd_parent_ready_state_t * state = slot_state( self, skipped_slot );
  if( FD_UNLIKELY( state->skip ) ) return 0UL;
  state->skip = 1;

  /* The skip extends every chain ending at skipped_slot down to b_lo,
     the highest slot below skipped_slot that is not skipped.  The
     newly ready parents are the notar fallbacks of [b_lo,skipped_slot).
     Setting b_lo makes all of them ready, and parent_ready_lo is set to
     their minimum. */

  fd_block_id_t parent = { .slot = ULONG_MAX };
  ulong         b_lo   = ULONG_MAX;
  ulong         first  = fd_first_slot_in_window( skipped_slot );
  for( ulong slot=skipped_slot; slot>fd_ulong_max( first, self->root ); ) {
    slot--;
    fd_parent_ready_state_t const * prev = fd_parent_ready_state_map_ele_query_const( self->states.map, &slot, NULL, self->states.pool );
    for( ulong i=0UL; prev && i<prev->notar_fallbacks_cnt; i++ ) {
      fd_block_id_t nf = fd_block_id( slot, prev->notar_fallbacks[i].uc );
      if( parent.slot==ULONG_MAX || fd_block_id_lt( &nf, &parent ) ) parent = nf;
    }
    if( FD_LIKELY( !prev || !prev->skip ) ) { b_lo = slot; break; }
  }
  if( FD_UNLIKELY( b_lo==ULONG_MAX ) ) { /* [first,skipped_slot) all skipped, the window start knows the rest */
    fd_parent_ready_state_t const * start = fd_parent_ready_state_map_ele_query_const( self->states.map, &first, NULL, self->states.pool );
    b_lo = ( start && start->b_lo!=ULONG_MAX ) ? start->b_lo : fd_ulong_sat_sub( first, 1UL );
    if( start && start->parent_ready_lo.slot!=ULONG_MAX && start->parent_ready_lo.slot>=self->root && ( parent.slot==ULONG_MAX || fd_block_id_lt( &start->parent_ready_lo, &parent ) ) ) parent = start->parent_ready_lo;
  }

  for( ulong s=skipped_slot+1UL; ; s++ ) {
    if( FD_UNLIKELY( fd_is_start_of_window( s ) ) ) {
      slot_state( self, s )->b_lo = b_lo;
      if( FD_LIKELY( parent.slot!=ULONG_MAX ) ) add_to_ready( self, s, &parent, newly_certified, &newly_certified_cnt );
    }
    fd_parent_ready_state_t const * next = fd_parent_ready_state_map_ele_query_const( self->states.map, &s, NULL, self->states.pool );
    if( FD_LIKELY( !next || !next->skip ) ) break;
  }
  return newly_certified_cnt;
}

ulong
fd_parent_ready_tracker_parents_ready( fd_parent_ready_tracker_t const * self,
                                       ulong                             slot,
                                       fd_block_id_t *                   out,
                                       ulong                             out_max ) {
  if( FD_UNLIKELY( !fd_is_start_of_window( slot ) || slot<=self->root ) ) return 0UL;

  fd_parent_ready_state_t const * state = fd_parent_ready_state_map_ele_query_const( self->states.map, &slot, NULL, self->states.pool );
  ulong                           b_lo  = ( state && state->b_lo!=ULONG_MAX ) ? state->b_lo : slot-1UL;

  ulong cnt = 0UL;
  for( ulong s=fd_ulong_max( b_lo, self->root ); s<slot; s++ ) {
    fd_parent_ready_state_t const * nf = fd_parent_ready_state_map_ele_query_const( self->states.map, &s, NULL, self->states.pool );
    for( ulong i=0UL; nf && i<nf->notar_fallbacks_cnt; i++ ) {
      if( FD_LIKELY( cnt<out_max ) ) out[ cnt ] = fd_block_id( s, nf->notar_fallbacks[i].uc );
      cnt++;
    }
  }
  return cnt;
}

int
fd_parent_ready_tracker_is_parent_ready( fd_parent_ready_tracker_t const * self,
                                         ulong                             slot,
                                         fd_block_id_t const *             parent ) {
  if( FD_UNLIKELY( !fd_is_start_of_window( slot ) || parent->slot>=slot || parent->slot<self->root ) ) return 0;

  fd_parent_ready_state_t const * state = fd_parent_ready_state_map_ele_query_const( self->states.map, &slot, NULL, self->states.pool );
  ulong                           b_lo  = ( state && state->b_lo!=ULONG_MAX ) ? state->b_lo : slot-1UL;
  if( FD_UNLIKELY( parent->slot<b_lo ) ) return 0;

  fd_parent_ready_state_t const * nf = fd_parent_ready_state_map_ele_query_const( self->states.map, &parent->slot, NULL, self->states.pool );
  for( ulong i=0UL; nf && i<nf->notar_fallbacks_cnt; i++ ) {
    if( FD_UNLIKELY( 0==memcmp( &nf->notar_fallbacks[i], &parent->hash, sizeof(fd_block_hash_t) ) ) ) return 1;
  }
  return 0;
}

fd_block_id_t
fd_parent_ready_tracker_wait_for_parent_ready( fd_parent_ready_tracker_t const * self,
                                               ulong                             slot ) {
  fd_parent_ready_state_t const * state = fd_parent_ready_state_map_ele_query_const( self->states.map, &slot, NULL, self->states.pool );
  if( FD_UNLIKELY( !state || state->parent_ready_lo.slot<self->root ) ) return (fd_block_id_t){ .slot = ULONG_MAX };
  return state->parent_ready_lo;
}

void
fd_parent_ready_tracker_prune( fd_parent_ready_tracker_t * self,
                               ulong                       new_root ) {
  fd_parent_ready_state_map_t * map  = self->states.map;
  fd_parent_ready_state_t *     pool = self->states.pool;
  for( ulong slot=self->root; slot<new_root; slot++ ) {
    fd_parent_ready_state_t * ele = fd_parent_ready_state_map_ele_remove( map, &slot, NULL, pool );
    if( FD_LIKELY( ele ) ) fd_parent_ready_state_pool_ele_release( pool, ele );
  }
  self->root = new_root;

  /* A window start whose lowest ready parent was pruned takes the
     lowest of its ready parents [b_lo,slot) still retained. */

  for( fd_parent_ready_state_map_iter_t iter = fd_parent_ready_state_map_iter_init( map, pool );
                                              !fd_parent_ready_state_map_iter_done( iter, map, pool );
                                        iter = fd_parent_ready_state_map_iter_next( iter, map, pool ) ) {
    fd_parent_ready_state_t * state = fd_parent_ready_state_map_iter_ele( iter, map, pool );
    if( FD_LIKELY( state->parent_ready_lo.slot==ULONG_MAX || state->parent_ready_lo.slot>=new_root ) ) continue;
    ulong b_lo = state->b_lo!=ULONG_MAX ? state->b_lo : state->slot-1UL;
    state->parent_ready_lo.slot = ULONG_MAX;
    for( ulong s=fd_ulong_max( b_lo, new_root ); s<state->slot; s++ ) {
      fd_parent_ready_state_t const * nf = fd_parent_ready_state_map_ele_query_const( map, &s, NULL, pool );
      for( ulong i=0UL; nf && i<nf->notar_fallbacks_cnt; i++ ) {
        fd_block_id_t id = fd_block_id( s, nf->notar_fallbacks[i].uc );
        if( state->parent_ready_lo.slot==ULONG_MAX || fd_block_id_lt( &id, &state->parent_ready_lo ) ) state->parent_ready_lo = id;
      }
    }
  }
}
