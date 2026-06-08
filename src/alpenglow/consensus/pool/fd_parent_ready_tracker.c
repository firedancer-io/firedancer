#include "fd_parent_ready_tracker.h"

/* Per-slot state pool keyed by slot.  A single `next` field serves both
   the pool free list and the map_chain hash chain (an element is either
   free-in-pool or acquired-and-in-map, never both), matching the
   fd_ghost idiom. */

#define POOL_NAME state_pool
#define POOL_T    fd_parent_ready_state_t
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               state_map
#define MAP_ELE_T              fd_parent_ready_state_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

/* fd_parent_ready_tracker_t is the top-level relocatable structure,
   holding only the wksp gaddrs of the bump-allocated pool and map plus
   the root slot.  Layout (mirrors fd_ghost):

   --------------------------------- <- fd_parent_ready_tracker_t *
   | fd_parent_ready_tracker_t     |
   ---------------------------------
   | state_pool                    |
   ---------------------------------
   | state_map                     |
   --------------------------------- */

struct __attribute__((aligned(128UL))) fd_parent_ready_tracker {
  ulong root;             /* lowest slot still tracked; everything below has been pruned */
  ulong wksp_gaddr;       /* wksp gaddr of this tracker in the backing wksp */
  ulong state_pool_gaddr; /* wksp gaddr of the per-slot state pool */
  ulong state_map_gaddr;  /* wksp gaddr of the slot->state map */
};

typedef fd_parent_ready_state_t state_pool_t;

FD_FN_PURE static inline fd_wksp_t *
wksp( fd_parent_ready_tracker_t const * tracker ) {
  return (fd_wksp_t *)( ((ulong)tracker) - tracker->wksp_gaddr );
}

static inline state_pool_t *
state_pool( fd_parent_ready_tracker_t * tracker ) {
  return (state_pool_t *)fd_wksp_laddr_fast( wksp( tracker ), tracker->state_pool_gaddr );
}

static inline state_map_t *
state_map( fd_parent_ready_tracker_t * tracker ) {
  return (state_map_t *)fd_wksp_laddr_fast( wksp( tracker ), tracker->state_map_gaddr );
}

ulong
fd_parent_ready_tracker_align( void ) {
  return alignof(fd_parent_ready_tracker_t);
}

ulong
fd_parent_ready_tracker_footprint( ulong slot_max ) {
  slot_max = fd_ulong_pow2_up( slot_max );
  ulong chain_cnt = state_map_chain_cnt_est( slot_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_parent_ready_tracker_t), sizeof(fd_parent_ready_tracker_t) ),
      state_pool_align(),                 state_pool_footprint( slot_max )  ),
      state_map_align(),                  state_map_footprint ( chain_cnt ) ),
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

  slot_max = fd_ulong_pow2_up( slot_max );

  fd_wksp_t * ws = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !ws ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  ulong chain_cnt = state_map_chain_cnt_est( slot_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_parent_ready_tracker_t * tracker    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_parent_ready_tracker_t), sizeof(fd_parent_ready_tracker_t) );
  void *                      state_pool = FD_SCRATCH_ALLOC_APPEND( l, state_pool_align(),                 state_pool_footprint( slot_max )  );
  void *                      state_map  = FD_SCRATCH_ALLOC_APPEND( l, state_map_align(),                  state_map_footprint ( chain_cnt ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_parent_ready_tracker_align() ) == (ulong)shmem + footprint );

  tracker->root             = 0UL;
  tracker->wksp_gaddr       = fd_wksp_gaddr_fast( ws, tracker );
  tracker->state_pool_gaddr = fd_wksp_gaddr_fast( ws, state_pool_join( state_pool_new( state_pool, slot_max             ) ) );
  tracker->state_map_gaddr  = fd_wksp_gaddr_fast( ws, state_map_join ( state_map_new ( state_map,  chain_cnt, seed      ) ) );

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
fd_parent_ready_tracker_leave( fd_parent_ready_tracker_t const * tracker ) {
  if( FD_UNLIKELY( !tracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  return (void *)tracker;
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

/* state_query returns the per-slot state for slot, or NULL if absent. */

static inline fd_parent_ready_state_t *
state_query( fd_parent_ready_tracker_t * tracker, ulong slot ) {
  return state_map_ele_query( state_map( tracker ), &slot, NULL, state_pool( tracker ) );
}

fd_parent_ready_state_t *
fd_parent_ready_tracker_slot_state( fd_parent_ready_tracker_t * tracker,
                                    ulong                       slot ) {

  /* Mirrors ParentReadyTracker::slot_state: initializes with Default if
     necessary. */

  fd_parent_ready_state_t * state = state_query( tracker, slot );
  if( FD_LIKELY( state ) ) return state;

  state_pool_t * pool = state_pool( tracker );
  if( FD_UNLIKELY( !state_pool_free( pool ) ) ) {
    FD_LOG_ERR(( "parent_ready_tracker: state pool exhausted (slot_max exceeded) at slot %lu", slot ));
  }

  state = state_pool_ele_acquire( pool );
  fd_parent_ready_state_init( state, slot );
  state_map_ele_insert( state_map( tracker ), state, pool );
  return state;
}

fd_parent_ready_tracker_t *
fd_parent_ready_tracker_default( fd_parent_ready_tracker_t * tracker ) {

  /* Mirrors the Rust Default impl: only the genesis block is initially
     considered notarized-fallback, and root = genesis slot 0. */

  state_pool_t * pool  = state_pool( tracker );
  fd_parent_ready_state_t * genesis = state_pool_ele_acquire( pool );
  fd_parent_ready_state_genesis( genesis, 0UL );
  state_map_ele_insert( state_map( tracker ), genesis, pool );
  tracker->root = 0UL;
  return tracker;
}

FD_FN_PURE ulong
fd_parent_ready_tracker_root( fd_parent_ready_tracker_t const * tracker ) {
  return tracker->root;
}

void
fd_parent_ready_tracker_mark_notar_fallback( fd_parent_ready_tracker_t * tracker,
                                             fd_block_id_t const *       id,
                                             fd_parent_ready_t *         out,
                                             ulong *                     out_cnt ) {
  *out_cnt = 0UL;

  ulong             slot = id->slot;
  fd_hash_t const * hash = &id->hash;

  /* already decided and pruned; its block is already fully propagated */

  if( FD_UNLIKELY( slot < tracker->root ) ) return;

  fd_parent_ready_state_t * state = fd_parent_ready_tracker_slot_state( tracker, slot );
  if( !fd_parent_ready_state_mark_notar_fallback( state, hash ) ) return;

  /* add this block as valid parent to any skip-connected future windows.

     future_slots() is an infinite forward iterator starting at slot+1;
     in C we loop, lazily creating each slot_state, breaking when a slot
     is not skip-certified.  Total created entries are bounded by
     slot_max (the pool). */

  for( ulong s=slot+1UL; ; s++ ) {
    fd_parent_ready_state_t * fstate = fd_parent_ready_tracker_slot_state( tracker, s );
    if( fd_alpenglow_is_start_of_window( s ) ) {
      fd_parent_ready_state_add_to_ready( fstate, id );
      FD_TEST( *out_cnt < FD_PARENT_READY_OUT_MAX );
      out[ *out_cnt ].slot   = s;
      out[ *out_cnt ].parent = *id;
      (*out_cnt)++;
    }
    if( !fd_parent_ready_state_is_skip_certified( fstate ) ) break;
  }
}

void
fd_parent_ready_tracker_mark_skipped( fd_parent_ready_tracker_t * tracker,
                                      ulong                       marked_slot,
                                      fd_parent_ready_t *         out,
                                      ulong *                     out_cnt ) {
  *out_cnt = 0UL;

  /* already decided and pruned; its parents are already fully propagated */

  if( FD_UNLIKELY( marked_slot < tracker->root ) ) return;

  fd_parent_ready_state_t * state = fd_parent_ready_tracker_slot_state( tracker, marked_slot );
  if( !fd_parent_ready_state_mark_skip( state ) ) return;

  /* find possible parents for future windows.

     potential_parents accumulates, going backward from marked_slot, any
     skip-connected parents, never reaching into already-pruned (decided)
     slots.  window_slots = marked_slot.slots_in_window() filtered to
     [root, marked_slot] and reversed (descending). */

  fd_block_id_t potential_parents[ FD_PARENT_READY_OUT_MAX ];
  ulong         potential_cnt = 0UL;

  ulong root            = tracker->root;
  ulong first           = fd_alpenglow_first_slot_in_window( marked_slot );
  /* iterate slots in window in descending order, filtered to <= marked_slot && >= root */
  for( ulong s=marked_slot; ; s-- ) {
    if( s>=first && s<=marked_slot && s>=root ) {
      fd_parent_ready_state_t * sstate = fd_parent_ready_tracker_slot_state( tracker, s );

      /* add any notarized-fallback blocks from this slot (but not from
         marked_slot itself) */

      if( s!=marked_slot ) {
        ulong             nf_cnt;
        fd_hash_t const * nfs = fd_parent_ready_state_notar_fallback_blocks( sstate, &nf_cnt );
        for( ulong i=0UL; i<nf_cnt; i++ ) {
          FD_TEST( potential_cnt < FD_PARENT_READY_OUT_MAX );
          potential_parents[ potential_cnt ].slot = s;
          potential_parents[ potential_cnt ].hash = nfs[i];
          potential_cnt++;
        }
      }

      /* stop as soon as we see any non-skipped slot */

      if( !fd_parent_ready_state_is_skip_certified( sstate ) ) break;

      /* if the slot is skipped, add its parents as well */

      ulong                 rb_cnt;
      fd_block_id_t const * rbs = fd_parent_ready_state_ready_block_ids( sstate, &rb_cnt );
      for( ulong i=0UL; i<rb_cnt; i++ ) {
        FD_TEST( potential_cnt < FD_PARENT_READY_OUT_MAX );
        potential_parents[ potential_cnt ] = rbs[i];
        potential_cnt++;
      }
    }
    if( s==0UL || s<first || s<root ) break; /* exhausted the descending window range */
  }

  /* add these as valid parents to any skip-connected future windows */

  for( ulong s=marked_slot+1UL; ; s++ ) {
    fd_parent_ready_state_t * fstate = fd_parent_ready_tracker_slot_state( tracker, s );
    if( fd_alpenglow_is_start_of_window( s ) ) {
      for( ulong i=0UL; i<potential_cnt; i++ ) {
        fd_parent_ready_state_add_to_ready( fstate, &potential_parents[i] );
        FD_TEST( *out_cnt < FD_PARENT_READY_OUT_MAX );
        out[ *out_cnt ].slot   = s;
        out[ *out_cnt ].parent = potential_parents[i];
        (*out_cnt)++;
      }
    }
    if( !fd_parent_ready_state_is_skip_certified( fstate ) ) break;
  }
}

void
fd_parent_ready_tracker_handle_finalization( fd_parent_ready_tracker_t * tracker,
                                             int                         has_finalized,
                                             fd_block_id_t const *       finalized,
                                             fd_block_id_t const *       implicitly_finalized,
                                             ulong                       if_cnt,
                                             ulong const *               implicitly_skipped,
                                             ulong                       is_cnt,
                                             fd_parent_ready_t *         out,
                                             ulong *                     out_cnt ) {

  /* Accumulate all parents-ready, then keep only the highest-slot one. */

  fd_parent_ready_t scratch[ FD_PARENT_READY_OUT_MAX ];
  ulong             scratch_cnt;

  int   have_max = 0;
  fd_parent_ready_t best; best.slot = 0UL; best.parent.slot = 0UL;
  fd_memset( &best.parent.hash, 0, sizeof(fd_hash_t) );

  if( has_finalized ) {
    fd_parent_ready_tracker_mark_notar_fallback( tracker, finalized, scratch, &scratch_cnt );
    for( ulong i=0UL; i<scratch_cnt; i++ ) {
      if( !have_max || scratch[i].slot > best.slot ) { best = scratch[i]; have_max = 1; }
    }
  }

  for( ulong j=0UL; j<if_cnt; j++ ) {
    fd_parent_ready_tracker_mark_notar_fallback( tracker, &implicitly_finalized[j], scratch, &scratch_cnt );
    for( ulong i=0UL; i<scratch_cnt; i++ ) {
      if( !have_max || scratch[i].slot > best.slot ) { best = scratch[i]; have_max = 1; }
    }
  }

  for( ulong j=0UL; j<is_cnt; j++ ) {
    fd_parent_ready_tracker_mark_skipped( tracker, implicitly_skipped[j], scratch, &scratch_cnt );
    for( ulong i=0UL; i<scratch_cnt; i++ ) {
      if( !have_max || scratch[i].slot > best.slot ) { best = scratch[i]; have_max = 1; }
    }
  }

  if( have_max ) {
    out[0]   = best;
    *out_cnt = 1UL;
  } else {
    *out_cnt = 0UL;
  }
}

fd_block_id_t const *
fd_parent_ready_tracker_parents_ready( fd_parent_ready_tracker_t * tracker,
                                       ulong                       slot,
                                       ulong *                     cnt ) {
  fd_parent_ready_state_t * state = state_query( tracker, slot );
  if( FD_UNLIKELY( !state ) ) { *cnt = 0UL; return NULL; }
  return fd_parent_ready_state_ready_block_ids( state, cnt );
}

int
fd_parent_ready_tracker_wait_for_parent_ready( fd_parent_ready_tracker_t * tracker,
                                               ulong                       slot,
                                               fd_block_id_t *             out_id ) {

  /* Mirrors ParentReadyTracker::wait_for_parent_ready: entry(slot).or_default(). */

  fd_parent_ready_state_t * state = fd_parent_ready_tracker_slot_state( tracker, slot );
  return fd_parent_ready_state_wait_for_parent_ready( state, out_id );
}

void
fd_parent_ready_tracker_prune( fd_parent_ready_tracker_t * tracker,
                               ulong                       new_root ) {

  /* Mirrors ParentReadyTracker::prune: retain only slots >= new_root. */

  tracker->root = new_root;

  state_map_t  * map  = state_map ( tracker );
  state_pool_t * pool = state_pool( tracker );

  /* Iterate the map collecting slots to drop, then remove + release.
     We cannot remove during iteration, so first gather into a temporary
     index list threaded through the pool's `next` of the removed
     elements is unsafe (next is the map chain field).  Instead, repeat a
     scan-and-remove pass until no element below new_root remains.  The
     map is small (bounded by slot_max) so this is acceptable. */

  for(;;) {
    ulong drop_slot = ULONG_MAX;
    for( state_map_iter_t iter = state_map_iter_init( map, pool );
         !state_map_iter_done( iter, map, pool );
         iter = state_map_iter_next( iter, map, pool ) ) {
      fd_parent_ready_state_t const * ele = state_map_iter_ele_const( iter, map, pool );
      if( ele->slot < new_root ) { drop_slot = ele->slot; break; }
    }
    if( drop_slot==ULONG_MAX ) break;
    fd_parent_ready_state_t * ele = state_map_ele_remove( map, &drop_slot, NULL, pool );
    FD_TEST( ele );
    state_pool_ele_release( pool, ele );
  }
}
