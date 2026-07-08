#include "ag_parent_ready_tracker.h"

#define POOL_NAME state_pool
#define POOL_T    ag_parent_ready_state_t
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               state_map
#define MAP_ELE_T              ag_parent_ready_state_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

typedef ag_parent_ready_state_t state_pool_t;

struct __attribute__((aligned(128UL))) ag_parent_ready_tracker {
  ulong          root;
  state_pool_t * state_pool;
  state_map_t *  state_map;
};

ulong
ag_parent_ready_tracker_align( void ) {
  return alignof(ag_parent_ready_tracker_t);
}

ulong
ag_parent_ready_tracker_footprint( ulong slot_max ) {
  slot_max = fd_ulong_pow2_up( slot_max );
  ulong chain_cnt = state_map_chain_cnt_est( slot_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(ag_parent_ready_tracker_t), sizeof(ag_parent_ready_tracker_t) ),
      state_pool_align(),                 state_pool_footprint( slot_max )  ),
      state_map_align(),                  state_map_footprint ( chain_cnt ) ),
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

  ulong chain_cnt = state_map_chain_cnt_est( slot_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  ag_parent_ready_tracker_t * tracker    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_parent_ready_tracker_t), sizeof(ag_parent_ready_tracker_t) );
  void *                      state_pool = FD_SCRATCH_ALLOC_APPEND( l, state_pool_align(),                 state_pool_footprint( slot_max )  );
  void *                      state_map  = FD_SCRATCH_ALLOC_APPEND( l, state_map_align(),                  state_map_footprint ( chain_cnt ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_parent_ready_tracker_align() ) == (ulong)shmem + footprint );

  tracker->root       = 0UL;
  tracker->state_pool = state_pool_join( state_pool_new( state_pool, slot_max        ) );
  tracker->state_map  = state_map_join ( state_map_new ( state_map,  chain_cnt, seed ) );

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

static inline ag_parent_ready_state_t *
state_query( ag_parent_ready_tracker_t * self,
             ulong                       slot ) {
  return state_map_ele_query( self->state_map, &slot, NULL, self->state_pool );
}

ag_parent_ready_state_t *
ag_parent_ready_tracker_slot_state( ag_parent_ready_tracker_t * self,
                                    ulong                       slot ) {

  ag_parent_ready_state_t * state = state_query( self, slot );
  if( FD_LIKELY( state ) ) return state;

  state_pool_t * pool = self->state_pool;
  if( FD_UNLIKELY( !state_pool_free( pool ) ) ) {
    FD_LOG_ERR(( "parent_ready_tracker: state pool exhausted (slot_max exceeded) at slot %lu", slot ));
  }

  state = state_pool_ele_acquire( pool );
  ag_parent_ready_state_init( state, slot );
  state_map_ele_insert( self->state_map, state, pool );
  return state;
}

ag_parent_ready_tracker_t *
ag_parent_ready_tracker_default( ag_parent_ready_tracker_t * tracker ) {

  state_pool_t * pool  = tracker->state_pool;
  ag_parent_ready_state_t * genesis = state_pool_ele_acquire( pool );
  ag_parent_ready_state_genesis( genesis, 0UL );
  state_map_ele_insert( tracker->state_map, genesis, pool );
  tracker->root = 0UL;
  return tracker;
}

ag_parent_ready_tracker_t *
ag_parent_ready_tracker_seed_root( ag_parent_ready_tracker_t * tracker,
                                   ulong                       root_slot,
                                   fd_hash_t const *           root_hash ) {
  state_pool_t *            pool = tracker->state_pool;
  ag_parent_ready_state_t * root = state_pool_ele_acquire( pool );
  ag_parent_ready_state_init( root, root_slot );
  ag_parent_ready_state_mark_notar_fallback( root, root_hash );
  state_map_ele_insert( tracker->state_map, root, pool );
  tracker->root = root_slot;
  return tracker;
}

FD_FN_PURE ulong
ag_parent_ready_tracker_root( ag_parent_ready_tracker_t const * self ) {
  return self->root;
}

void
ag_parent_ready_tracker_mark_notar_fallback( ag_parent_ready_tracker_t * self,
                                             ag_block_id_t const *       id,
                                             ag_parent_ready_t *         out,
                                             ulong *                     out_cnt ) {
  *out_cnt = 0UL;

  ulong             slot = id->slot;
  fd_hash_t const * hash = &id->hash;

  if( FD_UNLIKELY( slot < self->root ) ) return;

  ag_parent_ready_state_t * state = ag_parent_ready_tracker_slot_state( self, slot );
  if( !ag_parent_ready_state_mark_notar_fallback( state, hash ) ) return;

  for( ulong s=slot+1UL; ; s++ ) {
    ag_parent_ready_state_t * fstate = ag_parent_ready_tracker_slot_state( self, s );
    if( ag_alpenglow_is_start_of_window( s ) ) {
      ag_parent_ready_state_add_to_ready( fstate, id );
      FD_TEST( *out_cnt < AG_PARENT_READY_OUT_MAX );
      out[ *out_cnt ].slot   = s;
      out[ *out_cnt ].parent = *id;
      (*out_cnt)++;
    }
    if( !ag_parent_ready_state_is_skip_certified( fstate ) ) break;
  }
}

void
ag_parent_ready_tracker_mark_skipped( ag_parent_ready_tracker_t * self,
                                      ulong                       marked_slot,
                                      ag_parent_ready_t *         out,
                                      ulong *                     out_cnt ) {
  *out_cnt = 0UL;

  if( FD_UNLIKELY( marked_slot < self->root ) ) return;

  ag_parent_ready_state_t * state = ag_parent_ready_tracker_slot_state( self, marked_slot );
  if( !ag_parent_ready_state_mark_skip( state ) ) return;

  ag_block_id_t potential_parents[ AG_PARENT_READY_OUT_MAX ];
  ulong         potential_cnt = 0UL;

  ulong root            = self->root;
  ulong first           = ag_alpenglow_first_slot_in_window( marked_slot );

  for( ulong s=marked_slot; ; s-- ) {
    if( s>=first && s<=marked_slot && s>=root ) {
      ag_parent_ready_state_t * sstate = ag_parent_ready_tracker_slot_state( self, s );

      if( s!=marked_slot ) {
        ulong             nf_cnt;
        fd_hash_t const * nfs = ag_parent_ready_state_notar_fallback_blocks( sstate, &nf_cnt );
        for( ulong i=0UL; i<nf_cnt; i++ ) {
          FD_TEST( potential_cnt < AG_PARENT_READY_OUT_MAX );
          potential_parents[ potential_cnt ].slot = s;
          potential_parents[ potential_cnt ].hash = nfs[i];
          potential_cnt++;
        }
      }

      if( !ag_parent_ready_state_is_skip_certified( sstate ) ) break;

      ulong                 rb_cnt;
      ag_block_id_t const * rbs = ag_parent_ready_state_ready_block_ids( sstate, &rb_cnt );
      for( ulong i=0UL; i<rb_cnt; i++ ) {
        FD_TEST( potential_cnt < AG_PARENT_READY_OUT_MAX );
        potential_parents[ potential_cnt ] = rbs[i];
        potential_cnt++;
      }
    }
    if( s==0UL || s<first || s<root ) break;
  }

  for( ulong s=marked_slot+1UL; ; s++ ) {
    ag_parent_ready_state_t * fstate = ag_parent_ready_tracker_slot_state( self, s );
    if( ag_alpenglow_is_start_of_window( s ) ) {
      for( ulong i=0UL; i<potential_cnt; i++ ) {
        ag_parent_ready_state_add_to_ready( fstate, &potential_parents[i] );
        FD_TEST( *out_cnt < AG_PARENT_READY_OUT_MAX );
        out[ *out_cnt ].slot   = s;
        out[ *out_cnt ].parent = potential_parents[i];
        (*out_cnt)++;
      }
    }
    if( !ag_parent_ready_state_is_skip_certified( fstate ) ) break;
  }
}

void
ag_parent_ready_tracker_handle_finalization( ag_parent_ready_tracker_t * self,
                                             int                         has_finalized,
                                             ag_block_id_t const *       finalized,
                                             ag_block_id_t const *       implicitly_finalized,
                                             ulong                       if_cnt,
                                             ulong const *               implicitly_skipped,
                                             ulong                       is_cnt,
                                             ag_parent_ready_t *         out,
                                             ulong *                     out_cnt ) {

  ag_parent_ready_t scratch[ AG_PARENT_READY_OUT_MAX ];
  ulong             scratch_cnt;

  int   have_max = 0;
  ag_parent_ready_t best; best.slot = 0UL; best.parent.slot = 0UL;
  fd_memset( &best.parent.hash, 0, sizeof(fd_hash_t) );

  if( has_finalized ) {
    ag_parent_ready_tracker_mark_notar_fallback( self, finalized, scratch, &scratch_cnt );
    for( ulong i=0UL; i<scratch_cnt; i++ ) {
      if( !have_max || scratch[i].slot >= best.slot ) { best = scratch[i]; have_max = 1; } /* >=: last max wins (Rust max_by_key) */
    }
  }

  for( ulong j=0UL; j<if_cnt; j++ ) {
    ag_parent_ready_tracker_mark_notar_fallback( self, &implicitly_finalized[j], scratch, &scratch_cnt );
    for( ulong i=0UL; i<scratch_cnt; i++ ) {
      if( !have_max || scratch[i].slot >= best.slot ) { best = scratch[i]; have_max = 1; } /* >=: last max wins (Rust max_by_key) */
    }
  }

  for( ulong j=0UL; j<is_cnt; j++ ) {
    ag_parent_ready_tracker_mark_skipped( self, implicitly_skipped[j], scratch, &scratch_cnt );
    for( ulong i=0UL; i<scratch_cnt; i++ ) {
      if( !have_max || scratch[i].slot >= best.slot ) { best = scratch[i]; have_max = 1; } /* >=: last max wins (Rust max_by_key) */
    }
  }

  if( have_max ) {
    out[0]   = best;
    *out_cnt = 1UL;
  } else {
    *out_cnt = 0UL;
  }
}

ag_block_id_t const *
ag_parent_ready_tracker_parents_ready( ag_parent_ready_tracker_t * self,
                                       ulong                       slot,
                                       ulong *                     cnt ) {
  ag_parent_ready_state_t * state = state_query( self, slot );
  if( FD_UNLIKELY( !state ) ) { *cnt = 0UL; return NULL; }
  return ag_parent_ready_state_ready_block_ids( state, cnt );
}

int
ag_parent_ready_tracker_wait_for_parent_ready( ag_parent_ready_tracker_t * self,
                                               ulong                       slot,
                                               ag_block_id_t *             out_id ) {

  ag_parent_ready_state_t * state = ag_parent_ready_tracker_slot_state( self, slot );
  return ag_parent_ready_state_wait_for_parent_ready( state, out_id );
}

void
ag_parent_ready_tracker_prune( ag_parent_ready_tracker_t * self,
                               ulong                       new_root ) {

  self->root = new_root;

  state_map_t  * map  = self->state_map;
  state_pool_t * pool = self->state_pool;

  for(;;) {
    ulong drop_slot = ULONG_MAX;
    for( state_map_iter_t iter = state_map_iter_init( map, pool );
         !state_map_iter_done( iter, map, pool );
         iter = state_map_iter_next( iter, map, pool ) ) {
      ag_parent_ready_state_t const * ele = state_map_iter_ele_const( iter, map, pool );
      if( ele->slot < new_root ) { drop_slot = ele->slot; break; }
    }
    if( drop_slot==ULONG_MAX ) break;
    ag_parent_ready_state_t * ele = state_map_ele_remove( map, &drop_slot, NULL, pool );
    FD_TEST( ele );
    state_pool_ele_release( pool, ele );
  }
}
