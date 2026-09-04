#include "ag_finality_tracker.h"

              struct finalization_notarized            { ag_block_hash_t hash; };
__extension__ struct finalization_final_pending_notar  {                       };
              struct finalization_finalized            { ag_block_hash_t hash; };
              struct finalization_implicitly_finalized { ag_block_hash_t hash; };
__extension__ struct finalization_implicitly_skipped   {                       };

typedef struct finalization_notarized            finalization_notarized_t;
typedef struct finalization_final_pending_notar  finalization_final_pending_notar_t;
typedef struct finalization_finalized            finalization_finalized_t;
typedef struct finalization_implicitly_finalized finalization_implicitly_finalized_t;
typedef struct finalization_implicitly_skipped   finalization_implicitly_skipped_t;

struct finalization_status {
  int kind;
  union {
    finalization_notarized_t            notarized;
    finalization_final_pending_notar_t  final_pending_notar;
    finalization_finalized_t            finalized;
    finalization_implicitly_finalized_t implicitly_finalized;
    finalization_implicitly_skipped_t   implicitly_skipped;
  };
};
typedef struct finalization_status finalization_status_t;

struct status_ele {
  ulong                 slot;
  finalization_status_t status;
  ulong                 next;
};
typedef struct status_ele status_ele_t;

#define POOL_NAME status_pool
#define POOL_T    status_ele_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               status_map
#define MAP_ELE_T              status_ele_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct parent_ele {
  ag_block_id_t block_id;
  ag_block_id_t parent_block_id;
  ulong         next;
};
typedef struct parent_ele parent_ele_t;

#define POOL_NAME parent_pool
#define POOL_T    parent_ele_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               parent_map
#define MAP_ELE_T              parent_ele_t
#define MAP_KEY                block_id
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_EQ(k0,k1)      (ag_block_id_eq( (k0), (k1) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( (seed), (key), sizeof(ag_block_id_t) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct status {
  status_ele_t * pool;
  status_map_t * map;
};
typedef struct status status_t;

struct parents {
  parent_ele_t * pool;
  parent_map_t * map;
};
typedef struct parents parents_t;

struct ag_finality_tracker {
  status_t  status;
  parents_t parents;
  ulong     highest_finalized_slot;
  ulong     first_unpruned_slot;
};

FD_FN_PURE static uchar const *
status_hash( finalization_status_t const * status ) {
  switch( status->kind ) {
  case AG_FINALIZATION_STATUS_NOTARIZED:            return status->notarized.hash;
  case AG_FINALIZATION_STATUS_FINALIZED:            return status->finalized.hash;
  case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED: return status->implicitly_finalized.hash;
  case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:  return NULL;
  case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:   return NULL;
  default:                                          __builtin_unreachable();
  }
}

static parent_ele_t *
parent_below( ag_finality_tracker_t * self,
              ulong                   root ) {
  parent_map_t * map  = self->parents.map;
  parent_ele_t * pool = self->parents.pool;
  for( parent_map_iter_t iter = parent_map_iter_init( map, pool );
                               !parent_map_iter_done( iter, map, pool );
                         iter = parent_map_iter_next( iter, map, pool ) ) {
    parent_ele_t * e = parent_map_iter_ele( iter, map, pool );
    if( FD_UNLIKELY( e->block_id.slot<root ) ) return e;
  }
  return NULL;
}

static void
prune( ag_finality_tracker_t * self ) {
  ulong          root = self->first_unpruned_slot;
  ulong          next = root + 1UL;
  status_ele_t * se;
  while( ( se = status_map_ele_query( self->status.map, &next, NULL, self->status.pool ) ) &&
         ( se->status.kind==AG_FINALIZATION_STATUS_FINALIZED            ||
           se->status.kind==AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED ||
           se->status.kind==AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED   ) ) {
    self->first_unpruned_slot = next;
    next++;
  }

  for( ulong slot=root; slot<self->first_unpruned_slot; slot++ ) {
    status_ele_t * e = status_map_ele_remove( self->status.map, &slot, NULL, self->status.pool );
    if( FD_LIKELY( e ) ) status_pool_ele_release( self->status.pool, e );
  }

  parent_ele_t * pe;
  while( ( pe = parent_below( self, self->first_unpruned_slot ) ) ) {
    parent_map_ele_remove( self->parents.map, &pe->block_id, NULL, self->parents.pool );
    parent_pool_ele_release( self->parents.pool, pe );
  }
}

static void
handle_implicitly_finalized( ag_finality_tracker_t *   self,
                             ulong                     source_slot,
                             ag_block_id_t const *     implicitly_finalized,
                             ag_finalization_event_t * event ) {

  ag_block_id_t const * parent = implicitly_finalized;
  while( FD_LIKELY( parent ) ) {
    ag_block_id_t const * implicitly_finalized = parent; /* intentional shadowing */

    FD_TEST( source_slot > implicitly_finalized->slot );

    if( FD_UNLIKELY( implicitly_finalized->slot<self->first_unpruned_slot ) ) return;

    for( ulong slot=implicitly_finalized->slot+1UL; slot<source_slot; slot++ ) {
      status_ele_t * ele = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
      if( FD_UNLIKELY( ele ) ) {
        switch( ele->status.kind ) {
          case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
            return;
          case AG_FINALIZATION_STATUS_NOTARIZED:
            break;
          case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
          case AG_FINALIZATION_STATUS_FINALIZED:
          case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
            FD_LOG_CRIT(( "consensus safety violation" ));
          default:
            __builtin_unreachable();
        }
      }
      if( FD_UNLIKELY( !ele ) ) {
        ele       = status_pool_ele_acquire( self->status.pool );
        ele->slot = slot;
        status_map_ele_insert( self->status.map, ele, self->status.pool );
      }
      ele->status.kind = AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED;
      event->implicitly_skipped[ event->implicitly_skipped_cnt++ ] = slot;
    }

    ulong         slot       = implicitly_finalized->slot;
    uchar const * block_hash = implicitly_finalized->hash;

    status_ele_t * ele = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
    if( FD_UNLIKELY( !ele ) ) {
      ele       = status_pool_ele_acquire( self->status.pool );
      ele->slot = slot;
      status_map_ele_insert( self->status.map, ele, self->status.pool );
    } else {
      switch( ele->status.kind ) {
        case AG_FINALIZATION_STATUS_FINALIZED:
        case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
          FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), block_hash, sizeof(ag_block_hash_t) ), "consensus safety violation" );
          return;
        case AG_FINALIZATION_STATUS_NOTARIZED:
          FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), block_hash, sizeof(ag_block_hash_t) ), "consensus safety violation" );
          break;
        case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
          break;
        case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
          FD_LOG_CRIT(( "consensus safety violation" ));
        default:
          __builtin_unreachable();
      }
    }
    ele->status.kind = AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED;
    memcpy( ele->status.implicitly_finalized.hash, block_hash, sizeof(ag_block_hash_t) );
    event->implicitly_finalized[ event->implicitly_finalized_cnt++ ] = *implicitly_finalized;

    parent_ele_t * parent_ele = parent_map_ele_query( self->parents.map, implicitly_finalized, NULL, self->parents.pool );
    if( FD_UNLIKELY( !parent_ele ) ) return;
    source_slot = implicitly_finalized->slot;
    parent      = &parent_ele->parent_block_id;
  }
}

static void
handle_finalized_block( ag_finality_tracker_t *   self,
                        ag_block_id_t const *     finalized,
                        ag_finalization_event_t * event ) {
  ulong slot                   = finalized->slot;
  event->finalized             = *finalized;
  self->highest_finalized_slot = fd_ulong_max( slot, self->highest_finalized_slot );

  parent_ele_t * _parent = parent_map_ele_query( self->parents.map, finalized, NULL, self->parents.pool );
  if( FD_LIKELY( _parent ) ) {
    ag_block_id_t parent = _parent->parent_block_id;
    handle_implicitly_finalized( self, slot, &parent, event );
  }
  prune( self );
}

ulong
ag_finality_tracker_align( void ) {
  return alignof(ag_finality_tracker_t);
}

ulong
ag_finality_tracker_footprint( ulong slot_max ) {
  slot_max    = fd_ulong_pow2_up( slot_max    );
  ulong parent_max = slot_max*AG_EQVOC_BLOCK_HASH_MAX;
  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( parent_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(ag_finality_tracker_t), sizeof(ag_finality_tracker_t)                  ),
      status_pool_align(),            status_pool_footprint ( slot_max             ) ),
      status_map_align(),             status_map_footprint  ( status_chain_cnt     ) ),
      parent_pool_align(),            parent_pool_footprint ( parent_max           ) ),
      parent_map_align(),             parent_map_footprint  ( parent_chain_cnt     ) ),
    ag_finality_tracker_align() );
}

void *
ag_finality_tracker_new( void * shmem,
                         ulong  slot_max,
                         ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, ag_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !slot_max ) ) {
    FD_LOG_WARNING(( "zero slot_max" ));
    return NULL;
  }

  ulong footprint = ag_finality_tracker_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  slot_max         = fd_ulong_pow2_up( slot_max );
  ulong parent_max = slot_max*AG_EQVOC_BLOCK_HASH_MAX;

  fd_memset( shmem, 0, footprint );

  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( parent_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  ag_finality_tracker_t * tracker      = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_finality_tracker_t), sizeof(ag_finality_tracker_t)              );
  void *                  status_pool  = FD_SCRATCH_ALLOC_APPEND( l, status_pool_align(),            status_pool_footprint ( slot_max         ) );
  void *                  status_map   = FD_SCRATCH_ALLOC_APPEND( l, status_map_align(),             status_map_footprint  ( status_chain_cnt ) );
  void *                  parent_pool  = FD_SCRATCH_ALLOC_APPEND( l, parent_pool_align(),            parent_pool_footprint ( parent_max       ) );
  void *                  parent_map   = FD_SCRATCH_ALLOC_APPEND( l, parent_map_align(),             parent_map_footprint  ( parent_chain_cnt ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_finality_tracker_align() ) == (ulong)shmem + footprint );

  tracker->status.pool  = status_pool_join( status_pool_new( status_pool, slot_max               ) );
  tracker->status.map   = status_map_join ( status_map_new ( status_map,  status_chain_cnt, seed ) );
  tracker->parents.pool = parent_pool_join( parent_pool_new( parent_pool, parent_max            ) );
  tracker->parents.map  = parent_map_join ( parent_map_new ( parent_map,  parent_chain_cnt, seed ) );

  tracker->highest_finalized_slot = ULONG_MAX;
  tracker->first_unpruned_slot    = ULONG_MAX;

  return shmem;
}

void
ag_finality_tracker_init( ag_finality_tracker_t * self,
                          ulong                   slot ) {
  self->highest_finalized_slot = slot;
  self->first_unpruned_slot    = slot;
}

void
ag_finality_tracker_fini( ag_finality_tracker_t * self ) {
  self->highest_finalized_slot = ULONG_MAX;
  self->first_unpruned_slot    = ULONG_MAX;
}

ag_finality_tracker_t *
ag_finality_tracker_join( void * shtracker ) {
  ag_finality_tracker_t * tracker = (ag_finality_tracker_t *)shtracker;
  if( FD_UNLIKELY( !tracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)tracker, ag_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }
  return tracker;
}

void *
ag_finality_tracker_leave( ag_finality_tracker_t const * tracker ) {
  if( FD_UNLIKELY( !tracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  return (void *)tracker;
}

void *
ag_finality_tracker_delete( void * shtracker ) {
  if( FD_UNLIKELY( !shtracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtracker, ag_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }
  return shtracker;
}

void
ag_finality_tracker_add_parent( ag_finality_tracker_t *   self,
                                ag_block_id_t const *     block,
                                ag_block_id_t const *     parent,
                                ag_finalization_event_t * event ) {
  FD_TEST( block->slot > parent->slot );

  if( FD_UNLIKELY( block->slot<self->first_unpruned_slot ) ) return;

  parent_ele_t * pe = parent_map_ele_query( self->parents.map, block, NULL, self->parents.pool );
  if( FD_LIKELY( pe ) ) {
    FD_TEST( ag_block_id_eq( &pe->parent_block_id, parent ) );
    return;
  }
  {
    parent_ele_t * pool = self->parents.pool;
    FD_TEST( parent_pool_free( pool ) );
    pe         = parent_pool_ele_acquire( pool );
    pe->block_id    = *block;
    pe->parent_block_id = *parent;
    parent_map_ele_insert( self->parents.map, pe, pool );
  }

  status_ele_t * ele  = status_map_ele_query( self->status.map, &block->slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !ele ) ) return;

  switch( ele->status.kind ) {
    case AG_FINALIZATION_STATUS_FINALIZED:
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      if( 0==memcmp( block->hash, status_hash( &ele->status ), sizeof(ag_block_hash_t) ) ) {
        ag_block_id_t p = *parent;
        handle_implicitly_finalized( self, block->slot, &p, event );
        prune( self );
      }
      return;
    case AG_FINALIZATION_STATUS_NOTARIZED:
    case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
    case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
    default:
      return;
  }
}

void
ag_finality_tracker_mark_fast_finalized( ag_finality_tracker_t *   self,
                                         ag_block_id_t const *     block,
                                         ag_finalization_event_t * event ) {
  if( FD_UNLIKELY( block->slot<self->first_unpruned_slot ) ) return;

  ulong          slot = block->slot;
  status_ele_t * ele  = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !ele ) ) {
    ele       = status_pool_ele_acquire( self->status.pool );
    ele->slot = slot;
    status_map_ele_insert( self->status.map, ele, self->status.pool );
  } else {
    switch( ele->status.kind ) {
      case AG_FINALIZATION_STATUS_FINALIZED:
      case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
        FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), block->hash, sizeof(ag_block_hash_t) ), "consensus safety violation" );
        return;
      case AG_FINALIZATION_STATUS_NOTARIZED:
        FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), block->hash, sizeof(ag_block_hash_t) ), "consensus safety violation" );
        break;
      case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
        break;
      case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
        FD_LOG_CRIT(( "consensus safety violation" ));
      default:
        __builtin_unreachable();
    }
  }
  ele->status.kind = AG_FINALIZATION_STATUS_FINALIZED;
  memcpy( ele->status.finalized.hash, block->hash, sizeof(ag_block_hash_t) );

  handle_finalized_block( self, block, event );
}

void
ag_finality_tracker_mark_notarized( ag_finality_tracker_t *   self,
                                    ag_block_id_t const *     block,
                                    ag_finalization_event_t * event ) {
  if( FD_UNLIKELY( block->slot<self->first_unpruned_slot ) ) return;

  ulong          slot = block->slot;
  status_ele_t * ele  = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !ele ) ) {
    ele              = status_pool_ele_acquire( self->status.pool );
    ele->slot        = slot;
    ele->status.kind = AG_FINALIZATION_STATUS_NOTARIZED;
    memcpy( ele->status.notarized.hash, block->hash, sizeof(ag_block_hash_t) );
    status_map_ele_insert( self->status.map, ele, self->status.pool );
    return;
  }

  switch( ele->status.kind ) {
    case AG_FINALIZATION_STATUS_NOTARIZED:
    case AG_FINALIZATION_STATUS_FINALIZED:
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), block->hash, sizeof(ag_block_hash_t) ), "consensus safety violation" );
      return;
    case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
      return;
    case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR: {
      ele->status.kind = AG_FINALIZATION_STATUS_FINALIZED;
      memcpy( ele->status.finalized.hash, block->hash, sizeof(ag_block_hash_t) );
      handle_finalized_block( self, block, event );
      return;
    }
    default:
      __builtin_unreachable();
  }
}

void
ag_finality_tracker_mark_finalized( ag_finality_tracker_t *   self,
                                    ulong                     slot,
                                    ag_finalization_event_t * event ) {
  if( FD_UNLIKELY( slot<self->first_unpruned_slot ) ) return;

  status_ele_t * ele = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !ele ) ) {
    ele              = status_pool_ele_acquire( self->status.pool );
    ele->slot        = slot;
    ele->status.kind = AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR;
    status_map_ele_insert( self->status.map, ele, self->status.pool );
    return;
  }

  switch( ele->status.kind ) {
    case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
    case AG_FINALIZATION_STATUS_FINALIZED:
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      return;
    case AG_FINALIZATION_STATUS_NOTARIZED: {
      ag_block_id_t block = ag_block_id( slot, ele->status.notarized.hash );
      ele->status.kind    = AG_FINALIZATION_STATUS_FINALIZED;
      memcpy( ele->status.finalized.hash, block.hash, sizeof(ag_block_hash_t) );
      handle_finalized_block( self, &block, event );
      return;
    }
    case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
      FD_LOG_CRIT(( "consensus safety violation" ));
    default:
      __builtin_unreachable();
  }
}

ulong
ag_finality_tracker_highest_finalized_slot( ag_finality_tracker_t const * self ) {
  return self->highest_finalized_slot;
}

ulong
ag_finality_tracker_first_unpruned_slot( ag_finality_tracker_t const * self ) {
  return self->first_unpruned_slot;
}

int
ag_finality_tracker_status( ag_finality_tracker_t const * self,
                            ulong                         slot,
                            ag_block_hash_t               out_hash ) {
  status_ele_t const * e = status_map_ele_query_const( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !e ) ) return -1;
  if( out_hash ) {
    uchar const * hash = status_hash( &e->status );
    if( hash ) memcpy( out_hash, hash, sizeof(ag_block_hash_t) );
    else       fd_memset( out_hash, 0,    sizeof(ag_block_hash_t) );
  }
  return e->status.kind;
}

int
ag_finality_tracker_has_parent( ag_finality_tracker_t const * self,
                                ag_block_id_t const *         block ) {
  return !!parent_map_ele_query_const( self->parents.map, block, NULL, self->parents.pool );
}
