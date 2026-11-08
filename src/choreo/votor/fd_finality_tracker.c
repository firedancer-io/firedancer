#include "fd_finality_tracker.h"

              struct finalization_notarized            { fd_block_hash_t hash; };
__extension__ struct finalization_final_pending_notar  {                       };
              struct finalization_finalized            { fd_block_hash_t hash; };
              struct finalization_implicitly_finalized { fd_block_hash_t hash; };
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
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash((*(key))^(seed)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct parent_ele {
  fd_block_id_t block_id;
  fd_block_id_t parent_block_id;
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
#define MAP_KEY_T              fd_block_id_t
#define MAP_KEY_EQ(k0,k1)      (fd_block_id_eq((k0),(k1)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_block_id_t)))
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

struct fd_finality_tracker {
  status_t  status;
  parents_t parents;
  ulong     highest_finalized_slot;
  ulong     first_unpruned_slot;
};

FD_FN_PURE static fd_block_hash_t const *
status_hash( finalization_status_t const * status ) {
  switch( status->kind ) {
  case FD_FINALIZATION_STATUS_NOTARIZED:            return &status->notarized.hash;
  case FD_FINALIZATION_STATUS_FINALIZED:            return &status->finalized.hash;
  case FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED: return &status->implicitly_finalized.hash;
  case FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:  return NULL;
  case FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:   return NULL;
  default:                                          FD_LOG_CRIT(( "unreachable" ));
  }
}

static parent_ele_t *
parent_below( fd_finality_tracker_t * self,
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
prune( fd_finality_tracker_t * self ) {
  ulong          root = self->first_unpruned_slot;
  ulong          next = root + 1UL;
  status_ele_t * se;
  while( ( se = status_map_ele_query( self->status.map, &next, NULL, self->status.pool ) ) &&
         ( se->status.kind==FD_FINALIZATION_STATUS_FINALIZED            ||
           se->status.kind==FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED ||
           se->status.kind==FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED   ) ) {
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
handle_implicitly_finalized( fd_finality_tracker_t *   self,
                             ulong                     source_slot,
                             fd_block_id_t const *     implicitly_finalized,
                             fd_finalization_event_t * event ) {

  fd_block_id_t const * parent = implicitly_finalized;
  while( parent ) {
    fd_block_id_t const * implicitly_finalized = parent; /* intentional shadowing */

    FD_TEST( source_slot > implicitly_finalized->slot );

    if( FD_UNLIKELY( implicitly_finalized->slot<self->first_unpruned_slot ) ) return;

    for( ulong slot=implicitly_finalized->slot+1UL; slot<source_slot; slot++ ) {
      status_ele_t * ele = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
      if( FD_UNLIKELY( ele ) ) {
        switch( ele->status.kind ) {
          case FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
            return;
          case FD_FINALIZATION_STATUS_NOTARIZED:
            break;
          case FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
          case FD_FINALIZATION_STATUS_FINALIZED:
          case FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
            FD_LOG_CRIT(( "consensus safety violation" ));
          default:
            FD_LOG_CRIT(( "unreachable" ));
        }
      }
      if( FD_UNLIKELY( !ele ) ) {
        ele       = status_pool_ele_acquire( self->status.pool );
        ele->slot = slot;
        status_map_ele_insert( self->status.map, ele, self->status.pool );
      }
      ele->status.kind = FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED;
      event->implicitly_skipped[ event->implicitly_skipped_cnt++ ] = slot;
    }

    ulong                   slot       = implicitly_finalized->slot;
    fd_block_hash_t const * block_hash = &implicitly_finalized->hash;

    status_ele_t * ele = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
    if( FD_UNLIKELY( !ele ) ) {
      ele       = status_pool_ele_acquire( self->status.pool );
      ele->slot = slot;
      status_map_ele_insert( self->status.map, ele, self->status.pool );
    } else {
      switch( ele->status.kind ) {
        case FD_FINALIZATION_STATUS_FINALIZED:
        case FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
          FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), block_hash, sizeof(fd_block_hash_t) ), "consensus safety violation" );
          return;
        case FD_FINALIZATION_STATUS_NOTARIZED:
        case FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
          break;
        case FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
          FD_LOG_CRIT(( "consensus safety violation" ));
        default:
          FD_LOG_CRIT(( "unreachable" ));
      }
    }
    ele->status.kind = FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED;
    memcpy( &ele->status.implicitly_finalized.hash, block_hash, sizeof(fd_block_hash_t) );
    event->implicitly_finalized[ event->implicitly_finalized_cnt++ ] = *implicitly_finalized;

    parent_ele_t * parent_ele = parent_map_ele_query( self->parents.map, implicitly_finalized, NULL, self->parents.pool );
    if( FD_UNLIKELY( !parent_ele ) ) return;
    source_slot = implicitly_finalized->slot;
    parent      = &parent_ele->parent_block_id;
  }
}

static void
handle_finalized_block( fd_finality_tracker_t *   self,
                        fd_block_id_t const *     finalized,
                        fd_finalization_event_t * event ) {
  ulong slot                   = finalized->slot;
  event->finalized             = *finalized;
  self->highest_finalized_slot = fd_ulong_max( slot, self->highest_finalized_slot );

  parent_ele_t * _parent = parent_map_ele_query( self->parents.map, finalized, NULL, self->parents.pool );
  if( FD_LIKELY( _parent ) ) {
    fd_block_id_t parent = _parent->parent_block_id;
    handle_implicitly_finalized( self, slot, &parent, event );
  }
  prune( self );
}

ulong
fd_finality_tracker_align( void ) {
  return alignof(fd_finality_tracker_t);
}

ulong
fd_finality_tracker_footprint( ulong slot_max ) {
  slot_max    = fd_ulong_pow2_up( slot_max    );
  ulong parent_max = slot_max*FD_VOTOR_EQVOC_MAX;
  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( parent_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_finality_tracker_t), sizeof(fd_finality_tracker_t)                  ),
      status_pool_align(),            status_pool_footprint ( slot_max             ) ),
      status_map_align(),             status_map_footprint  ( status_chain_cnt     ) ),
      parent_pool_align(),            parent_pool_footprint ( parent_max           ) ),
      parent_map_align(),             parent_map_footprint  ( parent_chain_cnt     ) ),
    fd_finality_tracker_align() );
}

void *
fd_finality_tracker_new( void * shmem,
                         ulong  slot_max,
                         ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !slot_max ) ) {
    FD_LOG_WARNING(( "zero slot_max" ));
    return NULL;
  }

  ulong footprint = fd_finality_tracker_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  slot_max         = fd_ulong_pow2_up( slot_max );
  ulong parent_max = slot_max*FD_VOTOR_EQVOC_MAX;

  fd_memset( shmem, 0, footprint );

  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( parent_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_finality_tracker_t * tracker      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_finality_tracker_t), sizeof(fd_finality_tracker_t)              );
  void *                  status_pool  = FD_SCRATCH_ALLOC_APPEND( l, status_pool_align(),            status_pool_footprint ( slot_max         ) );
  void *                  status_map   = FD_SCRATCH_ALLOC_APPEND( l, status_map_align(),             status_map_footprint  ( status_chain_cnt ) );
  void *                  parent_pool  = FD_SCRATCH_ALLOC_APPEND( l, parent_pool_align(),            parent_pool_footprint ( parent_max       ) );
  void *                  parent_map   = FD_SCRATCH_ALLOC_APPEND( l, parent_map_align(),             parent_map_footprint  ( parent_chain_cnt ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_finality_tracker_align() ) == (ulong)shmem + footprint );

  tracker->status.pool  = status_pool_join( status_pool_new( status_pool, slot_max               ) );
  tracker->status.map   = status_map_join ( status_map_new ( status_map,  status_chain_cnt, seed ) );
  tracker->parents.pool = parent_pool_join( parent_pool_new( parent_pool, parent_max            ) );
  tracker->parents.map  = parent_map_join ( parent_map_new ( parent_map,  parent_chain_cnt, seed ) );

  tracker->highest_finalized_slot = ULONG_MAX;
  tracker->first_unpruned_slot    = ULONG_MAX;

  return shmem;
}

void
fd_finality_tracker_init( fd_finality_tracker_t * self,
                          ulong                   slot ) {
  self->highest_finalized_slot = slot;
  self->first_unpruned_slot    = slot;
}

void
fd_finality_tracker_fini( fd_finality_tracker_t * self ) {
  self->highest_finalized_slot = ULONG_MAX;
  self->first_unpruned_slot    = ULONG_MAX;
}

fd_finality_tracker_t *
fd_finality_tracker_join( void * shtracker ) {
  fd_finality_tracker_t * tracker = (fd_finality_tracker_t *)shtracker;
  if( FD_UNLIKELY( !tracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)tracker, fd_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }
  return tracker;
}

void *
fd_finality_tracker_leave( fd_finality_tracker_t const * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  return (void *)self;
}

void *
fd_finality_tracker_delete( void * shtracker ) {
  if( FD_UNLIKELY( !shtracker ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtracker, fd_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }
  return shtracker;
}

void
fd_finality_tracker_add_parent( fd_finality_tracker_t *   self,
                                fd_block_id_t const *     block,
                                fd_block_id_t const *     parent,
                                fd_finalization_event_t * event ) {
  FD_TEST( block->slot > parent->slot );

  if( FD_UNLIKELY( block->slot<self->first_unpruned_slot ) ) return;

  parent_ele_t * pe = parent_map_ele_query( self->parents.map, block, NULL, self->parents.pool );
  if( FD_LIKELY( pe ) ) {
    FD_TEST( fd_block_id_eq( &pe->parent_block_id, parent ) );
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
    case FD_FINALIZATION_STATUS_FINALIZED:
    case FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      if( FD_LIKELY( 0==memcmp( &block->hash, status_hash( &ele->status ), sizeof(fd_block_hash_t) ) ) ) {
        fd_block_id_t p = *parent;
        handle_implicitly_finalized( self, block->slot, &p, event );
        prune( self );
      }
      return;
    case FD_FINALIZATION_STATUS_NOTARIZED:
    case FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
    case FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
    default:
      return;
  }
}

void
fd_finality_tracker_mark_fast_finalized( fd_finality_tracker_t *   self,
                                         fd_block_id_t const *     block,
                                         fd_finalization_event_t * event ) {
  if( FD_UNLIKELY( block->slot<self->first_unpruned_slot ) ) return;

  ulong          slot = block->slot;
  status_ele_t * ele  = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !ele ) ) {
    ele       = status_pool_ele_acquire( self->status.pool );
    ele->slot = slot;
    status_map_ele_insert( self->status.map, ele, self->status.pool );
  } else {
    switch( ele->status.kind ) {
      case FD_FINALIZATION_STATUS_FINALIZED:
      case FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
        FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), &block->hash, sizeof(fd_block_hash_t) ), "consensus safety violation" );
        return;
      case FD_FINALIZATION_STATUS_NOTARIZED:
        FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), &block->hash, sizeof(fd_block_hash_t) ), "consensus safety violation" );
        break;
      case FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
        break;
      case FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
        FD_LOG_CRIT(( "consensus safety violation" ));
      default:
        FD_LOG_CRIT(( "unreachable" ));
    }
  }
  ele->status.kind = FD_FINALIZATION_STATUS_FINALIZED;
  memcpy( &ele->status.finalized.hash, &block->hash, sizeof(fd_block_hash_t) );

  handle_finalized_block( self, block, event );
}

void
fd_finality_tracker_mark_notarized( fd_finality_tracker_t *   self,
                                    fd_block_id_t const *     block,
                                    fd_finalization_event_t * event ) {
  if( FD_UNLIKELY( block->slot<self->first_unpruned_slot ) ) return;

  ulong          slot = block->slot;
  status_ele_t * ele  = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !ele ) ) {
    ele              = status_pool_ele_acquire( self->status.pool );
    ele->slot        = slot;
    ele->status.kind = FD_FINALIZATION_STATUS_NOTARIZED;
    memcpy( &ele->status.notarized.hash, &block->hash, sizeof(fd_block_hash_t) );
    status_map_ele_insert( self->status.map, ele, self->status.pool );
    return;
  }

  switch( ele->status.kind ) {
    case FD_FINALIZATION_STATUS_NOTARIZED:
    case FD_FINALIZATION_STATUS_FINALIZED:
      FD_CHECK_CRIT( 0==memcmp( status_hash( &ele->status ), &block->hash, sizeof(fd_block_hash_t) ), "consensus safety violation" );
      return;
    case FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
    case FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
      return;
    case FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR: {
      ele->status.kind = FD_FINALIZATION_STATUS_FINALIZED;
      memcpy( &ele->status.finalized.hash, &block->hash, sizeof(fd_block_hash_t) );
      handle_finalized_block( self, block, event );
      return;
    }
    default:
      FD_LOG_CRIT(( "unreachable" ));
  }
}

void
fd_finality_tracker_mark_finalized( fd_finality_tracker_t *   self,
                                    ulong                     slot,
                                    fd_finalization_event_t * event ) {
  if( FD_UNLIKELY( slot<self->first_unpruned_slot ) ) return;

  status_ele_t * ele = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !ele ) ) {
    ele              = status_pool_ele_acquire( self->status.pool );
    ele->slot        = slot;
    ele->status.kind = FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR;
    status_map_ele_insert( self->status.map, ele, self->status.pool );
    return;
  }

  switch( ele->status.kind ) {
    case FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
    case FD_FINALIZATION_STATUS_FINALIZED:
    case FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      return;
    case FD_FINALIZATION_STATUS_NOTARIZED: {
      fd_block_id_t block = fd_block_id( slot, ele->status.notarized.hash.uc );
      ele->status.kind    = FD_FINALIZATION_STATUS_FINALIZED;
      memcpy( &ele->status.finalized.hash, &block.hash, sizeof(fd_block_hash_t) );
      handle_finalized_block( self, &block, event );
      return;
    }
    case FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
      FD_LOG_CRIT(( "consensus safety violation" ));
    default:
      FD_LOG_CRIT(( "unreachable" ));
  }
}

ulong
fd_finality_tracker_highest_finalized_slot( fd_finality_tracker_t const * self ) {
  return self->highest_finalized_slot;
}

FD_FN_PURE fd_block_hash_t const *
fd_finality_tracker_highest_finalized_block_hash( fd_finality_tracker_t const * self ) {
  status_ele_t const * e = status_map_ele_query_const( self->status.map, &self->highest_finalized_slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !e || ( e->status.kind!=FD_FINALIZATION_STATUS_FINALIZED && e->status.kind!=FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED ) ) ) return NULL;
  return status_hash( &e->status );
}

ulong
fd_finality_tracker_first_unpruned_slot( fd_finality_tracker_t const * self ) {
  return self->first_unpruned_slot;
}

int
fd_finality_tracker_status( fd_finality_tracker_t const * self,
                            ulong                         slot,
                            fd_block_hash_t *             out_hash ) {
  status_ele_t const * e = status_map_ele_query_const( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !e ) ) return -1;
  if( FD_LIKELY( out_hash ) ) {
    fd_block_hash_t const * hash = status_hash( &e->status );
    if( FD_LIKELY( hash ) ) memcpy( out_hash, hash, sizeof(fd_block_hash_t) );
    else                    fd_memset( out_hash, 0,    sizeof(fd_block_hash_t) );
  }
  return e->status.kind;
}

int
fd_finality_tracker_has_parent( fd_finality_tracker_t const * self,
                                fd_block_id_t const *         block ) {
  return !!parent_map_ele_query_const( self->parents.map, block, NULL, self->parents.pool );
}
