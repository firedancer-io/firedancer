#include "ag_finality_tracker.h"

struct ag_ft_status_ele {
  ulong     slot;
  int       status;
  fd_hash_t hash;
  ulong     next;
  ulong     parent;
  ulong     left;
  ulong     right;
  ulong     prio;
};
typedef struct ag_ft_status_ele ag_ft_status_ele_t;

#define POOL_NAME status_pool
#define POOL_T    ag_ft_status_ele_t
#define POOL_NEXT next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               status_map
#define MAP_ELE_T              ag_ft_status_ele_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME      status_treap
#define TREAP_T         ag_ft_status_ele_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ( ((q)<(e)->slot) ? -1 : ( ((q)>(e)->slot) ? 1 : 0 ) )
#define TREAP_LT(e0,e1) ( (e0)->slot < (e1)->slot )
#include "../../../util/tmpl/fd_treap.c"

struct ag_ft_parent_ele {
  ag_block_id_t key;
  ag_block_id_t parent;
  ulong         next;
  ulong         tparent;
  ulong         left;
  ulong         right;
  ulong         prio;
};
typedef struct ag_ft_parent_ele ag_ft_parent_ele_t;

#define POOL_NAME parent_pool
#define POOL_T    ag_ft_parent_ele_t
#define POOL_NEXT next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               parent_map
#define MAP_ELE_T              ag_ft_parent_ele_t
#define MAP_KEY                key
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_EQ(k0,k1)      (ag_block_id_eq( (k0), (k1) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( (seed), (key), sizeof(ag_block_id_t) ))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME      parent_treap
#define TREAP_T         ag_ft_parent_ele_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ( ((q)<(e)->key.slot) ? -1 : ( ((q)>(e)->key.slot) ? 1 : 0 ) )
#define TREAP_LT(e0,e1) ( (e0)->key.slot < (e1)->key.slot )
#define TREAP_PARENT    tparent
#include "../../../util/tmpl/fd_treap.c"

typedef ag_ft_status_ele_t status_pool_t;
typedef ag_ft_parent_ele_t parent_pool_t;

struct __attribute__((aligned(128UL))) ag_finality_tracker {
  status_pool_t *  status_pool;
  status_map_t *   status_map;
  status_treap_t * status_treap;
  parent_pool_t *  parent_pool;
  parent_map_t *   parent_map;
  parent_treap_t * parent_treap;
  ulong highest_finalized_slot;
  ulong first_unpruned_slot;
};


static inline ag_ft_status_ele_t *
status_get( ag_finality_tracker_t * self,
            ulong                   slot ) {
  return status_map_ele_query( self->status_map, &slot, NULL, self->status_pool );
}

static int
status_insert( ag_finality_tracker_t * self,
               ulong                   slot,
               int                     status,
               fd_hash_t const *       hash,
               int *                   old_status,
               fd_hash_t *             old_hash ) {
  ag_ft_status_ele_t * e = status_get( self, slot );
  if( FD_LIKELY( e ) ) {
    if( old_status ) *old_status = e->status;
    if( old_hash   ) *old_hash   = e->hash;
    e->status = status;
    e->hash   = *hash;
    return 1;
  }
  status_pool_t * pool = self->status_pool;
  FD_TEST( status_pool_free( pool ) );
  e = status_pool_ele_acquire( pool );
  e->slot   = slot;
  e->status = status;
  e->hash   = *hash;
  status_map_ele_insert  ( self->status_map, e, pool );
  status_treap_ele_insert( self->status_treap, e, pool );
  return 0;
}

static inline ag_finalization_event_t
event_default( void ) {
  ag_finalization_event_t event;
  event.has_finalized = 0;
  event.if_cnt        = 0UL;
  event.is_cnt        = 0UL;
  return event;
}

static inline void
event_push_implicitly_finalized( ag_finalization_event_t * ev,
                                 ag_block_id_t const *     b ) {
  if( FD_UNLIKELY( ev->if_cnt>=AG_FINALITY_EVENT_CAP ) ) {
    FD_LOG_ERR(( "implicitly_finalized overflow (cap %lu)", AG_FINALITY_EVENT_CAP ));
  }
  ev->implicitly_finalized[ ev->if_cnt++ ] = *b;
}

static inline void
event_push_implicitly_skipped( ag_finalization_event_t * ev,
                               ulong                     slot ) {
  if( FD_UNLIKELY( ev->is_cnt>=AG_FINALITY_EVENT_CAP ) ) {
    FD_LOG_ERR(( "implicitly_skipped overflow (cap %lu)", AG_FINALITY_EVENT_CAP ));
  }
  ev->implicitly_skipped[ ev->is_cnt++ ] = slot;
}

static void
ft_prune( ag_finality_tracker_t * self ) {
  ulong next = self->first_unpruned_slot + 1UL;
  for(;;) {
    ag_ft_status_ele_t * e = status_get( self, next );
    if( FD_UNLIKELY( !e ) ) break;
    int decided = ( e->status==AG_FIN_STATUS_FINALIZED            ||
                    e->status==AG_FIN_STATUS_IMPLICITLY_FINALIZED ||
                    e->status==AG_FIN_STATUS_IMPLICITLY_SKIPPED   );
    if( FD_UNLIKELY( !decided ) ) break;
    self->first_unpruned_slot = next;
    next++;
  }
  ulong root = self->first_unpruned_slot;

  {
    status_pool_t  * pool  = self->status_pool;
    status_treap_t * treap = self->status_treap;
    status_map_t   * map   = self->status_map;
    for(;;) {
      status_treap_fwd_iter_t it = status_treap_fwd_iter_init( treap, pool );
      if( status_treap_fwd_iter_done( it ) ) break;
      ag_ft_status_ele_t * e = status_treap_fwd_iter_ele( it, pool );
      if( FD_LIKELY( e->slot >= root ) ) break;
      status_treap_ele_remove( treap, e, pool );
      status_map_ele_remove( map, &e->slot, NULL, pool );
      status_pool_ele_release( pool, e );
    }
  }

  {
    parent_pool_t  * pool  = self->parent_pool;
    parent_treap_t * treap = self->parent_treap;
    parent_map_t   * map   = self->parent_map;
    for(;;) {
      parent_treap_fwd_iter_t it = parent_treap_fwd_iter_init( treap, pool );
      if( parent_treap_fwd_iter_done( it ) ) break;
      ag_ft_parent_ele_t * e = parent_treap_fwd_iter_ele( it, pool );
      if( FD_LIKELY( e->key.slot >= root ) ) break;
      parent_treap_ele_remove( treap, e, pool );
      parent_map_ele_remove( map, &e->key, NULL, pool );
      parent_pool_ele_release( pool, e );
    }
  }
}

static void
handle_implicitly_finalized( ag_finality_tracker_t *   self,
                             ulong                     source_slot,
                             ag_block_id_t const *     implicitly_finalized,
                             ag_finalization_event_t * event ) {
  ag_block_id_t cur = *implicitly_finalized;
  fd_hash_t     zero; fd_memset( &zero, 0, sizeof(fd_hash_t) );

  for(;;) {
    FD_TEST( source_slot > cur.slot );

    if( FD_UNLIKELY( cur.slot < self->first_unpruned_slot ) ) return;

    int returned = 0;
    for( ulong slot = cur.slot+1UL; ; slot++ ) {
      if( slot==source_slot ) break;
      int old_status; fd_hash_t old_hash;
      int had = status_insert( self, slot, AG_FIN_STATUS_IMPLICITLY_SKIPPED, &zero, &old_status, &old_hash );
      (void)old_hash;
      if( had ) {
        switch( old_status ) {
          case AG_FIN_STATUS_IMPLICITLY_SKIPPED:
            returned = 1;
            break;
          case AG_FIN_STATUS_NOTARIZED:
            break;
          case AG_FIN_STATUS_FINAL_PENDING_NOTAR:
          case AG_FIN_STATUS_FINALIZED:
          case AG_FIN_STATUS_IMPLICITLY_FINALIZED:
          default:
            FD_LOG_ERR(( "consensus safety violation" ));
        }
      }
      if( FD_UNLIKELY( returned ) ) return;
      event_push_implicitly_skipped( event, slot );
    }

    int old_status; fd_hash_t old_hash;
    int had = status_insert( self, cur.slot, AG_FIN_STATUS_IMPLICITLY_FINALIZED, &cur.hash, &old_status, &old_hash );
    if( had ) {
      switch( old_status ) {
        case AG_FIN_STATUS_FINALIZED:
        case AG_FIN_STATUS_IMPLICITLY_FINALIZED:
          FD_TEST( 0==memcmp( old_hash.uc, cur.hash.uc, sizeof(fd_hash_t) ) );

          { int s2; fd_hash_t h2; status_insert( self, cur.slot, old_status, &old_hash, &s2, &h2 ); }
          return;
        case AG_FIN_STATUS_NOTARIZED:
          FD_TEST( 0==memcmp( old_hash.uc, cur.hash.uc, sizeof(fd_hash_t) ) );
          break;
        case AG_FIN_STATUS_FINAL_PENDING_NOTAR:
          break;
        case AG_FIN_STATUS_IMPLICITLY_SKIPPED:
        default:
          FD_LOG_ERR(( "consensus safety violation" ));
      }
    }
    event_push_implicitly_finalized( event, &cur );

    ag_ft_parent_ele_t * pe = parent_map_ele_query( self->parent_map, &cur, NULL, self->parent_pool );
    if( FD_UNLIKELY( !pe ) ) return;
    source_slot = cur.slot;
    cur         = pe->parent;
  }
}

static void
handle_finalized_block( ag_finality_tracker_t *   self,
                        ag_block_id_t const *     finalized,
                        ag_finalization_event_t * event ) {
  ulong slot = finalized->slot;
  event->has_finalized = 1;
  event->finalized     = *finalized;
  self->highest_finalized_slot = fd_ulong_max( slot, self->highest_finalized_slot );

  ag_ft_parent_ele_t * pe = parent_map_ele_query( self->parent_map, finalized, NULL, self->parent_pool );
  if( FD_LIKELY( pe ) ) {
    ag_block_id_t parent = pe->parent;
    handle_implicitly_finalized( self, slot, &parent, event );
  }
  ft_prune( self );
}

ulong
ag_finality_tracker_align( void ) {
  return alignof(ag_finality_tracker_t);
}

ulong
ag_finality_tracker_footprint( ulong slot_max,
                               ulong blockid_max ) {
  slot_max    = fd_ulong_pow2_up( slot_max    );
  blockid_max = fd_ulong_pow2_up( blockid_max );
  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( blockid_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(ag_finality_tracker_t), sizeof(ag_finality_tracker_t)         ),
      status_pool_align(),  status_pool_footprint ( slot_max             )  ),
      status_map_align(),   status_map_footprint  ( status_chain_cnt     )  ),
      status_treap_align(), status_treap_footprint( slot_max             )  ),
      parent_pool_align(),  parent_pool_footprint ( blockid_max          )  ),
      parent_map_align(),   parent_map_footprint  ( parent_chain_cnt     )  ),
      parent_treap_align(), parent_treap_footprint( blockid_max          )  ),
    ag_finality_tracker_align() );
}

void *
ag_finality_tracker_new( void *            shmem,
                         ulong             slot_max,
                         ulong             blockid_max,
                         ulong             seed,
                         ulong             root_slot,
                         fd_hash_t const * root_hash ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, ag_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !slot_max || !blockid_max ) ) {
    FD_LOG_WARNING(( "zero slot_max / blockid_max" ));
    return NULL;
  }

  ulong footprint = ag_finality_tracker_footprint( slot_max, blockid_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu) / blockid_max (%lu)", slot_max, blockid_max ));
    return NULL;
  }

  slot_max    = fd_ulong_pow2_up( slot_max    );
  blockid_max = fd_ulong_pow2_up( blockid_max );

  fd_memset( shmem, 0, footprint );

  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( blockid_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  ag_finality_tracker_t * t            = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_finality_tracker_t), sizeof(ag_finality_tracker_t)        );
  void *                  status_pool  = FD_SCRATCH_ALLOC_APPEND( l, status_pool_align(),  status_pool_footprint ( slot_max         )    );
  void *                  status_map   = FD_SCRATCH_ALLOC_APPEND( l, status_map_align(),   status_map_footprint  ( status_chain_cnt )    );
  void *                  status_treap = FD_SCRATCH_ALLOC_APPEND( l, status_treap_align(), status_treap_footprint( slot_max         )    );
  void *                  parent_pool  = FD_SCRATCH_ALLOC_APPEND( l, parent_pool_align(),  parent_pool_footprint ( blockid_max      )    );
  void *                  parent_map   = FD_SCRATCH_ALLOC_APPEND( l, parent_map_align(),   parent_map_footprint  ( parent_chain_cnt )    );
  void *                  parent_treap = FD_SCRATCH_ALLOC_APPEND( l, parent_treap_align(), parent_treap_footprint( blockid_max      )    );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_finality_tracker_align() ) == (ulong)shmem + footprint );

  status_pool_t * sp = status_pool_join( status_pool_new( status_pool, slot_max    ) );
  parent_pool_t * pp = parent_pool_join( parent_pool_new( parent_pool, blockid_max ) );

  t->status_pool  = sp;
  t->status_map   = status_map_join  ( status_map_new  ( status_map,  status_chain_cnt, seed ) );
  t->status_treap = status_treap_join( status_treap_new( status_treap, slot_max               ) );
  t->parent_pool  = pp;
  t->parent_map   = parent_map_join  ( parent_map_new  ( parent_map,  parent_chain_cnt, seed ) );
  t->parent_treap = parent_treap_join( parent_treap_new( parent_treap, blockid_max            ) );

  status_treap_seed( sp, slot_max,    seed );
  parent_treap_seed( pp, blockid_max, seed );

  t->highest_finalized_slot = root_slot;
  t->first_unpruned_slot    = root_slot;

  fd_hash_t zero; fd_memset( &zero, 0, sizeof(fd_hash_t) );
  status_insert( t, root_slot, AG_FIN_STATUS_NOTARIZED, root_hash ? root_hash : &zero, NULL, NULL );

  return shmem;
}

ag_finality_tracker_t *
ag_finality_tracker_join( void * shtracker ) {
  ag_finality_tracker_t * t = (ag_finality_tracker_t *)shtracker;
  if( FD_UNLIKELY( !t ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)t, ag_finality_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tracker" ));
    return NULL;
  }
  return t;
}

void *
ag_finality_tracker_leave( ag_finality_tracker_t const * t ) {
  if( FD_UNLIKELY( !t ) ) {
    FD_LOG_WARNING(( "NULL tracker" ));
    return NULL;
  }
  return (void *)t;
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

ag_finalization_event_t
ag_finality_tracker_add_parent( ag_finality_tracker_t * self,
                                ag_block_id_t const *   block,
                                ag_block_id_t const *   parent ) {
  ag_finalization_event_t event = event_default();
  FD_TEST( block->slot > parent->slot );

  if( FD_UNLIKELY( block->slot < self->first_unpruned_slot ) ) return event;

  ag_ft_parent_ele_t * pe = parent_map_ele_query( self->parent_map, block, NULL, self->parent_pool );
  if( FD_LIKELY( pe ) ) {
    FD_TEST( ag_block_id_eq( &pe->parent, parent ) );
    return event;
  }
  {
    parent_pool_t * pool = self->parent_pool;
    FD_TEST( parent_pool_free( pool ) );
    pe         = parent_pool_ele_acquire( pool );
    pe->key    = *block;
    pe->parent = *parent;
    parent_map_ele_insert  ( self->parent_map, pe, pool );
    parent_treap_ele_insert( self->parent_treap, pe, pool );
  }

  ag_ft_status_ele_t * se = status_get( self, block->slot );
  if( FD_UNLIKELY( !se ) ) return event;

  switch( se->status ) {
    case AG_FIN_STATUS_FINALIZED:
    case AG_FIN_STATUS_IMPLICITLY_FINALIZED:
      if( 0==memcmp( block->hash.uc, se->hash.uc, sizeof(fd_hash_t) ) ) {
        ag_block_id_t p = *parent;
        handle_implicitly_finalized( self, block->slot, &p, &event );
        ft_prune( self );
      }
      return event;
    case AG_FIN_STATUS_NOTARIZED:
    case AG_FIN_STATUS_FINAL_PENDING_NOTAR:
    case AG_FIN_STATUS_IMPLICITLY_SKIPPED:
    default:
      return event;
  }
}

ag_finalization_event_t
ag_finality_tracker_mark_fast_finalized( ag_finality_tracker_t * self,
                                         ag_block_id_t const *   block ) {
  ag_finalization_event_t event = event_default();
  if( FD_UNLIKELY( block->slot < self->first_unpruned_slot ) ) return event;

  int old_status; fd_hash_t old_hash;
  int had = status_insert( self, block->slot, AG_FIN_STATUS_FINALIZED, &block->hash, &old_status, &old_hash );
  if( had ) {
    switch( old_status ) {
      case AG_FIN_STATUS_FINALIZED:
      case AG_FIN_STATUS_IMPLICITLY_FINALIZED:
        FD_TEST( 0==memcmp( old_hash.uc, block->hash.uc, sizeof(fd_hash_t) ) );
        return event;
      case AG_FIN_STATUS_NOTARIZED:
        FD_TEST( 0==memcmp( old_hash.uc, block->hash.uc, sizeof(fd_hash_t) ) );
        break;
      case AG_FIN_STATUS_FINAL_PENDING_NOTAR:
        break;
      case AG_FIN_STATUS_IMPLICITLY_SKIPPED:
      default:
        FD_LOG_ERR(( "consensus safety violation" ));
    }
  }

  handle_finalized_block( self, block, &event );
  return event;
}

ag_finalization_event_t
ag_finality_tracker_mark_notarized( ag_finality_tracker_t * self,
                                    ag_block_id_t const *   block ) {
  ag_finalization_event_t event = event_default();
  if( FD_UNLIKELY( block->slot < self->first_unpruned_slot ) ) return event;

  int old_status; fd_hash_t old_hash;
  int had = status_insert( self, block->slot, AG_FIN_STATUS_NOTARIZED, &block->hash, &old_status, &old_hash );
  if( FD_UNLIKELY( !had ) ) return event;

  switch( old_status ) {
    case AG_FIN_STATUS_NOTARIZED:
    case AG_FIN_STATUS_FINALIZED:
    case AG_FIN_STATUS_IMPLICITLY_FINALIZED:
      FD_TEST( 0==memcmp( old_hash.uc, block->hash.uc, sizeof(fd_hash_t) ) );
      return event;
    case AG_FIN_STATUS_IMPLICITLY_SKIPPED:
      return event;
    case AG_FIN_STATUS_FINAL_PENDING_NOTAR: {
      int s2; fd_hash_t h2;
      status_insert( self, block->slot, AG_FIN_STATUS_FINALIZED, &block->hash, &s2, &h2 );
      handle_finalized_block( self, block, &event );
      return event;
    }
    default:
      FD_LOG_ERR(( "unexpected status %d", old_status ));
  }
}

ag_finalization_event_t
ag_finality_tracker_mark_finalized( ag_finality_tracker_t * self,
                                    ulong                   slot ) {
  ag_finalization_event_t event = event_default();
  if( FD_UNLIKELY( slot < self->first_unpruned_slot ) ) return event;

  fd_hash_t zero; fd_memset( &zero, 0, sizeof(fd_hash_t) );
  int old_status; fd_hash_t old_hash;
  int had = status_insert( self, slot, AG_FIN_STATUS_FINAL_PENDING_NOTAR, &zero, &old_status, &old_hash );
  if( FD_UNLIKELY( !had ) ) return event;

  switch( old_status ) {
    case AG_FIN_STATUS_FINAL_PENDING_NOTAR:
    case AG_FIN_STATUS_FINALIZED:
    case AG_FIN_STATUS_IMPLICITLY_FINALIZED:
      return event;
    case AG_FIN_STATUS_NOTARIZED: {
      ag_block_id_t block = { .slot=slot, .hash=old_hash };
      int s2; fd_hash_t h2;
      status_insert( self, slot, AG_FIN_STATUS_FINALIZED, &old_hash, &s2, &h2 );
      handle_finalized_block( self, &block, &event );
      return event;
    }
    case AG_FIN_STATUS_IMPLICITLY_SKIPPED:
    default:
      FD_LOG_ERR(( "consensus safety violation" ));
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
                            fd_hash_t *                   out_hash ) {
  ag_ft_status_ele_t const * e = status_map_ele_query_const( self->status_map, &slot, NULL, self->status_pool );
  if( FD_UNLIKELY( !e ) ) return -1;
  if( out_hash ) *out_hash = e->hash;
  return e->status;
}

int
ag_finality_tracker_has_parent( ag_finality_tracker_t const * self,
                                ag_block_id_t const *         block ) {
  return !!parent_map_ele_query_const( self->parent_map, block, NULL, self->parent_pool );
}
