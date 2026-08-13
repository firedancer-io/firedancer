#include "ag_finality_tracker.h"

/* status_hash returns the hash the status carries, or NULL for the two
   kinds that carry none -- the same shape as ag_cert_block_hash. */

FD_FN_PURE static fd_hash_t const *
status_hash( ag_finalization_status_t const * status ) {
  switch( status->kind ) {
  case AG_FINALIZATION_STATUS_NOTARIZED:            return &status->inner.notarized.hash;
  case AG_FINALIZATION_STATUS_FINALIZED:            return &status->inner.finalized.hash;
  case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED: return &status->inner.implicitly_finalized.hash;
  default:                                          return NULL;
  }
}

struct status_ele {
  ulong                    slot;
  ag_finalization_status_t status;
  ulong                    next;
};
typedef struct status_ele status_ele_t;

#define POOL_NAME status_pool
#define POOL_T    status_ele_t
#define POOL_NEXT next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               status_map
#define MAP_ELE_T              status_ele_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

struct parent_ele {
  ag_block_id_t block_id; /* key */
  ag_block_id_t parent_block_id;
  ulong         next;
};
typedef struct parent_ele parent_ele_t;

#define POOL_NAME parent_pool
#define POOL_T    parent_ele_t
#define POOL_NEXT next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               parent_map
#define MAP_ELE_T              parent_ele_t
#define MAP_KEY                block_id
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_EQ(k0,k1)      (ag_block_id_eq( (k0), (k1) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( (seed), (key), sizeof(ag_block_id_t) ))
#define MAP_NEXT               next
#include "../../../util/tmpl/fd_map_chain.c"

/* Each of the reference's two BTreeMaps (finality_tracker.rs) is two
   objects here: the fd_pool the elements live in and the fd_map_chain
   that keys them.  Neither needs the ordering a BTreeMap gives -- pruning
   drops status by walking the slots it just decided, and parents by the
   same scan the reference's retain does -- so there is no third,
   order-keeping object.  Wrapping the pair gives the tracker the same
   field list the reference has -- status, parents, and the two
   watermarks -- rather than spreading one logical map over two fields. */

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

  struct {
    ag_block_id_t * implicitly_finalized;
    ulong *         implicitly_skipped;
  } scratch;
};


/* status_insert is the reference's status.insert: records slot's status and
   returns 1 with whatever it displaced written to old_status, or 0 if the
   slot had none (old_status untouched).  old_status may be NULL. */

static int
status_insert( ag_finality_tracker_t *    self,
               ulong                      slot,
               ag_finalization_status_t   status,
               ag_finalization_status_t * old ) {
  status_ele_t * ele = status_map_ele_query( self->status.map, &slot, NULL, self->status.pool );
  if( FD_LIKELY( ele ) ) {
    if( old ) *old = ele->status;
    ele->status = status;
    return 1;
  }
  status_ele_t * pool = self->status.pool;
  ele                 = status_pool_ele_acquire( pool );
  ele->slot           = slot;
  ele->status         = status;
  status_map_ele_insert( self->status.map, ele, pool );
  return 0;
}

/* parent_below returns any parent entry for a slot under root, or NULL
   once none is left.  parents is keyed by block id, so there is no slot to
   look a victim up by and the search is a scan -- the same one the
   reference's parents.retain does, just one victim at a time because the
   map iterator does not survive a removal. */

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
  /* status.get(&next).is_some_and( decided ) */
  ulong          root = self->first_unpruned_slot; /* where the last prune stopped */
  ulong          next = root + 1UL;
  status_ele_t * se;
  while( ( se = status_map_ele_query( self->status.map, &next, NULL, self->status.pool ) ) &&
         ( se->status.kind==AG_FINALIZATION_STATUS_FINALIZED            ||
           se->status.kind==AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED ||
           se->status.kind==AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED   ) ) {
    self->first_unpruned_slot = next;
    next++;
  }

  /* status.split_off(&root): slot-keyed, so the drop is a walk over the
     slots this call just decided rather than a search for the lowest. */

  for( ulong slot=root; slot<self->first_unpruned_slot; slot++ ) {
    status_ele_t * e = status_map_ele_remove( self->status.map, &slot, NULL, self->status.pool );
    if( FD_LIKELY( e ) ) status_pool_ele_release( self->status.pool, e );
  }

  /* parents.retain( slot>=root ) */

  parent_ele_t * pe;
  while( ( pe = parent_below( self, self->first_unpruned_slot ) ) ) {
    parent_map_ele_remove( self->parents.map, &pe->block_id, NULL, self->parents.pool );
    parent_pool_ele_release( self->parents.pool, pe );
  }
}

/* hash_is_zero: the all-zeros hash is the placeholder recorded by the
   mid-chain root seed (ag_finality_tracker_new / seed_root with an
   unknown root block id at snapshot boot).  Genesis is otherwise the only
   slot whose real hash IS zero. */

static inline int
hash_is_zero( fd_hash_t const * h ) {
  return 0UL==( h->ul[0] | h->ul[1] | h->ul[2] | h->ul[3] );
}

/* check_same_hash aborts with full context when a slot is reported with
   two different hashes -- either real cluster equivocation past quorum
   (consensus safety violation) or a cert verified against the wrong
   validator set.  A zero old hash is the seed placeholder, not a
   conflict: the caller's status_insert has already recorded the real
   hash, so just adopt it. */

static void
check_same_hash( char const *      where,
                 ulong             slot,
                 int               old_status,
                 fd_hash_t const * old_hash,
                 fd_hash_t const * new_hash ) {
  if( FD_LIKELY( 0==memcmp( old_hash->uc, new_hash->uc, sizeof(fd_hash_t) ) ) ) return;
  if( FD_UNLIKELY( hash_is_zero( old_hash ) ) ) {
    FD_LOG_INFO(( "adopting block id for zero-seeded slot %lu (%s)", slot, where ));
    return;
  }
  FD_BASE58_ENCODE_32_BYTES( old_hash->uc, old_b58 );
  FD_BASE58_ENCODE_32_BYTES( new_hash->uc, new_b58 );
  FD_LOG_ERR(( "consensus safety violation (%s): slot %lu old_status %d old_hash %s new_hash %s",
               where, slot, old_status, old_b58, new_b58 ));
}

static void
handle_implicitly_finalized( ag_finality_tracker_t *   self,
                             ulong                     source_slot,
                             ag_block_id_t const *     implicitly_finalized,
                             ag_finalization_event_t * event ) {
  FD_TEST( source_slot > implicitly_finalized->slot );

  /* Both lists push into the tracker's scratch.  event_default leaves them
     empty, so the first walk to reach here is what aims them; doing it
     unconditionally keeps the pushes below a plain event mutation. */

  event->implicitly_finalized = self->scratch.implicitly_finalized;
  event->implicitly_skipped   = self->scratch.implicitly_skipped;

  for(ulong slot = implicitly_finalized->slot + 1; ; slot++) {
  if( FD_UNLIKELY( slot==source_slot ) ) break;

    ag_finalization_status_t old;
    int some = status_insert( self, slot, (ag_finalization_status_t){ .kind = AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED }, &old );
    if( some ) {
      switch( old.kind ) {
        case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
          return; /* already walked this stretch */
        case AG_FINALIZATION_STATUS_NOTARIZED:
          break;
        case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
        case AG_FINALIZATION_STATUS_FINALIZED:
        case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
        default:
          FD_LOG_ERR(( "consensus safety violation (implicit_skip): slot %lu old_status %d", slot, old.kind ));
      }
    }
    event->implicitly_skipped[ event->implicitly_skipped_cnt++ ] = slot;
  }

    ag_finalization_status_t implicitly_finalized = { .kind = AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED, .inner.implicitly_finalized.hash = cur.hash };
    ag_finalization_status_t old;
    int had = status_insert( self, cur.slot, &implicitly_finalized, &old );
    if( had ) {
      fd_hash_t const * old_hash = status_hash( &old );
      switch( old.kind ) {
        case AG_FINALIZATION_STATUS_FINALIZED:
        case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
          check_same_hash( "implicit_finalize", cur.slot, old.kind, old_hash, &cur.hash );

          /* Restore the kind we displaced, keeping its hash unless it was
             the zero seed placeholder. */
          { ag_finalization_status_t keep = old;
            if( hash_is_zero( old_hash ) ) keep.inner.finalized.hash = cur.hash;
            status_insert( self, cur.slot, &keep, NULL ); }
          return;
        case AG_FINALIZATION_STATUS_NOTARIZED:
          check_same_hash( "implicit_finalize", cur.slot, old.kind, old_hash, &cur.hash );
          break;
        case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
          break;
        case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
        default:
          FD_LOG_ERR(( "consensus safety violation (implicit_finalize): slot %lu old_status %d", cur.slot, old.kind ));
      }
    }
    event->implicitly_finalized[ event->implicitly_finalized_cnt++ ] = cur;

    parent_ele_t * pe = parent_map_ele_query( self->parents.map, &cur, NULL, self->parents.pool );
    if( FD_UNLIKELY( !pe ) ) return;
    source_slot = cur.slot;
    cur         = pe->parent_block_id;
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
  ulong parent_max = AG_BLOCKID_MAX( slot_max ); /* one entry per block id the window can hold */
  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( parent_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
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
      alignof(ag_block_id_t),         sizeof(ag_block_id_t)*slot_max                 ),
      alignof(ulong),                 sizeof(ulong)        *slot_max                 ),
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

  slot_max    = fd_ulong_pow2_up( slot_max    );
  ulong parent_max = AG_BLOCKID_MAX( slot_max ); /* one entry per block id the window can hold */

  fd_memset( shmem, 0, footprint );

  ulong status_chain_cnt = status_map_chain_cnt_est( slot_max    );
  ulong parent_chain_cnt = parent_map_chain_cnt_est( parent_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  ag_finality_tracker_t * tracker      = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_finality_tracker_t), sizeof(ag_finality_tracker_t)              );
  void *                  status_pool  = FD_SCRATCH_ALLOC_APPEND( l, status_pool_align(),            status_pool_footprint ( slot_max         ) );
  void *                  status_map   = FD_SCRATCH_ALLOC_APPEND( l, status_map_align(),             status_map_footprint  ( status_chain_cnt ) );
  void *                  parent_pool  = FD_SCRATCH_ALLOC_APPEND( l, parent_pool_align(),            parent_pool_footprint ( parent_max       ) );
  void *                  parent_map   = FD_SCRATCH_ALLOC_APPEND( l, parent_map_align(),             parent_map_footprint  ( parent_chain_cnt ) );
  void *                  if_scratch   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_block_id_t),         sizeof(ag_block_id_t)*slot_max             );
  void *                  is_scratch   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                 sizeof(ulong)        *slot_max             );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, ag_finality_tracker_align() ) == (ulong)shmem + footprint );

  tracker->status.pool  = status_pool_join( status_pool_new( status_pool, slot_max               ) );
  tracker->status.map   = status_map_join ( status_map_new ( status_map,  status_chain_cnt, seed ) );
  tracker->parents.pool = parent_pool_join( parent_pool_new( parent_pool, parent_max            ) );
  tracker->parents.map  = parent_map_join ( parent_map_new ( parent_map,  parent_chain_cnt, seed ) );

  tracker->scratch.implicitly_finalized = (ag_block_id_t *)if_scratch;
  tracker->scratch.implicitly_skipped   = (ulong *)is_scratch;

  tracker->highest_finalized_slot = ULONG_MAX; /* no root until set_root */
  tracker->first_unpruned_slot    = ULONG_MAX;

  return shmem;
}

void
ag_finality_tracker_set_root( ag_finality_tracker_t * self,
                              ulong                   root_slot,
                              fd_hash_t const *       root_hash ) {
  FD_TEST( self->highest_finalized_slot==ULONG_MAX ); /* set_root is once-only */

  self->highest_finalized_slot = root_slot;
  self->first_unpruned_slot    = root_slot;

  ag_finalization_status_t notarized = { .kind = AG_FINALIZATION_STATUS_NOTARIZED };
  if( root_hash ) notarized.inner.notarized.hash = *root_hash; /* else the zero seed placeholder */
  status_insert( self, root_slot, &notarized, NULL );
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
  ag_finalization_event_t event = ag_finalization_event_default();
  FD_TEST( block->slot > parent->slot );

  if( FD_UNLIKELY( block->slot < self->first_unpruned_slot ) ) return event;

  parent_ele_t * pe = parent_map_ele_query( self->parents.map, block, NULL, self->parents.pool );
  if( FD_LIKELY( pe ) ) {
    FD_TEST( ag_block_id_eq( &pe->parent_block_id, parent ) );
    return event;
  }
  {
    parent_ele_t * pool = self->parents.pool;
    FD_TEST( parent_pool_free( pool ) );
    pe         = parent_pool_ele_acquire( pool );
    pe->block_id    = *block;
    pe->parent_block_id = *parent;
    parent_map_ele_insert( self->parents.map, pe, pool );
  }

  status_ele_t * se = status_map_ele_query( self->status.map, &block->slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !se ) ) return event;

  switch( se->status.kind ) {
    case AG_FINALIZATION_STATUS_FINALIZED:
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      if( 0==memcmp( block->hash.uc, status_hash( &se->status )->uc, sizeof(fd_hash_t) ) ) {
        ag_block_id_t p = *parent;
        handle_implicitly_finalized( self, block->slot, &p, &event );
        prune( self );
      }
      return event;
    case AG_FINALIZATION_STATUS_NOTARIZED:
    case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
    case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
    default:
      return event;
  }
}

ag_finalization_event_t
ag_finality_tracker_mark_fast_finalized( ag_finality_tracker_t * self,
                                         ag_block_id_t const *   block ) {
  ag_finalization_event_t event = ag_finalization_event_default();
  if( FD_UNLIKELY( block->slot < self->first_unpruned_slot ) ) return event;

  ag_finalization_status_t finalized = { .kind = AG_FINALIZATION_STATUS_FINALIZED, .inner.finalized.hash = block->hash };
  ag_finalization_status_t old;
  int had = status_insert( self, block->slot, &finalized, &old );
  if( had ) {
    switch( old.kind ) {
      case AG_FINALIZATION_STATUS_FINALIZED:
      case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
        check_same_hash( "fast_finalize", block->slot, old.kind, status_hash( &old ), &block->hash );
        return event;
      case AG_FINALIZATION_STATUS_NOTARIZED:
        check_same_hash( "fast_finalize", block->slot, old.kind, status_hash( &old ), &block->hash );
        break;
      case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
        break;
      case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
      default:
        FD_LOG_ERR(( "consensus safety violation (fast_finalize): slot %lu old_status %d", block->slot, old.kind ));
    }
  }

  handle_finalized_block( self, block, &event );
  return event;
}

ag_finalization_event_t
ag_finality_tracker_mark_notarized( ag_finality_tracker_t * self,
                                    ag_block_id_t const *   block ) {
  ag_finalization_event_t event = ag_finalization_event_default();
  if( FD_UNLIKELY( block->slot < self->first_unpruned_slot ) ) return event;

  ag_finalization_status_t notarized = { .kind = AG_FINALIZATION_STATUS_NOTARIZED, .inner.notarized.hash = block->hash };
  ag_finalization_status_t old;
  int had = status_insert( self, block->slot, &notarized, &old );
  if( FD_UNLIKELY( !had ) ) return event;

  switch( old.kind ) {
    case AG_FINALIZATION_STATUS_NOTARIZED:
    case AG_FINALIZATION_STATUS_FINALIZED:
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      check_same_hash( "notarize", block->slot, old.kind, status_hash( &old ), &block->hash );
      return event;
    case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
      return event;
    case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR: {
      ag_finalization_status_t finalized = { .kind = AG_FINALIZATION_STATUS_FINALIZED, .inner.finalized.hash = block->hash };
      status_insert( self, block->slot, &finalized, NULL );
      handle_finalized_block( self, block, &event );
      return event;
    }
    default:
      FD_LOG_ERR(( "unexpected status %d", old.kind ));
  }
}

ag_finalization_event_t
ag_finality_tracker_mark_finalized( ag_finality_tracker_t * self,
                                    ulong                   slot ) {
  ag_finalization_event_t event = ag_finalization_event_default();
  if( FD_UNLIKELY( slot < self->first_unpruned_slot ) ) return event;

  ag_finalization_status_t pending = { .kind = AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR };
  ag_finalization_status_t old;
  int had = status_insert( self, slot, &pending, &old );
  if( FD_UNLIKELY( !had ) ) return event;

  switch( old.kind ) {
    case AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR:
    case AG_FINALIZATION_STATUS_FINALIZED:
    case AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED:
      return event;
    case AG_FINALIZATION_STATUS_NOTARIZED: {
      if( FD_UNLIKELY( hash_is_zero( &old.inner.notarized.hash ) ) ) return event; /* zero-seeded root: hash unknown, stay FINAL_PENDING_NOTAR until the notar cert supplies it */
      ag_block_id_t         block     = { .slot=slot, .hash=old.inner.notarized.hash };
      ag_finalization_status_t finalized = { .kind = AG_FINALIZATION_STATUS_FINALIZED, .inner.finalized.hash = old.inner.notarized.hash };
      status_insert( self, slot, &finalized, NULL );
      handle_finalized_block( self, &block, &event );
      return event;
    }
    case AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED:
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
  status_ele_t const * e = status_map_ele_query_const( self->status.map, &slot, NULL, self->status.pool );
  if( FD_UNLIKELY( !e ) ) return -1;
  if( out_hash ) {
    fd_hash_t const * hash = status_hash( &e->status );
    if( hash ) *out_hash = *hash;
    else       fd_memset( out_hash, 0, sizeof(fd_hash_t) ); /* kind carries none */
  }
  return e->status.kind;
}

int
ag_finality_tracker_has_parent( ag_finality_tracker_t const * self,
                                ag_block_id_t const *         block ) {
  return !!parent_map_ele_query_const( self->parents.map, block, NULL, self->parents.pool );
}
