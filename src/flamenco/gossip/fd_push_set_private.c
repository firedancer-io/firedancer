/* source file meant to be directly included in fd_gossip.c */

struct push_set_entry {
  fd_gossip_crds_msg_builder_t builder[1];
  /* We use fd_pool APIs because fd_dlist doesn't work without it and
    there are no suitable linked list APIs. However, because we want
    to track the active set indices, we also need to bypass the native
    acquire/release mechanism provided by fd_pool and use it as an
    array instead. */
  struct {
    ulong next;
    uchar in_use;
  } pool;
  struct{
    long  wallclock_nanos;
    ulong prev;
    ulong next;
  } last_hit;
};

typedef struct push_set_entry push_set_entry_t;

#define POOL_NAME pset_entry_pool
#define POOL_T    push_set_entry_t
#define POOL_NEXT pool.next
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  pset_last_hit
#define DLIST_ELE_T push_set_entry_t
#define DLIST_PREV  last_hit.prev
#define DLIST_NEXT  last_hit.next

#include "../../util/tmpl/fd_dlist.c"

struct push_set {
  push_set_entry_t *  pool;
  pset_last_hit_t *   last_hit;
};

typedef struct push_set push_set_t;

ulong
push_set_align( void ) {
  return pset_entry_pool_align();
}

ulong
push_set_footprint( ulong ele_max ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, pset_entry_pool_align(), pset_entry_pool_footprint( ele_max ) );
  l = FD_LAYOUT_APPEND( l, pset_last_hit_align(),   pset_last_hit_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(push_set_t),     sizeof(push_set_t) );
  l = FD_LAYOUT_FINI( l, push_set_align() );
  return l;
}

void *
push_set_new( void * shmem,
               ulong ele_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_ERR(( "NULL shmem" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, push_set_align() ) ) ) {
    FD_LOG_ERR(( "misaligned shmem" ));
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void *       _pool          = FD_SCRATCH_ALLOC_APPEND( l, pset_entry_pool_align(), pset_entry_pool_footprint( ele_max ) );
  void *       _last_appended = FD_SCRATCH_ALLOC_APPEND( l, pset_last_hit_align(), pset_last_hit_footprint() );
  push_set_t * push_set       = FD_SCRATCH_ALLOC_APPEND( l, alignof(push_set_t), sizeof(push_set_t) );

  push_set->pool     = pset_entry_pool_join(   pset_entry_pool_new( _pool, ele_max ) );
  push_set->last_hit = pset_last_hit_join( pset_last_hit_new( _last_appended ) );

  for( ulong i=0UL; i<ele_max; i++ ) {
    push_set_entry_t * entry = pset_entry_pool_ele( push_set->pool, i );
    entry->pool.in_use       = 0U;
  }

  return (void *)push_set;
}

push_set_t *
push_set_join( void * shpool ) {
  if( FD_UNLIKELY( !shpool ) ) {
    FD_LOG_ERR(( "NULL shpool" ));
  }
  return (push_set_t *)shpool;
}

void
push_set_pop_append( push_set_t *       pset,
                     push_set_entry_t * state,
                     long               now ) {
  state->last_hit.wallclock_nanos = now;
  pset_last_hit_ele_remove( pset->last_hit, state, pset->pool );
  pset_last_hit_ele_push_tail( pset->last_hit, state, pset->pool );
}
