#include "fd_trusted_slots.h"

ulong
fd_trusted_slots_align( void ) {
  return alignof(fd_trusted_slots_t);
}

ulong
fd_trusted_slots_footprint( ulong slots_max ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_trusted_slots_t), sizeof(fd_trusted_slots_t) );
  l = FD_LAYOUT_APPEND( l, fd_slot_pool_align(),        fd_slot_pool_footprint( slots_max ) );
  l = FD_LAYOUT_APPEND( l, fd_slot_treap_align(),       fd_slot_treap_footprint( slots_max ) );
  l = FD_LAYOUT_FINI( l, fd_trusted_slots_align() );
  return l;
}

void *
fd_trusted_slots_new( void * shmem, ulong slot_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL trusted_slots" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_trusted_slots_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned trusted_slots" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT(l, shmem);
  fd_trusted_slots_t * trusted_slots = (fd_trusted_slots_t *)FD_SCRATCH_ALLOC_APPEND( l,  alignof(fd_trusted_slots_t), sizeof(fd_trusted_slots_t) );
  
  void * slot_pool_mem = fd_slot_pool_new( FD_SCRATCH_ALLOC_APPEND( l, fd_slot_pool_align(), fd_slot_pool_footprint( slot_max ) ), slot_max );
  if( !slot_pool_mem ) {
    FD_LOG_WARNING(( "fd_slot_pool_new failed" ));
    return NULL;
  }

  void * slot_treap_mem = fd_slot_treap_new( FD_SCRATCH_ALLOC_APPEND( l, fd_slot_treap_align(), fd_slot_treap_footprint( slot_max ) ), slot_max );
  if( !slot_treap_mem ) {
    FD_LOG_WARNING(( "fd_slot_heap_new failed" ));
    return NULL;
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if ( scratch_top > (ulong)shmem + fd_trusted_slots_footprint( slot_max ) ) {
    FD_LOG_WARNING(( "not enough space allocated for trusted_slots" ));
    return NULL;
  }

  trusted_slots->slot_pool = (fd_slot_ele_t *)slot_pool_mem;
  trusted_slots->slot_treap = (fd_slot_treap_t *)slot_treap_mem;

  return shmem;
}

fd_trusted_slots_t *
fd_trusted_slots_join( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL trusted_slots" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_trusted_slots_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned trusted_slots" ));
    return NULL;
  }
  
  fd_trusted_slots_t * trusted_slots = (fd_trusted_slots_t *)shmem;
  trusted_slots->slot_pool = fd_slot_pool_join( trusted_slots->slot_pool );
  if( !trusted_slots->slot_pool ) {
    FD_LOG_WARNING(( "fd_slot_pool_join failed" ));
    return NULL;
  }

  trusted_slots->slot_treap = fd_slot_treap_join( trusted_slots->slot_treap );
  if( !trusted_slots->slot_treap ) {
    FD_LOG_WARNING(( "fd_slot_heap_join failed" ));
    return NULL;
  }

  return trusted_slots;
}

int
fd_trusted_slots_find( fd_trusted_slots_t * trusted_slots,
                       ulong                slot ) {  
  fd_slot_ele_t * ele = fd_slot_treap_ele_query( trusted_slots->slot_treap, slot, trusted_slots->slot_pool );
  return (ele!=NULL);
}

void
fd_trusted_slots_add( fd_trusted_slots_t * trusted_slots,
                      ulong                slot ) {
  if( fd_trusted_slots_find( trusted_slots, slot ) ) {
    return;
  }

  fd_slot_ele_t * ele = fd_slot_pool_ele_acquire( trusted_slots->slot_pool );
  ele->key = slot;
  
  fd_slot_treap_ele_insert( trusted_slots->slot_treap, ele, trusted_slots->slot_pool );
}

void
fd_trusted_slots_publish( fd_trusted_slots_t * trusted_slots,
                          ulong                root ) {
  fd_slot_ele_t * remove_ele = NULL;
  for( fd_slot_treap_fwd_iter_t iter = fd_slot_treap_fwd_iter_init( trusted_slots->slot_treap, trusted_slots->slot_pool );
       !fd_slot_treap_fwd_iter_done( iter );
       iter = fd_slot_treap_fwd_iter_next( iter, trusted_slots->slot_pool ) ) {
    fd_slot_ele_t * ele = fd_slot_treap_fwd_iter_ele( iter, trusted_slots->slot_pool );
    if( root>ele->key ) {
      /* this next slot is behind the root, delete it */
      remove_ele = ele;
    }

    if( remove_ele!=NULL ) {
      fd_slot_treap_ele_remove( trusted_slots->slot_treap, remove_ele, trusted_slots->slot_pool );
      fd_slot_pool_ele_release( trusted_slots->slot_pool, remove_ele );
      remove_ele = NULL;
    }
  }

  if( remove_ele!=NULL ) {
    fd_slot_treap_ele_remove( trusted_slots->slot_treap, remove_ele, trusted_slots->slot_pool );
    fd_slot_pool_ele_release( trusted_slots->slot_pool, remove_ele );
  }
}