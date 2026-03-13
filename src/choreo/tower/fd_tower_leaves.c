#include "fd_tower_leaves.h"
#include "fd_tower.h"

void *
fd_tower_leaves_new( void * shmem,
                     ulong  slot_max,
                     ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong footprint = fd_tower_leaves_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tower_leaves_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_tower_leaves_t * leaves = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_leaves_align(),       sizeof(fd_tower_leaves_t)                  );
  void *              map    = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_leaves_map_align(),   fd_tower_leaves_map_footprint ( slot_max ) );
  void *              dlist  = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_leaves_dlist_align(), fd_tower_leaves_dlist_footprint()          );
  void *              pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_leaves_pool_align(),  fd_tower_leaves_pool_footprint( slot_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_tower_leaves_align() ) == (ulong)shmem + footprint );

  leaves->map   = fd_tower_leaves_map_new  ( map,  slot_max, seed );
  leaves->pool  = fd_tower_leaves_pool_new ( pool, slot_max       );
  leaves->dlist = fd_tower_leaves_dlist_new( dlist                );

  FD_TEST( leaves->map );
  FD_TEST( leaves->pool );
  FD_TEST( leaves->dlist );

  return shmem;
}

fd_tower_leaves_t *
fd_tower_leaves_join( void * shleaves ) {
  fd_tower_leaves_t * leaves = (fd_tower_leaves_t *)shleaves;

  if( FD_UNLIKELY( !leaves ) ) {
    FD_LOG_WARNING(( "NULL tower_leaves" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)leaves, fd_tower_leaves_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tower_leaves" ));
    return NULL;
  }

  leaves->pool  = fd_tower_leaves_pool_join ( leaves->pool  );
  leaves->map   = fd_tower_leaves_map_join  ( leaves->map   );
  leaves->dlist = fd_tower_leaves_dlist_join( leaves->dlist );

  return leaves;
}

void *
fd_tower_leaves_leave( fd_tower_leaves_t const * leaves ) {

  if( FD_UNLIKELY( !leaves ) ) {
    FD_LOG_WARNING(( "NULL leaves" ));
    return NULL;
  }

  return (void *)leaves;
}

void *
fd_tower_leaves_delete( void * leaves ) {

  if( FD_UNLIKELY( !leaves ) ) {
    FD_LOG_WARNING(( "NULL leaves" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)leaves, fd_tower_leaves_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned leaves" ));
    return NULL;
  }

  return leaves;
}

void
fd_tower_leaves_upsert( fd_tower_leaves_t * leaves,
                        ulong               slot,
                        ulong               parent_slot ) {

  fd_tower_leaves_remove( leaves, parent_slot );
  if( FD_UNLIKELY( fd_tower_leaves_map_ele_query( leaves->map, &slot, NULL, leaves->pool ) ) ) {
    FD_LOG_WARNING(( "[%s] slot %lu already in leaves. ignoring.", __func__, slot )); /* FIXME equivocation cases https://github.com/firedancer-io/firedancer/issues/8743 */
  }
  fd_tower_leaf_t * leaf = fd_tower_leaves_pool_ele_acquire( leaves->pool );
  leaf->slot             = slot;
  fd_tower_leaves_map_ele_insert( leaves->map, leaf, leaves->pool );
  fd_tower_leaves_dlist_ele_push_tail( leaves->dlist, leaf, leaves->pool );
}

void
fd_tower_leaves_remove( fd_tower_leaves_t * leaves,
                        ulong               slot ) {

  fd_tower_leaf_t * leaf = fd_tower_leaves_map_ele_remove( leaves->map, &slot, NULL, leaves->pool );
  if( FD_UNLIKELY( leaf ) ) {
    fd_tower_leaves_dlist_ele_remove( leaves->dlist, leaf, leaves->pool );
    fd_tower_leaves_pool_ele_release( leaves->pool,  leaf );
  }
}
