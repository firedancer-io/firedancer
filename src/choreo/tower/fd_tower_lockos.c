#include "fd_tower_lockos.h"
#include "fd_tower.h"

void *
fd_tower_lockos_new( void * shmem,
                     ulong  slot_max,
                     ulong  vtr_max,
                     ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong footprint = fd_tower_lockos_footprint( slot_max, vtr_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tower_lockos_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong interval_max = fd_ulong_pow2_up( FD_TOWER_LOCKOS_MAX*slot_max*vtr_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_tower_lockos_t * lockos        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_lockos_t),            sizeof(fd_tower_lockos_t)                               );
  void *              slot_pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_lockos_slot_pool_align(),     fd_tower_lockos_slot_pool_footprint( interval_max )     );
  void *              slot_map      = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_lockos_slot_map_align(),      fd_tower_lockos_slot_map_footprint ( slot_max )         );
  void *              interval_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_lockos_interval_pool_align(), fd_tower_lockos_interval_pool_footprint( interval_max ) );
  void *              interval_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_lockos_interval_map_align(),  fd_tower_lockos_interval_map_footprint ( interval_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_tower_lockos_align() )==(ulong)shmem + footprint );

  lockos->slot_pool     = fd_tower_lockos_slot_pool_new    ( slot_pool,     interval_max       );
  lockos->slot_map      = fd_tower_lockos_slot_map_new     ( slot_map,      slot_max,     seed );
  lockos->interval_pool = fd_tower_lockos_interval_pool_new( interval_pool, interval_max       );
  lockos->interval_map  = fd_tower_lockos_interval_map_new ( interval_map,  interval_max, seed );

  FD_TEST( lockos->slot_map );
  FD_TEST( lockos->slot_pool );
  FD_TEST( lockos->interval_map );
  FD_TEST( lockos->interval_pool );

  return shmem;
}

fd_tower_lockos_t *
fd_tower_lockos_join( void * shlockos ) {

  fd_tower_lockos_t * lockos = (fd_tower_lockos_t *)shlockos;

  if( FD_UNLIKELY( !lockos ) ) {
    FD_LOG_WARNING(( "NULL tower_lockos" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)lockos, fd_tower_lockos_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tower_lockos" ));
    return NULL;
  }

  lockos->slot_map      = fd_tower_lockos_slot_map_join     ( lockos->slot_map      );
  lockos->slot_pool     = fd_tower_lockos_slot_pool_join    ( lockos->slot_pool     );
  lockos->interval_map  = fd_tower_lockos_interval_map_join ( lockos->interval_map  );
  lockos->interval_pool = fd_tower_lockos_interval_pool_join( lockos->interval_pool );

  FD_TEST( lockos->slot_map );
  FD_TEST( lockos->slot_pool );
  FD_TEST( lockos->interval_map );
  FD_TEST( lockos->interval_pool );

  return lockos;
}

void *
fd_tower_lockos_leave( fd_tower_lockos_t const * lockos ) {

  if( FD_UNLIKELY( !lockos ) ) {
    FD_LOG_WARNING(( "NULL lockos" ));
    return NULL;
  }

  return (void *)lockos;
}

void *
fd_tower_lockos_delete( void * lockos ) {

  if( FD_UNLIKELY( !lockos ) ) {
    FD_LOG_WARNING(( "NULL lockos" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)lockos, fd_tower_lockos_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned lockos" ));
    return NULL;
  }

  return lockos;
}

void
fd_tower_lockos_insert( fd_tower_lockos_t * lockos,
                        ulong               slot,
                        fd_hash_t const *   addr,
                        fd_tower_voters_t * voters ) {

  uchar __attribute__((aligned(FD_TOWER_ALIGN))) scratch[ FD_TOWER_FOOTPRINT ];
  fd_tower_t * scratch_tower = fd_tower_join( fd_tower_new( scratch ) );

  FD_TEST( voters->valid_data );
  fd_tower_from_vote_acc( scratch_tower, voters->data );

  for( fd_tower_iter_t iter = fd_tower_iter_init( scratch_tower );
                             !fd_tower_iter_done( scratch_tower, iter );
                       iter = fd_tower_iter_next( scratch_tower, iter ) ) {
    fd_tower_t * vote           = fd_tower_iter_ele( scratch_tower, iter );
    ulong        interval_start = vote->slot;
    ulong        interval_end   = vote->slot + ( 1UL << vote->conf );
    ulong        key            = fd_tower_lockos_interval_key( slot, interval_end );

    if( !fd_tower_lockos_interval_map_ele_query( lockos->interval_map, &key, NULL, lockos->interval_pool ) ) {
      FD_TEST( fd_tower_lockos_slot_pool_free( lockos->slot_pool ) ); /* [slot, interval_end] is a new vote interval. guaranteed to have space because we size slot pool to max voters * max slots. */
      fd_tower_lockos_slot_t * slot_ele = fd_tower_lockos_slot_pool_ele_acquire( lockos->slot_pool );
      slot_ele->fork_slot               = slot; /* map multi, multiple keys for the same fork_slot */
      slot_ele->interval_end            = interval_end;
      FD_TEST( fd_tower_lockos_slot_map_ele_insert( lockos->slot_map, slot_ele, lockos->slot_pool ) );
    }

    FD_TEST( fd_tower_lockos_interval_pool_free( lockos->interval_pool ) );
    fd_tower_lockos_interval_t * interval = fd_tower_lockos_interval_pool_ele_acquire( lockos->interval_pool );
    interval->key                         = key;
    interval->addr                        = *addr;
    interval->start                       = interval_start;
    FD_TEST( fd_tower_lockos_interval_map_ele_insert( lockos->interval_map, interval, lockos->interval_pool ) );
  }
}

void
fd_tower_lockos_remove( fd_tower_lockos_t * lockos,
                        ulong               slot ) {

  for( fd_tower_lockos_slot_t * sloti = fd_tower_lockos_slot_map_ele_remove( lockos->slot_map, &slot, NULL, lockos->slot_pool );
                                sloti;
                                sloti = fd_tower_lockos_slot_map_ele_remove( lockos->slot_map, &slot, NULL, lockos->slot_pool ) ) {
    ulong key = fd_tower_lockos_interval_key( slot, sloti->interval_end );
    for( fd_tower_lockos_interval_t * itrvl = fd_tower_lockos_interval_map_ele_remove( lockos->interval_map, &key, NULL, lockos->interval_pool );
                                      itrvl;
                                      itrvl = fd_tower_lockos_interval_map_ele_remove( lockos->interval_map, &key, NULL, lockos->interval_pool ) ) {
      fd_tower_lockos_interval_pool_ele_release( lockos->interval_pool, itrvl );
    }
    fd_tower_lockos_slot_pool_ele_release( lockos->slot_pool, sloti );
  }
}
