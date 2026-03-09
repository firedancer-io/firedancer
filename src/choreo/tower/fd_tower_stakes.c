#include "fd_tower_stakes.h"

void *
fd_tower_stakes_new( void * shmem,
                     ulong  slot_max,
                     ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong footprint = fd_tower_stakes_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tower_stakes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  int lg_slot_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_tower_stakes_t * tower_stakes      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_stakes_t),       sizeof(fd_tower_stakes_t)                                     );
  void *              voter_stake_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_vtr_map_align(),  fd_tower_stakes_vtr_map_footprint ( FD_VOTER_MAX * slot_max ) );
  void *              voter_stake_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_vtr_pool_align(), fd_tower_stakes_vtr_pool_footprint( FD_VOTER_MAX * slot_max ) );
  void *              tower_stakes_slot = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_slot_align(),      fd_tower_stakes_slot_footprint( lg_slot_cnt )                  );
  void *              used_acc_scratch  = FD_SCRATCH_ALLOC_APPEND( l, fd_used_acc_scratch_align(),      fd_used_acc_scratch_footprint( FD_VOTER_MAX * slot_max )      );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_tower_stakes_align() )==(ulong)shmem + footprint );

  tower_stakes->vtr_map          = fd_tower_stakes_vtr_map_new ( voter_stake_map,  FD_VOTER_MAX * slot_max, seed );
  tower_stakes->vtr_pool         = fd_tower_stakes_vtr_pool_new( voter_stake_pool, FD_VOTER_MAX * slot_max       );
  tower_stakes->slot_map         = fd_tower_stakes_slot_new    ( tower_stakes_slot, lg_slot_cnt,            seed );
  tower_stakes->used_acc_scratch = fd_used_acc_scratch_new     ( used_acc_scratch, FD_VOTER_MAX * slot_max       );
  return shmem;
}

fd_tower_stakes_t *
fd_tower_stakes_join( void * shstakes ) {

  fd_tower_stakes_t * stakes = (fd_tower_stakes_t *)shstakes;

  if( FD_UNLIKELY( !stakes ) ) {
    FD_LOG_WARNING(( "NULL tower_stakes" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)stakes, fd_tower_stakes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tower_stakes" ));
    return NULL;
  }

  stakes->vtr_map            = fd_tower_stakes_vtr_map_join( stakes->vtr_map );
  stakes->vtr_pool           = fd_tower_stakes_vtr_pool_join( stakes->vtr_pool );
  stakes->slot_map           = fd_tower_stakes_slot_join( stakes->slot_map );
  stakes->used_acc_scratch   = fd_used_acc_scratch_join( stakes->used_acc_scratch );

  FD_TEST( stakes->vtr_map );
  FD_TEST( stakes->vtr_pool );
  FD_TEST( stakes->slot_map );
  FD_TEST( stakes->used_acc_scratch );

  return stakes;
}

void *
fd_tower_stakes_leave( fd_tower_stakes_t const * stakes ) {

  if( FD_UNLIKELY( !stakes ) ) {
    FD_LOG_WARNING(( "NULL stakes" ));
    return NULL;
  }

  return (void *)stakes;
}

void *
fd_tower_stakes_delete( void * stakes ) {

  if( FD_UNLIKELY( !stakes ) ) {
    FD_LOG_WARNING(( "NULL stakes" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)stakes, fd_tower_stakes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned stakes" ));
    return NULL;
  }

  return stakes;
}

ulong
fd_tower_stakes_insert( fd_tower_stakes_t * tower_stakes,
                        ulong               slot,
                        fd_hash_t const *   vote_account,
                        ulong               stake,
                        ulong               prev_voter_idx ) {

  fd_tower_stakes_vtr_t * pool = tower_stakes->vtr_pool;
  if( FD_UNLIKELY( !fd_tower_stakes_vtr_pool_free( pool ) ) ) FD_LOG_CRIT(( "no free voter stakes in pool" ));
  fd_tower_stakes_vtr_t * new_voter_stake = fd_tower_stakes_vtr_pool_ele_acquire( pool );
  new_voter_stake->key   = (fd_tower_stakes_vtr_xid_t){ .addr = *vote_account, .slot = slot };
  new_voter_stake->stake = stake;
  new_voter_stake->prev  = prev_voter_idx;
  fd_tower_stakes_vtr_map_ele_insert( tower_stakes->vtr_map, new_voter_stake, pool );

  /* Point to first vtr (head of list). */

  fd_tower_stakes_slot_t * blk = fd_tower_stakes_slot_query( tower_stakes->slot_map, slot, NULL );
  if( FD_UNLIKELY( !blk ) ) blk = fd_tower_stakes_slot_insert( tower_stakes->slot_map, slot );
  blk->head = fd_tower_stakes_vtr_pool_idx( pool, new_voter_stake );
  return blk->head;
}

void
fd_tower_stakes_remove( fd_tower_stakes_t * tower_stakes,
                        ulong               slot ) {

  fd_tower_stakes_slot_t * blk = fd_tower_stakes_slot_query( tower_stakes->slot_map, slot, NULL );
  if( FD_UNLIKELY( !blk ) ) return;
  ulong voter_idx = blk->head;

  /* Remove the linked list of voters. */

  while( FD_UNLIKELY( voter_idx!=ULONG_MAX ) ) {
    fd_tower_stakes_vtr_t * voter_stake = fd_tower_stakes_vtr_pool_ele( tower_stakes->vtr_pool, voter_idx );
    voter_idx = voter_stake->prev;
    fd_tower_stakes_vtr_t * remove = fd_tower_stakes_vtr_map_ele_remove( tower_stakes->vtr_map, &voter_stake->key, NULL, tower_stakes->vtr_pool );
    if( FD_UNLIKELY( !remove ) ) FD_LOG_CRIT(( "invariant violation: voter stake does not exist in map" ));
    fd_tower_stakes_vtr_pool_ele_release( tower_stakes->vtr_pool, voter_stake );
  }
  fd_tower_stakes_slot_remove( tower_stakes->slot_map, blk );
}
