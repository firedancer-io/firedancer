#include "fd_tower_stakes.h"

void *
fd_tower_stakes_new( void * shmem,
                     ulong  slot_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
      FD_LOG_WARNING(( "shmem must be part of a workspace" ));
      return NULL;
  }
  ulong footprint = fd_tower_stakes_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }
  /* verify aligned to fd_tower_stakes_align() */
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tower_stakes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  int lg_slot_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_tower_stakes_t * tower_stakes          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_stakes_t),       sizeof(fd_tower_stakes_t)                                     );
  void *              voter_stake_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_vtr_map_align(),  fd_tower_stakes_vtr_map_footprint ( FD_VOTER_MAX * slot_max ) );
  void *              voter_stake_pool      = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_vtr_pool_align(), fd_tower_stakes_vtr_pool_footprint( FD_VOTER_MAX * slot_max ) );
  void *              tower_stakes_blk = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_blk_align(),      fd_tower_stakes_blk_footprint( lg_slot_cnt )             );
  void *              used_acc_scratch      = FD_SCRATCH_ALLOC_APPEND( l, fd_used_acc_scratch_align(),      fd_used_acc_scratch_footprint( FD_VOTER_MAX * slot_max )      );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_tower_stakes_align() ) == (ulong)shmem + footprint );

  tower_stakes->voter_stake_map  = fd_tower_stakes_vtr_map_join      ( fd_tower_stakes_vtr_map_new      ( voter_stake_map,  FD_VOTER_MAX * slot_max, 0 ) );
  tower_stakes->voter_stake_pool = fd_tower_stakes_vtr_pool_join     ( fd_tower_stakes_vtr_pool_new     ( voter_stake_pool, FD_VOTER_MAX * slot_max ) );
  tower_stakes->slot_stakes_map  = fd_tower_stakes_blk_join( fd_tower_stakes_blk_new( tower_stakes_blk, lg_slot_cnt, 0UL ) );      /* FIXME seed? */
  tower_stakes->used_acc_scratch = fd_used_acc_scratch_join     ( fd_used_acc_scratch_new     ( used_acc_scratch, FD_VOTER_MAX * slot_max ) );
  return shmem;
}

fd_tower_stakes_t *
fd_tower_stakes_join( void * shtower_stakes ) {
  return shtower_stakes;
}

ulong
fd_tower_stakes_vtr_insert( fd_tower_stakes_t * tower_stakes,
                            ulong               slot,
                            fd_hash_t const *   vote_account,
                            ulong               stake,
                            ulong               prev_voter_idx ) {
  fd_tower_stakes_vtr_t * pool = tower_stakes->voter_stake_pool;
  if( FD_UNLIKELY( !fd_tower_stakes_vtr_pool_free( pool ) ) ) FD_LOG_CRIT(( "no free voter stakes in pool" ));
  fd_tower_stakes_vtr_t * new_voter_stake = fd_tower_stakes_vtr_pool_ele_acquire( pool );
  new_voter_stake->key   = (fd_vote_acc_stake_key_t){ .addr = *vote_account, .slot = slot };
  new_voter_stake->stake = stake;
  new_voter_stake->prev  = prev_voter_idx;
  fd_tower_stakes_vtr_map_ele_insert( tower_stakes->voter_stake_map, new_voter_stake, pool );

  /* now update the slot_stakes_map to point to the new head of the linkedlist */
  fd_tower_stakes_blk_t * slot_stakes = fd_tower_stakes_blk_query( tower_stakes->slot_stakes_map, slot, NULL );
  if( FD_UNLIKELY( !slot_stakes ) ) {
    slot_stakes = fd_tower_stakes_blk_insert( tower_stakes->slot_stakes_map, slot );
  }
  slot_stakes->head = fd_tower_stakes_vtr_pool_idx( pool, new_voter_stake );
  return slot_stakes->head;
}

void
fd_tower_stakes_blk_prune( fd_tower_stakes_t     * tower_stakes,
                            fd_tower_stakes_blk_t * blk ) {
  /* walk stakes linkedlist and remove the voter stake at the given index */
  ulong voter_idx = blk->head;
  while( FD_UNLIKELY( voter_idx != ULONG_MAX ) ) {
    fd_tower_stakes_vtr_t * voter_stake = fd_tower_stakes_vtr_pool_ele( tower_stakes->voter_stake_pool, voter_idx );
    voter_idx = voter_stake->prev;
    fd_tower_stakes_vtr_t * remove = fd_tower_stakes_vtr_map_ele_remove( tower_stakes->voter_stake_map, &voter_stake->key, NULL, tower_stakes->voter_stake_pool );
    if( FD_UNLIKELY( !remove ) ) FD_LOG_CRIT(( "invariant violation: voter stake does not exist in map" ));
    fd_tower_stakes_vtr_pool_ele_release( tower_stakes->voter_stake_pool, voter_stake );
  }
  fd_tower_stakes_blk_remove( tower_stakes->slot_stakes_map, blk );
}
