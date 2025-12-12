#include "fd_epoch_stakes.h"

void *
fd_epoch_stakes_new( void * shmem,
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
  ulong footprint = fd_epoch_stakes_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }
  /* verify aligned to fd_epoch_stakes_align() */
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_epoch_stakes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  int lg_slot_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_epoch_stakes_t * epoch_stakes          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_epoch_stakes_t),       sizeof(fd_epoch_stakes_t) );
  void *              voter_stake_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_voter_stake_map_align(),       fd_voter_stake_map_footprint ( FD_VOTER_MAX * slot_max ) );
  void *              voter_stake_pool      = FD_SCRATCH_ALLOC_APPEND( l, fd_voter_stake_pool_align(),      fd_voter_stake_pool_footprint( FD_VOTER_MAX * slot_max ) );
  void *              epoch_stakes_slot_map = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stakes_slot_map_align(), fd_epoch_stakes_slot_map_footprint( lg_slot_cnt ) );
  void *              used_acc_scratch      = FD_SCRATCH_ALLOC_APPEND( l, fd_used_acc_scratch_align(),      fd_used_acc_scratch_footprint( FD_VOTER_MAX * slot_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_epoch_stakes_align() ) == (ulong)shmem + footprint );

  epoch_stakes->voter_stake_map  = fd_voter_stake_map_join      ( fd_voter_stake_map_new      ( voter_stake_map,  FD_VOTER_MAX * slot_max, 0 ) );
  epoch_stakes->voter_stake_pool = fd_voter_stake_pool_join     ( fd_voter_stake_pool_new     ( voter_stake_pool, FD_VOTER_MAX * slot_max ) );
  epoch_stakes->slot_stakes_map  = fd_epoch_stakes_slot_map_join( fd_epoch_stakes_slot_map_new( epoch_stakes_slot_map, lg_slot_cnt, 0UL ) );      /* FIXME seed? */
  epoch_stakes->used_acc_scratch = fd_used_acc_scratch_join     ( fd_used_acc_scratch_new     ( used_acc_scratch, FD_VOTER_MAX * slot_max ) );
  return shmem;
}

fd_epoch_stakes_t *
fd_epoch_stakes_join( void * shepoch_stakes ) {
  return shepoch_stakes;
}

ulong
fd_epoch_stakes_slot_stakes_add( fd_epoch_stakes_t * epoch_stakes, ulong slot, fd_hash_t const * vote_account, ulong stake, ulong prev_voter_idx ) {
  fd_voter_stake_t * pool = epoch_stakes->voter_stake_pool;
  if( FD_UNLIKELY( !fd_voter_stake_pool_free( pool ) ) ) FD_LOG_CRIT(( "no free voter stakes in pool" ));
  fd_voter_stake_t * new_voter_stake = fd_voter_stake_pool_ele_acquire( pool );
  new_voter_stake->key   = (fd_voter_stake_key_t){ .vote_account = *vote_account, .slot = slot };
  new_voter_stake->stake = stake;
  new_voter_stake->prev  = prev_voter_idx;
  fd_voter_stake_map_ele_insert( epoch_stakes->voter_stake_map, new_voter_stake, pool );

  /* now update the slot_stakes_map to point to the new head of the linkedlist */
  fd_epoch_stakes_slot_t * slot_stakes = fd_epoch_stakes_slot_map_query( epoch_stakes->slot_stakes_map, slot, NULL );
  if( FD_UNLIKELY( !slot_stakes ) ) {
    slot_stakes = fd_epoch_stakes_slot_map_insert( epoch_stakes->slot_stakes_map, slot );
  }
  slot_stakes->voter_stake_idx = fd_voter_stake_pool_idx( pool, new_voter_stake );
  return slot_stakes->voter_stake_idx;
}

void
fd_epoch_stakes_slot_stakes_remove( fd_epoch_stakes_t * epoch_stakes, fd_epoch_stakes_slot_t * slot ) {
  /* walk stakes linkedlist and remove the voter stake at the given index */
  ulong voter_idx = slot->voter_stake_idx;
  while( FD_UNLIKELY( voter_idx != ULONG_MAX ) ) {
    fd_voter_stake_t * voter_stake = fd_voter_stake_pool_ele( epoch_stakes->voter_stake_pool, voter_idx );
    voter_idx = voter_stake->prev;
    fd_voter_stake_t * remove = fd_voter_stake_map_ele_remove( epoch_stakes->voter_stake_map, &voter_stake->key, NULL, epoch_stakes->voter_stake_pool );
    if( FD_UNLIKELY( !remove ) ) FD_LOG_CRIT(( "invariant violation: voter stake does not exist in map" ));
    fd_voter_stake_pool_ele_release( epoch_stakes->voter_stake_pool, voter_stake );
  }
  fd_epoch_stakes_slot_map_remove( epoch_stakes->slot_stakes_map, slot );
}
