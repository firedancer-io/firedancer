#include "fd_tower_blocks.h"

void *
fd_tower_blocks_new( void * shmem,
                     ulong  slot_max,
                     ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong footprint = fd_tower_blocks_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tower_blocks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  int   lg_slot_max  = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_tower_blocks_t * blocks = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_blocks_align(), sizeof(fd_tower_blocks_t)             );
  void *              map    = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_blk_align(),    fd_tower_blk_footprint( lg_slot_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_tower_blocks_align() ) == (ulong)shmem + footprint );

  blocks->blk_map = fd_tower_blk_new( map, lg_slot_max, seed );
  FD_TEST( blocks->blk_map );

  return shmem;
}

fd_tower_blocks_t *
fd_tower_blocks_join( void * shblocks ) {
  fd_tower_blocks_t * blocks = (fd_tower_blocks_t *)shblocks;

  if( FD_UNLIKELY( !blocks ) ) {
    FD_LOG_WARNING(( "NULL tower_blocks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)blocks, fd_tower_blocks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tower_blocks" ));
    return NULL;
  }

  blocks->blk_map = fd_tower_blk_join( blocks->blk_map );
  FD_TEST( blocks->blk_map );

  return blocks;
}

void *
fd_tower_blocks_leave( fd_tower_blocks_t const * blocks ) {

  if( FD_UNLIKELY( !blocks ) ) {
    FD_LOG_WARNING(( "NULL blocks" ));
    return NULL;
  }

  return (void *)blocks;
}

void *
fd_tower_blocks_delete( void * blocks ) {

  if( FD_UNLIKELY( !blocks ) ) {
    FD_LOG_WARNING(( "NULL blocks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)blocks, fd_tower_blocks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned blocks" ));
    return NULL;
  }

  return blocks;
}

int
is_ancestor( fd_tower_blk_t * forks,
             ulong              slot,
             ulong              ancestor_slot ) {
  fd_tower_blk_t * anc = fd_tower_blk_query( forks, slot, NULL );
  while( FD_LIKELY( anc ) ) {
    if( FD_LIKELY( anc->parent_slot == ancestor_slot ) ) return 1;
    anc = anc->parent_slot == ULONG_MAX ? NULL : fd_tower_blk_query( forks, anc->parent_slot, NULL );
  }
  return 0;
}

int
fd_tower_blocks_is_slot_ancestor( fd_tower_blocks_t * forks,
                           ulong        descendant_slot,
                           ulong        ancestor_slot ) {
  return is_ancestor( forks->blk_map, descendant_slot, ancestor_slot );
}

int
fd_tower_blocks_is_slot_descendant( fd_tower_blocks_t * forks,
                             ulong        ancestor_slot,
                             ulong        descendant_slot ) {
  return is_ancestor( forks->blk_map, descendant_slot, ancestor_slot );
}

ulong
fd_tower_blocks_lowest_common_ancestor( fd_tower_blocks_t * forks,
                                        ulong               slot1,
                                        ulong               slot2 ) {

  fd_tower_blk_t * fork1 = fd_tower_blk_query( forks->blk_map, slot1, NULL );
  fd_tower_blk_t * fork2 = fd_tower_blk_query( forks->blk_map, slot2, NULL );

  if( FD_UNLIKELY( !fork1 )) FD_LOG_CRIT(( "slot1 %lu not found", slot1 ));
  if( FD_UNLIKELY( !fork2 )) FD_LOG_CRIT(( "slot2 %lu not found", slot2 ));

  while( FD_LIKELY( fork1 && fork2 ) ) {
    if( FD_UNLIKELY( fork1->slot == fork2->slot ) ) return fork1->slot;
    if( fork1->slot > fork2->slot                 ) fork1 = fd_tower_blk_query( forks->blk_map, fork1->parent_slot, NULL );
    else                                            fork2 = fd_tower_blk_query( forks->blk_map, fork2->parent_slot, NULL );
  }

  /* If we reach here, then one of the slots is on a minority fork who's
     ancestor that connected it to the main fork has been pruned (i.e.)
     we have a dangling leaf right now! There is no LCA in this case. */

  return ULONG_MAX;
}

fd_hash_t const *
fd_tower_blocks_canonical_block_id( fd_tower_blocks_t * forks,
                                    ulong               slot ) {
  fd_tower_blk_t * fork = fd_tower_blk_query( forks->blk_map, slot, NULL );
  if( FD_UNLIKELY( !fork ) ) return NULL;
  if     ( FD_LIKELY( fork->confirmed ) ) return &fork->confirmed_block_id;
  else if( FD_LIKELY( fork->voted     ) ) return &fork->voted_block_id;
  else                                    return &fork->replayed_block_id;
}

fd_tower_blk_t *
fd_tower_blocks_query( fd_tower_blocks_t * forks, ulong slot ) {
  return fd_tower_blk_query( forks->blk_map, slot, NULL );
}

fd_tower_blk_t *
fd_tower_blocks_insert( fd_tower_blocks_t * forks,
                        ulong               slot,
                        ulong               parent_slot ) {
  fd_tower_blk_t * fork = fd_tower_blk_insert( forks->blk_map, slot );
  if( FD_UNLIKELY( !fork ) ) return NULL;

  memset( fork, 0, sizeof(fd_tower_blk_t) );
  fork->parent_slot      = parent_slot;
  fork->slot             = slot;
  fork->confirmed        = 0;
  fork->voted            = 0;
  fork->prev_leader_slot = ULONG_MAX;
  fork->leader           = 0;
  fork->propagated       = 0;
  return fork;
}

void
fd_tower_blocks_remove( fd_tower_blocks_t * forks,
                        ulong               slot ) {
  fd_tower_blk_t * blk = fd_tower_blk_query( forks->blk_map, slot, NULL ); /* validate slot exists before removing */
  if( FD_LIKELY( blk ) ) fd_tower_blk_remove( forks->blk_map, blk );
}
