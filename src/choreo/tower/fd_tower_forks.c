#include "fd_tower_forks.h"

int
is_ancestor( fd_tower_forks_t * forks,
             ulong              slot,
             ulong              ancestor_slot ) {
  fd_tower_forks_t * anc = fd_tower_forks_query( forks, slot, NULL );
  while( FD_LIKELY( anc ) ) {
    if( FD_LIKELY( anc->parent_slot == ancestor_slot ) ) return 1;
    anc = fd_tower_forks_query( forks, anc->parent_slot, NULL );
  }
  return 0;
}

int
fd_tower_forks_is_slot_ancestor( fd_tower_forks_t * forks,
                                 ulong              descendant_slot,
                                 ulong              ancestor_slot ) {
  return is_ancestor( forks, descendant_slot, ancestor_slot );
}

int
fd_tower_forks_is_slot_descendant( fd_tower_forks_t * forks,
                                   ulong              ancestor_slot,
                                   ulong              descendant_slot ) {
  return is_ancestor( forks, descendant_slot, ancestor_slot );
}

ulong
fd_tower_forks_lowest_common_ancestor( fd_tower_forks_t * forks,
                                       ulong              slot1,
                                       ulong              slot2 ) {
  fd_tower_forks_t * fork1 = fd_tower_forks_query( forks, slot1, NULL );
  fd_tower_forks_t * fork2 = fd_tower_forks_query( forks, slot2, NULL );

  while( FD_LIKELY( fork1 && fork2 ) ) {
    if( FD_UNLIKELY( fork1->slot == fork2->slot ) ) return fork1->slot;
    if( fork1->slot > fork2->slot                 ) fork1 = fd_tower_forks_query( forks, fork1->parent_slot, NULL );
    else                                            fork2 = fd_tower_forks_query( forks, fork2->parent_slot, NULL );
  }
  FD_LOG_CRIT(( "invalid forks" ));
}

fd_hash_t const *
fd_tower_forks_canonical_block_id( fd_tower_forks_t * forks,
                                   ulong              slot ) {
  fd_tower_forks_t * fork = fd_tower_forks_query( forks, slot, NULL );
  if( FD_UNLIKELY( !fork ) ) return NULL;
  if     ( FD_LIKELY( fork->confirmed ) ) return &fork->confirmed_block_id;
  else if( FD_LIKELY( fork->voted     ) ) return &fork->voted_block_id;
  else if( FD_LIKELY( fork->replayed  ) ) return &fork->replayed_block_id;
  else return NULL;
}
