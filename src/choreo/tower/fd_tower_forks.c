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
fd_tower_forks_is_ancestor( fd_tower_forks_t * forks,
                            ulong              slot,
                            ulong              ancestor_slot ) {
  return is_ancestor( forks, slot, ancestor_slot );
}

int
fd_tower_forks_is_descendant( fd_tower_forks_t * forks,
                              ulong              slot,
                              ulong              descendant_slot ) {
  return is_ancestor( forks, descendant_slot, slot );
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
