#include "fd_progcache_lineage.h"

fd_progcache_xid_t const *
fd_progcache_lineage_xid( fd_progcache_lineage_t const * lineage,
                          ulong                          slot ) {
  ulong depth = lineage->fork_depth;
  for( ulong i=0UL; i<depth; i++ ) {
    if( lineage->fork[ i ].ul[0] == slot ) {
      return &lineage->fork[ i ];
    }
  }
  return NULL;
}
