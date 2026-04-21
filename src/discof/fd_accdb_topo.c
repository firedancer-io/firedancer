#include "fd_accdb_topo.h"
#include "../flamenco/progcache/fd_progcache_user.h"
#include "../util/pod/fd_pod.h"

void
fd_progcache_init_from_topo( fd_progcache_t *  progcache,
                             fd_topo_t const * topo,
                             uchar *           scratch,
                             ulong             scratch_sz ) {
  ulong progcache_obj_id;
  FD_TEST( (progcache_obj_id  = fd_pod_query_ulong( topo->props, "progcache", ULONG_MAX ))!=ULONG_MAX );
  FD_TEST( fd_progcache_join( progcache,
      fd_topo_obj_laddr( topo, progcache_obj_id  ),
      scratch,
      scratch_sz ) );
}
