#include "fd_accdb_topo.h"
#include "../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../flamenco/progcache/fd_progcache_user.h"
#include "../util/pod/fd_pod.h"

void
fd_accdb_init_from_topo( fd_accdb_user_t * accdb,
                         fd_topo_t const * topo,
                         ulong             max_depth ) {
  ulong funk_obj_id;
  ulong locks_obj_id;
  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ))!=ULONG_MAX );
  FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ))!=ULONG_MAX );
  FD_TEST( fd_accdb_user_v1_init( accdb,
      fd_topo_obj_laddr( topo, funk_obj_id  ),
      fd_topo_obj_laddr( topo, locks_obj_id ),
      max_depth ) );
}

void
fd_progcache_init_from_topo( fd_progcache_t *  progcache,
                             fd_topo_t const * topo,
                             uchar *           scratch,
                             ulong             scratch_sz ) {
  ulong funk_obj_id;
  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "progcache", ULONG_MAX ))!=ULONG_MAX );
  FD_TEST( fd_progcache_join( progcache,
      fd_topo_obj_laddr( topo, funk_obj_id  ),
      scratch,
      scratch_sz ) );
}
