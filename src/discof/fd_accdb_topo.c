#include "fd_accdb_topo.h"
#include "../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../flamenco/accdb/fd_accdb_impl_v2.h"
#include "../flamenco/progcache/fd_progcache_user.h"
#include "../util/pod/fd_pod.h"
#include "../util/pod/fd_pod_format.h"

void
fd_accdb_init_from_topo( fd_accdb_user_t *      accdb,
                         fd_topo_t const *      topo,
                         fd_topo_tile_t const * tile,
                         ulong                  max_depth ) {
  ulong funk_obj_id;
  ulong locks_obj_id;
  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ))!=ULONG_MAX );
  FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ))!=ULONG_MAX );
  fd_topo_obj_t const * vinyl_data = fd_topo_find_tile_obj( topo, tile, "vinyl_data" );
  if( !vinyl_data ) {
    FD_TEST( fd_accdb_user_v1_init( accdb,
        fd_topo_obj_laddr( topo, funk_obj_id  ),
        fd_topo_obj_laddr( topo, locks_obj_id ),
        max_depth ) );
  } else {
    fd_topo_obj_t const * vinyl_rq       = fd_topo_find_tile_obj( topo, tile, "vinyl_rq"     ); FD_TEST( vinyl_rq );
    fd_topo_obj_t const * vinyl_req_pool = fd_topo_find_tile_obj( topo, tile, "vinyl_rpool"  ); FD_TEST( vinyl_req_pool );
    fd_topo_obj_t const * vinyl_meta     = fd_topo_find_tile_obj( topo, tile, "vinyl_meta"   ); FD_TEST( vinyl_meta );
    fd_topo_obj_t const * vinyl_ele      = fd_topo_find_tile_obj( topo, tile, "vinyl_meta_e" ); FD_TEST( vinyl_ele );
    fd_topo_obj_t const * vinyl_line     = fd_topo_find_tile_obj( topo, tile, "vinyl_line"   ); FD_TEST( vinyl_line );
    ulong vinyl_line_cnt = vinyl_line
        ? fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.line_max", vinyl_line->id )
        : 0UL;
    FD_TEST( fd_accdb_user_v2_init( accdb,
        fd_topo_obj_laddr( topo, funk_obj_id  ),
        fd_topo_obj_laddr( topo, locks_obj_id ),
        fd_topo_obj_laddr( topo, vinyl_rq->id ),
        topo->workspaces[ vinyl_data->wksp_id ].wksp,
        fd_topo_obj_laddr( topo, vinyl_req_pool->id ),
        vinyl_rq->id,
        max_depth ) );
    fd_accdb_user_v2_init_cache( accdb,
       fd_topo_obj_laddr( topo, vinyl_meta->id ),
       fd_topo_obj_laddr( topo, vinyl_ele->id  ),
       fd_topo_obj_laddr( topo, vinyl_line->id ),
       vinyl_line_cnt );
  }
}

void
fd_progcache_init_from_topo( fd_progcache_t *  progcache,
                             fd_topo_t const * topo,
                             uchar *           scratch,
                             ulong             scratch_sz ) {
  ulong funk_obj_id;
  ulong locks_obj_id;
  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "progcache",       ULONG_MAX ))!=ULONG_MAX );
  FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "progcache_locks", ULONG_MAX ))!=ULONG_MAX );
  FD_TEST( fd_progcache_join( progcache,
      fd_topo_obj_laddr( topo, funk_obj_id  ),
      fd_topo_obj_laddr( topo, locks_obj_id ),
      scratch,
      scratch_sz ) );
}
