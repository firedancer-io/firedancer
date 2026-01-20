#include "fd_accdb_topo.h"
#include "../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../flamenco/accdb/fd_accdb_impl_v2.h"
#include "../util/pod/fd_pod.h"

void
fd_accdb_init_from_topo( fd_accdb_user_t *      accdb,
                         fd_topo_t const *      topo,
                         fd_topo_tile_t const * tile ) {
  ulong funk_obj_id;
  FD_TEST( (funk_obj_id = fd_pod_query_ulong( topo->props, "funk", ULONG_MAX ))!=ULONG_MAX );
  fd_topo_obj_t const * vinyl_data = fd_topo_find_tile_obj( topo, tile, "vinyl_data" );
  if( !vinyl_data ) {
    FD_TEST( fd_accdb_user_v1_init( accdb, fd_topo_obj_laddr( topo, funk_obj_id ) ) );
  } else {
    fd_topo_obj_t const * vinyl_rq       = fd_topo_find_tile_obj( topo, tile, "vinyl_rq"    );
    fd_topo_obj_t const * vinyl_req_pool = fd_topo_find_tile_obj( topo, tile, "vinyl_rpool" );
    FD_TEST( fd_accdb_user_v2_init( accdb,
        fd_topo_obj_laddr( topo, funk_obj_id ),
        fd_topo_obj_laddr( topo, vinyl_rq->id ),
        topo->workspaces[ vinyl_data->wksp_id ].wksp,
        fd_topo_obj_laddr( topo, vinyl_req_pool->id ),
        vinyl_rq->id ) );
  }
}
