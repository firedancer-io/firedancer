#ifndef HEADER_fd_src_disco_topo_fd_topo_vinyl_h
#define HEADER_fd_src_disco_topo_fd_topo_vinyl_h

/* fd_topob_vinyl.h provides APIs for building topologies with vinyl
   servers and clients. */

#include "fd_topob.h"
#include "../../util/pod/fd_pod_format.h"

FD_PROTOTYPES_BEGIN

FD_FN_UNUSED static fd_topo_obj_t *
fd_topob_vinyl_rq( fd_topo_t *      topob,
                   char const *     link_name,
                   char const *     wksp_name,
                   ulong            req_max ) {
  fd_topo_obj_t * rq_obj = fd_topob_obj_named( topob, "vinyl_rq", wksp_name, link_name );
  FD_TEST( fd_pod_insertf_ulong( topob->props, req_max, "obj.%lu.req_max", rq_obj->id ) );

  fd_topo_obj_t * req_pool_obj = fd_topob_obj_named( topob, "vinyl_req_pool", wksp_name, link_name );

  FD_TEST( rq_obj->label_idx==req_pool_obj->label_idx ); /* keep rq and req_pool in sync */
  return rq_obj;
}

FD_FN_UNUSED static void
fd_topob_vinyl_rq_out( fd_topo_t *  topo,
                       char const * tile_name,
                       ulong        tile_kind_id,
                       char const * link_name,
                       ulong        link_kind_id ) {
  ulong tile_id = fd_topo_find_tile( topo, tile_name, tile_kind_id );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile not found: %s:%lu", tile_name, tile_kind_id ));
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];

  fd_topo_obj_t const * rq_obj       = fd_topo_find_obj( topo, "vinyl_rq",       link_name, link_kind_id );
  fd_topo_obj_t const * req_pool_obj = fd_topo_find_obj( topo, "vinyl_req_pool", link_name, link_kind_id );
  if( FD_UNLIKELY( !rq_obj ) ) FD_LOG_ERR(( "vinyl_rq not found: %s:%lu", link_name, link_kind_id ));

  fd_topob_tile_uses( topo, tile, rq_obj,       FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, tile, req_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
}

FD_FN_UNUSED static void
fd_topob_vinyl_rq_in( fd_topo_t *  topo,
                      char const * tile_name,
                      ulong        tile_kind_id,
                      char const * link_name,
                      ulong        link_kind_id ) {
  ulong tile_id = fd_topo_find_tile( topo, tile_name, tile_kind_id );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile not found: %s:%lu", tile_name, tile_kind_id ));
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];

  fd_topo_obj_t const * rq_obj       = fd_topo_find_obj( topo, "vinyl_rq",       link_name, link_kind_id );
  fd_topo_obj_t const * req_pool_obj = fd_topo_find_obj( topo, "vinyl_req_pool", link_name, link_kind_id );
  if( FD_UNLIKELY( !rq_obj ) ) FD_LOG_ERR(( "vinyl_rq not found: %s:%lu", link_name, link_kind_id ));

  fd_topob_tile_uses( topo, tile, rq_obj,       FD_SHMEM_JOIN_MODE_READ_ONLY  );
  fd_topob_tile_uses( topo, tile, req_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_topo_vinyl_h */
