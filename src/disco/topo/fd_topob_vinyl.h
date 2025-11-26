#ifndef HEADER_fd_src_disco_topo_fd_topo_vinyl_h
#define HEADER_fd_src_disco_topo_fd_topo_vinyl_h

/* fd_topob_vinyl.h provides APIs for building topologies with vinyl
   servers and clients. */

#include "fd_topob.h"
#include "../../util/pod/fd_pod_format.h"

FD_PROTOTYPES_BEGIN

/* fd_topob_vinyl_client declares a new vinyl client and attaches it to
   a vinyl instance.  Creates vinyl_rq and vinyl_req_pool objects,
   reserves a link_id, and maps the objects into client and vinyl tiles. */

FD_FN_UNUSED static fd_topo_obj_t *
fd_topob_vinyl_rq( fd_topo_t *  topo,
                   char const * tile_name,
                   ulong        tile_kind_id,
                   char const * wksp_name,
                   char const * link_name,
                   ulong        req_batch_max,
                   ulong        req_batch_key_max,
                   ulong        quota_max ) {

  /* Assumes there is only one vinyl tile in the topology */
  ulong vinyl_tile_id;
  FD_TEST( ( vinyl_tile_id = fd_topo_find_tile( topo, "vinyl", 0UL ) )!=ULONG_MAX );
  fd_topo_tile_t * vinyl_tile = &topo->tiles[ vinyl_tile_id ];

  ulong client_tile_id;
  FD_TEST( ( client_tile_id = fd_topo_find_tile( topo, tile_name, tile_kind_id ) )!=ULONG_MAX );
  if( FD_UNLIKELY( client_tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile not found: %s:%lu", tile_name, tile_kind_id ));
  fd_topo_tile_t * client_tile = &topo->tiles[ client_tile_id ];

  fd_topo_obj_t * req_pool_obj = fd_topob_obj_named( topo, "vinyl_rpool", wksp_name, link_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, req_batch_max,     "obj.%lu.batch_max",     req_pool_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, req_batch_key_max, "obj.%lu.batch_key_max", req_pool_obj->id ) );

  fd_topo_obj_t * rq_obj = fd_topob_obj_named( topo, "vinyl_rq", wksp_name, link_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, req_batch_max, "obj.%lu.req_cnt",   rq_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, rq_obj->id,    "obj.%lu.link_id",   rq_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, quota_max,     "obj.%lu.quota_max", rq_obj->id ) );

  /* No database client uses the completion queue yet, but one is
     required to join a database client to the server. */
  fd_topo_obj_t * cq_obj = fd_topob_obj_named( topo, "vinyl_cq", wksp_name, link_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, 4UL, "obj.%lu.comp_cnt", cq_obj->id ) );

  /* Associate req_pool and cq with rq */
  FD_TEST( fd_pod_insertf_ulong( topo->props, req_pool_obj->id, "obj.%lu.req_pool_obj_id", rq_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, cq_obj->id,       "obj.%lu.cq_obj_id",       rq_obj->id ) );

  fd_topob_tile_uses( topo, vinyl_tile,  req_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, vinyl_tile,  rq_obj,       FD_SHMEM_JOIN_MODE_READ_ONLY  );
  fd_topob_tile_uses( topo, vinyl_tile,  cq_obj,       FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_tile_uses( topo, client_tile, req_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, client_tile, rq_obj,       FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, client_tile, cq_obj,       FD_SHMEM_JOIN_MODE_READ_ONLY  );

  FD_TEST( rq_obj->label_idx==req_pool_obj->label_idx ); /* keep rq and req_pool in sync */
  return rq_obj;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_topo_vinyl_h */
