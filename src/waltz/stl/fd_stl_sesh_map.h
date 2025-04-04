// #ifndef HEADER_fd_src_waltz_stl_fd_stl_sesh_map_h
// #define HEADER_fd_src_waltz_stl_fd_stl_sesh_map_h

// #include "fd_stl_base.h"
// #include "fd_stl_sesh.h"

// struct __attribute__((aligned(16))) fd_stl_sesh_map {
//   ulong sesh_id;
//   fd_stl_sesh_t *  sesh;
// };
// typedef struct fd_stl_sesh_map fd_stl_sesh_map_t;

// #define MAP_NAME        fd_stl_sesh_map
// #define MAP_T           fd_stl_sesh_map_t
// #define MAP_KEY         sesh_id
// #define MAP_MEMOIZE     0
// #include "../../util/tmpl/fd_map_dynamic.c"

// FD_PROTOTYPES_BEGIN

// fd_stl_sesh_t *
// fd_stl_sesh_query( fd_stl_sesh_map_t * map,
//                    ulong              sesh_id ) {
//   fd_stl_sesh_map_t sentinel = {0};
//   if( !sesh_id ) return NULL;
//   fd_stl_sesh_map_t * entry = fd_stl_sesh_map_query( map, sesh_id, &sentinel );
//   fd_stl_sesh_t *     sesh  = entry->sesh;
//   return sesh;
// }


// FD_PROTOTYPES_END

// #endif /* HEADER_fd_src_waltz_stl_fd_stl_sesh_map_h */

