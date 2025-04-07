// #ifndef HEADER_fd_src_waltz_snp_fd_snp_sesh_map_h
// #define HEADER_fd_src_waltz_snp_fd_snp_sesh_map_h

// #include "fd_snp_base.h"
// #include "fd_snp_sesh.h"

// struct __attribute__((aligned(16))) fd_snp_sesh_map {
//   ulong sesh_id;
//   fd_snp_sesh_t *  sesh;
// };
// typedef struct fd_snp_sesh_map fd_snp_sesh_map_t;

// #define MAP_NAME        fd_snp_sesh_map
// #define MAP_T           fd_snp_sesh_map_t
// #define MAP_KEY         sesh_id
// #define MAP_MEMOIZE     0
// #include "../../util/tmpl/fd_map_dynamic.c"

// FD_PROTOTYPES_BEGIN

// fd_snp_sesh_t *
// fd_snp_sesh_query( fd_snp_sesh_map_t * map,
//                    ulong              sesh_id ) {
//   fd_snp_sesh_map_t sentinel = {0};
//   if( !sesh_id ) return NULL;
//   fd_snp_sesh_map_t * entry = fd_snp_sesh_map_query( map, sesh_id, &sentinel );
//   fd_snp_sesh_t *     sesh  = entry->sesh;
//   return sesh;
// }


// FD_PROTOTYPES_END

// #endif /* HEADER_fd_src_waltz_snp_fd_snp_sesh_map_h */

