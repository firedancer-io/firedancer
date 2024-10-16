#ifndef HEADER_fd_src_waltz_quic_fd_quic_conn_map_h
#define HEADER_fd_src_waltz_quic_fd_quic_conn_map_h

#include "../../util/fd_util_base.h"

struct fd_quic_conn_map {
  ulong conn_id;
  uint  seq; /* sequence number used to manage new and retired connection ids */
  uint  conn_idx;
};
typedef struct fd_quic_conn_map fd_quic_conn_map_t;

#define MAP_NAME      fd_quic_conn_map
#define MAP_T         fd_quic_conn_map_t
#define MAP_KEY       conn_id
#define MAP_QUERY_OPT 1
#define MAP_MEMOIZE   0
#include "../../util/tmpl/fd_map_dynamic.c"

#endif /* HEADER_fd_src_waltz_quic_fd_quic_conn_map_h */

