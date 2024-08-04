#ifndef HEADER_fd_src_waltz_qos_fd_qos_map
#define HEADER_fd_src_waltz_qos_fd_qos_map

#include "fd_qos_entry.h"

#define MAP_NAME              fd_qos_map
#define MAP_T                 fd_qos_entry_t
#define MAP_KEY_T             uint
#define MAP_KEY_NULL          0U
#define MAP_KEY_INVAL(k)      (!k)
#define MAP_KEY_EQUAL(u,v)    ((u)==(v))
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(k)       ((MAP_HASH_T)fd_uint_hash(k))
#include "../../util/tmpl/fd_map_dynamic.c"

typedef fd_qos_entry_t fd_qos_map_t;

#endif /* HEADER_fd_src_waltz_qos_fd_qos_map */
