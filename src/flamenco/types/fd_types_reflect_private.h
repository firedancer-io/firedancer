#ifndef HEADER_fd_src_flamenco_types_fd_types_reflect_private_h
#define HEADER_fd_src_flamenco_types_fd_types_reflect_private_h

#include "fd_types_reflect.h"

/* Map API for looking up types by name. */

#define FD_TYPES_MAP_LG_SLOT_CNT 9
#define MAP_NAME              fd_types_map
#define MAP_LG_SLOT_CNT       FD_TYPES_MAP_LG_SLOT_CNT
#define MAP_T                 fd_types_vt_t
#define MAP_KEY_T             fd_types_vt_key_t
#define MAP_KEY_EQUAL(a,b)    ( ((a).name_len==(b).name_len) && 0==memcmp( (a).name, (b).name, (a).name_len ) )
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_NULL          (fd_types_vt_key_t){0}
#define MAP_KEY_INVAL(k)      ((k).name_len==0)
#define MAP_KEY_HASH(k)       (uint)fd_hash( 88UL, (k).name, (k).name_len )
#include "../../util/tmpl/fd_map.c"

FD_PROTOTYPES_BEGIN

/* Declare a map for type lookup by name */
extern fd_types_vt_t fd_types_map[ 1<<FD_TYPES_MAP_LG_SLOT_CNT ];

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_types_fd_types_reflect_private_h */
