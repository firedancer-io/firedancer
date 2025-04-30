#include "fd_types_reflect_private.h"

fd_types_vt_t fd_types_map[ 1<<FD_TYPES_MAP_LG_SLOT_CNT ];

fd_types_vt_t const *
fd_types_vt_by_name( char const * name,
                     ulong        name_len ) {
  FD_ONCE_BEGIN {
    fd_types_vt_t * map = fd_types_map_join( fd_types_map_new( fd_types_map ) );
    for( fd_types_vt_t const * v = fd_types_vt_list; v->name; v++ ) {
      fd_types_vt_t * entry = fd_types_map_insert( map, v->key );
      if( FD_UNLIKELY( !entry ) ) FD_LOG_ERR(( "FD_TYPES_MAP_LG_SLOT_CNT is too small" ));
      *entry = *v;
    }
  }
  FD_ONCE_END;

  if( FD_UNLIKELY( !name_len || name_len>USHORT_MAX ) ) return NULL;
  fd_types_vt_key_t key = { .name=name, .name_len=(ushort)name_len };
  return fd_types_map_query( fd_types_map, key, NULL );
}

