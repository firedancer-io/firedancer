#include "fd_quic_conn_map.h"

/* define a map for connection id -> connection */
#define MAP_NAME              fd_quic_conn_map_impl
#define MAP_T                 fd_quic_conn_entry_t
#define MAP_KEY_T             fd_quic_conn_id_t
#define MAP_KEY_NULL          FD_QUIC_CONN_ID_NULL
#define MAP_KEY_INVAL(key)    FD_QUIC_CONN_ID_INVAL(key)
#define MAP_KEY_EQUAL(k0,k1)  FD_QUIC_CONN_ID_EQUAL(k0,k1)
#define MAP_KEY_HASH(key)     FD_QUIC_CONN_ID_HASH(key)
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_QUERY_OPT         1

/* TODO define MAP_MOVE and MAP_KEY_MOVE? memcpy? */

#include "../../util/tmpl/fd_map_dynamic.c"


ulong
fd_quic_conn_map_align( void ) {
  return fd_quic_conn_map_impl_align();
}

ulong
fd_quic_conn_map_footprint( int lg_slot_cnt ) {
  return fd_quic_conn_map_impl_footprint( lg_slot_cnt );
}

fd_quic_conn_map_t *
fd_quic_conn_map_new( void * mem,
                      int    lg_slot_cnt ) {
  mem = fd_quic_conn_map_impl_new( mem, lg_slot_cnt );
  mem = fd_quic_conn_map_impl_join( mem );
  return mem;
}

void
fd_quic_conn_map_delete( fd_quic_conn_map_t * map ) {
  void * mem = fd_quic_conn_map_impl_leave( map );
  fd_quic_conn_map_impl_delete( mem );
}

fd_quic_conn_entry_t *
fd_quic_conn_map_insert( fd_quic_conn_map_t * map, fd_quic_conn_id_t const * key ) {
  return fd_quic_conn_map_impl_insert( map, *key );
}

void
fd_quic_conn_map_remove( fd_quic_conn_map_t * map, fd_quic_conn_entry_t * entry ) {
  fd_quic_conn_map_impl_remove( map, entry );
}

fd_quic_conn_entry_t *
fd_quic_conn_map_query( fd_quic_conn_map_t * map, fd_quic_conn_id_t * key ) {
  return fd_quic_conn_map_impl_query( map, *key, NULL );
}

/* max entries in the map */
ulong
fd_quic_conn_map_max( fd_quic_conn_map_t * map ) {
  return fd_quic_conn_map_impl_key_max( map );
}

