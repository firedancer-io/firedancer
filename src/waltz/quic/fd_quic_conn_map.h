#ifndef HEADER_fd_src_waltz_quic_fd_quic_conn_map_h
#define HEADER_fd_src_waltz_quic_fd_quic_conn_map_h

#include "fd_quic_conn_id.h"

/* forward declare */
typedef struct fd_quic_conn fd_quic_conn_t;

/* entries in the connection id map */
struct fd_quic_conn_entry {
  fd_quic_conn_id_t key;
  uint              hash;

  uint              seq; /* sequence number used to manage new and retired
                            connection ids */

  fd_quic_conn_t *  conn;
};
typedef struct fd_quic_conn_entry fd_quic_conn_entry_t;

/* the map itself is the first entry */
typedef fd_quic_conn_entry_t fd_quic_conn_map_t;

FD_PROTOTYPES_BEGIN

/* returns the required alignment of the connection map memory */
FD_FN_CONST
ulong
fd_quic_conn_map_align( void );

/* returns the amount of memory required to initialize the connection map */
FD_FN_CONST
ulong
fd_quic_conn_map_footprint( int lg_slot_cnt );

/* initialize connection map

   (also does a join)

   args
     mem          memory to use to initialize the map
                    must be aligned according to fd_quic_conn_map_align(),
                    and sized according to fd_quic_conn_map_footprint()
     lg_slot_cnt  log_2(number of slots in map) */
fd_quic_conn_map_t *
fd_quic_conn_map_new( void * mem, int lg_slot_cnt );

/* delete a connection map
   (also does leave) */
void
fd_quic_conn_map_delete( fd_quic_conn_map_t * map );

/* insert a key into map
   returns NULL if key already in map, or map full */
fd_quic_conn_entry_t *
fd_quic_conn_map_insert( fd_quic_conn_map_t * map, fd_quic_conn_id_t const * key );

/* removes an entry from a map */
void
fd_quic_conn_map_remove( fd_quic_conn_map_t * map, fd_quic_conn_entry_t * entry );

/* query for key in map */
fd_quic_conn_entry_t *
fd_quic_conn_map_query( fd_quic_conn_map_t * map, fd_quic_conn_id_t * key );

/* max entries in the map */
ulong
fd_quic_conn_map_max( fd_quic_conn_map_t * map );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_conn_map_h */

