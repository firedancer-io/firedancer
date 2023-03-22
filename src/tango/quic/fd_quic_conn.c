#include "fd_quic_conn.h"
#include "fd_quic_common.h"
#include "../../util/fd_util.h"

/* define a map for stream_id -> stream* */
#define MAP_NAME              fd_quic_stream_map
#define MAP_KEY               stream_id
#define MAP_T                 fd_quic_stream_map_t
#define MAP_KEY_NULL          FD_QUIC_STREAM_ID_UNUSED
#define MAP_KEY_INVAL(key)    ((key)==MAP_KEY_NULL)
#define MAP_QUERY_OPT         1

#include "../../util/tmpl/fd_map_dynamic.c"


ulong
fd_quic_conn_align( void ) {
  ulong align = fd_ulong_max( alignof( fd_quic_conn_t ), alignof( fd_quic_stream_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_ack_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_pkt_meta_t ) );
  align = fd_ulong_max( align, fd_quic_stream_map_align() );
  return align;
}

ulong
fd_quic_conn_footprint( ulong tx_buf_sz,
                        ulong rx_buf_sz,
                        ulong max_concur_streams_per_type,
                        ulong max_in_flight_pkts ) {
  ulong imem  = 0;
  ulong align = fd_quic_conn_align();

  imem += FD_QUIC_POW2_ALIGN( sizeof( fd_quic_conn_t ), align );

  ulong tot_num_streams = 4 * max_concur_streams_per_type;

  /* space for the array of stream pointers */
  /* four types of stream */
  imem += FD_QUIC_POW2_ALIGN( tot_num_streams * sizeof(void*), align );

  /* space for stream instances */
  imem += FD_QUIC_POW2_ALIGN( tot_num_streams * fd_quic_stream_footprint( tx_buf_sz, rx_buf_sz ), align );

  /* space for stream hash map */
  ulong lg = 0;
  while( lg < 40 && (1ul<<lg) < (ulong)((double)tot_num_streams*FD_QUIC_SPARSITY) ) {
    lg++;
  }
  imem += FD_QUIC_POW2_ALIGN( fd_quic_stream_map_footprint( (int)lg ), align );

  ulong num_pkt_meta = max_in_flight_pkts;
  imem += FD_QUIC_POW2_ALIGN( num_pkt_meta * sizeof( fd_quic_pkt_meta_t ), align );

  ulong num_acks = max_in_flight_pkts;
  imem += FD_QUIC_POW2_ALIGN( num_acks * sizeof( fd_quic_ack_t ), align );

  return imem;
}

fd_quic_conn_t *
fd_quic_conn_new( void *      mem,
                  fd_quic_t * quic,
                  ulong       tx_buf_sz,
                  ulong       rx_buf_sz,
                  ulong       max_concur_streams_per_type,
                  ulong       max_in_flight_pkts ) {
  ulong imem      = (ulong)mem;
  ulong align     = fd_quic_conn_align();

  fd_quic_conn_t * conn = (fd_quic_conn_t*)imem;

  fd_memset( conn, 0, sizeof( fd_quic_conn_t ) );
  conn->quic             = quic;
  conn->stream_tx_buf_sz = tx_buf_sz;
  conn->stream_rx_buf_sz = rx_buf_sz;

  imem += FD_QUIC_POW2_ALIGN( sizeof( fd_quic_conn_t ), align );

  /* allocate streams */

  /* max_concur_streams is per-type, and there are 4 types */
  ulong tot_num_streams = 4 * max_concur_streams_per_type;
  conn->tot_num_streams = tot_num_streams;

  /* space for the array of stream pointers */
  conn->streams = (fd_quic_stream_t**)imem;
  imem += FD_QUIC_POW2_ALIGN( tot_num_streams * sizeof(void*), align );

  /* initialize each stream */
  ulong stream_footprint = fd_quic_stream_footprint( tx_buf_sz, rx_buf_sz );
  for( ulong j = 0; j < conn->tot_num_streams; ++j ) {
    conn->streams[j] = fd_quic_stream_new( (void*)imem, conn, tx_buf_sz, rx_buf_sz );

    conn->streams[j]->next = NULL;

    /* insert into unused list */
    if( j == 0 ) {
      conn->unused_streams = conn->streams[j];
    } else {
      conn->streams[j-1]->next = conn->streams[j];
    }

    imem += stream_footprint;
  }

  /* space for stream hash map */
  ulong lg = 0;
  while( lg < 64 && (1ul<<lg) < (ulong)((double)tot_num_streams*FD_QUIC_SPARSITY) ) {
    lg++;
  }
  /* TODO move join into fd_quic_conn_join */
  conn->stream_map = fd_quic_stream_map_join( fd_quic_stream_map_new( (void*)imem, (int)lg ) );
  imem += FD_QUIC_POW2_ALIGN( fd_quic_stream_map_footprint( (int)lg ), align );

  /* allocate pkt_meta_t */
  fd_quic_pkt_meta_t * pkt_meta = (fd_quic_pkt_meta_t*)imem;

  /* initialize pkt_meta */
  ulong num_pkt_meta = max_in_flight_pkts;
  fd_memset( pkt_meta, 0, num_pkt_meta * sizeof( *pkt_meta ) );

  /* initialize free list of packet metadata */
  conn->pkt_meta_free = pkt_meta;
  for( ulong j = 0; j < num_pkt_meta; ++j ) {
    ulong k = j + 1;
    pkt_meta[j].next =  k < num_pkt_meta ? pkt_meta + k : NULL;
  }

  imem += FD_QUIC_POW2_ALIGN( num_pkt_meta * sizeof( fd_quic_pkt_meta_t ), align );

  /* allocate ack_t */
  fd_quic_ack_t * acks = (fd_quic_ack_t*)imem;

  /* initialize acks */
  ulong num_acks = max_in_flight_pkts;
  fd_memset( acks, 0, num_acks * sizeof( *acks ) );

  /* initialize free list of acks metadata */
  conn->acks_free = acks;
  for( ulong j = 0; j < num_acks; ++j ) {
    ulong k = j + 1;
    acks[j].next =  k < num_acks ? acks + k : NULL;
  }

  imem += FD_QUIC_POW2_ALIGN( num_acks * sizeof( fd_quic_ack_t ), align );

  /* sanity check */
  ulong fp =
        fd_quic_conn_footprint( tx_buf_sz, rx_buf_sz, max_concur_streams_per_type,
                  max_in_flight_pkts  );
  if( FD_UNLIKELY( ( imem - (ulong)mem ) != fp ) ) {
    FD_LOG_ERR(( "memory used does not match memory allocated" ));
  }

  return conn;
}


