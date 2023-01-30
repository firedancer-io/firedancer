#include "fd_quic_conn.h"

#include "fd_quic_common.h"

ulong
fd_quic_conn_align() {
  ulong align = fd_ulong_max( alignof( fd_quic_conn_t ), alignof( fd_quic_stream_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_ack_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_pkt_meta_t ) );
  return align;
}

ulong
fd_quic_conn_footprint( fd_quic_config_t const * config ) {
  ulong imem  = 0;
  ulong align = fd_quic_conn_align();

  imem += FD_QUIC_POW2_ALIGN( sizeof( fd_quic_conn_t ), align );

  ulong tot_num_streams = 4 * config->max_concur_streams;
  imem += FD_QUIC_POW2_ALIGN( tot_num_streams * fd_quic_stream_footprint(), align );

  ulong num_pkt_meta = config->max_in_flight_pkts;
  imem += FD_QUIC_POW2_ALIGN( num_pkt_meta * sizeof( fd_quic_pkt_meta_t ), align );

  ulong num_acks = config->max_in_flight_pkts;
  imem += FD_QUIC_POW2_ALIGN( num_acks * sizeof( fd_quic_ack_t ), align );

  return imem;
}

fd_quic_conn_t *
fd_quic_conn_new( void * mem, fd_quic_t * quic, fd_quic_config_t const * config ) {
  ulong imem      = (ulong)mem;
  ulong align     = fd_quic_conn_align();

  fd_quic_conn_t * conn = (fd_quic_conn_t*)imem;

  fd_memset( conn, 0, sizeof( fd_quic_conn_t ) );
  conn->quic = quic;

  imem += FD_QUIC_POW2_ALIGN( sizeof( fd_quic_conn_t ), align );

  /* allocate streams */
  conn->streams = (fd_quic_stream_t*)imem;

  /* initialize streams here
     max_concur_streams is per-type, and there are 4 types */
  conn->tot_num_streams = 4 * config->max_concur_streams;
  fd_memset( conn->streams, 0, conn->tot_num_streams * fd_quic_stream_footprint() );

  /* NOTE: fd_quic_stream_footprint() == sizeof( fd_quic_stream_t )
     conn->stream is simply an array of fd_quic_stream_t */
  for( ulong j = 0; j < conn->tot_num_streams; ++j ) {
    conn->streams[j].stream_id = ~conn->streams[j].stream_id;
    conn->streams[j].conn      = conn;
  }

  imem += FD_QUIC_POW2_ALIGN( conn->tot_num_streams * fd_quic_stream_footprint(), align );

  /* allocate pkt_meta_t */
  fd_quic_pkt_meta_t * pkt_meta = (fd_quic_pkt_meta_t*)imem;

  /* initialize pkt_meta */
  ulong num_pkt_meta = config->max_in_flight_pkts;
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
  ulong num_acks = config->max_in_flight_pkts;
  fd_memset( acks, 0, num_acks * sizeof( *acks ) );

  /* initialize free list of acks metadata */
  conn->acks_free = acks;
  for( ulong j = 0; j < num_acks; ++j ) {
    ulong k = j + 1;
    acks[j].next =  k < num_acks ? acks + k : NULL;
  }

  imem += FD_QUIC_POW2_ALIGN( num_acks * sizeof( fd_quic_ack_t ), align );

  /* sanity check */
  if( FD_UNLIKELY( ( imem - (ulong)mem ) != fd_quic_conn_footprint( config ) ) ) {
    FD_LOG_ERR(( "memory used does not match memory allocated" ));
  }

  return conn;
}


