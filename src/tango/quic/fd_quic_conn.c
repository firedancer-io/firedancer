#include "fd_quic_conn.h"
#include "fd_quic_common.h"
#include "../../util/fd_util.h"

ulong
fd_quic_conn_align() {
  ulong align = fd_ulong_max( alignof( fd_quic_conn_t ), alignof( fd_quic_stream_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_ack_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_pkt_meta_t ) );
  return align;
}

ulong
fd_quic_conn_footprint( fd_quic_config_t const * config ) {
  /* use same stream data for each kind of stream
     TODO update this to use minimal required space
     TODO or possibly a per-connection limit rather than a per-stream */
  ulong stream_data = config->transport_params->initial_max_stream_data_uni;
  stream_data = fd_ulong_max( stream_data, config->transport_params->initial_max_stream_data_bidi_remote );
  stream_data = fd_ulong_max( stream_data, config->transport_params->initial_max_stream_data_bidi_local );
  ulong tx_buf_sz = config->tx_buf_sz;
  ulong rx_buf_sz = stream_data;

  ulong imem  = 0;
  ulong align = fd_quic_conn_align();

  imem += FD_QUIC_POW2_ALIGN( sizeof( fd_quic_conn_t ), align );

  ulong tot_num_streams = 4 * config->max_concur_streams;

  /* space for the array of stream pointers */
  imem += FD_QUIC_POW2_ALIGN( tot_num_streams * sizeof(void*), align );

  /* space for stream instances */
  imem += FD_QUIC_POW2_ALIGN( tot_num_streams * fd_quic_stream_footprint( tx_buf_sz, rx_buf_sz ), align );

  ulong num_pkt_meta = config->max_in_flight_pkts;
  imem += FD_QUIC_POW2_ALIGN( num_pkt_meta * sizeof( fd_quic_pkt_meta_t ), align );

  ulong num_acks = config->max_in_flight_pkts;
  imem += FD_QUIC_POW2_ALIGN( num_acks * sizeof( fd_quic_ack_t ), align );

  return imem;
}

fd_quic_conn_t *
fd_quic_conn_new( void * mem, fd_quic_t * quic, fd_quic_config_t const * config ) {
  /* use same stream data for each kind of stream
     TODO update this to use minimal required space
     TODO or possibly a per-connection limit rather than a per-stream */
  ulong stream_data = config->transport_params->initial_max_stream_data_uni;
  stream_data     = fd_ulong_max( stream_data, config->transport_params->initial_max_stream_data_bidi_remote );
  stream_data     = fd_ulong_max( stream_data, config->transport_params->initial_max_stream_data_bidi_local );
  ulong tx_buf_sz = config->tx_buf_sz;
  ulong rx_buf_sz = stream_data;

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
  ulong tot_num_streams = 4 * config->max_concur_streams;
  conn->tot_num_streams = tot_num_streams;

  /* space for the array of stream pointers */
  conn->streams = (fd_quic_stream_t**)imem;
  imem += FD_QUIC_POW2_ALIGN( tot_num_streams * sizeof(void*), align );

  /* initialize each stream */
  ulong stream_footprint = fd_quic_stream_footprint( tx_buf_sz, rx_buf_sz );
  for( ulong j = 0; j < conn->tot_num_streams; ++j ) {
    conn->streams[j] = fd_quic_stream_new( (void*)imem, conn, tx_buf_sz, rx_buf_sz );

    imem += stream_footprint;
  }

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


