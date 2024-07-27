/* fd_quic_rx_entry_harness.c tests fd_quic handling of raw IP packets.
   Actual QUIC packet handling is stubbed out. */

#include <assert.h>
#include <waltz/quic/fd_quic.h>
#include <waltz/quic/fd_quic_conn_map.h>
#include <stdlib.h>

/* Stub QUIC functions */

fd_quic_conn_entry_t *
fd_quic_conn_map_query( fd_quic_conn_map_t * map, fd_quic_conn_id_t * key ) {
  fd_quic_conn_entry_t * entry;
  return entry;
}

ulong
fd_quic_process_quic_packet_v1( fd_quic_t *     quic,
                                fd_quic_pkt_t * pkt,
                                uchar *         cur_ptr,
                                ulong           cur_sz ) {
  __CPROVER_r_ok( cur_ptr, cur_sz );
  ulong rc;
  __CPROVER_assume( rc==FD_QUIC_PARSE_FAIL || rc<=cur_sz );
  return rc;
}

void
harness( void ) {
  fd_quic_t * quic = calloc( 1, 0x2000 );
  __CPROVER_assume( quic );

  /* Generate a random packet */
  ulong data_sz;
  __CPROVER_assume( data_sz < 0x10000 );
  uchar data[data_sz];

  /* Pass it to the user entrypoint */
  fd_quic_process_packet( quic, data, data_sz );
}

