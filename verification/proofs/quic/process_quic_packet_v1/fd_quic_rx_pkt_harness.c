#include <assert.h>
#include <waltz/quic/fd_quic.h>
#include <waltz/quic/fd_quic_private.h>
#include <waltz/quic/fd_quic_conn_map.h>
#include <stdlib.h>

static ulong s_data_sz;
static uchar * s_data;

static fd_quic_conn_t dummy_conn = {0};

fd_quic_conn_entry_t *
fd_quic_conn_map_query( fd_quic_conn_map_t * map, fd_quic_conn_id_t * key ) {
  fd_quic_conn_entry_t * entry = malloc(sizeof(fd_quic_conn_entry_t));
  if( entry ) entry->conn = &dummy_conn;
  /* entry may be NULL */
  return entry;
}

void
fd_quic_ack_pkt( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_pkt_t * pkt ) {
  assert(conn);
  return;
}

ulong
fd_quic_parse_bits( uchar const * buf,
                    ulong         cur_bit,
                    ulong         bits ) {
  assert( bits<64UL );
  ulong b0 =  cur_bit          /8UL;
  ulong b1 = (cur_bit+bits-1UL)/8UL;
  __CPROVER_r_ok( buf+b0, b1-b0+1UL );
  ulong res; __CPROVER_assume( res<(1UL<<bits) );
  return res;
}

ulong
fd_quic_handle_v1_initial( fd_quic_t *               quic,
                           fd_quic_conn_t **         p_conn,
                           fd_quic_pkt_t *           pkt,
                           fd_quic_conn_id_t const * conn_id,
                           uchar *                   cur_ptr,
                           ulong                     cur_sz ) {
  assert( quic );
  assert( p_conn );
  assert( cur_sz <= s_data_sz );
  assert( cur_ptr >= s_data && cur_ptr < s_data + s_data_sz );
  assert( conn_id && conn_id->sz <= FD_QUIC_MAX_CONN_ID_SZ );
  fd_quic_conn_t * conn = NULL;
  int has_conn;
  if( has_conn ) conn==&dummy_conn;
  *p_conn = conn;
  ulong rc;
  __CPROVER_assume( rc==FD_QUIC_PARSE_FAIL || rc<=cur_sz );
  return rc;
}

ulong
fd_quic_handle_v1_handshake(
    fd_quic_t *           quic,
    fd_quic_conn_t *      conn,
    fd_quic_pkt_t *       pkt,
    uchar *               cur_ptr,
    ulong                 cur_sz ) {
  assert( quic );
  assert( cur_sz <= s_data_sz );
  assert( cur_ptr >= s_data && cur_ptr < s_data + s_data_sz );
  ulong rc;
  __CPROVER_assume( rc==FD_QUIC_PARSE_FAIL || rc<=cur_sz );
  return rc;
}

ulong
fd_quic_handle_v1_retry(
    fd_quic_t *           quic,
    fd_quic_conn_t *      conn,
    fd_quic_pkt_t const * pkt,
    uchar const *         cur_ptr,
    ulong                 cur_sz ) {
  assert( quic );
  assert( cur_sz <= s_data_sz );
  assert( cur_ptr >= s_data && cur_ptr < s_data + s_data_sz );
  ulong rc;
  __CPROVER_assume( rc==FD_QUIC_PARSE_FAIL || rc<=cur_sz );
  return rc;
}

ulong
fd_quic_handle_v1_zero_rtt( fd_quic_t *      quic,
                            fd_quic_conn_t * conn,
                            fd_quic_pkt_t *  pkt,
                            uchar *    const cur_ptr,
                            ulong      const cur_sz ) {
  assert( quic );
  assert( cur_sz <= s_data_sz );
  assert( cur_ptr >= s_data && cur_ptr < s_data + s_data_sz );
  ulong rc;
  __CPROVER_assume( rc==FD_QUIC_PARSE_FAIL || rc<=cur_sz );
  return rc;
}

ulong
fd_quic_handle_v1_one_rtt( fd_quic_t *           quic,
                           fd_quic_conn_t *      conn,
                           fd_quic_pkt_t *       pkt,
                           uchar *         const cur_ptr,
                           ulong           const tot_sz ) {
  assert( quic );
  assert( tot_sz <= s_data_sz );
  assert( cur_ptr >= s_data && cur_ptr < s_data + s_data_sz );
  ulong rc;
  __CPROVER_assume( rc==FD_QUIC_PARSE_FAIL || rc<=tot_sz );
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

  s_data    = data;
  s_data_sz = data_sz;

  fd_quic_pkt_t pkt;

  /* Pass it to the user entrypoint */
  ulong rc = fd_quic_process_quic_packet_v1( quic, &pkt, data, data_sz );
}

