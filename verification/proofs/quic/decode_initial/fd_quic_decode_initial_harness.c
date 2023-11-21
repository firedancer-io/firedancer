#include <assert.h>
#include <tango/quic/fd_quic_proto.h>

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

void
harness( void ) {
  uint size;  __CPROVER_assume(size <= 1500);
  uchar buf[ size ];

  fd_quic_initial_t initial;

  ulong byte_cnt = fd_quic_decode_initial( &initial, buf, size );
  if( byte_cnt==FD_QUIC_PARSE_FAIL ) return;

  assert( byte_cnt <= size );

  assert( initial.hdr_form         <= 1);
  assert( initial.fixed_bit        <= 1);
  assert( initial.long_packet_type <= 4 );
  assert( initial.reserved_bits    <= 4 );
  assert( initial.pkt_number_len   <= 4 );

  assert( initial.dst_conn_id_len <= 20       );
  assert( initial.src_conn_id_len <= 20       );
  assert( initial.len             < (1UL<<62) );
}
