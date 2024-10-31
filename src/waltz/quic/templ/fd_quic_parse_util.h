#ifndef FD_QUIC_WALTZ_QUIC_TEMPL_FD_QUIC_PARSE_UTIL_H
#define FD_QUIC_WALTZ_QUIC_TEMPL_FD_QUIC_PARSE_UTIL_H

#include <stddef.h>

#include "../fd_quic_common.h"

static inline uint
fd_quic_varint_min_sz( ulong val ) {
  val = fd_ulong_min( val, 0x3fffffffffffffffUL );
  int sz_class = fd_uint_find_msb( (uint)fd_ulong_find_msb( val|0x3fUL ) + 2 ) - 2;
  return 1U<<sz_class;
}

static inline uint
fd_quic_varint_encode( uchar out[8],
                       ulong val ) {

  /* input byte pattern:
     - sz 1: aa 00 00 00 00 00 00 00
     - sz 2: aa bb 00 00 00 00 00 00
     - sz 4: aa bb cc dd 00 00 00 00
     - sz 8: aa bb cc dd ee ff ff gg */

  uint sz = fd_quic_varint_min_sz( val );

  /* shifted byte pattern
     - sz 1: 00 00 00 00 00 00 00 aa
     - sz 2: 00 00 00 00 00 00 aa bb
     - sz 4: 00 00 00 00 aa bb cc dd
     - sz 8: aa bb cc dd ee ff ff gg */

  ulong shifted = val << ( 8 * ( 8 - sz ) );

  /* swapped byte pattern
     - sz 1: aa 00 00 00 00 00 00 00
     - sz 2: bb aa 00 00 00 00 00 00
     - sz 4: dd cc bb aa 00 00 00 00
     - sz 8: gg ff ee dd cc bb aa 00 */

  ulong encoded = fd_ulong_bswap( shifted );

  /* set length indication */

  encoded &= 0xffffffffffffff3fUL;
  encoded |= ((ulong)fd_uint_find_msb( sz ))<<6;

  FD_STORE( ulong, out, encoded );
  return sz;
}


/* encode a VARINT "val" into "buf" of size "buf_sz"
   buf must be a mutable uchar pointer, and will be updated to point to
     the remaining buffer
   buf_sz must be a mutable integer and will be reduced by the number of
     bytes written
   bounds are checked before writing into buf */
#define FD_QUIC_ENCODE_VARINT(buf,buf_sz,val)                 \
  do {                                                        \
    if( FD_UNLIKELY( buf_sz<8 ) ) return FD_QUIC_ENCODE_FAIL; \
    uint sz = fd_quic_varint_encode( buf, (val) );            \
    buf += sz; buf_sz -= sz;                                  \
  } while(0);

/* fd_quic_h0_hdr_form extract the 'Header Form' bit, the first bit of a QUIC v1 packet.
   Returns 1 if the packet is a long header packet, 0 if the packet is a short header packet.
   Does not require decryption of the packet header. */
static inline uchar
fd_quic_h0_hdr_form( uchar hdr ) {
  return hdr>>7;
}

/* fd_quic_h0_long_packet_type extracts the 'Long Packet Type' from
   the first byte of a QUIC v1 long header packet.  Returns FD_QUIC_PKTTYPE_V1_{...}
   in range [0,4).  Does not require decryption of the packet header. */
static inline uchar
fd_quic_h0_long_packet_type( uchar hdr ) {
  return (hdr>>4)&3;
}

static inline uchar
fd_quic_h0_pkt_num_len( uint h0 ) {
  return (uchar)( h0 & 0x03 );
}

static inline uchar
fd_quic_initial_h0( uint pkt_num_len /* [0,3] */ ) {
  return (uchar)( 0xc0 | pkt_num_len );
}

static inline uchar
fd_quic_handshake_h0( uint pkt_num_len /* [0,3] */ ) {
  return (uchar)( 0xe0 | pkt_num_len );
}

static inline uchar
fd_quic_one_rtt_h0( uint spin_bit,   /* [0,1] */
                    uint key_phase,  /* [0,1] */
                    uint pkt_num_len /* [0,3] */ ) {
  return (uchar)( 0x40 | (spin_bit<<5) | (key_phase<<2) | pkt_num_len );
}

__attribute__((used)) static ulong
fd_quic_varint_decode( uchar const * buf,
                       uint          msb2 ) {
  switch( msb2 ) {
  case 3:
    return __builtin_bswap64( FD_LOAD( ulong,  buf ) ) & 0x3fffffffffffffff;
  case 2:
    return __builtin_bswap32( FD_LOAD( uint,   buf ) ) &         0x3fffffff;
  case 1:
    return __builtin_bswap16( FD_LOAD( ushort, buf ) ) &             0x3fff;
  case 0:
    return buf[0] & 0x3f;
  default:
    __builtin_unreachable();
  }
}

static inline ulong
fd_quic_pktnum_decode( uchar const * buf,
                       ulong         sz ) {
  uchar scratch[4] = {0};
  uint n = 0;
  switch( sz ) {
  case 4: scratch[3] = buf[ n++ ]; __attribute__((fallthrough));
  case 3: scratch[2] = buf[ n++ ]; __attribute__((fallthrough));
  case 2: scratch[1] = buf[ n++ ]; __attribute__((fallthrough));
  case 1: scratch[0] = buf[ n   ];
  }
  return FD_LOAD( uint, scratch );
}

#endif
