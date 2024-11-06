#include <stddef.h>

#include "../fd_quic_common.h"

/* fd_quic_test_negative "returns" (x<0), but in a way that doesn't produce
   warnings/errors when x is unsigned

   this optimizes well in experiments */
#if 1
#define fd_quic_test_negative(x) ( (_Bool)( (double)(x) < 0 ) )
#else
/* alternative that seems heavy-handed and is gcc specific */
#pragma GCC diagnostic ignored "-Wtype-limits"
#define fd_quic_test_negative(x) ( (x) < 0 )
#endif

/* determine the encoded VARINT length of a given value */
/* VARINT isn't valid for negatives .. shouldn't occur */
#define FD_QUIC_ENCODE_VARINT_LEN(val)               \
  (                                                  \
    fd_quic_test_negative(val) ? FD_QUIC_ENCODE_FAIL \
    :                                                \
    ( (ulong)(val) < ( 1UL << ( 0x08 - 2 ) ) ) ? 1   \
    :                                                \
    ( (ulong)(val) < ( 1UL << ( 0x10 - 2 ) ) ) ? 2   \
    :                                                \
    ( (ulong)(val) < ( 1UL << ( 0x20 - 2 ) ) ) ? 4   \
    :                                                \
    ( (ulong)(val) < ( 1UL << ( 0x40 - 2 ) ) ) ? 8   \
    :                                                \
    FD_QUIC_ENCODE_FAIL                              \
  )


/* determine whether a value is valid for a VARINT encoding
   0 <= varint < 2^62 */
/* VARINT isn't valid for negatives .. shouldn't occur */
#define FD_QUIC_VALIDATE_VARINT(val)                               \
  (                                                                \
    (!fd_quic_test_negative(val)) & ( (ulong)(val) < (1UL<<62UL) ) \
  )


/* encode a VARINT "val" into "buf" of size "buf_sz"
   buf must be a mutable uchar pointer, and will be updated to point to
     the remaining buffer
   buf_sz must be a mutable integer and will be reduced by the number of
     bytes written
   bounds are checked before writing into buf */
#define FD_QUIC_ENCODE_VARINT(buf,buf_sz,val)                             \
  do {                                                                    \
    ulong val64 = fd_quic_test_negative(val) ? 0 : (val);                 \
    if( val64 < ( 1UL << ( 0x08 - 2 ) ) ) {                               \
      if( buf_sz < 1 ) return FD_QUIC_ENCODE_FAIL;                        \
      buf[0] = (uchar)val64;                                              \
      buf++; buf_sz--;                                                    \
    } else                                                                \
    if( val64 < ( 1UL << ( 0x10 - 2 ) ) ) {                               \
      if( buf_sz < 2 ) return FD_QUIC_ENCODE_FAIL;                        \
      buf[0] = (uchar)( ( ( val64 >> 0x08 ) & 0xfful ) | 0x40u );         \
      buf[1] = ( val64 >> 0x00 ) & 0xffu;                                 \
      buf+=2; buf_sz-=2;                                                  \
    } else                                                                \
    if( val64 < ( (ulong)1 << ( 0x20 - 2 ) ) ) {                          \
      if( buf_sz < 4 ) return FD_QUIC_ENCODE_FAIL;                        \
      buf[0] = (uchar)( ( ( val64 >> 0x18 ) & 0xffu ) | 0x80u );          \
      buf[1] = ( val64 >> 0x10 ) & 0xffu;                                 \
      buf[2] = ( val64 >> 0x08 ) & 0xffu;                                 \
      buf[3] = ( val64 >> 0x00 ) & 0xffu;                                 \
      buf+=4; buf_sz-=4;                                                  \
    } else                                                                \
    if( val64 < ( (ulong)1 << ( 0x40 - 2 ) ) ) {                          \
      if( buf_sz < 8 ) return FD_QUIC_ENCODE_FAIL;                        \
      buf[0] = (uchar)( ( ( val64 >> 0x38 ) & 0xffu ) | 0xc0u );          \
      buf[1] = ( val64 >> 0x30 ) & 0xffu;                                 \
      buf[2] = ( val64 >> 0x28 ) & 0xffu;                                 \
      buf[3] = ( val64 >> 0x20 ) & 0xffu;                                 \
      buf[4] = ( val64 >> 0x18 ) & 0xffu;                                 \
      buf[5] = ( val64 >> 0x10 ) & 0xffu;                                 \
      buf[6] = ( val64 >> 0x08 ) & 0xffu;                                 \
      buf[7] = ( val64 >> 0x00 ) & 0xffu;                                 \
      buf+=8; buf_sz-=8;                                                  \
    } else                                                                \
      return FD_QUIC_ENCODE_FAIL;                                         \
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
