#include <stddef.h>
#include <stdint.h>

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
    ( val < ( (uint64_t)1 << ( 0x08 - 2 ) ) ) ? 1    \
    :                                                \
    ( val < ( (uint64_t)1 << ( 0x10 - 2 ) ) ) ? 2    \
    :                                                \
    ( val < ( (uint64_t)1 << ( 0x20 - 2 ) ) ) ? 4    \
    :                                                \
    ( val < ( (uint64_t)1 << ( 0x40 - 2 ) ) ) ? 8    \
    :                                                \
    FD_QUIC_ENCODE_FAIL                              \
  )


/* encode a VARINT "val" into "buf" of size "buf_sz"
   buf must be a mutable uchar pointer, and will be updated to point to
     the remaining buffer
   buf_sz must be a mutable integer and will be reduced by the number of
     bytes written
   bounds are checked before writing into buf */
#define FD_QUIC_ENCODE_VARINT(buf,buf_sz,val)                             \
  do {                                                                    \
    uint64_t val64 = fd_quic_test_negative(val) ? 0 : (val);              \
    if( val64 < ( (uint64_t)1 << ( 0x08 - 2 ) ) ) {                       \
      if( buf_sz < 1 ) return FD_QUIC_ENCODE_FAIL;                        \
      buf[0] = (uchar)val64;                                              \
      buf++; buf_sz--;                                                    \
    } else                                                                \
    if( val64 < ( (uint64_t)1 << ( 0x10 - 2 ) ) ) {                       \
      if( buf_sz < 2 ) return FD_QUIC_ENCODE_FAIL;                        \
      buf[0] = (uchar)( ( ( val64 >> 0x08 ) & 0xfful ) | 0x40u );         \
      buf[1] = ( val64 >> 0x00 ) & 0xffu;                                 \
      buf+=2; buf_sz-=2;                                                  \
    } else                                                                \
    if( val64 < ( (uint64_t)1 << ( 0x20 - 2 ) ) ) {                       \
      if( buf_sz < 4 ) return FD_QUIC_ENCODE_FAIL;                        \
      buf[0] = (uchar)( ( ( val64 >> 0x18 ) & 0xffu ) | 0x80u );          \
      buf[1] = ( val64 >> 0x10 ) & 0xffu;                                 \
      buf[2] = ( val64 >> 0x08 ) & 0xffu;                                 \
      buf[3] = ( val64 >> 0x00 ) & 0xffu;                                 \
      buf+=4; buf_sz-=4;                                                  \
    } else                                                                \
    if( val64 < ( (uint64_t)1 << ( 0x40 - 2 ) ) ) {                       \
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


#if 0
inline
uint64_t
fd_quic_parse_bits( uchar const * buf, size_t cur_bit, size_t bits ) {
  if( bits == 0 ) return 0;
  if( bits > 64 ) return 0;

  if( cur_bit == 0 && bits >= 8 ) {
    return ( (uint64_t)buf[0] << (bits-8) ) + fd_quic_parse_bits( buf + 1, cur_bit, bits - 8 );
  }

  if( cur_bit == 0 ) {
    // must be less than 8 bits
    return ( buf[0] >> ( 8 - bits ) ) & ( ( 1 << bits ) - 1 );
  }

  // align remainder
  if( bits <= 8 - cur_bit ) {
    return ( (uint64_t)buf[0] >> ( 8 - cur_bit - bits ) ) & ( ( 1 << bits ) - 1 );
  }

  return ( ( (uint64_t)buf[0] & ( ( 1 << ( 8 - cur_bit ) ) - 1 ) ) << ( bits - ( 8 - cur_bit ) ) )
         + fd_quic_parse_bits( buf + 1, 0, ( bits - ( 8 - cur_bit ) ) );
}
#elif 1

inline
uint64_t
fd_quic_parse_bits( uchar const * buf, size_t cur_bit, size_t bits ) {
  /* written to assist compiler in optimizing
     when written naively, the compiler emits branches and calls
       whereas this way almost all the code is elided
     the parameters are largely known at compile time
     single return statement and no local vars helps tail recursion optimization
     and inlining */
  return (
           ( bits == 0u ) ? 0u  // essentially "if( bits == 0 ) return 0; ..."
           :
           ( bits > 64u ) ? 0u
           :
           ( cur_bit == 0u && bits >= 8u ) ?
             ( ( (uint64_t)buf[0u] << (bits-8u) ) + fd_quic_parse_bits( buf + 1u, cur_bit, bits - 8u ) )
           :
           ( cur_bit == 0u ) ?
             ( ( (uint64_t)buf[0u] >> ( 8u - bits ) ) & ( ( 1u << bits ) - 1u ) )
          
           :
           ( bits <= 8u - cur_bit ) ?
             ( ( (uint64_t)buf[0u] >> ( 8u - cur_bit - bits ) ) & ( ( 1u << bits ) - 1u ) )
          
           :
           ( ( ( (uint64_t)buf[0u] & ( ( 1u << ( 8u - cur_bit ) ) - 1u ) ) << ( bits - ( 8u - cur_bit ) ) )
                  + fd_quic_parse_bits( buf + 1u, 0u, ( bits - ( 8u - cur_bit ) ) ) )
        );
}



/* encode contiguos unaligned bits across bytes
   caller responsible for ensuring enough space for oparation
   returns 0 for success */
inline
int
fd_quic_encode_bits( uchar * buf, size_t cur_bit, uint64_t val, size_t bits ) {
  /* TODO optimize this */

  if( bits == 0u || bits > 64u ) return 1;

  for( size_t j = 0; j < bits; ++j ) {
    size_t k = cur_bit + j;
    size_t bit_offs  = k & 7u;
    size_t byte_offs = k >> 3u; 

    /* at each new byte, clear it */
    uchar cur_byte = bit_offs == 0 ? 0 : buf[byte_offs];

    /* val bit 0 corresponds to bit offset bits-1 */
    /* j == 0 is the leftmost bit, which is val bit (bits-1) */
    /* j == 1 is the leftmost bit, which is val bit (bits-2) */
    /* so we want to shift val right by ( bits-1-j ) */

    buf[byte_offs] = cur_byte | (uchar) ( ( (val >> (bits-1u-j)) & 1u ) << ( 7u - bit_offs ) );
  }

  return 0;
}
#endif
