#include "fd_hex.h"

static inline int
fd_hex_unhex( int c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+0xa;
  if( c>='A' && c<='F' ) return c-'A'+0xa;
  return -1;
}

#if FD_HAS_AVX
#include "../../util/simd/fd_sse.h"
#include "../../util/simd/fd_avx.h"

static inline wb_t
decode_32( wb_t   c,
           uint * invalid ) {
  wb_t lower       = wb_or( c, wb_bcast( 0x20 ) );
  wb_t alpha       = wb_and( wb_gt( lower, wb_bcast( '`' ) ), wb_gt( wb_bcast( 'g' ), lower ) );
  wb_t digit       = wb_and( wb_gt( c, wb_bcast( '/' ) ),     wb_gt( wb_bcast( ':' ), c ) );
  wb_t valid       = wb_or( digit, alpha );
  wb_t nibbles     = wb_add( wb_and( c, wb_bcast( 0x0f ) ), wb_notczero( alpha, wb_bcast( 9 ) ) );
  wb_t pairs       = _mm256_maddubs_epi16( nibbles, wh_bcast( 0x0110 ) );
  wb_t compressed  = _mm256_shuffle_epi8( pairs, wb_bcast_hex( 0x00,0x02,0x04,0x06,0x08,0x0A,0x0C,0x0E,
                                                               0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF ) );

  *invalid = (uint)_mm256_movemask_epi8( wb_lnot( valid ) );
  return _mm256_permute4x64_epi64( compressed, 0xd8 );
}

static inline wb_t
encode_16( vb_t x ) {
  wb_t expanded = _mm256_cvtepu8_epi16( x );
  wb_t nibbles  = wb_and( wb_or( wh_shr( expanded, 4 ), wh_shl( expanded, 8 ) ), wb_bcast( 0x0f ) );
  wb_t adjust   = wb_notczero( wb_gt( nibbles, wb_bcast( 9 ) ), wb_bcast( 39 ) );
  return wb_add( wb_add( nibbles, adjust ), wb_bcast( '0' ) );
}

#endif

#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"

static inline wb_t
decode_64( wwb_t   c,
           ulong * invalid ) {
  wwb_t lower      = wwb_or( c, wwb_bcast( 0x20 ) );
  ulong alpha      = wwb_gt( lower, wwb_bcast( '`' ) ) & wwb_gt( wwb_bcast( 'g' ), lower );
  ulong digit      = wwb_gt( c, wwb_bcast( '/' ) )     & wwb_gt( wwb_bcast( ':' ), c );
  ulong valid      = digit | alpha;
  wwb_t nibbles    = wwb_add( wwb_and( c, wwb_bcast( 0x0f ) ), _mm512_maskz_set1_epi8( alpha, 9 ) );
  wwb_t pairs      = _mm512_maddubs_epi16( nibbles, wwh_bcast( 0x0110 ) );
  wwb_t compressed = _mm512_shuffle_epi8( pairs, wwb_bcast_hex( 0x00,0x02,0x04,0x06,0x08,0x0A,0x0C,0x0E,
                                                                0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF ) );

  *invalid = ~valid;
  return _mm512_castsi512_si256( _mm512_maskz_compress_epi64( (__mmask8)0x55, compressed ) );
}

static inline wwb_t
encode_32( wb_t x ) {
  wwb_t expanded = _mm512_cvtepu8_epi16( x );
  wwb_t nibbles  = wwb_and( wwb_or( wwh_shr( expanded, 4 ), wwh_shl( expanded, 8 ) ), wwb_bcast( 0x0f ) );
  wwb_t adjust   = _mm512_maskz_set1_epi8( wwb_gt( nibbles, wwb_bcast( 9 ) ), 39 );
  return wwb_add( wwb_add( nibbles, adjust ), wwb_bcast( '0' ) );
}

#endif

ulong
fd_hex_decode( void *       _dst,
               char const * hex,
               ulong        sz ) {
  uchar const * src = (uchar const *)hex;
  uchar * dst = _dst;

  ulong i=0UL;
#if FD_HAS_AVX512
  for( ; i+32UL<=sz; i+=32UL ) {
    ulong invalid;
    wb_t bytes = decode_64( wwb_ldu( src + 2UL*i ), &invalid );
    if( FD_UNLIKELY( invalid ) ) return i + (ulong)fd_ulong_find_lsb( invalid )/2UL;
    wb_stu( fd_type_pun( dst + i ), bytes );
  }
#endif
#if FD_HAS_AVX
  for( ; i+16UL<=sz; i+=16UL ) {
    uint invalid;
    wb_t bytes = decode_32( wb_ldu( src + 2UL*i ), &invalid );
    if( FD_UNLIKELY( invalid ) ) return i + (ulong)fd_uint_find_lsb( invalid )/2UL;
    vb_stu( fd_type_pun( dst + i ), _mm256_castsi256_si128( bytes ) );
  }
#endif

  src += 2UL*i;
  dst += i;

  for( ; i<sz; i++ ) {
    int hi = fd_hex_unhex( *src++ );
    int lo = fd_hex_unhex( *src++ );
    if( FD_UNLIKELY( (hi<0) | (lo<0) ) ) return i;
    *dst++ = (uchar)( ((uint)hi<<4) | (uint)lo );
  }

  return i;
}

char *
fd_hex_encode( char *       dst,
               void const * _src,
               ulong        sz ) {

  uchar const * src = (uchar const *)_src;
  ulong j=0UL;
#if FD_HAS_AVX512
  for( ; j+32UL<=sz; j+=32UL ) {
    wwb_t out = encode_32( wb_ldu( src + j ) );
    wwb_stu( fd_type_pun( dst + 2UL*j ), out );
  }
#endif
#if FD_HAS_AVX
  for( ; j+16UL<=sz; j+=16UL ) {
    wb_t out = encode_16( vb_ldu( fd_type_pun_const( src + j ) ) );
    wb_stu( fd_type_pun( dst + 2UL*j ), out );
  }
#endif

  src += j;
  dst += 2UL*j;
  sz  -= j;

  static char const lut[ 16 ] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
  for( ulong j=0UL; j<sz; j++ ) {
    ulong c = src[j];
    *dst++ = lut[ c >> 4UL ];
    *dst++ = lut[ c & 0xfUL ];
  }
  return dst;
}
