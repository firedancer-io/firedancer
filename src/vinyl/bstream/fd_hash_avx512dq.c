#include "fd_vinyl_bstream.h"
#if !FD_HAS_AVX512
#error "fd_hash_avx512dq requires AVX-512"
#endif

#include "../../util/simd/fd_avx512.h"
#include "../../util/simd/fd_avx.h"

#if defined(__AVX512DQ__)

FD_FN_PURE void
fd_vinyl_bstream_hash_batch8( ulong                                  seed_,
                              ulong *                    FD_RESTRICT out,
                              void const * FD_RESTRICT * FD_RESTRICT buf_,
                              ulong const *              FD_RESTRICT sz_ ) {
  wwv_t const c1 = wwv_bcast( 11400714785074694791UL );
  wwv_t const c2 = wwv_bcast( 14029467366897019727UL );
  wwv_t const c3 = wwv_bcast(  1609587929392839161UL );
  wwv_t const c4 = wwv_bcast(  9650029242287828579UL );

  wwv_t       buf  = wwv_ldu  ( (void const *)buf_ );
  wwv_t const seed = wwv_bcast( seed_ );
  wwl_t const sz   = wwv_ldu  ( sz_   );
  wwl_t       rem  = sz;

  static uchar scratch_[64] __attribute__((aligned(64)));
  wwv_t const scratch = wwv_bcast( (ulong)scratch_ );

  wwv_t w = wwv_add( seed, wwv_add( c1, c2 ) );
  wwv_t x = wwv_add( seed, c2 );
  wwv_t y = seed;
  wwv_t z = wwv_sub( seed, c1 );

  /* Load input */
  wwv_t h;
  for(;;) {
    int mask = wwl_ge( rem, wwl_bcast( 32UL ) );
    if( !mask ) break;

    wwv_t msg = wwv_if( mask, buf, scratch );
    ulong _W0; ulong _W1; ulong _W2; ulong _W3; ulong _W4; ulong _W5; ulong _W6; ulong _W7;
    wwv_unpack( msg, _W0, _W1, _W2, _W3, _W4, _W5, _W6, _W7 );

    /* Transpose input */
    wv_t  buf0 = wv_ldu( ( (uchar const *)_W0 ) );
    wv_t  buf1 = wv_ldu( ( (uchar const *)_W1 ) );
    wv_t  buf2 = wv_ldu( ( (uchar const *)_W2 ) );
    wv_t  buf3 = wv_ldu( ( (uchar const *)_W3 ) );
    wv_t  buf4 = wv_ldu( ( (uchar const *)_W4 ) );
    wv_t  buf5 = wv_ldu( ( (uchar const *)_W5 ) );
    wv_t  buf6 = wv_ldu( ( (uchar const *)_W6 ) );
    wv_t  buf7 = wv_ldu( ( (uchar const *)_W7 ) );
    wwv_t z01 = _mm512_inserti64x4( _mm512_castsi256_si512( buf0 ), buf1, 1 );
    wwv_t z23 = _mm512_inserti64x4( _mm512_castsi256_si512( buf2 ), buf3, 1 );
    wwv_t z45 = _mm512_inserti64x4( _mm512_castsi256_si512( buf4 ), buf5, 1 );
    wwv_t z67 = _mm512_inserti64x4( _mm512_castsi256_si512( buf6 ), buf7, 1 );
    wwv_t t0  = _mm512_unpacklo_epi64( z01, z23 );
    wwv_t t1  = _mm512_unpackhi_epi64( z01, z23 );
    wwv_t t2  = _mm512_unpacklo_epi64( z45, z67 );
    wwv_t t3  = _mm512_unpackhi_epi64( z45, z67 );
    wwv_t s0  = _mm512_shuffle_i64x2( t0, t2, 0x44 );
    wwv_t s1  = _mm512_shuffle_i64x2( t0, t2, 0xEE );
    wwv_t s2  = _mm512_shuffle_i64x2( t1, t3, 0x44 );
    wwv_t s3  = _mm512_shuffle_i64x2( t1, t3, 0xEE );
    wwv_t u0  = _mm512_unpacklo_epi64( s0, s1 );
    wwv_t u1  = _mm512_unpackhi_epi64( s0, s1 );
    wwv_t u2  = _mm512_unpacklo_epi64( s2, s3 );
    wwv_t u3  = _mm512_unpackhi_epi64( s2, s3 );
    wwv_t v0  = _mm512_shuffle_i64x2( u0, u1, 0x44 );
    wwv_t v1  = _mm512_shuffle_i64x2( u0, u1, 0xEE );
    wwv_t v2  = _mm512_shuffle_i64x2( u2, u3, 0x44 );
    wwv_t v3  = _mm512_shuffle_i64x2( u2, u3, 0xEE );
    wwv_t p0  = _mm512_shuffle_i64x2( v0, v1, 0x88 );
    wwv_t p1  = _mm512_shuffle_i64x2( v2, v3, 0x88 );
    wwv_t p2  = _mm512_shuffle_i64x2( v0, v1, 0xDD );
    wwv_t p3  = _mm512_shuffle_i64x2( v2, v3, 0xDD );

    wwv_t nw = wwv_add( w,  wwv_mul( p0, c2 ) );
    /* */ nw = wwv_rol( nw, 31 );
    /* */ nw = wwv_mul( nw, c1 );
    wwv_t nx = wwv_add( x,  wwv_mul( p1, c2 ) );
    /* */ nx = wwv_rol( nx, 31 );
    /* */ nx = wwv_mul( nx, c1 );
    wwv_t ny = wwv_add( y,  wwv_mul( p2, c2 ) );
    /* */ ny = wwv_rol( ny, 31 );
    /* */ ny = wwv_mul( ny, c1 );
    wwv_t nz = wwv_add( z,  wwv_mul( p3, c2 ) );
    /* */ nz = wwv_rol( nz, 31 );
    /* */ nz = wwv_mul( nz, c1 );

    w = wwv_if( mask, nw, w );
    x = wwv_if( mask, nx, x );
    y = wwv_if( mask, ny, y );
    z = wwv_if( mask, nz, z );

    buf = wwv_add_if( mask, buf, wwv_bcast( 32UL ), buf );
    rem = wwl_sub_if( mask, rem, wwl_bcast( 32UL ), rem );
  }

  h = wwv_add(
      wwv_add( wwv_rol( w,  1 ), wwv_rol( x,  7 ) ),
      wwv_add( wwv_rol( y, 12 ), wwv_rol( z, 18 ) )
  );

  w = wwv_mul( w, c2 );
  w = wwv_rol( w, 31 );
  w = wwv_mul( w, c1 );
  h = wwv_xor( h, w );
  h = wwv_add( wwv_mul( h, c1 ), c4 );
  x = wwv_mul( x, c2 );
  x = wwv_rol( x, 31 );
  x = wwv_mul( x, c1 );
  h = wwv_xor( h, x );
  h = wwv_add( wwv_mul( h, c1 ), c4 );
  y = wwv_mul( y, c2 );
  y = wwv_rol( y, 31 );
  y = wwv_mul( y, c1 );
  h = wwv_xor( h, y );
  h = wwv_add( wwv_mul( h, c1 ), c4 );
  z = wwv_mul( z, c2 );
  z = wwv_rol( z, 31 );
  z = wwv_mul( z, c1 );
  h = wwv_xor( h, z );
  h = wwv_add( wwv_mul( h, c1 ), c4 );

  h = wwv_add( h, sz );

  /* Final avalanche */
  h = wwv_xor( h, wwv_shr( h, 33 ) );
  h = wwv_mul( h, c2 );
  h = wwv_xor( h, wwv_shr( h, 29 ) );
  h = wwv_mul( h, c3 );
  h = wwv_xor( h, wwv_shr( h, 32 ) );

  wwv_stu( out, h );
}

#endif
