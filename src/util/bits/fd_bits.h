#ifndef HEADER_fd_src_util_bits_fd_bits_h
#define HEADER_fd_src_util_bits_fd_bits_h

/* Bit manipulation APIs */

#include "../fd_util_base.h"

FD_PROTOTYPES_BEGIN

/* fd_ulong_is_pow2    ( x          ) returns 1 if x is a positive integral power of 2 and 0 otherwise.
   fd_ulong_pow2       ( n          ) returns 2^n mod 2^64.  U.B. if n is negative.

   fd_ulong_mask_bit   ( b          ) returns the ulong with bit b set and all other bits 0.  U.B. if b is not in [0,64).
   fd_ulong_clear_bit  ( x, b       ) returns x with bit b cleared.  U.B. if b is not in [0,64).
   fd_ulong_set_bit    ( x, b       ) returns x with bit b set. U.B. if b is not in [0,64).
   fd_ulong_extract_bit( x, b       ) returns bit b of x as an int in {0,1}.  U.B. if b is not in [0,64).
   fd_ulong_insert_bit ( x, b, y    ) returns x with bit b set to y.  U.B. if b is not in [0,64) and/or y is not in {0,1}.

   fd_ulong_mask_lsb   ( n          ) returns the ulong bits [0,n) set and all other bits 0.  U.B. if n is not in [0,64].
   fd_ulong_clear_lsb  ( x, n       ) returns x with bits [0,n) cleared.  U.B. if n is not in [0,64].
   fd_ulong_set_lsb    ( x, n       ) returns x with bits [0,n) set. U.B. if n is not in [0,64].
   fd_ulong_flip_lsb   ( x, n       ) returns x with bits [0,n) flipped. U.B. if n is not in [0,64].
   fd_ulong_extract_lsb( x, n       ) returns bits [0,n) of x.  U.B. if b is not in [0,64).
   fd_ulong_insert_lsb ( x, n, y    ) returns x with bits [0,n) set to y.  U.B. if b is not in [0,64) and/or y is not in [0,2^n).

   fd_ulong_mask       ( l, h       ) returns the ulong bits [l,h] set and all other bits 0.  U.B. if not 0<=l<=h<64.
   fd_ulong_clear      ( x, l, h    ) returns x with bits [l,h] cleared.  U.B. if not 0<=l<=h<64.
   fd_ulong_set        ( x, l, h    ) returns x with bits [l,h] set.  U.B. if not 0<=l<=h<64.
   fd_ulong_flip       ( x, l, h    ) returns x with bits [l,h] flipped.  U.B. if not 0<=l<=h<64.
   fd_ulong_extract    ( x, l, h    ) returns bits [l,h] of x.  U.B. if not 0<=l<=h<64.
   fd_ulong_insert     ( x, l, h, y ) returns x with bits [l,h] set to y.
                                      U.B. if not 0<=l<=h<64 and/or y is not in in [0,2^(h-l+1)).

   fd_ulong_pop_lsb    ( x          ) returns x with the least significant set bit cleared (0 returns 0).

   FIXME: CONSIDER HAVING (A,X) INSTEAD OF (X,A)?
   fd_ulong_is_aligned ( x, a       ) returns 1 if x is an integral multiple of a and 0 otherwise.  U.B. if !fd_ulong_is_pow2( a )
   fd_ulong_alignment  ( x, a       ) returns x mod a.  U.B. if !fd_ulong_is_pow2( a )
   fd_ulong_align_dn   ( x, a       ) returns x rounded down to the closest multiple of a <= x.  U.B. if !fd_ulong_is_pow2( a )
   fd_ulong_align_up   ( x, a       ) returns x rounded up to the closest multiple of a >= x mod 2^64.
                                      U.B. if !fd_ulong_is_pow2( a )

   fd_ulong_blend      ( m, t, f    ) returns forms a ulong by selecting bits from t where m is 1 and from f where m is 0.
   fd_ulong_if         ( c, t, f    ) returns t if c is 1 and f if c is 0.  U.B. if c is not in {0,1}
   fd_ulong_abs        ( x          ) returns |x| as a ulong
   fd_ulong_min        ( x, y       ) returns min(x,y)
   fd_ulong_max        ( x, y       ) returns max(x,y)

   fd_ulong_rotate_left ( x, n ) returns x with its bits rotated left n times (negative values rotate right)
   fd_ulong_rotate_right( x, n ) returns x with its bits rotated right n times (negative values rotate left)

   fd_ulong_popcnt            ( x    ) returns the number of bits set in x, in [0,64].
   fd_ulong_find_lsb          ( x    ) returns the index of the least significant bit set in x, in [0,64).  U.B. if x is zero.
   fd_ulong_find_lsb_w_default( x, d ) returns the index of the least significant bit set in x, in [0,64).  d if x is zero.
   fd_ulong_find_msb          ( x    ) returns the index of the most significant bit set in x, in [0,64).  U.B. if x is zero.
   fd_ulong_find_msb_w_default( x, d ) returns the index of the most significant bit set in x, in [0,64).  d if x is zero.
   fd_ulong_bswap             ( x    ) returns x with its bytes swapped
   fd_ulong_pow2_up           ( x    ) returns y mod 2^64 where y is the smallest integer power of 2 >= x.
                                       x returns 0 (U.B. behavior or 1 might arguable alternatives here)

   Similarly for uchar,ushort,uint,uint128

   FIXME: mask_msb, clear_msb, set_msb, flip_msb, extract_msb,
   insert_msb, bitrev, wide shifts, signed extending shifts, rounding
   right shift, ... */

#define FD_SRC_UTIL_BITS_FD_BITS_IMPL(T,w)                                                                                        \
FD_FN_CONST static inline int fd_##T##_is_pow2     ( T x               ) { return (!!x) & (!(x & (x-(T)1)));                    } \
FD_FN_CONST static inline T   fd_##T##_pow2        ( int n             ) { return (T)(((T)(n<w))<<(n&(w-1)));                   } \
FD_FN_CONST static inline T   fd_##T##_mask_bit    ( int b             ) { return (T)(((T)1)<<b);                               } \
FD_FN_CONST static inline T   fd_##T##_clear_bit   ( T x, int b        ) { return (T)(x & ~fd_##T##_mask_bit(b));               } \
FD_FN_CONST static inline T   fd_##T##_set_bit     ( T x, int b        ) { return (T)(x |  fd_##T##_mask_bit(b));               } \
FD_FN_CONST static inline T   fd_##T##_flip_bit    ( T x, int b        ) { return (T)(x ^  fd_##T##_mask_bit(b));               } \
FD_FN_CONST static inline int fd_##T##_extract_bit ( T x, int b        ) { return (int)((x>>b) & (T)1);                         } \
FD_FN_CONST static inline T   fd_##T##_insert_bit  ( T x, int b, int y ) { return (T)((x & ~fd_##T##_mask_bit(b))|(((T)y)<<b)); } \
FD_FN_CONST static inline T   fd_##T##_mask_lsb    ( int n             ) { return (T)((((T)(n<w))<<(n&(w-1)))-((T)1));          } \
FD_FN_CONST static inline T   fd_##T##_clear_lsb   ( T x, int n        ) { return (T)(x & ~fd_##T##_mask_lsb(n));               } \
FD_FN_CONST static inline T   fd_##T##_set_lsb     ( T x, int n        ) { return (T)(x |  fd_##T##_mask_lsb(n));               } \
FD_FN_CONST static inline T   fd_##T##_flip_lsb    ( T x, int n        ) { return (T)(x ^  fd_##T##_mask_lsb(n));               } \
FD_FN_CONST static inline T   fd_##T##_extract_lsb ( T x, int n        ) { return (T)(x &  fd_##T##_mask_lsb(n));               } \
FD_FN_CONST static inline T   fd_##T##_insert_lsb  ( T x, int n, T y   ) { return (T)(fd_##T##_clear_lsb(x,n) | y);             } \
FD_FN_CONST static inline T   fd_##T##_mask        ( int l, int h      ) { return (T)( fd_##T##_mask_lsb(h-l+1) << l );         } \
FD_FN_CONST static inline T   fd_##T##_clear       ( T x, int l, int h ) { return (T)(x & ~fd_##T##_mask(l,h));                 } \
FD_FN_CONST static inline T   fd_##T##_set         ( T x, int l, int h ) { return (T)(x |  fd_##T##_mask(l,h));                 } \
FD_FN_CONST static inline T   fd_##T##_flip        ( T x, int l, int h ) { return (T)(x ^  fd_##T##_mask(l,h));                 } \
FD_FN_CONST static inline T   fd_##T##_extract     ( T x, int l, int h ) { return (T)( (x>>l) & fd_##T##_mask_lsb(h-l+1) );     } \
FD_FN_CONST static inline T   fd_##T##_insert      ( T x, int l, int h, T y ) { return (T)(fd_##T##_clear(x,l,h) | (y<<l));     } \
FD_FN_CONST static inline T   fd_##T##_pop_lsb     ( T x               ) { return (T)(x & (x-(T)1));                            } \
FD_FN_CONST static inline int fd_##T##_is_aligned  ( T x, T a          ) { a--; return !(x & a);                                } \
FD_FN_CONST static inline T   fd_##T##_alignment   ( T x, T a          ) { a--; return (T)( x    &  a);                         } \
FD_FN_CONST static inline T   fd_##T##_align_dn    ( T x, T a          ) { a--; return (T)( x    & ~a);                         } \
FD_FN_CONST static inline T   fd_##T##_align_up    ( T x, T a          ) { a--; return (T)((x+a) & ~a);                         } \
FD_FN_CONST static inline T   fd_##T##_blend       ( T m, T t, T f     ) { return (T)((t & m) | (f & ~m));                      } \
FD_FN_CONST static inline T   fd_##T##_if          ( int c, T t, T f   ) { return c ? t : f;     /* cmov */                     } \
FD_FN_CONST static inline T   fd_##T##_abs         ( T x               ) { return x;                                            } \
FD_FN_CONST static inline T   fd_##T##_min         ( T x, T y          ) { return (x<y) ? x : y; /* cmov */                     } \
FD_FN_CONST static inline T   fd_##T##_max         ( T x, T y          ) { return (x>y) ? x : y; /* cmov */                     } \
FD_FN_CONST static inline T   fd_##T##_rotate_left ( T x, int n        ) { n &= w-1; return (T)((x << n) | (x >> (w-n)));       } \
FD_FN_CONST static inline T   fd_##T##_rotate_right( T x, int n        ) { n &= w-1; return (T)((x >> n) | (x << (w-n)));       }

FD_SRC_UTIL_BITS_FD_BITS_IMPL(uchar,  8)
FD_SRC_UTIL_BITS_FD_BITS_IMPL(ushort,16)
FD_SRC_UTIL_BITS_FD_BITS_IMPL(uint,  32)
FD_SRC_UTIL_BITS_FD_BITS_IMPL(ulong, 64)

#if FD_HAS_INT128 /* FIXME: These probably could benefit from x86 specializations */
FD_SRC_UTIL_BITS_FD_BITS_IMPL(uint128,128)
#endif

#undef FD_SRC_UTIL_BITS_FD_BITS_IMPL

FD_FN_CONST static inline int fd_uchar_popcnt ( uchar  x ) { return __builtin_popcount ( (uint)x ); }
FD_FN_CONST static inline int fd_ushort_popcnt( ushort x ) { return __builtin_popcount ( (uint)x ); }
FD_FN_CONST static inline int fd_uint_popcnt  ( uint   x ) { return __builtin_popcount (       x ); }
FD_FN_CONST static inline int fd_ulong_popcnt ( ulong  x ) { return __builtin_popcountl(       x ); }

#if FD_HAS_INT128 
FD_FN_CONST static inline int
fd_uint128_popcnt( uint128 x ) {
  return  __builtin_popcountl( (ulong) x ) + __builtin_popcountl( (ulong)(x>>64) );
}
#endif

#include "fd_bits_find_lsb.h" /* Provides find_lsb_w_default too */
#include "fd_bits_find_msb.h" /* Provides find_msb_w_default too */ /* Note that find_msb==floor( log2( x ) ) for non-zero x */

FD_FN_CONST static inline uchar  fd_uchar_bswap ( uchar  x ) { return x; }
FD_FN_CONST static inline ushort fd_ushort_bswap( ushort x ) { return __builtin_bswap16( x ); }
FD_FN_CONST static inline uint   fd_uint_bswap  ( uint   x ) { return __builtin_bswap32( x ); }
FD_FN_CONST static inline ulong  fd_ulong_bswap ( ulong  x ) { return __builtin_bswap64( x ); }

#if FD_HAS_INT128
FD_FN_CONST static inline uint128
fd_uint128_bswap( uint128 x ) {
  ulong xl = (ulong) x;
  ulong xh = (ulong)(x>>64);
  return (((uint128)fd_ulong_bswap( xl )) << 64) | ((uint128)fd_ulong_bswap( xh ));
}
#endif

/* FIXME: CONSIDER FIND_MSB BASED SOLUTION? */

FD_FN_CONST static inline uchar
fd_uchar_pow2_up( uchar _x ) {
  uint x = (uint)_x;
  x--;
  x |= (x>> 1);
  x |= (x>> 2);
  x |= (x>> 4);
  x++;
  return (uchar)x;
}

FD_FN_CONST static inline ushort
fd_ushort_pow2_up( ushort _x ) {
  uint x = (uint)_x;
  x--;
  x |= (x>> 1);
  x |= (x>> 2);
  x |= (x>> 4);
  x |= (x>> 8);
  x++;
  return (ushort)x;
}

FD_FN_CONST static inline uint
fd_uint_pow2_up( uint x ) {
  x--;
  x |= (x>> 1);
  x |= (x>> 2);
  x |= (x>> 4);
  x |= (x>> 8);
  x |= (x>>16);
  x++;
  return x;
}

FD_FN_CONST static inline ulong
fd_ulong_pow2_up( ulong x ) {
  x--;
  x |= (x>> 1);
  x |= (x>> 2);
  x |= (x>> 4);
  x |= (x>> 8);
  x |= (x>>16);
  x |= (x>>32);
  x++;
  return x;
}

#if FD_HAS_INT128
FD_FN_CONST static inline uint128
fd_uint128_pow2_up( uint128 x ) {
  x--;
  x |= (x>> 1);
  x |= (x>> 2);
  x |= (x>> 4);
  x |= (x>> 8);
  x |= (x>>16);
  x |= (x>>32);
  x |= (x>>64);
  x++;
  return x;
}
#endif

#define FD_SRC_UTIL_BITS_FD_BITS_IMPL(T,w)                                                        \
FD_FN_CONST static inline T fd_##T##_if ( int c, T t, T f ) { return c ? t : f;      /* cmov */ } \
FD_FN_CONST static inline T fd_##T##_min( T x, T y        ) { return (x<=y) ? x : y; /* cmov */ } \
FD_FN_CONST static inline T fd_##T##_max( T x, T y        ) { return (x>=y) ? x : y; /* cmov */ }

FD_SRC_UTIL_BITS_FD_BITS_IMPL(schar,   8)
FD_SRC_UTIL_BITS_FD_BITS_IMPL(short,  16)
FD_SRC_UTIL_BITS_FD_BITS_IMPL(int,    32)
FD_SRC_UTIL_BITS_FD_BITS_IMPL(long,   64)

#if FD_HAS_INT128
FD_SRC_UTIL_BITS_FD_BITS_IMPL(int128,128)
#endif

#undef FD_SRC_UTIL_BITS_FD_BITS_IMPL

/* Brokeness of indeterminant char sign strikes again ... sigh.  We
   can't provide a char_min/char_max between platforms as they don't
   necessarily produce the same results.  But it is useful to have a
   char_if to help with string operations. */

FD_FN_CONST static inline char fd_char_if( int c, char t, char f ) { return c ? t : f; }

/* Brokeness of indeterminant char sign strikes again ... sigh.  The
   uchar token is not related to the schar token by simply appending u
   to schar.  We don't provide a fd_char_abs because it will not produce
   equivalent results between platforms. */

#if 0

FD_FN_CONST static inline uchar  fd_schar_abs( schar x ) { return (uchar )fd_schar_if( x<(schar)0, (schar)-x, x ); }
FD_FN_CONST static inline ushort fd_short_abs( short x ) { return (ushort)fd_short_if( x<(short)0, (short)-x, x ); }
FD_FN_CONST static inline uint   fd_int_abs  ( int   x ) { return (uint  )fd_int_if  ( x<(int  )0, (int  )-x, x ); }
FD_FN_CONST static inline ulong  fd_long_abs ( long  x ) { return (ulong )fd_long_if ( x<(long )0, (long )-x, x ); }

#if FD_HAS_INT128
FD_FN_CONST static inline uint128 fd_int128_abs( int128 x ) { return (uint128)fd_int128_if( x<(int128)0, (int128)-x, x ); }
#endif

#else

FD_FN_CONST static inline uint    fd_int_abs   ( int    x ) { int    m = x>>31;  return (uint   )((x+m)^m); }
FD_FN_CONST static inline ulong   fd_long_abs  ( long   x ) { long   m = x>>63;  return (ulong  )((x+m)^m); }

#if FD_HAS_INT128
FD_FN_CONST static inline uint128 fd_int128_abs( int128 x ) { int128 m = x>>127; return (uint128)((x+m)^m); }
#endif

FD_FN_CONST static inline uchar   fd_schar_abs ( schar  x ) { return (uchar )fd_int_abs( (int)x ); }
FD_FN_CONST static inline ushort  fd_short_abs ( short  x ) { return (ushort)fd_int_abs( (int)x ); }

#endif

/* FIXME: ADD HASHING PAIRS FOR UCHAR AND USHORT? */

/* High quality (full avalanche) high speed integer to integer hashing.
   fd_uint_hash has the properties that [0,2^32) hashes to a random
   looking permutation of [0,2^32) and hash(0)==0.  Similarly for
   fd_ulong_hash.  Based on Google's Murmur3 hash finalizer (public
   domain).  Not cryptographically secure but passes various strict
   tests of randomness when used as a PRNG. */

static inline uint
fd_uint_hash( uint x ) {
  x ^= x >> 16;
  x *= 0x85ebca6bU;
  x ^= x >> 13;
  x *= 0xc2b2ae35U;
  x ^= x >> 16;
  return x;
}

static inline ulong
fd_ulong_hash( ulong x ) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdUL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53UL;
  x ^= x >> 33;
  return x;
}

/* Inverses of the above.  E.g.:
     fd_uint_hash_inverse( fd_uint_hash( (uint)x ) )==(uint)x
   and:
     fd_uint_hash( fd_uint_hash_inverse( (uint)x ) )==(uint)x
   Similarly for fd_ulong_hash_inverse.  These by themselves are similar
   quality hashes to the above and having the inverses of the above can
   be useful.  The fact these have (nearly) identical operations /
   operation counts concretely demonstrates that none of these are
   standalone cryptographically secure. */

static inline uint
fd_uint_hash_inverse( uint x ) {
  x ^= x >> 16;
  x *= 0x7ed1b41dU;
  x ^= (x >> 13) ^ (x >> 26);
  x *= 0xa5cb9243U;
  x ^= x >> 16;
  return x;
}

static inline ulong
fd_ulong_hash_inverse( ulong x ) {
  x ^= x >> 33;
  x *= 0x9cb4b2f8129337dbUL;
  x ^= x >> 33;
  x *= 0x4f74430c22a54005UL;
  x ^= x >> 33;
  return x;
}

/* fd_ulong_base10_dig_cnt returns the number of digits in the base 10
   representation of x.  FIXME: USE BETTER ALGO. */

#define FD_SRC_UTIL_BITS_FD_BITS_IMPL(T,M) \
FD_FN_CONST static inline ulong            \
fd_##T##_base10_dig_cnt( T _x ) {          \
  ulong x      = (ulong)_x;                \
  ulong cnt    = 1UL;                      \
  ulong thresh = 10UL;                     \
  do {                                     \
    if( FD_LIKELY( x<thresh ) ) break;     \
    cnt++;                                 \
    thresh *= 10UL;                        \
  } while( FD_LIKELY( cnt<M ) );           \
  return cnt;                              \
}

FD_SRC_UTIL_BITS_FD_BITS_IMPL(uchar,  3UL) /*                  255 ->  3 dig */
FD_SRC_UTIL_BITS_FD_BITS_IMPL(ushort, 5UL) /*                65535 ->  5 dig */
FD_SRC_UTIL_BITS_FD_BITS_IMPL(uint,  10UL) /*           4294967295 -> 10 dig */
FD_SRC_UTIL_BITS_FD_BITS_IMPL(ulong, 20UL) /* 18446744073709551615 -> 20 dig */

#undef FD_SRC_UTIL_BITS_FD_BITS_IMPL

/* fd_float_if, fd_float_abs are described above.  Ideally, the system
   will implement fd_float_abs by just clearing the sign bit.
   fd_float_eq tests to floating point values for whether or not their
   bit representations are identical.  Useful when IEEE handling of
   equality with +/-0 or nan are not desired (e.g. can test if nans have
   different signs or syndromes). */

FD_FN_CONST static inline float fd_float_if ( int c, float t, float f ) { return c ? t : f; }
FD_FN_CONST static inline float fd_float_abs( float x ) { return __builtin_fabsf( x ); }
FD_FN_CONST static inline int
fd_float_eq( float x,
             float y ) {
  union { float f; uint u; } tx, ty;
  tx.f = x;
  ty.f = y;
  return tx.u==ty.u;
}

/* fd_double_if, fd_double_abs and fd_double_eq are double precision
   versions of the above. */

#if FD_HAS_DOUBLE
FD_FN_CONST static inline double fd_double_if ( int c, double t, double f ) { return c ? t : f; }
FD_FN_CONST static inline double fd_double_abs( double x ) { return __builtin_fabs( x ); }
FD_FN_CONST static inline int
fd_double_eq( double x,
              double y ) {
  union { double f; ulong u; } tx, ty;
  tx.f = x;
  ty.f = y;
  return tx.u==ty.u;
}
#endif

/* fd_ulong_svw_enc_sz returns the number of bytes needed to encode
   x as a symmetric variable width encoded integer.  This is at most
   FD_ULONG_SVW_ENC_MAX (9).  Result will be in {1,2,3,4,5,8,9}. */

#define FD_ULONG_SVW_ENC_MAX (9UL) /* For compile time use */

FD_FN_UNUSED FD_FN_CONST static ulong /* Work around -Winline */
fd_ulong_svw_enc_sz( ulong x ) {
  /* FIXME: CONSIDER FIND_MSB BASED TABLE LOOKUP? */
  if( FD_LIKELY( x<(1UL<< 6) ) ) return 1UL;
  if( FD_LIKELY( x<(1UL<<10) ) ) return 2UL;
  if( FD_LIKELY( x<(1UL<<18) ) ) return 3UL;
  if( FD_LIKELY( x<(1UL<<24) ) ) return 4UL;
  if( FD_LIKELY( x<(1UL<<32) ) ) return 5UL;
  if( FD_LIKELY( x<(1UL<<56) ) ) return 8UL;
  /**/                           return 9UL;
}

/* fd_ulong_svw_enc appends x to the byte stream b as a symmetric
   variable width encoded integer.  b should have room from
   fd_ulong_svw_env_sz(x) (note that 9 is sufficient for all possible
   x).  Returns the next location in the byte system. */

static inline uchar *
fd_ulong_svw_enc( uchar * b,
                  ulong   x ) {
  if( FD_LIKELY( x<(1UL<< 6) ) ) { *          b = (uchar )                        (x<<1) ;                                   return b+1; } /* 0    | x( 6) |    0 */
  if( FD_LIKELY( x<(1UL<<10) ) ) { *(ushort *)b = (ushort)(            0x8001UL | (x<<3));                                   return b+2; } /* 100  | x(10) |  001 */
  if( FD_LIKELY( x<(1UL<<18) ) ) { *(ushort *)b = (ushort)(               0x5UL | (x<<3)); b[2] = (uchar)(0xa0UL | (x>>13)); return b+3; } /* 101  | x(18) |  101 */
  if( FD_LIKELY( x<(1UL<<24) ) ) { *(uint   *)b = (uint  )(        0xc0000003UL | (x<<4));                                   return b+4; } /* 1100 | x(24) | 0011 */
  if( FD_LIKELY( x<(1UL<<32) ) ) { *(uint   *)b = (uint  )(               0xbUL | (x<<4)); b[4] = (uchar)(0xd0UL | (x>>28)); return b+5; } /* 1101 | x(32) | 1011 */
  if( FD_LIKELY( x<(1UL<<56) ) ) { *(ulong  *)b =          0xe000000000000007UL | (x<<4) ;                                   return b+8; } /* 1110 | x(56) | 0111 */
  /**/                             *(ulong  *)b =                         0xfUL | (x<<4) ; b[8] = (uchar)(0xf0UL | (x>>60)); return b+9;   /* 1111 | x(64) | 1111 */
}

/* fd_ulong_svw_enc_fixed appends x to the byte stream b as a symmetric
   csz width encoded integer.  csz is assumed to be in {1,2,3,4,5,8,9}.
   b should have room from csz bytes and x should be known apriori to be
   compatible with csz.  Useful for updating in place an existing
   encoded integer to a value that is <= the current value.  Returns
   b+csz. */

FD_FN_UNUSED static uchar * /* Work around -Winline */
fd_ulong_svw_enc_fixed( uchar * b,
                        ulong   csz,
                        ulong   x ) {
  if(      FD_LIKELY( csz==1UL ) ) { *          b = (uchar )                        (x<<1) ;                                   } /* 0    | x( 6) |    0 */
  else if( FD_LIKELY( csz==2UL ) ) { *(ushort *)b = (ushort)(            0x8001UL | (x<<3));                                   } /* 100  | x(10) |  001 */
  else if( FD_LIKELY( csz==3UL ) ) { *(ushort *)b = (ushort)(               0x5UL | (x<<3)); b[2] = (uchar)(0xa0UL | (x>>13)); } /* 101  | x(18) |  101 */
  else if( FD_LIKELY( csz==4UL ) ) { *(uint   *)b = (uint  )(        0xc0000003UL | (x<<4));                                   } /* 1100 | x(24) | 0011 */
  else if( FD_LIKELY( csz==5UL ) ) { *(uint   *)b = (uint  )(               0xbUL | (x<<4)); b[4] = (uchar)(0xd0UL | (x>>28)); } /* 1101 | x(32) | 1011 */
  else if( FD_LIKELY( csz==8UL ) ) { *(ulong  *)b =          0xe000000000000007UL | (x<<4) ;                                   } /* 1110 | x(56) | 0111 */
  else             /* csz==9UL */  { *(ulong  *)b =                         0xfUL | (x<<4) ; b[8] = (uchar)(0xf0UL | (x>>60)); } /* 1111 | x(64) | 1111 */
  return b+csz;
}

/* fd_ulong_svw_dec_sz returns the number of bytes representing an svw
   encoded integer.  b points to the first byte of the encoded integer.
   Result will be in {1,2,3,4,5,8,9}. */

FD_FN_PURE static inline ulong
fd_ulong_svw_dec_sz( uchar const * b ) {

  /* LSB:         Compressed size
     xxxx|xxx0 -> 1B
     xxxx|x001 -> 2B
     xxxx|x101 -> 3B
     xxxx|0011 -> 4B
     xxxx|1011 -> 5B
     xxxx|0111 -> 8B
     xxxx|1111 -> 9B

      15   14   13   12   11   10    9    8    7    6    5    4    3    2    1    0
     1111 1110 1101 1100 1011 1010 1001 1000 0111 0110 0101 0100 0011 0010 0001 0000
       9    1    3    1    5    1    2    1    8    1    3    1    4    1    2    1 */

  return (0x9131512181314121UL >> ((((ulong)b[0]) & 15UL) << 2)) & 15UL;
}

/* fd_ulong_svw_dec_tail_sz returns the number of bytes representing an
   svw encoded integer.  b points to one after the last byte of the
   encoded integer.  Result will be in {1,2,3,4,5,8,9}. */

FD_FN_PURE static inline ulong
fd_ulong_svw_dec_tail_sz( uchar const * b ) {

  /* MSB:         Compressed size
     0xxx|xxxx -> 1B
     100x|xxxx -> 2B
     101x|xxxx -> 3B
     1100|xxxx -> 4B
     1101|xxxx -> 5B
     1110|xxxx -> 8B
     1111|xxxx -> 9B

      15   14   13   12   11   10    9    8    7    6    5    4    3    2    1    0
     1111 1110 1101 1100 1011 1010 1001 1000 0111 0110 0101 0100 0011 0010 0001 0000
       9    8    5    4    3    3    2    2    1    1    1    1    1    1    1    1 */

  return (0x9854332211111111UL >> ((((ulong)b[-1]) >> 4) << 2)) & 15UL;
}

/* fd_ulong_svw_dec_fixed decodes a ulong encoded as a symmetric
   variable width encoded integer whose width is known.  b points to the
   first byte of the encoded integer and the encoded integer is csz
   byte.  csz is assumed to be in {1,2,3,4,5,8,9}. */

FD_FN_UNUSED static ulong /* Work around -Winline */
fd_ulong_svw_dec_fixed( uchar const * b,
                        ulong         csz ) {
  if( FD_LIKELY( csz==1UL ) ) return (((ulong)*          b) >> 1);
  if( FD_LIKELY( csz==2UL ) ) return (((ulong)*(ushort *)b) >> 3) &              1023UL;
  if( FD_LIKELY( csz==3UL ) ) return (((ulong)*(ushort *)b) >> 3) | ((((ulong)b[2]) & 0x1fUL) << 13);
  if( FD_LIKELY( csz==4UL ) ) return (((ulong)*(uint   *)b) >> 4) &          16777215UL;
  if( FD_LIKELY( csz==5UL ) ) return (((ulong)*(uint   *)b) >> 4) | ((((ulong)b[4]) & 0x0fUL) << 28);
  if( FD_LIKELY( csz==8UL ) ) return ((       *(ulong  *)b) >> 4) & 72057594037927935UL;
  /**/        /* csz==9UL */  return ((       *(ulong  *)b) >> 4) | ( ((ulong)b[8])           << 60);
}

/* fd_ulong_svw_dec decodes a ulong encoded as a symmetric variable
   width encoded integer.  b points to the first byte of the encoded
   integer.  Returns a pointer to the first byte after the symvarint and
   *_x will hold the uncompressed value on return.  If the byte stream
   might be corrupt, it should be safe to read up to 9 bytes starting a
   b. */

static inline uchar const *
fd_ulong_svw_dec( uchar const * b,
                  ulong *       _x ) {
  ulong csz = fd_ulong_svw_dec_sz( b );
  *_x = fd_ulong_svw_dec_fixed( b, csz ); b += csz;
  return b;
}

/* fd_ulong_svw_dec_tail decodes a ulong encoded as a symmetric variable
   width encoded integer.  b points to the first byte after the encoded
   integer.  Returns a pointer to the first byte of the encoded integer
   and *_x will have the hold the uncompressed value on return.  If the
   byte stream might be corrupt, it should be safe to read up to 9 bytes
   immediately before b. */

static inline uchar const *
fd_ulong_svw_dec_tail( uchar const * b,
                       ulong *       _x ) {
  ulong csz = fd_ulong_svw_dec_tail_sz( b );
  b -= csz; *_x = fd_ulong_svw_dec_fixed( b, csz );
  return b;
}

/* Support for zig zag encoding.  Losslessly maps a signed integer to
   an unsigned integer such that, if the magnitude of the signed integer
   was small, the magnitude of the unsigned integer will be small too. */

FD_FN_CONST static inline uchar   fd_schar_zz_enc ( schar   x ) { return   (uchar)(( ((int)x) >>   7) ^  (( (int)x) << 1  )); }
FD_FN_CONST static inline schar   fd_schar_zz_dec ( uchar   x ) { return   (schar)((((uint)x) >>   1) ^ -(((uint)x) &  1U )); }

FD_FN_CONST static inline ushort  fd_short_zz_enc (  short  x ) { return  (ushort)(( ((int)x) >>  15) ^  (( (int)x) << 1  )); }
FD_FN_CONST static inline short   fd_short_zz_dec ( ushort  x ) { return   (short)((((uint)x) >>   1) ^ -(((uint)x) &  1U )); }

FD_FN_CONST static inline uint    fd_int_zz_enc   (  int    x ) { return    (uint)((       x  >>  31) ^  (       x  << 1  )); }
FD_FN_CONST static inline int     fd_int_zz_dec   ( uint    x ) { return     (int)((       x  >>   1) ^ -(       x  &  1U )); }

FD_FN_CONST static inline ulong   fd_long_zz_enc  (  long   x ) { return   (ulong)((       x  >>  63) ^  (       x  << 1  )); }
FD_FN_CONST static inline long    fd_long_zz_dec  ( ulong   x ) { return    (long)((       x  >>   1) ^ -(       x  &  1UL)); }

#if FD_HAS_INT128
FD_FN_CONST static inline uint128 fd_int128_zz_enc(  int128 x ) { return (uint128)((       x  >> 127) ^  (       x  << 1  )); }
FD_FN_CONST static inline int128  fd_int128_zz_dec( uint128 x ) { return  (int128)((       x  >>   1) ^ -(       x  &  1UL)); }
#endif

/* FD_ULONG_ALIGN_UP is the same as fd_ulong_align_up but can be used
   at compile time.  The tradeoff is a must be safe against multiple
   evaluation at compile time.  x and a should be ulong compatible. */

#define FD_ULONG_ALIGN_UP( x, a ) (((x)+((a)-1UL)) & (~((a)-1UL)))

/* FD_LAYOUT_{INIT,APPEND,FINI} are useful for compile time
   determination of the required footprint of shared memory regions with
   dynamic sizes and complex alignment restrictions.

   FD_LAYOUT_INIT starts a layout.  Returns a handle to the layout.

   FD_LAYOUT_APPEND appends a s byte region of alignment a to a layout
   where l is an in progress layout.

   FD_LAYOUT_FINI returns the final layout footprint.  a is the
   alignment to be used for the overall layout.  It should be the
   alignment of all appends.  The final footprint will be a multiple of
   a.

   All arguments should be ulong compatible.  All alignment should be a
   positive integer power of 2 and safe against multiple evaluation.

   The caller further promises the layout is not unreasonably large that
   overflow might be an issue (i.e. will be at most
   fd_ulong_align_dn(ULONG_MAX,a) where is the a used for FINI in size).

   Example usage:

     FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
       align0, size0 ),
       align0, size1 ),
       page_sz )

   would return the number of pages as a page_sz multiple for a shared
   memory region that starts with a initial/final region of size0/size1
   bytes and alignment align0/align1.  Correct operation requires
   page_sz>=max(align0,align1),  page_sz, align0 and align1 be positive
   integer powers of 2, page_sz, size0, align0 and align1 should be
   ulong compatible, page_sz, align0 and align1 be safe against multiple
   evaluation, and the final size be at most ULONG_MAX-page_sz+1. */

#define FD_LAYOUT_INIT              (0UL)
#define FD_LAYOUT_APPEND( l, a, s ) (FD_ULONG_ALIGN_UP( (l), (a) ) + (s))
#define FD_LAYOUT_FINI( l, a )      FD_ULONG_ALIGN_UP( (l), (a) )

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_bits_fd_bits_h */

