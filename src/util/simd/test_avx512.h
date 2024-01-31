#ifndef HEADER_fd_src_util_simd_test_avx512_h
#define HEADER_fd_src_util_simd_test_avx512_h

/* This header provides common functionality for the various AVX-512
   unit tests */

#include "../fd_util.h"
#include "fd_avx512.h"

FD_STATIC_ASSERT( WW_WIDTH       ==16, unit_test );
FD_STATIC_ASSERT( WW_FOOTPRINT   ==64, unit_test );
FD_STATIC_ASSERT( WW_ALIGN       ==64, unit_test );
FD_STATIC_ASSERT( WW_LG_WIDTH    == 4, unit_test );
FD_STATIC_ASSERT( WW_LG_FOOTPRINT== 6, unit_test );
FD_STATIC_ASSERT( WW_LG_ALIGN    == 6, unit_test );

#define WWI_TEST( x, x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf ) do {                                                 \
    int _t[16] WW_ATTR;                                                                                                     \
    int _u[16] WW_ATTR;                                                                                                     \
    wwi_st( _t, (x) );                                                                                                      \
    _u[ 0] = (x0); _u[ 1] = (x1); _u[ 2] = (x2); _u[ 3] = (x3); _u[ 4] = (x4); _u[ 5] = (x5); _u[ 6] = (x6); _u[ 7] = (x7); \
    _u[ 8] = (x8); _u[ 9] = (x9); _u[10] = (xa); _u[11] = (xb); _u[12] = (xc); _u[13] = (xd); _u[14] = (xe); _u[15] = (xf); \
    for( int _lane=0; _lane<16; _lane++ )                                                                                   \
      if( FD_UNLIKELY( _t[_lane]!=_u[_lane] ) )                                                                             \
        FD_LOG_ERR(( "FAIL: %s @ lane %i\n\t"                                                                               \
                     "  got 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x "                                       \
                           "0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n\t"                                    \
                     "  exp 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x "                                       \
                           "0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x",                                       \
                     #x, _lane,                                                                                             \
                     _t[ 0], _t[ 1], _t[ 2], _t[ 3], _t[ 4], _t[ 5], _t[ 6], _t[ 7],                                        \
                     _t[ 8], _t[ 9], _t[10], _t[11], _t[12], _t[13], _t[14], _t[15],                                        \
                     _u[ 0], _u[ 1], _u[ 2], _u[ 3], _u[ 4], _u[ 5], _u[ 6], _u[ 7],                                        \
                     _u[ 8], _u[ 9], _u[10], _u[11], _u[12], _u[13], _u[14], _u[15] ));                                     \
  } while(0)

#define WWU_TEST( x, x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf ) do {                                                 \
    uint _t[16] WW_ATTR;                                                                                                    \
    uint _u[16] WW_ATTR;                                                                                                    \
    wwu_st( _t, (x) );                                                                                                      \
    _u[ 0] = (x0); _u[ 1] = (x1); _u[ 2] = (x2); _u[ 3] = (x3); _u[ 4] = (x4); _u[ 5] = (x5); _u[ 6] = (x6); _u[ 7] = (x7); \
    _u[ 8] = (x8); _u[ 9] = (x9); _u[10] = (xa); _u[11] = (xb); _u[12] = (xc); _u[13] = (xd); _u[14] = (xe); _u[15] = (xf); \
    for( int _lane=0; _lane<16; _lane++ )                                                                                   \
      if( FD_UNLIKELY( _t[_lane]!=_u[_lane] ) )                                                                             \
        FD_LOG_ERR(( "FAIL: %s @ lane %i\n\t"                                                                               \
                     "  got 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU "                               \
                           "0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU\n\t"                            \
                     "  exp 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU "                               \
                           "0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU 0x%08xU",                               \
                     #x, _lane,                                                                                             \
                     _t[ 0], _t[ 1], _t[ 2], _t[ 3], _t[ 4], _t[ 5], _t[ 6], _t[ 7],                                        \
                     _t[ 8], _t[ 9], _t[10], _t[11], _t[12], _t[13], _t[14], _t[15],                                        \
                     _u[ 0], _u[ 1], _u[ 2], _u[ 3], _u[ 4], _u[ 5], _u[ 6], _u[ 7],                                        \
                     _u[ 8], _u[ 9], _u[10], _u[11], _u[12], _u[13], _u[14], _u[15] ));                                     \
  } while(0)

#define WWL_TEST( x, x0,x1,x2,x3,x4,x5,x6,x7 ) do {                                                                 \
    long _t[8] WW_ATTR;                                                                                             \
    long _u[8] WW_ATTR;                                                                                             \
    wwl_st( _t, (x) );                                                                                              \
    _u[0] = (x0); _u[1] = (x1); _u[2] = (x2); _u[3] = (x3); _u[4] = (x4); _u[5] = (x5); _u[6] = (x6); _u[7] = (x7); \
    for( int _lane=0; _lane<8; _lane++ )                                                                            \
      if( FD_UNLIKELY( _t[_lane]!=_u[_lane] ) )                                                                     \
        FD_LOG_ERR(( "FAIL: %s @ lane %i\n\t"                                                                       \
                     "  got 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL\n\t"    \
                     "  exp 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL",       \
                     #x, _lane,                                                                                     \
                     (ulong)_t[0], (ulong)_t[1], (ulong)_t[2], (ulong)_t[3],                                        \
                     (ulong)_t[4], (ulong)_t[5], (ulong)_t[6], (ulong)_t[7],                                        \
                     (ulong)_u[0], (ulong)_u[1], (ulong)_u[2], (ulong)_u[3],                                        \
                     (ulong)_u[4], (ulong)_u[5], (ulong)_u[6], (ulong)_u[7] ));                                     \
  } while(0)

#define WWV_TEST( x, x0,x1,x2,x3,x4,x5,x6,x7 ) do {                                                                      \
    ulong _t[8] WW_ATTR;                                                                                                 \
    ulong _u[8] WW_ATTR;                                                                                                 \
    wwv_st( _t, (x) );                                                                                                   \
    _u[0] = (x0); _u[1] = (x1); _u[2] = (x2); _u[3] = (x3); _u[4] = (x4); _u[5] = (x5); _u[6] = (x6); _u[7] = (x7);      \
    for( int _lane=0; _lane<8; _lane++ )                                                                                 \
      if( FD_UNLIKELY( _t[_lane]!=_u[_lane] ) )                                                                          \
        FD_LOG_ERR(( "FAIL: %s @ lane %i\n\t"                                                                            \
                     "  got 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL\n\t" \
                     "  exp 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL 0x%016lxUL",    \
                     #x, _lane,                                                                                          \
                     _t[0], _t[1], _t[2], _t[3], _t[4], _t[5], _t[6], _t[7],                                             \
                     _u[0], _u[1], _u[2], _u[3], _u[4], _u[5], _u[6], _u[7] ));                                          \
  } while(0)


/* Some utility macros for testing functions that need compile time
   values.
   EXPAND_n( F, j ) expands F n times with j, j+1, ..., j+n-1 as the
   argument (not a literal, but a compile time constant).

   COMPARE_n( C, p, fn1, fn2, j ) uses comparator function C to test the
   result of fn1(p, j) against fn2(p0, j), fn2(p1, j), ... fn3(p{n-1},
   j), where the counters for p, the prefix, are in hex.  C must take
   n+1 arguments. */

#define EXPAND_4( F, j) F(j)              F((j)+1)             F((j)+2)             F((j)+3)
#define EXPAND_16(F, j) EXPAND_4( F, (j)) EXPAND_4( F, (j)+ 4) EXPAND_4( F, (j)+ 8) EXPAND_4( F, (j)+12)
#define EXPAND_32(F, j) EXPAND_16(F, (j))                      EXPAND_16(F, (j)+16)
#define EXPAND_64(F, j) EXPAND_32(F, (j))                      EXPAND_32(F, (j)+32)

#define COMPARE8( C, p, fn1, fn2, j)  C( fn1(p, j), fn2( p##0, j ), fn2( p##1, j ), fn2( p##2, j ), fn2( p##3, j ), \
                                                    fn2( p##4, j ), fn2( p##5, j ), fn2( p##6, j ), fn2( p##7, j ) )

#define COMPARE16(C, p, fn1, fn2, j)  C( fn1(p, j), fn2( p##0, j ), fn2( p##1, j ), fn2( p##2, j ), fn2( p##3, j ), \
                                                    fn2( p##4, j ), fn2( p##5, j ), fn2( p##6, j ), fn2( p##7, j ), \
                                                    fn2( p##8, j ), fn2( p##9, j ), fn2( p##a, j ), fn2( p##b, j ), \
                                                    fn2( p##c, j ), fn2( p##d, j ), fn2( p##e, j ), fn2( p##f, j ) )


#endif /* HEADER_fd_src_util_simd_test_avx512_h */
