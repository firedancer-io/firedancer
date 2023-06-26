#include "../fd_util.h"
#include "fd_sqrt.h"

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  int ctr = 0;                                                                                                                      
  for( int i=0; i<50000000; i++ ) {
    if( !ctr ) { FD_LOG_NOTICE(( "Completed %i iterations", i )); ctr = 1000000; }
    ctr--;

#   define TEST(UINT,INT,w) do {                                              \
      int  n = ((int)fd_rng_uint( rng )) & (w-1);                             \
      UINT x = (UINT)(fd_rng_##UINT( rng ) >> n);                             \
      UINT y = fd_##UINT##_sqrt( x );                                         \
      UINT r = (UINT)(x - y*y);                                               \
      if( FD_UNLIKELY( (y>=(((UINT)1)<<(w/2))) | (r>(y<<1)) ) )               \
        FD_LOG_ERR(( "FAIL: iter %i op sqrt_uint" #w " x %lx y %lx r %lx)",   \
                     i, (ulong)x, (ulong)y, (ulong)r ));                      \
      INT u = (INT)x;                                                         \
      if( u>=((INT)0) ) {                                                     \
        INT v = fd_##INT##_sqrt( u );                                         \
        INT s = (INT)(u - v*v);                                               \
        if( FD_UNLIKELY( !((((INT)0)<=s) & (s<=(v<<1))) ) )                   \
          FD_LOG_ERR(( "FAIL: iter %i op sqrt_int" #w " u %li v %li s %li",   \
                       i, (long)u, (long)v, (long)s ));                       \
      }                                                                       \
      INT v = fd_##INT##_re_sqrt( u );                                        \
      INT s = (INT)(u - v*v);                                                 \
      if( !( FD_UNLIKELY( ((u>=((INT)0)) & (((INT)0)<=s) & (s<=(v<<1))) |     \
                          ((u< ((INT)0)) & (v==((INT)0))              ) ) ) ) \
        FD_LOG_ERR(( "FAIL: iter %i op sqrt_re_int" #w " u %li v %li s %li",  \
                     i, (long)u, (long)v, (long)s ));                         \
      v = fd_##INT##_sqrt_abs( u );                                           \
      s = (INT)fd_##UINT##_sqrt( fd_##INT##_abs( u ) );                       \
      if( FD_UNLIKELY( v!=s ) )                                               \
        FD_LOG_ERR(( "FAIL: iter %i op sqrt_abs_int" #w " u %li v %li s %li", \
                     i, (long)u, (long)v, (long)s ));                         \
    } while(0)

    TEST(uchar, schar, 8);
    TEST(ushort,short,16);
    TEST(uint,  int,  32);
    TEST(ulong, long, 64);

#   undef TEST
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

