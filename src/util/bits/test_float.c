#include "../fd_util.h"
#include "fd_float.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define _(_f,_u,_s,_b,_m) do {                                         \
    ulong u = fd_fltbits       ( _f ); FD_TEST( u==_u                ); \
    ulong s = fd_fltbits_sign  ( u  ); FD_TEST( s==_s                ); \
    ulong b = fd_fltbits_bexp  ( u  ); FD_TEST( b==_b                ); \
    ulong m = fd_fltbits_mant  ( u  ); FD_TEST( m==_m                ); \
    long  e = fd_fltbits_unbias( b  ); FD_TEST( e==(((long)_b)-127L) ); \
    FD_TEST( fd_fltbits_bias( e )==b );                                 \
    FD_TEST( fd_fltbits_pack( s, b, m )==u );                           \
    FD_TEST( fd_float( u )==_f );                                       \
  } while(0)
  _(  0.f,         0x00000000UL, 0UL,   0UL,       0UL ); 
  _(  FLT_MIN,     0x00800000UL, 0UL,   1UL,       0UL ); 
  _(  FLT_EPSILON, 0x34000000UL, 0UL, 104UL,       0UL ); 
  _(  1.f,         0x3f800000UL, 0UL, 127UL,       0UL ); 
  _(  FLT_MAX,     0x7f7fffffUL, 0UL, 254UL, 8388607UL ); 
  _( -0.f,         0x80000000UL, 1UL,   0UL,       0UL ); 
  _( -FLT_MIN,     0x80800000UL, 1UL,   1UL,       0UL ); 
  _( -FLT_EPSILON, 0xb4000000UL, 1UL, 104UL,       0UL ); 
  _( -1.f,         0xbf800000UL, 1UL, 127UL,       0UL ); 
  _( -FLT_MAX,     0xff7fffffUL, 1UL, 254UL, 8388607UL ); 
# undef _

# if FD_HAS_DOUBLE
# define _(_f,_u,_s,_b,_m) do {                                          \
    ulong u = fd_dblbits       ( _f ); FD_TEST( u==_u                 ); \
    ulong s = fd_dblbits_sign  ( u  ); FD_TEST( s==_s                 ); \
    ulong b = fd_dblbits_bexp  ( u  ); FD_TEST( b==_b                 ); \
    ulong m = fd_dblbits_mant  ( u  ); FD_TEST( m==_m                 ); \
    long  e = fd_dblbits_unbias( b  ); FD_TEST( e==(((long)_b)-1023L) ); \
    FD_TEST( fd_dblbits_bias( e )==b );                                  \
    FD_TEST( fd_dblbits_pack( s, b, m )==u );                            \
    FD_TEST( fd_double( u )==_f );                                       \
  } while(0)
  _(  0.,          0x0000000000000000UL, 0UL,    0UL,                0UL );
  _(  DBL_MIN,     0x0010000000000000UL, 0UL,    1UL,                0UL );
  _(  DBL_EPSILON, 0x3cb0000000000000UL, 0UL,  971UL,                0UL );
  _(  1.,          0x3ff0000000000000UL, 0UL, 1023UL,                0UL );
  _(  DBL_MAX,     0x7fefffffffffffffUL, 0UL, 2046UL, 4503599627370495UL );
  _( -0.,          0x8000000000000000UL, 1UL,    0UL,                0UL );
  _( -DBL_MIN,     0x8010000000000000UL, 1UL,    1UL,                0UL );
  _( -DBL_EPSILON, 0xbcb0000000000000UL, 1UL,  971UL,                0UL );
  _( -1.,          0xbff0000000000000UL, 1UL, 1023UL,                0UL );
  _( -DBL_MAX,     0xffefffffffffffffUL, 1UL, 2046UL, 4503599627370495UL );
# undef _
# endif

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

