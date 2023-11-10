#include "../fd_util.h"

#if FD_HAS_INT128

#include <math.h>

/* Create random bit patterns with lots of leading and/or trailing zeros
   or ones to really stress limits of implementations. */

static inline ulong
make_test_rand_ulong( ulong x,        /* Random 64-bit */
                       uint *_ctl ) { /* Least significant 8 bits random, uses them up */
  uint ctl = *_ctl;
  int s = (int)(ctl & 63U); ctl >>= 6; /* Shift, in [0,63] */
  int d = (int)(ctl &  1U); ctl >>= 1; /* Direction, in [0,1] */
  int i = (int)(ctl &  1U); ctl >>= 1; /* Invert, in [0,1] */
  *_ctl = ctl;
  x = d ? (x<<s) : (x>>s);
  return i ? (~x) : x;
}

static inline uint
make_test_rand_uint( uint x,        /* Random 32-bit */
                     uint *_ctl ) { /* Least significant 8 bits random, uses them up */
  uint ctl = *_ctl;
  int s = (int)(ctl & 31U); ctl >>= 6; /* Shift, in [0,31] */
  int d = (int)(ctl &  1U); ctl >>= 1; /* Direction, in [0,1] */
  int i = (int)(ctl &  1U); ctl >>= 1; /* Invert, in [0,1] */
  *_ctl = ctl;
  x = d ? (x<<s) : (x>>s);
  return i ? (~x) : x;
}

#if FD_HAS_INT128

static inline __uint128_t
make_test_rand_uint128( __uint128_t x,        /* Random 32-bit */
                        uint *      _ctl ) { /* Least significant 8 bits random, uses them up */
  uint ctl = *_ctl;
  int s = (int)(ctl & 31U); ctl >>= 6; /* Shift, in [0,31] */
  int d = (int)(ctl &  1U); ctl >>= 1; /* Direction, in [0,1] */
  int i = (int)(ctl &  1U); ctl >>= 1; /* Invert, in [0,1] */
  *_ctl = ctl;
  x = d ? (x<<s) : (x>>s);
  return i ? (~x) : x;
}

#endif

static inline ulong
fd_ulong_sat_add_ref( ulong x,
                        ulong y ) {
  uint128 ref = x;
  ref += y;

  if( ref > ULONG_MAX ) {
    return ULONG_MAX;
  } else {
    return (ulong) ref;
  }
}

static inline ulong
fd_ulong_sat_sub_ref( ulong x,
                        ulong y ) {
  uint128 ref = x;
  ref -= y;

  if( y > x ) {
    return 0;
  } else {
    return (ulong) ref;
  }
}

static inline ulong
fd_ulong_sat_mul_ref( ulong x,
                       ulong y ) {
  uint128 ref = x;
  ref *= y;

  if( x == 0 || y == 0 ) {
    return 0;
  }

  if( ( ref < x ) || ( ref < y ) || ( ( ref/x ) != y ) || (ref > ULONG_MAX)) {
    return ULONG_MAX;
  } else {
    return (ulong) ref;
  }
}

static inline uint
fd_uint_sat_add_ref( uint x,
                       uint y ) {
  uint128 ref = x;
  ref += y;

  if( ref > UINT_MAX ) {
    return UINT_MAX;
  } else {
    return (uint) ref;
  }
}

static inline uint
fd_uint_sat_sub_ref( uint x,
                       uint y ) {
  uint128 ref = x;
  ref -= y;

  if( y > x ) {
    return 0;
  } else {
    return (uint) ref;
  }
}

static inline uint
fd_uint_sat_mul_ref( uint x,
                      uint y ) {
  ulong ref = x;
  ref *= y;

  if( x == 0 || y == 0 ) {
    return 0;
  }

  if( ( ref < x ) || ( ref < y ) || ( ( ref / x ) != y )  || (ref > UINT_MAX) ) {
    return UINT_MAX;
  } else {
    return (uint) ref;
  }
}

#if FD_HAS_INT128

static inline __uint128_t
fd_uint128_sat_add_ref( __uint128_t x, __uint128_t y ) {
  __uint128_t res = x + y;
  return fd_uint128_if( res < x, UINT128_MAX, res );
}

static inline __uint128_t
fd_uint128_sat_mul_ref( __uint128_t x, __uint128_t y ) {
  __uint128_t res = x * y;
  uchar overflow = ( x != 0 ) && ( y != 0 ) && ( ( res < x ) || ( res < y ) || ( ( res / x ) != y ) );
  return fd_uint128_if( overflow, UINT128_MAX, res );
}

static inline __uint128_t
fd_uint128_sat_sub_ref( __uint128_t x, __uint128_t y ) {
  __uint128_t res = x - y;
  return fd_uint128_if( res > x, 0, res );
}

#endif

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

#   define TEST(op,x,y)                                   \
    do {                                              \
      ulong ref   = fd_ulong_sat_##op##_ref ( x, y ); \
      ulong res   = fd_ulong_sat_##op ( x, y );    \
      if( ref != res ) { \
        FD_LOG_ERR(( "FAIL: fd_ulong_sat_" #op " x %lu y %lu ref %lu res %lu", (ulong)x, (ulong)y, ref, res )); \
      } \
    } while(0)

    TEST(add,0,ULONG_MAX);
    TEST(add,ULONG_MAX,10);
    TEST(add,ULONG_MAX - 10,ULONG_MAX - 10);
    TEST(sub,0,ULONG_MAX);
    TEST(add,ULONG_MAX,10);
    TEST(sub,ULONG_MAX - 10,ULONG_MAX - 10);
    TEST(mul,0,ULONG_MAX);
    TEST(mul,ULONG_MAX,10);
    TEST(mul,ULONG_MAX - 10,ULONG_MAX - 10);

#   undef TEST

#   define TEST(op,x,y)                                \
    do {                                               \
      uint ref   = fd_uint_sat_##op##_ref ( x, y ); \
      uint res   = fd_uint_sat_## op      ( x, y ); \
      if( ref != res ) { \
        FD_LOG_ERR(( "FAIL: fd_uint_sat_" #op " x %u y %u ref %u res %u", x, y, ref, res )); \
      } \
    } while(0)

    TEST(add,0,UINT_MAX);
    TEST(add,UINT_MAX,10);
    TEST(add,UINT_MAX - 10,UINT_MAX - 10);
    TEST(sub,0,UINT_MAX);
    TEST(add,UINT_MAX,10);
    TEST(sub,UINT_MAX - 10,UINT_MAX - 10);
    TEST(mul,0,UINT_MAX);
    TEST(mul,UINT_MAX,10);
    TEST(mul,UINT_MAX - 10,UINT_MAX - 10);

#   undef TEST

#if FD_HAS_INT128

#   define TEST(op,x,y)                                \
    do {                                               \
      __uint128_t ref   = fd_uint128_sat_##op##_ref ( x, y ); \
      __uint128_t res   = fd_uint128_sat_## op      ( x, y ); \
      if( ref != res ) { \
        FD_LOG_ERR(( "FAIL: fd_uint128_sat_" #op " x %llu y %llu ref %llu res %llu", x, y, ref, res )); \
      } \
    } while(0)

    TEST(add,0,UINT128_MAX);
    TEST(add,UINT128_MAX,10);
    TEST(add,UINT128_MAX - 10,UINT128_MAX - 10);
    TEST(sub,0,UINT128_MAX);
    TEST(add,UINT128_MAX,10);
    TEST(sub,UINT128_MAX - 10,UINT128_MAX - 10);
    TEST(mul,0,UINT128_MAX);
    TEST(mul,UINT128_MAX,10);
    TEST(mul,UINT128_MAX - 10,UINT128_MAX - 10);

#   undef TEST

#endif

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  int ctr = 0;
  for( int i=0; i<100000000; i++ ) {
    if( !ctr ) { FD_LOG_NOTICE(( "Completed %i iterations", i )); ctr = 10000000; }
    ctr--;

#   define TEST(op)                                  \
    do {                                             \
      uint  t =  fd_rng_uint ( rng );                             \
      ulong x  = make_test_rand_ulong( fd_rng_ulong( rng ), &t ); \
      ulong y  = make_test_rand_ulong( fd_rng_ulong( rng ), &t ); \
      ulong ref   = fd_ulong_sat_##op##_ref ( x, y ); \
      ulong res   = fd_ulong_sat_##op       ( x, y ); \
      if( ref != res ) { \
        FD_LOG_ERR(( "FAIL: %i fd_ulong_sat_" #op " x %lu y %lu ref %lu res %lu", i, (ulong)x, (ulong)y, ref, res )); \
      } \
    } while(0)

    TEST(add);
    TEST(sub);
    TEST(mul);

#   undef TEST

#   define TEST(op)                                  \
    do {                                             \
      uint t =  fd_rng_uint ( rng );                \
      uint x  = make_test_rand_uint( fd_rng_uint( rng ), &t ); \
      uint y  = make_test_rand_uint( fd_rng_uint( rng ), &t ); \
      uint ref   = fd_uint_sat_##op##_ref ( x, y ); \
      uint res   = fd_uint_sat_##op       ( x, y ); \
      if( ref != res ) { \
        FD_LOG_ERR(( "FAIL: %i fd_uint_sat_" #op " x %u y %u ref %u res %u", i, x, y, ref, res )); \
      } \
    } while(0)

    TEST(add);
    TEST(sub);
    TEST(mul);

#   undef TEST

#if FD_HAS_INT128

#   define TEST(op)                                  \
    do {                                             \
      uint    t =  fd_rng_uint ( rng );                \
      __uint128_t x  = make_test_rand_uint128( fd_rng_uint128( rng ), &t ); \
      __uint128_t y  = make_test_rand_uint128( fd_rng_uint128( rng ), &t ); \
      __uint128_t ref   = fd_uint128_sat_##op##_ref ( x, y ); \
      __uint128_t res   = fd_uint128_sat_##op       ( x, y ); \
      if( ref != res ) { \
        FD_LOG_ERR(( "FAIL: %i fd_uint128_sat_" #op " x %llu y %llu ref %llu res %llu", i, x, y, ref, res )); \
      } \
    } while(0)

    TEST(add);
    TEST(sub);
    TEST(mul);

#   undef TEST

#endif

  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_INT128 capability" ));
  fd_halt();
  return 0;
}

#endif
