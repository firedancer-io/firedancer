#include "fd_util.h"

#if FD_HAS_HOSTED
#include <stddef.h>
#include <sys/types.h>
#endif
#include <stdint.h>

FD_STATIC_ASSERT( !(FD_HAS_THREADS && !FD_HAS_ATOMIC), devenv );
FD_STATIC_ASSERT( !(FD_HAS_THREADS && !FD_HAS_HOSTED), devenv );

FD_STATIC_ASSERT( !(FD_HAS_SSE    && !FD_HAS_X86), devenv );
FD_STATIC_ASSERT( !(FD_HAS_AVX    && !FD_HAS_SSE), devenv );
FD_STATIC_ASSERT( !(FD_HAS_AVX512 && !FD_HAS_AVX), devenv );
FD_STATIC_ASSERT( !(FD_HAS_SHANI  && !FD_HAS_AVX), devenv );
FD_STATIC_ASSERT( !(FD_HAS_GFNI   && !FD_HAS_AVX), devenv );

/* Test size_t <> ulong, uintptr_t <> ulong, intptr_t <> long (which
   then further imply sizeof and alignof return a ulong and that
   pointers can be interchangably treated as a ulong or long). */

FD_STATIC_ASSERT( __builtin_types_compatible_p( ulong, size_t    ), devenv );
FD_STATIC_ASSERT( __builtin_types_compatible_p( ulong, uintptr_t ), devenv );
FD_STATIC_ASSERT( __builtin_types_compatible_p( long,  intptr_t  ), devenv );
#if FD_HAS_HOSTED
FD_STATIC_ASSERT( __builtin_types_compatible_p( long,  ptrdiff_t ), devenv );
FD_STATIC_ASSERT( __builtin_types_compatible_p( long,  ssize_t   ), devenv );
#endif

/* 8-bit chars, 64-bit pointers, char/short/int/long are 8/16/32/64-bit
   respectively, float/double are 32/64-bit wide */

FD_STATIC_ASSERT( (int)CHAR_BIT ==8,   devenv );
FD_STATIC_ASSERT( sizeof(void *)==8UL, devenv );
FD_STATIC_ASSERT( sizeof(char  )==1UL, devenv );
FD_STATIC_ASSERT( sizeof(short )==2UL, devenv );
FD_STATIC_ASSERT( sizeof(int   )==4UL, devenv );
FD_STATIC_ASSERT( sizeof(long  )==8UL, devenv );
FD_STATIC_ASSERT( sizeof(uchar )==1UL, devenv );
FD_STATIC_ASSERT( sizeof(ushort)==2UL, devenv );
FD_STATIC_ASSERT( sizeof(uint  )==4UL, devenv );
FD_STATIC_ASSERT( sizeof(ulong )==8UL, devenv );
FD_STATIC_ASSERT( sizeof(float )==4UL, devenv );
#if FD_HAS_DOUBLE
FD_STATIC_ASSERT( sizeof(double)==8UL, devenv );
#endif

/* Test twos complement representation (the -1 is to work around a
   language flaw with large negative integer constants). */

/* Unqualified char types should be avoided outside of cstr
   representations. */

//FD_STATIC_ASSERT( (int) CHAR_MIN==                -127 -1,  devenv );
//FD_STATIC_ASSERT( (int) CHAR_MAX==                 127,     devenv );

FD_STATIC_ASSERT( (int) SCHAR_MIN==                -127 -1,  devenv );
FD_STATIC_ASSERT( (int) SCHAR_MAX==                 127,     devenv );
FD_STATIC_ASSERT( (int) UCHAR_MAX==                 255,     devenv );
FD_STATIC_ASSERT( (int) SHORT_MIN==              -32767 -1,  devenv );
FD_STATIC_ASSERT( (int) SHORT_MAX==               32767,     devenv );
FD_STATIC_ASSERT( (int)USHORT_MAX==               65535,     devenv );
FD_STATIC_ASSERT(         INT_MIN==         -2147483647 -1,  devenv );
FD_STATIC_ASSERT(         INT_MAX==          2147483647,     devenv );
FD_STATIC_ASSERT(        UINT_MAX==          4294967295U,    devenv );
FD_STATIC_ASSERT(        LONG_MIN==-9223372036854775807L-1L, devenv );
FD_STATIC_ASSERT(        LONG_MAX== 9223372036854775807L,    devenv );
FD_STATIC_ASSERT(       ULONG_MAX==18446744073709551615UL,   devenv );

/* FIXME: no way to specify int128/uint128 compile time constants
   cleanly currently.  (Could make macros that stitch together two
   64-bit words though.) */

/* Test signed right shift is arithemetic (i.e. sign extending) and
   unsigned right shift is logical (i.e. zero padding).  (Zero padding
   signed right shift is also allowed by the language.) */

FD_STATIC_ASSERT( (((schar)-2)>>1)==((schar)-1), devenv );
FD_STATIC_ASSERT( (((short)-2)>>1)==((short)-1), devenv );
FD_STATIC_ASSERT( (((int  )-2)>>1)==((int  )-1), devenv );
FD_STATIC_ASSERT( (((long )-2)>>1)==((long )-1), devenv );

FD_STATIC_ASSERT( (((uchar ) UCHAR_MAX)>>1)==((uchar )((1UL<< 7)-1UL)), devenv );
FD_STATIC_ASSERT( (((ushort)USHORT_MAX)>>1)==((ushort)((1UL<<15)-1UL)), devenv );
FD_STATIC_ASSERT( (((uint  )  UINT_MAX)>>1)==((uint  )((1UL<<31)-1UL)), devenv );
FD_STATIC_ASSERT( (((ulong ) ULONG_MAX)>>1)==((ulong )((1UL<<63)-1UL)), devenv );

/* Test signed integer division is round toward zero (round toward
   negative infinity rounding is also allowed by the language).  Note
   that round toward zero signed integer division implies that signed
   integer modulus can be either positive or negative (floor rounding
   implies signed integer modulus can only be positive). */

FD_STATIC_ASSERT( !(((schar)+1)/((schar)+2)), devenv );
FD_STATIC_ASSERT( !(((schar)-1)/((schar)+2)), devenv );
FD_STATIC_ASSERT( !(((schar)+1)/((schar)-2)), devenv );
FD_STATIC_ASSERT( !(((schar)-1)/((schar)-2)), devenv );

FD_STATIC_ASSERT( !(((short)+1)/((short)+2)), devenv );
FD_STATIC_ASSERT( !(((short)-1)/((short)+2)), devenv );
FD_STATIC_ASSERT( !(((short)+1)/((short)-2)), devenv );
FD_STATIC_ASSERT( !(((short)-1)/((short)-2)), devenv );

FD_STATIC_ASSERT( !(((int  )+1)/((int  )+2)), devenv );
FD_STATIC_ASSERT( !(((int  )-1)/((int  )+2)), devenv );
FD_STATIC_ASSERT( !(((int  )+1)/((int  )-2)), devenv );
FD_STATIC_ASSERT( !(((int  )-1)/((int  )-2)), devenv );

FD_STATIC_ASSERT( !(((long )+1)/((long )+2)), devenv );
FD_STATIC_ASSERT( !(((long )-1)/((long )+2)), devenv );
FD_STATIC_ASSERT( !(((long )+1)/((long )-2)), devenv );
FD_STATIC_ASSERT( !(((long )-1)/((long )-2)), devenv );

/* Test binary includes by including this source file. */

FD_IMPORT_BINARY( quine_binary, __FILE__ );
FD_IMPORT_CSTR  ( quine_cstr,   __FILE__ );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Test signed integer overflow is wrapping.  Needs to be at run time
     because a strict compile will complain about the intentional
     overflow if done in a static assert.  Because of this and the
     compiler's willingness to exploit the U.B. behavior of signed
     integer overflow, even if the underlying platform is wrapping,
     signed integer overflow behavior this shouldn't be relied upon in
     code. */

  do {
    schar i = SCHAR_MIN; schar j = SCHAR_MAX;
    FD_TEST( (schar)(FD_VOLATILE(i)-(schar)1)==FD_VOLATILE(j) && (schar)(FD_VOLATILE(j)+(schar)1)==FD_VOLATILE(i) );
  } while(0);
  do {
    short i = SHORT_MIN; short j = SHORT_MAX;
    FD_TEST( (short)(FD_VOLATILE(i)-(short)1)==FD_VOLATILE(j) && (short)(FD_VOLATILE(j)+(short)1)==FD_VOLATILE(i) );
  } while(0);
  do {
    int   i =   INT_MIN; int   j =   INT_MAX;
    FD_TEST( (int  )(FD_VOLATILE(i)-(int  )1)==FD_VOLATILE(j) && (int  )(FD_VOLATILE(j)+(int  )1)==FD_VOLATILE(i) );
  } while(0);
  do {
    long  i =  LONG_MIN; long  j =  LONG_MAX;
    FD_TEST( (long )(FD_VOLATILE(i)-(long )1)==FD_VOLATILE(j) && (long )(FD_VOLATILE(j)+(long )1)==FD_VOLATILE(i) );
  } while(0);
# if FD_HAS_INT128
  do {
    int128 i = INT128_MIN; int128 j = INT128_MAX;
    FD_TEST( (int128)(FD_VOLATILE(i)-(int128)1)==FD_VOLATILE(j) && (int128)(FD_VOLATILE(j)+(int128)1)==FD_VOLATILE(i) );
  } while(0);
# endif

  /* Test signed shifts */

  for( ulong iter=0UL; iter<1048576UL; iter++ ) {
    schar x = (schar)fd_rng_uchar( rng );
    int   n = (int)(fd_rng_uint( rng ) & 7U);
    uchar m = (uchar)-(((uchar)x)>>7);
    FD_TEST( (schar)(x<<n)==(schar)(((uchar)x)<<n) );
    FD_TEST( (schar)(x>>n)==(schar)(((((uchar)x)^m)>>n)^m) );
  }

  for( ulong iter=0UL; iter<1048576UL; iter++ ) {
    short  x = (short)fd_rng_ushort( rng );
    int    n = (int)(fd_rng_uint( rng ) & 15U);
    ushort m = (ushort)-(((ushort)x)>>15);
    FD_TEST( (short)(x<<n)==(short)(((ushort)x)<<n) );
    FD_TEST( (short)(x>>n)==(short)(((((ushort)x)^m)>>n)^m) );
  }

  for( ulong iter=0UL; iter<1048576UL; iter++ ) {
    int  x = (int)fd_rng_uint( rng );
    int  n = (int)(fd_rng_uint( rng ) & 31U);
    uint m = -(((uint)x)>>31);
    FD_TEST( (x<<n)==(int)(((uint)x)<<n)         );
    FD_TEST( (x>>n)==(int)(((((uint)x)^m)>>n)^m) );
  }

  for( ulong iter=0UL; iter<1048576UL; iter++ ) {
    long  x = (long)fd_rng_ulong( rng );
    int   n = (int)(fd_rng_uint( rng ) & 63U);
    ulong m = -(((ulong)x)>>63);
    FD_TEST( (x<<n)==(long)(((ulong)x)<<n)         );
    FD_TEST( (x>>n)==(long)(((((ulong)x)^m)>>n)^m) );
  }

# if FD_HAS_INT128
  for( ulong iter=0UL; iter<1048576UL; iter++ ) {
    int128  x = (int128)fd_rng_uint128( rng );
    int     n = (int)(fd_rng_uint( rng ) & 127U);
    uint128 m = -(((uint128)x)>>127);
    FD_TEST( (x<<n)==(int128)(((uint128)x)<<n)         );
    FD_TEST( (x>>n)==(int128)(((((uint128)x)^m)>>n)^m) );
  }
# endif

  /* Test floating point handling is as expected.  This also has to be
     done run time due to unfortunate language handling around fenv that
     prevents the compiler from verifying these via static assert. */

  FD_TEST( FLT_MIN    ==1.1754943508222875e-38f );
  FD_TEST( FLT_MAX    ==3.4028234663852886e+38f );
  FD_TEST( FLT_EPSILON==1.1920928955078125e-07f );
  FD_TEST( (1.f+      FLT_EPSILON)> 1.f ); /* RNE to 1+eps */
  FD_TEST( (1.f+0.50f*FLT_EPSILON)==1.f ); /* RNE to 1 */
  FD_TEST( (1.f-0.25f*FLT_EPSILON)==1.f ); /* RNE to 1 */
  FD_TEST( (1.f-0.50f*FLT_EPSILON)< 1.f ); /* RNE to 1-0.5eps */

# if FD_HAS_DOUBLE
  FD_TEST( DBL_MIN    ==2.2250738585072014e-308 );
  FD_TEST( DBL_MAX    ==1.7976931348623157e+308 );
  FD_TEST( DBL_EPSILON==2.2204460492503131e-16  );
  FD_TEST( (1.+     DBL_EPSILON)> 1. ); /* RNE to 1+eps */
  FD_TEST( (1.+0.50*DBL_EPSILON)==1. ); /* RNE to 1 */
  FD_TEST( (1.-0.25*DBL_EPSILON)==1. ); /* RNE to 1 */
  FD_TEST( (1.-0.50*DBL_EPSILON)< 1. ); /* RNE to 1-0.5eps */
# endif

  /* Test little endian */

  union {
    uchar  uc[8];
    ushort us;
    uint   ui;
    ulong  ul;
  } _;
  _.uc[0] = (uchar)0; _.uc[1] = (uchar)1; _.uc[2] = (uchar)2; _.uc[3] = (uchar)3;
  _.uc[4] = (uchar)4; _.uc[5] = (uchar)5; _.uc[6] = (uchar)6; _.uc[7] = (uchar)7;
  FD_TEST( _.us==(ushort)            0x0100   );
  FD_TEST( _.ui==                0x03020100U  );
  FD_TEST( _.ul==        0x0706050403020100UL );

  /* Test unaligned access */

  do {
    uchar buf[256]; for( ulong off=0UL; off<256UL; off++ ) buf[off] = (uchar)off;

    ulong magic = 0x0706050403020100UL;
    for( ulong off=0UL; off<(256UL-8UL); off++ ) {
      ulong tmp = magic;
#     define _(T) do {                                          \
        T * ptr = (T *)(buf+off);                               \
        FD_COMPILER_FORGET( ptr ); FD_TEST( ptr[0]==(T)magic ); \
        FD_COMPILER_FORGET( ptr ); ptr[0] = (T)(++tmp);         \
        FD_COMPILER_FORGET( ptr ); FD_TEST( ptr[0]==(T)tmp );   \
        FD_COMPILER_FORGET( ptr ); ptr[0] = (T)magic;           \
        FD_COMPILER_FORGET( ptr ); FD_TEST( ptr[0]==(T)magic ); \
      } while(0)
      _(uchar ); _(schar); _(char);
      _(ushort); _(short);
      _(uint  ); _(int  );
      _(ulong ); _(long );
#     undef _

#     define _(T) do {                                 \
        T * _f = (T *)(buf+off);                       \
        T    f = (T)off;                               \
        FD_COMPILER_FORGET( _f ); _f[0] = f;           \
        FD_COMPILER_FORGET( _f ); FD_TEST( _f[0]==f ); \
        ulong * ptr = (ulong *)(buf+off);              \
        FD_COMPILER_FORGET( ptr ); ptr[0] = magic;     \
      } while(0);
      _(float );
#     if FD_HAS_DOUBLE
      _(double);
#     endif
#     undef _

      magic = ((off+8UL)<<56) | (magic>>8);
    }

#   if FD_HAS_INT128
    uint128 m128 = (((uint128)0x0f0e0d0c0b0a0908UL) << 64) | (uint128)0x0706050403020100UL;
    for( ulong off=0UL; off<(256UL-16UL); off++ ) {
      uint128 tmp = m128;
#     define _(T) do {                                          \
        T * ptr = (T *)(buf+off);                               \
        FD_COMPILER_FORGET( ptr ); FD_TEST( ptr[0]==(T)m128  ); \
        FD_COMPILER_FORGET( ptr ); ptr[0] = (T)(++tmp);         \
        FD_COMPILER_FORGET( ptr ); FD_TEST( ptr[0]==(T)tmp );   \
        FD_COMPILER_FORGET( ptr ); ptr[0] = (T)m128;            \
        FD_COMPILER_FORGET( ptr ); FD_TEST( ptr[0]==(T)m128 );  \
      } while(0)
      _(uint128); _(int128);
#     undef _
      m128 = (((uint128)(off+16UL))<<120) | (m128>>8);
    }
#   endif

  } while(0);

  do { /* FIXME: PROBABLY SHOULD MORE AGGRESIVELY TEST SOME OF THIS */
    int c = 1;
    FD_COMPILER_FORGET(        c ); FD_TEST( c==1 );
    FD_COMPILER_UNPREDICTABLE( c ); FD_TEST( c==1 );

    int ctr[6]; ctr[0] = 0; ctr[1] = 0; ctr[2] = 0; ctr[3] = 0; ctr[4] = 0; ctr[5] = 0;

    FD_TEST( fd_type_pun      ( ctr )==(void       *)ctr );
    FD_TEST( fd_type_pun_const( ctr )==(void const *)ctr );

    struct __attribute__((packed)) { char c; int i; } p; fd_memset( &p, 0, sizeof(p) );
    int * pi  = FD_ADDRESS_OF_PACKED_MEMBER( p.i ); FD_TEST( (ulong)pi==(((ulong)&p)+1UL) );
    ((void)p.c);

    FD_COMPILER_MFENCE();

    FD_SPIN_PAUSE();
    FD_YIELD();

    FD_TEST( FD_VOLATILE_CONST( ctr[0] )==0 );
    FD_VOLATILE( ctr[0] ) = 1; FD_TEST( FD_VOLATILE_CONST( ctr[0] )==1 );
#   if FD_HAS_ATOMIC
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_FETCH_AND_ADD( ctr, 5 )== 3 ); FD_TEST( ctr[0]== 8 );
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_FETCH_AND_SUB( ctr, 5 )== 3 ); FD_TEST( ctr[0]==-2 );
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_FETCH_AND_AND( ctr, 5 )== 3 ); FD_TEST( ctr[0]== 1 );
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_FETCH_AND_OR(  ctr, 5 )== 3 ); FD_TEST( ctr[0]== 7 );
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_FETCH_AND_XOR( ctr, 5 )== 3 ); FD_TEST( ctr[0]== 6 );

    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_ADD_AND_FETCH( ctr, 5 )== 8 ); FD_TEST( ctr[0]== 8 );
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_SUB_AND_FETCH( ctr, 5 )==-2 ); FD_TEST( ctr[0]==-2 );
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_AND_AND_FETCH( ctr, 5 )== 1 ); FD_TEST( ctr[0]== 1 );
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_OR_AND_FETCH(  ctr, 5 )== 7 ); FD_TEST( ctr[0]== 7 );
    FD_VOLATILE( ctr[0] ) = 3; FD_TEST( FD_ATOMIC_XOR_AND_FETCH( ctr, 5 )== 6 ); FD_TEST( ctr[0]== 6 );

    FD_VOLATILE( ctr[0] ) = 1;
    FD_TEST( FD_ATOMIC_CAS( ctr, 0, 2 )==1 && FD_VOLATILE_CONST( ctr[0] )==1 );
    FD_TEST( FD_ATOMIC_CAS( ctr, 1, 3 )==1 && FD_VOLATILE_CONST( ctr[0] )==3 );

    FD_TEST( FD_ATOMIC_XCHG( ctr, 4 )==3 && FD_VOLATILE_CONST( ctr[0] )==4 );
#   endif

    FD_VOLATILE( ctr[0] ) = 0; FD_TEST( FD_VOLATILE_CONST( ctr[0] )==0 );

    for( int i=0; i<10; i++ ) {
      FD_ONCE_BEGIN {
        ctr[0]++;
        FD_ONCE_BEGIN        { ctr[1]++; } FD_ONCE_END;
        FD_THREAD_ONCE_BEGIN { ctr[2]++; } FD_THREAD_ONCE_END;
      } FD_ONCE_END;

      FD_THREAD_ONCE_BEGIN {
        ctr[3]++;
        FD_ONCE_BEGIN        { ctr[4]++; } FD_ONCE_END;
        FD_THREAD_ONCE_BEGIN { ctr[5]++; } FD_THREAD_ONCE_END;
      } FD_THREAD_ONCE_END;
    }

    FD_TEST( ctr[0]==1 && ctr[1]==1 && ctr[2]==1 && ctr[3]==1 && ctr[4]==1 && ctr[5]==1 );
  } while(0);

  do {
    char const * buf = "The quick brown fox jumps over the lazy dog.";
    ulong        sz  = strlen(buf)+1UL;
    FD_TEST( fd_hash( 0UL, buf, sz )==0xf3f632730b075fa5UL );
    FD_TEST( fd_hash( 1UL, buf, sz )==0x9d33e5e77b3544ceUL );
  } while(0);

  FD_TEST( fd_memeq( NULL, NULL, 0UL ) );

  do {
    uchar src[2048]; memset( src, 0, 2048UL );
    uchar dst[2048]; memset( dst, 0, 2048UL );
    for( ulong iter=0UL; iter<1000000UL; iter++ )  {

      ulong _s0 = (ulong)fd_rng_uint_roll( rng, 2049UL );
      ulong _s1 = (ulong)fd_rng_uint_roll( rng, 2049UL );
      ulong s0  = fd_ulong_min( _s0, _s1 );
      ulong s1  = fd_ulong_max( _s0, _s1 );
      ulong sz  = s1-s0;

      ulong d0 = (ulong)fd_rng_uint_roll( rng, (uint)(2049UL-sz) );
      ulong d1 = d0 + sz;

      ulong hs0 = fd_hash( 0UL, src, s0 ); ulong hs1 = fd_hash( 0UL, src+s1, 2048UL-s1 );
      ulong hd0 = fd_hash( 0UL, dst, d0 ); ulong hd1 = fd_hash( 0UL, dst+d1, 2048UL-d1 );

      int c = (int)fd_rng_uchar( rng );
      memset( src+s0, c, sz );
      FD_TEST( fd_memset( dst+d0, c, sz )==(dst+d0) );
      FD_TEST( !memcmp ( dst+d0, src+s0, sz ) );
      FD_TEST( fd_memeq( dst+d0, src+s0, sz ) );
      FD_TEST( fd_hash( 0UL, src, s0 )==hs0 ); FD_TEST( fd_hash( 0UL, src+s1, 2048UL-s1 )==hs1 );
      FD_TEST( fd_hash( 0UL, dst, d0 )==hd0 ); FD_TEST( fd_hash( 0UL, dst+d1, 2048UL-d1 )==hd1 );

      for( ulong b=s0; b<s1; b++ ) src[b] = fd_rng_uchar( rng );

      FD_TEST( fd_memcpy( dst+d0, src+s0, sz )==(dst+d0) );
      FD_TEST( !memcmp ( dst+d0, src+s0, sz ) );
      FD_TEST( fd_memeq( dst+d0, src+s0, sz ) );
      FD_TEST( fd_hash( 0UL, src, s0 )==hs0 ); FD_TEST( fd_hash( 0UL, src+s1, 2048UL-s1 )==hs1 );
      FD_TEST( fd_hash( 0UL, dst, d0 )==hd0 ); FD_TEST( fd_hash( 0UL, dst+d1, 2048UL-d1 )==hd1 );

      for( ulong b=s0; b<s1; b++ ) src[b] = fd_rng_uchar( rng );

      ulong seed = fd_rng_ulong( rng );
      ulong hash = fd_hash( seed, src+s0, sz );
      FD_TEST( fd_hash_memcpy( seed, dst+d0, src+s0, sz )==hash );
      FD_TEST( !memcmp ( dst+d0, src+s0, sz ) );
      FD_TEST( fd_memeq( dst+d0, src+s0, sz ) );

      /* Flip some bits */

      if( sz>0UL ) {
        ulong dflip = d0 + (ulong)fd_rng_uint_roll( rng, (uint)sz );
        int c2 = (int)fd_rng_uchar( rng );
        dst[ dflip ] = (uchar)(dst[ dflip ] ^ (uchar)c2);
        FD_TEST( fd_memeq( dst+d0, src+s0, sz )==(!c2) );
      }
    }
  } while(0);

  /* Test fd_tickcount (FIXME: TEST MORE THAN MONOTONICITY?) */

  long tic = fd_tickcount();
  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    long toc = fd_tickcount();
    FD_TEST( (toc - tic) > 0L );
    tic = toc;
  }

  /* Test FD_IMPORT */

  FD_TEST( (strlen( quine_cstr )+1UL)==quine_cstr_sz              );
  FD_TEST( !strncmp( quine_cstr, "#include \"fd_util.h\"", 20UL ) );

  FD_TEST( (quine_binary_sz+1UL     )==quine_cstr_sz             );
  FD_TEST( fd_ulong_is_aligned( (ulong)quine_binary, 128UL )     );
  FD_TEST( !memcmp ( quine_binary, quine_cstr, quine_binary_sz ) );
  FD_TEST( fd_memeq( quine_binary, quine_cstr, quine_binary_sz ) );

  /* FIXME: ADD HASH QUALITY CHECKER HERE */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
