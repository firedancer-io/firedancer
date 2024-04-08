#include "../fd_util.h"
#if FD_HAS_INT128

#include "fd_uwide.h"

static inline ulong split_hi( uint128 x ) { return (ulong)(x>>64); }
static inline ulong split_lo( uint128 x ) { return (ulong) x;      }

static inline uint128 join( ulong xh, ulong xl ) { return (((uint128)xh)<<64) | ((uint128)xl); }

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  int ctr = 0;
  for( int i=0; i<500000000; i++ ) {
    if( !ctr ) { FD_LOG_NOTICE(( "Completed %i iterations", i )); ctr = 10000000; }
    ctr--;

    /* Generate a random test vector */

    uint t = fd_rng_uint( rng );
    int nx =  1+(((int)t) & 127); t >>= 7; /* Bit width of the x, in [1,128] */
    int ny =  1+(((int)t) & 127); t >>= 7; /* Bit width of the y, in [1,128] */
    int nc =  1+(((int)t) &  63); t >>= 6; /* Bit width of the c, in [1,64] */
    int b0 =     ((int)t) &   1;  t >>= 1; /* Random bit, in [0,1] */
    int b1 =     ((int)t) &   1;  t >>= 1;
    int s  = b1+(((int)t) & 127); t >>= 8; /* Shift magnitude, in [0,128] (0 and 128 at half prob) */

    uint128 x = fd_rng_uint128( rng ) >> (128-nx); ulong xh = split_hi( x ); ulong xl = split_lo( x );
    uint128 y = fd_rng_uint128( rng ) >> (128-ny); ulong yh = split_hi( y ); ulong yl = split_lo( y );
    ulong   c = fd_rng_ulong  ( rng ) >> ( 64-nc);

    /* Add two random uint128 x and y with a random 64-bit carry in c */

    do {
      uint128 z0 = (uint128)c + x; ulong w0 = (ulong)(z0<x); z0 += y; w0 += (ulong)(z0<y);
      ulong zh,zl, w = fd_uwide_add( &zh,&zl, xh,xl, yh,yl, c );
      uint128 z = join( zh,zl );
      if( z!=z0 || w!=w0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_add\n\t"
                     "x %016lx %016lx y %016lx %016lx c %016lx z %016lx %016lx w %016lx z0 %016lx %016lx w0 %016lx",
                     i, xh,xl, yh,yl, c, zh,zl,w, split_hi(z0),split_lo(z0),w0 ));
    } while(0);

    /* Increment random uint128 x by random 64-bit c */

    do {
      uint128 z0 = x + c;
      ulong zh,zl; fd_uwide_inc( &zh,&zl, xh,xl, c );
      uint128 z = join( zh,zl );
      if( z!=z0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_inc\n\t"
                     "x %016lx %016lx c %016lx z %016lx %016lx z0 %016lx %016lx",
                     i, xh,xl, c, zh,zl, split_hi(z0),split_lo(z0) ));
    } while(0);

    /* Subtract two random uint128 x and y with a random 64-bit borrow c */

    do {
      ulong w0 = (ulong)(x<(uint128)c); uint128 z0 = x - (uint128)c; w0 += (ulong)(z0<y); z0 -= y;
      ulong zh,zl, w = fd_uwide_sub( &zh,&zl, xh,xl, yh,yl, c );
      uint128 z = join( zh,zl );
      if( z!=z0 || w!=w0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_sub\n\t"
                     "x %016lx %016lx y %016lx %016lx c %016lx z %016lx %016lx w %016lx z0 %016lx %016lx w0 %016lx",
                     i, xh,xl, yh,yl, c, zh,zl,w, split_hi(z0),split_lo(z0),w0 ));
    } while(0);

    /* Decrement random uint128 x by random 64-bit c */

    do {
      uint128 z0 = x - c;
      ulong zh,zl; fd_uwide_dec( &zh,&zl, xh,xl, c );
      uint128 z = join( zh,zl );
      if( z!=z0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_dec\n\t"
                     "x %016lx %016lx c %016lx z %016lx %016lx z0 %016lx %016lx",
                     i, xh,xl, c, zh,zl, split_hi(z0),split_lo(z0) ));
    } while(0);

    /* Multiply two random uint128 x and y */

    do {
      uint128 z0 = ((uint128)xl)*((uint128)yl);
      ulong zh,zl; fd_uwide_mul( &zh,&zl, xl,yl );
      uint128 z = join( zh,zl );
      if( z!=z0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_mul\n\t"
                     "x %016lx y %016lx z %016lx %016lx z0 %016lx %016lx",
                     i, xl, yl, zh,zl, split_hi(z0),split_lo(z0) ));
    } while(0);

    /* Divide a random uint128 x by a random non-zero d */

    do {
      ulong   d  = c | (1UL << (nc-1)); /* d is a random nc bit denom with leading 1 set */
      uint128 z0 = x / (uint128)d;
      ulong   zh,zl; fd_uwide_div( &zh,&zl, xh,xl, d );
      uint128 z = join( zh,zl );
      if( z!=z0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_div\n\t"
                     "x %016lx %016lx d %016lx z %016lx %016lx z0 %016lx %016lx",
                     i, xh,xl, d, zh,zl, split_hi(z0),split_lo(z0) ));
    } while(0);

    /* Divide a random uint128 x by a random non-zero d and get the remainder */

    do {
      ulong   d  = c | (1UL << (nc-1)); /* d is a random nc bit denom with leading 1 set */
      uint128 z0 =         x / (uint128)d;
      ulong   w0 = (ulong)(x % (uint128)d);
      ulong   zh,zl; ulong w = fd_uwide_divrem( &zh,&zl, xh,xl, d );
      uint128 z = join( zh,zl );
      if( z!=z0 || w!=w0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_divrem\n\t"
                     "x %016lx %016lx d %016lx z %016lx %016lx w %016lx z0 %016lx %016lx w0 %016lx",
                     i, xh,xl, d, zh,zl,w, split_hi(z0),split_lo(z0),w0 ));
    } while(0);

    /* Compute the log2 of a random uint128 x (sets leading bit of x)  */

    do {
      x |= ((uint128)1) << (nx-1); xh = split_hi( x ); xl = split_lo( x ); /* Set the leading bit */
      int n0 = nx-1;
      int n  = fd_uwide_find_msb( xh, xl );
      if( n!=n0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_find_msb\n\t"
                     "x %016lx %016lx n %i n0 %i",
                     i, xh,xl, n, n0 ));
    } while(0);

    /* Compute the log2 of a random uint128 x with default (clobbers leading bit of x) */

    do {
      if( nx==1 ) { /* If 1 bit wide, use a coin test to we sample the default */
        x = (uint128)b0; xh = split_hi( x ); xl = split_lo( x );
        int n0 = (x ? 0 : 1234);
        int n  = fd_uwide_find_msb_def( xh,xl, 1234 );
        if( n!=n0 )
          FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_find_msb_def\n\t"
                       "x %016lx %016lx n %i n0 %i",
                       i, xh,xl, n, n0 ));
      } else { /* If wider, def should not happen (assumes leading bit of x set) */
        int n  = fd_uwide_find_msb_def( xh, xl, 1234 );
        int n0 = nx-1;
        if( n!=n0 )
          FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_find_msb_def\n\t"
                       "x %016lx %016lx n %i n0 %i",
                       i, xh,xl, n, n0 ));
      }
    } while(0);

    /* Left shift a random uint128 y */

    do {
      uint128 z0           = s==128 ? (uint128)0 : y<<s;
      int     f0           = (s==0) ? 0 : (s==128) ? !!y : !!(y>>(128-s));
      ulong   zh,zl; int f = fd_uwide_sl( &zh,&zl, yh,yl, s );
      uint128 z            = join( zh,zl );
      if( z!=z0 || f!=f0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_sl\n\t"
                     "y %016lx %016lx s %i z %016lx %016lx f %i z0 %016lx %016lx f0 %i",
                     i, yh,yl, s, zh,zl, f, split_hi(z0),split_lo(z0), f0 ));
    } while(0);

    /* Right shift a random uint128 y */

    do {
      uint128 z0           = s==128 ? (uint128)0 : y>>s;
      int     f0           = (s==0) ? 0 : (s==128) ? !!y : !!(y<<(128-s));
      ulong   zh,zl; int f = fd_uwide_sr( &zh,&zl, yh,yl, s );
      uint128 z            = join( zh,zl );
      if( z!=z0 || f!=f0 )
        FD_LOG_ERR(( "FAIL: iter %i op fd_uwide_sr\n\t"
                     "y %016lx %016lx s %i z %016lx %016lx f %i z0 %016lx %016lx f0 %i",
                     i, yh,yl, s, zh,zl, f, split_hi(z0),split_lo(z0), f0 ));
    } while(0);
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

