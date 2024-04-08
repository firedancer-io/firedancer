#ifndef HEADER_fd_src_util_math_fd_fxp_h
#define HEADER_fd_src_util_math_fd_fxp_h

/* Large set of primitives for portable fixed point arithmetic with
   correct rounding and/or overflow detection.  Strongly targeted at
   platforms with reasonable performance C-style 64b unsigned integer
   arithmetic under the hood.  Likewise, strongly targets unsigned fixed
   point representations that fit within 64b and have 30 fractional
   bits.  Adapted from the Pyth Oracle. */

#include "fd_sqrt.h"

#if !FD_HAS_INT128
#include "../bits/fd_uwide.h"
#endif

FD_PROTOTYPES_BEGIN

/* Private API ********************************************************/

#if FD_HAS_INT128 /* See the uwide-based implementations for details how these work */

FD_FN_CONST static inline uint128 fd_fxp_private_expand( ulong x ) { return ((uint128)x)<<30; }
static inline ulong fd_fxp_private_contract( uint128 x, ulong * _c ) { x >>= 30; *_c = (ulong)(x>>64); return (ulong)x; }

/* Return the low 64-bits of a uint128 and store the high 64-bits at *_h */

static inline ulong fd_fxp_private_split( uint128 x, ulong * _h ) { *_h = (ulong)(x>>64); return (ulong)x; }

#else /* uwide based implementations from pyth */

/* Helper used by the below that computes
     2^64 yh + yl = 2^30 x
   (i.e. widen a 64b number to 128b and shift it left by 30.)  Exact.
   yh<2^30. */

static inline void fd_fxp_private_expand( ulong * _yh, ulong * _yl, ulong x ) { *_yh = x>>34; *_yl = x<<30; }

/* Helper used by the below that computes
     2^64 c + y = floor( (2^64 xh + xl) / 2^30 )
   (i.e. shift a 128b uint right by 30).  Exact.  c<2^34. */

static inline ulong fd_fxp_private_contract( ulong xh, ulong xl, ulong * _c ) { *_c = xh>>30; return (xh<<34) | (xl>>30); }

#endif

/* FIXED POINT ADDITION ***********************************************/

/* Compute:
     (c 2^64 + z)/2^30 = x/2^30 + y/2^30
   Exact.  c will be in [0,1].  Fast variant assumes that the user knows
   c is zero or is not needed. */

static inline ulong fd_fxp_add( ulong x, ulong y, ulong * _c ) { *_c = (ulong)(x>(~y)); return x + y; }
FD_FN_CONST static inline ulong fd_fxp_add_fast( ulong x, ulong y ) { return x + y; }

/* FIXED POINT SUBTRACTION ********************************************/

/* Compute:
     z/2^30 = (2^64 b + x)/2^30 - y/2^30
   Exact.  b will be in [0,1].  Fast variant assumes that the user knows
   b is zero (i.e. x>=y) or is not needed. */

static inline ulong fd_fxp_sub( ulong x, ulong y, ulong * _b ) { *_b = (ulong)(x<y); return x - y; }
FD_FN_CONST static inline ulong fd_fxp_sub_fast( ulong x, ulong y ) { return x - y; }

/* FIXED POINT MULTIPLICATION *****************************************/

/* Compute:
     (2^64 c + z)/2^30 ~ (x/2^30)(y/2^30)
   under various rounding modes.  c<2^34. */

#if FD_HAS_INT128 /* See the uwide-based implementations for details how these work */

static inline ulong
fd_fxp_mul_rtz( ulong   x,
                ulong   y,
                ulong * _c ) {
  return fd_fxp_private_contract( ((uint128)x)*((uint128)y), _c );
}

static inline ulong
fd_fxp_mul_raz( ulong   x,
                ulong   y,
                ulong * _c ) {
  return fd_fxp_private_contract( ((uint128)x)*((uint128)y)+(uint128)((1UL<<30)-1UL), _c );
}

static inline ulong
fd_fxp_mul_rnz( ulong   x,
                ulong   y,
                ulong * _c ) {
  return fd_fxp_private_contract( ((uint128)x)*((uint128)y)+(uint128)((1UL<<29)-1UL), _c );
}

static inline ulong
fd_fxp_mul_rna( ulong   x,
                ulong   y,
                ulong * _c ) {
  return fd_fxp_private_contract( ((uint128)x)*((uint128)y)+(uint128)(1UL<<29), _c );
}

static inline ulong
fd_fxp_mul_rne( ulong   x,
                ulong   y,
                ulong * _c ) {
  uint128 z = ((uint128)x)*((uint128)y);
  return fd_fxp_private_contract( z + (uint128)(((1UL<<29)-1UL) + (((ulong)(z>>30)) & 1UL)), _c );
}

static inline ulong
fd_fxp_mul_rno( ulong   x,
                ulong   y,
                ulong * _c ) {
  uint128 z = ((uint128)x)*((uint128)y);
  return fd_fxp_private_contract( z + (uint128)((1UL<<29) - (((ulong)(z>>30)) & 1UL)), _c );
}

#else /* uwide based implementations from pyth */

/* rtz -> Round toward zero (aka truncate rounding)
   Fast variant assumes x*y < 2^64 (i.e. exact result < ~2^4).
   Based on:
        z/2^30 ~ (x/2^30)(y/2^30)
     -> z      ~ x y / 2^30
   With RTZ rounding: 
        z      = floor( x y / 2^30 )
               = (x*y) >> 30
   As x*y might overflow 64 bits, we need to do a 64b*64b->128b
   multiplication (fd_uwide_mul) and a 128b shift right by 30
   (fd_fxp_private_contract).
   
   Fastest style of rounding.  Rounding error in [0,1) ulp.
   (ulp==2^-30). */

static inline ulong
fd_fxp_mul_rtz( ulong   x,
                ulong   y,
                ulong * _c ) {
  ulong zh,zl; fd_uwide_mul( &zh,&zl, x, y ); /* <= 2^128 - 2^65 + 1 so no overflow */
  return fd_fxp_private_contract( zh,zl, _c );
}

/* raz -> Round away from zero
   Fast variant assumes x*y < 2^64-2^30+1 (i.e. exact result < ~2^4)
   Based on:
        z/2^30 ~ (x/2^30)(y/2^30)
     -> z      ~ x y / 2^30
   With RAZ rounding: 
        z      = ceil( x y / 2^30 )
               = floor( (x y + 2^30 - 1) / 2^30 )
               = (x*y + 2^30 -1) >> 30
   As x*y might overflow 64 bits, we need to do a 64b*64b->128b
   multiplication (fd_uwide_mul), a 64b increment of a 128b
   (fd_uwide_inc) and a 128b shift right by 30
   (fd_fxp_private_contract).
   
   Slightly more expensive (one fd_uwide_inc) than RTZ rounding.
   Rounding error in (-1,0] ulp.  (ulp==2^-30). */

static inline ulong
fd_fxp_mul_raz( ulong   x,
                ulong   y,
                ulong * _c ) {
  ulong zh,zl; fd_uwide_mul( &zh,&zl, x, y );    /* <= 2^128 - 2^65 + 1 so no overflow */
  fd_uwide_inc( &zh,&zl, zh,zl, (1UL<<30)-1UL ); /* <= 2^128 - 2^65 + 2^30 so no overflow */
  return fd_fxp_private_contract( zh,zl, _c );
}

/* rnz -> Round nearest with ties toward zero
   Fast variant assumes x*y < 2^64-2^29+1 (i.e. exact result < ~2^4)
   Based on:
        z/2^30 ~ (x/2^30)(y/2^30)
     -> z      ~ x y / 2^30
   Let frac be the least significant 30 bits of x*y.  If frac<2^29
   (frac>2^29), we should round down (up).  frac==2^29 is a tie and we
   should round down.  If we add 2^29-1 to frac, the result will be
   <2^30 when frac<=2^29 and will be >=2^30.  Thus bit 30 of frac+2^29-1
   indicates whether we need to round up or down.  This yields:
        z = floor( x y + 2^29 - 1 ) / 2^30 )
          = (x*y + 2^29 - 1) >> 30
   As x*y might overflow 64 bits, we need to do a 64b*64b->128b
   multiplication (fd_uwide_mul), a 64b increment of a 128b
   (fd_uwide_inc) and a 128b shift right by 30
   (fd_fxp_private_contract).

   Slightly more expensive (one fd_uwide_inc) than RTZ rounding.
   Rounding error in (-1/2,1/2] ulp.  (ulp==2^-30). */

static inline ulong
fd_fxp_mul_rnz( ulong   x,
                ulong   y,
                ulong * _c ) {
  ulong zh,zl; fd_uwide_mul( &zh,&zl, x, y ); /* <= 2^128 - 2^65 + 1 so no overflow */
  fd_uwide_inc( &zh,&zl, zh,zl, (1UL<<29)-1UL ); /* <= 2^128 - 2^65 + 2^29 so no overflow */
  return fd_fxp_private_contract( zh,zl, _c );
}

/* rna -> Round nearest with ties away from zero (aka grade school rounding)
   Fast variant assumes x*y < 2^64-2^29 (i.e. exact result < ~2^4)
   Based on:
        z/2^30 ~ (x/2^30)(y/2^30)
     -> z      ~ x y / 2^30
   Let frac be the least significant 30 bits of x*y.  If frac<2^29
   (frac>2^29), we should round down (up).  frac==2^29 is a tie and we
   should round up.  If we add 2^29-1 to frac, the result will be <2^30
   when frac<=2^29 and will be >=2^30.  Thus bit 30 of frac+2^29
   indicates whether we need to round up or down.  This yields:
        z = floor( x y + 2^29 ) / 2^30 )
          = (x*y + 2^29) >> 30
   As x*y might overflow 64 bits, we need to do a 64b*64b->128b
   multiplication (fd_uwide_mul), a 64b increment of a 128b
   (fd_uwide_inc) and a 128b shift right by 30
   (fd_fxp_private_contract).

   Slightly more expensive (one fd_uwide_inc) than RTZ rounding.
   Rounding error in [-1/2,1/2) ulp.  (ulp==2^-30). */

static inline ulong
fd_fxp_mul_rna( ulong   x,
                ulong   y,
                ulong * _c ) {
  ulong zh,zl; fd_uwide_mul( &zh,&zl, x, y ); /* <= 2^128 - 2^65 + 1 so no overflow */
  fd_uwide_inc( &zh,&zl, zh,zl, 1UL<<29 );    /* <= 2^128 - 2^65 + 2^29 so no overflow */
  return fd_fxp_private_contract( zh,zl, _c );
}

/* rne -> Round toward nearest with ties toward even (aka banker's rounding / IEEE style rounding)
   Fast variant assumes x*y < 2^64-2^29 (i.e. exact result < ~2^4)
   Based on the observation that rnz / rna rounding should be used when
   floor(x*y/2^30) is even/odd.  That is, use the rnz / rna increment of
   2^29-1 / 2^29 when bit 30 of x*y is 0 / 1.  As x*y might overflow 64
   bits, we need to do a 64b*64b->128b multiplication (fd_uwide_mul), a
   64b increment of a 128b (fd_uwide_inc) and a 128b shift right by 30
   (fd_fxp_private_contract).
   
   The most accurate style of rounding usually and somewhat more
   expensive (some sequentially dependent bit ops and one fd_uwide_inc)
   than RTZ rounding.  Rounding error in [-1/2,1/2] ulp (unbiased).
   (ulp==2^-30). */

static inline ulong
fd_fxp_mul_rne( ulong   x,
                ulong   y,
                ulong * _c ) {
  ulong zh,zl; fd_uwide_mul( &zh,&zl, x, y );   /* <= 2^128 - 2^65 + 1 */
  ulong t = ((1UL<<29)-1UL) + ((zl>>30) & 1UL); /* t = 2^29-1 / 2^29 when bit 30 of x*y is 0 / 1 */
  fd_uwide_inc( &zh,&zl, zh,zl, t );            /* <= 2^128 - 2^65 + 2^29 */
  return fd_fxp_private_contract( zh,zl, _c );
}

/* rno -> Round toward nearest with ties toward odd
   Fast variant assumes x*y < 2^64-2^29 (i.e. exact result < ~2^4)
   Same as rne with the parity flipped for the increment.  As x*y might
   overflow 64 bits, we need to do a 64b*64b->128b multiplication
   (fd_uwide_mul), a 64b increment of a 128b (fd_uwide_inc) and a 128b
   shift right by 30 (fd_fxp_private_contract).
   
   Somewhat more expensive (some sequentially dependent bit ops and one
   fd_uwide_inc) than RTZ rounding.  Rounding error in [-1/2,1/2] ulp
   (unbiased).  (ulp==2^-30). */

static inline ulong
fd_fxp_mul_rno( ulong   x,
                ulong   y,
                ulong * _c ) {
  ulong zh,zl; fd_uwide_mul( &zh,&zl, x, y ); /* <= 2^128 - 2^65 + 1 */
  ulong t = (1UL<<29) - ((zl>>30) & 1UL);     /* t = 2^29 / 2^29-1 when bit 30 of x*y is 0 / 1 */
  fd_uwide_inc( &zh,&zl, zh,zl, t );          /* <= 2^128 - 2^65 + 2^29 */
  return fd_fxp_private_contract( zh,zl, _c );
}

#endif

FD_FN_CONST static inline ulong fd_fxp_mul_rtz_fast( ulong x, ulong y ) { return (x*y)                 >> 30; }
FD_FN_CONST static inline ulong fd_fxp_mul_raz_fast( ulong x, ulong y ) { return (x*y+((1UL<<30)-1UL)) >> 30; }
FD_FN_CONST static inline ulong fd_fxp_mul_rnz_fast( ulong x, ulong y ) { return (x*y+((1UL<<29)-1UL)) >> 30; }
FD_FN_CONST static inline ulong fd_fxp_mul_rna_fast( ulong x, ulong y ) { return (x*y+ (1UL<<29))      >> 30; }

FD_FN_CONST static inline ulong
fd_fxp_mul_rne_fast( ulong x,
                     ulong y ) {
  ulong z = x*y;
  ulong t = ((1UL<<29)-1UL) + ((z>>30) & 1UL); /* t = 2^29-1 / 2^29 when bit 30 of x*y is 0 / 1 */
  return (z + t) >> 30;
}

FD_FN_CONST static inline ulong
fd_fxp_mul_rno_fast( ulong x,
                     ulong y ) {
  ulong z = x*y;
  ulong t = (1UL<<29) - ((z>>30) & 1UL); /* t = 2^29-1 / 2^29 when bit 30 of x*y is 0 / 1 */
  return (z + t) >> 30;
}

/* Other rounding modes:
     rdn -> Round down                   / toward floor / toward -inf ... same as rtz for unsigned
     rup -> Round up                     / toward ceil  / toward +inf ... same as raz for unsigned
     rnd -> Round nearest with ties down / toward floor / toward -inf ... same as rnz for unsigned
     rnu -> Round nearest with ties up   / toward ceil  / toward -inf ... same as rna for unsigned */

static inline ulong fd_fxp_mul_rdn( ulong x, ulong y, ulong * _c ) { return fd_fxp_mul_rtz( x, y, _c ); }
static inline ulong fd_fxp_mul_rup( ulong x, ulong y, ulong * _c ) { return fd_fxp_mul_raz( x, y, _c ); }
static inline ulong fd_fxp_mul_rnd( ulong x, ulong y, ulong * _c ) { return fd_fxp_mul_rnz( x, y, _c ); }
static inline ulong fd_fxp_mul_rnu( ulong x, ulong y, ulong * _c ) { return fd_fxp_mul_rna( x, y, _c ); }

FD_FN_CONST static inline ulong fd_fxp_mul_rdn_fast( ulong x, ulong y ) { return fd_fxp_mul_rtz_fast( x, y ); }
FD_FN_CONST static inline ulong fd_fxp_mul_rup_fast( ulong x, ulong y ) { return fd_fxp_mul_raz_fast( x, y ); }
FD_FN_CONST static inline ulong fd_fxp_mul_rnd_fast( ulong x, ulong y ) { return fd_fxp_mul_rnz_fast( x, y ); }
FD_FN_CONST static inline ulong fd_fxp_mul_rnu_fast( ulong x, ulong y ) { return fd_fxp_mul_rna_fast( x, y ); }

/* FIXED POINT DIVISION ***********************************************/

/* Compute:
     (2^64 c + z)/2^30 ~ (x/2^30)/(y/2^30)
   under various rounding modes.  c<2^30 if y is non-zero.  Returns
   c=ULONG_MAX,z=0 if y is zero. */

#if FD_HAS_INT128 /* See the uwide-based implementations for details how these work */

static inline ulong
fd_fxp_div_rtz( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }
  return fd_fxp_private_split( fd_fxp_private_expand( x ) / (uint128)y, _c );
}

static inline ulong
fd_fxp_div_raz( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }
  return fd_fxp_private_split( (fd_fxp_private_expand( x )+(uint128)(y-1UL)) / (uint128)y, _c );
}

static inline ulong
fd_fxp_div_rnz( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }
  return fd_fxp_private_split( (fd_fxp_private_expand( x )+(uint128)((y-1UL)>>1)) / (uint128)y, _c );
}

static inline ulong
fd_fxp_div_rna( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }
  return fd_fxp_private_split( (fd_fxp_private_expand( x )+(uint128)(y>>1)) / (uint128)y, _c );
}

static inline ulong
fd_fxp_div_rne( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }
  uint128 n    = fd_fxp_private_expand( x );
  uint128 q    = n / (uint128)y;
  ulong   r    = (ulong)(n - q*y);
  ulong   flhy = y>>1;
  return fd_fxp_private_split( q + (uint128)(ulong)( (r>flhy) | ((r==flhy) & !!((~y) & ((ulong)q) & 1UL)) ), _c );
}

static inline ulong
fd_fxp_div_rno( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }
  uint128 n    = fd_fxp_private_expand( x );
  uint128 q    = n / (uint128)y;
  ulong   r    = (ulong)(n - q*y);
  ulong   flhy = y>>1;
  return fd_fxp_private_split( q + (uint128)(ulong)( (r>flhy) | ((r==flhy) & !!((~y) & (~(ulong)q) & 1UL)) ), _c );
}

#else /* uwide based implementations from pyth */

/* rtz -> Round toward zero (aka truncate rounding)
   Fast variant assumes y!=0 and x<2^34 (i.e. exact result < ~2^34)
   Based on:
        z/2^30 ~ (x/2^30) / (y/2^30)
     -> z      ~ 2^30 x / y
   With RTZ rounding: 
        z      = floor( 2^30 x / y )
   As 2^30 x might overflow 64 bits, we need to expand x
   (fd_fxp_private_expand) and then use a 128b/64b -> 128b divider.
   (fd_uwide_div).

   Fastest style of rounding.  Rounding error in [0,1) ulp.
   (ulp==2^-30). */

static inline ulong
fd_fxp_div_rtz( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }         /* Handle divide by zero */
  ulong zh,zl; fd_fxp_private_expand( &zh,&zl, x ); /* 2^30 x  <= 2^94-2^30 so no overflow */
  fd_uwide_div( &zh,&zl, zh,zl, y );                /* <zh,zl> <= 2^94-2^30 so no overflow */
  *_c = zh; return zl;
}

/* raz -> Round away from zero
   Fast variant assumes y!=0 and 2^30*x+y-1<2^64 (i.e. exact result < ~2^34)
   Based on:
        z/2^30 ~ (x/2^30) / (y/2^30)
     -> z      ~ 2^30 x / y
   With RAZ rounding: 
        z      = ceil( 2^30 x / y )
               = floor( (2^30 x + y - 1) / y )
   As 2^30 x might overflow 64 bits, we need to expand x
   (fd_fxp_private_expand), increment it by the 64b y-1 (fd_uwide_inc)
   and then use a 128b/64b->128b divider (fd_uwide_div).

   Slightly more expensive (one fd_uwide_inc) than RTZ rounding.
   Rounding error in (-1,0] ulp. (ulp==2^-30). */

static inline ulong
fd_fxp_div_raz( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }         /* Handle divide by zero */
  ulong zh,zl; fd_fxp_private_expand( &zh,&zl, x ); /* 2^30 x  <= 2^94-2^30 so no overflow */
  fd_uwide_inc( &zh,&zl, zh,zl, y-1UL );            /* <zh,zl> <= 2^94+2^64-2^30-2 so no overflow */
  fd_uwide_div( &zh,&zl, zh,zl, y );                /* <zh,zl> = ceil( 2^30 x / y ) <= 2^94-2^30 so no overflow */
  *_c = zh; return zl;
}

/* rnz -> Round nearest with ties toward zero
   Fast variant assumes y!=0 and 2^30*x+floor((y-1)/2)<2^64 (i.e. exact result < ~2^34)

   Consider:
     z = floor( (2^30 x + floor( (y-1)/2 )) / y )
   where y>0.
   
   If y is even:                                   odd
     z       = floor( (2^30 x + (y/2) - 1) / y )     = floor( (2^30 x + (y-1)/2) / y )
   or:
     z y + r = 2^30 x + (y/2)-1                      = 2^30 x + (y-1)/2
   for some r in [0,y-1].  Or:
     z y     = 2^30 x + delta                        = 2^30 x + delta                        
   where:
     delta   in [-y/2,y/2-1]                         in [-y/2+1/2,y/2-1/2]
   or:
     z       = 2^30 x / y + epsilon                  = 2^30 x / y + epsilon
   where:
     epsilon in [-1/2,1/2-1/y]                       in [-1/2+1/(2y),1/2-1/(2y)]
   Thus we have:
     2^30 x/y - 1/2 <= z < 2^30 x/y + 1/2            2^30 x/y - 1/2 < z < 2^30 x/y + 1/2

   Combining yields:

     2^30 x/y - 1/2 <= z < 2^30 x/y + 1/2

   Thus, the z computed as per the above is the RNZ rounded result.  As
   2^30 x might overflow 64 bits, we need to expand x
   (fd_fxp_private_expand), increment it by the 64b (y-1)>>1
   (fd_uwide_inc) and then use a 128b/64b->128b divider (fd_uwide_div).

   Slightly more expensive (one fd_uwide_inc) than RTZ rounding.
   Rounding error in (-1/2,1/2] ulp. (ulp==2^-30). */

static inline ulong
fd_fxp_div_rnz( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }         /* Handle divide by zero */
  ulong zh,zl; fd_fxp_private_expand( &zh,&zl, x ); /* 2^30 x <= 2^94-2^30 so no overflow */
  fd_uwide_inc( &zh,&zl, zh,zl, (y-1UL)>>1 );       /* <zh,zl> <= 2^94-2^30 + 2^63-1 so no overflow */
  fd_uwide_div( &zh,&zl, zh,zl, y );                /* <zh,zl> <= ceil(2^30 x/y) <= 2^94-2^30 so no overflow */
  *_c = zh; return zl;
}

/* rna -> Round nearest with ties away from zero (aka grade school rounding)
   Fast variant assumes y!=0 and 2^30*x+floor(y/2)<2^64 (i.e. exact result < ~2^34)

   Consider:
     z = floor( (2^30 x + floor( y/2 )) / y )
   where y>0.
   
   If y is even:                                   odd
     z       = floor( (2^30 x + (y/2)) / y )         = floor( (2^30 x + (y-1)/2) / y )
   or:
     z y + r = 2^30 x + (y/2)                        = 2^30 x + (y-1)/2
   for some r in [0,y-1].  Or:
     z y     = 2^30 x + delta                        = 2^30 x + delta                        
   where:
     delta   in [-y/2+1,y/2]                         in [-y/2+1/2,y/2-1/2]
   or:
     z       = 2^30 x / y + epsilon                  = 2^30 x / y + epsilon
   where:
     epsilon in [-1/2+1/y,1/2]                       in [-1/2+1/(2y),1/2-1/(2y)]
   Thus we have:
     2^30 x/y - 1/2 < z <= 2^30 x/y + 1/2            2^30 x/y - 1/2 < z < 2^30 x/y + 1/2

   Combining yields:

     2^30 x/y - 1/2 < z <= 2^30 x/y + 1/2

   Thus, the z computed as per the above is the RNA rounded result.  As
   2^30 x might overflow 64 bits, we need to expand x
   (fd_fxp_private_expand), increment it by the 64b y>>1 (fd_uwide_inc)
   and then use a 128b/64b->128b divider (fd_uwide_div).

   Slightly more expensive (one fd_uwide_inc) than RTZ rounding.
   Rounding error in [-1/2,1/2) ulp. (ulp==2^-30).
   
   Probably worth noting that if y has its least significant bit set,
   all the rnz/rna/rne/rno modes yield the same result (as ties aren't
   possible) and this is the cheapest of the round nearest modes.*/

static inline ulong
fd_fxp_div_rna( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }         /* Handle divide by zero */
  ulong zh,zl; fd_fxp_private_expand( &zh,&zl, x ); /* 2^30 x <= 2^94-2^30 so no overflow */
  fd_uwide_inc( &zh,&zl, zh,zl, y>>1 );             /* <zh,zl> <= 2^94-2^30 + 2^63-1 so no overflow */
  fd_uwide_div( &zh,&zl, zh,zl, y );                /* <zh,zl> <= ceil(2^30 x/y) <= 2^94-2^30 so no overflow */
  *_c = zh; return zl;
}

/* rne -> Round nearest with ties toward even (aka banker's rounding / IEEE style rounding)
   Fast variant assumes y!=0 and 2^30 x < 2^64 (i.e. exact result < ~2^34)

   Based on computing (when y>0):

     q y + r = 2^30 x

   where q = floor( 2^30 x / y ) and r is in [0,y-1].

   If r < y/2, the result should round down.  And if r > y/2 the result
   should round up.  If r==y/2 (which is only possible if y is even),
   the result should round down / up when q is even / odd.
   
   Combining yields we need to round up when:

     r>floor(y/2) or (r==floor(y/2) and y is even and q is odd)

   As 2^30 x might overflow 64 bits, we need to expand x
   (fd_fxp_private_expand).  Since we need both the 128b quotient and
   the 64b remainder, we need a 128b/64b->128b,64b divider
   (fd_uwide_divrem ... if there was a way to quickly determine if
   floor( 2^30 x / y ) is even or odd, we wouldn't need the remainder
   and could select the appropriate RNZ/RNA based fd_uwide_inc
   increment) and then a 128b conditional increment (fd_uwide_inc).

   The most accurate style of rounding usually and somewhat more
   expensive (needs remainder, some sequentially dependent bit ops and
   one fd_uwide_inc) than RTZ rounding.  Rounding error in [-1/2,1/2]
   ulp (unbiased).  (ulp==2^-30). */

static inline ulong
fd_fxp_div_rne( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }          /* Handle divide by zero */
  ulong zh,zl; fd_fxp_private_expand( &zh,&zl, x );  /* 2^30 x <= 2^94-2^30 so no overflow */
  ulong r    = fd_uwide_divrem( &zh,&zl, zh,zl, y ); /* <zh,zl>*y + r = 2^30 x where r is in [0,y-1] so no overflow */
  ulong flhy = y>>1;                                 /* floor(y/2) so no overflow */
  fd_uwide_inc( &zh,&zl, zh,zl, (ulong)( (r>flhy) | ((r==flhy) & !!((~y) & zl & 1UL)) ) );
  /* <zh,zl> <= ceil( 2^30 x / y ) <= 2^94-2^30 so no overflow */
  *_c = zh; return zl;
}

/* rno -> Round nearest with ties toward odd
   Fast variant assumes y!=0 and 2^30 x < 2^64 (i.e. exact result < ~2^34)

   Similar considerations as RNE with the parity for rounding on ties
   swapped.

   Somewhat more expensive (needs remainder, some sequentially dependent
   bit ops and one fd_uwide_inc) than RTZ rounding.  Rounding error in
   [-1/2,1/2] ulp (unbiased).  (ulp==2^-30). */

static inline ulong
fd_fxp_div_rno( ulong   x,
                ulong   y,
                ulong * _c ) {
  if( !y ) { *_c = ULONG_MAX; return 0UL; }          /* Handle divide by zero */
  ulong zh,zl; fd_fxp_private_expand( &zh,&zl, x );  /* 2^30 x <= 2^94-2^30 so no overflow */
  ulong r    = fd_uwide_divrem( &zh,&zl, zh,zl, y ); /* <zh,zl>*y + r = 2^30 x where r is in [0,y-1] so no overflow */
  ulong flhy = y>>1;                                 /* floor(y/2) so no overflow */
  fd_uwide_inc( &zh,&zl, zh,zl, (ulong)( (r>flhy) | ((r==flhy) & !!((~y) & (~zl) & 1UL)) ) );
  /* <zh,zl> <= ceil( 2^30 x / y ) <= 2^94-2^30 so no overflow */
  *_c = zh; return zl;
}

#endif

FD_FN_CONST static inline ulong fd_fxp_div_rtz_fast( ulong x, ulong y ) { return ( x<<30              ) / y; }
FD_FN_CONST static inline ulong fd_fxp_div_raz_fast( ulong x, ulong y ) { return ((x<<30)+ (y-1UL)    ) / y; }
FD_FN_CONST static inline ulong fd_fxp_div_rnz_fast( ulong x, ulong y ) { return ((x<<30)+((y-1UL)>>1)) / y; }
FD_FN_CONST static inline ulong fd_fxp_div_rna_fast( ulong x, ulong y ) { return ((x<<30)+ (y     >>1)) / y; }

FD_FN_CONST static inline ulong
fd_fxp_div_rne_fast( ulong x,
                     ulong y ) {
  ulong n    = x << 30;
  ulong q    = n / y;
  ulong r    = n - q*y;
  ulong flhy = y>>1;
  return q + (ulong)( (r>flhy) | ((r==flhy) & !!((~y) & q & 1UL)) );
}

FD_FN_CONST static inline ulong
fd_fxp_div_rno_fast( ulong x,
                     ulong y ) {
  ulong n    = x << 30;
  ulong q    = n / y;
  ulong r    = n - q*y;
  ulong flhy = y>>1;
  return q + (ulong)( (r>flhy) | ((r==flhy) & !!((~y) & (~q) & 1UL)) );
}

/* Other rounding modes:
     rdn -> Round down                   / toward floor / toward -inf ... same as rtz for unsigned
     rup -> Round up                     / toward ceil  / toward +inf ... same as raz for unsigned
     rnd -> Round nearest with ties down / toward floor / toward -inf ... same as rnz for unsigned
     rnu -> Round nearest with ties up   / toward ceil  / toward -inf ... same as rna for unsigned */

static inline ulong fd_fxp_div_rdn( ulong x, ulong y, ulong * _c ) { return fd_fxp_div_rtz( x, y, _c ); }
static inline ulong fd_fxp_div_rup( ulong x, ulong y, ulong * _c ) { return fd_fxp_div_raz( x, y, _c ); }
static inline ulong fd_fxp_div_rnd( ulong x, ulong y, ulong * _c ) { return fd_fxp_div_rnz( x, y, _c ); }
static inline ulong fd_fxp_div_rnu( ulong x, ulong y, ulong * _c ) { return fd_fxp_div_rna( x, y, _c ); }

FD_FN_CONST static inline ulong fd_fxp_div_rdn_fast( ulong x, ulong y ) { return fd_fxp_div_rtz_fast( x, y ); }
FD_FN_CONST static inline ulong fd_fxp_div_rup_fast( ulong x, ulong y ) { return fd_fxp_div_raz_fast( x, y ); }
FD_FN_CONST static inline ulong fd_fxp_div_rnd_fast( ulong x, ulong y ) { return fd_fxp_div_rnz_fast( x, y ); }
FD_FN_CONST static inline ulong fd_fxp_div_rnu_fast( ulong x, ulong y ) { return fd_fxp_div_rna_fast( x, y ); }

/* FIXED POINT SQRT ***************************************************/

/* Compute:
     z/2^30 ~ sqrt( x/2^30 )
   under various rounding modes. */

#if FD_HAS_INT128 /* See the uwide-based implementations for details how these work */

/* FIXME: USE X86 FPU TRICKS FOR BETTER INITIAL APPROXIMATION HERE? */

FD_FN_CONST static inline ulong
fd_fxp_sqrt_rtz( ulong x ) {
  if( !x ) return 0UL;
  int s = (63-fd_ulong_find_msb( x )) >> 1;
  if( s>15 ) s = 15;
  ulong y = fd_ulong_sqrt( x << (s<<1) ) << (15-s);
  if( s==15 ) return y;

  uint128 _x = fd_fxp_private_expand( x );
  uint128 _y =  (uint128)y;
  for(;;) {
    uint128 _z = (_y*_y + _y + _x) / ((_y<<1)+(uint128)1);
    if( _z==_y ) break;
    _y = _z;
  }
  return (ulong)_y;
}

FD_FN_CONST static inline ulong
fd_fxp_sqrt_raz( ulong x ) {
  if( !x ) return 0UL;
  int s = (63-fd_ulong_find_msb( x )) >> 1;
  if( s>15 ) s = 15;
  ulong xl = x << (s<<1);
  ulong y = fd_ulong_sqrt( xl ) << (15-s);
  if( s==15 ) return y + (ulong)!!(xl-y*y);

  uint128 _x = fd_fxp_private_expand( x ) - (uint128)2;
  uint128 _y =  (uint128)y;
  for(;;) {
    uint128 _z = (_y*_y + _y + _x) / ((_y<<1)-(uint128)1);
    if( _z==_y ) break;
    _y = _z;
  }
  return (ulong)_y;
}

FD_FN_CONST static inline ulong
fd_fxp_sqrt_rnz( ulong x ) {
  if( !x ) return 0UL;
  int s = (63-fd_ulong_find_msb( x )) >> 1;
  if( s>15 ) s = 15;
  ulong xl = x << (s<<1);
  ulong y = fd_ulong_sqrt( xl ) << (15-s);
  if( s==15 ) return y + (ulong)((xl-y*y)>y);

  uint128 _x = fd_fxp_private_expand( x ) -(uint128)1;
  uint128 _y =  (uint128)y;
  for(;;) {
    uint128 _z = (_y*_y + _y + _x) / (_y<<1);
    if( _z==_y ) break;
    _y = _z;
  }
  return (ulong)_y;
}

#else /* uwide based implementations from pyth */

/* rtz -> Round toward zero (aka truncate rounding)
   Fast variant assumes x<2^34
   Based on:
        z/2^30 ~ sqrt( x/2^30)
     -> z      ~ sqrt( 2^30 x )
   With RTZ rounding:
        z      = floor( sqrt( 2^30 x ) )
   Fastest style of rounding.  Rounding error in [0,1) ulp.
   (ulp==2^-30). */

FD_FN_CONST static inline ulong
fd_fxp_sqrt_rtz( ulong x ) {

  /* Initial guess.  Want to compute
       y = sqrt( x 2^30 )
     but x 2^30 does not fit into 64-bits at this point.  So we instead
     approximate:
       y = sqrt( x 2^(2s) 2^(30-2s) )
         = sqrt( x 2^(2s) ) 2^(15-s)
         ~ floor( sqrt( x 2^(2s) ) ) 2^(15-s)
     where s is the largest integer such that x 2^(2s) does not
     overflow. */

  int s = (63-fd_ulong_find_msb( x )) >> 1;         /* lg x in [34,63], 63-lg x in [0,29], s in [0,14] when x>=2^34 */
  if( s>15 ) s = 15;                                /* s==15 when x<2^34 */
  ulong y = fd_ulong_sqrt( x << (s<<1) ) << (15-s); /* All shifts well defined */
  if( s==15 ) return y;                             /* No iteration if x<2^34 */

  /* Expand x to 2^30 x for the fixed point iteration */
  ulong xh,xl; fd_fxp_private_expand( &xh,&xl, x );
  for(;;) {

    /* Iterate y' = floor( (y(y+1) + 2^30 x) / (2y+1) ).  This is the
       same iteration as sqrt_uint{8,16,32,64} (which converges on the
       floor(sqrt(x)) but applied to the (wider than 64b) quantity
       2^30*x and then starting from an exceptionally good guess (such
       that ~2 iterations should be needed at most). */

    ulong yh,yl;
    fd_uwide_mul( &yh,&yl, y,y+1UL );
    fd_uwide_add( &yh,&yl, yh,yl, xh,xl, 0UL );
    fd_uwide_div( &yh,&yl, yh,yl, (y<<1)+1UL );
    if( yl==y ) break;
    y = yl;
  }

  return y;
}

/* raz -> Round away zero
   Fast variant assumes x<2^34
   Based on:
        z/2^30 ~ sqrt( x/2^30)
     -> z      ~ sqrt( 2^30 x )
   Let y be the RTZ rounded result:
        y = floor( sqrt( 2^30 x ) )
   and consider the residual:
        r = 2^30 x - y^2
   which, given the above, will be in [0,2y].  If r==0, the result
   is exact and thus already correctly rounded.  Otherwise, we need
   to round up.  We note that the residual of the RTZ iteration is
   the same as this residual at convergence:
        y = floor( (y^2 + y + 2^30 x) / (2y+1) )
          = (y^2 + y + 2^30 x - r') / (2y+1)
   where r' in [0,2y]:
        2y^2 + y = y^2 + y + 2^30 x - r'
        y^2 = 2^30 x - r'
        r' = 2^30 x - y^2
     -> r' = r
   Thus we can use explicitly compute the remainder or use
   fd_uwide_divrem in the iteration itself to produce the needed
   residual.

   Alternatively, the iteration
        y = floor( (y^2 + y - 2 + 2^30 x) / (2y-1) )
          = floor( (y(y+1) + (2^30 x-2)) / (2y-1) )
   should converge on the RAZ rounded result as:
        y = (y^2 + y - 2 + 2^30 x - r'') / (2y-1)
   where r'' in [0,2y-2]
        2y^2 - y = y^2 + y - 2 + 2^30 x - r''
        y^2 - 2 y + 2 + r'' = 2^30 x
   Thus at r'' = 0:
        (y-1)^2 + 1 = 2^30 x
     -> (y-1)^2 < 2^30 x
   and at r'' = 2y-2
        y^2 = 2^30 x
   such that:
        (y-1)^2 < 2^30 x <= y^2
   which means y is the correctly rounded result.

   Slightly more expensive than RTZ rounding.  Rounding error in (-1,0]
   ulp.  (ulp==2^-30). */

FD_FN_CONST static inline ulong
fd_fxp_sqrt_raz( ulong x ) {
  ulong xh, xl;

  /* Same guess as rtz rounding */
  int s = (63-fd_ulong_find_msb( x )) >> 1;
  if( s>15 ) s = 15;
  xl = x << (s<<1);
  ulong y = fd_ulong_sqrt( xl ) << (15-s);
  if( s==15 ) return y + (ulong)!!(xl-y*y); /* Explicitly compute residual to round when no iteration needed */

  /* Use the modified iteration to converge on raz rounded result */
  fd_fxp_private_expand( &xh,&xl, x );
  fd_uwide_dec( &xh,&xl, xh, xl, 2UL );
  for(;;) {
    ulong yh,yl;
    fd_uwide_mul( &yh,&yl, y, y+1UL );
    fd_uwide_add( &yh,&yl, yh,yl, xh,xl, 0UL );
    fd_uwide_div( &yh,&yl, yh,yl, (y<<1)-1UL );
    if( yl==y ) break;
    y = yl;
  }

  return y;
}

/* rnz/rna/rne/rno -> Round nearest with ties toward zero/away zero/toward even/toward odd
   Fast variant assumes x<2^34
   Based on:
        z/2^30 ~ sqrt( x/2^30)
     -> z      ~ sqrt( 2^30 x )
   Assuming there are no ties, we want to integer z such that:
        (z-1/2)^2 < 2^30 x < (z+1/2)^2
        z^2 - z + 1/4 < 2^30 x < z^2 + z + 1/4
   since z is integral, this is equivalent to finding a z such that:
     -> z^2 - z + 1 <= 2^30 x < z^2 + z + 1
     -> r = 2^30 x - (z^2 - z + 1) and is in [0,2z)
   This suggests using the iteration:
        z = floor( (z^2 + z - 1 + 2^30 x) / (2z) )
          = floor( (z(z+1) + (2^30 x-1)) / (2z) )
   which, at convergence, has:
        2z^2 = z^2 + z - 1 + 2^30 x - r'
   where r' is in [0,2z).  Solving for r', at convergence:
        r' = 2^30 x - (z^2 - z + 1)
        r' = r
   Thus, this iteration converges to the correctly rounded z when there
   are no ties.  But this also demonstrates that no ties are possible
   when z is integral ... the above derivation hold when either endpoint
   of the initial inequality is closed because the endpoint values are
   fraction and cannot be exactly met for any integral z.  As such,
   there are no ties and all round nearest styles can use the same
   iteration for the sqrt function.

   For computing a faster result for small x, let y be the RTZ rounded
   result:
        y = floor( sqrt( 2^30 x ) )
   and consider the residual:
        r'' = 2^30 x - y^2
   which, given the above, will be in [0,2y].  If r''==0, the result is
   exact and thus already correctly rounded.  Otherwise, let:
        z = y when r''<=y and y+1 when when r''>y
   Consider r''' from the above for this z.
        r''' = 2^30 x - z^2
             = 2^30 x - y^2 when r''<=y and 2^30 x - (y+1)^2 o.w.
             = r''' when r''<=y and r'' - 2y - 1 o.w.
     -> r''' in [0,y] when r''<=y and in [y+1,2y]-2y-1 o.w.
     -> r''' in [0,y] when r''<=y and in [-y,-1]-2y-1 o.w.
     -> r''' in [-y,y] and is negative when r''>y
     -> r''' in [-z+1,z]
   This implies that  we have for
        2^30 x - (z^2-z+1) = r''' + z-1 is in [0,2z)
   As such, z computed by this method is also correctly rounded.  Thus
   we can use explicitly compute the remainder or use fd_uwide_divrem in
   the iteration itself to produce the needed residual.

   Very slightly more expensive than RTZ rounding.  Rounding error in
   (-1/2,1/2) ulp.  (ulp==2^-30). */

FD_FN_CONST static inline ulong
fd_fxp_sqrt_rnz( ulong x ) {
  ulong xh, xl;

  /* Same guess as rtz rounding */
  int s = (63-fd_ulong_find_msb( x )) >> 1;
  if( s>15 ) s = 15;
  xl = x << (s<<1);
  ulong y = fd_ulong_sqrt( xl ) << (15-s);
  if( s==15 ) return y + (ulong)((xl-y*y)>y); /* Explicitly compute residual to round when no iteration needed */

  /* Use the modified iteration to converge on rnz rounded result */
  fd_fxp_private_expand( &xh,&xl, x );          /* 2^30 x */
  fd_uwide_dec( &xh,&xl, xh,xl, 1UL );          /* 2^30 x - 1 */
  for(;;) {
    ulong yh,yl;
    fd_uwide_mul( &yh,&yl, y,y+1UL );           /* y^2 + y */
    fd_uwide_add( &yh,&yl, yh,yl, xh,xl, 0UL ); /* y^2 + y - 1 + 2^30 x */
    fd_uwide_div( &yh,&yl, yh,yl, y<<1 );
    if( yl==y ) break;
    y = yl;
  }

  return y;
}

#endif

FD_FN_CONST static inline ulong fd_fxp_sqrt_rna( ulong x ) { return fd_fxp_sqrt_rnz( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rne( ulong x ) { return fd_fxp_sqrt_rnz( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rno( ulong x ) { return fd_fxp_sqrt_rnz( x ); }

FD_FN_CONST static inline ulong fd_fxp_sqrt_rtz_fast( ulong x ) { return fd_ulong_sqrt( x<<30 ); }

FD_FN_CONST static inline ulong
fd_fxp_sqrt_raz_fast( ulong x ) {
  ulong xl = x<<30;
  ulong y  = fd_ulong_sqrt( xl );
  ulong r  = xl - y*y;
  return y + (ulong)!!r;
}

FD_FN_CONST static inline ulong
fd_fxp_sqrt_rnz_fast( ulong x ) {
  ulong xl = x<<30;
  ulong y  = fd_ulong_sqrt( xl );
  ulong r  = xl - y*y;
  return y + (ulong)(r>y);
}

FD_FN_CONST static inline ulong fd_fxp_sqrt_rna_fast( ulong x ) { return fd_fxp_sqrt_rnz_fast( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rne_fast( ulong x ) { return fd_fxp_sqrt_rnz_fast( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rno_fast( ulong x ) { return fd_fxp_sqrt_rnz_fast( x ); }

/* Other rounding modes:
     rdn -> Round down                   / toward floor / toward -inf ... same as rtz for unsigned
     rup -> Round up                     / toward ceil  / toward +inf ... same as raz for unsigned
     rnd -> Round nearest with ties down / toward floor / toward -inf ... same as rnz for unsigned
     rnu -> Round nearest with ties up   / toward ceil  / toward -inf ... same as rna for unsigned */

FD_FN_CONST static inline ulong fd_fxp_sqrt_rdn( ulong x ) { return fd_fxp_sqrt_rtz( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rup( ulong x ) { return fd_fxp_sqrt_raz( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rnd( ulong x ) { return fd_fxp_sqrt_rnz( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rnu( ulong x ) { return fd_fxp_sqrt_rnz( x ); }

FD_FN_CONST static inline ulong fd_fxp_sqrt_rdn_fast( ulong x ) { return fd_fxp_sqrt_rtz_fast( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rup_fast( ulong x ) { return fd_fxp_sqrt_raz_fast( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rnd_fast( ulong x ) { return fd_fxp_sqrt_rnz_fast( x ); }
FD_FN_CONST static inline ulong fd_fxp_sqrt_rnu_fast( ulong x ) { return fd_fxp_sqrt_rnz_fast( x ); }

/* FIXED POINT LOG2 ***************************************************/

/* Compute:

     e + f/2^30 ~ log2( x/2^30 )

   If x is non-zero, e will be in [-30,33] and f will be in [0,2^30]

   Note: This is not guaranteed to be exactly rounded and thus this
   doesn't have variants for every rounding mode under the sun.  The
   current implementation has <=2 ulp error with a round-nearest flavor
   though.

   Given the round-nearest flavor, it is possible to have a f/2^30=1
   exactly (e.g. log2_approx( ULONG_MAX ) will have e=33 and f/2^30=1
   such that e still is exactly determined by the index of x's most
   significant bit but the fractional part is 1 after rounding up.

   It is possible modify this while retaining a round-nearest flavor
   such that e is strictly in [-30,34] and f/2^30 is strictly in [0,1)
   (e will no longer strictly be determined the index of x's most
   significant bit so technically this retains less info than the
   above).

   Likewise, it is possible to modify this to use a round-toward-zero
   flavor such that e will be in [-30,33] and f/2^30 is in [0,1) always.
   The resulting approximation accuracy would be slightly lower and
   slightly biased.

   If x is zero, the result is undefined mathematically (the limit
   x->zero+ is -inf ... this implementation returns i=INT_MIN<<-30 and
   f=0 for specificity). */
/* FIXME: CONSIDER MAKING THIS A FUNCTION CALL? */

static inline ulong              /* f, in [0,2^30] (yes, closed ... see note above) */
fd_fxp_log2_approx( ulong x,
                    int * _e ) { /* e, in [-30,33] (==fd_ulong_find_msb(x)-30 ... see note above) */

  /* Handle bad inputs */

  if( !x ) { *_e = INT_MIN; return 0UL; }

  /* Crack x into:

       x = 2^i ( 1 + y/2^63 )

     where y is in [0,2^63).  This can always be done _exactly_ for
     non-zero x.  That is, i is the index of x's most significant
     non-zero bit (in [0,63]) and y is trailing i bits shifted up to be
     63b wide. */

  int   i = fd_ulong_find_msb( x );    /* In [0,63] */
  ulong y = (x << (63-i)) - (1UL<<63); /* In [0,2^63) */

  /* Convert this to a fixed point approximation of x:

       x ~ 2^i ( 1 + d/2^30 )

     via:

       d = floor( (y+2^32) / 2^33 )

     This representation is still exact when i <= 30 and at most 1/2 ulp
     error in d when i>30 (rna / round nearest with ties away from zero
     rounding ... consider using ties toward even or truncate rounding
     here as per note above).  Given the use of a round nearest style, d
     is in [0,2^30] (closed at both ends). */

  ulong d = (y + (1UL<<32)) >> 33;

  /* Given this, we have:

       e + f/2^30 = log2( x/2^30 )
                  = log2( x ) - 30
                  ~ log2( 2^i ( 1+ d/2^30 ) ) - 30
                  = i-30 + log2( 1 + d/2^30 )

     From this, we identify:

       e      = i-30               (exact)
       f/2^30 ~ log2( 1 + d/2^30 ) (approximate)

     Thus, f of a 30b fixed point lg1p calculator with a 30b fixed point
     input.  The below is automatically generated code for a fixed point
     implementation of a minimax Pade(4,3) approximant to log2(1+x) over
     the domain [0,1].  In exact math, the approximation has an accuracy
     better than 1/2 ulp over the whole domain and is exact at the
     endpoints.  As implemented, the accuracy is O(1) ulp over the whole
     domain (with round nearest flavored rounding), monotonic and still
     exact at the endpoints. */

  ulong f;
  ulong g;

  /* BEGIN AUTOGENERATED CODE */
  /* bits 31.8 rms_aerr 1.9e-10 rms_rerr 1.3e-10 max_aerr 2.7e-10 max_rerr 2.7e-10 */

  f = 0x0000000245c36b35UL;               /* scale 41 bout 34 bmul  - */
  f = 0x000000029c5b8e15UL + ((f*d)>>36); /* scale 35 bout 34 bmul 64 */
  f = 0x0000000303d59639UL + ((f*d)>>32); /* scale 33 bout 34 bmul 64 */
  f = 0x00000001715475ccUL + ((f*d)>>31); /* scale 32 bout 34 bmul 64 */
  f =                         (f*d);      /* scale 62 bout 64 bmul 64 */
  /* f max 0xd1fb651800000000 */

  g = 0x000000024357c946UL;               /* scale 37 bout 34 bmul  - */
  g = 0x00000002a94e3723UL + ((g*d)>>33); /* scale 34 bout 34 bmul 64 */
  g = 0x000000018b7f484dUL + ((g*d)>>32); /* scale 32 bout 34 bmul 64 */
  g = 0x0000000100000000UL + ((g*d)>>30); /* scale 32 bout 34 bmul 64 */
  /* g max 0x0000000347ed945f */

  f = (f + (g>>1)) / g; /* RNA style rounding */
  /* END AUTOGENERATED CODE */

  *_e = i-30; return f;
}

/* FIXED POINT EXP2 / REXP2 *******************************************/

/* fd_fxp_exp2_approx computes:

     y/2^30 ~ exp2( x/2^30 )

   with an error of O(1) ulp for x/2^30 < ~1.  This uses a minimax
   polynomial that is better than 0.5 ulp accurate in exact arithmetic.
   As implemented, this is +/-1 ulp of the correctly rounded RNE result
   when x<=2^30, has the leading ~30 bits correct for larger x and is
   exact for input values that yield exactly representable outputs.
   Returns ULONG_MAX if output would overflow the 34.30u output. */
/* FIXME: CONSIDER MAKING THIS A FUNCTION CALL? */

FD_FN_CONST static inline ulong
fd_fxp_exp2_approx( ulong x ) {
  ulong i = x >> 30;
  if( i>=34UL ) return ULONG_MAX;
  ulong d = x & ((1UL<<30)-1UL);
  ulong y;
  /* BEGIN AUTOGENERATED CODE */
  /* bits 33.8 rms_aerr 4.7e-11 rms_rerr 3.5e-11 max_aerr 6.7e-11 max_rerr 6.6e-11 */
  y = 0x00000002d6e2cc42UL;               /* scale 49 bout 34 bmul  - */
  y = 0x0000000257c0894cUL + ((y*d)>>33); /* scale 46 bout 34 bmul 64 */
  y = 0x00000002c01421b9UL + ((y*d)>>33); /* scale 43 bout 34 bmul 64 */
  y = 0x000000027609e3a4UL + ((y*d)>>33); /* scale 40 bout 34 bmul 64 */
  y = 0x00000001c6b2ea70UL + ((y*d)>>33); /* scale 37 bout 34 bmul 64 */
  y = 0x00000001ebfbce13UL + ((y*d)>>32); /* scale 35 bout 34 bmul 64 */
  y = 0x00000002c5c8603bUL + ((y*d)>>31); /* scale 34 bout 34 bmul 64 */
  y =                         (y*d);      /* scale 64 bout 64 bmul 64 */
  /* END AUTOGENERATED CODE */
  int s = 34-(int)i;
  return ((y + (1UL<<(s-1))) >> s) + (1UL<<(64-s));
}

/* fd_fxp_rexp2_approx computes:

     y/2^30 ~ exp2( -x/2^30 )

   with an error of O(1) ulp everywhere.  This uses a minimax polynomial
   that is better than 0.5 ulp accurate in exact arithmetic.  As
   implemented, this is +/-1 ulp of the correctly rounded RNE result
   everywhere and exact for input values that have exactly representable
   outputs. */
/* FIXME: CONSIDER MAKING THIS A FUNCTION CALL? */

FD_FN_CONST static inline ulong
fd_fxp_rexp2_approx( ulong x ) {
  ulong i = x >> 30;
  if( i>=31UL ) return 0UL;
  ulong d = x & ((1UL<<30)-1UL);
  ulong y;
  /* BEGIN AUTOGENERATED CODE */
  /* bits 35.4 rms_aerr 2.4e-11 rms_rerr 1.4e-11 max_aerr 3.3e-11 max_rerr 2.2e-11 */
  y = 0x00000002d6e2c6a2UL;               /* scale 50 bout 34 bmul  - */
  y = 0x0000000269e37ccbUL - ((y*d)>>34); /* scale 46 bout 34 bmul 64 */
  y = 0x00000002b83379a8UL - ((y*d)>>33); /* scale 43 bout 34 bmul 64 */
  y = 0x00000002762c0ceaUL - ((y*d)>>33); /* scale 40 bout 34 bmul 64 */
  y = 0x00000001c6af4b81UL - ((y*d)>>33); /* scale 37 bout 34 bmul 64 */
  y = 0x00000001ebfbd6aaUL - ((y*d)>>32); /* scale 35 bout 34 bmul 64 */
  y = 0x00000002c5c85fb1UL - ((y*d)>>31); /* scale 34 bout 34 bmul 64 */
  y = 0x8000000000000000UL - ((y*d)>> 1); /* scale 63 bout 64 bmul 64 */
  /* END AUTOGENERATED CODE */
  int s = 33+(int)i;
  return (y + (1UL<<(s-1))) >> s;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_math_fd_fxp_h */

