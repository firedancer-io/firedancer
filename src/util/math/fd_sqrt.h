#ifndef HEADER_fd_src_util_math_fd_sqrt_h
#define HEADER_fd_src_util_math_fd_sqrt_h

/* Portable robust integer sqrt.  Adapted from Pyth Oracle. */

#include "../bits/fd_bits.h"

FD_PROTOTYPES_BEGIN

/* Compute y = floor( sqrt( x ) ) for unsigned integers exactly.  This
   is based on the fixed point iteration:

     y' = (y + x/y) / 2

   In continuum math, this converges quadratically to sqrt(x).  This is
   a useful starting point for a method because we have a relatively low
   cost unsigned integer division in the machine model and the
   operations and intermediates in this calculation all have magnitudes
   smaller than x (so limited concern about overflow issues).

   We don't do this iteration in integer arithmetic directly because the
   iteration has two roundoff errors while the actual result only has
   one (the floor of the continuum value).  As such, even if it did
   converge in integer arithmetic, probably would not always converge
   exactly.

   We instead combine the two divisions into one, yielding single round
   off error iteration:

     y' = floor( (y^2 + x) / (2 y) )

   As y has about half the width of x given a good initial guess, 2 y
   will not overflow and y^2 + x will be ~2 x and thus any potential
   intermediate overflow issues are cheap to handle.  If this converges,
   at convergence:

        y = (y^2 + x - r) / (2 y)
     -> 2 y^2 = y^2 + x - r
     -> y^2 = x - r

   for some r in [0,2 y-1].  We note that if y = floor( sqrt( x ) )
   exactly though:

        y^2 <= x < (y+1)^2
     -> y^2 <= x < y^2 + 2 y + 1
     -> y^2  = x - r'

   for some r' in [0,2 y].  r' is r with the element 2 y added.  And it
   is possible to have y^2 = x - 2 y.  Namely if x+1 = z^2 for integer
   z, this becomes y^2 + 2 y + 1 = z^2 -> y = z-1.  That is, when
   x = z^2 - 1 for integral z, the relationship can never converge.  If
   we instead used a denominator of 2y+1 in the iteration, r would have
   the necessary range:

     y' = floor( (y^2 + x) / (2 y + 1) )

   At convergence we have:

        y = (y^2 + x - r) / (2 y+1)
     -> 2 y^2 + y = (y^2 + x - r)
     -> y^2 = x-y-r

   for some r in [0,2 y].  This isn't quite right but we change the
   recurrence numerator to compensate:

     y' = floor( (y^2 + y + x) / (2 y + 1) )
  
   At convergence we now have:

     y^2 = x-r

   for some r in [0,2 y].  That is, at convergence y = floor( sqrt(x) )
   exactly!  The addition of y to the numerator has not made
   intermediate overflow much more difficult to deal with either as y
   <<< x for large x.  So to compute this without intermediate overflow,
   we compute the terms individually and then combine the remainders
   appropriately.  x/(2y+1) term is trivial.  The other term,
   (y^2+y)/(2y+1) is asymptotically approximately y/2.  Breaking it into
   its asymptotic and residual:

      (y^2 + y) / (2y+1) = y/2 + ( y^2 + y - (y/2)(2y+1) ) / (2y+1)
                         = y/2 + ( y^2 + y - y^2 - y/2   ) / (2y+1)
                         = y/2 + (y/2) / (2y+1)

   For even y, y/2 = y>>1 = yh and we have the partial quotient yh and
   remainder yh.  For odd y, we have:

                         = yh + (1/2) + (yh+(1/2)) / (2y+1)
                         = yh + ((1/2)(2y+1)+yh+(1/2)) / (2y+1)
                         = yh + (y+yh+1) / (2y+1)

   with partial quotent yh and remainder y+yh+1.  This yields the
   iteration:

     y ~ sqrt(x)                               // <<< INT_MAX for all x
     for(;;) {
       d  = 2*y + 1;
       qx = x / d; rx = x - qx*d;              // Compute x  /(2y+1), rx in [0,2y]
       qy = y>>1;  ry = (y&1) ? (y+yh+1) : yh; // Compute y^2/(2y+1), ry in [0,2y]
       q  = qx+qy; r  = rx+ry;                 // Combine partials, r in [0,4y]
       if( r>=d ) q++, r-=d;                   // Handle carry (at most 1), r in [0,2y]
       if( y==q ) break;                       // At convergence y = floor(sqrt(x))
       y = q;
     }

   The better the initial guess, the faster this will converge.  Since
   convergence is still quadratic though, it will converge even given
   very simple guesses.  We use:

     y = sqrt(x) = sqrt( 2^n + d ) <~ 2^(n/2)
   
   where n is the index of the MSB and d is in [0,2^n) (i.e. is n bits
   wide).  Thus:

     y ~ 2^(n>>1) if n is even and 2^(n>>1) sqrt(2) if n is odd

   and we can do a simple fixed point calculation to compute this.

   For small values of x, we encode a 20 entry 3-bit wide lookup table
   in a 64-bit constant and just do a quick lookup.
   
   For types narrower than 64-bit, we can do the iteration portably in a
   wider type and simplify the operation.  We also do this if the
   underlying platform supports 128-bit wide types.

   FIXME: USE THE X86 FPU TO GET A REALLY GOOD INITIAL GUESS? */

FD_FN_CONST static inline uint
fd_uint_sqrt( uint x ) {
  if( x<21U ) return (uint)((0x49246db6da492248UL >> (3*(int)x)) & 7UL);
  int  n = fd_uint_find_msb( x );
  uint y = ( ((n & 1) ? 0xb504U /* floor( 2^15 sqrt(2) ) */ : 0x8000U /* 2^15 */) >> (15-(n>>1)) );
  ulong _y = (ulong)y;
  ulong _x = (ulong)x;
  for(;;) {
    ulong _z = (_y*_y + _y + _x) / ((_y<<1)+1UL);
    if( _z==_y ) break;
    _y = _z;
  }
  return (uint)_y;
}

#if FD_HAS_INT128

FD_FN_CONST static inline ulong
fd_ulong_sqrt( ulong x ) {
  if( x<21UL ) return (0x49246db6da492248UL >> (3*(int)x)) & 7UL;
  int   n = fd_ulong_find_msb( x );
  ulong y = ((n & 1) ? 0xb504f333UL /* floor( 2^31 sqrt(2) ) */ : 0x80000000UL /* 2^31 */) >> (31-(n>>1));
  uint128 _y = (uint128)y;
  uint128 _x = (uint128)x;
  for(;;) {
    uint128 _z = (_y*_y + _y + _x) / ((_y<<1)+(uint128)1);
    if( _z==_y ) break;
    _y = _z;
  }
  return (ulong)_y;
}

#else

FD_FN_CONST static inline ulong
fd_ulong_sqrt( ulong x ) {
  if( x<21UL ) return (0x49246db6da492248UL >> (3*(int)x)) & 7UL;
  int   n = fd_ulong_find_msb( x );
  ulong y = ((n & 1) ? 0xb504f333UL /* floor( 2^31 sqrt(2) ) */ : 0x80000000UL /* 2^31 */) >> (31-(n>>1));
  for(;;) {
    ulong d = (y<<1); d++;
    ulong qx = x / d; ulong rx = x - qx*d;
    ulong qy = y>>1;  ulong ry = fd_ulong_if( y & 1UL, y+qy+1UL, qy );
    ulong q  = qx+qy; ulong r  = rx+ry;
    q += (ulong)(r>=d);
    if( y==q ) break;
    y = q;
  }
  return y;
}

#endif

/* FIXME: CONSIDER USING A TABLE LOOKUP UCHAR AND, TO A LESSER EXTENT,
   USHORT FOR THESE */

FD_FN_CONST static inline uchar  fd_uchar_sqrt ( uchar  x ) { return (uchar )fd_uint_sqrt( (uint)x ); }
FD_FN_CONST static inline ushort fd_ushort_sqrt( ushort x ) { return (ushort)fd_uint_sqrt( (uint)x ); }

/* These return floor( sqrt( x ) ), undefined behavior for negative x. */

FD_FN_CONST static inline schar fd_schar_sqrt( schar x ) { return (schar)fd_uchar_sqrt ( (uchar )x ); }
FD_FN_CONST static inline short fd_short_sqrt( short x ) { return (short)fd_ushort_sqrt( (ushort)x ); }
FD_FN_CONST static inline int   fd_int_sqrt  ( int   x ) { return (int  )fd_uint_sqrt  ( (uint  )x ); }
FD_FN_CONST static inline long  fd_long_sqrt ( long  x ) { return (long )fd_ulong_sqrt ( (ulong )x ); }

/* These return the floor( re sqrt(x) ) */

FD_FN_CONST static inline schar fd_schar_re_sqrt( schar x ) { return fd_schar_if( x>(schar)0,  (schar)fd_uchar_sqrt ( (uchar )x ), (schar)0  ); }
FD_FN_CONST static inline short fd_short_re_sqrt( short x ) { return fd_short_if( x>(short)0,  (short)fd_ushort_sqrt( (ushort)x ), (short)0  ); }
FD_FN_CONST static inline int   fd_int_re_sqrt  ( int   x ) { return fd_int_if  ( x>       0,  (int  )fd_uint_sqrt  ( (uint  )x ),        0  ); }
FD_FN_CONST static inline long  fd_long_re_sqrt ( long  x ) { return fd_long_if ( x>       0L, (long )fd_ulong_sqrt ( (ulong )x ),        0L ); }

/* These return the floor( sqrt( |x| ) ) */

FD_FN_CONST static inline schar fd_schar_sqrt_abs( schar x ) { return (schar)fd_uchar_sqrt ( fd_schar_abs( x ) ); }
FD_FN_CONST static inline short fd_short_sqrt_abs( short x ) { return (short)fd_ushort_sqrt( fd_short_abs( x ) ); }
FD_FN_CONST static inline int   fd_int_sqrt_abs  ( int   x ) { return (int  )fd_uint_sqrt  ( fd_int_abs  ( x ) ); }
FD_FN_CONST static inline long  fd_long_sqrt_abs ( long  x ) { return (long )fd_ulong_sqrt ( fd_long_abs ( x ) ); }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_math_fd_sqrt_h */
