#ifndef HEADER_fd_src_util_bits_fd_uwide_h
#define HEADER_fd_src_util_bits_fd_uwide_h

/* Useful operations for unsigned 128-bit integer operations on
   platforms without 128-bit wide integer support.  A 128-bit wide
   number is represented as a pair of ulong.  In the notation below
   <xh,xl> == xh 2^64 + xl where xh and xl are ulong's.  Imported from
   pyth. */

#include "fd_bits.h"

FD_PROTOTYPES_BEGIN

/* fd_uwide_add computes co 2^128 + <zh,zl> = <xh,xl> + <yh,yl> + ci
   exactly.  Returns the carry out.  Note that the carry in / carry
   operations should be compile time optimized out if ci is 0 at compile
   time on input and/or return value is not used.  Assumes _zh and _zl
   are valid (e.g.  non-NULL and non-overlapping).  Ignoring carry
   in/out related operations costs 4 u64 adds, 1 u64 compare and 1 u64
   conditional increment. */

static inline ulong
fd_uwide_add( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
              ulong               xh,  ulong               xl,
              ulong               yh,  ulong               yl,
              ulong               ci ) {
  ulong zh = xh; ulong zl = xl;
  ulong ct;      ulong co;
  zl += ci; ct  = (ulong)(zl<ci);
  zl += yl; ct += (ulong)(zl<yl);
  zh += ct; co  = (ulong)(zh<ct);
  zh += yh; co += (ulong)(zh<yh);
  *_zh = zh; *_zl = zl; return co;
}

/* fd_uwide_inc computes <zh,zl> = (<xh,xl> + y) mod 2^128 exactly (a
   common use of the above) */

static inline void
fd_uwide_inc( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
              ulong               xh,  ulong               xl,
              ulong               y ) {
  ulong zl = xl + y;
  ulong zh = xh + (zl<xl);
  *_zh = zh; *_zl = zl;
}

/* fd_uwide_sub compute <zh,zl> = bo 2^128 + <xh,xl> - <yh,yl> - bi
   exactly.  Returns the borrow out.  Note that the borrow in / borrow
   operations should be compile time optimized out if b is 0 at compile
   time on input and/or return value is not used.  Assumes _zh and _zl
   are valid (e.g.  non-NULL and non-overlapping).  Ignoring borrow
   in/out related operations costs 4 u64 subs, 1 u64 compare and 1 u64
   conditional decrement. */

static inline ulong
fd_uwide_sub( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
              ulong               xh,  ulong               xl,
              ulong               yh,  ulong               yl,
              ulong               bi ) {
  ulong zh = xh; ulong zl = xl;
  ulong bt;      ulong bo;
  bt  = (ulong)(zl<bi); zl -= bi;
  bt += (ulong)(zl<yl); zl -= yl;
  bo  = (ulong)(zh<bt); zh -= bt;
  bo += (ulong)(zh<yh); zh -= yh;
  *_zh = zh; *_zl = zl; return bo;
}

/* fd_uwide_dec computes <zh,zl> = (<xh,xl> - y) mod 2^128 exactly (a
   common use of the above) */

static inline void
fd_uwide_dec( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
              ulong               xh,  ulong               xl,
              ulong               y ) {
  ulong zh = xh - (ulong)(y>xl);
  ulong zl = xl - y;
  *_zh = zh; *_zl = zl;
}

/* fd_uwide_mul computes <zh,zl> = x*y exactly, will be in
   [0,2^128-2^65+1].  Assumes _zh and _zl are valid (e.g. non-NULL and
   non-overlapping).  Cost is 4 u32*u32->u64 muls, 4 u64 adds, 2 u64
   compares, 2 u64 conditional increments, 8 u64 u32 word extractions. */

static inline void
fd_uwide_mul( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
              ulong               x,
              ulong               y ) {
  ulong x1  = x>>32;  ulong x0  = (ulong)(uint)x;   /* both 2^32-1 @ worst case (x==y==2^64-1) */
  ulong y1  = y>>32;  ulong y0  = (ulong)(uint)y;   /* both 2^32-1 @ worst case */

  ulong w0  = x0*y0;  ulong w1  = x0*y1;            /* both 2^64-2^33+1 @ worst case */
  ulong w2  = x1*y0;  ulong w3  = x1*y1;            /* both 2^64-2^33+1 @ worst case */

  ulong w1h = w1>>32; ulong w1l = (ulong)(uint)w1;  /* w1h 2^32-2, w1l 1 @ worst case */
  ulong w2h = w2>>32; ulong w2l = (ulong)(uint)w2;  /* w2h 2^32-2, w2l 1 @ worst case */

  ulong zh  = w1h + w2h + w3;                       /* 2^64-3                     @ worst case */
  ulong t0  = w0 + (w1l<<32); zh += (ulong)(t0<w0); /* t 2^64-2^32+1, zh 2^64 - 3 @ worst case */
  ulong zl  = t0 + (w2l<<32); zh += (ulong)(zl<t0); /* t 1,           zh 2^64 - 2 @ worst case */
  /* zh 2^64 + zl == 2^128-2^65+1 @ worst case */

  *_zh = zh; *_zl = zl;
}

/* fd_uwide_find_msb returns floor( log2 <xh,xl> ) exactly.  Assumes
   <xh,xl> is not 0. */

static inline int
fd_uwide_find_msb( ulong xh,
                   ulong xl ) {
  int off = 0;
  if( xh ) { off = 64; xl = xh; } /* FIXME: BRANCHLESS? */
  return off + fd_ulong_find_msb( xl );
}

/* fd_uwide_find_msb_def same as the fd_uwide_find_msb but returns def
   is <xh,xl> is 0.  FIXME: BRANCHLESS? */

static inline int fd_uwide_find_msb_def( ulong xh, ulong xl, int def ) { return (xh|xl) ? fd_uwide_find_msb(xh,xl) : def; }

/* fd_uwide_sl computes <zh,zl> = <xh,xl> << s.  Assumes _zh and _zl are
   valid (e.g.  non-NULL and non-overlapping) and s is non-negative.
   Large values of s are fine (shifts to zero).  Returns the inexact
   flag (will be 0 or 1) which indicates if any non-zero bits of <xh,xl>
   were lost in the process.  Note that inexact handling and various
   cases should be compile time optimized out if if s is known at
   compile time on input and/or return value is not used.  Ignoring
   inexact handling and assuming compile time s, for the worst case s,
   cost is 3 u64 shifts and 1 u64 bit or.  FIXME: CONSIDER HAVING AN
   INVALID FLAG FOR NEGATIVE S?  FIXME: BRANCHLESS? */

static inline int
fd_uwide_sl( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
             ulong               xh,  ulong               xl,
             int                 s ) {
  if( s>=128 ) {                        *_zh = 0UL;             *_zl = 0UL;   return !!(xh| xl    ); }
  if( s>  64 ) { s -= 64; int t = 64-s; *_zh =  xl<<s;          *_zl = 0UL;   return !!(xh|(xl>>t)); }
  if( s== 64 ) {                        *_zh =  xl;             *_zl = 0UL;   return !! xh;          }
  if( s>   0 ) {          int t = 64-s; *_zh = (xh<<s)|(xl>>t); *_zl = xl<<s; return !!(xh>>t);      }
  /*  s==  0 */                         *_zh =  xh;             *_zl = xl;    return 0;
}

/* fd_uwide_sr compute <zh,zl> = <xh,xl> >> s.  Assumes _zh and _zl are
   valid (e.g. non-NULL and non-overlapping) and s is non-negative.
   Large values of s are fine (shifts to zero).  Returns the inexact
   flag (will be 0 or 1) which indicates if any non-zero bits of <xh,xl>
   were lost in the process.  Note that inexact handling and various
   cases should be compile time optimized out if if s is known at
   compile time on input and/or return value is not used.  Ignoring
   inexact handling and assuming compile time s, for the worst case s,
   cost is 3 u64 shifts and 1 u64 bit or.  (FIXME: CONSIDER HAVING AN
   INVALID FLAG FOR NEGATIVE S AND/OR MORE DETAILED INEXACT FLAGS TO
   SIMPLIFY IMPLEMENTING FIXED AND FLOATING POINT ROUNDING MODES?) */

static inline int
fd_uwide_sr( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
             ulong               xh,  ulong                xl,
             int                 s ) {
  if( s>=128 ) {                        *_zh = 0UL;   *_zl = 0UL;             return !!( xh    |xl); }
  if( s>  64 ) { s -= 64; int t = 64-s; *_zh = 0UL;   *_zl =  xh>>s;          return !!((xh<<t)|xl); }
  if( s== 64 ) {                        *_zh = 0UL;   *_zl =  xh;             return !!         xl;  }
  if( s>   0 ) {          int t = 64-s; *_zh = xh>>s; *_zl = (xl>>s)|(xh<<t); return !!( xl<<t    ); }
  /*  s==  0 */                         *_zh = xh;    *_zl =  xl;             return 0;
}

/* FIXME: LOOK FOR IMPROVED DIV ALGORITHMICS HERE! */

/* fd_uwide_private_div_approx_init/fd_uwide_private_div_approx computes
   a ~32-bit accurate approximation qa of q = floor(n 2^64 / d) where d
   is in [2^63,2^64) cheaply.  Approximation will be at most q.

   In the general case, qa is up to 65 bits wide (worst case is n=2^64-1
   and d=2^63 such that q is 2^65-2 and qa is precise enough to need 65
   bits too).  The implementation here assumes n is is less than d so
   that q and qa are both known to fit within 64 bits.

   Cost to setup for a given d is approximately a 1 u64 u32 extract, 1
   u64 increment, 1 u64 neg, 1 u64/u64 div, 1 u64 add.  Cost per n/d
   afterward is 2 u32*u32->u64 mul, 2 u64 add, 1 u64 u32 extract.

   Theory: Let q d + r = n 2^64 where q = floor( n 2^64 / d ).  Note r
   is in [0,d).  Break d into d = dh 2^32 + dl where dh and dl are
   32-bit words:
     q+r/d = n 2^64 / d =  n 2^64 / ( dh 2^32 + dl )
                        =  n 2^64 / ( (dh+1) 2^32 - (2^32-dl) ) ... dh+1 can be computed without overflow, 2^32-dl is positive
                        >  n 2^64 / ( (dh+1) 2^32 )
                        >= n floor( 2^64/(dh+1) ) / 2^32
   Note that floor( 2^64/(dh+1) ) is in [2^32,2^33-4].  This suggests
   letting:
     2^32 + m = floor( 2^64/(dh+1) )
   where m is in [0,2^32-4] (fits in a uint).  Then we have:
     q+r/d > n (2^32 + m) / 2^32
           = n + n m / 2^32
   Similarly breaking n into n = nh 2^32 + nl:
     q+r/d > n + (nh m) + (nl m/2^32)
           >= n + nh m + floor( nl m / 2^32 )
   We get:
     q+r/d > n + nh*m + ((nl*m)>>32)
   And, as q is integral, r/d is less than 1 and the right hand side is
   integral:
     q >= qa
   where:
     qa = n + nh*m + (((nl*m)>>32)
   and:
     m  = floor( 2^64 / (dh+1) ) - 2^32

   To compute m efficiently, note:
     m  = floor( 1 + (2^64-(dh+1))/(dh+1) ) - 2^32
        = floor( (2^64-(dh+1))/(dh+1) ) - (2^32-1)
   and in "C style" modulo 2^64 arithmetic, 2^64 - x = -x.  This yields:
     m  = (-(dh+1))/(dh+1) - (2^32-1)

   Applications should avoid using these directly.  (They might be
   removed in the future, different approximations might get used for
   different targets, might be changed to be faster but less accurate or
   slower and more accurate, etc.) */

static inline ulong                           /* In [0,2^32) */
fd_uwide_private_div_approx_init( ulong d ) { /* d in [2^63,2^64) */
  ulong m = (d>>32) + 1UL;                    /* m = dh+1 and is in (2^31,2^32]  ... exact */
  return ((-m)/m) - (ulong)UINT_MAX;          /* m = floor( 2^64/(dh+1) ) - 2^32 ... exact */
}

static inline ulong                      /* In [n,2^64) and <= floor(n 2^64/d) */
fd_uwide_private_div_approx( ulong n,    /* In [0,d) */
                             ulong m ) { /* Output of fd_uwide_private_div_approx_init for the desired d */
  ulong nh = n>>32;
  ulong nl = (ulong)(uint)n;
  return n + nh*m + ((nl*m)>>32);
}

/* fd_uwide_div computes zh 2^64 + zl = floor( (xh 2^64 + xl) / y ).
   Assumes _zh and _zl are valid (e.g. non-NULL and non-overlapping).
   Requires y to be non-zero.  Returns the exception flag if y is 0
   (<zh,zl>=0 in this case).  This is not very cheap and cost is highly
   variable depending on properties of both n and d.  Worst case is
   roughly ~3 u64/u64 divides, ~24 u64*u64->u64 muls plus other minor
   ops.

   Breakdown in worst case 1 u64 log2, 2 u64/u64 div, 1 u64*u64->u64
   mul, 1 u64 sub, 1 int sub, 1 u128 variable shift, 1 1 u64 variable
   shift, 1 u64 div approx init, 4*(1 u64 div approx, 1 u64*u64->u128
   mul, 1 u128 sub) plus various operations to facilitating shortcutting
   (e.g. when xh is zero, cost is 1 u64/u64 div). */

FD_FN_UNUSED static int /* Work around -Winline */
fd_uwide_div( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
              ulong               xh,  ulong               xl,
              ulong               y ) {

  /* Simple cases (y==0, x==0 and y==2^n) */

  if( FD_UNLIKELY( !y  ) ) { *_zh = 0UL; *_zl = 0UL;    return 1; }
  if( FD_UNLIKELY( !xh ) ) { *_zh = 0UL; *_zl = xl / y; return 0; }

  int n = fd_ulong_find_msb( y );
  if( FD_UNLIKELY( !fd_ulong_pop_lsb(y) ) ) { fd_uwide_sr( _zh,_zl, xh,xl, n ); return 0; }

  /* General case ... compute zh noting that:
       <zh,zl> = floor( (xh 2^64 + xl) / y )
               = floor( ((qh y + rh) 2^64 + xl) / y )
     where xh = qh y + rh and qh is floor(xh/y), rh = xh%y and rh is in
     [0,y).  Thus:
       = qh 2^64 + floor( (rh 2^64 + xl) / y )
     where the right term is less that 2^64 such that zh is qh and
     zl = floor( (rh 2^64 + xl) / y ). */

  ulong qh = xh / y;
  ulong rh = xh - qh*y;

  /* Simple zl shortcut */

  if( FD_UNLIKELY( !rh ) ) { *_zh = qh; *_zl = xl / y; return 0; }

  /* At this point, zh is qh and zl is floor( (rh 2^64 + xl) / y ) where
     rh is in (0,y) and y is a positive non-power of 2.

     Normalize this by noting for:
       q=n/d; r=n-q*d=n%d
     we have:
       -> n   = q d + r where q = floor(n/d) and r in [0,d).
       -> n w = q d w + r w for some integer w>0
     That is, if we scale up both n and d by w, it doesn't affect q (it
     just scales the remainder).  We use a scale factor of 2^s on
     <rh,xl> and y such that y will have its most significant bit set.
     This will not cause <rh,xl> to overflow as rh is less than y at
     this point. */

  int s = 63-n;
  ulong nh, nl; fd_uwide_sl( &nh,&nl, rh,xl, s );
  ulong d = y << s;

  /* At this point zh = qh and zl is floor( (nh 2^64 + nl) / d ) where
     nh is in (0,d) and d is in (2^63,2^64). */

  ulong m  = fd_uwide_private_div_approx_init( d );
  ulong eh = nh; ulong el = nl;
  ulong ql = 0UL;
  do {

    /* At this point, n-ql*d has an error of <eh,el> such that:
         d < 2^64 <= <eh,el>
       (i.e. eh is non-zero).  If we increment ql by the correction
       floor(<eh,el>/d), we'd be at the solution but computing this is
       as hard as the original problem.  We do have the ability to
       very quickly compute a ~32-bit accurate estimate dqest of
       floor(<eh,0>/d) such that:
         1 <= eh <= dqest <= floor(<eh,0>/d) <= floor(<eh,el)/d).
       so we use that as our increment.  Practically, this loop will
       require at most ~4 iterations. */

    ql += fd_uwide_private_div_approx( eh, m ); /* Guaranteed to make progress if eh > 0 */
    fd_uwide_mul( &eh,&el, ql, d );             /* <eh,el> = ql*d */
    fd_uwide_sub( &eh,&el, nh,nl, eh,el, 0UL ); /* <eh,el> = <nh,nl> - ql d */
  } while( eh );

  /* At this point, n - ql*d has an error less than 2^64 so we can
     directly compute the remaining correction. */

  ql += el/d;

  *_zh = qh; *_zl = ql; return 0;
}

/* fd_uwide_divrem is same as the above but returns the value of the
   remainder too.  For non-zero y, remainder will be in [0,y).  If y==0,
   returns <zh,zl>=0 with a remainder of ULONG_MAX (to signal error). */

static inline ulong
fd_uwide_divrem( ulong * FD_RESTRICT _zh, ulong * FD_RESTRICT _zl,
                 ulong               xh,  ulong               xl,
                 ulong               y ) {

  if( FD_UNLIKELY( !y  ) ) { *_zh = 0UL; *_zl = 0UL; return ULONG_MAX; }
  if( FD_UNLIKELY( !xh ) ) { ulong ql = xl / y; ulong r = xl - ql*y; *_zh = 0UL; *_zl = ql; return r; }

  int n = fd_ulong_find_msb( y );
  if( FD_UNLIKELY( !fd_ulong_pop_lsb(y) ) ) { int s = 64-n; fd_uwide_sr( _zh,_zl, xh,xl, n ); return n ? ((xl << s) >> s) : 0UL; }

  ulong qh = xh / y;
  ulong rh = xh - qh*y;

  if( FD_UNLIKELY( !rh ) ) { ulong ql = xl / y; ulong r = xl - ql*y; *_zh = qh; *_zl = ql; return r; }

  int s = 63-n;
  ulong nh, nl; fd_uwide_sl( &nh,&nl, rh,xl, s );
  ulong d = y << s;

  ulong m  = fd_uwide_private_div_approx_init( d );
  ulong eh = nh; ulong el = nl;
  ulong ql = 0UL;
  do {
    ql += fd_uwide_private_div_approx( eh, m );
    fd_uwide_mul( &eh,&el, ql, d );
    fd_uwide_sub( &eh,&el, nh,nl, eh,el, 0UL );
  } while( eh );

  ulong dq = el / d;
  ulong r  = (el - dq*d) >> s;
  ql += dq;

  *_zh = qh; *_zl = ql; return r;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_bits_fd_uwide_h */

