#include "fd_x25519.h"

#ifndef FD_X25519_IMPL
#if FD_HAS_GFNI /* TODO: MAKE AVX-512 FLAG */
#define FD_X25519_IMPL 1
#else
#define FD_X25519_IMPL 0
#endif
#endif

#if FD_X25519_IMPL==0 /* Original scalar and AVX implementations */

#include "fd_ed25519_private.h"

#ifndef FD_X25519_VECTORIZE
#if FD_ED25519_FE_IMPL==1
#define FD_X25519_VECTORIZE 1
#else
#define FD_X25519_VECTORIZE 0
#endif
#endif

/* fd_x25519_basepoint is the canonical Curve25519 base point. */

static uchar const fd_x25519_basepoint[ 32 ] = { 9 };

static void *
fd_x25519_scalar_mul( void * dst,
                      void const * scalar,
                      void const * point ) {

  uchar e[ 32UL ];
  memcpy( e, scalar, 32UL );
  e[  0 ] = (uchar)( e[  0 ] & 0xf8 );
  e[ 31 ] = (uchar)( e[ 31 ] & 0x7f );
  e[ 31 ] = (uchar)( e[ 31 ] | 0x40 );

  fd_ed25519_fe_t x1;
  fd_ed25519_fe_frombytes( &x1, point );

  fd_ed25519_fe_t x2;
  fd_ed25519_fe_1( &x2 );

  fd_ed25519_fe_t x3;
  fd_ed25519_fe_copy( &x3, &x1 );

  fd_ed25519_fe_t z2={0};
  fd_ed25519_fe_t z3;
  fd_ed25519_fe_1( &z3 );

  fd_ed25519_fe_t tmp0;
  fd_ed25519_fe_t tmp1;

  int swap = 0;
  for( long pos=254UL; pos>=0; pos-- ) {
    int b = e[ pos / 8L ] >> ( pos & 7L );
    b &= 1;
    swap ^= b;
    fd_ed25519_fe_swap_if( &x2, &x3, swap );
    fd_ed25519_fe_swap_if( &z2, &z3, swap );
    swap = b;

    fd_ed25519_fe_sub( &tmp0, &x3,   &z3   );
    fd_ed25519_fe_sub( &tmp1, &x2,   &z2   );
    fd_ed25519_fe_add( &x2,   &x2,   &z2   );
    fd_ed25519_fe_add( &z2,   &x3,   &z3   );

#   if FD_X25519_VECTORIZE /* Note that okay to use less efficient squaring because we get it for free in unused vector lanes */
    fd_ed25519_fe_mul4( &z3,   &tmp0, &x2,
                        &z2,   &z2,   &tmp1,
                        &tmp0, &tmp1, &tmp1,
                        &tmp1, &x2,   &x2   );
#   else /* Use more efficient squaring if scalar implementation */
    fd_ed25519_fe_mul( &z3,   &tmp0, &x2   );
    fd_ed25519_fe_mul( &z2,   &z2,   &tmp1 );
    fd_ed25519_fe_sq ( &tmp0, &tmp1        );
    fd_ed25519_fe_sq ( &tmp1, &x2          );
#   endif
    fd_ed25519_fe_add( &x3,   &z3,   &z2   );
    fd_ed25519_fe_sub( &z2,   &z3,   &z2   );
#   if FD_X25519_VECTORIZE /* See note above */
    fd_ed25519_fe_mul2( &x2,   &tmp1, &tmp0,
                        &z2,   &z2,   &z2   );
#   else
    fd_ed25519_fe_mul( &x2,   &tmp1, &tmp0 );
    fd_ed25519_fe_sq ( &z2,   &z2          );
#   endif
    fd_ed25519_fe_sub( &tmp1, &tmp1, &tmp0 );

    fd_ed25519_fe_mul121666( &z3, &tmp1 );
    fd_ed25519_fe_add( &tmp0, &tmp0, &z3   );
#   if FD_X25519_VECTORIZE /* See note above */
    fd_ed25519_fe_mul3( &x3,   &x3,   &x3,
                        &z3,   &x1,   &z2,
                        &z2,   &tmp1, &tmp0 );
#   else
    fd_ed25519_fe_sq ( &x3,   &x3          );
    fd_ed25519_fe_mul( &z3,   &x1,   &z2   );
    fd_ed25519_fe_mul( &z2,   &tmp1, &tmp0 );
#   endif
  }

  fd_ed25519_fe_swap_if( &x2, &x3, swap );
  fd_ed25519_fe_swap_if( &z2, &z3, swap );

  fd_ed25519_fe_invert( &z2, &z2 );
  fd_ed25519_fe_mul( &x2, &x2, &z2 );

  fd_ed25519_fe_tobytes( (uchar *)dst, &x2 );
  return dst;
}

void *
fd_x25519_public( void *       self_public_key,
                  void const * self_private_key ) {
  fd_x25519_exchange( self_public_key, self_private_key, fd_x25519_basepoint );
  return self_public_key;
}

void *
fd_x25519_exchange( void *       secret,
                    void const * self_private_key,
                    void const * peer_public_key ) {

  fd_x25519_scalar_mul( secret, self_private_key, peer_public_key );
  uchar * out = (uchar *)secret;

  /* Reject low order points */
  int is_zero = 1;
  for( ulong i=0UL; i<32UL; i++ )
    is_zero &= ( !out[ i ] );
  if( FD_UNLIKELY( is_zero ) )
    return NULL;

  return out;
}

#else /* AVX-512 accelerated implementation */

#include "avx512/fd_r43x6.h"

/* IETF RFC 7748 Section 5 (page 9) */

static void *
fd_x25519_scalar_mul( void *       _r,
                      void const * _k,
                      void const * _u ) {

  /* These macros make it easy to use different field element
     representations without needing to change the actual code. */

# define FE_T            r43x6_t
# define LD(m)           r43x6_unpack( wv_ldu( (m) ) )                           /* uint256   -> unpacked (subset of unreduced) */
# define ST(x,m)         wv_stu( (m), r43x6_pack( r43x6_mod_unreduced( (x) ) ) ) /* unreduced -> uint256 in [0,p) */
# define ZERO()          r43x6_zero()                                            /* reduced (subset of unreduced) */
# define ONE()           r43x6_one()                                             /* reduced (subset of unreduced) */
# define ADD(x,y)        r43x6_fold_unsigned( r43x6_add_fast( (x), (y) ) )       /* unreduced x unreduced -> unreduced */
# define SUB(x,y)        r43x6_fold_signed  ( r43x6_sub_fast( (x), (y) ) )       /* unreduced x unreduced -> unreduced */
# define MUL(x,y)        r43x6_mul_fast( (x), (y) )                              /* unreduced x unreduced -> unreduced */
# define SQR(x)          r43x6_sqr_fast( (x) )                                   /* unreduced             -> unreduced */
# define SCALEADD(a,x,y) r43x6_scaleadd_fast((a),(x),(y))                        /* [0,2^47)  x unreduced -> unreduced */
# define INVERT(x)       r43x6_invert_fast( (x) )                                /* unreduced             -> unreduced */
# define CSWAP(c,x,y)    r43x6_swap_if((c),(x),(y))                              /* branchless */

  uchar const * k = (uchar const *)_k;

  FE_T x_1  = LD( _u );                    // x_1 = u
  FE_T x_2  = ONE();                       // x_2 = 1
  FE_T z_2  = ZERO();                      // z_2 = 0
  FE_T x_3  = x_1;                         // x_3 = u
  FE_T z_3  = x_2;                         // z_3 = 1
  int  swap = 0;                           // swap = 0

  for( int t=254UL; t>=0; t-- ) {          // For t = bits-1 down to 0:
    int k_t = (k[t>>3] >> (t&7)) & 1;      //   k_t = (k >> t) & 1;
    swap ^= k_t;                           //   swap ^= k_t
    CSWAP( swap, x_2, x_3 );               //   (x_2, x_3) = cswap(swap, x_2, x_3)
    CSWAP( swap, z_2, z_3 );               //   (z_2, z_3) = cswap(swap, z_2, z_3)
    swap = k_t;                            //   swap = k_t

    /* These operations are exactly from the RFC but have been reordered
       slightly to make it easier for the compiler to extract ILP. */

    FE_T A   = ADD( x_2, z_2 );            //   A = x_2 + z_2
    FE_T B   = SUB( x_2, z_2 );            //   B = x_2 - z_2
    FE_T C   = ADD( x_3, z_3 );            //   C = x_3 + z_3
    FE_T D   = SUB( x_3, z_3 );            //   D = x_3 - z_3
    FE_T AA  = SQR( A );                   //   AA = A^2
    FE_T BB  = SQR( B );                   //   BB = B^2
    FE_T DA  = MUL( D, A );                //   DA = D * A
    FE_T CB  = MUL( C, B );                //   CB = C * B
    FE_T E   = SUB( AA, BB );              //   E = AA-BB
    FE_T F   = ADD( DA, CB );
    FE_T G   = SUB( DA, CB );
    FE_T GG  = SQR( G );
    FE_T H   = SCALEADD( AA, 121665L, E );
    /**/ x_2 = MUL( AA,  BB );             //   x_2 = AA * BB
    /**/ x_3 = SQR( F );                   //   x_3 = (DA + CB)^2
    /**/ z_3 = MUL( x_1, GG );             //   z_3 = x_1 * (DA - CB)^2
    /**/ z_2 = MUL( E, H );                //   z_2 = E * (AA + a24 * E)
  }

  CSWAP( swap, x_2, x_3 );                 // (x_2, x_3) = cswap(swap, x_2, x_3)
  CSWAP( swap, z_2, z_3 );                 // (z_2, z_3) = cswap(swap, z_2, z_3)
  ST( MUL( x_2, INVERT( z_2 ) ), _r );     // Return x_2 * (z_2^(p - 2))
  return _r;

# undef CSWAP
# undef INVERT
# undef SCALEADD
# undef SQR
# undef MUL
# undef SUB
# undef ADD
# undef ONE
# undef ZERO
# undef ST
# undef LD
# undef FE_T

}

void *
fd_x25519_exchange( void *       secret,
                    void const * self_private_key,
                    void const * peer_public_key ) {

  /* IETF RFC 7748 Section 5 (page 8) decodeScalar25519 (TODO: VECTORIZE?) */

  uchar scalar[ 32 ] __attribute__((aligned(32)));
  memcpy( scalar, self_private_key, 32UL );
  scalar[  0 ] = (uchar)( scalar[  0 ] & (uchar)248 );
  scalar[ 31 ] = (uchar)( scalar[ 31 ] & (uchar)127 );
  scalar[ 31 ] = (uchar)( scalar[ 31 ] | (uchar) 64 );

  /* TODO: decodeScalar25519 maps an arbitrary self_private_key to a
     little endian uint256 of the form:

       2^254 + 8*i for i in [0,2^251)

     The resulting value is in usually [0,p).  But two values, when
     i=2^251-2 and i=2^251-1, scalar is 2^255-16 and 2^255-8
     respectively.  These are not in [0,p) (remember p=2^255-19).

     scalar_mul itself is fine with such ... it will equivalent to
     pasing 3 and 11 for scalar.  But since these are not of the form
     produced by decodeScalar25519, it looks suspect to do so and the
     RFC is not obvious here.  Might want to reject these two scalars so
     there is no ambiguity here.  (Maybe this is implicitly covered by
     the reject low order points test below?) */

  fd_x25519_scalar_mul( secret, scalar, peer_public_key );

  return fd_ptr_if( wc_any( wv_to_wc( wv_ldu( secret ) ) ), secret, NULL ); /* Reject low order points */
}

void *
fd_x25519_public( void *       self_public_key,
                  void const * self_private_key ) {

  /* IETF RFC 7748 Section 4.1 (page 3) */

  static uchar const basepoint_u[ 32 ] __attribute__((aligned(32))) = {
    (uchar)9, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0,
    (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0,
    (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0,
    (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0,
  };

  return fd_x25519_exchange( self_public_key, self_private_key, basepoint_u );
}

#endif
