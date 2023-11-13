#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h

#include "fd_ed25519.h"

/* Field element API **************************************************/

#ifndef FD_ED25519_FE_IMPL
#if FD_HAS_AVX
#define FD_ED25519_FE_IMPL 1
#else
#define FD_ED25519_FE_IMPL 0
#endif
#endif

#if FD_ED25519_FE_IMPL==0
#include "ref/fd_ed25519_fe.h"
#elif FD_ED25519_FE_IMPL==1
#include "avx/fd_ed25519_fe.h"
#else
#error "Unsupported FD_ED25519_FE_IMPL"
#endif

/* Group element API **************************************************/

/* A fd_ed25519_ge_*_t stores an ed25519 group element.  Here the group
   is the set of pairs (x,y) of field elements satisfying
     -x^2 + y^2 = 1 + d x^2y^2
   where d = -121665/121666.  Useful representations include:

     p2 (projective): (X:Y:Z)   satisfying x=X/Z, y=Y/Z
     p3 (extended):   (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT */

struct fd_ed25519_ge_p2_private {
  fd_ed25519_fe_t X[1];
  fd_ed25519_fe_t Y[1];
  fd_ed25519_fe_t Z[1];
};

typedef struct fd_ed25519_ge_p2_private fd_ed25519_ge_p2_t;

struct fd_ed25519_ge_p3_private {
  fd_ed25519_fe_t X[1];
  fd_ed25519_fe_t Y[1];
  fd_ed25519_fe_t Z[1];
  fd_ed25519_fe_t T[1];
};

typedef struct fd_ed25519_ge_p3_private fd_ed25519_ge_p3_t;

FD_PROTOTYPES_BEGIN

/* FIXME: DOCUMENT THESE */

uchar *
fd_ed25519_ge_tobytes( uchar *                    s,   /* 32 */
                       fd_ed25519_ge_p2_t const * h );

uchar *
fd_ed25519_ge_p3_tobytes( uchar *                    s,   /* 32 */
                          fd_ed25519_ge_p3_t const * h );

int
fd_ed25519_ge_frombytes_vartime( fd_ed25519_ge_p3_t * h,
                                 uchar const *        s ); /* 32 */

int
fd_ed25519_ge_frombytes_vartime_2( fd_ed25519_ge_p3_t * h0, uchar const * s0,   /* 32 */
                                   fd_ed25519_ge_p3_t * h1, uchar const * s1 ); /* 32 */

int fd_ed25519_ge_p3_is_small_order(fd_ed25519_ge_p3_t * const p);

static inline fd_ed25519_ge_p2_t *
fd_ed25519_ge_p2_0( fd_ed25519_ge_p2_t * h ) {
  fd_ed25519_fe_0( h->X );
  fd_ed25519_fe_1( h->Y );
  fd_ed25519_fe_1( h->Z );
  return h;
}

static inline fd_ed25519_ge_p3_t *
fd_ed25519_ge_p3_0( fd_ed25519_ge_p3_t * h ) {
  fd_ed25519_fe_0( h->X );
  fd_ed25519_fe_1( h->Y );
  fd_ed25519_fe_1( h->Z );
  fd_ed25519_fe_0( h->T );
  return h;
}

static inline int
fd_ed25519_ge_eq( fd_ed25519_ge_p3_t * const p,
                  fd_ed25519_ge_p3_t * const q ) {
  fd_ed25519_fe_t cmp[2];
  fd_ed25519_fe_mul( &cmp[ 0 ], p->X, q->Z );
  fd_ed25519_fe_mul( &cmp[ 1 ], q->X, p->Z );
  int x = fd_ed25519_fe_eq( &cmp[ 0 ], &cmp[ 1 ] );

  fd_ed25519_fe_mul( &cmp[ 0 ], p->Y, q->Z );
  fd_ed25519_fe_mul( &cmp[ 1 ], q->Y, p->Z );
  int y = fd_ed25519_fe_eq( &cmp[ 0 ], &cmp[ 1 ] );

  return x & y;
}

fd_ed25519_ge_p3_t *
fd_ed25519_ge_scalarmult_base( fd_ed25519_ge_p3_t * h,
                               uchar const *        a );

fd_ed25519_ge_p2_t *
fd_ed25519_ge_double_scalarmult_vartime( fd_ed25519_ge_p2_t *       r,
                                         uchar const *              a,
                                         fd_ed25519_ge_p3_t const * A,
                                         uchar const *              b );

/* User APIs **********************************************************/

/* fd_ed25519_sc_reduce computes s mod l where s is a 512-bit value.  s
   is stored in 64-byte little endian form and in points to the first
   byte of s.  l is:

     2^252 + 27742317777372353535851937790883648493.

   The result can be represented as a 256-bit value and stored in a
   32-byte little endian form.  out points to where to store the result.
   
   Does no input argument checking.  The caller takes a write interest
   in out and a read interest in in for the duration of the call.
   Returns out and, on return, out will be populated with the 256-bit
   result.  In-place operation fine. */

uchar *
fd_ed25519_sc_reduce( uchar *       out, 
                      uchar const * in );

/* fd_ed25519_sc_muladd computes s = (a*b+c) mod l where a, b and c
   are 256-bit values.  a is stored in 32-byte little endian form and a
   points to the first byte of a.  Similarly for b and c.  l is:
   
     2^252 + 27742317777372353535851937790883648493.

   The result can be represented as a 256-bit value and stored in a
   32-byte little endian form.  s points to where to store the result.

   Does no input argument checking.  The caller takes a write interest
   in s and a read interest in a, b and c for the duration of the call.
   Returns s and, on return, s will be populated with the 256-bit
   result.  In-place operation fine. */

uchar *
fd_ed25519_sc_muladd( uchar *       s,
                      uchar const * a,
                      uchar const * b,
                      uchar const * c );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h */
