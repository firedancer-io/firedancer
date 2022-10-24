#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h

#include "fd_ed25519.h"

/* Helpers for writing implementations ********************************/

/* FD_MASK_{LSB,MSB} returns a ulong with the {least,most} n significant
   bits set. */

#define FD_MASK_LSB(n) ((1UL<<(n))-1UL)
#define FD_MASK_MSB(n) (~FD_MASK_LSB(64-(n)))

FD_PROTOTYPES_BEGIN

/* load_n loads the n (for n in 1:8) bytes at p into the least
   significant bytes of a ulong and zero pads the rest of the ulong and
   returns the result.  load_n_fast is the same but assumes it is safe
   to tail read a limited number of bytes past n in the buffer. */

FD_FN_PURE static inline ulong fd_load_1( uchar const * p ) { return (ulong)*                p; }
FD_FN_PURE static inline ulong fd_load_2( uchar const * p ) { return (ulong)*(ushort const *)p; }
FD_FN_PURE static inline ulong fd_load_4( uchar const * p ) { return (ulong)*(uint   const *)p; }
FD_FN_PURE static inline ulong fd_load_8( uchar const * p ) { return        *(ulong  const *)p; }

FD_FN_PURE static inline ulong fd_load_3( uchar const * p ) { return fd_load_2( p ) | (fd_load_1( p+2UL )<<16); }
FD_FN_PURE static inline ulong fd_load_5( uchar const * p ) { return fd_load_4( p ) | (fd_load_1( p+4UL )<<32); }
FD_FN_PURE static inline ulong fd_load_6( uchar const * p ) { return fd_load_4( p ) | (fd_load_2( p+4UL )<<32); }
FD_FN_PURE static inline ulong fd_load_7( uchar const * p ) { return fd_load_6( p ) | (fd_load_1( p+6UL )<<48); }

#define fd_load_1_fast fd_load_1 /* No tail read */
#define fd_load_2_fast fd_load_2 /* No tail read */
#define fd_load_4_fast fd_load_4 /* No tail read */
#define fd_load_8_fast fd_load_8 /* No tail read */

FD_FN_PURE static inline ulong fd_load_3_fast( uchar const * p ) { return fd_load_4( p ) & FD_MASK_LSB(24); } /* Tail read 1B */
FD_FN_PURE static inline ulong fd_load_5_fast( uchar const * p ) { return fd_load_8( p ) & FD_MASK_LSB(40); } /* Tail read 3B */
FD_FN_PURE static inline ulong fd_load_6_fast( uchar const * p ) { return fd_load_8( p ) & FD_MASK_LSB(48); } /* Tail read 2B */
FD_FN_PURE static inline ulong fd_load_7_fast( uchar const * p ) { return fd_load_8( p ) & FD_MASK_LSB(56); } /* Tail read 1B */

FD_PROTOTYPES_END

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
