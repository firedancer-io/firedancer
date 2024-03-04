#ifndef HEADER_fd_src_ballet_ed25519_fd_curve25519_scalar_h
#define HEADER_fd_src_ballet_ed25519_fd_curve25519_scalar_h

/* fd_curve25519_scalar.h provides the public Curve25519 scalar API.

   All operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data) */

#include "../fd_ballet_base.h"

static const uchar fd_curve25519_scalar_zero[ 32 ] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static const uchar fd_curve25519_scalar_one[ 32 ] = {
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* l   = 2^252 + 27742317777372353535851937790883648493
       = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
   l-1 = 0x10...ec */
static const uchar fd_curve25519_scalar_minus_one[ 32 ] = {
  0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

FD_PROTOTYPES_BEGIN

/* fd_curve25519_scalar_reduce computes s mod l where s is a 512-bit value.  s
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
fd_curve25519_scalar_reduce( uchar       out[ static 32 ],
                             uchar const in [ static 64 ] );

/* fd_curve25519_scalar_validate checks whether the given Ed25519 scalar n
   matches the canonical byte representation.
   Not constant time and thus should not be exposed to secrets.
   Returns s if canonical, NULL otherwise. */

static inline uchar const *
fd_curve25519_scalar_validate( uchar const s[ static 32 ] ) {
  ulong s0 = *(ulong *)(&s[  0 ]);
  ulong s1 = *(ulong *)(&s[  8 ]);
  ulong s2 = *(ulong *)(&s[ 16 ]);
  ulong s3 = *(ulong *)(&s[ 24 ]);
  ulong l0 = *(ulong *)(&fd_curve25519_scalar_minus_one[  0 ]);
  ulong l1 = *(ulong *)(&fd_curve25519_scalar_minus_one[  8 ]);
  ulong l2 = *(ulong *)(&fd_curve25519_scalar_minus_one[ 16 ]);
  ulong l3 = *(ulong *)(&fd_curve25519_scalar_minus_one[ 24 ]);
  return (
    (s3 < l3)
    || ((s3 == l3) && (s2 < l2))
    || ((s3 == l3) && (s2 == l2) && (s1 < l1))
    || ((s3 == l3) && (s2 == l2) && (s1 == l1) && (s0 <= l0))
  ) ? s : NULL;
}

/* fd_curve25519_scalar_muladd computes s = (a*b+c) mod l where a, b and c
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
fd_curve25519_scalar_muladd( uchar       s[ static 32 ],
                             uchar const * a,
                             uchar const b[ static 32 ],
                             uchar const c[ static 32 ] );

static inline uchar *
fd_curve25519_scalar_mul   ( uchar *       s,
                             uchar const * a,
                             uchar const * b ) {
  return fd_curve25519_scalar_muladd( s, a, b, fd_curve25519_scalar_zero );
}

static inline uchar *
fd_curve25519_scalar_add   ( uchar *       s,
                             uchar const * a,
                             uchar const * b ) {
  return fd_curve25519_scalar_muladd( s, a, fd_curve25519_scalar_one, b );
}

static inline uchar *
fd_curve25519_scalar_sub   ( uchar *       s,
                             uchar const * a,
                             uchar const * b ) {
  //TODO implement dedicated neg/sub
  return fd_curve25519_scalar_muladd( s, fd_curve25519_scalar_minus_one, b, a );
}

static inline uchar *
fd_curve25519_scalar_neg   ( uchar *       s,
                             uchar const * a ) {
  //TODO implement dedicated neg/sub
  return fd_curve25519_scalar_muladd( s, fd_curve25519_scalar_minus_one, a, fd_curve25519_scalar_zero );
}

static inline uchar *
fd_curve25519_scalar_inv( uchar *       s,
                          uchar const * a ) {
  uchar t[ 32 ];
  // TODO: use mul chain to save ~12% https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion
  /* the bits of -2 are the same as -1, except the first few (that we skip):
     -1 = 0xEC ... = b 1110 1100 ...
     -2 = 0xEB ... = b 1110 1011 ...
                       ^ bit 7 ^ bit 0
   */
  /* bit 0 == 1 */
  fd_memcpy( t, a, 32 );
  fd_memcpy( s, a, 32 );
  /* bit 1 == 1 */
  fd_curve25519_scalar_mul( t, t, t );
  fd_curve25519_scalar_mul( s, s, t );
  /* bit 2 == 0 */
  fd_curve25519_scalar_mul( t, t, t );
  /* from bit 3 on, use -1 bits */
  for( ulong i=3; i<=252; i++ ) {
    fd_curve25519_scalar_mul( t, t, t );
    if( (fd_curve25519_scalar_minus_one[ i/8 ] & (1 << (i % 8))) ) {
      fd_curve25519_scalar_mul( s, s, t );
    }
  }
  return s;
}

static inline void
fd_curve25519_scalar_batch_inv( uchar       s     [ static 32 ], /* sz scalars */
                                uchar       allinv[ static 32 ], /* 1 scalar */
                                uchar const a     [ static 32 ], /* sz scalars */
                                ulong       sz ) {
  uchar acc[ 32 ];
  fd_memcpy( acc, fd_curve25519_scalar_one, 32 );
  for( ulong i=0; i<sz; i++ ) {
    fd_memcpy( &s[ i*32 ], acc, 32 );
    fd_curve25519_scalar_mul( acc, acc, &a[ i*32 ] );
  }

  fd_curve25519_scalar_inv( acc, acc );
  fd_memcpy( allinv, acc, 32 );

  for( int i=(int)sz-1; i>=0; i-- ) {
    fd_curve25519_scalar_mul( &s[ i*32 ], &s[ i*32 ], acc );
    fd_curve25519_scalar_mul( acc, acc, &a[ i*32 ] );
  }
}

void
fd_curve25519_scalar_wnaf( short       slides[ static 256 ], /* 256-entry */
                           uchar const n[ static 32 ],       /* 32-byte, assumes valid scalar */
                           int         bits );               /* range: [1:12], 1 = NAF */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_curve25519_scalar_h */
