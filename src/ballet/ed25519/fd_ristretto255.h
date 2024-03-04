#ifndef HEADER_fd_src_ballet_ed25519_fd_ristretto255_h
#define HEADER_fd_src_ballet_ed25519_fd_ristretto255_h

/* fd_ristretto255.h provides the public ristretto255 group element
   API.

   This API is specifically only provided for the Solana virtual machine
   syscall sol_curve_group_op (slow!).  It is guaranteed to be stable
   irrespective of underlying backend chosen (ref, avx, etc...)

   All operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data) */

#include "fd_curve25519.h"

/* fd_ristretto255 provides APIs for the ristretto255 prime order group */

static const uchar fd_ristretto255_compressed_zero[ 32 ] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* fd_ristretto255_point_t is a opaque handle to a ristretto255 group
   element.  Although it is the same type as an Ed25519 group element,
   it is unsafe to mix Ed25519 point and ristretto point APIs. */

typedef fd_ed25519_point_t fd_ristretto255_point_t;

#define fd_ristretto255_point_set_zero   fd_ed25519_point_set_zero
#define fd_ristretto255_point_set        fd_ed25519_point_set
#define fd_ristretto255_point_add        fd_ed25519_point_add
#define fd_ristretto255_point_sub        fd_ed25519_point_sub
#define fd_ristretto255_scalar_validate  fd_ed25519_scalar_validate
#define fd_ristretto255_scalar_mul       fd_ed25519_scalar_mul
#define fd_ristretto255_multi_scalar_mul fd_ed25519_multi_scalar_mul
#define fd_ristretto255_point_decompress fd_ristretto255_point_frombytes
#define fd_ristretto255_point_compress   fd_ristretto255_point_tobytes

FD_PROTOTYPES_BEGIN

uchar *
fd_ristretto255_point_tobytes( uchar                           buf[ static 32 ],
                               fd_ristretto255_point_t const * p );

/* fd_ristretto255_point_frombytes decompresses a 32-byte array into
   an element of the ristretto group h.
   It returns p on success, NULL on failure. */

fd_ristretto255_point_t *
fd_ristretto255_point_frombytes( fd_ristretto255_point_t * p,
                                  uchar const              buf[ static 32 ] );

/* fd_ristretto255_point_validate checks if a 32-byte array represents
   a valid element of the ristretto group h.
   It returns 1 on success, 0 on failure. */

static inline int
fd_ristretto255_point_validate( uchar const buf[ static 32 ] ) {
  fd_ristretto255_point_t t[1];
  return !!fd_ristretto255_point_frombytes( t, buf );
}

/* fd_ristretto255_point_eq checks if two elements of the ristretto group
   p and q are equal.
   It returns 1 on success, 0 on failure. */

static inline int
fd_ristretto255_point_eq( fd_ristretto255_point_t * const p,
                          fd_ristretto255_point_t * const q ) {
  // https://ristretto.group/details/equality.html
  fd_f25519_t cmp[2];
  fd_f25519_t x[2], y[2], _z[2], _t[2];
  fd_ed25519_point_to( &x[0], &y[0], &_z[0], &_t[0], p );
  fd_ed25519_point_to( &x[1], &y[1], &_z[1], &_t[1], q );

  fd_f25519_mul( &cmp[ 0 ], &x[0], &y[1] );
  fd_f25519_mul( &cmp[ 1 ], &x[1], &y[0] );
  int xx = fd_f25519_eq( &cmp[ 0 ], &cmp[ 1 ] );

  fd_f25519_mul( &cmp[ 0 ], &x[0], &x[1] );
  fd_f25519_mul( &cmp[ 1 ], &y[0], &y[1] );
  int yy = fd_f25519_eq( &cmp[ 0 ], &cmp[ 1 ] );

  return xx | yy;
}

/* fd_ristretto255_point_eq_neg checks if two elements of the ristretto group
   p and q are such that -p == q. This uses just 1 extra neg.
   It returns 1 on success, 0 on failure. */

static inline int
fd_ristretto255_point_eq_neg( fd_ristretto255_point_t * const p,
                              fd_ristretto255_point_t * const q ) {
  // https://ristretto.group/details/equality.html
  fd_f25519_t neg[1];
  fd_f25519_t cmp[2];
  fd_f25519_t x[2], y[2], _z[2], _t[2];
  fd_ed25519_point_to( &x[0], &y[0], &_z[0], &_t[0], p );
  fd_ed25519_point_to( &x[1], &y[1], &_z[1], &_t[1], q );

  fd_f25519_neg( neg, &x[0] );
  fd_f25519_mul( &cmp[ 0 ], neg, &y[1] );
  fd_f25519_mul( &cmp[ 1 ], &x[1], &y[0] );
  int xx = fd_f25519_eq( &cmp[ 0 ], &cmp[ 1 ] );

  fd_f25519_mul( &cmp[ 0 ], neg, &x[1] );
  fd_f25519_mul( &cmp[ 1 ], &y[0], &y[1] );
  int yy = fd_f25519_eq( &cmp[ 0 ], &cmp[ 1 ] );

  return xx | yy;
}

/* fd_ristretto255_hash_to_curve computes an element h of the ristretto group
   given an array s of 64-byte of uniformly random input (e.g., the output of a
   hash function).
   This function behaves like a random oracle.
   It returns h. */

fd_ristretto255_point_t *
fd_ristretto255_hash_to_curve( fd_ristretto255_point_t * h,
                               uchar const               s[ static 64 ] );

/* fd_ristretto255_map_to_curve implements the elligato2 map for curve25519,
   and computes an element h of the ristretto group given an array s of 32-byte 
   of uniformly random input (e.g., the output of a hash function).
   This function does NOT behave like a random oracle, and is intended for
   internal use.
   It returns h. */

fd_ristretto255_point_t *
fd_ristretto255_map_to_curve( fd_ristretto255_point_t * h,
                              uchar const               s[ static 32 ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ristretto255_h */
