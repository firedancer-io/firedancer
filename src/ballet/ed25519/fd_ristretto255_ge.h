#ifndef HEADER_fd_src_ballet_ed25519_fd_ristretto255_ge_h
#define HEADER_fd_src_ballet_ed25519_fd_ristretto255_ge_h

/* fd_ristretto255_ge.h provides the public ristretto255 group element
   API.

   This API is specifically only provided for the Solana virtual machine
   syscall sol_curve_group_op (slow!).  It is guaranteed to be stable
   irrespective of underlying backend chosen (ref, avx, etc...)

   All operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data) */

#include "fd_ed25519_ge.h"
#include "fd_ristretto255_ge_private.h"

/* fd_ristretto255 provides APIs for the ristretto255 prime order group */

/* fd_ristretto255_point_t is a opaque handle to a ristretto255 group
   element.  Although it is the same type as an Ed25519 group element,
   it is unsafe to mix Ed25519 point and ristretto point APIs, with the
   exception of the cases below. */

typedef fd_ed25519_point_t fd_ristretto255_point_t;

FD_PROTOTYPES_BEGIN

/* fd_ristretto255_point_compress compresses the ristretto element f
   to a 32-byte canonical representation and stores the result in s.
   It returns s. */

static inline uchar *
fd_ristretto255_point_compress( uchar                           s[ static 32 ],
                                fd_ristretto255_point_t const * f_ ) {
  fd_ed25519_ge_p3_t const * f = fd_type_pun_const( f_ );
  return fd_ristretto255_ge_tobytes( s, f );
}

/* fd_ristretto255_point_decompress decompresses a 32-byte array into
   an element of the ristretto group h.
   It returns h on success, NULL on failure. */

static inline fd_ristretto255_point_t *
fd_ristretto255_point_decompress( fd_ristretto255_point_t * h_,
                                  uchar const               s[ static 32 ] ) {
  fd_ed25519_ge_p3_t * h = fd_type_pun( h_ );
  return fd_type_pun( fd_ristretto255_ge_frombytes_vartime( h, s ) );
}

/* fd_ristretto255_point_validate checks if a 32-byte array represents
   a valid element of the ristretto group h.
   It returns 1 on success, 0 on failure. */

static inline int
fd_ristretto255_point_validate( uchar const s[ static 32 ] ) {
  fd_ristretto255_point_t A[1];
  return !!fd_ristretto255_point_decompress( A, s );
}

/* fd_ristretto255_extended_tobytes stores the internal representation
   of an element of the ristretto group f (extended coordinates) into
   a 256-byte array.
   This can be used to efficiently cache and retrieve a point, but should
   NOT be used to deal with user input/output.
   It returns s. */

static inline uchar *
fd_ristretto255_extended_tobytes( uchar                           s[ static 32*4 ],
                                  fd_ristretto255_point_t const * f_ ) {
  fd_ed25519_ge_p3_t const * f = fd_type_pun_const( f_ );
  fd_ed25519_fe_tobytes( s,    f->X );
  fd_ed25519_fe_tobytes( s+32, f->Y );
  fd_ed25519_fe_tobytes( s+64, f->Z );
  fd_ed25519_fe_tobytes( s+96, f->T );
  return s;
}

/* fd_ristretto255_extended_tobytes loads a 256-byte array into
   an element of the ristretto group h, assuming extended coordinates.
   This can be used to efficiently cache and retrieve a point, but should
   NOT be used to deal with user input/output.
   It returns h, and doesn't check for failures. */

static inline fd_ristretto255_point_t *
fd_ristretto255_extended_frombytes( fd_ristretto255_point_t * h_,
                                    uchar const               s[ static 32*4 ] ) {
  fd_ed25519_ge_p3_t * h = fd_type_pun( h_ );
  fd_ed25519_fe_frombytes( h->X, s    );
  fd_ed25519_fe_frombytes( h->Y, s+32 );
  fd_ed25519_fe_frombytes( h->Z, s+64 );
  fd_ed25519_fe_frombytes( h->T, s+96 );
  return h_;
}

/* fd_ristretto255_point_eq checks if two elements of the ristretto group 
   p and q are equal.
   It returns 1 on success, 0 on failure. */

static inline int
fd_ristretto255_point_eq( fd_ristretto255_point_t * const p_,
                          fd_ristretto255_point_t * const q_ ) {
  // https://ristretto.group/details/equality.html
  fd_ed25519_ge_p3_t const * p = fd_type_pun_const( p_ );
  fd_ed25519_ge_p3_t const * q = fd_type_pun_const( q_ );
  fd_ed25519_fe_t cmp[2];

  fd_ed25519_fe_mul( &cmp[ 0 ], p->X, q->Y );
  fd_ed25519_fe_mul( &cmp[ 1 ], q->X, p->Y );
  int x = fd_ed25519_fe_eq( &cmp[ 0 ], &cmp[ 1 ] );

  fd_ed25519_fe_mul( &cmp[ 0 ], p->X, q->X );
  fd_ed25519_fe_mul( &cmp[ 1 ], p->Y, q->Y );
  int y = fd_ed25519_fe_eq( &cmp[ 0 ], &cmp[ 1 ] );

  return x | y;
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

/* fd_ristretto255_map_to_curve_4 is like fd_ristretto255_map_to_curve,
   and processes 4 inputs at a time, for better performance. */

void
fd_ristretto255_map_to_curve_4( fd_ristretto255_point_t * ha_,
                                uchar const               ta[ static 32 ],
                                fd_ristretto255_point_t * hb_,
                                uchar const               tb[ static 32 ],
                                fd_ristretto255_point_t * hc_,
                                uchar const               tc[ static 32 ],
                                fd_ristretto255_point_t * hd_,
                                uchar const               td[ static 32 ] );

#define fd_ristretto255_point_0          fd_ed25519_point_0
#define fd_ristretto255_point_add        fd_ed25519_point_add
#define fd_ristretto255_point_sub        fd_ed25519_point_sub
#define fd_ristretto255_scalar_validate  fd_ed25519_scalar_validate
#define fd_ristretto255_point_scalarmult fd_ed25519_point_scalarmult
#define fd_ristretto255_multiscalar_mul  fd_ed25519_multiscalar_mul

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ristretto255_ge_h */
