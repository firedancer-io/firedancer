#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_ge_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_ge_h

/* fd_ed25519_ge.h provides the public Ed25519 group element API.

   This API is specifically only provided for the Solana virtual machine
   syscall sol_curve_group_op (slow!).  It is guaranteed to be stable
   irrespective of underlying backend chosen (ref, avx, etc...)

   All operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data) */

#include "../fd_ballet_base.h"

/* FD_ED25519_POINT_{ALIGN,FOOTPRINT} specify requirements for a memory
   region suitable to hold an fd_ed25519_point_t. */

#define FD_ED25519_POINT_ALIGN     ( 64UL)
#define FD_ED25519_POINT_FOOTPRINT (256UL)

/* fd_ed25519_point_t is a opaque handle to an Ed25519 group element.
   User of this API must not read or write contents of this struct
   directly because the contents are implementation-defined.
   (Contains a fd_ed25519_ge_p3_t defined in fd_ed25519_private.h) */

struct __attribute__((aligned(FD_ED25519_POINT_ALIGN))) fd_ed25519_point {
  uchar v[ FD_ED25519_POINT_FOOTPRINT ];
};

typedef struct fd_ed25519_point fd_ed25519_point_t;

FD_PROTOTYPES_BEGIN

fd_ed25519_point_t *
fd_ed25519_point_decompress( fd_ed25519_point_t * h,
                             uchar const          s[ static 32 ] );

static inline int
fd_ed25519_point_validate( uchar const s[ static 32 ] ) {
  fd_ed25519_point_t A[1];
  return !!fd_ed25519_point_decompress( A, s );
}

uchar *
fd_ed25519_point_compress( uchar                      s[ static 32 ],
                           fd_ed25519_point_t const * f );

fd_ed25519_point_t *
fd_ed25519_point_0( fd_ed25519_point_t * h );

/* fd_ed25519_point_{add,sub} compute `f+g` and `f-g` respectively.
   Stores the result into h and returns h.  Return value is never NULL. */

fd_ed25519_point_t *
fd_ed25519_point_add( fd_ed25519_point_t *       h,
                      fd_ed25519_point_t const * f,
                      fd_ed25519_point_t const * g );

fd_ed25519_point_t *
fd_ed25519_point_sub( fd_ed25519_point_t *       h,
                      fd_ed25519_point_t const * f,
                      fd_ed25519_point_t const * g );

/* fd_ed25519_scalar_validate checks whether the given Ed25519 scalar
   matches the canonical byte representation.  Not constant time and
   thus should not be exposed to secret data.  Returns s if canonical,
   NULL otherwise. */

uchar const *
fd_ed25519_scalar_validate( uchar const s[ static 32 ] );

/* fd_ed25519_point_scalarmult computes a scalar multiplication.
   Stores the result of `[a]A` into h.  a must be valid Ed25519 scalar
   (see fd_ed25519_scalar_validate).  Returns h. */

fd_ed25519_point_t *
fd_ed25519_point_scalarmult( fd_ed25519_point_t *       h,
                             uchar const                a[ static 32 ],
                             fd_ed25519_point_t const * A );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ed25519_ge_h */
