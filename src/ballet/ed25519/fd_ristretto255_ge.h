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

/* fd_ristretto255 provides APIs for the ristretto255 prime order group */

/* fd_ristretto255_point_t is a opaque handle to a ristretto255 group
   element.  Although it is the same type as an Ed25519 group element,
   it is unsafe to mix Ed25519 point and ristretto point APIs, with the
   exception of the cases below. */

typedef fd_ed25519_point_t fd_ristretto255_point_t;

FD_PROTOTYPES_BEGIN

fd_ristretto255_point_t *
fd_ristretto255_point_decompress( fd_ristretto255_point_t * h,
                                  uchar const               s[ static 32 ] );

static inline int
fd_ristretto255_point_validate( uchar const s[ static 32 ] ) {
  fd_ristretto255_point_t A[1];
  return !!fd_ristretto255_point_decompress( A, s );
}

uchar *
fd_ristretto255_point_compress( uchar                           s[ static 32 ],
                                fd_ristretto255_point_t const * f );

#define fd_ristretto255_point_add fd_ed25519_point_add
#define fd_ristretto255_point_sub fd_ed25519_point_sub

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ristretto255_ge_h */
