#ifndef HEADER_fd_src_ballet_bn254_fd_poseidon_private_h
#define HEADER_fd_src_ballet_bn254_fd_poseidon_private_h

#include "./fd_poseidon.h"

/* Keeping each width in its own translation unit lets the compiler optimize
   the width-specialized permutation bodies in parallel. */

FD_PROTOTYPES_BEGIN

void
fd_poseidon_private_apply_mds( fd_bn254_scalar_t         state[],
                               ulong                     width,
                               fd_bn254_scalar_t const * mds );

void
fd_poseidon_private_apply_sparse_mds( fd_bn254_scalar_t         state[],
                                      ulong                     width,
                                      fd_bn254_scalar_t const * row,
                                      fd_bn254_scalar_t const * col );

#define FD_POSEIDON_FINI_DECL(n)                                      \
uchar *                                                              \
fd_poseidon_private_fini_##n( fd_poseidon_t * pos,                    \
                              uchar           hash[ FD_POSEIDON_HASH_SZ ] )

FD_POSEIDON_FINI_DECL( 2  );
FD_POSEIDON_FINI_DECL( 3  );
FD_POSEIDON_FINI_DECL( 4  );
FD_POSEIDON_FINI_DECL( 5  );
FD_POSEIDON_FINI_DECL( 6  );
FD_POSEIDON_FINI_DECL( 7  );
FD_POSEIDON_FINI_DECL( 8  );
FD_POSEIDON_FINI_DECL( 9  );
FD_POSEIDON_FINI_DECL( 10 );
FD_POSEIDON_FINI_DECL( 11 );
FD_POSEIDON_FINI_DECL( 12 );
FD_POSEIDON_FINI_DECL( 13 );

#undef FD_POSEIDON_FINI_DECL

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bn254_fd_poseidon_private_h */
