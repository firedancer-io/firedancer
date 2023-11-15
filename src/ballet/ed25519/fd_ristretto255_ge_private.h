#ifndef HEADER_fd_src_ballet_ed25519_fd_ristretto255_ge_private_h
#define HEADER_fd_src_ballet_ed25519_fd_ristretto255_ge_private_h

#include "fd_ed25519_private.h"

/* fd_ristretto255 provides internal APIs for the ristretto255 prime
   order group. */

FD_PROTOTYPES_BEGIN

fd_ed25519_ge_p3_t *
fd_ristretto255_ge_frombytes_vartime( fd_ed25519_ge_p3_t * h,
                                      uchar const          s[ static 32 ] );

uchar *
fd_ristretto255_ge_tobytes( uchar *                    s,
                            fd_ed25519_ge_p3_t const * h );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ristretto255_ge_private_h */
