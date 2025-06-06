#ifndef HEADER_fd_src_ballet_bls_fd_bls12_381_h
#define HEADER_fd_src_ballet_bls_fd_bls12_381_h

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

int
fd_bls12_381_g1_add_syscall( uchar       r[48],
                             uchar const p[48],
                             uchar const q[48] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bls_fd_bls12_381_h */
