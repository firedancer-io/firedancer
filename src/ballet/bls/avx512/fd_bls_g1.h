#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_g1_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_g1_h

#include "../fd_bls.h"

FD_PROTOTYPES_BEGIN
void fd_bls_g1_add( fd_bls_fp_t * p, fd_bls_fp_t const * q );
/* out = sum of pubs[0..cnt) (any representation, identities allowed). */
void fd_bls_g1_sum_batch( fd_bls_pub_t * out, fd_bls_pub_t const * const pubs[], ulong cnt );
int  fd_bls_g1_in_g1_affine( fd_bls_fp_t const * x, fd_bls_fp_t const * y );
int  fd_bls_fp_sqrt_rns    ( fd_bls_fp_t * out, fd_bls_fp_t const * x );
FD_PROTOTYPES_END

#endif
