#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_final_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_final_h

/* Final exponentiation and Fp12 utilities for the AVX-512 pairing. */

#include "fd_bls_field.h"

FD_PROTOTYPES_BEGIN

void fd_bls_final_exp( fd_bls_fp12_t * out, fd_bls_fp12_t const * in );
int  fd_bls_fp12_is_one( fd_bls_fp12_t const * in );

FD_PROTOTYPES_END

#endif
