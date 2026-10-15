#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_final_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_final_h

/* Final exponentiation and Fp12 utilities for the AVX-512 pairing. */

#include "../../vroom/fd_vroom_field.h"

#if FD_HAS_AVX512
FD_PROTOTYPES_BEGIN

void fd_bls_final_exp( vroom_fp12_t * out, vroom_fp12_t const * in );
void vroom_fp12_inverse( vroom_fp12_t * out, vroom_fp12_t const * in );
void fd_bls_fp12_frobenius( vroom_fp12_t * out, vroom_fp12_t const * in, ulong n );

FD_PROTOTYPES_END
#endif

#endif
