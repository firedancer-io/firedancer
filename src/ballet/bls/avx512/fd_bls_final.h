#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_final_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_final_h

#include "fd_bls_field.h"

#if FD_HAS_AVX512
FD_PROTOTYPES_BEGIN

void fd_bls_final_exp( fd_bls_fp12_t * out, fd_bls_fp12_t const * in );
void fd_bls_fp12_inverse( fd_bls_fp12_t * out, fd_bls_fp12_t const * in );
void fd_bls_fp12_frobenius( fd_bls_fp12_t * out, fd_bls_fp12_t const * in, ulong n );
int  fd_bls_fp12_is_one( fd_bls_fp12_t const * in );

FD_PROTOTYPES_END
#endif

#endif
