#ifndef HEADER_fd_src_ballet_bls_vroom_fd_vroom_final_h
#define HEADER_fd_src_ballet_bls_vroom_fd_vroom_final_h

#include "fd_vroom_field.h"

#if FD_HAS_AVX512
FD_PROTOTYPES_BEGIN

void fd_vroom_final_exp_c( fd_vroom_fp12_t * out, fd_vroom_fp12_t const * in );
void fd_vroom_fp12_inverse_c( fd_vroom_fp12_t * out, fd_vroom_fp12_t const * in );
void fd_vroom_fp12_frobenius_c( fd_vroom_fp12_t * out, fd_vroom_fp12_t const * in, ulong n );
int  fd_vroom_fp12_is_one_c( fd_vroom_fp12_t const * in );

FD_PROTOTYPES_END
#endif

#endif
