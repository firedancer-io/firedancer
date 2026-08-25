#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_field_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_field_h

#include "fd_bls_rns.h"

#if FD_HAS_AVX512
/* BLS12-381 tower:
     Fp2  = Fp[u]/(u^2+1),
     Fp12 = Fp2[v,w]/(v^3-(u+1), w^2-v).
   c[6*i+2*j+k] is the coefficient of w^i v^j u^k. */
typedef struct { fd_bls_fp_t c[2];  } fd_bls_fp2_t;
typedef struct { fd_bls_fp_t c[12]; } fd_bls_fp12_t;

FD_PROTOTYPES_BEGIN

void fd_bls_fp2_add( fd_bls_fp2_t * out, fd_bls_fp2_t const * a, fd_bls_fp2_t const * b );
void fd_bls_fp2_sub( fd_bls_fp2_t * out, fd_bls_fp2_t const * a, fd_bls_fp2_t const * b );
void fd_bls_fp2_mul( fd_bls_fp2_t * out, fd_bls_fp2_t const * a, fd_bls_fp2_t const * b );
void fd_bls_fp2_sqr( fd_bls_fp2_t * out, fd_bls_fp2_t const * a );
void fd_bls_fp2_neg( fd_bls_fp2_t * out, fd_bls_fp2_t const * a );

void fd_bls_fp12_mul       ( fd_bls_fp12_t * out, fd_bls_fp12_t const * a, fd_bls_fp12_t const * b );
void fd_bls_fp12_sqr       ( fd_bls_fp12_t * out, fd_bls_fp12_t const * a );
void fd_bls_fp12_cyclotomic_sqr( fd_bls_fp12_t * out, fd_bls_fp12_t const * a );
void fd_bls_fp12_mul_sparse( fd_bls_fp12_t * out, fd_bls_fp12_t const * a, fd_bls_fp_t const line[6] );
void fd_bls_fp12_one       ( fd_bls_fp12_t * out );

FD_PROTOTYPES_END
#endif

#endif
