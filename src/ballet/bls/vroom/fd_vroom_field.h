#ifndef HEADER_fd_src_ballet_bls_vroom_fd_vroom_field_h
#define HEADER_fd_src_ballet_bls_vroom_fd_vroom_field_h

#include "fd_vroom_rns.h"

#if FD_HAS_AVX512
typedef struct { fd_vroom_fp_t c[2];  } fd_vroom_fp2_t;
typedef struct { fd_vroom_fp_t c[12]; } fd_vroom_fp12_t;

FD_PROTOTYPES_BEGIN

void fd_vroom_fp2_add( fd_vroom_fp2_t * out, fd_vroom_fp2_t const * a, fd_vroom_fp2_t const * b );
void fd_vroom_fp2_sub( fd_vroom_fp2_t * out, fd_vroom_fp2_t const * a, fd_vroom_fp2_t const * b );
void fd_vroom_fp2_mul( fd_vroom_fp2_t * out, fd_vroom_fp2_t const * a, fd_vroom_fp2_t const * b );
void fd_vroom_fp2_sqr( fd_vroom_fp2_t * out, fd_vroom_fp2_t const * a );
void fd_vroom_fp2_neg( fd_vroom_fp2_t * out, fd_vroom_fp2_t const * a );

void fd_vroom_fp12_mul       ( fd_vroom_fp12_t * out, fd_vroom_fp12_t const * a, fd_vroom_fp12_t const * b );
void fd_vroom_fp12_sqr       ( fd_vroom_fp12_t * out, fd_vroom_fp12_t const * a );
void fd_vroom_fp12_cyclotomic_sqr( fd_vroom_fp12_t * out, fd_vroom_fp12_t const * a );
void fd_vroom_fp12_mul_sparse( fd_vroom_fp12_t * out, fd_vroom_fp12_t const * a, fd_vroom_fp_t const line[6] );
void fd_vroom_fp12_one       ( fd_vroom_fp12_t * out );

FD_PROTOTYPES_END
#endif

#endif
