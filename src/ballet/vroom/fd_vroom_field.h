#ifndef HEADER_fd_src_ballet_vroom_fd_vroom_field_h
#define HEADER_fd_src_ballet_vroom_fd_vroom_field_h

#include "fd_vroom_rns.h"

#if FD_HAS_AVX512
/* Tower field layout: Fp2 = Fp[u]/(u^2+1), Fp12 = Fp2[v,w]/(v^3-xi, w^2-v)
   with the curve's sextic nonresidue xi.  c[6*i+2*j+k] is the coefficient
   of w^i v^j u^k. */
typedef struct { vroom_fp_t c[2];  } vroom_fp2_t;
typedef struct { vroom_fp_t c[12]; } vroom_fp12_t;

FD_PROTOTYPES_BEGIN

VROOM_FN void vroom_fp2_add( vroom_fp2_t * out, vroom_fp2_t const * a, vroom_fp2_t const * b );
VROOM_FN void vroom_fp2_sub( vroom_fp2_t * out, vroom_fp2_t const * a, vroom_fp2_t const * b );
VROOM_FN void vroom_fp2_mul( vroom_fp2_t * out, vroom_fp2_t const * a, vroom_fp2_t const * b );
VROOM_FN void vroom_fp2_sqr( vroom_fp2_t * out, vroom_fp2_t const * a );
VROOM_FN void vroom_fp2_neg( vroom_fp2_t * out, vroom_fp2_t const * a );

VROOM_FN void vroom_fp12_mul           ( vroom_fp12_t * out, vroom_fp12_t const * a, vroom_fp12_t const * b );
VROOM_FN void vroom_fp12_sqr           ( vroom_fp12_t * out, vroom_fp12_t const * a );
VROOM_FN void vroom_fp12_cyclotomic_sqr( vroom_fp12_t * out, vroom_fp12_t const * a );
VROOM_FN void vroom_fp12_mul_sparse    ( vroom_fp12_t * out, vroom_fp12_t const * a, vroom_fp_t const line[6] );
VROOM_FN int  vroom_fp12_is_one       ( vroom_fp12_t const * in );
VROOM_FN void vroom_fp12_one           ( vroom_fp12_t * out );

FD_PROTOTYPES_END
#endif

#endif
