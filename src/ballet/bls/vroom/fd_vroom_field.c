#include "fd_vroom_field.h"

#if FD_HAS_AVX512

#include "fd_vroom_constants.h"
#include "fd_vroom_fp12_generated.inc"

void
fd_vroom_fp2_add( fd_vroom_fp2_t *       out,
                  fd_vroom_fp2_t const * a,
                  fd_vroom_fp2_t const * b ) {
  fd_vroom_fp_add( &out->c[0], &a->c[0], &b->c[0] );
  fd_vroom_fp_add( &out->c[1], &a->c[1], &b->c[1] );
}

void
fd_vroom_fp2_sub( fd_vroom_fp2_t *       out,
                  fd_vroom_fp2_t const * a,
                  fd_vroom_fp2_t const * b ) {
  fd_vroom_fp_sub( &out->c[0], &a->c[0], &b->c[0] );
  fd_vroom_fp_sub( &out->c[1], &a->c[1], &b->c[1] );
}

void
fd_vroom_fp2_neg( fd_vroom_fp2_t *       out,
                  fd_vroom_fp2_t const * a ) {
  fd_vroom_fp_neg( &out->c[0], &a->c[0] );
  fd_vroom_fp_neg( &out->c[1], &a->c[1] );
}

void
fd_vroom_fp2_mul( fd_vroom_fp2_t *       out,
                  fd_vroom_fp2_t const * a,
                  fd_vroom_fp2_t const * b ) {
  fd_vroom_fp_wide_t x, y;
  fd_vroom_fp_wide_offset( &x );
  fd_vroom_fp_wide_addmul( &x, &a->c[0], &b->c[0] );
  fd_vroom_fp_wide_submul( &x, &a->c[1], &b->c[1] );
  fd_vroom_fp_wide_offset( &y );
  fd_vroom_fp_wide_addmul( &y, &a->c[0], &b->c[1] );
  fd_vroom_fp_wide_addmul( &y, &a->c[1], &b->c[0] );
  fd_vroom_fp_reduce_wide( &out->c[0], &x );
  fd_vroom_fp_reduce_wide( &out->c[1], &y );
}

void
fd_vroom_fp2_sqr( fd_vroom_fp2_t *       out,
                  fd_vroom_fp2_t const * a ) {
  fd_vroom_fp_t twice_a1;
  twice_a1.m1 = _mm512_add_epi64( a->c[1].m1, a->c[1].m1 );
  twice_a1.m2 = _mm512_add_epi64( a->c[1].m2, a->c[1].m2 );

  fd_vroom_fp_wide_t wide[2];
  fd_vroom_fp_wide_offset( &wide[0] );
  fd_vroom_fp_wide_addmul( &wide[0], &a->c[0], &a->c[0] );
  fd_vroom_fp_wide_submul( &wide[0], &a->c[1], &a->c[1] );
  fd_vroom_fp_wide_offset( &wide[1] );
  fd_vroom_fp_wide_addmul( &wide[1], &a->c[0], &twice_a1 );

  fd_vroom_fp_reduce_wide_batch2( &out->c[0], &wide[0] );
}

void
fd_vroom_fp12_mul( fd_vroom_fp12_t *       out,
                   fd_vroom_fp12_t const * a,
                   fd_vroom_fp12_t const * b ) {
  fd_vroom_fp12_t tmp;
  fp12_mul_generated( &tmp, a, b );
  *out = tmp;
}

void
fd_vroom_fp12_sqr( fd_vroom_fp12_t *       out,
                   fd_vroom_fp12_t const * a ) {
  fp12_sqr_generated( out, a );
}

void
fd_vroom_fp12_cyclotomic_sqr( fd_vroom_fp12_t *       out,
                              fd_vroom_fp12_t const * a ) {
  fp12_cyclotomic_sqr_generated( out, a );
}

void
fd_vroom_fp12_mul_sparse( fd_vroom_fp12_t *       out,
                          fd_vroom_fp12_t const * a,
                          fd_vroom_fp_t const      line[6] ) {
  fp12_mul_sparse_generated( out, a, line );
}

void
fd_vroom_fp12_one( fd_vroom_fp12_t * out ) {
  fd_vroom_fp_one( &out->c[0] );
  for( int i=1; i<12; i++ ) fd_vroom_fp_zero( &out->c[i] );
}

#endif
