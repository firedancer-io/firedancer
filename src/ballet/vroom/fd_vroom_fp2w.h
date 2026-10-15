#ifndef HEADER_fd_src_ballet_vroom_fd_vroom_fp2w_h
#define HEADER_fd_src_ballet_vroom_fd_vroom_fp2w_h

/* VROOM engine: lazy wide Fp2 accumulators and the shared batch-reduce
   shapes used by the curve layers.  Unity-TU fragment: include AFTER
   fd_vroom_rns.c and fd_vroom_field.c (relies on their statics). */

#if FD_HAS_AVX512

typedef struct { vroom_fp_wide_t c[2]; } vroom_fp2_wide_t;
typedef struct { vroom_fp2_t x, y, z; } vroom_p2_projective_t;

static inline void
vroom_fp2_wide_zero( vroom_fp2_wide_t * out ) {
  vroom_fp_wide_offset( &out->c[0] ); /* out.re = 0 mod p, with a positive lazy offset. */
  vroom_fp_wide_offset( &out->c[1] ); /* out.im = 0 mod p.                              */
}

static inline void
vroom_fp2_wide_addmul( vroom_fp2_wide_t *  out,
                       vroom_fp2_t const * a,
                       vroom_fp2_t const * b ) {
  vroom_fp_wide_addmul( &out->c[0], &a->c[0], &b->c[0] ); /* out.re += a0*b0. */
  vroom_fp_wide_submul( &out->c[0], &a->c[1], &b->c[1] ); /* out.re -= a1*b1. */
  vroom_fp_wide_addmul( &out->c[1], &a->c[0], &b->c[1] ); /* out.im += a0*b1. */
  vroom_fp_wide_addmul( &out->c[1], &a->c[1], &b->c[0] ); /* out.im += a1*b0, hence out += a*b. */
}

static inline void
vroom_fp2_wide_submul( vroom_fp2_wide_t *  out,
                       vroom_fp2_t const * a,
                       vroom_fp2_t const * b ) {
  vroom_fp_wide_submul( &out->c[0], &a->c[0], &b->c[0] ); /* out.re -= a0*b0. */
  vroom_fp_wide_addmul( &out->c[0], &a->c[1], &b->c[1] ); /* out.re += a1*b1. */
  vroom_fp_wide_submul( &out->c[1], &a->c[0], &b->c[1] ); /* out.im -= a0*b1. */
  vroom_fp_wide_submul( &out->c[1], &a->c[1], &b->c[0] ); /* out.im -= a1*b0, hence out -= a*b. */
}

static inline void
vroom_fp2_wide_addmul_fp( vroom_fp2_wide_t *  out,
                          vroom_fp2_t const * a,
                          vroom_fp_t const *  b ) {
  vroom_fp_wide_addmul( &out->c[0], &a->c[0], b ); /* out.re += a0*b. */
  vroom_fp_wide_addmul( &out->c[1], &a->c[1], b ); /* out.im += a1*b, hence out += a*b. */
}

static inline void
vroom_fp2_wide_set_mul( vroom_fp2_wide_t *  out,
                        vroom_fp2_t const * a,
                        vroom_fp2_t const * b ) {
  vroom_fp2_wide_zero( out );
  vroom_fp2_wide_addmul( out, a, b );
}

static inline void
vroom_fp2_wide_set_mul_fp( vroom_fp2_wide_t *  out,
                           vroom_fp2_t const * a,
                           vroom_fp_t const *  b ) {
  vroom_fp2_wide_zero( out );
  vroom_fp2_wide_addmul_fp( out, a, b );
}

static inline void
vroom_fp2_reduce_batch2( vroom_fp2_t      out[2],
                         vroom_fp2_wide_t in [2] ) {
  vroom_fp_reduce_wide_batch4( &out[0].c[0], &in[0].c[0] );
}

static inline void
vroom_fp2_reduce_batch3( vroom_fp2_t      out[3],
                         vroom_fp2_wide_t in [3] ) {
  vroom_fp_reduce_wide_batch6( &out[0].c[0], &in[0].c[0] );
}

static inline void
vroom_fp2_reduce_batch4( vroom_fp2_t      out[4],
                         vroom_fp2_wide_t in [4] ) {
  vroom_fp_reduce_wide_batch8( &out[0].c[0], &in[0].c[0] );
}

static inline void
vroom_fp2_reduce_batch5( vroom_fp2_t      out[5],
                         vroom_fp2_wide_t in [5] ) {
  /* One interleaved batch10 over all 10 base-field wide elements of the
     five Fp2 products. */
  vroom_fp_reduce_wide_batch10( &out[0].c[0], &in[0].c[0] );
}

static inline void
vroom_fp2_reduce_batch6( vroom_fp2_t      out[6],
                         vroom_fp2_wide_t in [6] ) {
  vroom_fp_reduce_wide_batch6( &out[0].c[0], &in[0].c[0] );
  vroom_fp_reduce_wide_batch6( &out[3].c[0], &in[3].c[0] );
}

static inline void
vroom_fp2_mul_small( vroom_fp2_t *       out,
                     vroom_fp2_t const * a,
                     uint                n ) {
  vroom_fp_mul_small( &out->c[0], &a->c[0], n );
  vroom_fp_mul_small( &out->c[1], &a->c[1], n );
}

static inline void
vroom_fp2_one( vroom_fp2_t * out ) {
  vroom_fp_one( &out->c[0] );
  vroom_fp_zero( &out->c[1] );
}

static inline int
vroom_fp2_equal( vroom_fp2_t const * a,
                 vroom_fp2_t const * b ) {
  return vroom_fp_equal( &a->c[0], &b->c[0] ) &
         vroom_fp_equal( &a->c[1], &b->c[1] );
}

static inline void
vroom_fp_from_normal( vroom_fp_t * out,
                      ulong const  in[6] ) {
  vroom_fp_from_uint64( out, in );
}

static inline void
vroom_fp2_from_normal( vroom_fp2_t * out,
                       ulong const   in[2][6] ) {
  vroom_fp_from_normal( &out->c[0], in[0] );
  vroom_fp_from_normal( &out->c[1], in[1] );
}

#endif /* FD_HAS_AVX512 */

#endif
