#ifndef HEADER_fd_src_ballet_bn254_fd_bn254_internal_h
#define HEADER_fd_src_ballet_bn254_fd_bn254_internal_h

#include "./fd_bn254.h"

/* Base field */

typedef fd_uint256_t fd_bn254_fp_t;

/* Extension fields */

struct FD_ALIGNED fd_bn254_fp2 {
  fd_bn254_fp_t el[2];
};
typedef struct fd_bn254_fp2 fd_bn254_fp2_t;

struct FD_ALIGNED fd_bn254_fp6 {
  fd_bn254_fp2_t el[3];
};
typedef struct fd_bn254_fp6 fd_bn254_fp6_t;

struct FD_ALIGNED fd_bn254_fp12 {
  fd_bn254_fp6_t el[2];
};
typedef struct fd_bn254_fp12 fd_bn254_fp12_t;

/* Point on G1, Jacobian coordinates */
struct FD_ALIGNED fd_bn254_g1 {
  fd_bn254_fp_t X;
  fd_bn254_fp_t Y;
  fd_bn254_fp_t Z;
};
typedef struct fd_bn254_g1 fd_bn254_g1_t;

/* Point on G2, Jacobian coordinates */
struct FD_ALIGNED fd_bn254_g2 {
  fd_bn254_fp2_t X;
  fd_bn254_fp2_t Y;
  fd_bn254_fp2_t Z;
};
typedef struct fd_bn254_g2 fd_bn254_g2_t;

/* Field utilities */

/* const 1. Montgomery.
   0x0e0a77c19a07df2f666ea36f7879462c0a78eb28f5c70b3dd35d438dc58f0d9d */
extern const fd_bn254_fp_t fd_bn254_const_one_mont[1];

static inline int
fd_bn254_fp_is_zero( fd_bn254_fp_t const * r ) {
  return r->limbs[0] == 0UL
      && r->limbs[1] == 0UL
      && r->limbs[2] == 0UL
      && r->limbs[3] == 0UL;
}

static inline int
fd_bn254_fp_is_one( fd_bn254_fp_t const * r ) {
  return r->limbs[0] == fd_bn254_const_one_mont->limbs[0]
      && r->limbs[1] == fd_bn254_const_one_mont->limbs[1]
      && r->limbs[2] == fd_bn254_const_one_mont->limbs[2]
      && r->limbs[3] == fd_bn254_const_one_mont->limbs[3];
}

static inline fd_bn254_fp_t *
fd_bn254_fp_set_zero( fd_bn254_fp_t * r ) {
  r->limbs[0] = 0UL;
  r->limbs[1] = 0UL;
  r->limbs[2] = 0UL;
  r->limbs[3] = 0UL;
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_set_one( fd_bn254_fp_t * r ) {
  r->limbs[0] = fd_bn254_const_one_mont->limbs[0];
  r->limbs[1] = fd_bn254_const_one_mont->limbs[1];
  r->limbs[2] = fd_bn254_const_one_mont->limbs[2];
  r->limbs[3] = fd_bn254_const_one_mont->limbs[3];
  return r;
}

/* Extension fields utilities */

static inline int
fd_bn254_fp2_is_zero( fd_bn254_fp2_t const * a ) {
  return fd_bn254_fp_is_zero( &a->el[0] )
      && fd_bn254_fp_is_zero( &a->el[1] );
}

static inline int
fd_bn254_fp2_is_one( fd_bn254_fp2_t const * a ) {
  return fd_bn254_fp_is_one ( &a->el[0] )
      && fd_bn254_fp_is_zero( &a->el[1] );
}

static inline fd_bn254_fp2_t *
fd_bn254_fp2_set_zero( fd_bn254_fp2_t * r ) {
  fd_bn254_fp_set_zero( &r->el[0] );
  fd_bn254_fp_set_zero( &r->el[1] );
  return r;
}

static inline fd_bn254_fp2_t *
fd_bn254_fp2_set_one( fd_bn254_fp2_t * r ) {
  fd_bn254_fp_set_one ( &r->el[0] );
  fd_bn254_fp_set_zero( &r->el[1] );
  return r;
}

/* Fp6 */

static inline int
fd_bn254_fp6_is_zero( fd_bn254_fp6_t const * a ) {
  return fd_bn254_fp2_is_zero( &a->el[0] )
      && fd_bn254_fp2_is_zero( &a->el[1] )
      && fd_bn254_fp2_is_zero( &a->el[2] );
}

static inline int
fd_bn254_fp6_is_one( fd_bn254_fp6_t const * a ) {
  return fd_bn254_fp2_is_one ( &a->el[0] )
      && fd_bn254_fp2_is_zero( &a->el[1] )
      && fd_bn254_fp2_is_zero( &a->el[2] );
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_set_zero( fd_bn254_fp6_t * r ) {
  fd_bn254_fp2_set_zero( &r->el[0] );
  fd_bn254_fp2_set_zero( &r->el[1] );
  fd_bn254_fp2_set_zero( &r->el[2] );
  return r;
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_set_one( fd_bn254_fp6_t * r ) {
  fd_bn254_fp2_set_one ( &r->el[0] );
  fd_bn254_fp2_set_zero( &r->el[1] );
  fd_bn254_fp2_set_zero( &r->el[2] );
  return r;
}

/* Fp12 */

static inline int
fd_bn254_fp12_is_zero( fd_bn254_fp12_t const * a ) {
  return fd_bn254_fp6_is_zero( &a->el[0] )
      && fd_bn254_fp6_is_zero( &a->el[1] );
}

static inline int
fd_bn254_fp12_is_one( fd_bn254_fp12_t const * a ) {
  return fd_bn254_fp6_is_one ( &a->el[0] )
      && fd_bn254_fp6_is_zero( &a->el[1] );
}

// static inline fd_bn254_fp12_t *
// fd_bn254_fp12_set_zero( fd_bn254_fp12_t * r ) {
//   fd_bn254_fp6_set_zero( &r->el[0] );
//   fd_bn254_fp6_set_zero( &r->el[1] );
//   return r;
// }

static inline fd_bn254_fp12_t *
fd_bn254_fp12_set_one( fd_bn254_fp12_t * r ) {
  fd_bn254_fp6_set_one ( &r->el[0] );
  fd_bn254_fp6_set_zero( &r->el[1] );
  return r;
}

/* Functions to test */

fd_bn254_fp12_t *
fd_bn254_fp12_mul( fd_bn254_fp12_t * r,
                   fd_bn254_fp12_t const * a,
                   fd_bn254_fp12_t const * b );

fd_bn254_fp12_t *
fd_bn254_fp12_inv( fd_bn254_fp12_t * r,
                   fd_bn254_fp12_t const * a );

fd_bn254_fp12_t *
fd_bn254_final_exp( fd_bn254_fp12_t *       r,
                    fd_bn254_fp12_t * const x );

fd_bn254_fp12_t *
fd_bn254_miller_loop( fd_bn254_fp12_t *   r,
                      fd_bn254_g1_t const p[],
                      fd_bn254_g2_t const q[],
                      ulong               sz );

#endif /* HEADER_fd_src_ballet_bn254_fd_bn254_internal_h */
