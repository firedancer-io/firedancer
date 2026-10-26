#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_g2_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_g2_h

#include "fd_bls_field.h"

typedef struct { fd_bls_fp2_t x, y, z; } fd_bls_p2_projective_t;

extern uint const fd_bls_miller_iterations[5];

FD_PROTOTYPES_BEGIN

/* Outputs may alias inputs. */
void fd_bls_g2_double( fd_bls_p2_projective_t * out, fd_bls_p2_projective_t const * p, int first );
/* Complete mixed addition out = p + (qx,qy); q must not be the identity. */
void fd_bls_g2_add_affine( fd_bls_p2_projective_t * out, fd_bls_p2_projective_t const * p,
                           fd_bls_fp2_t const * qx, fd_bls_fp2_t const * qy );
void fd_bls_g2_add_projective( fd_bls_p2_projective_t * out, fd_bls_p2_projective_t const * p,
                                                  fd_bls_p2_projective_t const * q );
fd_bls_p2_projective_t fd_bls_g2_ladder_minus_z_affine( fd_bls_fp2_t const * x,
                                                         fd_bls_fp2_t const * y );
int fd_bls_g2_validate_affine( fd_bls_fp2_t const * x, fd_bls_fp2_t const * y );
int fd_bls_g2_validate_mont       ( ulong const * xyz ); /* 3*2*6 Montgomery limbs */
int fd_bls_g2_validate_affine_mont( ulong const * xy );  /* 2*2*6 Montgomery limbs */

FD_PROTOTYPES_END

#endif
