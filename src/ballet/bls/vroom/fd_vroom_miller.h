#ifndef HEADER_fd_src_ballet_bls_vroom_fd_vroom_miller_h
#define HEADER_fd_src_ballet_bls_vroom_fd_vroom_miller_h

#include "fd_vroom_field.h"
#include "../fd_vroom.h"

#if FD_HAS_AVX512
FD_PROTOTYPES_BEGIN

void fd_vroom_miller_loop_c( fd_vroom_fp12_t * out,
                             fd_vroom_g1_affine_t const * p,
                             fd_vroom_g2_affine_t const * q );

int fd_vroom_g2_prepare_c( fd_vroom_g2_prepared_t *    out,
                           fd_vroom_g2_affine_t const * q );

int fd_vroom_pairing_finalverify_prepared_checked_c(
    fd_vroom_g1_affine_t const *   p_prepared,
    fd_vroom_g2_prepared_t const * q_prepared,
    fd_vroom_g1_affine_t const *   p_checked,
    fd_vroom_g2_affine_t const *   q_checked );

/* Inputs are canonical normal-form limbs for already validated points. */
int fd_vroom_pairing_finalverify_c( fd_vroom_g1_affine_t const * p,
                                    fd_vroom_g2_affine_t const * q,
                                    ulong                  cnt );
int fd_vroom_pairing_finalverify_checked_c( fd_vroom_g1_affine_t const * p,
                                            fd_vroom_g2_affine_t const * q,
                                            ulong                  cnt,
                                            ulong                  q_subgroup_mask );

FD_PROTOTYPES_END
#endif

#endif
