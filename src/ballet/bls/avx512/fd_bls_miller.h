#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_miller_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_miller_h

#include "fd_bls_field.h"
#include "../fd_bls.h"

#if FD_HAS_AVX512
FD_PROTOTYPES_BEGIN

void fd_bls_miller_loop_avx512( fd_bls_fp12_t * out,
                             fd_bls_g1_t const * p,
                             fd_bls_g2_t const * q );

int fd_bls_pairing_avx512( fd_bls_fp12_t * out,
                        fd_bls_g1_t const * p,
                        fd_bls_g2_t const * q,
                        ulong                         cnt );

int fd_bls_g2_prepare_avx512( fd_bls_g2_prepared_t *    out,
                           fd_bls_g2_t const * q );

int fd_bls_pairing_finalverify_prepared_checked_avx512(
    fd_bls_g1_t const *   p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *   p_checked,
    fd_bls_g2_t const *   q_checked );

/* Inputs are canonical normal-form limbs for already validated points. */
int fd_bls_pairing_finalverify_avx512( fd_bls_g1_t const * p,
                                    fd_bls_g2_t const * q,
                                    ulong                  cnt );
int fd_bls_pairing_finalverify_checked_avx512( fd_bls_g1_t const * p,
                                               fd_bls_g2_t const * q,
                                               ulong               cnt,
                                               ulong               q_subgroup_mask );

FD_PROTOTYPES_END
#endif

#endif
