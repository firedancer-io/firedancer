#ifndef HEADER_fd_src_ballet_bn254_fd_bn254_backend_h
#define HEADER_fd_src_ballet_bn254_fd_bn254_backend_h

/* Internal compile-time backend dispatch for the fd_bn254 hot paths.
   The scalar reference implementation provides the full surface; on
   AVX-512 builds the VROOM backend (avx512/) overrides the pairing
   product, the G2 subgroup check, and G1/G2 scalar multiplication.
   Byte parsing, flag handling and curve-equation validation always stay
   in the portable code. */

#include "./fd_bn254_internal.h"

FD_PROTOTYPES_BEGIN

/* Reference cores (defined in fd_bn254.c / fd_bn254_g2_check.c; thin
   names over the existing scalar code). */

/* One iff q (affine, on-curve, not infinity) is in the order-r subgroup. */
int fd_bn254_ref_g2_in_subgroup( fd_bn254_g2_t const * q );

/* One iff prod_i e(p_i, q_i) == 1 over already-validated affine pairs. */
int fd_bn254_ref_pairing_is_one( fd_bn254_g1_t const * p,
                                 fd_bn254_g2_t const * q,
                                 ulong                 sz );

#if FD_HAS_AVX512

int  fd_bn254_avx512_g2_in_subgroup( fd_bn254_g2_t const * q );
int  fd_bn254_avx512_pairing_is_one( fd_bn254_g1_t const * p,
                                     fd_bn254_g2_t const * q,
                                     ulong                 sz );
void fd_bn254_avx512_g1_scalar_mul( fd_bn254_g1_t *           r,
                                    fd_bn254_g1_t const *     p,
                                    fd_bn254_scalar_t const * s );
void fd_bn254_avx512_g2_scalar_mul( fd_bn254_g2_t *           r,
                                    fd_bn254_g2_t const *     q,
                                    fd_bn254_scalar_t const * s );

#endif

FD_PROTOTYPES_END

#if FD_HAS_AVX512
#define fd_bn254_backend_g2_in_subgroup fd_bn254_avx512_g2_in_subgroup
#define fd_bn254_backend_pairing_is_one fd_bn254_avx512_pairing_is_one
#define fd_bn254_backend_g1_scalar_mul  fd_bn254_avx512_g1_scalar_mul
#define fd_bn254_backend_g2_scalar_mul  fd_bn254_avx512_g2_scalar_mul
#else
#define fd_bn254_backend_g2_in_subgroup fd_bn254_ref_g2_in_subgroup
#define fd_bn254_backend_pairing_is_one fd_bn254_ref_pairing_is_one
#define fd_bn254_backend_g1_scalar_mul  fd_bn254_g1_scalar_mul
#define fd_bn254_backend_g2_scalar_mul  fd_bn254_g2_scalar_mul
#endif

#endif /* HEADER_fd_src_ballet_bn254_fd_bn254_backend_h */
