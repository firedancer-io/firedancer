#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_miller_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_miller_h

/* Internal AVX-512 pairing entry points (Miller loop + final
   exponentiation).  Inputs are canonical normal-form limbs for already
   validated points. */

#include "fd_bls_g2.h"
#include "../fd_bls.h"

#define FD_BLS_PAIR_MAX              (64UL)
#define FD_BLS_G2_PREPARED_ALIGN     (64UL)
#define FD_BLS_G2_PREPARED_FOOTPRINT (52224UL)

typedef struct { ulong x[6];    ulong y[6];    } fd_bls_g1_affine_t;
typedef struct { ulong x[2][6]; ulong y[2][6]; } fd_bls_g2_affine_t;
typedef struct { fd_bls_fp_t  x, y; } fd_bls_g1_rns_affine_t;
typedef struct { fd_bls_fp2_t x, y; } fd_bls_g2_rns_affine_t;
typedef union __attribute__((aligned(FD_BLS_G2_PREPARED_ALIGN))) {
  ulong align[ FD_BLS_G2_PREPARED_ALIGN/sizeof(ulong) ];
  uchar opaque[ FD_BLS_G2_PREPARED_FOOTPRINT ];
} fd_bls_g2_prepared_t;

FD_PROTOTYPES_BEGIN

void fd_bls_miller_loop( fd_bls_fp12_t *     out,
                                fd_bls_g1_affine_t const * p,
                                fd_bls_g2_affine_t const * q );

int fd_bls_pairing( fd_bls_fp12_t *     out,
                           fd_bls_g1_affine_t const * p,
                           fd_bls_g2_affine_t const * q,
                           ulong               cnt );

int fd_bls_g2_prepare( fd_bls_g2_prepared_t * out,
                              fd_bls_g2_affine_t const *    q );

int fd_bls_pairing_finalverify_prepared_checked(
    fd_bls_g1_affine_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_affine_t const *          p_checked,
    fd_bls_g2_affine_t const *          q_checked );

int fd_bls_pairing_finalverify( fd_bls_g1_affine_t const * p,
                                       fd_bls_g2_affine_t const * q,
                                       ulong               cnt );

/* Pair affine points already in blst Montgomery representation without a
   Montgomery-to-canonical-to-RNS round trip. */
int fd_bls_pairing_finalverify_mont( blst_p1_affine const * p,
                                      blst_p2_affine const * q,
                                      ulong                  cnt );
/* out = the pairing product of the cnt<=3 pairs (final exponentiation
   applied); returns 1 on success. */
int fd_bls_pairing_rns( fd_bls_fp12_t *                out,
                        fd_bls_g1_rns_affine_t const * p,
                        fd_bls_g2_rns_affine_t const * q,
                        ulong                          cnt );
int fd_bls_pairing_finalverify_rns( fd_bls_g1_rns_affine_t const * p,
                                    fd_bls_g2_rns_affine_t const * q,
                                    ulong                           cnt );

int fd_bls_pairing_finalverify_checked( fd_bls_g1_affine_t const * p,
                                               fd_bls_g2_affine_t const * q,
                                               ulong               cnt,
                                               ulong               q_subgroup_mask );

/* RFC 9380 map_to_curve(u[0]) + map_to_curve(u[1]) followed by
   clear_cofactor (the encode-free half of hash_to_curve for
   BLS12381G2_XMD:SHA-256_SSWU_RO_), on RNS field elements.  The output is
   the affine G2 point fd_bls_hash_to_g2 produces. */

void fd_bls_hash_to_g2_from_field( fd_bls_hash_t *    h,
                                    fd_bls_fp2_t const u[2] );

FD_PROTOTYPES_END
#endif
