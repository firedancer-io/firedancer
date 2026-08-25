#ifndef HEADER_fd_src_ballet_bls_fd_vroom_h
#define HEADER_fd_src_ballet_bls_fd_vroom_h

#ifdef __cplusplus
extern "C" {
#endif

#define FD_VROOM_PAIR_MAX (64UL)
#define FD_VROOM_G2_PREPARED_ALIGN     (64UL)
#define FD_VROOM_G2_PREPARED_FOOTPRINT (52224UL)

/* Canonical little-endian base-field limbs.  These types are the dependency-
   free input boundary of the C backend.  The BLST-affine entry points below
   are compatibility adapters for existing Firedancer callers. */
typedef struct {
  unsigned long x[6];
  unsigned long y[6];
} fd_vroom_g1_affine_t;

typedef struct {
  unsigned long x[2][6];
  unsigned long y[2][6];
} fd_vroom_g2_affine_t;

/* Opaque, host-local Miller-loop preparation for one trusted G2 subgroup
   point.  Preparation deliberately does not repeat curve/subgroup checks:
   callers must derive q from hash-to-G2 or validate it first.  This is
   derived state: never put it on the wire or persist it. */
typedef union __attribute__((aligned(FD_VROOM_G2_PREPARED_ALIGN))) {
  unsigned long align[ FD_VROOM_G2_PREPARED_ALIGN/sizeof(unsigned long) ];
  unsigned char opaque[ FD_VROOM_G2_PREPARED_FOOTPRINT ];
} fd_vroom_g2_prepared_t;

int
fd_vroom_g2_prepare_normal( fd_vroom_g2_prepared_t *    out,
                            fd_vroom_g2_affine_t const * q );

/* Verifies e(p_prepared,q_prepared)*e(p_checked,q_checked)==1.  The prepared
   point must have come from a validated subgroup point.  q_checked is still
   subgroup checked inside the live Miller loop. */
int
fd_vroom_pairing_finalverify_prepared_normal_checked(
    fd_vroom_g1_affine_t const *  p_prepared,
    fd_vroom_g2_prepared_t const * q_prepared,
    fd_vroom_g1_affine_t const *  p_checked,
    fd_vroom_g2_affine_t const *  q_checked );

int
fd_vroom_pairing_finalverify_normal( fd_vroom_g1_affine_t const * p,
                                     fd_vroom_g2_affine_t const * q,
                                     unsigned long                cnt );

int
fd_vroom_pairing_finalverify_normal_checked( fd_vroom_g1_affine_t const * p,
                                             fd_vroom_g2_affine_t const * q,
                                             unsigned long                cnt,
                                             unsigned long                q_subgroup_mask );

/* fd_vroom_pairing_finalverify computes the product of cnt BLS12-381
   pairings and returns one if it is the identity in GT, zero if it is not,
   and -1 on an internal error.  Inputs use native BLST affine layout and are
   adapted to the canonical-limb API above.  This AVX-512 IFMA implementation
   does not validate curve or subgroup membership. */

int
fd_vroom_pairing_finalverify( void const *  p,
                              void const *  q,
                              unsigned long cnt );

/* As above, while also checking G2 subgroup membership for each q[i] whose
   bit is set in q_subgroup_mask.  The check reuses the [-z]q[i] projective
   point already produced by the Miller loop instead of doing a second
   scalar multiplication.  Inputs still need canonical/on-curve decoding. */

int
fd_vroom_pairing_finalverify_checked( void const *  p,
                                      void const *  q,
                                      unsigned long cnt,
                                      unsigned long q_subgroup_mask );

/* BLST-layout compatibility adapters for the prepared API. */
int
fd_vroom_g2_prepare( fd_vroom_g2_prepared_t * out,
                     void const *             q );

int
fd_vroom_pairing_finalverify_prepared_checked(
    void const *                       p_prepared,
    fd_vroom_g2_prepared_t const *     q_prepared,
    void const *                       p_checked,
    void const *                       q_checked );

#ifdef __cplusplus
}
#endif

#endif
