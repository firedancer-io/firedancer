#ifndef HEADER_fd_src_ballet_bls_fd_bls_h
#define HEADER_fd_src_ballet_bls_fd_bls_h

/* fd_bls is the BLS12-381 signature/pairing API used by the Alpenglow
   certificate path and the Solana BLS syscalls.  Operations dispatch at
   compile time (fd_bls_backend.h) to the AVX-512 backend (avx512/) when
   available, falling back to the blst-based reference backend (ref/). */

#include "../../util/fd_util.h"
#include "../../third_party/blst/bindings/blst.h"

#define FD_BLS_SEC_SZ            (32UL)
#define FD_BLS_PUB_SZ            (96UL)
#define FD_BLS_PUB_COMPRESSED_SZ (48UL)
#define FD_BLS_SIG_SZ            (192UL)
#define FD_BLS_SIG_COMPRESSED_SZ (96UL)
#define FD_BLS_SET_MAX           (2000UL) /* TODO make set_dynamic so this isn't dependent on the VAT cap */
#define FD_BLS_DST               "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define FD_BLS_DST_SZ            (sizeof(FD_BLS_DST)-1UL)
#define FD_BLS_PAIR_MAX          (64UL)

typedef blst_scalar fd_bls_sec_t;
typedef blst_p1     fd_bls_pub_t;
typedef blst_p2     fd_bls_sig_t;

#define SET_NAME fd_bls_set
#define SET_MAX  FD_BLS_SET_MAX
#include "../../util/tmpl/fd_set.c" /* TODO make set_dynamic so this isn't dependent on the VAT cap */

struct fd_bls_agg {
  fd_bls_pub_t pub;
  fd_bls_sig_t sig;
  fd_bls_set_t set[ fd_bls_set_word_cnt ]; /* each bit position corresponds to a signer's rank in the epoch (based on ag_epoch_info) */
};
typedef struct fd_bls_agg fd_bls_agg_t;

/* Backend-neutral BLS12-381 point types.  Coordinates are canonical
   little-endian base-field limbs.  The prepared G2 representation is
   backend-local. */

typedef struct {
  ulong x[6];
  ulong y[6];
} fd_bls_g1_t;

typedef struct {
  ulong x[2][6];
  ulong y[2][6];
} fd_bls_g2_t;

/* Hash-to-G2 output: the affine point H(msg). */
typedef blst_p2_affine fd_bls_hash_t;

/* Backend-selected prepared G2 representation (precomputed Miller lines
   on the AVX-512 backend; the validated affine point on the reference
   backend, which has no reusable public Miller-line representation). */
#if FD_HAS_AVX512

#define FD_BLS_G2_PREPARED_ALIGN     (64UL)
#define FD_BLS_G2_PREPARED_FOOTPRINT (52224UL)

typedef union __attribute__((aligned(FD_BLS_G2_PREPARED_ALIGN))) {
  ulong align[ FD_BLS_G2_PREPARED_ALIGN/sizeof(ulong) ];
  uchar opaque[ FD_BLS_G2_PREPARED_FOOTPRINT ];
} fd_bls_g2_prepared_t;

#else

typedef struct {
  fd_bls_g2_t q;
} fd_bls_g2_prepared_t;

#endif

FD_PROTOTYPES_BEGIN

/* --- secret keys --- */

void
fd_bls_sec_to_pub( fd_bls_sec_t const * sec,
                   fd_bls_pub_t *       pub );

void
fd_bls_sec_derive( fd_bls_sec_t * sec,
                   uchar const *  ikm,
                   ulong          ikm_sz );

void
fd_bls_sec_sign( fd_bls_sec_t const * sec,
                 uchar const *        msg,
                 ulong                msg_sz,
                 fd_bls_sig_t *       sig );

/* --- public keys (G1) --- */

int
fd_bls_pub_de( fd_bls_pub_t * pub,
               uchar const *  buf,
               ulong          buf_sz );

void
fd_bls_pub_ser( fd_bls_pub_t const * pub,
                uchar                buf[ static FD_BLS_PUB_SZ ] );

void
fd_bls_pub_compress( fd_bls_pub_t const * pub,
                     uchar                buf[ static FD_BLS_PUB_COMPRESSED_SZ ] );

int
fd_bls_pub_de_compressed( fd_bls_pub_t * pub,
                          uchar const    buf[ static FD_BLS_PUB_COMPRESSED_SZ ] );

void
fd_bls_pub_add( fd_bls_pub_t *       out,
                fd_bls_pub_t const * a,
                fd_bls_pub_t const * b );

void
fd_bls_pub_neg( fd_bls_pub_t *       out,
                fd_bls_pub_t const * a );

int
fd_bls_pub_is_inf( fd_bls_pub_t const * pub );

int
fd_bls_pub_eq( fd_bls_pub_t const * a,
               fd_bls_pub_t const * b );

/* Accumulates the set-selected public keys into out (caller initializes
   out; a fresh sum starts from the all-zero point). */
void
fd_bls_pub_sum( fd_bls_pub_t *       out,
                fd_bls_pub_t const * pubs,
                fd_bls_set_t const * set );

/* --- signatures (G2) --- */

void
fd_bls_sig_ser( fd_bls_sig_t const * sig,
                uchar                buf[ static FD_BLS_SIG_SZ ] );

/* fd_bls_sig_de deserializes and subgroup-validates a signature. */
int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    buf[ static FD_BLS_SIG_SZ ] );

void
fd_bls_sig_compress( fd_bls_sig_t const * sig,
                     uchar                buf[ static FD_BLS_SIG_COMPRESSED_SZ ] );

int
fd_bls_sig_de_compressed( fd_bls_sig_t * sig,
                          uchar const    buf[ static FD_BLS_SIG_COMPRESSED_SZ ] );

int
fd_bls_sig_de_unchecked( fd_bls_sig_t * sig,
                         uchar const    buf[ static FD_BLS_SIG_SZ ] );

void
fd_bls_sig_add( fd_bls_sig_t *       out,
                fd_bls_sig_t const * a,
                fd_bls_sig_t const * b );

void
fd_bls_sig_neg( fd_bls_sig_t *       out,
                fd_bls_sig_t const * a );

/* One iff sig is a validated subgroup point (infinity per blst). */
int
fd_bls_sig_validate( fd_bls_sig_t const * sig );

/* One iff sig is the point at infinity. */
int
fd_bls_sig_is_inf( fd_bls_sig_t const * sig );

int
fd_bls_sig_eq( fd_bls_sig_t const * a,
               fd_bls_sig_t const * b );

/* --- hash-to-curve and aggregate verification --- */

/* fd_bls_hash_msg sets h to H(msg) in G2 under FD_BLS_DST. */
void
fd_bls_hash_msg( uchar const *  msg,
                 ulong          msg_sz,
                 fd_bls_hash_t * h );

/* fd_bls_agg_verify_hashed verifies e(pub,H(msg))*e(-G1,sig)==1 with a
   precomputed hash. */
int
fd_bls_agg_verify_hashed( fd_bls_hash_t const * h,
                          fd_bls_pub_t const *  pub,
                          fd_bls_sig_t const *  sig );

fd_bls_agg_t *
fd_bls_agg_null( fd_bls_agg_t * agg );

fd_bls_agg_t *
fd_bls_agg_construct( fd_bls_agg_t *       agg,
                      fd_bls_pub_t const * pub,
                      fd_bls_sig_t const * sig,
                      fd_bls_set_t const * set );

int
fd_bls_agg_verify( uchar const *        msg,
                   ulong                msg_sz,
                   fd_bls_pub_t const * pub,
                   fd_bls_sig_t const * sig );

int
fd_bls_agg_verify_pair( uchar const *        msg,
                        ulong                msg_sz,
                        fd_bls_pub_t const * pub,
                        uchar const *        msg_fb,
                        ulong                msg_fb_sz,
                        fd_bls_pub_t const * pub_fb,
                        fd_bls_sig_t const * sig );

fd_bls_set_t *
fd_bls_agg_verify_linear( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad );

fd_bls_set_t *
fd_bls_agg_verify_bisect( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad );

int
fd_bls_agg_verify_subtract( fd_bls_agg_t *       agg,
                            uchar const *        msg,
                            ulong                msg_sz,
                            fd_bls_pub_t const * pub,
                            fd_bls_sig_t const * sig,
                            fd_bls_set_t *       bad );

/* --- byte-oriented (syscall) operations --- */

/* The byte-oriented operations use the Solana syscall encodings.  A G1
   point is x||y, a G2 point is x||y over Fp2, and big_endian selects the
   byte order of every field element and scalar.  Arithmetic accepts the
   same validation level as SIMD-0388: add/sub check curve encoding while
   mul additionally checks subgroup membership and scalar range.

   These operations return zero on success and -1 on failure.  Validation
   returns one for a valid subgroup point and zero otherwise. */

int fd_bls_g1_decompress( uchar       out[ 96 ],
                          uchar const in [ 48 ],
                          int         big_endian );
int fd_bls_g1_validate  ( uchar const in [ 96 ],
                          int         big_endian );
int fd_bls_g1_add       ( uchar       out[ 96 ],
                          uchar const a  [ 96 ],
                          uchar const b  [ 96 ],
                          int         big_endian );
int fd_bls_g1_sub       ( uchar       out[ 96 ],
                          uchar const a  [ 96 ],
                          uchar const b  [ 96 ],
                          int         big_endian );
int fd_bls_g1_mul       ( uchar       out[ 96 ],
                          uchar const scalar[ 32 ],
                          uchar const a     [ 96 ],
                          int         big_endian );

int fd_bls_g2_decompress( uchar       out[ 192 ],
                          uchar const in [  96 ],
                          int         big_endian );
int fd_bls_g2_compress  ( uchar       out[  96 ],
                          uchar const in [ 192 ],
                          int         big_endian );
int fd_bls_g2_validate  ( uchar const in [ 192 ],
                          int         big_endian );
int fd_bls_g2_add       ( uchar       out[ 192 ],
                          uchar const a  [ 192 ],
                          uchar const b  [ 192 ],
                          int         big_endian );
int fd_bls_g2_sub       ( uchar       out[ 192 ],
                          uchar const a  [ 192 ],
                          uchar const b  [ 192 ],
                          int         big_endian );
int fd_bls_g2_mul       ( uchar       out[ 192 ],
                          uchar const scalar[  32 ],
                          uchar const a     [ 192 ],
                          int         big_endian );

/* Computes prod_i e(g1[i],g2[i]) from byte-encoded subgroup points and
   writes the twelve Fp coefficients of GT in syscall wire order. */
int fd_bls_pairing_bytes( uchar       out[ 48*12 ],
                          uchar const g1 [],
                          uchar const g2 [],
                          ulong       cnt,
                          int         big_endian );

/* Verifies e(public_key,H(msg,domain))*e(-G1,signature)==1. */
int fd_bls_verify( uchar const  msg[],
                   ulong        msg_sz,
                   uchar const  signature[ 96 ],
                   uchar const  public_key[ 48 ],
                   char const * domain,
                   ulong        domain_len );

/* --- pairing over backend-neutral points --- */

/* Preparation trusts that q is a validated subgroup point. */
int fd_bls_g2_prepare( fd_bls_g2_prepared_t * out,
                       fd_bls_g2_t const *    q );

/* Verifies e(p_prepared,q_prepared)*e(p_checked,q_checked)==1.  q_checked is
   subgroup checked; the prepared pair is trusted. */
int fd_bls_pairing_finalverify_prepared_checked(
    fd_bls_g1_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *          p_checked,
    fd_bls_g2_t const *          q_checked );

/* Return one for the GT identity, zero otherwise, and -1 for invalid args. */
int fd_bls_pairing_finalverify( fd_bls_g1_t const * p,
                                fd_bls_g2_t const * q,
                                ulong               cnt );

/* q_subgroup_mask selects q inputs that are checked during the pairing. */
int fd_bls_pairing_finalverify_checked( fd_bls_g1_t const * p,
                                        fd_bls_g2_t const * q,
                                        ulong               cnt,
                                        ulong               q_subgroup_mask );

/* Computes prod_i e(p[i],q[i]) and exports its twelve Fp coefficients as
   canonical little-endian limbs.  The empty product is one. */
int fd_bls_pairing( ulong               out[12][6],
                    fd_bls_g1_t const * p,
                    fd_bls_g2_t const * q,
                    ulong               cnt );

FD_PROTOTYPES_END

#endif
