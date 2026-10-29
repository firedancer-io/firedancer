#ifndef HEADER_fd_src_ballet_bls_fd_bls_h
#define HEADER_fd_src_ballet_bls_fd_bls_h

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

typedef blst_scalar    fd_bls_sec_t;
typedef blst_p1        fd_bls_pub_t;
typedef blst_p2        fd_bls_sig_t;
typedef blst_p2_affine fd_bls_hash_t;

#define SET_NAME fd_bls_set
#define SET_MAX  FD_BLS_SET_MAX
#include "../../util/tmpl/fd_set.c" /* TODO make set_dynamic so this isn't dependent on the VAT cap */

struct fd_bls_agg {
  fd_bls_pub_t pub;
  fd_bls_sig_t sig;
  fd_bls_set_t set[ fd_bls_set_word_cnt ]; /* bit position is the signer's epoch rank */
};
typedef struct fd_bls_agg fd_bls_agg_t;

FD_PROTOTYPES_BEGIN

/* Secret keys */
void fd_bls_sec_to_pub( fd_bls_sec_t const * sec, fd_bls_pub_t * pub );
void fd_bls_sec_derive( fd_bls_sec_t * sec, uchar const * ikm, ulong ikm_sz );
void fd_bls_sec_sign( fd_bls_sec_t const * sec, uchar const * msg, ulong msg_sz, fd_bls_sig_t * sig );

/* Public Keys (G1).  fd_bls_pub_de accepts compressed or uncompressed
   encodings and rejects infinity and points outside G1. */
int  fd_bls_pub_de          ( fd_bls_pub_t * pub, uchar const * buf, ulong buf_sz );
/* fd_bls_pub_de_unchecked accepts only an uncompressed encoding and checks
   that it is a curve point, but skips the infinity and G1 subgroup checks.
   It is only for keys that have already passed those checks. */
int  fd_bls_pub_de_unchecked( fd_bls_pub_t * pub, uchar const buf[ static FD_BLS_PUB_SZ ] );
void fd_bls_pub_compress( fd_bls_pub_t const * pub, uchar buf[ static FD_BLS_PUB_COMPRESSED_SZ ] );
void fd_bls_pub_add     ( fd_bls_pub_t * out, fd_bls_pub_t const * a, fd_bls_pub_t const * b );
void fd_bls_pub_neg     ( fd_bls_pub_t * out, fd_bls_pub_t const * a );
int  fd_bls_pub_is_inf  ( fd_bls_pub_t const * pub );
int  fd_bls_pub_eq      ( fd_bls_pub_t const * a, fd_bls_pub_t const * b );
/* Overwrites out with the sum of the set-selected public keys.  The
   cached variant may use full (the sum of pubs[0..pub_cnt)) to subtract
   the complement when set is dense.  full may be NULL. */
void fd_bls_pub_sum       ( fd_bls_pub_t * out, fd_bls_pub_t const * pubs,                fd_bls_set_t const * set );
void fd_bls_pub_sum_cached( fd_bls_pub_t * out, fd_bls_pub_t const * pubs, ulong pub_cnt, fd_bls_set_t const * set, fd_bls_pub_t const * full );

/* Signatures (G2).  fd_bls_sig_de and _de_compressed subgorup-check their
   input.  _de_unchecked only checks that an uncompressed encoding is a curve
   point.*/
void fd_bls_sig_ser          ( fd_bls_sig_t const * sig, uchar buf[ static FD_BLS_SIG_SZ ] );
void fd_bls_sig_compress     ( fd_bls_sig_t const * sig, uchar buf[ static FD_BLS_SIG_COMPRESSED_SZ ] );
int  fd_bls_sig_de           ( fd_bls_sig_t * sig, uchar const buf[ static FD_BLS_SIG_SZ ] );
int  fd_bls_sig_de_compressed( fd_bls_sig_t * sig, uchar const buf[ static FD_BLS_SIG_COMPRESSED_SZ ] );
int  fd_bls_sig_de_unchecked ( fd_bls_sig_t * sig, uchar const buf[ static FD_BLS_SIG_SZ ] );
void fd_bls_sig_add          ( fd_bls_sig_t * out, fd_bls_sig_t const * a, fd_bls_sig_t const * b );
void fd_bls_sig_neg          ( fd_bls_sig_t * out, fd_bls_sig_t const * a );
int  fd_bls_sig_validate     ( fd_bls_sig_t const * sig );
int  fd_bls_sig_is_inf       ( fd_bls_sig_t const * sig );
int  fd_bls_sig_eq           ( fd_bls_sig_t const * a, fd_bls_sig_t const * b );

/* Hash-to-curve and verification */
void fd_bls_hash_msg( uchar const * msg, ulong msg_sz, fd_bls_hash_t * hash );
int  fd_bls_hash_eq( fd_bls_hash_t const * a, fd_bls_hash_t const * b );
int  fd_bls_agg_verify_hashed( fd_bls_hash_t const * hash, fd_bls_pub_t const * pub, fd_bls_sig_t const * sig );
int  fd_bls_agg_verify( uchar const * msg, ulong msg_sz, fd_bls_pub_t const * pub, fd_bls_sig_t const * sig );
int  fd_bls_agg_verify_pair( uchar const * msg, ulong msg_sz,
                             fd_bls_pub_t const * pub,
                             uchar const * msg_fallback, ulong msg_fallback_sz,
                             fd_bls_pub_t const * pub_fallback, fd_bls_sig_t const * sig );

/* Aggregate bookkeeping and bad-signer isolation */
fd_bls_agg_t * fd_bls_agg_null( fd_bls_agg_t * agg );
fd_bls_agg_t * fd_bls_agg_construct( fd_bls_agg_t * agg,       fd_bls_pub_t const * pub,
                                     fd_bls_sig_t const * sig, fd_bls_set_t const * set );
int fd_bls_agg_verify_subtract( fd_bls_agg_t * agg,
                                uchar const * msg, ulong msg_sz,
                                fd_bls_pub_t const * pub, fd_bls_sig_t const * sig,
                                fd_bls_set_t * bad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bls_fd_bls_h */
