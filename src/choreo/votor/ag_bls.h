#ifndef HEADER_fd_src_choreo_votor_ag_bls_h
#define HEADER_fd_src_choreo_votor_ag_bls_h

#include "../../util/fd_util.h"
#include "../../third_party/blst/bindings/blst.h"
#include "ag_votor_base.h"

#define AG_BLS_SEC_SZ            (32UL)
#define AG_BLS_PUB_SZ            (96UL)
#define AG_BLS_PUB_COMPRESSED_SZ (48UL)
#define AG_BLS_SIG_SZ            (192UL)
#define AG_BLS_SIG_COMPRESSED_SZ (96UL)
#define AG_BLS_SET_MAX           (AG_VAT_MAX)
#define AG_BLS_DST               "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define AG_BLS_DST_SZ            (sizeof(AG_BLS_DST)-1UL)

typedef blst_scalar ag_bls_sec_t;
typedef blst_p1     ag_bls_pub_t;
typedef blst_p2     ag_bls_sig_t;

#define SET_NAME ag_bls_set
#define SET_MAX  AG_BLS_SET_MAX
#include "../../util/tmpl/fd_set.c"

struct ag_bls_agg {
  ag_bls_sig_t sig;
  ag_bls_set_t set[ ag_bls_set_word_cnt ]; /* each bit position corresponds to a signer's rank in the epoch (based on ag_epoch_info) */
};
typedef struct ag_bls_agg ag_bls_agg_t;

typedef void
(* ag_bls_sign_fn)( void *         ctx,
                    ag_bls_sig_t * sig,
                    uchar const *  payload,
                    ulong          payload_sz );

FD_PROTOTYPES_BEGIN

/* SecretKey::to_pk */

void
ag_bls_sec_to_pub( ag_bls_sec_t const * sec,
                   ag_bls_pub_t *       pub );

/* solana_bls_signatures::SecretKey::derive */

void
ag_bls_sec_derive( ag_bls_sec_t * sec,
                   uchar const *  ikm,
                   ulong          ikm_sz );

/* SecretKey::sign_bytes */

void
ag_bls_sec_sign( ag_bls_sec_t const * sec,
                 uchar const *        msg,
                 ulong                msg_sz,
                 ag_bls_sig_t *       sig );

/* ag_bls_sec_sign_fn is an ag_bls_sign_fn adapter around
   ag_bls_sec_sign; ctx points to an ag_bls_sec_t.  For tests that have
   the secret key in-memory; a live validator should be signing via the
   keyguard client instead. */

void
ag_bls_sec_sign_fn( void *         ctx,
                    ag_bls_sig_t * sig,
                    uchar const *  msg,
                    ulong          msg_sz );

/* ag_bls_sig_ser writes the canonical uncompressed encoding of sig
   (AG_BLS_SIG_SZ bytes) to out.  ag_bls_sig_de parses such an encoding
   into sig, returning 0 on success and -1 if the bytes are not a valid
   G2 point.  Translates between raw bytes and the canonical encoding. */

void
ag_bls_sig_ser( uchar                out[ static AG_BLS_SIG_SZ ],
                ag_bls_sig_t const * sig );

int
ag_bls_sig_de( ag_bls_sig_t * sig,
               uchar const    in[ static AG_BLS_SIG_SZ ] );

/* PublicKey::try_from_bytes */

int
ag_bls_pub_try_from_bytes( ag_bls_pub_t * out,
                           uchar const *  in,
                           ulong          in_sz );

int
ag_bls_agg_verify( ag_bls_pub_t const * pub,
                   ag_bls_sig_t const * agg,
                   uchar const *        msg,
                   ulong                msg_sz );

FD_PROTOTYPES_END

#endif
