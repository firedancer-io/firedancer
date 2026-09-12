#ifndef HEADER_fd_src_ballet_bls_fd_bls_h
#define HEADER_fd_src_ballet_bls_fd_bls_h

#include "../../util/fd_util.h"
#include "../../third_party/blst/bindings/blst.h"
#include "fd_bls_err.h"

#define FD_BLS_SEC_SZ            (32UL)
#define FD_BLS_PUB_SZ            (96UL)
#define FD_BLS_PUB_COMPRESSED_SZ (48UL)
#define FD_BLS_SIG_SZ            (192UL)
#define FD_BLS_SIG_COMPRESSED_SZ (96UL)
#define FD_BLS_SET_MAX           (2000UL) /* TODO make set_dynamic so this isn't dependent on the VAT cap */
#define FD_BLS_DST               "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define FD_BLS_DST_SZ            (sizeof(FD_BLS_DST)-1UL)

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

FD_PROTOTYPES_BEGIN

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

void
fd_bls_sig_ser( fd_bls_sig_t const * sig,
                uchar                buf[ static FD_BLS_SIG_SZ ] );

int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    buf[ static FD_BLS_SIG_SZ ] );

int
fd_bls_pub_de( fd_bls_pub_t * pub,
               uchar const *  buf,
               ulong          buf_sz );

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

FD_PROTOTYPES_END

#endif
