#ifndef HEADER_fd_src_choreo_votor_ag_bls_h
#define HEADER_fd_src_choreo_votor_ag_bls_h

#include "../../util/fd_util.h"

#define AG_BLS_SEC_SZ            (32UL)
#define AG_BLS_PUB_SZ            (96UL)
#define AG_BLS_PUB_COMPRESSED_SZ (48UL)
#define AG_BLS_SIG_SZ            (192UL)
#define AG_BLS_SIG_COMPRESSED_SZ (96UL)
#define AG_BLS_SIGNERS_MAX       (2048UL)

#define SET_NAME signer_set
#define SET_MAX  AG_BLS_SIGNERS_MAX
#include "../../util/tmpl/fd_set.c"

typedef uchar ag_bls_sec_t[ AG_BLS_SEC_SZ ];
typedef uchar ag_bls_pub_t[ AG_BLS_PUB_SZ ];
typedef uchar ag_bls_sig_t[ AG_BLS_SIG_SZ ];

struct ag_bls_agg {
  ag_bls_sig_t sig;
  signer_set_t bitmask[ signer_set_word_cnt ];
};
typedef struct ag_bls_agg ag_bls_agg_t;

#define AG_BLS_WORDS_FOR_BITS(bit_cnt) (((bit_cnt)+63UL)/64UL)
#define AG_BLS_SER_SZ(bit_cnt)         (AG_BLS_SIG_SZ + 8UL + 8UL + 8UL*AG_BLS_WORDS_FOR_BITS(bit_cnt))
#define AG_BLS_SER_MAX                 (AG_BLS_SER_SZ(AG_BLS_SIGNERS_MAX))

typedef void
(* ag_bls_sign_fn)( void *        ctx,
                    ag_bls_sig_t  sig,
                    uchar const * payload,
                    ulong         payload_sz );

FD_PROTOTYPES_BEGIN

/* SecretKey::to_pk */

void
ag_bls_sec_to_pub( ag_bls_sec_t const sec,
                   ag_bls_pub_t       pub );

/* solana_bls_signatures::SecretKey::derive */

void
ag_bls_sec_derive( ag_bls_sec_t  sec,
                   uchar const * ikm,
                   ulong         ikm_sz );

/* SecretKey::sign_bytes */

void
ag_bls_sec_sign( ag_bls_sec_t const sec,
                 ag_bls_sig_t       sig,
                 uchar const *      msg,
                 ulong              msg_sz );

/* PublicKey::try_from_bytes */

int
ag_bls_pub_try_from_bytes( ag_bls_pub_t  out,
                           uchar const * in,
                           ulong         in_sz );

/* IndividualSignature::verify_bytes */

int
ag_bls_sig_verify( ag_bls_sig_t const sig,
                   ag_bls_pub_t const pub,
                   uchar const *      msg,
                   ulong              msg_sz );

/* AggregateSignature::new */

void
ag_bls_agg_zero( ag_bls_agg_t * agg );

/* AggregateSignature::new */

void
ag_bls_agg_add( ag_bls_agg_t *     self,
                ulong              rank,
                ag_bls_sig_t const sig );

/* agave AggregateAccumulator::add_aggregate */

void
ag_bls_agg_merge( ag_bls_agg_t * dst,
                  ag_bls_agg_t * src );

/* agave AggregateAccumulator::is_identity */

int
ag_bls_agg_is_identity( ag_bls_agg_t const * self );

/* AggregateSignature::verify_bytes */

int
ag_bls_agg_verify( ag_bls_agg_t const * self,
                   uchar const *        msg,
                   ulong                msg_sz,
                   uchar const *        pk0,
                   ulong                pk_stride,
                   ulong                pk_cnt );

/* AggregateSignature::verify_without_bitmask */

int
ag_bls_agg_verify_without_bitmask( ag_bls_agg_t const * self,
                                   uchar const *        msg,
                                   ulong                msg_sz,
                                   uchar const *        pk0,
                                   ulong                pk_stride,
                                   ulong                pk_cnt );

/* agave verify_base3 */

int
ag_bls_agg_verify_merged( ag_bls_agg_t const * agg_base,
                         uchar const *        msg_base,
                         ulong                msg_base_sz,
                         ag_bls_agg_t const * agg_fb,
                         uchar const *        msg_fb,
                         ulong                msg_fb_sz,
                         uchar const *        pk0,
                         ulong                pk_stride,
                         ulong                pk_cnt );

/* AggregateSignature::is_signer */

FD_FN_PURE static inline int
ag_bls_agg_is_signer( ag_bls_agg_t const * self,
                      ulong                rank ) {
  if( FD_UNLIKELY( rank>=AG_BLS_SIGNERS_MAX ) ) return 0;
  return signer_set_test( self->bitmask, rank );
}

/* AggregateSignature::signers */

FD_FN_PURE static inline ulong
ag_bls_agg_signer_cnt( ag_bls_agg_t const * self ) {
  return signer_set_cnt( self->bitmask );
}

FD_FN_PURE static inline ulong
ag_bls_agg_signers_iter_init( ag_bls_agg_t const * self ) {
  return signer_set_const_iter_init( self->bitmask );
}

FD_FN_CONST static inline int
ag_bls_agg_signers_iter_done( ulong i ) {
  return !!signer_set_const_iter_done( i );
}

FD_FN_PURE static inline ulong
ag_bls_agg_signers_iter_next( ag_bls_agg_t const * self,
                              ulong                i ) {
  return signer_set_const_iter_next( self->bitmask, i );
}

FD_PROTOTYPES_END

#endif
