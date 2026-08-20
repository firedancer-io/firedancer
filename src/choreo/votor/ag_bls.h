/* TODO remove an replace with proper BLS lib */

#ifndef HEADER_fd_src_choreo_votor_ag_bls_h
#define HEADER_fd_src_choreo_votor_ag_bls_h

#include "ag_votor_base.h"

#define SET_NAME voter_set
#define SET_MAX  AG_VAT_MAX
#include "../../util/tmpl/fd_set.c"

#define AG_BLS_SEC_SZ            (32UL)
#define AG_BLS_PUB_SZ            (96UL)
#define AG_BLS_PUB_COMPRESSED_SZ (48UL)
#define AG_BLS_SIG_SZ            (192UL)
#define AG_BLS_SIG_COMPRESSED_SZ (96UL)
#define AG_BLS_MAX_SIGNERS       (2000UL)

/* A BLS secret key, public key and individual signature.  These are
   fixed size byte blobs with no value semantics: pass them by decay and
   copy them with fd_memcpy, never by assignment. */

typedef uchar ag_bls_sec_t[ AG_BLS_SEC_SZ ];
typedef uchar ag_bls_pub_t[ AG_BLS_PUB_SZ ];
typedef uchar ag_bls_sig_t[ AG_BLS_SIG_SZ ];

/* An aggregate signature: the aggregated curve point plus the bitmask
   naming which validator ranks contributed to it. */

struct ag_bls_agg {
  ag_bls_sig_t sig;
  ulong        nbits;
  voter_set_t  bitmask[ voter_set_word_cnt ];
};
typedef struct ag_bls_agg ag_bls_agg_t;

#define AG_BLS_WORDS_FOR_BITS(nbits) (((nbits)+63UL)/64UL)
#define AG_BLS_SERIALIZED_SZ(nbits)  (AG_BLS_SIG_SZ + 8UL + 8UL + 8UL*AG_BLS_WORDS_FOR_BITS(nbits))

#define AG_BLS_SERIALIZED_MAX        (AG_BLS_SERIALIZED_SZ(AG_BLS_MAX_SIGNERS))

typedef void
(* ag_bls_sign_fn)( void *        ctx,
                    ag_bls_sig_t  sig,
                    uchar const * payload,
                    ulong         payload_sz );

FD_PROTOTYPES_BEGIN

void
ag_bls_sign_local( void *        ctx,
                   ag_bls_sig_t  sig,
                   uchar const * payload,
                   ulong         payload_sz );

void
ag_bls_sec_to_pub( ag_bls_pub_t       pub,
                   ag_bls_sec_t const sec );

void
ag_bls_sec_to_pub_compressed( uchar              out[ AG_BLS_PUB_COMPRESSED_SZ ],
                              ag_bls_sec_t const sec );

void
ag_bls_sec_derive( ag_bls_sec_t  sec,
                   uchar const * ikm,
                   ulong         ikm_sz );

/* ag_bls_pub_try_from_bytes mirrors PublicKey::try_from_bytes: it
   validates that `in` is a well formed, prime-order, non-infinity G1
   point and materialises it uncompressed.  Accepts either the
   compressed (AG_BLS_PUB_COMPRESSED_SZ) or affine (AG_BLS_PUB_SZ)
   encoding.  Returns 0 on success, -1 otherwise, in which case out is
   untouched. */

int
ag_bls_pub_try_from_bytes( ag_bls_pub_t  out,
                           uchar const * in,
                           ulong         in_sz );

void
ag_bls_sec_sign_bytes( ag_bls_sig_t       sig,
                       ag_bls_sec_t const sec,
                       uchar const *      msg,
                       ulong              msg_sz );

int
ag_bls_sig_verify_bytes( ag_bls_sig_t const sig,
                         ag_bls_pub_t const pub,
                         uchar const *      msg,
                         ulong              msg_sz );

void
ag_bls_agg_new( ag_bls_agg_t *       agg,
                ag_bls_sig_t const * sigs,
                ulong const *        indices,
                ulong                cnt,
                ulong                nbits );

void
ag_bls_agg_init( ag_bls_agg_t * agg,
                 ulong          nbits );

void
ag_bls_agg_add( ag_bls_agg_t *     self,
                ulong              signer_idx,
                ag_bls_sig_t const sig );

void
ag_bls_agg_merge( ag_bls_agg_t * dst,
                  ag_bls_agg_t * src );

int
ag_bls_agg_verify_bytes( ag_bls_agg_t const * self,
                         uchar const *        msg,
                         ulong                msg_sz,
                         uchar const *        pk0,
                         ulong                pk_stride,
                         ulong                pk_cnt );

/* ag_bls_agg_verify_without_bitmask mirrors
   AggregateSignature::verify_without_bitmask: the caller supplies
   exactly the signers' keys rather than the whole validator set, so the
   bitmask selects nothing and every supplied key is aggregated.  Fails
   unless signer_cnt equals pk_cnt. */

int
ag_bls_agg_verify_without_bitmask( ag_bls_agg_t const * self,
                                   uchar const *        msg,
                                   ulong                msg_sz,
                                   uchar const *        pk0,
                                   ulong                pk_stride,
                                   ulong                pk_cnt );

int
ag_bls_agg_verify_mixed_bytes( ag_bls_agg_t const * agg_base,
                               uchar const *        msg_base,
                               ulong                msg_base_sz,
                               ag_bls_agg_t const * agg_fb,
                               uchar const *        msg_fb,
                               ulong                msg_fb_sz,
                               uchar const *        pk0,
                               ulong                pk_stride,
                               ulong                pk_cnt );

FD_FN_PURE static inline int
ag_bls_agg_is_signer( ag_bls_agg_t const * self,
                      ulong                validator_idx ) {
  if( FD_UNLIKELY( validator_idx>=self->nbits ) ) return 0;
  return voter_set_test( self->bitmask, validator_idx );
}

FD_FN_PURE static inline ulong
ag_bls_agg_signer_cnt( ag_bls_agg_t const * self ) {
  return voter_set_cnt( self->bitmask );
}

/* ag_bls_agg_signers_* mirror AggregateSignature::signers(): they
   iterate the validator indices whose signature is in the aggregate, so
   callers need not reach into the bitmask.  Usage:

     for( ulong i=ag_bls_agg_signers_init( agg );
          !ag_bls_agg_signers_done( i );
          i=ag_bls_agg_signers_next( agg, i ) ) ... */

FD_FN_PURE static inline ulong
ag_bls_agg_signers_init( ag_bls_agg_t const * self ) {
  return voter_set_const_iter_init( self->bitmask );
}

FD_FN_CONST static inline int
ag_bls_agg_signers_done( ulong i ) {
  return !!voter_set_const_iter_done( i ); /* tmpl returns ulong; narrow to 0/1 */
}

FD_FN_PURE static inline ulong
ag_bls_agg_signers_next( ag_bls_agg_t const * self,
                         ulong                i ) {
  return voter_set_const_iter_next( self->bitmask, i );
}

FD_PROTOTYPES_END

#endif
