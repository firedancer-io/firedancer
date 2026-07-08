#ifndef HEADER_fd_src_alpenglow_crypto_ag_aggsig_h
#define HEADER_fd_src_alpenglow_crypto_ag_aggsig_h

#include "../ag_alpenglow_base.h"

#define SET_NAME signer_set
#define SET_MAX  2048
#include "../../util/tmpl/fd_set.c"

#define AG_AGGSIG_SECKEY_SZ            (32UL)
#define AG_AGGSIG_PUBKEY_SZ            (96UL)  /* uncompressed G1 (min_sig) */
#define AG_AGGSIG_PUBKEY_COMPRESSED_SZ (48UL)
#define AG_AGGSIG_SIG_SZ               (192UL) /* uncompressed G2 (min_sig) */
#define AG_AGGSIG_SIG_COMPRESSED_SZ    (96UL)
#define AG_AGGSIG_MAX_SIGNERS          (2048UL)

struct ag_aggsig_sk { uchar v[ AG_AGGSIG_SECKEY_SZ ]; };
typedef struct ag_aggsig_sk ag_aggsig_sk_t;

struct ag_aggsig_pk { uchar v[ AG_AGGSIG_PUBKEY_SZ ]; };
typedef struct ag_aggsig_pk ag_aggsig_pk_t;

struct ag_aggsig_sig { uchar v[ AG_AGGSIG_SIG_SZ ]; };
typedef struct ag_aggsig_sig ag_aggsig_sig_t;

struct ag_aggsig {
  uchar        sig[ AG_AGGSIG_SIG_SZ ];
  ulong        nbits;
  signer_set_t bitmask[ signer_set_word_cnt ];
};
typedef struct ag_aggsig ag_aggsig_t;

#define AG_AGGSIG_WORDS_FOR_BITS(nbits) (((nbits)+63UL)/64UL)
#define AG_AGGSIG_SERIALIZED_SZ(nbits)  (AG_AGGSIG_SIG_SZ + 8UL + 8UL + 8UL*AG_AGGSIG_WORDS_FOR_BITS(nbits))

#define AG_AGGSIG_SERIALIZED_MAX        (AG_AGGSIG_SERIALIZED_SZ(AG_AGGSIG_MAX_SIGNERS))

FD_PROTOTYPES_BEGIN

void
ag_aggsig_sk_to_pk( ag_aggsig_pk_t *       pk,
                    ag_aggsig_sk_t const * sk );

void
ag_aggsig_sk_derive( ag_aggsig_sk_t * sk,
                     uchar const *    ikm,
                     ulong            ikm_sz );

void
ag_aggsig_sign_bytes( ag_aggsig_sig_t *      sig,
                      ag_aggsig_sk_t const * sk,
                      uchar const *          msg,
                      ulong                  msg_sz );

int
ag_aggsig_individual_verify_bytes( ag_aggsig_sig_t const * self,
                                   ag_aggsig_pk_t const *  pk,
                                   uchar const *           msg,
                                   ulong                   msg_sz );

void
ag_aggsig_new( ag_aggsig_t *           agg,
               ag_aggsig_sig_t const * sigs,
               ulong const *           indices,
               ulong                   cnt,
               ulong                   nbits );

void
ag_aggsig_init( ag_aggsig_t * agg,
                ulong         nbits );

void
ag_aggsig_add( ag_aggsig_t *           self,
               ulong                   signer_idx,
               ag_aggsig_sig_t const * sig );

/* ag_aggsig_merge_sig folds src's partial aggregate sig into dst and zeroes
   src's sig: one total aggregate sig (in the base agg) covers both signer
   groups, per verify_mixed_bytes and the wire encoding. */

void
ag_aggsig_merge_sig( ag_aggsig_t * dst,
                     ag_aggsig_t * src );

int
ag_aggsig_verify_bytes( ag_aggsig_t const *    self,
                        uchar const *          msg,
                        ulong                  msg_sz,
                        ag_aggsig_pk_t const * pks,
                        ulong                  pk_cnt );

int
ag_aggsig_verify_mixed_bytes( ag_aggsig_t const *    agg_base,
                              uchar const *          msg_base,
                              ulong                  msg_base_sz,
                              ag_aggsig_t const *    agg_fb,
                              uchar const *          msg_fb,
                              ulong                  msg_fb_sz,
                              ag_aggsig_pk_t const * pks,
                              ulong                  pk_cnt );

FD_FN_PURE static inline int
ag_aggsig_is_signer( ag_aggsig_t const * self,
                     ulong               validator_idx ) {
  if( FD_UNLIKELY( validator_idx>=self->nbits ) ) return 0;
  return signer_set_test( self->bitmask, validator_idx );
}

FD_FN_PURE static inline ulong
ag_aggsig_signer_cnt( ag_aggsig_t const * self ) {
  return signer_set_cnt( self->bitmask );
}

ulong
ag_aggsig_serialize( ag_aggsig_t const * agg,
                     uchar *             out,
                     ulong               out_max );

ulong
ag_aggsig_deserialize( ag_aggsig_t * agg,
                       uchar const * in,
                       ulong         in_sz );

FD_PROTOTYPES_END

#endif
