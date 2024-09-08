#ifndef HEADER_fd_zksdk_batched_range_proofs_h
#define HEADER_fd_zksdk_batched_range_proofs_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) fd_zksdk_range_proof_u64_proof {
  fd_rangeproofs_range_proof_t range_proof;
  fd_rangeproofs_ipp_vecs_t    ipp_lr_vec[ 6 ]; // log(bit_length) points
  uchar                        ipp_a[ 32 ];     // scalar
  uchar                        ipp_b[ 32 ];     // scalar
};
typedef struct fd_zksdk_range_proof_u64_proof fd_zksdk_range_proof_u64_proof_t;

struct __attribute__((packed)) fd_zksdk_range_proof_u128_proof {
  fd_rangeproofs_range_proof_t range_proof;
  fd_rangeproofs_ipp_vecs_t    ipp_lr_vec[ 7 ]; // log(bit_length) points
  uchar                        ipp_a[ 32 ];     // scalar
  uchar                        ipp_b[ 32 ];     // scalar
};
typedef struct fd_zksdk_range_proof_u128_proof fd_zksdk_range_proof_u128_proof_t;

struct __attribute__((packed)) fd_zksdk_range_proof_u256_proof {
  fd_rangeproofs_range_proof_t range_proof;
  fd_rangeproofs_ipp_vecs_t    ipp_lr_vec[ 8 ]; // log(bit_length) points
  uchar                        ipp_a[ 32 ];     // scalar
  uchar                        ipp_b[ 32 ];     // scalar
};
typedef struct fd_zksdk_range_proof_u256_proof fd_zksdk_range_proof_u256_proof_t;

#define FD_ZKSDK_MAX_COMMITMENTS FD_RANGEPROOFS_MAX_COMMITMENTS
struct __attribute__((packed)) fd_zksdk_batched_range_proof_context {
  uchar commitments[ FD_ZKSDK_MAX_COMMITMENTS * 32 ]; // points
  uchar bit_lengths[ FD_ZKSDK_MAX_COMMITMENTS ];
};
typedef struct fd_zksdk_batched_range_proof_context fd_zksdk_batched_range_proof_context_t;

static inline void
batched_range_proof_transcript_init( fd_zksdk_transcript_t *                        transcript,
                                     fd_zksdk_batched_range_proof_context_t const * context) {
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("batched-range-proof-instruction") );
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("commitments"), context->commitments, FD_ZKSDK_MAX_COMMITMENTS * 32 );
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("bit-lengths"), context->bit_lengths, FD_ZKSDK_MAX_COMMITMENTS );
}

/* batched_range_proof_init_and_validate implements verify_proof() for range proofs:
   https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u64.rs#L82
   It validates context, initializes the transcript, and returns the length of
   commitments / bit_lenghts, i.e. the size of the batch in the batch proof, aka m.
   For compatibility with Agave, this is the critical rule:
   https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/mod.rs#L112
   i.e., the length is determined by the first all-zero commitment.
   Note that Agave is decompressing points while parsing the context, we don't do
   that here but at the very beginning of the ZKP verify, e.g. fd_zksdk_verify_proof_range_u128(). */
static inline int
batched_range_proof_init_and_validate( uchar *                                        len,
                                       fd_zksdk_batched_range_proof_context_t const * context,
                                       fd_zksdk_transcript_t *                        transcript ) {

  uchar i = 0;
  for( ; i < FD_ZKSDK_MAX_COMMITMENTS; i++ ) {
    if( fd_memeq( &context->commitments[ i*32 ], fd_ristretto255_compressed_zero, 32 ) ) {
      break;
    }
  }
  *len = i;

  //TODO: https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u64.rs#L87

  batched_range_proof_transcript_init( transcript, context );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

#endif /* HEADER_fd_zksdk_batched_range_proofs_h */
