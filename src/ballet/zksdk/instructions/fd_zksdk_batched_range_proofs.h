#ifndef HEADER_fd_src_ballet_zksdk_instructions_fd_zksdk_batched_range_proofs_h
#define HEADER_fd_src_ballet_zksdk_instructions_fd_zksdk_batched_range_proofs_h

#include "../fd_zksdk_common.h"

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

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/mod.rs#L63 */
static inline void
batched_range_proof_context_new_transcript( fd_zksdk_transcript_t *                        transcript,
                                            fd_zksdk_batched_range_proof_context_t const * context) {
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("batched-range-proof-instruction") );
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("commitments"), context->commitments, FD_ZKSDK_MAX_COMMITMENTS * 32 );
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("bit-lengths"), context->bit_lengths, FD_ZKSDK_MAX_COMMITMENTS );
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/mod.rs#L117 */
static inline int
batched_range_proof_context_try_into( uchar *                                        _len,
                                      fd_zksdk_batched_range_proof_context_t const * context ) {

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/mod.rs#L118-L121
     Compute len as index of first commitment set to zero. */
  uchar len = 0;
  for( ; len<FD_ZKSDK_MAX_COMMITMENTS; len++ ) {
    if( fd_memeq( &context->commitments[ len*32 ], fd_ristretto255_compressed_zero, 32 ) ) {
      break;
    }
  }

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/mod.rs#L134-L136 */
  if( FD_UNLIKELY( len == 0 ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/mod.rs#L139-L144
     All bit lengths must be non-zero and <= 64. */
  for( uchar i=0; i<len; i++ ) {
    if( FD_UNLIKELY( context->bit_lengths[ i ]==0 || context->bit_lengths[ i ]>64 ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
  }

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/mod.rs#L147-L158
     All commitments and bit lengths after len must be zero. */
  for( uchar i=len; i<FD_ZKSDK_MAX_COMMITMENTS; i++ ) {
    if( FD_UNLIKELY(
      !fd_memeq( &context->commitments[ i*32 ], fd_ristretto255_compressed_zero, 32 )
      || context->bit_lengths[ i ]!=0
    ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
  }

  *_len = len;
  return FD_ZKSDK_VERIFY_PROOF_SUCCESS;
}

#endif /* HEADER_fd_src_ballet_zksdk_instructions_fd_zksdk_batched_range_proofs_h */
