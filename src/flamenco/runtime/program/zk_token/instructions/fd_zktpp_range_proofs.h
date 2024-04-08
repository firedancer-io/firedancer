#ifndef HEADER_fd_zktpp_range_proofs_h
#define HEADER_fd_zktpp_range_proofs_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) fd_zktpp_range_proof_u64_proof {
  fd_bulletproofs_range_proof_t range_proof;
  fd_bulletproofs_ipp_vecs_t    ipp_lr_vec[ 6 ]; // log(bit_length) points
  uchar                         ipp_a[ 32 ];     // scalar
  uchar                         ipp_b[ 32 ];     // scalar
};
typedef struct fd_zktpp_range_proof_u64_proof fd_zktpp_range_proof_u64_proof_t;

struct __attribute__((packed)) fd_zktpp_range_proof_u128_proof {
  fd_bulletproofs_range_proof_t range_proof;
  fd_bulletproofs_ipp_vecs_t    ipp_lr_vec[ 7 ]; // log(bit_length) points
  uchar                         ipp_a[ 32 ];     // scalar
  uchar                         ipp_b[ 32 ];     // scalar
};
typedef struct fd_zktpp_range_proof_u128_proof fd_zktpp_range_proof_u128_proof_t;

struct __attribute__((packed)) fd_zktpp_range_proof_u256_proof {
  fd_bulletproofs_range_proof_t range_proof;
  fd_bulletproofs_ipp_vecs_t    ipp_lr_vec[ 8 ]; // log(bit_length) points
  uchar                         ipp_a[ 32 ];     // scalar
  uchar                         ipp_b[ 32 ];     // scalar
};
typedef struct fd_zktpp_range_proof_u256_proof fd_zktpp_range_proof_u256_proof_t;

#define FD_ZKTPP_MAX_COMMITMENTS FD_BULLETPROOFS_MAX_COMMITMENTS
struct __attribute__((packed)) fd_zktpp_batched_range_proof_context {
  uchar commitments[ FD_ZKTPP_MAX_COMMITMENTS * 32 ]; // points
  uchar bit_lengths[ FD_ZKTPP_MAX_COMMITMENTS ];
};
typedef struct fd_zktpp_batched_range_proof_context fd_zktpp_batched_range_proof_context_t;

struct __attribute__((packed)) fd_zktpp_single_range_proof_context {
  uchar commitment[ 32 ]; // point
};
typedef struct fd_zktpp_single_range_proof_context fd_zktpp_single_range_proof_context_t;


static inline void
batched_range_proof_transcript_init( fd_zktpp_transcript_t *                        transcript,
                                     fd_zktpp_batched_range_proof_context_t const * context) {
  fd_zktpp_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("BatchedRangeProof") );
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("commitments"), context->commitments, FD_ZKTPP_MAX_COMMITMENTS * 32 );
  fd_merlin_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("bit-lengths"), context->bit_lengths, FD_ZKTPP_MAX_COMMITMENTS );
}

/* batched_range_proof_validate_context validates a context and return the length
   of commitments / bit_lenghts, i.e. the size of the batch in the batch proof, aka m.
   For compatibility with Solana, this is the critical rule:
   https://github.com/solana-labs/solana/blob/v1.17.15/zk-token-sdk/src/instruction/batched_range_proof/mod.rs#L108
   i.e., the length is determined by the first all-zero commitment.
   Note that Solana is decompressing points while parsing the context, we don't do
   that here but at the very beginning of the ZKP verify, e.g. fd_zktpp_verify_proof_range_u128().
   In this implementation we guarantee that len <= FD_ZKTPP_MAX_COMMITMENTS. */
static inline int
batched_range_proof_validate_context( uchar *                                        len,
                                      fd_zktpp_batched_range_proof_context_t const * context ) {
  uchar i = 0;
  for( ; i < FD_ZKTPP_MAX_COMMITMENTS; i++ ) {
    if( fd_memeq( &context->commitments[ i*32 ], fd_ristretto255_compressed_zero, 32 ) ) {
      break;
    }
  }
  *len = i;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_zktpp_verify_proof_range_u64(
  fd_zktpp_range_proof_u64_proof_t const * proof,
  uchar const                              commitments [ static 32 ],
  uchar const                              bit_lengths [ static 1 ],
  uchar const                              batch_len,
  fd_zktpp_transcript_t *                  transcript );

int
fd_zktpp_verify_proof_range_u128(
  fd_zktpp_range_proof_u128_proof_t const * proof,
  uchar const                               commitments [ static 32 ],
  uchar const                               bit_lengths [ static 1 ],
  uchar const                               batch_len,
  fd_zktpp_transcript_t *                   transcript );

#endif /* HEADER_fd_zktpp_range_proofs_h */
