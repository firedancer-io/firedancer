#include "../fd_zktpp_private.h"

#define FD_ZKTPP_TRANSFER_SOURCE_AMOUNT_BITS     64
#define FD_ZKTPP_TRANSFER_AMOUNT_LO_BITS         16
#define FD_ZKTPP_TRANSFER_AMOUNT_LO_NEGATED_BITS 16
#define FD_ZKTPP_TRANSFER_AMOUNT_HI_BITS         16

static void
transfer_transcript_init( fd_zktpp_transcript_t *             transcript,
                          fd_zktpp_transfer_context_t const * context ) {
  fd_zktpp_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("transfer-proof") );
  fd_zktpp_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("ciphertext-lo"), (const uchar *)&context->ciphertext_lo, 128 );
  fd_zktpp_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("ciphertext-hi"), (const uchar *)&context->ciphertext_hi, 128 );
  fd_zktpp_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("transfer-pubkeys"), (const uchar *)&context->transfer_pubkeys, 96 );
  fd_zktpp_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("new-source-ciphertext"), context->new_source_ciphertext, 64 );
}

int
fd_zktpp_instr_verify_proof_transfer_without_fee( void const * _context, void const *_proof ) {
  fd_zktpp_transcript_t               transcript[1];
  fd_zktpp_transfer_context_t const * context = _context;
  fd_zktpp_transfer_proof_t const *   proof = _proof;
  int zkp_res = 0;

  transfer_transcript_init( transcript, context );
  fd_zktpp_transcript_append_commitment( transcript, FD_TRANSCRIPT_LITERAL("commitment-new-source"), proof->new_source_commitment );

  zkp_res = fd_zktpp_verify_proof_ciphertext_commitment_equality(
    &proof->equality_proof,
    context->transfer_pubkeys.source,
    context->new_source_ciphertext,
    proof->new_source_commitment,
    transcript
  );
  if( FD_UNLIKELY( zkp_res!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  zkp_res = fd_zktpp_verify_proof_batched_grouped_ciphertext_validity(
    &proof->validity_proof,
    context->transfer_pubkeys.destination,
    context->transfer_pubkeys.auditor,
    context->ciphertext_lo.commitment,
    context->ciphertext_hi.commitment,
    context->ciphertext_lo.destination_handle,
    context->ciphertext_hi.destination_handle,
    context->ciphertext_lo.auditor_handle,
    context->ciphertext_hi.auditor_handle,
    transcript
  );
  if( FD_UNLIKELY( zkp_res!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  //TODO: case TRANSFER_AMOUNT_LO_BITS == 32

  uchar commitment_lo_negated[ 32 ];
  fd_memset( commitment_lo_negated, 0, 32 );
  //TODO: compute commitment_lo_negated
  uchar commitments[ 32*4 ];
  fd_memcpy( &commitments[  0 ], proof->new_source_commitment, 32 );
  fd_memcpy( &commitments[ 32 ], context->ciphertext_lo.commitment, 32 );
  fd_memcpy( &commitments[ 64 ], commitment_lo_negated, 32 );
  fd_memcpy( &commitments[ 96 ], context->ciphertext_hi.commitment, 32 );

  uchar bit_lengths[4] = {
    FD_ZKTPP_TRANSFER_SOURCE_AMOUNT_BITS,
    FD_ZKTPP_TRANSFER_AMOUNT_LO_BITS,
    FD_ZKTPP_TRANSFER_AMOUNT_LO_NEGATED_BITS,
    FD_ZKTPP_TRANSFER_AMOUNT_HI_BITS,
  };
  zkp_res = fd_zktpp_verify_proof_range_u128(
    &proof->range_proof,
    commitments,
    bit_lengths,
    4,
    transcript
  );
  if( FD_UNLIKELY( zkp_res!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
