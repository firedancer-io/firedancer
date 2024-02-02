#include "../fd_zktpp_private.h"

static inline void
single_range_proof_transcript_init( fd_zktpp_transcript_t *                       transcript,
                                    fd_zktpp_single_range_proof_context_t const * context ) {
  fd_zktpp_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("RangeProof") );
  fd_zktpp_transcript_append_commitment( transcript, FD_TRANSCRIPT_LITERAL("commitment"), context->commitment );
}

int
fd_zktpp_instr_verify_proof_range_proof_u64( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_single_range_proof_context_t const * context = _context;
  fd_zktpp_range_proof_u64_proof_t const *      proof   = _proof;

  FD_LOG_DEBUG(( "fd_zktpp_instr_verify_proof_range_proof_u64" ));

  single_range_proof_transcript_init( transcript, context );

  const uchar bit_lengths[1] = { 64 };
  return fd_zktpp_verify_proof_range_u64( proof, context->commitment, bit_lengths, 1, transcript );
}
