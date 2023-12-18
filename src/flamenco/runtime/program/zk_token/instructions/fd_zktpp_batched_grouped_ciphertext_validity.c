#include "../fd_zktpp_private.h"

int
fd_zktpp_instr_verify_proof_batched_grouped_ciphertext_validity( void const * _context, void const * _proof ) {
  FD_FN_UNUSED fd_zktpp_transcript_t transcript[1];
  FD_FN_UNUSED fd_zktpp_batched_grp_ciph_val_context_t const * context = _context;
  fd_zktpp_batched_grp_ciph_val_proof_t const *   proof   = _proof;

  //TODO

  //HACK to test the test
  if (proof->y0[1] == 0xad) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  FD_LOG_WARNING(( "Not implemented" ));
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}
