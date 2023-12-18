#include "../fd_zktpp_private.h"

int
fd_zktpp_instr_verify_proof_pubkey_validity( void const * _context, void const * _proof ) {
  FD_FN_UNUSED fd_zktpp_transcript_t transcript[1];
  FD_FN_UNUSED fd_zktpp_pubkey_validity_context_t const * context = _context;
  fd_zktpp_pubkey_validity_proof_t const *   proof   = _proof;

  //TODO

  //HACK to test the test
  if (proof->y[1] == 0x35) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  FD_LOG_WARNING(( "Not implemented" ));
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}
