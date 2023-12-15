#include "../fd_zktpp_private.h"
#include "../bulletproofs/fd_bulletproofs.h"
#include "../encryption/fd_zktpp_encryption.h"
#include "../twisted_elgamal/fd_twisted_elgamal.h"

int
fd_zktpp_instr_verify_proof_zero_balance( FD_FN_UNUSED void const * context, FD_FN_UNUSED void const * proof ) {
  //TODO
  fd_bulletproofs_placeholder( context );
  fd_zktpp_encryption_placeholder( context );
  fd_twisted_elgamal_placeholder( context );
  FD_LOG_WARNING(( "Not implemented" ));
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}
