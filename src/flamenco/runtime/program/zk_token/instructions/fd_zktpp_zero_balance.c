#include "../fd_zktpp_private.h"
#include "../bulletproofs/fd_bulletproofs.h"
#include "../encryption/fd_zktpp_encryption.h"
#include "../twisted_elgamal/fd_twisted_elgamal.h"

int
fd_zktpp_verify_proof_zero_balance( FD_FN_UNUSED void * ctx ) {
  //TODO
  fd_bulletproofs_placeholder( ctx );
  fd_zktpp_encryption_placeholder( ctx );
  fd_twisted_elgamal_placeholder( ctx );
  return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
}
