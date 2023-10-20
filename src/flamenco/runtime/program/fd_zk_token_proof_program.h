#ifndef HEADER_fd_src_flamenco_runtime_program_fd_zk_token_proof_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_zk_token_proof_program_h

#include "../context/fd_exec_instr_ctx.h"

/* FD_ZKTPP_INSTR_{...} identify ZK Token Proof program instruction
   types. */

#define FD_ZKTPP_INSTR_CLOSE_CONTEXT_STATE                   ((uchar) 0)
#define FD_ZKTPP_INSTR_VERIFY_ZERO_BALANCE                   ((uchar) 1)
#define FD_ZKTPP_INSTR_VERIFY_WITHDRAW                       ((uchar) 2)
#define FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_EQUALITY            ((uchar) 3)
#define FD_ZKTPP_INSTR_VERIFY_TRANSFER                       ((uchar) 4)
#define FD_ZKTPP_INSTR_VERIFY_TRANSFER_WITH_FEE              ((uchar) 5)
#define FD_ZKTPP_INSTR_VERIFY_PUBKEY_VALIDITY                ((uchar) 6)
#define FD_ZKTPP_INSTR_VERIFY_RANGE_PROOF_U64                ((uchar) 7)
#define FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64        ((uchar) 8)
#define FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128       ((uchar) 9)
#define FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256       ((uchar)10)
#define FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY ((uchar)11)
#define FD_ZKTPP_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY         ((uchar)12)
#define FD_ZKTPP_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY ((uchar)13)
#define FD_ZKTPP_INSTR_VERIFY_FEE_SIGMA                      ((uchar)14)

FD_PROTOTYPES_BEGIN

int
fd_executor_zk_token_proof_program_execute_instruction( fd_exec_instr_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_zk_token_proof_program_h */
