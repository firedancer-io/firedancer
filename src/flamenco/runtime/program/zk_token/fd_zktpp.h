#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_h

#include "../../../fd_flamenco_base.h"
#include "../../context/fd_exec_instr_ctx.h"

FD_PROTOTYPES_BEGIN

/* fd_zktpp_process_close_context_state
   executes the logic to close a context account. */
int
fd_zktpp_process_close_context_state( fd_exec_instr_ctx_t ctx );

/* fd_zktpp_process_verify_proof
   executes the common logic among all the zktpp instructions:
   parse data (context + proof), verify proof, create context account. */
int
fd_zktpp_process_verify_proof( fd_exec_instr_ctx_t ctx );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_h */
