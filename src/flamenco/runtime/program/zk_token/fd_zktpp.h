#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_h

#include "../../../fd_flamenco_base.h"
#include "../../context/fd_exec_instr_ctx.h"

FD_PROTOTYPES_BEGIN

int
fd_zktpp_process_close_proof_context( fd_exec_instr_ctx_t ctx );

/* process_verify_proof
   executes the common logic among all the zktpp instructions:
   parse data (context + proof), verify proof, store context. */
int
fd_zktpp_process_verify_proof( fd_exec_instr_ctx_t ctx,
                               uchar               instr_id );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_h */
