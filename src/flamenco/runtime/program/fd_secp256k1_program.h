#ifndef HEADER_fd_src_flamenco_runtime_builtins_fd_secp256k1_program_h
#define HEADER_fd_src_flamenco_runtime_builtins_fd_secp256k1_program_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

/* Entry-point for the Solana Secp256k1 Program */
int fd_executor_secp256k1_program_execute_instruction( fd_exec_instr_ctx_t ctx ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_builtins_fd_secp256k1_program_h */
