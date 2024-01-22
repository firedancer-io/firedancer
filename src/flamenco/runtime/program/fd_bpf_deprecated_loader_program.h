#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_deprecated_loader_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_deprecated_loader_program_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

/* Entry-point for the Solana BPF Loader Program */
int fd_executor_bpf_deprecated_loader_program_execute_instruction( fd_exec_instr_ctx_t ctx ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_deprecated_loader_program_h */
