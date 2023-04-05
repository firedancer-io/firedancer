#ifndef HEADER_fd_src_ballet_runtime_program_fd_system_program_h
#define HEADER_fd_src_ballet_runtime_program_fd_system_program_h

#include "../../fd_ballet_base.h"
#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

/* Entry-point for the Solana System Program */
int fd_executor_system_program_execute_instruction( instruction_ctx_t ctx ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_program_fd_system_program_h */
