#ifndef HEADER_fd_src_flamenco_runtime_program_fd_config_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_config_program_h

/* The config program is a native program which implements a single instruction:
a convenience method for storing lists of pubkeys in accounts. Some of these pubkeys are designated "signers".
To change the list of pubkeys, all the designated signers have to sign the instruction.

https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs */

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_account.h"

FD_PROTOTYPES_BEGIN

/* Entry-point for the Solana Config Program */
int fd_executor_config_program_execute_instruction( fd_exec_instr_ctx_t ctx ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_config_program_h */
