#ifndef HEADER_fd_src_ballet_runtime_program_fd_config_program_h
#define HEADER_fd_src_ballet_runtime_program_fd_config_program_h

/* The config program is a native program which provides a conveience method for creating accounts
which store lists of pubkeys, some of which have signed the config data. The config program is 
only responsible for maintaining this list, the actual config accounts are created independently to this.

https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs */

#include "../../fd_ballet_base.h"
#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

/* Entry-point for the Solana Config Program */
int fd_executor_config_program_execute_instruction( instruction_ctx_t ctx ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_program_fd_config_program_h */
