#ifndef HEADER_fd_src_flamenco_runtime_program_fd_config_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_config_program_h

/* The config program is a native program which implements a single
   instruction: A convenience method for storing lists of pubkeys in
   accounts. Some of these pubkeys are designated "signers".  To change
   the list of pubkeys, all the designated signers have to sign the
   instruction.

   Address: Config1111111111111111111111111111111111111 */

#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

/* fd_config_program_execute is the instruction processing entrypoint
   for the config program. */

int
fd_config_program_execute( fd_exec_instr_ctx_t ctx ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_config_program_h */
