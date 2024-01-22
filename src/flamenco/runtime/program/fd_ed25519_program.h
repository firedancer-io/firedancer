#ifndef HEADER_fd_src_flamenco_runtime_program_fd_ed25519_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_ed25519_program_h

/* fd_ed25519_program implements the "Ed25519 Program" (native program).

   Address: Ed25519SigVerify111111111111111111111111111 */

#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

/* fd_ed25519_program_execute is the instruction processing entrypoint
   for the Ed25519 program. */

int
fd_ed25519_program_execute( fd_exec_instr_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_ed25519_program_h */
