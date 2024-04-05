#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h

/* fd_bpf_loader_v2_program.h implements the second version of the BPF
   loader program, which is now deprecated.  Currently, it is a simple
   stub that returns an error on any invocation.  This means that new
   programs cannot deployed with this loader.  The execution of
   existing programs is still allowed.

   Address: BPFLoader2111111111111111111111111111111111 */

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

/* fd_bpf_loader_v2_program_execute processes an execution of the
   BPF Loader v2 itself. */

int
fd_bpf_loader_v2_program_execute( fd_exec_instr_ctx_t ctx );

/* fd_bpf_loader_v2_user_execute processes an execution of a program
   owner by the BPF Loader v2. */

int
fd_bpf_loader_v2_user_execute( fd_exec_instr_ctx_t ctx );

int
fd_executor_bpf_loader_program_is_executable_program_account( fd_exec_slot_ctx_t * slot_ctx, fd_pubkey_t const * pubkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h */
