#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v1_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v1_program_h

/* fd_bpf_loader_v1_program.h implements the first version of the BPF
   loader program, which is now deprecated.  Currently, it is a simple
   stub that returns an error on any invocation.

   Address: BPFLoader1111111111111111111111111111111111 */

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

int
fd_bpf_loader_v1_program_execute( fd_exec_instr_ctx_t ctx ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_v1_program_h */
