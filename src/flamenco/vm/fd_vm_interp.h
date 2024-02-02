#ifndef HEADER_fd_src_flamenco_vm_fd_vm_interp_h
#define HEADER_fd_src_flamenco_vm_fd_vm_interp_h

#include "fd_vm_context.h"

FD_PROTOTYPES_BEGIN

/* fd_vm_interp_instrs runs the sBPF program from the context until
   completion or a fault occurs.  Returns 0UL success or an error/fault
   code. */

ulong
fd_vm_interp_instrs( fd_vm_exec_context_t * ctx );

ulong
fd_vm_interp_instrs_trace( fd_vm_exec_context_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_interp_h */
