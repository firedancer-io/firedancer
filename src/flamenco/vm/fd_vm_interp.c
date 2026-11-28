#include "fd_vm_base.h"
#include "fd_vm_private.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../runtime/tests/fd_dump_pb.h"

int
fd_vm_exec_notrace( fd_vm_t * vm ) {

# undef FD_VM_INTERP_EXE_TRACING_ENABLED

  ulong const * FD_RESTRICT text = vm->text;

  int err = FD_VM_SUCCESS;

  /* Run the VM */
# include "fd_vm_interp_core.c"

  return err;
}

int
fd_vm_exec_trace( fd_vm_t * vm ) {

# define FD_VM_INTERP_EXE_TRACING_ENABLED 1

  ulong const * FD_RESTRICT text = vm->text;

  int err = FD_VM_SUCCESS;

  /* Run the VM */
# include "fd_vm_interp_core.c"

# undef FD_VM_INTERP_EXE_TRACING_ENABLED

  return err;
}
