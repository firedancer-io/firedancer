#ifndef HEADER_fd_src_ballet_runtime_vm_fd_sbpf_interp_h
#define HEADER_fd_src_ballet_runtime_vm_fd_sbpf_interp_h

// #include "../ballet/fd_ballet_base.h"
#include "fd_opcodes.h"
#include "fd_mem_map.h"
#include "fd_stack.h"

#define FD_VM_HEAP_SZ (32*1024)

#define FD_VM_SBPF_VALIDATE_SUCCESS               (0UL)
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_OPCODE    (1UL)
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_SRC_REG   (2UL)
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_DST_REG   (3UL)
#define FD_VM_SBPF_VALIDATE_ERR_INF_LOOP          (4UL)
#define FD_VM_SBPF_VALIDATE_ERR_JMP_OUT_OF_BOUNDS (5UL)
#define FD_VM_SBPF_VALIDATE_ERR_JMP_TO_ADDL_IMM   (6UL)
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_END_IMM   (7UL)
#define FD_VM_SBPF_VALIDATE_ERR_INCOMPLETE_LDQ    (8UL)
#define FD_VM_SBPF_VALIDATE_ERR_LDQ_NO_ADDL_IMM   (9UL)
#define FD_VM_SBPF_VALIDATE_ERR_NO_SUCH_EXT_CALL  (10UL)

struct fd_vm_sbpf_exec_context {
  long                  entrypoint;
  ulong                 num_ext_funcs;
  ulong                 register_file[11];
  fd_vm_sbpf_instr_t *  instrs;
  ulong                 instrs_sz;

  uchar *       read_only;
  ulong         read_only_sz;
  uchar *       input;
  ulong         input_sz;
  fd_vm_stack_t stack;
  uchar         heap[FD_VM_HEAP_SZ];
};
typedef struct fd_vm_sbpf_exec_context fd_vm_sbpf_exec_context_t;

struct fd_vm_sbpf_program {
  ulong num_ext_funcs;
};
typedef struct fd_vm_sbpf_program fd_vm_sbpf_program_t;

void fd_vm_sbpf_interp_instrs(fd_vm_sbpf_exec_context_t * ctx );

ulong fd_vm_sbpf_interp_validate( fd_vm_sbpf_exec_context_t const * ctx );

#endif /* HEADER_fd_src_ballet_runtime_vm_fd_sbpf_interp_h */
