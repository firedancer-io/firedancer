#ifndef HEADER_fd_src_flamenco_vm_fd_vm_disasm_h
#define HEADER_fd_src_flamenco_vm_fd_vm_disasm_h

#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"

# define MAX_BUFFER_LEN 100000

FD_PROTOTYPES_BEGIN

int
fd_vm_disassemble_instr( fd_sbpf_instr_t const * instr,
                         ulong                   pc,
                         fd_sbpf_syscalls_t *    syscalls,
                         void *                  out,
                         ulong *                 out_len);

int
fd_vm_disassemble_program( fd_sbpf_instr_t const * instrs,
                           ulong                   instrs_cnt,
                           fd_sbpf_syscalls_t *    syscalls,
                           void *                  out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_disasm_h */
