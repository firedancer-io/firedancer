#ifndef HEADER_fd_src_vm_fd_sbpf_disasm_h
#define HEADER_fd_src_vm_fd_sbpf_disasm_h

#include "../util/fd_util.h"
#include "fd_instr.h"
#include "../ballet/sbpf/fd_sbpf_loader.h"

FD_PROTOTYPES_BEGIN

int
fd_sbpf_disassemble_program( fd_vm_sbpf_instr_t const * instrs,
                             ulong                      instrs_cnt,
                             fd_sbpf_syscalls_t *       syscalls,
                             void *                     out_file );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vm_fd_sbpf_disasm_h */
