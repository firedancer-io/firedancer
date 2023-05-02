#ifndef HEADER_fd_src_vm_fd_sbpf_disasm_h
#define HEADER_fd_src_vm_fd_sbpf_disasm_h

#include "../util/fd_util.h"
#include "fd_instr.h"

FD_PROTOTYPES_BEGIN

char * fd_sbpf_disassemble_program( fd_vm_sbpf_instr_t const *  instrs, 
                                  ulong                 instrs_sz, 
                                  char *                out, 
                                  ulong                 out_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vm_fd_sbpf_disasm_h */
