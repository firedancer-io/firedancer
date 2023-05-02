#include "elf/fd_elf_loader.h"
#include "elf/fd_elf_types.h"
#include "fd_sbpf_interp.h"
#include "fd_syscalls.h"

#include "../util/fd_util.h"
#include <string.h>
#include <stdio.h>
#include <immintrin.h>


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar buf[1024*1024];

  FILE * file = fopen("/home/lheeger/DrrJDyBzyuyYAzkkjd6Vu9ZzaDLsKRf4RPXyRE7Uk2A8.bin", "r");

  ulong nread = fread(buf, 1, sizeof(buf), file);

  fd_elf64_relocated_sbfp_program_t program;
  fd_elf_relocate_sbpf_program(buf, nread, &program);

  fd_vm_sbpf_exec_context_t ctx = {
    .entrypoint = 0,
    .program_counter = 0,
    .instruction_counter = 0,
    .instrs = (fd_vm_sbpf_instr_t *)program.text_section,
    .instrs_sz = program.text_section_len / sizeof(fd_vm_sbpf_instr_t),
  };

  fd_vm_syscall_register_all( &ctx );

  ulong validation_res = fd_vm_sbpf_interp_validate( &ctx ); 
  if (validation_res != 0) {
    FD_LOG_WARNING(( "VAL_RES: %lu", validation_res ));
  }
  FD_TEST( validation_res==FD_VM_SBPF_VALIDATE_SUCCESS );

  fd_halt();
  return 0;
}

