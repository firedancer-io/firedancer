#include "elf/fd_elf_loader.h"                                                                      
#include "elf/fd_elf_types.h"                                                                       
#include "fd_sbpf_interp.h"                                                                         
#include "fd_sbpf_disasm.h"                                                                         
#include "fd_syscalls.h"        
#include "../util/fd_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
 
  uchar * prog_buf = malloc(16 * 1024 * 1024);
  char * out_buf = malloc(16 * 1024 * 1024);

  FD_LOG_NOTICE(( "Opening: %s", argv[1] ));
  FILE * file = fopen(argv[1], "r");
  ulong nread = fread(prog_buf, 1, 16*1024*1024, file);

  fd_elf64_relocated_sbfp_program_t program;                                                        
  fd_elf_relocate_sbpf_program(prog_buf, nread, &program);                                               
                                                                                                    
  fd_vm_sbpf_exec_context_t ctx = {                                                                 
    .entrypoint = 0,                                                                                
    .program_counter = 0,                                                                           
    .instruction_counter = 0,                                                                       
    .instrs = (fd_vm_sbpf_instr_t *)program.text_section,                                           
    .instrs_sz = program.text_section_len / sizeof(fd_vm_sbpf_instr_t),                             
  };                                                                                                
                                                                                                    
  fd_vm_syscall_register_all( &ctx );     

  fd_sbpf_disassemble_program( ctx.instrs, ctx.instrs_sz, out_buf, 16*1024*1024 );

	printf("%s", out_buf);

  fclose(file);

  fd_halt();
}
