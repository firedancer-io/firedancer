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


int cmd_disasm( char const * program_file ) {
  uchar * prog_buf = malloc(16 * 1024 * 1024);
  char * out_buf = malloc(16 * 1024 * 1024);

  FD_LOG_NOTICE(( "Opening: %s", program_file ));
  FILE * file = fopen(program_file, "r");
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

  return 0;
}

int cmd_trace( char const * program_file ) {
  uchar * prog_buf = malloc(16 * 1024 * 1024);
  char * out_buf = malloc(16 * 1024 * 1024);

  ulong trace_sz = 128 * 1024;
  ulong trace_used = 0;
  fd_vm_sbpf_trace_entry_t * trace = (fd_vm_sbpf_trace_entry_t *) malloc(trace_sz * sizeof(fd_vm_sbpf_trace_entry_t));

  FD_LOG_NOTICE(( "Opening: %s", program_file ));
  FILE * file = fopen(program_file, "r");
  ulong nread = fread(prog_buf, 1, 16*1024*1024, file);

  fd_elf64_relocated_sbfp_program_t program;                                                        
  fd_elf_relocate_sbpf_program(prog_buf, nread, &program);                                               
                                                                                                    
  fd_vm_sbpf_exec_context_t ctx = {                                                                 
    .entrypoint = program.entrypoint,                                                                                
    .program_counter = 0,                                                                           
    .instruction_counter = 0,                                          
    .instrs = (fd_vm_sbpf_instr_t *)program.text_section,                                           
    .instrs_sz = program.text_section_len / sizeof(fd_vm_sbpf_instr_t),                             
  };                                                                                                
                                                                                                    
  fd_vm_syscall_register_all( &ctx );

  ulong interp_res = fd_vm_sbpf_interp_instrs_trace( &ctx, trace, trace_sz, &trace_used ); 
  if( interp_res != 0 ) {
    return 1;
  }

  sprintf(out_buf, "Frame 0\n"); 

  for( ulong i = 0; i < trace_used; i++ ) {
    fd_vm_sbpf_trace_entry_t trace_ent = trace[i];
    sprintf(out_buf, "%4lu [%016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX] %lu:\n",
        trace_ent.ic, 
        trace_ent.register_file[0], 
        trace_ent.register_file[1], 
        trace_ent.register_file[2], 
        trace_ent.register_file[3], 
        trace_ent.register_file[4], 
        trace_ent.register_file[5], 
        trace_ent.register_file[6], 
        trace_ent.register_file[7], 
        trace_ent.register_file[8], 
        trace_ent.register_file[9], 
        trace_ent.register_file[10],
        trace_ent.pc
      );
  }

	printf("%s", out_buf);

  fclose(file);

  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * cmd = fd_env_strip_cmdline_cstr( &argc, &argv, "--cmd", NULL, NULL );
  
  if( !strcmp( cmd, "disasm" ) ) {
    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program_file", NULL, NULL );
  
    if( cmd_disasm( program_file )!=0 ) {
      FD_LOG_ERR(( "error during disassembly" ));
    }
  } else if( !strcmp( cmd, "trace" ) ) {
    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program_file", NULL, NULL );
  
    if( cmd_trace( program_file )!=0 ) {
      FD_LOG_ERR(( "error during trace" ));
    }
  
  } else {
    FD_LOG_ERR(( "unknown command: %s", cmd ));
  }
  fd_halt();
  return 0;
}

