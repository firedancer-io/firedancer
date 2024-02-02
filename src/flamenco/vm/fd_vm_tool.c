#include "../fd_flamenco_base.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "fd_vm_interp.h"
#include "fd_vm_disasm.h"
#include "fd_vm_syscalls.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

struct fd_vm_tool_prog {
  void *               bin_buf;
  fd_sbpf_program_t *  prog;
  fd_sbpf_syscalls_t * syscalls;
};

typedef struct fd_vm_tool_prog fd_vm_tool_prog_t;

static fd_vm_tool_prog_t *
fd_vm_tool_prog_create( fd_vm_tool_prog_t * tool_prog,
                        char const *        bin_path ) {

  /* Open file */

  FILE * bin_file = fopen( bin_path, "r" );
  if( FD_UNLIKELY( !bin_file ) )
    FD_LOG_ERR(( "fopen(\"%s\") failed (%i-%s)", bin_path, errno, fd_io_strerror( errno ) ));

  struct stat bin_stat;
  if( FD_UNLIKELY( 0!=fstat( fileno( bin_file ), &bin_stat ) ) )
    FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !S_ISREG( bin_stat.st_mode ) ) )
    FD_LOG_ERR(( "File \"%s\" not a regular file", bin_path ));

  /* Allocate file buffer */

  ulong  bin_sz  = (ulong)bin_stat.st_size;
  void * bin_buf = malloc( bin_sz+8UL );
  if( FD_UNLIKELY( !bin_buf ) )
    FD_LOG_ERR(( "malloc(%#lx) failed (%i-%s)", bin_sz, errno, fd_io_strerror( errno ) ));

  /* Read program */

  if( FD_UNLIKELY( fread( bin_buf, bin_sz, 1UL, bin_file )!=1UL ) )
    FD_LOG_ERR(( "fread() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( 0==fclose( bin_file ) );

  /* Extract ELF info */

  fd_sbpf_elf_info_t elf_info;
  FD_TEST( fd_sbpf_elf_peek( &elf_info, bin_buf, bin_sz ) );

  /* Allocate rodata segment */

  void * rodata = malloc( elf_info.rodata_footprint );
  FD_TEST( rodata );

  /* Allocate program buffer */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( aligned_alloc( prog_align, prog_footprint ), &elf_info, rodata );
  FD_TEST( prog );

  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new(
      aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls );
  /* Load program */

  if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, bin_buf, bin_sz, syscalls ) ) )
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));

  tool_prog->bin_buf  = bin_buf;
  tool_prog->prog     = prog;
  tool_prog->syscalls = syscalls;

  return tool_prog;
}

static void
fd_vm_tool_prog_free( fd_vm_tool_prog_t * prog ) {
  free( prog->prog->rodata );
  free( prog->bin_buf      );
  free( fd_sbpf_program_delete ( prog->prog     ) );
  free( fd_sbpf_syscalls_delete( prog->syscalls ) );
}

int
cmd_disasm( char const * bin_path ) {

  fd_vm_tool_prog_t tool_prog;
  fd_vm_tool_prog_create( &tool_prog, bin_path );
  FD_LOG_NOTICE(( "Loading sBPF program: %s", bin_path ));

  fd_vm_exec_context_t ctx = {
    .entrypoint          = 0,
    .program_counter     = 0,
    .instruction_counter = 0,
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( tool_prog.prog->text ),
    .instrs_sz           = tool_prog.prog->text_cnt,
  };
  char out[MAX_BUFFER_LEN*10];
  int res = fd_vm_disassemble_program( ctx.instrs, ctx.instrs_sz, tool_prog.syscalls, out );
  puts( out );

  fd_vm_tool_prog_free( &tool_prog );

  return res;
}

static uchar *
read_input_file( char const * input_path, ulong * _input_sz ) {
  if( _input_sz==NULL ) {
    FD_LOG_ERR(( "input_sz cannot be NULL" ));
  }

  /* Open file */

  FILE * input_file = fopen( input_path, "r" );
  if( FD_UNLIKELY( !input_file ) )
    FD_LOG_ERR(( "fopen(\"%s\") failed (%i-%s)", input_path, errno, fd_io_strerror( errno ) ));

  struct stat input_stat;
  if( FD_UNLIKELY( 0!=fstat( fileno( input_file ), &input_stat ) ) )
    FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !S_ISREG( input_stat.st_mode ) ) )
    FD_LOG_ERR(( "File \"%s\" not a regular file", input_path ));

  /* Allocate file buffer */

  ulong input_sz  = (ulong)input_stat.st_size;
  void * input_buf = malloc( input_sz );
  if( FD_UNLIKELY( !input_buf ) )
    FD_LOG_ERR(( "malloc(%#lx) failed (%i-%s)", input_sz, errno, fd_io_strerror( errno ) ));

  /* Read input */

  if( FD_UNLIKELY( fread( input_buf, input_sz, 1UL, input_file )!=1UL ) )
    FD_LOG_ERR(( "fread() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( 0==fclose( input_file ) );

  *_input_sz = input_sz;

  return input_buf;
}

int cmd_trace( char const * bin_path, char const * input_path ) {

  fd_vm_tool_prog_t tool_prog;
  fd_vm_tool_prog_create( &tool_prog, bin_path );
  FD_LOG_NOTICE(( "Loading sBPF program: %s", bin_path ));

  ulong input_sz = 0;
  uchar * input = read_input_file( input_path, &input_sz );

  ulong trace_sz = 128 * 1024;
  ulong trace_used = 0;
  fd_vm_trace_entry_t * trace = (fd_vm_trace_entry_t *) malloc(trace_sz * sizeof(fd_vm_trace_entry_t));

  fd_vm_exec_context_t ctx = {
    .entrypoint          = (long)tool_prog.prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( tool_prog.prog->text ),
    .instrs_sz           = tool_prog.prog->text_cnt,
    .instrs_offset       = (ulong)tool_prog.prog->text - (ulong)tool_prog.prog->rodata,
    .syscall_map         = tool_prog.syscalls,
    .calldests           = tool_prog.prog->calldests,
    .input               = input,
    .input_sz            = input_sz,
    .read_only           = (uchar *)fd_type_pun_const(tool_prog.prog->rodata),
    .read_only_sz        = tool_prog.prog->rodata_sz
  };

  ctx.register_file[1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  ctx.register_file[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  long  dt = -fd_log_wallclock();
  ulong interp_res = fd_vm_interp_instrs_trace( &ctx );
  dt += fd_log_wallclock();

  if( interp_res != 0 ) {
    return 1;
  }

  printf( "Frame 0\n" );

  for( ulong i = 0; i < trace_used; i++ ) {
    fd_vm_trace_entry_t trace_ent = trace[i];
    fprintf(stdout, "%5lu [%016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX] %5lu: ",
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
        trace_ent.pc+29 /* FIXME: THIS OFFSET IS FOR TESTING ONLY */
      );
    char out[100];
    fd_vm_disassemble_instr(&ctx.instrs[trace[i].pc], trace[i].pc, ctx.syscall_map, out, 0);
    puts( out );
  }

  fprintf(stdout, "Return value: %lu\n", ctx.register_file[0]);
  fprintf(stdout, "Fault code: %lu\n", ctx.cond_fault);
  fprintf(stdout, "Instruction counter: %lu\n", ctx.instruction_counter);
  fprintf(stdout, "Time: %lu\n", dt);

  free( trace );

  return 0;
}

int cmd_run( char const * bin_path, char const * input_path ) {

  fd_vm_tool_prog_t tool_prog;
  fd_vm_tool_prog_create( &tool_prog, bin_path );
  FD_LOG_NOTICE(( "Loading sBPF program: %s", bin_path ));

  ulong input_sz = 0;
  uchar * input = read_input_file( input_path, &input_sz );

  fd_vm_exec_context_t ctx = {
    .entrypoint          = (long)tool_prog.prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .instrs              = (fd_sbpf_instr_t const *)fd_type_pun_const( tool_prog.prog->text ),
    .instrs_sz           = tool_prog.prog->text_cnt,
    .instrs_offset       = (ulong)tool_prog.prog->text - (ulong)tool_prog.prog->rodata,
    .syscall_map         = tool_prog.syscalls,
    .calldests           = tool_prog.prog->calldests,
    .input               = input,
    .input_sz            = input_sz,
    .read_only           = (uchar *)fd_type_pun_const(tool_prog.prog->rodata),
    .read_only_sz        = tool_prog.prog->rodata_sz
  };

  ctx.register_file[1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  ctx.register_file[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  long  dt = -fd_log_wallclock();
  ulong interp_res = fd_vm_interp_instrs( &ctx );
  dt += fd_log_wallclock();

  if( interp_res != 0 ) {
    return 1;
  }

  fprintf(stdout, "Return value: %lu\n", ctx.register_file[0]);
  fprintf(stdout, "Fault code: %lu\n", ctx.cond_fault);
  fprintf(stdout, "Instruction counter: %lu\n", ctx.instruction_counter);
  fprintf(stdout, "Time: %lu\n", dt);

  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * cmd = fd_env_strip_cmdline_cstr( &argc, &argv, "--cmd", NULL, NULL );
  if( FD_UNLIKELY( !cmd ) ) {
    FD_LOG_ERR(( "missing command" ));
    fd_halt();
    return 1;
  }

  if( !strcmp( cmd, "disasm" ) ) {
    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program-file", NULL, NULL );

    if( FD_UNLIKELY( program_file==NULL ) ) {
      FD_LOG_ERR(( "Please specify a --program-file" ));
    }

    if( FD_UNLIKELY( !cmd_disasm( program_file ) ) ) {
      FD_LOG_ERR(( "error during disassembly" ));
    }
  } else if( !strcmp( cmd, "trace" ) ) {
    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program-file", NULL, NULL );
    char const * input_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--input-file", NULL, NULL );

    if( FD_UNLIKELY( program_file==NULL ) ) {
      FD_LOG_ERR(( "Please specify a --program-file" ));
    }

    if( FD_UNLIKELY( input_file==NULL ) ) {
      FD_LOG_ERR(( "Please specify a --input-file" ));
    }

    if( FD_UNLIKELY( cmd_trace( program_file, input_file ) ) ) {
      FD_LOG_ERR(( "error during trace" ));
    }
  } else if( !strcmp( cmd, "run" ) ) {
    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program-file", NULL, NULL );
    char const * input_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--input-file", NULL, NULL );

    if( FD_UNLIKELY( program_file==NULL ) ) {
      FD_LOG_ERR(( "Please specify a --program-file" ));
    }

    if( FD_UNLIKELY( input_file==NULL ) ) {
      FD_LOG_ERR(( "Please specify a --input-file" ));
    }

    if( FD_UNLIKELY( cmd_run( program_file, input_file ) ) ) {
      FD_LOG_ERR(( "error during run" ));
    }
  } else {
    FD_LOG_ERR(( "unknown command: %s", cmd ));
  }

  fd_halt();
  return 0;
}
