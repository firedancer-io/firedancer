#include "fd_vm.h"

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
  fd_vm_tool_prog_create( &tool_prog, bin_path ); /* FIXME: RENAME INIT? */

  fd_vm_t vm = {
    .entrypoint          = (long)tool_prog.prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .text                = tool_prog.prog->text,
    .text_cnt            = tool_prog.prog->text_cnt,
    .text_off            = tool_prog.prog->text_off, /* FIXME: WHAT IF TEXT OFF NOT MULTIPLE OF 8 */
    .calldests           = tool_prog.prog->calldests,
    .syscalls            = tool_prog.syscalls
  };

  ulong  out_max = 128UL*vm.text_cnt; /* FIXME: OVERFLOW */
  ulong  out_len = 0UL;
  char * out     = (char *)malloc( out_max ); /* FIXME: GROSS */
  if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "malloc failed" ));
  out[0] = '\0';

  int err = fd_vm_disasm_program( vm.text, vm.text_cnt, vm.syscalls, out, out_max, &out_len );

  puts( out );

  free( out ); /* FIXME: GROSS */

  fd_vm_tool_prog_free( &tool_prog ); /* FIXME: RENAME DESTROY (OR MAYBE FINI)*/

  return err;
}

int
cmd_validate( char const * bin_path ) {

  fd_vm_tool_prog_t tool_prog;
  fd_vm_tool_prog_create( &tool_prog, bin_path );

  fd_vm_t vm = {
    .entrypoint          = (long)tool_prog.prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .text                = tool_prog.prog->text,
    .text_cnt            = tool_prog.prog->text_cnt,
    .text_off            = tool_prog.prog->text_off, /* FIXME: WHAT IF TEXT OFF NOT MULTIPLE OF 8 */
    .calldests           = tool_prog.prog->calldests,
    .syscalls            = tool_prog.syscalls,
  };

  int err = fd_vm_validate( &vm );

  fd_vm_tool_prog_free( &tool_prog );

  return err;
}

static uchar *
read_input_file( char const * input_path, ulong * _input_sz ) {
  if( FD_UNLIKELY( !_input_sz ) ) FD_LOG_ERR(( "input_sz cannot be NULL" ));

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

int
cmd_trace( char const * bin_path,
           char const * input_path ) {

  fd_vm_tool_prog_t tool_prog;
  fd_vm_tool_prog_create( &tool_prog, bin_path );

  ulong   input_sz = 0UL;
  uchar * input    = read_input_file( input_path, &input_sz ); /* FIXME: WHERE IS INPUT FREED? */

  ulong event_max      = 1UL<<30; /* 1 GiB default storage */
  ulong event_data_max = 2048UL;  /* 2 KiB memory range captures by default */
  fd_vm_trace_t * trace = fd_vm_trace_join( fd_vm_trace_new( aligned_alloc(
    fd_vm_trace_align(), fd_vm_trace_footprint( event_max, event_data_max ) ), event_max, event_data_max ) ); /* logs details */
  if( FD_UNLIKELY( !trace ) ) FD_LOG_ERR(( "Unable to construct trace" ));

  /* FIXME: Gross init */
  fd_vm_t vm = {
    .entrypoint          = (long)tool_prog.prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .text                = tool_prog.prog->text,
    .text_cnt            = tool_prog.prog->text_cnt,
    .text_off            = (ulong)tool_prog.prog->text - (ulong)tool_prog.prog->rodata, /* Note: byte offset (FIXME: WHAT IF MISALIGNED) */
    .syscalls            = tool_prog.syscalls,
    .calldests           = tool_prog.prog->calldests,
    .input               = input,
    .input_sz            = input_sz,
    .read_only           = (uchar *)tool_prog.prog->rodata,
    .read_only_sz        = tool_prog.prog->rodata_sz,
    .trace               = trace
  };

  vm.register_file[ 1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm.register_file[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  long dt = -fd_log_wallclock();
  int err = fd_vm_exec_trace( &vm );
  dt += fd_log_wallclock();

  printf( "Frame 0\n" );
  int trace_err = fd_vm_trace_printf( vm.trace, vm.text, vm.text_cnt, vm.syscalls ); /* logs details */
  if( FD_UNLIKELY( trace_err ) ) FD_LOG_WARNING(( "fd_vm_trace_printf failed (%i-%s)", trace_err, fd_vm_strerror( trace_err ) ));

  free( fd_vm_trace_delete( fd_vm_trace_leave( trace ) ) ); /* logs details */

  printf( "Interp_res:          %i (%s)\n", err, fd_vm_strerror( err ) );
  printf( "Return value:        %lu\n",     vm.register_file[0]        );
  printf( "Fault code:          %lu\n",     vm.cond_fault              );
  printf( "Instruction counter: %lu\n",     vm.instruction_counter     );
  printf( "Time:                %lu\n",     dt                         );

  return err;
}

int
cmd_run( char const * bin_path,
         char const * input_path ) {

  fd_vm_tool_prog_t tool_prog;
  fd_vm_tool_prog_create( &tool_prog, bin_path );

  ulong   input_sz = 0UL;
  uchar * input    = read_input_file( input_path, &input_sz ); /* FIXME: WHERE IS INPUT FREED? */

  fd_vm_t vm = {
    .entrypoint          = (long)tool_prog.prog->entry_pc,
    .program_counter     = 0,
    .instruction_counter = 0,
    .text                = tool_prog.prog->text,
    .text_cnt            = tool_prog.prog->text_cnt,
    .text_off            = (ulong)tool_prog.prog->text - (ulong)tool_prog.prog->rodata, /* Note: byte offset (FIXME: WHAT IF NOT ALIGNED 8) */
    .syscalls            = tool_prog.syscalls,
    .calldests           = tool_prog.prog->calldests,
    .input               = input,
    .input_sz            = input_sz,
    .read_only           = (uchar *)tool_prog.prog->rodata,
    .read_only_sz        = tool_prog.prog->rodata_sz
  };

  vm.register_file[1]  = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm.register_file[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  long dt = -fd_log_wallclock();
  int err = fd_vm_exec( &vm );
  dt += fd_log_wallclock();

  printf( "Interp_res:          %i (%s)\n", err, fd_vm_strerror( err ) );
  printf( "Return value:        %lu\n", vm.register_file[0]    );
  printf( "Fault code:          %lu\n", vm.cond_fault          );
  printf( "Instruction counter: %lu\n", vm.instruction_counter );
  printf( "Time:                %lu\n", dt                     );

  return err;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * cmd = fd_env_strip_cmdline_cstr( &argc, &argv, "--cmd", NULL, NULL );
  if( FD_UNLIKELY( !cmd ) ) FD_LOG_ERR(( "Please specify a command" ));

  if( !strcmp( cmd, "disasm" ) ) {

    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program-file", NULL, NULL );

    if( FD_UNLIKELY( program_file==NULL ) ) FD_LOG_ERR(( "Please specify a --program-file" ));

    FD_LOG_NOTICE(( "disasm --program-file %s", program_file ));

    int err = cmd_disasm( program_file );

    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "disasm failed (%i-%s)", err, fd_vm_strerror( err ) ));
    FD_LOG_NOTICE(( "disasm success" ));

  } else if( !strcmp( cmd, "validate" ) ) {

    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program-file", NULL, NULL );

    if( FD_UNLIKELY( !program_file ) ) FD_LOG_ERR(( "Please specify a --program-file" ));

    FD_LOG_NOTICE(( "validate --program-file %s", program_file ));

    int err = cmd_validate( program_file );

    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "validate failed (%i-%s)", err, fd_vm_strerror( err ) ));
    FD_LOG_NOTICE(( "validate success" ));

  } else if( !strcmp( cmd, "trace" ) ) {

    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program-file", NULL, NULL );
    char const * input_file   = fd_env_strip_cmdline_cstr( &argc, &argv, "--input-file", NULL, NULL );

    if( FD_UNLIKELY( !program_file ) ) FD_LOG_ERR(( "Please specify a --program-file" ));
    if( FD_UNLIKELY( !input_file   ) ) FD_LOG_ERR(( "Please specify a --input-file"   ));

    FD_LOG_NOTICE(( "trace --program-file %s --input-file %s", program_file, input_file ));

    int err = cmd_trace( program_file, input_file );

    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "trace failed (%i-%s)", err, fd_vm_strerror( err ) ));
    FD_LOG_NOTICE(( "trace success" ));

  } else if( !strcmp( cmd, "run" ) ) {

    char const * program_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--program-file", NULL, NULL );
    char const * input_file   = fd_env_strip_cmdline_cstr( &argc, &argv, "--input-file",   NULL, NULL );

    if( FD_UNLIKELY( !program_file ) ) FD_LOG_ERR(( "Please specify a --program-file" ));
    if( FD_UNLIKELY( !input_file   ) ) FD_LOG_ERR(( "Please specify a --input-file"   ));

    FD_LOG_NOTICE(( "run --program-file %s --input-file %s", program_file, input_file ));

    int err = cmd_run( program_file, input_file );

    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "run failed (%i-%s)", err, fd_vm_strerror( err ) ));
    FD_LOG_NOTICE(( "run success" ));

  } else {

    FD_LOG_ERR(( "unknown command: %s", cmd ));

  }

  fd_halt();
  return 0;
}
