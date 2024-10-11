#define _GNU_SOURCE

#include "../../util/fd_util_base.h"
#if defined(__linux__) && FD_HAS_X86
#define FD_VM_TOOL_HAS_JIT 1
#else
#define FD_VM_TOOL_HAS_JIT 0
#endif

#include "fd_vm_base.h"
#include "fd_vm_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#if FD_VM_TOOL_HAS_JIT
#include "jit/fd_jit.h"
#include <sys/mman.h>
#endif

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
  FD_TEST( fd_sbpf_elf_peek( &elf_info, bin_buf, bin_sz, /* deploy checks */ 0 ) );

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

  fd_vm_syscall_register_all( syscalls, 0 );

  /* Load program */
  if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, bin_buf, bin_sz, syscalls, false ) ) )
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

  /* FIXME: DOES DISASM NEED THE TEXT_OFF TOO FOR CALLS? */
  /* FIXME: WOULD DISASM BENEFIT BY ANNOTATING THE ENTRY PC AND/OR THE
     CALLDESTS? */

  ulong  out_max = 128UL*tool_prog.prog->text_cnt; /* FIXME: OVERFLOW */
  ulong  out_len = 0UL;
  char * out     = (char *)malloc( out_max ); /* FIXME: GROSS */
  if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "malloc failed" ));
  out[0] = '\0';

  int err = fd_vm_disasm_program( tool_prog.prog->text, tool_prog.prog->text_cnt, tool_prog.syscalls, out, out_max, &out_len );

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
    .text      = tool_prog.prog->text,
    .text_cnt  = tool_prog.prog->text_cnt,
    .text_off  = tool_prog.prog->text_off,
    .entry_pc  = tool_prog.prog->entry_pc,
    .calldests = tool_prog.prog->calldests,
    .syscalls  = tool_prog.syscalls,
    .trace     = NULL
  };

  /* FIXME: DO WE REALLY NEED THE WHOLE VM TO VALIDATE? */

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

  /* Turn input into a single memory region */
  fd_vm_input_region_t input_region = {
    .vaddr_offset = 0UL,
    .haddr        = (ulong)input,
    .region_sz    = (uint)input_sz,
    .is_writable  = 1U
  };


  ulong event_max      = 1UL<<30; /* 1 GiB default storage */
  ulong event_data_max = 2048UL;  /* 2 KiB memory range captures by default */
  fd_vm_trace_t * trace = fd_vm_trace_join( fd_vm_trace_new( aligned_alloc(
    fd_vm_trace_align(), fd_vm_trace_footprint( event_max, event_data_max ) ), event_max, event_data_max ) ); /* logs details */
  if( FD_UNLIKELY( !trace ) ) {
    FD_LOG_WARNING(( "unable to create trace" ));
    return FD_VM_ERR_INVAL; /* FIXME: ERR CODE */
  }

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  /* FIXME: Gross init */
  fd_vm_t vm = {
    .instr_ctx             = NULL, /* FIXME */
    .heap_max              = FD_VM_HEAP_DEFAULT, /* FIXME: CONFIGURE */
    .entry_cu              = FD_VM_COMPUTE_UNIT_LIMIT, /* FIXME: CONFIGURE */
    .rodata                = tool_prog.prog->rodata,
    .rodata_sz             = tool_prog.prog->rodata_sz,
    .text                  = tool_prog.prog->text,
    .text_cnt              = tool_prog.prog->text_cnt,
    .text_off              = (ulong)tool_prog.prog->text - (ulong)tool_prog.prog->rodata,
    .entry_pc              = tool_prog.prog->entry_pc,
    .calldests             = tool_prog.prog->calldests,
    .syscalls              = tool_prog.syscalls,
    .input_mem_regions     = &input_region,
    .input_mem_regions_cnt = 1U,
    .trace                 = trace,
    .sha                   = sha,
  };

  /* FIXME: MOVE TO EXEC */
  vm.reg[ 1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm.reg[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  long dt = -fd_log_wallclock();
  int exec_err = fd_vm_exec( &vm );
  dt += fd_log_wallclock();

  printf( "Frame 0\n" );
  int err = fd_vm_trace_printf( vm.trace, vm.syscalls ); /* logs details */
  if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "fd_vm_trace_printf failed (%i-%s)", err, fd_vm_strerror( err ) ));

  printf( "Interp_res:          %i (%s)\n", exec_err, fd_vm_strerror( exec_err ) );
  printf( "Return value:        %lu\n",     vm.reg[0]                            );
  printf( "Instruction counter: %lu\n",     vm.ic                                );
  printf( "Time:                %lu\n",     dt                                   );

  free( fd_vm_trace_delete( fd_vm_trace_leave( trace ) ) ); /* logs details */

  return err;
}

int
cmd_run( char const * bin_path,
         char const * input_path,
         int          use_jit /* in [0,1] */ ) {

  fd_vm_tool_prog_t tool_prog;
  fd_vm_tool_prog_create( &tool_prog, bin_path );

  ulong   input_sz = 0UL;
  uchar * input    = read_input_file( input_path, &input_sz ); /* FIXME: WHERE IS INPUT FREED? */

  /* Turn input into a single memory region */
  fd_vm_input_region_t input_region = {
    .vaddr_offset = 0UL,
    .haddr        = (ulong)input,
    .region_sz    = (uint)input_sz,
    .is_writable  = 1U
  };

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t vm = {
    .instr_ctx             = NULL, /* FIXME */
    .heap_max              = FD_VM_HEAP_DEFAULT, /* FIXME: CONFIGURE */
    .entry_cu              = FD_VM_COMPUTE_UNIT_LIMIT, /* FIXME: CONFIGURE */
    .rodata                = tool_prog.prog->rodata,
    .rodata_sz             = tool_prog.prog->rodata_sz,
    .text                  = tool_prog.prog->text,
    .text_cnt              = tool_prog.prog->text_cnt,
    .text_off              = (ulong)tool_prog.prog->text - (ulong)tool_prog.prog->rodata,
    .entry_pc              = tool_prog.prog->entry_pc,
    .calldests             = tool_prog.prog->calldests,
    .syscalls              = tool_prog.syscalls,
    .input_mem_regions     = &input_region,
    .input_mem_regions_cnt = 1U,
    .trace                 = NULL,
    .sha                   = sha,
  };

  /* FIXME: MOVE TO EXEC */
  vm.reg[ 1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm.reg[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  int exec_err    = FD_VM_ERR_UNSUP;
  long dt         = 0L;
  long compile_dt = 0L;

  if( use_jit ) {
#   if FD_VM_TOOL_HAS_JIT

    ulong   code_bufsz = fd_ulong_align_up( fd_jit_est_code_sz( tool_prog.prog->text_sz ), FD_SHMEM_NORMAL_PAGE_SZ );
    uchar * code_buf   = mmap( 0, code_bufsz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    if( FD_UNLIKELY( code_buf==MAP_FAILED ) ) FD_LOG_ERR(( "mmap failed" ));

    ulong  scratch_bufsz = fd_jit_est_scratch_sz( tool_prog.prog->text_sz );
    void * scratch_buf   = malloc( scratch_bufsz );

    for( ulong j=0; j<code_bufsz; j+=2 ) {
      code_buf[ j   ] = 0x0f;
      code_buf[ j+1 ] = 0x0b;
    }
    fd_memset( scratch_buf, 0, scratch_bufsz );

    compile_dt = -fd_log_wallclock();
    int compile_err = FD_VM_ERR_EBPF_JIT_NOT_COMPILED;
    fd_jit_prog_t _jit_prog[1];
    fd_jit_prog_t * jit_prog = fd_jit_prog_new(
        _jit_prog,
        tool_prog.prog,
        tool_prog.syscalls,
        code_buf, code_bufsz,
        scratch_buf, scratch_bufsz,
        &compile_err
    );
    if( FD_UNLIKELY( !jit_prog ) ) {
      FD_LOG_ERR(( "JIT compile failed (%d-%s)", compile_err, fd_vm_strerror( compile_err ) ));
    }
    compile_dt += fd_log_wallclock();

    free( scratch_buf );
    mprotect( code_buf, fd_ulong_align_up( jit_prog->code_sz, FD_SHMEM_NORMAL_PAGE_SZ ), PROT_READ | PROT_EXEC );

    dt = -fd_log_wallclock();
    exec_err = fd_jit_exec( jit_prog, &vm );
    dt += fd_log_wallclock();

    fd_jit_prog_delete( jit_prog );
    munmap( code_buf, code_bufsz );

#   endif
  } else {

    dt = -fd_log_wallclock();
    exec_err = fd_vm_exec( &vm );
    dt += fd_log_wallclock();

  }

  printf( "Interp_res:          %i (%s)\n", exec_err, fd_vm_strerror( exec_err ) );
  printf( "Return value:        %lu\n",     vm.reg[0]                            );
  printf( "Instruction counter: %lu\n",     vm.ic                                );
  printf( "Time:                %lu\n",     dt                                   );
  if( compile_dt ) {
    printf( "Compile time:        %lu\n",     compile_dt                           );
  }

  return FD_VM_SUCCESS;
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
    char const * backend      = fd_env_strip_cmdline_cstr( &argc, &argv, "--backend", NULL, "interp" );
    int use_jit = 0;
    if( 0==strcmp( backend, "interp" ) ) {
      use_jit = 0;
    } else if( FD_VM_TOOL_HAS_JIT && 0==strcmp( backend, "jit" ) ) {
      use_jit = 1;
    } else {
      FD_LOG_ERR(( "Unsupported --backend \"%s\"", backend ));
    }

    if( FD_UNLIKELY( !program_file ) ) FD_LOG_ERR(( "Please specify a --program-file" ));
    if( FD_UNLIKELY( !input_file   ) ) FD_LOG_ERR(( "Please specify a --input-file"   ));

    FD_LOG_NOTICE(( "run --program-file %s --input-file %s --backend %s", program_file, input_file, backend ));

    int err = cmd_run( program_file, input_file, use_jit );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "run failed (%i-%s)", err, fd_vm_strerror( err ) ));

    FD_LOG_NOTICE(( "run success" ));

  } else {

    FD_LOG_ERR(( "unknown command: %s", cmd ));

  }

  fd_halt();
  return 0;
}
