/* test_sol_compat_so.c is like test_sol_compat.so, but executes
   solfuzz inputs, not fixtures, and uses the public ABI by loading a
   shared object using dlopen. */

#include "fd_sol_compat.h"
#include <errno.h>
#include <dlfcn.h> /* dlopen */
#include <fcntl.h> /* open */
#include <stdio.h> /* fprintf */
#include <stdlib.h> /* malloc */
#include <sys/stat.h> /* stat */
#include <unistd.h> /* read */

/* Allow conversion from void * to function pointer */
#pragma GCC diagnostic ignored "-Wpedantic"

__attribute__((noreturn)) static void
usage( void ) {
  fputs(
    "Usage: test_sol_compat_so --target <path> --type <input type> [Protobuf input files ...]\n"
    "Supported types: instr, txn, block, elf_parse, vm_syscall, vm_interp, shred_parse\n",
    stderr );
  exit( 1 );
}

static void
process_file( char const * arg,
              __typeof__(&sol_compat_instr_execute_v1) execute_fn,
              void *       out_buf,
              ulong        out_bufsz ) {
  int fd = open( arg, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", arg, errno, fd_io_strerror( errno ) ));
  }
  struct stat in_stat;
  if( FD_UNLIKELY( 0!=fstat( fd, &in_stat ) ) ) {
    FD_LOG_ERR(( "stat(%s) failed (%i-%s)", arg, errno, fd_io_strerror( errno ) ));
  }
  ulong   in_sz    = (ulong)in_stat.st_size;
  uchar * file_buf = malloc( in_sz );
  if( FD_UNLIKELY( !file_buf ) ) FD_LOG_ERR(( "out of memory" ));
  if( FD_UNLIKELY( (long)in_sz!=read( fd, file_buf, in_sz ) ) ) {
    FD_LOG_ERR(( "read(%s,%p,%lu) failed (%i-%s)", arg, file_buf, in_sz, errno, fd_io_strerror( errno ) ));
  }
  ulong out_sz = out_bufsz;
  int status = execute_fn( out_buf, &out_sz, file_buf, in_sz );
  free( file_buf );
  /* For now, discard output */

  FD_LOG_NOTICE(( "%s: %d", arg, status ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * target = fd_env_strip_cmdline_cstr( &argc, &argv, "--target", NULL, NULL );
  if( FD_UNLIKELY( !target ) ) usage();
  char const * type   = fd_env_strip_cmdline_cstr( &argc, &argv, "--type", NULL, NULL );
  if( FD_UNLIKELY( !type ) ) usage();

  void * so = dlopen( target, RTLD_LAZY );
  if( FD_UNLIKELY( !so ) ) {
    FD_LOG_ERR(( "dlopen failed: %s", dlerror() ));
  }

  __typeof__(&sol_compat_init) init_fn = dlsym( so, "sol_compat_init" );
  if( FD_UNLIKELY( !init_fn ) ) FD_LOG_ERR(( "dlsym failed: %s", dlerror() ));
  __typeof__(&sol_compat_fini) fini_fn = dlsym( so, "sol_compat_fini" );
  if( FD_UNLIKELY( !init_fn ) ) FD_LOG_ERR(( "dlsym failed: %s", dlerror() ));

  char const * fn_name = NULL;
  if(      0==strcmp( type, "instr"       ) ) fn_name = "sol_compat_instr_execute_v1";
  else if( 0==strcmp( type, "txn"         ) ) fn_name = "sol_compat_txn_execute_v1";
  else if( 0==strcmp( type, "block"       ) ) fn_name = "sol_compat_block_execute_v1";
  else if( 0==strcmp( type, "elf_parse"   ) ) fn_name = "sol_compat_elf_loader_v1";
  else if( 0==strcmp( type, "vm_syscall"  ) ) fn_name = "sol_compat_vm_syscall_execute_v1";
  else if( 0==strcmp( type, "vm_interp"   ) ) fn_name = "sol_compat_vm_interp_v1";
  else if( 0==strcmp( type, "shred_parse" ) ) fn_name = "sol_compat_shred_parse_v1";
  else usage();

  __typeof__(&sol_compat_instr_execute_v1) execute_fn = dlsym( so, fn_name );
  if( FD_UNLIKELY( !execute_fn ) ) FD_LOG_ERR(( "dlsym failed: %s", dlerror() ));

  init_fn( 0 );

  ulong  const out_bufsz = 64UL<<20;
  void * const out_buf   = malloc( out_bufsz );
  if( FD_UNLIKELY( !out_buf ) ) FD_LOG_ERR(( "out of memory" ));

  for( int i=1; i<argc; i++ ) {
    char const * arg = argv[i];
    if( arg[0]=='-' && arg[1]=='-' ) {
      fprintf( stderr, "Unsupported flag: %s\n", arg );
      usage();
    }
    process_file( arg, execute_fn, out_buf, out_bufsz );
  }

  fini_fn();
  dlclose( so );
  free( out_buf );

  fd_halt();
  return 0;
}
