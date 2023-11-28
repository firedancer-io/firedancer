/* FIXME: This duplicates fd_sbpf_tool.
   Should probably remove this file entirely as it is completely
   redundant. */

#include "fd_sbpf_loader.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "fd_sbpf_maps.c"

uint const _syscalls[] = {
  0xb6fc1a11, 0x686093bb, 0x207559bd, 0x5c2a3178, 0x52ba5096,
  0x7ef088ca, 0x9377323c, 0x48504a38, 0x11f49d86, 0xd7793abb,
  0x17e40350, 0x174c5122, 0xaa2607ca, 0xdd1c41a6, 0xd56b5fe9,
  0x23a29a61, 0x3b97b73c, 0xbf7188f6, 0x717cc4a3, 0x434371f8,
  0x5fdcde31, 0x3770fb22, 0xa22b9c85, 0xd7449092, 0x83f00e8f,
  0xa226d3eb, 0x5d2245e4, 0x7317b434, 0xadb8efc8, 0x85532d94,
  0U
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Parse command line arguments */

  char const * bin_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--bin", NULL, NULL );

  /* Validate command line arguments */

  if( FD_UNLIKELY( !bin_path ) )
    FD_LOG_ERR(( "--bin not specified" ));

  /* Open file */

  FILE * bin_file = fopen( bin_path, "rb" );
  if( FD_UNLIKELY( !bin_file ) ) FD_LOG_ERR(( "Failed to open \"%s\" (%i-%s)", bin_path, errno, fd_io_strerror( errno ) ));

  /* Check file type */

  struct stat bin_stat;
  if( FD_UNLIKELY( 0!=fstat( fileno( bin_file ), &bin_stat ) ) )
    FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !S_ISREG( bin_stat.st_mode ) ) )
    FD_LOG_ERR(( "File \"%s\" not a regular file", bin_path ));
  if( FD_UNLIKELY( bin_stat.st_size<0L ) )
    FD_LOG_ERR(( "File \"%s\" has invalid size %ld", bin_path, bin_stat.st_size ));

  /* Read file into memory */

  FD_LOG_NOTICE(( "Loading sBPF program: %s", bin_path ));

  ulong  bin_sz  = (ulong)bin_stat.st_size;
  void * bin_buf = malloc( bin_sz+8UL );
  if( FD_UNLIKELY( !bin_buf ) ) FD_LOG_ERR(( "malloc(%#lx) failed (%i-%s)", bin_sz, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( fread( bin_buf, bin_sz, 1UL, bin_file )!=1UL ) )
    FD_LOG_ERR(( "fread() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Extract ELF info */

  fd_sbpf_elf_info_t elf_info;
  if( FD_UNLIKELY( !fd_sbpf_elf_peek( &elf_info, bin_buf, bin_sz ) ) )
    FD_LOG_ERR(( "FAIL: %s", fd_sbpf_strerror() ));

  /* Allocate rodata segment */

  void * rodata = malloc( elf_info.rodata_footprint );
  FD_TEST( rodata );

  /* Allocate objects */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  void * prog_buf       = aligned_alloc( prog_align, prog_footprint );
  if( FD_UNLIKELY( !prog_buf ) )
    FD_LOG_ERR(( "aligned_alloc(%#lx, %#lx) failed (%i-%s)", prog_align, prog_footprint, errno, fd_io_strerror( errno ) ));

  fd_sbpf_program_t * prog = fd_sbpf_program_new( prog_buf, &elf_info, rodata );
  FD_TEST( prog );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new(
      aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  /* Load and reloc program */

  for( uint const * x = _syscalls; *x; x++ )
    fd_sbpf_syscalls_insert( syscalls, *x );

  int load_err = fd_sbpf_program_load( prog, bin_buf, bin_sz, syscalls );

  FD_LOG_HEXDUMP_NOTICE(( "Output rodata segment", prog->rodata, prog->rodata_sz ));

  /* Clean up */

  fd_sbpf_program_delete( prog );
  free( rodata   );
  free( bin_buf  );
  free( prog_buf );
  free( fd_sbpf_syscalls_delete( syscalls ) );

  if( FD_UNLIKELY( 0!=fclose( bin_file ) ) ) FD_LOG_WARNING(( "fclose() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Yield result */

  if( FD_UNLIKELY( load_err!=0 ) )
    FD_LOG_ERR(( "FAIL: %s", fd_sbpf_strerror() ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
