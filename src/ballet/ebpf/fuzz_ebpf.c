#include "fd_ebpf.h"
#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"

#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  /* Don't print warning log */
  fd_log_level_logfile_set( 4 );
  fd_log_level_stderr_set( 4 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * const data,
                        ulong         const size ) {

  /* TODO: For now hardcode symbol map, as that is the usual way
           programs for programs to interact */

  fd_ebpf_sym_t syms[ 2 ] = {
    { .name = "fd_xdp_udp_dsts", .value = 10 },
    { .name = "fd_xdp_xsks",     .value = 20 }
  };

  /* heap allocated buffers */
  ulong * bpf = NULL;
  uchar * elf = NULL;

  do {
    ulong bpf_sz = size >> 3;
    bpf = malloc( bpf_sz );
    if( !bpf ) break;

    elf = malloc( size );
    if( !elf ) break;
    fd_memcpy( elf, data, size );

    fd_ebpf_link_opts_t link_opts = {
      .section = "xdp",
      .sym     = syms,
      .sym_cnt = 2UL,
      .bpf     = bpf,
      .bpf_sz  = bpf_sz
    };

    fd_ebpf_static_link( &link_opts, elf, size );
  } while(0);

  free( bpf );
  free( elf );
  return 0;
}
