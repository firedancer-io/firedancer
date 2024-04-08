#include "fd_ebpf.h"
#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"

#include <assert.h>
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

  static fd_ebpf_sym_t const syms[ 2 ] = {
    { .name = "fd_xdp_udp_dsts", .value = 10 },
    { .name = "fd_xdp_xsks",     .value = 20 }
  };

  /* heap allocated buffers */
  uchar * elf = NULL;

  do {
    elf = malloc( size );
    if( !elf ) break;
    fd_memcpy( elf, data, size );

    fd_ebpf_link_opts_t link_opts = {
      .section = "xdp",
      .sym     = syms,
      .sym_cnt = 2UL
    };

    fd_ebpf_link_opts_t * res = fd_ebpf_static_link( &link_opts, elf, size );
    if( res ) {
      assert( res == &link_opts );
      assert( ( (ulong)res->bpf >= (ulong)elf           ) &
              ( res->bpf_sz     <= size                 ) &
              ( fd_ulong_is_aligned( res->bpf_sz, 8UL ) ) );
    }
  } while(0);

  free( elf );
  return 0;
}
