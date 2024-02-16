#define _DEFAULT_SOURCE
#include "fd_ebpf.h"
#include "../../util/fd_util.h"

FD_IMPORT_BINARY( test_prog, "src/waltz/xdp/fd_xdp_redirect_prog.o" );

static uchar prog_buf[ 2048UL ];

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( test_prog_sz<=2048UL );
  fd_memcpy( prog_buf, test_prog, test_prog_sz );

  fd_ebpf_sym_t syms[ 2 ] = {
    { .name = "fd_xdp_udp_dsts", .value = 0x41424344 },
    { .name = "fd_xdp_xsks",     .value = 0x45464748 }
  };
  fd_ebpf_link_opts_t opts = {
    .section = "xdp",
    .sym     = syms,
    .sym_cnt = 2UL
  };

  fd_ebpf_link_opts_t * res =
    fd_ebpf_static_link( &opts, prog_buf, test_prog_sz );
  FD_TEST( res );

  FD_TEST( opts.bpf );
  FD_TEST( fd_ulong_is_aligned( (ulong)opts.bpf,    8UL ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)opts.bpf_sz, 8UL ) );

  FD_LOG_HEXDUMP_INFO(( "post reloc", opts.bpf, opts.bpf_sz ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
