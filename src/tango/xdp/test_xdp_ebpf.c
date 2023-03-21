/* test_xdp_ebpf: Exercises unit test invocations of ebpf_xdp_flow via
   bpf(2) syscall in BPF_PROG_TEST_RUN mode. */

#if !defined(__linux__) || !FD_HAS_LIBBPF
#error "fd_xdp_steer requires Linux operating system with XDP support"
#endif

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "fd_xdp_redirect_user.h"
#include "../../util/fd_util.h"


/* Test support *******************************************************/

/* fd_xdp_redirect_prog is eBPF ELF object containing the XDP program.
   It is embedded into this program. Build with `make ebpf-bin`. */

FD_IMPORT_BINARY( fd_xdp_redirect_prog, "build/ebpf/clang/bin/fd_xdp_redirect_prog.o" );

/* Kernel file descriptors */

int prog_fd     = -1; /* BPF program */
int udp_dsts_fd = -1; /* UDP destinations */
int xsks_fd     = -1; /* Queue-to-XSK map */
int xsk_fd      = -1; /* AF_XDP socket */

/* Test harness *******************************************************/

typedef struct { ulong k; int v; } fd_udp_dst_kv_t;
typedef struct { int   k; int v; } fd_xsks_kv_t;

struct fd_xdp_redirect_test {
  /* Input ****************/
  char const * name;

  uchar const * packet;    /* Packet content (starting at Ethernet) */
  ulong const * packet_sz; /* Pointer to size */

  /* Note: Relies on little-endian addressing */
  fd_udp_dst_kv_t *udp_dsts_kv; /* Null-delimited key-value pairs in UDP dsts map */
  fd_xsks_kv_t    *xsks_kv;     /* Null-delimited key-value pairs in XSKs map     */

  /* Output ***************/

  uint xdp_action;
};
typedef struct fd_xdp_redirect_test fd_xdp_redirect_test_t;

static int
fd_bpf_map_clear( int map_fd ) {
  ulong key = 0UL;

  for(;;) {
    ulong next_key;
    int res = bpf_map_get_next_key( map_fd, &key, &next_key );
    if( FD_UNLIKELY( res!=0 ) ) {
      if( FD_LIKELY( errno==ENOENT ) ) break;
      FD_LOG_ERR(( "bpf_map_get_next_key(%d,%#lx,%p) failed (%d-%s)",
                   map_fd, key, (void *)&next_key, errno, strerror( errno ) ));
    }

    if( FD_UNLIKELY( 0!=bpf_map_delete_elem( map_fd, &next_key ) ) )
      FD_LOG_ERR(( "bpf_map_delete_elem(%d,%#lx) failed (%d-%s)",
                   map_fd, next_key, errno, strerror( errno ) ));

    key = next_key;
  }

  return 0;
}

static void
fd_run_xdp_redirect_test( fd_xdp_redirect_test_t const * test ) {
  fd_bpf_map_clear( udp_dsts_fd );
  fd_bpf_map_clear( xsks_fd     );

# define FD_XDP_TEST(c) do { if( FD_UNLIKELY( !(c) ) ) FD_LOG_ERR(( "FAIL (%s): %s", test->name, #c )); } while(0)

  if( test->udp_dsts_kv ) {
    for( fd_udp_dst_kv_t *kv=test->udp_dsts_kv; kv->k; kv++ ) {
      if( FD_UNLIKELY( 0!=bpf_map_update_elem( udp_dsts_fd, &kv->k, &kv->v, 0UL ) ) ) {
        FD_LOG_ERR(( "bpf_map_update_elem(%d,%#lx,%#x,0) failed (%d-%s)",
                    udp_dsts_fd, kv->k, kv->v, errno, strerror( errno ) ));
      }
    }
  } else {
    /* Add 127.0.0.1:8001 to map by default */
    ulong k=fd_xdp_udp_dst_key( 0x7f000001U, 8001U );
    uint  v=0U;
    FD_TEST( 0==bpf_map_update_elem( udp_dsts_fd, &k, &v, 0UL ) );
  }

  /* Hook up to XSK */
  int rx_queue = 0;
  FD_TEST( 0==bpf_map_update_elem( xsks_fd, &rx_queue, &xsk_fd, 0UL ) );

  struct bpf_test_run_opts test_run = {
    .sz           = sizeof(struct bpf_test_run_opts),
    .data_in      =        test->packet,
    .data_size_in = (uint)*test->packet_sz,
  };
  FD_XDP_TEST( 0==bpf_prog_test_run_opts( prog_fd, &test_run ) );

  FD_LOG_INFO(( "bpf test %s returned %#x", test->name, test_run.retval ));

  FD_XDP_TEST( test_run.retval == test->xdp_action );

# undef FD_XDP_TEST
}

/* Test runs **********************************************************/

FD_IMPORT_BINARY( tcp_syn,         "src/tango/xdp/fixtures/tcp_syn.bin"         );
FD_IMPORT_BINARY( tcp_ack,         "src/tango/xdp/fixtures/tcp_ack.bin"         );
FD_IMPORT_BINARY( tcp_syn_ack,     "src/tango/xdp/fixtures/tcp_syn_ack.bin"     );
FD_IMPORT_BINARY( arp_request,     "src/tango/xdp/fixtures/arp_request.bin"     );
FD_IMPORT_BINARY( arp_reply,       "src/tango/xdp/fixtures/arp_reply.bin"       );
FD_IMPORT_BINARY( icmp_echo_reply, "src/tango/xdp/fixtures/icmp_echo_reply.bin" );
FD_IMPORT_BINARY( icmp_echo,       "src/tango/xdp/fixtures/icmp_echo.bin"       );
FD_IMPORT_BINARY( dns_query_a,     "src/tango/xdp/fixtures/dns_query_a.bin"     );
FD_IMPORT_BINARY( tcp_rst,         "src/tango/xdp/fixtures/tcp_rst.bin"         );

FD_IMPORT_BINARY( quic_initial,    "src/tango/xdp/fixtures/quic_initial.bin"    );

fd_xdp_redirect_test_t tests[] = {
  /* Ensure that program sets XDP_PASS on common packet types that are
     not part of the Firedancer application layer. */
  #define TEST(x) .name = #x , .packet = x , .packet_sz = &x##_sz,

  { TEST( tcp_syn         ) .xdp_action = XDP_PASS },
  { TEST( tcp_ack         ) .xdp_action = XDP_PASS },
  { TEST( tcp_syn_ack     ) .xdp_action = XDP_PASS },
  { TEST( arp_request     ) .xdp_action = XDP_PASS },
  { TEST( arp_reply       ) .xdp_action = XDP_PASS },
  { TEST( icmp_echo_reply ) .xdp_action = XDP_PASS },
  { TEST( icmp_echo       ) .xdp_action = XDP_PASS },
  { TEST( dns_query_a     ) .xdp_action = XDP_PASS },
  { TEST( tcp_rst         ) .xdp_action = XDP_PASS },

  { TEST( quic_initial    ) .xdp_action = XDP_REDIRECT },

  #undef TEST
  {0}
};


int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  /* Open program */

  struct bpf_object_open_opts open_opts = {
    .sz = sizeof(struct bpf_object_open_opts)
  };
  struct bpf_object * obj = bpf_object__open_mem( fd_xdp_redirect_prog, fd_xdp_redirect_prog_sz, &open_opts );
  FD_TEST( obj );

  /* Load object into kernel */

  if( FD_UNLIKELY( 0!=bpf_object__load( obj ) ) ) {
    if( errno==EPERM ) {
      FD_LOG_WARNING(( "skip: insufficient permissions to load BPF object" ));
      bpf_object__close( obj );
      fd_halt();
      return 0;
    }
    FD_LOG_ERR(( "bpf_object__load failed (%d-%s)", errno, strerror( errno ) ));
  }

  /* Open handles of object's resources */

  struct bpf_program * prog         = bpf_object__find_program_by_name( obj, "fd_xdp_redirect" );
  struct bpf_map *     udp_dsts_map = bpf_object__find_map_by_name    ( obj, "fd_xdp_udp_dsts" );
  struct bpf_map *     xsks_map     = bpf_object__find_map_by_name    ( obj, "fd_xdp_xsks"     );

  FD_TEST( prog         );
  FD_TEST( udp_dsts_map );
  FD_TEST( xsks_map     );

  /* Query program/maps from BPF object */
  int _prog_fd     = bpf_program__fd( prog         );
  int _udp_dsts_fd = bpf_map__fd    ( udp_dsts_map );
  int _xsks_fd     = bpf_map__fd    ( xsks_map     );
  /* Create new AF_XDP socket. Doesn't actually have to be operational
     for bpf_redirect_map() to return XDP_REDIRECT. */
  int _xsk_fd      = socket( AF_XDP, SOCK_RAW, 0 );

  FD_TEST( _prog_fd    >=0 );
  FD_TEST( _udp_dsts_fd>=0 );
  FD_TEST( _xsks_fd    >=0 );
  FD_TEST( _xsk_fd     >=0 );

  /* Set globals */

  prog_fd     = _prog_fd;
  udp_dsts_fd = _udp_dsts_fd;
  xsks_fd     = _xsks_fd;
  xsk_fd      = _xsk_fd;

  /* Run tests */

  for( fd_xdp_redirect_test_t * t=tests; t->packet; t++ )
    fd_run_xdp_redirect_test( t );

  /* Clean up */

  bpf_object__close( obj ); /* Also unloads programs */
  close( xsk_fd );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
