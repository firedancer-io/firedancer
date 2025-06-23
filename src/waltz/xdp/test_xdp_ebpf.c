/* test_xdp_ebpf: Exercises unit test invocations of ebpf_xdp_flow via
   bpf(2) syscall in BPF_PROG_TEST_RUN mode. */

#if !defined(__linux__)
#error "test_xdp_ebpf requires Linux operating system with XDP support"
#endif

#define _DEFAULT_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../ebpf/fd_linux_bpf.h"
#include "fd_xdp1.h"

/* Test support *******************************************************/

int prog_fd     = -1; /* BPF program */
int xsks_fd     = -1; /* Queue-to-XSK map */
int xsk_fd      = -1; /* AF_XDP socket */

/* Test harness *******************************************************/

static int
fd_bpf_map_clear( int map_fd ) {
  ulong key = 0UL;

  for(;;) {
    ulong next_key;
    if( FD_UNLIKELY( 0!=fd_bpf_map_get_next_key( map_fd, &key, &next_key ) ) ) {
      if( FD_LIKELY( errno==ENOENT ) ) break;
      FD_LOG_ERR(( "bpf_map_get_next_key(%d,%#lx,%p) failed (%i-%s)",
                   map_fd, key, (void *)&next_key, errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( 0!=fd_bpf_map_delete_elem( map_fd, &next_key ) ) )
      FD_LOG_ERR(( "bpf_map_delete_elem(%d,%#lx) failed (%i-%s)", map_fd, next_key, errno, fd_io_strerror( errno ) ));

    key = next_key;
  }

  return 0;
}

static int
load_prog( ulong * code_buf,
           ulong   code_cnt ) {
  static char ebpf_kern_log[ 32768UL ];
  ebpf_kern_log[0] = 0;
  union bpf_attr attr = {
    .prog_type = BPF_PROG_TYPE_XDP,
    .insn_cnt  = (uint)code_cnt,
    .insns     = (ulong)code_buf,
    .license   = (ulong)"Apache-2.0",
    .prog_name = "fd_redirect",
    .log_level = 6,
    .log_size  = 32768UL,
    .log_buf   = (ulong)ebpf_kern_log
  };
  prog_fd = (int)bpf( BPF_PROG_LOAD, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( prog_fd<0 ) ) {
    if( errno==EPERM ) {
      FD_LOG_WARNING(( "skip: insufficient permissions to load BPF object" ));
      fd_halt();
      exit( 0 );
    }
    FD_LOG_WARNING(( "eBPF verifier log:\n%s", ebpf_kern_log ));
    FD_LOG_ERR(( "BPF_PROG_LOAD failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  return prog_fd;
}

static void
prog_test( uchar const * pkt,
           ulong         pkt_sz,
           char const *  name,
           uint          expected_action ) {
  fd_bpf_map_clear( xsks_fd );

# define FD_XDP_TEST(c) do { if( FD_UNLIKELY( !(c) ) ) FD_LOG_ERR(( "FAIL (%s): %s", name, #c )); } while(0)

  /* Hook up to XSK */
  int rx_queue = 0;
  FD_TEST( 0==fd_bpf_map_update_elem( xsks_fd, &rx_queue, &xsk_fd, 0UL ) );

  union bpf_attr attr = {
    .test = {
      .prog_fd      = (uint)prog_fd,
      .data_in      = (ulong)pkt,
      .data_size_in = (uint)pkt_sz
    }
  };
  FD_XDP_TEST( 0==bpf( BPF_PROG_TEST_RUN, &attr, sizeof(union bpf_attr) ) );

  FD_LOG_INFO(( "bpf test %s returned %#x", name, attr.test.retval ));

  FD_XDP_TEST( attr.test.retval == expected_action );

# undef FD_XDP_TEST
}

/* Test runs **********************************************************/

FD_IMPORT_BINARY( tcp_syn,         "src/waltz/xdp/fixtures/tcp_syn.bin"         );
FD_IMPORT_BINARY( tcp_ack,         "src/waltz/xdp/fixtures/tcp_ack.bin"         );
FD_IMPORT_BINARY( tcp_syn_ack,     "src/waltz/xdp/fixtures/tcp_syn_ack.bin"     );
FD_IMPORT_BINARY( arp_request,     "src/waltz/xdp/fixtures/arp_request.bin"     );
FD_IMPORT_BINARY( arp_reply,       "src/waltz/xdp/fixtures/arp_reply.bin"       );
FD_IMPORT_BINARY( icmp_echo_reply, "src/waltz/xdp/fixtures/icmp_echo_reply.bin" );
FD_IMPORT_BINARY( icmp_echo,       "src/waltz/xdp/fixtures/icmp_echo.bin"       );
FD_IMPORT_BINARY( dns_query_a,     "src/waltz/xdp/fixtures/dns_query_a.bin"     );
FD_IMPORT_BINARY( tcp_rst,         "src/waltz/xdp/fixtures/tcp_rst.bin"         );
FD_IMPORT_BINARY( quic_initial,    "src/waltz/xdp/fixtures/quic_initial.bin"    );

#define PORT0 8001
#define PORT1 9090

#define USHORT_BSWAP( v ) ((ushort)(((v>>8)|(v<<8))))

static void
run_tests( uint dst_ip ) {
  union {
    uchar b[ 42 ];
    struct __attribute__((packed)) {
      fd_eth_hdr_t eth;
      fd_ip4_hdr_t ip4;
      fd_udp_hdr_t udp;
    };
  } m = {
    .eth = { .net_type = USHORT_BSWAP( FD_ETH_HDR_TYPE_IP ) },
    .ip4 = { .verihl = 0x45, .protocol = FD_IP4_HDR_PROTOCOL_UDP,
             .net_tot_len = fd_ushort_bswap( 28 ) },
    .udp = { .net_dport = 0 }
  };
  m.ip4.daddr = dst_ip;

  /* Check UDP dest port */
  for( uint port=0; port<65536; port++ ) {
    uint expect = XDP_PASS;
    if( port==PORT0 ) expect = XDP_REDIRECT;
    if( port==PORT1 ) expect = XDP_REDIRECT;
    m.udp.net_dport = (ushort)fd_ushort_bswap( (ushort)port );
    char test_name[ 16 ];
    snprintf( test_name, sizeof(test_name), "udp_dport_%u", port );
    prog_test( m.b, sizeof(m), test_name, expect );
  }
  m.udp.net_dport = USHORT_BSWAP( PORT0 );

  /* Check IPv4 proto field */
  prog_test( m.b, sizeof(m), "sanity", XDP_REDIRECT );
  m.ip4.protocol = FD_IP4_HDR_PROTOCOL_ICMP;
  prog_test( m.b, sizeof(m), "icmp", XDP_PASS );
  m.ip4.protocol = FD_IP4_HDR_PROTOCOL_TCP;
  prog_test( m.b, sizeof(m), "tcp", XDP_PASS );
  m.ip4.protocol = FD_IP4_HDR_PROTOCOL_UDP;

  /* Check IPv4 dst IP */
  prog_test( m.b, sizeof(m), "sanity", XDP_REDIRECT );
  m.ip4.daddr++;
  prog_test( m.b, sizeof(m), "other_dst", dst_ip ? XDP_PASS : XDP_REDIRECT );
  m.ip4.daddr = 0;
  prog_test( m.b, sizeof(m), "other_dst", dst_ip ? XDP_PASS : XDP_REDIRECT );
  m.ip4.daddr = dst_ip;

  /* Check Ethertype */
  prog_test( m.b, sizeof(m), "sanity", XDP_REDIRECT );
  for( uint ethertype=0; ethertype<65536; ethertype++ ) {
    uint expect = XDP_PASS;
    if( ethertype==FD_ETH_HDR_TYPE_IP ) expect = XDP_REDIRECT;
    m.eth.net_type = (ushort)fd_ushort_bswap( (ushort)ethertype );
    char test_name[ 16 ];
    snprintf( test_name, sizeof(test_name), "ethertype_%04x", fd_ushort_bswap( (ushort)ethertype ) );
    prog_test( m.b, sizeof(m), test_name, expect );
  }
  m.eth.net_type = USHORT_BSWAP( FD_ETH_HDR_TYPE_IP );
  prog_test( m.b, sizeof(m), "sanity", XDP_REDIRECT );

  /* Check IHL */
  union {
    uchar b[ 46 ];
    struct __attribute__((packed)) {
      fd_eth_hdr_t eth;
      fd_ip4_hdr_t ip4;
      uint         ip4_opt;
      fd_udp_hdr_t udp;
    };
  } m1 = {
    .eth = { .net_type = USHORT_BSWAP( FD_ETH_HDR_TYPE_IP ) },
    .ip4 = { .verihl = 0x46, .protocol = FD_IP4_HDR_PROTOCOL_UDP },
    .udp = { .net_dport = USHORT_BSWAP( PORT0 ) }
  };
  m1.ip4.daddr = dst_ip;
  prog_test( m1.b, sizeof(m1), "ihl6", XDP_REDIRECT );

# define TEST_FIXTURE(name) name, name##_sz, #name
  prog_test( TEST_FIXTURE( tcp_syn         ), XDP_PASS );
  prog_test( TEST_FIXTURE( tcp_ack         ), XDP_PASS );
  prog_test( TEST_FIXTURE( tcp_syn_ack     ), XDP_PASS );
  prog_test( TEST_FIXTURE( arp_request     ), XDP_PASS );
  prog_test( TEST_FIXTURE( arp_reply       ), XDP_PASS );
  prog_test( TEST_FIXTURE( icmp_echo_reply ), XDP_PASS );
  prog_test( TEST_FIXTURE( icmp_echo       ), XDP_PASS );
  prog_test( TEST_FIXTURE( dns_query_a     ), XDP_PASS );
  prog_test( TEST_FIXTURE( tcp_rst         ), XDP_PASS );
  prog_test( TEST_FIXTURE( quic_initial    ), XDP_REDIRECT );
# undef TEST_FIXTURE
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  /* Create maps */

  union bpf_attr attr = {
    .map_type    = BPF_MAP_TYPE_XSKMAP,
    .key_size    = 4U,
    .value_size  = 4U,
    .max_entries = 4U,
    .map_name    = "fd_xdp_xsks"
  };
  xsks_fd = (int)bpf( BPF_MAP_CREATE, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( xsks_fd<0 ) ) {
    if( FD_UNLIKELY( errno==EPERM ) ) {
      FD_LOG_WARNING(( "skip: insufficient perms" ));
      fd_halt();
      return 0;
    }
    FD_LOG_WARNING(( "Failed to create XSKMAP (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Create new AF_XDP socket. Doesn't actually have to be operational
     for bpf_redirect_map() to return XDP_REDIRECT. */
  xsk_fd = socket( AF_XDP, SOCK_RAW, 0 );
  FD_TEST( xsk_fd>=0 );

  /* Load program */

  ushort ports[2] = { PORT0, PORT1 };
  ulong code_buf[ 512 ];
  ulong code_cnt = fd_xdp_gen_program( code_buf, xsks_fd, FD_IP4_ADDR( 10,1,2,3 ), ports, 2UL );
  int prog_fd = load_prog( code_buf, code_cnt );
  run_tests( FD_IP4_ADDR( 10,1,2,3 ) );
  close( prog_fd );

  code_cnt = fd_xdp_gen_program( code_buf, xsks_fd, 0U, ports, 2UL );
  prog_fd = load_prog( code_buf, code_cnt );
  run_tests( FD_IP4_ADDR( 0,0,0,0 ) );
  close( prog_fd );

  /* Clean up */

  close( xsk_fd );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
