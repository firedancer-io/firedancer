/* fd_xdp_redirect_prog: XDP program implementing AF_XDP redirection.

   This program is the primary entrypoint for handling network traffic
   on a Firedancer instance at line rate. The entrypoint is invoked for
   every packet as part of the XDP stage of the Linux host.  Its task is
   to forward packets to the appropriate destination which may be the
   XSKs handling Firedancer traffic or the regular Linux networking
   stack for unrelated traffic.  It may also be used in the future to
   protect against packet floods.

   The following code targets the Linux eBPF virtual machine which does
   not yet support libc and has strict control-flow and memory
   restrictions. */


#if !defined(__bpf__)
#error "ebpf_xdp_flow requires eBPF target"
#endif

#include "../ebpf/fd_ebpf_base.h"
#include "fd_xdp_redirect_prog.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


/* TODO: Some devices only support one XSK which requires multiplexing
         traffic.  Add flow identifier (application) to packet metadata
         so fd_xsk consumer can separate network flows. */


/* Metadata ***********************************************************/

char __license[] __attribute__(( section("license") )) = "Apache-2.0";

/* eBPF maps **********************************************************/

/* eBPF maps allows sharing information between the Linux userspace and
   eBPF programs (XDP).  In this program, they are used to lookup flow
   steering configuration. */

/* firedancer_xsks: Available XSKs for AF_XDP
   key in the interface queue index (in host byte order). */
struct {
  __uint( type,        BPF_MAP_TYPE_XSKMAP );
  __uint( max_entries, FD_XDP_XSKS_MAP_CNT );
  __type( key,         int                 );
  __type( value,       int                 );
} firedancer_xsks SEC(".maps");

/* firedancer_udp_dsts: UDP/IP listen addrs
   key is hex pattern 0000AAAAAAAABBBB where AAAAAAAA is the IP dest
   addr and BBBB is the UDP dest port (in network byte order). */
struct {
  __uint( type,        BPF_MAP_TYPE_HASH  );
  __uint( max_entries, FD_XDP_UDP_MAP_CNT );
  __type( key,         ulong              );
  __type( value,       int                );
} firedancer_udp_dsts SEC(".maps");

/* Executable Code ****************************************************/

/* firedancer_redirect: Entrypoint of redirect XDP program.
   ctx is the XDP context for an Ethernet/IP packet.
   Returns an XDP action code in XDP_{PASS,REDIRECT,DROP}. */
__attribute__(( section("xdp"), used ))
int firedancer_redirect( struct xdp_md *ctx ) {

  uchar const * data      = (uchar const*)(ulong)ctx->data;
  uchar const * data_end  = (uchar const*)(ulong)ctx->data_end;

  if( FD_UNLIKELY( data + 60U > data_end ) ) return XDP_PASS;

  uchar const * iphdr = data + 14U;

  /* Filter for UDP/IPv4 packets.
     Test for ethtype and ipproto in 1 branch */
  uint test_ethip = ( (uint)data[12] << 16u ) | ( (uint)data[13] << 8u ) | (uint)data[23];
  if( FD_UNLIKELY( test_ethip!=0x080011 ) ) return XDP_PASS;

  /* IPv4 is variable-length, so lookup IHL to find start of UDP */
  uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
  uchar const * udp = iphdr + iplen;

  /* Ignore if UDP header is too short */
  if( udp+4U > data_end ) return XDP_PASS;

  /* Extract IP dest addr and UDP dest port */
  ulong ip_dstaddr  = *(uint   *)( iphdr+16UL );
  ulong udp_dstport = *(ushort *)( udp+2UL    );
  ulong flow_key    = (ip_dstaddr<<16) | udp_dstport;

  /* Filter for known UDP dest ports of interest */
  uint * udp_value = bpf_map_lookup_elem( &firedancer_udp_dsts, &flow_key );
  if( !udp_value ) return XDP_PASS;

  /* Look up the interface queue to find the socket to forward to */
  uint socket_key = ctx->rx_queue_index;
  return bpf_redirect_map( &firedancer_xsks, socket_key, 0 );
}

