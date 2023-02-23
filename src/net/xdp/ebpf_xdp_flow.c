/* ebpf_xdp_flow: XDP program implementing flow steering.

   This program is the primary entrypoint for handling network traffic
   on a Firedancer instance at line rate. The entrypoint is invoked for
   every packet as part of the XDP stage of the Linux host.  Its task is
   to forward packets to the appropriate destination which may be the
   XSKs handling Firedancer traffic or the regular Linux networking
   stack for unrelated traffic.  It may also be used in the future to
   protect against packet floods.

   The following code targets the Linux eBPF virtual machine which does
   not yet support libc and has severe control-flow and memory
   restrictions. */


#if !defined(__bpf__)
#error "ebpf_xdp_flow requires eBPF target"
#endif

#include "../ebpf/fd_ebpf_base.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


/* Runtime limits *****************************************************/

/* FD_XDP_XSKS_MAP_SZ: Max supported number of XSKs (queues).
   The actual limit may be lower in practice depending on hardware. */
#if !defined(FD_XDP_XSKS_MAP_SZ)
#  define FD_XDP_XSKS_MAP_SZ 256
#endif

/* FD_XDP_UDP_MAP_SZ: Max supported number of UDP port mappings. */
#if !defined(FD_XDP_UDP_MAP_SZ)
#  define FD_XDP_UDP_MAP_SZ 64
#endif

/* Metadata ***********************************************************/

char __license[] __attribute__(( section("license") )) = "Apache-2.0";

/* eBPF maps **********************************************************/

/* eBPF maps allows sharing information between the Linux userspace and
   eBPF programs (XDP).  In this program, they are used to lookup flow
   steering configuration. */

/* firedancer_xsk_map: Available XSKs for AF_XDP */
struct {
  __uint( type,        BPF_MAP_TYPE_XSKMAP );
  __uint( max_entries, FD_XDP_XSKS_MAP_SZ  );
  __type( key,         int                 );
  __type( value,       int                 );
  __uint( pinning,     1                   );
} firedancer_xsk_map SEC(".maps");

/* firedancer_udp_map: UDP destination ports assigned to Firedancer modules */
struct {
  __uint( type,        BPF_MAP_TYPE_HASH );
  __uint( max_entries, FD_XDP_UDP_MAP_SZ );
  __type( key,         int               );
  __type( value,       int               );
  __uint( pinning,     1                 );
} firedancer_udp_map SEC(".maps");

/* Executable Code ****************************************************/

/* firedancer_flow_steer: Entrypoint of flow steering XDP program.
   ctx is the XDP context for an Ethernet/IP packet.
   Returns an XDP action code in XDP_{PASS,REDIRECT,DROP}. */
__attribute__(( section("xdp"), used ))
int firedancer_steer( struct xdp_md *ctx ) {

  uchar const * data      = (uchar const*)(ulong)ctx->data;
  uchar const * data_end  = (uchar const*)(ulong)ctx->data_end;

  if( data + 60ul > data_end ) return XDP_PASS;

  /* Filter for UDP/IPv4 packets.
     Test for ethtype and ipproto in 1 branch */
  uint test_ethip = ( (uint)data[12] << 16u ) | ( (uint)data[13] << 8u ) | (uint)data[23];
  if( FD_UNLIKELY( test_ethip!=0x080011 ) ) return XDP_PASS;

  /* IPv4 is variable-length, so lookup IHL to find start of UDP */
  uint iplen = ( ( (uint)data[14] ) & 0xfu ) * 4u;
  uchar const * udp = data + iplen + 14;

  /* TODO: Filter for IP destination address.
           The XDP program may be deployed on a device that forwards
           traffic to other machines.  The current logic hijacks traffic
           that it is not supposed to look for. */

  /* Ignore if UDP header is too short */
  if( udp+16UL >= data_end ) return XDP_PASS;

  /* Extract UDP dest port */
  uint udp_key = ( ( (uint)udp[2] ) << 8u ) | (uint)udp[3];

  /* Filter for known UDP dest ports of interest */
  uint * udp_value = bpf_map_lookup_elem( &firedancer_udp_map, &udp_key );
  if( !udp_value ) return XDP_PASS;

  /* Look up the interface queue to find the socket to forward to */
  uint socket_key = ctx->rx_queue_index;
  return bpf_redirect_map( &firedancer_xsk_map, socket_key, 0 );
}

