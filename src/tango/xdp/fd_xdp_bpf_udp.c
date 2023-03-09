#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* limits the number of nic queues supported */
#if !defined(FD_XDP_XSKS_MAP_SZ)
#  define FD_XDP_XSKS_MAP_SZ 256
#endif

/* limits the number of udp ports we can listen on */
#if !defined(FD_XDP_UDP_MAP_SZ)
#  define FD_XDP_UDP_MAP_SZ 64
#endif

/* BPF program cannot have too many dependencies
   so simply define these here */
typedef unsigned char uchar;
typedef unsigned int  uint;
typedef unsigned long ulong;

/* map for forwarding packets to an xdp socket */
struct bpf_map_def
__attribute__(( section( "maps" ), used ))
xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = FD_XDP_XSKS_MAP_SZ,
};

/* map for listening on udp port */
struct bpf_map_def
__attribute__(( section( "maps" ), used ))
udp_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = FD_XDP_UDP_MAP_SZ,
};

__attribute__(( section( "xdp_sock" ), used ))
int xdp_sock_prog( struct xdp_md *ctx )
{
  uchar const * data     = ( (const uchar*)(ulong)ctx->data );
  uchar const * data_end = ( (const uchar*)(ulong)ctx->data_end );

  if( data + 60ul > data_end ) return XDP_PASS;

  // // data[12..13] is eth type
  // // data[12] is ipproto
  // uint ethtype1 = ( (uint)data[12] << 8u ) | (uint)data[13];
  // //uint vlan     = ( (uint)data[14] << 8u ) | (uint)data[15];
  // //uint ethtype2 = ( (uint)data[16] << 8u ) | (uint)data[17];

  // // do we have an IP packet?
  // if( ethtype1 != 0x0800u ) return XDP_PASS;

  // // do we have a UDP packet?
  // uint ipproto = (uint)data[23];
  // if( ipproto != 0x11 ) return XDP_PASS;

  // test ethtype and ipproto in 1 branch
  uint test = ( (uint)data[12] << 16u ) | ( (uint)data[13] << 8u ) | (uint)data[23];
  if( test != 0x080011 ) return XDP_PASS;

  // IP may have options, so calculate IP header length to find
  // start of UDP header
  uint iplen = ( ( (uint)data[14] ) & 0xfu ) * 4u;

  uchar const * udp = data + iplen + 14;

  if( udp + 16ul >= data_end ) return XDP_PASS;

  // udp[2..3] is udp dst port
  //uint udp_key = ( (uint)data[udp_ofs_0] << 8u ) | (uint)data[udp_ofs_1];
  uint udp_key = ( ( (uint)udp[2] ) << 8u ) | (uint)udp[3];

  uint * udp_value = bpf_map_lookup_elem( &udp_map, &udp_key );
  if( !udp_value ) {
    // no match, pass to kernel
    return XDP_PASS;
  }

  /* look up the interface queue to find the socket to forward to */
  uint socket_key = ctx->rx_queue_index;

  return bpf_redirect_map( &xsks_map, socket_key, 0 );

}

