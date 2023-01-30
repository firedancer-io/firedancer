#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#if !defined(FD_XDP_XSKS_MAP_SZ)
#  define FD_XDP_XSKS_MAP_SZ 16
#endif

#if !defined(FD_XDP_UDP_MAP_SZ)
#  define FD_XDP_UDP_MAP_SZ 64
#endif

struct bpf_map_def
__attribute__(( section( "maps" ), used ))
xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = FD_XDP_XSKS_MAP_SZ,
};

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
  // unsigned ethtype1 = ( (unsigned)data[12] << 8u ) | (unsigned)data[13];
  // //unsigned vlan     = ( (unsigned)data[14] << 8u ) | (unsigned)data[15];
  // //unsigned ethtype2 = ( (unsigned)data[16] << 8u ) | (unsigned)data[17];

  // // do we have an IP packet?
  // if( ethtype1 != 0x0800u ) return XDP_PASS;

  // // do we have a UDP packet?
  // unsigned ipproto = (unsigned)data[23];
  // if( ipproto != 0x11 ) return XDP_PASS;

  // test ethtype and ipproto in 1 branch
  unsigned test = ( (unsigned)data[12] << 16u ) | ( (unsigned)data[13] << 8u ) | (unsigned)data[23];
  if( test != 0x080011 ) return XDP_PASS;

  // IP may have options, so calculate IP header length to find
  // start of UDP header
  unsigned iplen = ( ( (unsigned)data[14] ) & 0xfu ) * 4u;

  uchar const * udp = data + iplen + 14;

  if( udp + 16ul >= data_end ) return XDP_PASS;

  // udp[2..3] is udp dst port
  //unsigned udp_key = ( (unsigned)data[udp_ofs_0] << 8u ) | (unsigned)data[udp_ofs_1];
  unsigned udp_key = ( ( (unsigned)udp[2] ) << 8u ) | (unsigned)udp[3];

  unsigned * udp_value = bpf_map_lookup_elem( &udp_map, &udp_key );
  if( !udp_value ) {
    // no match, pass to kernel
    return XDP_PASS;
  }

  unsigned socket_key = *udp_value;

  return bpf_redirect_map( &xsks_map, socket_key, 0 );

}

