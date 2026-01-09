#ifndef HEADER_fd_src_util_net_fd_net_headers_h
#define HEADER_fd_src_util_net_fd_net_headers_h

#include "fd_eth.h"
#include "fd_ip4.h"
#include "fd_udp.h"
#include "fd_gre.h"

/* fd_ip4_udp_hdrs is useful to construct Ethernet+IPv4+UDP network
   headers. Assumes that the IPv4 header has no options (IHL=5). */

union fd_ip4_udp_hdrs {
  uchar uc[ 42 ];
  struct {
    fd_eth_hdr_t eth[1];
    fd_ip4_hdr_t ip4[1];
    fd_udp_hdr_t udp[1];
  };
};

typedef union fd_ip4_udp_hdrs fd_ip4_udp_hdrs_t;

FD_PROTOTYPES_BEGIN

/* Helper method to populate a header template containing Ethernet,
   IPv4 (no options), and UDP headers.  Note that IPv4 and UDP header
   checksums are set to 0. */

static inline fd_ip4_udp_hdrs_t *
fd_ip4_udp_hdr_init( fd_ip4_udp_hdrs_t * hdrs,
                     ulong               payload_sz,
                     uint                src_ip,
                     ushort              src_port ) {
  fd_eth_hdr_t * eth = hdrs->eth;
  memset( eth->dst, 0, 6UL );
  memset( eth->src, 0, 6UL );
  eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

  fd_ip4_hdr_t * ip4 = hdrs->ip4;
  ip4->verihl       = FD_IP4_VERIHL( 4U, 5U );
  ip4->tos          = (uchar)0;
  ip4->net_tot_len  = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  ip4->net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
  ip4->ttl          = (uchar)64;
  ip4->protocol     = FD_IP4_HDR_PROTOCOL_UDP;
  ip4->check        = 0U;
  ip4->saddr        = src_ip;
  ip4->daddr        = 0;

  fd_udp_hdr_t * udp = hdrs->udp;
  udp->net_sport = fd_ushort_bswap( src_port );
  udp->net_dport = (ushort)0;
  udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  udp->check     = (ushort)0;

  return hdrs;
}

FD_PROTOTYPES_END

/* fd_ip4_port encapsulates an IP4 address and the udp port  */

union fd_ip4_port {
  struct {
    uint   addr;  /* net order */
    ushort port;  /* net order */
  };
  ulong l : 48;
};

typedef union fd_ip4_port fd_ip4_port_t;

#endif /* HEADER_fd_src_util_net_fd_net_headers_h */
