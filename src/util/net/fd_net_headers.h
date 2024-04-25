#ifndef HEADER_fd_src_util_net_util_h
#define HEADER_fd_src_util_net_util_h

#include "fd_udp.h"
#include "fd_eth.h"

typedef struct __attribute__((packed)) {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];
} fd_net_hdrs_t;

FD_PROTOTYPES_BEGIN

/* Helper method to populate a header template
   containing ethernet, UDP and IP headers with
   default values. Used for pre-staging headers. */

fd_net_hdrs_t *
fd_net_create_packet_header_template( fd_net_hdrs_t * pkt,
                                 ulong          payload_sz,
                                 uint           src_ip,
                                 uchar const *  src_mac,
                                 ushort         src_port ) {
  memset( pkt->eth->dst, 0,       6UL );
  memcpy( pkt->eth->src, src_mac, 6UL );
  pkt->eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

  pkt->ip4->verihl       = FD_IP4_VERIHL( 4U, 5U );
  pkt->ip4->tos          = (uchar)0;
  pkt->ip4->net_tot_len  = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  pkt->ip4->net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
  pkt->ip4->ttl          = (uchar)64;
  pkt->ip4->protocol     = FD_IP4_HDR_PROTOCOL_UDP;
  pkt->ip4->check        = 0U;
  memcpy( pkt->ip4->saddr_c, &src_ip, 4UL );
  memset( pkt->ip4->daddr_c, 0,       4UL );

  pkt->udp->net_sport = fd_ushort_bswap( src_port );
  pkt->udp->net_dport = (ushort)0;
  pkt->udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  pkt->udp->check     = (ushort)0;

  return pkt;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_net_util_h */
