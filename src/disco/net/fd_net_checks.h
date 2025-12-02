#ifndef HEADER_fd_src_disco_net_fd_net_checks_h
#define HEADER_fd_src_disco_net_fd_net_checks_h

/* fd_net_checks.h is the authoritative definition of 'valid' RX packets from the
   firedancer networking stack. When an app tile receives a packet from the network stack,
   it can assume the frame has passed the following checks:

   1. Ethernet:
      - The ethernet header fits in the packet.
      - Ethernet net_type is IP (FD_ETH_HDR_TYPE_IP)
   2. IP:
      - The header uses IPv4
      - The claimed header size is large enough for a minimal IP header,
        and it fits in the packet.
      - The IP protocol is UDP. The network stack should be GRE-capable, but
        will unwrap the GRE headers before passing to app tiles.
   3. GRE:
      - The GRE header will fit in the packet.
   4. UDP:
      - The udp net_len is large enough for a minimal UDP header,
        and it fits in the packet.
*/
#include "../../util/net/fd_net_headers.h"
#include "fd_net_common.h"

/* FD_NET_SUCCESS, FD_NET_ERR_* error codes are defined in fd_net_common.h */

/* fd_ip4_hdr_check_len performs a series of checks on an IPv4 header. The firedancer
   networking stack guarantees that downstream app-tiles will only receive RX packets
   with an IP header that has passed these checks.

   hdr points to the IP header.
   ip4_sz is the number of bytes from beginning of ip hdr to end of packet.
   proto_allow_mask is a bitmask of allowed IP protocols. Must be one of FD_IP4_HDR_PROTO_MASK_*.
   If used by an app tile, proto_allow_mask must be FD_IP4_HDR_PROTO_MASK_UDP.

   Returns FD_NET_SUCCESS (defined in fd_net_common.h) if valid, or FD_NET_ERR_* on failure. */

FD_FN_PURE static inline int
fd_ip4_hdr_check_len( fd_ip4_hdr_t const * hdr,
                      ulong                ip4_sz,
                      ulong                proto_allow_mask ) {
  ulong ipver = FD_IP4_GET_VERSION( *hdr );
  if( FD_UNLIKELY( ipver!=0x4U ) ) return FD_NET_ERR_INVAL_IP4_HDR;

  ulong iplen = FD_IP4_GET_LEN( *hdr );
  if( FD_UNLIKELY( (iplen<20UL) | (iplen>ip4_sz) ) ) return FD_NET_ERR_INVAL_IP4_HDR;

  uchar const proto = hdr->protocol;
  if( FD_UNLIKELY( !fd_ulong_extract_bit( proto_allow_mask, proto ) ) ) return FD_NET_ERR_DISALLOW_IP_PROTO;

  return FD_NET_SUCCESS;
}

/* fd_gre_hdr_check_len validates that the remaining packet size is sufficient
   for the GRE header.

   hdr points to the GRE header.
   gre_sz is the number of bytes from beginning of GRE header to end of packet.

   Returns FD_NET_SUCCESS if valid, else FD_NET_ERR_INVAL_GRE_HDR. */

FD_FN_PURE static inline int
fd_gre_hdr_check_len( fd_gre_hdr_t const * hdr FD_PARAM_UNUSED,
                      ulong                gre_sz ) {
  if( FD_UNLIKELY( gre_sz<sizeof(fd_gre_hdr_t) ) ) return FD_NET_ERR_INVAL_GRE_HDR;
  return FD_NET_SUCCESS;
}

/* fd_udp_hdr_check_len validates the UDP header's size and its net_len field.

   hdr points to the UDP header.
   udp_sz is the number of bytes from beginning of UDP header to end of packet.

   Returns FD_NET_SUCCESS if valid, or FD_NET_ERR_INVAL_UDP_HDR if either:
   - net_len and/or udp_sz is impossibly small OR
   - net_len is larger than udp_sz */

FD_FN_PURE static inline int
fd_udp_hdr_check_len( fd_udp_hdr_t const * hdr,
                      ulong                udp_sz ) {
  ushort net_len = fd_ushort_bswap( hdr->net_len );
  /* Fail in the following cases:
    1. specified net_len is impossibly small
    2. Specified net_len is larger than the remaining packet size */
  if( FD_UNLIKELY( (net_len<sizeof(fd_udp_hdr_t)) | (net_len>udp_sz) ) )
    return FD_NET_ERR_INVAL_UDP_HDR;

  return FD_NET_SUCCESS;
}


/* fd_eth_ip4_hdrs_check_len validates Ethernet+IPv4 headers.

   eth points to start of Ethernet frame.
   data_sz is the size of the frame in bytes.

   If opt_ip4 is non-NULL, stores pointer to validated IP4 header.
   ip_proto_mask is a bitmask of allowed IP protocols (one of FD_IP4_HDR_PROTO_MASK_*).
   Returns FD_NET_SUCCESS if valid, or FD_NET_ERR_* on failure. */

static inline int
fd_eth_ip4_hdrs_check_len( fd_eth_hdr_t const *  eth,
                           ulong                 data_sz,
                           fd_ip4_hdr_t ** const opt_ip4,
                           ulong                 ip_proto_mask ) {
  /* Check minimum size */
  ulong const min_sz = sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t);
  if( FD_UNLIKELY( data_sz<min_sz ) ) return FD_NET_ERR_INVAL_IP4_HDR;

  /* Validate Ethernet type */
  if( FD_UNLIKELY( eth->net_type!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) )
    return FD_NET_ERR_DISALLOW_ETH_TYPE;

  /* Validate IP4 header */
  fd_ip4_hdr_t * ip4 = (fd_ip4_hdr_t *)((ulong)eth + sizeof(fd_eth_hdr_t));
  int err = fd_ip4_hdr_check_len( ip4, data_sz - sizeof(fd_eth_hdr_t), ip_proto_mask );
  if( FD_UNLIKELY( err ) ) return err;

  /* Populate output pointer */
  if( opt_ip4 ) *opt_ip4 = ip4;

  return FD_NET_SUCCESS;
}

/* fd_ip4_udp_hdrs_check_len validates Ethernet+IPv4+UDP headers.

  eth points to start of Ethernet frame.
  data_sz is the size of the frame in bytes.

  If opt_ip4 is non-NULL, stores pointer to validated IP4 header.
  If opt_udp is non-NULL, stores pointer to validated UDP header.

  Returns FD_NET_SUCCESS if valid, or FD_NET_ERR_* on failure. */

static inline int
fd_ip4_udp_hdrs_check_len( fd_eth_hdr_t const *  eth,
                           ulong                 data_sz,
                           fd_ip4_hdr_t ** const opt_ip4,
                           fd_udp_hdr_t ** const opt_udp ) {
  fd_ip4_hdr_t * ip4;

  int err = fd_eth_ip4_hdrs_check_len( eth, data_sz, &ip4, FD_IP4_HDR_PROTO_MASK_UDP );
  if( FD_UNLIKELY( err ) ) return err;

  /* Validate UDP header */
  ulong iplen = FD_IP4_GET_LEN( *ip4 );
  fd_udp_hdr_t * udp = (fd_udp_hdr_t *)((uchar *)ip4 + iplen);
  err = fd_udp_hdr_check_len( udp, data_sz - sizeof(fd_eth_hdr_t) - iplen );
  if( FD_UNLIKELY( err ) ) return err;

  /* Populate output pointers */
  if( opt_ip4 ) *opt_ip4 = ip4;
  if( opt_udp ) *opt_udp = udp;

  return FD_NET_SUCCESS;
}

/* fd_ip4_udp_hdr_strip deconstructs a network packet, assuming it is
   Ethernet+IPv4+UDP.  If any opt_* are set to NULL, then they are not
   populated. It copies pointers to Ethernet, IPv4 (no options), and
   UDP headers into opt_eth, opt_ip4, and opt_udp respectively. It copies
   a pointer to the start of the packet payload into opt_payload, and the
   packet payload size into opt_payload_sz.

   A few basic integrity checks are preformed on included size fields.
   Returns 1 on success and 0 on failure */

static inline int
fd_ip4_udp_hdr_strip( uchar const *         data,
                      ulong                 data_sz,
                      uchar ** const        opt_payload,
                      ulong *               opt_payload_sz,
                      fd_eth_hdr_t ** const opt_eth,
                      fd_ip4_hdr_t ** const opt_ip4,
                      fd_udp_hdr_t ** const opt_udp ) {

  /* Validate headers */

  fd_eth_hdr_t const * eth = (fd_eth_hdr_t const *)data;
  fd_ip4_hdr_t       * ip4;
  fd_udp_hdr_t       * udp;
  int err = fd_ip4_udp_hdrs_check_len( eth, data_sz, &ip4, &udp );
  if( FD_UNLIKELY( err ) ) return 0;

  /* Extract payload */

  ulong udp_sz = fd_ushort_bswap( udp->net_len );
  ulong payload_sz_ = udp_sz - sizeof(fd_udp_hdr_t);
  uchar * payload_  = (uchar *)udp + sizeof(fd_udp_hdr_t);

  /* Populate output pointers */

  fd_ulong_store_if( !!opt_eth,        (ulong*)opt_eth,     (ulong)data     );
  fd_ulong_store_if( !!opt_ip4,        (ulong*)opt_ip4,     (ulong)ip4      );
  fd_ulong_store_if( !!opt_udp,        (ulong*)opt_udp,     (ulong)udp      );
  fd_ulong_store_if( !!opt_payload,    (ulong*)opt_payload, (ulong)payload_ );
  fd_ulong_store_if( !!opt_payload_sz, opt_payload_sz,      payload_sz_     );

  return 1;
}

#endif /* HEADER_fd_src_disco_net_fd_net_checks_h */
