#ifndef HEADER_fd_src_util_net_headers_h
#define HEADER_fd_src_util_net_headers_h

#include "fd_udp.h"
#include "fd_eth.h"

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

union fd_ip4_port {
  struct {
    uint   addr;  /* net order */
    ushort port;  /* net order */
  };
  ulong l;
};

typedef union fd_ip4_port fd_ip4_port_t;

/* fd_ip4_udp_hdr_strip deconstructs a network packet.  If any opt_* are
   set to NULL, then they are not populated. It copies pointers to
   Ethernet, IPv4 (no options), and UDP headers into opt_eth, opt_ip4,
   and opt_udp respectively. It copies a pointer to the start of the
   packet payload into opt_payload, and the packet payload size into
   opt_payload_sz.

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
  fd_eth_hdr_t const * eth = (fd_eth_hdr_t const *)data;
  fd_ip4_hdr_t const * ip4 = (fd_ip4_hdr_t const *)( (ulong)eth + sizeof(fd_eth_hdr_t) );
  fd_udp_hdr_t const * udp = (fd_udp_hdr_t const *)( (ulong)ip4 + FD_IP4_GET_LEN( *ip4 ) );

  /* data_sz is less than the observed combined header size */
  if( FD_UNLIKELY( (ulong)udp+sizeof(fd_udp_hdr_t) > (ulong)eth+data_sz ) ) return 0;
  ulong udp_sz = fd_ushort_bswap( udp->net_len );

  /* observed udp_hdr+payload sz is smaller than minimum udp header sz */
  if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) ) ) return 0;
  ulong payload_sz_ = udp_sz-sizeof(fd_udp_hdr_t);
  uchar * payload_     = (uchar *)( (ulong)udp + sizeof(fd_udp_hdr_t) );

  /* payload_sz is greater than the total packet size */
  if( FD_UNLIKELY( payload_+payload_sz_>data+data_sz ) ) return 0;

  fd_ulong_store_if( !!opt_eth,        (ulong*)opt_eth,     (ulong)eth      );
  fd_ulong_store_if( !!opt_ip4,        (ulong*)opt_ip4,     (ulong)ip4      );
  fd_ulong_store_if( !!opt_udp,        (ulong*)opt_udp,     (ulong)udp      );
  fd_ulong_store_if( !!opt_payload,    (ulong*)opt_payload, (ulong)payload_ );
  fd_ulong_store_if( !!opt_payload_sz, opt_payload_sz,      payload_sz_     );

  return 1;
}

#endif /* HEADER_fd_src_util_net_headers_h */
