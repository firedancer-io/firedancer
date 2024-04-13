#ifndef HEADER_fd_src_waltz_quic_fd_quic_proto_h
#define HEADER_fd_src_waltz_quic_fd_quic_proto_h

#include "fd_quic_proto_structs.h"

#include "fd_quic_common.h"
#include "fd_quic_types.h"

#include "templ/fd_quic_parsers_decl.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_templ_dump_decl.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_max_footprint.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_encoders_decl.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_frame_handler_decl.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

/* Parses an Ethernet header into out.  src, dst are kept in network
   byte order.  ethertype is converted to host byte order.  buf points
   to the first byte of the Ethernet header on the wire.  sz is the
   size of input buffer region at buf. */

static inline ulong
fd_quic_decode_eth( fd_eth_hdr_t * FD_RESTRICT out,
                    uchar const *  FD_RESTRICT buf,
                    ulong                      sz ) {
  if( FD_UNLIKELY( sz < sizeof(fd_eth_hdr_t) ) )
    return FD_QUIC_PARSE_FAIL;
  memcpy( out, buf, sizeof(fd_eth_hdr_t) );
  out->net_type = (ushort)fd_ushort_bswap( (ushort)out->net_type );
  return sizeof(fd_eth_hdr_t);
}

/* Encodes an Ethernet header into buf suitable for transmit over the
   wire.  sz is the number of bytes that buf can hold.  frame is an
   Ethernet header with {src,dst} in network byte order and ethertype
   in host byte order.  Returns the number of bytes written or
   FD_QUIC_PARSE_FAIL if sz is too small. */

static inline ulong
fd_quic_encode_eth( uchar *              buf,
                    ulong                sz,
                    fd_eth_hdr_t const * frame ) {
  if( FD_UNLIKELY( sz < sizeof(fd_eth_hdr_t) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }
  fd_eth_hdr_t netorder = *frame;
  netorder.net_type = (ushort)fd_ushort_bswap( (ushort)netorder.net_type );
  memcpy( buf, &netorder, sizeof(fd_eth_hdr_t) );
  return sizeof(fd_eth_hdr_t);
}

/* Parses an IPv4 header into out with host byte order.  buf points to
   the first byte of the IPv4 header on the wire. */

static inline ulong
fd_quic_decode_ip4( fd_ip4_hdr_t * FD_RESTRICT out,
                    uchar const *  FD_RESTRICT buf,
                    ulong                      sz ) {
  if( FD_UNLIKELY( sz < sizeof( fd_ip4_hdr_t ) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* FIXME unaligned accesses */
  fd_ip4_hdr_t const * peek = (fd_ip4_hdr_t const *)fd_type_pun_const( buf );
  ulong hdr_len = FD_IP4_GET_LEN(*peek);
  ulong version = FD_IP4_GET_VERSION(*peek);
  if( FD_UNLIKELY( (version!=4) | (hdr_len<20UL) | (sz<hdr_len) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  *out = *peek;
  fd_ip4_hdr_bswap( out );
  return hdr_len;
}

/* Encodes a short IPv4 header into buf suitable for transmit over the
   wire.  sz is the number of bytes that buf can hold.  frame is an IPv4
   header in host byte order.  Returns the number of bytes written or
   FD_QUIC_PARSE_FAIL if sz is too small. */

static inline ulong
fd_quic_encode_ip4( uchar *              buf,
                    ulong                sz,
                    fd_ip4_hdr_t const * frame ) {
  if( FD_UNLIKELY( sz < sizeof(fd_ip4_hdr_t) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }
  fd_ip4_hdr_t netorder = *frame;
  fd_ip4_hdr_bswap( &netorder );
  memcpy( buf, &netorder, sizeof(fd_ip4_hdr_t) );
  return sizeof(fd_ip4_hdr_t);
}

/* Parses a UDP header into out with host byte order.  buf points to the
   first byte of the UDP header on the wire. */

static inline ulong
fd_quic_decode_udp( fd_udp_hdr_t * FD_RESTRICT out,
                    uchar const *  FD_RESTRICT buf,
                    ulong                      sz ) {
  if( FD_UNLIKELY( sz < sizeof(fd_udp_hdr_t) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }
  memcpy( out, buf, sizeof(fd_udp_hdr_t) );
  fd_udp_hdr_bswap( out );
  return sizeof(fd_udp_hdr_t);
}

/* Encodes a UDP header into buf suitable for transmit over the wire.
   sz is the number of bytes that buf can hold.  frame is a UDP header
   in host byte order.  Returns the number of bytes written or
   FD_QUIC_PARSE_FAIL if sz is too small.*/

static inline ulong
fd_quic_encode_udp( uchar *              buf,
                    ulong                sz,
                    fd_udp_hdr_t const * frame ) {
  if( FD_UNLIKELY( sz < sizeof(fd_udp_hdr_t) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }
  fd_udp_hdr_t netorder = *frame;
  fd_udp_hdr_bswap( &netorder );
  memcpy( buf, &netorder, sizeof(fd_udp_hdr_t) );
  return sizeof(fd_udp_hdr_t);
}

#endif /* HEADER_fd_src_waltz_quic_fd_quic_proto_h */

