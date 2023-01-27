/* This file instantiates all the structures and functions
   of the QUIC protocol */

/* there are cases where we make tests in generic macros
   that fail for certain types
   TODO replace with code that passes these checks */
#pragma GCC diagnostic ignored "-Wtype-limits"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fd_quic_types.h"
#include "fd_quic_common.h"

#include "templ/fd_quic_parse_util.h"

#include "templ/fd_quic_defs.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_ipv4.h"
#include "templ/fd_quic_udp.h"
#include "templ/fd_quic_eth.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_parsers.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_ipv4.h"
#include "templ/fd_quic_udp.h"
#include "templ/fd_quic_eth.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_encoders.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_ipv4.h"
#include "templ/fd_quic_udp.h"
#include "templ/fd_quic_eth.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_encoders_footprint.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_ipv4.h"
#include "templ/fd_quic_udp.h"
#include "templ/fd_quic_eth.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_templ_dump.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_ipv4.h"
#include "templ/fd_quic_udp.h"
#include "templ/fd_quic_eth.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_transport_params.h"


// TODO fix these:
typedef void fd_quic_t;
#define FD_UNLIKELY

size_t
fd_quic_handle_initial_pkt( fd_quic_t * quic, uchar const * buf, size_t buf_sz ) {
  // TODO remove these:
  (void)quic;
  (void)buf;
  (void)buf_sz;

  fd_quic_initial_t initial_pkt[1];

  size_t rc = fd_quic_decode_initial( initial_pkt, buf, buf_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

  // look up src and dst connection ids
  //   or look up dst connection id?

  // if dcid is zero length, use source/dest ip:port

  // src must have a preferred ip:port
  //   but we may accept from other ip:port
  //   see: migration

  // shared secrets pertain to a connection as a whole

  // if dcid is not found, either create a new connection
  //   (initial packets) or send stateless reset

  // Packets that are matched to an existing connection are discarded if 
  //   the packets are inconsistent with the state of that connection.
  //   E.g. if the version in the packet does not match the version of the 
  //     connection

  // If a server refuses to accept a new connection, it SHOULD send an
  //   Initial packet containing a CONNECTION_CLOSE frame with error code
  //   CONNECTION_REFUSED.

  return FD_QUIC_PARSE_FAIL;
}

size_t
fd_quic_handle_pkt( fd_quic_t * quic, uchar const * buf, size_t buf_sz ) {
  if( FD_UNLIKELY( buf_sz == 0 ) ) return 0;

  // long or short header
  fd_quic_common_hdr_t common_hdr[1];

  // only decodes first byte
  size_t skip = fd_quic_decode_common_hdr( common_hdr, buf, buf_sz );
  if( skip == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

  // should decode/look up version here
  //   Initial packets may refuse new connection based on version
  //     may send version negotiation
  //       may not send larger packet than received
  //   Packets that indicate different version than expected on the connection
  //     may be discarded
  //   Packets may require different templates, depending on version

  // Versions at time of writing
  //   Value       Status       Specification          Date       Notes 
  //   0x00000000  permanent    [RFC9000]              2021-02-11 Reserved for Version Negotiation
  //   0x00000001  permanent    [RFC9000]              2021-02-11 
  //   0x51303433  provisional  2021-10-15             Google     
  //   0x51303436  provisional  2021-10-15             Google     
  //   0x51303530  provisional  2021-10-15             Google     
  //   0x709a50c4  permanent    [RFC-ietf-quic-v2-07]  2022-11-17 

  // Only supporting versions 0 and 1

  if( common_hdr->hdr_form ) { // long header
    // Note - the value of long_packet_type is mapped differently
    //   in QUICV2
    switch( common_hdr[0].long_packet_type ) {
      case FD_QUIC_PKTTYPE_V1_INITIAL:
        return fd_quic_handle_initial_pkt( quic, buf, buf_sz );
      case FD_QUIC_PKTTYPE_V1_ZERO_RTT:
        printf( "NOT IMPLEMENTED\n" ); break;
      case FD_QUIC_PKTTYPE_V1_HANDSHAKE:
        printf( "NOT IMPLEMENTED\n" ); break;
      case FD_QUIC_PKTTYPE_V1_RETRY:
        printf( "NOT IMPLEMENTED\n" ); break;
      default:
        return FD_QUIC_PARSE_FAIL;
    }
  } else { // short header
  }

  return FD_QUIC_PARSE_FAIL;
}

