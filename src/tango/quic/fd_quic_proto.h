#ifndef HEADER_fd_src_tango_quic_fd_quic_proto_h
#define HEADER_fd_src_tango_quic_fd_quic_proto_h

#include "fd_quic_common.h"
#include "fd_quic_types.h"

#include "templ/fd_quic_defs.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_parsers_decl.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_templ_dump_decl.h"
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

static inline ulong
fd_quic_decode_eth( fd_eth_hdr_t * FD_RESTRICT out,
                    uchar const *  FD_RESTRICT buf,
                    ulong                      sz ) {
  if( FD_UNLIKELY( sz < sizeof(fd_eth_hdr_t) ) )
    return FD_QUIC_PARSE_FAIL;
  memcpy( out, buf, sizeof(fd_eth_hdr_t) );
  return sizeof(fd_eth_hdr_t);
}

static inline ulong
fd_quic_encode_eth( uchar *              buf,
                    ulong                sz,
                    fd_eth_hdr_t const * frame ) {
  if( FD_UNLIKELY( sz < sizeof(fd_eth_hdr_t) ) )
    return FD_QUIC_PARSE_FAIL;
  memcpy( buf, frame, sizeof(fd_eth_hdr_t) );
  return sizeof(fd_eth_hdr_t);
}

static inline ulong
fd_quic_decode_ip4( fd_ip4_hdr_t * FD_RESTRICT out,
                    uchar const *  FD_RESTRICT buf,
                    ulong                      sz ) {
  if( FD_UNLIKELY( sz < sizeof( fd_ip4_hdr_t ) ) )
    return FD_QUIC_PARSE_FAIL;
  fd_ip4_hdr_t const * peek = (fd_ip4_hdr_t const *)fd_type_pun_const( buf );
  ulong hdr_len = peek->ihl * 4UL;
  if( FD_UNLIKELY( (hdr_len<20UL) | (sz<hdr_len) ) )
    return FD_QUIC_PARSE_FAIL;
  fd_memcpy( out, buf, hdr_len );
  return hdr_len;
}

static inline ulong
fd_quic_encode_ip4( uchar *              buf,
                    ulong                sz,
                    fd_ip4_hdr_t const * frame ) {
  if( FD_UNLIKELY( sz < sizeof(fd_ip4_hdr_t) ) )
    return FD_QUIC_PARSE_FAIL;
  memcpy( buf, frame, sizeof(fd_ip4_hdr_t) );
  return sizeof(fd_ip4_hdr_t);
}

static inline ulong
fd_quic_decode_udp( fd_udp_hdr_t * FD_RESTRICT out,
                    uchar const *  FD_RESTRICT buf,
                    ulong                      sz ) {
  if( FD_UNLIKELY( sz < sizeof(fd_udp_hdr_t) ) )
    return FD_QUIC_PARSE_FAIL;
  memcpy( out, buf, sizeof(fd_udp_hdr_t) );
  return sizeof(fd_udp_hdr_t);
}

static inline ulong
fd_quic_encode_udp( uchar *              buf,
                    ulong                sz,
                    fd_udp_hdr_t const * frame ) {
  if( FD_UNLIKELY( sz < sizeof(fd_udp_hdr_t) ) )
    return FD_QUIC_PARSE_FAIL;
  memcpy( buf, frame, sizeof(fd_udp_hdr_t) );
  return sizeof(fd_udp_hdr_t);
}

#endif /* HEADER_fd_src_tango_quic_fd_quic_proto_h */

