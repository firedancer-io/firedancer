#include "fd_failover_wire.h"

#include <string.h>

void
fd_failover_wire_session_init( fd_failover_wire_session_t * session ) {
  session->tx_seq = 0UL;
  session->rx_seq = 0UL;
}

void
fd_failover_wire_session_wipe( fd_failover_wire_session_t * session ) {
  fd_memzero_explicit( session, sizeof(fd_failover_wire_session_t) );
}

ulong
fd_failover_wire_encode( fd_failover_wire_session_t * session,
                         uchar *                      out,
                         ushort                       type,
                         uchar const *                payload,
                         ulong                        payload_sz ) {
  if( FD_UNLIKELY( type>=FD_FAILOVER_MSG_RESERVED ||
                   payload_sz>FD_FAILOVER_PAYLOAD_MAX ||
                   session->tx_seq==ULONG_MAX ) ) return 0UL;

  ulong frame_sz = FD_FAILOVER_FRAME_HDR_SZ+payload_sz;

  fd_failover_frame_hdr_t hdr = {
    .version = (ushort)FD_FAILOVER_VERSION,
    .len     = (uint)frame_sz,
    .type    = type,
    .seq     = session->tx_seq,
  };
  fd_memcpy( out, &hdr, FD_FAILOVER_FRAME_HDR_SZ );
  if( FD_LIKELY( payload_sz ) ) fd_memcpy( out+FD_FAILOVER_FRAME_HDR_SZ, payload, payload_sz );

  session->tx_seq++;
  return frame_sz;
}

int
fd_failover_wire_decode( fd_failover_wire_session_t * session,
                         uchar const *                buf,
                         ulong                        buf_sz,
                         ushort *                     out_type,
                         uchar const **               out_payload,
                         ulong *                      out_payload_sz,
                         ulong *                      out_frame_sz ) {
  if( FD_UNLIKELY( buf_sz<FD_FAILOVER_FRAME_HDR_SZ ) ) return FD_FAILOVER_WIRE_ERR_AGAIN;

  fd_failover_frame_hdr_t hdr;
  fd_memcpy( &hdr, buf, FD_FAILOVER_FRAME_HDR_SZ );

  ulong frame_sz = (ulong)hdr.len;
  if( FD_UNLIKELY( frame_sz<FD_FAILOVER_FRAME_HDR_SZ ) ) return FD_FAILOVER_WIRE_ERR_SZ;
  if( FD_UNLIKELY( frame_sz>FD_FAILOVER_FRAME_MAX ) )    return FD_FAILOVER_WIRE_ERR_SZ;
  if( FD_UNLIKELY( buf_sz<frame_sz ) )                   return FD_FAILOVER_WIRE_ERR_AGAIN;

  ulong payload_sz = frame_sz-FD_FAILOVER_FRAME_HDR_SZ;

  if( FD_UNLIKELY( hdr.version!=(ushort)FD_FAILOVER_VERSION ) ) return FD_FAILOVER_WIRE_ERR_VERSION;
  if( FD_UNLIKELY( session->rx_seq==ULONG_MAX || hdr.seq!=session->rx_seq ) ) return FD_FAILOVER_WIRE_ERR_SEQ;
  if( FD_UNLIKELY( hdr.type>=FD_FAILOVER_MSG_RESERVED ) ) return FD_FAILOVER_WIRE_ERR_TYPE;

  session->rx_seq++;
  *out_type       = hdr.type;
  *out_payload    = buf+FD_FAILOVER_FRAME_HDR_SZ;
  *out_payload_sz = payload_sz;
  *out_frame_sz   = frame_sz;
  return FD_FAILOVER_WIRE_SUCCESS;
}
