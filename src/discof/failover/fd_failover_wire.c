#include "fd_failover_wire.h"

#include <string.h>

static ulong const payload_max[ FD_FAILOVER_MSG_CNT ] = {
  sizeof(fd_failover_hello_t),
  sizeof(fd_failover_handoff_request_t),
  FD_FAILOVER_DEMOTED_PAYLOAD_MAX,
  sizeof(fd_failover_promote_ack_t),
  sizeof(fd_failover_promote_rejected_t),
  sizeof(fd_failover_handoff_result_t),
  0UL /* KEEPALIVE */
};

ulong
fd_failover_wire_encode( uchar *       out,
                         ushort        type,
                         uchar const * payload,
                         ulong         payload_sz ) {
  if( FD_UNLIKELY( type>=FD_FAILOVER_MSG_CNT ||
                   payload_sz>payload_max[type] ) ) return 0UL;

  ulong frame_sz = FD_FAILOVER_FRAME_HDR_SZ+payload_sz;

  fd_failover_frame_hdr_t hdr = {
    .version = (ushort)FD_FAILOVER_VERSION,
    .len     = (uint)frame_sz,
    .type    = type,
  };
  fd_memcpy( out, &hdr, FD_FAILOVER_FRAME_HDR_SZ );
  if( FD_LIKELY( payload_sz ) ) fd_memcpy( out+FD_FAILOVER_FRAME_HDR_SZ, payload, payload_sz );

  return frame_sz;
}

int
fd_failover_wire_decode( uchar const *  buf,
                         ulong          buf_sz,
                         ushort *       out_type,
                         uchar const ** out_payload,
                         ulong *        out_payload_sz,
                         ulong *        out_frame_sz ) {
  if( FD_UNLIKELY( buf_sz<FD_FAILOVER_FRAME_HDR_SZ ) ) return FD_FAILOVER_WIRE_ERR_AGAIN;

  fd_failover_frame_hdr_t hdr;
  fd_memcpy( &hdr, buf, FD_FAILOVER_FRAME_HDR_SZ );

  ulong frame_sz = (ulong)hdr.len;
  if( FD_UNLIKELY( frame_sz<FD_FAILOVER_FRAME_HDR_SZ ) ) return FD_FAILOVER_WIRE_ERR_SZ;
  if( FD_UNLIKELY( frame_sz>FD_FAILOVER_FRAME_MAX ) )    return FD_FAILOVER_WIRE_ERR_SZ;

  ulong payload_sz = frame_sz-FD_FAILOVER_FRAME_HDR_SZ;

  if( FD_UNLIKELY( hdr.version!=(ushort)FD_FAILOVER_VERSION ) ) return FD_FAILOVER_WIRE_ERR_VERSION;
  if( FD_UNLIKELY( hdr.type>=FD_FAILOVER_MSG_CNT ) ) return FD_FAILOVER_WIRE_ERR_TYPE;

  if( FD_UNLIKELY( payload_sz>payload_max[hdr.type] ) ) return FD_FAILOVER_WIRE_ERR_SZ;
  if( FD_UNLIKELY( buf_sz<frame_sz ) ) return FD_FAILOVER_WIRE_ERR_AGAIN;

  *out_type       = hdr.type;
  *out_payload    = buf+FD_FAILOVER_FRAME_HDR_SZ;
  *out_payload_sz = payload_sz;
  *out_frame_sz   = frame_sz;
  return FD_FAILOVER_WIRE_SUCCESS;
}
