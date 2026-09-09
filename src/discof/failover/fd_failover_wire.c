#include "fd_failover_wire.h"

#include "../../ballet/hmac/fd_hmac.h"

#include <string.h>

#define HELLO_DIALER_LABEL   "fd_failover_hello_dialer_v1"
#define HELLO_LISTENER_LABEL "fd_failover_hello_listener_v1"

static int
mac_equal( uchar const * a,
           uchar const * b ) {
  uint diff = 0U;
  for( ulong i=0UL; i<FD_FAILOVER_MAC_SZ; i++ ) diff |= (uint)( a[ i ] ^ b[ i ] );
  return !diff;
}

static void
derive_key( uchar *       key,
            uchar const * pair_secret,
            ulong         pair_secret_sz,
            uchar const * first_nonce,
            uchar const * second_nonce ) {
  uchar data[ 32 ];
  memcpy( data,      first_nonce,  16UL );
  memcpy( data+16UL, second_nonce, 16UL );
  fd_hmac_sha256( data, 32UL, pair_secret, pair_secret_sz, key );
}

void
fd_failover_wire_session_init( fd_failover_wire_session_t * session,
                               uchar const *                pair_secret,
                               ulong                        pair_secret_sz,
                               int                          dial_peer ) {
  char const * tx_label = dial_peer ? HELLO_DIALER_LABEL   : HELLO_LISTENER_LABEL;
  char const * rx_label = dial_peer ? HELLO_LISTENER_LABEL : HELLO_DIALER_LABEL;
  ulong tx_label_sz = dial_peer ? sizeof(HELLO_DIALER_LABEL)-1UL : sizeof(HELLO_LISTENER_LABEL)-1UL;
  ulong rx_label_sz = dial_peer ? sizeof(HELLO_LISTENER_LABEL)-1UL : sizeof(HELLO_DIALER_LABEL)-1UL;
  fd_hmac_sha256( tx_label, tx_label_sz, pair_secret, pair_secret_sz, session->tx_key );
  fd_hmac_sha256( rx_label, rx_label_sz, pair_secret, pair_secret_sz, session->rx_key );
  session->tx_seq = 0UL;
  session->rx_seq = 0UL;
}

void
fd_failover_wire_session_keys( fd_failover_wire_session_t * session,
                               uchar const *                pair_secret,
                               ulong                        pair_secret_sz,
                               uchar const *                self_nonce,
                               uchar const *                peer_nonce ) {
  derive_key( session->tx_key, pair_secret, pair_secret_sz, self_nonce, peer_nonce );
  derive_key( session->rx_key, pair_secret, pair_secret_sz, peer_nonce, self_nonce );
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

  ulong frame_sz = FD_FAILOVER_FRAME_HDR_SZ+payload_sz+FD_FAILOVER_MAC_SZ;

  fd_failover_frame_hdr_t hdr = {
    .version = (ushort)FD_FAILOVER_VERSION,
    .len     = (uint)frame_sz,
    .type    = type,
    .seq     = session->tx_seq,
  };
  memcpy( out, &hdr, FD_FAILOVER_FRAME_HDR_SZ );
  if( FD_LIKELY( payload_sz ) ) memcpy( out+FD_FAILOVER_FRAME_HDR_SZ, payload, payload_sz );
  fd_hmac_sha256( out, FD_FAILOVER_FRAME_HDR_SZ+payload_sz, session->tx_key, 32UL,
                  out+FD_FAILOVER_FRAME_HDR_SZ+payload_sz );

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
  memcpy( &hdr, buf, FD_FAILOVER_FRAME_HDR_SZ );

  ulong frame_sz = (ulong)hdr.len;
  if( FD_UNLIKELY( frame_sz<FD_FAILOVER_FRAME_HDR_SZ+FD_FAILOVER_MAC_SZ ) ) return FD_FAILOVER_WIRE_ERR_SZ;
  if( FD_UNLIKELY( frame_sz>FD_FAILOVER_FRAME_MAX ) )                       return FD_FAILOVER_WIRE_ERR_SZ;
  if( FD_UNLIKELY( buf_sz<frame_sz ) )                                      return FD_FAILOVER_WIRE_ERR_AGAIN;

  ulong payload_sz = frame_sz-FD_FAILOVER_FRAME_HDR_SZ-FD_FAILOVER_MAC_SZ;

  uchar mac[ FD_FAILOVER_MAC_SZ ];
  fd_hmac_sha256( buf, FD_FAILOVER_FRAME_HDR_SZ+payload_sz, session->rx_key, 32UL, mac );
  if( FD_UNLIKELY( !mac_equal( mac, buf+FD_FAILOVER_FRAME_HDR_SZ+payload_sz ) ) ) return FD_FAILOVER_WIRE_ERR_MAC;

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
