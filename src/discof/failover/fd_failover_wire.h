#ifndef HEADER_fd_src_discof_failover_fd_failover_wire_h
#define HEADER_fd_src_discof_failover_fd_failover_wire_h

/* Authenticated framing for failover messages */

#include "fd_failover_proto.h"

/* Frame layout bounds */
#define FD_FAILOVER_FRAME_HDR_SZ (16UL)
#define FD_FAILOVER_MAC_SZ       (32UL)
#define FD_FAILOVER_PAYLOAD_MAX  (65536UL)
#define FD_FAILOVER_FRAME_MAX    (FD_FAILOVER_FRAME_HDR_SZ+FD_FAILOVER_PAYLOAD_MAX+FD_FAILOVER_MAC_SZ)

/* Decode results. AGAIN means the caller has not yet buffered the whole frame. Every other session error is fatal. */
#define FD_FAILOVER_WIRE_SUCCESS     (0)
#define FD_FAILOVER_WIRE_ERR_AGAIN   (-1)
#define FD_FAILOVER_WIRE_ERR_VERSION (-2)
#define FD_FAILOVER_WIRE_ERR_SZ      (-3)
#define FD_FAILOVER_WIRE_ERR_TYPE    (-4)
#define FD_FAILOVER_WIRE_ERR_MAC     (-5)
#define FD_FAILOVER_WIRE_ERR_SEQ     (-6)

struct __attribute__((packed)) fd_failover_frame_hdr {
  ushort version; /* FD_FAILOVER_VERSION */
  uint   len;     /* total frame length in bytes */
  ushort type;    /* FD_FAILOVER_MSG_* */
  ulong  seq;     /* per direction, starts at zero */
};

typedef struct fd_failover_frame_hdr fd_failover_frame_hdr_t;

FD_STATIC_ASSERT( sizeof(fd_failover_frame_hdr_t)==FD_FAILOVER_FRAME_HDR_SZ, wire_layout );

/* A failover wire session holds the two directional keys and the two sequence number
   counters of the TCP connection. Callers should treat it as an opaque struct
   and need to wipe it when the connection ends. */
struct fd_failover_wire_session {
  uchar tx_key[ 32 ];
  uchar rx_key[ 32 ];
  ulong tx_seq;
  ulong rx_seq;
};

typedef struct fd_failover_wire_session fd_failover_wire_session_t;

FD_PROTOTYPES_BEGIN

/* Prepares session for the HELLO handshake */
void
fd_failover_wire_session_init( fd_failover_wire_session_t * session,
                               uchar const *                pair_secret,
                               ulong                        pair_secret_sz,
                               int                          dial_peer );

/* Derives the two directional keys from the pair secret and HELLO nonces */
void
fd_failover_wire_session_keys( fd_failover_wire_session_t * session,
                               uchar const *                pair_secret,
                               ulong                        pair_secret_sz,
                               uchar const *                self_nonce,
                               uchar const *                peer_nonce );

/* Wipes the session's key */
void
fd_failover_wire_session_wipe( fd_failover_wire_session_t * session );

/* Writes one authenticated frame+payload into out, which must hold at least
   FD_FAILOVER_FRAME_MAX bytes in its buffer */
ulong
fd_failover_wire_encode( fd_failover_wire_session_t * session,
                         uchar *                      out,
                         ushort                       type,
                         uchar const *                payload,
                         ulong                        payload_sz );

/* Decodes the frame at the start of buf and if successful, points
   *out_payload / *out_payload_sz to buf. */
int
fd_failover_wire_decode( fd_failover_wire_session_t * session,
                         uchar const *                buf,
                         ulong                        buf_sz,
                         ushort *                     out_type,
                         uchar const **               out_payload,
                         ulong *                      out_payload_sz,
                         ulong *                      out_frame_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_wire_h */
