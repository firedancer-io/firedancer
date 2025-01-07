#ifndef HEADER_fd_src_waltz_quic_templ_fd_quic_frame_h
#define HEADER_fd_src_waltz_quic_templ_fd_quic_frame_h

#include "../../../util/fd_util_base.h"
#include "../fd_quic_enum.h"

/* FD_QUIC_FRAME_TYPES describes QUIC frame types and their attributes.
   Indexed by frame ID.  Some frame IDs have the same handler.

   Columns:
   - ID:   frame type as seen on the wire
   - MID:  frame ID used in fd_quic metrics (FIXME use ID instead when fd_metrics supports sparse enums)
   - Flags:
     - '_': Placeholder
     - 'I': Allowed in Initial packet
     - 'H': Allowed in Handshake packet
     - '0': Allowed in 0-RTT packet
     - '1': Allowed in 1-RTT packet
     - 'N': Not ACK eliciting (absence implies the contrary) */

#define FD_QUIC_FRAME_TYPES(X)                                          \
/*  ID    MID Name                 Flags */                             \
  X(0x00, 21, padding,             I, H, 0, 1, N)  /* Section 19.1  */  \
  X(0x01, 20, ping,                I, H, 0, 1, _)  /* Section 19.2  */  \
  X(0x02,  1, ack,                 I, H, _, 1, N)  /* Section 19.3  */  \
  X(0x03,  1, ack,                 I, H, _, 1, N)  /* Section 19.3  */  \
  X(0x04,  2, reset_stream,        _, _, 0, 1, _)  /* Section 19.4  */  \
  X(0x05,  3, stop_sending,        _, _, 0, 1, _)  /* Section 19.5  */  \
  X(0x06,  4, crypto,              I, H, _, 1, _)  /* Section 19.6  */  \
  X(0x07,  5, new_token,           _, _, _, 1, _)  /* Section 19.7  */  \
  X(0x08,  6, stream_8,            _, _, 0, 1, _)  /* Section 19.8  */  \
  X(0x09,  6, stream_8,            _, _, 0, 1, _)  /* Section 19.8  */  \
  X(0x0a,  6, stream_a,            _, _, 0, 1, _)  /* Section 19.8  */  \
  X(0x0b,  6, stream_a,            _, _, 0, 1, _)  /* Section 19.8  */  \
  X(0x0c,  6, stream_c,            _, _, 0, 1, _)  /* Section 19.8  */  \
  X(0x0d,  6, stream_c,            _, _, 0, 1, _)  /* Section 19.8  */  \
  X(0x0e,  6, stream_e,            _, _, 0, 1, _)  /* Section 19.8  */  \
  X(0x0f,  6, stream_e,            _, _, 0, 1, _)  /* Section 19.8  */  \
  X(0x10,  7, max_data,            _, _, 0, 1, _)  /* Section 19.9  */  \
  X(0x11,  8, max_stream_data,     _, _, 0, 1, _)  /* Section 19.10 */  \
  X(0x12,  9, max_streams,         _, _, 0, 1, _)  /* Section 19.11 */  \
  X(0x13,  9, max_streams,         _, _, 0, 1, _)  /* Section 19.11 */  \
  X(0x14, 10, data_blocked,        _, _, 0, 1, _)  /* Section 19.12 */  \
  X(0x15, 11, stream_data_blocked, _, _, 0, 1, _)  /* Section 19.13 */  \
  X(0x16, 12, streams_blocked,     _, _, 0, 1, _)  /* Section 19.14 */  \
  X(0x17, 12, streams_blocked,     _, _, 0, 1, _)  /* Section 19.14 */  \
  X(0x18, 13, new_conn_id,         _, _, 0, 1, _)  /* Section 19.15 */  \
  X(0x19, 14, retire_conn_id,      _, _, 0, 1, _)  /* Section 19.16 */  \
  X(0x1a, 15, path_challenge,      _, _, 0, 1, _)  /* Section 19.17 */  \
  X(0x1b, 16, path_response,       _, _, _, 1, _)  /* Section 19.18 */  \
  X(0x1c, 17, conn_close_0,        I, H, 0, 1, N)  /* Section 19.19 */  \
  X(0x1d, 18, conn_close_1,        _, _, 0, 1, N)  /* Section 19.19 */  \
  X(0x1e, 19, handshake_done,      _, _, _, 1, _)  /* Section 19.20 */

#define FD_QUIC_FRAME_TYPE_CNT (0x1f) /* lookup tables should have this many entries */

extern uchar const __attribute__((aligned(0x20)))
fd_quic_frame_type_flags[ FD_QUIC_FRAME_TYPE_CNT ];

#define FD_QUIC_FRAME_FLAG__ 0u
#define FD_QUIC_FRAME_FLAG_I (1u<<FD_QUIC_PKT_TYPE_INITIAL)    /* allowed in INITIAL */
#define FD_QUIC_FRAME_FLAG_H (1u<<FD_QUIC_PKT_TYPE_HANDSHAKE)  /* allowed in HANDSHAKE */
#define FD_QUIC_FRAME_FLAG_0 (1u<<FD_QUIC_PKT_TYPE_ZERO_RTT)   /* allowed in 0-RTT */
#define FD_QUIC_FRAME_FLAG_1 (1u<<FD_QUIC_PKT_TYPE_ONE_RTT)    /* allowed in 1-RTT */
#define FD_QUIC_FRAME_FLAG_N (1u<<5)                           /* not ack eliciting */

FD_PROTOTYPES_BEGIN

/* fd_quic_frame_type_allowed checks whether a frame type is allowed for
   a given packet type.  pkt_type is one of FD_QUIC_PKT_TYPE_{INITIAL,
   HANDSHAKE,ZERO_RTT,ONE_RTT}.  Returns 1 if the frame type is allowed,
   0 otherwise. */

FD_FN_PURE static inline int
fd_quic_frame_type_allowed( uint pkt_type,
                            uint frame_type ) {
  if( FD_UNLIKELY( pkt_type>4 ) ) return 0;
  if( FD_UNLIKELY( frame_type>=FD_QUIC_FRAME_TYPE_CNT ) ) return 0;
  return !!( fd_quic_frame_type_flags[frame_type] & (1u<<pkt_type) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_templ_fd_quic_frame_h */
