#ifndef HEADER_fd_src_waltz_quic_templ_fd_quic_frame_h
#define HEADER_fd_src_waltz_quic_templ_fd_quic_frame_h

#include "../../../util/fd_util_base.h"

/* FD_QUIC_FRAME_TYPES describes the frame types and their attributes.

   Columns:
   - ID:  frame type as seen on the wire
   - MID: frame ID used in fd_quic metrics (FIXME use ID instead when fd_metrics supports sparse enums) */

#define FD_QUIC_FRAME_TYPES(X)                                                    \
/*  ID    MID Handler              Definition        Pkts          Spec */ \
  X(0x00, 21, padding,             "Section 19.1 ",  I, H, 0, 1,   N, P)   \
  X(0x01, 20, ping,                "Section 19.2 ",  I, H, 0, 1,    ,  )   \
  X(0x02,  1, ack,                 "Section 19.3 ",  I, H, _, 1,   N, C)   \
  X(0x03,  1, ack,                 "Section 19.3 ",  I, H, _, 1,   N, C)   \
  X(0x04,  2, reset_stream,        "Section 19.4 ",  _, _, 0, 1,    ,  )   \
  X(0x05,  3, stop_sending,        "Section 19.5 ",  _, _, 0, 1,    ,  )   \
  X(0x06,  4, crypto,              "Section 19.6 ",  I, H, _, 1,    ,  )   \
  X(0x07,  5, new_token,           "Section 19.7 ",  _, _, _, 1,    ,  )   \
  X(0x08,  6, stream,              "Section 19.8 ",  _, _, 0, 1,   F,  )   \
  X(0x09,  6, stream,              "Section 19.8 ",  _, _, 0, 1,   F,  )   \
  X(0x0a,  6, stream,              "Section 19.8 ",  _, _, 0, 1,   F,  )   \
  X(0x0b,  6, stream,              "Section 19.8 ",  _, _, 0, 1,   F,  )   \
  X(0x0c,  6, stream,              "Section 19.8 ",  _, _, 0, 1,   F,  )   \
  X(0x0d,  6, stream,              "Section 19.8 ",  _, _, 0, 1,   F,  )   \
  X(0x0e,  6, stream,              "Section 19.8 ",  _, _, 0, 1,   F,  )   \
  X(0x0f,  6, stream,              "Section 19.8 ",  _, _, 0, 1,   F,  )   \
  X(0x10,  7, max_data,            "Section 19.9 ",  _, _, 0, 1,    ,  )   \
  X(0x11,  8, max_stream_data,     "Section 19.10",  _, _, 0, 1,    ,  )   \
  X(0x12,  9, max_streams,         "Section 19.11",  _, _, 0, 1,    ,  )   \
  X(0x13,  9, max_streams,         "Section 19.11",  _, _, 0, 1,    ,  )   \
  X(0x14, 10, data_blocked,        "Section 19.12",  _, _, 0, 1,    ,  )   \
  X(0x15, 11, stream_data_blocked, "Section 19.13",  _, _, 0, 1,    ,  )   \
  X(0x16, 12, streams_blocked,     "Section 19.14",  _, _, 0, 1,    ,  )   \
  X(0x17, 12, streams_blocked,     "Section 19.14",  _, _, 0, 1,    ,  )   \
  X(0x18, 13, new_conn_id,         "Section 19.15",  _, _, 0, 1,   P,  )   \
  X(0x19, 14, retire_conn_id,      "Section 19.16",  _, _, 0, 1,    ,  )   \
  X(0x1a, 15, path_challenge,      "Section 19.17",  _, _, 0, 1,   P,  )   \
  X(0x1b, 16, path_response,       "Section 19.18",  _, _, _, 1,   P,  )   \
  X(0x1c, 17, conn_close_0,        "Section 19.19",  I, H, 0, 1,   N,  )   \
  X(0x1d, 18, conn_close_1,        "Section 19.19",  _, _, 0, 1,   N,  )   \
  X(0x1e, 19, handshake_done,      "Section 19.20",  _, _, _, 1,    ,  )

#define FD_QUIC_FRAME_TYPE_CNT (0x1f) /* lookup tables should have this many entries */

extern uchar const __attribute__((aligned(0x20)))
fd_quic_frame_type_flags[ FD_QUIC_FRAME_TYPE_CNT ];

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
