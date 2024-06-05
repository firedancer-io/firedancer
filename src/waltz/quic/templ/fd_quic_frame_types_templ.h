#ifndef HEADER_fd_src_waltz_quic_templ_fd_quic_frame_types_templ_h
#define HEADER_fd_src_waltz_quic_templ_fd_quic_frame_types_templ_h

#include "../fd_quic_enum.h"

/* describes the frame types and their attributes */

/*  Type  Sub   Frame Type Name       Definition        Pkts          Spec */

#define FD_QUIC_FRAME_TYPES(X,...)                                           \
  X(0x00, 0x00, PADDING,              "Section 19.1 ",  I, H, 0, 1,   N, P, __VA_ARGS__) \
  X(0x01, 0x00, PING,                 "Section 19.2 ",  I, H, 0, 1,    ,  , __VA_ARGS__) \
  X(0x02, 0x00, ACK,                  "Section 19.3 ",  I, H, _, 1,   N, C, __VA_ARGS__) \
  X(0x02, 0x01, ACK,                  "Section 19.3 ",  I, H, _, 1,   N, C, __VA_ARGS__) \
  X(0x04, 0x00, RESET_STREAM,         "Section 19.4 ",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x05, 0x00, STOP_SENDING,         "Section 19.5 ",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x06, 0x00, CRYPTO,               "Section 19.6 ",  I, H, _, 1,    ,  , __VA_ARGS__) \
  X(0x07, 0x00, NEW_TOKEN,            "Section 19.7 ",  _, _, _, 1,    ,  , __VA_ARGS__) \
  X(0x08, 0x00, STREAM,               "Section 19.8 ",  _, _, 0, 1,   F,  , __VA_ARGS__) \
  X(0x08, 0x01, STREAM,               "Section 19.8 ",  _, _, 0, 1,   F,  , __VA_ARGS__) \
  X(0x08, 0x02, STREAM,               "Section 19.8 ",  _, _, 0, 1,   F,  , __VA_ARGS__) \
  X(0x08, 0x03, STREAM,               "Section 19.8 ",  _, _, 0, 1,   F,  , __VA_ARGS__) \
  X(0x08, 0x04, STREAM,               "Section 19.8 ",  _, _, 0, 1,   F,  , __VA_ARGS__) \
  X(0x08, 0x05, STREAM,               "Section 19.8 ",  _, _, 0, 1,   F,  , __VA_ARGS__) \
  X(0x08, 0x06, STREAM,               "Section 19.8 ",  _, _, 0, 1,   F,  , __VA_ARGS__) \
  X(0x08, 0x07, STREAM,               "Section 19.8 ",  _, _, 0, 1,   F,  , __VA_ARGS__) \
  X(0x10, 0x00, MAX_DATA,             "Section 19.9 ",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x11, 0x00, MAX_STREAM_DATA,      "Section 19.10",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x12, 0x00, MAX_STREAMS,          "Section 19.11",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x12, 0x01, MAX_STREAMS,          "Section 19.11",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x14, 0x00, DATA_BLOCKED,         "Section 19.12",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x15, 0x00, STREAM_DATA_BLOCKED,  "Section 19.13",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x16, 0x00, STREAMS_BLOCKED,      "Section 19.14",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x16, 0x01, STREAMS_BLOCKED,      "Section 19.14",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x18, 0x00, NEW_CONNECTION_ID,    "Section 19.15",  _, _, 0, 1,   P,  , __VA_ARGS__) \
  X(0x19, 0x00, RETIRE_CONNECTION_ID, "Section 19.16",  _, _, 0, 1,    ,  , __VA_ARGS__) \
  X(0x1a, 0x00, PATH_CHALLENGE,       "Section 19.17",  _, _, 0, 1,   P,  , __VA_ARGS__) \
  X(0x1b, 0x00, PATH_RESPONSE,        "Section 19.18",  _, _, _, 1,   P,  , __VA_ARGS__) \
  X(0x1c, 0x00, CONNECTION_CLOSE,     "Section 19.19",  I, H, 0, 1,   N,  , __VA_ARGS__) \
  X(0x1c, 0x01, CONNECTION_CLOSE,     "Section 19.19",  _, _, 0, 1,   N,  , __VA_ARGS__) \
  X(0x1e, 0x00, HANDSHAKE_DONE,       "Section 19.20",  _, _, _, 1,    ,  , __VA_ARGS__)


/* packets
 * defines the flag for each packet type
 *   _ placeholder
 *   I INITIAL packet
 *   H HANDSHAKE packet
 *   0 ZERO RTT packet
 *   1 ONE RTT packet */
#define PKT_FLAG__ 0u
#define PKT_FLAG_I (1u<<FD_QUIC_PKT_TYPE_INITIAL)
#define PKT_FLAG_H (1u<<FD_QUIC_PKT_TYPE_HANDSHAKE)
#define PKT_FLAG_0 (1u<<FD_QUIC_PKT_TYPE_ZERO_RTT)
#define PKT_FLAG_1 (1u<<FD_QUIC_PKT_TYPE_ONE_RTT)


/* fd_quic_frame_type_allowed
 *
 * Returns an int representing whether the given combination of
 * packet type and frame type is allowed.
 *
 * args
 *  pkt_type    the type of packet:
 *                FD_QUIC_PKT_TYPE_INITIAL
 *                FD_QUIC_PKT_TYPE_HANDSHAKE
 *                FD_QUIC_PKT_TYPE_ZERO_RTT
 *                FD_QUIC_PKT_TYPE_ONE_RTT
 *  frame_type  the type of frame (0x00-0x1e)
 *
 *  returns
 *    1   If the frame type is allowed in the given packet type
 *    0   Otherwise */
FD_FN_PURE static inline
int
fd_quic_frame_type_allowed( uint pkt_type, uint frame_type ) {
  if( FD_UNLIKELY( pkt_type > 3u ) ) FD_LOG_ERR(( "Packet type not valid: %x", pkt_type ));

  /* macro used to initialize the lookup table */
# define INIT(T,S,NAME,_0,F0,F1,F2,F3,...) \
      [T+S] = PKT_FLAG_##F0 + PKT_FLAG_##F1 + PKT_FLAG_##F2 + PKT_FLAG_##F3,

  /* construct table from the frame types */
  /* this results in a handfull of compile time constants */
  uchar tbl[] = {
    FD_QUIC_FRAME_TYPES(INIT,a)
  };

# undef INIT

  if( FD_UNLIKELY( frame_type > sizeof(tbl) / sizeof(tbl[0]) ) ) return 0;

  return !!(tbl[frame_type] & (1u<<pkt_type));
}

#undef PKT_FLAG__
#undef PKT_FLAG_I
#undef PKT_FLAG_H
#undef PKT_FLAG_0
#undef PKT_FLAG_1

#endif
