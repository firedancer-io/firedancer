#ifdef HEADER_fd_src_waltz_quic_templ_fd_quic_frame_types_templ_h
#error "fd_quic_frame_types_templ.c included twice"
#endif
#define HEADER_fd_src_waltz_quic_templ_fd_quic_frame_types_templ_h

#include "../fd_quic_enum.h"
#include "../../../util/fd_util.h"

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


/* Lookup table for allowed frame types *******************************/

#define PKT_FLAG__ 0u
#define PKT_FLAG_I (1u<<FD_QUIC_PKT_TYPE_INITIAL)    /* allowed in INITIAL */
#define PKT_FLAG_H (1u<<FD_QUIC_PKT_TYPE_HANDSHAKE)  /* allowed in HANDSHAKE */
#define PKT_FLAG_0 (1u<<FD_QUIC_PKT_TYPE_ZERO_RTT)   /* allowed in 0-RTT */
#define PKT_FLAG_1 (1u<<FD_QUIC_PKT_TYPE_ONE_RTT)    /* allowed in 1-RTT */

static uchar const __attribute__((aligned(0x20)))
fd_quic_frame_type_flags[ FD_QUIC_FRAME_TYPE_CNT ] = {

  #define F(T,MID,NAME,_0,F0,F1,F2,F3,...) \
      [T] = PKT_FLAG_##F0 + PKT_FLAG_##F1 + PKT_FLAG_##F2 + PKT_FLAG_##F3,
    FD_QUIC_FRAME_TYPES(F)
  #undef F

};

#undef PKT_FLAG__
#undef PKT_FLAG_I
#undef PKT_FLAG_H
#undef PKT_FLAG_0
#undef PKT_FLAG_1

/* fd_quic_frame_type_allowed checks whether a frame type is allowed for
   a given packet type.  pkt_type is one of FD_QUIC_PKT_TYPE_{INITIAL,
   HANDSHAKE,ZERO_RTT,ONE_RTT}.  Returns 1 if the frame type is allowed,
   0 otherwise. */

FD_FN_PURE static inline int
fd_quic_frame_type_allowed( uint pkt_type,
                            uint frame_type ) {
  if( FD_UNLIKELY( pkt_type > FD_QUIC_PKT_TYPE_ONE_RTT ) ) return 0;
  if( FD_UNLIKELY( frame_type >= FD_QUIC_FRAME_TYPE_CNT ) ) return 0;
  return !!( fd_quic_frame_type_flags[frame_type] & (1u<<pkt_type) );
}


/* Lookup table for frame metric IDs **********************************/

static uchar const __attribute__((aligned(0x20)))
fd_quic_frame_metric_id[ FD_QUIC_FRAME_TYPE_CNT ] = {
  # define F(T,MID,...) [T] = (MID),
    FD_QUIC_FRAME_TYPES(F)
  # undef F
};


/* Frame handlers *****************************************************/

/* Generate frame interpreter (decode + handle) */

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                   \
  static ulong fd_quic_interpret_##NAME(                                  \
      void *        const ctx,                                            \
      uchar const * const buf,                                            \
      ulong         const buf_sz                                          \
  ) {                                                                     \
    fd_quic_##NAME##_t frame[1];                                          \
    uchar const *       p0 = buf;                                         \
    uchar const * const p1 = buf+buf_sz;                                  \
    ulong               rc;                                               \
                                                                          \
    rc = fd_quic_decode_##NAME( frame, p0, (ulong)(p1-p0) );              \
    if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;\
    p0 += rc;                                                             \
                                                                          \
    rc = fd_quic_frame_handle_##NAME( ctx, frame, p0, (ulong)(p1-p0) );   \
    if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;\
    p0 += rc;                                                             \
                                                                          \
    return (ulong)(p0-buf);                                               \
  }
#include "fd_quic_dft.h"
#include "fd_quic_frames_templ.h"
#include "fd_quic_undefs.h"
