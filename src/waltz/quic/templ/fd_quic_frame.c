#ifdef HEADER_fd_src_waltz_quic_templ_fd_quic_frame_types_templ_h
#error "fd_quic_frame_types_templ.c included twice"
#endif
#define HEADER_fd_src_waltz_quic_templ_fd_quic_frame_types_templ_h

#include "fd_quic_frame.h"

/* Lookup table for allowed frame types *******************************/

uchar const __attribute__((aligned(0x20)))
fd_quic_frame_type_flags[ FD_QUIC_FRAME_TYPE_CNT ] = {

  #define F(T,MID,NAME,F0,F1,F2,F3,F4) \
      [T] = FD_QUIC_FRAME_FLAG_##F0 + \
            FD_QUIC_FRAME_FLAG_##F1 + \
            FD_QUIC_FRAME_FLAG_##F2 + \
            FD_QUIC_FRAME_FLAG_##F3 + \
            FD_QUIC_FRAME_FLAG_##F4,
    FD_QUIC_FRAME_TYPES(F)
  #undef F

};


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
      fd_quic_frame_ctx_t * const ctx,                                    \
      uchar const *         const buf,                                    \
      ulong                 const buf_sz                                  \
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
    rc = fd_quic_handle_##NAME( ctx, frame, p0, (ulong)(p1-p0) );         \
    if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;\
    p0 += rc;                                                             \
                                                                          \
    return (ulong)(p0-buf);                                               \
  }
#include "fd_quic_dft.h"
#include "fd_quic_frames_templ.h"
#include "fd_quic_undefs.h"
