/* fd_quic_parse_frame.h generates a switch table that parses and then
   immediately handles an incoming encoded frame.  This code is used as
   part of fd_quic_handle_v1_frame. */

/* this is defines the body of the frame parsing logic
   there should be a set up prior to including this, and a tear down after
   user is responsible for ensuring at least 1 byte exists in input (p) */

/* example set up:
   // input start (p) and end (p_end)
     uchar const * p     = buf;
     uchar const * p_end = buf + buf_sz;

     if( p == p_end ) return FD_QUIC_PARSE_FAIL;

     // frame id, and internal vars (id_lo, and id_hi )
     uchar id    = *p;
     uchar id_lo = 255; // allow for fragments to work
     uchar id_hi = 0;
*/

/* decode each frame, call handler
   handlers are named as follows:
     fd_quic_frame_handle_{TYPE}
   they have the following signature:
     ulong
     handler( void * frame_context, fd_quic_{TYPE} * parsed_frame, uchar const * cur_ptr, ulong cur_sz );
   they should handle the frame "parsed_frame", consume cur_ptr as required, and return either:
     the number of extra bytes consumed
     FD_QUIC_PARSE_FAIL
*/


/* first byte of frame is always frame type
     0x00 frame type is padding, and next byte will be a new frame */

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME) \
  do { \
    fd_quic_##NAME##_t * data = &frame_union->NAME;

#define FD_TEMPL_MBR_FRAME_TYPE(NAME,ID_LO,ID_HI) \
    id_lo = ID_LO;                                \
    id_hi = ID_HI;

#define FD_TEMPL_MBR_FRAME_TYPE_FLAG(NAME,MASK)                                     \
    data->NAME = id & (MASK);

#define FD_TEMPL_DEF_STRUCT_END(NAME)                                               \
    if( id >= id_lo && id <= id_hi ) {                                              \
      ulong rc = fd_quic_decode_##NAME( data, p, (ulong)(p_end-p) );                \
      if( rc == FD_QUIC_PARSE_FAIL ) {                                              \
        return FD_QUIC_PARSE_FAIL;                                                  \
      }                                                                             \
      p += rc;                                                                      \
      rc = fd_quic_frame_handle_##NAME( frame_context, data,                        \
                                        p, (ulong)(p_end-p) );                      \
      if( rc == FD_QUIC_PARSE_FAIL ) {                                              \
        return FD_QUIC_PARSE_FAIL;                                                  \
      }                                                                             \
      p += rc;                                                                      \
      return (ulong)(p - buf);                                                      \
    }                                                                               \
  } while(0);

#include "fd_quic_dft.h"

