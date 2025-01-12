/* This file instantiates all the structures and functions
   of the QUIC protocol */

/* there are cases where we make tests in generic macros
   that fail for certain types
   TODO replace with code that passes these checks */
#pragma GCC diagnostic ignored "-Wtype-limits"

#include "fd_quic_types.h"
#include "fd_quic_common.h"

#include "fd_quic_proto.h"

#include "templ/fd_quic_parse_util.h"

#include "templ/fd_quic_parsers.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_encoders.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_encoders_footprint.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_templ_dump.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_transport_params.h"

/* fd_quic_encode_stream_frame is an optimized encoder for stream headers. */

FD_FN_UNUSED static ulong
fd_quic_encode_stream_frame( uchar * const buf,
                             uchar * const buf_end,
                             ulong   const stream_id,
                             ulong   const offset,
                             ulong   const data_sz,
                             _Bool   const fin ) {
  uchar * cur = buf;

  /* stream_hdr_max is the max size of a stream header:
      1 byte type
      8 bytes stream ID
      8 bytes offset
      8 bytes length */
  ulong const stream_hdr_max = 1+8+8+8;

  /* No space to write frame?
     (Buffer should fit max stream header size and at least 1 byte of data) */
  if( buf+stream_hdr_max+1 > buf_end ) return FD_QUIC_ENCODE_FAIL;

  /* Leave placeholder for frame/stream type */
  uchar * const frame_type_p = cur++;
  uint          frame_type   = 0x0a; /* stream frame with length */

  /* Encode stream ID */
  cur += fd_quic_varint_encode( cur, stream_id );

  /* Optionally encode offset */
  if( offset>0 ) {
    frame_type |= 0x04; /* with offset field */
    cur += fd_quic_varint_encode( cur, offset );
  }

  /* Encode length */
  ushort data_sz_varint = fd_ushort_bswap( (ushort)( 0x4000u | (uint)data_sz ) );
  FD_STORE( ushort, cur, data_sz_varint );
  cur += 2;

  /* Encode stream type */
  frame_type |= fin;
  *frame_type_p = (uchar)frame_type;
  /* Done encoding stream header */

  return (ulong)(cur-buf);
}
