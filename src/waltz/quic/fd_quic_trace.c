#pragma GCC diagnostic ignored "-Wtype-limits"

#include "templ/fd_quic_templ_trace.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

/* Generate frame trace */

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                    \
  static ulong fd_quic_trace_frame_##NAME(                                 \
      fd_quic_##NAME##_t * frame,                                          \
      char **              out_buf,                                        \
      ulong *              out_buf_sz,                                     \
      uchar const * const  buf,                                            \
      ulong         const  buf_sz                                          \
  ) {                                                                      \
    uchar const *       p0 = buf;                                          \
    uchar const * const p1 = buf+buf_sz;                                   \
    ulong               rc;                                                \
                                                                           \
    rc = fd_quic_decode_##NAME( frame, p0, (ulong)(p1-p0) );               \
    if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL; \
    p0 += rc;                                                              \
                                                                           \
    fd_quic_trace_struct_##NAME( out_buf, out_buf_sz, frame );             \
                                                                           \
    return (ulong)(p0-buf);                                                \
  }
#include "templ/fd_quic_dft.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_frame.h"


#define safe_snprintf( out, sz, ... ) \
  (__extension__({ \
    int rtn = snprintf( (out), (sz), __VA_ARGS__ ); \
    if( rtn < 0 ) rtn = 0; \
    (ulong)rtn; }))

ulong
fd_quic_trace_v1_frame( char **           out_buf,
                        ulong *           out_buf_sz,
                        uchar const *     buf,
                        ulong             buf_sz ) {
  if( FD_UNLIKELY( buf_sz<1UL ) ) return FD_QUIC_PARSE_FAIL;

  uchar const * cur_buf = buf;
  uchar const * buf_end = buf + buf_sz;

  if( cur_buf[0] == 0x00 ) { /* handle padding separately */
    ulong padding_cnt = 0;
    while( cur_buf < buf_end && *cur_buf == 0x00 ) {
      padding_cnt++;
      cur_buf++;
    }

    ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"frame_type\": \"0-padding\", \"count\": %lu, ", padding_cnt );
    *out_buf    += sz;
    *out_buf_sz -= sz;

    if( FD_UNLIKELY( cur_buf == buf_end ) ) return (ulong)( cur_buf - buf );
  }

  /* Frame ID is technically a varint but it's sufficient to look at the
     first byte. */
  uint id = cur_buf[0];
  if( FD_UNLIKELY( id >= FD_QUIC_FRAME_TYPE_CNT ) ) {
    ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"frame_type\": \"%x-unknown\", ...", (uint)id );
    *out_buf    += sz;
    *out_buf_sz -= sz;

    return FD_QUIC_PARSE_FAIL;
  }

  ulong consumed = 0UL;

  union {
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME) fd_quic_##NAME##_t NAME;
#include "templ/fd_quic_dft.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"
  } data;

  memset( &data, 0, sizeof( data ) );

  /* tail call to frame handler */
  switch( id ) {

# define F(T,MID,NAME,...) \
    case T: { \
      ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"frame_type\": \"%u-" #NAME "\", ", (uint)id ); \
      *out_buf    += sz; \
      *out_buf_sz -= sz; \
      consumed = fd_quic_trace_frame_##NAME##_frame( &data.NAME##_frame, out_buf, out_buf_sz, cur_buf, (ulong)( buf_end - cur_buf ) ); \
      break; \
    }
  FD_QUIC_FRAME_TYPES(F)
# undef F

  default:
    /* we're unable to consume more bytes, since this is invalid */
    /* TODO put error key in json */
    return FD_QUIC_PARSE_FAIL;
  }

  if( consumed == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

  /* handle repeating blocks, etc. */
  cur_buf += consumed;

  switch( id ) {
    case 0x02:
    case 0x03:
    {
      if( data.ack_frame.type & 1U ) {
        fd_quic_ecn_counts_frag_t ecn_counts[1] = {0};
        ulong rc = fd_quic_decode_ecn_counts_frag( ecn_counts, cur_buf, (ulong)( buf_end - cur_buf ) );
        if( rc == FD_QUIC_PARSE_FAIL ) {
          ulong out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"parse-ecn-counts\"" );
          *out_buf    += out_sz;
          *out_buf_sz -= out_sz;
          return FD_QUIC_PARSE_FAIL;
        }

        cur_buf += rc;
      }

      break;
    }

    case 0x06:
    {
      ulong out_sz = 0;
      ulong remain  = (ulong)( buf_end - cur_buf );
      ulong data_sz = data.crypto_frame.length;
      if( data_sz > remain ) {
        out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\"" );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;

        return FD_QUIC_PARSE_FAIL;
      }

      if( data_sz > remain ) {
        out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\"" );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;

        return FD_QUIC_PARSE_FAIL;
      }

      out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"data\": [ " );
      *out_buf    += out_sz;
      *out_buf_sz -= out_sz;

      for( ulong j = 0; j < data_sz; ++j ) {
        out_sz = safe_snprintf( *out_buf, *out_buf_sz, "0x%02x, ", cur_buf[j] );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;
      }

      out_sz = safe_snprintf( *out_buf, *out_buf_sz, "], " );
      *out_buf    += out_sz;
      *out_buf_sz -= out_sz;

      cur_buf  += data_sz;

      break;
    }

    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:
    case 0x0e:
    case 0x0f:
    {
      /* stream */
      /* offset field is optional, implied 0 */
      ulong offset      = fd_ulong_if( data.stream_frame.offset_opt, data.stream_frame.offset, 0UL );
      ulong stream_id   = data.stream_frame.stream_id;
      ulong stream_type = stream_id & 3UL;
      ulong remain      = (ulong)( buf_end - cur_buf );
      ulong data_sz     = fd_ulong_if( data.stream_frame.length_opt, data.stream_frame.length, remain );

      ulong out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"stream_type\": %u, \"offset\": %lu, \"length\": %lu, ", (uint)stream_type, offset, data_sz );
      *out_buf    += out_sz;
      *out_buf_sz -= out_sz;

      if( data_sz > remain ) {
        out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\"" );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;

        return FD_QUIC_PARSE_FAIL;
      }

      out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"data\": [ " );
      *out_buf    += out_sz;
      *out_buf_sz -= out_sz;

      for( ulong j = 0; j < data_sz; ++j ) {
        out_sz = safe_snprintf( *out_buf, *out_buf_sz, "0x%02x, ", cur_buf[j] );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;
      }

      out_sz = safe_snprintf( *out_buf, *out_buf_sz, "], " );
      *out_buf    += out_sz;
      *out_buf_sz -= out_sz;

      cur_buf  += data_sz;

      break;
    }

    case 0x1c: /* connection close */
    {
      /* the conn_close_1_frame structure is different to conn_close_0_frame */
      ulong reason_phrase_length = data.conn_close_0_frame.reason_phrase_length;
      ulong remain               = (ulong)( buf_end - cur_buf );
      if( FD_UNLIKELY( reason_phrase_length > remain ) ) {
        ulong out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\"" );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;

        return FD_QUIC_PARSE_FAIL;
      }

      /* TODO trace the reason phrase */

      cur_buf += reason_phrase_length;

      break;
    }

    case 0x1d: /* connection close */
    {
      /* the conn_close_1_frame structure is different to conn_close_0_frame */
      ulong reason_phrase_length = data.conn_close_1_frame.reason_phrase_length;
      ulong remain               = (ulong)( buf_end - cur_buf );
      if( FD_UNLIKELY( reason_phrase_length > remain ) ) {
        ulong out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\"" );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;

        return FD_QUIC_PARSE_FAIL;
      }

      /* TODO trace the reason phrase */

      cur_buf += reason_phrase_length;

      break;
    }
  }

  return (ulong)( cur_buf - buf );

}

void
fd_quic_trace_v1_frames( uchar const *     buf,
                         ulong             buf_sz ) {
  static char trace_buf[16384];

  char * out_buf    = &trace_buf[0];
  ulong  out_buf_sz = sizeof( trace_buf ) - 1UL;

  ulong sz = safe_snprintf( out_buf, out_buf_sz, "{ \"type\": \"packet\", \"frames\": [ " );
  out_buf    += sz;
  out_buf_sz -= sz;

  while( buf_sz > 0 ) {
    sz          = safe_snprintf( out_buf, out_buf_sz, "{ \"type\": \"frame\", " );
    out_buf    += sz;
    out_buf_sz -= sz;

    ulong rc = fd_quic_trace_v1_frame( &out_buf, &out_buf_sz, buf, buf_sz );
    if( rc == FD_QUIC_PARSE_FAIL ) break;

    sz          = safe_snprintf( out_buf, out_buf_sz, " }, " );
    out_buf    += sz;
    out_buf_sz -= sz;

    if( rc >= buf_sz ) break;

    buf    += rc;
    buf_sz -= rc;
  }

  sz          = safe_snprintf( out_buf, out_buf_sz, " ] }, " );
  out_buf    += sz;
  out_buf_sz -= sz;

  *out_buf = '\0';

  /* TODO out_buf should be output here */
  printf( "TRACE: %s\n", trace_buf );
}
