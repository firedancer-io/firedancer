#pragma GCC diagnostic ignored "-Wtype-limits"

#include "templ/fd_quic_pretty_print.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"
#include "fd_quic_private.h"
#include "fd_quic_pretty_print.h"

/* Generate frame pretty-print */

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                    \
  static ulong fd_quic_pretty_print_frame_##NAME(                          \
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
    fd_quic_pretty_print_struct_##NAME( out_buf, out_buf_sz, frame );      \
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
    if( rtn > (int)(sz) ) rtn = (int)(sz); \
    (ulong)rtn; }))

ulong
fd_quic_pretty_print_frame( char **           out_buf,
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
      consumed = fd_quic_pretty_print_frame_##NAME##_frame( &data.NAME##_frame, out_buf, out_buf_sz, cur_buf, (ulong)( buf_end - cur_buf ) ); \
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
      ulong ack_range_count = data.ack_frame.ack_range_count;

      /* skip ack ranges */
      for( ulong j = 0UL; j < ack_range_count; ++j ) {
        fd_quic_ack_range_frag_t ack_range[1];
        ulong rc = fd_quic_decode_ack_range_frag( ack_range, cur_buf, (ulong)( buf_end - cur_buf ) );
        if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
          ulong out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"parse-ack-ranges\"" );
          *out_buf    += out_sz;
          *out_buf_sz -= out_sz;
          return FD_QUIC_PARSE_FAIL;
        }

        fd_quic_pretty_print_struct_ack_range_frag( out_buf, out_buf_sz, ack_range );
      }

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
        out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\", " );
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
      ulong fin         = (ulong)data.stream_frame.fin_opt;

      ulong out_sz = safe_snprintf(
                       *out_buf,
                       *out_buf_sz,
                       "\"stream_type\": %u, \"offset\": %lu, \"length\": %lu, \"fin\": %lu, ",
                       (uint)stream_type, offset, data_sz, fin );
      *out_buf    += out_sz;
      *out_buf_sz -= out_sz;

      if( data_sz > remain ) {
        out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\", " );
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
        ulong out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\", " );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;

        return FD_QUIC_PARSE_FAIL;
      }

      /* TODO pretty print the reason phrase */

      cur_buf += reason_phrase_length;

      break;
    }

    case 0x1d: /* connection close */
    {
      /* the conn_close_1_frame structure is different to conn_close_0_frame */
      ulong reason_phrase_length = data.conn_close_1_frame.reason_phrase_length;
      ulong remain               = (ulong)( buf_end - cur_buf );
      if( FD_UNLIKELY( reason_phrase_length > remain ) ) {
        ulong out_sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"overflow\", " );
        *out_buf    += out_sz;
        *out_buf_sz -= out_sz;

        return FD_QUIC_PARSE_FAIL;
      }

      /* TODO pretty print the reason phrase */

      cur_buf += reason_phrase_length;

      break;
    }
  }

  return (ulong)( cur_buf - buf );

}

ulong
fd_quic_pretty_print_frames( char **           out_buf,
                             ulong *           out_buf_sz,
                             uchar const *     buf,
                             ulong             buf_sz );


ulong
fd_quic_pretty_print_quic_hdr_initial( char **        out_buf,
                                       ulong *        out_buf_sz,
                                       uchar const ** frame_ptr,
                                       ulong *        frame_sz,
                                       uchar const *  buf,
                                       ulong          buf_sz ) {
  ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"hdr_type\": \"initial\", " );
  *out_buf    += sz;
  *out_buf_sz -= sz;

  fd_quic_initial_t initial[1] = {0};
  ulong rc = fd_quic_decode_initial( initial, buf, buf_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"hdr_parse_failed\", " );
    *out_buf    += sz;
    *out_buf_sz -= sz;

    FD_LOG_HEXDUMP_ERR(( "hdr_parse_failed", buf, fd_ulong_min( 16, buf_sz ) ));

    return FD_QUIC_PARSE_FAIL;
  }

  ulong body_sz       = initial->len;  /* not a protected field */
  ulong pn_offset     = initial->pkt_num_pnoff;
  ulong pkt_number_sz = fd_quic_h0_pkt_num_len( buf[0] ) + 1u;
  ulong payload_off   = pn_offset + pkt_number_sz;

  /* now we have decrypted packet number */
  ulong pkt_number = fd_quic_pktnum_decode( buf+pn_offset, pkt_number_sz );

  /* write pkt_number_sz into initial, for tracing */
  /* note this is the raw packet number, which may have been truncated */
  initial->pkt_num = pkt_number;

  *frame_ptr   = buf + payload_off;
  *frame_sz    = body_sz - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */

  fd_quic_pretty_print_struct_initial( out_buf, out_buf_sz, initial );

  return payload_off;
}


ulong
fd_quic_pretty_print_quic_hdr_handshake( char **        out_buf,
                                         ulong *        out_buf_sz,
                                         uchar const ** frame_ptr,
                                         ulong *        frame_sz,
                                         uchar const *  buf,
                                         ulong          buf_sz ) {
  ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"hdr_type\": \"handshake\", " );
  *out_buf    += sz;
  *out_buf_sz -= sz;

  fd_quic_handshake_t handshake[1] = {0};
  ulong rc = fd_quic_decode_handshake( handshake, buf, buf_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"hdr_parse_failed\", " );
    *out_buf    += sz;
    *out_buf_sz -= sz;

    FD_LOG_HEXDUMP_ERR(( "hdr_parse_failed", buf, fd_ulong_min( 16, buf_sz ) ));

    return FD_QUIC_PARSE_FAIL;
  }

  ulong body_sz       = handshake->len;  /* not a protected field */
  ulong pn_offset     = handshake->pkt_num_pnoff;
  ulong pkt_number_sz = fd_quic_h0_pkt_num_len( buf[0] ) + 1u;
  ulong payload_off   = pn_offset + pkt_number_sz;

  /* now we have decrypted packet number */
  ulong pkt_number = fd_quic_pktnum_decode( buf+pn_offset, pkt_number_sz );

  /* write pkt_number_sz into handshake, for tracing */
  /* note this is the raw packet number, which may have been truncated */
  handshake->pkt_num = pkt_number;

  *frame_ptr   = buf + payload_off;
  *frame_sz    = body_sz - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */

  fd_quic_pretty_print_struct_handshake( out_buf, out_buf_sz, handshake );

  return payload_off;
}


ulong
fd_quic_pretty_print_quic_hdr_one_rtt( char **        out_buf,
                                       ulong *        out_buf_sz,
                                       uchar const ** frame_ptr,
                                       ulong *        frame_sz,
                                       uchar const *  buf,
                                       ulong          buf_sz ) {
  ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"hdr_type\": \"1-rtt\", " );
  *out_buf    += sz;
  *out_buf_sz -= sz;

  fd_quic_one_rtt_t one_rtt[1] = {0};

  /* hidden field needed by decode function */
  one_rtt->dst_conn_id_len = 8;

  ulong rc = fd_quic_decode_one_rtt( one_rtt, buf, buf_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    ulong sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"hdr_parse_failed\", " );
    *out_buf    += sz;
    *out_buf_sz -= sz;

    FD_LOG_HEXDUMP_ERR(( "hdr_parse_failed", buf, fd_ulong_min( 16, buf_sz ) ));

    return FD_QUIC_PARSE_FAIL;
  }

  ulong pn_offset     = one_rtt->pkt_num_pnoff;
  ulong pkt_number_sz = fd_quic_h0_pkt_num_len( buf[0] ) + 1u;
  ulong payload_off   = pn_offset + pkt_number_sz;
  ulong payload_sz    = buf_sz - pn_offset - pkt_number_sz; /* includes auth tag */

  /* now we have decrypted packet number */
  ulong pkt_number = fd_quic_pktnum_decode( buf+pn_offset, pkt_number_sz );

  /* write pkt_number_sz into one_rtt, for tracing */
  /* note this is the raw packet number, which may have been truncated */
  one_rtt->pkt_num = pkt_number;

  *frame_ptr   = buf + payload_off;
  *frame_sz    = payload_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */

  fd_quic_pretty_print_struct_one_rtt( out_buf, out_buf_sz, one_rtt );

  return payload_off;
}


ulong
fd_quic_pretty_print_quic_hdr( char **        out_buf,
                               ulong *        out_buf_sz,
                               uchar const ** frame_ptr,
                               ulong *        frame_sz,
                               uchar const *  buf,
                               ulong          buf_sz ) {
  ulong sz;

  uint first   = (uint)buf[0];
  uint is_long = first >> 7u;

  if( !is_long ) {
      return fd_quic_pretty_print_quic_hdr_one_rtt( out_buf, out_buf_sz, frame_ptr, frame_sz, buf, buf_sz );
  }

  uint long_type = ( first >> 4u ) & 0x03u;

  switch( long_type ) {
    case 0x00: /* initial */
      return fd_quic_pretty_print_quic_hdr_initial( out_buf, out_buf_sz, frame_ptr, frame_sz, buf, buf_sz );
    case 0x01: /* 0-rtt - unused */
      sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"0-rtt\", " );
      *out_buf    += sz;
      *out_buf_sz -= sz;
      return FD_QUIC_PARSE_FAIL;
    case 0x02: /* handshake */
      return fd_quic_pretty_print_quic_hdr_handshake( out_buf, out_buf_sz, frame_ptr, frame_sz, buf, buf_sz );
    case 0x03:
      sz = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"not-implemented-retry\", " );
      *out_buf    += sz;
      *out_buf_sz -= sz;
      return FD_QUIC_PARSE_FAIL;
  }

  /* long type is uint & 0x03u - yet gcc thinks this is reachable */
  return FD_QUIC_PARSE_FAIL;
}


ulong
fd_quic_pretty_print_quic_pkt( fd_quic_pretty_print_t * pretty_print,
                               ulong                    now,
                               uchar const *            buf,
                               ulong                    buf_sz,
                               char const *             flow ) {
  (void)pretty_print;
  (void)now;

  static FD_TL char pretty_print_buf[16384];

  memset( pretty_print_buf, 0, sizeof( pretty_print_buf ) );

  char * out_buf    = &pretty_print_buf[0];
  ulong  out_buf_sz = sizeof( pretty_print_buf ) - 1UL;

  uchar const * frame_ptr = NULL;
  ulong         frame_sz  = 0;

  ulong sz = safe_snprintf( out_buf, out_buf_sz, "{ \"type\": \"packet\", \"flow\": \"%s\", ", flow );
  out_buf    += sz;
  out_buf_sz -= sz;

  ulong hdr_rc = fd_quic_pretty_print_quic_hdr( &out_buf,
                                                &out_buf_sz,
                                                &frame_ptr,
                                                &frame_sz,
                                                buf,
                                                buf_sz );
  if( hdr_rc == FD_QUIC_PARSE_FAIL ) {
    sz = safe_snprintf( out_buf, out_buf_sz, "\"err\": \"parse_fail\" } " );
    out_buf    += sz;
    out_buf_sz -= sz;

    return FD_QUIC_PARSE_FAIL;
  }

  sz = safe_snprintf( out_buf, out_buf_sz, "\"frames\": [ " );
  out_buf    += sz;
  out_buf_sz -= sz;

  ulong rc = fd_quic_pretty_print_frames( &out_buf,
                                          &out_buf_sz,
                                          frame_ptr,
                                          frame_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    sz = safe_snprintf( out_buf, out_buf_sz, "], \"err\": \"parse_fail\" }, " );
    out_buf    += sz;
    out_buf_sz -= sz;
    printf( "\nTRACE: %s\n", pretty_print_buf );
    fflush( stdout );
    return FD_QUIC_PARSE_FAIL;
  }

  sz = safe_snprintf( out_buf, out_buf_sz, "] }, " );
  out_buf    += sz;
  out_buf_sz -= sz;

  for( ulong j = 0; j < (ulong)( out_buf - pretty_print_buf); ++j ) {
    if( pretty_print_buf[j] == '\0' ) pretty_print_buf[j] = '*';
  }

  //FD_LOG_NOTICE(( "TRACE: [ %s ]", pretty_print_buf ));
  printf( "TRACE: [ %s ]\n", pretty_print_buf );

  return rc;
}

ulong
fd_quic_pretty_print_frames( char **           out_buf,
                             ulong *           out_buf_sz,
                             uchar const *     buf,
                             ulong             buf_sz ) {
  uchar const * orig_buf = buf;
  ulong sz;

  while( buf_sz > 0 ) {
    sz          = safe_snprintf( *out_buf, *out_buf_sz, "{ \"type\": \"frame\", " );
    *out_buf    += sz;
    *out_buf_sz -= sz;

    ulong rc = fd_quic_pretty_print_frame( out_buf, out_buf_sz, buf, buf_sz );
    if( rc == FD_QUIC_PARSE_FAIL ) {
      sz          = safe_snprintf( *out_buf, *out_buf_sz, "\"err\": \"parse_fail\" }, " );
      *out_buf    += sz;
      *out_buf_sz -= sz;
      break;
    }

    sz          = safe_snprintf( *out_buf, *out_buf_sz, " }, " );
    *out_buf    += sz;
    *out_buf_sz -= sz;

    if( rc >= buf_sz ) break;

    buf    += rc;
    buf_sz -= rc;
  }

  return (ulong)( buf - orig_buf );
}
